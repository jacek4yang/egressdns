//! Bounded query-popularity tracking used to drive prefetching.
//!
//! Popularity is tracked in aggregate only. Per-client histories are never recorded and
//! query names are never exported as metric labels.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::time::Instant;

use super::CacheKey;

/// One tracked entry.
#[derive(Debug, Clone)]
pub struct HotEntry {
    /// Decayed hit count.
    pub score: f32,
    /// Raw lifetime hit count.
    pub hits: u64,
    /// Last observation.
    pub last_seen: Instant,
    /// Last time a prefetch was issued for this key.
    pub last_prefetch: Option<Instant>,
}

/// Bounded hot-name tracker with exponential decay.
pub struct HotSet {
    inner: Mutex<Inner>,
    capacity: usize,
    half_life_secs: f32,
}

struct Inner {
    map: HashMap<CacheKey, HotEntry>,
    last_decay: Instant,
    /// Bounded aggregate transition table: `previous key -> next key -> weight`.
    transitions: HashMap<CacheKey, HashMap<CacheKey, f32>>,
    transition_capacity: usize,
}

impl HotSet {
    /// Create a tracker.
    pub fn new(capacity: usize, half_life_secs: f32, transition_capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                last_decay: Instant::now(),
                transitions: HashMap::new(),
                transition_capacity,
            }),
            capacity: capacity.max(1),
            half_life_secs: half_life_secs.max(1.0),
        }
    }

    /// Record an observation of `key`, optionally noting the key that preceded it.
    pub fn observe(&self, key: &CacheKey, previous: Option<&CacheKey>, now: Instant) {
        let mut inner = self.inner.lock();
        self.decay_locked(&mut inner, now);
        let entry = inner.map.entry(key.clone()).or_insert(HotEntry {
            score: 0.0,
            hits: 0,
            last_seen: now,
            last_prefetch: None,
        });
        entry.score += 1.0;
        entry.hits += 1;
        entry.last_seen = now;

        if inner.map.len() > self.capacity {
            self.evict_locked(&mut inner, key);
        }

        if inner.transition_capacity > 0 {
            if let Some(prev) = previous {
                if prev != key {
                    let cap = inner.transition_capacity;
                    let row = inner.transitions.entry(prev.clone()).or_default();
                    let w = row.entry(key.clone()).or_insert(0.0);
                    *w += 1.0;
                    if row.len() > 8 {
                        // Keep only the strongest successors.
                        let mut items: Vec<_> = row.iter().map(|(k, v)| (k.clone(), *v)).collect();
                        items.sort_by(|a, b| b.1.total_cmp(&a.1));
                        items.truncate(8);
                        *row = items.into_iter().collect();
                    }
                    if inner.transitions.len() > cap {
                        let victim = inner.transitions.keys().next().cloned();
                        if let Some(v) = victim {
                            inner.transitions.remove(&v);
                        }
                    }
                }
            }
        }
    }

    /// Record that a prefetch was issued for `key`.
    pub fn mark_prefetch(&self, key: &CacheKey, now: Instant) {
        let mut inner = self.inner.lock();
        if let Some(e) = inner.map.get_mut(key) {
            e.last_prefetch = Some(now);
        }
    }

    /// Read the tracked entry for a key.
    pub fn get(&self, key: &CacheKey) -> Option<HotEntry> {
        self.inner.lock().map.get(key).cloned()
    }

    /// The `n` hottest keys, most popular first.
    pub fn top(&self, n: usize) -> Vec<(CacheKey, HotEntry)> {
        let inner = self.inner.lock();
        let mut items: Vec<_> = inner
            .map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        items.sort_by(|a, b| b.1.score.total_cmp(&a.1.score));
        items.truncate(n);
        items
    }

    /// Likely successors of `key`, strongest first.
    pub fn successors(&self, key: &CacheKey, n: usize) -> Vec<CacheKey> {
        let inner = self.inner.lock();
        let Some(row) = inner.transitions.get(key) else {
            return Vec::new();
        };
        let mut items: Vec<_> = row.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| b.1.total_cmp(&a.1));
        items.truncate(n);
        items.into_iter().map(|(k, _)| k).collect()
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    /// True when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop everything.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.map.clear();
        inner.transitions.clear();
    }

    fn decay_locked(&self, inner: &mut Inner, now: Instant) {
        let elapsed = now
            .saturating_duration_since(inner.last_decay)
            .as_secs_f32();
        if elapsed < 1.0 {
            return;
        }
        let factor = 0.5f32.powf(elapsed / self.half_life_secs);
        if factor >= 0.999 {
            inner.last_decay = now;
            return;
        }
        for e in inner.map.values_mut() {
            e.score *= factor;
        }
        inner.map.retain(|_, e| e.score > 0.01);
        for row in inner.transitions.values_mut() {
            for w in row.values_mut() {
                *w *= factor;
            }
            row.retain(|_, w| *w > 0.01);
        }
        inner.transitions.retain(|_, row| !row.is_empty());
        inner.last_decay = now;
    }

    /// Trim the map back under its ceiling.
    ///
    /// This runs on the request path, so its cost matters more than its precision. The
    /// obvious implementation — clone every key, sort, drop the lowest — is O(n log n) with
    /// n allocations, and once the map is full it runs on *every* query: at the default
    /// ceiling that is a 20 000-element sort per DNS query, under a global mutex. Measured
    /// end to end it cost roughly a factor of four in miss-heavy throughput.
    ///
    /// Instead: pick the eviction threshold in O(n) without sorting, drop a whole batch at
    /// once so the cost is amortised over many inserts, and never clone a key.
    ///
    /// `protect` is the key that was just observed. Excluding it is not a nicety: when the
    /// set is full of one-hit names every score is tied, so an arbitrary tie-break can
    /// evict the entry that was just inserted — and then a genuinely popular name can never
    /// accumulate a score at all, because each of its observations is undone immediately.
    fn evict_locked(&self, inner: &mut Inner, protect: &CacheKey) {
        let len = inner.map.len();
        let overflow = len.saturating_sub(self.capacity);
        if overflow == 0 || len < 2 {
            return;
        }
        // The overflow plus a tenth of the ceiling of headroom, so the next eviction is
        // many inserts away.
        let batch = (overflow + self.capacity / 10 + 1).min(len - 1).max(1);

        // Rank by score, then by recency, so among equally popular names the one seen
        // longest ago goes first.
        fn rank(a: (f32, Instant), b: (f32, Instant)) -> std::cmp::Ordering {
            a.0.total_cmp(&b.0).then(a.1.cmp(&b.1))
        }

        let mut ranks: Vec<(f32, Instant)> =
            inner.map.values().map(|e| (e.score, e.last_seen)).collect();
        let idx = batch.min(ranks.len() - 1);
        ranks.select_nth_unstable_by(idx, |a, b| rank(*a, *b));
        let threshold = ranks[idx];

        inner.map.retain(|k, e| {
            k == protect || rank((e.score, e.last_seen), threshold) == std::cmp::Ordering::Greater
        });

        // Exact ties on both score and recency are possible under a burst, so a bounded
        // second pass finishes the job.
        let mut still_over = inner.map.len().saturating_sub(self.capacity);
        if still_over > 0 {
            let victims: Vec<CacheKey> = inner
                .map
                .iter()
                .filter(|(k, _)| *k != protect)
                .map(|(k, _)| k.clone())
                .take(still_over)
                .collect();
            for k in victims {
                inner.map.remove(&k);
                still_over -= 1;
                if still_over == 0 {
                    break;
                }
            }
        }
    }
}

/// Shared handle.
pub type SharedHotSet = Arc<HotSet>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{DnssecMode, PolicyView};
    use hickory_proto::rr::{DNSClass, RecordType};
    use std::time::Duration;

    fn key(name: &str) -> CacheKey {
        CacheKey::new(
            name,
            RecordType::A,
            DNSClass::IN,
            PolicyView::plain(Arc::from("default")),
            DnssecMode {
                dnssec_ok: false,
                checking_disabled: false,
            },
        )
    }

    #[tokio::test(start_paused = true)]
    async fn tracks_and_bounds() {
        let hs = HotSet::new(8, 60.0, 8);
        let now = Instant::now();
        for i in 0..64 {
            hs.observe(&key(&format!("n{i}.example.")), None, now);
        }
        assert!(hs.len() <= 8, "grew to {}", hs.len());
    }

    #[tokio::test(start_paused = true)]
    async fn hot_names_rank_first() {
        let hs = HotSet::new(16, 60.0, 0);
        let now = Instant::now();
        for _ in 0..10 {
            hs.observe(&key("hot.example."), None, now);
        }
        hs.observe(&key("cold.example."), None, now);
        let top = hs.top(1);
        assert_eq!(top.len(), 1);
        assert_eq!(&*top[0].0.name, "hot.example.");
    }

    #[tokio::test(start_paused = true)]
    async fn scores_decay() {
        let hs = HotSet::new(16, 10.0, 0);
        let now = Instant::now();
        for _ in 0..4 {
            hs.observe(&key("a.example."), None, now);
        }
        let before = hs.get(&key("a.example.")).expect("entry").score;
        let later = now + Duration::from_secs(10);
        hs.observe(&key("b.example."), None, later);
        let after = hs.get(&key("a.example.")).expect("entry").score;
        assert!(after < before, "{after} should be below {before}");
        assert!(
            (after - before / 2.0).abs() < 0.1,
            "half-life mismatch: {after}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn transitions_are_bounded_and_ordered() {
        let hs = HotSet::new(64, 600.0, 4);
        let now = Instant::now();
        for _ in 0..5 {
            hs.observe(&key("second.example."), Some(&key("first.example.")), now);
        }
        hs.observe(&key("third.example."), Some(&key("first.example.")), now);
        let succ = hs.successors(&key("first.example."), 2);
        assert_eq!(&*succ[0].name, "second.example.");
    }
}
