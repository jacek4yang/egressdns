//! Hot-name prefetching.
//!
//! Popular names are refreshed shortly before they expire so that the common case is
//! always a cache hit. The whole mechanism is budgeted: a global queries-per-second
//! ceiling that also sizes the in-flight semaphore, and a per-key minimum interval. If
//! the foreground path starts to suffer, prefetching disables itself rather than
//! competing with real queries.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::cache::hotset::SharedHotSet;
use crate::cache::{DnsCache, Lookup};
use crate::config::PrefetchConfig;
use crate::dns::resolver::Resolver;

/// Runtime state of the prefetcher, exposed through the admin socket.
#[derive(Debug, Default)]
pub struct PrefetchState {
    enabled: AtomicBool,
    issued: AtomicU64,
    skipped: AtomicU64,
}

impl PrefetchState {
    /// Create the state, initially enabled.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            issued: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        }
    }

    /// Whether prefetching is currently active.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Disable prefetching, for example under sustained pressure.
    pub fn disable(&self, reason: &str) {
        if self.enabled.swap(false, Ordering::Relaxed) {
            tracing::warn!(event = "prefetch.disabled", reason);
        }
    }

    /// Re-enable prefetching.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// Set the enabled state, used by a configuration reload.
    pub fn set_enabled(&self, enabled: bool) {
        if self.enabled.swap(enabled, Ordering::Relaxed) != enabled {
            tracing::info!(event = "prefetch.enabled_changed", enabled);
        }
    }

    /// Count one issued prefetch.
    pub fn count_issued(&self) {
        self.issued.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of prefetches issued.
    pub fn issued(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }

    /// Number of candidates skipped for budget reasons.
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }
}

/// Run the prefetcher until cancelled.
pub async fn run(ctx: super::Ctx) {
    let Some(app) = ctx.app() else { return };
    let cache = Arc::clone(&app.cache);
    let hotset = Arc::clone(&app.hotset);
    let state = Arc::clone(&app.prefetch);
    let cancel = ctx.cancel.clone();
    drop(app);

    let mut budget_cache: Option<(u32, Arc<Semaphore>)> = None;
    let mut round: u64 = 0;
    let mut warmed = false;

    loop {
        if !super::tick(Duration::from_secs(1), &cancel).await {
            return;
        }
        round = round.wrapping_add(1);

        // Live configuration and, critically, the *current* resolver. Capturing the
        // resolver once meant prefetch kept using the pre-reload upstream registry for the
        // lifetime of the process — including a registry whose connections had already
        // been drained.
        let Some(config) = ctx.config() else {
            return;
        };
        let cfg = config.prefetch.clone();
        let Some(resolver) = ctx.resolver() else {
            return;
        };
        if !cfg.enabled || !state.is_enabled() {
            continue;
        }
        let qps = cfg.global_qps.max(1);
        let budget = match &budget_cache {
            Some((n, sem)) if *n == qps => Arc::clone(sem),
            _ => {
                let sem = Arc::new(Semaphore::new(qps as usize));
                budget_cache = Some((qps, Arc::clone(&sem)));
                sem
            }
        };

        let now = Instant::now();
        if !warmed && cfg.warm_on_start > 0 {
            warmed = true;
            warm_start(&cfg, &resolver, &hotset, &state, &cancel, now).await;
        }
        let candidates = select_candidates(&cfg, &cache, &hotset, now);
        for key in candidates.into_iter().take(cfg.global_qps.max(1) as usize) {
            let Ok(permit) = Arc::clone(&budget).try_acquire_owned() else {
                state.skipped.fetch_add(1, Ordering::Relaxed);
                break;
            };
            hotset.mark_prefetch(&key, now);
            state.issued.fetch_add(1, Ordering::Relaxed);
            let resolver = Arc::clone(&resolver);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let outcome = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    r = resolver.refresh(key) => r,
                };
                metrics::counter!(
                    crate::metrics::names::PREFETCH_TOTAL,
                    "outcome" => if outcome.is_ok() { "ok" } else { "failed" },
                )
                .increment(1);
            });
        }
    }
}

/// Refresh the hottest known names once, shortly after startup.
///
/// After a restart the cache is empty but the hot set has been restored from persisted
/// state, so the names this LAN actually uses are known. Warming them turns the first query
/// for each into a cache hit instead of an upstream round trip. Bounded by
/// `prefetch.warm_on_start` and by the same per-round budget as ordinary prefetching, and
/// skipped entirely when the hot set is empty.
async fn warm_start(
    cfg: &PrefetchConfig,
    resolver: &Arc<Resolver>,
    hotset: &SharedHotSet,
    state: &Arc<PrefetchState>,
    cancel: &CancellationToken,
    now: Instant,
) {
    let want = cfg.warm_on_start.min(cfg.hot_set_size).min(1_024);
    let keys: Vec<crate::cache::CacheKey> = hotset
        .top(want)
        .into_iter()
        .map(|(key, _)| key)
        .take(want)
        .collect();
    if keys.is_empty() {
        return;
    }
    tracing::info!(event = "prefetch.warm_start", names = keys.len());
    let permits = Arc::new(Semaphore::new(cfg.global_qps.max(1) as usize));
    let mut tasks = tokio::task::JoinSet::new();
    for key in keys {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            break;
        };
        if cancel.is_cancelled() {
            break;
        }
        hotset.mark_prefetch(&key, now);
        state.count_issued();
        let resolver = Arc::clone(resolver);
        tasks.spawn(async move {
            let _permit = permit;
            let _ = resolver.refresh(key).await;
        });
    }
    // Bounded: the warm-up never outlives its own deadline, and never blocks steady-state
    // prefetching behind it.
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .is_err()
    {
        tasks.abort_all();
    }
}

/// Choose which hot keys are close enough to expiry to be worth refreshing.
pub fn select_candidates(
    cfg: &PrefetchConfig,
    cache: &DnsCache,
    hotset: &SharedHotSet,
    now: Instant,
) -> Vec<crate::cache::CacheKey> {
    let mut out = Vec::new();
    for (key, entry) in hotset.top(cfg.hot_set_size.min(4_096)) {
        if entry.hits < u64::from(cfg.min_hits) {
            continue;
        }
        if let Some(last) = entry.last_prefetch {
            if now.saturating_duration_since(last) < cfg.per_key_min_interval {
                continue;
            }
        }
        match cache.get(&key, now) {
            Lookup::Fresh {
                entry: cached,
                remaining,
            } => {
                if cached.ttl == 0 {
                    continue;
                }
                let fraction = f64::from(remaining) / f64::from(cached.ttl);
                if fraction <= cfg.trigger_fraction {
                    out.push(key);
                }
            }
            // Expired entries are refreshed by the next real query or by serve-stale, not
            // speculatively: prefetching data nobody asked for again wastes budget.
            _ => continue,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::hotset::HotSet;
    use crate::cache::{
        AnswerSource, CacheEntry, CacheKey, DnssecMode, DnssecStatus, EntryKind, PolicyView,
    };
    use crate::config::{CacheConfig, ServeStaleConfig, TransportKind};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;

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

    fn entry(ttl: u32, now: Instant) -> Arc<CacheEntry> {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("hot.example.").expect("name"),
            RecordType::A,
        ));
        m.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_str("hot.example.").expect("name"),
            ttl,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                "1.2.3.4".parse().expect("v4"),
            )),
        ));
        Arc::new(CacheEntry {
            approx_bytes: 256,
            fingerprint: 1,
            message: Arc::new(m),
            received_at: now,
            received_unix: 0,
            ttl,
            kind: EntryKind::Positive,
            dnssec: DnssecStatus::Insecure,
            source: AnswerSource {
                server: Arc::from("test"),
                transport: TransportKind::Udp,
            },
            rrsig_expiry_unix: None,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn only_nearly_expired_hot_names_are_selected() {
        let cfg = PrefetchConfig {
            min_hits: 2,
            trigger_fraction: 0.2,
            ..PrefetchConfig::default()
        };
        let cache = DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default());
        let hotset: SharedHotSet = Arc::new(HotSet::new(64, 600.0, 0));
        let now = Instant::now();

        let fresh = key("fresh.example.");
        let expiring = key("hot.example.");
        cache.insert(fresh.clone(), entry(300, now));
        cache.insert(expiring.clone(), entry(100, now));
        for _ in 0..5 {
            hotset.observe(&fresh, None, now);
            hotset.observe(&expiring, None, now);
        }

        let later = now + Duration::from_secs(90);
        let picks = select_candidates(&cfg, &cache, &hotset, later);
        assert!(picks.contains(&expiring));
        assert!(!picks.contains(&fresh));
    }

    #[tokio::test(start_paused = true)]
    async fn unpopular_names_are_never_prefetched() {
        let cfg = PrefetchConfig {
            min_hits: 10,
            trigger_fraction: 0.9,
            ..PrefetchConfig::default()
        };
        let cache = DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default());
        let hotset: SharedHotSet = Arc::new(HotSet::new(64, 600.0, 0));
        let now = Instant::now();
        let k = key("cold.example.");
        cache.insert(k.clone(), entry(100, now));
        hotset.observe(&k, None, now);
        assert!(select_candidates(&cfg, &cache, &hotset, now).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn per_key_interval_is_respected() {
        let cfg = PrefetchConfig {
            min_hits: 1,
            trigger_fraction: 0.99,
            per_key_min_interval: Duration::from_secs(60),
            ..PrefetchConfig::default()
        };
        let cache = DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default());
        let hotset: SharedHotSet = Arc::new(HotSet::new(64, 600.0, 0));
        let t0 = Instant::now();
        let k = key("hot.example.");
        cache.insert(k.clone(), entry(300, t0));
        hotset.observe(&k, None, t0);

        // A brand-new entry has a remaining fraction of exactly 1.0 and is never a
        // prefetch candidate; only an entry inside the trigger window is.
        assert!(select_candidates(&cfg, &cache, &hotset, t0).is_empty());

        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(select_candidates(&cfg, &cache, &hotset, t1).len(), 1);

        hotset.mark_prefetch(&k, t1);
        assert!(
            select_candidates(&cfg, &cache, &hotset, t1).is_empty(),
            "a key just prefetched must not be prefetched again"
        );

        let t2 = t1 + Duration::from_secs(61);
        assert_eq!(select_candidates(&cfg, &cache, &hotset, t2).len(), 1);
    }
    #[tokio::test]
    async fn prefetch_state_can_be_disabled() {
        let s = PrefetchState::new(true);
        assert!(s.is_enabled());
        s.disable("test");
        assert!(!s.is_enabled());
        s.enable();
        assert!(s.is_enabled());
    }
}
