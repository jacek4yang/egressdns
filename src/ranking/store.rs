//! Bounded storage of per-address quality statistics.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;

use crate::config::RankingConfig;
use crate::ranking::model::{ObservationClass, PersistedQuality, QualityStats};

/// Identity of a measurement series.
///
/// Measurements are keyed by more than the address: the same address can behave very
/// differently for different services and ports, and evidence from one network generation
/// must not be mixed with another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    /// Target address.
    pub addr: IpAddr,
    /// Target port.
    pub port: u16,
    /// Bounded profile identifier, for example `https:www.example.com` or `generic`.
    pub profile: Arc<str>,
}

impl ProbeKey {
    /// A key for a hostname-specific HTTPS measurement.
    pub fn https(addr: IpAddr, port: u16, hostname: &str) -> Self {
        Self {
            addr,
            port,
            profile: Arc::from(format!("https:{}", hostname.trim_end_matches('.'))),
        }
    }

    /// A key for a generic reachability measurement.
    pub fn generic(addr: IpAddr, port: u16) -> Self {
        Self {
            addr,
            port,
            profile: Arc::from("generic"),
        }
    }

    /// A key for a QUIC/HTTP-3 reachability measurement.
    ///
    /// Kept separate from the HTTPS key on purpose: QUIC uses UDP/443, which is blocked on
    /// far more paths than TCP/443, so mixing the two would let a blocked UDP path drag
    /// down an address that is perfectly good over TCP.
    pub fn quic(addr: IpAddr, port: u16) -> Self {
        Self {
            addr,
            port,
            profile: Arc::from("quic"),
        }
    }

    /// True when the key describes an IPv4 measurement.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }
}

/// Bounded store of quality statistics.
pub struct QualityStore {
    inner: Mutex<HashMap<ProbeKey, QualityStats>>,
    capacity: usize,
}

impl QualityStore {
    /// Create a store with a hard capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Record an observation.
    pub fn record(
        &self,
        key: ProbeKey,
        class: ObservationClass,
        latency: Option<Duration>,
        generation: u64,
        now: Instant,
        cfg: &RankingConfig,
    ) {
        let mut map = self.inner.lock();
        if map.len() >= self.capacity && !map.contains_key(&key) {
            evict(&mut map, self.capacity / 16 + 1);
        }
        let entry = map
            .entry(key)
            .or_insert_with(|| QualityStats::new(generation));
        if entry.generation() != generation {
            entry.demote_to_prior(generation, cfg.neutral_cost_ms.min(1.0));
        }
        entry.record(class, latency, now, cfg);
    }

    /// Read the statistics for a key.
    pub fn get(&self, key: &ProbeKey) -> Option<QualityStats> {
        self.inner.lock().get(key).cloned()
    }

    /// Build the address-keyed map the answer policy needs.
    ///
    /// Addresses with no applicable evidence are simply absent, which the ranking code
    /// treats as neutral.
    pub fn snapshot_for(
        &self,
        addrs: &[IpAddr],
        port: u16,
        hostname: &str,
    ) -> HashMap<IpAddr, QualityStats> {
        let map = self.inner.lock();
        let mut out = HashMap::with_capacity(addrs.len());
        for addr in addrs {
            let specific = ProbeKey::https(*addr, port, hostname);
            if let Some(s) = map.get(&specific) {
                out.insert(*addr, s.clone());
                continue;
            }
            let generic = ProbeKey::generic(*addr, port);
            if let Some(s) = map.get(&generic) {
                out.insert(*addr, s.clone());
            }
        }
        out
    }

    /// Apply a network-generation change to every series.
    pub fn on_generation_change(&self, generation: u64, factor: f64) {
        let mut map = self.inner.lock();
        for s in map.values_mut() {
            s.demote_to_prior(generation, factor);
        }
    }

    /// Number of tracked series.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export every series for persistence.
    pub fn export(&self) -> Vec<(ProbeKey, PersistedQuality)> {
        self.inner
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.to_persisted()))
            .collect()
    }

    /// Import persisted series.
    pub fn import(&self, rows: impl IntoIterator<Item = (ProbeKey, PersistedQuality)>) {
        let mut map = self.inner.lock();
        for (key, p) in rows {
            if map.len() >= self.capacity {
                break;
            }
            map.insert(
                key,
                QualityStats::from_persisted(
                    p.generation,
                    p.alpha,
                    p.beta,
                    p.ewma_ms,
                    p.p95_ms,
                    p.jitter_ms,
                    p.samples,
                    p.successes,
                ),
            );
        }
    }

    /// Remove everything.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

fn evict(map: &mut HashMap<ProbeKey, QualityStats>, count: usize) {
    let mut victims: Vec<(ProbeKey, u32)> = map
        .iter()
        .map(|(k, v)| (k.clone(), v.sample_count()))
        .collect();
    victims.sort_by_key(|(_, n)| *n);
    for (k, _) in victims.into_iter().take(count) {
        map.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    #[tokio::test(start_paused = true)]
    async fn records_and_reads_back() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let store = QualityStore::new(100);
        let key = ProbeKey::https(ip("104.16.0.1"), 443, "example.com");
        store.record(
            key.clone(),
            ObservationClass::Success,
            Some(Duration::from_millis(12)),
            1,
            now,
            &cfg,
        );
        let s = store.get(&key).expect("present");
        assert_eq!(s.success_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_is_enforced() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let store = QualityStore::new(32);
        for i in 0..500u32 {
            let key = ProbeKey::generic(ip(&format!("104.16.{}.{}", i / 256, i % 256)), 443);
            store.record(key, ObservationClass::Success, None, 1, now, &cfg);
        }
        assert!(store.len() <= 32, "grew to {}", store.len());
    }

    #[tokio::test(start_paused = true)]
    async fn hostname_specific_evidence_wins_over_generic() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let store = QualityStore::new(100);
        let addr = ip("104.16.0.1");
        store.record(
            ProbeKey::generic(addr, 443),
            ObservationClass::Success,
            Some(Duration::from_millis(200)),
            1,
            now,
            &cfg,
        );
        store.record(
            ProbeKey::https(addr, 443, "example.com"),
            ObservationClass::Success,
            Some(Duration::from_millis(5)),
            1,
            now,
            &cfg,
        );
        let snap = store.snapshot_for(&[addr], 443, "example.com");
        assert!((snap[&addr].ewma_ms() - 5.0).abs() < 0.001);
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_addresses_are_absent_from_the_snapshot() {
        let store = QualityStore::new(10);
        let snap = store.snapshot_for(&[ip("104.16.0.1")], 443, "example.com");
        assert!(snap.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn generation_change_weakens_everything() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let store = QualityStore::new(100);
        let key = ProbeKey::generic(ip("104.16.0.1"), 443);
        for _ in 0..50 {
            store.record(
                key.clone(),
                ObservationClass::Success,
                Some(Duration::from_millis(5)),
                1,
                now,
                &cfg,
            );
        }
        let strong = store
            .get(&key)
            .expect("present")
            .success_probability_lower_bound();
        store.on_generation_change(2, 0.25);
        let weak = store.get(&key).expect("present");
        assert_eq!(weak.generation(), 2);
        assert!(weak.success_probability_lower_bound() < strong);
    }

    #[tokio::test(start_paused = true)]
    async fn export_import_round_trip() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let store = QualityStore::new(100);
        let key = ProbeKey::https(ip("104.16.0.1"), 443, "example.com");
        for _ in 0..10 {
            store.record(
                key.clone(),
                ObservationClass::Success,
                Some(Duration::from_millis(20)),
                7,
                now,
                &cfg,
            );
        }
        let exported = store.export();
        let restored = QualityStore::new(100);
        restored.import(exported);
        let s = restored.get(&key).expect("present");
        assert_eq!(s.sample_count(), 10);
        assert_eq!(s.generation(), 7);
    }
}
