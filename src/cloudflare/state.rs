//! Shared Cloudflare optimization state.
//!
//! Everything the foreground path reads is either an atomic pointer load (the prefix
//! snapshot) or a short critical section over a bounded map. Nothing here performs I/O.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::time::Instant;

use crate::config::{CloudflareConfig, CloudflareMode};

use super::candidates::CandidatePool;
use super::prefixes::PrefixSnapshot;
use super::sampler::StratifiedSampler;

/// Outcome of the most recent update of one data source.
#[derive(Debug, Clone)]
pub struct SourceStatus {
    /// Bounded source name.
    pub name: Arc<str>,
    /// Whether the last attempt succeeded.
    pub ok: bool,
    /// Bounded description of the last error.
    pub detail: String,
    /// Wall-clock second of the last attempt.
    pub attempted_unix: u64,
    /// Wall-clock second of the last success.
    pub succeeded_unix: Option<u64>,
    /// Number of items accepted by the last successful attempt.
    pub accepted: usize,
    /// Number of items rejected by the last successful attempt.
    pub rejected: usize,
}

/// Key of a domain-level validation record: origin hostname plus candidate address.
pub type ValidationKey = (Arc<str>, IpAddr);

/// Result of domain-level validation of one candidate for one hostname.
#[derive(Debug, Clone)]
pub struct DomainValidation {
    /// Consecutive successful validations.
    pub successes: u32,
    /// Consecutive failures.
    pub failures: u32,
    /// Last successful validation.
    pub last_success: Option<Instant>,
    /// Last attempt.
    pub last_attempt: Option<Instant>,
    /// Cloudflare datacentre reported during validation.
    pub colo: Option<String>,
}

impl DomainValidation {
    fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            last_success: None,
            last_attempt: None,
            colo: None,
        }
    }

    /// True when the most recent success is still inside the validity window.
    pub fn is_fresh(&self, now: Instant, ttl: Duration) -> bool {
        self.last_success
            .map(|t| now.saturating_duration_since(t) < ttl)
            .unwrap_or(false)
    }
}

/// Whether the original upstream addresses for a hostname have been shown to work.
#[derive(Debug, Clone, Default)]
pub struct BaselineState {
    /// Whether at least one original address completed TLS and HTTP validation.
    pub validated: bool,
    /// Last successful baseline validation.
    pub last_success_unix: u64,
}

/// Shared Cloudflare state.
pub struct CloudflareState {
    prefixes: ArcSwap<Option<PrefixSnapshot>>,
    pool: CandidatePool,
    sampler: StratifiedSampler,
    validations: Mutex<HashMap<ValidationKey, DomainValidation>>,
    baseline: Mutex<HashMap<Arc<str>, BaselineState>>,
    sources: Mutex<HashMap<Arc<str>, SourceStatus>>,
    /// Master switch, stored atomically so a reload can flip it without rebuilding the
    /// state. Read once per eligible answer with a relaxed load.
    enabled: AtomicBool,
    /// Configured response mode, encoded like `mode_override` so a reload can replace it
    /// with a relaxed store. Never 0; use [`mode_from_u8`] to decode.
    mode: AtomicU8,
    /// Runtime override of `mode`, set through the admin socket.
    ///
    /// Encoded as a `u8` so it can be read from the answer path with a relaxed atomic load
    /// and no lock: 0 means "no override", otherwise `mode_from_u8`. The override may only
    /// ever *weaken* the configured mode, so an operator cannot enable verified-augment at
    /// runtime and bypass the configuration rule that it requires a working probe engine.
    mode_override: AtomicU8,
    max_validation_entries: usize,
}

/// Strength ordering: a runtime override may move down this scale but never up.
fn mode_rank(mode: CloudflareMode) -> u8 {
    match mode {
        CloudflareMode::Off => 0,
        CloudflareMode::Preserve => 1,
        CloudflareMode::VerifiedAugment => 2,
    }
}

fn mode_to_u8(mode: CloudflareMode) -> u8 {
    mode_rank(mode) + 1
}

fn mode_from_u8(raw: u8) -> Option<CloudflareMode> {
    match raw {
        1 => Some(CloudflareMode::Off),
        2 => Some(CloudflareMode::Preserve),
        3 => Some(CloudflareMode::VerifiedAugment),
        _ => None,
    }
}

impl CloudflareState {
    /// Build the shared state from configuration.
    ///
    /// The compiled-in bootstrap snapshot is installed immediately so that the very first
    /// answers can already be classified correctly; it is replaced by a freshly fetched
    /// snapshot within seconds of startup.
    pub fn new(cfg: &CloudflareConfig) -> Self {
        Self {
            prefixes: ArcSwap::from_pointee(Some(PrefixSnapshot::builtin())),
            pool: CandidatePool::new(cfg.candidate_pool_max),
            sampler: StratifiedSampler::new(&cfg.sampling),
            validations: Mutex::new(HashMap::new()),
            baseline: Mutex::new(HashMap::new()),
            sources: Mutex::new(HashMap::new()),
            enabled: AtomicBool::new(cfg.enabled),
            mode: AtomicU8::new(mode_to_u8(cfg.mode)),
            mode_override: AtomicU8::new(0),
            max_validation_entries: cfg.candidate_pool_max.saturating_mul(4).max(1_024),
        }
    }

    /// Whether the subsystem is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Effective response mode: the runtime override when one is set, else the configured
    /// mode. This is read once per eligible answer, so it is a single relaxed load.
    pub fn mode(&self) -> CloudflareMode {
        match mode_from_u8(self.mode_override.load(Ordering::Relaxed)) {
            Some(m) => m,
            None => self.configured_mode(),
        }
    }

    /// The mode from the configuration file, ignoring any runtime override.
    pub fn configured_mode(&self) -> CloudflareMode {
        // `mode` is only ever written through `mode_to_u8`, which never produces a value
        // `mode_from_u8` rejects; the fallback is unreachable but keeps this total.
        mode_from_u8(self.mode.load(Ordering::Relaxed)).unwrap_or(CloudflareMode::Off)
    }

    /// Apply the reloadable part of a reloaded configuration.
    ///
    /// Only `enabled` and `mode` can change live: the candidate pool, the sampler and the
    /// validation bounds are sized once at construction, and [`crate::config::reload`]
    /// refuses a reload that tries to change them. If a reload weakened the configured
    /// mode below an active runtime override, the override would now strengthen it —
    /// violating the "an override may only weaken" invariant — so it is cleared.
    pub fn reconfigure(&self, cfg: &CloudflareConfig) {
        self.enabled.store(cfg.enabled, Ordering::Relaxed);
        self.mode.store(mode_to_u8(cfg.mode), Ordering::Relaxed);
        if let Some(over) = self.mode_override() {
            if mode_rank(over) > mode_rank(cfg.mode) {
                self.mode_override.store(0, Ordering::Relaxed);
                tracing::warn!(
                    event = "cloudflare.mode_override_cleared",
                    mode = ?cfg.mode,
                    "the reloaded configured mode is weaker than the runtime override; \
                     the override was cleared"
                );
            }
        }
    }

    /// The runtime override, if one is in force.
    pub fn mode_override(&self) -> Option<CloudflareMode> {
        mode_from_u8(self.mode_override.load(Ordering::Relaxed))
    }

    /// Apply a runtime override.
    ///
    /// Returns an error when the requested mode is stronger than the configured mode. The
    /// admin socket is an operational control for turning optimization *down* during an
    /// incident; turning it up is a configuration change, so that it goes through
    /// validation and survives a restart in a form somebody can review.
    pub fn set_mode_override(&self, mode: CloudflareMode) -> Result<(), &'static str> {
        if mode_rank(mode) > mode_rank(self.configured_mode()) {
            return Err(
                "a runtime override may only weaken the configured mode; edit the \
                 configuration and reload to strengthen it",
            );
        }
        self.mode_override
            .store(mode_to_u8(mode), Ordering::Relaxed);
        tracing::warn!(
            event = "cloudflare.mode_override",
            mode = ?mode,
            configured = ?self.configured_mode(),
        );
        Ok(())
    }

    /// Drop any runtime override and return to the configured mode.
    pub fn clear_mode_override(&self) {
        if self.mode_override.swap(0, Ordering::Relaxed) != 0 {
            tracing::warn!(
                event = "cloudflare.mode_override_cleared",
                mode = ?self.configured_mode(),
            );
        }
    }

    /// Current official prefix snapshot.
    pub fn prefixes(&self) -> Arc<Option<PrefixSnapshot>> {
        self.prefixes.load_full()
    }

    /// Replace the prefix snapshot.
    pub fn set_prefixes(&self, snapshot: PrefixSnapshot) {
        let removed = self.pool.revalidate(&snapshot);
        if removed > 0 {
            tracing::info!(
                event = "cloudflare.prefix_change",
                removed,
                "candidates outside the new official prefix set were dropped"
            );
        }
        self.prefixes.store(Arc::new(Some(snapshot)));
    }

    /// The candidate pool.
    pub fn pool(&self) -> &CandidatePool {
        &self.pool
    }

    /// The prefix sampler.
    pub fn sampler(&self) -> &StratifiedSampler {
        &self.sampler
    }

    /// Record the outcome of a source update.
    pub fn record_source(&self, status: SourceStatus) {
        let mut map = self.sources.lock();
        if map.len() > 64 {
            map.clear();
        }
        map.insert(Arc::clone(&status.name), status);
    }

    /// Status of every data source.
    pub fn sources(&self) -> Vec<SourceStatus> {
        let mut items: Vec<SourceStatus> = self.sources.lock().values().cloned().collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }

    /// Record a domain-level validation attempt.
    pub fn record_validation(
        &self,
        hostname: &str,
        addr: IpAddr,
        success: bool,
        colo: Option<String>,
        now: Instant,
    ) {
        let key = (Arc::from(hostname.trim_end_matches('.')), addr);
        let mut map = self.validations.lock();
        if map.len() >= self.max_validation_entries && !map.contains_key(&key) {
            // Drop the least recently attempted entries.
            let mut items: Vec<(ValidationKey, Option<Instant>)> = map
                .iter()
                .map(|(k, v)| (k.clone(), v.last_attempt))
                .collect();
            items.sort_by_key(|(_, t)| *t);
            for (k, _) in items.into_iter().take(self.max_validation_entries / 16 + 1) {
                map.remove(&k);
            }
        }
        let entry = map.entry(key).or_insert_with(DomainValidation::new);
        entry.last_attempt = Some(now);
        if success {
            entry.successes = entry.successes.saturating_add(1);
            entry.failures = 0;
            entry.last_success = Some(now);
            if colo.is_some() {
                entry.colo = colo;
            }
        } else {
            entry.failures = entry.failures.saturating_add(1);
            // A failure resets the success streak but never deletes the record: the
            // address may still be perfectly usable for other hostnames.
            entry.successes = 0;
        }
    }

    /// Read the validation record for a hostname and address.
    pub fn validation(&self, hostname: &str, addr: IpAddr) -> Option<DomainValidation> {
        let key = (Arc::from(hostname.trim_end_matches('.')), addr);
        self.validations.lock().get(&key).cloned()
    }

    /// Verified candidates for a hostname, best first.
    pub fn verified_for(
        &self,
        hostname: &str,
        ipv4: bool,
        min_validations: u32,
        validation_ttl: Duration,
        now: Instant,
        cost: impl Fn(IpAddr) -> (f64, u32),
    ) -> Vec<crate::policy::answer::VerifiedCandidate> {
        let host: Arc<str> = Arc::from(hostname.trim_end_matches('.'));
        let map = self.validations.lock();
        let mut out: Vec<crate::policy::answer::VerifiedCandidate> = map
            .iter()
            .filter(|((h, addr), _)| *h == host && addr.is_ipv4() == ipv4)
            .filter(|(_, v)| v.successes >= min_validations)
            .map(|((_, addr), v)| {
                let (cost_ms, samples) = cost(*addr);
                crate::policy::answer::VerifiedCandidate {
                    addr: *addr,
                    successes: v.successes,
                    cost_ms,
                    samples,
                    fresh: v.is_fresh(now, validation_ttl),
                }
            })
            .collect();
        out.sort_by(|a, b| a.cost_ms.total_cmp(&b.cost_ms));
        out
    }

    /// Record whether the original addresses for a hostname work.
    pub fn set_baseline(&self, hostname: &str, validated: bool, now_unix: u64) {
        let mut map = self.baseline.lock();
        if map.len() > self.max_validation_entries {
            map.clear();
        }
        let entry = map
            .entry(Arc::from(hostname.trim_end_matches('.')))
            .or_default();
        entry.validated = validated;
        if validated {
            entry.last_success_unix = now_unix;
        }
    }

    /// Whether the original addresses for a hostname are known to work.
    pub fn baseline(&self, hostname: &str) -> bool {
        self.baseline
            .lock()
            .get(&Arc::from(hostname.trim_end_matches('.')))
            .map(|b| b.validated)
            .unwrap_or(false)
    }

    /// Apply a network-generation change.
    pub fn on_generation_change(&self, generation: u64) {
        self.pool.on_generation_change(generation);
        self.validations.lock().clear();
        self.baseline.lock().clear();
    }

    /// Number of tracked validations, for metrics.
    pub fn validation_count(&self) -> usize {
        self.validations.lock().len()
    }
}

/// Shared handle.
pub type SharedCloudflare = Arc<CloudflareState>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    fn state() -> CloudflareState {
        CloudflareState::new(&CloudflareConfig {
            enabled: true,
            mode: CloudflareMode::VerifiedAugment,
            ..CloudflareConfig::default()
        })
    }

    #[tokio::test(start_paused = true)]
    async fn builtin_prefixes_are_available_immediately() {
        let s = state();
        let p = s.prefixes();
        assert!(p
            .as_ref()
            .as_ref()
            .expect("snapshot")
            .contains(ip("104.16.0.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn validations_accumulate_and_expire() {
        let now = Instant::now();
        let s = state();
        for _ in 0..3 {
            s.record_validation("www.example.com", ip("104.16.0.1"), true, None, now);
        }
        let v = s
            .validation("www.example.com.", ip("104.16.0.1"))
            .expect("record");
        assert_eq!(v.successes, 3);
        assert!(v.is_fresh(now, Duration::from_secs(60)));
        assert!(!v.is_fresh(now + Duration::from_secs(120), Duration::from_secs(60)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_resets_the_streak_but_keeps_the_record() {
        let now = Instant::now();
        let s = state();
        for _ in 0..5 {
            s.record_validation("www.example.com", ip("104.16.0.1"), true, None, now);
        }
        s.record_validation("www.example.com", ip("104.16.0.1"), false, None, now);
        let v = s
            .validation("www.example.com", ip("104.16.0.1"))
            .expect("record");
        assert_eq!(v.successes, 0);
        assert_eq!(v.failures, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn verified_candidates_are_filtered_and_sorted() {
        let now = Instant::now();
        let s = state();
        for _ in 0..3 {
            s.record_validation("www.example.com", ip("104.16.0.1"), true, None, now);
            s.record_validation("www.example.com", ip("104.16.0.2"), true, None, now);
            s.record_validation("other.example.com", ip("104.16.0.3"), true, None, now);
        }
        s.record_validation("www.example.com", ip("104.16.0.9"), true, None, now);
        let costs = |a: IpAddr| {
            if a == ip("104.16.0.2") {
                (5.0, 64)
            } else {
                (50.0, 64)
            }
        };
        let out = s.verified_for(
            "www.example.com",
            true,
            3,
            Duration::from_secs(60),
            now,
            costs,
        );
        assert_eq!(out.len(), 2, "only addresses with enough validations");
        assert_eq!(out[0].addr, ip("104.16.0.2"), "cheapest first");
        assert!(out.iter().all(|c| c.fresh));
    }

    #[tokio::test(start_paused = true)]
    async fn generation_change_clears_derived_state() {
        let now = Instant::now();
        let s = state();
        s.record_validation("www.example.com", ip("104.16.0.1"), true, None, now);
        s.set_baseline("www.example.com", true, 100);
        assert!(s.baseline("www.example.com"));
        s.on_generation_change(2);
        assert_eq!(s.validation_count(), 0);
        assert!(!s.baseline("www.example.com"));
    }

    #[tokio::test(start_paused = true)]
    async fn prefix_replacement_drops_stale_candidates() {
        let now = Instant::now();
        let s = state();
        let snap = PrefixSnapshot::builtin();
        s.pool().admit(
            ip("172.64.0.1"),
            super::super::candidates::CandidateOrigin::Seed,
            Some(&snap),
            1,
            now,
            None,
        );
        let narrowed = PrefixSnapshot::new(
            vec!["104.16.0.0/13".parse().expect("net")],
            Vec::new(),
            None,
            0,
            super::super::prefixes::PrefixSource::Api,
        );
        s.set_prefixes(narrowed);
        assert!(s.pool().get(ip("172.64.0.1")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn source_status_is_bounded_and_sorted() {
        let s = state();
        for i in 0..200 {
            s.record_source(SourceStatus {
                name: Arc::from(format!("src{i}")),
                ok: true,
                detail: String::new(),
                attempted_unix: i as u64,
                succeeded_unix: Some(i as u64),
                accepted: 1,
                rejected: 0,
            });
        }
        let list = s.sources();
        assert!(list.len() <= 65, "grew to {}", list.len());
        let mut sorted = list.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            list.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            sorted.iter().map(|s| s.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_runtime_override_may_only_weaken_the_configured_mode() {
        let cfg = CloudflareConfig {
            mode: CloudflareMode::VerifiedAugment,
            ..CloudflareConfig::default()
        };
        let state = CloudflareState::new(&cfg);
        assert_eq!(state.mode(), CloudflareMode::VerifiedAugment);
        assert!(state.mode_override().is_none());

        // Weakening is allowed and takes effect immediately.
        assert!(state.set_mode_override(CloudflareMode::Preserve).is_ok());
        assert_eq!(state.mode(), CloudflareMode::Preserve);
        assert_eq!(state.configured_mode(), CloudflareMode::VerifiedAugment);
        assert!(state.set_mode_override(CloudflareMode::Off).is_ok());
        assert_eq!(state.mode(), CloudflareMode::Off);

        // Clearing restores the configured mode.
        state.clear_mode_override();
        assert_eq!(state.mode(), CloudflareMode::VerifiedAugment);
        assert!(state.mode_override().is_none());
    }

    #[test]
    fn a_runtime_override_can_never_strengthen_the_configured_mode() {
        let cfg = CloudflareConfig {
            mode: CloudflareMode::Preserve,
            ..CloudflareConfig::default()
        };
        let state = CloudflareState::new(&cfg);
        assert!(state
            .set_mode_override(CloudflareMode::VerifiedAugment)
            .is_err());
        assert_eq!(state.mode(), CloudflareMode::Preserve);

        let cfg = CloudflareConfig {
            mode: CloudflareMode::Off,
            ..CloudflareConfig::default()
        };
        let state = CloudflareState::new(&cfg);
        for stronger in [CloudflareMode::Preserve, CloudflareMode::VerifiedAugment] {
            assert!(state.set_mode_override(stronger).is_err());
        }
        assert_eq!(state.mode(), CloudflareMode::Off);
        // Setting the same mode is a no-op, not an error.
        assert!(state.set_mode_override(CloudflareMode::Off).is_ok());
    }

    fn reload_cfg(enabled: bool, mode: CloudflareMode) -> CloudflareConfig {
        CloudflareConfig {
            enabled,
            mode,
            ..CloudflareConfig::default()
        }
    }

    #[test]
    fn reconfigure_applies_enabled_and_mode_without_a_restart() {
        let state = CloudflareState::new(&reload_cfg(false, CloudflareMode::Off));
        assert!(!state.enabled());
        assert_eq!(state.mode(), CloudflareMode::Off);

        state.reconfigure(&reload_cfg(true, CloudflareMode::Preserve));
        assert!(state.enabled(), "enabled must flip on reconfigure");
        assert_eq!(state.mode(), CloudflareMode::Preserve);
        assert_eq!(state.configured_mode(), CloudflareMode::Preserve);

        state.reconfigure(&reload_cfg(false, CloudflareMode::VerifiedAugment));
        assert!(!state.enabled(), "disabling must also flip on reconfigure");
        assert_eq!(state.mode(), CloudflareMode::VerifiedAugment);
    }

    #[test]
    fn reconfigure_clears_an_override_that_the_new_mode_makes_too_strong() {
        let state = CloudflareState::new(&reload_cfg(true, CloudflareMode::VerifiedAugment));
        state
            .set_mode_override(CloudflareMode::Preserve)
            .expect("weakening is allowed");
        assert_eq!(state.mode(), CloudflareMode::Preserve);

        // The reload weakens the configured mode below the active override; the override
        // would now strengthen, which is never allowed, so it must be cleared.
        state.reconfigure(&reload_cfg(true, CloudflareMode::Off));
        assert!(state.mode_override().is_none());
        assert_eq!(state.mode(), CloudflareMode::Off);
    }

    #[test]
    fn reconfigure_keeps_an_override_that_still_weakens_the_new_mode() {
        let state = CloudflareState::new(&reload_cfg(true, CloudflareMode::Preserve));
        state
            .set_mode_override(CloudflareMode::Off)
            .expect("weakening is allowed");

        // Strengthening the configured mode keeps a weaker override valid and in force.
        state.reconfigure(&reload_cfg(true, CloudflareMode::VerifiedAugment));
        assert_eq!(state.mode_override(), Some(CloudflareMode::Off));
        assert_eq!(state.mode(), CloudflareMode::Off);
        assert_eq!(state.configured_mode(), CloudflareMode::VerifiedAugment);
    }

    #[test]
    fn an_override_set_after_a_reload_is_bounded_by_the_new_configured_mode() {
        let state = CloudflareState::new(&reload_cfg(true, CloudflareMode::VerifiedAugment));
        state.reconfigure(&reload_cfg(true, CloudflareMode::Off));
        assert!(state.set_mode_override(CloudflareMode::Preserve).is_err());
        assert_eq!(state.mode(), CloudflareMode::Off);
    }
}
