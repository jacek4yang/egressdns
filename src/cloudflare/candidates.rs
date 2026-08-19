//! The Cloudflare candidate pool.
//!
//! Every address that reaches the pool has passed the same admission pipeline regardless
//! of where it came from:
//!
//! ```text
//! external seed / local sampling / observed DNS answer / configuration
//!     -> strict parsing
//!     -> current official Cloudflare prefix membership
//!     -> special-use and private-address filtering
//!     -> bounded pool admission
//!     -> probe stages (TCP, TLS, HTTP)
//!     -> repeated success and confidence threshold
//!     -> eligible for use
//! ```

use std::collections::HashMap;
use std::net::IpAddr;

use parking_lot::Mutex;
use tokio::time::Instant;

use super::prefixes::PrefixSnapshot;

/// Where a candidate came from. Origin never grants trust; it is diagnostic only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateOrigin {
    /// Observed as a Cloudflare-owned address inside a valid upstream DNS answer.
    DnsAnswer,
    /// Proposed by a third-party seed endpoint.
    Seed,
    /// Produced by bounded sampling of official prefixes.
    Sampling,
    /// Configured by the administrator.
    Config,
    /// Restored from the local quality database.
    Persisted,
}

impl CandidateOrigin {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::DnsAnswer => "dns_answer",
            Self::Seed => "seed",
            Self::Sampling => "sampling",
            Self::Config => "config",
            Self::Persisted => "persisted",
        }
    }

    /// Priority order used when the pool is full: evidence from real answers outranks a
    /// third-party hint, which outranks a random sample.
    pub fn priority(self) -> u8 {
        match self {
            Self::DnsAnswer => 0,
            Self::Config => 1,
            Self::Persisted => 2,
            Self::Seed => 3,
            Self::Sampling => 4,
        }
    }
}

/// Why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// The address is not inside the current official Cloudflare prefix snapshot.
    NotOfficialPrefix,
    /// The address is in a special-use range.
    SpecialUse,
    /// No official prefix snapshot is available yet.
    NoSnapshot,
    /// The pool is full and nothing lower-priority could be evicted.
    PoolFull,
    /// The hourly admission budget for this origin is exhausted.
    BudgetExhausted,
    /// IPv6 sampling is disabled.
    Ipv6SamplingDisabled,
}

impl RejectReason {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::NotOfficialPrefix => "not_official_prefix",
            Self::SpecialUse => "special_use",
            Self::NoSnapshot => "no_snapshot",
            Self::PoolFull => "pool_full",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Ipv6SamplingDisabled => "ipv6_sampling_disabled",
        }
    }
}

/// Validation progress of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateStage {
    /// Admitted but never probed.
    New,
    /// TCP connect succeeded.
    TcpOk,
    /// TLS handshake with correct SNI and a verified chain succeeded.
    TlsOk,
    /// A full HTTP exchange succeeded.
    HttpOk,
}

impl CandidateStage {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::TcpOk => "tcp_ok",
            Self::TlsOk => "tls_ok",
            Self::HttpOk => "http_ok",
        }
    }
}

/// A pooled candidate address.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The address.
    pub addr: IpAddr,
    /// Where it was first seen.
    pub origin: CandidateOrigin,
    /// First admission.
    pub first_seen: Instant,
    /// Most recent time it was proposed again.
    pub last_seen: Instant,
    /// Most recent probe.
    pub last_probe: Option<Instant>,
    /// Highest stage reached.
    pub stage: CandidateStage,
    /// Consecutive stage-appropriate successes.
    pub consecutive_successes: u32,
    /// Network generation the evidence belongs to.
    pub generation: u64,
    /// Cloudflare datacentre reported by the edge, when known.
    pub colo: Option<String>,
}

impl Candidate {
    /// True when the candidate has passed enough validation to be considered eligible.
    pub fn is_eligible(&self, min_successes: u32) -> bool {
        self.stage == CandidateStage::HttpOk && self.consecutive_successes >= min_successes
    }
}

/// A bounded candidate pool.
pub struct CandidatePool {
    inner: Mutex<PoolInner>,
    capacity: usize,
}

struct PoolInner {
    v4: HashMap<IpAddr, Candidate>,
    v6: HashMap<IpAddr, Candidate>,
    admitted_this_hour: usize,
    hour_started: Option<Instant>,
}

/// Outcome of an admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A new candidate was added.
    Added,
    /// The candidate was already present and its timestamp was refreshed.
    Refreshed,
    /// The candidate was refused.
    Rejected(RejectReason),
}

impl CandidatePool {
    /// Create a pool with a hard capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                v4: HashMap::new(),
                v6: HashMap::new(),
                admitted_this_hour: 0,
                hour_started: None,
            }),
            capacity: capacity.max(1),
        }
    }

    /// Try to admit an address.
    ///
    /// `hourly_budget` bounds how many *new* addresses may be admitted per hour; refreshes
    /// of existing candidates are free.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &self,
        addr: IpAddr,
        origin: CandidateOrigin,
        snapshot: Option<&PrefixSnapshot>,
        generation: u64,
        now: Instant,
        hourly_budget: Option<usize>,
    ) -> Admission {
        // 1. Special-use filtering happens before anything else so that a hostile source
        //    can never point the probe engine at loopback or a metadata service.
        if crate::util::ipclass::classify(addr).is_some() {
            return Admission::Rejected(RejectReason::SpecialUse);
        }
        // 2. Official prefix membership. This is the only authority on Cloudflare
        //    ownership.
        let Some(snapshot) = snapshot else {
            return Admission::Rejected(RejectReason::NoSnapshot);
        };
        if !snapshot.contains(addr) {
            return Admission::Rejected(RejectReason::NotOfficialPrefix);
        }

        let mut inner = self.inner.lock();
        let is_v4 = addr.is_ipv4();
        {
            let map = if is_v4 { &mut inner.v4 } else { &mut inner.v6 };
            if let Some(existing) = map.get_mut(&addr) {
                existing.last_seen = now;
                if origin.priority() < existing.origin.priority() {
                    existing.origin = origin;
                }
                return Admission::Refreshed;
            }
        }

        // 3. Hourly admission budget.
        if let Some(budget) = hourly_budget {
            let reset = match inner.hour_started {
                None => true,
                Some(start) => now.saturating_duration_since(start).as_secs() >= 3_600,
            };
            if reset {
                inner.hour_started = Some(now);
                inner.admitted_this_hour = 0;
            }
            if inner.admitted_this_hour >= budget {
                return Admission::Rejected(RejectReason::BudgetExhausted);
            }
        }

        // 4. Bounded pool admission, evicting only strictly lower-priority entries.
        let total = inner.v4.len() + inner.v6.len();
        if total >= self.capacity && !self.evict_one(&mut inner, origin, now) {
            return Admission::Rejected(RejectReason::PoolFull);
        }

        let map = if is_v4 { &mut inner.v4 } else { &mut inner.v6 };
        map.insert(
            addr,
            Candidate {
                addr,
                origin,
                first_seen: now,
                last_seen: now,
                last_probe: None,
                stage: CandidateStage::New,
                consecutive_successes: 0,
                generation,
                colo: None,
            },
        );
        inner.admitted_this_hour += 1;
        Admission::Added
    }

    fn evict_one(&self, inner: &mut PoolInner, incoming: CandidateOrigin, _now: Instant) -> bool {
        let mut victim: Option<(IpAddr, bool, u8, Instant)> = None;
        for (family_is_v4, map) in [(true, &inner.v4), (false, &inner.v6)] {
            for (addr, c) in map.iter() {
                if c.origin.priority() <= incoming.priority() && c.stage != CandidateStage::New {
                    continue;
                }
                let replace = match &victim {
                    None => true,
                    Some((_, _, prio, seen)) => {
                        c.origin.priority() > *prio
                            || (c.origin.priority() == *prio && c.last_seen < *seen)
                    }
                };
                if replace {
                    victim = Some((*addr, family_is_v4, c.origin.priority(), c.last_seen));
                }
            }
        }
        match victim {
            Some((addr, true, _, _)) => inner.v4.remove(&addr).is_some(),
            Some((addr, false, _, _)) => inner.v6.remove(&addr).is_some(),
            None => false,
        }
    }

    /// Record a probe outcome for a candidate.
    pub fn record_stage(
        &self,
        addr: IpAddr,
        stage: CandidateStage,
        success: bool,
        colo: Option<String>,
        now: Instant,
    ) {
        let mut inner = self.inner.lock();
        let map = if addr.is_ipv4() {
            &mut inner.v4
        } else {
            &mut inner.v6
        };
        let Some(c) = map.get_mut(&addr) else {
            return;
        };
        c.last_probe = Some(now);
        if success {
            if stage > c.stage {
                c.stage = stage;
            }
            c.consecutive_successes = c.consecutive_successes.saturating_add(1);
            if colo.is_some() {
                c.colo = colo;
            }
        } else {
            c.consecutive_successes = 0;
            // A failure never removes the candidate: a single failure is not proof that
            // an address is unusable, and the quality model already applies the penalty.
        }
    }

    /// Read a candidate.
    pub fn get(&self, addr: IpAddr) -> Option<Candidate> {
        let inner = self.inner.lock();
        if addr.is_ipv4() {
            inner.v4.get(&addr).cloned()
        } else {
            inner.v6.get(&addr).cloned()
        }
    }

    /// All candidates of a family.
    pub fn list(&self, ipv4: bool) -> Vec<Candidate> {
        let inner = self.inner.lock();
        let map = if ipv4 { &inner.v4 } else { &inner.v6 };
        map.values().cloned().collect()
    }

    /// Candidates that are eligible for use.
    pub fn eligible(&self, ipv4: bool, min_successes: u32) -> Vec<Candidate> {
        let inner = self.inner.lock();
        let map = if ipv4 { &inner.v4 } else { &inner.v6 };
        map.values()
            .filter(|c| c.is_eligible(min_successes))
            .cloned()
            .collect()
    }

    /// Candidates due for a probe, oldest first.
    pub fn due_for_probe(
        &self,
        cooldown: std::time::Duration,
        now: Instant,
        limit: usize,
    ) -> Vec<Candidate> {
        let inner = self.inner.lock();
        let mut items: Vec<Candidate> = inner
            .v4
            .values()
            .chain(inner.v6.values())
            .filter(|c| match c.last_probe {
                None => true,
                Some(t) => now.saturating_duration_since(t) >= cooldown,
            })
            .cloned()
            .collect();
        items.sort_by_key(|c| c.last_probe.unwrap_or(c.first_seen));
        items.truncate(limit);
        items
    }

    /// Drop candidates that are no longer inside the official prefix snapshot.
    ///
    /// Cloudflare occasionally retires a prefix. When that happens, every candidate inside
    /// it must stop being usable immediately.
    pub fn revalidate(&self, snapshot: &PrefixSnapshot) -> usize {
        let mut inner = self.inner.lock();
        let before = inner.v4.len() + inner.v6.len();
        inner.v4.retain(|addr, _| snapshot.contains(*addr));
        inner.v6.retain(|addr, _| snapshot.contains(*addr));
        before - (inner.v4.len() + inner.v6.len())
    }

    /// Reset evidence after a network-generation change.
    pub fn on_generation_change(&self, generation: u64) {
        let mut inner = self.inner.lock();
        let PoolInner { v4, v6, .. } = &mut *inner;
        for c in v4.values_mut().chain(v6.values_mut()) {
            c.generation = generation;
            c.consecutive_successes = 0;
            c.stage = CandidateStage::New;
            c.last_probe = None;
        }
    }

    /// Counts per family.
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.inner.lock();
        (inner.v4.len(), inner.v6.len())
    }

    /// Remove everything.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.v4.clear();
        inner.v6.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    #[tokio::test(start_paused = true)]
    async fn only_official_prefixes_are_admitted() {
        let pool = CandidatePool::new(64);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        assert_eq!(
            pool.admit(
                ip("104.16.0.1"),
                CandidateOrigin::Seed,
                Some(&snap),
                1,
                now,
                None
            ),
            Admission::Added
        );
        // Real addresses observed from the live seed endpoints that are not Cloudflare.
        for outside in ["188.164.248.83", "91.193.59.179", "8.35.211.212", "8.8.8.8"] {
            assert_eq!(
                pool.admit(
                    ip(outside),
                    CandidateOrigin::Seed,
                    Some(&snap),
                    1,
                    now,
                    None
                ),
                Admission::Rejected(RejectReason::NotOfficialPrefix),
                "{outside} must be rejected"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn special_use_is_rejected_before_prefix_lookup() {
        let pool = CandidatePool::new(64);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fd00:ec2::254",
            "224.0.0.1",
        ] {
            assert_eq!(
                pool.admit(ip(bad), CandidateOrigin::Seed, Some(&snap), 1, now, None),
                Admission::Rejected(RejectReason::SpecialUse),
                "{bad} must be rejected"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_snapshot_nothing_is_admitted() {
        let pool = CandidatePool::new(64);
        let now = Instant::now();
        assert_eq!(
            pool.admit(ip("104.16.0.1"), CandidateOrigin::Seed, None, 1, now, None),
            Admission::Rejected(RejectReason::NoSnapshot)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pool_is_bounded() {
        let pool = CandidatePool::new(4);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        for i in 0..64u32 {
            let a = ip(&format!("104.16.{}.{}", i / 256, i % 256));
            let _ = pool.admit(a, CandidateOrigin::Sampling, Some(&snap), 1, now, None);
        }
        let (v4, v6) = pool.counts();
        assert!(v4 + v6 <= 4, "pool grew to {}", v4 + v6);
    }

    #[tokio::test(start_paused = true)]
    async fn hourly_budget_is_enforced_and_resets() {
        let pool = CandidatePool::new(1_000);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        let mut added = 0;
        for i in 0..20u32 {
            let a = ip(&format!("104.16.1.{i}"));
            if pool.admit(a, CandidateOrigin::Sampling, Some(&snap), 1, now, Some(5))
                == Admission::Added
            {
                added += 1;
            }
        }
        assert_eq!(added, 5);
        let later = now + Duration::from_secs(3_601);
        assert_eq!(
            pool.admit(
                ip("104.16.2.1"),
                CandidateOrigin::Sampling,
                Some(&snap),
                1,
                later,
                Some(5)
            ),
            Admission::Added
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_failure_never_removes_a_candidate() {
        let pool = CandidatePool::new(16);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        let a = ip("104.16.0.1");
        pool.admit(a, CandidateOrigin::DnsAnswer, Some(&snap), 1, now, None);
        pool.record_stage(a, CandidateStage::TcpOk, true, None, now);
        pool.record_stage(a, CandidateStage::TlsOk, false, None, now);
        let c = pool.get(a).expect("still present");
        assert_eq!(c.stage, CandidateStage::TcpOk);
        assert_eq!(c.consecutive_successes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn eligibility_requires_repeated_http_success() {
        let pool = CandidatePool::new(16);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        let a = ip("104.16.0.1");
        pool.admit(a, CandidateOrigin::DnsAnswer, Some(&snap), 1, now, None);
        for _ in 0..2 {
            pool.record_stage(a, CandidateStage::HttpOk, true, Some("FRA".into()), now);
        }
        assert!(pool.eligible(true, 3).is_empty());
        pool.record_stage(a, CandidateStage::HttpOk, true, None, now);
        assert_eq!(pool.eligible(true, 3).len(), 1);
        assert_eq!(pool.get(a).expect("present").colo.as_deref(), Some("FRA"));
    }

    #[tokio::test(start_paused = true)]
    async fn retired_prefixes_evict_candidates() {
        let pool = CandidatePool::new(16);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        pool.admit(
            ip("104.16.0.1"),
            CandidateOrigin::Seed,
            Some(&snap),
            1,
            now,
            None,
        );
        pool.admit(
            ip("172.64.0.1"),
            CandidateOrigin::Seed,
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
        assert_eq!(pool.revalidate(&narrowed), 1);
        assert!(pool.get(ip("172.64.0.1")).is_none());
        assert!(pool.get(ip("104.16.0.1")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn generation_change_resets_validation() {
        let pool = CandidatePool::new(16);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        let a = ip("104.16.0.1");
        pool.admit(a, CandidateOrigin::DnsAnswer, Some(&snap), 1, now, None);
        for _ in 0..5 {
            pool.record_stage(a, CandidateStage::HttpOk, true, None, now);
        }
        pool.on_generation_change(2);
        let c = pool.get(a).expect("present");
        assert_eq!(c.stage, CandidateStage::New);
        assert_eq!(c.consecutive_successes, 0);
        assert_eq!(c.generation, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn due_for_probe_respects_cooldown() {
        let pool = CandidatePool::new(16);
        let snap = PrefixSnapshot::builtin();
        let now = Instant::now();
        let a = ip("104.16.0.1");
        pool.admit(a, CandidateOrigin::Seed, Some(&snap), 1, now, None);
        assert_eq!(
            pool.due_for_probe(Duration::from_secs(60), now, 10).len(),
            1
        );
        pool.record_stage(a, CandidateStage::TcpOk, true, None, now);
        assert!(pool
            .due_for_probe(Duration::from_secs(60), now, 10)
            .is_empty());
        assert_eq!(
            pool.due_for_probe(Duration::from_secs(60), now + Duration::from_secs(61), 10)
                .len(),
            1
        );
    }
}
