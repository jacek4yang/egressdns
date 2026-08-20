//! Address quality model and standards-safe answer ordering.
//!
//! Two ideas keep this subsystem honest:
//!
//! 1. *Lack of evidence is not evidence of failure.* An address nobody has measured gets a
//!    neutral cost, never a penalty.
//! 2. *Only applicable failures count.* A failed TCP 443 probe is evidence about HTTPS on
//!    that address, and nothing else. It can never make an ordinary DNS answer disappear.

pub mod model;
pub mod service;
pub mod store;

pub use model::{Confidence, ObservationClass, QualityStats};
pub use store::{ProbeKey, QualityStore};

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::time::Instant;

use crate::config::RankingConfig;

/// Why the final order was chosen, for metrics and `egressdnsctl` diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderDecision {
    /// Ordering is disabled by configuration.
    Disabled,
    /// No address had applicable evidence, so the upstream order was preserved.
    NoEvidence,
    /// Evidence existed but the advantage did not clear the hysteresis threshold.
    BelowHysteresis,
    /// A deliberate exploration decision preserved the original order.
    Exploration,
    /// The order was changed on the strength of the evidence.
    Reordered,
    /// The order already matched the evidence.
    Unchanged,
}

impl OrderDecision {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NoEvidence => "no_evidence",
            Self::BelowHysteresis => "below_hysteresis",
            Self::Exploration => "exploration",
            Self::Reordered => "reordered",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Result of an ordering computation.
#[derive(Debug, Clone)]
pub struct Ordering {
    /// The addresses in their final order. Always a permutation of the input.
    pub addresses: Vec<IpAddr>,
    /// Why this order was chosen.
    pub decision: OrderDecision,
    /// Confidence class of the leading address.
    pub confidence: Confidence,
}

/// Compute a standards-safe ordering for one complete A or AAAA RRset.
///
/// The returned vector is always a permutation of `original`: no address is ever added and
/// none is ever removed. The original order is the final tie-breaker, so equal evidence
/// always yields the upstream order.
pub fn order_addresses(
    original: &[IpAddr],
    stats: &HashMap<IpAddr, QualityStats>,
    cfg: &RankingConfig,
    now: Instant,
    explore_seed: u64,
) -> Ordering {
    if !cfg.enabled || original.len() < 2 {
        return Ordering {
            addresses: original.to_vec(),
            decision: OrderDecision::Disabled,
            confidence: Confidence::Unknown,
        };
    }

    let mut scored: Vec<(usize, IpAddr, f64, Confidence)> = Vec::with_capacity(original.len());
    let mut any_evidence = false;
    for (idx, addr) in original.iter().enumerate() {
        match stats.get(addr) {
            Some(s) if s.has_applicable_evidence() => {
                any_evidence = true;
                scored.push((
                    idx,
                    *addr,
                    s.expected_cost(cfg, now),
                    s.confidence(cfg, now),
                ));
            }
            _ => scored.push((idx, *addr, cfg.neutral_cost_ms, Confidence::Unknown)),
        }
    }

    if !any_evidence {
        return Ordering {
            addresses: original.to_vec(),
            decision: OrderDecision::NoEvidence,
            confidence: Confidence::Unknown,
        };
    }

    // Deterministic exploration: a fixed fraction of decisions keeps the upstream order so
    // that an address that once looked bad can be re-measured.
    if cfg.exploration_rate > 0.0 {
        let unit = unit_from_seed(explore_seed);
        if unit < cfg.exploration_rate {
            return Ordering {
                addresses: original.to_vec(),
                decision: OrderDecision::Exploration,
                confidence: Confidence::Unknown,
            };
        }
    }

    let incumbent_cost = scored[0].2;
    let mut sorted = scored.clone();
    // Stable sort by cost; ties fall back to the original index, which preserves upstream
    // order exactly.
    sorted.sort_by(|a, b| a.2.total_cmp(&b.2).then(a.0.cmp(&b.0)));

    let challenger = &sorted[0];
    let leader_changed = challenger.0 != 0;

    if leader_changed {
        // Require both a meaningful relative advantage and enough successful evidence
        // before displacing the address the upstream put first.
        let advantage = (incumbent_cost - challenger.2) / incumbent_cost.max(1.0);
        let successes = stats
            .get(&challenger.1)
            .map(|s| s.success_count())
            .unwrap_or(0);
        if advantage < cfg.hysteresis || successes < cfg.min_successes_to_lead {
            return Ordering {
                addresses: original.to_vec(),
                decision: OrderDecision::BelowHysteresis,
                confidence: challenger.3,
            };
        }
    }

    let addresses: Vec<IpAddr> = sorted.iter().map(|(_, a, _, _)| *a).collect();
    let decision = if addresses == original {
        OrderDecision::Unchanged
    } else {
        OrderDecision::Reordered
    };
    Ordering {
        addresses,
        decision,
        confidence: sorted[0].3,
    }
}

/// Deterministic `[0, 1)` value from a seed. Used for exploration decisions so that a test
/// with a fixed seed always produces the same ordering.
pub fn unit_from_seed(seed: u64) -> f64 {
    let mixed = crate::util::fnv1a64(&seed.to_le_bytes());
    (mixed >> 11) as f64 / ((1u64 << 53) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    fn good(now: Instant, latency_ms: u64, n: u32) -> QualityStats {
        let mut s = QualityStats::new(1);
        for i in 0..n {
            s.record_success(
                Duration::from_millis(latency_ms),
                now + Duration::from_millis(u64::from(i)),
                &RankingConfig::default(),
            );
        }
        s
    }

    fn bad(now: Instant, n: u32) -> QualityStats {
        let mut s = QualityStats::new(1);
        for i in 0..n {
            s.record_failure(
                ObservationClass::ApplicableFailure,
                now + Duration::from_millis(u64::from(i)),
                &RankingConfig::default(),
            );
        }
        s
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_addresses_are_neutral_and_order_is_preserved() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")];
        let stats = HashMap::new();
        let out = order_addresses(&addrs, &stats, &cfg, now, 12345);
        assert_eq!(out.addresses, addrs);
        assert_eq!(out.decision, OrderDecision::NoEvidence);
    }

    #[tokio::test(start_paused = true)]
    async fn ordering_is_always_a_permutation() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")];
        let mut stats = HashMap::new();
        stats.insert(addrs[0], bad(now, 5));
        stats.insert(addrs[2], good(now, 5, 10));
        let out = order_addresses(&addrs, &stats, &cfg, now, 1);
        let mut a = out.addresses.clone();
        let mut b = addrs.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
        assert_eq!(out.addresses.len(), addrs.len());
    }

    #[tokio::test(start_paused = true)]
    async fn clear_winner_is_promoted() {
        let now = Instant::now();
        let cfg = RankingConfig {
            exploration_rate: 0.0,
            ..RankingConfig::default()
        };
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2")];
        let mut stats = HashMap::new();
        stats.insert(addrs[0], good(now, 200, 20));
        stats.insert(addrs[1], good(now, 5, 20));
        let out = order_addresses(&addrs, &stats, &cfg, now, 7);
        assert_eq!(out.addresses[0], addrs[1]);
        assert_eq!(out.decision, OrderDecision::Reordered);
    }

    #[tokio::test(start_paused = true)]
    async fn marginal_advantage_keeps_original_order() {
        let now = Instant::now();
        let cfg = RankingConfig {
            exploration_rate: 0.0,
            ..RankingConfig::default()
        };
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2")];
        let mut stats = HashMap::new();
        stats.insert(addrs[0], good(now, 100, 20));
        stats.insert(addrs[1], good(now, 97, 20));
        let out = order_addresses(&addrs, &stats, &cfg, now, 7);
        assert_eq!(out.addresses, addrs);
        assert_eq!(out.decision, OrderDecision::BelowHysteresis);
    }

    #[tokio::test(start_paused = true)]
    async fn few_successes_cannot_take_the_lead() {
        let now = Instant::now();
        let cfg = RankingConfig {
            exploration_rate: 0.0,
            min_successes_to_lead: 10,
            ..RankingConfig::default()
        };
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2")];
        let mut stats = HashMap::new();
        stats.insert(addrs[0], good(now, 200, 20));
        stats.insert(addrs[1], good(now, 1, 2));
        let out = order_addresses(&addrs, &stats, &cfg, now, 7);
        assert_eq!(out.addresses, addrs);
    }

    #[tokio::test(start_paused = true)]
    async fn ordering_is_deterministic() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let addrs = vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")];
        let mut stats = HashMap::new();
        stats.insert(addrs[0], good(now, 50, 10));
        stats.insert(addrs[1], good(now, 10, 10));
        stats.insert(addrs[2], good(now, 30, 10));
        let a = order_addresses(&addrs, &stats, &cfg, now, 99);
        let b = order_addresses(&addrs, &stats, &cfg, now, 99);
        assert_eq!(a.addresses, b.addresses);
        assert_eq!(a.decision, b.decision);
    }

    #[tokio::test(start_paused = true)]
    async fn single_address_is_untouched() {
        let now = Instant::now();
        let cfg = RankingConfig::default();
        let addrs = vec![ip("1.1.1.1")];
        let out = order_addresses(&addrs, &HashMap::new(), &cfg, now, 1);
        assert_eq!(out.addresses, addrs);
    }
}
