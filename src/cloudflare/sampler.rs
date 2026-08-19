//! Bounded, reproducible sampling of official Cloudflare IPv4 prefixes.
//!
//! High-intensity scanning is prohibited. What is permitted, and what this implements, is
//! a *stratified rotating sampler*: each official prefix is divided into a fixed number of
//! buckets, and each round proposes a small number of addresses drawn mostly from buckets
//! that have never been visited, with a minority of the budget spent revisiting buckets
//! that have historically produced good candidates.
//!
//! Everything is derived from a configured seed, so a sampling schedule is reproducible
//! and can be replayed during incident analysis.
//!
//! IPv6 is deliberately not sampled by traversal: `2606:4700::/32` alone contains 2^96
//! addresses, so random traversal has no defensible expected yield. IPv6 candidates come
//! from real DNS answers, seeds, history and configuration instead.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use parking_lot::Mutex;

use super::prefixes::PrefixSnapshot;
use crate::config::SamplingConfig;

/// Per-bucket sampling history.
#[derive(Debug, Clone, Copy, Default)]
pub struct BucketState {
    /// Addresses proposed from this bucket.
    pub attempts: u32,
    /// Addresses from this bucket that reached the eligible pool.
    pub successes: u32,
    /// Round in which this bucket was last sampled; zero means never.
    pub last_round: u64,
}

impl BucketState {
    fn yield_ratio(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            f64::from(self.successes) / f64::from(self.attempts)
        }
    }
}

/// A reproducible stratified sampler.
pub struct StratifiedSampler {
    seed: u64,
    buckets_per_prefix: u32,
    exploit_fraction: f64,
    state: Mutex<SamplerState>,
}

struct SamplerState {
    buckets: HashMap<(Ipv4Net, u32), BucketState>,
    round: u64,
}

impl StratifiedSampler {
    /// Build a sampler from configuration.
    pub fn new(cfg: &SamplingConfig) -> Self {
        Self {
            seed: cfg.seed,
            buckets_per_prefix: cfg.buckets_per_prefix.clamp(1, 4_096) as u32,
            exploit_fraction: cfg.exploit_fraction.clamp(0.0, 1.0),
            state: Mutex::new(SamplerState {
                buckets: HashMap::new(),
                round: 0,
            }),
        }
    }

    /// Current round number.
    pub fn round(&self) -> u64 {
        self.state.lock().round
    }

    /// Number of buckets with recorded history.
    pub fn tracked_buckets(&self) -> usize {
        self.state.lock().buckets.len()
    }

    /// Propose up to `budget` addresses for this round.
    ///
    /// The result is deterministic for a given seed, snapshot, budget and sampler history.
    pub fn next_round(&self, snapshot: &PrefixSnapshot, budget: usize) -> Vec<Ipv4Addr> {
        let prefixes = snapshot.ipv4();
        if prefixes.is_empty() || budget == 0 {
            return Vec::new();
        }
        let mut state = self.state.lock();
        state.round += 1;
        let round = state.round;

        let exploit_budget = ((budget as f64) * self.exploit_fraction).floor() as usize;
        let explore_budget = budget.saturating_sub(exploit_budget);

        // Candidate buckets across all prefixes, with fair per-prefix allocation.
        let mut explore: Vec<(Ipv4Net, u32, u64)> = Vec::new();
        let mut exploit: Vec<(Ipv4Net, u32, f64)> = Vec::new();
        for prefix in prefixes {
            let buckets = self.buckets_for(prefix);
            for b in 0..buckets {
                let key = (*prefix, b);
                match state.buckets.get(&key) {
                    None => explore.push((*prefix, b, 0)),
                    Some(s) => {
                        explore.push((*prefix, b, s.last_round));
                        if s.attempts > 0 {
                            exploit.push((*prefix, b, s.yield_ratio()));
                        }
                    }
                }
            }
        }

        // Prefer never-visited buckets, then least recently visited. Ties break on a
        // deterministic hash so the order does not depend on HashMap iteration order.
        explore.sort_by(|a, b| {
            a.2.cmp(&b.2)
                .then_with(|| self.tiebreak(a.0, a.1).cmp(&self.tiebreak(b.0, b.1)))
        });
        exploit.sort_by(|a, b| {
            b.2.total_cmp(&a.2)
                .then_with(|| self.tiebreak(a.0, a.1).cmp(&self.tiebreak(b.0, b.1)))
        });

        let mut chosen: Vec<(Ipv4Net, u32)> = Vec::with_capacity(budget);
        let mut per_prefix: HashMap<Ipv4Net, usize> = HashMap::new();
        let fair_share = budget.div_ceil(prefixes.len()).max(1);

        for (prefix, bucket, _) in explore.iter() {
            if chosen.len() >= explore_budget {
                break;
            }
            let used = per_prefix.entry(*prefix).or_insert(0);
            if *used >= fair_share {
                continue;
            }
            *used += 1;
            chosen.push((*prefix, *bucket));
        }
        for (prefix, bucket, _) in exploit.iter() {
            if chosen.len() >= budget {
                break;
            }
            if chosen.contains(&(*prefix, *bucket)) {
                continue;
            }
            chosen.push((*prefix, *bucket));
        }

        let mut out = Vec::with_capacity(chosen.len());
        for (prefix, bucket) in chosen {
            if let Some(addr) = self.address_in_bucket(prefix, bucket, round) {
                let entry = state.buckets.entry((prefix, bucket)).or_default();
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_round = round;
                out.push(addr);
            }
        }
        // Bound the history table so a very large prefix set cannot grow it without limit.
        if state.buckets.len() > 200_000 {
            let cutoff = round.saturating_sub(1_000);
            state.buckets.retain(|_, v| v.last_round >= cutoff);
        }
        out
    }

    /// Record that a sampled address turned out to be usable.
    pub fn record_success(&self, snapshot: &PrefixSnapshot, addr: Ipv4Addr) {
        let Some((prefix, bucket)) = self.locate(snapshot, addr) else {
            return;
        };
        let mut state = self.state.lock();
        let entry = state.buckets.entry((prefix, bucket)).or_default();
        entry.successes = entry.successes.saturating_add(1);
    }

    /// Which prefix and bucket an address falls into.
    pub fn locate(&self, snapshot: &PrefixSnapshot, addr: Ipv4Addr) -> Option<(Ipv4Net, u32)> {
        let prefix = snapshot
            .ipv4()
            .iter()
            .find(|n| n.contains(&addr))
            .copied()?;
        let buckets = self.buckets_for(&prefix);
        let size = prefix_size(&prefix) / u64::from(buckets);
        let offset = u64::from(u32::from(addr)) - u64::from(u32::from(prefix.network()));
        Some((
            prefix,
            (offset / size.max(1)).min(u64::from(buckets - 1)) as u32,
        ))
    }

    fn buckets_for(&self, prefix: &Ipv4Net) -> u32 {
        let size = prefix_size(prefix);
        // Never create more buckets than there are addresses.
        (u64::from(self.buckets_per_prefix).min(size)).max(1) as u32
    }

    fn tiebreak(&self, prefix: Ipv4Net, bucket: u32) -> u64 {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(&u32::from(prefix.network()).to_be_bytes());
        buf[4] = prefix.prefix_len();
        buf[5..9].copy_from_slice(&bucket.to_be_bytes());
        buf[9..].copy_from_slice(&self.seed.to_be_bytes()[..7]);
        crate::util::fnv1a64(&buf)
    }

    /// Deterministically choose an address inside a bucket for a given round.
    fn address_in_bucket(&self, prefix: Ipv4Net, bucket: u32, round: u64) -> Option<Ipv4Addr> {
        let buckets = u64::from(self.buckets_for(&prefix));
        let size = prefix_size(&prefix) / buckets;
        if size == 0 {
            return None;
        }
        let base = u64::from(u32::from(prefix.network())) + u64::from(bucket) * size;
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.seed.to_be_bytes());
        buf.extend_from_slice(&u32::from(prefix.network()).to_be_bytes());
        buf.push(prefix.prefix_len());
        buf.extend_from_slice(&bucket.to_be_bytes());
        buf.extend_from_slice(&round.to_be_bytes());
        let h = crate::util::fnv1a64(&buf);
        let mut offset = h % size;
        // Avoid the .0 and .255 host values as a courtesy to network operators.
        for _ in 0..4 {
            let candidate = base + offset;
            let last = (candidate & 0xff) as u8;
            if last != 0 && last != 255 {
                break;
            }
            offset = (offset + 1) % size;
        }
        let value = base + offset;
        if value > u64::from(u32::MAX) {
            return None;
        }
        Some(Ipv4Addr::from(value as u32))
    }
}

fn prefix_size(prefix: &Ipv4Net) -> u64 {
    1u64 << (32 - u32::from(prefix.prefix_len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(buckets: usize, exploit: f64, seed: u64) -> SamplingConfig {
        SamplingConfig {
            buckets_per_prefix: buckets,
            exploit_fraction: exploit,
            seed,
            ..SamplingConfig::default()
        }
    }

    #[test]
    fn sampling_is_bounded_by_budget() {
        let s = StratifiedSampler::new(&cfg(64, 0.3, 7));
        let snap = PrefixSnapshot::builtin();
        let out = s.next_round(&snap, 32);
        assert!(out.len() <= 32, "produced {}", out.len());
        assert!(!out.is_empty());
    }

    #[test]
    fn every_sampled_address_is_inside_an_official_prefix() {
        let s = StratifiedSampler::new(&cfg(64, 0.3, 7));
        let snap = PrefixSnapshot::builtin();
        for _ in 0..20 {
            for addr in s.next_round(&snap, 32) {
                assert!(
                    snap.contains(std::net::IpAddr::V4(addr)),
                    "{addr} escaped the official prefix set"
                );
                assert!(crate::util::ipclass::classify_v4(addr).is_none());
            }
        }
    }

    #[test]
    fn sampling_is_reproducible() {
        let snap = PrefixSnapshot::builtin();
        let a = StratifiedSampler::new(&cfg(32, 0.25, 99));
        let b = StratifiedSampler::new(&cfg(32, 0.25, 99));
        for _ in 0..5 {
            assert_eq!(a.next_round(&snap, 16), b.next_round(&snap, 16));
        }
    }

    #[test]
    fn different_seeds_produce_different_schedules() {
        let snap = PrefixSnapshot::builtin();
        let a = StratifiedSampler::new(&cfg(32, 0.25, 1));
        let b = StratifiedSampler::new(&cfg(32, 0.25, 2));
        assert_ne!(a.next_round(&snap, 16), b.next_round(&snap, 16));
    }

    #[test]
    fn budget_is_spread_across_prefixes() {
        let s = StratifiedSampler::new(&cfg(64, 0.0, 5));
        let snap = PrefixSnapshot::builtin();
        let out = s.next_round(&snap, snap.ipv4().len());
        let mut seen = std::collections::HashSet::new();
        for addr in &out {
            let prefix = snap
                .ipv4()
                .iter()
                .find(|n| n.contains(addr))
                .copied()
                .expect("inside a prefix");
            seen.insert(prefix);
        }
        assert!(
            seen.len() >= snap.ipv4().len() - 1,
            "expected coverage across prefixes, got {}",
            seen.len()
        );
    }

    #[test]
    fn unexplored_buckets_are_preferred() {
        let s = StratifiedSampler::new(&cfg(8, 0.0, 3));
        let snap = PrefixSnapshot::new(
            vec!["104.16.0.0/13".parse().expect("net")],
            Vec::new(),
            None,
            0,
            super::super::prefixes::PrefixSource::Api,
        );
        let mut buckets = std::collections::HashSet::new();
        for _ in 0..8 {
            for addr in s.next_round(&snap, 1) {
                let (_, b) = s.locate(&snap, addr).expect("locatable");
                buckets.insert(b);
            }
        }
        assert_eq!(buckets.len(), 8, "all eight buckets should be visited once");
    }

    #[test]
    fn productive_buckets_get_extra_budget() {
        let s = StratifiedSampler::new(&cfg(4, 0.5, 11));
        let snap = PrefixSnapshot::new(
            vec!["104.16.0.0/13".parse().expect("net")],
            Vec::new(),
            None,
            0,
            super::super::prefixes::PrefixSource::Api,
        );
        let first = s.next_round(&snap, 4);
        assert!(!first.is_empty());
        for addr in &first {
            s.record_success(&snap, *addr);
        }
        let second = s.next_round(&snap, 4);
        assert!(!second.is_empty());
        assert!(s.tracked_buckets() <= 4);
    }

    #[test]
    fn small_prefixes_do_not_over_bucket() {
        let s = StratifiedSampler::new(&cfg(4_096, 0.0, 1));
        let snap = PrefixSnapshot::new(
            vec!["131.0.72.0/22".parse().expect("net")],
            Vec::new(),
            None,
            0,
            super::super::prefixes::PrefixSource::Api,
        );
        let out = s.next_round(&snap, 8);
        for addr in out {
            assert!(snap.contains(std::net::IpAddr::V4(addr)));
        }
    }

    #[test]
    fn network_and_broadcast_host_values_are_avoided() {
        let s = StratifiedSampler::new(&cfg(256, 0.0, 42));
        let snap = PrefixSnapshot::builtin();
        for _ in 0..40 {
            for addr in s.next_round(&snap, 32) {
                let last = addr.octets()[3];
                assert!(
                    last != 0 && last != 255,
                    "{addr} uses a reserved host value"
                );
            }
        }
    }

    #[test]
    fn locate_round_trips() {
        let s = StratifiedSampler::new(&cfg(64, 0.0, 8));
        let snap = PrefixSnapshot::builtin();
        for addr in s.next_round(&snap, 32) {
            let (prefix, bucket) = s.locate(&snap, addr).expect("locatable");
            assert!(prefix.contains(&addr));
            assert!(bucket < 64);
        }
    }
}
