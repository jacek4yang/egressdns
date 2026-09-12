//! Offer-side deduplication for probe jobs.
//!
//! The foreground path offers one probe per answer address on **every** cache hit, and
//! the safety guard refuses offers inside an address's cooldown window at *execution*
//! time. Without an offer-side gate, a name queried at high rate floods the bounded
//! probe queue with duplicate offers of the same few addresses: the queue fills, and
//! first-time candidates from other names are dropped at the queue while duplicates
//! burn worker wakeups and — worse — were recorded as `PolicyBlocked` observations,
//! fabricating evidence for addresses that were never probed.
//!
//! The gate mirrors the guard's per-address cooldown at offer time: an offer for an
//! (address, port, hostname) triple is suppressed until the longest cooldown that would
//! refuse it has elapsed since the last offer. The map is bounded and pruned on insert,
//! so a hostile cardinality of names cannot grow it without limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use parking_lot::Mutex;

/// Maximum tracked (address, port, hostname) triples. At the default cooldowns this
/// bounds the gate to a few thousand entries; beyond it, the oldest entries are
/// forgotten and the worst case is a duplicate offer, which is what happened before
/// the gate existed.
const MAX_ENTRIES: usize = 8_192;

/// Offer-side deduplication state.
#[derive(Default)]
pub struct OfferGate {
    seen: Mutex<HashMap<OfferKey, Instant>>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct OfferKey {
    addr: IpAddr,
    port: u16,
    /// Empty for hostname-independent offers (Cloudflare candidates).
    hostname: Arc<str>,
}

impl OfferGate {
    /// An empty gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an offer for this triple may enter the queue at `now`.
    ///
    /// `cooldown` is the execution-side window that would refuse the probe — the
    /// longest of the guard's per-address and per-domain cooldowns. Returns `true` and
    /// records the offer when the last offer for this triple is older than `cooldown`;
    /// returns `false` otherwise.
    ///
    /// The effective window is jittered deterministically per triple (0.8×–1.2× of
    /// `cooldown`): a thousand names learned at the same moment would otherwise all
    /// become offerable in the same instant, and the guard's connection-rate limit
    /// would serially starve whichever triples sort last — every window, forever.
    pub fn allow(
        &self,
        addr: IpAddr,
        port: u16,
        hostname: &str,
        cooldown: Duration,
        now: Instant,
    ) -> bool {
        let key = OfferKey {
            addr,
            port,
            hostname: Arc::from(hostname),
        };
        let window = Self::jittered(cooldown, &key);
        let mut seen = self.seen.lock();
        if let Some(last) = seen.get(&key) {
            if now.saturating_duration_since(*last) < window {
                return false;
            }
        }
        if seen.len() >= MAX_ENTRIES {
            seen.retain(|_, t| now.saturating_duration_since(*t) < window);
            if seen.len() >= MAX_ENTRIES {
                // Compact by dropping the oldest quarter rather than growing forever.
                let oldest: Vec<OfferKey> = {
                    let mut keys: Vec<(&OfferKey, Instant)> =
                        seen.iter().map(|(k, t)| (k, *t)).collect();
                    keys.sort_by_key(|(_, t)| *t);
                    let drop = keys.len() - keys.len() / 4;
                    keys.into_iter()
                        .take(drop)
                        .map(|(k, _)| k.clone())
                        .collect()
                };
                for k in oldest {
                    seen.remove(&k);
                }
            }
        }
        seen.insert(key, now);
        true
    }

    /// Deterministic per-triple jitter: 0.8×–1.2× of the cooldown, derived from the
    /// triple's hash so the spread is stable across restarts.
    fn jittered(cooldown: Duration, key: &OfferKey) -> Duration {
        let hash = crate::util::fnv1a64(
            [
                key.addr.to_string().as_bytes(),
                &key.port.to_be_bytes(),
                key.hostname.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        let tenths = 8 + (hash % 5) as u32; // 8..=12
        cooldown * tenths / 10
    }

    /// Number of tracked triples, for metrics and tests.
    pub fn tracked(&self) -> usize {
        self.seen.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(octet: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, octet))
    }

    #[test]
    fn first_offer_passes_and_duplicates_are_suppressed_inside_the_window() {
        let gate = OfferGate::new();
        let now = Instant::now();
        let cooldown = Duration::from_secs(300);

        assert!(gate.allow(addr(1), 443, "a.example.test", cooldown, now));
        assert!(
            !gate.allow(
                addr(1),
                443,
                "a.example.test",
                cooldown,
                now + Duration::from_secs(1)
            ),
            "a duplicate inside the cooldown must be suppressed"
        );
        assert!(
            gate.allow(addr(1), 443, "a.example.test", cooldown, now + cooldown),
            "after the cooldown the offer passes again"
        );
    }

    #[test]
    fn different_hostnames_and_addresses_are_independent() {
        let gate = OfferGate::new();
        let now = Instant::now();
        let cooldown = Duration::from_secs(300);

        assert!(gate.allow(addr(1), 443, "a.example.test", cooldown, now));
        assert!(
            gate.allow(addr(1), 443, "b.example.test", cooldown, now),
            "the same address for another hostname is a different measurement"
        );
        assert!(
            gate.allow(addr(2), 443, "a.example.test", cooldown, now),
            "another address for the same hostname is a different measurement"
        );
    }

    #[test]
    fn the_map_is_bounded_under_hostile_cardinality() {
        let gate = OfferGate::new();
        let now = Instant::now();
        let cooldown = Duration::from_secs(3600);
        // Far more distinct triples than MAX_ENTRIES, all "fresh".
        for i in 0..50_000u32 {
            let o1 = (i / 250 % 250) as u8;
            let o2 = (i % 250) as u8;
            let o0 = (i / 62_500 % 250) as u8;
            let _ = gate.allow(
                IpAddr::V4(std::net::Ipv4Addr::new(203, o0, o1, o2)),
                443,
                "hostile.example.test",
                cooldown,
                now,
            );
        }
        assert!(
            gate.tracked() <= MAX_ENTRIES,
            "the gate must not grow without bound"
        );
    }
}
