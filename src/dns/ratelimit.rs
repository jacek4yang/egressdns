//! Bounded inbound rate limiting.
//!
//! A global limiter protects the process, and a bounded keyed limiter protects against a
//! single misbehaving client. The keyed table has a hard capacity so that a spoofed-source
//! flood cannot exhaust memory: when the table is full, new clients share the global
//! budget only.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::Mutex;

use crate::config::RateLimitConfig;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The query may proceed.
    Allow,
    /// The per-client budget is exhausted.
    ClientLimited,
    /// The global budget is exhausted.
    GlobalLimited,
}

/// Inbound rate limiter.
pub struct InboundLimiter {
    enabled: bool,
    global: Option<Arc<DirectLimiter>>,
    per_client: Option<ClientTable>,
}

struct ClientTable {
    quota: Quota,
    capacity: usize,
    inner: Mutex<ClientTableInner>,
}

struct ClientTableInner {
    /// Bounded map of client address to limiter. A simple two-generation scheme keeps
    /// memory bounded without a full LRU: when `current` fills up it becomes `previous`
    /// and a fresh map is started.
    current: std::collections::HashMap<IpAddr, Arc<DirectLimiter>>,
    previous: std::collections::HashMap<IpAddr, Arc<DirectLimiter>>,
}

impl InboundLimiter {
    /// Build a limiter from configuration.
    pub fn new(cfg: &RateLimitConfig) -> Self {
        if !cfg.enabled {
            return Self {
                enabled: false,
                global: None,
                per_client: None,
            };
        }
        let global = NonZeroU32::new(cfg.global_qps).map(|qps| {
            let burst = NonZeroU32::new(cfg.global_burst.max(cfg.global_qps)).unwrap_or(qps);
            Arc::new(RateLimiter::direct(
                Quota::per_second(qps).allow_burst(burst),
            ))
        });
        let per_client = NonZeroU32::new(cfg.per_client_qps).map(|qps| {
            let burst =
                NonZeroU32::new(cfg.per_client_burst.max(cfg.per_client_qps)).unwrap_or(qps);
            ClientTable {
                quota: Quota::per_second(qps).allow_burst(burst),
                capacity: cfg.client_table_size.max(1),
                inner: Mutex::new(ClientTableInner {
                    current: std::collections::HashMap::new(),
                    previous: std::collections::HashMap::new(),
                }),
            }
        });
        Self {
            enabled: true,
            global,
            per_client,
        }
    }

    /// Check whether a query from `client` may proceed.
    pub fn check(&self, client: IpAddr) -> RateDecision {
        if !self.enabled {
            return RateDecision::Allow;
        }
        if let Some(table) = &self.per_client {
            if let Some(limiter) = table.limiter_for(client) {
                if limiter.check().is_err() {
                    return RateDecision::ClientLimited;
                }
            }
        }
        if let Some(global) = &self.global {
            if global.check().is_err() {
                return RateDecision::GlobalLimited;
            }
        }
        RateDecision::Allow
    }

    /// Number of tracked clients, for metrics.
    pub fn tracked_clients(&self) -> usize {
        self.per_client
            .as_ref()
            .map(|t| {
                let inner = t.inner.lock();
                inner.current.len() + inner.previous.len()
            })
            .unwrap_or(0)
    }
}

impl ClientTable {
    fn limiter_for(&self, client: IpAddr) -> Option<Arc<DirectLimiter>> {
        let mut inner = self.inner.lock();
        if let Some(l) = inner.current.get(&client) {
            return Some(Arc::clone(l));
        }
        if let Some(l) = inner.previous.get(&client).cloned() {
            inner.current.insert(client, Arc::clone(&l));
            return Some(l);
        }
        if inner.current.len() >= self.capacity {
            // Rotate generations. This bounds memory to 2 * capacity entries.
            let old = std::mem::take(&mut inner.current);
            inner.previous = old;
        }
        let limiter = Arc::new(RateLimiter::direct(self.quota));
        inner.current.insert(client, Arc::clone(&limiter));
        Some(limiter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cfg(enabled: bool, per_client: u32, global: u32, table: usize) -> RateLimitConfig {
        RateLimitConfig {
            enabled,
            per_client_qps: per_client,
            per_client_burst: per_client,
            global_qps: global,
            global_burst: global,
            client_table_size: table,
        }
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let l = InboundLimiter::new(&cfg(false, 1, 1, 10));
        let ip = IpAddr::from_str("10.0.0.1").expect("ip");
        for _ in 0..1000 {
            assert_eq!(l.check(ip), RateDecision::Allow);
        }
    }

    #[test]
    fn per_client_budget_is_enforced() {
        let l = InboundLimiter::new(&cfg(true, 5, 1_000_000, 100));
        let ip = IpAddr::from_str("10.0.0.1").expect("ip");
        let mut allowed = 0;
        for _ in 0..50 {
            if l.check(ip) == RateDecision::Allow {
                allowed += 1;
            }
        }
        assert!(allowed <= 6, "allowed {allowed}");
        // A different client still has its own budget.
        assert_eq!(
            l.check(IpAddr::from_str("10.0.0.2").expect("ip")),
            RateDecision::Allow
        );
    }

    #[test]
    fn client_table_is_bounded() {
        let l = InboundLimiter::new(&cfg(true, 1_000, 1_000_000, 8));
        for i in 0..200u8 {
            let ip = IpAddr::from_str(&format!("10.0.0.{i}")).expect("ip");
            let _ = l.check(ip);
        }
        assert!(
            l.tracked_clients() <= 16,
            "table grew to {}",
            l.tracked_clients()
        );
    }

    #[test]
    fn global_budget_is_enforced() {
        let l = InboundLimiter::new(&cfg(true, 1_000_000, 3, 100));
        let mut allowed = 0;
        for i in 0..50u8 {
            let ip = IpAddr::from_str(&format!("10.0.1.{i}")).expect("ip");
            if l.check(ip) == RateDecision::Allow {
                allowed += 1;
            }
        }
        assert!(allowed <= 4, "allowed {allowed}");
    }
}
