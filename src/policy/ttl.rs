//! Client-facing TTL policy.
//!
//! The single invariant that matters here: a client TTL is *never* larger than the
//! remaining authoritative TTL. Every code path takes a minimum, never a maximum, so no
//! configuration value can extend the lifetime of upstream data.

use crate::config::TtlConfig;

/// Why a particular cap was chosen. Exposed through metrics and `egressdnsctl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlReason {
    /// Answer served from the stale cache.
    ServeStale,
    /// The network generation changed recently.
    NetworkChange,
    /// Verified Cloudflare addresses were prepended.
    CloudflareAugment,
    /// A Cloudflare RRset was reordered in preserve mode.
    CloudflarePreserve,
    /// A multi-address answer was reordered using quality evidence.
    OptimizedMulti,
    /// No optimization applied.
    Default,
}

impl TtlReason {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::ServeStale => "serve_stale",
            Self::NetworkChange => "network_change",
            Self::CloudflareAugment => "cloudflare_augment",
            Self::CloudflarePreserve => "cloudflare_preserve",
            Self::OptimizedMulti => "optimized_multi",
            Self::Default => "default",
        }
    }
}

/// Inputs to the TTL decision.
#[derive(Debug, Clone, Copy)]
pub struct TtlInputs {
    /// Remaining authoritative TTL in seconds. This is a hard upper bound.
    pub remaining_authoritative: u32,
    /// Remaining RRSIG lifetime in seconds, when the answer is signed.
    pub remaining_signature: Option<u32>,
    /// The answer came from the stale cache.
    pub is_stale: bool,
    /// The network generation changed inside the configured window.
    pub recent_network_change: bool,
    /// Verified Cloudflare addresses were prepended.
    pub cloudflare_augmented: bool,
    /// A Cloudflare RRset was reordered without modification of its membership.
    pub cloudflare_preserved: bool,
    /// A multi-address answer was reordered using quality evidence.
    pub optimized_multi: bool,
}

/// Compute the effective client-facing TTL and the reason for it.
pub fn effective_client_ttl(cfg: &TtlConfig, inputs: TtlInputs) -> (u32, TtlReason) {
    // Choose the policy cap. The strongest (smallest) applicable reason wins.
    let (cap, reason) = if inputs.is_stale {
        (cfg.cap_serve_stale, TtlReason::ServeStale)
    } else if inputs.cloudflare_augmented {
        (cfg.cap_cloudflare_augment, TtlReason::CloudflareAugment)
    } else if inputs.recent_network_change {
        (cfg.cap_network_change, TtlReason::NetworkChange)
    } else if inputs.cloudflare_preserved {
        (cfg.cap_cloudflare_preserve, TtlReason::CloudflarePreserve)
    } else if inputs.optimized_multi {
        (cfg.cap_optimized_multi, TtlReason::OptimizedMulti)
    } else {
        (cfg.cap_default, TtlReason::Default)
    };

    // A recent network change also bounds any other reason, without ever raising a TTL.
    let cap = if inputs.recent_network_change {
        cap.min(cfg.cap_network_change)
    } else {
        cap
    };

    let mut ttl = inputs.remaining_authoritative.min(cap);
    if let Some(sig) = inputs.remaining_signature {
        ttl = ttl.min(sig);
    }
    (ttl, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TtlInputs {
        TtlInputs {
            remaining_authoritative: 3_600,
            remaining_signature: None,
            is_stale: false,
            recent_network_change: false,
            cloudflare_augmented: false,
            cloudflare_preserved: false,
            optimized_multi: false,
        }
    }

    #[test]
    fn never_exceeds_remaining_authoritative_ttl() {
        let cfg = TtlConfig::default();
        for remaining in [0u32, 1, 5, 29, 59, 61, 299, 301, 100_000] {
            let inputs = TtlInputs {
                remaining_authoritative: remaining,
                ..base()
            };
            let (ttl, _) = effective_client_ttl(&cfg, inputs);
            assert!(
                ttl <= remaining,
                "ttl {ttl} exceeded remaining authoritative {remaining}"
            );
        }
    }

    #[test]
    fn signature_lifetime_bounds_the_ttl() {
        let cfg = TtlConfig::default();
        let inputs = TtlInputs {
            remaining_authoritative: 3_600,
            remaining_signature: Some(7),
            ..base()
        };
        let (ttl, _) = effective_client_ttl(&cfg, inputs);
        assert_eq!(ttl, 7);
    }

    #[test]
    fn caps_follow_the_documented_ordering() {
        let cfg = TtlConfig::default();
        let (t, r) = effective_client_ttl(&cfg, base());
        assert_eq!((t, r), (cfg.cap_default, TtlReason::Default));

        let (t, r) = effective_client_ttl(
            &cfg,
            TtlInputs {
                optimized_multi: true,
                ..base()
            },
        );
        assert_eq!((t, r), (cfg.cap_optimized_multi, TtlReason::OptimizedMulti));

        let (t, r) = effective_client_ttl(
            &cfg,
            TtlInputs {
                cloudflare_preserved: true,
                optimized_multi: true,
                ..base()
            },
        );
        assert_eq!(
            (t, r),
            (cfg.cap_cloudflare_preserve, TtlReason::CloudflarePreserve)
        );

        let (t, r) = effective_client_ttl(
            &cfg,
            TtlInputs {
                cloudflare_augmented: true,
                cloudflare_preserved: true,
                ..base()
            },
        );
        assert_eq!(
            (t, r),
            (cfg.cap_cloudflare_augment, TtlReason::CloudflareAugment)
        );

        let (t, r) = effective_client_ttl(
            &cfg,
            TtlInputs {
                is_stale: true,
                cloudflare_augmented: true,
                ..base()
            },
        );
        assert_eq!((t, r), (cfg.cap_serve_stale, TtlReason::ServeStale));
    }

    #[test]
    fn network_change_bounds_every_other_reason() {
        let cfg = TtlConfig::default();
        for extra in [
            TtlInputs {
                recent_network_change: true,
                ..base()
            },
            TtlInputs {
                recent_network_change: true,
                optimized_multi: true,
                ..base()
            },
            TtlInputs {
                recent_network_change: true,
                cloudflare_preserved: true,
                ..base()
            },
            TtlInputs {
                recent_network_change: true,
                cloudflare_augmented: true,
                ..base()
            },
        ] {
            let (ttl, _) = effective_client_ttl(&cfg, extra);
            assert!(
                ttl <= cfg.cap_network_change,
                "ttl {ttl} exceeded the network-change cap"
            );
        }
    }

    #[test]
    fn augment_cap_is_short() {
        let cfg = TtlConfig::default();
        let (ttl, _) = effective_client_ttl(
            &cfg,
            TtlInputs {
                cloudflare_augmented: true,
                ..base()
            },
        );
        assert!((20..=30).contains(&ttl), "augment TTL was {ttl}");
    }

    #[test]
    fn zero_remaining_ttl_stays_zero() {
        let cfg = TtlConfig::default();
        let (ttl, _) = effective_client_ttl(
            &cfg,
            TtlInputs {
                remaining_authoritative: 0,
                ..base()
            },
        );
        assert_eq!(ttl, 0);
    }
}
