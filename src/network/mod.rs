//! IPv4/IPv6 environment detection and network generations.
//!
//! Quality measurements are only meaningful relative to the path they were taken on. When
//! the egress path changes — a new default route, a new source address, an interface
//! flap — historical evidence becomes a weak prior rather than fact. That transition is
//! modelled explicitly as a *network generation*: a monotonically increasing identifier
//! attached to every quality sample.
//!
//! Detection reads the kernel routing tables and the interface address list, and asks the
//! kernel which source address it would select for a reference destination. Determining
//! the source address uses `connect(2)` on an unconnected UDP socket, which performs a
//! route lookup without transmitting anything.

pub mod detect;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;

/// Usability of one address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyState {
    /// Never determined.
    Unknown,
    /// A default route and a usable global source address exist.
    Usable,
    /// No usable path was found.
    Unusable,
}

impl FamilyState {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Usable => "usable",
            Self::Unusable => "unusable",
        }
    }

    /// Numeric value for the gauge: 0 unknown, 1 usable, 2 unusable.
    pub fn gauge(self) -> f64 {
        match self {
            Self::Unknown => 0.0,
            Self::Usable => 1.0,
            Self::Unusable => 2.0,
        }
    }
}

/// Every address this host currently carries, loopback included.
///
/// Used to notice that a "gateway" is in fact ourselves, which is a forwarding loop
/// waiting to happen. Reads the interface list directly rather than the cached snapshot,
/// because it is consulted at startup before the detector has run.
pub fn local_addresses() -> Vec<std::net::IpAddr> {
    let mut out = vec![
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ];
    let Ok(output) = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    else {
        return out;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        // `2: enp2s0    inet 192.168.31.204/24 brd ...`
        let Some(cidr) = fields.nth(3) else { continue };
        let addr = cidr.split('/').next().unwrap_or(cidr);
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            out.push(ip);
        }
    }
    out
}

/// Raw observation of the host's network state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawNetworkState {
    /// Interface carrying the IPv4 default route.
    pub default_iface_v4: Option<String>,
    /// IPv4 default gateway.
    pub gateway_v4: Option<Ipv4Addr>,
    /// Interface carrying the IPv6 default route.
    pub default_iface_v6: Option<String>,
    /// IPv6 default gateway.
    pub gateway_v6: Option<Ipv6Addr>,
    /// Source address the kernel would select for the IPv4 reference destination.
    pub source_v4: Option<Ipv4Addr>,
    /// Source address the kernel would select for the IPv6 reference destination.
    pub source_v6: Option<Ipv6Addr>,
    /// Sorted list of global-scope interface addresses, as strings.
    pub global_addresses: Vec<String>,
}

impl RawNetworkState {
    /// A stable fingerprint of everything that defines the egress path.
    pub fn fingerprint(&self) -> u64 {
        let mut buf = Vec::with_capacity(256);
        let mut push = |s: &str| {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0x1f);
        };
        push(self.default_iface_v4.as_deref().unwrap_or("-"));
        push(&self.gateway_v4.map(|g| g.to_string()).unwrap_or_default());
        push(self.default_iface_v6.as_deref().unwrap_or("-"));
        push(&self.gateway_v6.map(|g| g.to_string()).unwrap_or_default());
        push(&self.source_v4.map(|g| g.to_string()).unwrap_or_default());
        push(&self.source_v6.map(|g| g.to_string()).unwrap_or_default());
        for a in &self.global_addresses {
            push(a);
        }
        crate::util::fnv1a64(&buf)
    }

    /// Derived IPv4 usability.
    pub fn v4_state(&self) -> FamilyState {
        match (self.default_iface_v4.is_some(), self.source_v4) {
            (true, Some(addr)) if !addr.is_loopback() && !addr.is_unspecified() => {
                FamilyState::Usable
            }
            _ => FamilyState::Unusable,
        }
    }

    /// Derived IPv6 usability.
    pub fn v6_state(&self) -> FamilyState {
        match (self.default_iface_v6.is_some(), self.source_v6) {
            (true, Some(addr))
                if !addr.is_loopback() && !addr.is_unspecified() && !is_link_local_v6(addr) =>
            {
                FamilyState::Usable
            }
            _ => FamilyState::Unusable,
        }
    }
}

fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Published, immutable view of the network state.
#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    /// Monotonically increasing generation identifier.
    pub generation: u64,
    /// IPv4 usability.
    pub v4: FamilyState,
    /// IPv6 usability.
    pub v6: FamilyState,
    /// Raw observation this snapshot was derived from.
    pub raw: RawNetworkState,
    /// Wall-clock second the generation was published.
    pub published_unix: u64,
}

impl NetworkSnapshot {
    /// An "unknown" snapshot published before the first successful detection.
    pub fn unknown() -> Self {
        Self {
            generation: 1,
            v4: FamilyState::Unknown,
            v6: FamilyState::Unknown,
            raw: RawNetworkState::default(),
            published_unix: 0,
        }
    }

    /// True when at least one family can reach the Internet.
    pub fn any_usable(&self) -> bool {
        matches!(self.v4, FamilyState::Usable | FamilyState::Unknown)
            || matches!(self.v6, FamilyState::Usable | FamilyState::Unknown)
    }
}

/// Shared, atomically swappable network state.
pub struct NetworkState {
    current: ArcSwap<NetworkSnapshot>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkState {
    /// Create the shared state with an unknown snapshot.
    pub fn new() -> Self {
        Self {
            current: ArcSwap::from_pointee(NetworkSnapshot::unknown()),
        }
    }

    /// Read the current snapshot. This is a single atomic load and is safe on the hot path.
    pub fn load(&self) -> Arc<NetworkSnapshot> {
        self.current.load_full()
    }

    /// Current generation identifier.
    pub fn generation(&self) -> u64 {
        self.current.load().generation
    }

    /// Publish a new snapshot, incrementing the generation when the path changed.
    ///
    /// Returns `true` when the generation advanced.
    pub fn publish(&self, raw: RawNetworkState, now_unix: u64) -> bool {
        let previous = self.current.load_full();
        let changed = previous.raw.fingerprint() != raw.fingerprint();
        let generation = if changed {
            previous.generation.saturating_add(1)
        } else {
            previous.generation
        };
        let snapshot = NetworkSnapshot {
            generation,
            v4: raw.v4_state(),
            v6: raw.v6_state(),
            raw,
            published_unix: if changed {
                now_unix
            } else {
                previous.published_unix
            },
        };
        self.current.store(Arc::new(snapshot));
        changed
    }

    /// True while the accelerated relearning window after a change is open.
    pub fn in_relearn_window(&self, now_unix: u64, window_secs: u64) -> bool {
        let s = self.current.load();
        s.published_unix > 0 && now_unix.saturating_sub(s.published_unix) < window_secs
    }
}

/// Shared handle.
pub type SharedNetworkState = Arc<NetworkState>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn raw(v4: bool, v6: bool) -> RawNetworkState {
        RawNetworkState {
            default_iface_v4: v4.then(|| "eth0".to_string()),
            gateway_v4: v4.then(|| Ipv4Addr::new(10, 0, 0, 1)),
            default_iface_v6: v6.then(|| "eth0".to_string()),
            gateway_v6: v6.then(|| Ipv6Addr::from_str("fe80::1").expect("v6")),
            source_v4: v4.then(|| Ipv4Addr::new(10, 0, 0, 53)),
            source_v6: v6.then(|| Ipv6Addr::from_str("2001:db8::53").expect("v6")),
            global_addresses: vec!["10.0.0.53".to_string()],
        }
    }

    #[test]
    fn families_are_independent() {
        let only_v4 = raw(true, false);
        assert_eq!(only_v4.v4_state(), FamilyState::Usable);
        assert_eq!(only_v4.v6_state(), FamilyState::Unusable);
        let only_v6 = raw(false, true);
        assert_eq!(only_v6.v4_state(), FamilyState::Unusable);
        assert_eq!(only_v6.v6_state(), FamilyState::Usable);
    }

    #[test]
    fn link_local_v6_source_is_not_usable() {
        let mut r = raw(false, true);
        r.source_v6 = Some(Ipv6Addr::from_str("fe80::1234").expect("v6"));
        assert_eq!(r.v6_state(), FamilyState::Unusable);
    }

    #[test]
    fn generation_advances_only_on_change() {
        let state = NetworkState::new();
        assert_eq!(state.generation(), 1);
        assert!(state.publish(raw(true, true), 100));
        let g = state.generation();
        assert_eq!(g, 2);
        assert!(!state.publish(raw(true, true), 200));
        assert_eq!(state.generation(), 2);
        assert!(state.publish(raw(true, false), 300));
        assert_eq!(state.generation(), 3);
    }

    #[test]
    fn relearn_window_closes() {
        let state = NetworkState::new();
        state.publish(raw(true, true), 1_000);
        assert!(state.in_relearn_window(1_100, 600));
        assert!(!state.in_relearn_window(2_000, 600));
    }

    #[test]
    fn fingerprint_is_sensitive_to_gateway_change() {
        let a = raw(true, true);
        let mut b = a.clone();
        b.gateway_v4 = Some(Ipv4Addr::new(10, 0, 0, 254));
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn unknown_snapshot_is_permissive() {
        let s = NetworkSnapshot::unknown();
        assert!(
            s.any_usable(),
            "an undetermined network must not block queries"
        );
    }
}
