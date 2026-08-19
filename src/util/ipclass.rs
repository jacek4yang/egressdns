//! Classification of IP addresses into special-use ranges.
//!
//! Probe safety depends on never dialling addresses that a hostile or merely broken
//! upstream could use to reach link-local metadata services, loopback services or other
//! internal endpoints (DNS-driven SSRF). The tables below follow the IANA Special-Purpose
//! Address Registries for IPv4 and IPv6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Why an address is considered special-use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialUse {
    /// `0.0.0.0/8`, `::/128` and friends.
    Unspecified,
    /// Loopback ranges.
    Loopback,
    /// RFC1918 / ULA private ranges.
    Private,
    /// Carrier-grade NAT (`100.64.0.0/10`).
    SharedAddressSpace,
    /// Link-local ranges, including cloud metadata services.
    LinkLocal,
    /// Well-known cloud instance metadata addresses.
    CloudMetadata,
    /// Documentation / test ranges.
    Documentation,
    /// Benchmarking ranges.
    Benchmarking,
    /// IETF protocol assignments.
    ProtocolAssignment,
    /// Multicast ranges.
    Multicast,
    /// Reserved / future use, including the limited broadcast address.
    Reserved,
    /// Translation mechanisms (6to4, Teredo, NAT64).
    Translation,
}

impl SpecialUse {
    /// Stable, bounded label suitable for a metrics dimension.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared_address_space",
            Self::LinkLocal => "link_local",
            Self::CloudMetadata => "cloud_metadata",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::ProtocolAssignment => "protocol_assignment",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Translation => "translation",
        }
    }
}

const V4_TABLE: &[(&str, SpecialUse)] = &[
    ("0.0.0.0/8", SpecialUse::Unspecified),
    ("10.0.0.0/8", SpecialUse::Private),
    ("100.64.0.0/10", SpecialUse::SharedAddressSpace),
    ("127.0.0.0/8", SpecialUse::Loopback),
    ("169.254.0.0/16", SpecialUse::LinkLocal),
    ("172.16.0.0/12", SpecialUse::Private),
    ("192.0.0.0/24", SpecialUse::ProtocolAssignment),
    ("192.0.2.0/24", SpecialUse::Documentation),
    ("192.88.99.0/24", SpecialUse::Translation),
    ("192.168.0.0/16", SpecialUse::Private),
    ("198.18.0.0/15", SpecialUse::Benchmarking),
    ("198.51.100.0/24", SpecialUse::Documentation),
    ("203.0.113.0/24", SpecialUse::Documentation),
    ("224.0.0.0/4", SpecialUse::Multicast),
    ("240.0.0.0/4", SpecialUse::Reserved),
];

const V6_TABLE: &[(&str, SpecialUse)] = &[
    ("::/128", SpecialUse::Unspecified),
    ("::1/128", SpecialUse::Loopback),
    ("::ffff:0:0/96", SpecialUse::Translation),
    ("64:ff9b::/96", SpecialUse::Translation),
    ("64:ff9b:1::/48", SpecialUse::Translation),
    ("100::/64", SpecialUse::Reserved),
    ("2001:2::/48", SpecialUse::Benchmarking),
    ("2001:db8::/32", SpecialUse::Documentation),
    ("2001::/23", SpecialUse::ProtocolAssignment),
    ("2002::/16", SpecialUse::Translation),
    ("fc00::/7", SpecialUse::Private),
    ("fe80::/10", SpecialUse::LinkLocal),
    ("ff00::/8", SpecialUse::Multicast),
];

/// Well-known cloud instance metadata endpoints that must never be probed.
const METADATA_V4: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(169, 254, 170, 2),
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
];

/// Classify an address, returning `None` when it is ordinary global unicast.
pub fn classify(addr: IpAddr) -> Option<SpecialUse> {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Classify an IPv4 address.
pub fn classify_v4(addr: Ipv4Addr) -> Option<SpecialUse> {
    if METADATA_V4.contains(&addr) {
        return Some(SpecialUse::CloudMetadata);
    }
    if addr == Ipv4Addr::BROADCAST {
        return Some(SpecialUse::Reserved);
    }
    for (cidr, class) in V4_TABLE {
        // The table is a compile-time constant of valid CIDRs.
        if let Ok(net) = cidr.parse::<Ipv4Net>() {
            if net.contains(&addr) {
                return Some(*class);
            }
        }
    }
    None
}

/// Classify an IPv6 address.
pub fn classify_v6(addr: Ipv6Addr) -> Option<SpecialUse> {
    // AWS IPv6 instance metadata endpoint.
    if addr == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) {
        return Some(SpecialUse::CloudMetadata);
    }
    if let Some(mapped) = addr.to_ipv4_mapped() {
        // An IPv4-mapped address inherits the IPv4 classification, and is itself
        // a translation range, so it is always special-use.
        return Some(classify_v4(mapped).unwrap_or(SpecialUse::Translation));
    }
    for (cidr, class) in V6_TABLE {
        if let Ok(net) = cidr.parse::<Ipv6Net>() {
            if net.contains(&addr) {
                return Some(*class);
            }
        }
    }
    None
}

/// True when the address is ordinary global unicast and therefore probe-eligible by default.
pub fn is_global_unicast(addr: IpAddr) -> bool {
    classify(addr).is_none()
}

/// Parse the special-use table into `IpNet` values, for diagnostics and admin output.
pub fn special_use_networks() -> Vec<(IpNet, SpecialUse)> {
    let mut out = Vec::with_capacity(V4_TABLE.len() + V6_TABLE.len());
    for (cidr, class) in V4_TABLE {
        if let Ok(net) = cidr.parse::<Ipv4Net>() {
            out.push((IpNet::V4(net), *class));
        }
    }
    for (cidr, class) in V6_TABLE {
        if let Ok(net) = cidr.parse::<Ipv6Net>() {
            out.push((IpNet::V6(net), *class));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn metadata_is_blocked() {
        assert_eq!(
            classify(IpAddr::from_str("169.254.169.254").unwrap()),
            Some(SpecialUse::CloudMetadata)
        );
        assert_eq!(
            classify(IpAddr::from_str("fd00:ec2::254").unwrap()),
            Some(SpecialUse::CloudMetadata)
        );
    }

    #[test]
    fn private_and_loopback_blocked() {
        for s in [
            "10.1.2.3",
            "192.168.4.5",
            "172.20.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "100.100.0.1",
            "::1",
            "fe80::1",
            "fd12:3456::1",
            "ff02::1",
        ] {
            assert!(
                classify(IpAddr::from_str(s).unwrap()).is_some(),
                "{s} should be special-use"
            );
        }
    }

    #[test]
    fn cloudflare_addresses_are_global() {
        for s in ["104.16.0.1", "172.64.1.1", "1.1.1.1", "2606:4700::1111"] {
            assert!(
                is_global_unicast(IpAddr::from_str(s).unwrap()),
                "{s} should be global unicast"
            );
        }
    }

    #[test]
    fn documentation_and_benchmarking_blocked() {
        assert_eq!(
            classify(IpAddr::from_str("192.0.2.1").unwrap()),
            Some(SpecialUse::Documentation)
        );
        assert_eq!(
            classify(IpAddr::from_str("198.19.0.1").unwrap()),
            Some(SpecialUse::Benchmarking)
        );
        assert_eq!(
            classify(IpAddr::from_str("2001:db8::1").unwrap()),
            Some(SpecialUse::Documentation)
        );
    }

    #[test]
    fn ipv4_mapped_v6_is_special() {
        assert!(classify(IpAddr::from_str("::ffff:104.16.0.1").unwrap()).is_some());
    }
}
