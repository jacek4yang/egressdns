//! Host network-state detection.
//!
//! Two sources are combined:
//!
//! * The kernel routing tables exposed through `/proc/net/route` and
//!   `/proc/net/ipv6_route`, which give the default route and its interface.
//! * A `connect(2)` on an unconnected UDP socket towards a reference destination, which
//!   performs a route lookup and reveals the source address the kernel would choose. No
//!   packet is transmitted.
//!
//! Interface addresses come from `getifaddrs(3)` via the `nix` crate, which uses netlink
//! on Linux. All of this is blocking work and therefore runs on a blocking thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;

use super::RawNetworkState;

/// Something that can observe the host's network state.
pub trait NetworkProbe: Send + Sync + 'static {
    /// Take one observation.
    fn sample(&self, reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState;
}

/// The production probe.
#[derive(Debug, Clone, Default)]
pub struct HostProbe {
    /// Override for the IPv4 route table path, used by tests.
    pub route_v4_path: Option<String>,
    /// Override for the IPv6 route table path, used by tests.
    pub route_v6_path: Option<String>,
}

impl NetworkProbe for HostProbe {
    fn sample(&self, reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState {
        let v4_path = self
            .route_v4_path
            .clone()
            .unwrap_or_else(|| "/proc/net/route".to_string());
        let v6_path = self
            .route_v6_path
            .clone()
            .unwrap_or_else(|| "/proc/net/ipv6_route".to_string());

        let (default_iface_v4, gateway_v4) = parse_route_v4(&read_file(&v4_path));
        let (default_iface_v6, gateway_v6) = parse_route_v6(&read_file(&v6_path));

        RawNetworkState {
            default_iface_v4,
            gateway_v4,
            default_iface_v6,
            gateway_v6,
            source_v4: match select_source(reference_v4) {
                Some(IpAddr::V4(a)) => Some(a),
                _ => None,
            },
            source_v6: match select_source(reference_v6) {
                Some(IpAddr::V6(a)) => Some(a),
                _ => None,
            },
            global_addresses: global_interface_addresses(),
        }
    }
}

fn read_file(path: &str) -> String {
    if !Path::new(path).exists() {
        return String::new();
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Parse `/proc/net/route`, returning the interface and gateway of the default route.
///
/// Columns are `Iface Destination Gateway Flags RefCnt Use Metric Mask ...`, with the
/// addresses in little-endian hexadecimal.
pub fn parse_route_v4(text: &str) -> (Option<String>, Option<Ipv4Addr>) {
    let mut best: Option<(u32, String, Option<Ipv4Addr>)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let dest = u32::from_str_radix(cols[1], 16).unwrap_or(u32::MAX);
        let mask = u32::from_str_radix(cols[7], 16).unwrap_or(u32::MAX);
        if dest != 0 || mask != 0 {
            continue;
        }
        let metric: u32 = cols[6].parse().unwrap_or(u32::MAX);
        let gw = u32::from_str_radix(cols[2], 16)
            .ok()
            .filter(|g| *g != 0)
            .map(|g| Ipv4Addr::from(g.to_be()));
        let replace = match &best {
            None => true,
            Some((m, _, _)) => metric < *m,
        };
        if replace {
            best = Some((metric, cols[0].to_string(), gw));
        }
    }
    match best {
        Some((_, iface, gw)) => (Some(iface), gw),
        None => (None, None),
    }
}

/// Parse `/proc/net/ipv6_route`, returning the interface and gateway of the default route.
///
/// Columns are `dest_prefix prefix_len src_prefix src_prefix_len next_hop metric refcnt
/// use flags iface`.
pub fn parse_route_v6(text: &str) -> (Option<String>, Option<Ipv6Addr>) {
    let mut best: Option<(u32, String, Option<Ipv6Addr>)> = None;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if cols[0] != "00000000000000000000000000000000" || cols[1] != "00" {
            continue;
        }
        let iface = cols[9].to_string();
        if iface == "lo" {
            continue;
        }
        let metric = u32::from_str_radix(cols[5], 16).unwrap_or(u32::MAX);
        let gw = parse_hex_v6(cols[4]).filter(|a| !a.is_unspecified());
        let replace = match &best {
            None => true,
            Some((m, _, _)) => metric < *m,
        };
        if replace {
            best = Some((metric, iface, gw));
        }
    }
    match best {
        Some((_, iface, gw)) => (Some(iface), gw),
        None => (None, None),
    }
}

fn parse_hex_v6(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

/// Ask the kernel which source address it would use to reach `dest`.
///
/// `connect(2)` on a UDP socket only performs a route lookup; nothing is transmitted.
pub fn select_source(dest: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match dest {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(SocketAddr::new(dest, 53)).ok()?;
    let local = socket.local_addr().ok()?;
    Some(local.ip())
}

/// Sorted list of global-scope interface addresses.
pub fn global_interface_addresses() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return out;
    };
    for ifaddr in addrs {
        let Some(storage) = ifaddr.address else {
            continue;
        };
        let ip = if let Some(sin) = storage.as_sockaddr_in() {
            IpAddr::V4(sin.ip())
        } else if let Some(sin6) = storage.as_sockaddr_in6() {
            IpAddr::V6(sin6.ip())
        } else {
            continue;
        };
        if crate::util::ipclass::is_global_unicast(ip)
            || matches!(
                crate::util::ipclass::classify(ip),
                Some(crate::util::ipclass::SpecialUse::Private)
                    | Some(crate::util::ipclass::SpecialUse::SharedAddressSpace)
            )
        {
            out.push(format!("{}%{}", ip, ifaddr.interface_name));
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const ROUTE_V4: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    const ROUTE_V6: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000001 00000001     eth0\n";

    #[test]
    fn parses_ipv4_default_route() {
        let (iface, gw) = parse_route_v4(ROUTE_V4);
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert_eq!(gw, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn parses_ipv6_default_route() {
        let (iface, gw) = parse_route_v6(ROUTE_V6);
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert_eq!(gw, Some(Ipv6Addr::from_str("fe80::1").expect("v6")));
    }

    #[test]
    fn missing_default_route_is_reported() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert_eq!(parse_route_v4(text), (None, None));
        assert_eq!(parse_route_v6(""), (None, None));
    }

    #[test]
    fn garbage_route_tables_do_not_panic() {
        for text in ["", "\n\n", "not a route table", "a b c", "\u{0}\u{1}"] {
            let _ = parse_route_v4(text);
            let _ = parse_route_v6(text);
        }
    }

    #[test]
    fn source_selection_for_loopback_works() {
        // Loopback is always routable, so this asserts the mechanism rather than the
        // host's Internet connectivity.
        let src = select_source(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(matches!(src, Some(IpAddr::V4(_))));
    }

    #[test]
    fn interface_enumeration_is_bounded_and_sorted() {
        let addrs = global_interface_addresses();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted);
    }
}
