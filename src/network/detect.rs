//! Host network-state detection.
//!
//! Two kinds of observation are combined, per platform:
//!
//! * The default routes: the interface and gateway the kernel would use. On Linux these
//!   are read from `/proc/net/route` and `/proc/net/ipv6_route`; on Windows from the
//!   IP helper API via the `netdev` crate.
//! * A `connect(2)` on an unconnected UDP socket towards a reference destination, which
//!   performs a route lookup and reveals the source address the kernel would choose. No
//!   packet is transmitted. This works identically on every platform.
//!
//! All of this is blocking work and therefore runs on a blocking thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

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

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    use super::RawNetworkState;

    /// Linux observation: parse `/proc`, then ask the kernel for the source addresses.
    pub(super) fn sample(
        reference_v4: IpAddr,
        reference_v6: IpAddr,
        route_v4_path: Option<&str>,
        route_v6_path: Option<&str>,
    ) -> RawNetworkState {
        let v4_path = route_v4_path.unwrap_or("/proc/net/route").to_string();
        let v6_path = route_v6_path.unwrap_or("/proc/net/ipv6_route").to_string();

        let (default_iface_v4, gateway_v4) = parse_route_v4(&read_file(&v4_path));
        let (default_iface_v6, gateway_v6) = parse_route_v6(&read_file(&v6_path));

        RawNetworkState {
            default_iface_v4,
            gateway_v4,
            default_iface_v6,
            gateway_v6,
            source_v4: match super::select_source(reference_v4) {
                Some(IpAddr::V4(a)) => Some(a),
                _ => None,
            },
            source_v6: match super::select_source(reference_v6) {
                Some(IpAddr::V6(a)) => Some(a),
                _ => None,
            },
            global_addresses: super::global_interface_addresses(),
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
}

#[cfg(windows)]
mod windows {
    use std::net::IpAddr;

    use super::RawNetworkState;

    /// Windows observation: the default route and gateways come from the system adapter
    /// tables (via `netdev`), the source addresses from the portable UDP `connect` trick.
    pub(super) fn sample(reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState {
        let interfaces = netdev::get_interfaces();

        // The adapter carrying a default gateway for the family, preferring the one that
        // holds the default source address. `netdev` exposes the gateway as the device
        // address the adapter routes to.
        let local_v4 = match super::select_source(reference_v4) {
            Some(IpAddr::V4(a)) => Some(a),
            _ => None,
        };
        let local_v6 = match super::select_source(reference_v6) {
            Some(IpAddr::V6(a)) => Some(a),
            _ => None,
        };

        let mut default_iface_v4 = None;
        let mut gateway_v4 = None;
        let mut default_iface_v6 = None;
        let mut gateway_v6 = None;
        for iface in &interfaces {
            let name = iface
                .friendly_name
                .clone()
                .unwrap_or_else(|| iface.name.clone());
            let Some(device) = iface.gateway.as_ref() else {
                continue;
            };
            if gateway_v4.is_none() {
                if let Some(&gw) = device.ipv4.first() {
                    gateway_v4 = Some(gw);
                    default_iface_v4 = Some(name.clone());
                }
            }
            if gateway_v6.is_none() {
                if let Some(&gw) = device.ipv6.first() {
                    gateway_v6 = Some(gw);
                    default_iface_v6 = Some(name);
                }
            }
        }

        RawNetworkState {
            default_iface_v4,
            gateway_v4,
            default_iface_v6,
            gateway_v6,
            source_v4: local_v4,
            source_v6: local_v6,
            global_addresses: super::global_interface_addresses(),
        }
    }
}

impl NetworkProbe for HostProbe {
    #[cfg(target_os = "linux")]
    fn sample(&self, reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState {
        linux::sample(
            reference_v4,
            reference_v6,
            self.route_v4_path.as_deref(),
            self.route_v6_path.as_deref(),
        )
    }

    #[cfg(windows)]
    fn sample(&self, reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState {
        // The route-path overrides are a Linux test seam; the Windows probe always reads
        // the live route tables.
        let _ = (&self.route_v4_path, &self.route_v6_path);
        windows::sample(reference_v4, reference_v6)
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn sample(&self, reference_v4: IpAddr, reference_v6: IpAddr) -> RawNetworkState {
        // No route-table reader on this platform: still report the source addresses the
        // kernel would choose, which is the observation the egress fingerprint relies on
        // most. Gateways and interface names stay unknown rather than guessed.
        RawNetworkState {
            default_iface_v4: None,
            gateway_v4: None,
            default_iface_v6: None,
            gateway_v6: None,
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
#[cfg(unix)]
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

/// Sorted list of global-scope interface addresses, Windows form `ip%adapter`.
#[cfg(windows)]
pub fn global_interface_addresses() -> Vec<String> {
    let mut out = Vec::new();
    for iface in netdev::get_interfaces() {
        let name = iface
            .friendly_name
            .clone()
            .unwrap_or_else(|| iface.name.clone());
        for net in iface.ipv4.iter() {
            let ip = IpAddr::V4(net.addr());
            if address_is_reportable(ip) {
                out.push(format!("{ip}%{name}"));
            }
        }
        for net in iface.ipv6.iter() {
            let ip = IpAddr::V6(net.addr());
            if address_is_reportable(ip) {
                out.push(format!("{ip}%{name}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether an interface address belongs in the reported address list: global unicast, or
/// private/shared space that a LAN deployment legitimately uses.
#[cfg(windows)]
fn address_is_reportable(ip: IpAddr) -> bool {
    crate::util::ipclass::is_global_unicast(ip)
        || matches!(
            crate::util::ipclass::classify(ip),
            Some(crate::util::ipclass::SpecialUse::Private)
                | Some(crate::util::ipclass::SpecialUse::SharedAddressSpace)
        )
}

/// Every address on a local interface, as `(interface, address)`, loopback included.
///
/// Used by `doctor`; on Windows the same observation comes from the IP helper API via
/// `netdev`.
pub fn interface_addresses() -> Vec<(String, IpAddr)> {
    #[cfg(unix)]
    {
        let mut out = Vec::new();
        if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
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
                out.push((ifaddr.interface_name.clone(), ip));
            }
        }
        out
    }
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        for iface in netdev::get_interfaces() {
            let name = iface
                .friendly_name
                .clone()
                .unwrap_or_else(|| iface.name.clone());
            for net in iface.ipv4.iter() {
                out.push((name.clone(), IpAddr::V4(net.addr())));
            }
            for net in iface.ipv6.iter() {
                out.push((name.clone(), IpAddr::V6(net.addr())));
            }
        }
        out
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::str::FromStr;

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        const ROUTE_V4: &str =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

        const ROUTE_V6: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000001 00000001     eth0\n";

        #[test]
        fn parses_ipv4_default_route() {
            let (iface, gw) = linux::parse_route_v4(ROUTE_V4);
            assert_eq!(iface.as_deref(), Some("eth0"));
            assert_eq!(gw, Some(Ipv4Addr::new(10, 0, 0, 1)));
        }

        #[test]
        fn parses_ipv6_default_route() {
            let (iface, gw) = linux::parse_route_v6(ROUTE_V6);
            assert_eq!(iface.as_deref(), Some("eth0"));
            assert_eq!(gw, Some(Ipv6Addr::from_str("fe80::1").expect("v6")));
        }

        #[test]
        fn missing_default_route_is_reported() {
            let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
            assert_eq!(linux::parse_route_v4(text), (None, None));
            assert_eq!(linux::parse_route_v6(""), (None, None));
        }

        #[test]
        fn garbage_route_tables_do_not_panic() {
            for text in ["", "\n\n", "not a route table", "a b c", "\u{0}\u{1}"] {
                let _ = linux::parse_route_v4(text);
                let _ = linux::parse_route_v6(text);
            }
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
