//! `upstreams = ["auto"]`: working out where to ask, at startup.
//!
//! The default configuration names no resolvers at all. It cannot sensibly name any: the
//! best source for a household behind a consumer router is that router, the best source in
//! mainland China is not the best source in Frankfurt, and an operator who has to know
//! which is which before the resolver works is being asked to do the resolver's job.
//!
//! So `auto` is resolved on the host, at startup, from what is actually there:
//!
//! * the **default gateway**, when it answers DNS and does not point back at us. It is
//!   usually the lowest-latency source on the network and the only one that knows about
//!   local names, and it is the one no static list can contain.
//! * **regional public resolvers**, chosen by which region the host appears to be in.
//! * **independent encrypted resolvers**, for a source whose answers an on-path observer
//!   can neither read nor forge.
//! * **literal addresses throughout**, so that nothing here needs DNS to bootstrap DNS.
//!
//! The gateway is the part that needs care, and [`GatewayProbe`] is where that care lives:
//! a forwarder that points back at this resolver would otherwise turn one query into a
//! loop between two processes that each believe the other is authoritative.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// What a resolver is to us, which is not the same as how we reach it.
///
/// The distinction exists because "fastest source" and "independent authority" are
/// different jobs, and a home gateway is emphatically the first without being the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverRole {
    /// A full resolver we treat as an independent opinion.
    Authority,
    /// The local network's forwarder — typically the default gateway.
    ///
    /// May be the fastest source, and is usually the only one that answers for local
    /// names and returns regionally sensible GeoDNS results. It is *not* an independent
    /// authority: it forwards to somebody else, so agreeing with it proves only that we
    /// and it asked the same upstream. It therefore cannot corroborate an NXDOMAIN and
    /// cannot serve as a DNSSEC oracle.
    LocalForwarder,
}

impl ResolverRole {
    /// Whether an answer from this role counts as an independent second opinion.
    pub fn is_independent(self) -> bool {
        matches!(self, Self::Authority)
    }

    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::LocalForwarder => "local_forwarder",
        }
    }
}

/// Why a detected gateway was not adopted as a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayRejection {
    /// No default route, so there is no gateway to ask.
    NoGateway,
    /// The gateway did not answer DNS on UDP or TCP.
    NotAResolver,
    /// The gateway address is one of our own listeners.
    IsOurself,
    /// The gateway forwards back to an EgressDNS listener.
    ForwardsToUs,
}

impl GatewayRejection {
    /// A sentence an operator can act on.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoGateway => "no default route was detected",
            Self::NotAResolver => "the gateway did not answer DNS over UDP or TCP",
            Self::IsOurself => "the gateway address is one of this resolver's own listeners",
            Self::ForwardsToUs => {
                "the gateway forwards DNS back to this resolver, which would loop"
            }
        }
    }
}

/// The result of examining the local gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayProbe {
    /// Usable as a `LocalForwarder` source.
    Usable {
        /// The gateway address.
        addr: IpAddr,
        /// Whether it answered over UDP.
        udp: bool,
        /// Whether it answered over TCP.
        tcp: bool,
    },
    /// Not usable, with the reason.
    Rejected(GatewayRejection),
}

impl GatewayProbe {
    /// The address, when the gateway is usable.
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Self::Usable { addr, .. } => Some(*addr),
            Self::Rejected(_) => None,
        }
    }
}

/// Decide whether a gateway may be used, given what was observed about it.
///
/// Split out from the I/O so the rules are testable without a network. Every rejection
/// here is a loop that would otherwise be discovered in production, by a router and a
/// resolver forwarding one query to each other until something gives up.
pub fn judge_gateway(
    gateway: Option<IpAddr>,
    listeners: &[SocketAddr],
    udp_answered: bool,
    tcp_answered: bool,
    loop_detected: bool,
) -> GatewayProbe {
    let Some(addr) = gateway else {
        return GatewayProbe::Rejected(GatewayRejection::NoGateway);
    };

    // A wildcard listener owns every address on the host, so a gateway that happens to be
    // a local address is us. This is the configuration where a bridge or container host
    // is its own gateway, and it loops immediately.
    let ours = listeners
        .iter()
        .any(|l| l.ip() == addr || (l.ip().is_unspecified() && is_local_address(addr)));
    if ours {
        return GatewayProbe::Rejected(GatewayRejection::IsOurself);
    }

    if loop_detected {
        return GatewayProbe::Rejected(GatewayRejection::ForwardsToUs);
    }

    if !udp_answered && !tcp_answered {
        return GatewayProbe::Rejected(GatewayRejection::NotAResolver);
    }

    GatewayProbe::Usable {
        addr,
        udp: udp_answered,
        tcp: tcp_answered,
    }
}

/// Whether an address belongs to this host.
///
/// Deliberately conservative: loopback is always ours, and anything else is only ours if
/// an interface actually carries it. Guessing wrong in the permissive direction means
/// refusing a working gateway; guessing wrong the other way means a forwarding loop.
fn is_local_address(addr: IpAddr) -> bool {
    if addr.is_loopback() {
        return true;
    }
    crate::network::local_addresses().contains(&addr)
}

/// How long a gateway probe may take.
///
/// Short: this runs at startup, before the resolver serves anything, and a gateway that
/// needs longer than this to answer is not the fast local source `auto` is looking for.
pub const GATEWAY_PROBE_TIMEOUT: Duration = Duration::from_millis(700);

/// The marker that makes a forwarding loop visible.
///
/// A query for this name is answered from local data by every EgressDNS instance and by
/// nothing else. If the gateway returns our answer for it, the gateway is forwarding to us
/// — directly, or around a chain of hops that ends here — and adopting it as a source
/// would close the loop.
///
/// Under `.invalid`, which RFC 6761 guarantees can never be delegated, so a public
/// resolver has no way to answer it except by NXDOMAIN.
pub const LOOP_MARKER_SUFFIX: &str = "loop-probe.egressdns.invalid";

/// The per-instance loop marker, distinct for every process.
///
/// Per-instance rather than fixed so that two EgressDNS resolvers pointed at each other
/// each detect the *other*, rather than both matching a shared constant and each
/// concluding it found itself.
pub fn loop_marker(instance: u64) -> String {
    format!("{instance:016x}.{LOOP_MARKER_SUFFIX}")
}

/// Whether a name is a loop marker, and so must be answered locally.
pub fn is_loop_marker(name: &str) -> bool {
    name.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(LOOP_MARKER_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn gw(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("address"))
    }

    fn listener(s: &str) -> SocketAddr {
        s.parse().expect("socket address")
    }

    #[test]
    fn a_gateway_that_answers_dns_is_usable() {
        let probe = judge_gateway(
            gw("192.168.31.1"),
            &[listener("127.0.0.1:53")],
            true,
            true,
            false,
        );
        assert_eq!(
            probe,
            GatewayProbe::Usable {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1)),
                udp: true,
                tcp: true,
            }
        );
    }

    /// UDP alone is enough to be useful; the TCP result is recorded, not required.
    #[test]
    fn udp_alone_is_enough() {
        let probe = judge_gateway(
            gw("192.168.31.1"),
            &[listener("127.0.0.1:53")],
            true,
            false,
            false,
        );
        assert!(matches!(
            probe,
            GatewayProbe::Usable {
                udp: true,
                tcp: false,
                ..
            }
        ));
    }

    #[test]
    fn a_gateway_that_does_not_answer_dns_is_not_a_resolver() {
        let probe = judge_gateway(
            gw("192.168.31.1"),
            &[listener("127.0.0.1:53")],
            false,
            false,
            false,
        );
        assert_eq!(
            probe,
            GatewayProbe::Rejected(GatewayRejection::NotAResolver)
        );
    }

    /// The loop that costs an afternoon to diagnose: the router forwards to us and we
    /// forward to the router.
    #[test]
    fn a_gateway_that_forwards_back_to_us_is_refused() {
        let probe = judge_gateway(
            gw("192.168.31.1"),
            &[listener("0.0.0.0:53")],
            true,
            true,
            true,
        );
        assert_eq!(
            probe,
            GatewayProbe::Rejected(GatewayRejection::ForwardsToUs)
        );
    }

    /// A loop is refused even when the gateway answers perfectly well, because answering
    /// is exactly what it does when it is asking us.
    #[test]
    fn answering_does_not_excuse_a_loop() {
        let looping = judge_gateway(
            gw("10.0.0.1"),
            &[listener("127.0.0.1:53")],
            true,
            true,
            true,
        );
        assert!(matches!(
            looping,
            GatewayProbe::Rejected(GatewayRejection::ForwardsToUs)
        ));
    }

    #[test]
    fn a_gateway_that_is_one_of_our_listeners_is_refused() {
        let probe = judge_gateway(
            gw("192.168.31.204"),
            &[listener("192.168.31.204:53")],
            true,
            true,
            false,
        );
        assert_eq!(probe, GatewayProbe::Rejected(GatewayRejection::IsOurself));
    }

    #[test]
    fn no_default_route_means_no_gateway_source() {
        let probe = judge_gateway(None, &[listener("127.0.0.1:53")], true, true, false);
        assert_eq!(probe, GatewayProbe::Rejected(GatewayRejection::NoGateway));
    }

    /// A forwarder is a source, never a second opinion.
    #[test]
    fn a_local_forwarder_is_not_an_independent_authority() {
        assert!(!ResolverRole::LocalForwarder.is_independent());
        assert!(ResolverRole::Authority.is_independent());
    }

    /// Two EgressDNS instances pointed at each other must each detect the other rather
    /// than both matching one shared constant.
    #[test]
    fn loop_markers_are_per_instance() {
        let a = loop_marker(1);
        let b = loop_marker(2);
        assert_ne!(a, b);
        assert!(is_loop_marker(&a));
        assert!(is_loop_marker(&b));
        assert!(is_loop_marker("DEAD.LOOP-PROBE.EGRESSDNS.INVALID."));
        assert!(!is_loop_marker("example.com"));
    }

    /// The marker lives under `.invalid`, which RFC 6761 says can never be delegated, so
    /// no public resolver can answer it except by saying it does not exist.
    #[test]
    fn the_loop_marker_cannot_be_delegated() {
        assert!(LOOP_MARKER_SUFFIX.ends_with(".invalid"));
    }
}

/// Which part of the world this host appears to be in.
///
/// Inferred, never configured. A resolver that needs to be told its own region before it
/// works usefully is one more thing an operator has to know, and the answer is observable:
/// the regionally fast resolvers are the ones that answer fastest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Networks where the global providers are impaired and the regional ones are not.
    China,
    /// Everywhere else.
    Global,
}

/// The endpoints `auto` expands to, given what was found on the host.
///
/// Ordered by what each contributes rather than by preference — the scheduler decides
/// preference from measurement, and every one of these is a literal address or a name with
/// pinned bootstrap addresses so that nothing here needs DNS to reach DNS.
pub fn expand(gateway: &GatewayProbe, region: Region) -> Vec<String> {
    let mut out = Vec::new();

    // The gateway first, when it is usable. It is normally the lowest-latency source on
    // the network, the only one that answers for local names, and the only one no static
    // list could have contained.
    if let Some(addr) = gateway.address() {
        out.push(addr.to_string());
    }

    match region {
        Region::China => {
            // Regional plaintext, for latency, plus the same operators' encrypted
            // endpoints with their addresses pinned.
            out.extend(
                [
                    "223.5.5.5",
                    "223.6.6.6",
                    "119.29.29.29",
                    "https://dns.alidns.com/dns-query?addr=223.5.5.5&addr=223.6.6.6",
                    "https://doh.pub/dns-query?addr=1.12.12.21&addr=120.53.53.53",
                    // One independent global authority, so that every source is not the
                    // same jurisdiction.
                    "https://cloudflare-dns.com/dns-query?addr=1.1.1.1&addr=1.0.0.1",
                ]
                .map(String::from),
            );
        }
        Region::Global => {
            out.extend(
                [
                    "1.1.1.1",
                    "8.8.8.8",
                    "9.9.9.10",
                    "https://cloudflare-dns.com/dns-query?addr=1.1.1.1&addr=1.0.0.1",
                    "https://dns.google/dns-query?addr=8.8.8.8&addr=8.8.4.4",
                    "https://dns10.quad9.net/dns-query?addr=9.9.9.10&addr=149.112.112.10",
                ]
                .map(String::from),
            );
        }
    }

    out
}

/// Which role an expanded `auto` entry plays.
///
/// The gateway is the first entry when present, and is the only `LocalForwarder`.
pub fn role_of(entry: &str, gateway: &GatewayProbe) -> ResolverRole {
    match gateway.address() {
        Some(addr) if entry == addr.to_string() => ResolverRole::LocalForwarder,
        _ => ResolverRole::Authority,
    }
}

#[cfg(test)]
mod expand_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn usable(addr: &str) -> GatewayProbe {
        GatewayProbe::Usable {
            addr: addr.parse().expect("address"),
            udp: true,
            tcp: true,
        }
    }

    /// The host this was built for: `auto` must put the router first.
    #[test]
    fn a_usable_gateway_leads_the_expansion() {
        let out = expand(&usable("192.168.31.1"), Region::China);
        assert_eq!(out.first().map(String::as_str), Some("192.168.31.1"));
        assert_eq!(
            role_of("192.168.31.1", &usable("192.168.31.1")),
            ResolverRole::LocalForwarder
        );
        assert_eq!(
            role_of("223.5.5.5", &usable("192.168.31.1")),
            ResolverRole::Authority
        );
    }

    /// Without a gateway there is still a working resolver.
    #[test]
    fn expansion_without_a_gateway_still_works() {
        let rejected = GatewayProbe::Rejected(GatewayRejection::NoGateway);
        let out = expand(&rejected, Region::Global);
        assert!(!out.is_empty());
        assert!(
            !out.iter().any(|e| e.starts_with("192.168.")),
            "a rejected gateway must not appear: {out:?}"
        );
    }

    /// Every entry must be reachable without first resolving a name, or the resolver
    /// cannot start on a host whose only resolver is itself.
    #[test]
    fn nothing_in_the_expansion_needs_dns_to_bootstrap() {
        for region in [Region::China, Region::Global] {
            for entry in expand(&usable("192.168.31.1"), region) {
                if entry.contains("://") {
                    assert!(
                        entry.contains("addr="),
                        "{entry} is a name with no pinned address, so it needs DNS to \
                         reach DNS"
                    );
                } else {
                    assert!(
                        entry.parse::<IpAddr>().is_ok(),
                        "{entry} is neither a literal address nor a pinned URI"
                    );
                }
            }
        }
    }

    /// Every expansion must parse into real routes, and reach more than one operator.
    #[test]
    fn every_expansion_parses_and_is_diverse() {
        for region in [Region::China, Region::Global] {
            let entries = expand(&usable("192.168.31.1"), region);
            let servers = crate::config::endpoint::desugar(&entries)
                .unwrap_or_else(|e| panic!("{region:?} expansion must parse: {e}"));
            assert!(
                servers.len() >= 6,
                "{region:?} produced too few routes: {}",
                servers.len()
            );
            let encrypted = servers.iter().filter(|s| s.server_name.is_some()).count();
            assert!(
                encrypted >= 3,
                "{region:?} needs encrypted routes, saw {encrypted}"
            );
        }
    }

    /// A region choice must not collapse to one jurisdiction.
    #[test]
    fn the_china_profile_still_includes_an_independent_global_authority() {
        let out = expand(&usable("192.168.31.1"), Region::China);
        assert!(
            out.iter().any(|e| e.contains("cloudflare")),
            "every source in one jurisdiction is not diversity: {out:?}"
        );
    }

    #[test]
    fn a_rejected_gateway_is_never_a_forwarder() {
        let rejected = GatewayProbe::Rejected(GatewayRejection::ForwardsToUs);
        assert_eq!(role_of("192.168.31.1", &rejected), ResolverRole::Authority);
        assert!(rejected.address().is_none());
    }

    #[test]
    fn ipv6_gateways_expand_too() {
        let gw = GatewayProbe::Usable {
            addr: IpAddr::V6("fe80::1".parse::<std::net::Ipv6Addr>().expect("v6")),
            udp: true,
            tcp: false,
        };
        let out = expand(&gw, Region::Global);
        assert_eq!(out.first().map(String::as_str), Some("fe80::1"));
    }

    #[test]
    fn ipv4_gateway_addresses_round_trip() {
        let gw = usable("10.0.0.1");
        assert_eq!(gw.address(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }
}
