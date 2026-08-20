//! Special-use domain names (RFC 6761 and friends).
//!
//! A forwarder that blindly relays every question sends `printer.local`,
//! `1.168.192.in-addr.arpa` and `mybox.home.arpa` to a public resolver. That leaks the
//! shape of the LAN to a third party, wastes an RTT on a guaranteed NXDOMAIN, and — for
//! `localhost` — risks an upstream that answers with something other than the loopback
//! address. The registries below say these names are not part of the public namespace, so
//! this module answers them locally.
//!
//! Deliberate constraints:
//!
//! * Operator configuration wins. `local_answer()` runs **before** this module, so a site
//!   that really does serve `home.arpa` or a private reverse zone from its own
//!   configuration keeps doing so.
//! * Only names with a documented registry entry are matched. There is no heuristic for
//!   "looks internal", because guessing wrong silently breaks a real name.
//! * Matching is on whole labels, never on string suffixes: `notlocal.` does not match
//!   `local.`, and `example.com.` does not match `ample.com.`.
//! * The whole module can be switched off with `server.special_use = "forward"` for
//!   deployments whose upstream is itself the internal resolver.

use hickory_proto::rr::RecordType;

/// What to do with a name that falls inside a special-use registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Not special; carry on with normal resolution.
    Forward,
    /// Answer with the loopback address for A/AAAA, NODATA otherwise (RFC 6761 §6.3).
    Loopback,
    /// Answer NXDOMAIN locally and never query an upstream.
    NxDomain,
    /// Answer with the loop-detection marker address.
    ///
    /// Only for names under [`crate::config::auto::LOOP_MARKER_SUFFIX`]. Answered
    /// *positively*, which is the whole point: `auto` asks the local gateway for one of
    /// these, and only an EgressDNS instance can produce an answer. Getting one back means
    /// the gateway forwards to us, and adopting it as a source would close the loop.
    ///
    /// It has to be positive because the enclosing zone is `.invalid`, which every correct
    /// resolver — including this one — answers with NXDOMAIN. An NXDOMAIN proves nothing;
    /// an address proves the query came home.
    LoopMarker,
}

/// The registry entry a name matched, used for metrics and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    /// RFC 6761 §6.3 — `localhost.`
    Localhost,
    /// RFC 6761 §6.4 — `invalid.`
    Invalid,
    /// RFC 6761 §6.2 — `test.`; recognised but not blocked, see `NXDOMAIN_SUFFIXES`.
    Test,
    /// RFC 6762 §22 — `local.` (multicast DNS)
    MulticastDns,
    /// RFC 8375 — `home.arpa.`
    HomeArpa,
    /// RFC 7686 — `onion.`
    Onion,
    /// RFC 6761 §6.1 — reverse zones for private and link-local address space
    PrivateReverse,
}

impl Registry {
    /// Short stable label for metrics; bounded cardinality by construction.
    pub fn label(self) -> &'static str {
        match self {
            Self::Localhost => "localhost",
            Self::Invalid => "invalid",
            Self::Test => "test",
            Self::MulticastDns => "mdns",
            Self::HomeArpa => "home_arpa",
            Self::Onion => "onion",
            Self::PrivateReverse => "private_reverse",
        }
    }
}

/// Names whose entire subtree is locally answered with NXDOMAIN.
///
/// Every entry is a fully qualified, lower-case, dot-terminated suffix taken from the IANA
/// Special-Use Domain Names registry. `10.in-addr.arpa` covers `10/8`; the 16 entries for
/// `172.16/12` are listed individually because the zone cut is on a label boundary and a
/// range check would also swallow `172.15` and `172.32`.
///
/// `test.` (RFC 6761 §6.2) is deliberately **absent**. That section tells caching servers
/// not to query *authoritative* servers for test names; this daemon is a forwarder and
/// never queries an authoritative server, and `.test` is the TLD the IETF recommends for
/// exactly the local development environments whose resolver is the configured upstream.
/// Answering NXDOMAIN for it would break more setups than it protects. `Registry::Test`
/// still exists so the classification is available to callers that want it.
const NXDOMAIN_SUFFIXES: &[(&str, Registry)] = &[
    ("invalid.", Registry::Invalid),
    ("local.", Registry::MulticastDns),
    ("home.arpa.", Registry::HomeArpa),
    ("onion.", Registry::Onion),
    // IPv4 private space (RFC 1918) and link-local (RFC 3927).
    ("10.in-addr.arpa.", Registry::PrivateReverse),
    ("16.172.in-addr.arpa.", Registry::PrivateReverse),
    ("17.172.in-addr.arpa.", Registry::PrivateReverse),
    ("18.172.in-addr.arpa.", Registry::PrivateReverse),
    ("19.172.in-addr.arpa.", Registry::PrivateReverse),
    ("20.172.in-addr.arpa.", Registry::PrivateReverse),
    ("21.172.in-addr.arpa.", Registry::PrivateReverse),
    ("22.172.in-addr.arpa.", Registry::PrivateReverse),
    ("23.172.in-addr.arpa.", Registry::PrivateReverse),
    ("24.172.in-addr.arpa.", Registry::PrivateReverse),
    ("25.172.in-addr.arpa.", Registry::PrivateReverse),
    ("26.172.in-addr.arpa.", Registry::PrivateReverse),
    ("27.172.in-addr.arpa.", Registry::PrivateReverse),
    ("28.172.in-addr.arpa.", Registry::PrivateReverse),
    ("29.172.in-addr.arpa.", Registry::PrivateReverse),
    ("30.172.in-addr.arpa.", Registry::PrivateReverse),
    ("31.172.in-addr.arpa.", Registry::PrivateReverse),
    ("168.192.in-addr.arpa.", Registry::PrivateReverse),
    ("254.169.in-addr.arpa.", Registry::PrivateReverse),
    // IPv6 link-local `fe80::/10` and unique-local `fc00::/7`.
    ("8.e.f.ip6.arpa.", Registry::PrivateReverse),
    ("9.e.f.ip6.arpa.", Registry::PrivateReverse),
    ("a.e.f.ip6.arpa.", Registry::PrivateReverse),
    ("b.e.f.ip6.arpa.", Registry::PrivateReverse),
    ("c.f.ip6.arpa.", Registry::PrivateReverse),
    ("d.f.ip6.arpa.", Registry::PrivateReverse),
];

/// Classify a query name.
///
/// `qname` must be the presentation form of the question, which Hickory always renders
/// fully qualified with a trailing dot. Comparison is ASCII case-insensitive, matching the
/// DNS rule that labels compare case-insensitively.
pub fn classify(qname: &str) -> Option<(Registry, Disposition)> {
    let lowered = qname.to_ascii_lowercase();
    let name = if lowered.ends_with('.') {
        lowered
    } else {
        format!("{lowered}.")
    };

    if suffix_matches(&name, "localhost.") {
        return Some((Registry::Localhost, Disposition::Loopback));
    }
    // Before the `.invalid` rule below, which would otherwise answer NXDOMAIN and hide
    // the very signal this name exists to produce.
    if crate::config::auto::is_loop_marker(&name) {
        return Some((Registry::Invalid, Disposition::LoopMarker));
    }
    for (suffix, registry) in NXDOMAIN_SUFFIXES {
        if suffix_matches(&name, suffix) {
            return Some((*registry, Disposition::NxDomain));
        }
    }
    None
}

/// True when `name` is `suffix` itself or a descendant of it, respecting label boundaries.
fn suffix_matches(name: &str, suffix: &str) -> bool {
    if name == suffix {
        return true;
    }
    match name.len().checked_sub(suffix.len()) {
        // A descendant must have at least one extra label, so at least two extra bytes
        // (one character plus the separating dot).
        Some(cut) if cut >= 2 => {
            name.ends_with(suffix) && name.as_bytes().get(cut - 1) == Some(&b'.')
        }
        _ => false,
    }
}

/// The address a loop-detection marker answers with.
///
/// TEST-NET-1 (RFC 5737), which is documentation space: it routes nowhere, so an answer
/// that escapes into a cache harms nothing, and it is unmistakable in a packet capture.
pub fn loop_marker_rdata(qtype: RecordType) -> Option<hickory_proto::rr::RData> {
    use hickory_proto::rr::{rdata, RData};
    match qtype {
        RecordType::A => Some(RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 53)))),
        _ => None,
    }
}

/// The loopback address a `localhost` query of this type should receive, if any.
///
/// Returns `None` for every type other than A and AAAA, which means NODATA: `localhost`
/// has no MX, no TXT and no NS, and inventing one would be worse than saying nothing.
pub fn loopback_rdata(qtype: RecordType) -> Option<hickory_proto::rr::RData> {
    use hickory_proto::rr::{rdata, RData};
    match qtype {
        RecordType::A => Some(RData::A(rdata::A(std::net::Ipv4Addr::LOCALHOST))),
        RecordType::AAAA => Some(RData::AAAA(rdata::AAAA(std::net::Ipv6Addr::LOCALHOST))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_and_its_descendants_are_loopback() {
        for name in ["localhost.", "LOCALHOST.", "a.localhost.", "x.y.localhost."] {
            assert_eq!(
                classify(name),
                Some((Registry::Localhost, Disposition::Loopback)),
                "{name}"
            );
        }
        assert!(loopback_rdata(RecordType::A).is_some());
        assert!(loopback_rdata(RecordType::AAAA).is_some());
        assert!(loopback_rdata(RecordType::MX).is_none());
        assert!(loopback_rdata(RecordType::TXT).is_none());
    }

    #[test]
    fn registries_are_answered_locally_with_nxdomain() {
        let cases = [
            ("invalid.", Registry::Invalid),
            ("nothing.invalid.", Registry::Invalid),
            ("printer.local.", Registry::MulticastDns),
            ("home.arpa.", Registry::HomeArpa),
            ("nas.home.arpa.", Registry::HomeArpa),
            ("facebookcorewwwi.onion.", Registry::Onion),
            ("1.0.168.192.in-addr.arpa.", Registry::PrivateReverse),
            ("5.4.3.10.in-addr.arpa.", Registry::PrivateReverse),
            ("7.20.172.in-addr.arpa.", Registry::PrivateReverse),
            ("1.254.169.in-addr.arpa.", Registry::PrivateReverse),
            ("1.0.0.0.8.e.f.ip6.arpa.", Registry::PrivateReverse),
            ("2.0.0.0.d.f.ip6.arpa.", Registry::PrivateReverse),
        ];
        for (name, registry) in cases {
            assert_eq!(
                classify(name),
                Some((registry, Disposition::NxDomain)),
                "{name}"
            );
        }
    }

    #[test]
    fn ordinary_names_are_forwarded() {
        for name in [
            "example.com.",
            "www.example.org.",
            "notlocal.",
            "mylocal.",
            "localhost.example.com.",
            "local.example.com.",
            "onion.example.com.",
            // `.test` is recognised but intentionally forwarded; see NXDOMAIN_SUFFIXES.
            "test.",
            "anything.test.",
            "x.example.test.",
            // 172.15 and 172.32 are public; only 172.16-31 is private.
            "1.2.15.172.in-addr.arpa.",
            "1.2.32.172.in-addr.arpa.",
            // 8.e.f.ip6.arpa is fe80::/10, but e.f.ip6.arpa alone is not reserved.
            "1.f.ip6.arpa.",
            "9.9.9.9.in-addr.arpa.",
            "168.192.in-addr.arpa.example.com.",
        ] {
            assert_eq!(
                classify(name),
                None,
                "{name} must not be treated as special"
            );
        }
    }

    #[test]
    fn matching_respects_label_boundaries() {
        assert!(suffix_matches("a.local.", "local."));
        assert!(suffix_matches("local.", "local."));
        assert!(!suffix_matches("notlocal.", "local."));
        assert!(!suffix_matches("xlocal.", "local."));
        // A bare extra dot is not a label.
        assert!(!suffix_matches(".local.", "local."));
    }

    #[test]
    fn every_registry_label_is_unique_and_short() {
        let mut seen = std::collections::BTreeSet::new();
        for r in [
            Registry::Localhost,
            Registry::Invalid,
            Registry::Test,
            Registry::MulticastDns,
            Registry::HomeArpa,
            Registry::Onion,
            Registry::PrivateReverse,
        ] {
            assert!(seen.insert(r.label()), "duplicate label {}", r.label());
            assert!(r.label().len() <= 16);
        }
    }
}

#[cfg(test)]
mod loop_marker_tests {
    use super::*;

    /// The gateway loop probe must be answered *positively*, or the signal it exists to
    /// produce is indistinguishable from the `.invalid` NXDOMAIN every resolver gives.
    #[test]
    fn a_loop_marker_is_answered_positively_despite_being_under_invalid() {
        let name = "deadbeefdeadbeef.loop-probe.egressdns.invalid.";
        assert_eq!(
            classify(name),
            Some((Registry::Invalid, Disposition::LoopMarker)),
            "the marker must outrank the .invalid NXDOMAIN rule"
        );
        assert!(loop_marker_rdata(RecordType::A).is_some());
    }

    /// Any other name under `.invalid` is still NXDOMAIN.
    #[test]
    fn an_ordinary_invalid_name_is_still_nxdomain() {
        assert_eq!(
            classify("something.invalid."),
            Some((Registry::Invalid, Disposition::NxDomain))
        );
    }
}
