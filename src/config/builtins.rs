//! The built-in resolver catalog.
//!
//! `upstreams = ["builtin:recommended"]` has to produce a resolver that works on a
//! stranger's network without them knowing anything about DNS. That means the catalog is
//! a curated list of independently operated public resolvers, with the endpoints taken
//! from each operator's own documentation rather than from an aggregator.
//!
//! Two properties matter more than breadth:
//!
//! * **Independence.** A provider's Do53 addresses and its DoH hostname are the *same*
//!   authority. Corroboration counts authorities, so a catalog that let one operator
//!   appear several times would let one operator's answer look like a consensus.
//! * **Separation of policy.** A filtering, family-safe or ad-blocking resolver returns
//!   deliberately different answers from an unfiltered one. Mixing them into one pool
//!   would make ordinary GeoDNS variation indistinguishable from a block, so the profiles
//!   keep them apart and `recommended` contains none of them.
//!
//! The catalog is metadata, not code: adding a provider is a table entry, and the tests
//! check every entry for the properties above.

/// What a resolver does to answers it does not like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteringPolicy {
    /// Answers are returned as the authority gave them.
    Unfiltered,
    /// Known-malicious names are withheld.
    SecurityFiltered,
    /// Advertising and tracking names are withheld.
    AdBlocking,
}

/// One public resolver operator.
///
/// Every endpoint here is from the operator's own documentation. `verified` records when
/// that was last checked, so a stale entry is visible rather than merely old.
#[derive(Debug, Clone, Copy)]
pub struct Provider {
    /// Stable authority identifier. Never changes once published, because persisted
    /// route quality is keyed on it.
    pub id: &'static str,
    /// Operator, for diagnostics.
    pub operator: &'static str,
    /// Short names an operator may write in `upstreams`.
    pub aliases: &'static [&'static str],
    /// Published Do53 addresses, IPv4 and IPv6. Also the bootstrap addresses for this
    /// provider's encrypted endpoints, which is why one list serves both.
    pub addresses: &'static [&'static str],
    /// DoH endpoint, if the operator publishes one.
    pub doh: Option<&'static str>,
    /// DoT authentication name, if the operator publishes one.
    pub dot: Option<&'static str>,
    /// DoQ authentication name, if the operator publishes one.
    pub doq: Option<&'static str>,
    /// What this endpoint does to answers.
    pub filtering: FilteringPolicy,
    /// Anything an operator should know before choosing it.
    pub notes: &'static str,
    /// Operator documentation the entry was taken from.
    pub source: &'static str,
    /// When the endpoints above were last checked against `source`.
    pub verified: &'static str,
}

/// The catalog.
///
/// Ordered by how generally useful the provider is, because `recommended` takes from the
/// front and ties in ranking break on configuration order.
pub const CATALOG: &[Provider] = &[
    Provider {
        id: "cloudflare",
        operator: "Cloudflare",
        aliases: &["cloudflare", "cloudflare-dns.com", "one.one.one.one"],
        addresses: &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ],
        doh: Some("https://cloudflare-dns.com/dns-query"),
        dot: Some("cloudflare-dns.com"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Global anycast. The 1.1.1.2 and 1.1.1.3 variants filter and are separate \
                entries.",
        source: "https://developers.cloudflare.com/1.1.1.1/setup/",
        verified: "2026-08-20",
    },
    Provider {
        id: "google",
        operator: "Google",
        aliases: &["google", "dns.google"],
        addresses: &[
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
        ],
        doh: Some("https://dns.google/dns-query"),
        dot: Some("dns.google"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Global anycast, very widely reachable.",
        source: "https://developers.google.com/speed/public-dns/docs/using",
        verified: "2026-08-20",
    },
    Provider {
        id: "quad9",
        operator: "Quad9 Foundation",
        aliases: &["quad9", "dns.quad9.net"],
        addresses: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        doh: Some("https://dns.quad9.net/dns-query"),
        dot: Some("dns.quad9.net"),
        doq: None,
        filtering: FilteringPolicy::SecurityFiltered,
        notes: "Withholds known-malicious names. Swiss non-profit. The unfiltered variant \
                is a separate entry.",
        source: "https://www.quad9.net/service/service-addresses-and-features/",
        verified: "2026-08-20",
    },
    Provider {
        id: "quad9-unfiltered",
        operator: "Quad9 Foundation",
        aliases: &["quad9-unfiltered", "dns10.quad9.net"],
        addresses: &[
            "9.9.9.10",
            "149.112.112.10",
            "2620:fe::10",
            "2620:fe::fe:10",
        ],
        doh: Some("https://dns10.quad9.net/dns-query"),
        dot: Some("dns10.quad9.net"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Quad9 without the malware blocklist and without DNSSEC validation on the \
                resolver side.",
        source: "https://www.quad9.net/service/service-addresses-and-features/",
        verified: "2026-08-20",
    },
    Provider {
        id: "dnssb",
        operator: "DNS.SB",
        aliases: &["dnssb", "dns.sb", "doh.dns.sb"],
        addresses: &["185.222.222.222", "45.11.45.11", "2a09::", "2a11::"],
        doh: Some("https://doh.dns.sb/dns-query"),
        dot: Some("dot.sb"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "No-logging unfiltered resolver, anycast.",
        source: "https://dns.sb/doh/",
        verified: "2026-08-20",
    },
    Provider {
        id: "mullvad",
        operator: "Mullvad VPN AB",
        aliases: &["mullvad", "dns.mullvad.net"],
        addresses: &["194.242.2.2", "2a07:e340::2"],
        doh: Some("https://dns.mullvad.net/dns-query"),
        dot: Some("dns.mullvad.net"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Public, no account required. Ad-blocking variants are separate hostnames.",
        source: "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls",
        verified: "2026-08-20",
    },
    Provider {
        id: "dns0",
        operator: "DNS0.eu",
        aliases: &["dns0", "dns0.eu"],
        addresses: &["193.110.81.0", "185.253.5.0", "2a0f:fc80::", "2a0f:fc81::"],
        doh: Some("https://dns0.eu/"),
        dot: Some("dns0.eu"),
        doq: None,
        filtering: FilteringPolicy::SecurityFiltered,
        notes: "European non-profit. Blocks malicious names; `zero.dns0.eu` is the \
                stricter variant and `open.dns0.eu` the unfiltered one.",
        source: "https://www.dns0.eu/",
        verified: "2026-08-20",
    },
    Provider {
        id: "dns0-open",
        operator: "DNS0.eu",
        aliases: &["dns0-open", "open.dns0.eu"],
        addresses: &[
            "193.110.81.9",
            "185.253.5.9",
            "2a0f:fc80::9",
            "2a0f:fc81::9",
        ],
        doh: Some("https://open.dns0.eu/"),
        dot: Some("open.dns0.eu"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "DNS0.eu with no blocklist.",
        source: "https://www.dns0.eu/open",
        verified: "2026-08-20",
    },
    Provider {
        id: "adguard",
        operator: "AdGuard",
        aliases: &["adguard", "dns.adguard-dns.com"],
        addresses: &[
            "94.140.14.14",
            "94.140.15.15",
            "2a10:50c0::ad1:ff",
            "2a10:50c0::ad2:ff",
        ],
        doh: Some("https://dns.adguard-dns.com/dns-query"),
        dot: Some("dns.adguard-dns.com"),
        doq: Some("dns.adguard-dns.com"),
        filtering: FilteringPolicy::AdBlocking,
        notes: "Blocks advertising and tracking names. Not in the default pool: an \
                ad-blocking answer differs deliberately from an unfiltered one.",
        source: "https://adguard-dns.io/en/public-dns.html",
        verified: "2026-08-20",
    },
    Provider {
        id: "adguard-unfiltered",
        operator: "AdGuard",
        aliases: &["adguard-unfiltered", "unfiltered.adguard-dns.com"],
        addresses: &[
            "94.140.14.140",
            "94.140.14.141",
            "2a10:50c0::1:ff",
            "2a10:50c0::2:ff",
        ],
        doh: Some("https://unfiltered.adguard-dns.com/dns-query"),
        dot: Some("unfiltered.adguard-dns.com"),
        doq: Some("unfiltered.adguard-dns.com"),
        filtering: FilteringPolicy::Unfiltered,
        notes: "AdGuard with no blocklist and no security filter.",
        source: "https://adguard-dns.io/en/public-dns.html",
        verified: "2026-08-20",
    },
    Provider {
        id: "opendns",
        operator: "Cisco OpenDNS",
        aliases: &["opendns", "dns.opendns.com"],
        addresses: &[
            "208.67.222.222",
            "208.67.220.220",
            "2620:119:35::35",
            "2620:119:53::53",
        ],
        doh: Some("https://doh.opendns.com/dns-query"),
        dot: None,
        doq: None,
        filtering: FilteringPolicy::SecurityFiltered,
        notes: "Blocks phishing by default. Returns a redirect page for NXDOMAIN on some \
                configurations, so it is not in the default pool.",
        source: "https://www.opendns.com/setupguide/",
        verified: "2026-08-20",
    },
    Provider {
        id: "alidns",
        operator: "Alibaba Cloud",
        aliases: &["alidns", "dns.alidns.com"],
        addresses: &[
            "223.5.5.5",
            "223.6.6.6",
            "2400:3200::1",
            "2400:3200:baba::1",
        ],
        doh: Some("https://dns.alidns.com/dns-query"),
        dot: Some("dns.alidns.com"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Mainland China. Far lower latency there than the global providers, which \
                are frequently unreachable from that network.",
        source: "https://alidns.com/",
        verified: "2026-08-20",
    },
    Provider {
        id: "dnspod",
        operator: "Tencent DNSPod",
        aliases: &["dnspod", "doh.pub"],
        addresses: &["119.29.29.29", "119.28.28.28"],
        doh: Some("https://doh.pub/dns-query"),
        dot: Some("dot.pub"),
        doq: None,
        filtering: FilteringPolicy::Unfiltered,
        notes: "Mainland China.",
        source: "https://www.dnspod.cn/products/publicdns",
        verified: "2026-08-20",
    },
];

/// A named set of providers.
pub struct Profile {
    /// The `builtin:` name.
    pub name: &'static str,
    /// What it is for.
    pub description: &'static str,
    /// Provider ids, in preference order.
    pub members: &'static [&'static str],
}

/// The profiles `builtin:` understands.
///
/// `recommended` is what the installer writes. It is deliberately five independent
/// operators rather than a dozen: enough that several can be blocked or slow without
/// resolution stopping, few enough that the scheduler converges quickly and no single
/// operator appears twice.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "recommended",
        description: "Independent, general-purpose, unfiltered resolvers. The default.",
        members: &[
            "cloudflare",
            "google",
            "quad9-unfiltered",
            "dnssb",
            "mullvad",
        ],
    },
    Profile {
        name: "global",
        description: "Widely reachable resolvers, unfiltered.",
        members: &[
            "cloudflare",
            "google",
            "quad9-unfiltered",
            "dnssb",
            "mullvad",
            "dns0-open",
            "adguard-unfiltered",
        ],
    },
    Profile {
        name: "china",
        description: "Resolvers reachable with low latency from mainland China.",
        members: &["alidns", "dnspod", "cloudflare"],
    },
    Profile {
        name: "privacy",
        description: "Operators with an explicit no-logging policy.",
        members: &["mullvad", "dnssb", "quad9-unfiltered", "dns0-open"],
    },
    Profile {
        name: "security-filtered",
        description: "Resolvers that withhold known-malicious names.",
        members: &["quad9", "dns0", "cloudflare"],
    },
    Profile {
        name: "ad-blocking",
        description: "Resolvers that withhold advertising and tracking names.",
        members: &["adguard", "mullvad"],
    },
];

/// Look a provider up by id, alias, Do53 address, or any endpoint hostname.
///
/// Endpoint hostnames count because that is how bootstrap addresses are found: a
/// configuration naming `https://doh.dns.sb/dns-query` needs DNS.SB's literal addresses to
/// open the first connection, and `doh.dns.sb` is the only handle it has.
pub fn provider(name: &str) -> Option<&'static Provider> {
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    CATALOG.iter().find(|p| {
        p.id == key
            || p.aliases.iter().any(|a| *a == key)
            || p.addresses.iter().any(|a| *a == key)
            || endpoint_hosts(p)
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&key))
    })
}

/// Every hostname this provider's encrypted endpoints authenticate as.
fn endpoint_hosts(p: &Provider) -> Vec<&'static str> {
    let mut out = Vec::new();
    if let Some(doh) = p.doh {
        let host = doh
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(doh);
        out.push(host);
    }
    out.extend([p.dot, p.doq].into_iter().flatten());
    out
}

/// True when `name` is a short handle for a provider rather than a real hostname.
///
/// `quad9` is a handle; `dns.quad9.net` is the hostname its certificate carries. Only a
/// handle may be rewritten — see [`alias_endpoint_host`].
pub fn is_bare_alias(name: &str) -> bool {
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    let Some(p) = provider(&key) else {
        return false;
    };
    // An entry that is also a real endpoint hostname is not a handle.
    if endpoint_hosts(p)
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&key))
    {
        return false;
    }
    p.id == key || p.aliases.iter().any(|a| *a == key)
}

/// The hostname a bare alias should authenticate as, for a given transport.
///
/// Only for handles: a hostname written in a URI is used exactly as written, because the
/// certificate has to match what the operator asked for. `tls://quad9` and
/// `https://quad9` can differ, and for some operators they do — DNS.SB serves DoH from
/// `doh.dns.sb` and DoT from `dot.sb`.
pub fn alias_endpoint_host(name: &str, transport: Transport) -> Option<&'static str> {
    let p = provider(name)?;
    let doh_host = p.doh.map(|d| {
        d.trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(d)
    });
    match transport {
        Transport::Doh => doh_host.or(p.dot).or(p.doq),
        Transport::Dot => p.dot.or(doh_host).or(p.doq),
        Transport::Doq => p.doq.or(p.dot).or(doh_host),
    }
}

/// Which endpoint a caller wants the hostname for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// DNS over HTTPS.
    Doh,
    /// DNS over TLS.
    Dot,
    /// DNS over QUIC.
    Doq,
}

/// Look a profile up by name.
pub fn profile(name: &str) -> Option<&'static Profile> {
    let key = name.trim().to_ascii_lowercase();
    PROFILES.iter().find(|p| p.name == key)
}

/// The endpoint URIs a profile expands to.
///
/// Each provider contributes one encrypted endpoint where it publishes one, plus its Do53
/// addresses. The Do53 seeds matter: they need no name resolution, so they are what makes
/// the encrypted endpoints reachable on a host with no working DNS yet.
pub fn expand(name: &str) -> Option<Vec<String>> {
    let profile = profile(name)?;
    let mut out = Vec::new();
    for id in profile.members {
        let Some(p) = provider(id) else { continue };
        // A Do53 seed first: it is the bootstrap for everything else.
        if let Some(first) = p.addresses.first() {
            out.push((*first).to_string());
        }
        // Then the encrypted endpoint, preferring DoH because one entry yields both
        // HTTP/3 and HTTP/2 candidates and the scheduler picks.
        if let Some(doh) = p.doh {
            out.push(doh.to_string());
        } else if let Some(dot) = p.dot {
            out.push(format!("tls://{dot}"));
        }
    }
    Some(out)
}

/// Every profile name, for diagnostics and error messages.
pub fn profile_names() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.name).collect()
}

/// The authority id for a hostname or address belonging to a built-in provider.
///
/// This is what stops one operator corroborating itself: `1.1.1.1`,
/// `cloudflare-dns.com` and `one.one.one.one` all answer `cloudflare`.
pub fn authority_for(host: &str) -> Option<&'static str> {
    let key = host.trim_end_matches('.').to_ascii_lowercase();
    provider(&key).map(|p| p.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    /// Every entry must be usable: real addresses, a documented source, and at least one
    /// endpoint to actually reach.
    #[test]
    fn every_provider_has_valid_metadata() {
        assert!(
            CATALOG.len() >= 10,
            "the catalog should cover a useful range of operators, saw {}",
            CATALOG.len()
        );
        for p in CATALOG {
            assert!(!p.id.is_empty(), "missing id");
            assert!(!p.operator.is_empty(), "{} has no operator", p.id);
            assert!(
                p.aliases.contains(&p.id),
                "{} should be reachable by its own id",
                p.id
            );
            assert!(!p.addresses.is_empty(), "{} has no Do53 addresses", p.id);
            for a in p.addresses {
                a.parse::<IpAddr>()
                    .unwrap_or_else(|_| panic!("{} has a malformed address `{a}`", p.id));
            }
            assert!(
                p.doh.is_some() || p.dot.is_some() || p.doq.is_some(),
                "{} publishes no encrypted endpoint",
                p.id
            );
            if let Some(doh) = p.doh {
                assert!(doh.starts_with("https://"), "{} doh must be https", p.id);
            }
            assert!(
                p.source.starts_with("https://"),
                "{} must cite operator documentation",
                p.id
            );
            assert!(!p.notes.is_empty(), "{} has no notes", p.id);
            assert_eq!(p.verified.len(), 10, "{} verified date malformed", p.id);
        }
    }

    #[test]
    fn provider_ids_and_aliases_are_unique() {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for p in CATALOG {
            assert!(seen.insert(p.id), "duplicate provider id `{}`", p.id);
            for a in p.aliases {
                assert!(seen.insert(a) || *a == p.id, "alias `{a}` is claimed twice");
            }
        }
    }

    /// An address must not be claimed by two operators, or authority identity is
    /// ambiguous exactly where it matters.
    #[test]
    fn no_address_belongs_to_two_providers() {
        let mut owner: std::collections::BTreeMap<&str, &str> = Default::default();
        for p in CATALOG {
            for a in p.addresses {
                if let Some(prev) = owner.insert(a, p.id) {
                    panic!("address {a} is claimed by both `{prev}` and `{}`", p.id);
                }
            }
        }
    }

    /// The property the whole model rests on: every way of naming one operator resolves
    /// to one authority. Otherwise a provider's Do53 address could corroborate its own
    /// DoH hostname and one operator's answer would look like a consensus.
    #[test]
    fn every_alias_address_and_endpoint_maps_to_one_authority() {
        for p in CATALOG {
            for alias in p.aliases {
                assert_eq!(authority_for(alias), Some(p.id), "alias {alias}");
            }
            for addr in p.addresses {
                assert_eq!(authority_for(addr), Some(p.id), "address {addr}");
            }
            if let Some(dot) = p.dot {
                assert_eq!(authority_for(dot), Some(p.id), "dot {dot}");
            }
            if let Some(doh) = p.doh {
                let host = doh
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .unwrap();
                assert_eq!(authority_for(host), Some(p.id), "doh {host}");
            }
        }
    }

    #[test]
    fn cloudflare_do53_and_doh_are_the_same_authority() {
        assert_eq!(
            authority_for("1.1.1.1"),
            authority_for("cloudflare-dns.com")
        );
        assert_eq!(authority_for("1.0.0.1"), authority_for("one.one.one.one"));
        assert_ne!(authority_for("1.1.1.1"), authority_for("8.8.8.8"));
    }

    #[test]
    fn every_profile_names_only_real_providers() {
        for prof in PROFILES {
            assert!(!prof.members.is_empty(), "{} is empty", prof.name);
            assert!(
                !prof.description.is_empty(),
                "{} has no description",
                prof.name
            );
            for id in prof.members {
                assert!(provider(id).is_some(), "{} names unknown `{id}`", prof.name);
            }
        }
    }

    /// The default must be several *independent* operators, so one being blocked is
    /// survivable and no operator can appear to agree with itself.
    #[test]
    fn recommended_is_several_independent_authorities() {
        let prof = profile("recommended").expect("recommended exists");
        let authorities: BTreeSet<&str> = prof.members.iter().copied().collect();
        assert!(
            authorities.len() >= 5,
            "recommended should carry at least five independent authorities, saw {}",
            authorities.len()
        );
        assert!(
            authorities.len() <= 8,
            "recommended should stay small enough to converge quickly, saw {}",
            authorities.len()
        );

        // Distinct *operators*, not merely distinct ids: two endpoints from one company
        // are one authority for corroboration.
        let operators: BTreeSet<&str> = prof
            .members
            .iter()
            .filter_map(|id| provider(id))
            .map(|p| p.operator)
            .collect();
        assert_eq!(
            operators.len(),
            prof.members.len(),
            "recommended must not name one operator twice: {operators:?}"
        );
    }

    /// A filtering resolver returns deliberately different answers. Mixing one into the
    /// default pool would make a block indistinguishable from GeoDNS variation.
    #[test]
    fn the_default_profile_contains_no_filtering_resolver() {
        let prof = profile("recommended").expect("recommended exists");
        for id in prof.members {
            let p = provider(id).expect("member exists");
            assert_eq!(
                p.filtering,
                FilteringPolicy::Unfiltered,
                "`{id}` filters and must not be in the default pool"
            );
        }
    }

    /// The expansion has to work before DNS does, so it must carry literal seeds.
    #[test]
    fn recommended_expands_to_seeds_and_encrypted_endpoints() {
        let uris = expand("recommended").expect("expands");
        let literals = uris.iter().filter(|u| u.parse::<IpAddr>().is_ok()).count();
        let encrypted = uris
            .iter()
            .filter(|u| u.starts_with("https://") || u.starts_with("tls://"))
            .count();
        assert!(
            literals >= 1,
            "at least one Do53 seed is needed to bootstrap the encrypted endpoints: {uris:?}"
        );
        assert!(
            encrypted >= 3,
            "expected several encrypted endpoints: {uris:?}"
        );
        assert_eq!(literals, 5, "one seed per recommended provider: {uris:?}");
    }

    #[test]
    fn every_profile_expands_to_something_usable() {
        for name in profile_names() {
            let uris = expand(name).unwrap_or_else(|| panic!("{name} expands"));
            assert!(!uris.is_empty(), "{name} expanded to nothing");
        }
    }

    #[test]
    fn an_unknown_profile_is_not_invented() {
        assert!(profile("does-not-exist").is_none());
        assert!(expand("does-not-exist").is_none());
    }

    #[test]
    fn lookup_is_case_and_trailing_dot_insensitive() {
        assert_eq!(provider("CloudFlare").map(|p| p.id), Some("cloudflare"));
        assert_eq!(provider("dns.google.").map(|p| p.id), Some("google"));
        assert_eq!(authority_for("DNS.QUAD9.NET."), Some("quad9"));
    }
}
