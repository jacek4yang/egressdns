//! The intent-oriented endpoint model.
//!
//! A v2 configuration describes *where to ask*, not *how to ask*. An operator writes
//!
//! ```toml
//! version = 2
//! upstreams = ["1.1.1.1", "https://cloudflare-dns.com/dns-query", "tls://dns.quad9.net"]
//! ```
//!
//! and the daemon derives the transports, address families and route candidates. There is
//! no knob for UDP versus TCP, for HTTP/2 versus HTTP/3, or for IPv4 versus IPv6: those
//! are decisions the scheduler makes from measured evidence, and an operator who has to
//! pick them in advance is being asked to guess.
//!
//! This module is the parser and the desugaring. It performs no I/O, so `check-config`
//! and `doctor` work on a host with no network at all.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use url::Url;

use crate::config::{TransportKind, UpstreamServerConfig};

/// Where an endpoint lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHost {
    /// A literal address. Needs no bootstrap.
    Addr(IpAddr),
    /// A name, which is both the bootstrap question and the TLS identity.
    Name(String),
}

/// One resolved route candidate derived from an endpoint URI.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    /// Transport this candidate uses.
    pub transport: TransportKind,
    /// Host, which for an encrypted transport is also the authentication identity.
    pub host: EndpointHost,
    /// Port.
    pub port: u16,
    /// DoH path, for the HTTP transports only.
    pub path: Option<String>,
    /// Bootstrap addresses pinned with `?addr=`, if any.
    pub hints: Vec<IpAddr>,
}

fn provider_for(host: &str) -> Option<&'static crate::config::builtins::Provider> {
    crate::config::builtins::provider(host)
}

/// The identity a host in a URI authenticates as: itself.
///
/// A hostname written in a URI is never rewritten. Mapping it to some other name from the
/// catalog would authenticate against a certificate the operator did not ask for — and it
/// broke `https://doh.dns.sb/...`, which was silently turned into `dot.sb`.
fn canonical_name(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Bootstrap addresses for a name, when the registry knows it.
fn bootstrap_addresses(host: &str) -> Option<Vec<IpAddr>> {
    let p = crate::config::builtins::provider(host)?;
    Some(
        p.addresses
            .iter()
            .filter_map(|a| a.parse::<IpAddr>().ok())
            .collect(),
    )
}

/// Parse one endpoint entry into the route candidates it implies.
///
/// A bare address yields Do53; the TCP companion that RFC 7766 truncation retries need is
/// added by the upstream registry, not here. An `https://` endpoint yields *two*
/// candidates, HTTP/3 and HTTP/2, because which one is better is a measurement rather than
/// a configuration choice — the scheduler ranks them and falls back between them on its
/// own evidence.
pub fn parse(entry: &str) -> Result<Vec<Endpoint>, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err(String::from("empty upstream entry"));
    }

    // A bare address or address:port, which needs no scheme and no bootstrap.
    if let Some(endpoint) = parse_bare(entry)? {
        return Ok(vec![endpoint]);
    }

    // A bare provider alias, e.g. "cloudflare".
    if !entry.contains("://") {
        if let Some(p) = provider_for(entry) {
            // A bare alias, unlike a URI host, does have to be mapped to the hostname
            // its certificate carries.
            let host = crate::config::builtins::alias_endpoint_host(
                entry,
                crate::config::builtins::Transport::Doh,
            )
            .unwrap_or(p.id)
            .to_string();
            let path = p
                .doh
                .and_then(|d| {
                    d.trim_start_matches("https://")
                        .split_once('/')
                        .map(|(_, r)| r)
                })
                .map(|r| format!("/{r}"))
                .unwrap_or_else(|| String::from("/dns-query"));
            return Ok(doh_candidates(
                EndpointHost::Name(host),
                443,
                &path,
                Vec::new(),
            ));
        }
        return Err(format!(
            "`{entry}` is neither an IP address, a known provider alias, nor a URI with a \
             scheme; write an address like `1.1.1.1`, or a URI like \
             `https://dns.example.net/dns-query`, `tls://dns.example.net` or \
             `quic://dns.example.net`"
        ));
    }

    let url = Url::parse(entry).map_err(|e| format!("`{entry}` is not a valid URI: {e}"))?;

    // `?addr=` pins bootstrap addresses for a name DNS cannot resolve yet: a resolver on
    // a private network, one named by a certificate that does not match its address, or
    // one being stood up before its own record exists. It is the same information SVCB
    // carries as ipv4hint/ipv6hint, and it changes only which socket is opened — the TLS
    // identity is still the hostname, so a wrong hint fails closed rather than silently
    // reaching somebody else.
    let mut hints: Vec<IpAddr> = Vec::new();
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "addr" => {
                let addr = value.parse::<IpAddr>().map_err(|_| {
                    format!("`{entry}` has an `addr` hint that is not an IP address: `{value}`")
                })?;
                hints.push(addr);
            }
            other => {
                return Err(format!(
                    "`{entry}` has the unsupported query parameter `{other}`; only `addr` \
                     is understood"
                ))
            }
        }
    }

    let host_str = url
        .host_str()
        .ok_or_else(|| format!("`{entry}` has no host"))?;
    // `Url` keeps IPv6 literals in brackets in some accessors; normalise here so the host
    // is either a clean literal or a clean name.
    let host_str = host_str.trim_start_matches('[').trim_end_matches(']');
    let transport = match url.scheme() {
        "tls" => crate::config::builtins::Transport::Dot,
        "quic" => crate::config::builtins::Transport::Doq,
        _ => crate::config::builtins::Transport::Doh,
    };
    let host = match host_str.parse::<IpAddr>() {
        Ok(addr) => EndpointHost::Addr(addr),
        // A handle like `tls://quad9` is expanded; a real hostname is left alone.
        Err(_) if crate::config::builtins::is_bare_alias(host_str) => EndpointHost::Name(
            crate::config::builtins::alias_endpoint_host(host_str, transport)
                .unwrap_or(host_str)
                .to_string(),
        ),
        Err(_) => EndpointHost::Name(canonical_name(host_str)),
    };

    match url.scheme() {
        "https" => {
            let path = match url.path() {
                "" | "/" => String::from("/dns-query"),
                p => p.to_string(),
            };
            Ok(doh_candidates(
                host,
                url.port().unwrap_or(443),
                &path,
                hints,
            ))
        }
        "tls" => Ok(vec![Endpoint {
            transport: TransportKind::Dot,
            host,
            port: url.port().unwrap_or(853),
            path: None,
            hints,
        }]),
        "quic" => Ok(vec![Endpoint {
            transport: TransportKind::Doq,
            host,
            port: url.port().unwrap_or(853),
            path: None,
            hints,
        }]),
        "udp" | "dns" => Ok(vec![Endpoint {
            transport: TransportKind::Udp,
            host,
            port: url.port().unwrap_or(53),
            path: None,
            hints,
        }]),
        "tcp" => Ok(vec![Endpoint {
            transport: TransportKind::Tcp,
            host,
            port: url.port().unwrap_or(53),
            path: None,
            hints,
        }]),
        // `http://` is deliberately refused: an unauthenticated DoH endpoint has the
        // privacy cost of DoH and none of its integrity, which is strictly worse than
        // Do53 on the same path.
        "http" => Err(format!(
            "`{entry}` uses plaintext HTTP, which authenticates nothing; use `https://` \
             for DoH, or a bare address for Do53"
        )),
        other => Err(format!(
            "`{entry}` uses the unsupported scheme `{other}`; supported schemes are \
             https, tls, quic, udp and tcp"
        )),
    }
}

/// One DoH endpoint becomes an HTTP/3 candidate and an HTTP/2 candidate.
fn doh_candidates(host: EndpointHost, port: u16, path: &str, hints: Vec<IpAddr>) -> Vec<Endpoint> {
    vec![
        Endpoint {
            transport: TransportKind::Doh3,
            host: host.clone(),
            port,
            path: Some(path.to_string()),
            hints: hints.clone(),
        },
        Endpoint {
            transport: TransportKind::Doh2,
            host,
            port,
            path: Some(path.to_string()),
            hints,
        },
    ]
}

/// Parse the schemeless address forms, returning `None` when `entry` is not one.
fn parse_bare(entry: &str) -> Result<Option<Endpoint>, String> {
    if entry.contains("://") {
        return Ok(None);
    }
    // A bare IPv6 literal contains colons but no port; try it before `SocketAddr`.
    if let Ok(addr) = IpAddr::from_str(entry) {
        return Ok(Some(Endpoint {
            transport: TransportKind::Udp,
            host: EndpointHost::Addr(addr),
            port: 53,
            path: None,
            hints: Vec::new(),
        }));
    }
    if let Ok(sock) = SocketAddr::from_str(entry) {
        return Ok(Some(Endpoint {
            transport: TransportKind::Udp,
            host: EndpointHost::Addr(sock.ip()),
            port: sock.port(),
            path: None,
            hints: Vec::new(),
        }));
    }
    // `1.2.3.4:53` parses as a `SocketAddr` above; a bracketed v6 form without a port
    // does not, so handle it explicitly rather than sending it to the URI parser.
    if let Some(inner) = entry.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(addr) = IpAddr::from_str(inner) {
            return Ok(Some(Endpoint {
                transport: TransportKind::Udp,
                host: EndpointHost::Addr(addr),
                port: 53,
                path: None,
                hints: Vec::new(),
            }));
        }
    }
    Ok(None)
}

/// Turn the `upstreams` list into the normalised tree the scheduler runs on.
///
/// This is the only way an `UpstreamConfig` is ever produced from a file: the tree is not
/// a configuration surface, so there is exactly one path into it and one shape it can
/// take.
pub fn build_upstreams(upstreams: &[String]) -> Result<crate::config::UpstreamConfig, String> {
    let servers = desugar(upstreams)?;
    Ok(crate::config::UpstreamConfig {
        default_group: String::from("default"),
        groups: vec![crate::config::UpstreamGroupConfig {
            name: String::from("default"),
            servers,
            scheduler: crate::config::SchedulerConfig::default(),
        }],
        tls: crate::config::UpstreamTlsConfig::default(),
    })
}

/// Turn the `upstreams` list into server definitions.
///
/// Each entry keeps its position in the generated name so that metrics, logs and
/// `egressdnsctl upstreams` point back at the line the operator wrote.
pub fn desugar(upstreams: &[String]) -> Result<Vec<UpstreamServerConfig>, String> {
    // `builtin:` names expand to the URIs of a curated profile before anything else is
    // parsed, so the rest of this function never has to know the catalog exists.
    let mut expanded: Vec<String> = Vec::with_capacity(upstreams.len());
    for entry in upstreams {
        // `auto` is normally replaced at startup by what was measured on the host — the
        // local gateway, the regionally fast resolvers. It is accepted here too so that
        // `check-config` on a file containing it is meaningful, and so that a
        // configuration is never invalid merely because probing has not happened yet. The
        // static expansion is the one that works from anywhere.
        if entry.trim() == "auto" {
            expanded.extend(crate::config::auto::expand(
                &crate::config::auto::GatewayProbe::Rejected(
                    crate::config::auto::GatewayRejection::NoGateway,
                ),
                crate::config::auto::Region::Global,
            ));
            continue;
        }
        if let Some(profile) = entry.trim().strip_prefix("builtin:") {
            let uris = crate::config::builtins::expand(profile).ok_or_else(|| {
                format!(
                    "`{entry}` names an unknown built-in profile; available profiles are {}",
                    crate::config::builtins::profile_names().join(", ")
                )
            })?;
            expanded.extend(uris);
        } else {
            expanded.push(entry.clone());
        }
    }
    let upstreams = &expanded;

    let mut out = Vec::new();
    for (index, entry) in upstreams.iter().enumerate() {
        for candidate in parse(entry)? {
            let (addresses, server_name) = match &candidate.host {
                EndpointHost::Addr(addr) => {
                    if candidate.transport.is_encrypted() {
                        // An encrypted transport to a bare address has no name to
                        // authenticate, and accepting one would mean accepting any
                        // certificate. Refuse rather than silently downgrade.
                        return Err(format!(
                            "`{entry}` uses an encrypted transport with a literal address, \
                             so there is no identity to authenticate; write the resolver's \
                             name instead, for example `tls://dns.quad9.net`"
                        ));
                    }
                    (vec![*addr], None)
                }
                EndpointHost::Name(name) => {
                    // A name the registry knows starts with published bootstrap
                    // addresses. Any other name starts with none and is resolved at
                    // startup by `bootstrap`. Either way the TLS identity is `name`, so
                    // a bootstrap address only decides who we open a socket to, never
                    // who we are willing to trust once it answers.
                    let addresses = if candidate.hints.is_empty() {
                        bootstrap_addresses(name).unwrap_or_default()
                    } else {
                        candidate.hints.clone()
                    };
                    (addresses, Some(name.clone()))
                }
            };

            out.push(UpstreamServerConfig {
                name: format!("u{index}-{}", candidate.transport.label()),
                transport: candidate.transport,
                addresses,
                server_name,
                port: Some(candidate.port),
                path: candidate.path.clone(),
                ..UpstreamServerConfig::default()
            });
        }
    }
    if out.is_empty() {
        return Err(String::from(
            "`upstreams` is empty; a forwarder with no upstream can answer nothing",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(entry: &str) -> Endpoint {
        let mut v = parse(entry).expect("parses");
        assert_eq!(v.len(), 1, "{entry} should yield one candidate");
        v.remove(0)
    }

    #[test]
    fn a_bare_ipv4_address_becomes_do53() {
        let e = one("1.1.1.1");
        assert_eq!(e.transport, TransportKind::Udp);
        assert_eq!(e.host, EndpointHost::Addr("1.1.1.1".parse().expect("ip")));
        assert_eq!(e.port, 53);
    }

    #[test]
    fn a_bare_ipv6_address_becomes_do53() {
        let e = one("2606:4700:4700::1111");
        assert_eq!(e.transport, TransportKind::Udp);
        assert_eq!(
            e.host,
            EndpointHost::Addr("2606:4700:4700::1111".parse().expect("ip"))
        );
        assert_eq!(e.port, 53);
    }

    #[test]
    fn explicit_ports_are_honoured_on_both_families() {
        assert_eq!(one("1.1.1.1:5353").port, 5353);
        let v6 = one("[2606:4700:4700::1111]:5353");
        assert_eq!(v6.port, 5353);
        assert_eq!(
            v6.host,
            EndpointHost::Addr("2606:4700:4700::1111".parse().expect("ip"))
        );
        assert_eq!(one("[2606:4700:4700::1111]").port, 53);
    }

    /// One HTTPS endpoint is one logical resolver reached two ways. Which way is better
    /// is a measurement, so both are offered and the scheduler decides.
    #[test]
    fn one_https_endpoint_yields_h3_and_h2_candidates() {
        let v = parse("https://cloudflare-dns.com/dns-query").expect("parses");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].transport, TransportKind::Doh3, "H3 is offered first");
        assert_eq!(v[1].transport, TransportKind::Doh2);
        for e in &v {
            assert_eq!(e.port, 443);
            assert_eq!(e.path.as_deref(), Some("/dns-query"));
            assert_eq!(
                e.host,
                EndpointHost::Name(String::from("cloudflare-dns.com"))
            );
        }
    }

    #[test]
    fn tls_and_quic_uris_map_to_dot_and_doq_on_port_853() {
        let dot = one("tls://dns.quad9.net");
        assert_eq!(dot.transport, TransportKind::Dot);
        assert_eq!(dot.port, 853);
        let doq = one("quic://dns.adguard-dns.com");
        assert_eq!(doq.transport, TransportKind::Doq);
        assert_eq!(doq.port, 853);
        assert_eq!(one("tls://dns.quad9.net:8853").port, 8853);
    }

    #[test]
    fn provider_aliases_expand_to_the_canonical_authentication_name() {
        let v = parse("cloudflare").expect("parses");
        assert_eq!(
            v[0].host,
            EndpointHost::Name(String::from("cloudflare-dns.com"))
        );
        let q = one("tls://quad9");
        assert_eq!(q.host, EndpointHost::Name(String::from("dns.quad9.net")));
    }

    #[test]
    fn a_missing_doh_path_defaults_sensibly() {
        let v = parse("https://cloudflare-dns.com").expect("parses");
        assert_eq!(v[0].path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn plaintext_http_is_refused() {
        let e = parse("http://dns.example.net/dns-query").expect_err("must be refused");
        assert!(e.contains("authenticates nothing"), "{e}");
    }

    #[test]
    fn an_unknown_scheme_is_refused_with_the_supported_list() {
        let e = parse("gopher://dns.example.net").expect_err("must be refused");
        assert!(e.contains("unsupported scheme"), "{e}");
        assert!(e.contains("https"), "{e}");
    }

    #[test]
    fn a_bare_word_that_is_not_a_provider_is_refused() {
        let e = parse("not-a-resolver").expect_err("must be refused");
        assert!(e.contains("neither an IP address"), "{e}");
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert!(parse("   ").is_err());
    }

    /// An encrypted transport needs a name to authenticate. Accepting a literal address
    /// would mean accepting whatever certificate arrived.
    #[test]
    fn an_encrypted_transport_to_a_literal_address_is_refused() {
        let e = desugar(&[String::from("tls://1.1.1.1")]).expect_err("must be refused");
        assert!(e.contains("no identity to authenticate"), "{e}");
    }

    /// An arbitrary named endpoint is accepted and left for the bootstrap resolver.
    ///
    /// Requiring membership of a built-in provider registry meant a private or
    /// self-hosted resolver could not be named at all, which is not a resolver anyone
    /// would ship.
    #[test]
    fn an_arbitrary_named_endpoint_is_accepted_without_bootstrap_addresses() {
        let servers = desugar(&[String::from("tls://dns.example.net")]).expect("accepted");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name.as_deref(), Some("dns.example.net"));
        assert!(
            servers[0].addresses.is_empty(),
            "an unknown name carries no bootstrap addresses; startup resolves it"
        );
    }

    /// A registry name still starts with published addresses, so it works with no DNS.
    #[test]
    fn a_known_provider_still_carries_bootstrap_addresses() {
        let servers = desugar(&[String::from("tls://dns.quad9.net")]).expect("accepted");
        assert_eq!(servers[0].addresses.len(), 4);
    }

    #[test]
    fn desugaring_produces_usable_server_definitions() {
        let servers = desugar(&[
            String::from("1.1.1.1"),
            String::from("tls://dns.quad9.net"),
            String::from("https://cloudflare-dns.com/dns-query"),
        ])
        .expect("desugars");

        // One Do53, one DoT, and the H3/H2 pair.
        assert_eq!(servers.len(), 4);

        assert_eq!(servers[0].transport, TransportKind::Udp);
        assert_eq!(servers[0].port, Some(53));
        assert!(servers[0].server_name.is_none());

        assert_eq!(servers[1].transport, TransportKind::Dot);
        assert_eq!(servers[1].server_name.as_deref(), Some("dns.quad9.net"));
        assert_eq!(servers[1].port, Some(853));
        assert_eq!(
            servers[1].addresses.len(),
            4,
            "bootstrap addresses attached"
        );

        assert_eq!(servers[2].transport, TransportKind::Doh3);
        assert_eq!(servers[3].transport, TransportKind::Doh2);
        for s in &servers[2..] {
            assert_eq!(s.server_name.as_deref(), Some("cloudflare-dns.com"));
            assert_eq!(s.path.as_deref(), Some("/dns-query"));
            assert_eq!(s.port, Some(443));
        }

        // Names are unique, because they become metric labels.
        let mut names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "server names must be unique");
    }

    #[test]
    fn an_empty_upstream_list_is_refused() {
        assert!(desugar(&[]).is_err());
    }

    /// A `builtin:` profile expands to the catalog's endpoints, seeds included.
    ///
    /// The catalog itself is checked in `config::builtins`; this is the seam.
    #[test]
    fn a_builtin_profile_expands_into_real_servers() {
        let servers = desugar(&[String::from("builtin:recommended")]).expect("expands");
        assert!(
            servers.len() >= 10,
            "expected several routes, saw {}",
            servers.len()
        );

        let literal_seeds = servers.iter().filter(|s| s.server_name.is_none()).count();
        assert!(
            literal_seeds >= 5,
            "each provider contributes a Do53 seed so the encrypted endpoints can be \
             bootstrapped before DNS works, saw {literal_seeds}"
        );
        assert!(
            servers.iter().any(|s| s.transport == TransportKind::Doh3),
            "an https:// endpoint should yield an HTTP/3 candidate"
        );
        for s in servers.iter().filter(|s| s.server_name.is_some()) {
            assert!(
                !s.addresses.is_empty(),
                "a catalog endpoint must carry bootstrap addresses: {s:?}"
            );
        }
    }

    #[test]
    fn an_unknown_builtin_profile_names_the_real_ones() {
        let e = desugar(&[String::from("builtin:nonsense")]).expect_err("refused");
        assert!(e.contains("unknown built-in profile"), "{e}");
        assert!(e.contains("recommended"), "{e}");
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        assert_eq!(canonical_name("Cloudflare-DNS.COM."), "cloudflare-dns.com");
        assert_eq!(canonical_name("DNS.Quad9.NET."), "dns.quad9.net");
    }

    /// A real hostname in a URI is never swapped for another operator name.
    ///
    /// DNS.SB serves DoH from `doh.dns.sb` and DoT from `dot.sb`. Canonicalising the
    /// former to the latter authenticated the connection against a certificate the
    /// operator never asked for, and left it with no bootstrap addresses.
    #[test]
    fn a_hostname_written_in_a_uri_keeps_its_own_identity() {
        let v = parse("https://doh.dns.sb/dns-query").expect("parses");
        for c in &v {
            assert_eq!(c.host, EndpointHost::Name(String::from("doh.dns.sb")));
        }

        let t = one("tls://dot.sb");
        assert_eq!(t.host, EndpointHost::Name(String::from("dot.sb")));
    }
}
