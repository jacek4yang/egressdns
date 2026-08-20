//! Resolving the addresses of named upstreams, before DNS works.
//!
//! `upstreams = ["tls://dns.example.net"]` names a resolver by the identity its
//! certificate carries. To open a socket to it we need an address, and the obvious way to
//! get one is to ask DNS — which is the thing we are trying to start.
//!
//! So the addresses come from somewhere that cannot depend on us:
//!
//! 1. a hint written in the URI (`?addr=`), which needs nothing at all;
//! 2. the published bootstrap addresses of a known provider;
//! 3. a bare-IP upstream from the same configuration, which needs no name resolution;
//! 4. the system resolver, as a last resort.
//!
//! An address from any of these is *only* an address. The TLS identity is always the
//! configured hostname, so a hijacked bootstrap answer produces a certificate failure
//! rather than a working connection to the wrong resolver. That is what makes step 4
//! acceptable: the system resolver can tell us where to look, and cannot tell us who to
//! trust.
//!
//! Before any of it runs, the dependency graph is checked for cycles. A resolver
//! configured to bootstrap through itself, directly or through a chain, would otherwise
//! hang at startup with nothing in the log explaining why.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::config::Config;

/// How long the whole bootstrap phase may take.
///
/// Bounded because it delays the listeners. A name that cannot be resolved in this window
/// is left without addresses and retried in the background: one unreachable upstream must
/// not stop a resolver that has others.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one name may take.
const PER_NAME_TIMEOUT: Duration = Duration::from_secs(3);

/// A name that needs addresses before it can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Group the server belongs to.
    pub group: String,
    /// Server name within the group.
    pub server: String,
    /// The hostname to resolve.
    pub host: String,
}

/// What bootstrap did.
#[derive(Debug, Default)]
pub struct Report {
    /// Names resolved, with the addresses found.
    pub resolved: Vec<(String, Vec<IpAddr>)>,
    /// Names that could not be resolved, with the reason.
    pub failed: Vec<(String, String)>,
}

/// Every named upstream that has no address yet.
pub fn pending(config: &Config) -> Vec<Pending> {
    let mut out = Vec::new();
    for group in &config.upstream.groups {
        for server in group.servers.iter().filter(|s| s.enabled) {
            if server.addresses.is_empty() {
                if let Some(host) = server.server_name.as_deref() {
                    out.push(Pending {
                        group: group.name.clone(),
                        server: server.name.clone(),
                        host: host.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Addresses usable to reach a resolver without resolving anything first.
///
/// These are the bare-IP upstreams from the same file. They are preferred over the system
/// resolver because they are the operator's stated choice and because they cannot be
/// pointed back at us by a `/etc/resolv.conf` we do not control.
pub fn seed_resolvers(config: &Config) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for group in &config.upstream.groups {
        for server in group.servers.iter().filter(|s| s.enabled) {
            // Only unencrypted Do53: an encrypted transport needs a name, and a name is
            // what we are trying to resolve.
            if server.server_name.is_some() {
                continue;
            }
            for addr in &server.addresses {
                out.push(SocketAddr::new(*addr, server.effective_port()));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A bootstrap dependency that would resolve through us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    /// The path, in order, ending where it began.
    pub path: Vec<String>,
}

impl std::fmt::Display for Cycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.path.join(" -> "))
    }
}

/// Check the bootstrap graph for cycles before any network I/O happens.
///
/// The cycle that actually occurs in the field is short: an upstream pointed at this
/// host's own listener, or at a local stub that forwards here. Both make the resolver
/// wait on itself, and neither produces a useful error at the point of failure.
pub fn detect_cycles(config: &Config) -> Vec<Cycle> {
    let mut out = Vec::new();

    let listeners: HashSet<SocketAddr> = config
        .server
        .udp_listen
        .iter()
        .chain(config.server.tcp_listen.iter())
        .copied()
        .collect();
    let listen_ports: HashSet<u16> = listeners.iter().map(|a| a.port()).collect();
    let wildcard_ports: HashSet<u16> = listeners
        .iter()
        .filter(|a| a.ip().is_unspecified())
        .map(|a| a.port())
        .collect();

    for group in &config.upstream.groups {
        for server in group.servers.iter().filter(|s| s.enabled) {
            let port = server.effective_port();
            for addr in &server.addresses {
                let sock = SocketAddr::new(*addr, port);

                // Exactly one of our own listen addresses.
                let direct = listeners.contains(&sock);
                // A wildcard listener owns this port on every local address of its
                // family, so an upstream at any local address on that port is us.
                let via_wildcard = wildcard_ports.contains(&port)
                    && (addr.is_loopback()
                        || crate::doctor::probes::local_addresses().contains(addr));

                if direct || via_wildcard {
                    out.push(Cycle {
                        path: vec![
                            String::from("egressdns"),
                            format!("upstream `{}` at {sock}", server.name),
                            String::from("egressdns"),
                        ],
                    });
                    continue;
                }

                // A well-known local stub forwards somewhere else by design, and on a
                // host running EgressDNS that somewhere is frequently EgressDNS.
                if crate::doctor::probes::is_known_stub(*addr) && listen_ports.contains(&53) {
                    out.push(Cycle {
                        path: vec![
                            String::from("egressdns"),
                            format!("upstream `{}` at {sock} (local stub resolver)", server.name),
                            String::from("egressdns"),
                        ],
                    });
                }
            }
        }
    }
    out
}

/// Resolve every pending name and fill in the addresses.
///
/// Returns what happened rather than failing: a resolver with three upstreams, one of
/// which cannot be bootstrapped right now, should start and serve from the other two.
pub async fn resolve_pending(config: &mut Config) -> Report {
    let mut report = Report::default();
    let names = pending(config);
    if names.is_empty() {
        return report;
    }

    let seeds = seed_resolvers(config);
    let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;

    let mut found: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for name in &names {
        if tokio::time::Instant::now() >= deadline {
            report.failed.push((
                name.host.clone(),
                String::from("the bootstrap phase ran out of time"),
            ));
            continue;
        }
        match lookup(&name.host, &seeds).await {
            Ok(addrs) if !addrs.is_empty() => found.push((name.host.clone(), addrs)),
            Ok(_) => report.failed.push((
                name.host.clone(),
                String::from("no addresses were returned"),
            )),
            Err(e) => report.failed.push((name.host.clone(), e)),
        }
    }

    for (host, addrs) in &found {
        apply(config, host, addrs);
        report.resolved.push((host.clone(), addrs.clone()));
    }
    report
}

/// Write resolved addresses into every server that names `host`.
fn apply(config: &mut Config, host: &str, addrs: &[IpAddr]) {
    for group in &mut config.upstream.groups {
        for server in &mut group.servers {
            if server.addresses.is_empty() && server.server_name.as_deref() == Some(host) {
                server.addresses = addrs.to_vec();
            }
        }
    }
}

/// Look one name up, preferring the configured bare-IP resolvers.
async fn lookup(host: &str, seeds: &[SocketAddr]) -> Result<Vec<IpAddr>, String> {
    if !seeds.is_empty() {
        match tokio::time::timeout(PER_NAME_TIMEOUT, lookup_via(host, seeds)).await {
            Ok(Ok(addrs)) if !addrs.is_empty() => return Ok(addrs),
            // Falls through to the system resolver: a configured seed that cannot answer
            // is a reason to try elsewhere, not a reason to give up.
            _ => {}
        }
    }
    match tokio::time::timeout(PER_NAME_TIMEOUT, lookup_via_system(host)).await {
        Ok(result) => result,
        Err(_) => Err(String::from("timed out")),
    }
}

/// Ask the configured bare-IP resolvers over plain UDP.
async fn lookup_via(host: &str, seeds: &[SocketAddr]) -> Result<Vec<IpAddr>, String> {
    let mut last = String::from("no seed resolver answered");
    for seed in seeds {
        let mut addrs = Vec::new();
        for rtype in ["A", "AAAA"] {
            let outcome = crate::dns::query::run(crate::dns::query::Request {
                name: host.to_string(),
                rtype: rtype.to_string(),
                server: seed.ip().to_string(),
                port: seed.port(),
                tcp: false,
                dnssec: false,
                timeout: Duration::from_millis(1_500),
            })
            .await;
            match outcome {
                crate::dns::query::QueryOutcome::Answered { addresses, .. } => {
                    addrs.extend(addresses.iter().filter_map(|a| a.parse::<IpAddr>().ok()));
                }
                crate::dns::query::QueryOutcome::Failed { reason } => last = reason,
            }
        }
        if !addrs.is_empty() {
            return Ok(addrs);
        }
    }
    Err(last)
}

/// Ask the system resolver, as a source of candidate addresses only.
///
/// Whatever it returns still has to present a certificate for the configured name, so a
/// wrong or hostile answer fails closed instead of silently redirecting us.
async fn lookup_via_system(host: &str) -> Result<Vec<IpAddr>, String> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        // The port is irrelevant; `ToSocketAddrs` just needs one.
        match (host.as_str(), 443u16).to_socket_addrs() {
            Ok(iter) => {
                let mut addrs: Vec<IpAddr> = iter.map(|s| s.ip()).collect();
                addrs.sort();
                addrs.dedup();
                Ok(addrs)
            }
            Err(e) => Err(format!("the system resolver could not resolve it: {e}")),
        }
    })
    .await
    .unwrap_or_else(|e| Err(format!("bootstrap task failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::from_toml(text, "test").expect("valid test configuration")
    }

    #[test]
    fn a_named_endpoint_without_addresses_is_pending() {
        let c = config("upstreams = [\"tls://dns.example.net\"]\nproxies = []\n");
        let p = pending(&c);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].host, "dns.example.net");
    }

    #[test]
    fn an_address_hint_removes_the_need_to_bootstrap() {
        let c = config("upstreams = [\"tls://dns.example.net?addr=10.0.0.53\"]\nproxies = []\n");
        assert!(pending(&c).is_empty(), "a hinted endpoint needs no lookup");
    }

    #[test]
    fn a_known_provider_needs_no_bootstrap() {
        let c = config("upstreams = [\"tls://dns.quad9.net\"]\nproxies = []\n");
        assert!(pending(&c).is_empty(), "published addresses are enough");
    }

    /// Only bare-IP upstreams can seed, because an encrypted one needs the very name
    /// resolution being bootstrapped.
    #[test]
    fn only_plain_upstreams_are_used_as_seeds() {
        let c = config(
            "upstreams = [\"9.9.9.9\", \"1.1.1.1:5353\", \"tls://dns.quad9.net\"]\nproxies = []\n",
        );
        let seeds = seed_resolvers(&c);
        assert!(
            seeds.contains(&"9.9.9.9:53".parse().expect("addr")),
            "{seeds:?}"
        );
        assert!(
            seeds.contains(&"1.1.1.1:5353".parse().expect("addr")),
            "{seeds:?}"
        );
        assert_eq!(
            seeds.len(),
            2,
            "the DoT server must not seed itself: {seeds:?}"
        );
    }

    /// An upstream that is one of our own listeners makes the resolver wait on itself.
    #[test]
    fn an_upstream_pointing_at_our_own_listener_is_a_cycle() {
        let c = config(
            "upstreams = [\"127.0.0.1:15353\"]\nproxies = []\n\n[server]\n\
             udp_listen = [\"127.0.0.1:15353\"]\ntcp_listen = [\"127.0.0.1:15353\"]\n",
        );
        let cycles = detect_cycles(&c);
        assert_eq!(cycles.len(), 1, "{cycles:?}");
        let text = cycles[0].to_string();
        assert!(text.starts_with("egressdns ->"), "{text}");
        assert!(text.ends_with("-> egressdns"), "{text}");
        assert!(text.contains("127.0.0.1:15353"), "{text}");
    }

    /// A wildcard listener owns the port on every local address, so an upstream on
    /// loopback at that port is still us.
    #[test]
    fn a_wildcard_listener_catches_a_loopback_upstream_on_the_same_port() {
        let c = config(
            "upstreams = [\"127.0.0.1:15354\"]\nproxies = []\n\n[server]\n\
             udp_listen = [\"0.0.0.0:15354\"]\ntcp_listen = [\"0.0.0.0:15354\"]\n\
             allow_from = [\"127.0.0.0/8\"]\n",
        );
        assert_eq!(detect_cycles(&c).len(), 1);
    }

    #[test]
    fn an_ordinary_external_upstream_is_not_a_cycle() {
        let c = config(
            "upstreams = [\"9.9.9.9\"]\nproxies = []\n\n[server]\n\
             udp_listen = [\"127.0.0.1:15355\"]\ntcp_listen = [\"127.0.0.1:15355\"]\n",
        );
        assert!(detect_cycles(&c).is_empty());
    }

    /// Applying resolved addresses must not overwrite one that was already known.
    #[tokio::test]
    async fn applying_addresses_only_fills_empty_servers() {
        let mut c = config(
            "upstreams = [\"tls://a.example?addr=10.0.0.1\", \"tls://b.example\"]\nproxies = []\n",
        );
        apply(&mut c, "b.example", &["10.0.0.2".parse().expect("ip")]);
        let servers = &c.upstream.groups[0].servers;
        let a = servers
            .iter()
            .find(|s| s.server_name.as_deref() == Some("a.example"))
            .expect("a");
        let b = servers
            .iter()
            .find(|s| s.server_name.as_deref() == Some("b.example"))
            .expect("b");
        assert_eq!(a.addresses, vec!["10.0.0.1".parse::<IpAddr>().expect("ip")]);
        assert_eq!(b.addresses, vec!["10.0.0.2".parse::<IpAddr>().expect("ip")]);
    }

    /// Resolution goes through the configured bare-IP resolver rather than the system
    /// one when a seed is available.
    #[tokio::test]
    async fn a_seed_resolver_answers_the_bootstrap_lookup() {
        // A UDP responder that answers any A query with one address.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let seed = socket.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = hickory_proto::op::Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut resp = hickory_proto::op::Message::response(req.id, req.metadata.op_code);
                resp.add_queries(req.queries.iter().cloned());
                if let Some(q) = req.queries.first() {
                    if q.query_type() == hickory_proto::rr::RecordType::A {
                        resp.add_answer(hickory_proto::rr::Record::from_rdata(
                            q.name().clone(),
                            300,
                            hickory_proto::rr::RData::A("10.9.9.9".parse().expect("ip")),
                        ));
                    }
                }
                if let Ok(bytes) = resp.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });

        let addrs = lookup_via("dns.internal.example", &[seed])
            .await
            .expect("the seed answers");
        assert_eq!(addrs, vec!["10.9.9.9".parse::<IpAddr>().expect("ip")]);
    }
}
