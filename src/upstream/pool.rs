//! Upstream route definitions and connection pooling.
//!
//! One [`Route`] is the triple (configured server, transport, remote address). Connections
//! for the stream-oriented transports are created lazily, reused, and recreated after a
//! transport failure. Plain UDP has no persistent connection: hickory opens a fresh
//! randomised source port per query, which is what RFC 5452 wants.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message};
use hickory_resolver::config::{ConnectionConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::PoolContext;
use hickory_resolver::{ConnectionProvider, TlsConfig};
use parking_lot::Mutex as SyncMutex;
use rustls::RootCertStore;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;

use crate::config::proxy::ProxyEndpoint;
use crate::config::{
    EcsScope, SchedulerConfig, TransportKind, UpstreamConfig, UpstreamServerConfig,
};
use crate::error::ResolveError;
use crate::upstream::egress::{EgressPath, EgressProvider};
use crate::upstream::health::{AttemptOutcome, RouteHealth};

/// Stable identity of a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// Configured server name, used as a bounded metrics label.
    pub server: Arc<str>,
    /// Transport.
    pub transport: TransportKind,
    /// Remote address.
    pub addr: IpAddr,
    /// How this route leaves the host: `direct`, or a proxy identity.
    ///
    /// Part of the identity because a direct route and a proxied route to the same
    /// server are different paths with different failure modes, and each must carry its
    /// own health. They are *not* different authorities: see [`RouteKey::authority`].
    pub path: Arc<str>,
    /// Which resolver is actually answering.
    ///
    /// Cloudflare over DoH/3, Cloudflare over DoH/2, Cloudflare over IPv6 and Cloudflare
    /// through a proxy are four routes and **one** authority. Counting them as four
    /// independent opinions would let one operator's outage, or one operator's forged
    /// answer, look like a consensus.
    ///
    /// Derived conservatively: an encrypted endpoint is identified by the name its
    /// certificate must carry, and a plaintext one by its address, because that is all we
    /// can prove about it. When two things might be the same authority, they are treated
    /// as the same one — under-counting independence is the safe direction.
    pub authority: Arc<str>,
}

impl std::fmt::Display for RouteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.server,
            self.transport.label(),
            self.addr,
            self.path
        )
    }
}

/// RFC 7873 cookie state for one route.
#[derive(Debug, Clone)]
pub struct CookieState {
    /// The client cookie sent to this server.
    pub client: [u8; 8],
    /// The most recently learned server cookie.
    pub server: Option<Vec<u8>>,
}

impl CookieState {
    fn new(key: &RouteKey) -> Self {
        // The client cookie must be unpredictable and stable per (client, server) pair
        // for the lifetime of the association (RFC 7873 section 4).
        let mut seed = [0u8; 32];
        let text = key.to_string();
        let digest = crate::util::sha256(text.as_bytes());
        seed.copy_from_slice(&digest);
        let mut client = [0u8; 8];
        client.copy_from_slice(&seed[..8]);
        // Mix in per-process randomness so that two nodes do not share a client cookie.
        let random: u64 = rand::random();
        for (i, b) in client.iter_mut().enumerate() {
            *b ^= random.to_le_bytes()[i];
        }
        Self {
            client,
            server: None,
        }
    }
}

/// One upstream route.
pub struct Route {
    /// Identity.
    pub key: RouteKey,
    /// Static preference weight.
    pub weight: u32,
    /// Per-server ECS override.
    pub ecs: Option<EcsScope>,
    /// Whether DNS Cookies are used on this route.
    pub cookies_enabled: bool,
    /// Whether this server's AD bit may be trusted, subject to global policy.
    pub trust_ad: bool,
    /// How this route leaves the host.
    pub egress: EgressPath,
    /// Connection factory for this route's egress path.
    provider: EgressProvider,
    /// Whether this route exists only as the TCP companion of a configured UDP server.
    ///
    /// A companion is reachable for truncation retries and never for an ordinary query:
    /// an operator who configured UDP asked for UDP, and silently sending half the
    /// traffic over TCP would be a different deployment from the one they described.
    pub stream_companion: bool,
    connection_config: ConnectionConfig,
    connection: AsyncMutex<Option<DnsExchange<EgressProvider>>>,
    health: SyncMutex<RouteHealth>,
    cookie: SyncMutex<CookieState>,
}

impl Route {
    /// Read a snapshot of the route health.
    pub fn health(&self) -> RouteHealth {
        self.health.lock().clone()
    }

    /// Mutate the route health.
    pub fn with_health<R>(&self, f: impl FnOnce(&mut RouteHealth) -> R) -> R {
        let mut guard = self.health.lock();
        f(&mut guard)
    }

    /// Current cookie state.
    pub fn cookie(&self) -> CookieState {
        self.cookie.lock().clone()
    }

    /// Record a learned server cookie.
    pub fn set_server_cookie(&self, server: Option<Vec<u8>>) {
        self.cookie.lock().server = server;
    }

    /// Drop any pooled connection so the next attempt reconnects.
    pub async fn reset_connection(&self) {
        let mut guard = self.connection.lock().await;
        *guard = None;
    }

    /// Obtain a usable connection, creating one if necessary.
    async fn connection(&self, cx: &PoolContext) -> Result<DnsExchange<EgressProvider>, String> {
        {
            let guard = self.connection.lock().await;
            if let Some(conn) = guard.as_ref() {
                return Ok(conn.clone());
            }
        }
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let start = Instant::now();
        let future = self
            .provider
            .new_connection(self.key.addr, &self.connection_config, cx)
            .map_err(|e| crate::util::bounded(&e.to_string(), 160))?;
        let conn = future
            .await
            .map_err(|e| crate::util::bounded(&e.to_string(), 160))?;
        self.with_health(|h| h.record_connect(start.elapsed()));
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Send one request over this route.
    ///
    /// Returns the response together with the measured latency. A transport failure drops
    /// the pooled connection so the next attempt reconnects.
    pub async fn send(
        &self,
        cx: &PoolContext,
        message: Message,
        options: DnsRequestOptions,
        timeout: Duration,
    ) -> Result<(DnsResponse, Duration), (AttemptOutcome, String)> {
        let conn = match self.connection(cx).await {
            Ok(c) => c,
            Err(e) => return Err((AttemptOutcome::TransportError, e)),
        };
        let request = DnsRequest::new(message, options);
        let start = Instant::now();
        let result = tokio::time::timeout(timeout, conn.send(request).first_answer()).await;
        match result {
            Err(_) => {
                if self.key.transport.is_stream() {
                    self.reset_connection().await;
                }
                Err((AttemptOutcome::Timeout, "upstream timeout".to_string()))
            }
            Ok(Err(e)) => {
                let msg = crate::util::bounded(&e.to_string(), 160);
                if self.key.transport.is_stream() {
                    self.reset_connection().await;
                }
                Err((AttemptOutcome::TransportError, msg))
            }
            Ok(Ok(response)) => Ok((response, start.elapsed())),
        }
    }
}

/// A named group of routes plus its scheduling policy.
pub struct UpstreamGroup {
    /// Group name.
    pub name: Arc<str>,
    /// Member routes.
    pub routes: Vec<Arc<Route>>,
    /// Scheduling policy.
    pub scheduler: SchedulerConfig,
}

impl UpstreamGroup {
    /// Routes that use a stream transport, used for truncation retries.
    pub fn stream_routes(&self) -> Vec<Arc<Route>> {
        self.routes
            .iter()
            .filter(|r| r.key.transport.is_stream())
            .cloned()
            .collect()
    }
}

/// All configured groups.
pub struct UpstreamRegistry {
    groups: HashMap<Arc<str>, Arc<UpstreamGroup>>,
    default_group: Arc<str>,
    context: Arc<PoolContext>,
}

impl UpstreamRegistry {
    /// Build the registry from configuration.
    pub fn build(
        cfg: &UpstreamConfig,
        proxies: &[ProxyEndpoint],
        roots: Arc<RootCertStore>,
        query_timeout: Duration,
        edns_payload_len: u16,
    ) -> Result<Self, ResolveError> {
        let mut opts = ResolverOpts::default();
        opts.timeout = query_timeout;
        opts.edns_payload_len = edns_payload_len;
        opts.attempts = 1;
        opts.recursion_desired = true;
        // RFC 5452: randomise the case of the query name so that an off-path attacker must
        // guess it in addition to the query ID and source port.
        opts.case_randomization = true;
        opts.validate = false;
        opts.num_concurrent_reqs = 1;

        let mut tls = TlsConfig::new().map_err(|e| ResolveError::AllFailed {
            detail: crate::util::bounded(&e.to_string(), 120),
        })?;
        tls.config = crate::tls::client_config(Arc::clone(&roots), &[], cfg.tls.session_resumption);
        let context = Arc::new(PoolContext::new(opts, tls));

        // One provider per egress path, cloned into every route that uses it. Building
        // them once means a route's identity, its connection pool and its health all
        // refer to the same way out of this host.
        let mut paths: Vec<(EgressPath, EgressProvider)> = vec![(
            EgressPath::Direct,
            EgressProvider::direct(Arc::clone(&roots)),
        )];
        for proxy in proxies {
            let proxy = Arc::new(proxy.clone());
            paths.push((
                EgressPath::Proxy(Arc::clone(&proxy)),
                EgressProvider::through(proxy, Arc::clone(&roots)),
            ));
        }

        let mut groups = HashMap::new();
        for group in &cfg.groups {
            let mut routes = Vec::new();
            for server in group.servers.iter().filter(|s| s.enabled) {
                for addr in &server.addresses {
                    for (path, provider) in &paths {
                        // A proxy that cannot carry this transport is not a route. UDP,
                        // DoQ and DoH3 need datagrams, and no proxy implemented here
                        // carries them — offering the route anyway would produce a
                        // timeout rather than an error.
                        if !path_supports(path, server.transport) {
                            continue;
                        }

                        let connection_config = connection_config_for(server, *addr)?;
                        let key = RouteKey {
                            server: Arc::from(server.name.as_str()),
                            transport: server.transport,
                            addr: *addr,
                            path: Arc::from(path.id().as_str()),
                            authority: Arc::from(authority_of(server, *addr).as_str()),
                        };
                        let cookie = CookieState::new(&key);
                        routes.push(Arc::new(Route {
                            key,
                            weight: server.weight,
                            ecs: server.ecs.clone(),
                            cookies_enabled: server.cookies_effective(),
                            trust_ad: server.trust_ad,
                            stream_companion: false,
                            egress: path.clone(),
                            provider: provider.clone(),
                            connection_config,
                            connection: AsyncMutex::new(None),
                            health: SyncMutex::new(RouteHealth::new()),
                            cookie: SyncMutex::new(cookie),
                        }));

                        // RFC 1035 §4.2.1 and RFC 7766 §5: a truncated UDP answer is
                        // retried over TCP *to the same server*. Every UDP server
                        // therefore gets a companion TCP route to the same address and
                        // port, created here rather than demanded from the operator.
                        //
                        // Without it, an entirely reasonable UDP-only configuration turns
                        // every large answer into SERVFAIL, because a truncated answer
                        // must never be parsed opportunistically and there would be no
                        // stream transport to retry over. The companion is marked so it
                        // is used for truncation retries only and never chosen for an
                        // ordinary query.
                        //
                        // The companion is a *stream*, so unlike its UDP parent it can
                        // also exist on a proxied path.
                        if server.transport == TransportKind::Udp {
                            for (cpath, cprovider) in &paths {
                                let mut companion = ConnectionConfig::new(ProtocolConfig::Tcp);
                                companion.port = server.effective_port();
                                companion.bind_addr = server.bind_addr;
                                let key = RouteKey {
                                    server: Arc::from(server.name.as_str()),
                                    transport: TransportKind::Tcp,
                                    addr: *addr,
                                    path: Arc::from(cpath.id().as_str()),
                                    authority: Arc::from(authority_of(server, *addr).as_str()),
                                };
                                let cookie = CookieState::new(&key);
                                routes.push(Arc::new(Route {
                                    key,
                                    weight: server.weight,
                                    ecs: server.ecs.clone(),
                                    cookies_enabled: server.cookies_effective(),
                                    trust_ad: server.trust_ad,
                                    egress: cpath.clone(),
                                    provider: cprovider.clone(),
                                    connection_config: companion,
                                    connection: AsyncMutex::new(None),
                                    health: SyncMutex::new(RouteHealth::new()),
                                    cookie: SyncMutex::new(cookie),
                                    stream_companion: true,
                                }));
                            }
                        }
                        // The UDP parent exists only on the direct path, so its companion
                        // block runs once; break out rather than repeating it per proxy.
                        if server.transport == TransportKind::Udp {
                            break;
                        }
                    }
                }
            }
            let name: Arc<str> = Arc::from(group.name.as_str());
            groups.insert(
                Arc::clone(&name),
                Arc::new(UpstreamGroup {
                    name,
                    routes,
                    scheduler: group.scheduler.clone(),
                }),
            );
        }

        Ok(Self {
            groups,
            default_group: Arc::from(cfg.default_group.as_str()),
            context,
        })
    }

    /// Look up a group by name, falling back to the default group.
    pub fn group(&self, name: &str) -> Option<Arc<UpstreamGroup>> {
        self.groups
            .get(name)
            .cloned()
            .or_else(|| self.groups.get(&self.default_group).cloned())
    }

    /// The default group.
    pub fn default_group(&self) -> Option<Arc<UpstreamGroup>> {
        self.groups.get(&self.default_group).cloned()
    }

    /// All group names.
    pub fn group_names(&self) -> Vec<Arc<str>> {
        let mut names: Vec<Arc<str>> = self.groups.keys().cloned().collect();
        names.sort();
        names
    }

    /// The shared pool context.
    pub fn context(&self) -> &PoolContext {
        &self.context
    }

    /// Every route across every group.
    pub fn all_routes(&self) -> Vec<Arc<Route>> {
        let mut out = Vec::new();
        for g in self.groups.values() {
            out.extend(g.routes.iter().cloned());
        }
        out
    }

    /// Drop every pooled connection. Used when draining after a configuration reload.
    pub async fn drain(&self) {
        for route in self.all_routes() {
            route.reset_connection().await;
        }
    }
}

/// The resolver authority a route reaches.
///
/// An encrypted endpoint is its authentication name: whatever address we opened a socket
/// to, the certificate had to be for that name, so that is the identity we can actually
/// prove. A plaintext endpoint has no proven identity beyond the address it answered
/// from, so the address is used.
///
/// The consequence that matters: `https://dns.google/dns-query` and `tls://dns.google`
/// are one authority reached two ways, and `1.1.1.1` and `1.0.0.1` are two authorities
/// even though one operator runs both — because nothing in the protocol lets us prove
/// they are related.
fn authority_of(server: &UpstreamServerConfig, addr: IpAddr) -> String {
    match server.server_name.as_deref() {
        Some(name) => name.trim_end_matches('.').to_ascii_lowercase(),
        // Address *and* port. Two resolvers can share an address and differ only by port
        // — a co-located forwarder on 127.0.0.1:5353 beside one on 127.0.0.1:53 is two
        // independent resolvers, and collapsing them would mean one could corroborate
        // itself.
        None => SocketAddr::new(addr, server.effective_port()).to_string(),
    }
}

/// Whether `path` can carry `transport`.
///
/// The datagram transports need UDP, and no proxy implemented here carries datagrams.
/// Offering such a route would produce a timeout instead of an error, which is the worst
/// of both.
fn path_supports(path: &EgressPath, transport: TransportKind) -> bool {
    if transport.is_stream() {
        true
    } else {
        path.carries_udp()
    }
}

fn connection_config_for(
    server: &UpstreamServerConfig,
    _addr: IpAddr,
) -> Result<ConnectionConfig, ResolveError> {
    let port = server.effective_port();
    let protocol = match server.transport {
        TransportKind::Udp => ProtocolConfig::Udp,
        TransportKind::Tcp => ProtocolConfig::Tcp,
        TransportKind::Dot => ProtocolConfig::Tls {
            server_name: Arc::from(require_name(server)?),
        },
        TransportKind::Doh2 => ProtocolConfig::Https {
            server_name: Arc::from(require_name(server)?),
            path: Arc::from(server.path.as_deref().unwrap_or("/dns-query")),
        },
        TransportKind::Doq => ProtocolConfig::Quic {
            server_name: Arc::from(require_name(server)?),
        },
        TransportKind::Doh3 => ProtocolConfig::H3 {
            server_name: Arc::from(require_name(server)?),
            path: Arc::from(server.path.as_deref().unwrap_or("/dns-query")),
            disable_grease: false,
        },
    };
    let mut cfg = ConnectionConfig::new(protocol);
    cfg.port = port;
    cfg.bind_addr = server.bind_addr;
    Ok(cfg)
}

fn require_name(server: &UpstreamServerConfig) -> Result<&str, ResolveError> {
    server
        .server_name
        .as_deref()
        .ok_or_else(|| ResolveError::NoRoute {
            group: server.name.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{UpstreamGroupConfig, UpstreamTlsConfig};

    fn roots() -> Arc<RootCertStore> {
        crate::tls::install_crypto_provider();
        Arc::new(crate::tls::root_store(false, &[]).expect("roots"))
    }

    fn server(name: &str, transport: TransportKind, addr: &str) -> UpstreamServerConfig {
        UpstreamServerConfig {
            name: name.to_string(),
            transport,
            addresses: vec![addr.parse().expect("ip")],
            server_name: transport
                .is_encrypted()
                .then(|| "dns.example.test".to_string()),
            ..UpstreamServerConfig::default()
        }
    }

    fn registry(servers: Vec<UpstreamServerConfig>) -> UpstreamRegistry {
        let cfg = UpstreamConfig {
            default_group: "default".into(),
            groups: vec![UpstreamGroupConfig {
                name: "default".into(),
                servers,
                scheduler: SchedulerConfig::default(),
            }],
            tls: UpstreamTlsConfig::default(),
        };
        UpstreamRegistry::build(&cfg, &[], roots(), Duration::from_secs(2), 1232).expect("registry")
    }

    #[tokio::test]
    async fn every_transport_builds_a_route() {
        let reg = registry(vec![
            server("udp", TransportKind::Udp, "192.0.2.1"),
            server("tcp", TransportKind::Tcp, "192.0.2.2"),
            server("dot", TransportKind::Dot, "192.0.2.3"),
            server("doh2", TransportKind::Doh2, "192.0.2.4"),
            server("doh3", TransportKind::Doh3, "192.0.2.5"),
            server("doq", TransportKind::Doq, "192.0.2.6"),
        ]);
        let group = reg.default_group().expect("group");
        // Six configured servers plus one TCP companion for the UDP server.
        assert_eq!(group.routes.len(), 7);
        assert_eq!(
            group.routes.iter().filter(|r| r.stream_companion).count(),
            1,
            "only the UDP server gets a companion"
        );
        let transports: Vec<_> = group.routes.iter().map(|r| r.key.transport).collect();
        for t in [
            TransportKind::Udp,
            TransportKind::Tcp,
            TransportKind::Dot,
            TransportKind::Doh2,
            TransportKind::Doh3,
            TransportKind::Doq,
        ] {
            assert!(transports.contains(&t), "{t:?} missing");
        }
        assert_eq!(group.stream_routes().len(), 6);
    }

    /// A UDP-only configuration must still be able to satisfy RFC 7766.
    ///
    /// Truncated UDP answers are never parsed opportunistically, so without a stream
    /// route to retry over, every large answer from a UDP-only upstream would become
    /// SERVFAIL. The companion route exists so the operator does not have to know that.
    #[tokio::test]
    async fn a_udp_only_server_gets_a_tcp_companion_for_truncation_retries() {
        let reg = registry(vec![server("udp", TransportKind::Udp, "192.0.2.1")]);
        let group = reg.default_group().expect("group");
        assert_eq!(
            group.routes.len(),
            2,
            "one configured route plus a companion"
        );

        let companion = group
            .routes
            .iter()
            .find(|r| r.stream_companion)
            .expect("companion exists");
        assert_eq!(companion.key.transport, TransportKind::Tcp);
        assert_eq!(
            companion.key.addr,
            "192.0.2.1".parse::<std::net::IpAddr>().expect("ip"),
            "the retry goes to the same server, per RFC 1035 4.2.1"
        );
        assert_eq!(
            group.stream_routes().len(),
            1,
            "the companion is available as a stream route"
        );
    }

    /// An explicitly configured TCP server is not a companion and is used normally.
    #[tokio::test]
    async fn an_explicit_tcp_server_is_not_marked_as_a_companion() {
        let reg = registry(vec![server("tcp", TransportKind::Tcp, "192.0.2.2")]);
        let group = reg.default_group().expect("group");
        assert_eq!(group.routes.len(), 1);
        assert!(!group.routes[0].stream_companion);
    }

    #[tokio::test]
    async fn one_route_per_address() {
        let mut s = server("multi", TransportKind::Udp, "192.0.2.1");
        s.addresses.push("192.0.2.2".parse().expect("ip"));
        s.addresses.push("2001:db8::1".parse().expect("ip"));
        let reg = registry(vec![s]);
        let group = reg.default_group().expect("group");
        // Three addresses, each with a TCP companion.
        assert_eq!(group.routes.len(), 6);
        assert_eq!(
            group.routes.iter().filter(|r| !r.stream_companion).count(),
            3,
            "one configured route per address"
        );
    }

    #[tokio::test]
    async fn cookies_are_disabled_for_encrypted_transports() {
        let reg = registry(vec![
            server("udp", TransportKind::Udp, "192.0.2.1"),
            server("dot", TransportKind::Dot, "192.0.2.3"),
        ]);
        let group = reg.default_group().expect("group");
        for r in &group.routes {
            assert_eq!(r.cookies_enabled, !r.key.transport.is_encrypted());
        }
    }

    #[tokio::test]
    async fn client_cookies_differ_per_route() {
        let reg = registry(vec![
            server("a", TransportKind::Udp, "192.0.2.1"),
            server("b", TransportKind::Udp, "192.0.2.2"),
        ]);
        let group = reg.default_group().expect("group");
        assert_ne!(
            group.routes[0].cookie().client,
            group.routes[1].cookie().client
        );
    }

    #[tokio::test]
    async fn unknown_group_falls_back_to_default() {
        let reg = registry(vec![server("udp", TransportKind::Udp, "192.0.2.1")]);
        assert!(reg.group("does-not-exist").is_some());
        assert_eq!(
            &*reg.group("does-not-exist").expect("group").name,
            "default"
        );
    }
}
