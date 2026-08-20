//! Deployment diagnosis.
//!
//! `doctor` answers one question: if this configuration were activated on this host right
//! now, what would break? It runs *before* a cutover, without the daemon, and it reports
//! evidence rather than opinions — the address that is already bound, the PID that owns
//! it, the exact cycle in a bootstrap dependency graph.
//!
//! Every check reports one of five states. `Fail` is reserved for something that will
//! actually stop the resolver from serving; `Warning` is something an operator should
//! know but that still resolves; `NotTested` is honest about a check this invocation
//! could not perform, and is never silently upgraded to `Pass`.
//!
//! Nothing here runs on the request path.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::config::Config;

pub mod probes;

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// The check ran and found nothing wrong.
    Pass,
    /// The check ran and found something an operator should know about.
    Warning,
    /// The check ran and found something that will stop the resolver working.
    Fail,
    /// The check does not apply to this configuration.
    NotApplicable,
    /// The check could not be performed. Never treat this as a pass.
    NotTested,
}

impl Status {
    /// Fixed-width label used by the human-readable renderer.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warning => "WARNING",
            Self::Fail => "FAIL",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::NotTested => "NOT_TESTED",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    /// Stable identifier, safe to match on in scripts.
    pub id: &'static str,
    /// What was checked.
    pub title: &'static str,
    /// Outcome.
    pub status: Status,
    /// Evidence: what was actually observed.
    pub detail: String,
    /// What to do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Check {
    fn new(
        id: &'static str,
        title: &'static str,
        status: Status,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            title,
            status,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// A complete diagnosis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    /// Every check, in the order they were run.
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether any check found a condition that stops the resolver working.
    pub fn has_failure(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    /// Whether any check raised a warning.
    pub fn has_warning(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Warning)
    }

    /// Count of each status, for the summary line.
    pub fn tally(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for c in &self.checks {
            *out.entry(c.status.label()).or_insert(0) += 1;
        }
        out
    }

    /// Process exit code: non-zero when a critical check failed.
    pub fn exit_code(&self) -> u8 {
        if self.has_failure() {
            2
        } else {
            0
        }
    }
}

/// What the daemon would listen on, derived from configuration.
fn listeners(config: &Config) -> Vec<(SocketAddr, &'static str)> {
    let mut out = Vec::new();
    for a in &config.server.udp_listen {
        out.push((*a, "udp"));
    }
    for a in &config.server.tcp_listen {
        out.push((*a, "tcp"));
    }
    out
}

/// Run every check that can be run against `config` on this host.
///
/// `config_path` is reported in permission diagnostics. When `config` failed to load the
/// caller passes `None` and only the file-level checks run.
pub fn run(config: &Config, config_path: &Path) -> Report {
    let mut checks = Vec::new();

    checks.push(check_config_readable(config_path));
    checks.extend(check_listeners(config));
    checks.extend(check_loops(config));
    checks.push(check_acl(config));
    checks.push(check_resolv_conf(config));
    checks.extend(check_permissions(config, config_path));
    checks.push(check_privileged_ports(config));
    checks.push(check_address_families(config));
    checks.extend(check_upstream_reachability(config));
    checks.push(check_systemd());

    Report { checks }
}

/// How long a single reachability probe may take.
const REACH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2_500);

/// Ceiling on the addresses probed, so a large configuration cannot make `doctor` slow.
const REACH_MAX_TARGETS: usize = 24;

/// Test whether the configured upstreams can actually be reached from this host.
///
/// This is the check that distinguishes "the resolver is broken" from "this network
/// filters port 853". Both produce SERVFAIL on every query and identical logs; only an
/// egress test tells them apart.
///
/// One reachable upstream is enough to resolve, so a single unreachable server is a
/// warning and *every* server being unreachable is a failure.
fn check_upstream_reachability(config: &Config) -> Vec<Check> {
    let mut out = Vec::new();
    let mut reachable = 0usize;
    let mut tested = 0usize;
    let mut unreachable: Vec<String> = Vec::new();
    let mut untested: Vec<String> = Vec::new();

    'groups: for group in &config.upstream.groups {
        for server in group.servers.iter().filter(|s| s.enabled) {
            let port = server.effective_port();
            for addr in &server.addresses {
                if tested + untested.len() >= REACH_MAX_TARGETS {
                    break 'groups;
                }
                let sock = SocketAddr::new(*addr, port);
                let label = format!("{} {}/{sock}", server.name, server.transport.label());
                let result = match server.transport {
                    crate::config::TransportKind::Udp => {
                        probes::udp_dns_reachable(sock, REACH_TIMEOUT)
                    }
                    // DoQ and DoH3 ride QUIC. A UDP probe cannot distinguish "filtered"
                    // from "this endpoint does not answer plain DNS", so rather than
                    // guess, they are reported as untested.
                    crate::config::TransportKind::Doq | crate::config::TransportKind::Doh3 => {
                        untested.push(label);
                        continue;
                    }
                    _ => probes::tcp_reachable(sock, REACH_TIMEOUT),
                };
                tested += 1;
                match result {
                    Ok(()) => reachable += 1,
                    Err(e) => unreachable.push(format!("{label}: {e}")),
                }
            }
        }
    }

    if tested == 0 {
        out.push(Check::new(
            "upstream.reachable",
            "Configured upstreams are reachable",
            Status::NotTested,
            if untested.is_empty() {
                String::from("no upstream address could be probed")
            } else {
                format!(
                    "only QUIC-based upstreams are configured, which this check does \
                     not probe: {}",
                    untested.join(", ")
                )
            },
        ));
        return out;
    }

    if reachable == 0 {
        out.push(
            Check::new(
                "upstream.reachable",
                "Configured upstreams are reachable",
                Status::Fail,
                format!(
                    "none of the {tested} probed upstream endpoints answered: {}",
                    unreachable.join("; ")
                ),
            )
            .with_remedy(
                "every query will SERVFAIL. If the encrypted ports are filtered on this \
                 network, configure an upstream whose transport is permitted here",
            ),
        );
    } else if !unreachable.is_empty() {
        out.push(
            Check::new(
                "upstream.reachable",
                "Configured upstreams are reachable",
                Status::Warning,
                format!(
                    "{reachable} of {tested} probed upstream endpoints answered; \
                     unreachable: {}",
                    unreachable.join("; ")
                ),
            )
            .with_remedy(
                "resolution still works through the reachable upstreams, but the dead \
                 ones cost latency on every fallback",
            ),
        );
    } else {
        out.push(Check::new(
            "upstream.reachable",
            "Configured upstreams are reachable",
            Status::Pass,
            format!("all {tested} probed upstream endpoints answered"),
        ));
    }

    if !untested.is_empty() {
        out.push(Check::new(
            "upstream.quic_untested",
            "QUIC upstreams were not probed",
            Status::NotTested,
            format!(
                "DoQ and DoH3 endpoints are not probed by this check: {}",
                untested.join(", ")
            ),
        ));
    }
    out
}

fn check_config_readable(path: &Path) -> Check {
    match std::fs::metadata(path) {
        Ok(_) => Check::new(
            "config.readable",
            "Configuration file is readable",
            Status::Pass,
            format!("{} is present and readable", path.display()),
        ),
        Err(e) => Check::new(
            "config.readable",
            "Configuration file is readable",
            Status::Fail,
            format!("{}: {e}", path.display()),
        )
        .with_remedy("check the path and the service user's read permission"),
    }
}

/// Detect whether each configured listen address is already owned.
///
/// Ownership is established by actually trying to bind, which is the only test that
/// matches what the daemon will do at start-up. When the bind fails the owning process is
/// resolved from `/proc` so the operator gets a name and a PID rather than `EADDRINUSE`.
fn check_listeners(config: &Config) -> Vec<Check> {
    let mut out = Vec::new();
    let sockets = probes::listening_sockets();

    for (addr, proto) in listeners(config) {
        let state = match proto {
            "udp" => probes::udp_port_state(addr),
            _ => probes::tcp_port_state(addr),
        };
        let check = match state {
            probes::PortState::Free => Check::new(
                "listener.available",
                "Configured listen addresses are free",
                Status::Pass,
                format!("{proto}/{addr} is available"),
            ),
            // An address held by our own running daemon is the expected state on a live
            // host, not a conflict. Reporting it as one makes `doctor` useless for
            // checking a deployment that is already up, which is when operators reach
            // for it most.
            probes::PortState::InUse => match probes::owner_of(&sockets, addr, proto) {
                Some(owner) if owner.is_egressdns() => Check::new(
                    "listener.available",
                    "Configured listen addresses are free",
                    Status::Pass,
                    format!("{proto}/{addr} is held by the running EgressDNS instance, {owner}"),
                ),
                Some(owner) => Check::new(
                    "listener.conflict",
                    "Configured listen addresses are free",
                    Status::Fail,
                    format!("{proto}/{addr} is already owned by {owner}"),
                )
                .with_remedy(format!(
                    "stop or reconfigure {owner}, or move EgressDNS to another address; \
                     never disable another resolver without a rollback path"
                )),
                None => Check::new(
                    "listener.conflict",
                    "Configured listen addresses are free",
                    Status::Fail,
                    format!(
                        "{proto}/{addr} is already in use; the owning process could not \
                         be identified"
                    ),
                )
                .with_remedy(
                    "run as root so /proc can be read, or inspect with `ss -lnpu` / `ss -lnpt`",
                ),
            },
            // Not a conflict. Whether the port is free is genuinely unknown from here,
            // and `privilege.bind` already reports the privilege problem itself.
            probes::PortState::PermissionDenied => Check::new(
                "listener.available",
                "Configured listen addresses are free",
                Status::NotTested,
                format!(
                    "{proto}/{addr} could not be bound by this process (permission \
                     denied), so ownership is unknown; re-run as root to test it"
                ),
            ),
            probes::PortState::Unknown(e) => Check::new(
                "listener.available",
                "Configured listen addresses are free",
                Status::Warning,
                format!("{proto}/{addr} could not be tested: {e}"),
            ),
        };
        out.push(check);
    }
    if out.is_empty() {
        out.push(Check::new(
            "listener.available",
            "Configured listen addresses are free",
            Status::Warning,
            "no listen address is configured",
        ));
    }
    out
}

/// Detect configurations in which the resolver would ask itself.
///
/// Three shapes are caught: an upstream that is literally one of our own listeners, an
/// upstream on a local address that is a known stub resolver, and an upstream that is a
/// local address on the DNS port where the dependency cannot be proven acyclic.
fn check_loops(config: &Config) -> Vec<Check> {
    let mut out = Vec::new();
    let own: HashSet<SocketAddr> = listeners(config)
        .into_iter()
        .map(|(a, _)| a)
        .flat_map(expand_wildcard)
        .collect();
    let local = probes::local_addresses();

    let mut direct = Vec::new();
    let mut stub = Vec::new();
    let mut local_dns = Vec::new();

    for group in &config.upstream.groups {
        for server in group.servers.iter().filter(|s| s.enabled) {
            let port = server.effective_port();
            for addr in &server.addresses {
                let sock = SocketAddr::new(*addr, port);
                if own.contains(&sock) {
                    direct.push(format!("{} -> {sock} -> {}", server.name, sock));
                } else if probes::is_known_stub(*addr) {
                    stub.push(format!("{} -> {sock}", server.name));
                } else if local.contains(addr) && port == 53 {
                    local_dns.push(format!("{} -> {sock}", server.name));
                }
            }
        }
    }

    out.push(if direct.is_empty() {
        Check::new(
            "loop.direct",
            "No upstream points back at our own listener",
            Status::Pass,
            "no configured upstream matches a configured listen address",
        )
    } else {
        Check::new(
            "loop.direct",
            "No upstream points back at our own listener",
            Status::Fail,
            format!("forwarding cycle: {}", direct.join("; ")),
        )
        .with_remedy("point the upstream at a real recursive resolver, not at EgressDNS itself")
    });

    out.push(if stub.is_empty() {
        Check::new(
            "loop.stub",
            "No upstream is a local stub resolver",
            Status::Pass,
            "no configured upstream is a known local stub address",
        )
    } else {
        Check::new(
            "loop.stub",
            "No upstream is a local stub resolver",
            Status::Fail,
            format!(
                "upstream is a local stub resolver, which is normally configured to \
                 forward back to this host: {}",
                stub.join("; ")
            ),
        )
        .with_remedy(
            "use the upstream the stub itself forwards to, or an external resolver; \
             forwarding to 127.0.0.53 while systemd-resolved forwards here is a cycle",
        )
    });

    out.push(if local_dns.is_empty() {
        Check::new(
            "loop.local",
            "No upstream is a local address on the DNS port",
            Status::Pass,
            "no configured upstream is a local interface address on port 53",
        )
    } else {
        Check::new(
            "loop.local",
            "No upstream is a local address on the DNS port",
            Status::Warning,
            format!(
                "upstream is a local address on port 53; this is legal only if that \
                 service does not forward back here: {}",
                local_dns.join("; ")
            ),
        )
        .with_remedy("prove the dependency is acyclic, or use a distinct upstream")
    });

    out
}

/// A wildcard listener occupies the port on every local address, so a loop check against
/// it has to consider the concrete addresses it will actually answer on.
fn expand_wildcard(addr: SocketAddr) -> Vec<SocketAddr> {
    if !addr.ip().is_unspecified() {
        return vec![addr];
    }
    let mut out = vec![addr];
    for ip in probes::local_addresses() {
        if ip.is_ipv4() == addr.is_ipv4() {
            out.push(SocketAddr::new(ip, addr.port()));
        }
    }
    out
}

/// Check that the ACL admits somebody, and that it does not admit everybody by accident.
fn check_acl(config: &Config) -> Check {
    let allow = config.effective_allow_from();
    let allow = &allow;
    if allow.is_empty() {
        return Check::new(
            "acl.coverage",
            "Client ACL admits the intended clients",
            Status::Fail,
            "server.allow_from is empty, so every client is refused",
        )
        .with_remedy(
            "list the client networks that should be served, e.g. [\"127.0.0.0/8\", \"::1/128\"]",
        );
    }

    // Constants rather than parsed literals: nothing on a production path should be able
    // to panic, however obviously well-formed the input looks.
    let loopback_v4 = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let loopback_v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    let covers_loopback = allow.iter().any(|n| n.contains(&loopback_v4))
        || allow.iter().any(|n| n.contains(&loopback_v6));

    let world = allow.iter().any(|n| n.prefix_len() == 0);
    let public_listener = listeners(config).iter().any(|(a, _)| {
        let ip = a.ip();
        ip.is_unspecified() || !probes::is_private_or_loopback(ip)
    });

    if world && public_listener {
        return Check::new(
            "acl.open_resolver",
            "Client ACL admits the intended clients",
            Status::Fail,
            "server.allow_from admits every address while a non-loopback listener is \
             configured: this is an open resolver",
        )
        .with_remedy("restrict server.allow_from to the LAN prefixes that should be served");
    }

    if !covers_loopback {
        return Check::new(
            "acl.coverage",
            "Client ACL admits the intended clients",
            Status::Warning,
            "server.allow_from does not cover loopback, so local health checks and \
             locally originated queries will be refused",
        )
        .with_remedy("add 127.0.0.0/8 and ::1/128 unless local clients are deliberately excluded");
    }

    Check::new(
        "acl.coverage",
        "Client ACL admits the intended clients",
        Status::Pass,
        format!(
            "{} client network(s) permitted, including loopback",
            allow.len()
        ),
    )
}

/// Classify `/etc/resolv.conf` without touching it.
fn check_resolv_conf(config: &Config) -> Check {
    let path = Path::new("/etc/resolv.conf");
    let kind = probes::classify_resolv_conf(path);
    let Some(kind) = kind else {
        return Check::new(
            "resolv_conf.kind",
            "System resolver configuration is understood",
            Status::NotTested,
            "/etc/resolv.conf is not present or not readable",
        );
    };

    let points_here = probes::resolv_conf_nameservers(path).iter().any(|ip| {
        listeners(config)
            .iter()
            .any(|(a, _)| a.ip() == *ip || (a.ip().is_unspecified() && probes::is_loopback(*ip)))
    });

    let detail = format!(
        "{kind}; {}",
        if points_here {
            "already points at an EgressDNS listener"
        } else {
            "does not currently point at an EgressDNS listener"
        }
    );

    match kind {
        probes::ResolvConf::SystemdStub => Check::new(
            "resolv_conf.kind",
            "System resolver configuration is understood",
            Status::Warning,
            detail,
        )
        .with_remedy(
            "this is a systemd-resolved stub symlink; replacing it blindly will be undone. \
             Either point systemd-resolved at EgressDNS with DNS=/DNSStubListener=no, or \
             replace the symlink deliberately as part of the cutover",
        ),
        _ => Check::new(
            "resolv_conf.kind",
            "System resolver configuration is understood",
            Status::Pass,
            detail,
        ),
    }
}

/// Verify the paths the daemon must read and write.
fn check_permissions(config: &Config, config_path: &Path) -> Vec<Check> {
    let mut out = Vec::new();

    if config.storage.enabled {
        let dir = config
            .storage
            .path
            .parent()
            .unwrap_or_else(|| Path::new("/"));
        out.push(match probes::writable_dir(dir) {
            Ok(()) => Check::new(
                "permissions.state",
                "State directory is writable",
                Status::Pass,
                format!("{} is writable", dir.display()),
            ),
            Err(e) => Check::new(
                "permissions.state",
                "State directory is writable",
                Status::Fail,
                format!("{}: {e}", dir.display()),
            )
            .with_remedy("create the directory and give the service user write permission"),
        });
    } else {
        out.push(Check::new(
            "permissions.state",
            "State directory is writable",
            Status::NotApplicable,
            "storage is disabled",
        ));
    }

    if let Some(anchor) = config.dnssec.trust_anchor_file.as_deref() {
        out.push(match std::fs::File::open(anchor) {
            Ok(_) => Check::new(
                "permissions.trust_anchor",
                "DNSSEC trust anchors are readable",
                Status::Pass,
                format!("{} is readable", anchor.display()),
            ),
            Err(e) => Check::new(
                "permissions.trust_anchor",
                "DNSSEC trust anchors are readable",
                Status::Fail,
                format!("{}: {e}", anchor.display()),
            )
            .with_remedy("validation fails closed, so an unreadable anchor file stops resolution"),
        });
    } else {
        out.push(Check::new(
            "permissions.trust_anchor",
            "DNSSEC trust anchors are readable",
            Status::NotApplicable,
            "no trust anchor file is configured; the compiled-in root keys are used",
        ));
    }

    if config.admin.enabled {
        let dir = config
            .admin
            .socket
            .parent()
            .unwrap_or_else(|| Path::new("/"));
        out.push(match probes::writable_dir(dir) {
            Ok(()) => Check::new(
                "permissions.admin_socket",
                "Administration socket directory is writable",
                Status::Pass,
                format!("{} is writable", dir.display()),
            ),
            Err(e) => Check::new(
                "permissions.admin_socket",
                "Administration socket directory is writable",
                Status::Warning,
                format!("{}: {e}", dir.display()),
            )
            .with_remedy(
                "systemd creates this via RuntimeDirectory; it may not exist before first start",
            ),
        });
    }

    let _ = config_path;
    out
}

/// Binding a port below 1024 needs either root or `CAP_NET_BIND_SERVICE`.
fn check_privileged_ports(config: &Config) -> Check {
    let privileged: Vec<String> = listeners(config)
        .into_iter()
        .filter(|(a, _)| a.port() < 1024)
        .map(|(a, p)| format!("{p}/{a}"))
        .collect();

    if privileged.is_empty() {
        return Check::new(
            "privilege.bind",
            "Privileged ports can be bound",
            Status::NotApplicable,
            "no listener uses a port below 1024",
        );
    }

    if probes::is_root() {
        return Check::new(
            "privilege.bind",
            "Privileged ports can be bound",
            Status::Pass,
            format!("running as root; {} can be bound", privileged.join(", ")),
        );
    }

    match probes::has_net_bind_service() {
        Some(true) => Check::new(
            "privilege.bind",
            "Privileged ports can be bound",
            Status::Pass,
            format!(
                "CAP_NET_BIND_SERVICE is present; {} can be bound",
                privileged.join(", ")
            ),
        ),
        Some(false) => Check::new(
            "privilege.bind",
            "Privileged ports can be bound",
            Status::Fail,
            format!(
                "not root and CAP_NET_BIND_SERVICE is absent, so {} cannot be bound",
                privileged.join(", ")
            ),
        )
        .with_remedy("add AmbientCapabilities=CAP_NET_BIND_SERVICE to the systemd unit"),
        None => Check::new(
            "privilege.bind",
            "Privileged ports can be bound",
            Status::NotTested,
            "capability state could not be read from /proc/self/status",
        ),
    }
}

/// Report which address families this host can actually originate traffic on.
fn check_address_families(config: &Config) -> Check {
    let v4 = probes::can_originate_v4();
    let v6 = probes::can_originate_v6();

    let needs_v6 = config.upstream.groups.iter().any(|g| {
        g.servers
            .iter()
            .filter(|s| s.enabled)
            .any(|s| s.addresses.iter().any(|a| a.is_ipv6()))
    });

    match (v4, v6, needs_v6) {
        (true, true, _) => Check::new(
            "network.families",
            "Required address families are usable",
            Status::Pass,
            "IPv4 and IPv6 egress are both available",
        ),
        (true, false, true) => Check::new(
            "network.families",
            "Required address families are usable",
            Status::Warning,
            "IPv6 egress is unavailable but IPv6 upstreams are configured; those routes \
             will be skipped until IPv6 returns",
        )
        .with_remedy("this is survivable — IPv4 routes still answer — but the IPv6 upstreams are dead weight"),
        (true, false, false) => Check::new(
            "network.families",
            "Required address families are usable",
            Status::Pass,
            "IPv4 egress is available; no IPv6 upstream is configured",
        ),
        (false, true, _) => Check::new(
            "network.families",
            "Required address families are usable",
            Status::Warning,
            "IPv4 egress appears unavailable",
        ),
        (false, false, _) => Check::new(
            "network.families",
            "Required address families are usable",
            Status::Fail,
            "neither IPv4 nor IPv6 egress is available",
        )
        .with_remedy("check routing and firewall policy; no upstream can be reached"),
    }
}

/// Report the systemd unit state, when systemd is present.
fn check_systemd() -> Check {
    match probes::systemd_unit_state("egressdns.service") {
        None => Check::new(
            "systemd.unit",
            "systemd unit state",
            Status::NotApplicable,
            "systemctl is not available on this host",
        ),
        Some(state) if state.trim() == "not-found" => Check::new(
            "systemd.unit",
            "systemd unit state",
            Status::NotApplicable,
            "egressdns.service is not installed",
        ),
        Some(state) => Check::new(
            "systemd.unit",
            "systemd unit state",
            Status::Pass,
            format!("egressdns.service is {}", state.trim()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port number free on both UDP and TCP at the moment of the call.
    ///
    /// The doctor tests run in parallel and each one binds its configured listeners, so a
    /// shared fixed port makes them fail each other rather than the code.
    fn free_port() -> u16 {
        for _ in 0..64 {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let port = udp.local_addr().expect("addr").port();
            drop(udp);
            if let Ok(tcp) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                drop(tcp);
                return port;
            }
        }
        panic!("no port free on both UDP and TCP");
    }

    fn base_config(extra: &str) -> Config {
        let port = free_port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = ["127.0.0.1:{port}"]
allow_from = ["127.0.0.0/8", "::1/128"]

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "up"
transport = "udp"
addresses = ["9.9.9.9"]
{extra}
"#
        );
        Config::from_toml(&text, "test").expect("valid test configuration")
    }

    fn check<'a>(report: &'a Report, id: &str) -> &'a Check {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("check {id} missing from report"))
    }

    #[test]
    fn a_clean_configuration_reports_no_failure() {
        let config = base_config("");
        let report = run(&config, Path::new("/etc/hostname"));
        assert!(
            !report.has_failure(),
            "unexpected failures: {:?}",
            report
                .checks
                .iter()
                .filter(|c| c.status == Status::Fail)
                .collect::<Vec<_>>()
        );
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn an_upstream_pointing_at_our_own_listener_is_a_failure() {
        // The upstream is exactly the configured listen address.
        let port = free_port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = ["127.0.0.1:{port}"]
allow_from = ["127.0.0.0/8"]

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "self"
transport = "udp"
addresses = ["127.0.0.1"]
port = {port}
"#
        );
        let config = Config::from_toml(&text, "test").expect("valid");
        let report = run(&config, Path::new("/etc/hostname"));
        let c = check(&report, "loop.direct");
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(c.detail.contains(&format!("127.0.0.1:{port}")));
        assert!(report.has_failure());
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn the_systemd_stub_resolver_as_an_upstream_is_a_failure() {
        let port = free_port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = ["127.0.0.1:{port}"]
allow_from = ["127.0.0.0/8"]

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "stub"
transport = "udp"
addresses = ["127.0.0.53"]
"#
        );
        let config = Config::from_toml(&text, "test").expect("valid");
        let report = run(&config, Path::new("/etc/hostname"));
        let c = check(&report, "loop.stub");
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(c.detail.contains("127.0.0.53"));
    }

    #[test]
    fn an_empty_acl_refuses_every_client_and_fails() {
        let port = free_port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = ["127.0.0.1:{port}"]
allow_from = []

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "up"
transport = "udp"
addresses = ["9.9.9.9"]
"#
        );
        let config = Config::from_toml(&text, "test").expect("valid");
        let report = run(&config, Path::new("/etc/hostname"));
        let c = check(&report, "acl.coverage");
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
    }

    #[test]
    fn an_acl_that_excludes_the_client_subnet_warns() {
        // Serves a LAN prefix but not loopback, so local health checks are refused.
        let port = free_port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = ["127.0.0.1:{port}"]
allow_from = ["10.0.0.0/8"]

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "up"
transport = "udp"
addresses = ["9.9.9.9"]
"#
        );
        let config = Config::from_toml(&text, "test").expect("valid");
        let report = run(&config, Path::new("/etc/hostname"));
        let c = check(&report, "acl.coverage");
        assert_eq!(c.status, Status::Warning, "{}", c.detail);
    }

    /// A bound port must be reported as a conflict, with the address named.
    #[test]
    fn a_port_already_in_use_is_reported_as_a_conflict() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let text = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:{port}"]
tcp_listen = []
allow_from = ["127.0.0.0/8"]

[storage]
enabled = false

[admin]
enabled = false

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "up"
transport = "udp"
addresses = ["9.9.9.9"]
"#
        );
        let config = Config::from_toml(&text, "test").expect("valid");
        let report = run(&config, Path::new("/etc/hostname"));
        let c = check(&report, "listener.conflict");
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(c.detail.contains(&port.to_string()));
    }

    #[test]
    fn statuses_serialise_as_stable_screaming_snake_case() {
        let json = serde_json::to_string(&Status::NotApplicable).expect("json");
        assert_eq!(json, "\"NOT_APPLICABLE\"");
    }
}
