//! Host inspection primitives used by [`super::run`].
//!
//! Everything here reads the live system: the routing stack, the socket tables, the
//! filesystem. Each function is written to degrade to "unknown" rather than to guess,
//! because a diagnosis that invents evidence is worse than one that admits it could not
//! look. Platform differences are confined to this file; the checks in [`super`] call the
//! same functions everywhere.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::fmt;
#[cfg(target_os = "linux")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

/// Whether the current process runs with full administrator rights (Windows) or as root
/// (Unix).
#[cfg(unix)]
pub fn is_root() -> bool {
    // Safe: `geteuid` cannot fail and takes no arguments.
    nix::unistd::geteuid().is_root()
}

/// Windows has no privileged-port concept, but full administrator rights are what the
/// "run as root" advice below means there.
#[cfg(windows)]
pub fn is_root() -> bool {
    is_elevated::is_elevated()
}

/// Whether the process may bind ports below 1024.
///
/// Returns `None` when the capability set could not be read, which is reported as
/// `NOT_TESTED` rather than assumed either way.
#[cfg(target_os = "linux")]
pub fn has_net_bind_service() -> Option<bool> {
    // CAP_NET_BIND_SERVICE is bit 10.
    const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status
        .lines()
        .find(|l| l.starts_with("CapEff:"))?
        .split_whitespace()
        .nth(1)?
        .to_string();
    let bits = u64::from_str_radix(&line, 16).ok()?;
    Some(bits & CAP_NET_BIND_SERVICE != 0)
}

/// Windows has no privileged-port concept: any process that is not explicitly denied can
/// bind port 53.
#[cfg(windows)]
pub fn has_net_bind_service() -> Option<bool> {
    Some(true)
}

/// Neither root nor capabilities are known on other platforms; report honestly.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn has_net_bind_service() -> Option<bool> {
    None
}

/// What a bind attempt revealed about a listen address.
///
/// The distinction matters more than it looks. A non-root process binding port 53 fails
/// with `EACCES`, not `EADDRINUSE`; treating every bind error as a conflict tells the
/// operator to go hunting for a resolver that is not running, which is a worse outcome
/// than saying nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// The address can be bound right now.
    Free,
    /// Something else already holds it.
    InUse,
    /// This process may not bind it, so ownership could not be determined.
    PermissionDenied,
    /// The bind failed for some other reason.
    Unknown(String),
}

fn classify_bind(result: std::io::Result<()>) -> PortState {
    match result {
        Ok(()) => PortState::Free,
        Err(e) => match e.kind() {
            std::io::ErrorKind::AddrInUse => PortState::InUse,
            std::io::ErrorKind::PermissionDenied => PortState::PermissionDenied,
            _ => PortState::Unknown(e.to_string()),
        },
    }
}

/// Whether a UDP listen address can be bound.
pub fn udp_port_state(addr: SocketAddr) -> PortState {
    // `SO_REUSEADDR` is deliberately not set: the question is whether the daemon could
    // take exclusive ownership, which is what its own bind will attempt.
    let state = classify_bind(std::net::UdpSocket::bind(addr).map(|_| ()));
    windows_exclusive_bind(state)
}

/// Whether a TCP listen address can be bound.
pub fn tcp_port_state(addr: SocketAddr) -> PortState {
    let state = classify_bind(std::net::TcpListener::bind(addr).map(|_| ()));
    windows_exclusive_bind(state)
}

/// Windows reports an exclusive-binding conflict as `WSAEACCES`, not `WSAEADDRINUSE`.
///
/// Windows has no privileged-port concept, so a permission failure there is never "this
/// process is not allowed to bind port 53" — it is either another socket holding an
/// exclusive bind or a system port reservation. Reporting `InUse` is strictly more
/// useful than the Unix reading of the same error code.
#[cfg(windows)]
fn windows_exclusive_bind(state: PortState) -> PortState {
    if state == PortState::PermissionDenied {
        PortState::InUse
    } else {
        state
    }
}

#[cfg(not(windows))]
fn windows_exclusive_bind(state: PortState) -> PortState {
    state
}

/// One listening socket read from the system socket tables.
#[derive(Debug, Clone)]
pub struct ListeningSocket {
    /// Local address.
    pub addr: SocketAddr,
    /// `"udp"` or `"tcp"`.
    pub proto: &'static str,
    /// Socket inode, used to find the owning process on Linux.
    pub inode: u64,
    /// Owning process id, when the platform reports it with the socket (Windows).
    pub pid: Option<u32>,
}

/// Every listening TCP and UDP socket this process is allowed to see.
#[cfg(target_os = "linux")]
pub fn listening_sockets() -> Vec<ListeningSocket> {
    let mut out = Vec::new();
    for (file, proto, v6) in [
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
    ] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            // TCP sockets are only interesting in the LISTEN state (0A); UDP has no
            // listen state, so every bound socket counts.
            if proto == "tcp" && f[3] != "0A" {
                continue;
            }
            let Some(addr) = parse_proc_addr(f[1], v6) else {
                continue;
            };
            let inode = f[9].parse::<u64>().unwrap_or(0);
            out.push(ListeningSocket {
                addr,
                proto,
                inode,
                pid: None,
            });
        }
    }
    out
}

/// Every listening TCP and UDP socket, with owning PIDs, from the IP helper API.
#[cfg(windows)]
pub fn listening_sockets() -> Vec<ListeningSocket> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    let mut out = Vec::new();
    let families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let Ok(sockets) = netstat2::get_sockets_info(families, protocols) else {
        return out;
    };
    for socket in sockets {
        let pid = socket.associated_pids.first().copied();
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                if tcp.state != netstat2::TcpState::Listen {
                    continue;
                }
                out.push(ListeningSocket {
                    addr: SocketAddr::new(tcp.local_addr, tcp.local_port),
                    proto: "tcp",
                    inode: 0,
                    pid,
                });
            }
            ProtocolSocketInfo::Udp(udp) => {
                out.push(ListeningSocket {
                    addr: SocketAddr::new(udp.local_addr, udp.local_port),
                    proto: "udp",
                    inode: 0,
                    pid,
                });
            }
        }
    }
    out
}

/// No socket table is readable on this platform.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn listening_sockets() -> Vec<ListeningSocket> {
    Vec::new()
}

/// Parse the `HEXADDR:HEXPORT` form used throughout `/proc/net`.
#[cfg(target_os = "linux")]
fn parse_proc_addr(field: &str, v6: bool) -> Option<SocketAddr> {
    let (a, p) = field.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if v6 {
        if a.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        // Each 32-bit word is little-endian within itself.
        for word in 0..4 {
            let raw = u32::from_str_radix(&a[word * 8..word * 8 + 8], 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&raw.to_le_bytes());
        }
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        if a.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(a, 16).ok()?;
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())),
            port,
        ))
    }
}

/// Map socket inodes to `(name, pid)`, for as many processes as we may inspect.
#[cfg(target_os = "linux")]
fn inode_owners() -> HashMap<u64, (String, u32)> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| String::from("?"));
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(text) = target.to_str() else {
                continue;
            };
            if let Some(rest) = text.strip_prefix("socket:[") {
                if let Ok(inode) = rest.trim_end_matches(']').parse::<u64>() {
                    out.entry(inode).or_insert_with(|| (comm.clone(), pid));
                }
            }
        }
    }
    out
}

/// Who holds a listening address.
#[derive(Debug, Clone)]
pub struct SocketOwner {
    /// Process name from `/proc/<pid>/comm`, when it could be read.
    pub comm: Option<String>,
    /// Owning process, when it could be identified.
    pub pid: Option<u32>,
    /// The socket address actually held, which may be a wildcard.
    pub addr: SocketAddr,
    /// `"udp"` or `"tcp"`.
    pub proto: &'static str,
}

impl fmt::Display for SocketOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.comm, self.pid) {
            (Some(comm), Some(pid)) => {
                write!(f, "{comm} (pid {pid}) on {}/{}", self.proto, self.addr)
            }
            (Some(comm), None) => write!(f, "{comm} on {}/{}", self.proto, self.addr),
            (None, Some(pid)) => write!(f, "pid {pid} on {}/{}", self.proto, self.addr),
            _ => write!(f, "an unidentified process on {}/{}", self.proto, self.addr),
        }
    }
}

impl SocketOwner {
    /// Whether this is an EgressDNS daemon rather than a foreign resolver.
    pub fn is_egressdns(&self) -> bool {
        self.comm.as_deref() == Some("egressdnsd")
    }
}

/// Identify the process holding `addr` for `proto`, if it can be determined.
///
/// A wildcard socket owns the port on every address *of its own family*: an
/// `0.0.0.0:53` socket does not hold `[::]:53`, and reporting that it does turns one
/// listener into four phantom conflicts.
pub fn owner_of(sockets: &[ListeningSocket], addr: SocketAddr, proto: &str) -> Option<SocketOwner> {
    let matching: Vec<&ListeningSocket> = sockets
        .iter()
        .filter(|s| s.proto == proto && s.addr.port() == addr.port())
        .filter(|s| s.addr.is_ipv4() == addr.is_ipv4())
        .filter(|s| s.addr.ip() == addr.ip() || s.addr.ip().is_unspecified())
        .collect();
    let first = matching.first()?;
    // Windows reports owning PIDs with the socket table; the process name is recovered
    // from the pidfile the daemon writes next to its state database.
    #[cfg(windows)]
    if let Some(pid) = first.pid {
        return Some(SocketOwner {
            comm: process_name_for_pid(pid),
            pid: Some(pid),
            addr: first.addr,
            proto: first.proto,
        });
    }
    #[cfg(target_os = "linux")]
    {
        let owners = inode_owners();
        for s in &matching {
            if let Some((comm, pid)) = owners.get(&s.inode) {
                return Some(SocketOwner {
                    comm: Some(comm.clone()),
                    pid: Some(*pid),
                    addr: s.addr,
                    proto: s.proto,
                });
            }
        }
    }
    // The socket exists but its owner is invisible — usually another user's process.
    Some(SocketOwner {
        comm: None,
        pid: None,
        addr: first.addr,
        proto: first.proto,
    })
}

/// The process name behind `pid`, when this platform can know it.
///
/// Windows offers no unprivileged way to read an arbitrary process's image name, so the
/// daemon is recognised by what it publishes: its pidfile, or the service control
/// manager's record of the service process. Anything else is reported as an unidentified
/// pid rather than guessed at — including our *own* process, which in a `doctor` run is
/// the inspector, not the daemon.
#[cfg(windows)]
fn process_name_for_pid(pid: u32) -> Option<String> {
    read_pidfile_owner(pid).or_else(|| service_pid_owner(pid))
}

/// Match `pid` against the pidfile the daemon writes at startup.
///
/// On Windows there is no `/proc` to read a process name from without elevation; the
/// daemon publishing its own PID is the honest, unprivileged way to answer "is the
/// process on port 53 ours?"
#[cfg(windows)]
fn read_pidfile_owner(pid: u32) -> Option<String> {
    let bases = [
        crate::platform::state_dir(),
        std::env::var_os("ProgramData")
            .map(std::path::PathBuf::from)
            .unwrap_or_default()
            .join("egressdns"),
    ];
    for base in bases {
        let path = base.join("egressdnsd.pid");
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        if body.trim() == pid.to_string() {
            return Some(String::from("egressdnsd"));
        }
    }
    None
}

/// Match `pid` against the service control manager's record of the running service.
#[cfg(windows)]
fn service_pid_owner(pid: u32) -> Option<String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(
            crate::platform::WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS,
        )
        .ok()?;
    let status = service.query_status().ok()?;
    if status.process_id == Some(pid) {
        Some(String::from("egressdnsd"))
    } else {
        None
    }
}

/// Every address currently configured on a local interface.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = crate::network::detect::interface_addresses()
        .into_iter()
        .map(|(_, ip)| ip)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether an address is a well-known local stub resolver.
///
/// These forward somewhere else by design, and on a host running EgressDNS that
/// "somewhere else" is frequently EgressDNS itself.
pub fn is_known_stub(addr: IpAddr) -> bool {
    match addr {
        // systemd-resolved's stub listener, and its extra listener.
        IpAddr::V4(v4) => v4 == Ipv4Addr::new(127, 0, 0, 53) || v4 == Ipv4Addr::new(127, 0, 0, 54),
        IpAddr::V6(_) => false,
    }
}

/// Whether an address is loopback.
pub fn is_loopback(addr: IpAddr) -> bool {
    addr.is_loopback()
}

/// Whether an address is private, loopback or otherwise not globally reachable.
pub fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_unicast_link_local()
        }
    }
}

/// How `/etc/resolv.conf` is managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvConf {
    /// A symlink into systemd-resolved's stub configuration.
    SystemdStub,
    /// A symlink somewhere else.
    Symlink,
    /// Generated by NetworkManager.
    NetworkManager,
    /// An ordinary file nothing claims to manage.
    Plain,
}

impl fmt::Display for ResolvConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::SystemdStub => "/etc/resolv.conf is a systemd-resolved stub symlink",
            Self::Symlink => "/etc/resolv.conf is a symlink",
            Self::NetworkManager => "/etc/resolv.conf is generated by NetworkManager",
            Self::Plain => "/etc/resolv.conf is a regular file",
        };
        f.write_str(text)
    }
}

/// Classify `/etc/resolv.conf`, without modifying it.
#[cfg(unix)]
pub fn classify_resolv_conf(path: &Path) -> Option<ResolvConf> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        let text = target.to_string_lossy();
        if text.contains("stub-resolv.conf") || text.contains("systemd") {
            return Some(ResolvConf::SystemdStub);
        }
        return Some(ResolvConf::Symlink);
    }
    let body = std::fs::read_to_string(path).ok()?;
    if body.contains("NetworkManager") {
        return Some(ResolvConf::NetworkManager);
    }
    Some(ResolvConf::Plain)
}

/// Nameserver addresses listed in a resolv.conf-format file.
pub fn resolv_conf_nameservers(path: &Path) -> Vec<IpAddr> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nameserver")?;
            rest.split_whitespace().next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

/// Whether a directory exists and accepts a write from this process.
///
/// Tested by creating and removing a uniquely named file: the permission bits alone do
/// not account for read-only mounts, full filesystems or a restrictive sandbox.
pub fn writable_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Err(String::from("directory does not exist"));
    }
    if !dir.is_dir() {
        return Err(String::from("path is not a directory"));
    }
    let probe = dir.join(format!(".egressdns-doctor-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Whether this host can originate IPv4 traffic.
///
/// Connecting a UDP socket performs a route lookup without sending a packet, so this
/// answers "is there a route" without generating any traffic at all.
pub fn can_originate_v4() -> bool {
    can_route("192.0.2.1:53")
}

/// Whether this host can originate IPv6 traffic.
pub fn can_originate_v6() -> bool {
    can_route("[2001:db8::1]:53")
}

fn can_route(target: &str) -> bool {
    let Ok(addr) = target.parse::<SocketAddr>() else {
        return false;
    };
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    socket.connect(addr).is_ok()
}

/// Whether a TCP endpoint completes a connection inside `timeout`.
pub fn tcp_reachable(addr: SocketAddr, timeout: std::time::Duration) -> Result<(), String> {
    match std::net::TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether a Do53 endpoint answers a real query inside `timeout`.
///
/// A UDP `connect` proves only that a route exists, so this sends an actual DNS query and
/// waits for a reply: on a filtered path the route is fine and the answer never comes,
/// which is exactly the case worth reporting.
pub fn udp_dns_reachable(addr: SocketAddr, timeout: std::time::Duration) -> Result<(), String> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| e.to_string())?;

    // A minimal query for the root NS: 12-byte header, QNAME ".", QTYPE NS, QCLASS IN.
    let query: [u8; 17] = [
        0x5a, 0x5a, // transaction id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer, authority, additional
        0x00, // root name
        0x00, 0x02, // QTYPE NS
        0x00, 0x01, // QCLASS IN
    ];
    socket.send(&query).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    match socket.recv(&mut buf) {
        Ok(n) if n >= 12 && buf[0] == 0x5a && buf[1] == 0x5a => Ok(()),
        Ok(_) => Err(String::from("reply did not match the query")),
        Err(e) => Err(e.to_string()),
    }
}

/// Perform a real DNS exchange over `transport` and report what happened.
///
/// A TCP connection to port 443 proves that a socket opened. It does not prove that
/// anything there speaks DoH, that the certificate is for the name we configured, that
/// ALPN negotiated, or that a DNS answer comes back — and each of those is a way a
/// deployment fails while the port test passes. So each transport is exercised as itself.
///
/// Returns `Ok(detail)` describing a successful exchange, or `Err(reason)`.
pub async fn transport_canary(
    transport: crate::config::TransportKind,
    addr: SocketAddr,
    server_name: Option<&str>,
    // DoH path. Unused until an HTTP canary exists; kept so the signature does not
    // have to change when one is added.
    _path: Option<&str>,
    roots: std::sync::Arc<rustls::RootCertStore>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use crate::config::TransportKind as T;
    match transport {
        T::Udp => plain_dns_canary(addr, false, timeout).await,
        T::Tcp => plain_dns_canary(addr, true, timeout).await,
        T::Dot => dot_canary(addr, server_name, roots, timeout).await,
        // DoH and DoQ ride HTTP/2, HTTP/3 and QUIC. Exercising them properly means
        // running the real client stack, which the daemon already contains; doing it
        // here would mean a second implementation that could disagree with the first.
        // Reported honestly as untested rather than approximated with a port check.
        T::Doh2 | T::Doh3 | T::Doq => Err(String::from(
            "NOT_TESTED: this check does not implement an HTTP/2, HTTP/3 or QUIC client; \
             a port probe would not prove the protocol works",
        )),
    }
}

/// A real Do53 exchange, over UDP or TCP.
async fn plain_dns_canary(
    addr: SocketAddr,
    tcp: bool,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let outcome = crate::dns::query::run(crate::dns::query::Request {
        // The root NS is answerable by every recursive resolver and is not a name whose
        // absence says anything about the resolver's filtering policy.
        name: String::from("."),
        rtype: String::from("NS"),
        server: addr.ip().to_string(),
        port: addr.port(),
        tcp,
        dnssec: false,
        timeout,
    })
    .await;
    match outcome {
        crate::dns::query::QueryOutcome::Answered {
            rcode, elapsed_ms, ..
        } if rcode == "NOERROR" => Ok(format!("answered NOERROR in {elapsed_ms}ms")),
        crate::dns::query::QueryOutcome::Answered { rcode, .. } => {
            Err(format!("answered {rcode} rather than NOERROR"))
        }
        crate::dns::query::QueryOutcome::Failed { reason } => Err(reason),
    }
}

/// A real DoT exchange: TLS with certificate validation against the configured name,
/// then a length-prefixed DNS query (RFC 7858).
async fn dot_canary(
    addr: SocketAddr,
    server_name: Option<&str>,
    roots: std::sync::Arc<rustls::RootCertStore>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(name) = server_name else {
        return Err(String::from(
            "no server name is configured, so the certificate could not be validated",
        ));
    };
    let started = std::time::Instant::now();

    let result = tokio::time::timeout(timeout, async {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("could not connect: {e}"))?;
        let config = crate::tls::client_config(roots, &["dot"], false);
        let dns_name = rustls_pki_types::ServerName::try_from(name.to_string())
            .map_err(|_| format!("`{name}` is not a valid TLS name"))?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let mut tls = connector
            .connect(dns_name, tcp)
            .await
            .map_err(|e| format!("TLS to `{name}` failed: {e}"))?;

        let mut message = hickory_proto::op::Message::query();
        let id = message.id;
        message.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::root(),
            hickory_proto::rr::RecordType::NS,
        ));
        message.metadata.recursion_desired = true;
        let bytes = message
            .to_vec()
            .map_err(|e| format!("could not encode the query: {e}"))?;
        let len = u16::try_from(bytes.len()).map_err(|_| String::from("query too long"))?;
        tls.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        tls.write_all(&bytes)
            .await
            .map_err(|e| format!("write failed: {e}"))?;

        let mut header = [0u8; 2];
        tls.read_exact(&mut header)
            .await
            .map_err(|e| format!("no answer: {e}"))?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(header))];
        tls.read_exact(&mut body)
            .await
            .map_err(|e| format!("truncated answer: {e}"))?;
        let parsed = hickory_proto::op::Message::from_vec(&body)
            .map_err(|e| format!("unparseable answer: {e}"))?;
        if parsed.id != id {
            return Err(String::from("the answer did not match the query id"));
        }
        Ok(parsed.metadata.response_code)
    })
    .await;

    match result {
        Err(_) => Err(format!("timed out after {timeout:?}")),
        Ok(Err(e)) => Err(e),
        Ok(Ok(hickory_proto::op::ResponseCode::NoError)) => Ok(format!(
            "TLS validated for `{}` and DNS answered NOERROR in {}ms",
            server_name.unwrap_or("?"),
            started.elapsed().as_millis()
        )),
        Ok(Ok(code)) => Err(format!("TLS validated but DNS answered {code}")),
    }
}

/// The systemd state of a unit, or `None` when systemd is not available.
///
/// `LoadState` is consulted first and `ActiveState` only afterwards, because
/// `systemctl is-active` reports a unit systemd has never heard of as `inactive` — which
/// would let `doctor` claim an uninstalled service is merely stopped.
#[cfg(target_os = "linux")]
pub fn systemd_unit_state(unit: &str) -> Option<String> {
    let load = std::process::Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", unit])
        .output()
        .ok()?;
    let load = String::from_utf8_lossy(&load.stdout).trim().to_string();
    if load.is_empty() || load == "not-found" {
        return Some(String::from("not-found"));
    }
    let active = std::process::Command::new("systemctl")
        .args(["show", "-p", "ActiveState", "--value", unit])
        .output()
        .ok()?;
    let active = String::from_utf8_lossy(&active.stdout).trim().to_string();
    if active.is_empty() {
        return Some(load);
    }
    Some(active)
}

/// The state of a Windows service, or `None` when the service manager is unreachable.
///
/// A service that is not installed reads as `not-found`, matching the systemd branch:
/// "stopped" would let `doctor` report a working install that does not exist.
#[cfg(windows)]
pub fn service_state(name: &str) -> Option<String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let Ok(service) = manager.open_service(name, ServiceAccess::QUERY_STATUS) else {
        return Some(String::from("not-found"));
    };
    let Ok(status) = service.query_status() else {
        return Some(String::from("unknown"));
    };
    Some(
        match status.current_state {
            windows_service::service::ServiceState::Stopped => "stopped",
            windows_service::service::ServiceState::StartPending => "start-pending",
            windows_service::service::ServiceState::StopPending => "stop-pending",
            windows_service::service::ServiceState::Running => "running",
            windows_service::service::ServiceState::ContinuePending => "continue-pending",
            windows_service::service::ServiceState::PausePending => "pause-pending",
            windows_service::service::ServiceState::Paused => "paused",
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_proc_addresses_decode_little_endian() {
        // 0100007F:0035 is 127.0.0.1:53 as /proc writes it.
        let addr = parse_proc_addr("0100007F:0035", false).expect("parse");
        assert_eq!(addr, "127.0.0.1:53".parse::<SocketAddr>().expect("literal"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_proc_addresses_decode_per_word() {
        // The unspecified address on port 53.
        let addr = parse_proc_addr("00000000000000000000000000000000:0035", true).expect("parse");
        assert_eq!(addr, "[::]:53".parse::<SocketAddr>().expect("literal"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_malformed_proc_address_is_rejected_rather_than_guessed() {
        assert!(parse_proc_addr("nonsense", false).is_none());
        assert!(parse_proc_addr("0100007F", false).is_none());
        assert!(parse_proc_addr("ABC:0035", false).is_none());
    }

    #[test]
    fn a_bound_port_is_seen_as_in_use_and_a_free_one_is_not() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = socket.local_addr().expect("addr");
        assert_eq!(udp_port_state(addr), PortState::InUse);
        drop(socket);
        assert_eq!(udp_port_state(addr), PortState::Free);
    }

    /// A privilege failure must never be reported as a port conflict.
    ///
    /// Binding port 53 unprivileged fails with `EACCES`. Reporting that as `InUse` sends
    /// an operator looking for a resolver that is not running.
    #[test]
    fn a_permission_failure_is_not_reported_as_a_conflict() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(classify_bind(Err(denied)), PortState::PermissionDenied);
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert_eq!(classify_bind(Err(in_use)), PortState::InUse);
    }

    /// A unit systemd has never heard of must read as `not-found`, not as `inactive`.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unknown_systemd_unit_is_reported_as_not_found() {
        if std::process::Command::new("systemctl")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let state = systemd_unit_state("egressdns-doctor-nonexistent-unit.service");
        assert_eq!(state.as_deref(), Some("not-found"));
    }

    fn socket(addr: &str, proto: &'static str) -> ListeningSocket {
        ListeningSocket {
            addr: addr.parse().expect("literal"),
            proto,
            inode: 0,
            pid: None,
        }
    }

    /// A wildcard socket owns its own family's addresses and nothing else.
    ///
    /// Treating an `0.0.0.0:53` listener as the owner of `[::]:53` turned a single
    /// healthy listener into four phantom conflicts on a dual-stack host.
    #[test]
    fn a_v4_wildcard_socket_does_not_own_a_v6_address() {
        let sockets = vec![socket("0.0.0.0:53", "udp")];
        assert!(
            owner_of(&sockets, "0.0.0.0:53".parse().expect("literal"), "udp").is_some(),
            "the v4 wildcard owns v4"
        );
        assert!(
            owner_of(&sockets, "192.0.2.1:53".parse().expect("literal"), "udp").is_some(),
            "the v4 wildcard owns every v4 address"
        );
        assert!(
            owner_of(&sockets, "[::]:53".parse().expect("literal"), "udp").is_none(),
            "the v4 wildcard must not own a v6 address"
        );
    }

    #[test]
    fn a_socket_on_another_port_or_protocol_is_not_an_owner() {
        let sockets = vec![socket("0.0.0.0:53", "udp")];
        assert!(owner_of(&sockets, "0.0.0.0:5353".parse().expect("literal"), "udp").is_none());
        assert!(owner_of(&sockets, "0.0.0.0:53".parse().expect("literal"), "tcp").is_none());
    }

    /// Our own daemon must be distinguishable from a foreign resolver, so a live host
    /// does not report its own healthy listeners as conflicts.
    #[test]
    fn our_own_daemon_is_recognised_as_such() {
        let ours = SocketOwner {
            comm: Some(String::from("egressdnsd")),
            pid: Some(1),
            addr: "0.0.0.0:53".parse().expect("literal"),
            proto: "udp",
        };
        let theirs = SocketOwner {
            comm: Some(String::from("systemd-resolve")),
            pid: Some(2),
            addr: "127.0.0.53:53".parse().expect("literal"),
            proto: "udp",
        };
        assert!(ours.is_egressdns());
        assert!(!theirs.is_egressdns());
        assert!(theirs.to_string().contains("systemd-resolve"));
        assert!(theirs.to_string().contains("pid 2"));
    }

    #[test]
    fn tcp_reachability_distinguishes_a_listener_from_a_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        assert!(tcp_reachable(addr, std::time::Duration::from_millis(500)).is_ok());

        // The closed-port half needs a port the kernel will not hand to somebody else
        // between the drop and the probe. An ephemeral port is exactly the wrong choice:
        // dropping it returns it to the pool, and any other test in this binary binding
        // `:0` at that moment can be given it, at which point the port under test is open
        // again and this assertion fails for reasons that have nothing to do with the
        // code. Ports below `ip_local_port_range` are never auto-assigned.
        let closed = std::net::TcpListener::bind("127.0.0.1:19531")
            .or_else(|_| std::net::TcpListener::bind("127.0.0.1:19532"))
            .expect("a fixed low port is free");
        let closed_addr = closed.local_addr().expect("addr");
        drop(closed);
        assert!(tcp_reachable(closed_addr, std::time::Duration::from_millis(500)).is_err());
    }

    /// A Do53 probe must require an *answer*, not merely a route.
    #[test]
    fn udp_reachability_requires_a_matching_reply() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = server.recv_from(&mut buf) {
                // Echo the transaction id back with the response bit set.
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                let _ = server.send_to(&reply, peer);
            }
        });
        assert!(udp_dns_reachable(addr, std::time::Duration::from_secs(2)).is_ok());
        let _ = handle.join();

        // A socket bound but never answering must read as unreachable, not reachable:
        // this is the filtered-path case the check exists for.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let silent_addr = silent.local_addr().expect("addr");
        assert!(udp_dns_reachable(silent_addr, std::time::Duration::from_millis(300)).is_err());
    }

    #[test]
    fn the_systemd_stub_is_recognised() {
        assert!(is_known_stub("127.0.0.53".parse().expect("literal")));
        assert!(!is_known_stub("127.0.0.1".parse().expect("literal")));
        assert!(!is_known_stub("9.9.9.9".parse().expect("literal")));
    }

    #[cfg(unix)]
    #[test]
    fn nameservers_are_read_from_a_resolv_conf_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("resolv.conf");
        std::fs::write(
            &path,
            "# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver 9.9.9.9\n",
        )
        .expect("write");
        let found = resolv_conf_nameservers(&path);
        assert_eq!(
            found,
            vec![
                "127.0.0.53".parse::<IpAddr>().expect("literal"),
                "9.9.9.9".parse::<IpAddr>().expect("literal"),
            ]
        );
    }

    #[test]
    fn a_writable_directory_is_detected_and_a_missing_one_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(writable_dir(dir.path()).is_ok());
        assert!(writable_dir(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn local_addresses_include_loopback() {
        let addrs = local_addresses();
        assert!(
            addrs.iter().any(|a| a.is_loopback()),
            "loopback must appear among local addresses, saw {addrs:?}"
        );
    }
}
