//! Host inspection primitives used by [`super::run`].
//!
//! Everything here reads the live system: `/proc`, the routing stack, the filesystem.
//! Each function is written to degrade to "unknown" rather than to guess, because a
//! diagnosis that invents evidence is worse than one that admits it could not look.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Whether the current process is root.
pub fn is_root() -> bool {
    // Safe: `geteuid` cannot fail and takes no arguments.
    nix::unistd::geteuid().is_root()
}

/// Whether `CAP_NET_BIND_SERVICE` is in the effective capability set.
///
/// Returns `None` when the capability set could not be read, which is reported as
/// `NOT_TESTED` rather than assumed either way.
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
    classify_bind(std::net::UdpSocket::bind(addr).map(|_| ()))
}

/// Whether a TCP listen address can be bound.
pub fn tcp_port_state(addr: SocketAddr) -> PortState {
    classify_bind(std::net::TcpListener::bind(addr).map(|_| ()))
}

/// One listening socket read from `/proc/net`.
#[derive(Debug, Clone)]
pub struct ListeningSocket {
    /// Local address.
    pub addr: SocketAddr,
    /// `"udp"` or `"tcp"`.
    pub proto: &'static str,
    /// Socket inode, used to find the owning process.
    pub inode: u64,
}

/// Every listening TCP and UDP socket this process is allowed to see.
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
            out.push(ListeningSocket { addr, proto, inode });
        }
    }
    out
}

/// Parse the `HEXADDR:HEXPORT` form used throughout `/proc/net`.
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

/// Map socket inodes to `pid/name`, for as many processes as we may inspect.
fn inode_owners() -> HashMap<u64, String> {
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
                    out.entry(inode)
                        .or_insert_with(|| format!("{comm} (pid {pid})"));
                }
            }
        }
    }
    out
}

/// Identify the process holding `addr` for `proto`, if it can be determined.
///
/// A wildcard socket owns the port on every address, so an exact match is tried first and
/// a wildcard match second.
pub fn owner_of(sockets: &[ListeningSocket], addr: SocketAddr, proto: &str) -> Option<String> {
    let matching: Vec<&ListeningSocket> = sockets
        .iter()
        .filter(|s| s.proto == proto && s.addr.port() == addr.port())
        .filter(|s| s.addr.ip() == addr.ip() || s.addr.ip().is_unspecified())
        .collect();
    if matching.is_empty() {
        return None;
    }
    let owners = inode_owners();
    for s in &matching {
        if let Some(name) = owners.get(&s.inode) {
            return Some(format!("{name} on {}/{}", s.proto, s.addr));
        }
    }
    // The socket exists but its owner is invisible — usually another user's process.
    Some(format!(
        "an unidentified process on {}/{}",
        matching[0].proto, matching[0].addr
    ))
}

/// Every address currently configured on a local interface.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifaddr in addrs {
            let Some(storage) = ifaddr.address else {
                continue;
            };
            if let Some(v4) = storage.as_sockaddr_in() {
                out.push(IpAddr::V4(v4.ip()));
            } else if let Some(v6) = storage.as_sockaddr_in6() {
                out.push(IpAddr::V6(v6.ip()));
            }
        }
    }
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

/// The systemd state of a unit, or `None` when systemd is not available.
///
/// `LoadState` is consulted first and `ActiveState` only afterwards, because
/// `systemctl is-active` reports a unit systemd has never heard of as `inactive` — which
/// would let `doctor` claim an uninstalled service is merely stopped.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_proc_addresses_decode_little_endian() {
        // 0100007F:0035 is 127.0.0.1:53 as /proc writes it.
        let addr = parse_proc_addr("0100007F:0035", false).expect("parse");
        assert_eq!(addr, "127.0.0.1:53".parse::<SocketAddr>().expect("literal"));
    }

    #[test]
    fn ipv6_proc_addresses_decode_per_word() {
        // The unspecified address on port 53.
        let addr = parse_proc_addr("00000000000000000000000000000000:0035", true).expect("parse");
        assert_eq!(addr, "[::]:53".parse::<SocketAddr>().expect("literal"));
    }

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

    #[test]
    fn the_systemd_stub_is_recognised() {
        assert!(is_known_stub("127.0.0.53".parse().expect("literal")));
        assert!(!is_known_stub("127.0.0.1".parse().expect("literal")));
        assert!(!is_known_stub("9.9.9.9".parse().expect("literal")));
    }

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
