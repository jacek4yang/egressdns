//! Probing the local gateway, on the host, at startup.
//!
//! The rules live in [`crate::config::auto`] and are pure; this is the I/O that feeds
//! them. Kept apart so the decisions stay testable without a network, because the
//! interesting cases — a router that forwards back to us, a gateway that is really this
//! machine — are the ones nobody has a spare network for.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::{TcpStream, UdpSocket};

use super::auto::{judge_gateway, loop_marker, GatewayProbe, Region, GATEWAY_PROBE_TIMEOUT};

/// The host's default gateway, IPv4 preferred.
///
/// IPv4 first because a consumer router almost always forwards DNS on IPv4 and often does
/// not on IPv6, and this is a latency optimisation rather than a policy choice.
pub fn default_gateway() -> Option<IpAddr> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some(addr) = parse_gateway(&text) {
        return Some(addr);
    }
    let out = std::process::Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .ok()?;
    parse_gateway(&String::from_utf8_lossy(&out.stdout))
}

/// Pull the next-hop address out of `ip route show default` output.
fn parse_gateway(text: &str) -> Option<IpAddr> {
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        while let Some(field) = fields.next() {
            if field == "via" {
                if let Some(addr) = fields.next() {
                    // Strip a scope suffix such as `fe80::1%enp2s0`.
                    let addr = addr.split('%').next().unwrap_or(addr);
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Examine the gateway and decide whether `auto` may use it.
///
/// Three questions, in the order that matters: does it answer DNS at all, does it answer
/// over TCP as well, and — the one that costs an afternoon when it is missed — does it
/// forward back to us?
pub async fn probe_gateway(listeners: &[SocketAddr], instance: u64) -> GatewayProbe {
    let Some(addr) = default_gateway() else {
        return judge_gateway(None, listeners, false, false, false);
    };
    let target = SocketAddr::new(addr, 53);

    let udp = query_udp(target, "example.com", RecordType::A)
        .await
        .is_some();
    let tcp = query_tcp(target, "example.com", RecordType::A)
        .await
        .is_some();

    // The loop question. A name under `.invalid` that only an EgressDNS instance answers:
    // if the gateway returns anything but "no such name", our query came back to us.
    let marker = loop_marker(instance);
    let looped = match query_udp(target, &marker, RecordType::A).await {
        Some(msg) => {
            !msg.answers.is_empty()
                && msg.metadata.response_code == hickory_proto::op::ResponseCode::NoError
        }
        None => false,
    };

    judge_gateway(Some(addr), listeners, udp, tcp, looped)
}

/// Which region this host looks like it is in.
///
/// Decided by measurement rather than by asking: whichever regional resolver answers
/// first is the one that is close, and that is the whole question. Falls back to Global,
/// which is the set that works from most places.
pub async fn detect_region() -> Region {
    let china: SocketAddr = "223.5.5.5:53".parse().expect("literal");
    let global: SocketAddr = "1.1.1.1:53".parse().expect("literal");

    let (cn, gl) = tokio::join!(timed(china, "example.com"), timed(global, "example.com"),);

    match (cn, gl) {
        (Some(a), Some(b)) if a < b => Region::China,
        // Only the regional resolver answered, which is itself the signal: on a network
        // where the global providers are impaired, they do not answer at all.
        (Some(_), None) => Region::China,
        _ => Region::Global,
    }
}

async fn timed(server: SocketAddr, name: &str) -> Option<Duration> {
    let start = std::time::Instant::now();
    query_udp(server, name, RecordType::A).await?;
    Some(start.elapsed())
}

fn build_query(name: &str, qtype: RecordType) -> Option<Message> {
    let mut qname = Name::from_utf8(name).ok()?;
    qname.set_fqdn(true);
    let mut message = Message::query();
    message.metadata.id = rand::random();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(qname, qtype));
    Some(message)
}

/// One UDP query, bounded, with the reply matched to the request.
async fn query_udp(server: SocketAddr, name: &str, qtype: RecordType) -> Option<Message> {
    let message = build_query(name, qtype)?;
    let id = message.metadata.id;
    let bytes = message.to_vec().ok()?;

    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };

    let result = tokio::time::timeout(GATEWAY_PROBE_TIMEOUT, async {
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.connect(server).await.ok()?;
        socket.send(&bytes).await.ok()?;
        let mut buf = vec![0u8; 1232];
        let n = socket.recv(&mut buf).await.ok()?;
        Message::from_vec(&buf[..n]).ok()
    })
    .await
    .ok()??;

    // An unmatched id is somebody else's packet, not an answer.
    (result.metadata.id == id).then_some(result)
}

/// One TCP query, with RFC 7766 length framing.
async fn query_tcp(server: SocketAddr, name: &str, qtype: RecordType) -> Option<Message> {
    let message = build_query(name, qtype)?;
    let id = message.metadata.id;
    let bytes = message.to_vec().ok()?;

    let result = tokio::time::timeout(GATEWAY_PROBE_TIMEOUT, async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect(server).await.ok()?;
        let len = u16::try_from(bytes.len()).ok()?;
        stream.write_all(&len.to_be_bytes()).await.ok()?;
        stream.write_all(&bytes).await.ok()?;
        stream.flush().await.ok()?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.ok()?;
        let expect = usize::from(u16::from_be_bytes(len_buf));
        if expect == 0 || expect > 65_535 {
            return None;
        }
        let mut buf = vec![0u8; expect];
        stream.read_exact(&mut buf).await.ok()?;
        Message::from_vec(&buf).ok()
    })
    .await
    .ok()??;

    (result.metadata.id == id).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_route_yields_its_next_hop() {
        let text = "default via 192.168.31.1 dev enp2s0 proto static \n";
        assert_eq!(
            parse_gateway(text),
            Some("192.168.31.1".parse::<IpAddr>().expect("v4"))
        );
    }

    /// A link-local IPv6 next hop carries a scope that is not part of the address.
    #[test]
    fn an_ipv6_scope_suffix_is_stripped() {
        let text = "default via fe80::1%enp2s0 dev enp2s0 proto ra metric 1024\n";
        assert_eq!(
            parse_gateway(text),
            Some("fe80::1".parse::<IpAddr>().expect("v6"))
        );
    }

    #[test]
    fn no_default_route_yields_nothing() {
        assert_eq!(parse_gateway(""), None);
        assert_eq!(parse_gateway("10.0.0.0/8 dev eth0 scope link\n"), None);
    }

    /// A route with no `via` is on-link and has no next hop to ask.
    #[test]
    fn an_onlink_default_route_has_no_gateway() {
        assert_eq!(parse_gateway("default dev tun0 scope link\n"), None);
    }

    #[tokio::test]
    async fn a_probe_against_nothing_times_out_rather_than_hanging() {
        // TEST-NET-1 (RFC 5737): routable syntax, guaranteed to answer nothing.
        let dead: SocketAddr = "192.0.2.1:53".parse().expect("literal");
        let start = std::time::Instant::now();
        assert!(query_udp(dead, "example.com", RecordType::A)
            .await
            .is_none());
        assert!(
            start.elapsed() < GATEWAY_PROBE_TIMEOUT * 3,
            "the probe must be bounded by its own timeout"
        );
    }
}
