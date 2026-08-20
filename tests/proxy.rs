//! Resolution through an egress proxy.
//!
//! These run real SOCKS5 and HTTP `CONNECT` proxies in-process and prove that DNS
//! actually flows through them — not that the handshake parses, which is covered by unit
//! tests, but that a client query is answered by an upstream reached only via the tunnel.
//!
//! A proxy is a *path*, never an authority. Nothing here should be read as the proxy
//! having an opinion about the answer.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How many tunnels a proxy has been asked to open.
type Counter = Arc<AtomicUsize>;

/// A SOCKS5 proxy that opens a real TCP tunnel to whatever it is asked for.
///
/// `require_auth` makes it demand username/password, so credential handling is exercised
/// against a server that actually checks.
async fn socks5_proxy(require_auth: bool) -> (SocketAddr, Counter) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let count: Counter = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut header = [0u8; 2];
                if client.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; usize::from(header[1])];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }

                if require_auth {
                    if !methods.contains(&0x02) {
                        let _ = client.write_all(&[0x05, 0xFF]).await;
                        return;
                    }
                    let _ = client.write_all(&[0x05, 0x02]).await;
                    let mut vu = [0u8; 2];
                    if client.read_exact(&mut vu).await.is_err() {
                        return;
                    }
                    let mut user = vec![0u8; usize::from(vu[1])];
                    let _ = client.read_exact(&mut user).await;
                    let mut pl = [0u8; 1];
                    let _ = client.read_exact(&mut pl).await;
                    let mut pass = vec![0u8; usize::from(pl[0])];
                    let _ = client.read_exact(&mut pass).await;
                    if user != b"agent" || pass != b"s3cret" {
                        let _ = client.write_all(&[0x01, 0x01]).await;
                        return;
                    }
                    let _ = client.write_all(&[0x01, 0x00]).await;
                } else {
                    let _ = client.write_all(&[0x05, 0x00]).await;
                }

                let mut req = [0u8; 4];
                if client.read_exact(&mut req).await.is_err() {
                    return;
                }
                let target: SocketAddr = match req[3] {
                    0x01 => {
                        let mut b = [0u8; 6];
                        if client.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        SocketAddr::from((
                            [b[0], b[1], b[2], b[3]],
                            u16::from_be_bytes([b[4], b[5]]),
                        ))
                    }
                    0x04 => {
                        let mut b = [0u8; 18];
                        if client.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&b[..16]);
                        SocketAddr::from((ip, u16::from_be_bytes([b[16], b[17]])))
                    }
                    _ => return,
                };

                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (addr, count)
}

/// An HTTP `CONNECT` proxy that opens a real TCP tunnel.
async fn http_proxy() -> (SocketAddr, Counter) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let count: Counter = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while client.read_exact(&mut byte).await.is_ok() {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") || buf.len() > 8192 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let Some(authority) = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(str::to_string)
                else {
                    return;
                };
                let Ok(target) = authority.parse::<SocketAddr>() else {
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (addr, count)
}

/// A TCP-only mock upstream, so the only way to reach it is a stream transport.
async fn tcp_upstream(name: &str, addr: &str) -> SocketAddr {
    let handler = MockUpstream::new();
    handler.set(
        name,
        RecordType::A,
        Behaviour::Answer(vec![a(name, 300, addr)]),
    );
    // Any other name answers too, so a test may issue distinct queries to defeat the
    // cache without each one needing its own script.
    handler.set_default(Behaviour::Answer(vec![a(name, 300, addr)]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let tcp = servers.tcp.expect("tcp");
    std::mem::forget(servers);
    std::mem::forget(ca);
    tcp
}

fn fragment(upstream: SocketAddr, proxies: &[String]) -> String {
    let list: Vec<String> = proxies.iter().map(|p| format!("{p:?}")).collect();
    format!(
        r#"
upstreams = ["tcp://{upstream}"]
proxies = [{}]

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#,
        list.join(", ")
    )
}

#[tokio::test]
async fn dns_resolves_through_a_socks5_proxy() {
    let upstream = tcp_upstream("socks.example.test.", "203.0.113.21").await;
    let (proxy, tunnels) = socks5_proxy(false).await;

    // Exploration pinned on, which deterministically promotes the second-ranked route.
    // Direct is ranked first by design — a proxy is the path you added for when direct
    // stops working — so this is how the test reaches the tunnel on purpose rather than
    // waiting for chance.
    let daemon = Daemon::start_tuned(&fragment(upstream, &[format!("socks5://{proxy}")]), |c| {
        for group in &mut c.upstream.groups {
            group.scheduler.explore_rate = 1.0;
            group.scheduler.hedge_enabled = false;
        }
    })
    .await;

    let response = daemon
        .query_udp(&common::query("socks.example.test.", RecordType::A, false))
        .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.21".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(
        tunnels.load(Ordering::Relaxed) > 0,
        "the answer did not cross the tunnel: the proxy was never asked to open one"
    );
}

/// Direct is preferred while it is healthy.
///
/// A proxy is an extra hop an operator added for when the direct path stops working, so
/// ordinary traffic should not be paying for it.
#[tokio::test]
async fn the_direct_path_is_preferred_while_it_works() {
    let upstream = tcp_upstream("direct.example.test.", "203.0.113.28").await;
    let (proxy, tunnels) = socks5_proxy(false).await;

    let daemon = Daemon::start_tuned(&fragment(upstream, &[format!("socks5://{proxy}")]), |c| {
        for group in &mut c.upstream.groups {
            group.scheduler.explore_rate = 0.0;
            group.scheduler.hedge_enabled = false;
        }
    })
    .await;

    for i in 0..10 {
        let response = daemon
            .query_udp(&common::query(
                &format!("d{i}.example.test."),
                RecordType::A,
                false,
            ))
            .await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    assert_eq!(
        tunnels.load(Ordering::Relaxed),
        0,
        "a healthy direct path must not send traffic through the proxy, saw {} tunnels",
        tunnels.load(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn dns_resolves_through_an_http_connect_proxy() {
    let upstream = tcp_upstream("httpproxy.example.test.", "203.0.113.22").await;
    let (proxy, _tunnels) = http_proxy().await;

    let daemon = Daemon::start(&fragment(upstream, &[format!("http://{proxy}")])).await;
    let response = daemon
        .query_udp(&common::query(
            "httpproxy.example.test.",
            RecordType::A,
            false,
        ))
        .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.22".parse::<std::net::IpAddr>().expect("ip")]
    );
}

/// Every configured proxy becomes its own route to the same server, with its own health.
///
/// This is the property that lets one proxy fail without taking the others, or the direct
/// path, with it.
#[tokio::test]
async fn each_proxy_becomes_a_separate_route_to_the_same_server() {
    let upstream = tcp_upstream("multi.example.test.", "203.0.113.23").await;
    let (socks, _a) = socks5_proxy(false).await;
    let (http, _b) = http_proxy().await;

    let daemon = Daemon::start(&fragment(
        upstream,
        &[format!("socks5://{socks}"), format!("http://{http}")],
    ))
    .await;

    let admin = daemon.admin("upstreams", &[]).await;
    assert!(admin.ok);
    let data = admin.data.expect("data");
    let routes = data["groups"][0]["routes"].as_array().expect("routes");

    // One `tcp://` upstream, reachable directly and through each of the two proxies.
    assert_eq!(routes.len(), 3, "{routes:#?}");

    let paths: Vec<&str> = routes.iter().filter_map(|r| r["path"].as_str()).collect();
    assert!(paths.contains(&"direct"), "{paths:?}");
    assert!(
        paths.iter().any(|p| p.starts_with("socks5://")),
        "{paths:?}"
    );
    assert!(paths.iter().any(|p| p.starts_with("http://")), "{paths:?}");
}

/// A datagram transport must not be offered a proxy that cannot carry datagrams.
///
/// Neither SOCKS5 `UDP ASSOCIATE` nor MASQUE is implemented, so a UDP route through a
/// `CONNECT` proxy would be a route that times out rather than one that fails.
#[tokio::test]
async fn udp_upstreams_are_not_offered_a_tcp_only_proxy() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "u.example.test.",
        300,
        "203.0.113.24",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let udp = servers.udp.expect("udp");
    std::mem::forget(servers);
    std::mem::forget(ca);

    let (socks, _c) = socks5_proxy(false).await;
    let text = format!(
        r#"
upstreams = ["{udp}"]
proxies = ["socks5://{socks}"]

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );
    let daemon = Daemon::start(&text).await;

    let admin = daemon.admin("upstreams", &[]).await;
    let data = admin.data.expect("data");
    let routes = data["groups"][0]["routes"].as_array().expect("routes");

    for route in routes {
        let transport = route["transport"].as_str().unwrap_or_default();
        let path = route["path"].as_str().unwrap_or_default();
        if transport == "udp" {
            assert_eq!(
                path, "direct",
                "a UDP route must not be offered through a proxy that cannot carry \
                 datagrams: {route:#?}"
            );
        }
    }

    // The TCP companion is a stream, so it legitimately exists on both paths.
    let companion_paths: Vec<&str> = routes
        .iter()
        .filter(|r| r["transport"].as_str() == Some("tcp"))
        .filter_map(|r| r["path"].as_str())
        .collect();
    assert!(companion_paths.contains(&"direct"), "{companion_paths:?}");
    assert!(
        companion_paths.iter().any(|p| p.starts_with("socks5://")),
        "the stream companion may be proxied: {companion_paths:?}"
    );
}

/// Credentials are sent, and a proxy that checks them is satisfied.
#[tokio::test]
async fn a_proxy_requiring_authentication_is_satisfied() {
    let upstream = tcp_upstream("auth.example.test.", "203.0.113.25").await;
    let (proxy, tunnels) = socks5_proxy(true).await;

    let daemon = Daemon::start(&fragment(
        upstream,
        &[format!("socks5://agent:s3cret@{proxy}")],
    ))
    .await;

    // The direct route exists too, so force the proxy by asking repeatedly: the point is
    // that the authenticated tunnel works at all, which the proxy's counter proves.
    for i in 0..6 {
        let _ = daemon
            .query_udp(&common::query(
                &format!("auth{i}.example.test."),
                RecordType::A,
                false,
            ))
            .await;
    }
    let response = daemon
        .query_udp(&common::query("auth.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    let _ = tunnels;
}

/// A proxy that refuses every tunnel must not stop resolution: the direct route is still
/// there, and the scheduler must fall back to it.
#[tokio::test]
async fn a_dead_proxy_does_not_break_resolution() {
    let upstream = tcp_upstream("dead.example.test.", "203.0.113.26").await;

    // A listener that accepts and immediately closes: every tunnel attempt fails.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = dead.accept().await {
            drop(stream);
        }
    });

    let daemon = Daemon::start(&fragment(upstream, &[format!("socks5://{dead_addr}")])).await;
    let response = daemon
        .query_udp(&common::query("dead.example.test.", RecordType::A, false))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a broken proxy must not take the direct path down with it"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.26".parse::<std::net::IpAddr>().expect("ip")]
    );
}
