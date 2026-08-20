//! Every upstream transport must work against a deterministic local server.
//!
//! These tests exercise acceptance gate G4: UDP, TCP, DNS-over-TLS, DNS-over-HTTPS on
//! HTTP/2, DNS-over-HTTPS on HTTP/3 and DNS-over-QUIC.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

const HOSTNAME: &str = "dns.example.test";

/// The endpoint URI that reaches the mock over `transport`.
///
/// Named transports use `?addr=` to pin the mock's ephemeral address: the certificate is
/// issued for `HOSTNAME`, so the name is the identity and the hint only decides where the
/// socket is opened — exactly the split the bootstrap resolver relies on.
fn upstream_uri(transport: &str, addr: SocketAddr) -> String {
    match transport {
        "udp" => format!("{addr}"),
        "tcp" => format!("tcp://{addr}"),
        "dot" => format!("tls://{HOSTNAME}:{}?addr={}", addr.port(), addr.ip()),
        "doq" => format!("quic://{HOSTNAME}:{}?addr={}", addr.port(), addr.ip()),
        "doh2" | "doh3" => format!(
            "https://{HOSTNAME}:{}/dns-query?addr={}",
            addr.port(),
            addr.ip()
        ),
        other => panic!("unknown transport {other}"),
    }
}

fn fragment(transport: &str, addr: SocketAddr, ca_path: &std::path::Path, extra: &str) -> String {
    format!(
        r#"
upstreams = ["{uri}"]
proxies = []

[tls]
extra_ca_files = ["{ca}"]

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
{extra}
"#,
        uri = upstream_uri(transport, addr),
        ca = ca_path.display(),
    )
}

/// Keep only the routes that use `transport`.
///
/// One `https://` endpoint deliberately yields both an HTTP/3 and an HTTP/2 candidate,
/// because choosing between them is a measurement rather than a setting. That is right in
/// production and wrong for a test whose purpose is to prove one specific transport works
/// end to end, so the choice is pinned here — through the internal structures, not through
/// a file, so no user gains an H2/H3 knob.
fn pin_transport(config: &mut egressdns::config::Config, transport: &str) {
    use egressdns::config::TransportKind as T;
    let want = match transport {
        "udp" => T::Udp,
        "tcp" => T::Tcp,
        "dot" => T::Dot,
        "doq" => T::Doq,
        "doh2" => T::Doh2,
        "doh3" => T::Doh3,
        other => panic!("unknown transport {other}"),
    };
    for group in &mut config.upstream.groups {
        group.servers.retain(|s| s.transport == want);
        assert!(!group.servers.is_empty(), "no {transport} route after pinning");
    }
}


async fn check_transport(transport: &str, pick: fn(&common::MockServers) -> Option<SocketAddr>) {
    let handler = MockUpstream::new();
    let name = format!("{transport}.example.test.");
    handler.set(
        &name,
        RecordType::A,
        Behaviour::Answer(vec![a(&name, 300, "203.0.113.42")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler.clone(), &ca, HOSTNAME, Transports::all()).await;
    let addr = pick(&servers).unwrap_or_else(|| panic!("{transport} listener not started"));

    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca.write_bundle(dir.path());
    let t = transport.to_string();
    let daemon = Daemon::start_tuned(&fragment(transport, addr, &ca_path, ""), move |c| {
        pin_transport(c, &t)
    })
    .await;

    let response = daemon
        .query_udp(&common::query(&name, RecordType::A, false))
        .await;
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "{transport} query failed"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.42".parse::<std::net::IpAddr>().expect("ip")],
        "{transport} returned the wrong answer"
    );
    assert!(handler.query_count() >= 1);
}

#[tokio::test]
async fn upstream_over_udp() {
    check_transport("udp", |s| s.udp).await;
}

#[tokio::test]
async fn upstream_over_tcp() {
    check_transport("tcp", |s| s.tcp).await;
}

#[tokio::test]
async fn upstream_over_dns_over_tls() {
    check_transport("dot", |s| s.dot).await;
}

#[tokio::test]
async fn upstream_over_dns_over_https_h2() {
    check_transport("doh2", |s| s.doh2).await;
}

#[tokio::test]
async fn upstream_over_dns_over_quic() {
    check_transport("doq", |s| s.doq).await;
}

#[tokio::test]
async fn upstream_over_dns_over_https_h3() {
    check_transport("doh3", |s| s.doh3).await;
}

#[tokio::test]
async fn an_untrusted_upstream_certificate_is_refused() {
    let handler = MockUpstream::new();
    handler.set(
        "tls.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("tls.example.test.", 300, "203.0.113.42")]),
    );
    // The server presents a certificate from one CA; the daemon trusts a different one.
    let server_ca = TestCa::new();
    let other_ca = TestCa::new();
    let servers =
        common::start_mock(handler.clone(), &server_ca, HOSTNAME, Transports::all()).await;
    let addr = servers.dot.expect("dot listener");

    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = other_ca.write_bundle(dir.path());
    let daemon = Daemon::start(&fragment("dot", addr, &ca_path, "")).await;

    let response = daemon
        .query_udp(&common::query("tls.example.test.", RecordType::A, false))
        .await;
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "an unverifiable upstream certificate must not yield an answer"
    );
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn a_wrong_server_name_is_refused() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "x.example.test.",
        300,
        "203.0.113.1",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, HOSTNAME, Transports::all()).await;
    let addr = servers.dot.expect("dot listener");
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca.write_bundle(dir.path());

    // Trust the right CA but authenticate against the wrong hostname. The identity now
    // lives in the URI, and `?addr=` still points at the real listener — so this reaches
    // the correct server and refuses it, which is the property under test.
    let text = format!(
        r#"
upstreams = ["tls://wrong.example.test:{port}?addr={ip}"]
proxies = []

[tls]
extra_ca_files = ["{ca}"]

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#,
        port = addr.port(),
        ip = addr.ip(),
        ca = ca_path.display()
    );
    let daemon = Daemon::start(&text).await;
    let response = daemon
        .query_udp(&common::query("x.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn every_transport_answers_from_one_configuration() {
    // A single group containing all six transports must still resolve, and the scheduler
    // must pick a working route without operator intervention.
    let handler = MockUpstream::new();
    handler.set(
        "all.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("all.example.test.", 300, "203.0.113.77")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler.clone(), &ca, HOSTNAME, Transports::all()).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca.write_bundle(dir.path());

    let uris: Vec<String> = [
        ("udp", servers.udp),
        ("tcp", servers.tcp),
        ("dot", servers.dot),
        ("doh2", servers.doh2),
        ("doq", servers.doq),
        ("doh3", servers.doh3),
    ]
    .iter()
    .map(|(t, a)| format!("{:?}", upstream_uri(t, a.expect("listener"))))
    .collect();

    let text = format!(
        r#"
upstreams = [{list}]
proxies = []

[tls]
extra_ca_files = ["{ca}"]

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#,
        list = uris.join(", "),
        ca = ca_path.display()
    );

    let daemon = Daemon::start(&text).await;
    let response = daemon
        .query_udp(&common::query("all.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(common::addresses(&response).len(), 1);

    let admin = daemon.admin("upstreams", &[]).await;
    assert!(admin.ok);
    let groups = admin.data.expect("data")["groups"].clone();
    let routes = groups[0]["routes"].as_array().expect("routes");
    // Six endpoint URIs, but nine routes. Each of the two `https://` entries yields an
    // HTTP/3 *and* an HTTP/2 candidate for one logical resolver, because which performs
    // better is a measurement rather than a setting; and the bare address gains the TCP
    // companion a truncated answer is retried over (RFC 7766).
    assert_eq!(
        routes.len(),
        9,
        "4 single-transport URIs + 2 HTTPS URIs x 2 HTTP versions + 1 TCP companion, \
         saw {routes:?}"
    );
    let transports: Vec<&str> = routes
        .iter()
        .filter_map(|r| r["transport"].as_str())
        .collect();
    for expected in ["udp", "tcp", "dot", "doh2", "doh3", "doq"] {
        assert!(
            transports.contains(&expected),
            "{expected} missing from {transports:?}"
        );
    }
}

#[tokio::test]
async fn a_dead_upstream_does_not_stall_the_client() {
    let handler = MockUpstream::new();
    handler.set("gone.example.test.", RecordType::A, Behaviour::Drop);
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, HOSTNAME, Transports::plain()).await;
    let udp = servers.udp.expect("udp");
    let daemon = Daemon::start(&common::udp_upstream_fragment(udp)).await;

    let started = std::time::Instant::now();
    let response = daemon
        .query_udp(&common::query("gone.example.test.", RecordType::A, false))
        .await;
    let elapsed = started.elapsed();
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(
        elapsed < Duration::from_secs(8),
        "the client waited {elapsed:?}, which exceeds the foreground budget"
    );
}
