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

fn fragment(transport: &str, addr: SocketAddr, ca_path: &std::path::Path, extra: &str) -> String {
    let (server_name, path) = match transport {
        "dot" | "doq" => (format!("server_name = \"{HOSTNAME}\""), String::new()),
        "doh2" | "doh3" => (
            format!("server_name = \"{HOSTNAME}\""),
            "path = \"/dns-query\"".to_string(),
        ),
        _ => (String::new(), String::new()),
    };
    format!(
        r#"
[upstream.tls]
extra_ca_files = ["{ca}"]

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "mock"
transport = "{transport}"
addresses = ["{ip}"]
port = {port}
{server_name}
{path}

[upstream.groups.scheduler]
hedge_enabled = false
query_timeout = "2s"

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
{extra}
"#,
        ca = ca_path.display(),
        ip = addr.ip(),
        port = addr.port(),
    )
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
    let daemon = Daemon::start(&fragment(transport, addr, &ca_path, "")).await;

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

    // Trust the right CA but expect the wrong hostname.
    let text = fragment("dot", addr, &ca_path, "").replace(
        &format!("server_name = \"{HOSTNAME}\""),
        "server_name = \"wrong.example.test\"",
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

    let mut text = format!(
        "[upstream.tls]\nextra_ca_files = [\"{}\"]\n\n[[upstream.groups]]\nname = \"default\"\n",
        ca_path.display()
    );
    for (name, transport, addr, needs_name, needs_path) in [
        ("m-udp", "udp", servers.udp, false, false),
        ("m-tcp", "tcp", servers.tcp, false, false),
        ("m-dot", "dot", servers.dot, true, false),
        ("m-doh2", "doh2", servers.doh2, true, true),
        ("m-doq", "doq", servers.doq, true, false),
        ("m-doh3", "doh3", servers.doh3, true, true),
    ] {
        let addr = addr.expect("listener");
        text.push_str(&format!(
            "\n[[upstream.groups.servers]]\nname = \"{name}\"\ntransport = \"{transport}\"\n\
             addresses = [\"{ip}\"]\nport = {port}\n",
            ip = addr.ip(),
            port = addr.port()
        ));
        if needs_name {
            text.push_str(&format!("server_name = \"{HOSTNAME}\"\n"));
        }
        if needs_path {
            text.push_str("path = \"/dns-query\"\n");
        }
    }
    text.push_str(
        "\n[upstream.groups.scheduler]\nquery_timeout = \"2s\"\n\n\
         [dnssec]\nmode = \"off\"\n\n[probe]\nenabled = false\n\n[prefetch]\nenabled = false\n",
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
    // Six configured servers, plus the TCP companion the UDP server gets so that a
    // truncated answer can be retried over a stream transport (RFC 7766).
    assert_eq!(routes.len(), 7, "six transports plus one TCP companion");
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
