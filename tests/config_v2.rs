//! The v2 configuration front-end, tested through the daemon rather than the parser.
//!
//! The point of `version = 2` is that an operator writes where to ask and gets a working
//! resolver. These tests assert that: a two-line file starts and answers, and every way of
//! writing it wrongly produces an error that says what to do instead.

mod common;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use egressdns::config::{Config, TransportKind};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn err(text: &str) -> String {
    Config::from_toml(text, "test")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| panic!("expected this configuration to be refused:\n{text}"))
}

/// The headline claim: upstreams and nothing else.
#[tokio::test]
async fn a_minimal_v2_configuration_starts_and_answers() {
    let handler = MockUpstream::new();
    handler.set(
        "v2.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("v2.example.test.", 300, "203.0.113.200")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let addr = servers.udp.expect("udp");

    // The whole upstream configuration: one endpoint URI.
    let prelude = format!(
        "version = 2\nupstreams = [\"{ip}:{port}\"]\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let fragment = String::from(
        r#"
[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#,
    );

    let daemon = Daemon::start_with_prelude(&prelude, &fragment).await;
    let response = daemon
        .query_udp(&common::query("v2.example.test.", RecordType::A, false))
        .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.200".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(handler.query_count() >= 1);
}

/// A bare address must produce both the UDP route and the TCP companion that RFC 7766
/// truncation retries need, without the operator asking for either.
#[test]
fn a_bare_address_produces_udp_and_a_stream_path() {
    let cfg = Config::from_toml("version = 2\nupstreams = [\"1.1.1.1\"]\n", "test").expect("valid");
    let group = &cfg.upstream.groups[0];
    assert_eq!(group.servers.len(), 1);
    assert_eq!(group.servers[0].transport, TransportKind::Udp);
    assert_eq!(group.servers[0].effective_port(), 53);
    // The TCP companion is created by the upstream registry, not the config, so it is
    // asserted where it is built; see `upstream::pool` tests.
}

/// One HTTPS endpoint becomes an H3 candidate and an H2 candidate for one resolver.
#[test]
fn one_https_upstream_becomes_both_http_versions() {
    let cfg = Config::from_toml(
        "version = 2\nupstreams = [\"https://cloudflare-dns.com/dns-query\"]\n",
        "test",
    )
    .expect("valid");
    let transports: Vec<TransportKind> = cfg.upstream.groups[0]
        .servers
        .iter()
        .map(|s| s.transport)
        .collect();
    assert!(transports.contains(&TransportKind::Doh3));
    assert!(transports.contains(&TransportKind::Doh2));
    for s in &cfg.upstream.groups[0].servers {
        assert_eq!(s.server_name.as_deref(), Some("cloudflare-dns.com"));
        assert!(
            !s.addresses.is_empty(),
            "a named endpoint must carry bootstrap addresses"
        );
    }
}

#[test]
fn every_endpoint_form_is_accepted_together() {
    let cfg = Config::from_toml(
        r#"
version = 2
upstreams = [
    "1.1.1.1",
    "[2606:4700:4700::1111]:5353",
    "https://dns.google/dns-query",
    "tls://dns.quad9.net",
    "quic://dns.adguard-dns.com",
    "cloudflare",
]
"#,
        "test",
    )
    .expect("valid");
    let servers = &cfg.upstream.groups[0].servers;
    // 1 Do53 + 1 Do53 + 2 DoH + 1 DoT + 1 DoQ + 2 DoH from the alias.
    assert_eq!(servers.len(), 8, "{servers:#?}");
    assert_eq!(servers[1].effective_port(), 5353);
}

/// A v1-shaped file must not be silently half-applied under `version = 2`.
#[test]
fn a_v2_file_that_also_declares_upstream_groups_is_refused() {
    let text = r#"
version = 2
upstreams = ["1.1.1.1"]

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "legacy"
transport = "udp"
addresses = ["9.9.9.9"]
"#;
    let e = err(text);
    assert!(e.contains("upstream.groups"), "{e}");
    assert!(e.contains("upstreams"), "{e}");
}

/// Endpoint URIs without `version = 2` would otherwise be parsed and ignored, leaving the
/// daemon talking to something the file does not mention.
#[test]
fn upstream_uris_without_version_two_are_refused() {
    let e = err("upstreams = [\"1.1.1.1\"]\n");
    assert!(e.contains("version = 2"), "{e}");
}

#[test]
fn an_unknown_configuration_version_is_refused() {
    let e = err("version = 3\nupstreams = [\"1.1.1.1\"]\n");
    assert!(e.contains("version 3"), "{e}");
}

/// Proxy support is not implemented. Accepting the key and doing nothing would tell the
/// operator their egress is tunnelled when it is not.
#[test]
fn declaring_a_proxy_is_refused_rather_than_ignored() {
    let e =
        err("version = 2\nupstreams = [\"1.1.1.1\"]\nproxies = [\"socks5h://127.0.0.1:1080\"]\n");
    assert!(e.contains("not implemented"), "{e}");
}

#[test]
fn an_empty_upstream_list_is_refused() {
    let e = err("version = 2\nupstreams = []\n");
    assert!(e.contains("upstream"), "{e}");
}

#[test]
fn a_malformed_endpoint_names_the_entry_and_the_supported_forms() {
    let e = err("version = 2\nupstreams = [\"ftp://dns.example.net\"]\n");
    assert!(e.contains("ftp"), "{e}");
    assert!(e.contains("https"), "{e}");
}

/// The advanced form keeps working exactly as before, so an existing deployment is not
/// forced through the front-end to keep an endpoint the registry does not know.
#[test]
fn the_advanced_form_still_works_without_a_version_key() {
    let cfg = Config::from_toml(
        r#"
[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "custom"
transport = "dot"
addresses = ["9.9.9.9"]
server_name = "dns.example.net"
"#,
        "test",
    )
    .expect("the advanced form remains valid");
    assert_eq!(
        cfg.upstream.groups[0].servers[0].transport,
        TransportKind::Dot
    );
    assert!(cfg.version.is_none());
}
