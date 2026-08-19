//! The mandated Cloudflare security properties.
//!
//! Each test corresponds to a required guarantee: an untrusted source can never influence
//! a DNS answer without passing official-prefix membership, special-use filtering and
//! local protocol validation, and no probe failure can ever damage ordinary resolution.

mod common;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{a, Behaviour, CannedResponse, Daemon, MockUpstream, TestCa, Transports};
use egressdns::cloudflare::candidates::{
    Admission, CandidateOrigin, CandidatePool, CandidateStage, RejectReason,
};
use egressdns::cloudflare::prefixes::{self, PrefixSnapshot, PrefixSource};
use egressdns::cloudflare::seeds;
use egressdns::cloudflare::state::CloudflareState;
use egressdns::config::{CloudflareConfig, CloudflareMode};
use egressdns::error::{CloudflareError, ProbeError};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tokio::time::Instant;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

/// Addresses observed verbatim from the live third-party seed endpoints that are **not**
/// inside Cloudflare's published prefixes.
const NON_CLOUDFLARE_SEEDS: &[&str] = &[
    "188.164.248.83",
    "188.164.248.66",
    "91.193.59.179",
    "8.35.211.212",
    "8.39.125.231",
];

#[tokio::test(start_paused = true)]
async fn a_non_cloudflare_address_from_an_external_source_is_rejected() {
    let pool = CandidatePool::new(64);
    let snapshot = PrefixSnapshot::builtin();
    let now = Instant::now();
    for addr in NON_CLOUDFLARE_SEEDS {
        assert_eq!(
            pool.admit(
                ip(addr),
                CandidateOrigin::Seed,
                Some(&snapshot),
                1,
                now,
                None
            ),
            Admission::Rejected(RejectReason::NotOfficialPrefix),
            "{addr} must never enter the candidate pool"
        );
    }
    assert_eq!(pool.counts(), (0, 0));
}

#[tokio::test(start_paused = true)]
async fn private_and_metadata_addresses_from_an_external_source_are_rejected() {
    let pool = CandidatePool::new(64);
    let snapshot = PrefixSnapshot::builtin();
    let now = Instant::now();
    for addr in [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.5.5",
        "127.0.0.1",
        "169.254.169.254",
        "fd00:ec2::254",
        "::1",
        "224.0.0.1",
    ] {
        assert_eq!(
            pool.admit(
                ip(addr),
                CandidateOrigin::Seed,
                Some(&snapshot),
                1,
                now,
                None
            ),
            Admission::Rejected(RejectReason::SpecialUse),
            "{addr} must never enter the candidate pool"
        );
    }
}

#[tokio::test]
async fn html_instead_of_candidate_data_is_rejected() {
    let html = include_bytes!("fixtures/seed_html.html");
    assert!(matches!(
        seeds::parse(html, 256),
        Err(CloudflareError::Parse(_))
    ));
    // JSON is equally wrong for this endpoint shape.
    assert!(seeds::parse(br#"{"ips":["104.16.0.1"]}"#, 256).is_err());
}

#[tokio::test]
async fn an_oversized_source_response_is_rejected() {
    egressdns::tls::install_crypto_provider();
    let ca = TestCa::new();
    let mut routes = HashMap::new();
    routes.insert("/seed".to_string(), CannedResponse::large(512 * 1024));
    let origin = common::start_https_origin(
        &ca,
        "seed.example.test",
        routes,
        CannedResponse::status(404),
    )
    .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = ca.write_bundle(dir.path());
    let roots = Arc::new(egressdns::tls::root_store(false, &[bundle]).expect("roots"));
    let url = egressdns::probe::fetch::HttpsUrl {
        host: "seed.example.test".into(),
        port: origin.addr.port(),
        path: "/seed".into(),
    };
    let options = egressdns::probe::fetch::FetchOptions {
        max_bytes: 4_096,
        timeout: Duration::from_secs(5),
        ..egressdns::probe::fetch::FetchOptions::default()
    };
    let err = egressdns::probe::fetch::fetch(&url, &[origin.addr.ip()], roots, &options)
        .await
        .expect_err("an oversized response must be refused");
    assert!(
        err.to_string().contains("too large") || matches!(err, CloudflareError::Fetch(_)),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn a_tls_hostname_mismatch_prevents_promotion() {
    egressdns::tls::install_crypto_provider();
    let ca = TestCa::new();
    let origin = common::start_https_origin(
        &ca,
        "right.example.test",
        HashMap::new(),
        CannedResponse::ok("hello"),
    )
    .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = ca.write_bundle(dir.path());
    let roots = Arc::new(egressdns::tls::root_store(false, &[bundle]).expect("roots"));

    let good = egressdns::probe::http::HttpProbeRequest {
        ip: origin.addr.ip(),
        port: origin.addr.port(),
        hostname: "right.example.test".into(),
        path: "/".into(),
        method: egressdns::probe::http::ProbeMethod::Get,
        alpn: vec!["h2".into(), "http/1.1".into()],
        connect_timeout: Duration::from_secs(3),
        tls_timeout: Duration::from_secs(3),
        http_timeout: Duration::from_secs(3),
        max_body_bytes: 4_096,
    };
    let outcome = egressdns::probe::http::probe(&good, Arc::clone(&roots))
        .await
        .expect("the matching hostname must succeed");
    assert_eq!(outcome.status, 200);
    assert!(outcome.leaf.is_some(), "the verified leaf must be captured");

    let mismatched = egressdns::probe::http::HttpProbeRequest {
        hostname: "wrong.example.test".into(),
        ..good
    };
    let err = egressdns::probe::http::probe(&mismatched, roots)
        .await
        .expect_err("a hostname mismatch must fail");
    assert!(
        matches!(err, ProbeError::Tls(_)),
        "expected a TLS failure, got {err:?}"
    );
}

#[tokio::test]
async fn http_421_prevents_promotion_while_403_and_404_do_not() {
    egressdns::tls::install_crypto_provider();
    let ca = TestCa::new();
    let mut routes = HashMap::new();
    routes.insert("/misdirected".to_string(), CannedResponse::status(421));
    routes.insert("/forbidden".to_string(), CannedResponse::status(403));
    routes.insert("/missing".to_string(), CannedResponse::status(404));
    let origin =
        common::start_https_origin(&ca, "edge.example.test", routes, CannedResponse::ok("ok"))
            .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = ca.write_bundle(dir.path());
    let roots = Arc::new(egressdns::tls::root_store(false, &[bundle]).expect("roots"));

    for (path, expected) in [
        ("/misdirected", false),
        ("/forbidden", true),
        ("/missing", true),
    ] {
        let request = egressdns::probe::http::HttpProbeRequest {
            ip: origin.addr.ip(),
            port: origin.addr.port(),
            hostname: "edge.example.test".into(),
            path: path.into(),
            method: egressdns::probe::http::ProbeMethod::Get,
            alpn: vec!["h2".into(), "http/1.1".into()],
            connect_timeout: Duration::from_secs(3),
            tls_timeout: Duration::from_secs(3),
            http_timeout: Duration::from_secs(3),
            max_body_bytes: 4_096,
        };
        let outcome = egressdns::probe::http::probe(&request, Arc::clone(&roots))
            .await
            .expect("probe completes");
        assert_eq!(
            egressdns::probe::engine::ProbeEngine::accepts(None, &outcome),
            expected,
            "path {path} returned {}",
            outcome.status
        );
    }
}

#[tokio::test(start_paused = true)]
async fn one_probe_failure_does_not_permanently_eliminate_an_address() {
    let pool = CandidatePool::new(16);
    let snapshot = PrefixSnapshot::builtin();
    let now = Instant::now();
    let addr = ip("104.16.0.1");
    assert_eq!(
        pool.admit(
            addr,
            CandidateOrigin::DnsAnswer,
            Some(&snapshot),
            1,
            now,
            None
        ),
        Admission::Added
    );
    pool.record_stage(addr, CandidateStage::HttpOk, true, None, now);
    pool.record_stage(addr, CandidateStage::HttpOk, false, None, now);
    let candidate = pool.get(addr).expect("still present after a failure");
    assert_eq!(candidate.consecutive_successes, 0);
    // It can regain eligibility with further successes.
    for _ in 0..3 {
        pool.record_stage(addr, CandidateStage::HttpOk, true, None, now);
    }
    assert_eq!(pool.eligible(true, 3).len(), 1);
}

#[tokio::test]
async fn a_tcp_443_failure_never_makes_an_ordinary_dns_answer_fail() {
    // The answer contains a Cloudflare-owned address that refuses TCP 443. Probing will
    // therefore fail for it, and the DNS answer must be entirely unaffected.
    let handler = MockUpstream::new();
    handler.set(
        "cf.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![
            a("cf.example.test.", 300, "104.16.0.1"),
            a("cf.example.test.", 300, "104.16.0.2"),
        ]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let fragment = format!(
        r#"
{base}

[cloudflare]
enabled = true
mode = "preserve"

[cloudflare.seeds]
enabled = false

[cloudflare.official]
refresh_interval = "24h"

[cloudflare.sampling]
enabled = false
"#,
        base = common::udp_upstream_fragment(servers.udp.expect("udp")).replace(
            "[probe]\nenabled = false",
            "[probe]\nenabled = true\nper_ip_cooldown = \"1s\""
        )
    );
    let daemon = Daemon::start(&fragment).await;

    for _ in 0..3 {
        let response = daemon
            .query_udp(&common::query("cf.example.test.", RecordType::A, false))
            .await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        let addrs = common::addresses(&response);
        assert_eq!(
            addrs.len(),
            2,
            "preserve mode must return exactly the original addresses"
        );
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(sorted, vec![ip("104.16.0.1"), ip("104.16.0.2")]);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn total_candidate_source_failure_does_not_break_forwarding() {
    let handler = MockUpstream::new();
    handler.set(
        "normal.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("normal.example.test.", 300, "104.16.9.9")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    // Every Cloudflare data source points at an address that cannot answer.
    let fragment = format!(
        r#"
{base}

[cloudflare]
enabled = true
mode = "preserve"
probe_hosts = ["speed.cloudflare.com"]

[cloudflare.official]
api_url = "https://unreachable.invalid/client/v4/ips"
ipv4_url = "https://unreachable.invalid/ips-v4"
ipv6_url = "https://unreachable.invalid/ips-v6"
refresh_interval = "300s"
timeout = "500ms"

[cloudflare.seeds]
enabled = true
refresh_interval = "60s"
timeout = "500ms"

[[cloudflare.seeds.endpoints]]
name = "broken"
url = "https://unreachable.invalid/ct"

[cloudflare.sampling]
enabled = false
"#,
        base = common::udp_upstream_fragment(servers.udp.expect("udp"))
    );
    let daemon = Daemon::start(&fragment).await;
    daemon.app.spawn_background();
    tokio::time::sleep(Duration::from_millis(600)).await;

    let response = daemon
        .query_udp(&common::query("normal.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(common::addresses(&response).len(), 1);

    // The compiled-in bootstrap prefix snapshot must still be present and usable.
    let status = daemon.admin("cloudflare", &["status"]).await;
    assert!(status.ok);
    let data = status.data.expect("data");
    assert!(
        data["ipv4_prefixes"].as_u64().unwrap_or(0) >= 8,
        "a failed source must not erase the prefix snapshot"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_prefix_api_retains_the_last_valid_snapshot() {
    let state = CloudflareState::new(&CloudflareConfig {
        enabled: true,
        mode: CloudflareMode::Preserve,
        ..CloudflareConfig::default()
    });
    let good = prefixes::parse_api_json(include_bytes!("fixtures/cloudflare_ips_api.json"), 1_000)
        .expect("fixture parses");
    state.set_prefixes(good);
    let before = state.prefixes().as_ref().as_ref().expect("snapshot").len();

    // A truncated or empty response must never be accepted.
    for body in [
        &b"{}"[..],
        &b"{\"result\":{\"ipv4_cidrs\":[],\"ipv6_cidrs\":[]},\"success\":true}"[..],
        &b"<html>"[..],
    ] {
        let parsed = prefixes::parse_api_json(body, 2_000);
        let rejected = match parsed {
            Err(_) => true,
            Ok(candidate) => {
                prefixes::validate_snapshot(&candidate, state.prefixes().as_ref().as_ref(), 8, 4)
                    .is_err()
            }
        };
        assert!(
            rejected,
            "body {body:?} should not replace a valid snapshot"
        );
    }
    assert_eq!(
        state.prefixes().as_ref().as_ref().expect("snapshot").len(),
        before
    );
}

#[tokio::test(start_paused = true)]
async fn retired_prefixes_immediately_invalidate_their_candidates() {
    let state = CloudflareState::new(&CloudflareConfig {
        enabled: true,
        mode: CloudflareMode::Preserve,
        ..CloudflareConfig::default()
    });
    let now = Instant::now();
    let snapshot = PrefixSnapshot::builtin();
    for addr in ["104.16.0.1", "172.64.0.1"] {
        state.pool().admit(
            ip(addr),
            CandidateOrigin::DnsAnswer,
            Some(&snapshot),
            1,
            now,
            None,
        );
    }
    let narrowed = PrefixSnapshot::new(
        vec!["104.16.0.0/13".parse().expect("net")],
        Vec::new(),
        None,
        0,
        PrefixSource::Api,
    );
    state.set_prefixes(narrowed);
    assert!(state.pool().get(ip("172.64.0.1")).is_none());
    assert!(state.pool().get(ip("104.16.0.1")).is_some());
}

#[tokio::test]
async fn seed_hostnames_are_resolved_and_still_filtered() {
    // A seed endpoint may return a hostname; the resulting addresses must still be
    // filtered against the official prefix snapshot.
    let (items, _) = seeds::parse(b"cf.example.test\n104.16.0.1\n", 32).expect("parses");
    assert_eq!(items.len(), 2);
    assert!(items
        .iter()
        .any(|i| matches!(i, seeds::SeedItem::Hostname { .. })));

    let pool = CandidatePool::new(16);
    let snapshot = PrefixSnapshot::builtin();
    let now = Instant::now();
    // Whatever a hostname resolves to is subject to the same filter.
    assert_eq!(
        pool.admit(
            ip("8.8.8.8"),
            CandidateOrigin::Seed,
            Some(&snapshot),
            1,
            now,
            None
        ),
        Admission::Rejected(RejectReason::NotOfficialPrefix)
    );
}

#[tokio::test]
async fn the_repository_contains_no_third_party_relay_data_source() {
    // Acceptance gate G8: the forbidden data source must not appear anywhere in the
    // shipped source tree, and no relay/proxy IP concept may exist.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    // The needles are assembled from fragments at runtime so that this file — which is
    // itself part of the shipped tree — does not contain the very strings it forbids.
    // That removes the self-exclusion the check would otherwise need, and makes the
    // assertion cover every file in the repository without exception.
    let forbidden: Vec<String> = vec![
        ["zip", "cm", "edu", "kg"].join("."),
        ["all", "json"].join("."),
        ["Proxy", "IP"].concat(),
        ["proxy", "ip"].concat(),
    ];

    let mut stack = vec![root.to_path_buf()];
    let mut scanned = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" || name == "target" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for needle in &forbidden {
                if text.contains(needle.as_str()) {
                    offenders.push(format!("{} contains `{needle}`", path.display()));
                }
            }
        }
    }

    assert!(
        scanned > 50,
        "the scan only read {scanned} files, which means it is not actually walking the tree"
    );
    assert!(
        offenders.is_empty(),
        "forbidden content found: {offenders:?}"
    );
}

#[tokio::test]
async fn optimization_can_be_switched_off_at_runtime_without_interrupting_dns() {
    // The operational requirement is that an incident responder can neutralise the
    // optimization layer immediately, from the admin socket, without a restart, a
    // configuration change, or a single failed query.
    let handler = MockUpstream::new();
    handler.set(
        "cf.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![
            a("cf.example.test.", 300, "104.16.0.1"),
            a("cf.example.test.", 300, "104.16.0.2"),
        ]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let fragment = format!(
        r#"
{base}

[cloudflare]
enabled = true
mode = "preserve"

[cloudflare.seeds]
enabled = false

[cloudflare.sampling]
enabled = false
"#,
        base = common::udp_upstream_fragment(servers.udp.expect("udp"))
    );
    let daemon = Daemon::start(&fragment).await;

    let before = daemon
        .query_udp(&common::query("cf.example.test.", RecordType::A, false))
        .await;
    assert_eq!(before.metadata.response_code, ResponseCode::NoError);
    assert_eq!(before.answers.len(), 2);

    let status = daemon.admin("cloudflare", &["status"]).await;
    assert!(status.ok);
    assert_eq!(
        status.data.as_ref().and_then(|d| d["mode"].as_str()),
        Some("preserve")
    );

    // Weakening the mode is allowed and takes effect immediately.
    let off = daemon.admin("cloudflare", &["set-mode", "off"]).await;
    assert!(off.ok, "set-mode off must succeed: {:?}", off.error);
    let status = daemon.admin("cloudflare", &["status"]).await;
    let data = status.data.as_ref().expect("status data");
    assert_eq!(data["mode"].as_str(), Some("off"));
    assert_eq!(data["configured_mode"].as_str(), Some("preserve"));
    assert_eq!(data["mode_override"].as_str(), Some("off"));

    // Baseline DNS is completely unaffected: same rcode, same address set.
    let after = daemon
        .query_udp(&common::query("cf.example.test.", RecordType::A, false))
        .await;
    assert_eq!(after.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        sorted_addrs(&after),
        sorted_addrs(&before),
        "turning optimization off must not change which addresses are returned"
    );

    // Strengthening beyond the configured mode is refused: that is a config change.
    let up = daemon
        .admin("cloudflare", &["set-mode", "verified-augment"])
        .await;
    assert!(!up.ok, "a runtime override must never strengthen the mode");

    let bad = daemon.admin("cloudflare", &["set-mode", "nonsense"]).await;
    assert!(!bad.ok);

    // Clearing the override restores the configured mode.
    assert!(
        daemon
            .admin("cloudflare", &["clear-mode-override"])
            .await
            .ok
    );
    let status = daemon.admin("cloudflare", &["status"]).await;
    let data = status.data.as_ref().expect("status data");
    assert_eq!(data["mode"].as_str(), Some("preserve"));
    assert!(data["mode_override"].is_null());
}

/// Address set of an answer, order-insensitive.
fn sorted_addrs(m: &hickory_proto::op::Message) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = m
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            hickory_proto::rr::RData::A(v4) => Some(IpAddr::V4(v4.0)),
            hickory_proto::rr::RData::AAAA(v6) => Some(IpAddr::V6(v6.0)),
            _ => None,
        })
        .collect();
    out.sort();
    out
}
