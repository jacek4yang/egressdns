//! Scheduling, degradation and reload behaviour.

mod common;

use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn two_upstream_fragment(
    slow: std::net::SocketAddr,
    fast: std::net::SocketAddr,
    extra: &str,
) -> String {
    format!(
        r#"
[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "slow"
transport = "udp"
addresses = ["{sip}"]
port = {sport}
weight = 100

[[upstream.groups.servers]]
name = "fast"
transport = "udp"
addresses = ["{fip}"]
port = {fport}
weight = 100

[upstream.groups.scheduler]
hedge_enabled = true
hedge_min_delay = "50ms"
hedge_max_delay = "200ms"
hedge_max_fraction = 1.0
query_timeout = "2s"

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
{extra}
"#,
        sip = slow.ip(),
        sport = slow.port(),
        fip = fast.ip(),
        fport = fast.port()
    )
}

#[tokio::test]
async fn a_hedge_rescues_a_stalled_primary() {
    let slow_handler = MockUpstream::new();
    slow_handler.set(
        "hedge.example.test.",
        RecordType::A,
        Behaviour::Delay(
            Duration::from_millis(1_500),
            Box::new(Behaviour::Answer(vec![a(
                "hedge.example.test.",
                300,
                "203.0.113.1",
            )])),
        ),
    );
    let fast_handler = MockUpstream::new();
    fast_handler.set(
        "hedge.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("hedge.example.test.", 300, "203.0.113.2")]),
    );

    let ca = TestCa::new();
    let slow = common::start_mock(slow_handler, &ca, "dns.example.test", Transports::plain()).await;
    let fast = common::start_mock(
        fast_handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let daemon = Daemon::start(&two_upstream_fragment(
        slow.udp.expect("slow udp"),
        fast.udp.expect("fast udp"),
        "",
    ))
    .await;

    let started = std::time::Instant::now();
    let response = daemon
        .query_udp(&common::query("hedge.example.test.", RecordType::A, false))
        .await;
    let elapsed = started.elapsed();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(common::addresses(&response).len(), 1);
    assert!(
        elapsed < Duration::from_millis(1_400),
        "the hedge should have answered long before the slow route, took {elapsed:?}"
    );
    assert!(
        fast_handler.query_count() >= 1,
        "the hedge must actually be sent"
    );
}

#[tokio::test]
async fn all_upstreams_failing_without_stale_data_returns_servfail() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::ServFail);
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(servers.udp.expect("udp"))).await;

    let response = daemon
        .query_udp(&common::query("down.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn stale_data_is_served_when_every_upstream_fails() {
    let handler = MockUpstream::new();
    handler.set(
        "stale.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("stale.example.test.", 1, "203.0.113.55")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let fragment = format!(
        "{}\n[serve_stale]\nenabled = true\nclient_timeout = \"300ms\"\nmax_stale = \"1h\"\n",
        common::udp_upstream_fragment(servers.udp.expect("udp"))
    );
    let daemon = Daemon::start(&fragment).await;

    // Populate the cache with a one-second TTL.
    let warm = daemon
        .query_udp(&common::query("stale.example.test.", RecordType::A, false))
        .await;
    assert_eq!(common::addresses(&warm).len(), 1);

    // Break the upstream and let the entry expire.
    handler.set("stale.example.test.", RecordType::A, Behaviour::Drop);
    tokio::time::sleep(Duration::from_millis(1_400)).await;

    let response = daemon
        .query_udp(&common::query("stale.example.test.", RecordType::A, false))
        .await;
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "RFC 8767 stale data should still be served"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.55".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(
        response.answers[0].ttl <= 30,
        "a stale answer must carry a short TTL, got {}",
        response.answers[0].ttl
    );
    // RFC 8914 Extended DNS Error 3 (Stale Answer).
    let edes = egressdns::dns::message::extract_edes(&response);
    assert!(
        edes.iter().any(|(code, _)| *code == 3),
        "a stale answer should carry EDE 3, saw {edes:?}"
    );
}

#[tokio::test]
async fn a_broken_upstream_opens_its_circuit_and_recovers() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::ServFail);
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let fragment = common::udp_upstream_fragment(servers.udp.expect("udp")).replace(
        "query_timeout = \"2s\"",
        "query_timeout = \"500ms\"\ncircuit_failure_threshold = 3\ncircuit_open_duration = \"500ms\"\ncircuit_half_open_successes = 1",
    );
    let daemon = Daemon::start(&fragment).await;

    for i in 0..12u8 {
        let _ = daemon
            .query_udp(&common::query(
                &format!("f{i}.example.test."),
                RecordType::A,
                false,
            ))
            .await;
    }
    let admin = daemon.admin("upstreams", &[]).await;
    let data = admin.data.expect("data");
    let circuit = data["groups"][0]["routes"][0]["circuit"]
        .as_str()
        .expect("circuit")
        .to_string();
    assert!(
        circuit == "open" || circuit == "suspect" || circuit == "half_open",
        "a persistently failing route should not stay closed, saw {circuit}"
    );

    // Once the upstream recovers, resolution must resume.
    handler.set_default(Behaviour::Answer(vec![a(
        "ok.example.test.",
        300,
        "203.0.113.9",
    )]));
    let mut recovered = false;
    for attempt in 0..40u32 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        // A fresh name each round so RFC 9520 failure suppression does not mask recovery.
        let r = daemon
            .query_udp(&common::query(
                &format!("ok{attempt}.example.test."),
                RecordType::A,
                false,
            ))
            .await;
        if r.metadata.response_code == ResponseCode::NoError && !r.answers.is_empty() {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "the resolver must recover after the upstream does"
    );
}

#[tokio::test]
async fn configuration_reload_does_not_interrupt_service() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "live.example.test.",
        60,
        "203.0.113.30",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let base = common::udp_upstream_fragment(servers.udp.expect("udp"));
    let daemon = std::sync::Arc::new(Daemon::start(&base).await);

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let errors = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let successes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut workers = Vec::new();
    for _ in 0..4 {
        let d = std::sync::Arc::clone(&daemon);
        let stop = std::sync::Arc::clone(&stop);
        let errors = std::sync::Arc::clone(&errors);
        let successes = std::sync::Arc::clone(&successes);
        workers.push(tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let r = d
                    .try_query_udp(
                        &common::query("live.example.test.", RecordType::A, false),
                        Duration::from_secs(5),
                    )
                    .await;
                match r {
                    Some(m) if m.metadata.response_code == ResponseCode::NoError => {
                        successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {
                        errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    // Reload repeatedly while traffic flows.
    let original = std::fs::read_to_string(&daemon.config_path).expect("read");
    for cap in [45u32, 55, 65, 75] {
        tokio::time::sleep(Duration::from_millis(120)).await;
        let updated = format!("{original}\n[ttl]\ncap_default = {cap}\n");
        std::fs::write(&daemon.config_path, updated).expect("write");
        daemon.app.reload().expect("reload must succeed");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for w in workers {
        let _ = w.await;
    }

    let ok = successes.load(std::sync::atomic::Ordering::Relaxed);
    let bad = errors.load(std::sync::atomic::Ordering::Relaxed);
    assert!(ok > 20, "expected sustained traffic, saw {ok} successes");
    assert_eq!(bad, 0, "reloading must not drop or fail any query");
    assert_eq!(daemon.app.config().ttl.cap_default, 75);
    assert_eq!(daemon.app.reload_count(), 4);
}

#[tokio::test]
async fn an_invalid_reload_leaves_the_daemon_serving() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "keep.example.test.",
        60,
        "203.0.113.31",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(servers.udp.expect("udp"))).await;

    let before = daemon
        .query_udp(&common::query("keep.example.test.", RecordType::A, false))
        .await;
    assert_eq!(before.metadata.response_code, ResponseCode::NoError);

    std::fs::write(&daemon.config_path, "this is not valid toml {{{").expect("write");
    assert!(daemon.app.reload().is_err());

    let after = daemon
        .query_udp(&common::query("keep.example.test.", RecordType::A, false))
        .await;
    assert_eq!(after.metadata.response_code, ResponseCode::NoError);
    assert_eq!(common::addresses(&after).len(), 1);
    assert!(daemon.app.last_reload_error().is_some());
}

#[tokio::test]
async fn admin_flush_forces_a_fresh_upstream_query() {
    let handler = MockUpstream::new();
    handler.set(
        "flush.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("flush.example.test.", 3_600, "203.0.113.40")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(servers.udp.expect("udp"))).await;

    daemon
        .query_udp(&common::query("flush.example.test.", RecordType::A, false))
        .await;
    daemon
        .query_udp(&common::query("flush.example.test.", RecordType::A, false))
        .await;
    assert_eq!(handler.count_for("flush.example.test.", RecordType::A), 1);

    assert!(
        daemon
            .admin("flush-name", &["flush.example.test."])
            .await
            .ok
    );
    daemon
        .query_udp(&common::query("flush.example.test.", RecordType::A, false))
        .await;
    assert_eq!(
        handler.count_for("flush.example.test.", RecordType::A),
        2,
        "flushing must force a fresh upstream query"
    );
}

#[tokio::test]
async fn local_zones_and_hosts_answer_without_any_upstream() {
    // No upstream is reachable at all; local data must still resolve.
    let fragment = r#"
[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "unreachable"
transport = "udp"
addresses = ["10.255.255.1"]
port = 53

[upstream.groups.scheduler]
query_timeout = "300ms"

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false

[local]
local_ttl = 45

[[local.hosts]]
name = "printer.corp.test"
addresses = ["10.0.0.9"]

[[local.zones]]
name = "corp.test"
authoritative = true

[[local.zones.records]]
name = "gw"
rtype = "A"
value = "10.0.0.1"
"#;
    let daemon = Daemon::start(fragment).await;

    let hosts = daemon
        .query_udp(&common::query("printer.corp.test.", RecordType::A, false))
        .await;
    assert_eq!(hosts.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&hosts),
        vec!["10.0.0.9".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert_eq!(hosts.answers[0].ttl, 45);

    let zone = daemon
        .query_udp(&common::query("gw.corp.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&zone),
        vec!["10.0.0.1".parse::<std::net::IpAddr>().expect("ip")]
    );

    let missing = daemon
        .query_udp(&common::query("nope.corp.test.", RecordType::A, false))
        .await;
    assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
}
