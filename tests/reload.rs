//! Behavioural hot-reload tests.
//!
//! Every test here asserts on **observable runtime behaviour** after a reload — which
//! upstream answered, whether probing stopped, what the client received — rather than on
//! the contents of the in-memory configuration. Inspecting `app.config()` after a reload
//! only proves that a struct was replaced; it says nothing about whether the data plane
//! and the control plane are actually using it, which was exactly the defect this suite
//! exists to prevent from returning.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::rr::RecordType;

/// Start one plain UDP mock upstream and return its address alongside the handler.
async fn mock() -> (MockUpstream, std::net::SocketAddr, common::MockServers) {
    let handler = MockUpstream::new();
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports {
            udp: true,
            tcp: true,
            ..Transports::default()
        },
    )
    .await;
    let addr = servers.udp.expect("mock udp");
    (handler, addr, servers)
}

/// A reload must change which upstream the *foreground* path uses.
///
/// This is the load-bearing case: a reload that leaves foreground queries pinned to the
/// old upstream is not a reload at all.
#[tokio::test]
async fn a_reload_moves_foreground_queries_to_the_new_upstream() {
    let (first, first_addr, _first_servers) = mock().await;
    let (second, second_addr, _second_servers) = mock().await;
    first.set(
        "moved.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("moved.test.", 1, "192.0.2.1")]),
    );
    second.set(
        "moved.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("moved.test.", 1, "198.51.100.1")]),
    );

    let daemon = Daemon::start(&common::udp_upstream_fragment(first_addr)).await;
    let response = daemon
        .query_udp(&common::query("moved.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.1".parse::<std::net::IpAddr>().expect("ip")],
        "the first upstream must answer before the reload"
    );

    daemon
        .reload_with(&common::udp_upstream_fragment(second_addr))
        .expect("changing an upstream address is reloadable");

    // A fresh name, so the answer cannot come from the cache.
    second.set(
        "after.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("after.test.", 1, "198.51.100.2")]),
    );
    let response = daemon
        .query_udp(&common::query("after.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&response),
        vec!["198.51.100.2".parse::<std::net::IpAddr>().expect("ip")],
        "the reloaded upstream must answer after the reload"
    );
    assert_eq!(
        first.count_for("after.test.", RecordType::A),
        0,
        "the pre-reload upstream must not receive post-reload queries"
    );
}

/// Turning probing off by reload must actually stop probe work.
///
/// The probe queue used to be created enabled at startup and never consulted the live
/// configuration, so `probe.enabled = false` was accepted, reported as reloaded, and
/// changed nothing until the process restarted.
#[tokio::test]
async fn disabling_probing_by_reload_stops_probe_work() {
    let (_handler, addr, _servers) = mock().await;
    let base = common::udp_upstream_fragment(addr);
    let enabled = base.replace(
        "[probe]\nenabled = false",
        "[probe]\nenabled = true\nqueue_size = 64",
    );
    let daemon = Daemon::start(&enabled).await;
    assert!(
        daemon.app.config().probe.enabled,
        "the fixture must start with probing enabled"
    );
    assert!(
        daemon.app.probes.is_enabled(),
        "the probe queue must accept work while probing is enabled"
    );

    let disabled = enabled.replace(
        "[probe]\nenabled = true\nqueue_size = 64",
        "[probe]\nenabled = false\nqueue_size = 64",
    );
    daemon
        .reload_with(&disabled)
        .expect("probe.enabled is reloadable");

    assert!(
        !daemon.app.probes.is_enabled(),
        "the probe queue must refuse work after probing is disabled by reload"
    );
    assert!(
        !daemon
            .app
            .probes
            .offer(egressdns::probe::job::ProbeJob::Candidate {
                addr: "104.16.0.1".parse().expect("ip"),
                port: 443,
                generation: 0,
            }),
        "an offer made while probing is disabled must be refused, not queued"
    );

    // ... and re-enabling by reload must bring it back without a restart.
    daemon
        .reload_with(&enabled)
        .expect("probe.enabled is reloadable in both directions");
    assert!(
        daemon.app.probes.is_enabled(),
        "re-enabling probing by reload must not require a restart"
    );
}

/// A restart-required change must be refused by name, and must change nothing.
#[tokio::test]
async fn a_restart_required_change_is_refused_and_leaves_the_process_untouched() {
    let (handler, addr, _servers) = mock().await;
    handler.set(
        "still-up.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("still-up.test.", 1, "192.0.2.11")]),
    );
    let base = common::udp_upstream_fragment(addr);
    let daemon = Daemon::start(&base).await;
    let before_reloads = daemon.app.reload_count();
    let before_budget = daemon.app.config().cache.max_memory_bytes;

    let changed = format!("{base}\n[cache]\nmax_memory_bytes = 134217728\n");
    let error = daemon
        .reload_with(&changed)
        .expect_err("cache.max_memory_bytes must be refused as restart-required");

    assert!(
        error.contains("cache.max_memory_bytes"),
        "the refusal must name the offending field, got: {error}"
    );
    assert!(
        error.contains("restart"),
        "the refusal must say a restart is required, got: {error}"
    );
    assert_eq!(
        daemon.app.config().cache.max_memory_bytes,
        before_budget,
        "a refused reload must not partially apply"
    );
    assert_eq!(
        daemon.app.reload_count(),
        before_reloads,
        "a refused reload must not be counted as a successful one"
    );
    assert_eq!(
        daemon.app.last_reload_error().as_deref(),
        Some(error.as_str()),
        "the refusal must be visible to an operator"
    );

    // The daemon must still answer queries normally.
    let response = daemon
        .query_udp(&common::query("still-up.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.11".parse::<std::net::IpAddr>().expect("ip")],
        "a refused reload must leave the data plane serving normally"
    );
}

/// Reloading `cloudflare.mode` must reach the shared state the answer path reads.
///
/// `CloudflareState` is retained across reloads and used to capture `mode` at
/// construction, so a reloaded mode was accepted, reported as applied, and ignored by
/// the foreground until a restart.
#[tokio::test]
async fn reloading_the_cloudflare_mode_reaches_the_foreground_state() {
    let (_handler, addr, _servers) = mock().await;
    let base = common::udp_upstream_fragment(addr);
    // verified-augment is only valid with probing on.
    let probing = base.replace("[probe]\nenabled = false", "[probe]\nenabled = true");
    let preserve = format!("{probing}\n[cloudflare]\nenabled = true\nmode = \"preserve\"\n");
    let daemon = Daemon::start(&preserve).await;
    assert_eq!(
        daemon.app.cloudflare.mode(),
        egressdns::config::CloudflareMode::Preserve,
        "the configured mode must be live at startup"
    );

    let augment = preserve.replace("mode = \"preserve\"", "mode = \"verified-augment\"");
    daemon
        .reload_with(&augment)
        .expect("cloudflare.mode is reloadable");

    assert_eq!(
        daemon.app.cloudflare.mode(),
        egressdns::config::CloudflareMode::VerifiedAugment,
        "the retained Cloudflare state must follow the reloaded mode"
    );
    assert_eq!(
        daemon.app.cloudflare.configured_mode(),
        egressdns::config::CloudflareMode::VerifiedAugment,
        "the configured mode, not just the effective one, must follow the reload"
    );

    // The admin surface reads the same shared state as the answer path.
    let status = daemon.admin("cloudflare", &["status"]).await;
    assert!(status.ok, "cloudflare status must succeed: {status:?}");
    let data = status.data.expect("status payload");
    assert_eq!(data["mode"].as_str(), Some("verified_augment"));
    assert_eq!(data["configured_mode"].as_str(), Some("verified_augment"));
}

/// Toggling `cloudflare.enabled` by reload must flip what the answer path reads.
#[tokio::test]
async fn toggling_cloudflare_enabled_by_reload_reaches_the_foreground_state() {
    let (_handler, addr, _servers) = mock().await;
    let base = common::udp_upstream_fragment(addr);
    let daemon = Daemon::start(&base).await;
    assert!(
        !daemon.app.cloudflare.enabled(),
        "the fixture must start with the subsystem disabled"
    );

    let enabled = format!("{base}\n[cloudflare]\nenabled = true\nmode = \"preserve\"\n");
    daemon
        .reload_with(&enabled)
        .expect("cloudflare.enabled is reloadable");
    assert!(
        daemon.app.cloudflare.enabled(),
        "the retained Cloudflare state must follow the reloaded switch"
    );

    daemon
        .reload_with(&base)
        .expect("cloudflare.enabled is reloadable in both directions");
    assert!(
        !daemon.app.cloudflare.enabled(),
        "disabling the subsystem by reload must not require a restart"
    );
}

/// Cloudflare's structural settings are fixed at construction and must be refused.
#[tokio::test]
async fn cloudflare_structural_changes_are_refused_as_restart_required() {
    let (handler, addr, _servers) = mock().await;
    handler.set(
        "still-up.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("still-up.test.", 1, "192.0.2.13")]),
    );
    let base = common::udp_upstream_fragment(addr);
    let daemon = Daemon::start(&base).await;
    let before_reloads = daemon.app.reload_count();

    for (addition, field) in [
        (
            "[cloudflare]\ncandidate_pool_max = 8192",
            "cloudflare.candidate_pool_max",
        ),
        (
            "[cloudflare.sampling]\nseed = 42",
            "cloudflare.sampling.seed",
        ),
        (
            "[cloudflare.sampling]\nbuckets_per_prefix = 128",
            "cloudflare.sampling.buckets_per_prefix",
        ),
        (
            "[cloudflare.sampling]\nexploit_fraction = 0.9",
            "cloudflare.sampling.exploit_fraction",
        ),
    ] {
        let changed = format!("{base}\n{addition}\n");
        let error = daemon
            .reload_with(&changed)
            .expect_err("structural Cloudflare settings must be restart-required");
        assert!(
            error.contains(field),
            "the refusal must name {field}, got: {error}"
        );
        assert!(
            error.contains("restart"),
            "the refusal must say a restart is required, got: {error}"
        );
    }

    assert_eq!(
        daemon.app.reload_count(),
        before_reloads,
        "refused reloads must not be counted as successful"
    );

    // The daemon must still answer queries normally from the untouched configuration.
    let response = daemon
        .query_udp(&common::query("still-up.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.13".parse::<std::net::IpAddr>().expect("ip")],
        "a refused reload must leave the data plane serving normally"
    );
}

/// An invalid configuration must leave a *working* daemon behind, not a half-applied one.
#[tokio::test]
async fn an_invalid_reload_leaves_the_runtime_healthy() {
    let (handler, addr, _servers) = mock().await;
    handler.set(
        "healthy.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("healthy.test.", 1, "192.0.2.7")]),
    );
    let base = common::udp_upstream_fragment(addr);
    let daemon = Daemon::start(&base).await;
    let before = daemon.app.reload_count();

    for broken in [
        "this is not toml at all {{{",
        "[upstream]\nno_such_field = 1",
        // Parses, but fails semantic validation: a group with no servers.
        "[[upstream.groups]]\nname = \"empty\"\n",
    ] {
        let error = daemon
            .reload_with(broken)
            .expect_err("an invalid configuration must be refused");
        assert!(!error.is_empty(), "a refusal must explain itself");
        assert_eq!(
            daemon.app.reload_count(),
            before,
            "a failed reload must not be counted"
        );

        let response = daemon
            .query_udp(&common::query("healthy.test.", RecordType::A, false))
            .await;
        assert_eq!(
            common::addresses(&response),
            vec!["192.0.2.7".parse::<std::net::IpAddr>().expect("ip")],
            "the daemon must keep serving from the last good configuration"
        );
    }
}

/// A background task must observe the new configuration, not the one it started with.
///
/// This is the structural version of the P0 defect: every supervised task used to receive
/// a `Config` clone at spawn time. Here the control plane is actually running, and the
/// assertion is that a task's view of the world changes after a reload.
#[tokio::test]
async fn background_tasks_observe_the_reloaded_configuration() {
    let (_handler, addr, _servers) = mock().await;
    let base = common::udp_upstream_fragment(addr);
    let daemon = Daemon::start(&base).await;
    daemon.spawn_background();
    assert!(
        daemon.app.background_tasks() > 0,
        "the control plane must actually be running for this test to mean anything"
    );

    // The prefetcher is the clearest case: it is a background task that issues upstream
    // queries, so its resolver must follow a reload.
    let before = Arc::as_ptr(&daemon.app.state().resolver);
    daemon
        .reload_with(&base.replace("hedge_enabled = false", "hedge_enabled = true"))
        .expect("scheduler settings are reloadable");
    let after = Arc::as_ptr(&daemon.app.state().resolver);
    assert_ne!(
        before, after,
        "a reload must install a new resolver, not mutate the old one"
    );

    // Give the tasks a tick to observe it, then confirm none of them died.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        daemon.app.background_tasks() > 0,
        "no background task may exit because of a reload"
    );
    assert!(
        daemon.app.config().upstream.groups[0]
            .scheduler
            .hedge_enabled,
        "the reloaded value must be the live one"
    );
}

/// Repeated reloads under query load must not deadlock, leak tasks, or drop answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_reloads_under_load_stay_healthy() {
    let (handler, addr, _servers) = mock().await;
    handler.set_default(Behaviour::Answer(vec![a("load.test.", 1, "192.0.2.9")]));
    let base = common::udp_upstream_fragment(addr);
    let daemon = Arc::new(Daemon::start(&base).await);
    daemon.spawn_background();
    let tasks_before = daemon.app.background_tasks();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut load = Vec::new();
    for worker in 0..4u32 {
        let daemon = Arc::clone(&daemon);
        let stop = Arc::clone(&stop);
        load.push(tokio::spawn(async move {
            let mut sent = 0u32;
            let mut answered = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let name = format!("q{worker}-{sent}.load.test.");
                sent += 1;
                if let Some(response) = daemon
                    .try_query_udp(
                        &common::query(&name, RecordType::A, false),
                        Duration::from_secs(5),
                    )
                    .await
                {
                    if response.metadata.response_code.low() == 0 {
                        answered += 1;
                    }
                }
            }
            (sent, answered)
        }));
    }

    // Alternate two reloadable configurations while the load is running.
    for round in 0..20u32 {
        let fragment = if round % 2 == 0 {
            base.replace("hedge_enabled = false", "hedge_enabled = true")
        } else {
            base.clone()
        };
        daemon
            .reload_with(&fragment)
            .unwrap_or_else(|e| panic!("reload {round} must succeed: {e}"));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut total_sent = 0u32;
    let mut total_answered = 0u32;
    for handle in load {
        let (sent, answered) = tokio::time::timeout(Duration::from_secs(20), handle)
            .await
            .expect("no load worker may hang across a reload")
            .expect("no load worker may panic");
        total_sent += sent;
        total_answered += answered;
    }

    assert!(
        total_sent > 20,
        "the test must have generated real load, got {total_sent} queries"
    );
    // Some loss is acceptable under a deliberately hostile reload storm; a collapse is not.
    let ratio = f64::from(total_answered) / f64::from(total_sent.max(1));
    assert!(
        ratio > 0.90,
        "queries must keep being answered across reloads: {total_answered}/{total_sent}"
    );
    assert_eq!(
        daemon.app.reload_count(),
        20,
        "every reload in the storm must have been applied"
    );
    assert_eq!(
        daemon.app.background_tasks(),
        tasks_before,
        "reloading must not leak or kill background tasks"
    );
}

/// Shutdown must actually wait for the control plane rather than sleeping and hoping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_joins_every_background_task() {
    let (_handler, addr, _servers) = mock().await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(addr)).await;
    daemon.spawn_background();
    let spawned = daemon.app.background_tasks();
    assert!(spawned > 0, "there must be tasks to join");

    let aborted = tokio::time::timeout(
        Duration::from_secs(30),
        daemon.app.shutdown_and_join(Duration::from_secs(10)),
    )
    .await
    .expect("shutdown must not hang");

    assert_eq!(
        aborted, 0,
        "every background task must stop within the deadline on its own"
    );
    assert_eq!(
        daemon.app.background_tasks(),
        0,
        "the supervisor must be empty after a joined shutdown"
    );
}
