//! Resource-bound regression tests.
//!
//! Every ceiling in `[resources]`, `[cache]`, `[dnssec]` and `[probe]` should be provable
//! by observation rather than by reading the code. These tests set a limit low enough that
//! exceeding it is unmistakable, then demonstrate that the limit actually binds.
//!
//! The failure mode this suite exists to catch is a configuration field that is parsed,
//! validated, documented and never consulted — a ceiling an operator believes protects
//! them and which in fact does nothing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

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

/// `resources.max_inflight_upstream` must bound concurrent upstream exchanges.
///
/// The ceiling used to exist only as a number in the configuration struct. Nothing on any
/// path acquired against it, so an upstream that stopped answering could accumulate an
/// unbounded number of in-flight exchanges. The semaphore now lives in the scheduler, on
/// the single path every physical upstream exchange goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_inflight_upstream_actually_bounds_upstream_work() {
    const LIMIT: usize = 4;
    let (handler, addr, _servers) = mock().await;

    // Every upstream exchange stalls for long enough that concurrency is observable, and
    // the mock counts how many it is handling at once.
    handler.set_default(Behaviour::Delay(
        Duration::from_millis(300),
        Box::new(Behaviour::Answer(vec![a("slow.test.", 1, "192.0.2.30")])),
    ));

    let fragment = format!(
        "{}\n[resources]\nmax_inflight_upstream = {LIMIT}\n",
        common::udp_upstream_fragment(addr)
    );
    let daemon = Arc::new(Daemon::start(&fragment).await);
    assert_eq!(
        daemon.app.upstream_capacity(),
        LIMIT,
        "the configured ceiling must be the one the scheduler enforces"
    );

    // Far more distinct names than the ceiling, so singleflight cannot mask the effect.
    let mut queries = Vec::new();
    for i in 0..40u32 {
        let daemon = Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            daemon
                .try_query_udp(
                    &common::query(&format!("n{i}.slow.test."), RecordType::A, false),
                    Duration::from_secs(15),
                )
                .await
        }));
    }
    for q in queries {
        let _ = tokio::time::timeout(Duration::from_secs(30), q).await;
    }

    let observed = handler.peak_inflight();
    assert!(observed > 0, "the upstream must have been reached at all");
    assert!(
        observed <= LIMIT,
        "upstream concurrency reached {observed}, above the configured ceiling of {LIMIT}"
    );
}

/// Queries shed at the upstream ceiling must be reported, not silently dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shedding_at_the_upstream_ceiling_is_visible() {
    let (handler, addr, _servers) = mock().await;
    handler.set_default(Behaviour::Delay(
        Duration::from_millis(400),
        Box::new(Behaviour::Answer(vec![a("shed.test.", 1, "192.0.2.31")])),
    ));
    // One name answers immediately, so recovery can be tested without fighting the
    // deliberately slow default.
    handler.set(
        "recovered.shed.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("recovered.shed.test.", 1, "192.0.2.35")]),
    );

    // One slot and a short budget, so waiting for a permit must time out rather than queue.
    let fragment = format!(
        "{}\n[resources]\nmax_inflight_upstream = 1\n",
        common::udp_upstream_fragment(addr)
            .replace("query_timeout = \"2s\"", "query_timeout = \"200ms\"")
    );
    let daemon = Arc::new(Daemon::start(&fragment).await);

    let mut queries = Vec::new();
    for i in 0..16u32 {
        let daemon = Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            daemon
                .try_query_udp(
                    &common::query(&format!("s{i}.shed.test."), RecordType::A, false),
                    Duration::from_secs(10),
                )
                .await
        }));
    }
    let mut servfails = 0;
    for q in queries {
        if let Ok(Ok(Some(response))) = tokio::time::timeout(Duration::from_secs(20), q).await {
            if response.metadata.response_code.low() == 2 {
                servfails += 1;
            }
        }
    }
    assert!(
        servfails > 0,
        "queries shed at the ceiling must be answered with SERVFAIL, not dropped"
    );
    // Overload must not become a permanent failure. The upstream circuit breaker may have
    // opened during the storm, so allow it a few attempts to close rather than asserting
    // on the very first query after the storm.
    let mut recovered = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let response = daemon
            .query_udp(&common::query("recovered.shed.test.", RecordType::A, false))
            .await;
        if response.metadata.response_code.low() == 0 {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "the daemon must recover once the overload passes; shedding is not a latch"
    );
    assert_eq!(
        daemon.app.upstream_slots_available(),
        1,
        "every shed and every success must return its permit"
    );
}

/// Hedging must not multiply the upstream ceiling.
///
/// One resolution can run a primary and a hedge at the same time, against two different
/// routes. When the permit was held per resolution rather than per physical exchange,
/// two in-flight resolutions became four concurrent exchanges at the upstream. The
/// permit now brackets each exchange, so two is two — and a hedge that cannot start
/// immediately is shed rather than queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hedging_cannot_multiply_the_upstream_ceiling() {
    const LIMIT: usize = 2;
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Delay(
        Duration::from_millis(300),
        Box::new(Behaviour::Answer(vec![a("hedged.test.", 1, "192.0.2.40")])),
    ));
    // Two addresses behind one handler: hedging needs two rankable routes, and the
    // shared handler keeps peak_inflight a global count across both of them.
    let (_servers, addrs) = common::start_mock_multi(handler.clone(), 2).await;

    let fragment = format!(
        "{}\n[resources]\nmax_inflight_upstream = {LIMIT}\n",
        common::udp_upstream_fragment_multi(&addrs).replace(
            "hedge_enabled = false",
            "hedge_enabled = true\nhedge_min_delay = \"1ms\"\nhedge_max_fraction = 1.0",
        )
    );
    let daemon = Arc::new(Daemon::start(&fragment).await);

    // Far more distinct names than the ceiling, so singleflight cannot mask the effect.
    let mut queries = Vec::new();
    for i in 0..40u32 {
        let daemon = Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            daemon
                .try_query_udp(
                    &common::query(&format!("h{i}.hedged.test."), RecordType::A, false),
                    Duration::from_secs(20),
                )
                .await
        }));
    }
    for q in queries {
        let _ = tokio::time::timeout(Duration::from_secs(40), q).await;
    }

    // A cancelled hedge cannot un-send its datagram: the mock still finishes processing
    // it after the permit has been released, so the server-side count can transiently
    // exceed the ceiling by the number of such zombies. Creating a zombie takes a
    // resolution holding *both* slots (winner plus loser), so with a ceiling of two at
    // most one can overlap the live exchanges.
    let observed = handler.peak_inflight();
    assert!(observed > 0, "the upstream must have been reached at all");
    assert!(
        observed <= LIMIT + 1,
        "upstream concurrency reached {observed}, more than one cancelled-hedge zombie \
         above the configured ceiling of {LIMIT}"
    );
    assert_eq!(
        daemon.app.upstream_slots_available(),
        LIMIT,
        "every exchange, shed or completed, must return its permit"
    );

    // Without queue pressure the exact bound is observable: two resolutions, each
    // wanting a primary plus a hedge, must never exceed two exchanges on the wire.
    // Before the fix this reached four.
    handler.reset_counts();
    let mut queries = Vec::new();
    for i in 0..LIMIT {
        let daemon = Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            daemon
                .try_query_udp(
                    &common::query(&format!("q{i}.hedged.test."), RecordType::A, false),
                    Duration::from_secs(20),
                )
                .await
        }));
    }
    for q in queries {
        let _ = tokio::time::timeout(Duration::from_secs(20), q).await;
    }
    let observed = handler.peak_inflight();
    assert!(
        observed > 1,
        "the two resolutions must actually overlap upstream for the bound to mean anything"
    );
    assert!(
        observed <= LIMIT,
        "primary plus hedge per resolution reached {observed} concurrent exchanges, \
         above the configured ceiling of {LIMIT}"
    );
}

/// Emergency fan-out must not multiply the upstream ceiling either.
///
/// Fan-out fires when every tried route failed, so its exchanges are real wire traffic
/// on top of the primary's. With a per-resolution permit, one resolution tripled the
/// configured ceiling here; with a per-exchange permit the fan-out attempts contend for
/// the same single slot as everything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emergency_fanout_cannot_multiply_the_upstream_ceiling() {
    let handler = MockUpstream::new();
    // Slow enough that overlapping exchanges are observable, failing so that fan-out
    // fires after the primary.
    handler.set_default(Behaviour::Delay(
        Duration::from_millis(100),
        Box::new(Behaviour::ServFail),
    ));
    let (_servers, addrs) = common::start_mock_multi(handler.clone(), 4).await;

    let fragment = format!(
        "{}\n[resources]\nmax_inflight_upstream = 1\n",
        common::udp_upstream_fragment_multi(&addrs)
    );
    let daemon = Arc::new(Daemon::start(&fragment).await);

    // One query at a time first, so the fan-out's non-blocking acquire is not crowded
    // out by queued primaries: this proves the fan-out really does reach the upstream
    // and is therefore covered by the bound asserted below.
    for i in 0..6u32 {
        let response = daemon
            .query_udp(&common::query(
                &format!("s{i}.fanout.test."),
                RecordType::A,
                false,
            ))
            .await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::ServFail,
            "a failing upstream must yield SERVFAIL"
        );
    }
    assert!(
        handler.query_count() >= 12,
        "each query should cost a primary plus a fan-out exchange, saw {}",
        handler.query_count()
    );

    // Then a concurrent burst, where primaries, fan-out attempts and sheds mix.
    let mut queries = Vec::new();
    for i in 0..12u32 {
        let daemon = Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            daemon
                .try_query_udp(
                    &common::query(&format!("c{i}.fanout.test."), RecordType::A, false),
                    Duration::from_secs(20),
                )
                .await
        }));
    }
    let mut answered = 0;
    for q in queries {
        if let Ok(Ok(Some(response))) = tokio::time::timeout(Duration::from_secs(30), q).await {
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::ServFail,
                "overload and upstream failure both surface as SERVFAIL"
            );
            answered += 1;
        }
    }
    assert_eq!(answered, 12, "every query must be answered, shed or not");

    assert_eq!(
        handler.peak_inflight(),
        1,
        "upstream concurrency reached {} against a configured ceiling of 1",
        handler.peak_inflight()
    );
    assert_eq!(
        daemon.app.upstream_slots_available(),
        1,
        "every exchange, shed or completed, must return its permit"
    );
}

/// A truncated UDP answer retried over TCP must not deadlock against the ceiling.
///
/// The stream retry is a second physical exchange inside one resolution. If the permit
/// were still held for the whole resolution while the retry had to acquire its own, a
/// limit of one would deadlock the resolution against itself: the retry could never get
/// the permit the resolution is holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncation_retry_does_not_deadlock_at_a_ceiling_of_one() {
    let (handler, addr, _servers) = mock().await;
    handler.set_default(Behaviour::TruncatedOnUdp(vec![a(
        "trunc.test.",
        300,
        "192.0.2.60",
    )]));

    let fragment = format!(
        "{}\n[resources]\nmax_inflight_upstream = 1\n",
        common::udp_upstream_fragment(addr)
    );
    let daemon = Daemon::start(&fragment).await;

    let response = tokio::time::timeout(
        Duration::from_secs(10),
        daemon.query_udp(&common::query("trunc.test.", RecordType::A, false)),
    )
    .await
    .expect("the stream retry must complete well inside the budget");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response).len(),
        1,
        "the full answer must come from the stream retry, not the truncated UDP answer"
    );
    assert_eq!(
        daemon.app.upstream_slots_available(),
        1,
        "the UDP exchange and the TCP retry must each return their permit"
    );
}

/// `resources.max_inflight_queries` must bound concurrent *client* work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_inflight_queries_bounds_client_concurrency() {
    let (handler, addr, _servers) = mock().await;
    handler.set_default(Behaviour::Answer(vec![a("fast.test.", 1, "192.0.2.32")]));
    let fragment = format!(
        "{}\n[resources]\nmax_inflight_queries = 8\n",
        common::udp_upstream_fragment(addr)
    );
    let daemon = Daemon::start(&fragment).await;
    assert_eq!(
        daemon.app.inflight.available_permits(),
        8,
        "the client ceiling must be the configured value, not a default"
    );
    // The permit is released on every path, so an idle daemon is back at full capacity.
    let _ = daemon
        .query_udp(&common::query("fast.test.", RecordType::A, false))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        daemon.app.inflight.available_permits(),
        8,
        "an answered query must return its permit"
    );
}

/// The answer cache must respect its byte budget rather than growing without limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cache_respects_its_byte_budget() {
    let (handler, addr, _servers) = mock().await;
    handler.set_default(Behaviour::Answer(vec![a("big.test.", 3600, "192.0.2.33")]));

    // 1 MiB is the validated minimum, which is small enough that a few thousand entries
    // must force eviction.
    let fragment = format!(
        "{}\n[cache]\nmax_memory_bytes = 1048576\nvariant_max_memory_bytes = 1048576\n",
        common::udp_upstream_fragment(addr)
    );
    let daemon = Daemon::start(&fragment).await;

    for i in 0..3_000u32 {
        let _ = daemon
            .try_query_udp(
                &common::query(&format!("k{i}.big.test."), RecordType::A, false),
                Duration::from_secs(5),
            )
            .await;
    }
    // moka evicts asynchronously; give it a moment to run the maintenance pass.
    daemon.app.cache.run_maintenance();
    tokio::time::sleep(Duration::from_millis(300)).await;
    daemon.app.cache.run_maintenance();

    let stats = daemon.app.cache.stats();
    assert!(
        stats.answer_bytes <= 2 * 1_048_576,
        "the cache grew to {} bytes against a 1 MiB budget",
        stats.answer_bytes
    );
    assert!(
        stats.answer_entries < 3_000,
        "a 1 MiB budget cannot hold 3000 answers; eviction did not run ({} entries)",
        stats.answer_entries
    );
}

/// `dnssec.max_concurrent_validations` must be a real semaphore, not a stored integer.
#[tokio::test]
async fn dnssec_validation_concurrency_is_bounded() {
    let (_handler, addr, _servers) = mock().await;
    let fragment = common::udp_upstream_fragment(addr).replace(
        "[dnssec]\nmode = \"off\"",
        "[dnssec]\nmode = \"validate\"\nmax_concurrent_validations = 3",
    );
    let daemon = Daemon::start(&fragment).await;
    assert_eq!(
        daemon.app.validation_capacity(),
        3,
        "the configured ceiling must be the one the resolver enforces"
    );
    assert_eq!(
        daemon.app.validation_slots_available(),
        3,
        "an idle daemon must hold no validation permits"
    );
}

/// The probe engine must not create a Tokio task per queued job.
///
/// The old engine received a job, spawned a task, and only then awaited a stage semaphore.
/// A burst of N jobs therefore became N live tasks regardless of the configured
/// concurrency, with the queue depth as the real ceiling. The permit is now acquired
/// before the job is taken from the channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_workers_are_bounded_before_a_job_is_dequeued() {
    let (_handler, addr, _servers) = mock().await;
    let fragment = common::udp_upstream_fragment(addr).replace(
        "[probe]\nenabled = false",
        "[probe]\nenabled = true\nqueue_size = 4096\nconcurrency = 2\n\
         global_connections_per_second = 1000",
    );
    let daemon = Daemon::start(&fragment).await;
    daemon.spawn_background();

    let before = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    for i in 0..2_000u32 {
        daemon
            .app
            .probes
            .offer(egressdns::probe::job::ProbeJob::Candidate {
                addr: format!("104.16.{}.{}", i / 256, i % 256)
                    .parse()
                    .expect("ip"),
                port: 443,
                generation: 0,
            });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let growth = after.saturating_sub(before);

    // A handful of tasks is expected: the engine itself, the in-flight probes, and the
    // supervisor. Two thousand is the bug.
    assert!(
        growth < 200,
        "offering 2000 probe jobs created {growth} live tasks; \
         the worker ceiling is not being applied before dequeue"
    );
}

/// The probe safety guard must bound how much state it accumulates.
#[tokio::test]
async fn the_probe_guard_prunes_its_cooldown_tables() {
    let cfg = egressdns::config::ProbeConfig {
        enabled: true,
        per_ip_cooldown: Duration::from_millis(1),
        per_prefix_cooldown: Duration::from_millis(1),
        per_domain_cooldown: Duration::from_millis(1),
        global_connections_per_second: 1_000_000,
        daily_bandwidth_budget_bytes: u64::MAX,
        ..egressdns::config::ProbeConfig::default()
    };
    let guard = egressdns::probe::safety::ProbeGuard::new(&cfg);
    let start = tokio::time::Instant::now();
    for i in 0..120_000u32 {
        let addr: std::net::IpAddr =
            format!("104.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)
                .parse()
                .expect("ip");
        let _ = guard.admit(
            addr,
            443,
            false,
            None,
            start + Duration::from_millis(u64::from(i)),
        );
    }
    let tracked = guard.tracked();
    assert!(
        tracked <= 60_000,
        "the cooldown table grew to {tracked} entries with no upper bound"
    );
}
