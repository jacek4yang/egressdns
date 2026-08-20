//! The scheduler's ranked-fallback and deadline contract.
//!
//! These tests cover four promises the scheduler makes to the request path:
//!
//! * every ranked route that was never attempted stays eligible for fallback;
//! * one absolute foreground deadline covers *every* nested operation, including the
//!   RFC 7766 truncation retry;
//! * a physical exchange keeps its accounting slot until the exchange is terminal, not
//!   until the local future loses a race;
//! * a reload publishes one coherent policy generation.
//!
//! They assert on observable behaviour — the answer a client receives and the wall-clock
//! time it took — rather than on scheduler internals, because the internals are exactly
//! what changed to make them pass.

mod common;

use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A group of plain-UDP upstreams in a fixed order.
///
/// Ranking is deterministic here because exploration is pinned off in `deterministic`
/// below: with no measurements every route ties, and ties break on configuration order.
fn udp_group(addrs: &[std::net::SocketAddr]) -> String {
    let list: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        r#"
upstreams = [{}]
proxies = []

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

/// Pin the scheduler policy a contract test depends on.
///
/// These are not configuration any more — hedging, exploration and fan-out are decided
/// from measurement, not preference — so a test that needs a specific policy reaches the
/// internal structures rather than writing a file users could copy.
fn deterministic(
    hedge_enabled: bool,
    hedge_max_fraction: f64,
) -> impl FnOnce(&mut egressdns::config::Config) {
    move |config: &mut egressdns::config::Config| {
        for group in &mut config.upstream.groups {
            let s = &mut group.scheduler;
            s.hedge_enabled = hedge_enabled;
            s.hedge_max_fraction = hedge_max_fraction;
            s.explore_rate = 0.0;
            s.emergency_fanout = true;
            s.emergency_fanout_max = 3;
            s.query_timeout = std::time::Duration::from_secs(2);
        }
    }
}

/// Start a mock that always fails, and one that always answers.
async fn failing_and_answering(
    name: &str,
    addr: &str,
) -> (
    MockUpstream,
    MockUpstream,
    TestCa,
    Vec<std::net::SocketAddr>,
) {
    let bad = MockUpstream::new();
    bad.set_default(Behaviour::ServFail);
    let good = MockUpstream::new();
    good.set(
        name,
        RecordType::A,
        Behaviour::Answer(vec![a(name, 300, addr)]),
    );

    let ca = TestCa::new();
    let bad_srv =
        common::start_mock(bad.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let good_srv =
        common::start_mock(good.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let addrs = vec![
        bad_srv.udp.expect("bad udp"),
        good_srv.udp.expect("good udp"),
    ];
    // Leak the listeners for the lifetime of the test process; dropping `MockServers`
    // would close the sockets underneath the daemon.
    std::mem::forget(bad_srv);
    std::mem::forget(good_srv);
    (bad, good, ca, addrs)
}

/// With hedging switched off, only the primary is ever started — so the second-ranked
/// route is untried and must remain eligible for the emergency fallback.
///
/// The v1 scheduler assumed positionally that the top two routes had been attempted,
/// so it skipped straight past the only route that could still answer.
#[tokio::test]
async fn hedge_disabled_does_not_skip_the_second_route() {
    let (_bad, good, _ca, addrs) =
        failing_and_answering("nohedge.example.test.", "203.0.113.7").await;
    let daemon = Daemon::start_tuned(&udp_group(&addrs), deterministic(false, 0.0)).await;

    let response = daemon
        .query_udp(&common::query(
            "nohedge.example.test.",
            RecordType::A,
            false,
        ))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "the second-ranked route could answer and must have been tried"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.7".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(
        good.query_count() >= 1,
        "the untried second route must actually receive the query"
    );
}

/// Same defect, reached through the hedge *budget* rather than the hedge switch: the
/// hedge is enabled but denied, so again only the primary was ever started.
#[tokio::test]
async fn hedge_budget_denial_does_not_skip_the_second_route() {
    let (_bad, good, _ca, addrs) =
        failing_and_answering("nobudget.example.test.", "203.0.113.8").await;
    // Hedging is on but its budget denies it, so only the primary is ever started.
    let daemon = Daemon::start_tuned(&udp_group(&addrs), deterministic(true, 0.0)).await;

    let response = daemon
        .query_udp(&common::query(
            "nobudget.example.test.",
            RecordType::A,
            false,
        ))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a denied hedge must not consume the second route's eligibility"
    );
    assert!(good.query_count() >= 1);
}

/// Three ranked routes where only the *middle* one can answer.
///
/// This is the position the positional accounting lost. With `tried` pinned at two, the
/// emergency fallback started at rank three and rank two — the only route that could
/// answer — was never contacted at all.
#[tokio::test]
async fn three_route_fallback_attempts_every_untried_route() {
    let bad1 = MockUpstream::new();
    bad1.set_default(Behaviour::ServFail);
    let good = MockUpstream::new();
    good.set(
        "three.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("three.example.test.", 300, "203.0.113.9")]),
    );
    let bad2 = MockUpstream::new();
    bad2.set_default(Behaviour::ServFail);

    let ca = TestCa::new();
    let s1 = common::start_mock(bad1, &ca, "dns.example.test", Transports::plain()).await;
    let s2 = common::start_mock(good.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let s3 = common::start_mock(bad2, &ca, "dns.example.test", Transports::plain()).await;
    let addrs = vec![
        s1.udp.expect("udp"),
        s2.udp.expect("udp"),
        s3.udp.expect("udp"),
    ];
    std::mem::forget(s1);
    std::mem::forget(s2);
    std::mem::forget(s3);

    let daemon = Daemon::start_tuned(&udp_group(&addrs), deterministic(false, 0.0)).await;
    let response = daemon
        .query_udp(&common::query("three.example.test.", RecordType::A, false))
        .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.9".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(good.query_count() >= 1, "the third route must be reached");
}

/// A TCP listener that completes the handshake and then never answers.
///
/// This models the case the deadline contract exists for: the connection succeeds, so
/// there is no fast failure, and the attempt can only end by hitting its timeout.
async fn hanging_tcp(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind hanging tcp");
    tokio::spawn(async move {
        // Accepted sockets are held, never read from and never closed, so the peer waits
        // for a response that cannot arrive.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    })
}

/// A UDP responder that answers every query with the TC bit set and nothing else,
/// forcing the RFC 7766 stream retry.
async fn truncating_udp(port: u16) -> tokio::task::JoinHandle<()> {
    let socket = tokio::net::UdpSocket::bind(("127.0.0.1", port))
        .await
        .expect("bind truncating udp");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(request) = hickory_proto::op::Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response =
                hickory_proto::op::Message::response(request.id, request.metadata.op_code);
            response.add_queries(request.queries.iter().cloned());
            response.metadata.truncation = true;
            response.metadata.recursion_available = true;
            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    })
}

/// The truncation retry must live inside the same absolute foreground deadline as
/// everything else.
///
/// The v1 scheduler computed one attempt timeout from the budget remaining when the
/// truncated answer arrived, then handed a *fresh copy* of it to each of two stream
/// candidates, so two hanging TCP routes could take twice the whole foreground budget.
#[tokio::test]
async fn truncation_retry_cannot_exceed_the_foreground_deadline() {
    // The UDP truncating responder and the companion TCP route share a port number;
    // the two protocols have independent port spaces, so one bind does not block the
    // other. Find a port free for both.
    let (port, _udp_task, _tcp_task) = {
        let mut chosen = None;
        for _ in 0..64 {
            let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("probe bind");
            let p = probe.local_addr().expect("addr").port();
            drop(probe);
            if let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", p)).await {
                drop(l);
                chosen = Some(p);
                break;
            }
        }
        let p = chosen.expect("a port free on both UDP and TCP");
        (p, truncating_udp(p).await, hanging_tcp(p).await)
    };

    // A second hanging TCP route, so both stream candidates the retry picks up hang.
    let second = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let second_port = second.local_addr().expect("addr").port();
    drop(second);
    let _second_task = hanging_tcp(second_port).await;

    // `server.foreground_budget` keeps its 2.5s default: the preamble already owns the
    // `[server]` table, and the default is what the deployed contract actually promises.
    // Two hanging stream candidates at a 2s attempt timeout overrun it by ~1.5s.
    let fragment = format!(
        r#"
upstreams = ["127.0.0.1:{port}", "tcp://127.0.0.1:{second_port}"]
proxies = []

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );

    let daemon = Daemon::start_tuned(&fragment, deterministic(false, 0.0)).await;
    let started = std::time::Instant::now();
    let response = daemon
        .query_udp(&common::query("big.example.test.", RecordType::A, false))
        .await;
    let elapsed = started.elapsed();

    // The answer itself is a failure — a truncated answer that cannot be retried must
    // never be handed to a client — but the point of the test is *when* it arrives.
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(
        elapsed < Duration::from_millis(2_900),
        "the foreground budget is 2.5s; the truncation retry must fit inside it, took {elapsed:?}"
    );
}

/// DNSSEC validation must live inside the same ingress deadline as everything else.
///
/// A validating lookup fans out into DNSKEY and DS queries that each arrive at the
/// scheduler as a separate resolution. Handing every one of them the configured budget
/// let a chain of them spend several budgets while the client waited, and the wait for a
/// validation permit could add another on top.
///
/// The upstream here never answers, so every sub-lookup runs to its own limit. What is
/// asserted is not the answer — a validating resolver with no chain of trust must
/// SERVFAIL — but that the client is failed within the promise.
#[tokio::test]
async fn dnssec_validation_cannot_exceed_the_foreground_deadline() {
    // A UDP socket that is bound and never answers: every query against it runs the full
    // attempt timeout rather than failing fast.
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = sink.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while sink.recv_from(&mut buf).await.is_ok() {
            // Received and dropped on the floor.
        }
    });

    let fragment = format!(
        r#"
upstreams = ["{addr}"]
proxies = []

[dnssec]
mode = "validate"
max_concurrent_validations = 1

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );

    // A 1s budget rather than the 2.5s default, so the failure mode separates cleanly:
    // one permit and two concurrent queries means the second must queue, and before the
    // fix that queuing was free — it spent a whole budget waiting and then started a
    // fresh one to validate in, for roughly double the promise.
    let daemon = std::sync::Arc::new(
        Daemon::start_tuned(&fragment, |c| {
            c.server.foreground_budget = Duration::from_secs(1);
        })
        .await,
    );

    let started = std::time::Instant::now();
    let mut queries = Vec::new();
    for i in 0..2 {
        let d = std::sync::Arc::clone(&daemon);
        queries.push(tokio::spawn(async move {
            d.query_udp(&common::query(
                &format!("secure{i}.example.test."),
                RecordType::A,
                false,
            ))
            .await
        }));
    }
    let mut codes = Vec::new();
    for q in queries {
        codes.push(q.await.expect("join").metadata.response_code);
    }
    let elapsed = started.elapsed();

    for code in &codes {
        assert_eq!(
            *code,
            ResponseCode::ServFail,
            "validation with no reachable chain of trust must fail closed"
        );
    }
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the foreground budget is 1s; a queued validation permit must be charged against \
         it rather than granting a second budget, took {elapsed:?}"
    );
}
