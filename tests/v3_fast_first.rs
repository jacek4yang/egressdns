//! The v3 execution model: answer first, prove afterwards.
//!
//! These are the properties that make a resolver usable rather than merely correct, and
//! each of them is one that a previous release got wrong.

mod common;

use std::time::Duration;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::rr::RecordType;

/// The shipped default: validation happens, but never in front of the client.
fn background_dnssec(addr: std::net::SocketAddr) -> String {
    common::udp_upstream_fragment(addr).replace(r#"mode = "off""#, r#"mode = "background""#)
}

/// The opt-in fail-closed mode, used here only to show what the default avoids.
fn strict_dnssec(addr: std::net::SocketAddr) -> String {
    common::udp_upstream_fragment(addr).replace(r#"mode = "off""#, r#"mode = "strict""#)
}

/// A positive answer must not wait for DNSSEC.
///
/// The failure this prevents: `www.bing.com` sat behind a four-zone CNAME chain whose
/// DS and DNSKEY lookups did not fit the foreground budget, the last was cut off, and the
/// resolver reported SERVFAIL for a name it could resolve perfectly well.
#[tokio::test]
async fn a_positive_answer_does_not_wait_for_dnssec() {
    let upstream = MockUpstream::new();
    upstream.set(
        "fast.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("fast.test.", 60, "192.0.2.10")]),
    );
    let ca = TestCa::new();
    let server = common::start_mock(upstream.clone(), &ca, "mock.test", Transports::plain()).await;

    let daemon = Daemon::start(&background_dnssec(server.udp.expect("udp listener"))).await;

    let started = std::time::Instant::now();
    let response = daemon
        .query_udp(&common::query("fast.test.", RecordType::A, false))
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.10".parse::<std::net::IpAddr>().expect("addr")],
    );
    // The mock serves no DNSKEY or DS at all, so a resolver that insisted on a complete
    // chain before answering would spend its whole budget and fail. Answering promptly is
    // the assertion.
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the answer took {elapsed:?}, which means something was waited on"
    );
}

/// The same shape as the real failure: a chain of unsigned zones, no DNSSEC data anywhere.
#[tokio::test]
async fn a_deep_unsigned_cname_chain_resolves() {
    let upstream = MockUpstream::new();
    upstream.set(
        "www.chain.test.",
        RecordType::A,
        Behaviour::Answer(vec![
            common::cname("www.chain.test.", 60, "a.mid.test."),
            common::cname("a.mid.test.", 60, "b.edge.test."),
            common::cname("b.edge.test.", 60, "c.cdn.test."),
            a("c.cdn.test.", 60, "192.0.2.20"),
        ]),
    );
    let ca = TestCa::new();
    let server = common::start_mock(upstream.clone(), &ca, "mock.test", Transports::plain()).await;
    let daemon = Daemon::start(&background_dnssec(server.udp.expect("udp listener"))).await;

    let response = daemon
        .query_udp(&common::query("www.chain.test.", RecordType::A, false))
        .await;
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError,
        "a chain of unsigned delegations must resolve, not SERVFAIL"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.20".parse::<std::net::IpAddr>().expect("addr")],
    );
}

/// The same, over TCP: the transport must not change the verdict.
#[tokio::test]
async fn a_deep_chain_resolves_over_tcp_too() {
    let upstream = MockUpstream::new();
    upstream.set(
        "www.chain.test.",
        RecordType::A,
        Behaviour::Answer(vec![
            common::cname("www.chain.test.", 60, "a.mid.test."),
            a("a.mid.test.", 60, "192.0.2.21"),
        ]),
    );
    let ca = TestCa::new();
    let server = common::start_mock(upstream.clone(), &ca, "mock.test", Transports::plain()).await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(
        server.udp.expect("udp listener"),
    ))
    .await;

    let response = daemon
        .query_tcp(&common::query("www.chain.test.", RecordType::A, false))
        .await;
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
}

/// An upstream that answers nothing at all must not make the resolver unavailable for
/// names another upstream can answer.
#[tokio::test]
async fn one_dead_upstream_does_not_deny_a_name() {
    let dead = MockUpstream::new();
    dead.set_default(Behaviour::Drop);
    let ca = TestCa::new();
    let dead_server = common::start_mock(dead.clone(), &ca, "mock.test", Transports::plain()).await;

    let live = MockUpstream::new();
    live.set(
        "reachable.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("reachable.test.", 60, "192.0.2.30")]),
    );
    let live_server = common::start_mock(live.clone(), &ca, "mock.test", Transports::plain()).await;

    let daemon = Daemon::start(&common::udp_upstream_fragment_multi(&[
        dead_server.udp.expect("udp"),
        live_server.udp.expect("udp"),
    ]))
    .await;

    let response = daemon
        .query_udp(&common::query("reachable.test.", RecordType::A, false))
        .await;
    assert_eq!(
        common::addresses(&response),
        vec!["192.0.2.30".parse::<std::net::IpAddr>().expect("addr")],
        "a dead route must be routed around, not waited on"
    );
}

/// A cache hit must be local-latency, with no upstream query at all.
#[tokio::test]
async fn a_cache_hit_costs_no_upstream_query() {
    let upstream = MockUpstream::new();
    upstream.set(
        "warm.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("warm.test.", 300, "192.0.2.40")]),
    );
    let ca = TestCa::new();
    let server = common::start_mock(upstream.clone(), &ca, "mock.test", Transports::plain()).await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(
        server.udp.expect("udp listener"),
    ))
    .await;

    daemon
        .query_udp(&common::query("warm.test.", RecordType::A, false))
        .await;
    let after_first = upstream.count_for("warm.test.", RecordType::A);

    for _ in 0..5 {
        let response = daemon
            .query_udp(&common::query("warm.test.", RecordType::A, false))
            .await;
        assert_eq!(
            common::addresses(&response),
            vec!["192.0.2.40".parse::<std::net::IpAddr>().expect("addr")]
        );
    }

    assert_eq!(
        upstream.count_for("warm.test.", RecordType::A),
        after_first,
        "five cache hits must not have produced a single upstream query"
    );
}

/// The first query must not fan out to every configured route.
///
/// Asking everybody is how a resolver turns one client query into N queries of somebody
/// else's traffic, and it is the mechanism this design most deliberately does not use.
#[tokio::test]
async fn the_first_query_does_not_contact_every_route() {
    let mocks: Vec<MockUpstream> = (0..5).map(|_| MockUpstream::new()).collect();
    let mut addrs = Vec::new();
    let mut servers = Vec::new();
    let ca = TestCa::new();
    for m in &mocks {
        m.set(
            "single.test.",
            RecordType::A,
            Behaviour::Answer(vec![a("single.test.", 60, "192.0.2.50")]),
        );
        let s = common::start_mock(m.clone(), &ca, "mock.test", Transports::plain()).await;
        addrs.push(s.udp.expect("udp"));
        servers.push(s);
    }

    let daemon = Daemon::start(&common::udp_upstream_fragment_multi(&addrs)).await;
    daemon
        .query_udp(&common::query("single.test.", RecordType::A, false))
        .await;

    let contacted = mocks
        .iter()
        .filter(|m| m.count_for("single.test.", RecordType::A) > 0)
        .count();
    assert!(
        contacted < mocks.len(),
        "all {} routes were queried for one name; the point of ranking is not to",
        mocks.len()
    );
}

/// The difference the default makes, stated as a comparison.
///
/// The same upstream, the same name, the same build — only the mode differs. Strict mode
/// cannot complete a chain this upstream does not serve, so it fails closed, which is
/// exactly what it promises. Background mode answers. This is the whole argument for the
/// change of default, and it is here so that a future change of default has to argue
/// with it.
#[tokio::test]
async fn background_mode_answers_where_strict_mode_refuses() {
    let upstream = MockUpstream::new();
    upstream.set(
        "unsigned.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("unsigned.test.", 60, "192.0.2.60")]),
    );
    let ca = TestCa::new();
    let server = common::start_mock(upstream.clone(), &ca, "mock.test", Transports::plain()).await;
    let addr = server.udp.expect("udp listener");

    let strict = Daemon::start(&strict_dnssec(addr)).await;
    let refused = strict
        .query_udp(&common::query("unsigned.test.", RecordType::A, false))
        .await;
    assert_eq!(
        refused.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail,
        "strict mode cannot prove a chain this upstream does not serve, and says so"
    );

    let background = Daemon::start(&background_dnssec(addr)).await;
    let answered = background
        .query_udp(&common::query("unsigned.test.", RecordType::A, false))
        .await;
    assert_eq!(
        answered.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError,
        "the default must answer: the client is owed an answer, not a proof"
    );
    assert_eq!(
        common::addresses(&answered),
        vec!["192.0.2.60".parse::<std::net::IpAddr>().expect("addr")]
    );
    assert!(
        !answered.metadata.authentic_data,
        "an answer that has not been validated must not claim AD"
    );
}
