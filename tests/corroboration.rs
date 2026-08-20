//! Corroborating a negative answer with a second resolver authority.
//!
//! A forged NXDOMAIN is how a name is made to disappear. Unlike a forged address it
//! leaves no evidence in the answer itself — there is nothing to compare against, because
//! the point of the answer is that there is nothing. The only defence available to an
//! unsigned zone is to ask somebody else.

mod common;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn two_upstreams(a1: std::net::SocketAddr, a2: std::net::SocketAddr) -> String {
    format!(
        r#"
upstreams = ["{a1}", "{a2}"]
proxies = []

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    )
}

/// One resolver denies a name that an independent resolver answers.
///
/// The positive answer wins, because a negative can be fabricated by deletion and a set
/// of records cannot.
#[tokio::test]
async fn an_unsigned_nxdomain_contradicted_by_another_resolver_does_not_win() {
    let liar = MockUpstream::new();
    liar.set_default(Behaviour::NxDomain { minimum: 300 });

    let honest = MockUpstream::new();
    honest.set(
        "contested.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("contested.example.test.", 300, "203.0.113.80")]),
    );

    let ca = TestCa::new();
    let s1 = common::start_mock(liar.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let s2 = common::start_mock(honest.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let first = s1.udp.expect("udp");
    let second = s2.udp.expect("udp");
    std::mem::forget(s1);
    std::mem::forget(s2);

    // Exploration off and hedging off, so the *first* authority is deterministically the
    // one that denies the name: the corroboration path is what has to save this.
    let daemon = Daemon::start_tuned(&two_upstreams(first, second), |c| {
        for group in &mut c.upstream.groups {
            group.scheduler.explore_rate = 0.0;
            group.scheduler.hedge_enabled = false;
        }
    })
    .await;

    let response = daemon
        .query_udp(&common::query(
            "contested.example.test.",
            RecordType::A,
            false,
        ))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "an independent resolver answered the name, so the unsigned denial must not stand"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.80".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(
        honest.query_count() >= 1,
        "the second authority must actually have been asked"
    );
}

/// When both independent resolvers deny the name, the denial stands.
///
/// Corroboration must not turn every NXDOMAIN into a retry storm or a SERVFAIL: agreeing
/// resolvers are the ordinary case and cost one extra query, not an answer.
#[tokio::test]
async fn an_nxdomain_both_resolvers_agree_on_is_returned() {
    let one = MockUpstream::new();
    one.set_default(Behaviour::NxDomain { minimum: 300 });
    let two = MockUpstream::new();
    two.set_default(Behaviour::NxDomain { minimum: 300 });

    let ca = TestCa::new();
    let s1 = common::start_mock(one, &ca, "dns.example.test", Transports::plain()).await;
    let s2 = common::start_mock(two.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let first = s1.udp.expect("udp");
    let second = s2.udp.expect("udp");
    std::mem::forget(s1);
    std::mem::forget(s2);

    let daemon = Daemon::start_tuned(&two_upstreams(first, second), |c| {
        for group in &mut c.upstream.groups {
            group.scheduler.explore_rate = 0.0;
            group.scheduler.hedge_enabled = false;
        }
    })
    .await;

    let response = daemon
        .query_udp(&common::query("gone.example.test.", RecordType::A, false))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NXDomain,
        "two independent resolvers agree the name does not exist"
    );
}

/// A positive answer is not second-guessed. Corroboration exists for the case where the
/// answer is an absence, and spending a query on every answer would be a privacy and
/// latency cost with nothing to show for it.
#[tokio::test]
async fn a_positive_answer_is_not_corroborated() {
    let one = MockUpstream::new();
    one.set(
        "fine.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("fine.example.test.", 300, "203.0.113.81")]),
    );
    let two = MockUpstream::new();
    two.set_default(Behaviour::Answer(vec![a(
        "fine.example.test.",
        300,
        "203.0.113.82",
    )]));

    let ca = TestCa::new();
    let s1 = common::start_mock(one, &ca, "dns.example.test", Transports::plain()).await;
    let s2 = common::start_mock(two.clone(), &ca, "dns.example.test", Transports::plain()).await;
    let first = s1.udp.expect("udp");
    let second = s2.udp.expect("udp");
    std::mem::forget(s1);
    std::mem::forget(s2);

    let daemon = Daemon::start_tuned(&two_upstreams(first, second), |c| {
        for group in &mut c.upstream.groups {
            group.scheduler.explore_rate = 0.0;
            group.scheduler.hedge_enabled = false;
        }
    })
    .await;

    let response = daemon
        .query_udp(&common::query("fine.example.test.", RecordType::A, false))
        .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.81".parse::<std::net::IpAddr>().expect("ip")],
        "the first authority's positive answer is returned unchanged"
    );
    assert_eq!(
        two.query_count(),
        0,
        "a positive answer must not cost a second query"
    );
}

/// With one authority configured there is nobody to ask, and the answer stands.
#[tokio::test]
async fn a_single_authority_nxdomain_is_returned_unchanged() {
    let only = MockUpstream::new();
    only.set_default(Behaviour::NxDomain { minimum: 300 });
    let ca = TestCa::new();
    let s = common::start_mock(only, &ca, "dns.example.test", Transports::plain()).await;
    let addr = s.udp.expect("udp");
    std::mem::forget(s);

    let daemon = Daemon::start(&common::udp_upstream_fragment(addr)).await;
    let response = daemon
        .query_udp(&common::query("solo.example.test.", RecordType::A, false))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NXDomain,
        "an absent second opinion is not evidence either way"
    );
}
