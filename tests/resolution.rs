//! End-to-end resolution behaviour: caching, negative caching, failure suppression,
//! serve-stale, TTL policy, record-type preservation, truncation and TCP pipelining.

mod common;

use std::time::Duration;

use common::{
    a, aaaa, cname, udp_upstream_fragment, Behaviour, Daemon, MockUpstream, TestCa, Transports,
};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{MX, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

async fn mock_and_daemon(handler: MockUpstream, extra: &str) -> (Daemon, common::MockServers) {
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler,
        &ca,
        "dns.example.test",
        Transports {
            udp: true,
            tcp: true,
            ..Transports::default()
        },
    )
    .await;
    let udp = servers.udp.expect("mock udp");
    let fragment = format!("{}{extra}", udp_upstream_fragment(udp));
    let daemon = Daemon::start(&fragment).await;
    (daemon, servers)
}

#[tokio::test]
async fn forwards_and_caches_a_records() {
    let handler = MockUpstream::new();
    handler.set(
        "www.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("www.example.test.", 300, "203.0.113.10")]),
    );
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;

    let request = common::query("www.example.test.", RecordType::A, false);
    let first = daemon.query_udp(&request).await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);
    assert_eq!(common::addresses(&first).len(), 1);
    assert!(first.metadata.recursion_available);

    // The second query must be served from cache.
    let second = daemon.query_udp(&request).await;
    assert_eq!(common::addresses(&second).len(), 1);
    assert_eq!(
        handler.count_for("www.example.test.", RecordType::A),
        1,
        "the second query must not reach the upstream"
    );
}

#[tokio::test]
async fn client_ttl_is_capped_but_never_extended() {
    let handler = MockUpstream::new();
    // A long authoritative TTL must be capped, a short one must be passed through as-is.
    handler.set(
        "long.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("long.example.test.", 86_400, "203.0.113.1")]),
    );
    handler.set(
        "short.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("short.example.test.", 7, "203.0.113.2")]),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "[ttl]\ncap_default = 60\n").await;

    let long = daemon
        .query_udp(&common::query("long.example.test.", RecordType::A, false))
        .await;
    assert_eq!(long.answers[0].ttl, 60, "long TTL must be capped");

    let short = daemon
        .query_udp(&common::query("short.example.test.", RecordType::A, false))
        .await;
    assert_eq!(
        short.answers[0].ttl, 7,
        "a short authoritative TTL must never be raised to the cap"
    );
}

#[tokio::test]
async fn negative_answers_are_cached() {
    let handler = MockUpstream::new();
    handler.set(
        "missing.example.test.",
        RecordType::A,
        Behaviour::NxDomain { minimum: 120 },
    );
    handler.set(
        "nodata.example.test.",
        RecordType::AAAA,
        Behaviour::NoData { minimum: 120 },
    );
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;

    let nx = daemon
        .query_udp(&common::query(
            "missing.example.test.",
            RecordType::A,
            false,
        ))
        .await;
    assert_eq!(nx.metadata.response_code, ResponseCode::NXDomain);
    let nx2 = daemon
        .query_udp(&common::query(
            "missing.example.test.",
            RecordType::A,
            false,
        ))
        .await;
    assert_eq!(nx2.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(handler.count_for("missing.example.test.", RecordType::A), 1);

    let nodata = daemon
        .query_udp(&common::query(
            "nodata.example.test.",
            RecordType::AAAA,
            false,
        ))
        .await;
    assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
    assert!(nodata.answers.is_empty());
    daemon
        .query_udp(&common::query(
            "nodata.example.test.",
            RecordType::AAAA,
            false,
        ))
        .await;
    assert_eq!(
        handler.count_for("nodata.example.test.", RecordType::AAAA),
        1
    );
}

#[tokio::test]
async fn resolution_failures_are_suppressed_and_do_not_hammer_the_upstream() {
    let handler = MockUpstream::new();
    handler.set("broken.example.test.", RecordType::A, Behaviour::ServFail);
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;

    for _ in 0..8 {
        let r = daemon
            .query_udp(&common::query("broken.example.test.", RecordType::A, false))
            .await;
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    }
    let attempts = handler.count_for("broken.example.test.", RecordType::A);
    assert!(
        attempts <= 3,
        "RFC 9520 forbids repeatedly re-querying a failing name; saw {attempts}"
    );
}

#[tokio::test]
async fn concurrent_identical_misses_produce_one_upstream_query() {
    let handler = MockUpstream::new();
    handler.set(
        "slow.example.test.",
        RecordType::A,
        Behaviour::Delay(
            Duration::from_millis(300),
            Box::new(Behaviour::Answer(vec![a(
                "slow.example.test.",
                300,
                "203.0.113.7",
            )])),
        ),
    );
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;
    let daemon = std::sync::Arc::new(daemon);

    let mut handles = Vec::new();
    for _ in 0..16 {
        let d = std::sync::Arc::clone(&daemon);
        handles.push(tokio::spawn(async move {
            d.query_udp(&common::query("slow.example.test.", RecordType::A, false))
                .await
        }));
    }
    for h in handles {
        let r = h.await.expect("join");
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(common::addresses(&r).len(), 1);
    }
    assert_eq!(
        handler.count_for("slow.example.test.", RecordType::A),
        1,
        "singleflight must collapse concurrent identical misses"
    );
}

/// A UDP-only upstream must still satisfy RFC 7766, without a second server entry.
///
/// A truncated UDP answer is never parsed opportunistically, so before the TCP companion
/// route existed the only outcomes for a UDP-only configuration were "retry over a stream
/// route the operator happened to configure" or SERVFAIL. That turned every large answer
/// into a failure for a configuration that looks entirely reasonable — and the failure
/// only appeared once real traffic produced a response over 512 bytes.
#[tokio::test]
async fn a_udp_only_upstream_still_retries_a_truncated_answer_over_tcp() {
    let handler = MockUpstream::new();
    handler.set(
        "big.example.test.",
        RecordType::A,
        Behaviour::TruncatedOnUdp(vec![a("big.example.test.", 300, "203.0.113.42")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let udp = servers.udp.expect("mock udp");

    // Exactly one upstream, a bare address, so Do53 only. The TCP companion the RFC
    // 7766 retry needs is created by the registry rather than written by the operator,
    // which is the point of the test.
    let fragment = format!(
        r#"
upstreams = ["{udp}"]
proxies = []

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );
    let daemon = Daemon::start(&fragment).await;

    let response = daemon
        .query_udp(&common::query("big.example.test.", RecordType::A, false))
        .await;

    assert!(
        handler.count_for("big.example.test.", RecordType::A) >= 2,
        "a UDP-only upstream must still be retried over a stream transport"
    );
    assert!(
        !response.metadata.truncation,
        "a truncated answer must never be passed to the client as if it were complete"
    );
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "the stream retry must produce a real answer, not SERVFAIL"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.42".parse::<std::net::IpAddr>().expect("ip")]
    );
}

#[tokio::test]
async fn truncated_udp_answers_are_retried_over_tcp() {
    let handler = MockUpstream::new();
    // The mock truncates on UDP; the TCP listener of the same mock returns real data.
    handler.set("tc.example.test.", RecordType::A, Behaviour::Truncated);
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let udp = servers.udp.expect("mock udp");
    let tcp = servers.tcp.expect("mock tcp");

    // Once the daemon retries over TCP the mock answers normally, because the scripted
    // behaviour is replaced before the retry can happen.
    let fragment = format!(
        r#"
upstreams = ["{udp}", "tcp://{tcp}"]
proxies = []

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );
    let daemon = Daemon::start(&fragment).await;

    // Let the truncated answer arrive first, then make the retry succeed.
    let daemon = std::sync::Arc::new(daemon);
    let h = handler.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        h.set(
            "tc.example.test.",
            RecordType::A,
            Behaviour::Answer(vec![a("tc.example.test.", 300, "203.0.113.99")]),
        );
    });
    let response = daemon
        .query_udp(&common::query("tc.example.test.", RecordType::A, false))
        .await;
    // Either the retry produced data, or the resolver reported failure honestly. It must
    // never return a truncated answer as if it were complete.
    if response.metadata.response_code == ResponseCode::NoError && !response.answers.is_empty() {
        assert!(!response.metadata.truncation);
    }
    assert!(
        handler.count_for("tc.example.test.", RecordType::A) >= 2,
        "a truncated UDP answer must trigger a stream retry"
    );
}

#[tokio::test]
async fn record_types_other_than_a_and_aaaa_pass_through_unchanged() {
    let handler = MockUpstream::new();
    let mx = vec![
        Record::from_rdata(
            Name::from_utf8("mail.example.test.").expect("name"),
            300,
            RData::MX(MX::new(
                10,
                Name::from_utf8("mx1.example.test.").expect("name"),
            )),
        ),
        Record::from_rdata(
            Name::from_utf8("mail.example.test.").expect("name"),
            300,
            RData::MX(MX::new(
                20,
                Name::from_utf8("mx2.example.test.").expect("name"),
            )),
        ),
    ];
    let srv = vec![Record::from_rdata(
        Name::from_utf8("_sip._tcp.example.test.").expect("name"),
        300,
        RData::SRV(SRV::new(
            10,
            60,
            5_060,
            Name::from_utf8("sip.example.test.").expect("name"),
        )),
    )];
    let txt = vec![Record::from_rdata(
        Name::from_utf8("txt.example.test.").expect("name"),
        300,
        RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])),
    )];
    handler.set(
        "mail.example.test.",
        RecordType::MX,
        Behaviour::Answer(mx.clone()),
    );
    handler.set(
        "_sip._tcp.example.test.",
        RecordType::SRV,
        Behaviour::Answer(srv.clone()),
    );
    handler.set(
        "txt.example.test.",
        RecordType::TXT,
        Behaviour::Answer(txt.clone()),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let response = daemon
        .query_udp(&common::query("mail.example.test.", RecordType::MX, false))
        .await;
    let rendered: Vec<String> = response
        .answers
        .iter()
        .map(|r| r.data.to_string())
        .collect();
    assert_eq!(
        rendered,
        vec!["10 mx1.example.test.", "20 mx2.example.test."]
    );

    let response = daemon
        .query_udp(&common::query(
            "_sip._tcp.example.test.",
            RecordType::SRV,
            false,
        ))
        .await;
    assert!(response.answers[0]
        .data
        .to_string()
        .starts_with("10 60 5060"));

    let response = daemon
        .query_udp(&common::query("txt.example.test.", RecordType::TXT, false))
        .await;
    assert!(response.answers[0].data.to_string().contains("spf1"));
}

#[tokio::test]
async fn cname_chains_keep_their_structure_and_per_record_ttls() {
    let handler = MockUpstream::new();
    handler.set(
        "alias.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![
            cname("alias.example.test.", 30, "target.example.test."),
            a("target.example.test.", 300, "203.0.113.5"),
            a("target.example.test.", 300, "203.0.113.6"),
        ]),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "[ttl]\ncap_default = 120\n").await;
    let response = daemon
        .query_udp(&common::query("alias.example.test.", RecordType::A, false))
        .await;
    assert_eq!(response.answers.len(), 3);
    assert!(matches!(response.answers[0].data, RData::CNAME(_)));
    assert_eq!(
        response.answers[0].ttl, 30,
        "the CNAME keeps its own shorter TTL"
    );
    assert!(response.answers[1].ttl <= 120);
    assert_eq!(common::addresses(&response).len(), 2);
}

#[tokio::test]
async fn a_and_aaaa_are_independent() {
    let handler = MockUpstream::new();
    handler.set(
        "dual.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("dual.example.test.", 300, "203.0.113.20")]),
    );
    handler.set(
        "dual.example.test.",
        RecordType::AAAA,
        Behaviour::Answer(vec![aaaa("dual.example.test.", 300, "2001:db8::20")]),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let v4 = daemon
        .query_udp(&common::query("dual.example.test.", RecordType::A, false))
        .await;
    let v6 = daemon
        .query_udp(&common::query(
            "dual.example.test.",
            RecordType::AAAA,
            false,
        ))
        .await;
    assert_eq!(common::addresses(&v4).len(), 1);
    assert_eq!(
        common::addresses(&v6).len(),
        1,
        "AAAA must never be hidden by default"
    );
    assert!(common::addresses(&v6)[0].is_ipv6());
}

#[tokio::test]
async fn tcp_pipelining_answers_every_query() {
    let handler = MockUpstream::new();
    for i in 0..8u8 {
        handler.set(
            &format!("p{i}.example.test."),
            RecordType::A,
            Behaviour::Answer(vec![a(
                &format!("p{i}.example.test."),
                300,
                &format!("203.0.113.{}", 100 + i),
            )]),
        );
    }
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let queries: Vec<_> = (0..8u8)
        .map(|i| common::query(&format!("p{i}.example.test."), RecordType::A, false))
        .collect();
    let responses = daemon.query_tcp_pipeline(&queries).await;
    assert_eq!(responses.len(), 8);
    let ids: std::collections::HashSet<u16> = responses.iter().map(|r| r.metadata.id).collect();
    let expected: std::collections::HashSet<u16> = queries.iter().map(|q| q.metadata.id).collect();
    assert_eq!(ids, expected, "every query must be answered exactly once");
}

#[tokio::test]
async fn out_of_order_completion_is_permitted_on_tcp() {
    let handler = MockUpstream::new();
    handler.set(
        "slowq.example.test.",
        RecordType::A,
        Behaviour::Delay(
            Duration::from_millis(400),
            Box::new(Behaviour::Answer(vec![a(
                "slowq.example.test.",
                300,
                "203.0.113.1",
            )])),
        ),
    );
    handler.set(
        "fastq.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("fastq.example.test.", 300, "203.0.113.2")]),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let slow = common::query("slowq.example.test.", RecordType::A, false);
    let fast = common::query("fastq.example.test.", RecordType::A, false);
    let responses = daemon
        .query_tcp_pipeline(&[slow.clone(), fast.clone()])
        .await;
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0].metadata.id, fast.metadata.id,
        "the fast query must not be blocked behind the slow one"
    );
}

#[tokio::test]
async fn clients_outside_the_acl_are_refused() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "any.example.test.",
        300,
        "203.0.113.1",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let udp = servers.udp.expect("mock udp");
    // An ACL that excludes loopback means every test client is refused.
    let fragment = format!(
        "{}\n[server]\nallow_from = [\"10.0.0.0/8\"]\n",
        udp_upstream_fragment(udp)
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("c.toml");
    let text = format!(
        "{}\n[server]\nudp_listen=[\"127.0.0.1:0\"]\ntcp_listen=[]\n\
         allow_from=[\"10.0.0.0/8\"]\n\
         [metrics]\nenabled=false\n[admin]\nenabled=false\n[storage]\nenabled=false\n",
        udp_upstream_fragment(udp)
    );
    std::fs::write(&path, &text).expect("write");
    let config =
        std::sync::Arc::new(egressdns::config::Config::from_toml(&text, "test").expect("valid"));
    let app = egressdns::runtime::App::from_config(config.clone(), path).expect("app");
    let ingress = egressdns::dns::server::Ingress::new(std::sync::Arc::clone(&app));
    let socket =
        egressdns::dns::server::bind_udp("127.0.0.1:0".parse().expect("addr"), &config.server.udp)
            .expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(egressdns::dns::server::serve_udp(
        std::sync::Arc::new(socket),
        ingress,
    ));

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    let request = common::query("any.example.test.", RecordType::A, false);
    client
        .send_to(&request.to_vec().expect("encode"), addr)
        .await
        .expect("send");
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("response")
        .expect("recv");
    let response = hickory_proto::op::Message::from_vec(&buf[..len]).expect("decode");
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    let _ = fragment;
}

#[tokio::test]
async fn unsupported_opcode_and_class_are_rejected_cleanly() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "x.example.test.",
        300,
        "203.0.113.1",
    )]));
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let mut status = common::query("x.example.test.", RecordType::A, false);
    status.metadata.op_code = hickory_proto::op::OpCode::Status;
    let response = daemon.query_udp(&status).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);

    let mut chaos = common::query("x.example.test.", RecordType::A, false);
    chaos.queries[0].set_query_class(hickory_proto::rr::DNSClass::HS);
    let response = daemon.query_udp(&chaos).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn unsupported_edns_version_yields_badvers() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "x.example.test.",
        300,
        "203.0.113.1",
    )]));
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let mut request = common::query("x.example.test.", RecordType::A, false);
    if let Some(edns) = request.edns.as_mut() {
        edns.set_version(1);
    }
    let response = daemon.query_udp(&request).await;
    // RFC 6895 assigns extended RCODE 16 to BADVERS (and BADSIG); after a wire round-trip
    // hickory may surface either name for the same value, so assert on the code itself.
    assert!(
        matches!(
            response.metadata.response_code,
            ResponseCode::BADVERS | ResponseCode::BADSIG
        ),
        "expected extended RCODE 16, got {:?}",
        response.metadata.response_code
    );
}

#[tokio::test]
async fn any_queries_get_a_minimal_answer_by_default() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "x.example.test.",
        300,
        "203.0.113.1",
    )]));
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;

    let response = daemon
        .query_udp(&common::query("x.example.test.", RecordType::ANY, false))
        .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(response.answers[0].data, RData::HINFO(_)));
    assert_eq!(
        handler.count_for("x.example.test.", RecordType::ANY),
        0,
        "RFC 8482 minimal ANY must not be forwarded"
    );
}

#[tokio::test]
async fn a_client_without_edns_never_receives_an_opt_record() {
    let handler = MockUpstream::new();
    handler.set(
        "plain.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("plain.example.test.", 300, "203.0.113.1")]),
    );
    let (daemon, _servers) = mock_and_daemon(handler, "").await;

    let mut request = common::query("plain.example.test.", RecordType::A, false);
    request.edns = None;
    let response = daemon.query_udp(&request).await;
    assert!(
        response.edns.is_none(),
        "RFC 6891 forbids adding OPT to a response for a client that sent none"
    );
    assert_eq!(common::addresses(&response).len(), 1);
}

#[tokio::test]
async fn large_answers_set_tc_on_udp_and_fit_on_tcp() {
    let handler = MockUpstream::new();
    let records: Vec<Record> = (0..120u32)
        .map(|i| {
            a(
                "big.example.test.",
                300,
                &format!("203.0.{}.{}", i / 250, (i % 250) + 1),
            )
        })
        .collect();
    handler.set(
        "big.example.test.",
        RecordType::A,
        Behaviour::Answer(records),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let tcp = servers.tcp.expect("mock tcp");
    // Use the TCP mock upstream so the large answer actually reaches the daemon.
    let fragment = format!(
        r#"
upstreams = ["tcp://{tcp}"]
proxies = []

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    );
    let daemon = Daemon::start(&fragment).await;

    let mut small = common::query("big.example.test.", RecordType::A, false);
    if let Some(edns) = small.edns.as_mut() {
        edns.set_max_payload(512);
    }
    let udp_response = daemon.query_udp(&small).await;
    assert!(
        udp_response.metadata.truncation,
        "an over-sized answer must set TC"
    );
    assert!(udp_response.answers.is_empty());

    let tcp_response = daemon
        .query_tcp(&common::query("big.example.test.", RecordType::A, false))
        .await;
    assert!(!tcp_response.metadata.truncation);
    assert!(tcp_response.answers.len() > 100);
}

#[tokio::test]
async fn special_use_names_are_answered_locally_and_never_forwarded() {
    let handler = MockUpstream::new();
    // If anything leaks upstream the mock would happily answer it, which makes the
    // "count_for == 0" assertions below meaningful rather than vacuous.
    handler.set_default(Behaviour::Answer(vec![a(
        "leaked.example.test.",
        300,
        "203.0.113.99",
    )]));
    let (daemon, _servers) = mock_and_daemon(handler.clone(), "").await;

    // localhost resolves to the loopback address of the requested family.
    let v4 = daemon
        .query_udp(&common::query("localhost.", RecordType::A, false))
        .await;
    assert_eq!(v4.metadata.response_code, ResponseCode::NoError);
    assert_eq!(v4.answers.len(), 1);
    assert!(
        matches!(v4.answers[0].data, RData::A(ref addr) if addr.0 == std::net::Ipv4Addr::LOCALHOST)
    );

    let v6 = daemon
        .query_udp(&common::query("host.localhost.", RecordType::AAAA, false))
        .await;
    assert_eq!(v6.answers.len(), 1);
    assert!(
        matches!(v6.answers[0].data, RData::AAAA(ref addr) if addr.0 == std::net::Ipv6Addr::LOCALHOST)
    );

    // localhost has no MX: NODATA, not a fabricated record and not an upstream query.
    let mx = daemon
        .query_udp(&common::query("localhost.", RecordType::MX, false))
        .await;
    assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
    assert!(mx.answers.is_empty(), "localhost must have no MX");

    // Registry names that are not part of the public namespace get a local NXDOMAIN.
    for name in [
        "printer.local.",
        "nas.home.arpa.",
        "nothing.invalid.",
        "1.0.168.192.in-addr.arpa.",
        "5.4.3.10.in-addr.arpa.",
    ] {
        let r = daemon
            .query_udp(&common::query(name, RecordType::A, false))
            .await;
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::NXDomain,
            "{name} must be NXDOMAIN"
        );
        assert!(r.metadata.authoritative, "{name} is answered locally");
    }

    assert_eq!(
        handler.query_count(),
        0,
        "no special-use name may ever reach an upstream"
    );

    // An ordinary name that merely contains a registry label still resolves normally.
    let ordinary = daemon
        .query_udp(&common::query("local.example.test.", RecordType::A, false))
        .await;
    assert_eq!(ordinary.metadata.response_code, ResponseCode::NoError);
    assert!(
        handler.query_count() > 0,
        "ordinary names must still be forwarded"
    );
}

#[tokio::test]
async fn a_configured_local_zone_overrides_the_special_use_registry() {
    let handler = MockUpstream::new();
    let (daemon, _servers) = mock_and_daemon(
        handler.clone(),
        r#"
[[local.zones]]
name = "home.arpa."
records = [{ name = "nas.home.arpa.", rtype = "A", value = "192.168.1.10" }]
"#,
    )
    .await;

    let r = daemon
        .query_udp(&common::query("nas.home.arpa.", RecordType::A, false))
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.answers.len(), 1, "operator configuration must win");
    assert_eq!(handler.query_count(), 0);
}

/// Background validation must not destroy an answer it could not finish checking.
///
/// A validation run against an upstream that supplies no chain of trust - a gateway
/// forwarder, a response with the records stripped, the in-process mock here - ends with
/// hickory stamping the records `Bogus`, because "I asked for the DS and got no proof
/// either way" and "the signature is wrong" surface the same way. The evidence plane's
/// contract is that only a validation by an upstream that actually returns DNSSEC
/// records may remove data. If this test fails, a DNSSEC-incapable upstream can churn
/// the cache for every unsigned name: served once, evicted, re-fetched forever.
///
/// The observable is upstream query counts. The validator always re-queries the A
/// record itself, so after the first client query and its background validation the
/// mock has seen the name twice; a second client query is then a cache hit (count stays
/// 2). An eviction forces a re-fetch (count 3).
#[tokio::test]
async fn background_validation_keeps_answers_a_proofless_upstream_cannot_confirm() {
    let handler = MockUpstream::new();
    handler.set(
        "cached.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("cached.example.test.", 300, "203.0.113.44")]),
    );
    // DS and DNSKEY queries reach names the mock has no records for. An empty NOERROR is
    // what a stripped or forwarding upstream produces; it gives the validator no proof.
    handler.set_default(Behaviour::NoData { minimum: 60 });

    // The default DNSSEC mode is `background`, so this fragment deliberately has no
    // `[dnssec]` section: `udp_upstream_fragment` pins `off`, and this test exists for
    // the background evidence path.
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
    let fragment = format!(
        r#"
upstreams = ["{}"]
proxies = []

[probe]
enabled = false

[prefetch]
enabled = false
"#,
        servers.udp.expect("mock udp")
    );
    let daemon = Daemon::start(&fragment).await;

    let first = daemon
        .query_udp(&common::query("cached.example.test.", RecordType::A, false))
        .await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    // Give the evidence plane time to run: it re-queries the A record and the chain
    // lookups, and - before the fix - evicts the cached answer.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let second = daemon
        .query_udp(&common::query("cached.example.test.", RecordType::A, false))
        .await;
    assert_eq!(second.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        handler.count_for("cached.example.test.", RecordType::A),
        2,
        "expected one client query plus one validator query; a third exchange means          background validation evicted an answer it merely could not finish checking"
    );
}
