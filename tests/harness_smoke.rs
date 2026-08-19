//! Verifies that the integration harness itself works before it is relied upon.

mod common;

use std::time::Duration;

use common::{a, Behaviour, MockUpstream, TestCa, Transports};
use hickory_proto::rr::RecordType;

#[tokio::test]
async fn mock_upstream_answers_over_udp() {
    let handler = MockUpstream::new();
    handler.set(
        "example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("example.test.", 300, "203.0.113.10")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let udp = servers.udp.expect("udp address");

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let request = common::query("example.test.", RecordType::A, false);
    let bytes = request.to_vec().expect("encode");
    socket.send_to(&bytes, udp).await.expect("send");
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("no timeout")
        .expect("recv");
    let response = hickory_proto::op::Message::from_vec(&buf[..len]).expect("decode");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.10".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert_eq!(handler.query_count(), 1);
}

#[tokio::test]
async fn test_ca_issues_verifiable_certificates() {
    egressdns::tls::install_crypto_provider();
    let ca = TestCa::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = ca.write_bundle(dir.path());
    let roots = egressdns::tls::root_store(false, &[bundle]).expect("roots");
    assert!(roots.len() > 50, "the Mozilla set plus the test CA");
    let (chain, _key) = ca.server_cert("dns.example.test");
    assert_eq!(chain.len(), 2, "leaf plus CA");
}
