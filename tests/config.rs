//! The configuration surface, tested as a black box.
//!
//! EgressDNS 2.0 has one configuration model. These tests pin what it accepts, what it
//! refuses, and — the part that is easy to get wrong and impossible to notice — what it
//! does when a setting is simply *absent*.
//!
//! The minimal-configuration tests deliberately build the file byte for byte instead of
//! using the shared harness. The harness injects listeners and an ACL, which is exactly
//! the hidden state that would make a broken default look fine.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{a, Behaviour, MockUpstream, TestCa, Transports};
use egressdns::config::{Config, TransportKind};
use egressdns::dns::server as dns_server;
use egressdns::dns::server::Ingress;
use egressdns::runtime::App;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn err(text: &str) -> String {
    Config::from_toml(text, "test")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| panic!("expected this configuration to be refused:\n{text}"))
}

// ---------------------------------------------------------------------------
// The minimal configuration, with nothing added
// ---------------------------------------------------------------------------

/// A daemon started from exactly `text`, with no injected listeners and no injected ACL.
///
/// The listeners come from the configuration itself, so this cannot accidentally prove
/// that a *different* configuration works.
struct Bare {
    _app: Arc<App>,
    udp: SocketAddr,
    tcp: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn start_bare(text: &str) -> Bare {
    egressdns::tls::install_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("egressdns.toml");
    std::fs::write(&path, text).expect("write");

    let config = Arc::new(
        Config::from_toml(text, &path.display().to_string()).expect("configuration must parse"),
    );
    let app = App::from_config(Arc::clone(&config), path).expect("assemble app");
    let ingress = Ingress::new(Arc::clone(&app));

    // Port 53 is not bindable in a test, so the *listen addresses* are overridden to
    // ephemeral loopback ports. Nothing else is: the ACL, in particular, is whatever the
    // configuration produced, which is the thing under test.
    let udp_socket = dns_server::bind_udp("127.0.0.1:0".parse().expect("addr"), &config.server.udp)
        .expect("bind udp");
    let udp = udp_socket.local_addr().expect("addr");
    tokio::spawn(dns_server::serve_udp(
        Arc::new(udp_socket),
        Arc::clone(&ingress),
    ));
    let tcp_listener =
        dns_server::bind_tcp("127.0.0.1:0".parse().expect("addr"), &config.server.tcp)
            .expect("bind tcp");
    let tcp = tcp_listener.local_addr().expect("addr");
    tokio::spawn(dns_server::serve_tcp(tcp_listener, Arc::clone(&ingress)));

    app.set_ready(true);
    Bare {
        _app: app,
        udp,
        tcp,
        _dir: dir,
    }
}

async fn query_udp(addr: SocketAddr, name: &str) -> hickory_proto::op::Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let bytes = common::query(name, RecordType::A, false)
        .to_vec()
        .expect("encode");
    socket.send_to(&bytes, addr).await.expect("send");
    let mut buf = vec![0u8; 65_535];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        socket.recv_from(&mut buf),
    )
    .await
    .expect("a response before the timeout")
    .expect("recv");
    hickory_proto::op::Message::from_vec(&buf[..len]).expect("decode")
}

async fn query_tcp(addr: SocketAddr, name: &str) -> hickory_proto::op::Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let bytes = common::query(name, RecordType::A, false)
        .to_vec()
        .expect("encode");
    let len = u16::try_from(bytes.len()).expect("length");
    stream.write_all(&len.to_be_bytes()).await.expect("write");
    stream.write_all(&bytes).await.expect("write");
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.expect("read length");
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(header))];
    stream.read_exact(&mut body).await.expect("read body");
    hickory_proto::op::Message::from_vec(&body).expect("decode")
}

async fn mock_upstream(name: &str, addr: &str) -> SocketAddr {
    let handler = MockUpstream::new();
    handler.set(
        name,
        RecordType::A,
        Behaviour::Answer(vec![a(name, 300, addr)]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let udp = servers.udp.expect("udp");
    // The listeners must outlive this function; dropping them would close the sockets.
    std::mem::forget(servers);
    std::mem::forget(ca);
    udp
}

/// The whole configuration is two keys, and it works from loopback.
///
/// This is the file the README opens with. If it does not serve, the documentation is a
/// lie and every other guarantee is downstream of a resolver nobody can start.
#[tokio::test]
async fn the_minimal_configuration_answers_over_udp_and_tcp() {
    let upstream = mock_upstream("min.example.test.", "203.0.113.5").await;

    // Exactly this, and nothing else. No [server], no allow_from, no listeners.
    let text = format!(
        "upstreams = [\"{upstream}\"]\nproxies = []\n\n[dnssec]\nmode = \"off\"\n\n\
         [probe]\nenabled = false\n\n[prefetch]\nenabled = false\n\n\
         [storage]\nenabled = false\n\n[metrics]\nenabled = false\n\n[admin]\nenabled = false\n"
    );

    let bare = start_bare(&text).await;

    let udp = query_udp(bare.udp, "min.example.test.").await;
    assert_eq!(
        udp.metadata.response_code,
        ResponseCode::NoError,
        "a loopback client must be served by a configuration that names no ACL"
    );
    assert_eq!(
        common::addresses(&udp),
        vec!["203.0.113.5".parse::<std::net::IpAddr>().expect("ip")]
    );

    let tcp = query_tcp(bare.tcp, "min.example.test.").await;
    assert_eq!(tcp.metadata.response_code, ResponseCode::NoError);
}

/// The default listeners are loopback only, so a minimal file cannot become an open
/// resolver by accident.
#[test]
fn the_default_listeners_are_loopback_only() {
    let cfg =
        Config::from_toml("upstreams = [\"1.1.1.1\"]\nproxies = []\n", "test").expect("valid");
    let listeners: Vec<std::net::IpAddr> = cfg
        .server
        .udp_listen
        .iter()
        .chain(cfg.server.tcp_listen.iter())
        .map(|a| a.ip())
        .collect();
    assert!(!listeners.is_empty(), "there must be default listeners");
    for ip in &listeners {
        assert!(ip.is_loopback(), "{ip} is not loopback");
    }
}

// ---------------------------------------------------------------------------
// ACL: omitted, explicitly empty, explicitly populated
// ---------------------------------------------------------------------------

/// Omitted means "this machine", which is what makes the two-key file usable.
#[test]
fn an_omitted_acl_admits_loopback() {
    let cfg =
        Config::from_toml("upstreams = [\"1.1.1.1\"]\nproxies = []\n", "test").expect("valid");
    assert!(cfg.server.allow_from.is_none(), "the field is absent");
    let allowed = cfg.effective_allow_from();
    let v4: std::net::IpAddr = "127.0.0.1".parse().expect("ip");
    let v6: std::net::IpAddr = "::1".parse().expect("ip");
    assert!(allowed.iter().any(|n| n.contains(&v4)), "{allowed:?}");
    assert!(allowed.iter().any(|n| n.contains(&v6)), "{allowed:?}");
}

/// Explicitly empty is a deliberate deny-all and must not be quietly turned into the
/// loopback default — that would override an operator who said "nobody, yet".
#[tokio::test]
async fn an_explicitly_empty_acl_refuses_everyone() {
    let upstream = mock_upstream("deny.example.test.", "203.0.113.6").await;
    let text = format!(
        "upstreams = [\"{upstream}\"]\nproxies = []\n\n[server]\nallow_from = []\n\n\
         [dnssec]\nmode = \"off\"\n\n[probe]\nenabled = false\n\n[prefetch]\nenabled = false\n\n\
         [storage]\nenabled = false\n\n[metrics]\nenabled = false\n\n[admin]\nenabled = false\n"
    );
    let cfg = Config::from_toml(&text, "test").expect("valid");
    assert_eq!(cfg.server.allow_from.as_deref(), Some(&[][..]));
    assert!(
        cfg.effective_allow_from().is_empty(),
        "an explicit empty list stays empty"
    );

    let bare = start_bare(&text).await;
    let response = query_udp(bare.udp, "deny.example.test.").await;
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::Refused,
        "an explicit deny-all must refuse even loopback"
    );
}

/// A non-loopback listener with no ACL is refused before anything binds. Guessing here
/// is how open resolvers happen.
#[test]
fn a_non_loopback_listener_without_an_acl_is_refused() {
    let e = err("upstreams = [\"1.1.1.1\"]\nproxies = []\n\n[server]\n\
         udp_listen = [\"0.0.0.0:53\"]\ntcp_listen = [\"0.0.0.0:53\"]\n");
    assert!(e.contains("allow_from"), "{e}");
    assert!(e.contains("open resolver"), "{e}");
}

#[test]
fn a_non_loopback_listener_with_an_explicit_acl_is_accepted() {
    let cfg = Config::from_toml(
        "upstreams = [\"1.1.1.1\"]\nproxies = []\n\n[server]\n\
         udp_listen = [\"0.0.0.0:53\"]\ntcp_listen = [\"0.0.0.0:53\"]\n\
         allow_from = [\"192.168.0.0/16\"]\n",
        "test",
    )
    .expect("valid");
    assert_eq!(cfg.effective_allow_from().len(), 1);
}

// ---------------------------------------------------------------------------
// The old format is gone
// ---------------------------------------------------------------------------

/// There is no configuration version field, and writing one says so.
#[test]
fn there_is_no_configuration_version_field() {
    let e = err("version = 2\nupstreams = [\"1.1.1.1\"]\nproxies = []\n");
    assert!(e.contains("no configuration version field"), "{e}");
    assert!(e.contains("MIGRATION"), "{e}");

    // And nothing in the serialized form reintroduces one.
    let cfg =
        Config::from_toml("upstreams = [\"1.1.1.1\"]\nproxies = []\n", "test").expect("valid");
    let rendered = cfg.to_redacted_toml();
    assert!(
        !rendered
            .lines()
            .any(|l| l.trim_start().starts_with("version")),
        "the effective configuration must not contain a version field:\n{rendered}"
    );
}

/// The old upstream tree is refused by name, with somewhere to go.
#[test]
fn the_legacy_upstream_group_syntax_is_refused_with_migration_advice() {
    let e = err("[[upstream.groups]]\nname = \"default\"\n\n\
         [[upstream.groups.servers]]\nname = \"a\"\ntransport = \"udp\"\n\
         addresses = [\"9.9.9.9\"]\n");
    assert!(e.contains("upstream"), "{e}");
    assert!(e.contains("`upstreams`"), "{e}");
    assert!(e.contains("MIGRATION-V1-TO-V2.md"), "{e}");
}

/// A v1 file usually carries both markers; the message must still be the useful one.
#[test]
fn a_complete_v1_file_is_refused_before_serde_sees_it() {
    let e = err("version = 2\n\n[[upstream.groups]]\nname = \"default\"\n\n\
         [[upstream.groups.servers]]\nname = \"a\"\ntransport = \"dot\"\n\
         addresses = [\"9.9.9.9\"]\nserver_name = \"dns.quad9.net\"\nweight = 100\n");
    assert!(
        !e.contains("unknown field"),
        "the migration message must win over serde's: {e}"
    );
    assert!(e.contains("MIGRATION"), "{e}");
}

// ---------------------------------------------------------------------------
// Endpoint and proxy URIs
// ---------------------------------------------------------------------------

#[test]
fn a_bare_address_produces_do53() {
    let cfg =
        Config::from_toml("upstreams = [\"1.1.1.1\"]\nproxies = []\n", "test").expect("valid");
    let servers = &cfg.upstream.groups[0].servers;
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].transport, TransportKind::Udp);
    assert_eq!(servers[0].effective_port(), 53);
}

#[test]
fn one_https_upstream_becomes_both_http_versions() {
    let cfg = Config::from_toml(
        "upstreams = [\"https://cloudflare-dns.com/dns-query\"]\nproxies = []\n",
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
}

/// An arbitrary name is accepted; it does not have to be a provider the binary knows.
#[test]
fn an_arbitrary_named_endpoint_is_accepted() {
    let cfg = Config::from_toml(
        "upstreams = [\"tls://dns.self-hosted.example\"]\nproxies = []\n",
        "test",
    )
    .expect("valid");
    let s = &cfg.upstream.groups[0].servers[0];
    assert_eq!(s.transport, TransportKind::Dot);
    assert_eq!(s.server_name.as_deref(), Some("dns.self-hosted.example"));
    assert!(s.addresses.is_empty(), "startup bootstrap resolves it");
}

/// `?addr=` pins where the socket is opened without changing who is authenticated.
#[test]
fn an_address_hint_supplies_bootstrap_without_changing_identity() {
    let cfg = Config::from_toml(
        "upstreams = [\"tls://dns.self-hosted.example:8853?addr=10.53.0.53\"]\nproxies = []\n",
        "test",
    )
    .expect("valid");
    let s = &cfg.upstream.groups[0].servers[0];
    assert_eq!(s.server_name.as_deref(), Some("dns.self-hosted.example"));
    assert_eq!(s.effective_port(), 8853);
    assert_eq!(
        s.addresses,
        vec!["10.53.0.53".parse::<std::net::IpAddr>().expect("ip")]
    );
}

#[test]
fn every_supported_proxy_scheme_is_accepted() {
    let cfg = Config::from_toml(
        "upstreams = [\"1.1.1.1\"]\nproxies = [\
         \"socks5://127.0.0.1:1080\", \"socks5h://127.0.0.1:1081\", \
         \"http://127.0.0.1:7890\", \"https://127.0.0.1:7891\"]\n",
        "test",
    )
    .expect("valid");
    assert_eq!(cfg.proxy.len(), 4);
    let ids: Vec<String> = cfg.proxy.iter().map(|p| p.id()).collect();
    assert!(
        ids.contains(&String::from("socks5h://127.0.0.1:1081")),
        "{ids:?}"
    );
}

/// Proxy credentials must not survive into anything an operator or a log can read.
#[test]
fn proxy_credentials_are_not_rendered_in_the_effective_configuration() {
    let cfg = Config::from_toml(
        "upstreams = [\"1.1.1.1\"]\nproxies = [\"socks5://user:hunter2@127.0.0.1:1080\"]\n",
        "test",
    )
    .expect("valid");
    assert!(cfg.proxy[0].credentials.is_some(), "parsed");
    let rendered = cfg.to_redacted_toml();
    assert!(
        !rendered.contains("hunter2"),
        "the password reached --dump-config:\n{rendered}"
    );
    assert!(!format!("{:?}", cfg.proxy[0]).contains("hunter2"));
}

#[test]
fn a_malformed_endpoint_names_the_entry_and_the_supported_forms() {
    let e = err("upstreams = [\"ftp://dns.example.net\"]\nproxies = []\n");
    assert!(e.contains("ftp"), "{e}");
    assert!(e.contains("https"), "{e}");
}

#[test]
fn an_empty_upstream_list_is_refused() {
    let e = err("upstreams = []\nproxies = []\n");
    assert!(e.contains("upstream"), "{e}");
}

#[test]
fn an_unsupported_proxy_scheme_is_refused() {
    let e = err("upstreams = [\"1.1.1.1\"]\nproxies = [\"ftp://127.0.0.1:21\"]\n");
    assert!(e.contains("unsupported proxy scheme"), "{e}");
}
