//! Shared integration-test harness.
//!
//! Provides deterministic local upstream servers for every transport EgressDNS supports,
//! a scripted behaviour table so a test can make an upstream time out, truncate, fail or
//! return a specific RRset, and helpers for assembling a daemon under test.
//!
//! Everything here is local to the test process: no test in this repository contacts the
//! Internet.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, UdpSocket};

/// How a mock upstream should answer one question.
#[derive(Debug, Clone)]
pub enum Behaviour {
    /// Return these records in the answer section.
    Answer(Vec<Record>),
    /// Return NXDOMAIN with an SOA in the authority section.
    NxDomain {
        /// SOA minimum, which becomes the negative TTL.
        minimum: u32,
    },
    /// Return NOERROR with no answers and an SOA in the authority section.
    NoData {
        /// SOA minimum, which becomes the negative TTL.
        minimum: u32,
    },
    /// Return SERVFAIL.
    ServFail,
    /// Return REFUSED.
    Refused,
    /// Return an empty answer with the TC bit set, forcing a stream retry.
    Truncated,
    /// Model an answer too large for UDP: TC and no records over datagram transports,
    /// the full RRset over any stream transport.
    ///
    /// This is what a real authoritative server does, and it is the only way to exercise
    /// the RFC 7766 retry end to end: a `Truncated` behaviour that also sets TC on the
    /// TCP retry would make the retry impossible to complete.
    TruncatedOnUdp(Vec<Record>),
    /// Delay before applying the wrapped behaviour.
    Delay(Duration, Box<Behaviour>),
    /// Never answer at all.
    Drop,
}

/// A scripted upstream.
#[derive(Clone, Default)]
pub struct MockUpstream {
    table: Arc<Mutex<HashMap<(String, RecordType), Behaviour>>>,
    default: Arc<Mutex<Option<Behaviour>>>,
    queries: Arc<AtomicUsize>,
    /// Number of queries observed per (name, type).
    per_key: Arc<Mutex<HashMap<(String, RecordType), usize>>>,
    /// Exchanges currently being handled.
    inflight: Arc<AtomicUsize>,
    /// Highest concurrent exchange count observed.
    peak_inflight: Arc<AtomicUsize>,
}

impl MockUpstream {
    /// Create an empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script a behaviour for a question.
    pub fn set(&self, name: &str, qtype: RecordType, behaviour: Behaviour) -> &Self {
        self.table
            .lock()
            .insert((normalise(name), qtype), behaviour);
        self
    }

    /// Script the fallback behaviour for unscripted questions.
    pub fn set_default(&self, behaviour: Behaviour) -> &Self {
        *self.default.lock() = Some(behaviour);
        self
    }

    /// Total queries received.
    pub fn query_count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    /// Queries received for one question.
    pub fn count_for(&self, name: &str, qtype: RecordType) -> usize {
        self.per_key
            .lock()
            .get(&(normalise(name), qtype))
            .copied()
            .unwrap_or(0)
    }

    /// Reset all counters.
    pub fn reset_counts(&self) {
        self.queries.store(0, Ordering::SeqCst);
        self.per_key.lock().clear();
        self.peak_inflight.store(0, Ordering::SeqCst);
    }

    /// Highest number of exchanges this upstream handled at the same time.
    ///
    /// This is how a test proves an upstream concurrency ceiling actually binds: the
    /// client can only observe latency, but the server can count what really arrived.
    pub fn peak_inflight(&self) -> usize {
        self.peak_inflight.load(Ordering::SeqCst)
    }

    fn behaviour_for(&self, name: &str, qtype: RecordType) -> Behaviour {
        self.table
            .lock()
            .get(&(normalise(name), qtype))
            .cloned()
            .or_else(|| self.default.lock().clone())
            .unwrap_or(Behaviour::ServFail)
    }
}

fn normalise(name: &str) -> String {
    let mut s = name.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

#[async_trait::async_trait]
impl RequestHandler for MockUpstream {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        self.queries.fetch_add(1, Ordering::SeqCst);
        let Some(query) = request.queries.queries().first() else {
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(&request.metadata, ResponseCode::FormErr);
            return response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| empty_info(&request.metadata));
        };
        let name = query.name().to_string();
        let qtype = query.query_type();
        *self
            .per_key
            .lock()
            .entry((normalise(&name), qtype))
            .or_insert(0) += 1;

        // Count concurrency around the whole exchange, including any scripted delay,
        // so that a test can observe how many queries an upstream really sees at once.
        let live = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_inflight.fetch_max(live, Ordering::SeqCst);
        let _inflight = InflightGuard(Arc::clone(&self.inflight));

        let mut behaviour = self.behaviour_for(&name, qtype);
        while let Behaviour::Delay(d, inner) = behaviour {
            tokio::time::sleep(d).await;
            behaviour = *inner;
        }
        if let Behaviour::TruncatedOnUdp(records) = behaviour {
            behaviour = if request.protocol() == hickory_server::net::xfer::Protocol::Udp {
                Behaviour::Truncated
            } else {
                Behaviour::Answer(records)
            };
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;

        let result = match behaviour {
            Behaviour::Drop => return empty_info(&request.metadata),
            Behaviour::ServFail => {
                response_handle
                    .send_response(builder.error_msg(&request.metadata, ResponseCode::ServFail))
                    .await
            }
            Behaviour::Refused => {
                response_handle
                    .send_response(builder.error_msg(&request.metadata, ResponseCode::Refused))
                    .await
            }
            Behaviour::Truncated => {
                metadata.truncation = true;
                response_handle
                    .send_response(builder.build(metadata, &[], &[], &[], &[]))
                    .await
            }
            Behaviour::NxDomain { minimum } => {
                metadata.response_code = ResponseCode::NXDomain;
                let soa = vec![soa_record(&name, minimum)];
                response_handle
                    .send_response(builder.build(metadata, &[], &[], &soa, &[]))
                    .await
            }
            Behaviour::NoData { minimum } => {
                let soa = vec![soa_record(&name, minimum)];
                response_handle
                    .send_response(builder.build(metadata, &[], &[], &soa, &[]))
                    .await
            }
            Behaviour::Answer(records) => {
                response_handle
                    .send_response(builder.build(metadata, &records, &[], &[], &[]))
                    .await
            }
            Behaviour::Delay(_, _) => unreachable!("delays are unwrapped above"),
            Behaviour::TruncatedOnUdp(_) => {
                unreachable!("resolved to Truncated or Answer above")
            }
        };
        result.unwrap_or_else(|_| empty_info(&request.metadata))
    }
}

/// Decrements the mock's in-flight counter however the exchange ends.
struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn empty_info(metadata: &Metadata) -> ResponseInfo {
    let mut header = hickory_proto::op::Header {
        metadata: *metadata,
        counts: hickory_proto::op::HeaderCounts::default(),
    };
    header.metadata.message_type = hickory_proto::op::MessageType::Response;
    ResponseInfo::from(header)
}

/// Build an SOA record for the zone apex of `name`.
pub fn soa_record(name: &str, minimum: u32) -> Record {
    let apex = apex_of(name);
    Record::from_rdata(
        apex.clone(),
        3_600,
        RData::SOA(SOA::new(
            Name::from_utf8(format!("ns.{apex}")).expect("ns name"),
            Name::from_utf8(format!("hostmaster.{apex}")).expect("rname"),
            1,
            7_200,
            3_600,
            1_209_600,
            minimum,
        )),
    )
}

fn apex_of(name: &str) -> Name {
    let n = normalise(name);
    let labels: Vec<&str> = n.trim_end_matches('.').split('.').collect();
    let apex = if labels.len() > 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        labels.join(".")
    };
    Name::from_utf8(format!("{apex}.")).expect("apex name")
}

/// Build an A record.
pub fn a(name: &str, ttl: u32, addr: &str) -> Record {
    Record::from_rdata(
        Name::from_utf8(normalise(name)).expect("name"),
        ttl,
        RData::A(A(addr.parse().expect("v4"))),
    )
}

/// Build an AAAA record.
pub fn aaaa(name: &str, ttl: u32, addr: &str) -> Record {
    Record::from_rdata(
        Name::from_utf8(normalise(name)).expect("name"),
        ttl,
        RData::AAAA(AAAA(addr.parse().expect("v6"))),
    )
}

/// Build a CNAME record.
pub fn cname(name: &str, ttl: u32, target: &str) -> Record {
    Record::from_rdata(
        Name::from_utf8(normalise(name)).expect("name"),
        ttl,
        RData::CNAME(CNAME(Name::from_utf8(normalise(target)).expect("target"))),
    )
}

/// A self-signed certificate authority for the test transports.
pub struct TestCa {
    /// PEM of the CA certificate.
    pub ca_pem: String,
    /// DER of the CA certificate.
    pub ca_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    /// Create a new CA.
    pub fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "EgressDNS Test CA");
        let cert = params.self_signed(&key).expect("ca cert");
        let ca_pem = cert.pem();
        let ca_der = cert.der().clone();
        let issuer = rcgen::Issuer::new(params, key);
        Self {
            ca_pem,
            ca_der,
            issuer,
        }
    }

    /// Issue a server certificate for `hostname`.
    pub fn server_cert(
        &self,
        hostname: &str,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let mut params =
            rcgen::CertificateParams::new(vec![hostname.to_string()]).expect("leaf params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        let cert = params.signed_by(&key, &self.issuer).expect("leaf cert");
        let chain = vec![cert.der().clone(), self.ca_der.clone()];
        let private = PrivateKeyDer::try_from(key.serialize_der()).expect("key der");
        (chain, private)
    }

    /// Write the CA bundle to a file and return its path.
    pub fn write_bundle(&self, dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("test-ca.pem");
        std::fs::write(&path, &self.ca_pem).expect("write ca");
        path
    }

    /// Build a rustls server configuration with the given ALPN protocols.
    pub fn server_config(&self, hostname: &str, alpn: &[&str]) -> Arc<ServerConfig> {
        let (chain, key) = self.server_cert(hostname);
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        Arc::new(config)
    }
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

/// A running set of mock upstream listeners.
pub struct MockServers {
    /// The server driving every registered listener.
    pub server: hickory_server::server::Server<MockUpstream>,
    /// Address of the UDP listener, when registered.
    pub udp: Option<SocketAddr>,
    /// Address of the TCP listener, when registered.
    pub tcp: Option<SocketAddr>,
    /// Address of the DoT listener, when registered.
    pub dot: Option<SocketAddr>,
    /// Address of the DoH2 listener, when registered.
    pub doh2: Option<SocketAddr>,
    /// Address of the DoQ listener, when registered.
    pub doq: Option<SocketAddr>,
    /// Address of the DoH3 listener, when registered.
    pub doh3: Option<SocketAddr>,
}

/// Which transports to start.
#[derive(Debug, Clone, Copy, Default)]
pub struct Transports {
    /// Start a UDP listener.
    pub udp: bool,
    /// Start a TCP listener.
    pub tcp: bool,
    /// Start a DNS-over-TLS listener.
    pub dot: bool,
    /// Start a DNS-over-HTTPS (HTTP/2) listener.
    pub doh2: bool,
    /// Start a DNS-over-QUIC listener.
    pub doq: bool,
    /// Start a DNS-over-HTTPS (HTTP/3) listener.
    pub doh3: bool,
}

impl Transports {
    /// UDP and TCP only.
    pub fn plain() -> Self {
        Self {
            udp: true,
            tcp: true,
            ..Self::default()
        }
    }

    /// Every supported transport.
    pub fn all() -> Self {
        Self {
            udp: true,
            tcp: true,
            dot: true,
            doh2: true,
            doq: true,
            doh3: true,
        }
    }
}

/// Start the requested mock listeners on loopback.
pub async fn start_mock(
    handler: MockUpstream,
    ca: &TestCa,
    hostname: &str,
    transports: Transports,
) -> MockServers {
    egressdns::tls::install_crypto_provider();
    let mut server = hickory_server::server::Server::new(handler);
    let mut out = MockServers {
        udp: None,
        tcp: None,
        dot: None,
        doh2: None,
        doq: None,
        doh3: None,
        server: hickory_server::server::Server::new(MockUpstream::new()),
    };

    if transports.udp {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
        out.udp = socket.local_addr().ok();
        server.register_socket(socket);
    }
    if transports.tcp {
        // A real DNS server answers UDP and TCP on the *same* port, and RFC 7766 retries
        // rely on that: a truncated UDP answer is retried over TCP to the same address
        // and port. Binding TCP to an unrelated ephemeral port would make the mock
        // unrepresentative of anything, and would make the retry path untestable.
        // The UDP and TCP port spaces are separate, so reusing the number is safe.
        let listener = match out.udp {
            Some(addr) => TcpListener::bind(addr)
                .await
                .or(TcpListener::bind("127.0.0.1:0").await)
                .expect("tcp bind"),
            None => TcpListener::bind("127.0.0.1:0").await.expect("tcp bind"),
        };
        out.tcp = listener.local_addr().ok();
        server.register_listener(listener, Duration::from_secs(10), 64);
    }
    if transports.dot {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("dot bind");
        out.dot = listener.local_addr().ok();
        server
            .register_tls_listener_with_tls_config(
                listener,
                Duration::from_secs(10),
                ca.server_config(hostname, &["dot"]),
            )
            .expect("dot listener");
    }
    if transports.doh2 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("doh2 bind");
        out.doh2 = listener.local_addr().ok();
        server
            .register_https_listener_with_tls_config(
                listener,
                Duration::from_secs(10),
                ca.server_config(hostname, &["h2"]),
                Some(hostname.to_string()),
                "/dns-query".to_string(),
            )
            .expect("doh2 listener");
    }
    if transports.doq {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("doq bind");
        out.doq = socket.local_addr().ok();
        server
            .register_quic_listener_and_tls_config(
                socket,
                Duration::from_secs(10),
                ca.server_config(hostname, &["doq"]),
            )
            .expect("doq listener");
    }
    if transports.doh3 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("doh3 bind");
        out.doh3 = socket.local_addr().ok();
        server
            .register_h3_listener_with_tls_config(
                socket,
                Duration::from_secs(10),
                ca.server_config(hostname, &["h3"]),
                Some(hostname.to_string()),
            )
            .expect("doh3 listener");
    }

    out.server = server;
    out
}

/// Start one mock handler behind several UDP listeners on loopback.
///
/// Routes are per address, so a group of N servers gives the scheduler N rankable
/// routes — the minimum hedging needs — while every listener is driven by the same
/// handler, which keeps `peak_inflight` a single global count across all of them.
pub async fn start_mock_multi(
    handler: MockUpstream,
    udp_listeners: usize,
) -> (MockServers, Vec<SocketAddr>) {
    let mut server = hickory_server::server::Server::new(handler);
    let mut addrs = Vec::with_capacity(udp_listeners);
    for _ in 0..udp_listeners {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
        addrs.push(socket.local_addr().expect("udp addr"));
        server.register_socket(socket);
    }
    let out = MockServers {
        udp: addrs.first().copied(),
        tcp: None,
        dot: None,
        doh2: None,
        doq: None,
        doh3: None,
        server,
    };
    (out, addrs)
}

/// Build a query message.
pub fn query(name: &str, qtype: RecordType, dnssec_ok: bool) -> hickory_proto::op::Message {
    let mut m = hickory_proto::op::Message::new(
        rand::random(),
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    m.metadata.recursion_desired = true;
    let mut q =
        hickory_proto::op::Query::query(Name::from_utf8(normalise(name)).expect("name"), qtype);
    q.set_query_class(DNSClass::IN);
    m.add_query(q);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(dnssec_ok);
    m.set_edns(edns);
    m
}

/// Extract the A/AAAA addresses of a response, in order.
pub fn addresses(message: &hickory_proto::op::Message) -> Vec<std::net::IpAddr> {
    message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(std::net::IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Daemon under test
// ---------------------------------------------------------------------------

use egressdns::config::Config;
use egressdns::dns::server::{self as dns_server, Ingress};
use egressdns::runtime::App;

/// A running EgressDNS instance bound to ephemeral loopback ports.
pub struct Daemon {
    /// The assembled process.
    pub app: Arc<App>,
    /// Bound UDP address.
    pub udp: SocketAddr,
    /// Bound TCP address.
    pub tcp: SocketAddr,
    /// Temporary directory holding the configuration and state.
    pub dir: tempfile::TempDir,
    /// Path of the configuration file, so a test can rewrite and reload it.
    pub config_path: std::path::PathBuf,
}

impl Daemon {
    /// Start a daemon from a configuration fragment.
    ///
    /// The fragment must not specify listeners; they are bound here on ephemeral ports so
    /// tests never need a fixed port or elevated privileges.
    pub async fn start(fragment: &str) -> Self {
        egressdns::tls::install_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("egressdns.toml");
        let preamble = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:0"]
tcp_listen = ["127.0.0.1:0"]
allow_from = ["127.0.0.0/8", "::1/128"]

[metrics]
enabled = false

[admin]
enabled = false

[storage]
enabled = false
path = "{}/state.sqlite3"
"#,
            dir.path().display()
        );
        let text = format!("{preamble}\n{fragment}\n");
        std::fs::write(&config_path, &text).expect("write config");
        let config = Arc::new(
            Config::from_toml(&text, &config_path.display().to_string())
                .expect("test configuration must be valid"),
        );
        let app = App::from_config(Arc::clone(&config), config_path.clone()).expect("assemble app");
        let ingress = Ingress::new(Arc::clone(&app));

        let udp_socket =
            dns_server::bind_udp("127.0.0.1:0".parse().expect("addr"), &config.server.udp)
                .expect("bind udp");
        let udp = udp_socket.local_addr().expect("udp addr");
        tokio::spawn(dns_server::serve_udp(
            Arc::new(udp_socket),
            Arc::clone(&ingress),
        ));

        let tcp_listener =
            dns_server::bind_tcp("127.0.0.1:0".parse().expect("addr"), &config.server.tcp)
                .expect("bind tcp");
        let tcp = tcp_listener.local_addr().expect("tcp addr");
        tokio::spawn(dns_server::serve_tcp(tcp_listener, Arc::clone(&ingress)));

        app.set_ready(true);
        Self {
            app,
            udp,
            tcp,
            dir,
            config_path,
        }
    }

    /// Send a query over UDP and return the decoded response.
    pub async fn query_udp(
        &self,
        message: &hickory_proto::op::Message,
    ) -> hickory_proto::op::Message {
        self.query_udp_raw(&message.to_vec().expect("encode")).await
    }

    /// Send raw bytes over UDP and return the decoded response.
    pub async fn query_udp_raw(&self, bytes: &[u8]) -> hickory_proto::op::Message {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client");
        socket.send_to(bytes, self.udp).await.expect("send");
        let mut buf = vec![0u8; 65_535];
        let (len, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
            .await
            .expect("response before the timeout")
            .expect("recv");
        hickory_proto::op::Message::from_vec(&buf[..len]).expect("decode")
    }

    /// Send raw bytes over UDP, returning `None` when the daemon deliberately drops them.
    pub async fn try_query_udp(
        &self,
        message: &hickory_proto::op::Message,
        wait: Duration,
    ) -> Option<hickory_proto::op::Message> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client");
        socket
            .send_to(&message.to_vec().expect("encode"), self.udp)
            .await
            .expect("send");
        let mut buf = vec![0u8; 65_535];
        match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => hickory_proto::op::Message::from_vec(&buf[..len]).ok(),
            _ => None,
        }
    }

    /// Send a query over TCP and return the decoded response.
    pub async fn query_tcp(
        &self,
        message: &hickory_proto::op::Message,
    ) -> hickory_proto::op::Message {
        let mut responses = self.query_tcp_pipeline(std::slice::from_ref(message)).await;
        responses.pop().expect("one response")
    }

    /// Send several queries on one connection without waiting, then collect the responses.
    ///
    /// This exercises RFC 7766 pipelining and out-of-order completion.
    pub async fn query_tcp_pipeline(
        &self,
        messages: &[hickory_proto::op::Message],
    ) -> Vec<hickory_proto::op::Message> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(self.tcp)
            .await
            .expect("connect");
        for message in messages {
            let bytes = message.to_vec().expect("encode");
            let len = bytes.len() as u16;
            stream
                .write_all(&len.to_be_bytes())
                .await
                .expect("write len");
            stream.write_all(&bytes).await.expect("write body");
        }
        stream.flush().await.expect("flush");

        let mut out = Vec::with_capacity(messages.len());
        for _ in 0..messages.len() {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
                .await
            {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let len = usize::from(u16::from_be_bytes(len_buf));
            let mut payload = vec![0u8; len];
            if tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
                .await
                .is_err()
            {
                break;
            }
            if let Ok(m) = hickory_proto::op::Message::from_vec(&payload) {
                out.push(m);
            }
        }
        out
    }

    /// Rewrite the configuration file with a new fragment, using the same preamble.
    ///
    /// Returns the full text written, so a test can assert on what the daemon will read.
    pub fn rewrite(&self, fragment: &str) -> String {
        // The listen addresses must match the original text exactly. The daemon really
        // did bind ephemeral ports, but the *configuration* still says `:0`, and the
        // reload contract correctly treats a changed listen address as restart-required.
        let preamble = format!(
            r#"
[server]
udp_listen = ["127.0.0.1:0"]
tcp_listen = ["127.0.0.1:0"]
allow_from = ["127.0.0.0/8", "::1/128"]

[metrics]
enabled = false

[admin]
enabled = false

[storage]
enabled = false
path = "{}/state.sqlite3"
"#,
            self.dir.path().display()
        );
        let text = format!("{preamble}\n{fragment}\n");
        std::fs::write(&self.config_path, &text).expect("write config");
        text
    }

    /// Rewrite the configuration and reload it, returning the reload outcome.
    pub fn reload_with(&self, fragment: &str) -> Result<(), String> {
        self.rewrite(fragment);
        self.app.reload()
    }

    /// Start every supervised background task for this instance.
    ///
    /// Off by default because most tests only exercise the data plane and starting the
    /// control plane would make them slower and less deterministic.
    pub fn spawn_background(&self) {
        self.app.spawn_background();
    }

    /// Run one administration command against this instance.
    pub async fn admin(&self, command: &str, args: &[&str]) -> egressdns::admin::Response {
        let request = egressdns::admin::Request {
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        };
        egressdns::admin::server::dispatch(&self.app, &request).await
    }
}

/// Configuration fragment for a single plain-UDP upstream group.
pub fn udp_upstream_fragment(addr: SocketAddr) -> String {
    format!(
        r#"
[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "mock-udp"
transport = "udp"
addresses = ["{ip}"]
port = {port}
enable_cookies = false

[upstream.groups.scheduler]
hedge_enabled = false
query_timeout = "2s"

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#,
        ip = addr.ip(),
        port = addr.port()
    )
}

/// Configuration fragment for a single upstream group with several plain-UDP servers.
///
/// All servers sit in one group, so the scheduler ranks them against each other;
/// hedging requires at least two rankable routes, which means at least two addresses.
pub fn udp_upstream_fragment_multi(addrs: &[SocketAddr]) -> String {
    let servers: String = addrs
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            format!(
                r#"
[[upstream.groups.servers]]
name = "mock-udp-{i}"
transport = "udp"
addresses = ["{ip}"]
port = {port}
enable_cookies = false
"#,
                ip = addr.ip(),
                port = addr.port()
            )
        })
        .collect();
    format!(
        r#"
[[upstream.groups]]
name = "default"
{servers}
[upstream.groups.scheduler]
hedge_enabled = false
query_timeout = "2s"

[dnssec]
mode = "off"

[probe]
enabled = false

[prefetch]
enabled = false
"#
    )
}

// ---------------------------------------------------------------------------
// Test HTTPS origin
// ---------------------------------------------------------------------------

/// A canned HTTP response.
#[derive(Debug, Clone)]
pub struct CannedResponse {
    /// Status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl CannedResponse {
    /// A 200 response with a body.
    pub fn ok(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("server".into(), "cloudflare".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A response with an explicit status and empty body.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![("server".into(), "cloudflare".into())],
            body: Vec::new(),
        }
    }

    /// A 200 response with a body of `n` bytes.
    pub fn large(n: usize) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: vec![b'x'; n],
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A local HTTPS origin used by probe and dataset-fetch tests.
pub struct TestOrigin {
    /// Bound address.
    pub addr: SocketAddr,
    /// Number of requests served.
    pub requests: Arc<AtomicUsize>,
}

/// Start a local HTTPS origin serving `routes`, with `fallback` for unknown paths.
pub async fn start_https_origin(
    ca: &TestCa,
    hostname: &str,
    routes: HashMap<String, CannedResponse>,
    fallback: CannedResponse,
) -> TestOrigin {
    egressdns::tls::install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr");
    let config = ca.server_config(hostname, &["h2", "http/1.1"]);
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let routes = Arc::new(routes);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let routes = Arc::clone(&routes);
            let fallback = fallback.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let negotiated = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p.to_vec())
                    .unwrap_or_default();
                let io = hyper_util::rt::TokioIo::new(tls);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let routes = Arc::clone(&routes);
                        let fallback = fallback.clone();
                        let counter = Arc::clone(&counter);
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            let canned = routes.get(req.uri().path()).cloned().unwrap_or(fallback);
                            let mut builder = hyper::Response::builder().status(canned.status);
                            for (name, value) in &canned.headers {
                                builder = builder.header(name.as_str(), value.as_str());
                            }
                            Ok::<_, std::convert::Infallible>(
                                builder
                                    .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                        canned.body,
                                    )))
                                    .expect("response"),
                            )
                        }
                    },
                );
                if negotiated == b"h2" {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });

    TestOrigin { addr, requests }
}
