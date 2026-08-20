//! Egress paths: direct, or through a proxy.
//!
//! Every stream-oriented upstream transport — Do53 over TCP, DoT, DoH over HTTP/2 —
//! reaches its server through exactly one function, `RuntimeProvider::connect_tcp`. That
//! makes it the right and only place to insert a proxy: the DNS transports above it do
//! not need to know, and cannot get it wrong.
//!
//! What a proxy is *not* is an opinion about the answer. A direct route and a tunnelled
//! route to the same resolver are two paths to one authority, measured separately and
//! trusted identically. Corroboration counts authorities, never paths.
//!
//! UDP and QUIC are deliberately not proxied. SOCKS5 `UDP ASSOCIATE` and MASQUE
//! `CONNECT-UDP` both exist and neither is implemented here, so `carries_udp()` is false
//! and datagram transports keep the direct path rather than being tunnelled through
//! something that cannot carry them.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_net::runtime::TokioTime;
use hickory_net::runtime::{QuicSocketBinder, RuntimeProvider, TokioHandle, TokioRuntimeProvider};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::config::proxy::{ProxyEndpoint, ProxyKind};

/// How traffic leaves this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPath {
    /// Straight out, no intermediary.
    Direct,
    /// Through a configured proxy.
    Proxy(Arc<ProxyEndpoint>),
}

impl EgressPath {
    /// Stable identity for metrics, health state and route keys.
    ///
    /// Never contains credentials: this is a metrics label and appears in operator output.
    pub fn id(&self) -> String {
        match self {
            Self::Direct => String::from("direct"),
            Self::Proxy(p) => p.id(),
        }
    }

    /// Whether this path can carry a transport that needs UDP datagrams.
    pub fn carries_udp(&self) -> bool {
        match self {
            Self::Direct => true,
            Self::Proxy(p) => p.kind.carries_udp(),
        }
    }
}

impl std::fmt::Display for EgressPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id())
    }
}

/// A byte stream to an upstream, however it got there.
///
/// One enum rather than a boxed trait object because the set is closed and the hot path
/// is per-byte: a `CONNECT` proxy that speaks TLS to *itself* wraps the stream, and
/// everything else is a plain socket.
#[derive(Debug)]
pub enum ProxiedStream {
    /// A direct socket, or one handed back by a cleartext proxy after its handshake.
    Plain(TcpStream),
    /// A socket to a proxy that authenticated itself with TLS first.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ProxiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A `RuntimeProvider` that sends stream transports along one egress path.
///
/// One instance per path, cloned into every route that uses it, so a route's identity and
/// its health are tied to how it actually leaves the host.
#[derive(Clone)]
pub struct EgressProvider {
    runtime: TokioRuntimeProvider,
    path: EgressPath,
    /// Trust roots, used only to authenticate an `https://` proxy.
    roots: Arc<rustls::RootCertStore>,
}

impl EgressProvider {
    /// A provider that connects directly.
    pub fn direct(roots: Arc<rustls::RootCertStore>) -> Self {
        Self {
            runtime: TokioRuntimeProvider::new(),
            path: EgressPath::Direct,
            roots,
        }
    }

    /// A provider that tunnels stream transports through `proxy`.
    pub fn through(proxy: Arc<ProxyEndpoint>, roots: Arc<rustls::RootCertStore>) -> Self {
        Self {
            runtime: TokioRuntimeProvider::new(),
            path: EgressPath::Proxy(proxy),
            roots,
        }
    }

    /// The path this provider uses.
    pub fn path(&self) -> &EgressPath {
        &self.path
    }
}

impl RuntimeProvider for EgressProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = AsyncIoTokioAsStd<ProxiedStream>;

    fn create_handle(&self) -> Self::Handle {
        self.runtime.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let path = self.path.clone();
        let roots = Arc::clone(&self.roots);
        let wait = timeout.unwrap_or(Duration::from_secs(5));
        Box::pin(async move {
            let stream = match &path {
                EgressPath::Direct => {
                    ProxiedStream::Plain(dial(server_addr, bind_addr, wait).await?)
                }
                EgressPath::Proxy(proxy) => {
                    connect_through(proxy, server_addr, roots, wait).await?
                }
            };
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        // Always direct. No proxy here carries datagrams, and pretending otherwise would
        // send UDP into a tunnel that silently drops it.
        self.runtime.bind_udp(local_addr, server_addr)
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        // Same reasoning as `bind_udp`: QUIC needs datagrams.
        self.runtime.quic_binder()
    }
}

/// Open a plain TCP connection.
async fn dial(
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    wait: Duration,
) -> io::Result<TcpStream> {
    let socket = match server_addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    }?;
    if let Some(bind) = bind_addr {
        socket.bind(bind)?;
    }
    socket.set_nodelay(true)?;
    match tokio::time::timeout(wait, socket.connect(server_addr)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connecting to {server_addr} timed out"),
        )),
    }
}

/// Establish a tunnel to `target` through `proxy`.
async fn connect_through(
    proxy: &ProxyEndpoint,
    target: SocketAddr,
    roots: Arc<rustls::RootCertStore>,
    wait: Duration,
) -> io::Result<ProxiedStream> {
    let proxy_addr = resolve_proxy(proxy).await?;
    let tcp = dial(proxy_addr, None, wait).await?;

    let result = tokio::time::timeout(wait, async move {
        match proxy.kind {
            ProxyKind::Socks5 | ProxyKind::Socks5Hostname => {
                let mut stream = tcp;
                socks5_handshake(&mut stream, proxy, target).await?;
                Ok(ProxiedStream::Plain(stream))
            }
            ProxyKind::HttpConnect => {
                let mut stream = tcp;
                http_connect(&mut stream, proxy, target).await?;
                Ok(ProxiedStream::Plain(stream))
            }
            ProxyKind::HttpsConnect => {
                // TLS to the proxy itself, then CONNECT inside it. The upstream's own
                // TLS, if any, is layered on top of this by the transport above.
                let config = crate::tls::client_config(roots, &[], true);
                let name =
                    rustls_pki_types::ServerName::try_from(proxy.host.clone()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("proxy host `{}` is not a valid TLS name", proxy.host),
                        )
                    })?;
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let mut tls = connector.connect(name, tcp).await?;
                http_connect(&mut tls, proxy, target).await?;
                Ok(ProxiedStream::Tls(Box::new(tls)))
            }
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the {} handshake timed out", proxy.kind),
        )),
    }
}

/// A proxy is addressed by name or literal; only a literal can be dialled.
async fn resolve_proxy(proxy: &ProxyEndpoint) -> io::Result<SocketAddr> {
    if let Ok(ip) = proxy.host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, proxy.port));
    }
    // A named proxy is resolved by the system, once per connection attempt. It cannot be
    // resolved through us: the proxy may be the only way out.
    let authority = format!("{}:{}", proxy.host, proxy.port);
    let mut addrs = tokio::net::lookup_host(authority.clone()).await?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no address for proxy {authority}"),
        )
    })
}

/// RFC 1928 greeting, optional RFC 1929 authentication, and `CONNECT`.
async fn socks5_handshake<S>(
    stream: &mut S,
    proxy: &ProxyEndpoint,
    target: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const VERSION: u8 = 0x05;
    const NO_AUTH: u8 = 0x00;
    const USER_PASS: u8 = 0x02;

    // Offer only what we can actually perform, so the proxy cannot select a method we
    // would then fail to complete.
    let methods: &[u8] = if proxy.credentials.is_some() {
        &[NO_AUTH, USER_PASS]
    } else {
        &[NO_AUTH]
    };
    let mut greeting = vec![VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;
    stream.flush().await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != VERSION {
        return Err(protocol_error(format!(
            "the proxy answered SOCKS version {}, not 5",
            reply[0]
        )));
    }
    match reply[1] {
        NO_AUTH => {}
        USER_PASS => {
            let Some(creds) = proxy.credentials.as_ref() else {
                return Err(protocol_error(
                    "the proxy demanded a username and password, and none is configured",
                ));
            };
            // RFC 1929. Both fields are length-prefixed and capped at 255 bytes.
            let user = creds.username.as_bytes();
            let pass = creds.password.as_bytes();
            if user.len() > 255 || pass.len() > 255 {
                return Err(protocol_error(
                    "SOCKS5 credentials are limited to 255 bytes",
                ));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            stream.write_all(&auth).await?;
            stream.flush().await?;

            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await?;
            if auth_reply[1] != 0x00 {
                // Deliberately does not echo the credentials.
                return Err(protocol_error(
                    "the proxy rejected the configured credentials",
                ));
            }
        }
        0xFF => {
            return Err(protocol_error(
                "the proxy offered no authentication method we support",
            ))
        }
        other => {
            return Err(protocol_error(format!(
                "the proxy selected unsupported SOCKS5 method {other:#04x}"
            )))
        }
    }

    // The target is always a literal here: route selection has already chosen which
    // address to reach, so asking the proxy to resolve a name would discard that choice.
    // `socks5h` still matters for *bootstrap*, where there is no address yet.
    let mut request = vec![VERSION, 0x01, 0x00];
    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            request.push(0x04);
            request.extend_from_slice(&v6.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(protocol_error(format!(
            "the proxy refused to reach {target}: {}",
            socks5_reply_text(head[1])
        )));
    }
    // Drain the bound address so the stream is positioned at the tunnelled bytes.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut skip).await?;
        }
        other => {
            return Err(protocol_error(format!(
                "the proxy replied with unknown address type {other:#04x}"
            )))
        }
    }
    Ok(())
}

/// RFC 9110 `CONNECT`, with optional RFC 7617 basic authentication.
async fn http_connect<S>(
    stream: &mut S,
    proxy: &ProxyEndpoint,
    target: SocketAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = match target.ip() {
        std::net::IpAddr::V4(v4) => format!("{v4}:{}", target.port()),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{}", target.port()),
    };
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(creds) = proxy.credentials.as_ref() {
        let token = base64(format!("{}:{}", creds.username, creds.password).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Read only as far as the end of the headers. Anything after them belongs to the
    // tunnel, so over-reading here would swallow the first bytes of the DNS exchange.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(protocol_error(
                "the proxy closed the connection mid-response",
            ));
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            return Err(protocol_error(
                "the proxy sent an oversized response header",
            ));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| protocol_error("the proxy sent no HTTP status line"))?;
    if !(200..300).contains(&status) {
        return Err(protocol_error(format!(
            "the proxy refused to reach {target}: HTTP {status}"
        )));
    }
    Ok(())
}

/// RFC 4648 base64, for the `Proxy-Authorization` header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown failure",
    }
}

fn protocol_error(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy;

    #[test]
    fn base64_matches_rfc_4648_examples() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"user:hunter2"), "dXNlcjpodW50ZXIy");
    }

    #[test]
    fn a_direct_path_carries_udp_and_a_proxied_one_does_not() {
        let roots = Arc::new(rustls::RootCertStore::empty());
        let direct = EgressProvider::direct(Arc::clone(&roots));
        assert!(direct.path().carries_udp());
        assert_eq!(direct.path().id(), "direct");

        for uri in ["socks5://h:1", "socks5h://h:1", "http://h:1", "https://h:1"] {
            let p = Arc::new(proxy::parse(uri).expect("parse"));
            let provider = EgressProvider::through(p, Arc::clone(&roots));
            assert!(
                !provider.path().carries_udp(),
                "{uri} must not claim to carry datagrams"
            );
        }
    }

    /// The path identity is a metrics label, so it must never carry a password.
    #[test]
    fn a_proxy_path_identity_excludes_credentials() {
        let p = Arc::new(proxy::parse("socks5://user:hunter2@127.0.0.1:1080").expect("parse"));
        let path = EgressPath::Proxy(p);
        assert_eq!(path.id(), "socks5://127.0.0.1:1080");
        assert!(!path.to_string().contains("hunter2"));
    }

    /// A full SOCKS5 exchange against a scripted server, including the reply drain: if
    /// the bound address is not consumed, the first bytes of DNS are read as SOCKS.
    #[tokio::test]
    async fn socks5_completes_a_connect_and_leaves_the_stream_at_the_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting[0], 0x05);
            s.write_all(&[0x05, 0x00]).await.expect("method");

            let mut head = [0u8; 4];
            s.read_exact(&mut head).await.expect("request");
            assert_eq!(head[1], 0x01, "CONNECT");
            assert_eq!(head[3], 0x01, "IPv4 target");
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.expect("target");
            assert_eq!(&rest[..4], &[203, 0, 113, 9]);
            assert_eq!(u16::from_be_bytes([rest[4], rest[5]]), 853);

            // Success, with a bound address the client must drain.
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35])
                .await
                .expect("reply");
            // Then the tunnelled payload.
            s.write_all(b"PAYLOAD").await.expect("payload");
        });

        let proxy = proxy::parse(&format!("socks5://{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        socks5_handshake(
            &mut stream,
            &proxy,
            "203.0.113.9:853".parse().expect("target"),
        )
        .await
        .expect("handshake");

        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.expect("payload");
        assert_eq!(
            &payload, b"PAYLOAD",
            "the bound address must be drained so the stream starts at the tunnel"
        );
        server.await.expect("server");
    }

    #[tokio::test]
    async fn socks5_reports_a_refusal_with_its_reason() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 3];
            let _ = s.read_exact(&mut greeting).await;
            let _ = s.write_all(&[0x05, 0x00]).await;
            let mut head = [0u8; 10];
            let _ = s.read_exact(&mut head).await;
            // 0x05 = connection refused.
            let _ = s
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        });

        let proxy = proxy::parse(&format!("socks5://{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let err = socks5_handshake(
            &mut stream,
            &proxy,
            "203.0.113.9:853".parse().expect("target"),
        )
        .await
        .expect_err("must fail");
        assert!(err.to_string().contains("connection refused"), "{err}");
    }

    /// Username/password authentication, and the guarantee that a rejection does not
    /// echo the credentials into an error that will be logged.
    #[tokio::test]
    async fn socks5_authenticates_and_never_echoes_the_password() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 4];
            let _ = s.read_exact(&mut greeting).await;
            // Demand username/password.
            let _ = s.write_all(&[0x05, 0x02]).await;
            let mut ver_ulen = [0u8; 2];
            let _ = s.read_exact(&mut ver_ulen).await;
            let mut user = vec![0u8; usize::from(ver_ulen[1])];
            let _ = s.read_exact(&mut user).await;
            let mut plen = [0u8; 1];
            let _ = s.read_exact(&mut plen).await;
            let mut pass = vec![0u8; usize::from(plen[0])];
            let _ = s.read_exact(&mut pass).await;
            assert_eq!(user, b"user");
            assert_eq!(pass, b"hunter2");
            // Reject, so the client must produce an error.
            let _ = s.write_all(&[0x01, 0x01]).await;
        });

        let proxy = proxy::parse(&format!("socks5://user:hunter2@{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let err = socks5_handshake(
            &mut stream,
            &proxy,
            "203.0.113.9:853".parse().expect("target"),
        )
        .await
        .expect_err("must fail");
        assert!(err.to_string().contains("rejected"), "{err}");
        assert!(
            !err.to_string().contains("hunter2"),
            "the error leaked the password: {err}"
        );
    }

    #[tokio::test]
    async fn http_connect_succeeds_and_stops_at_the_end_of_the_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while s.read_exact(&mut byte).await.is_ok() {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf).to_string();
            assert!(
                request.starts_with("CONNECT 203.0.113.9:853 HTTP/1.1"),
                "{request}"
            );
            assert!(
                request.contains("Proxy-Authorization: Basic dXNlcjpodW50ZXIy"),
                "{request}"
            );
            s.write_all(b"HTTP/1.1 200 Connection established\r\nX: y\r\n\r\nPAYLOAD")
                .await
                .expect("reply");
            request
        });

        let proxy = proxy::parse(&format!("http://user:hunter2@{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        http_connect(
            &mut stream,
            &proxy,
            "203.0.113.9:853".parse().expect("target"),
        )
        .await
        .expect("connect");

        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.expect("payload");
        assert_eq!(
            &payload, b"PAYLOAD",
            "reading past the header terminator would swallow the tunnel's first bytes"
        );
        server.await.expect("server");
    }

    #[tokio::test]
    async fn http_connect_reports_a_refusal_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while s.read_exact(&mut byte).await.is_ok() {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        });

        let proxy = proxy::parse(&format!("http://{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let err = http_connect(
            &mut stream,
            &proxy,
            "203.0.113.9:853".parse().expect("target"),
        )
        .await
        .expect_err("must fail");
        assert!(err.to_string().contains("403"), "{err}");
    }

    /// An IPv6 target must be bracketed in the request line, or the proxy sees a
    /// malformed authority.
    #[tokio::test]
    async fn http_connect_brackets_an_ipv6_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while s.read_exact(&mut byte).await.is_ok() {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            String::from_utf8_lossy(&buf).to_string()
        });

        let proxy = proxy::parse(&format!("http://{addr}")).expect("parse");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        http_connect(
            &mut stream,
            &proxy,
            "[2606:4700:4700::1111]:853".parse().expect("target"),
        )
        .await
        .expect("connect");
        let request = server.await.expect("server");
        assert!(
            request.starts_with("CONNECT [2606:4700:4700::1111]:853"),
            "{request}"
        );
    }
}
