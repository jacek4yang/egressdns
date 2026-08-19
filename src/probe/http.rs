//! Direct-to-IP HTTP client used by the probe engine and the dataset fetchers.
//!
//! The client always connects to an explicit address while presenting the *origin*
//! hostname as TLS SNI and as the HTTP `Host` / `:authority` header. That is exactly what
//! is needed to answer the question "would this Cloudflare edge address serve this
//! specific hostname correctly?", and it is why a general-purpose HTTP client is not used
//! here: the address must never be chosen by the HTTP stack's own resolver.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::error::ProbeError;
use crate::tls::CapturedLeaf;

/// HTTP method permitted for probes. Probes never mutate remote state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    /// `HEAD`.
    Head,
    /// `GET`.
    Get,
}

impl ProbeMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Head => "HEAD",
            Self::Get => "GET",
        }
    }

    /// Parse a configured method name.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "HEAD" => Some(Self::Head),
            "GET" => Some(Self::Get),
            _ => None,
        }
    }
}

/// A fully specified HTTP probe.
#[derive(Debug, Clone)]
pub struct HttpProbeRequest {
    /// Address to dial. Never derived from DNS inside this function.
    pub ip: IpAddr,
    /// Port to dial.
    pub port: u16,
    /// TLS server name and HTTP authority. Always the origin hostname.
    pub hostname: String,
    /// Request path, beginning with `/`.
    pub path: String,
    /// Method.
    pub method: ProbeMethod,
    /// ALPN protocols offered, in preference order.
    pub alpn: Vec<String>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// TLS handshake timeout.
    pub tls_timeout: Duration,
    /// HTTP exchange timeout.
    pub http_timeout: Duration,
    /// Hard cap on the number of response body bytes read.
    pub max_body_bytes: usize,
}

/// Result of a successful HTTP probe.
#[derive(Debug, Clone)]
pub struct HttpProbeOutcome {
    /// TCP connect duration.
    pub tcp: Duration,
    /// TLS handshake duration.
    pub tls: Duration,
    /// Time to first byte of the response, measured from the request being sent.
    pub ttfb: Duration,
    /// Total duration.
    pub total: Duration,
    /// HTTP status code.
    pub status: u16,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
    /// Response headers, bounded in count and size.
    pub headers: Vec<(String, String)>,
    /// Response body bytes actually read, up to the configured cap.
    pub body: Vec<u8>,
    /// SHA-256 of `body`.
    pub body_sha256: [u8; 32],
    /// Facts extracted from the verified leaf certificate.
    pub leaf: Option<CapturedLeaf>,
}

impl HttpProbeOutcome {
    /// Value of a response header, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Cloudflare edge datacentre identifier, parsed from the `cf-ray` header.
    pub fn cf_colo(&self) -> Option<&str> {
        self.header("cf-ray").and_then(|r| r.rsplit('-').next())
    }
}

/// Maximum number of response headers retained.
const MAX_HEADERS: usize = 32;
/// Maximum length of any retained header value.
const MAX_HEADER_VALUE: usize = 256;

/// Establish a TCP connection and report how long it took.
pub async fn tcp_connect(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<(TcpStream, Duration), ProbeError> {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connect(crate::util::bounded(&e.to_string(), 120)))?;
    let _ = stream.set_nodelay(true);
    Ok((stream, start.elapsed()))
}

/// Perform a TLS handshake over an established stream, verifying the certificate chain
/// and the hostname.
pub async fn tls_handshake(
    stream: TcpStream,
    hostname: &str,
    alpn: &[String],
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<
    (
        tokio_rustls::client::TlsStream<TcpStream>,
        Duration,
        Option<String>,
        Option<CapturedLeaf>,
    ),
    ProbeError,
> {
    let alpn_refs: Vec<&str> = alpn.iter().map(|s| s.as_str()).collect();
    let (config, captured) = crate::tls::capturing_client_config(roots, &alpn_refs)
        .map_err(|e| ProbeError::Tls(crate::util::bounded(&e.to_string(), 120)))?;
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|_| ProbeError::Tls("invalid server name".to_string()))?;
    let connector = TlsConnector::from(Arc::new(config));
    let start = Instant::now();
    let tls = tokio::time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Tls(crate::util::bounded(&e.to_string(), 160)))?;
    let elapsed = start.elapsed();
    let negotiated = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    Ok((tls, elapsed, negotiated, captured.leaf()))
}

/// Run a complete HTTP probe against an explicit address.
pub async fn probe(
    req: &HttpProbeRequest,
    roots: Arc<RootCertStore>,
) -> Result<HttpProbeOutcome, ProbeError> {
    let overall = Instant::now();
    let (stream, tcp) = tcp_connect(req.ip, req.port, req.connect_timeout).await?;
    let (tls_stream, tls, alpn, leaf) =
        tls_handshake(stream, &req.hostname, &req.alpn, roots, req.tls_timeout).await?;

    let uri: Uri = format!("https://{}{}", req.hostname, req.path)
        .parse()
        .map_err(|_| ProbeError::Http("invalid request URI".to_string()))?;
    let http_req = Request::builder()
        .method(req.method.as_str())
        .uri(uri)
        .header(hyper::header::HOST, req.hostname.as_str())
        .header(hyper::header::USER_AGENT, user_agent())
        .header(hyper::header::ACCEPT, "*/*")
        .body(Empty::<Bytes>::new())
        .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;

    let use_h2 = alpn.as_deref() == Some("h2");
    let io = TokioIo::new(tls_stream);
    let sent = Instant::now();

    let (status, headers, body) = if use_h2 {
        let (mut sender, conn) = tokio::time::timeout(
            req.http_timeout,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let result = exchange(&mut sender, http_req, req, sent).await;
        driver.abort();
        result?
    } else {
        let (mut sender, conn) =
            tokio::time::timeout(req.http_timeout, hyper::client::conn::http1::handshake(io))
                .await
                .map_err(|_| ProbeError::Timeout)?
                .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let result = exchange_h1(&mut sender, http_req, req, sent).await;
        driver.abort();
        result?
    };

    let body_sha256 = crate::util::sha256(&body);
    Ok(HttpProbeOutcome {
        tcp,
        tls,
        ttfb: status.1,
        total: overall.elapsed(),
        status: status.0,
        alpn,
        headers,
        body,
        body_sha256,
        leaf,
    })
}

type ExchangeResult = Result<((u16, Duration), Vec<(String, String)>, Vec<u8>), ProbeError>;

async fn exchange(
    sender: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    request: Request<Empty<Bytes>>,
    cfg: &HttpProbeRequest,
    sent: Instant,
) -> ExchangeResult {
    let response = tokio::time::timeout(cfg.http_timeout, sender.send_request(request))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Http(map_h2_error(&e)))?;
    finish(response, cfg, sent).await
}

async fn exchange_h1(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    request: Request<Empty<Bytes>>,
    cfg: &HttpProbeRequest,
    sent: Instant,
) -> ExchangeResult {
    let response = tokio::time::timeout(cfg.http_timeout, sender.send_request(request))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
    finish(response, cfg, sent).await
}

fn map_h2_error(e: &hyper::Error) -> String {
    crate::util::bounded(&e.to_string(), 120)
}

async fn finish(
    response: hyper::Response<hyper::body::Incoming>,
    cfg: &HttpProbeRequest,
    sent: Instant,
) -> ExchangeResult {
    let ttfb = sent.elapsed();
    let status: StatusCode = response.status();
    let headers = collect_headers(response.headers());
    let mut body = Vec::new();
    let mut incoming = response.into_body();
    let deadline = tokio::time::Instant::now() + cfg.http_timeout;
    while body.len() < cfg.max_body_bytes {
        let next = tokio::time::timeout_at(deadline, incoming.frame()).await;
        let frame = match next {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Err(_))) => break,
            Ok(Some(Ok(f))) => f,
        };
        if let Some(data) = frame.data_ref() {
            let take = (cfg.max_body_bytes - body.len()).min(data.len());
            body.extend_from_slice(&data[..take]);
            if take < data.len() {
                break;
            }
        }
    }
    Ok(((status.as_u16(), ttfb), headers, body))
}

fn collect_headers(map: &hyper::HeaderMap<HeaderValue>) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(MAX_HEADERS.min(map.len()));
    for (name, value) in map.iter().take(MAX_HEADERS) {
        out.push((
            name.as_str().to_string(),
            crate::util::bounded(&String::from_utf8_lossy(value.as_bytes()), MAX_HEADER_VALUE),
        ));
    }
    out
}

/// The `User-Agent` presented by probes and dataset fetches.
pub fn user_agent() -> String {
    format!("{}/{} (+dns-forwarder)", crate::PRODUCT, crate::VERSION)
}

/// Build a header pair, rejecting anything that is not a valid header name.
pub fn header_pair(name: &str, value: &str) -> Option<(HeaderName, HeaderValue)> {
    let n = HeaderName::try_from(name).ok()?;
    let v = HeaderValue::from_str(value).ok()?;
    Some((n, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_parsing_is_restricted() {
        assert_eq!(ProbeMethod::parse("get"), Some(ProbeMethod::Get));
        assert_eq!(ProbeMethod::parse("HEAD"), Some(ProbeMethod::Head));
        assert_eq!(ProbeMethod::parse("POST"), None);
        assert_eq!(ProbeMethod::parse("DELETE"), None);
    }

    #[test]
    fn user_agent_is_identifiable() {
        let ua = user_agent();
        assert!(ua.starts_with("EgressDNS/"));
    }

    #[test]
    fn cf_colo_is_parsed_from_cf_ray() {
        let outcome = HttpProbeOutcome {
            tcp: Duration::ZERO,
            tls: Duration::ZERO,
            ttfb: Duration::ZERO,
            total: Duration::ZERO,
            status: 200,
            alpn: Some("h2".into()),
            headers: vec![("cf-ray".into(), "8f0e1a2b3c4d5e6f-FRA".into())],
            body: Vec::new(),
            body_sha256: [0u8; 32],
            leaf: None,
        };
        assert_eq!(outcome.cf_colo(), Some("FRA"));
        assert_eq!(outcome.header("CF-RAY"), Some("8f0e1a2b3c4d5e6f-FRA"));
        assert_eq!(outcome.header("missing"), None);
    }

    #[tokio::test]
    async fn tcp_connect_to_a_closed_port_fails_fast() {
        // Bind and immediately drop a listener to obtain a port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let result = tcp_connect(addr.ip(), addr.port(), Duration::from_millis(500)).await;
        assert!(matches!(
            result,
            Err(ProbeError::Connect(_)) | Err(ProbeError::Timeout)
        ));
    }
}
