//! Bounded HTTPS fetching for background dataset updates.
//!
//! Used by the Cloudflare prefix updater and by the untrusted candidate seed provider.
//! Three properties matter:
//!
//! * The response size is capped before anything is parsed, so an oversized or endless
//!   response costs a fixed amount of memory.
//! * Hostnames are resolved through this daemon's own resolver, so a dataset update
//!   inherits the same DNSSEC policy, caching and upstream health as any other query.
//! * Redirects are not followed by default: a redirect is a change of authority, and a
//!   candidate list has no business moving.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;

use crate::error::CloudflareError;

/// A parsed absolute HTTPS URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    /// Host component.
    pub host: String,
    /// Port, defaulting to 443.
    pub port: u16,
    /// Path and query.
    pub path: String,
}

impl HttpsUrl {
    /// Parse an absolute `https://` URL. Any other scheme is refused.
    pub fn parse(url: &str) -> Result<Self, CloudflareError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| CloudflareError::Fetch("only https:// URLs are supported".into()))?;
        if rest.is_empty() || rest.len() > 2_048 {
            return Err(CloudflareError::Fetch("URL length is implausible".into()));
        }
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err(CloudflareError::Fetch(
                "userinfo is not permitted in a dataset URL".into(),
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && !h.contains(':') => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| CloudflareError::Fetch("invalid port".into()))?;
                (h.to_string(), port)
            }
            _ => (authority.to_string(), 443u16),
        };
        if host.is_empty() || host.len() > 253 {
            return Err(CloudflareError::Fetch("invalid host".into()));
        }
        Ok(Self {
            host,
            port,
            path: path.to_string(),
        })
    }
}

/// A completed fetch.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// HTTP status code.
    pub status: u16,
    /// Response body, capped at the requested size.
    pub body: Vec<u8>,
    /// `ETag` response header.
    pub etag: Option<String>,
    /// `Last-Modified` response header.
    pub last_modified: Option<String>,
    /// Address that served the response.
    pub served_by: IpAddr,
}

/// Options for one fetch.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Hard cap on the number of body bytes read.
    pub max_bytes: usize,
    /// Overall timeout.
    pub timeout: Duration,
    /// Conditional request `If-None-Match` value.
    pub etag: Option<String>,
    /// Conditional request `If-Modified-Since` value.
    pub last_modified: Option<String>,
    /// Optional bearer token. Never logged.
    pub bearer: Option<String>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024,
            timeout: Duration::from_secs(10),
            etag: None,
            last_modified: None,
            bearer: None,
        }
    }
}

/// Fetch a URL, trying each resolved address in turn.
pub async fn fetch(
    url: &HttpsUrl,
    addresses: &[IpAddr],
    roots: Arc<RootCertStore>,
    options: &FetchOptions,
) -> Result<FetchResult, CloudflareError> {
    if addresses.is_empty() {
        return Err(CloudflareError::Fetch(format!(
            "no addresses for {}",
            url.host
        )));
    }
    // `options.timeout` bounds a single stage, not the whole operation. Trying four
    // addresses, each running connect, handshake, request and body to their own timeout,
    // could keep a background task alive for well over an order of magnitude longer than
    // the configured value. `OVERALL_ATTEMPTS` addresses inside one overall budget makes
    // the setting mean what an operator reads it to mean.
    let overall = tokio::time::Instant::now() + options.timeout * OVERALL_TIMEOUT_MULTIPLIER;
    let mut last = String::from("no attempt made");
    for addr in addresses.iter().take(OVERALL_ATTEMPTS) {
        if tokio::time::Instant::now() >= overall {
            last = "overall fetch deadline exceeded".to_string();
            break;
        }
        let remaining = overall - tokio::time::Instant::now();
        match tokio::time::timeout(
            remaining,
            fetch_one(url, *addr, Arc::clone(&roots), options),
        )
        .await
        {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => {
                last = "overall fetch deadline exceeded".to_string();
                break;
            }
        }
    }
    Err(CloudflareError::Fetch(crate::util::bounded(&last, 160)))
}

/// Addresses tried before giving up on a host.
const OVERALL_ATTEMPTS: usize = 4;

/// Multiple of `options.timeout` allowed for the whole fetch, across every attempt.
const OVERALL_TIMEOUT_MULTIPLIER: u32 = 4;

/// Aborts a hyper connection-driver task when the exchange ends.
///
/// The driver must be polled for the entire exchange — including the response body, not
/// just the headers — so it cannot be aborted as soon as `send_request` returns. It must
/// also be aborted on *every* exit path, including the `?` early returns, or a failed
/// fetch leaves a task alive holding a TLS connection until the peer closes it. An RAII
/// guard gets both right without a cleanup call on each branch.
struct DriverGuard(tokio::task::JoinHandle<()>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn fetch_one(
    url: &HttpsUrl,
    addr: IpAddr,
    roots: Arc<RootCertStore>,
    options: &FetchOptions,
) -> Result<FetchResult, CloudflareError> {
    if crate::util::ipclass::classify(addr).is_some() {
        return Err(CloudflareError::Fetch(format!(
            "{addr} is a special-use address and will not be fetched from"
        )));
    }
    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let (stream, _) = super::http::tcp_connect(addr, url.port, options.timeout)
        .await
        .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;
    let (tls, _, negotiated, _) =
        super::http::tls_handshake(stream, &url.host, &alpn, roots, options.timeout)
            .await
            .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;

    let uri: Uri = format!("https://{}{}", url.host, url.path)
        .parse()
        .map_err(|_| CloudflareError::Fetch("invalid request URI".into()))?;
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header(hyper::header::HOST, url.host.as_str())
        .header(hyper::header::USER_AGENT, super::http::user_agent())
        .header(hyper::header::ACCEPT, "application/json, text/plain, */*");
    if let Some(etag) = &options.etag {
        builder = builder.header(hyper::header::IF_NONE_MATCH, etag.as_str());
    }
    if let Some(lm) = &options.last_modified {
        builder = builder.header(hyper::header::IF_MODIFIED_SINCE, lm.as_str());
    }
    if let Some(token) = &options.bearer {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;

    let io = TokioIo::new(tls);
    // `_driver` is held until the body has been fully read: aborting it after the headers
    // arrive stops the connection being polled, so the body would silently never arrive
    // and a 200 response would be returned with an empty payload.
    let (response, _driver) = if negotiated.as_deref() == Some("h2") {
        let (mut sender, conn) = tokio::time::timeout(
            options.timeout,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io),
        )
        .await
        .map_err(|_| CloudflareError::Fetch("handshake timed out".into()))?
        .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;
        let driver = DriverGuard(tokio::spawn(async move {
            let _ = conn.await;
        }));
        let out = tokio::time::timeout(options.timeout, sender.send_request(request))
            .await
            .map_err(|_| CloudflareError::Fetch("request timed out".into()))?
            .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;
        (out, driver)
    } else {
        let (mut sender, conn) =
            tokio::time::timeout(options.timeout, hyper::client::conn::http1::handshake(io))
                .await
                .map_err(|_| CloudflareError::Fetch("handshake timed out".into()))?
                .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;
        let driver = DriverGuard(tokio::spawn(async move {
            let _ = conn.await;
        }));
        let out = tokio::time::timeout(options.timeout, sender.send_request(request))
            .await
            .map_err(|_| CloudflareError::Fetch("request timed out".into()))?
            .map_err(|e| CloudflareError::Fetch(crate::util::bounded(&e.to_string(), 120)))?;
        (out, driver)
    };

    let status = response.status().as_u16();
    let etag = header_value(response.headers(), hyper::header::ETAG.as_str());
    let last_modified = header_value(response.headers(), "last-modified");

    let mut body = Vec::new();
    let mut incoming = response.into_body();
    let deadline = tokio::time::Instant::now() + options.timeout;
    let mut overflowed = false;
    loop {
        let frame = match tokio::time::timeout_at(deadline, incoming.frame()).await {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Err(_))) => break,
            Ok(Some(Ok(f))) => f,
        };
        if let Some(data) = frame.data_ref() {
            if body.len() + data.len() > options.max_bytes {
                overflowed = true;
                break;
            }
            body.extend_from_slice(data);
        }
    }
    if overflowed {
        return Err(CloudflareError::TooLarge {
            got: body.len(),
            limit: options.max_bytes,
        });
    }

    Ok(FetchResult {
        status,
        body,
        etag,
        last_modified,
        served_by: addr,
    })
}

fn header_value(map: &hyper::HeaderMap, name: &str) -> Option<String> {
    map.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| crate::util::bounded(s, 200))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_urls() {
        let u = HttpsUrl::parse("https://api.cloudflare.com/client/v4/ips").expect("parse");
        assert_eq!(u.host, "api.cloudflare.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/client/v4/ips");

        let u = HttpsUrl::parse("https://cf.090227.xyz/ct?ips=6").expect("parse");
        assert_eq!(u.host, "cf.090227.xyz");
        assert_eq!(u.path, "/ct?ips=6");

        let u = HttpsUrl::parse("https://example.test:8443").expect("parse");
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn rejects_non_https_and_userinfo() {
        assert!(HttpsUrl::parse("http://example.test/").is_err());
        assert!(HttpsUrl::parse("ftp://example.test/").is_err());
        assert!(HttpsUrl::parse("https://user:pass@example.test/").is_err());
        assert!(HttpsUrl::parse("https://").is_err());
        assert!(HttpsUrl::parse("https://example.test:99999/").is_err());
    }

    #[tokio::test]
    async fn empty_address_list_is_an_error() {
        crate::tls::install_crypto_provider();
        let roots = Arc::new(crate::tls::root_store(false, &[]).expect("roots"));
        let url = HttpsUrl::parse("https://example.test/").expect("parse");
        let err = fetch(&url, &[], roots, &FetchOptions::default())
            .await
            .expect_err("must fail");
        assert!(matches!(err, CloudflareError::Fetch(_)));
    }

    #[tokio::test]
    async fn special_use_addresses_are_refused() {
        crate::tls::install_crypto_provider();
        let roots = Arc::new(crate::tls::root_store(false, &[]).expect("roots"));
        let url = HttpsUrl::parse("https://example.test/").expect("parse");
        let err = fetch(
            &url,
            &["127.0.0.1".parse().expect("ip")],
            roots,
            &FetchOptions {
                timeout: Duration::from_millis(200),
                ..FetchOptions::default()
            },
        )
        .await
        .expect_err("must refuse loopback");
        assert!(err.to_string().contains("special-use"));
    }
}
