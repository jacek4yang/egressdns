//! QUIC and HTTP/3 probing.
//!
//! A successful QUIC handshake with the origin hostname as SNI and a verified certificate
//! chain already proves a great deal about a candidate address. An optional HTTP/3 HEAD
//! request adds evidence that the edge will actually serve that virtual host.
//!
//! Failure here is *never* treated as proof that an address is unusable: a network that
//! blocks UDP 443 makes every HTTP/3 probe fail while HTTPS over TCP works perfectly. Such
//! results are classified as unsupported or indeterminate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::RootCertStore;
use tokio::time::Instant;

use crate::error::ProbeError;

/// Outcome of a QUIC/HTTP3 probe.
#[derive(Debug, Clone)]
pub struct QuicProbeOutcome {
    /// Handshake duration.
    pub handshake: Duration,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
    /// HTTP status code, when an HTTP/3 request was made.
    pub status: Option<u16>,
    /// Time to first byte of the HTTP/3 response.
    pub ttfb: Option<Duration>,
}

/// Perform a QUIC handshake and, optionally, one HTTP/3 HEAD request.
pub async fn probe(
    addr: IpAddr,
    port: u16,
    hostname: &str,
    path: &str,
    roots: Arc<RootCertStore>,
    timeout: Duration,
    do_http: bool,
) -> Result<QuicProbeOutcome, ProbeError> {
    let bind: SocketAddr = match addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let mut endpoint = quinn::Endpoint::client(bind)
        .map_err(|e| ProbeError::Quic(crate::util::bounded(&e.to_string(), 120)))?;

    // ALPN `h3` only; 0-RTT is never offered.
    let tls = crate::tls::client_config(roots, &["h3"], false);
    let quic_crypto = QuicClientConfig::try_from(tls)
        .map_err(|e| ProbeError::Quic(crate::util::bounded(&e.to_string(), 120)))?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    endpoint.set_default_client_config(client_config);

    let remote = SocketAddr::new(addr, port);
    let start = Instant::now();
    let connecting = endpoint
        .connect(remote, hostname)
        .map_err(|e| ProbeError::Quic(crate::util::bounded(&e.to_string(), 120)))?;
    let connection = match tokio::time::timeout(timeout, connecting).await {
        Err(_) => {
            endpoint.close(0u32.into(), b"timeout");
            return Err(ProbeError::Timeout);
        }
        Ok(Err(e)) => {
            endpoint.close(0u32.into(), b"failed");
            return Err(ProbeError::Quic(crate::util::bounded(&e.to_string(), 160)));
        }
        Ok(Ok(c)) => c,
    };
    let handshake = start.elapsed();
    let alpn = connection
        .handshake_data()
        .and_then(|d| {
            d.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
                .and_then(|h| h.protocol)
        })
        .map(|p| String::from_utf8_lossy(&p).to_string());

    if !do_http {
        connection.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");
        return Ok(QuicProbeOutcome {
            handshake,
            alpn,
            status: None,
            ttfb: None,
        });
    }

    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let result = tokio::time::timeout(timeout, async move {
        let (mut driver, mut send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let uri: http::Uri = format!("https://{hostname}{path}")
            .parse()
            .map_err(|_| ProbeError::Http("invalid request URI".to_string()))?;
        let request = http::Request::builder()
            .method(http::Method::HEAD)
            .uri(uri)
            .header(http::header::USER_AGENT, super::http::user_agent())
            .body(())
            .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let sent = Instant::now();
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        stream
            .finish()
            .await
            .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|e| ProbeError::Http(crate::util::bounded(&e.to_string(), 120)))?;
        let ttfb = sent.elapsed();
        // Drain and discard at most one small body frame.
        let _: Option<Bytes> = stream.recv_data().await.ok().flatten().map(|mut b| {
            use bytes::Buf;
            b.copy_to_bytes(b.remaining().min(1024))
        });
        drive.abort();
        Ok::<_, ProbeError>((response.status().as_u16(), ttfb))
    })
    .await;

    connection.close(0u32.into(), b"done");
    endpoint.close(0u32.into(), b"done");

    match result {
        Err(_) => Err(ProbeError::Timeout),
        Ok(Err(e)) => Err(e),
        Ok(Ok((status, ttfb))) => Ok(QuicProbeOutcome {
            handshake,
            alpn,
            status: Some(status),
            ttfb: Some(ttfb),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_to_a_dead_address_fails_without_panicking() {
        crate::tls::install_crypto_provider();
        let roots = Arc::new(crate::tls::root_store(false, &[]).expect("roots"));
        // 192.0.2.0/24 is TEST-NET-1 and is guaranteed not to be routed.
        let result = probe(
            "192.0.2.1".parse().expect("ip"),
            443,
            "example.test",
            "/",
            roots,
            Duration::from_millis(300),
            false,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ProbeError::Timeout) | Err(ProbeError::Quic(_))
        ));
    }
}
