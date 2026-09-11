//! UDP and TCP ingress on port 53.
//!
//! Both listeners are deliberately thin: they parse, apply access control and rate limits,
//! hand the message to [`crate::dns::resolver::Resolver`], and serialise the answer with
//! the correct size limit. Everything that could block or take unbounded time lives
//! elsewhere.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::config::{TcpConfig, UdpConfig};
use crate::dns::acl::AclDecision;
use crate::dns::message as msgutil;
use crate::dns::ratelimit::RateDecision;
use crate::dns::resolver::ClientTransport;
use crate::error::ListenerError;
use crate::runtime::App;

/// Maximum inbound UDP datagram accepted.
const UDP_READ_BUFFER: usize = 4_096;

/// Shared ingress state.
///
/// The listener holds only the process handle and reads the active runtime state per
/// request, so a configuration reload takes effect immediately without restarting any
/// listener or dropping a connection.
pub struct Ingress {
    /// The assembled process.
    pub app: Arc<App>,
    /// Ceiling on concurrent in-flight client queries.
    pub inflight: Arc<Semaphore>,
    /// Shutdown signal.
    pub cancel: CancellationToken,
}

impl Ingress {
    /// Build an ingress handle.
    pub fn new(app: Arc<App>) -> Arc<Self> {
        let inflight = Arc::clone(&app.inflight);
        let cancel = app.cancel.clone();
        Arc::new(Self {
            app,
            inflight,
            cancel,
        })
    }

    /// Evaluate access control and rate limits for a client address.
    fn admit(&self, client: IpAddr) -> Result<(), &'static str> {
        let state = self.app.state();
        match state.acl.evaluate(client) {
            AclDecision::Allow => {}
            AclDecision::Denied => return Err("acl_denied"),
            AclDecision::NotAllowed => return Err("acl_not_allowed"),
        }
        match state.limiter.check(client) {
            RateDecision::Allow => Ok(()),
            RateDecision::ClientLimited => Err("rate_limited_client"),
            RateDecision::GlobalLimited => Err("rate_limited_global"),
        }
    }

    async fn respond(
        &self,
        bytes: &[u8],
        transport: ClientTransport,
        peer: SocketAddr,
    ) -> Option<msgutil::Serialized> {
        let request = match Message::from_vec(bytes) {
            Ok(m) => m,
            Err(_) => {
                metrics::counter!(
                    crate::metrics::names::REJECTED_TOTAL,
                    "reason" => "malformed",
                )
                .increment(1);
                // A message that cannot be parsed at all has no usable ID or question, so
                // there is nothing meaningful to answer with. Dropping is the standard
                // behaviour and avoids becoming a reflector.
                return None;
            }
        };
        if request.metadata.message_type != MessageType::Query {
            // Never answer a response; that is how loops start.
            return None;
        }

        let state = self.app.state();
        let started = tokio::time::Instant::now();
        metrics::counter!(
            crate::metrics::names::QUERIES_TOTAL,
            "transport" => transport.label(),
        )
        .increment(1);

        let answer = state.resolver.handle(&request, transport).await;
        let mut message = answer.message;

        if transport == ClientTransport::Tcp
            && state.config.server.tcp.advertise_edns_keepalive
            && message.edns.is_some()
        {
            if let Some(edns) = message.edns.as_mut() {
                edns.options_mut().insert(msgutil::encode_tcp_keepalive(
                    state.config.server.tcp.idle_timeout,
                ));
            }
        }

        metrics::counter!(
            crate::metrics::names::RESPONSES_TOTAL,
            "transport" => transport.label(),
            "rcode" => rcode_label(message.metadata.response_code),
            "origin" => answer.origin.label(),
        )
        .increment(1);
        let elapsed = started.elapsed();
        metrics::histogram!(
            crate::metrics::names::REQUEST_SECONDS,
            "transport" => transport.label(),
        )
        .record(elapsed.as_secs_f64());

        log_query(
            &state.config.logging,
            &request,
            &message,
            answer.origin,
            transport,
            peer,
            elapsed,
        );

        match msgutil::serialize_limited(&message, answer.max_size) {
            Ok(out) => {
                if out.truncated && transport == ClientTransport::Udp {
                    metrics::counter!(crate::metrics::names::UDP_TRUNCATED_TOTAL).increment(1);
                }
                Some(out)
            }
            Err(_) => {
                let fallback = msgutil::error_response(&request, ResponseCode::ServFail, true);
                msgutil::serialize_limited(&fallback, answer.max_size).ok()
            }
        }
    }

    fn refuse(&self, bytes: &[u8], reason: &'static str, max_size: usize) -> Option<Vec<u8>> {
        metrics::counter!(crate::metrics::names::REJECTED_TOTAL, "reason" => reason).increment(1);
        // A refused client still gets a well-formed REFUSED answer when the query parsed,
        // which is far easier to diagnose than silence. Rate-limited clients are dropped
        // instead, because answering them defeats the purpose of the limit.
        if reason.starts_with("rate_limited") {
            return None;
        }
        let request = Message::from_vec(bytes).ok()?;
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return None;
        }
        let response = msgutil::error_response(&request, ResponseCode::Refused, false);
        msgutil::serialize_limited(&response, max_size)
            .ok()
            .map(|s| s.bytes)
    }
}

/// Emit one structured line per sampled query, when `logging.query_log` is enabled.
///
/// This setting used to be parsed, validated and then never consulted, which made an
/// operator who turned it on believe they had an audit trail they did not have. It is now
/// read from the live configuration on every query, so enabling it — and changing the
/// sample rate — takes effect on reload.
///
/// Sampling is deterministic in the DNS message ID rather than random, so the same query
/// is not logged twice by two different processes, and a `RUST_LOG` filter can be applied
/// on top without changing which queries are eligible. Client addresses and query names
/// are personal data in most jurisdictions, which is why this is off by default and why
/// the sample rate defaults to 1%.
#[allow(clippy::too_many_arguments)]
fn log_query(
    cfg: &crate::config::LoggingConfig,
    request: &Message,
    response: &Message,
    origin: crate::dns::resolver::AnswerOrigin,
    transport: ClientTransport,
    peer: SocketAddr,
    elapsed: Duration,
) {
    if !cfg.query_log {
        return;
    }
    // `query_log_sample` is validated into [0, 1]; 0 logs nothing and 1 logs everything.
    if cfg.query_log_sample <= 0.0 {
        return;
    }
    if cfg.query_log_sample < 1.0 {
        let unit = crate::ranking::unit_from_seed(u64::from(request.id));
        if unit >= cfg.query_log_sample {
            return;
        }
    }
    let question = request.queries.first();
    tracing::info!(
        event = "query",
        client = %peer.ip(),
        transport = transport.label(),
        name = question.map(|q| q.name().to_ascii()).unwrap_or_default(),
        qtype = %question.map(|q| q.query_type().to_string()).unwrap_or_default(),
        qclass = %question.map(|q| q.query_class().to_string()).unwrap_or_default(),
        rcode = rcode_label(response.metadata.response_code),
        origin = origin.label(),
        answers = response.answers.len(),
        elapsed_ms = elapsed.as_secs_f64() * 1_000.0,
    );
}

fn rcode_label(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "noerror",
        ResponseCode::FormErr => "formerr",
        ResponseCode::ServFail => "servfail",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::NotImp => "notimp",
        ResponseCode::Refused => "refused",
        ResponseCode::BADVERS => "badvers",
        _ => "other",
    }
}

/// Bind a UDP socket with the configured options.
pub fn bind_udp(addr: SocketAddr, cfg: &UdpConfig) -> Result<UdpSocket, ListenerError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|source| {
        ListenerError::Bind {
            proto: "udp",
            addr,
            source,
        }
    })?;
    socket
        .set_nonblocking(true)
        .map_err(|source| ListenerError::SocketOption {
            proto: "udp",
            addr,
            source,
        })?;
    // On Unix, `SO_REUSEADDR` only avoids a TIME_WAIT stale-bind failure and cannot let a
    // second process steal the port. Windows' `SO_REUSEADDR` has no such guarantee — it
    // would allow another process to bind the same address and intercept traffic — so it
    // is deliberately not set there.
    #[cfg(unix)]
    socket
        .set_reuse_address(true)
        .map_err(|source| ListenerError::SocketOption {
            proto: "udp",
            addr,
            source,
        })?;
    if cfg.reuse_port {
        // `SO_REUSEPORT` is a Unix concept: one socket per worker, load-balanced by the
        // kernel. Windows has no equivalent, so the flag is reported and ignored rather
        // than silently pretending to have opened extra sockets.
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(|source| ListenerError::SocketOption {
                proto: "udp",
                addr,
                source,
            })?;
        #[cfg(windows)]
        tracing::warn!(
            event = "listener.udp.reuse_port_unsupported",
            address = %addr,
            "server.udp.reuse_port has no effect on Windows; one socket will be bound"
        );
    }
    if addr.is_ipv6() {
        // Keep the two families separate so that ACLs and metrics stay unambiguous.
        socket
            .set_only_v6(true)
            .map_err(|source| ListenerError::SocketOption {
                proto: "udp",
                addr,
                source,
            })?;
    }
    if let Some(size) = cfg.recv_buffer_bytes {
        let _ = socket.set_recv_buffer_size(size);
    }
    if let Some(size) = cfg.send_buffer_bytes {
        let _ = socket.set_send_buffer_size(size);
    }
    socket
        .bind(&addr.into())
        .map_err(|source| ListenerError::Bind {
            proto: "udp",
            addr,
            source,
        })?;
    UdpSocket::from_std(socket.into()).map_err(|source| ListenerError::Bind {
        proto: "udp",
        addr,
        source,
    })
}

/// Bind a TCP listener with the configured options.
pub fn bind_tcp(addr: SocketAddr, _cfg: &TcpConfig) -> Result<TcpListener, ListenerError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|source| {
        ListenerError::Bind {
            proto: "tcp",
            addr,
            source,
        }
    })?;
    socket
        .set_nonblocking(true)
        .map_err(|source| ListenerError::SocketOption {
            proto: "tcp",
            addr,
            source,
        })?;
    // Unix-only, for the same reason as the UDP socket: Windows `SO_REUSEADDR` would let
    // another process steal the port rather than merely permit a TIME_WAIT rebind.
    #[cfg(unix)]
    socket
        .set_reuse_address(true)
        .map_err(|source| ListenerError::SocketOption {
            proto: "tcp",
            addr,
            source,
        })?;
    if addr.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(|source| ListenerError::SocketOption {
                proto: "tcp",
                addr,
                source,
            })?;
    }
    socket
        .bind(&addr.into())
        .map_err(|source| ListenerError::Bind {
            proto: "tcp",
            addr,
            source,
        })?;
    socket.listen(1_024).map_err(|source| ListenerError::Bind {
        proto: "tcp",
        addr,
        source,
    })?;
    TcpListener::from_std(socket.into()).map_err(|source| ListenerError::Bind {
        proto: "tcp",
        addr,
        source,
    })
}

/// Serve UDP until cancelled.
pub async fn serve_udp(socket: Arc<UdpSocket>, ingress: Arc<Ingress>) {
    let mut buf = vec![0u8; UDP_READ_BUFFER];
    loop {
        let received = tokio::select! {
            biased;
            _ = ingress.cancel.cancelled() => break,
            r = socket.recv_from(&mut buf) => r,
        };
        let (len, peer) = match received {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::warn!(event = "udp.recv_failed", error = %e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let bytes = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let ingress = Arc::clone(&ingress);
        let Ok(permit) = Arc::clone(&ingress.inflight).try_acquire_owned() else {
            metrics::counter!(
                crate::metrics::names::REJECTED_TOTAL,
                "reason" => "inflight_limit",
            )
            .increment(1);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(reason) = ingress.admit(peer.ip()) {
                if let Some(out) = ingress.refuse(&bytes, reason, 512) {
                    let _ = socket.send_to(&out, peer).await;
                }
                return;
            }
            metrics::gauge!(crate::metrics::names::INFLIGHT_QUERIES).increment(1.0);
            let out = ingress.respond(&bytes, ClientTransport::Udp, peer).await;
            metrics::gauge!(crate::metrics::names::INFLIGHT_QUERIES).decrement(1.0);
            if let Some(out) = out {
                let _ = socket.send_to(&out.bytes, peer).await;
            }
        });
    }
}

/// Serve TCP until cancelled.
pub async fn serve_tcp(listener: TcpListener, ingress: Arc<Ingress>) {
    let tcp_cfg = ingress.app.config().server.tcp.clone();
    let connections = Arc::new(Semaphore::new(tcp_cfg.max_connections));
    let per_client = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::<
        IpAddr,
        Arc<AtomicUsize>,
    >::new()));
    loop {
        let accepted = tokio::select! {
            biased;
            _ = ingress.cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(event = "tcp.accept_failed", error = %e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            metrics::counter!(
                crate::metrics::names::TCP_REJECTED_TOTAL,
                "reason" => "global_limit",
            )
            .increment(1);
            continue;
        };
        if ingress.admit(peer.ip()).is_err() {
            metrics::counter!(
                crate::metrics::names::TCP_REJECTED_TOTAL,
                "reason" => "acl",
            )
            .increment(1);
            continue;
        }
        let counter = {
            let mut map = per_client.lock();
            if map.len() > 65_536 {
                map.retain(|_, v| v.load(Ordering::Relaxed) > 0);
            }
            Arc::clone(
                map.entry(peer.ip())
                    .or_insert_with(|| Arc::new(AtomicUsize::new(0))),
            )
        };
        if counter.load(Ordering::Relaxed) >= tcp_cfg.max_connections_per_client {
            metrics::counter!(
                crate::metrics::names::TCP_REJECTED_TOTAL,
                "reason" => "per_client_limit",
            )
            .increment(1);
            continue;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        metrics::gauge!(crate::metrics::names::TCP_ACTIVE_CONNECTIONS).increment(1.0);
        let ingress = Arc::clone(&ingress);
        tokio::spawn(async move {
            let _permit = permit;
            serve_tcp_connection(stream, peer, Arc::clone(&ingress)).await;
            counter.fetch_sub(1, Ordering::Relaxed);
            metrics::gauge!(crate::metrics::names::TCP_ACTIVE_CONNECTIONS).decrement(1.0);
        });
    }
}

/// Handle one DNS-over-TCP connection.
///
/// Queries are read as fast as they arrive and answered concurrently, so a slow query does
/// not head-of-line block the rest. Responses are written by a single writer task, which is
/// what allows out-of-order completion (RFC 7766 section 6.2.1.1).
async fn serve_tcp_connection(stream: TcpStream, peer: SocketAddr, ingress: Arc<Ingress>) {
    let cfg = ingress.app.config().server.tcp.clone();
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(cfg.max_pipelined_queries);
    let deadline = tokio::time::Instant::now() + cfg.max_connection_lifetime;

    let writer_task = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let len = payload.len().min(u16::MAX as usize) as u16;
            if writer.write_all(&len.to_be_bytes()).await.is_err() {
                break;
            }
            if writer
                .write_all(&payload[..usize::from(len)])
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    });

    let inflight = Arc::new(Semaphore::new(cfg.max_pipelined_queries));

    loop {
        let mut len_buf = [0u8; 2];
        let read = tokio::select! {
            biased;
            _ = ingress.cancel.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => break,
            r = tokio::time::timeout(cfg.idle_timeout, reader.read_exact(&mut len_buf)) => r,
        };
        match read {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len == 0 || len > cfg.max_message_bytes {
            break;
        }
        let mut payload = vec![0u8; len];
        match tokio::time::timeout(cfg.idle_timeout, reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let Ok(permit) = Arc::clone(&inflight).try_acquire_owned() else {
            // The client is pipelining beyond the configured depth. Applying backpressure
            // by pausing the read loop is the correct response.
            metrics::counter!(
                crate::metrics::names::TCP_REJECTED_TOTAL,
                "reason" => "pipeline_depth",
            )
            .increment(1);
            let permit = match Arc::clone(&inflight).acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            spawn_tcp_query(&ingress, permit, payload, tx.clone(), peer);
            continue;
        };
        spawn_tcp_query(&ingress, permit, payload, tx.clone(), peer);
    }

    drop(tx);
    let _ = writer_task.await;
}

fn spawn_tcp_query(
    ingress: &Arc<Ingress>,
    permit: tokio::sync::OwnedSemaphorePermit,
    payload: Vec<u8>,
    tx: mpsc::Sender<Vec<u8>>,
    peer: SocketAddr,
) {
    let ingress = Arc::clone(ingress);
    tokio::spawn(async move {
        let _permit = permit;
        let Ok(_global) = Arc::clone(&ingress.inflight).try_acquire_owned() else {
            metrics::counter!(
                crate::metrics::names::REJECTED_TOTAL,
                "reason" => "inflight_limit",
            )
            .increment(1);
            return;
        };
        metrics::gauge!(crate::metrics::names::INFLIGHT_QUERIES).increment(1.0);
        let out = ingress.respond(&payload, ClientTransport::Tcp, peer).await;
        metrics::gauge!(crate::metrics::names::INFLIGHT_QUERIES).decrement(1.0);
        if let Some(out) = out {
            let _ = tx.send(out.bytes).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_bind_applies_options() {
        let cfg = UdpConfig {
            recv_buffer_bytes: Some(1 << 20),
            send_buffer_bytes: Some(1 << 20),
            ..UdpConfig::default()
        };
        let socket = bind_udp("127.0.0.1:0".parse().expect("addr"), &cfg).expect("bind");
        assert!(socket.local_addr().expect("addr").port() > 0);
    }

    #[tokio::test]
    async fn tcp_bind_works() {
        let listener =
            bind_tcp("127.0.0.1:0".parse().expect("addr"), &TcpConfig::default()).expect("bind");
        assert!(listener.local_addr().expect("addr").port() > 0);
    }

    #[tokio::test]
    async fn ipv6_listener_is_v6_only() {
        let Ok(socket) = bind_udp("[::1]:0".parse().expect("addr"), &UdpConfig::default()) else {
            // IPv6 may be unavailable in a restricted build environment.
            return;
        };
        assert!(socket.local_addr().expect("addr").is_ipv6());
    }

    #[test]
    fn rcode_labels_are_bounded() {
        for code in [
            ResponseCode::NoError,
            ResponseCode::FormErr,
            ResponseCode::ServFail,
            ResponseCode::NXDomain,
            ResponseCode::NotImp,
            ResponseCode::Refused,
            ResponseCode::BADVERS,
            ResponseCode::BADKEY,
        ] {
            let label = rcode_label(code);
            assert!(!label.is_empty());
            assert!(label.chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}
