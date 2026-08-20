//! Metrics, liveness and readiness exposure.
//!
//! A deliberately tiny HTTP server on loopback (or a Unix socket) with three endpoints:
//!
//! * `/metrics` — Prometheus text format.
//! * `/healthz` — liveness: the process is running and its event loop responds.
//! * `/readyz`  — readiness: ingress is bound and at least one resolution path or valid
//!   stale capability exists.
//!
//! Liveness and readiness are separate on purpose: a resolver whose upstreams are all down
//! but which is still serving stale data correctly is alive, and taking it out of service
//! would make the outage worse.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;

use crate::runtime::App;

/// Serve the metrics and health endpoints until cancelled.
pub async fn serve(listener: TcpListener, app: Arc<App>, handle: Option<PrometheusHandle>) {
    let cancel = app.cancel.clone();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        let app = Arc::clone(&app);
        let handle = handle.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let app = Arc::clone(&app);
                let handle = handle.clone();
                async move { Ok::<_, Infallible>(route(&req, &app, handle.as_ref())) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

/// Route one request.
pub fn route(
    request: &Request<hyper::body::Incoming>,
    app: &Arc<App>,
    handle: Option<&PrometheusHandle>,
) -> Response<Full<Bytes>> {
    match request.uri().path() {
        "/metrics" => match handle {
            Some(h) => {
                h.run_upkeep();
                text(StatusCode::OK, h.render())
            }
            None => text(
                StatusCode::SERVICE_UNAVAILABLE,
                "metrics recorder is not installed\n".to_string(),
            ),
        },
        "/healthz" => text(StatusCode::OK, "ok\n".to_string()),
        "/readyz" => {
            if app.is_ready() {
                text(StatusCode::OK, "ready\n".to_string())
            } else {
                text(StatusCode::SERVICE_UNAVAILABLE, "not ready\n".to_string())
            }
        }
        "/" => text(
            StatusCode::OK,
            format!(
                "{} {}\nendpoints: /metrics /healthz /readyz\n",
                crate::PRODUCT,
                crate::VERSION
            ),
        ),
        _ => text(StatusCode::NOT_FOUND, "not found\n".to_string()),
    }
}

fn text(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"error"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const MINIMAL: &str = r#"
upstreams = ["9.9.9.9"]
proxies = []

[server]
udp_listen = ["127.0.0.1:0"]
tcp_listen = ["127.0.0.1:0"]
allow_from = ["127.0.0.0/8"]

[storage]
enabled = false

[metrics]
enabled = false

[admin]
enabled = false

[probe]
enabled = false
"#;

    fn build(dir: &tempfile::TempDir) -> (Arc<App>, PathBuf) {
        let path = dir.path().join("egressdns.toml");
        std::fs::write(&path, MINIMAL).expect("write");
        (App::build(&path).expect("build"), path)
    }

    #[tokio::test]
    async fn readiness_is_independent_of_liveness() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = build(&dir);
        assert!(!app.is_ready());
        app.set_ready(true);
        assert!(app.is_ready());
        app.set_ready(false);
        assert!(!app.is_ready());
    }

    #[test]
    fn text_response_has_no_store_cache_control() {
        let r = text(StatusCode::OK, "hello".into());
        assert_eq!(
            r.headers()
                .get(hyper::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
}
