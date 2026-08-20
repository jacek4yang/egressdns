//! The administration socket server.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::admin::{parse_request, Request, Response};
use crate::config::{CloudflareMode, Config};
use crate::error::AdminError;
use crate::probe::job::ProbeJob;
use crate::runtime::App;

/// Bind the administration socket, replacing a stale socket file if present.
pub fn bind(path: &Path, mode: u32) -> Result<UnixListener, AdminError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A leftover socket from a crashed process would otherwise make binding fail.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)?;
    Ok(listener)
}

/// Serve administration requests until cancelled.
pub async fn serve(listener: UnixListener, app: Arc<App>) {
    let cancel = app.cancel.clone();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        let Ok((stream, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            let _ = handle_connection(stream, app).await;
        });
    }
}

async fn handle_connection(stream: UnixStream, app: Arc<App>) -> Result<(), AdminError> {
    let max_bytes = app.config().admin.max_request_bytes;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match parse_request(&line, max_bytes) {
            Ok(request) => dispatch(&app, &request).await,
            Err(e) => Response::err(e.to_string()),
        };
        let mut text = serde_json::to_string(&response)
            .unwrap_or_else(|_| r#"{"ok":false,"error":"serialisation failed"}"#.to_string());
        text.push('\n');
        writer.write_all(text.as_bytes()).await?;
        writer.flush().await?;
    }
    Ok(())
}

/// Execute one command.
pub async fn dispatch(app: &Arc<App>, request: &Request) -> Response {
    match request.command.as_str() {
        "status" => Response::ok(status(app)),
        "check-config" => match Config::load(&app.config_path) {
            Ok(_) => Response::ok(json!({
                "valid": true,
                "path": app.config_path.display().to_string(),
            })),
            Err(e) => Response::err(e.to_string()),
        },
        "reload" => match app.reload() {
            Ok(()) => Response::ok(json!({"reloaded": true, "count": app.reload_count()})),
            Err(e) => Response::err(e),
        },
        "upstreams" => Response::ok(upstreams(app)),
        "network" => Response::ok(network(app)),
        "cache-stats" => Response::ok(cache_stats(app)),
        "flush-name" => match request.args.first() {
            None => Response::err("flush-name requires a domain name"),
            Some(name) => {
                if request.args.get(1).map(|s| s.as_str()) == Some("--suffix") {
                    app.cache.flush_suffix(name);
                } else {
                    app.cache.flush_name(name);
                }
                app.cache.run_maintenance();
                Response::ok(json!({"flushed": name}))
            }
        },
        "flush-all" => {
            app.cache.flush_all();
            app.cache.run_maintenance();
            Response::ok(json!({"flushed": "all"}))
        }
        "cloudflare" => cloudflare(app, &request.args),
        "dump-effective-config" => Response::ok(json!({"toml": app.config().to_redacted_toml()})),
        other => Response::err(format!("unknown command `{other}`")),
    }
}

fn status(app: &Arc<App>) -> serde_json::Value {
    let config = app.config();
    let stats = app.cache.stats();
    let network = app.network.load();
    json!({
        "product": crate::PRODUCT,
        "version": crate::VERSION,
        "ready": app.is_ready(),
        "started_unix": app.started_unix,
        "uptime_seconds": crate::util::time::SystemClock
            .unix_secs_now()
            .saturating_sub(app.started_unix),
        "config_path": app.config_path.display().to_string(),
        "reloads": app.reload_count(),
        "last_reload_error": app.last_reload_error(),
        "listeners": {
            "udp": config.server.udp_listen.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "tcp": config.server.tcp_listen.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        },
        "cache": {
            "answers": stats.answer_entries,
            "bytes": stats.answer_bytes,
            "failures": stats.failure_entries,
            "variants": stats.variant_entries,
        },
        "network_generation": network.generation,
        "ipv4": network.v4.label(),
        "ipv6": network.v6.label(),
        "dnssec": format!("{:?}", config.dnssec.mode),
        "cloudflare": if config.cloudflare.enabled {
            config.cloudflare.mode.label()
        } else {
            "disabled"
        },
        "probe_enabled": config.probe.enabled,
        "probe_healthy": app.probe_healthy(),
        "probe_queue_depth": app.probes.depth(),
        "storage_healthy": app.storage.is_healthy(),
        "storage_dropped_batches": app.storage.dropped(),
        "prefetch_enabled": app.prefetch.is_enabled(),
        "prefetch_issued": app.prefetch.issued(),
        "quality_series": app.quality.len(),
        "hot_names": app.hotset.len(),
    })
}

fn upstreams(app: &Arc<App>) -> serde_json::Value {
    let state = app.state();
    let mut groups = Vec::new();
    for name in state.registry.group_names() {
        let Some(group) = state.registry.group(&name) else {
            continue;
        };
        let routes: Vec<serde_json::Value> = group
            .routes
            .iter()
            .map(|route| {
                let h = route.health();
                json!({
                    "server": route.key.server.to_string(),
                    "transport": route.key.transport.label(),
                    "address": route.key.addr.to_string(),
                    "path": route.key.path.to_string(),
                    "authority": route.key.authority.to_string(),
                    // `local_forwarder` here is the answer to "why did my NXDOMAIN not
                    // get corroborated?" — a forwarder is a source, not a second opinion.
                    "role": route.key.role.label(),
                    "circuit": h.circuit().label(),
                    "samples": h.samples(),
                    "consecutive_failures": h.consecutive_failures(),
                    "success_probability": h.success_probability(),
                    "timeout_probability": h.timeout_probability(),
                    "servfail_probability": h.server_failure_probability(),
                    "malformed_probability": h.malformed_probability(),
                    "ewma_ms": h.ewma_ms(),
                    "p50_ms": h.p50_ms(),
                    "p95_ms": h.p95_ms(),
                    "p99_ms": h.p99_ms(),
                    "jitter_ms": h.jitter_ms(),
                    "connect_cost_ms": h.connect_cost_ms(),
                    "score": h.score(route.weight),
                    "cookies": route.cookies_enabled,
                })
            })
            .collect();
        groups.push(json!({
            "name": name.to_string(),
            "hedge_rate": state.scheduler.budget(&name).rate(),
            "routes": routes,
        }));
    }
    json!({ "groups": groups })
}

fn network(app: &Arc<App>) -> serde_json::Value {
    let snapshot = app.network.load();
    json!({
        "generation": snapshot.generation,
        "published_unix": snapshot.published_unix,
        "ipv4": snapshot.v4.label(),
        "ipv6": snapshot.v6.label(),
        "default_interface_v4": snapshot.raw.default_iface_v4,
        "default_interface_v6": snapshot.raw.default_iface_v6,
        "gateway_v4": snapshot.raw.gateway_v4.map(|g| g.to_string()),
        "gateway_v6": snapshot.raw.gateway_v6.map(|g| g.to_string()),
        "source_v4": snapshot.raw.source_v4.map(|g| g.to_string()),
        "source_v6": snapshot.raw.source_v6.map(|g| g.to_string()),
        "global_addresses": snapshot.raw.global_addresses,
    })
}

fn cache_stats(app: &Arc<App>) -> serde_json::Value {
    let stats = app.cache.stats();
    let hot: Vec<serde_json::Value> = app
        .hotset
        .top(20)
        .into_iter()
        .map(|(key, entry)| {
            json!({
                "name": key.name.to_string(),
                "qtype": key.qtype.to_string(),
                "hits": entry.hits,
                "score": entry.score,
            })
        })
        .collect();
    json!({
        "answers": stats.answer_entries,
        "bytes": stats.answer_bytes,
        "failures": stats.failure_entries,
        "variants": stats.variant_entries,
        "hot": hot,
    })
}

fn cloudflare(app: &Arc<App>, args: &[String]) -> Response {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if !super::CLOUDFLARE_SUBCOMMANDS.contains(&sub) {
        return Response::err(format!("unknown cloudflare sub-command `{sub}`"));
    }
    let config = app.config();
    if !config.cloudflare.enabled {
        return Response::ok(json!({"enabled": false}));
    }
    match sub {
        "status" => {
            let snapshot = app.cloudflare.prefixes();
            let (v4, v6) = app.cloudflare.pool().counts();
            let prefixes = snapshot.as_ref().as_ref();
            Response::ok(json!({
                "enabled": true,
                "mode": app.cloudflare.mode().label(),
                "configured_mode": app.cloudflare.configured_mode().label(),
                "mode_override": app.cloudflare.mode_override().map(|m| m.label()),
                "prefix_source": prefixes.map(|s| s.source.label()),
                "prefix_fetched_unix": prefixes.map(|s| s.fetched_unix),
                "ipv4_prefixes": prefixes.map(|s| s.ipv4().len()).unwrap_or(0),
                "ipv6_prefixes": prefixes.map(|s| s.ipv6().len()).unwrap_or(0),
                "candidates_v4": v4,
                "candidates_v6": v6,
                "validations": app.cloudflare.validation_count(),
                "sampler_round": app.cloudflare.sampler().round(),
                "probe_healthy": app.probe_healthy(),
            }))
        }
        "sources" => {
            let sources: Vec<serde_json::Value> = app
                .cloudflare
                .sources()
                .into_iter()
                .map(|s| {
                    json!({
                        "name": s.name.to_string(),
                        "ok": s.ok,
                        "detail": s.detail,
                        "attempted_unix": s.attempted_unix,
                        "succeeded_unix": s.succeeded_unix,
                        "accepted": s.accepted,
                        "rejected": s.rejected,
                    })
                })
                .collect();
            Response::ok(json!({"sources": sources}))
        }
        "candidates" => {
            let mut out = Vec::new();
            for ipv4 in [true, false] {
                for c in app.cloudflare.pool().list(ipv4) {
                    out.push(json!({
                        "address": c.addr.to_string(),
                        "origin": c.origin.label(),
                        "stage": c.stage.label(),
                        "successes": c.consecutive_successes,
                        "generation": c.generation,
                        "colo": c.colo,
                    }));
                }
            }
            out.truncate(500);
            Response::ok(json!({"candidates": out}))
        }
        "scan-now" => {
            let snapshot = app.cloudflare.prefixes();
            let Some(prefixes) = snapshot.as_ref().as_ref() else {
                return Response::err("no official prefix snapshot is loaded yet");
            };
            let generation = app.network.generation();
            let now = tokio::time::Instant::now();
            let mut queued = 0usize;
            for addr in app
                .cloudflare
                .sampler()
                .next_round(prefixes, config.cloudflare.sampling.addresses_per_round)
            {
                let ip = std::net::IpAddr::V4(addr);
                app.cloudflare.pool().admit(
                    ip,
                    crate::cloudflare::candidates::CandidateOrigin::Sampling,
                    Some(prefixes),
                    generation,
                    now,
                    None,
                );
                if app.probes.offer(ProbeJob::Candidate {
                    addr: ip,
                    port: 443,
                    generation,
                }) {
                    queued += 1;
                }
            }
            Response::ok(json!({"queued": queued}))
        }
        "set-mode" => {
            let Some(raw) = args.get(1) else {
                return Response::err("set-mode requires off|preserve|verified-augment");
            };
            let requested = match raw.as_str() {
                "off" => CloudflareMode::Off,
                "preserve" => CloudflareMode::Preserve,
                "verified-augment" | "verified_augment" => CloudflareMode::VerifiedAugment,
                other => {
                    return Response::err(format!(
                        "unknown mode `{other}`; expected off, preserve or verified-augment"
                    ))
                }
            };
            match app.cloudflare.set_mode_override(requested) {
                Ok(()) => Response::ok(json!({
                    "mode": app.cloudflare.mode().label(),
                    "configured_mode": app.cloudflare.configured_mode().label(),
                    "note": "runtime override; edit the configuration to make it survive a restart",
                })),
                Err(reason) => Response::err(reason),
            }
        }
        "clear-mode-override" => {
            app.cloudflare.clear_mode_override();
            Response::ok(json!({
                "mode": app.cloudflare.mode().label(),
                "configured_mode": app.cloudflare.configured_mode().label(),
            }))
        }
        "verify-domain" => {
            let Some(host) = args.get(1) else {
                return Response::err("verify-domain requires a hostname");
            };
            let generation = app.network.generation();
            let mut queued = 0usize;
            for ipv4 in [true, false] {
                for candidate in app.cloudflare.pool().eligible(ipv4, 1).into_iter().take(4) {
                    if app.probes.offer(ProbeJob::Validate {
                        hostname: Arc::from(host.as_str()),
                        addr: candidate.addr,
                        port: 443,
                        generation,
                    }) {
                        queued += 1;
                    }
                }
            }
            let existing: Vec<serde_json::Value> = app
                .cloudflare
                .pool()
                .list(true)
                .into_iter()
                .filter_map(|c| {
                    app.cloudflare.validation(host, c.addr).map(|v| {
                        json!({
                            "address": c.addr.to_string(),
                            "successes": v.successes,
                            "failures": v.failures,
                            "colo": v.colo,
                        })
                    })
                })
                .collect();
            Response::ok(json!({
                "hostname": host,
                "queued": queued,
                "baseline_validated": app.cloudflare.baseline(host),
                "validations": existing,
            }))
        }
        _ => Response::err("unsupported"),
    }
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

[probe]
enabled = false
"#;

    fn app(dir: &tempfile::TempDir) -> (Arc<App>, PathBuf) {
        let path = dir.path().join("egressdns.toml");
        std::fs::write(&path, MINIMAL).expect("write");
        let app = App::build(&path).expect("build");
        (app, path)
    }

    fn req(command: &str, args: &[&str]) -> Request {
        Request {
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn status_reports_the_essentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = app(&dir);
        let response = dispatch(&app, &req("status", &[])).await;
        assert!(response.ok);
        let data = response.data.expect("data");
        assert_eq!(data["version"], crate::VERSION);
        assert_eq!(data["ready"], false);
        assert!(data["listeners"]["udp"].is_array());
    }

    #[tokio::test]
    async fn check_config_and_reload_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, path) = app(&dir);
        assert!(dispatch(&app, &req("check-config", &[])).await.ok);
        assert!(dispatch(&app, &req("reload", &[])).await.ok);
        std::fs::write(&path, "not toml {{{").expect("write");
        let bad = dispatch(&app, &req("check-config", &[])).await;
        assert!(!bad.ok);
        assert!(bad.error.expect("error").contains("invalid TOML"));
    }

    #[tokio::test]
    async fn flush_commands_are_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = app(&dir);
        assert!(!dispatch(&app, &req("flush-name", &[])).await.ok);
        assert!(
            dispatch(&app, &req("flush-name", &["example.com"]))
                .await
                .ok
        );
        assert!(
            dispatch(&app, &req("flush-name", &["example.com", "--suffix"]))
                .await
                .ok
        );
        assert!(dispatch(&app, &req("flush-all", &[])).await.ok);
    }

    #[tokio::test]
    async fn upstreams_and_network_report_structure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = app(&dir);
        let up = dispatch(&app, &req("upstreams", &[])).await;
        assert!(up.ok);
        let groups = up.data.expect("data")["groups"].clone();
        assert!(!groups.as_array().expect("array").is_empty());

        let net = dispatch(&app, &req("network", &[])).await;
        assert!(net.ok);
        assert!(net.data.expect("data")["generation"].is_number());
    }

    #[tokio::test]
    async fn cloudflare_reports_disabled_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = app(&dir);
        let r = dispatch(&app, &req("cloudflare", &["status"])).await;
        assert!(r.ok);
        assert_eq!(r.data.expect("data")["enabled"], false);
        let bad = dispatch(&app, &req("cloudflare", &["nonsense"])).await;
        assert!(!bad.ok);
    }

    #[tokio::test]
    async fn effective_config_is_redacted_and_parses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (app, _) = app(&dir);
        let r = dispatch(&app, &req("dump-effective-config", &[])).await;
        assert!(r.ok);
        let toml_text = r.data.expect("data")["toml"]
            .as_str()
            .expect("string")
            .to_string();
        assert!(!toml_text.is_empty());
        // The dumped configuration must itself be valid.
        Config::from_toml(&toml_text, "<dump>").expect("dump round-trips");
    }

    #[tokio::test]
    async fn socket_permissions_are_restricted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("admin.sock");
        let listener = bind(&path, 0o660).expect("bind");
        let meta = std::fs::metadata(&path).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        drop(listener);
        // Binding again over a stale socket file must succeed.
        let _listener = bind(&path, 0o600).expect("rebind");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
