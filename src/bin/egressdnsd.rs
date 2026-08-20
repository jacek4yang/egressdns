//! `egressdnsd` — the EgressDNS daemon.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use egressdns::config::Config;
use egressdns::dns::server::{self, Ingress};
use egressdns::runtime::App;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "egressdnsd",
    version,
    about = "Adaptive, highly available DNS caching forwarder",
    long_about = None
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        env = "EGRESSDNS_CONFIG",
        default_value = "/etc/egressdns/config.toml"
    )]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check_config: bool,

    /// Print the effective configuration with secrets redacted and exit.
    #[arg(long)]
    dump_config: bool,

    /// Override the log filter, for example `info,egressdns::upstream=debug`.
    #[arg(long, env = "EGRESSDNS_LOG")]
    log: Option<String>,

    /// Emit newline-delimited JSON logs.
    #[arg(long)]
    json_logs: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("egressdnsd: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    // The configuration is parsed before the runtime starts so that a bad file is a fast,
    // obvious failure rather than a half-started daemon.
    let config =
        Config::load(&cli.config).with_context(|| format!("loading {}", cli.config.display()))?;

    init_logging(&config, &cli);

    if cli.check_config {
        println!("configuration at {} is valid", cli.config.display());
        return Ok(ExitCode::SUCCESS);
    }
    if cli.dump_config {
        print!("{}", config.to_redacted_toml());
        return Ok(ExitCode::SUCCESS);
    }

    let workers = config.resources.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(config.resources.max_blocking_threads)
        .enable_all()
        .thread_name("egressdns")
        .build()
        .context("building the async runtime")?;

    runtime.block_on(async move {
        let config = bootstrap(config).await?;
        serve(cli, Arc::new(config)).await
    })
}

/// Turn `upstreams = ["auto"]` into the resolvers this host should actually use.
///
/// Runs before bootstrap, so everything it produces goes through the same validation,
/// cycle detection and address resolution as a hand-written list. If nothing usable is
/// found the entry is left alone and configuration validation reports it, rather than the
/// resolver starting with no routes and reporting itself healthy.
async fn expand_auto(config: Config) -> Config {
    use egressdns::config::{auto, autoprobe};

    if !config.upstreams.iter().any(|u| u.trim() == "auto") {
        return config;
    }

    let listeners: Vec<std::net::SocketAddr> = config
        .server
        .udp_listen
        .iter()
        .chain(config.server.tcp_listen.iter())
        .copied()
        .collect();

    let instance: u64 = rand::random();
    let (gateway, region) = tokio::join!(
        autoprobe::probe_gateway(&listeners, instance),
        autoprobe::detect_region()
    );

    match &gateway {
        auto::GatewayProbe::Usable { addr, udp, tcp } => {
            tracing::info!(
                event = "auto.gateway_adopted",
                address = %addr,
                udp = udp,
                tcp = tcp,
                role = auto::ResolverRole::LocalForwarder.label(),
                "using the local gateway as a fast source; it is not an independent authority"
            );
        }
        auto::GatewayProbe::Rejected(why) => {
            tracing::info!(event = "auto.gateway_rejected", reason = why.reason(),);
        }
    }
    tracing::info!(event = "auto.region", region = ?region);

    let expanded = auto::expand(&gateway, region);
    tracing::info!(
        event = "auto.expanded",
        sources = expanded.len(),
        entries = %expanded.join(", "),
    );

    let mut config = config;
    let mut out: Vec<String> = Vec::new();
    for entry in std::mem::take(&mut config.upstreams) {
        if entry.trim() == "auto" {
            out.extend(expanded.iter().cloned());
        } else {
            out.push(entry);
        }
    }
    config.upstreams = out;
    config.local_forwarder = gateway.address();

    // Rebuild the derived route tree from the expanded list, and mark the route that came
    // from the gateway. The mark is what stops a forwarder being used as a second
    // opinion — it can be the fastest source on the network and still corroborate
    // nothing, because it forwards to somebody, quite possibly whoever we just asked.
    match egressdns::config::endpoint::build_upstreams(&config.upstreams) {
        Ok(mut upstream) => {
            if let Some(addr) = config.local_forwarder {
                for group in &mut upstream.groups {
                    for server in &mut group.servers {
                        if server.addresses.contains(&addr) {
                            server.role = auto::ResolverRole::LocalForwarder;
                        }
                    }
                }
            }
            upstream.tls = config.tls.clone();
            config.upstream = upstream;
        }
        Err(detail) => {
            // Leave the configuration as it was rather than starting with no routes.
            // Validation has already accepted the static `auto` expansion, so this can
            // only mean the measured expansion is malformed — a bug here, not an
            // operator error, and not a reason to take DNS down.
            tracing::error!(event = "auto.expansion_invalid", detail = %detail);
        }
    }
    config
}

fn init_logging(config: &Config, cli: &Cli) {
    let directive = cli
        .log
        .clone()
        .unwrap_or_else(|| config.logging.level.clone());
    let filter = EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"));
    let json = cli.json_logs || config.logging.json;
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json().with_target(true))
            .init();
    } else {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())),
            )
            .init();
    }
}

/// Give named upstreams their addresses, and refuse a configuration that would make the
/// resolver wait on itself.
///
/// Runs before the app is assembled, so the routes exist by the time the listeners bind.
/// It is bounded: a name that cannot be resolved right now leaves its upstream without
/// addresses and is logged, because a resolver with three upstreams and one unreachable
/// name should serve from the other two rather than refuse to start.
async fn bootstrap(config: Config) -> Result<Config> {
    use egressdns::upstream::bootstrap as boot;

    let config = expand_auto(config).await;

    let cycles = boot::detect_cycles(&config);
    if !cycles.is_empty() {
        // Refused before any I/O. A resolver configured to bootstrap through itself
        // would otherwise hang at startup with nothing in the log to explain it.
        for cycle in &cycles {
            tracing::error!(event = "bootstrap.cycle", path = %cycle);
        }
        anyhow::bail!(
            "the upstream configuration depends on this resolver: {}",
            cycles
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    let mut config = config;
    let report = boot::resolve_pending(&mut config).await;
    for (host, addrs) in &report.resolved {
        tracing::info!(
            event = "bootstrap.resolved",
            host = %host,
            addresses = addrs.len(),
        );
    }
    for (host, reason) in &report.failed {
        tracing::warn!(
            event = "bootstrap.failed",
            host = %host,
            reason = %reason,
            "this upstream is unusable until its name resolves",
        );
    }
    Ok(config)
}

async fn serve(cli: Cli, config: Arc<Config>) -> Result<ExitCode> {
    let metrics_handle = if config.metrics.enabled {
        egressdns::metrics::install()
    } else {
        None
    };
    egressdns::metrics::record_build_info();
    metrics::gauge!(egressdns::metrics::names::START_TIME_SECONDS)
        .set(egressdns::util::time::SystemClock.unix_secs_now() as f64);

    let app = App::from_config(Arc::clone(&config), cli.config.clone())
        .context("assembling the process")?;

    tracing::info!(
        event = "startup",
        version = egressdns::VERSION,
        config = %cli.config.display(),
        "starting"
    );

    // ---- ingress -------------------------------------------------------------------
    let ingress = Ingress::new(Arc::clone(&app));
    let mut bound_udp = 0usize;
    let mut bound_tcp = 0usize;

    for addr in &config.server.udp_listen {
        let workers = if config.server.udp.reuse_port {
            config.server.udp.workers_per_socket
        } else {
            1
        };
        for _ in 0..workers {
            let socket = server::bind_udp(*addr, &config.server.udp)
                .with_context(|| format!("binding UDP {addr}"))?;
            let actual = socket.local_addr().ok();
            tracing::info!(event = "listener.udp", address = ?actual);
            let socket = Arc::new(socket);
            let ingress = Arc::clone(&ingress);
            tokio::spawn(server::serve_udp(socket, ingress));
            bound_udp += 1;
        }
    }

    for addr in &config.server.tcp_listen {
        let listener = server::bind_tcp(*addr, &config.server.tcp)
            .with_context(|| format!("binding TCP {addr}"))?;
        tracing::info!(event = "listener.tcp", address = ?listener.local_addr().ok());
        let ingress = Arc::clone(&ingress);
        tokio::spawn(server::serve_tcp(listener, ingress));
        bound_tcp += 1;
    }

    if bound_udp == 0 && bound_tcp == 0 {
        anyhow::bail!("no listener could be bound");
    }

    // ---- administration socket -------------------------------------------------------
    if config.admin.enabled {
        match egressdns::admin::server::bind(&config.admin.socket, config.admin.socket_mode) {
            Ok(listener) => {
                tracing::info!(
                    event = "listener.admin",
                    path = %config.admin.socket.display()
                );
                tokio::spawn(egressdns::admin::server::serve(listener, Arc::clone(&app)));
            }
            Err(e) => {
                // The administration socket is convenience, not correctness.
                tracing::warn!(event = "admin.bind_failed", error = %e);
            }
        }
    }

    // ---- metrics and health ----------------------------------------------------------
    if config.metrics.enabled {
        match tokio::net::TcpListener::bind(config.metrics.listen).await {
            Ok(listener) => {
                tracing::info!(event = "listener.metrics", address = %config.metrics.listen);
                tokio::spawn(egressdns::runtime::observe::serve(
                    listener,
                    Arc::clone(&app),
                    metrics_handle,
                ));
            }
            Err(e) => {
                tracing::warn!(event = "metrics.bind_failed", error = %e);
            }
        }
    }

    app.spawn_background();
    app.set_ready(true);
    notify_systemd_ready();
    let watchdog = spawn_watchdog(&config, Arc::clone(&app));

    tracing::info!(
        event = "ready",
        udp_listeners = bound_udp,
        tcp_listeners = bound_tcp,
        "serving"
    );

    // ---- signals ---------------------------------------------------------------------
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing the SIGHUP handler")?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                tracing::info!(event = "reload.requested");
                match app.reload() {
                    Ok(()) => tracing::info!(event = "reload.applied"),
                    Err(e) => tracing::error!(
                        event = "reload.rejected",
                        error = %e,
                        "keeping the running configuration"
                    ),
                }
            }
            _ = sigterm.recv() => {
                tracing::info!(event = "shutdown.requested", signal = "SIGTERM");
                break;
            }
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    tracing::info!(event = "shutdown.requested", signal = "SIGINT");
                }
                break;
            }
        }
    }

    // ---- graceful shutdown -----------------------------------------------------------
    notify_systemd_stopping();
    app.set_ready(false);
    if let Some(handle) = watchdog {
        handle.abort();
    }

    // Cancel the control plane and actually *wait* for it. Sleeping for a fixed moment
    // and exiting was not a graceful shutdown: a background task could still be opening a
    // socket, holding a probe connection or writing to the state database as the process
    // called `exit`, which is how a half-written database survives a restart.
    let aborted = app.shutdown_and_join(SHUTDOWN_DEADLINE).await;
    if aborted > 0 {
        tracing::warn!(
            event = "shutdown.tasks_aborted",
            tasks = aborted,
            deadline_secs = SHUTDOWN_DEADLINE.as_secs(),
            "some background tasks did not stop within the deadline and were aborted"
        );
    }

    // `shutdown_and_join` already flushed the storage queue.
    if config.admin.enabled {
        let _ = std::fs::remove_file(&config.admin.socket);
    }
    tracing::info!(
        event = "shutdown.complete",
        tasks_aborted = aborted,
        clean = aborted == 0,
    );
    Ok(ExitCode::SUCCESS)
}

/// How long graceful shutdown waits for background tasks before aborting them.
///
/// systemd's default `TimeoutStopSec` is 90 s; staying well inside it means the unit is
/// stopped by our own bounded wait rather than by `SIGKILL`.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

fn spawn_watchdog(config: &Config, app: Arc<App>) -> Option<tokio::task::JoinHandle<()>> {
    if !config.resources.systemd_watchdog {
        return None;
    }
    let interval = sd_notify::watchdog_enabled()?;
    // Feed the watchdog at twice the required rate so a single late tick is harmless.
    let period = (interval / 2).max(Duration::from_secs(1));
    tracing::info!(
        event = "watchdog.enabled",
        period_ms = period.as_millis() as u64
    );
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = app.cancel.cancelled() => return,
                _ = tokio::time::sleep(period) => {}
            }
            // Only keep the watchdog fed while the daemon is actually able to serve.
            if app.is_ready() {
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
            }
        }
    }))
}

fn notify_systemd_ready() {
    let _ = sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("serving DNS"),
    ]);
}

fn notify_systemd_stopping() {
    let _ = sd_notify::notify(&[
        sd_notify::NotifyState::Stopping,
        sd_notify::NotifyState::Status("shutting down"),
    ]);
}
