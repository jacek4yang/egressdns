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
use tokio::sync::watch;
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
        default_value = egressdns::platform::DEFAULT_CONFIG_PATH
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

    /// Run under the Windows service control manager.
    ///
    /// Not useful interactively: the process connects to the service controller, which
    /// only exists for a process the service manager started. Installed as
    /// `egressdnsd.exe --service --config <path>`.
    #[cfg(windows)]
    #[arg(long)]
    service: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    #[cfg(windows)]
    if cli.service {
        return match service::dispatch() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("egressdnsd: cannot run as a Windows service: {e:#}");
                eprintln!(
                    "egressdnsd: this mode exists for the service control manager; \
                     run without --service to use the console"
                );
                ExitCode::from(1)
            }
        };
    }

    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("egressdnsd: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    run_daemon(cli, None)
}

/// Load, validate and serve, shared by console mode and the Windows service dispatcher.
///
/// `stop` is the service-control-manager stop request on Windows; it is `None` in console
/// mode, where shutdown comes from the console signal handlers instead.
fn run_daemon(cli: Cli, stop: Option<watch::Receiver<bool>>) -> Result<ExitCode> {
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
        serve(cli, Arc::new(config), stop).await
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

async fn serve(
    cli: Cli,
    config: Arc<Config>,
    mut stop: Option<watch::Receiver<bool>>,
) -> Result<ExitCode> {
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
    write_pidfile(&config);
    let watchdog = spawn_watchdog(&config, Arc::clone(&app));

    tracing::info!(
        event = "ready",
        udp_listeners = bound_udp,
        tcp_listeners = bound_tcp,
        "serving"
    );

    // ---- signals ---------------------------------------------------------------------
    // Unix has SIGHUP for reload and SIGTERM for shutdown. Windows has neither; there the
    // console handler reports Ctrl+C, and an installed service reports stop through the
    // service control manager via `stop`. Reload on Windows is `egressdnsctl reload`.
    #[cfg(unix)]
    {
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
                _ = stop_requested(&mut stop) => {
                    tracing::info!(event = "shutdown.requested", source = "service-control");
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
    }
    #[cfg(not(unix))]
    {
        // No reload signal on Windows: both events end the process, so a single select
        // suffices. `stop_requested` never resolves in console mode, where only Ctrl+C
        // (or closing the console) shuts the daemon down.
        tokio::select! {
            _ = stop_requested(&mut stop) => {
                tracing::info!(event = "shutdown.requested", source = "service-control");
            }
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    tracing::info!(event = "shutdown.requested", signal = "CTRL_C");
                }
            }
        }
    }

    // ---- graceful shutdown -----------------------------------------------------------
    notify_systemd_stopping();
    remove_pidfile(&config);
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
/// stopped by our own bounded wait rather than by `SIGKILL`. The Windows service is
/// registered with a matching stop timeout.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// Resolve when the service control manager asks the daemon to stop.
///
/// In console mode `stop` is `None` and this future never resolves, so it costs a branch
/// and nothing else.
async fn stop_requested(stop: &mut Option<watch::Receiver<bool>>) {
    match stop {
        Some(rx) => {
            if *rx.borrow() {
                return;
            }
            // `changed` returning Err means the sender is gone, which can only be the
            // service dispatcher ending; treat it as a stop request rather than spinning.
            let _ = rx.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(unix)]
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

#[cfg(not(unix))]
fn spawn_watchdog(_config: &Config, _app: Arc<App>) -> Option<tokio::task::JoinHandle<()>> {
    // The systemd watchdog protocol does not exist off Unix; `resources.systemd_watchdog`
    // is accepted and ignored there rather than made a second platform-specific field.
    None
}

#[cfg(unix)]
fn notify_systemd_ready() {
    let _ = sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("serving DNS"),
    ]);
}

#[cfg(not(unix))]
fn notify_systemd_ready() {}

#[cfg(unix)]
fn notify_systemd_stopping() {
    let _ = sd_notify::notify(&[
        sd_notify::NotifyState::Stopping,
        sd_notify::NotifyState::Status("shutting down"),
    ]);
}

#[cfg(not(unix))]
fn notify_systemd_stopping() {}

/// Publish this process id next to the state database, so `doctor` can tell the running
/// EgressDNS apart from a foreign resolver on Windows, where sockets cannot be mapped to
/// process names without elevation.
#[cfg(windows)]
fn write_pidfile(config: &Config) {
    let path = pidfile_path(config);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, format!("{}\n", std::process::id()));
}

#[cfg(not(windows))]
fn write_pidfile(_config: &Config) {}

#[cfg(windows)]
fn remove_pidfile(config: &Config) {
    let _ = std::fs::remove_file(pidfile_path(config));
}

#[cfg(not(windows))]
fn remove_pidfile(_config: &Config) {}

#[cfg(windows)]
fn pidfile_path(config: &Config) -> PathBuf {
    config
        .storage
        .path
        .parent()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(egressdns::platform::state_dir)
        .join("egressdnsd.pid")
}

/// Windows service integration.
///
/// The service controller starts `egressdnsd.exe --service --config <path>`. The
/// dispatcher connects to the SCM, reports progress, and translates the controller's stop
/// request into the same watch channel the console path uses for SIGTERM.
#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::time::Duration;

    use anyhow::Result;
    use clap::Parser as _;
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    /// Registered service name, used by `sc.exe`, `doctor` and the install scripts.
    pub const SERVICE_NAME: &str = "egressdns";

    define_windows_service!(ffi_service_main, service_main);

    /// Hand control to the service control manager. Blocks until the service stops.
    pub fn dispatch() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(arguments: Vec<OsString>) {
        let _ = run_service(arguments);
    }

    fn run_service(arguments: Vec<OsString>) -> Result<()> {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |event| match event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::UserEvent(_) => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        report(
            &status_handle,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            30,
        )?;

        // The SCM passes argv[0] plus the configured binPath arguments, so the service
        // command line parses exactly like the console one.
        let cli = match super::Cli::try_parse_from(&arguments) {
            Ok(cli) => cli,
            Err(e) => {
                eprintln!("egressdnsd: bad service command line: {e}");
                report(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    0,
                )?;
                anyhow::bail!("the service command line is not a valid daemon invocation");
            }
        };

        let outcome = super::run_daemon(cli, Some(stop_rx));

        report(
            &status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
        )?;
        // The exit code is meaningless to the service controller once Stopped is
        // reported; only the error matters.
        outcome.map(|_| ())
    }

    fn report(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        controls: ServiceControlAccept,
        wait_hint_secs: u64,
    ) -> Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(wait_hint_secs.max(1)),
            process_id: None,
        })?;
        Ok(())
    }
}
