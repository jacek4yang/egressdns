//! `egressdnsctl` — local administration for a running `egressdnsd`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use egressdns::admin::client;
use egressdns::admin::Response;
use serde_json::Value;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "egressdnsctl",
    version,
    about = "Control and inspect a running EgressDNS daemon"
)]
struct Cli {
    /// Administration socket path.
    #[arg(
        short,
        long,
        env = "EGRESSDNS_ADMIN_SOCKET",
        default_value = "/run/egressdns/admin.sock"
    )]
    socket: PathBuf,

    /// Configuration file, used by `check-config` when the daemon is not running.
    #[arg(
        short,
        long,
        env = "EGRESSDNS_CONFIG",
        default_value = "/etc/egressdns/config.toml"
    )]
    config: PathBuf,

    /// Emit raw JSON instead of a human-readable summary.
    #[arg(long)]
    json: bool,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    #[command(subcommand)]
    command: Command,
}

/// Supported commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon status.
    Status,
    /// Validate the configuration file.
    CheckConfig,
    /// Reload the configuration atomically.
    Reload,
    /// List every setting that cannot be changed by reload, and why.
    ///
    /// Answered locally without contacting the daemon: an operator planning a change
    /// needs this before deciding between `systemctl reload` and `systemctl restart`.
    ReloadContract,
    /// Show upstream routes and their health.
    Upstreams,
    /// Show IPv4/IPv6 environment state and the network generation.
    Network,
    /// Show cache statistics and the hottest names.
    CacheStats,
    /// Remove one name from every cache.
    FlushName {
        /// The name to remove.
        name: String,
        /// Remove the whole subtree beneath the name as well.
        #[arg(long)]
        suffix: bool,
    },
    /// Empty every cache.
    FlushAll,
    /// Cloudflare optimization commands.
    #[command(subcommand)]
    Cloudflare(CloudflareCommand),
    /// Print the effective configuration with secrets redacted.
    DumpEffectiveConfig,
}

/// Cloudflare sub-commands.
#[derive(Debug, Subcommand)]
enum CloudflareCommand {
    /// Show optimization status.
    Status,
    /// Show data-source health.
    Sources,
    /// List candidate addresses.
    Candidates,
    /// Run one sampling round immediately.
    ScanNow,
    /// Queue domain-level validation for a hostname.
    VerifyDomain {
        /// The hostname to validate.
        hostname: String,
    },
    /// Weaken the optimization mode at runtime, without a restart or a config change.
    ///
    /// The override takes effect on the next query and does not survive a restart. It may
    /// only weaken the configured mode: strengthening it is a configuration change, so it
    /// goes through validation and stays reviewable.
    SetMode {
        /// `off`, `preserve` or `verified-augment`.
        mode: String,
    },
    /// Drop a runtime mode override and return to the configured mode.
    ClearModeOverride,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("egressdnsctl: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("egressdnsctl: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    // `check-config` is answered locally when the daemon is not reachable, so an operator
    // can validate a file before starting anything.
    if matches!(cli.command, Command::ReloadContract) {
        let items = egressdns::config::reload::catalog();
        println!(
            "{} settings require a restart; everything else applies on reload.\n",
            items.len()
        );
        for item in &items {
            println!("{}\n    {}\n", item.field, item.reason);
        }
        return Ok(ExitCode::SUCCESS);
    }

    if matches!(cli.command, Command::CheckConfig) && !cli.socket.exists() {
        return match egressdns::config::Config::load(&cli.config) {
            Ok(_) => {
                println!("configuration at {} is valid", cli.config.display());
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("{e}");
                Ok(ExitCode::from(2))
            }
        };
    }

    let (command, args) = encode(&cli.command);
    let response = client::send(
        &cli.socket,
        &command,
        &args,
        Duration::from_secs(cli.timeout.clamp(1, 300)),
    )
    .await
    .with_context(|| format!("talking to {}", cli.socket.display()))?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        render(&cli.command, &response);
    }
    Ok(if response.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn encode(command: &Command) -> (String, Vec<String>) {
    match command {
        Command::Status => ("status".into(), vec![]),
        Command::CheckConfig => ("check-config".into(), vec![]),
        // Answered locally before this point is reached; never sent to the daemon.
        Command::ReloadContract => ("reload-contract".into(), vec![]),
        Command::Reload => ("reload".into(), vec![]),
        Command::Upstreams => ("upstreams".into(), vec![]),
        Command::Network => ("network".into(), vec![]),
        Command::CacheStats => ("cache-stats".into(), vec![]),
        Command::FlushName { name, suffix } => {
            let mut args = vec![name.clone()];
            if *suffix {
                args.push("--suffix".into());
            }
            ("flush-name".into(), args)
        }
        Command::FlushAll => ("flush-all".into(), vec![]),
        Command::DumpEffectiveConfig => ("dump-effective-config".into(), vec![]),
        Command::Cloudflare(sub) => {
            let mut args = vec![match sub {
                CloudflareCommand::Status => "status".to_string(),
                CloudflareCommand::Sources => "sources".to_string(),
                CloudflareCommand::Candidates => "candidates".to_string(),
                CloudflareCommand::ScanNow => "scan-now".to_string(),
                CloudflareCommand::VerifyDomain { .. } => "verify-domain".to_string(),
                CloudflareCommand::SetMode { .. } => "set-mode".to_string(),
                CloudflareCommand::ClearModeOverride => "clear-mode-override".to_string(),
            }];
            match sub {
                CloudflareCommand::VerifyDomain { hostname } => args.push(hostname.clone()),
                CloudflareCommand::SetMode { mode } => args.push(mode.clone()),
                _ => {}
            }
            ("cloudflare".into(), args)
        }
    }
}

fn render(command: &Command, response: &Response) {
    if !response.ok {
        eprintln!(
            "error: {}",
            response.error.as_deref().unwrap_or("unknown failure")
        );
        return;
    }
    let Some(data) = response.data.as_ref() else {
        println!("ok");
        return;
    };
    match command {
        Command::DumpEffectiveConfig => {
            if let Some(text) = data.get("toml").and_then(|v| v.as_str()) {
                print!("{text}");
            }
        }
        Command::Upstreams => render_upstreams(data),
        Command::CacheStats => render_cache(data),
        Command::Cloudflare(CloudflareCommand::Sources) => render_sources(data),
        Command::Cloudflare(CloudflareCommand::Candidates) => render_candidates(data),
        _ => render_flat(data),
    }
}

fn render_flat(data: &Value) {
    let Some(map) = data.as_object() else {
        println!("{data}");
        return;
    };
    let width = map.keys().map(|k| k.len()).max().unwrap_or(0);
    for (key, value) in map {
        println!("{key:<width$}  {}", scalar(value), width = width);
    }
}

fn render_upstreams(data: &Value) {
    let Some(groups) = data.get("groups").and_then(|v| v.as_array()) else {
        return;
    };
    for group in groups {
        println!(
            "group {}  (hedge rate {:.3})",
            group.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
            group
                .get("hedge_rate")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
        );
        println!(
            "  {:<20} {:<7} {:<40} {:<10} {:>8} {:>9} {:>9} {:>7}",
            "SERVER", "PROTO", "ADDRESS", "CIRCUIT", "EWMA_MS", "P95_MS", "SUCCESS", "SAMPLES"
        );
        let empty = Vec::new();
        for route in group
            .get("routes")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty)
        {
            println!(
                "  {:<20} {:<7} {:<40} {:<10} {:>8.1} {:>9.1} {:>8.1}% {:>7}",
                truncate(
                    route.get("server").and_then(|v| v.as_str()).unwrap_or("?"),
                    20
                ),
                route
                    .get("transport")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                truncate(
                    route.get("address").and_then(|v| v.as_str()).unwrap_or("?"),
                    40
                ),
                route.get("circuit").and_then(|v| v.as_str()).unwrap_or("?"),
                route.get("ewma_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
                route.get("p95_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
                route
                    .get("success_probability")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    * 100.0,
                route.get("samples").and_then(|v| v.as_u64()).unwrap_or(0),
            );
        }
    }
}

fn render_cache(data: &Value) {
    println!(
        "answers  {}\nbytes    {}\nfailures {}\nvariants {}",
        data.get("answers").and_then(|v| v.as_u64()).unwrap_or(0),
        data.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
        data.get("failures").and_then(|v| v.as_u64()).unwrap_or(0),
        data.get("variants").and_then(|v| v.as_u64()).unwrap_or(0),
    );
    let empty = Vec::new();
    let hot = data.get("hot").and_then(|v| v.as_array()).unwrap_or(&empty);
    if !hot.is_empty() {
        println!("\nhottest names:");
        for entry in hot {
            println!(
                "  {:<50} {:<6} hits={} score={:.2}",
                truncate(
                    entry.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    50
                ),
                entry.get("qtype").and_then(|v| v.as_str()).unwrap_or("?"),
                entry.get("hits").and_then(|v| v.as_u64()).unwrap_or(0),
                entry.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0),
            );
        }
    }
}

fn render_sources(data: &Value) {
    let empty = Vec::new();
    let sources = data
        .get("sources")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    println!(
        "{:<24} {:<6} {:>9} {:>9}  DETAIL",
        "SOURCE", "OK", "ACCEPTED", "REJECTED"
    );
    for s in sources {
        println!(
            "{:<24} {:<6} {:>9} {:>9}  {}",
            truncate(s.get("name").and_then(|v| v.as_str()).unwrap_or("?"), 24),
            s.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
            s.get("accepted").and_then(|v| v.as_u64()).unwrap_or(0),
            s.get("rejected").and_then(|v| v.as_u64()).unwrap_or(0),
            truncate(s.get("detail").and_then(|v| v.as_str()).unwrap_or(""), 60),
        );
    }
}

fn render_candidates(data: &Value) {
    let empty = Vec::new();
    let items = data
        .get("candidates")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    println!(
        "{:<42} {:<12} {:<9} {:>9}  COLO",
        "ADDRESS", "ORIGIN", "STAGE", "SUCCESSES"
    );
    for c in items {
        println!(
            "{:<42} {:<12} {:<9} {:>9}  {}",
            truncate(c.get("address").and_then(|v| v.as_str()).unwrap_or("?"), 42),
            c.get("origin").and_then(|v| v.as_str()).unwrap_or("?"),
            c.get("stage").and_then(|v| v.as_str()).unwrap_or("?"),
            c.get("successes").and_then(|v| v.as_u64()).unwrap_or(0),
            c.get("colo").and_then(|v| v.as_str()).unwrap_or("-"),
        );
    }
    println!("\n{} candidates", items.len());
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(scalar).collect::<Vec<_>>().join(", "),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".into()),
        other => other.to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
