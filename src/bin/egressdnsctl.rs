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
    // These four are global so they may be given before or after the subcommand:
    // `egressdnsctl doctor --config FILE` is the documented spelling, and making the
    // operator remember which side of the verb a flag lives on is a papercut.
    /// Administration socket path.
    #[arg(
        short,
        long,
        global = true,
        env = "EGRESSDNS_ADMIN_SOCKET",
        default_value = egressdns::platform::DEFAULT_ADMIN_ENDPOINT
    )]
    socket: PathBuf,

    /// Configuration file, used by `doctor` and by `check-config` when the daemon is not
    /// running.
    #[arg(
        short,
        long,
        global = true,
        env = "EGRESSDNS_CONFIG",
        default_value = egressdns::platform::DEFAULT_CONFIG_PATH
    )]
    config: PathBuf,

    /// Emit raw JSON instead of a human-readable summary.
    #[arg(long, global = true)]
    json: bool,

    /// Request timeout in seconds.
    #[arg(long, global = true, default_value_t = 10)]
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
    /// Diagnose whether this configuration would actually work on this host.
    ///
    /// Answered locally, without the daemon, so it can be run before a cutover. Exits
    /// non-zero when a check finds something that would stop the resolver serving.
    Doctor,
    /// Send one DNS query and report whether the answer is usable.
    ///
    /// Exists so that installation and health checks do not depend on `dig` being
    /// present. It also judges the *answer* rather than the exchange: `dig` exits 0 for
    /// SERVFAIL and REFUSED alike, which is how a resolver that answered nothing once
    /// passed a post-install check.
    Query {
        /// Name to look up.
        name: String,
        /// Record type.
        #[arg(long, default_value = "A")]
        rtype: String,
        /// Resolver to ask.
        #[arg(long, default_value = "127.0.0.1")]
        server: String,
        /// Port.
        #[arg(long, default_value_t = 53)]
        port: u16,
        /// Use TCP instead of UDP.
        #[arg(long)]
        tcp: bool,
        /// Request DNSSEC records and report the AD bit.
        #[arg(long)]
        dnssec: bool,
        /// Require an answer record, not merely NOERROR.
        #[arg(long)]
        require_answer: bool,
        /// Seconds to wait.
        #[arg(long, default_value_t = 5)]
        wait: u64,
    },
    /// Reload the configuration atomically.
    Reload,
    /// List every setting that cannot be changed by reload, and why.
    ///
    /// Answered locally without contacting the daemon: an operator planning a change
    /// needs this before deciding between `systemctl reload` and `systemctl restart`.
    ReloadContract,
    /// List the built-in resolver profiles and what they expand to.
    ///
    /// Answered locally, so `upstreams = ["builtin:recommended"]` can be inspected
    /// before it is deployed: a set of resolvers an operator has not seen is a set of
    /// resolvers an operator cannot audit.
    Builtins {
        /// Show one profile in full, with each provider's endpoints and source.
        profile: Option<String>,
    },
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
    /// Measure real DNS latency against real resolvers.
    ///
    /// Sends actual queries from this host — to `223.5.5.5`, a regional public resolver,
    /// or a running EgressDNS — and reports success rate, useful-answer rate and the
    /// latency distribution per resolver. This is the comparison the product claims to
    /// win; Criterion benchmarks cannot answer it.
    Bench {
        /// Resolvers to compare, as `host[:port]` specs. Repeatable.
        #[arg(long = "server", short = 's', default_values_t = bench_default_servers())]
        servers: Vec<String>,

        /// Extra names to measure, beyond the built-in corpus. Repeatable.
        #[arg(long = "name")]
        names: Vec<String>,

        /// Replace the built-in corpus with a name-per-line file.
        #[arg(long)]
        names_file: Option<PathBuf>,

        /// Cold (first query per name) rounds.
        #[arg(long, default_value_t = 1)]
        cold_rounds: usize,

        /// Warm (repeated query per name) rounds.
        #[arg(long, default_value_t = 5)]
        warm_rounds: usize,

        /// Maximum concurrent queries per server.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Per-query timeout in milliseconds.
        #[arg(long, default_value_t = 3_000)]
        timeout_ms: u64,

        /// Write the full report as JSON to this path. (`--json` is the global
        /// machine-readable rendering switch, so the file output gets its own name.)
        #[arg(long = "json-out")]
        json_out: Option<PathBuf>,
    },
}

/// The default comparison set: the project's reference baseline plus one encrypted
/// independent resolver.
fn bench_default_servers() -> Vec<String> {
    vec![String::from("223.5.5.5"), String::from("1.1.1.1")]
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

/// Print the catalog, either as an index or as one profile in full.
fn run_builtins(profile: Option<&str>, json: bool) -> Result<ExitCode> {
    use egressdns::config::builtins;

    let Some(name) = profile else {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&builtins::profile_names())?
            );
            return Ok(ExitCode::SUCCESS);
        }
        println!("Built-in resolver profiles. Use one as `upstreams = [\"builtin:<name>\"]`.\n");
        for name in builtins::profile_names() {
            let Some(profile) = builtins::profile(name) else {
                continue;
            };
            let operators: Vec<&str> = profile
                .members
                .iter()
                .filter_map(|id| builtins::provider(id).map(|p| p.operator))
                .collect();
            println!("  {name}\n    {}", profile.description);
            println!("    {}\n", operators.join(", "));
        }
        println!("`egressdnsctl builtins <name>` shows one in full.");
        return Ok(ExitCode::SUCCESS);
    };

    let Some(profile) = builtins::profile(name) else {
        eprintln!(
            "no built-in profile named `{name}`; try one of: {}",
            builtins::profile_names().join(", ")
        );
        return Ok(ExitCode::from(2));
    };

    if json {
        let uris = builtins::expand(name).unwrap_or_default();
        println!("{}", serde_json::to_string_pretty(&uris)?);
        return Ok(ExitCode::SUCCESS);
    }

    println!("builtin:{name} — {}\n", profile.description);
    for id in profile.members {
        let Some(p) = builtins::provider(id) else {
            continue;
        };
        println!("  {} ({})", p.operator, p.id);
        println!("    addresses  {}", p.addresses.join(", "));
        for (label, endpoint) in [("DoH", p.doh), ("DoT", p.dot), ("DoQ", p.doq)] {
            if let Some(e) = endpoint {
                println!("    {label}        {e}");
            }
        }
        println!("    filtering  {:?}", p.filtering);
        if !p.notes.is_empty() {
            println!("    notes      {}", p.notes);
        }
        println!("    source     {} (checked {})\n", p.source, p.verified);
    }
    Ok(ExitCode::SUCCESS)
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

    if let Command::Builtins { profile } = &cli.command {
        return run_builtins(profile.as_deref(), cli.json);
    }

    if let Command::Query {
        name,
        rtype,
        server,
        port,
        tcp,
        dnssec,
        require_answer,
        wait,
    } = &cli.command
    {
        return run_query(
            name,
            rtype,
            server,
            *port,
            *tcp,
            *dnssec,
            *require_answer,
            *wait,
            cli.json,
        )
        .await;
    }

    if let Command::Bench {
        servers,
        names,
        names_file,
        cold_rounds,
        warm_rounds,
        concurrency,
        timeout_ms,
        json_out,
    } = &cli.command
    {
        return run_bench(
            servers,
            names,
            names_file.as_deref(),
            *cold_rounds,
            *warm_rounds,
            *concurrency,
            *timeout_ms,
            json_out.as_deref(),
            cli.json,
        )
        .await;
    }

    // `doctor` is always answered locally. Its whole purpose is to run before the daemon
    // exists, against a configuration that has not been activated yet.
    if matches!(cli.command, Command::Doctor) {
        return Ok(run_doctor(&cli).await);
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

/// Diagnose the configuration against this host and render the report.
///
/// A configuration that does not even parse is itself the diagnosis, so it is reported as
/// a single failing check rather than as a CLI error: `doctor` should always produce a
/// report, and `--json` consumers should always get one document.
async fn run_doctor(cli: &Cli) -> ExitCode {
    let report = match egressdns::config::Config::load(&cli.config) {
        Ok(config) => egressdns::doctor::run(&config, &cli.config).await,
        Err(e) => egressdns::doctor::Report {
            checks: vec![egressdns::doctor::Check {
                id: "config.valid",
                title: "Configuration parses and validates",
                status: egressdns::doctor::Status::Fail,
                detail: e.to_string(),
                remedy: Some(String::from(
                    "fix the configuration; no other check can be trusted until it parses",
                )),
            }],
        },
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
        return ExitCode::from(report.exit_code());
    }

    println!(
        "EgressDNS deployment diagnosis for {}\n",
        cli.config.display()
    );
    for check in &report.checks {
        println!("[{:<14}] {}", check.status.label(), check.title);
        println!("                 {}", check.detail);
        if let Some(remedy) = &check.remedy {
            println!("                 -> {remedy}");
        }
    }
    let tally = report.tally();
    let summary: Vec<String> = tally.iter().map(|(k, v)| format!("{v} {k}")).collect();
    println!("\n{}", summary.join(", "));
    if report.has_failure() {
        println!("\nAt least one check would stop the resolver from serving.");
    } else if report.has_warning() {
        println!("\nNo blocking problem found; review the warnings before cutover.");
    } else {
        println!("\nNo problem found.");
    }
    ExitCode::from(report.exit_code())
}

/// Send one query and report on the answer.
///
/// Judged on the response, never on the fact that one arrived: a resolver that returns
/// SERVFAIL or REFUSED to everything has answered, and is broken.
#[allow(clippy::too_many_arguments)]
async fn run_query(
    name: &str,
    rtype: &str,
    server: &str,
    port: u16,
    tcp: bool,
    dnssec: bool,
    require_answer: bool,
    wait: u64,
    json: bool,
) -> Result<ExitCode> {
    use egressdns::dns::query::{self, QueryOutcome};

    let outcome = query::run(query::Request {
        name: name.to_string(),
        rtype: rtype.to_string(),
        server: server.to_string(),
        port,
        tcp,
        dnssec,
        timeout: Duration::from_secs(wait.clamp(1, 120)),
    })
    .await;

    let usable = match &outcome {
        QueryOutcome::Answered {
            rcode, addresses, ..
        } => rcode == "NOERROR" && (!require_answer || !addresses.is_empty()),
        _ => false,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        match &outcome {
            QueryOutcome::Answered {
                rcode,
                addresses,
                authenticated,
                elapsed_ms,
                ..
            } => {
                println!(
                    "{name} {rtype} via {}{server}:{port} -> {rcode}{} in {elapsed_ms}ms",
                    if tcp { "tcp/" } else { "udp/" },
                    if *authenticated { " (ad)" } else { "" }
                );
                for a in addresses {
                    println!("  {a}");
                }
            }
            QueryOutcome::Failed { reason } => {
                eprintln!("{name} {rtype} via {server}:{port} -> {reason}");
            }
        }
        if !usable {
            eprintln!("the resolver did not return a usable answer");
        }
    }

    Ok(if usable {
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
        Command::Doctor => ("doctor".into(), vec![]),
        Command::Query { .. } => ("query".into(), vec![]),
        // Answered locally before this point is reached; never sent to the daemon.
        Command::ReloadContract => ("reload-contract".into(), vec![]),
        Command::Builtins { .. } => ("builtins".into(), vec![]),
        Command::Reload => ("reload".into(), vec![]),
        // Answered locally before this point is reached; never sent to the daemon.
        Command::Bench { .. } => ("bench".into(), vec![]),
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

/// Measure real resolvers from this host and render the comparison.
#[allow(clippy::too_many_arguments)]
async fn run_bench(
    servers: &[String],
    extra_names: &[String],
    names_file: Option<&std::path::Path>,
    cold_rounds: usize,
    warm_rounds: usize,
    concurrency: usize,
    timeout_ms: u64,
    json_out: Option<&std::path::Path>,
    json: bool,
) -> Result<ExitCode> {
    use egressdns::bench;

    let mut names: Vec<String> = match names_file {
        Some(path) => {
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            body.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        }
        None => bench::DEFAULT_CORPUS
            .iter()
            .map(|s| String::from(*s))
            .collect(),
    };
    for name in extra_names {
        let name = name.trim().to_string();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        anyhow::bail!("no names to measure");
    }
    if servers.is_empty() {
        anyhow::bail!("no servers to measure");
    }

    let request = bench::BenchRequest {
        servers: servers.to_vec(),
        names,
        timeout: Duration::from_millis(timeout_ms.clamp(50, 60_000)),
        concurrency: concurrency.clamp(1, 256),
        cold_rounds: cold_rounds.min(64),
        warm_rounds: warm_rounds.min(512),
    };
    let report = bench::run(request).await;

    if let Some(path) = json_out {
        let text = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, text + "\n").with_context(|| format!("writing {}", path.display()))?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "DNS latency benchmark — {} name(s), cold {} round(s), warm {} round(s), {}ms timeout\n",
        report.names.len(),
        cold_rounds,
        warm_rounds,
        report.timeout_ms
    );
    println!(
        "{:<24} {:>7} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "SERVER", "USEFUL", "TIMEOUT", "P50_MS", "P90_MS", "P95_MS", "P99_MS", "MAX_MS", "MEAN_MS"
    );
    for server in &report.servers {
        for (label, workload) in [("cold", &server.cold), ("warm", &server.warm)] {
            let lat = &workload.latency;
            println!(
                "{:<24} {:>7} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
                format!("{}/{}", truncate(&server.server, 21), label),
                format!("{}/{}", workload.useful, workload.queries),
                workload.timeouts,
                format!("{:.1}", lat.p50_ms),
                format!("{:.1}", lat.p90_ms),
                format!("{:.1}", lat.p95_ms),
                format!("{:.1}", lat.p99_ms),
                format!("{:.1}", lat.max_ms),
                format!("{:.1}", lat.mean_ms),
            );
        }
    }
    println!(
        "\nUSEFUL is NOERROR answers with an address out of all queries. \
              warm measures whichever caching layer sits in front of the name."
    );
    Ok(ExitCode::SUCCESS)
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
