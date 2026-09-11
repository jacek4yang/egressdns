//! A real-DNS latency benchmark.
//!
//! Criterion numbers measure the library; this module measures what a user experiences:
//! end-to-end DNS exchanges against actual resolvers — the local EgressDNS instance,
//! `223.5.5.5`, regional public resolvers, or anything else addressable — over the same
//! code path `egressdnsctl query` uses.
//!
//! The design follows the project's measurement honesty rules:
//!
//! * a reply is not a success — only NOERROR with an answer record counts as *useful*;
//! * every workload records rcode counts, timeouts and failures, not just latencies;
//! * cold and warm behaviour are measured separately, because a caching resolver's
//!   whole point is the gap between them;
//! * the result is machine-readable JSON so reports are generated from data, never
//!   transcribed by hand.
//!
//! Nothing here is a substitute for `scripts/load-test.sh`: that harness drives
//! sustained concurrency through a real daemon. This one answers "which resolver is
//! faster for *this* host, for *these* names, right now".

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::dns::query::{self, QueryOutcome};

/// Names measured unless the operator supplies their own corpus.
///
/// Chosen to cover the failure modes the product exists for: deep CNAME chains
/// (`www.bing.com`), CDN-heavy and dual-stack names, signed and unsigned zones, and the
/// major regional CDNs whose answers differ most between resolvers.
pub const DEFAULT_CORPUS: &[&str] = &[
    "www.bing.com",
    "www.microsoft.com",
    "www.github.com",
    "github.com",
    "www.cloudflare.com",
    "www.apple.com",
    "www.amazon.com",
    "www.netflix.com",
    "www.baidu.com",
    "www.qq.com",
    "www.taobao.com",
    "www.bilibili.com",
    "www.wikipedia.org",
    "www.google.com",
];

/// What to measure.
#[derive(Debug, Clone)]
pub struct BenchRequest {
    /// Resolver specs, `host[:port]`, queried over UDP with TCP fallback by the shared
    /// query path.
    pub servers: Vec<String>,
    /// Names to resolve.
    pub names: Vec<String>,
    /// UDP timeout per query.
    pub timeout: Duration,
    /// Maximum concurrent queries per server.
    pub concurrency: usize,
    /// Cold workload: one timed first query per (server, name) pair.
    pub cold_rounds: usize,
    /// Warm workload: repeated queries for the same names, measuring the served-from-cache
    /// path of whichever resolver caches.
    pub warm_rounds: usize,
}

impl Default for BenchRequest {
    fn default() -> Self {
        Self {
            servers: vec![String::from("223.5.5.5")],
            names: DEFAULT_CORPUS.iter().map(|s| String::from(*s)).collect(),
            timeout: Duration::from_secs(3),
            concurrency: 8,
            cold_rounds: 1,
            warm_rounds: 5,
            // Warm rounds default chosen so the 95th percentile of a caching resolver has
            // something to stand on: five samples per name over a fourteen-name corpus.
        }
    }
}

/// Latency distribution summary, in milliseconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencySummary {
    /// Timed, answered exchanges (successes and useful answers).
    pub samples: usize,
    /// Mean of answered exchanges.
    pub mean_ms: f64,
    /// 50th percentile of answered exchanges, in milliseconds.
    pub p50_ms: f64,
    /// 90th percentile of answered exchanges, in milliseconds.
    pub p90_ms: f64,
    /// 95th percentile of answered exchanges, in milliseconds.
    pub p95_ms: f64,
    /// 99th percentile of answered exchanges, in milliseconds.
    pub p99_ms: f64,
    /// Slowest answered exchange.
    pub max_ms: f64,
}

/// Outcome tallies for one workload against one resolver.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkloadResult {
    /// Queries issued.
    pub queries: usize,
    /// NOERROR with at least one answer record — the only thing a client can use.
    pub useful: usize,
    /// NOERROR with an empty answer (e.g. a name with no A records).
    pub no_error_empty: usize,
    /// NXDOMAIN answers.
    pub nxdomain: usize,
    /// SERVFAIL answers.
    pub servfail: usize,
    /// REFUSED answers.
    pub refused: usize,
    /// Any other NOERROR-less rcode.
    pub other_rcode: usize,
    /// No reply inside the timeout.
    pub timeouts: usize,
    /// Malformed or otherwise unusable replies.
    pub failed: usize,
    /// Latency distribution over answered exchanges.
    pub latency: LatencySummary,
    /// Per-name detail rows.
    pub per_name: Vec<NameResult>,
}

impl WorkloadResult {
    /// Useful-answer ratio over issued queries.
    pub fn useful_rate(&self) -> f64 {
        if self.queries == 0 {
            0.0
        } else {
            self.useful as f64 / self.queries as f64
        }
    }
}

/// Per-name detail, so a report can show *which* names a resolver handles badly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameResult {
    /// The name queried.
    pub name: String,
    /// Workload the row came from (`cold` or `warm`).
    pub workload: String,
    /// Rcode of the first successful answer, if any.
    pub rcode: Option<String>,
    /// Latency of the fastest useful answer, in milliseconds.
    pub best_ms: Option<f64>,
    /// Latency of the slowest useful answer, in milliseconds.
    pub worst_ms: Option<f64>,
    /// Useful answers for this name.
    pub useful: usize,
    /// Queries issued for this name.
    pub queries: usize,
}

/// One resolver's complete result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerResult {
    /// The server spec as given.
    pub server: String,
    /// First-contact workload.
    pub cold: WorkloadResult,
    /// Repeated-contact workload.
    pub warm: WorkloadResult,
    /// Per-name detail across both workloads.
    pub per_name: Vec<NameResult>,
}

/// Full report; serialised to JSON with `--json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchReport {
    /// Unix timestamp of the run.
    pub started_unix: u64,
    /// Per-query timeout, in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent queries per server.
    pub concurrency: usize,
    /// Names measured.
    pub names: Vec<String>,
    /// Per-server results.
    pub servers: Vec<ServerResult>,
}

/// Run the benchmark described by `req`.
///
/// Per server, the cold workload runs first, so the warm workload of a caching resolver
/// measures its cache rather than the resolver's own first-encounter behaviour. Queries
/// are bounded by a semaphore so a slow server cannot hold thousands of tasks.
pub async fn run(req: BenchRequest) -> BenchReport {
    let started = crate::util::time::SystemClock.unix_secs_now();
    let mut servers = Vec::with_capacity(req.servers.len());
    for server in &req.servers {
        let result = bench_server(server, &req).await;
        servers.push(result);
    }
    BenchReport {
        started_unix: started,
        timeout_ms: req.timeout.as_millis() as u64,
        concurrency: req.concurrency,
        names: req.names.clone(),
        servers,
    }
}

async fn bench_server(server: &str, req: &BenchRequest) -> ServerResult {
    let semaphore = std::sync::Arc::new(Semaphore::new(req.concurrency.max(1)));
    let cold = run_workload(
        server,
        &req.names,
        req.cold_rounds,
        req.timeout,
        &semaphore,
        "cold",
    )
    .await;
    let warm = run_workload(
        server,
        &req.names,
        req.warm_rounds,
        req.timeout,
        &semaphore,
        "warm",
    )
    .await;
    let mut per_name = cold.per_name.clone();
    per_name.extend(warm.per_name.clone());
    ServerResult {
        server: server.to_string(),
        cold,
        warm,
        per_name,
    }
}

/// Query outcome classified into the report's counters.
#[derive(Debug, Clone, Copy)]
enum Classified {
    Useful(f64),
    NoErrorEmpty(f64),
    NxDomain(f64),
    ServFail(f64),
    Refused(f64),
    OtherRcode(f64),
    Timeout,
    Failed,
}

fn classify(outcome: &QueryOutcome) -> Classified {
    match outcome {
        QueryOutcome::Answered {
            rcode,
            addresses,
            elapsed_ms,
            ..
        } => {
            let ms = *elapsed_ms as f64;
            if rcode == "NOERROR" {
                if addresses.is_empty() {
                    Classified::NoErrorEmpty(ms)
                } else {
                    Classified::Useful(ms)
                }
            } else if rcode == "NXDOMAIN" {
                Classified::NxDomain(ms)
            } else if rcode == "SERVFAIL" {
                Classified::ServFail(ms)
            } else if rcode == "REFUSED" {
                Classified::Refused(ms)
            } else {
                Classified::OtherRcode(ms)
            }
        }
        QueryOutcome::Failed { reason } => {
            // The shared query path reports "timed out" for deadline expiry; everything
            // else (refused connection, malformed reply, socket error) is a plain failure.
            if reason.contains("timed out") || reason.contains("timeout") {
                Classified::Timeout
            } else {
                Classified::Failed
            }
        }
    }
}

/// A timed sample for one (name, round) cell, run concurrently.
#[derive(Debug)]
struct Sample {
    name: String,
    outcome: Result<QueryOutcome, ()>,
}

async fn run_workload(
    server: &str,
    names: &[String],
    rounds: usize,
    timeout: Duration,
    semaphore: &std::sync::Arc<Semaphore>,
    workload: &'static str,
) -> WorkloadResult {
    let mut result = WorkloadResult::default();
    if rounds == 0 || names.is_empty() {
        return result;
    }

    // One shared reservoir of latencies; per-name detail is kept alongside.
    let mut latencies: Vec<f64> = Vec::new();
    let mut per_name: std::collections::HashMap<String, NameResult> =
        std::collections::HashMap::new();

    let mut handles = Vec::with_capacity(names.len() * rounds);
    let (host, port) = split_spec(server);
    for _round in 0..rounds {
        for name in names {
            // The permit is held by the task until its query completes, so the launch
            // loop is the concurrency bound.
            let Ok(permit) = semaphore.clone().acquire_owned().await else {
                // The semaphore is never closed; treat an impossible error as a skipped
                // sample rather than panicking in a measurement tool.
                continue;
            };
            let name = name.clone();
            let host = host.clone();
            handles.push(tokio::spawn(async move {
                let outcome = query::run(query::Request {
                    name: name.clone(),
                    rtype: String::from("A"),
                    server: host,
                    port,
                    tcp: false,
                    dnssec: false,
                    timeout,
                })
                .await;
                drop(permit);
                Sample {
                    name,
                    outcome: Ok(outcome),
                }
            }));
        }
    }

    // Queries were launched per (name, round); the workload's semantics — cold first
    // contact versus repeated contact — come from the round structure above, not from
    // serialization, so a fast resolver is never artificially throttled.
    for handle in handles {
        let sample = match handle.await {
            Ok(s) => s,
            Err(_) => Sample {
                name: String::new(),
                outcome: Err(()),
            },
        };
        result.queries += 1;
        let entry = per_name.entry(sample.name.clone()).or_default();
        entry.name = sample.name.clone();
        entry.workload = workload.to_string();
        entry.queries += 1;
        match sample.outcome {
            Ok(outcome) => match classify(&outcome) {
                Classified::Useful(ms) => {
                    result.useful += 1;
                    latencies.push(ms);
                    entry.useful += 1;
                    entry.rcode.get_or_insert(String::from("NOERROR"));
                    entry.best_ms = Some(entry.best_ms.map_or(ms, |b: f64| b.min(ms)));
                    entry.worst_ms = Some(entry.worst_ms.map_or(ms, |w: f64| w.max(ms)));
                }
                Classified::NoErrorEmpty(ms) => {
                    result.no_error_empty += 1;
                    latencies.push(ms);
                    entry.rcode.get_or_insert(String::from("NOERROR"));
                }
                Classified::NxDomain(ms) => {
                    result.nxdomain += 1;
                    latencies.push(ms);
                    entry.rcode.get_or_insert(String::from("NXDOMAIN"));
                }
                Classified::ServFail(ms) => {
                    result.servfail += 1;
                    latencies.push(ms);
                    entry.rcode.get_or_insert(String::from("SERVFAIL"));
                }
                Classified::Refused(ms) => {
                    result.refused += 1;
                    latencies.push(ms);
                    entry.rcode.get_or_insert(String::from("REFUSED"));
                }
                Classified::OtherRcode(ms) => {
                    result.other_rcode += 1;
                    latencies.push(ms);
                }
                Classified::Timeout => result.timeouts += 1,
                Classified::Failed => result.failed += 1,
            },
            Err(()) => result.failed += 1,
        }
    }

    result.latency = summarise(&latencies);
    result.per_name = per_name.into_values().collect();
    result
}

/// Split a `host[:port]` spec; port 53 when absent.
///
/// Bracketed IPv6 literals keep their colons: `[::1]:5353` is host `::1`, port 5353.
fn split_spec(spec: &str) -> (String, u16) {
    if let Some(rest) = spec.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(53);
            return (host.to_string(), port);
        }
    }
    match spec.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), port.parse().unwrap_or(53))
        }
        _ => (spec.to_string(), 53),
    }
}

/// Distribution summary over answered exchanges.
fn summarise(latencies: &[f64]) -> LatencySummary {
    if latencies.is_empty() {
        return LatencySummary::default();
    }
    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    LatencySummary {
        samples: sorted.len(),
        mean_ms: mean,
        p50_ms: percentile(&sorted, 50.0),
        p90_ms: percentile(&sorted, 90.0),
        p95_ms: percentile(&sorted, 95.0),
        p99_ms: percentile(&sorted, 99.0),
        max_ms: *sorted.last().unwrap_or(&0.0),
    }
}

/// Nearest-rank percentile of an ascending-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil();
    let idx = rank.clamp(1.0, sorted.len() as f64) as usize - 1;
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_pick_the_nearest_rank() {
        let data: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&data, 50.0), 50.0);
        assert_eq!(percentile(&data, 90.0), 90.0);
        assert_eq!(percentile(&data, 95.0), 95.0);
        assert_eq!(percentile(&data, 99.0), 99.0);
        assert_eq!(percentile(&data, 100.0), 100.0);
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        let data = [42.0];
        assert_eq!(percentile(&data, 50.0), 42.0);
        assert_eq!(percentile(&data, 99.0), 42.0);
    }

    #[test]
    fn small_samples_round_up() {
        // Nearest-rank: the 95th percentile of three samples is the third.
        let data = [10.0, 20.0, 30.0];
        assert_eq!(percentile(&data, 95.0), 30.0);
        assert_eq!(percentile(&data, 50.0), 20.0);
    }

    #[test]
    fn server_specs_split_the_last_colon() {
        assert_eq!(split_spec("223.5.5.5"), (String::from("223.5.5.5"), 53));
        assert_eq!(
            split_spec("223.5.5.5:5353"),
            (String::from("223.5.5.5"), 5353)
        );
        assert_eq!(split_spec("[::1]"), (String::from("::1"), 53));
        assert_eq!(split_spec("[::1]:5353"), (String::from("::1"), 5353));
        assert_eq!(
            split_spec("dns.alidns.com"),
            (String::from("dns.alidns.com"), 53)
        );
    }

    #[test]
    fn empty_latencies_yield_an_empty_summary() {
        let s = summarise(&[]);
        assert_eq!(s.samples, 0);
        assert_eq!(s.p50_ms, 0.0);
    }
}
