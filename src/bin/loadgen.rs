//! `egressdns-loadgen` — a native high-rate DNS load generator.
//!
//! The Python harness (`scripts/loadtest.py`) is honest but generator-bound: on
//! Windows it saturates in the low thousands of queries per second, which reports the
//! generator's ceiling, not the daemon's. This tool speaks the same measurement
//! language — useful answers only, full rcode distribution, sorted percentiles — but
//! sends raw UDP DNS packets from a Tokio worker pool, so the generator stops being
//! the bottleneck.
//!
//! Measurement rules carried over unchanged:
//!
//! * a reply is not a success — the headline success rate counts NOERROR answers with
//!   at least one answer record;
//! * percentiles are computed from every retained latency sample, out to p99.9;
//! * resource saturation is reported as observed, never extrapolated.
//!
//! Open-loop pacing: the pacer emits `--qps` requests per second regardless of
//! completion, which is what reveals saturation (queueing shows up as latency and
//! timeouts rather than as a collapsed offer rate).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "egressdns-loadgen",
    version,
    about = "Native high-rate DNS load generator for saturation measurement"
)]
struct Cli {
    /// Resolver to load, `host[:port]`.
    #[arg(long, default_value = "127.0.0.1:1053")]
    target: String,

    /// Target query rate, in queries per second.
    #[arg(long, default_value_t = 1_000)]
    qps: u64,

    /// Duration of the run, in seconds.
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Worker sockets. Each worker owns one connected UDP socket and its own ID space.
    #[arg(long, default_value_t = 4)]
    workers: usize,

    /// Distinct names in rotation (1 = pure cache-hit workload; large = cache-miss).
    #[arg(long, default_value_t = 1)]
    names: u32,

    /// Zone suffix for generated names.
    #[arg(long, default_value = "load.test")]
    zone: String,

    /// Per-query timeout, in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    timeout_ms: u64,

    /// Write the full result as JSON to this path.
    #[arg(long)]
    json: Option<String>,
}

/// One completed query's measurement.
struct Sample {
    latency_us: u64,
    rcode: u8,
    answers: u16,
}

/// Shared counters.
#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    timeouts: AtomicU64,
    malformed: AtomicU64,
}

/// A pacing signal handed from the pacer to a worker; the worker builds the query
/// itself from its own sequence counter (which is what the `--names` rotation uses).
struct Request;

/// Per-worker reactor: one connected socket, one ID space, one pending map.
struct Worker {
    socket: UdpSocket,
    pending: HashMap<u16, Instant>,
    next_id: u16,
    timeout: Duration,
    rx: mpsc::Receiver<Request>,
    results: mpsc::Sender<Sample>,
    counters: Arc<Counters>,
    zone: String,
    names: u32,
    query_seq: u64,
}

impl Worker {
    /// Build the query wire packet for the next name: header, qname, A/IN.
    fn build_query(&mut self) -> (u16, Vec<u8>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let seq = self.query_seq;
        self.query_seq = self.query_seq.wrapping_add(1);
        let mut packet = Vec::with_capacity(64);
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let name = if self.names <= 1 {
            String::from("hit.")
        } else {
            format!("n{}.", seq % u64::from(self.names))
        };
        let name = format!("{name}{}", self.zone);
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        (id, packet)
    }

    /// React until cancelled: send paced requests, match responses by ID, expire
    /// deadlines.
    async fn run(mut self, cancel: tokio_util::sync::CancellationToken) {
        let mut buf = vec![0u8; 4096];
        let mut last_sweep = Instant::now();
        loop {
            // The socket branch comes FIRST and the select is not biased: responses
            // must always out-rank new requests, or a sustained offer rate starves
            // response reads completely (observed: completions froze at the pacer's
            // first burst while `sent` kept climbing).
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = self.socket.recv(&mut buf) => {
                    match result {
                        Ok(n) if n >= 12 => {
                            let id = u16::from_be_bytes([buf[0], buf[1]]);
                            if let Some(started) = self.pending.remove(&id) {
                                self.results
                                    .send(Sample {
                                        latency_us: started.elapsed().as_micros() as u64,
                                        rcode: buf[3] & 0x0f,
                                        answers: u16::from_be_bytes([buf[6], buf[7]]),
                                    })
                                    .await
                                    .ok();
                            }
                            // Datagrams for unknown IDs are late arrivals behind
                            // expired deadlines; the sample was already emitted.
                        }
                        _ => {
                            self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                request = self.rx.recv() => {
                    match request {
                        None => break,
                        Some(_request) => {
                            let (id, packet) = self.build_query();
                            self.counters.sent.fetch_add(1, Ordering::Relaxed);
                            if self.socket.send(&packet).await.is_ok() {
                                self.pending.insert(id, Instant::now());
                            } else {
                                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            // Sweep timeouts at most every 10 ms of real time: cheap, and keeps a
            // stalled target from leaving pending entries queued forever.
            if last_sweep.elapsed() >= Duration::from_millis(10) {
                last_sweep = Instant::now();
                let expired: Vec<u16> = self
                    .pending
                    .iter()
                    .filter(|(_, started)| last_sweep.duration_since(**started) > self.timeout)
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    self.pending.remove(&id);
                    self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// The report, mirroring the load-test JSON shape so both harnesses feed the same
/// documentation pipeline.
#[derive(serde::Serialize)]
struct Report {
    target: String,
    qps_target: u64,
    duration_secs: u64,
    sent: u64,
    completed: u64,
    timeouts: u64,
    malformed: u64,
    success_rate: f64,
    qps_achieved: f64,
    rcodes: HashMap<String, u64>,
    latency_ms: Latencies,
}

#[derive(serde::Serialize)]
struct Latencies {
    p50: f64,
    p95: f64,
    p99: f64,
    p999: f64,
    max: f64,
    mean: f64,
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil();
    let idx = rank.clamp(1.0, sorted.len() as f64) as usize - 1;
    sorted[idx] as f64 / 1000.0
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let Ok(target) = cli.target.parse::<SocketAddr>() else {
        eprintln!("invalid --target (expected ip:port): {}", cli.target);
        return std::process::ExitCode::from(2);
    };
    if cli.workers == 0 || cli.qps == 0 || cli.duration == 0 {
        eprintln!("--workers, --qps and --duration must be at least 1");
        return std::process::ExitCode::from(2);
    }

    let counters = Arc::new(Counters::default());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (results_tx, mut results_rx) = mpsc::channel::<Sample>(16_384);
    let mut worker_channels = Vec::with_capacity(cli.workers);
    let mut worker_tasks = Vec::with_capacity(cli.workers);

    for _ in 0..cli.workers {
        let socket = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .expect("bind worker socket");
        socket.connect(target).await.expect("connect target");
        let (tx, rx) = mpsc::channel::<Request>(1024);
        worker_channels.push(tx);
        let worker = Worker {
            socket,
            pending: HashMap::new(),
            next_id: rand_id(),
            timeout: Duration::from_millis(cli.timeout_ms),
            rx,
            results: results_tx.clone(),
            counters: Arc::clone(&counters),
            zone: cli.zone.clone(),
            names: cli.names,
            query_seq: 0,
        };
        worker_tasks.push(tokio::spawn(worker.run(cancel.clone())));
    }
    drop(results_tx);

    // The pacer: `qps` requests per second, spread evenly, distributed round-robin
    // over the workers. It cancels the run at the deadline.
    let pacer_qps = cli.qps;
    let pacer_duration = cli.duration;
    let run_cancel = cancel.clone();
    let pacer = tokio::spawn(async move {
        let interval = Duration::from_nanos(1_000_000_000 / pacer_qps.max(1));
        let deadline = Instant::now() + Duration::from_secs(pacer_duration);
        let mut next = Instant::now();
        let mut rr = 0usize;
        while Instant::now() < deadline {
            tokio::time::sleep_until(tokio::time::Instant::from_std(next)).await;
            next += interval;
            if worker_channels[rr % worker_channels.len()]
                .try_send(Request)
                .is_err()
            {
                // Worker channel full: the pacer is outrunning the send loops, which
                // at these rates means the run is host-bound anyway.
            }
            rr += 1;
        }
        run_cancel.cancel();
    });

    // The collector runs CONCURRENTLY with the pacer: the results channel is bounded,
    // and a collector that only starts after the pacer finishes lets it fill, which
    // blocks workers mid-run and freezes completions at the channel capacity.
    let collector_capacity = usize::try_from(cli.qps * (cli.duration + 2)).unwrap_or(1 << 20);
    let mut reservoir: Vec<Sample> = Vec::with_capacity(collector_capacity);
    let run_started = Instant::now();
    let collector = tokio::spawn(async move {
        while let Some(sample) = results_rx.recv().await {
            reservoir.push(sample);
        }
        reservoir
    });
    pacer.await.expect("pacer task");
    // One timeout window for stragglers, then close: dropping the last handles ends
    // the collector.
    tokio::time::sleep(Duration::from_millis(cli.timeout_ms + 500)).await;
    cancel.cancel();
    for task in worker_tasks {
        task.abort();
    }
    let reservoir = collector.await.expect("collector task");

    let sent = counters.sent.load(Ordering::Relaxed);
    let timeouts = counters.timeouts.load(Ordering::Relaxed);
    let malformed = counters.malformed.load(Ordering::Relaxed);
    let mut latencies: Vec<u64> = reservoir.iter().map(|s| s.latency_us).collect();
    latencies.sort_unstable();
    let mut rcodes: HashMap<String, u64> = HashMap::new();
    let mut useful = 0u64;
    for s in &reservoir {
        *rcodes.entry(rcode_name(s.rcode).to_string()).or_default() += 1;
        if s.rcode == 0 && s.answers > 0 {
            useful += 1;
        }
    }
    let completed = reservoir.len() as u64;
    let elapsed = run_started.elapsed().as_secs_f64().max(0.001);
    let mean = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<u64>() as f64 / latencies.len() as f64 / 1000.0
    };
    let report = Report {
        target: cli.target.clone(),
        qps_target: cli.qps,
        duration_secs: cli.duration,
        sent,
        completed,
        timeouts,
        malformed,
        success_rate: if sent > 0 {
            useful as f64 / sent as f64
        } else {
            0.0
        },
        qps_achieved: completed as f64 / elapsed,
        rcodes: rcodes.clone(),
        latency_ms: Latencies {
            p50: percentile(&latencies, 50.0),
            p95: percentile(&latencies, 95.0),
            p99: percentile(&latencies, 99.0),
            p999: percentile(&latencies, 99.9),
            max: percentile(&latencies, 100.0),
            mean,
        },
    };

    println!("sent {sent}  completed {completed}  timeouts {timeouts}  malformed {malformed}");
    println!(
        "useful qps: {:.0} (target {:.0});  success rate: {:.1}%",
        report.qps_achieved,
        report.qps_target,
        report.success_rate * 100.0
    );
    println!(
        "p50 {:.2}ms  p95 {:.2}ms  p99 {:.2}ms  p99.9 {:.2}ms  max {:.2}ms  mean {:.2}ms",
        report.latency_ms.p50,
        report.latency_ms.p95,
        report.latency_ms.p99,
        report.latency_ms.p999,
        report.latency_ms.max,
        report.latency_ms.mean
    );
    for (rcode, count) in &rcodes {
        println!("  {rcode}: {count}");
    }
    if let Some(path) = &cli.json {
        let text = serde_json::to_string_pretty(&report).unwrap_or_default();
        if std::fs::write(path, text + "\n").is_err() {
            eprintln!("could not write {}", path);
            return std::process::ExitCode::from(1);
        }
    }
    std::process::ExitCode::SUCCESS
}

fn rand_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos as u16 ^ (std::process::id() as u16)
}
