//! The asynchronous probe engine.
//!
//! Probes are observations, never gates. The engine consumes a bounded queue, runs a
//! three-stage pipeline (TCP, TLS, HTTP) under separate concurrency ceilings, and feeds
//! the results into the quality model and the Cloudflare validation records. It can be
//! stopped, saturated or broken without any effect on DNS resolution.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::cloudflare::candidates::{CandidateOrigin, CandidateStage};
use crate::cloudflare::state::SharedCloudflare;
use crate::config::{ProbeConfig, ProbeProfile};
use crate::error::ProbeError;
use crate::network::SharedNetworkState;
use crate::probe::http::{HttpProbeOutcome, HttpProbeRequest, ProbeMethod};
use crate::probe::job::ProbeJob;
use crate::probe::safety::ProbeGuard;
use crate::ranking::{ObservationClass, ProbeKey, QualityStore};

/// Health of the probe subsystem as a whole.
///
/// A broken clock, a missing CA store, file-descriptor exhaustion or a lost route makes
/// *every* probe fail. Attributing that to individual addresses would poison the whole
/// quality model, so the engine detects the pattern and downgrades new observations to
/// indeterminate until it recovers.
pub struct SubsystemHealth {
    healthy: AtomicBool,
    consecutive_failures: AtomicU32,
    distinct_failures: AtomicU32,
    threshold: u32,
}

impl SubsystemHealth {
    /// Create a health tracker.
    pub fn new(threshold: u32) -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_failures: AtomicU32::new(0),
            distinct_failures: AtomicU32::new(0),
            threshold: threshold.max(4),
        }
    }

    /// Whether the subsystem is currently believed to be working.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Record a successful probe.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.distinct_failures.store(0, Ordering::Relaxed);
        if !self.healthy.swap(true, Ordering::Relaxed) {
            tracing::info!(event = "probe.subsystem_recovered");
            metrics::gauge!(crate::metrics::names::PROBE_SUBSYSTEM_HEALTHY).set(1.0);
        }
    }

    /// Record a failed probe against a distinct address.
    pub fn record_failure(&self) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.distinct_failures.fetch_add(1, Ordering::Relaxed);
        if n >= self.threshold && self.healthy.swap(false, Ordering::Relaxed) {
            tracing::warn!(
                event = "probe.subsystem_degraded",
                consecutive = n,
                "every recent probe failed; new observations are indeterminate"
            );
            metrics::gauge!(crate::metrics::names::PROBE_SUBSYSTEM_HEALTHY).set(0.0);
        }
    }

    /// Classify a failure, taking subsystem health into account.
    pub fn classify(&self, error: &ProbeError) -> ObservationClass {
        if !self.is_healthy() {
            return ObservationClass::AmbiguousFailure;
        }
        match error {
            ProbeError::PolicyBlocked { .. } => ObservationClass::PolicyBlocked,
            ProbeError::Unsupported(_) => ObservationClass::Unsupported,
            ProbeError::Timeout => ObservationClass::Timeout,
            ProbeError::Connect(_) | ProbeError::Tls(_) | ProbeError::Http(_) => {
                ObservationClass::ApplicableFailure
            }
            // A QUIC failure very often means UDP 443 is blocked on the path, which says
            // nothing about the address itself.
            ProbeError::Quic(_) => ObservationClass::Unsupported,
        }
    }
}

/// The probe engine.
pub struct ProbeEngine {
    ctx: crate::tasks::Ctx,
    guard: Arc<ProbeGuard>,
    quality: Arc<QualityStore>,
    cloudflare: SharedCloudflare,
    network: SharedNetworkState,
    health: Arc<SubsystemHealth>,
    cancel: CancellationToken,
    /// Current worker ceiling and its semaphore, rebuilt when the configuration changes.
    workers: parking_lot::Mutex<(usize, Arc<Semaphore>)>,
}

impl ProbeEngine {
    /// Build the engine.
    /// Build the engine.
    ///
    /// The engine holds no copy of the configuration. Every job re-reads the live
    /// configuration through the context, so `probe.enabled`, the timeouts, the profiles
    /// and the safety limits all follow a reload.
    pub fn new(
        ctx: crate::tasks::Ctx,
        quality: Arc<QualityStore>,
        cloudflare: SharedCloudflare,
        network: SharedNetworkState,
    ) -> Arc<Self> {
        let cancel = ctx.cancel.clone();
        let initial = ctx.config().map(|c| c.probe.clone()).unwrap_or_default();
        Arc::new(Self {
            guard: Arc::new(ProbeGuard::new(&initial)),
            health: Arc::new(SubsystemHealth::new(initial.concurrency.max(8) as u32)),
            workers: parking_lot::Mutex::new((0, Arc::new(Semaphore::new(0)))),
            ctx,
            quality,
            cloudflare,
            network,
            cancel,
        })
    }

    /// Subsystem health handle.
    pub fn health(&self) -> Arc<SubsystemHealth> {
        Arc::clone(&self.health)
    }

    /// Safety guard handle, exposed for diagnostics.
    pub fn guard(&self) -> Arc<ProbeGuard> {
        Arc::clone(&self.guard)
    }

    /// Consume the job queue until cancelled.
    ///
    /// The permit is acquired **before** the job is taken off the channel and the worker is
    /// spawned, not inside the spawned task. Spawning first and waiting for a permit
    /// afterwards looks equivalent but is not: it lets the receiver drain a bounded channel
    /// at memory speed into an unbounded pile of sleeping tasks, so the "bounded queue"
    /// stops bounding anything and the drop path becomes unreachable. Acquiring first means
    /// backpressure reaches the channel, the channel fills, and `ProbeQueue::offer` starts
    /// dropping and counting jobs — which is the designed behaviour.
    ///
    /// Workers live in a `JoinSet` so shutdown can wait for in-flight probes rather than
    /// leaving them to open new connections after the daemon has stopped.
    pub async fn run(self: Arc<Self>, rx: &mut mpsc::Receiver<ProbeJob>) {
        let mut workers: JoinSet<()> = JoinSet::new();
        loop {
            while workers.try_join_next().is_some() {}

            let permit = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                p = Arc::clone(&self.worker_slots()).acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };

            let job = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                j = rx.recv() => match j {
                    Some(j) => j,
                    None => break,
                },
            };
            metrics::gauge!(crate::metrics::names::PROBE_QUEUE_DEPTH).set(rx.len() as f64);
            metrics::gauge!(crate::metrics::names::PROBE_WORKERS_ACTIVE)
                .set(workers.len() as f64 + 1.0);

            let me = Arc::clone(&self);
            workers.spawn(async move {
                // The permit is moved into the worker and released when it finishes, so
                // live workers can never exceed the configured ceiling.
                let _permit = permit;
                me.execute(job).await;
            });
        }

        // Drain in-flight probes before returning: a probe that outlives the engine would
        // open outbound connections after shutdown began.
        let drain = async {
            while let Some(result) = workers.join_next().await {
                if result.is_err() {
                    metrics::counter!(crate::metrics::names::TASK_RESTARTS_TOTAL, "task" => "probe")
                        .increment(1);
                }
            }
        };
        if tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .is_err()
        {
            tracing::warn!(
                event = "probe.drain_timeout",
                remaining = workers.len(),
                "aborting probes that did not finish in time"
            );
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        }
        metrics::gauge!(crate::metrics::names::PROBE_WORKERS_ACTIVE).set(0.0);
    }

    /// Measure HTTP/3 reachability for an address that already answered over TCP.
    async fn probe_http3(
        &self,
        addr: IpAddr,
        port: u16,
        hostname: &str,
        path: &str,
        cfg: &ProbeConfig,
        now: Instant,
    ) {
        let roots = match self.ctx.state() {
            Some(state) => Arc::clone(&state.roots),
            None => return,
        };
        let deadline = cfg.tcp_timeout + cfg.tls_timeout;
        let started = Instant::now();
        let outcome = match tokio::time::timeout(
            deadline,
            crate::probe::quic::probe(addr, port, hostname, path, roots, cfg.http_timeout, true),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::error::ProbeError::Quic("deadline exceeded".into())),
        };
        metrics::histogram!(
            crate::metrics::names::PROBE_SECONDS,
            "stage" => "quic",
            "family" => if addr.is_ipv4() { "v4" } else { "v6" },
        )
        .record(started.elapsed().as_secs_f64());

        let (class, latency) = match &outcome {
            Ok(result) => (ObservationClass::Success, Some(result.handshake)),
            // Unsupported, never ApplicableFailure: see the note at the call site.
            Err(_) => (ObservationClass::Unsupported, None),
        };
        metrics::counter!(
            crate::metrics::names::PROBE_RESULTS_TOTAL,
            "stage" => "quic",
            "family" => if addr.is_ipv4() { "v4" } else { "v6" },
            "class" => class.label(),
        )
        .increment(1);
        self.record(ProbeKey::quic(addr, port), class, latency, now);
    }

    /// The worker pool ceiling, resized when the configuration changes.
    ///
    /// A worker holds its slot for the whole TCP → TLS → HTTP exchange, so the single
    /// configured ceiling covers every stage.
    fn worker_slots(&self) -> Arc<Semaphore> {
        let want = self
            .ctx
            .config()
            .map(|c| c.probe.concurrency.max(1))
            .unwrap_or(1);
        let mut slots = self.workers.lock();
        if slots.0 != want {
            *slots = (want, Arc::new(Semaphore::new(want)));
        }
        Arc::clone(&slots.1)
    }

    async fn execute(&self, job: ProbeJob) {
        let now = Instant::now();
        let generation = self.network.generation();
        if job.generation() != generation {
            // Evidence from a previous network generation is not worth gathering.
            return;
        }
        let addr = job.addr();
        let port = job.port();

        match &job {
            ProbeJob::Observed {
                hostname,
                cloudflare,
                ..
            } => {
                if *cloudflare {
                    let snapshot = self.cloudflare.prefixes();
                    self.cloudflare.pool().admit(
                        addr,
                        CandidateOrigin::DnsAnswer,
                        snapshot.as_ref().as_ref(),
                        generation,
                        now,
                        None,
                    );
                }
                self.run_https(addr, port, hostname, None, ProbeIntent::Baseline, now)
                    .await;
            }
            ProbeJob::Baseline { hostname, .. } => {
                self.run_https(addr, port, hostname, None, ProbeIntent::Baseline, now)
                    .await;
            }
            ProbeJob::Validate { hostname, .. } => {
                self.run_https(addr, port, hostname, None, ProbeIntent::Validate, now)
                    .await;
            }
            ProbeJob::Candidate { .. } => {
                let host = self.probe_host(addr);
                self.run_https(addr, port, &host, None, ProbeIntent::Candidate, now)
                    .await;
            }
        }
    }

    /// Choose a Cloudflare probe hostname deterministically from the address, so that a
    /// single unhealthy probe site cannot condemn the whole candidate pool.
    fn probe_host(&self, addr: IpAddr) -> String {
        let Some(config) = self.ctx.config() else {
            return "speed.cloudflare.com".to_string();
        };
        let hosts = &config.cloudflare.probe_hosts;
        if hosts.is_empty() {
            return "speed.cloudflare.com".to_string();
        }
        let idx = (crate::util::fnv1a64(addr.to_string().as_bytes()) as usize) % hosts.len();
        hosts[idx].clone()
    }

    fn profile_for<'a>(cfg: &'a ProbeConfig, hostname: &str) -> Option<&'a ProbeProfile> {
        let h = hostname.trim_end_matches('.').to_ascii_lowercase();
        cfg.profiles.iter().find(|p| {
            p.domains.iter().any(|d| {
                let d = d.trim_end_matches('.').to_ascii_lowercase();
                match d.strip_prefix('.') {
                    Some(suffix) => h == suffix || h.ends_with(&format!(".{suffix}")),
                    None => h == d,
                }
            })
        })
    }

    /// Run the full TCP -> TLS -> HTTP pipeline against one address for one hostname.
    async fn run_https(
        &self,
        addr: IpAddr,
        port: u16,
        hostname: &str,
        declared_port: Option<u16>,
        intent: ProbeIntent,
        now: Instant,
    ) {
        // Live configuration, re-read per job: a reload changes probe behaviour on the
        // next job rather than at the next restart.
        let Some(config) = self.ctx.config() else {
            return;
        };
        let probe_cfg = &config.probe;
        if !probe_cfg.enabled {
            return;
        }
        self.guard.update_limits(probe_cfg);
        let roots = match self.ctx.state() {
            Some(state) => Arc::clone(&state.roots),
            None => return,
        };
        let host = hostname.trim_end_matches('.').to_string();
        if let Err(refusal) =
            self.guard
                .admit(addr, port, declared_port.is_some(), Some(&host), now)
        {
            metrics::counter!(
                crate::metrics::names::PROBE_DROPPED_TOTAL,
                "reason" => refusal.label(),
                "kind" => intent.label(),
            )
            .increment(1);
            // A policy block is never negative evidence about the address.
            self.record(
                ProbeKey::https(addr, port, &host),
                ObservationClass::PolicyBlocked,
                None,
                now,
            );
            return;
        }

        let profile = Self::profile_for(probe_cfg, &host);
        let request = HttpProbeRequest {
            ip: addr,
            port,
            hostname: host.clone(),
            path: profile
                .map(|p| p.path.clone())
                .unwrap_or_else(|| "/".into()),
            method: profile
                .and_then(|p| ProbeMethod::parse(&p.method))
                .unwrap_or(ProbeMethod::Head),
            alpn: profile
                .map(|p| p.alpn.clone())
                .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]),
            connect_timeout: probe_cfg.tcp_timeout,
            tls_timeout: probe_cfg.tls_timeout,
            http_timeout: probe_cfg.http_timeout,
            max_body_bytes: probe_cfg.max_response_bytes,
        };

        // The worker already holds its pool permit, which is the real concurrency bound;
        // no further permit is taken here. An overall deadline is applied so a probe
        // cannot occupy a worker for the sum of every per-stage timeout.
        let deadline = probe_cfg.tcp_timeout + probe_cfg.tls_timeout + probe_cfg.http_timeout;
        let started = Instant::now();
        let outcome = match tokio::time::timeout(
            deadline,
            crate::probe::http::probe(&request, roots),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(crate::error::ProbeError::Connect(
                "probe deadline exceeded".into(),
            )),
        };
        let elapsed = started.elapsed();
        self.guard
            .consume_bandwidth(estimated_probe_bytes(&outcome), now);
        metrics::histogram!(
            crate::metrics::names::PROBE_SECONDS,
            "stage" => "https",
            "family" => if addr.is_ipv4() { "v4" } else { "v6" },
        )
        .record(elapsed.as_secs_f64());

        // HTTP/3 reachability, when the target advertised it and the operator enabled it.
        //
        // Recorded as a *separate*, non-penalising observation. A QUIC failure very often
        // means UDP/443 is blocked somewhere on the path, which says nothing about whether
        // the address is good for anything else — so it must never demote an address that
        // answers perfectly well over TCP.
        if probe_cfg.enable_http3 && !self.cancel.is_cancelled() {
            if let Ok(result) = &outcome {
                if result.alpn.as_deref() == Some("h2") || result.header("alt-svc").is_some() {
                    self.probe_http3(addr, port, &host, &request.path, probe_cfg, now)
                        .await;
                }
            }
        }

        match outcome {
            Ok(result) => {
                let accepted = Self::accepts(profile, &result);
                self.health.record_success();
                metrics::counter!(
                    crate::metrics::names::PROBE_RESULTS_TOTAL,
                    "stage" => "https",
                    "family" => if addr.is_ipv4() { "v4" } else { "v6" },
                    "class" => if accepted { "success" } else { "applicable_failure" },
                )
                .increment(1);

                let class = if accepted {
                    ObservationClass::Success
                } else {
                    ObservationClass::ApplicableFailure
                };
                self.record(
                    ProbeKey::https(addr, port, &host),
                    class,
                    Some(result.tcp + result.tls + result.ttfb),
                    now,
                );
                self.record(ProbeKey::generic(addr, port), class, Some(result.tcp), now);

                let colo = result.cf_colo().map(|s| s.to_string());
                match intent {
                    ProbeIntent::Baseline => {
                        self.cloudflare.set_baseline(
                            &host,
                            accepted,
                            crate::util::time::SystemClock.unix_secs_now(),
                        );
                    }
                    ProbeIntent::Validate => {
                        self.cloudflare
                            .record_validation(&host, addr, accepted, colo.clone(), now);
                        metrics::counter!(
                            crate::metrics::names::CF_DOMAIN_VALIDATIONS_TOTAL,
                            "outcome" => if accepted { "accepted" } else { "rejected" },
                        )
                        .increment(1);
                    }
                    ProbeIntent::Candidate => {}
                }
                self.cloudflare.pool().record_stage(
                    addr,
                    if accepted {
                        CandidateStage::HttpOk
                    } else {
                        CandidateStage::TlsOk
                    },
                    accepted,
                    colo,
                    now,
                );
            }
            Err(error) => {
                let class = self.health.classify(&error);
                if class == ObservationClass::ApplicableFailure {
                    self.health.record_failure();
                }
                metrics::counter!(
                    crate::metrics::names::PROBE_RESULTS_TOTAL,
                    "stage" => "https",
                    "family" => if addr.is_ipv4() { "v4" } else { "v6" },
                    "class" => class.label(),
                )
                .increment(1);
                self.record(ProbeKey::https(addr, port, &host), class, None, now);
                // A failure against one hostname says nothing about generic reachability
                // unless the very first stage failed.
                if matches!(error, ProbeError::Connect(_) | ProbeError::Timeout) {
                    self.record(ProbeKey::generic(addr, port), class, None, now);
                }
                match intent {
                    ProbeIntent::Validate => {
                        // Only an applicable failure counts against a candidate.
                        if class == ObservationClass::ApplicableFailure {
                            self.cloudflare
                                .record_validation(&host, addr, false, None, now);
                            metrics::counter!(
                                crate::metrics::names::CF_DOMAIN_VALIDATIONS_TOTAL,
                                "outcome" => "rejected",
                            )
                            .increment(1);
                        }
                    }
                    ProbeIntent::Baseline | ProbeIntent::Candidate => {}
                }
                self.cloudflare
                    .pool()
                    .record_stage(addr, CandidateStage::New, false, None, now);
            }
        }
    }

    /// Whether an HTTP outcome satisfies the configured validation profile.
    ///
    /// Without a profile the bar is deliberately modest: a completed TLS handshake with a
    /// verified certificate for the origin hostname plus any HTTP status that is not an
    /// explicit routing error. HTTP 421 (Misdirected Request) is the one status that
    /// definitively means "this edge will not serve this virtual host".
    pub fn accepts(profile: Option<&ProbeProfile>, outcome: &HttpProbeOutcome) -> bool {
        if outcome.status == 421 {
            return false;
        }
        let Some(profile) = profile else {
            return (100..600).contains(&outcome.status);
        };
        if !profile.allowed_status.contains(&outcome.status) {
            return false;
        }
        if let Some(required) = &profile.required_header {
            match outcome.header(&required.name) {
                None => return false,
                Some(value) => {
                    if let Some(expected) = &required.value {
                        if !value.eq_ignore_ascii_case(expected) {
                            return false;
                        }
                    }
                }
            }
        }
        if let Some(expected) = &profile.body_sha256 {
            if crate::util::hex_encode(&outcome.body_sha256) != expected.to_ascii_lowercase() {
                return false;
            }
        }
        if !profile.spki_sha256.is_empty() {
            let Some(leaf) = outcome.leaf.as_ref() else {
                return false;
            };
            let Some(spki) = leaf.spki_sha256 else {
                return false;
            };
            let hex = crate::util::hex_encode(&spki);
            if !profile
                .spki_sha256
                .iter()
                .any(|p| p.to_ascii_lowercase() == hex)
            {
                return false;
            }
        }
        if let Some(expected) = &profile.required_issuer_cn {
            let Some(leaf) = outcome.leaf.as_ref() else {
                return false;
            };
            match leaf.issuer_cn.as_deref() {
                Some(cn) if cn.contains(expected.as_str()) => {}
                _ => return false,
            }
        }
        true
    }

    fn record(
        &self,
        key: ProbeKey,
        class: ObservationClass,
        latency: Option<Duration>,
        now: Instant,
    ) {
        let Some(config) = self.ctx.config() else {
            return;
        };
        self.quality.record(
            key,
            class,
            latency,
            self.network.generation(),
            now,
            &config.ranking,
        );
    }
}

/// What a probe is trying to establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeIntent {
    /// Confirm that the original upstream addresses work for a hostname.
    Baseline,
    /// Confirm that a Cloudflare candidate works for a specific hostname.
    Validate,
    /// Measure a candidate against a generic Cloudflare probe host.
    Candidate,
}

impl ProbeIntent {
    fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Validate => "validate",
            Self::Candidate => "candidate",
        }
    }
}

/// Rough byte cost of one probe, used for the daily bandwidth budget.
///
/// An estimate is the honest tool here: the exact wire cost includes TLS record framing
/// and TCP overhead the probe never sees. The constant covers a typical handshake plus
/// request headers; the body is counted exactly because it is the part that varies.
fn estimated_probe_bytes(outcome: &Result<HttpProbeOutcome, crate::error::ProbeError>) -> u64 {
    const HANDSHAKE_AND_HEADERS: u64 = 6_000;
    match outcome {
        Ok(result) => {
            let headers: usize = result
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len() + 4)
                .sum();
            HANDSHAKE_AND_HEADERS + result.body.len() as u64 + headers as u64
        }
        // A failed probe still spent a connection attempt and usually a partial handshake.
        Err(_) => HANDSHAKE_AND_HEADERS / 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RequiredHeader;

    fn outcome(status: u16) -> HttpProbeOutcome {
        HttpProbeOutcome {
            tcp: Duration::from_millis(1),
            tls: Duration::from_millis(2),
            ttfb: Duration::from_millis(3),
            total: Duration::from_millis(6),
            status,
            alpn: Some("h2".into()),
            headers: vec![("server".into(), "cloudflare".into())],
            body: Vec::new(),
            body_sha256: crate::util::sha256(b""),
            leaf: None,
        }
    }

    /// Build an engine bound to a live process handle.
    ///
    /// The `Arc<App>` must be kept alive by the caller: the engine holds only a weak
    /// reference, so that dropping the process stops the engine rather than leaking it.
    fn engine_with(config: crate::config::Config) -> (Arc<crate::runtime::App>, Arc<ProbeEngine>) {
        crate::tls::install_crypto_provider();
        let (app, ctx) = crate::tasks::test_ctx(config);
        let engine = ProbeEngine::new(
            ctx,
            Arc::clone(&app.quality),
            Arc::clone(&app.cloudflare),
            Arc::clone(&app.network),
        );
        (app, engine)
    }

    #[tokio::test]
    async fn misdirected_request_is_always_rejected() {
        assert!(!ProbeEngine::accepts(None, &outcome(421)));
    }

    #[tokio::test]
    async fn without_a_profile_any_plausible_status_is_accepted() {
        for status in [200u16, 301, 403, 404, 405, 429, 500] {
            assert!(
                ProbeEngine::accepts(None, &outcome(status)),
                "status {status}"
            );
        }
    }

    #[tokio::test]
    async fn profile_status_list_is_enforced() {
        let profile = ProbeProfile {
            name: "strict".into(),
            domains: vec!["example.test".into()],
            allowed_status: vec![200],
            ..ProbeProfile::default()
        };
        assert!(ProbeEngine::accepts(Some(&profile), &outcome(200)));
        assert!(!ProbeEngine::accepts(Some(&profile), &outcome(404)));
    }

    #[tokio::test]
    async fn profile_header_requirement_is_enforced() {
        let profile = ProbeProfile {
            name: "hdr".into(),
            domains: vec!["example.test".into()],
            allowed_status: vec![200],
            required_header: Some(RequiredHeader {
                name: "server".into(),
                value: Some("cloudflare".into()),
            }),
            ..ProbeProfile::default()
        };
        assert!(ProbeEngine::accepts(Some(&profile), &outcome(200)));
        let mut wrong = outcome(200);
        wrong.headers = vec![("server".into(), "nginx".into())];
        assert!(!ProbeEngine::accepts(Some(&profile), &wrong));
    }

    #[tokio::test]
    async fn profile_body_hash_is_enforced() {
        let profile = ProbeProfile {
            name: "body".into(),
            domains: vec!["example.test".into()],
            allowed_status: vec![200],
            body_sha256: Some(crate::util::hex_encode(&crate::util::sha256(b"ok"))),
            ..ProbeProfile::default()
        };
        let mut good = outcome(200);
        good.body_sha256 = crate::util::sha256(b"ok");
        assert!(ProbeEngine::accepts(Some(&profile), &good));
        assert!(!ProbeEngine::accepts(Some(&profile), &outcome(200)));
    }

    #[tokio::test]
    async fn profile_spki_pin_requires_a_captured_certificate() {
        let pin = crate::util::hex_encode(&crate::util::sha256(b"spki"));
        let profile = ProbeProfile {
            name: "pin".into(),
            domains: vec!["example.test".into()],
            allowed_status: vec![200],
            spki_sha256: vec![pin.clone()],
            ..ProbeProfile::default()
        };
        assert!(!ProbeEngine::accepts(Some(&profile), &outcome(200)));
        let mut with_leaf = outcome(200);
        with_leaf.leaf = Some(crate::tls::CapturedLeaf {
            spki_sha256: Some(crate::util::sha256(b"spki")),
            issuer_cn: Some("Test CA".into()),
        });
        assert!(ProbeEngine::accepts(Some(&profile), &with_leaf));
        let mut wrong = with_leaf.clone();
        wrong.leaf = Some(crate::tls::CapturedLeaf {
            spki_sha256: Some(crate::util::sha256(b"other")),
            issuer_cn: Some("Test CA".into()),
        });
        assert!(!ProbeEngine::accepts(Some(&profile), &wrong));
    }

    #[tokio::test]
    async fn subsystem_health_degrades_and_recovers() {
        let h = SubsystemHealth::new(4);
        assert!(h.is_healthy());
        for _ in 0..4 {
            h.record_failure();
        }
        assert!(!h.is_healthy());
        // While degraded, every failure is ambiguous rather than a penalty.
        assert_eq!(
            h.classify(&ProbeError::Connect("refused".into())),
            ObservationClass::AmbiguousFailure
        );
        h.record_success();
        assert!(h.is_healthy());
        assert_eq!(
            h.classify(&ProbeError::Connect("refused".into())),
            ObservationClass::ApplicableFailure
        );
    }

    #[tokio::test]
    async fn quic_failures_are_never_applicable_failures() {
        let h = SubsystemHealth::new(4);
        assert_eq!(
            h.classify(&ProbeError::Quic("udp blocked".into())),
            ObservationClass::Unsupported
        );
    }

    #[tokio::test]
    async fn probe_host_selection_is_deterministic_and_spread() {
        let mut config = crate::tasks::test_config();
        config.cloudflare.probe_hosts =
            vec!["a.example".into(), "b.example".into(), "c.example".into()];
        let (app, e) = engine_with(config);
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u8 {
            let a: IpAddr = format!("104.16.0.{i}").parse().expect("ip");
            let host = e.probe_host(a);
            assert_eq!(host, e.probe_host(a), "selection must be deterministic");
            seen.insert(host);
        }
        assert!(seen.len() >= 2, "probe hosts should be spread");
        drop(app);
    }

    /// A reload that changes the probe host list must change probe host selection.
    ///
    /// The engine used to copy `ProbeConfig` at construction time, so editing
    /// `cloudflare.probe_hosts` and reloading changed nothing until the process was
    /// restarted. Selection now reads the live configuration.
    #[tokio::test]
    async fn probe_host_selection_follows_a_reload() {
        let mut config = crate::tasks::test_config();
        config.cloudflare.probe_hosts = vec!["before.example".into()];
        let (app, e) = engine_with(config.clone());
        let addr: IpAddr = "104.16.0.1".parse().expect("ip");
        assert_eq!(e.probe_host(addr), "before.example");

        config.cloudflare.probe_hosts = vec!["after.example".into()];
        app.install_for_test(config);
        assert_eq!(
            e.probe_host(addr),
            "after.example",
            "probe host selection must follow the live configuration"
        );
        drop(app);
    }

    /// Worker admission is bounded before a job leaves the queue.
    ///
    /// Acquiring the permit after spawning would let the queue depth become the real
    /// concurrency limit, since every waiting job would already be a live Tokio task.
    #[tokio::test]
    async fn worker_slots_are_sized_from_the_live_configuration() {
        let mut config = crate::tasks::test_config();
        config.probe.concurrency = 4;
        let (app, e) = engine_with(config.clone());
        assert_eq!(
            e.worker_slots().available_permits(),
            4,
            "the ceiling is the configured concurrency"
        );

        config.probe.concurrency = 9;
        app.install_for_test(config);
        assert_eq!(
            e.worker_slots().available_permits(),
            9,
            "a reload must resize the worker ceiling"
        );
        drop(app);
    }
}
