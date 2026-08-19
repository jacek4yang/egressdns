//! Cloudflare background components.
//!
//! Four independent tasks:
//!
//! * the **official prefix updater**, which is the only thing allowed to decide what
//!   "Cloudflare-owned" means;
//! * the **untrusted seed updater**, which proposes candidates and has no authority;
//! * the **bounded prefix sampler**, which proposes a small number of addresses per round;
//! * the **candidate prober**, which schedules validation work.
//!
//! Any of them can fail permanently without affecting DNS resolution.
//!
//! None of these tasks captures configuration at startup. Each re-reads
//! [`Ctx::config`](super::Ctx::config) at the top of every iteration, so a reload that
//! changes an endpoint, an interval or the operating mode takes effect on the next tick
//! instead of at the next process restart. A task whose feature is currently disabled
//! idles rather than returning, so that enabling the feature by reload starts it working
//! again without a restart.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use tokio::time::Instant;

use crate::cloudflare::candidates::{Admission, CandidateOrigin};
use crate::cloudflare::prefixes::{self, PrefixSnapshot, PrefixSource, StoredSnapshot};
use crate::cloudflare::seeds::{self, SeedItem};
use crate::cloudflare::state::{SharedCloudflare, SourceStatus};
use crate::config::CloudflareConfig;
use crate::dns::resolver::Resolver;
use crate::network::SharedNetworkState;
use crate::probe::fetch::{self, FetchOptions, HttpsUrl};
use crate::probe::job::{ProbeJob, ProbeQueue};

/// How long a disabled task waits before re-checking whether a reload enabled it.
const DISABLED_POLL: Duration = Duration::from_secs(2);

/// Keep the official prefix snapshot current.
///
/// This is the only task with authority over what counts as a Cloudflare address. Every
/// other component filters against the snapshot it publishes.
pub async fn run_prefix_updater(ctx: super::Ctx) {
    let Some(app) = ctx.app() else {
        return;
    };
    let state = Arc::clone(&app.cloudflare);
    drop(app);

    // A previously cached snapshot is better than the compiled-in bootstrap values. Read
    // it once, off the runtime threads: this is blocking file I/O on the startup path.
    if let Some(cfg) = ctx.config() {
        let cf = cfg.cloudflare.clone();
        if cf.enabled {
            if let Some(snapshot) = read_cached_snapshot(&cf).await {
                state.set_prefixes(snapshot);
            }
        }
    }

    let mut etag: Option<String> = None;
    let mut round: u64 = 0;
    let mut first = true;
    loop {
        let Some(cfg) = ctx.config() else {
            return;
        };
        let cf = cfg.cloudflare.clone();
        if !cf.enabled {
            // Idle instead of returning: `cloudflare.enabled` is reloadable, and a task
            // that returned here could never be brought back without a restart.
            if !super::tick(DISABLED_POLL, &ctx.cancel).await {
                return;
            }
            continue;
        }

        // The first refresh happens immediately; later ones are jittered around the
        // configured interval, which is re-read each round so a reload changes the
        // cadence rather than being recorded and ignored.
        if !first {
            if !super::tick(
                super::jittered(cf.official.refresh_interval, round),
                &ctx.cancel,
            )
            .await
            {
                return;
            }
            round = round.wrapping_add(1);
            // Re-read after sleeping: the configuration may have changed while we waited.
            let Some(cfg) = ctx.config() else {
                return;
            };
            if !cfg.cloudflare.enabled {
                continue;
            }
        }
        first = false;

        let (Some(resolver), Some(rt)) = (ctx.resolver(), ctx.state()) else {
            return;
        };
        let roots = Arc::clone(&rt.roots);
        drop(rt);

        match update_prefixes(&cf, &state, &resolver, roots, etag.clone()).await {
            Ok(Some(new_etag)) => etag = Some(new_etag),
            Ok(None) => {}
            // A failed refresh keeps the last valid snapshot; the failure is already
            // recorded as source status and as a metric.
            Err(()) => {}
        }
        // Administrator-supplied candidates are admitted against whatever snapshot is
        // current, so a newly published prefix can rescue an address that was refused
        // on an earlier round.
        admit_static_candidates(&cf, &state, &ctx);
    }
}

/// Read the on-disk prefix cache without blocking a runtime worker.
///
/// Returns `None` unless the file exists, parses, and passes the same validation an
/// online refresh would have to pass. A corrupt or implausible cache must not be able to
/// shrink the trusted prefix set.
async fn read_cached_snapshot(cfg: &CloudflareConfig) -> Option<PrefixSnapshot> {
    let path: PathBuf = cfg.official.cache_file.clone()?;
    let min_v4 = cfg.official.min_ipv4_prefixes;
    let min_v6 = cfg.official.min_ipv6_prefixes;
    tokio::task::spawn_blocking(move || {
        let text = std::fs::read_to_string(&path).ok()?;
        let stored: StoredSnapshot = serde_json::from_str(&text).ok()?;
        let snapshot = PrefixSnapshot::from_stored(&stored, PrefixSource::LocalCache).ok()?;
        prefixes::validate_snapshot(&snapshot, None, min_v4, min_v6).ok()?;
        Some(snapshot)
    })
    .await
    .ok()
    .flatten()
}

/// Admit `cloudflare.static_candidates` against the current official snapshot.
///
/// These are administrator-supplied addresses, so they get [`CandidateOrigin::Config`]
/// and no hourly budget — but they are *not* exempt from prefix ownership. An address
/// that is not inside a current official Cloudflare prefix is refused here exactly as a
/// seed address would be.
fn admit_static_candidates(cfg: &CloudflareConfig, state: &SharedCloudflare, ctx: &super::Ctx) {
    if cfg.static_candidates.is_empty() {
        return;
    }
    let Some(app) = ctx.app() else {
        return;
    };
    let generation = app.network.generation();
    let probes = app.probes.clone();
    drop(app);
    let snapshot = state.prefixes();
    let now = Instant::now();
    for addr in &cfg.static_candidates {
        match state.pool().admit(
            *addr,
            CandidateOrigin::Config,
            snapshot.as_ref().as_ref(),
            generation,
            now,
            None,
        ) {
            Admission::Added => {
                probes.offer(ProbeJob::Candidate {
                    addr: *addr,
                    port: 443,
                    generation,
                });
            }
            Admission::Refreshed => {}
            Admission::Rejected(reason) => {
                metrics::counter!(
                    crate::metrics::names::CF_CANDIDATE_REJECTED_TOTAL,
                    "reason" => reason.label(),
                    "source" => "config",
                )
                .increment(1);
                tracing::warn!(
                    event = "cloudflare.static_candidate_rejected",
                    addr = %addr,
                    reason = reason.label(),
                    "configured candidate is not a currently owned Cloudflare address"
                );
            }
        }
    }
}
async fn update_prefixes(
    cfg: &CloudflareConfig,
    state: &SharedCloudflare,
    resolver: &Arc<Resolver>,
    roots: Arc<RootCertStore>,
    etag: Option<String>,
) -> Result<Option<String>, ()> {
    let now_unix = crate::util::time::SystemClock.unix_secs_now();
    // Reading the token touches the filesystem. Doing that on a runtime worker stalls
    // every future scheduled on it, including foreground queries.
    let token_file = cfg.official.api_token_file.clone();
    let token_env = cfg.official.api_token_env.clone();
    let token = tokio::task::spawn_blocking(move || {
        crate::config::read_secret(token_file.as_ref(), token_env.as_ref())
            .ok()
            .flatten()
    })
    .await
    .ok()
    .flatten();

    let url = match HttpsUrl::parse(&cfg.official.api_url) {
        Ok(u) => u,
        Err(e) => {
            record_failure(state, "cloudflare-api", &e.to_string(), now_unix);
            return Err(());
        }
    };
    let addresses = resolver.lookup_addresses(&url.host).await;
    let options = FetchOptions {
        max_bytes: cfg.official.max_response_bytes,
        timeout: cfg.official.timeout,
        etag,
        last_modified: None,
        bearer: token,
    };
    let result = match fetch::fetch(&url, &addresses, Arc::clone(&roots), &options).await {
        Ok(r) => r,
        Err(e) => {
            record_failure(state, "cloudflare-api", &e.to_string(), now_unix);
            return Err(());
        }
    };
    if result.status == 304 {
        record_success(state, "cloudflare-api", 0, 0, now_unix);
        return Ok(None);
    }
    if result.status != 200 {
        record_failure(
            state,
            "cloudflare-api",
            &format!("unexpected status {}", result.status),
            now_unix,
        );
        return Err(());
    }

    let candidate = match prefixes::parse_api_json(&result.body, now_unix) {
        Ok(s) => s,
        Err(e) => {
            record_failure(state, "cloudflare-api", &e.to_string(), now_unix);
            return Err(());
        }
    };
    let previous = state.prefixes();
    if let Err(e) = prefixes::validate_snapshot(
        &candidate,
        previous.as_ref().as_ref(),
        cfg.official.min_ipv4_prefixes,
        cfg.official.min_ipv6_prefixes,
    ) {
        record_failure(state, "cloudflare-api", &e.to_string(), now_unix);
        return Err(());
    }

    // Cross-check against the plain-text lists. Disagreement is reported, never fatal.
    if let (Ok(v4_url), Ok(v6_url)) = (
        HttpsUrl::parse(&cfg.official.ipv4_url),
        HttpsUrl::parse(&cfg.official.ipv6_url),
    ) {
        let v4_addrs = resolver.lookup_addresses(&v4_url.host).await;
        let text_opts = FetchOptions {
            max_bytes: cfg.official.max_response_bytes,
            timeout: cfg.official.timeout,
            ..FetchOptions::default()
        };
        let v4 = fetch::fetch(&v4_url, &v4_addrs, Arc::clone(&roots), &text_opts).await;
        let v6_addrs = resolver.lookup_addresses(&v6_url.host).await;
        let v6 = fetch::fetch(&v6_url, &v6_addrs, Arc::clone(&roots), &text_opts).await;
        if let (Ok(v4), Ok(v6)) = (v4, v6) {
            let parsed_v4 =
                prefixes::parse_text_list(&v4.body).and_then(|lines| prefixes::text_to_v4(&lines));
            let parsed_v6 =
                prefixes::parse_text_list(&v6.body).and_then(|lines| prefixes::text_to_v6(&lines));
            if let (Ok(a), Ok(b)) = (parsed_v4, parsed_v6) {
                let notes = prefixes::cross_check(&candidate, &a, &b);
                if !notes.is_empty() {
                    tracing::info!(
                        event = "cloudflare.prefix_cross_check",
                        differences = notes.len(),
                        first = %notes[0],
                        "official sources disagree; the API snapshot wins"
                    );
                }
                record_success(
                    state,
                    "cloudflare-text-lists",
                    a.len() + b.len(),
                    0,
                    now_unix,
                );
            }
        }
    }

    let new_etag = candidate.etag.clone().or(result.etag.clone());
    let ipv4 = candidate.ipv4().len();
    let ipv6 = candidate.ipv6().len();
    if let Some(path) = cfg.official.cache_file.clone() {
        let stored = candidate.to_stored();
        if let Ok(text) = serde_json::to_string(&stored) {
            // Write to a sibling temporary file and rename. A crash or a full disk
            // partway through a direct write would leave a truncated JSON document that
            // the next start would silently refuse to parse, quietly losing the cache.
            let _ = tokio::task::spawn_blocking(move || {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let tmp = path.with_extension("json.tmp");
                if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, &path).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                }
            })
            .await;
        }
    }
    state.set_prefixes(candidate);
    record_success(state, "cloudflare-api", ipv4 + ipv6, 0, now_unix);
    metrics::counter!(
        crate::metrics::names::CF_SOURCE_UPDATES_TOTAL,
        "source" => "cloudflare-api",
        "outcome" => "ok",
    )
    .increment(1);
    Ok(new_etag)
}

/// Poll the untrusted candidate seed endpoints.
///
/// Seed endpoints have no authority: everything they propose is filtered against the
/// official prefix snapshot before it can become a candidate, and probed before it can
/// become an answer.
pub async fn run_seed_updater(ctx: super::Ctx) {
    let Some(app) = ctx.app() else {
        return;
    };
    let state = Arc::clone(&app.cloudflare);
    let network = Arc::clone(&app.network);
    let probes = app.probes.clone();
    drop(app);

    let mut round: u64 = 0;
    loop {
        let Some(cfg) = ctx.config() else {
            return;
        };
        let cf = cfg.cloudflare.clone();
        if !cf.enabled || !cf.seeds.enabled {
            if !super::tick(DISABLED_POLL, &ctx.cancel).await {
                return;
            }
            continue;
        }

        let (Some(resolver), Some(rt)) = (ctx.resolver(), ctx.state()) else {
            return;
        };
        let roots = Arc::clone(&rt.roots);
        drop(rt);

        for endpoint in cf.seeds.endpoints.iter().filter(|e| e.enabled) {
            if ctx.cancel.is_cancelled() {
                return;
            }
            let _ = poll_seed(
                &cf,
                endpoint,
                &state,
                &resolver,
                Arc::clone(&roots),
                &network,
                &probes,
            )
            .await;
        }
        round = round.wrapping_add(1);
        if !super::tick(
            super::jittered(cf.seeds.refresh_interval, round),
            &ctx.cancel,
        )
        .await
        {
            return;
        }
    }
}
async fn poll_seed(
    cfg: &CloudflareConfig,
    endpoint: &crate::config::SeedEndpoint,
    state: &SharedCloudflare,
    resolver: &Arc<Resolver>,
    roots: Arc<RootCertStore>,
    network: &SharedNetworkState,
    probes: &ProbeQueue,
) -> Result<(), ()> {
    let now_unix = crate::util::time::SystemClock.unix_secs_now();
    let name: Arc<str> = Arc::from(endpoint.name.as_str());
    let url = match HttpsUrl::parse(&endpoint.url) {
        Ok(u) => u,
        Err(e) => {
            record_failure(state, &name, &e.to_string(), now_unix);
            return Err(());
        }
    };
    let addresses = resolver.lookup_addresses(&url.host).await;
    let options = FetchOptions {
        max_bytes: cfg.seeds.max_response_bytes,
        timeout: cfg.seeds.timeout,
        ..FetchOptions::default()
    };
    let result = match fetch::fetch(&url, &addresses, roots, &options).await {
        Ok(r) => r,
        Err(e) => {
            record_failure(state, &name, &e.to_string(), now_unix);
            return Err(());
        }
    };
    if result.status != 200 {
        record_failure(
            state,
            &name,
            &format!("unexpected status {}", result.status),
            now_unix,
        );
        return Err(());
    }
    let (items, stats) = match seeds::parse(&result.body, cfg.seeds.max_addresses_per_response) {
        Ok(v) => v,
        Err(e) => {
            record_failure(state, &name, &e.to_string(), now_unix);
            return Err(());
        }
    };

    let generation = network.generation();
    let now = Instant::now();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for item in items {
        let addrs: Vec<IpAddr> = match item {
            SeedItem::Address { addr, .. } => vec![addr],
            SeedItem::Hostname { host, .. } => {
                if !cfg.seeds.resolve_hostnames {
                    continue;
                }
                resolver.lookup_addresses(&host).await
            }
        };
        for addr in addrs {
            let snapshot = state.prefixes();
            match state.pool().admit(
                addr,
                CandidateOrigin::Seed,
                snapshot.as_ref().as_ref(),
                generation,
                now,
                None,
            ) {
                Admission::Added => {
                    accepted += 1;
                    probes.offer(ProbeJob::Candidate {
                        addr,
                        port: 443,
                        generation,
                    });
                }
                Admission::Refreshed => accepted += 1,
                Admission::Rejected(reason) => {
                    rejected += 1;
                    metrics::counter!(
                        crate::metrics::names::CF_CANDIDATE_REJECTED_TOTAL,
                        "reason" => reason.label(),
                        "source" => "seed",
                    )
                    .increment(1);
                    tracing::debug!(
                        event = "cloudflare.candidate_rejected",
                        source = %name,
                        reason = reason.label(),
                        "external candidate refused"
                    );
                }
            }
        }
    }
    tracing::info!(
        event = "cloudflare.seed_update",
        source = %name,
        accepted,
        rejected,
        malformed = stats.malformed,
        truncated = stats.truncated,
    );
    record_success(state, &name, accepted, rejected, now_unix);
    metrics::counter!(
        crate::metrics::names::CF_SOURCE_UPDATES_TOTAL,
        "source" => "seed",
        "outcome" => "ok",
    )
    .increment(1);
    Ok(())
}

/// Propose a bounded number of sampled addresses each round.
///
/// Sampling is IPv4-only by construction: the official IPv6 space is far too large for
/// random traversal to find anything, so IPv6 candidates come from observed answers and
/// seed lists instead.
pub async fn run_sampler(ctx: super::Ctx) {
    let Some(app) = ctx.app() else {
        return;
    };
    let state = Arc::clone(&app.cloudflare);
    let network = Arc::clone(&app.network);
    let probes = app.probes.clone();
    drop(app);

    let mut round: u64 = 0;
    loop {
        let Some(cfg) = ctx.config() else {
            return;
        };
        let cf = cfg.cloudflare.clone();
        if !cf.enabled || !cf.sampling.enabled {
            if !super::tick(DISABLED_POLL, &ctx.cancel).await {
                return;
            }
            continue;
        }
        if !super::tick(
            super::jittered(cf.sampling.round_interval, round),
            &ctx.cancel,
        )
        .await
        {
            return;
        }
        round = round.wrapping_add(1);

        // Re-read after sleeping: a reload during the interval must be honoured before
        // any addresses are proposed.
        let Some(cfg) = ctx.config() else {
            return;
        };
        let cf = &cfg.cloudflare;
        if !cf.enabled || !cf.sampling.enabled {
            continue;
        }

        let snapshot = state.prefixes();
        let Some(snapshot) = snapshot.as_ref().as_ref() else {
            continue;
        };
        let generation = network.generation();
        let now = Instant::now();
        let hourly = cf.sampling.max_new_candidates_per_hour;
        for addr in state
            .sampler()
            .next_round(snapshot, cf.sampling.addresses_per_round)
        {
            let ip = IpAddr::V4(addr);
            match state.pool().admit(
                ip,
                CandidateOrigin::Sampling,
                Some(snapshot),
                generation,
                now,
                Some(hourly),
            ) {
                Admission::Added => {
                    probes.offer(ProbeJob::Candidate {
                        addr: ip,
                        port: 443,
                        generation,
                    });
                }
                Admission::Refreshed => {}
                Admission::Rejected(reason) => {
                    metrics::counter!(
                        crate::metrics::names::CF_CANDIDATE_REJECTED_TOTAL,
                        "reason" => reason.label(),
                        "source" => "sampling",
                    )
                    .increment(1);
                }
            }
        }
    }
}

/// Schedule re-probing of known candidates and domain-level validation for hot domains.
pub async fn run_candidate_prober(ctx: super::Ctx) {
    let Some(app) = ctx.app() else {
        return;
    };
    let state = Arc::clone(&app.cloudflare);
    let hotset = Arc::clone(&app.hotset);
    let network = Arc::clone(&app.network);
    let probes = app.probes.clone();
    drop(app);

    let mut round: u64 = 0;
    loop {
        if !super::tick(super::jittered(Duration::from_secs(60), round), &ctx.cancel).await {
            return;
        }
        round = round.wrapping_add(1);

        let Some(cfg) = ctx.config() else {
            return;
        };
        let cf = &cfg.cloudflare;
        let probe_cfg = &cfg.probe;
        // Both switches are reloadable, so this is a per-round check rather than a
        // startup decision: turning probing back on must not require a restart.
        if !cf.enabled || !probe_cfg.enabled {
            continue;
        }

        let now = Instant::now();
        let generation = network.generation();

        // Re-measure known candidates that are out of cooldown.
        for candidate in state.pool().due_for_probe(
            probe_cfg.per_ip_cooldown,
            now,
            probe_cfg.http_concurrency * 2,
        ) {
            probes.offer(ProbeJob::Candidate {
                addr: candidate.addr,
                port: 443,
                generation,
            });
        }

        // Validate the best candidates against the hottest Cloudflare-hosted names.
        if cf.mode == crate::config::CloudflareMode::VerifiedAugment {
            let eligible_v4 = state.pool().eligible(true, 1);
            let eligible_v6 = state.pool().eligible(false, 1);
            for (key, _) in hotset.top(32) {
                if !matches!(
                    key.qtype,
                    hickory_proto::rr::RecordType::A | hickory_proto::rr::RecordType::AAAA
                ) {
                    continue;
                }
                let host: Arc<str> = Arc::clone(&key.name);
                if crate::policy::cloudflare::is_excluded(
                    &host,
                    &cf.allow_domains,
                    &cf.deny_domains,
                ) {
                    continue;
                }
                let pool = if key.qtype == hickory_proto::rr::RecordType::A {
                    &eligible_v4
                } else {
                    &eligible_v6
                };
                for candidate in pool.iter().take(cf.augment.max_added + 2) {
                    probes.offer(ProbeJob::Validate {
                        hostname: Arc::clone(&host),
                        addr: candidate.addr,
                        port: 443,
                        generation,
                    });
                }
            }
        }
    }
}

fn record_success(
    state: &SharedCloudflare,
    name: &str,
    accepted: usize,
    rejected: usize,
    now_unix: u64,
) {
    state.record_source(SourceStatus {
        name: Arc::from(name),
        ok: true,
        detail: String::new(),
        attempted_unix: now_unix,
        succeeded_unix: Some(now_unix),
        accepted,
        rejected,
    });
}

fn record_failure(state: &SharedCloudflare, name: &str, detail: &str, now_unix: u64) {
    let previous = state
        .sources()
        .into_iter()
        .find(|s| &*s.name == name)
        .and_then(|s| s.succeeded_unix);
    tracing::warn!(
        event = "cloudflare.source_failed",
        source = name,
        error = %crate::util::bounded(detail, 160),
        "keeping the last valid data"
    );
    metrics::counter!(
        crate::metrics::names::CF_SOURCE_UPDATES_TOTAL,
        "source" => name.to_string(),
        "outcome" => "error",
    )
    .increment(1);
    state.record_source(SourceStatus {
        name: Arc::from(name),
        ok: false,
        detail: crate::util::bounded(detail, 160),
        attempted_unix: now_unix,
        succeeded_unix: previous,
        accepted: 0,
        rejected: 0,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::state::CloudflareState;
    use crate::config::CloudflareMode;
    use std::net::Ipv4Addr;

    fn state() -> SharedCloudflare {
        Arc::new(CloudflareState::new(&CloudflareConfig {
            enabled: true,
            mode: CloudflareMode::VerifiedAugment,
            ..CloudflareConfig::default()
        }))
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_source_keeps_the_previous_snapshot() {
        let s = state();
        let before = s.prefixes();
        let before_len = before.as_ref().as_ref().expect("snapshot").len();
        record_failure(&s, "cloudflare-api", "connection refused", 100);
        let after = s.prefixes();
        assert_eq!(after.as_ref().as_ref().expect("snapshot").len(), before_len);
        let status = s
            .sources()
            .into_iter()
            .find(|x| &*x.name == "cloudflare-api")
            .expect("status");
        assert!(!status.ok);
        assert!(status.detail.contains("connection refused"));
    }

    #[tokio::test(start_paused = true)]
    async fn source_status_records_success_time() {
        let s = state();
        record_success(&s, "ct", 5, 2, 1_000);
        let status = s
            .sources()
            .into_iter()
            .find(|x| &*x.name == "ct")
            .expect("status");
        assert!(status.ok);
        assert_eq!(status.accepted, 5);
        assert_eq!(status.rejected, 2);
        assert_eq!(status.succeeded_unix, Some(1_000));
        // A later failure preserves the last success time.
        record_failure(&s, "ct", "timeout", 2_000);
        let status = s
            .sources()
            .into_iter()
            .find(|x| &*x.name == "ct")
            .expect("status");
        assert_eq!(status.succeeded_unix, Some(1_000));
    }

    /// A disabled task must keep running so that a later reload can enable it.
    ///
    /// The previous implementation returned immediately, which meant
    /// `cloudflare.enabled = false` at startup silently made the setting
    /// restart-required. Here the task is still alive after several disabled polls.
    #[tokio::test(start_paused = true)]
    async fn a_disabled_task_idles_instead_of_exiting() {
        let mut cfg = crate::tasks::test_config();
        cfg.cloudflare.enabled = false;
        let (app, ctx) = crate::tasks::test_ctx(cfg);
        let handle = tokio::spawn(run_sampler(ctx.clone()));
        for _ in 0..5 {
            tokio::time::advance(DISABLED_POLL * 2).await;
            tokio::task::yield_now().await;
        }
        assert!(!handle.is_finished(), "a disabled task must not exit");
        ctx.cancel.cancel();
        tokio::time::advance(DISABLED_POLL * 2).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .is_ok(),
            "a cancelled task must stop"
        );
        drop(app);
    }

    /// Losing the process must stop the task even if it was never cancelled.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_process_stops_the_task() {
        let (app, ctx) = crate::tasks::test_ctx(crate::tasks::test_config());
        drop(app);
        let handle = tokio::spawn(run_prefix_updater(ctx));
        assert!(
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .is_ok(),
            "a task holding only a dead Weak must return"
        );
    }

    /// `cloudflare.static_candidates` is a real setting, not a decoration.
    ///
    /// An address inside a current official prefix is admitted with
    /// [`CandidateOrigin::Config`]; one outside every official prefix is refused, because
    /// administrator intent does not make an address Cloudflare-owned.
    #[tokio::test(start_paused = true)]
    async fn static_candidates_are_admitted_but_still_prefix_checked() {
        let (app, ctx) = crate::tasks::test_ctx(crate::tasks::test_config());
        let s = Arc::clone(&app.cloudflare);
        let snapshot = s.prefixes();
        let owned = snapshot
            .as_ref()
            .as_ref()
            .expect("bootstrap snapshot")
            .ipv4()
            .first()
            .map(|net| IpAddr::V4(net.network()))
            .expect("at least one official IPv4 prefix");
        assert!(
            crate::util::ipclass::classify(owned).is_none(),
            "the bootstrap prefix used by this test must be globally routable"
        );
        // 192.0.2.0/24 is TEST-NET-1 and can never be a Cloudflare prefix.
        let foreign = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));

        let cfg = CloudflareConfig {
            enabled: true,
            static_candidates: vec![owned, foreign],
            ..CloudflareConfig::default()
        };
        admit_static_candidates(&cfg, &s, &ctx);

        let admitted = s.pool().get(owned).expect("owned address must be admitted");
        assert_eq!(
            admitted.origin,
            CandidateOrigin::Config,
            "a configured address must be attributed to the configuration"
        );
        assert!(
            s.pool().get(foreign).is_none(),
            "a configured address outside every official prefix must be refused"
        );
        drop(app);
    }
}
