//! Process assembly: shared state, atomic reload and background supervision.
//!
//! Long-lived state (caches, quality evidence, network generation, Cloudflare data,
//! persistence) survives a configuration reload. Everything derived from configuration
//! (ACLs, rate limiters, upstream routes, the resolver itself) is rebuilt and swapped
//! atomically, so an in-flight query either sees the whole old configuration or the whole
//! new one, never a mixture.

pub mod observe;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::RootCertStore;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::cache::hotset::{HotSet, SharedHotSet};
use crate::cache::singleflight::SingleFlight;
use crate::cache::{CacheEntry, CacheKey, DnsCache};
use crate::cloudflare::state::{CloudflareState, SharedCloudflare};
use crate::config::Config;
use crate::datasets::{DatasetStore, SharedDatasets};
use crate::dns::acl::Acl;
use crate::dns::ratelimit::InboundLimiter;
use crate::dns::resolver::Resolver;
use crate::error::ConfigError;
use crate::network::{NetworkState, SharedNetworkState};
use crate::probe::engine::ProbeEngine;
use crate::probe::job::{ProbeJob, ProbeQueue};
use crate::ranking::{ProbeKey, QualityStore};
use crate::storage::Storage;
use crate::tasks::prefetch::PrefetchState;
use crate::upstream::pool::UpstreamRegistry;
use crate::upstream::scheduler::Scheduler;

/// Everything derived from the active configuration.
pub struct RuntimeState {
    /// The active configuration.
    pub config: Arc<Config>,
    /// Client access control.
    pub acl: Arc<Acl>,
    /// Inbound rate limiting.
    pub limiter: Arc<InboundLimiter>,
    /// Upstream routes.
    pub registry: Arc<UpstreamRegistry>,
    /// Adaptive scheduler.
    pub scheduler: Arc<Scheduler>,
    /// Foreground resolver.
    pub resolver: Arc<Resolver>,
    /// TLS roots.
    pub roots: Arc<RootCertStore>,
}

/// The assembled process.
pub struct App {
    state: ArcSwap<RuntimeState>,
    /// Answer, negative, failure and variant caches.
    pub cache: Arc<DnsCache>,
    /// Request coalescing.
    pub singleflight: Arc<SingleFlight<CacheKey, Arc<CacheEntry>>>,
    /// Address quality evidence.
    pub quality: Arc<QualityStore>,
    /// Which names are known to be web services. Long-lived learned state, so it is owned
    /// by the process rather than rebuilt from configuration on every reload.
    pub services: crate::ranking::service::SharedServiceClassifier,
    /// Hot-name tracking.
    pub hotset: SharedHotSet,
    /// Dataset snapshots.
    pub datasets: SharedDatasets,
    /// Network generation and family state.
    pub network: SharedNetworkState,
    /// Cloudflare optimization state.
    pub cloudflare: SharedCloudflare,
    /// Persistent state.
    pub storage: Arc<Storage>,
    /// Probe work queue.
    pub probes: ProbeQueue,
    /// Prefetcher control.
    pub prefetch: Arc<PrefetchState>,
    /// Concurrency ceiling for in-flight client queries.
    pub inflight: Arc<Semaphore>,
    /// Shutdown token.
    pub cancel: CancellationToken,
    /// Path the configuration was loaded from.
    pub config_path: PathBuf,
    /// Wall-clock second the process started.
    pub started_unix: u64,
    /// Whether the daemon is ready to answer queries.
    ready: AtomicBool,
    /// Successful reload count.
    reloads: AtomicU64,
    /// Description of the most recent failed reload.
    last_reload_error: Mutex<Option<String>>,
    /// Probe engine, kept so its health can be reported.
    probe_engine: Mutex<Option<Arc<ProbeEngine>>>,
    /// Every supervised background task, so shutdown can actually wait for them.
    background: Mutex<crate::tasks::Supervisor>,
    /// Global ceiling on concurrent upstream queries, across every path that issues one.
    pub upstream_slots: Arc<Semaphore>,
    /// Global ceiling on concurrent DNSSEC validations.
    pub validation_slots: Arc<Semaphore>,
}

impl App {
    /// Build the process from a configuration file.
    pub fn build(config_path: &Path) -> Result<Arc<Self>, ConfigError> {
        let config = Arc::new(Config::load(config_path)?);
        Self::from_config(config, config_path.to_path_buf())
    }

    /// Build the process from an already-validated configuration.
    pub fn from_config(
        config: Arc<Config>,
        config_path: PathBuf,
    ) -> Result<Arc<Self>, ConfigError> {
        crate::tls::install_crypto_provider();

        let cache = Arc::new(DnsCache::new(&config.cache, &config.serve_stale));
        let singleflight =
            SingleFlight::new(64, (config.resources.max_inflight_queries / 64).max(64));
        let quality = Arc::new(QualityStore::new(config.cache.quality_max_entries as usize));
        let services: crate::ranking::service::SharedServiceClassifier = Arc::new(
            crate::ranking::service::ServiceClassifier::new(config.prefetch.hot_set_size),
        );
        let hotset: SharedHotSet = Arc::new(HotSet::new(
            config.prefetch.hot_set_size,
            600.0,
            if config.prefetch.transition_prediction {
                config.prefetch.transition_table_size
            } else {
                0
            },
        ));
        let datasets: SharedDatasets = Arc::new(DatasetStore::new());
        let network: SharedNetworkState = Arc::new(NetworkState::new());
        let cloudflare: SharedCloudflare = Arc::new(CloudflareState::new(&config.cloudflare));
        let storage = Storage::open(&config.storage);
        let cancel = CancellationToken::new();

        // Load the first dataset snapshot synchronously so that the very first query can
        // already see internal zones and hosts entries.
        let now_unix = crate::util::time::SystemClock.unix_secs_now();
        match crate::datasets::build(&config.datasets, &config.local, now_unix) {
            Ok(snapshot) => datasets.publish(Arc::new(snapshot)),
            Err(e) => {
                tracing::warn!(event = "dataset.initial_load_failed", error = %e);
            }
        }

        // The channel exists regardless of `probe.enabled`, and the queue carries a live
        // enable flag instead. Building it conditionally would make `probe.enabled` a
        // startup-only setting, which is precisely the class of dishonest reload this
        // design rejects.
        let (probe_tx, probe_rx) = mpsc::channel::<ProbeJob>(config.probe.queue_size);
        let probes = ProbeQueue::new(probe_tx, config.probe.enabled);

        let inflight = Arc::new(Semaphore::new(config.resources.max_inflight_queries));
        // Every physical upstream exchange, from every path, takes one of these. Without
        // a single shared ceiling, background work (prefetch, stale refresh, DNSSEC
        // auxiliary lookups) multiplies the real fan-out far past whatever the operator
        // configured.
        let upstream_slots = Arc::new(Semaphore::new(config.resources.max_inflight_upstream));
        let validation_slots = Arc::new(Semaphore::new(config.dnssec.max_concurrent_validations));
        let prefetch = Arc::new(PrefetchState::new(config.prefetch.enabled));

        let state = Self::build_state(
            Arc::clone(&config),
            Arc::clone(&cache),
            Arc::clone(&singleflight),
            Arc::clone(&datasets),
            Arc::clone(&network),
            Arc::clone(&cloudflare),
            Arc::clone(&quality),
            Arc::clone(&services),
            Arc::clone(&hotset),
            probes.clone(),
            Arc::clone(&upstream_slots),
            Arc::clone(&validation_slots),
        )?;

        let app = Arc::new(Self {
            state: ArcSwap::from_pointee(state),
            cache,
            singleflight,
            quality,
            services,
            hotset,
            datasets,
            network,
            cloudflare,
            storage,
            probes,
            prefetch,
            inflight,
            cancel,
            config_path,
            started_unix: now_unix,
            ready: AtomicBool::new(false),
            reloads: AtomicU64::new(0),
            last_reload_error: Mutex::new(None),
            probe_engine: Mutex::new(None),
            background: Mutex::new(crate::tasks::Supervisor::new()),
            upstream_slots,
            validation_slots,
        });

        app.restore_persisted_state();
        app.spawn_probe_engine(probe_rx);
        Ok(app)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_state(
        config: Arc<Config>,
        cache: Arc<DnsCache>,
        singleflight: Arc<SingleFlight<CacheKey, Arc<CacheEntry>>>,
        datasets: SharedDatasets,
        network: SharedNetworkState,
        cloudflare: SharedCloudflare,
        quality: Arc<QualityStore>,
        services: crate::ranking::service::SharedServiceClassifier,
        hotset: SharedHotSet,
        probes: ProbeQueue,
        upstream_slots: Arc<Semaphore>,
        validation_slots: Arc<Semaphore>,
    ) -> Result<RuntimeState, ConfigError> {
        let roots = Arc::new(
            crate::tls::root_store(
                config.upstream.tls.use_system_roots,
                &config.upstream.tls.extra_ca_files,
            )
            .map_err(|e| ConfigError::invalid("upstream.tls", e.to_string()))?,
        );
        let query_timeout = config
            .upstream
            .groups
            .iter()
            .map(|g| g.scheduler.query_timeout)
            .min()
            .unwrap_or(Duration::from_millis(1_500));
        let registry = Arc::new(
            UpstreamRegistry::build(
                &config.upstream,
                &config.proxy,
                Arc::clone(&roots),
                query_timeout,
                config.server.udp.max_payload,
            )
            .map_err(|e| ConfigError::invalid("upstream", e.to_string()))?,
        );
        let scheduler = Arc::new(Scheduler::new(
            Arc::clone(&registry),
            Arc::clone(&network),
            upstream_slots,
            config.network.relearn_window,
        ));
        let acl = Arc::new(Acl::new(
            config.effective_allow_from(),
            config.server.deny_from.clone(),
        ));
        let limiter = Arc::new(InboundLimiter::new(&config.server.rate_limit));
        let resolver = Arc::new(Resolver::new(
            Arc::clone(&config),
            cache,
            singleflight,
            Arc::clone(&scheduler),
            datasets,
            network,
            cloudflare,
            quality,
            services,
            hotset,
            probes,
            Arc::clone(&roots),
            validation_slots,
        )?);
        Ok(RuntimeState {
            config,
            acl,
            limiter,
            registry,
            scheduler,
            resolver,
            roots,
        })
    }

    /// Current runtime state. One atomic load; safe on the hot path.
    pub fn state(&self) -> Arc<RuntimeState> {
        self.state.load_full()
    }

    /// Active configuration.
    pub fn config(&self) -> Arc<Config> {
        self.state.load().config.clone()
    }

    /// Swap in a new runtime state built from `config`, for tests.
    ///
    /// This is the same swap a reload performs, without the restart-required check or the
    /// listener plumbing, so a test can assert that a component follows the live
    /// configuration rather than a copy it took at construction time.
    #[cfg(test)]
    pub(crate) fn install_for_test(&self, config: Config) {
        let config = Arc::new(config);
        let state = Self::build_state(
            Arc::clone(&config),
            Arc::clone(&self.cache),
            Arc::clone(&self.singleflight),
            Arc::clone(&self.datasets),
            Arc::clone(&self.network),
            Arc::clone(&self.cloudflare),
            Arc::clone(&self.quality),
            Arc::clone(&self.services),
            Arc::clone(&self.hotset),
            self.probes.clone(),
            Arc::clone(&self.upstream_slots),
            Arc::clone(&self.validation_slots),
        )
        .expect("test configuration builds a runtime state");
        self.state.store(Arc::new(state));
        self.cloudflare.reconfigure(&config.cloudflare);
    }

    /// Whether the daemon is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Mark the daemon ready or not ready.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
        metrics::gauge!(crate::metrics::names::READY).set(if ready { 1.0 } else { 0.0 });
    }

    /// Successful reload count.
    pub fn reload_count(&self) -> u64 {
        self.reloads.load(Ordering::Relaxed)
    }

    /// Description of the last failed reload.
    pub fn last_reload_error(&self) -> Option<String> {
        self.last_reload_error.lock().clone()
    }

    /// Probe subsystem health, when the engine is running.
    pub fn probe_healthy(&self) -> Option<bool> {
        self.probe_engine
            .lock()
            .as_ref()
            .map(|e| e.health().is_healthy())
    }

    /// Validate and activate a new configuration.
    ///
    /// The candidate configuration is fully parsed, validated and used to build a complete
    /// replacement state *before* anything is swapped. If any step fails, the running
    /// configuration is untouched.
    pub fn reload(&self) -> Result<(), String> {
        let candidate = match Config::load(&self.config_path) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                let text = e.to_string();
                *self.last_reload_error.lock() = Some(text.clone());
                metrics::counter!(
                    crate::metrics::names::CONFIG_RELOADS_TOTAL,
                    "outcome" => "invalid",
                )
                .increment(1);
                return Err(text);
            }
        };

        // The reload contract: a field that cannot take effect live must not be silently
        // accepted. Refusing leaves the running configuration exactly as it was.
        let blocking = crate::config::reload::restart_required(&self.config(), &candidate);
        if !blocking.is_empty() {
            let text = crate::config::reload::describe(&blocking);
            *self.last_reload_error.lock() = Some(text.clone());
            metrics::counter!(
                crate::metrics::names::CONFIG_RELOADS_TOTAL,
                "outcome" => "restart_required",
            )
            .increment(1);
            tracing::warn!(
                event = "config.reload_refused",
                fields = blocking.len(),
                "reload requires a restart"
            );
            return Err(text);
        }

        let new_state = match Self::build_state(
            Arc::clone(&candidate),
            Arc::clone(&self.cache),
            Arc::clone(&self.singleflight),
            Arc::clone(&self.datasets),
            Arc::clone(&self.network),
            Arc::clone(&self.cloudflare),
            Arc::clone(&self.quality),
            Arc::clone(&self.services),
            Arc::clone(&self.hotset),
            self.probes.clone(),
            Arc::clone(&self.upstream_slots),
            Arc::clone(&self.validation_slots),
        ) {
            Ok(s) => s,
            Err(e) => {
                let text = e.to_string();
                *self.last_reload_error.lock() = Some(text.clone());
                metrics::counter!(
                    crate::metrics::names::CONFIG_RELOADS_TOTAL,
                    "outcome" => "build_failed",
                )
                .increment(1);
                return Err(text);
            }
        };

        let previous = self.state.swap(Arc::new(new_state));
        // Toggles that live outside RuntimeState because they gate background work rather
        // than the request path. Updated here so the whole reload stays one logical step.
        self.probes.set_enabled(candidate.probe.enabled);
        self.prefetch.set_enabled(candidate.prefetch.enabled);
        self.cloudflare.reconfigure(&candidate.cloudflare);
        self.reloads.fetch_add(1, Ordering::Relaxed);
        *self.last_reload_error.lock() = None;
        metrics::counter!(
            crate::metrics::names::CONFIG_RELOADS_TOTAL,
            "outcome" => "ok",
        )
        .increment(1);

        // Drain the old upstream pools once nothing can still be using them.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            previous.registry.drain().await;
        });

        // Reload datasets in the background so a large file cannot stall the reload.
        let datasets = Arc::clone(&self.datasets);
        let cfg = Arc::clone(&candidate);
        tokio::task::spawn_blocking(move || {
            let now_unix = crate::util::time::SystemClock.unix_secs_now();
            match crate::datasets::build(&cfg.datasets, &cfg.local, now_unix) {
                Ok(snapshot) => {
                    datasets.publish(Arc::new(snapshot));
                    metrics::counter!(
                        crate::metrics::names::DATASET_RELOADS_TOTAL,
                        "outcome" => "ok",
                    )
                    .increment(1);
                }
                Err(e) => {
                    // The previous valid snapshot stays in place.
                    tracing::warn!(event = "dataset.reload_failed", error = %e);
                    metrics::counter!(
                        crate::metrics::names::DATASET_RELOADS_TOTAL,
                        "outcome" => "failed",
                    )
                    .increment(1);
                }
            }
        });

        Ok(())
    }

    fn restore_persisted_state(&self) {
        if !self.storage.is_healthy() {
            return;
        }
        let config = self.config();
        let rows = self
            .storage
            .load_quality(config.cache.quality_max_entries as usize);
        let mut imported = 0usize;
        let entries: Vec<(ProbeKey, crate::ranking::model::PersistedQuality)> = rows
            .into_iter()
            .filter_map(|row| {
                let addr = row.addr.parse().ok()?;
                imported += 1;
                Some((
                    ProbeKey {
                        addr,
                        port: row.port,
                        profile: Arc::from(row.profile.as_str()),
                    },
                    row.quality,
                ))
            })
            .collect();
        self.quality.import(entries);

        let generation = self.storage.load_generation();
        tracing::info!(
            event = "storage.restored",
            quality_rows = imported,
            generation = generation.map(|g| g.0).unwrap_or(0),
        );
    }

    fn spawn_probe_engine(self: &Arc<Self>, rx: mpsc::Receiver<ProbeJob>) {
        // The engine always runs. Whether it does any work is decided per job from the
        // live configuration, so `probe.enabled` is a true runtime switch.
        let engine = ProbeEngine::new(
            crate::tasks::Ctx::new(self),
            Arc::clone(&self.quality),
            Arc::clone(&self.cloudflare),
            Arc::clone(&self.network),
        );
        *self.probe_engine.lock() = Some(Arc::clone(&engine));
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        self.background
            .lock()
            .spawn("probe-engine", self.cancel.clone(), move || {
                let engine = Arc::clone(&engine);
                let rx = Arc::clone(&rx);
                async move {
                    let mut guard = rx.lock().await;
                    engine.run(&mut guard).await;
                }
            });
    }

    /// Start every supervised background task.
    ///
    /// No task receives a copy of the configuration or of any configuration-derived
    /// object. Each gets a [`crate::tasks::Ctx`] and re-reads what it needs from the live
    /// state on every iteration, which is what makes a reload actually reach the control
    /// plane. Handles live in a supervisor set so shutdown can wait for them.
    pub fn spawn_background(self: &Arc<Self>) {
        let ctx = crate::tasks::Ctx::new(self);
        let cancel = self.cancel.clone();
        let mut set = self.background.lock();

        macro_rules! task {
            ($name:literal, $run:path) => {{
                let ctx = ctx.clone();
                set.spawn($name, cancel.clone(), move || $run(ctx.clone()));
            }};
        }

        task!("network", crate::tasks::network::run);
        task!("cache-maintenance", crate::tasks::maintenance::run_cache);
        task!("persistence", crate::tasks::maintenance::run_persistence);
        task!("gauges", crate::tasks::maintenance::run_gauges);
        task!("datasets", crate::tasks::maintenance::run_datasets);
        task!("prefetch", crate::tasks::prefetch::run);
        task!(
            "cloudflare-prefixes",
            crate::tasks::cloudflare::run_prefix_updater
        );
        task!(
            "cloudflare-seeds",
            crate::tasks::cloudflare::run_seed_updater
        );
        task!("cloudflare-sampler", crate::tasks::cloudflare::run_sampler);
        task!(
            "cloudflare-prober",
            crate::tasks::cloudflare::run_candidate_prober
        );
    }

    /// Begin a graceful shutdown.
    ///
    /// Cancelling the token only *asks* the control plane to stop. Use
    /// [`App::shutdown_and_join`] where the process is about to exit and leaked workers
    /// would still be opening sockets.
    pub fn shutdown(&self) {
        self.set_ready(false);
        self.cancel.cancel();
    }

    /// Begin a graceful shutdown and wait for every background task to stop.
    ///
    /// Returns the number of tasks that had to be aborted because they did not finish
    /// within `deadline`; zero is a clean shutdown.
    pub async fn shutdown_and_join(&self, deadline: Duration) -> usize {
        self.shutdown();
        let mut set = std::mem::take(&mut *self.background.lock());
        let aborted = set.join_all(deadline).await;
        if aborted > 0 {
            tracing::warn!(
                event = "shutdown.tasks_aborted",
                count = aborted,
                "background tasks did not stop within the deadline"
            );
        }
        self.storage.flush().await;
        aborted
    }

    /// Number of supervised background tasks that have not yet finished.
    pub fn background_tasks(&self) -> usize {
        self.background.lock().len()
    }

    /// Configured ceiling on concurrent upstream exchanges.
    ///
    /// Exposed so a test can prove the number an operator configured is the number the
    /// scheduler actually enforces, rather than a value that is merely stored.
    pub fn upstream_capacity(&self) -> usize {
        self.state().scheduler.upstream_capacity()
    }

    /// Upstream permits currently available.
    pub fn upstream_slots_available(&self) -> usize {
        self.upstream_slots.available_permits()
    }

    /// Configured ceiling on concurrent DNSSEC validations.
    pub fn validation_capacity(&self) -> usize {
        self.config().dnssec.max_concurrent_validations
    }

    /// DNSSEC validation permits currently available.
    pub fn validation_slots_available(&self) -> usize {
        self.validation_slots.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("egressdns.toml");
        std::fs::write(&path, body).expect("write");
        path
    }

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

    #[tokio::test]
    async fn builds_and_reports_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, MINIMAL);
        let app = App::build(&path).expect("build");
        assert!(!app.is_ready());
        app.set_ready(true);
        assert!(app.is_ready());
        assert_eq!(app.reload_count(), 0);
        assert!(app.last_reload_error().is_none());
        app.shutdown();
        assert!(app.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn reload_activates_a_valid_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, MINIMAL);
        let app = App::build(&path).expect("build");
        let before = app.config().ttl.cap_default;
        let updated = format!("{MINIMAL}\n[ttl]\ncap_default = 45\n");
        std::fs::write(&path, updated).expect("write");
        app.reload().expect("reload");
        assert_eq!(app.reload_count(), 1);
        assert_ne!(app.config().ttl.cap_default, before);
        assert_eq!(app.config().ttl.cap_default, 45);
    }

    #[tokio::test]
    async fn a_failed_reload_keeps_the_running_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, MINIMAL);
        let app = App::build(&path).expect("build");
        let before = app.config().ttl.cap_default;
        std::fs::write(&path, "this is not valid toml {{{").expect("write");
        let err = app.reload().expect_err("must fail");
        assert!(!err.is_empty());
        assert_eq!(app.config().ttl.cap_default, before);
        assert_eq!(app.reload_count(), 0);
        assert!(app.last_reload_error().is_some());

        // An unknown field must also be refused.
        std::fs::write(&path, format!("{MINIMAL}\n[ttl]\nnope = 1\n")).expect("write");
        assert!(app.reload().is_err());
        assert_eq!(app.config().ttl.cap_default, before);
    }

    #[tokio::test]
    async fn semantically_invalid_reload_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, MINIMAL);
        let app = App::build(&path).expect("build");
        // A semantic failure that is *not* restart-required, so the refusal under test is
        // the semantic one rather than the listener check firing first. The open-resolver
        // ACL rule is a load-time rule and is covered in tests/config.rs.
        std::fs::write(
            &path,
            "upstreams = [\"ftp://nope.example\"]\nproxies = []\n[server]\n\
             udp_listen = [\"127.0.0.1:0\"]\ntcp_listen = [\"127.0.0.1:0\"]\n",
        )
        .expect("write");
        let err = app.reload().expect_err("must fail");
        assert!(err.contains("upstreams"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn caches_survive_a_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, MINIMAL);
        let app = App::build(&path).expect("build");
        let cache_ptr = Arc::as_ptr(&app.cache);
        std::fs::write(&path, format!("{MINIMAL}\n[ttl]\ncap_default = 77\n")).expect("write");
        app.reload().expect("reload");
        assert_eq!(
            cache_ptr,
            Arc::as_ptr(&app.cache),
            "the cache must not be rebuilt by a reload"
        );
    }
}
