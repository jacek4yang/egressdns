//! Cache maintenance, persistence flushing and metric publication.

use std::sync::Arc;
use std::time::Duration;

use crate::storage::{CandidateRow, HotRow, QualityRow, RowLimits, UpstreamRow, WriteBatch};

/// Run deferred cache housekeeping so the request path never pays for it.
pub async fn run_cache(ctx: super::Ctx) {
    let Some(app) = ctx.app() else { return };
    let cache = Arc::clone(&app.cache);
    let cancel = ctx.cancel.clone();
    drop(app);
    loop {
        cache.run_maintenance();
        let stats = cache.stats();
        metrics::gauge!(crate::metrics::names::CACHE_ENTRIES, "cache" => "answers")
            .set(stats.answer_entries as f64);
        metrics::gauge!(crate::metrics::names::CACHE_ENTRIES, "cache" => "failures")
            .set(stats.failure_entries as f64);
        metrics::gauge!(crate::metrics::names::CACHE_ENTRIES, "cache" => "variants")
            .set(stats.variant_entries as f64);
        metrics::gauge!(crate::metrics::names::CACHE_BYTES).set(stats.answer_bytes as f64);
        if !super::tick(Duration::from_secs(5), &cancel).await {
            return;
        }
    }
}

/// Periodically flush derived state to SQLite in batches.
#[allow(clippy::too_many_arguments)]
pub async fn run_persistence(ctx: super::Ctx) {
    let Some(app) = ctx.app() else { return };
    let storage = Arc::clone(&app.storage);
    let quality = Arc::clone(&app.quality);
    let hotset = Arc::clone(&app.hotset);
    let cloudflare = Arc::clone(&app.cloudflare);
    let network = Arc::clone(&app.network);
    let cancel = ctx.cancel.clone();
    drop(app);

    let mut rounds: u64 = 0;
    loop {
        // Live configuration and live registry: after a reload this flushes the routes the
        // daemon is actually using, with the intervals and row limits now configured.
        let Some(config) = ctx.config() else {
            return;
        };
        let cfg = config.storage.clone();
        let Some(upstreams) = ctx.state().map(|s| Arc::clone(&s.registry)) else {
            return;
        };
        if !cfg.enabled {
            if !super::tick(Duration::from_secs(5), &cancel).await {
                return;
            }
            continue;
        }
        let limits = RowLimits {
            quality: cfg.max_quality_rows,
            candidates: cfg.max_candidate_rows,
            hot: cfg.max_hot_rows,
        };
        if !super::tick(super::jittered(cfg.flush_interval, rounds), &cancel).await {
            return;
        }
        rounds = rounds.wrapping_add(1);
        let now_unix = crate::util::time::SystemClock.unix_secs_now();

        let quality_rows: Vec<QualityRow> = quality
            .export()
            .into_iter()
            .take(cfg.max_quality_rows)
            .map(|(key, q)| QualityRow {
                addr: key.addr.to_string(),
                profile: key.profile.to_string(),
                port: key.port,
                quality: q,
                updated_unix: now_unix,
            })
            .collect();
        if !quality_rows.is_empty() {
            storage.enqueue(WriteBatch::Quality(quality_rows));
        }

        let mut candidate_rows: Vec<CandidateRow> = Vec::new();
        for ipv4 in [true, false] {
            for c in cloudflare.pool().list(ipv4) {
                candidate_rows.push(CandidateRow {
                    addr: c.addr.to_string(),
                    origin: c.origin.label().to_string(),
                    stage: c.stage.label().to_string(),
                    last_seen_unix: now_unix,
                    generation: c.generation,
                });
            }
        }
        candidate_rows.truncate(cfg.max_candidate_rows);
        if !candidate_rows.is_empty() {
            storage.enqueue(WriteBatch::Candidates(candidate_rows));
        }

        let hot_rows: Vec<HotRow> = hotset
            .top(cfg.max_hot_rows)
            .into_iter()
            .map(|(key, entry)| HotRow {
                name: key.name.to_string(),
                qtype: u16::from(key.qtype),
                score: f64::from(entry.score),
                last_seen_unix: now_unix,
            })
            .collect();
        if !hot_rows.is_empty() {
            storage.enqueue(WriteBatch::Hot(hot_rows));
        }

        let upstream_rows: Vec<UpstreamRow> = upstreams
            .all_routes()
            .into_iter()
            .map(|route| {
                let h = route.health();
                UpstreamRow {
                    route: route.key.to_string(),
                    ewma_ms: h.ewma_ms(),
                    p95_ms: h.p95_ms(),
                    success_probability: h.success_probability(),
                    samples: h.samples(),
                    updated_unix: now_unix,
                }
            })
            .collect();
        if !upstream_rows.is_empty() {
            storage.enqueue(WriteBatch::Upstream(upstream_rows));
        }

        storage.enqueue(WriteBatch::Generation {
            generation: network.generation(),
            fingerprint: network.load().raw.fingerprint(),
            published_unix: network.load().published_unix,
        });

        if rounds.is_multiple_of(20) {
            storage.enqueue(WriteBatch::Prune {
                max_age_secs: cfg.row_max_age.as_secs(),
                limits,
            });
        }

        metrics::gauge!(crate::metrics::names::STORAGE_QUEUE_DEPTH)
            .set(storage.queue_depth() as f64);
        metrics::gauge!(crate::metrics::names::STORAGE_HEALTHY).set(if storage.is_healthy() {
            1.0
        } else {
            0.0
        });
    }
}

/// Publish gauges that are cheap to compute but not owned by any other task.
pub async fn run_gauges(ctx: super::Ctx) {
    let Some(app) = ctx.app() else { return };
    let cloudflare = Arc::clone(&app.cloudflare);
    let cancel = ctx.cancel.clone();
    drop(app);
    loop {
        let Some(config) = ctx.config() else {
            return;
        };
        let Some(state) = ctx.state() else {
            return;
        };
        let upstreams = Arc::clone(&state.registry);
        // Sampled here rather than incremented on acquire: a gauge only written when a
        // permit is taken never returns to zero, and reports a permanently busy resolver
        // once traffic stops.
        metrics::gauge!(crate::metrics::names::UPSTREAM_INFLIGHT)
            .set(state.scheduler.inflight() as f64);
        for route in upstreams.all_routes() {
            let h = route.health();
            metrics::gauge!(
                crate::metrics::names::UPSTREAM_CIRCUIT_STATE,
                "server" => route.key.server.to_string(),
                "transport" => route.key.transport.label(),
            )
            .set(h.circuit().gauge());
        }
        if config.cloudflare.enabled {
            let (v4, v6) = cloudflare.pool().counts();
            metrics::gauge!(crate::metrics::names::CF_CANDIDATES, "family" => "v4").set(v4 as f64);
            metrics::gauge!(crate::metrics::names::CF_CANDIDATES, "family" => "v6").set(v6 as f64);
            if let Some(snapshot) = cloudflare.prefixes().as_ref() {
                metrics::gauge!(crate::metrics::names::CF_PREFIXES, "family" => "v4")
                    .set(snapshot.ipv4().len() as f64);
                metrics::gauge!(crate::metrics::names::CF_PREFIXES, "family" => "v6")
                    .set(snapshot.ipv6().len() as f64);
            }
        }
        if !super::tick(Duration::from_secs(10), &cancel).await {
            return;
        }
    }
}

/// Periodically rebuild the dataset snapshot from disk.
///
/// `datasets.reload_interval` exists so hosts files and internal zone files can be updated
/// by configuration management without an `egressdnsctl reload`. The rebuild runs on a
/// blocking thread because it reads files, and a failure leaves the previous valid snapshot
/// in place: a truncated hosts file must never empty the resolver's local data.
pub async fn run_datasets(ctx: super::Ctx) {
    let Some(app) = ctx.app() else { return };
    let datasets = Arc::clone(&app.datasets);
    let cancel = ctx.cancel.clone();
    drop(app);

    let mut round: u64 = 0;
    loop {
        let Some(config) = ctx.config() else { return };
        let interval = config.datasets.reload_interval;
        if interval.is_zero() {
            // Zero disables periodic reloading; an explicit reload still rebuilds.
            if !super::tick(Duration::from_secs(30), &cancel).await {
                return;
            }
            continue;
        }
        if !super::tick(super::jittered(interval, round), &cancel).await {
            return;
        }
        round = round.wrapping_add(1);

        let cfg = Arc::clone(&config);
        let target = Arc::clone(&datasets);
        let outcome = tokio::task::spawn_blocking(move || {
            let now_unix = crate::util::time::SystemClock.unix_secs_now();
            crate::datasets::build(&cfg.datasets, &cfg.local, now_unix)
                .map(|snapshot| target.publish_if_changed(Arc::new(snapshot)))
        })
        .await;

        match outcome {
            Ok(Ok(true)) => {
                metrics::counter!(
                    crate::metrics::names::DATASET_RELOADS_TOTAL,
                    "outcome" => "changed",
                )
                .increment(1);
                tracing::info!(event = "dataset.reloaded");
            }
            Ok(Ok(false)) => {
                metrics::counter!(
                    crate::metrics::names::DATASET_RELOADS_TOTAL,
                    "outcome" => "unchanged",
                )
                .increment(1);
            }
            Ok(Err(e)) => {
                tracing::warn!(event = "dataset.reload_failed", error = %e);
                metrics::counter!(
                    crate::metrics::names::DATASET_RELOADS_TOTAL,
                    "outcome" => "failed",
                )
                .increment(1);
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{test_config, test_ctx};

    #[tokio::test]
    async fn cache_maintenance_stops_on_cancel() {
        let (app, ctx) = test_ctx(test_config());
        let handle = tokio::spawn(run_cache(ctx));
        tokio::time::sleep(Duration::from_millis(50)).await;
        app.shutdown();
        assert!(tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn persistence_idles_when_storage_is_disabled_and_stops_on_cancel() {
        let mut config = test_config();
        config.storage.enabled = false;
        let (app, ctx) = test_ctx(config);
        let handle = tokio::spawn(run_persistence(ctx));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Disabled storage must not make the task exit outright: enabling it by reload has
        // to be possible, so the task idles instead.
        assert!(!handle.is_finished());
        app.shutdown();
        assert!(tokio::time::timeout(Duration::from_secs(8), handle)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn dataset_reload_publishes_only_real_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "192.0.2.1 one.example.test\n").expect("write");

        let mut config = test_config();
        config.datasets.hosts_files = vec![hosts.clone()];
        config.datasets.reload_interval = Duration::from_millis(50);
        let (app, ctx) = test_ctx(config);

        let before = app.datasets.load().content_digest();
        let handle = tokio::spawn(run_datasets(ctx));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            app.datasets.load().content_digest(),
            before,
            "an unchanged file must not produce a new snapshot"
        );

        std::fs::write(
            &hosts,
            "192.0.2.1 one.example.test\n192.0.2.2 two.example.test\n",
        )
        .expect("write");
        let mut changed = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if app.datasets.load().content_digest() != before {
                changed = true;
                break;
            }
        }
        assert!(changed, "an edited hosts file must be picked up");
        assert!(app.datasets.load().hosts.get("two.example.test.").is_some());

        app.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
