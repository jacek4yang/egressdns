//! Network-generation monitoring.
//!
//! Polls the host's routing and address state, debounces transient flaps, and publishes a
//! new generation when the egress path really changed. On a change, historical quality
//! evidence is demoted to a weak prior and accelerated relearning begins.

use std::sync::Arc;
use std::time::Duration;

use crate::cloudflare::state::SharedCloudflare;
use crate::config::NetworkConfig;
use crate::network::detect::{HostProbe, NetworkProbe};
use crate::network::SharedNetworkState;
use crate::ranking::QualityStore;
use crate::storage::{Storage, WriteBatch};

/// Run the monitor until cancelled.
///
/// Configuration is re-read at the top of every iteration rather than captured once, so
/// `network.*` changes take effect on the next poll instead of the next restart. That
/// includes `network.enabled`: turning the monitor off leaves the loop idling rather than
/// exiting, so turning it back on works too.
pub async fn run(ctx: super::Ctx) {
    let probe: Arc<dyn NetworkProbe> = Arc::new(HostProbe::default());
    let mut pending: Option<(u64, tokio::time::Instant)> = None;
    let (state, quality, cloudflare, storage) = match ctx.app() {
        Some(app) => (
            Arc::clone(&app.network),
            Arc::clone(&app.quality),
            Arc::clone(&app.cloudflare),
            Arc::clone(&app.storage),
        ),
        None => return,
    };
    let cancel = ctx.cancel.clone();

    loop {
        let Some(config) = ctx.config() else {
            return;
        };
        let cfg = config.network.clone();
        if !cfg.enabled {
            pending = None;
            if !super::tick(Duration::from_secs(1), &cancel).await {
                return;
            }
            continue;
        }
        let sample = {
            let probe = Arc::clone(&probe);
            let v4 = cfg.reference_v4;
            let v6 = cfg.reference_v6;
            match tokio::task::spawn_blocking(move || probe.sample(v4, v6)).await {
                Ok(s) => s,
                Err(_) => {
                    if !super::tick(cfg.poll_interval, &cancel).await {
                        return;
                    }
                    continue;
                }
            }
        };

        let fingerprint = sample.fingerprint();
        let current = state.load();
        if current.raw.fingerprint() == fingerprint {
            pending = None;
        } else {
            let now = tokio::time::Instant::now();
            match pending {
                Some((fp, first_seen)) if fp == fingerprint => {
                    if now.saturating_duration_since(first_seen) >= cfg.debounce {
                        apply_change(&state, &quality, &cloudflare, &storage, sample, &cfg);
                        pending = None;
                    }
                }
                _ => pending = Some((fingerprint, now)),
            }
        }

        publish_gauges(&state);
        if !super::tick(cfg.poll_interval.max(Duration::from_millis(500)), &cancel).await {
            return;
        }
    }
}

fn apply_change(
    state: &SharedNetworkState,
    quality: &Arc<QualityStore>,
    cloudflare: &SharedCloudflare,
    storage: &Arc<Storage>,
    sample: crate::network::RawNetworkState,
    cfg: &NetworkConfig,
) {
    let now_unix = crate::util::time::SystemClock.unix_secs_now();
    let fingerprint = sample.fingerprint();
    let changed = state.publish(sample, now_unix);
    if !changed {
        return;
    }
    let generation = state.generation();
    tracing::info!(
        event = "network.generation_change",
        generation,
        "egress path changed; historical measurements demoted to a weak prior"
    );
    metrics::counter!(crate::metrics::names::NETWORK_GENERATION_CHANGES_TOTAL).increment(1);
    quality.on_generation_change(generation, cfg.confidence_decay_on_change);
    cloudflare.on_generation_change(generation);
    storage.enqueue(WriteBatch::Generation {
        generation,
        fingerprint,
        published_unix: now_unix,
    });
}

fn publish_gauges(state: &SharedNetworkState) {
    let snapshot = state.load();
    metrics::gauge!(crate::metrics::names::NETWORK_GENERATION).set(snapshot.generation as f64);
    metrics::gauge!(
        crate::metrics::names::NETWORK_FAMILY_STATE,
        "family" => "v4",
    )
    .set(snapshot.v4.gauge());
    metrics::gauge!(
        crate::metrics::names::NETWORK_FAMILY_STATE,
        "family" => "v6",
    )
    .set(snapshot.v6.gauge());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkState, RawNetworkState};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample(gw: u8) -> RawNetworkState {
        RawNetworkState {
            default_iface_v4: Some("eth0".into()),
            gateway_v4: Some(Ipv4Addr::new(10, 0, 0, gw)),
            default_iface_v6: None,
            gateway_v6: None,
            source_v4: Some(Ipv4Addr::new(10, 0, 0, 53)),
            source_v6: None,
            global_addresses: vec!["10.0.0.53".into()],
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_demotes_evidence_and_bumps_the_generation() {
        let state = Arc::new(NetworkState::new());
        let quality = Arc::new(QualityStore::new(100));
        let cloudflare = Arc::new(crate::cloudflare::state::CloudflareState::new(
            &crate::config::CloudflareConfig::default(),
        ));
        let storage = Storage::disabled();
        let cfg = NetworkConfig::default();

        let key = crate::ranking::ProbeKey::generic("104.16.0.1".parse().expect("ip"), 443);
        for _ in 0..50 {
            quality.record(
                key.clone(),
                crate::ranking::ObservationClass::Success,
                Some(Duration::from_millis(5)),
                1,
                tokio::time::Instant::now(),
                &crate::config::RankingConfig::default(),
            );
        }
        let before = quality
            .get(&key)
            .expect("present")
            .success_probability_lower_bound();

        apply_change(&state, &quality, &cloudflare, &storage, sample(1), &cfg);
        let generation = state.generation();
        assert_eq!(generation, 2);
        let after = quality
            .get(&key)
            .expect("present")
            .success_probability_lower_bound();
        assert!(after < before, "{after} should be below {before}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_sample_does_not_bump_the_generation() {
        let state = Arc::new(NetworkState::new());
        let quality = Arc::new(QualityStore::new(10));
        let cloudflare = Arc::new(crate::cloudflare::state::CloudflareState::new(
            &crate::config::CloudflareConfig::default(),
        ));
        let storage = Storage::disabled();
        let cfg = NetworkConfig::default();
        apply_change(&state, &quality, &cloudflare, &storage, sample(1), &cfg);
        let g = state.generation();
        apply_change(&state, &quality, &cloudflare, &storage, sample(1), &cfg);
        assert_eq!(state.generation(), g);
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_only_hosts_are_represented() {
        let raw = RawNetworkState {
            default_iface_v4: None,
            gateway_v4: None,
            default_iface_v6: Some("eth0".into()),
            gateway_v6: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            source_v4: None,
            source_v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53)),
            global_addresses: vec![],
        };
        assert_eq!(raw.v4_state(), crate::network::FamilyState::Unusable);
        assert_eq!(raw.v6_state(), crate::network::FamilyState::Usable);
    }

    #[tokio::test]
    async fn monitor_stops_when_cancelled() {
        let mut cfg = crate::tasks::test_config();
        cfg.network.poll_interval = Duration::from_millis(50);
        let (app, ctx) = crate::tasks::test_ctx(cfg);
        let handle = tokio::spawn(run(ctx.clone()));
        tokio::time::sleep(Duration::from_millis(120)).await;
        ctx.cancel.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .is_ok());
        drop(app);
    }

    /// A disabled monitor must idle rather than exit, so a reload can enable it.
    #[tokio::test]
    async fn a_disabled_monitor_idles_and_a_reload_starts_it() {
        let mut cfg = crate::tasks::test_config();
        cfg.network.enabled = false;
        cfg.network.poll_interval = Duration::from_millis(20);
        let (app, ctx) = crate::tasks::test_ctx(cfg.clone());
        let handle = tokio::spawn(run(ctx.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "a disabled monitor must stay available for a later reload"
        );

        cfg.network.enabled = true;
        app.install_for_test(cfg);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!handle.is_finished(), "an enabled monitor keeps running");

        ctx.cancel.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .is_ok());
        drop(app);
    }

    /// Dropping the process stops the monitor even without cancellation.
    #[tokio::test]
    async fn losing_the_process_stops_the_monitor() {
        let (app, ctx) = crate::tasks::test_ctx(crate::tasks::test_config());
        drop(app);
        let handle = tokio::spawn(run(ctx));
        assert!(tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .is_ok());
    }
}
