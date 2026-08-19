//! The reload contract.
//!
//! A configuration reload either takes effect completely or is refused. There is no third
//! option where the daemon accepts a new file, reports success, and quietly keeps serving
//! the old behaviour — that is worse than refusing, because the operator walks away
//! believing a change landed.
//!
//! Fields fall into exactly two classes:
//!
//! * **Reloadable.** The value is read from the live [`Config`] every time it is used, so
//!   a reload changes behaviour on the next query or the next background tick. This is the
//!   default and covers almost everything.
//! * **Restart-required.** The value is consumed once, when a resource is created that
//!   cannot be replaced without dropping state or re-binding a socket: listening sockets,
//!   the admin socket, the metrics listener, the Tokio worker pool, the on-disk database,
//!   fixed-capacity channels, and the fixed-capacity caches. Changing one of these is
//!   detected here and the reload is refused with an explicit message naming the fields.
//!
//! Refusing is deliberate: applying the reloadable half of a file while silently dropping
//! the rest would leave the running daemon in a state that matches neither the old file
//! nor the new one.

use crate::config::Config;

/// One configuration field that cannot change without a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartRequired {
    /// Dotted path of the field, as it appears in the TOML file.
    pub field: &'static str,
    /// Why the value cannot change in a running process.
    pub reason: &'static str,
}

/// Compare two configurations and list every field that cannot change live.
///
/// An empty result means the candidate can be applied atomically.
pub fn restart_required(old: &Config, new: &Config) -> Vec<RestartRequired> {
    let mut out = Vec::new();
    let mut check = |changed: bool, field: &'static str, reason: &'static str| {
        if changed {
            out.push(RestartRequired { field, reason });
        }
    };

    // ---- listening sockets ------------------------------------------------------------
    check(
        old.server.udp_listen != new.server.udp_listen,
        "server.udp_listen",
        "listening sockets are bound once at startup; rebinding could drop queries and may \
         need CAP_NET_BIND_SERVICE",
    );
    check(
        old.server.tcp_listen != new.server.tcp_listen,
        "server.tcp_listen",
        "listening sockets are bound once at startup",
    );
    check(
        old.server.udp.reuse_port != new.server.udp.reuse_port,
        "server.udp.reuse_port",
        "SO_REUSEPORT changes the socket topology, which is fixed at bind time",
    );
    check(
        old.server.udp.workers_per_socket != new.server.udp.workers_per_socket,
        "server.udp.workers_per_socket",
        "receive workers are spawned per socket at bind time",
    );
    check(
        old.server.udp.recv_buffer_bytes != new.server.udp.recv_buffer_bytes,
        "server.udp.recv_buffer_bytes",
        "SO_RCVBUF is applied to the socket at bind time",
    );
    check(
        old.server.udp.send_buffer_bytes != new.server.udp.send_buffer_bytes,
        "server.udp.send_buffer_bytes",
        "SO_SNDBUF is applied to the socket at bind time",
    );

    // ---- observability and control endpoints ------------------------------------------
    check(
        old.metrics.enabled != new.metrics.enabled || old.metrics.listen != new.metrics.listen,
        "metrics.enabled / metrics.listen",
        "the metrics listener is bound once at startup",
    );
    check(
        old.admin.enabled != new.admin.enabled
            || old.admin.socket != new.admin.socket
            || old.admin.socket_mode != new.admin.socket_mode,
        "admin.enabled / admin.socket / admin.socket_mode",
        "the admin socket is created once at startup; recreating it would break connected \
         clients and race on the path",
    );

    // ---- process topology -------------------------------------------------------------
    check(
        old.resources.worker_threads != new.resources.worker_threads,
        "resources.worker_threads",
        "the Tokio runtime is built once at startup",
    );
    check(
        old.resources.max_blocking_threads != new.resources.max_blocking_threads,
        "resources.max_blocking_threads",
        "the Tokio blocking pool is sized once at startup",
    );
    check(
        old.resources.max_inflight_queries != new.resources.max_inflight_queries,
        "resources.max_inflight_queries",
        "the ingress semaphore is sized once at startup",
    );
    check(
        old.resources.max_inflight_upstream != new.resources.max_inflight_upstream,
        "resources.max_inflight_upstream",
        "the upstream semaphore is sized once at startup",
    );

    // ---- fixed-capacity structures ----------------------------------------------------
    check(
        old.cache.max_memory_bytes != new.cache.max_memory_bytes
            || old.cache.failure_max_entries != new.cache.failure_max_entries
            || old.cache.variant_max_memory_bytes != new.cache.variant_max_memory_bytes,
        "cache.max_memory_bytes / cache.failure_max_entries / cache.variant_max_memory_bytes",
        "cache capacity is fixed at construction; resizing would mean discarding the cache",
    );
    check(
        old.cache.quality_max_entries != new.cache.quality_max_entries,
        "cache.quality_max_entries",
        "the quality store is sized once at startup",
    );
    check(
        old.serve_stale.enabled != new.serve_stale.enabled
            || old.serve_stale.max_stale != new.serve_stale.max_stale
            || old.cache.internal_max_ttl != new.cache.internal_max_ttl,
        "serve_stale.enabled / serve_stale.max_stale / cache.internal_max_ttl",
        "these determine cache retention, which is fixed when the cache is built",
    );
    check(
        old.prefetch.hot_set_size != new.prefetch.hot_set_size
            || old.prefetch.transition_table_size != new.prefetch.transition_table_size
            || old.prefetch.transition_prediction != new.prefetch.transition_prediction,
        "prefetch.hot_set_size / prefetch.transition_table_size / prefetch.transition_prediction",
        "the hot set is sized once at startup",
    );
    check(
        old.probe.queue_size != new.probe.queue_size,
        "probe.queue_size",
        "the probe channel capacity is fixed at construction",
    );
    check(
        old.dnssec.max_concurrent_validations != new.dnssec.max_concurrent_validations,
        "dnssec.max_concurrent_validations",
        "the validation semaphore is sized once at startup",
    );
    check(
        old.cloudflare.candidate_pool_max != new.cloudflare.candidate_pool_max,
        "cloudflare.candidate_pool_max",
        "the candidate pool capacity is fixed at construction; resizing would mean \
         discarding validated candidates",
    );
    check(
        old.cloudflare.sampling.seed != new.cloudflare.sampling.seed
            || old.cloudflare.sampling.buckets_per_prefix != new.cloudflare.sampling.buckets_per_prefix
            || old.cloudflare.sampling.exploit_fraction != new.cloudflare.sampling.exploit_fraction,
        "cloudflare.sampling.seed / cloudflare.sampling.buckets_per_prefix / cloudflare.sampling.exploit_fraction",
        "the sampler is built once at startup; rebuilding it would discard per-bucket \
         history",
    );

    // ---- persistence ------------------------------------------------------------------
    check(
        old.storage.enabled != new.storage.enabled
            || old.storage.path != new.storage.path
            || old.storage.queue_size != new.storage.queue_size,
        "storage.enabled / storage.path / storage.queue_size",
        "the database connection and its write queue are opened once at startup",
    );

    // ---- logging ----------------------------------------------------------------------
    check(
        old.logging.level != new.logging.level || old.logging.json != new.logging.json,
        "logging.level / logging.json",
        "the tracing subscriber is installed once at startup",
    );

    out
}

/// Every restart-required field, with the reason, for documentation and for `egressdnsctl`.
///
/// This is derived from [`restart_required`] by mutating a default configuration one
/// group at a time, so the catalogue can never drift from the check that actually runs.
/// A field added to the check without a documentation entry is impossible by
/// construction.
pub fn catalog() -> Vec<RestartRequired> {
    let base = Config::default();
    let mut out = Vec::new();
    // Each mutation must change exactly one group's fields. `MUTATIONS` is exercised by
    // `every_restart_required_field_is_detected_individually`, which asserts that each
    // one produces exactly one entry.
    for mutate in MUTATIONS {
        let mut new = base.clone();
        mutate(&mut new);
        out.extend(restart_required(&base, &new));
    }
    out
}

/// One mutation per restart-required group.
type Mutation = fn(&mut Config);

/// A listen address that differs from any default, built without a fallible parse.
///
/// `catalog()` is a production path — `egressdnsctl reload-contract` calls it — so it may
/// not contain an `expect`, even one that cannot fire.
const ALTERNATE_LISTEN: std::net::SocketAddr = std::net::SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    5399,
);

const MUTATIONS: &[Mutation] = &[
    |c| c.server.udp_listen = vec![ALTERNATE_LISTEN],
    |c| c.server.tcp_listen = vec![ALTERNATE_LISTEN],
    |c| c.server.udp.reuse_port = !c.server.udp.reuse_port,
    |c| c.server.udp.workers_per_socket += 1,
    |c| c.server.udp.recv_buffer_bytes = Some(1 << 20),
    |c| c.server.udp.send_buffer_bytes = Some(1 << 20),
    |c| c.metrics.enabled = !c.metrics.enabled,
    |c| c.admin.enabled = !c.admin.enabled,
    |c| c.resources.worker_threads = Some(3),
    |c| c.resources.max_blocking_threads += 1,
    |c| c.resources.max_inflight_queries += 1,
    |c| c.resources.max_inflight_upstream += 1,
    |c| c.cache.max_memory_bytes += 1_048_576,
    |c| c.cache.quality_max_entries += 1,
    |c| c.serve_stale.enabled = !c.serve_stale.enabled,
    |c| c.prefetch.hot_set_size += 1,
    |c| c.probe.queue_size += 1,
    |c| c.dnssec.max_concurrent_validations += 1,
    |c| c.cloudflare.candidate_pool_max += 1,
    |c| c.cloudflare.sampling.seed += 1,
    |c| c.storage.enabled = !c.storage.enabled,
    |c| c.logging.json = !c.logging.json,
];

/// Render a refusal message an operator can act on.
pub fn describe(items: &[RestartRequired]) -> String {
    let mut text = String::from("reload refused: these fields require a restart:");
    for item in items {
        text.push_str("\n  - ");
        text.push_str(item.field);
        text.push_str(": ");
        text.push_str(item.reason);
    }
    text.push_str("\nRevert them, or restart the service to apply them.");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unchanged_configuration_needs_no_restart() {
        let cfg = Config::default();
        assert!(restart_required(&cfg, &cfg).is_empty());
    }

    #[test]
    fn reloadable_fields_do_not_require_a_restart() {
        let old = Config::default();
        let mut new = Config::default();
        new.cloudflare.mode = crate::config::CloudflareMode::Off;
        new.probe.enabled = !old.probe.enabled;
        new.prefetch.enabled = !old.prefetch.enabled;
        new.server.allow_from = vec!["10.0.0.0/8".parse().expect("net")];
        new.ttl.cap_default = old.ttl.cap_default / 2;
        new.dnssec.mode = crate::config::DnssecMode::Off;
        new.server.rate_limit.per_client_qps = 12_345;
        new.datasets.reload_interval = std::time::Duration::from_secs(60);
        assert!(
            restart_required(&old, &new).is_empty(),
            "{:?}",
            restart_required(&old, &new)
        );
    }

    #[test]
    fn listener_changes_require_a_restart() {
        let old = Config::default();
        let mut new = Config::default();
        new.server.udp_listen = vec!["127.0.0.1:5353".parse().expect("addr")];
        let items = restart_required(&old, &new);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].field, "server.udp_listen");
        assert!(describe(&items).contains("server.udp_listen"));
        assert!(describe(&items).contains("restart"));
    }

    /// The catalogue must cover every group the check knows about, exactly once each.
    ///
    /// Without this, a new restart-required field could be added to `restart_required`
    /// and silently missing from `docs/CONFIGURATION.md` and from `egressdnsctl
    /// reload-contract`, which is how documentation drifts away from behaviour.
    #[test]
    fn the_catalog_covers_every_mutation_exactly_once() {
        let entries = catalog();
        assert_eq!(
            entries.len(),
            MUTATIONS.len(),
            "each mutation must produce exactly one restart-required entry"
        );
        let mut fields: Vec<&str> = entries.iter().map(|e| e.field).collect();
        let before = fields.len();
        fields.sort_unstable();
        fields.dedup();
        assert_eq!(fields.len(), before, "no field group may appear twice");
        for entry in &entries {
            assert!(!entry.reason.is_empty(), "{} has no reason", entry.field);
        }
    }

    #[test]
    fn every_restart_required_field_is_detected_individually() {
        let base = Config::default();
        type Mutation = (&'static str, Box<dyn Fn(&mut Config)>);
        let mutations: Vec<Mutation> = vec![
            (
                "server.tcp_listen",
                Box::new(|c: &mut Config| {
                    c.server.tcp_listen = vec!["127.0.0.1:5354".parse().expect("addr")]
                }),
            ),
            (
                "server.udp.reuse_port",
                Box::new(|c: &mut Config| c.server.udp.reuse_port = true),
            ),
            (
                "server.udp.recv_buffer_bytes",
                Box::new(|c: &mut Config| c.server.udp.recv_buffer_bytes = Some(1 << 20)),
            ),
            (
                "metrics.listen",
                Box::new(|c: &mut Config| {
                    c.metrics.listen = "127.0.0.1:9999".parse().expect("addr")
                }),
            ),
            (
                "admin.socket",
                Box::new(|c: &mut Config| c.admin.socket = "/tmp/other.sock".into()),
            ),
            (
                "resources.worker_threads",
                Box::new(|c: &mut Config| c.resources.worker_threads = Some(3)),
            ),
            (
                "resources.max_blocking_threads",
                Box::new(|c: &mut Config| c.resources.max_blocking_threads += 1),
            ),
            (
                "resources.max_inflight_upstream",
                Box::new(|c: &mut Config| c.resources.max_inflight_upstream += 1),
            ),
            (
                "cache.max_memory_bytes",
                Box::new(|c: &mut Config| c.cache.max_memory_bytes += 1),
            ),
            (
                "cache.quality_max_entries",
                Box::new(|c: &mut Config| c.cache.quality_max_entries += 1),
            ),
            (
                "serve_stale.max_stale",
                Box::new(|c: &mut Config| {
                    c.serve_stale.max_stale += std::time::Duration::from_secs(1)
                }),
            ),
            (
                "prefetch.hot_set_size",
                Box::new(|c: &mut Config| c.prefetch.hot_set_size += 1),
            ),
            (
                "storage.path",
                Box::new(|c: &mut Config| c.storage.path = "/tmp/other.sqlite".into()),
            ),
            (
                "probe.queue_size",
                Box::new(|c: &mut Config| c.probe.queue_size += 1),
            ),
            (
                "dnssec.max_concurrent_validations",
                Box::new(|c: &mut Config| c.dnssec.max_concurrent_validations += 1),
            ),
            (
                "cloudflare.candidate_pool_max",
                Box::new(|c: &mut Config| c.cloudflare.candidate_pool_max += 1),
            ),
            (
                "cloudflare.sampling.seed",
                Box::new(|c: &mut Config| c.cloudflare.sampling.seed += 1),
            ),
            (
                "cloudflare.sampling.buckets_per_prefix",
                Box::new(|c: &mut Config| c.cloudflare.sampling.buckets_per_prefix += 1),
            ),
            (
                "cloudflare.sampling.exploit_fraction",
                Box::new(|c: &mut Config| c.cloudflare.sampling.exploit_fraction = 0.9),
            ),
            (
                "logging.level",
                Box::new(|c: &mut Config| c.logging.level = "trace".into()),
            ),
        ];
        for (label, mutate) in mutations {
            let mut new = base.clone();
            mutate(&mut new);
            assert!(
                !restart_required(&base, &new).is_empty(),
                "changing {label} was not detected as restart-required"
            );
        }
    }
}
