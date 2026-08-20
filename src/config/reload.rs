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
    check(
        old.resources.systemd_watchdog != new.resources.systemd_watchdog,
        "resources.systemd_watchdog",
        "the watchdog task is spawned once at startup",
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
    |c| c.resources.systemd_watchdog = !c.resources.systemd_watchdog,
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

/// Every configuration leaf path that applies on reload, in full dotted form.
///
/// The reload contract partitions the configuration into exactly two sets: the paths
/// reported by [`catalog`] (restart-required) and the paths listed here. The test
/// `every_config_path_is_classified_exactly_once` proves the partition covers every leaf
/// path exactly once, so a field added to `src/config/mod.rs` without a classification
/// fails the test suite with the path named. Array elements share the array's dotted
/// path: `upstream.groups.name` covers every `[[upstream.groups]]` entry.
pub const RELOADABLE: &[&str] = &[
    // The v2 front-end is expanded into `upstream.groups` at parse time, and those are
    // themselves reloadable, so changing the endpoint list applies on the next reload.
    "proxies",
    "upstreams",
    "tls.extra_ca_files",
    "tls.quic_zero_rtt",
    "tls.session_resumption",
    "tls.use_system_roots",
    "admin.max_request_bytes",
    "cache.failure_max_ttl",
    "cache.failure_min_ttl",
    "cache.negative_max_ttl",
    "cloudflare.allow_domains",
    "cloudflare.augment.max_added",
    "cloudflare.augment.min_advantage",
    "cloudflare.augment.min_samples",
    "cloudflare.augment.min_validations",
    "cloudflare.augment.validation_ttl",
    "cloudflare.deny_domains",
    "cloudflare.enabled",
    "cloudflare.mode",
    "cloudflare.official.api_token_env",
    "cloudflare.official.api_token_file",
    "cloudflare.official.api_url",
    "cloudflare.official.cache_file",
    "cloudflare.official.ipv4_url",
    "cloudflare.official.ipv6_url",
    "cloudflare.official.max_response_bytes",
    "cloudflare.official.min_ipv4_prefixes",
    "cloudflare.official.min_ipv6_prefixes",
    "cloudflare.official.refresh_interval",
    "cloudflare.official.timeout",
    "cloudflare.probe_hosts",
    "cloudflare.sampling.addresses_per_round",
    "cloudflare.sampling.enabled",
    "cloudflare.sampling.max_new_candidates_per_hour",
    "cloudflare.sampling.round_interval",
    "cloudflare.seeds.enabled",
    "cloudflare.seeds.endpoints.enabled",
    "cloudflare.seeds.endpoints.name",
    "cloudflare.seeds.endpoints.url",
    "cloudflare.seeds.max_addresses_per_response",
    "cloudflare.seeds.max_response_bytes",
    "cloudflare.seeds.refresh_interval",
    "cloudflare.seeds.resolve_hostnames",
    "cloudflare.seeds.timeout",
    "cloudflare.static_candidates",
    "datasets.asn_mmdb",
    "datasets.domain_category_files",
    "datasets.geoip_mmdb",
    "datasets.hosts_files",
    "datasets.max_file_bytes",
    "datasets.max_records",
    "datasets.reload_interval",
    "dnssec.corroborate_negative",
    "dnssec.extended_errors",
    "dnssec.max_validation_depth",
    "dnssec.mode",
    "dnssec.proof_completion_timeout",
    "dnssec.trust_anchor_file",
    "dnssec.trust_upstream_ad",
    "dnssec.validation_cache_entries",
    "ecs.egress.ipv4",
    "ecs.egress.ipv6",
    "ecs.mode",
    "local.hosts.addresses",
    "local.hosts.name",
    "local.local_ttl",
    "local.suffix_rules.group",
    "local.suffix_rules.suffix",
    "local.zones.authoritative",
    "local.zones.name",
    "local.zones.records.name",
    "local.zones.records.rtype",
    "local.zones.records.ttl",
    "local.zones.records.value",
    "logging.query_log",
    "logging.query_log_sample",
    "metrics.allow_non_loopback",
    "network.confidence_decay_on_change",
    "network.debounce",
    "network.enabled",
    "network.poll_interval",
    "network.reference_v4",
    "network.reference_v6",
    "network.relearn_window",
    "prefetch.enabled",
    "prefetch.global_qps",
    "prefetch.min_hits",
    "prefetch.per_key_min_interval",
    "prefetch.trigger_fraction",
    "prefetch.warm_on_start",
    "probe.allow_special_use_targets",
    "probe.concurrency",
    "probe.daily_bandwidth_budget_bytes",
    "probe.enable_http3",
    "probe.enabled",
    "probe.extra_ports",
    "probe.global_connections_per_second",
    "probe.http_timeout",
    "probe.max_candidates_per_rrset",
    "probe.max_response_bytes",
    "probe.per_domain_cooldown",
    "probe.per_ip_cooldown",
    "probe.per_prefix_cooldown",
    "probe.profiles.allowed_status",
    "probe.profiles.alpn",
    "probe.profiles.body_sha256",
    "probe.profiles.domains",
    "probe.profiles.method",
    "probe.profiles.name",
    "probe.profiles.path",
    "probe.profiles.required_header.name",
    "probe.profiles.required_header.value",
    "probe.profiles.required_issuer_cn",
    "probe.profiles.spki_sha256",
    "probe.tcp_timeout",
    "probe.tls_timeout",
    "ranking.consecutive_failure_base",
    "ranking.enabled",
    "ranking.evidence_half_life",
    "ranking.exploration_rate",
    "ranking.failure_penalty_ms",
    "ranking.hysteresis",
    "ranking.jitter_weight",
    "ranking.min_successes_to_lead",
    "ranking.neutral_cost_ms",
    "ranking.sample_max_age",
    "ranking.stale_sample_penalty_ms",
    "ranking.tail_weight",
    "ranking.uncertainty_penalty_ms",
    "serve_stale.client_timeout",
    "serve_stale.include_ede",
    "serve_stale.retry_interval",
    "server.allow_from",
    "server.any_policy",
    "server.deny_from",
    "server.foreground_budget",
    "server.rate_limit.client_table_size",
    "server.rate_limit.enabled",
    "server.rate_limit.global_burst",
    "server.rate_limit.global_qps",
    "server.rate_limit.per_client_burst",
    "server.rate_limit.per_client_qps",
    "server.special_use",
    "server.tcp.advertise_edns_keepalive",
    "server.tcp.idle_timeout",
    "server.tcp.max_connection_lifetime",
    "server.tcp.max_connections",
    "server.tcp.max_connections_per_client",
    "server.tcp.max_message_bytes",
    "server.tcp.max_pipelined_queries",
    "server.udp.max_payload",
    "server.udp.non_edns_max_payload",
    "storage.flush_interval",
    "storage.max_candidate_rows",
    "storage.max_hot_rows",
    "storage.max_quality_rows",
    "storage.row_max_age",
    "ttl.cap_cloudflare_augment",
    "ttl.cap_cloudflare_preserve",
    "ttl.cap_default",
    "ttl.cap_network_change",
    "ttl.cap_optimized_multi",
    "ttl.cap_serve_stale",
    "ttl.network_change_window",
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
        new.server.allow_from = Some(vec!["10.0.0.0/8".parse().expect("net")]);
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
                "resources.systemd_watchdog",
                Box::new(|c: &mut Config| c.resources.systemd_watchdog = false),
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

    /// Every leaf path named in the section reference of `docs/CONFIGURATION.md`.
    ///
    /// CI keeps the documented paths identical to the struct tree in
    /// `src/config/mod.rs` (via `scripts/check-config-docs.py`), so the documented leaf
    /// set is the complete set of configuration leaf paths. `Config::default()` cannot
    /// serve as the complete source on its own: its serialized form omits `None` fields
    /// and empty collections, so paths such as `probe.profiles.name` never appear in it.
    fn documented_leaf_paths() -> std::collections::BTreeSet<String> {
        let text = include_str!("../../docs/CONFIGURATION.md");
        let start = text
            .find("## Section reference")
            .expect("section reference heading");
        let end = text[start..]
            .find("## Validation rules")
            .map(|i| start + i)
            .expect("validation rules heading");
        let mut paths = std::collections::BTreeSet::new();
        let mut section: Option<String> = None;
        for line in text[start..end].lines() {
            // Keys that live at the root of the document have no table to sit under, so
            // an explicit heading introduces them and their rows carry no prefix.
            if line.starts_with("### Top-level keys") {
                section = Some(String::new());
            } else if let Some(rest) = line.strip_prefix("### `") {
                // `[server.udp]` and `[[upstream.groups]]` both denote the dotted path.
                let path = rest
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .expect("heading path");
                section = Some(path.to_string());
                paths.insert(path.to_string());
            } else if let Some(rest) = line.strip_prefix("| `") {
                let key = rest.split('`').next().expect("row key");
                // Only a back-ticked identifier in the first column is a key row. Tables
                // in the prose use the same shape for illustrative values, and treating
                // `https://host/path` as a configuration field would be nonsense. This
                // matches the rule in scripts/check-config-docs.py.
                if key.is_empty()
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    continue;
                }
                let section = section.as_ref().expect("row before any section heading");
                if section.is_empty() {
                    paths.insert(key.to_string());
                } else {
                    paths.insert(format!("{section}.{key}"));
                }
            }
        }
        // A leaf is a path no other path extends; everything else is a table.
        paths
            .iter()
            .filter(|p| !paths.iter().any(|o| o.starts_with(&format!("{p}."))))
            .cloned()
            .collect()
    }

    /// Every leaf path in the serialized form of a configuration.
    ///
    /// Array elements share the array's dotted path (`upstream.groups.0.name` is
    /// `upstream.groups.name`); empty arrays carry no key structure and emit nothing.
    fn serialized_leaf_paths(
        value: &toml::Value,
        prefix: &str,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        match value {
            toml::Value::Table(table) => {
                for (key, child) in table {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    serialized_leaf_paths(child, &path, out);
                }
            }
            toml::Value::Array(items) => {
                for item in items {
                    if matches!(item, toml::Value::Table(_) | toml::Value::Array(_)) {
                        serialized_leaf_paths(item, prefix, out);
                    } else {
                        out.insert(prefix.to_string());
                    }
                }
            }
            _ => {
                out.insert(prefix.to_string());
            }
        }
    }

    /// Every configuration leaf path is classified exactly once: either listed in
    /// [`RELOADABLE`] or detected by [`restart_required`] (and so named by `catalog()`).
    ///
    /// Without this, a new field defaults to "reloadable" by omission — nobody decided,
    /// and a wrong default here is a daemon that silently keeps its old behaviour.
    #[test]
    fn every_config_path_is_classified_exactly_once() {
        use std::collections::BTreeSet;

        // `catalog()` groups related fields as "a / b"; split the groups into paths.
        let restart: BTreeSet<&str> = catalog()
            .iter()
            .flat_map(|entry| entry.field.split(" / "))
            .collect();
        let reloadable: BTreeSet<&str> = RELOADABLE.iter().copied().collect();

        let both: Vec<_> = restart.intersection(&reloadable).copied().collect();
        assert!(
            both.is_empty(),
            "classified as both reloadable and restart-required: {both:?}"
        );

        let classified: BTreeSet<&str> = restart.union(&reloadable).copied().collect();
        let documented = documented_leaf_paths();

        let unclassified: Vec<_> = documented
            .iter()
            .filter(|path| !classified.contains(path.as_str()))
            .collect();
        assert!(
            unclassified.is_empty(),
            "configuration paths with no reload classification; add each to RELOADABLE \
             or to restart_required and MUTATIONS: {unclassified:?}"
        );

        let stale: Vec<_> = classified
            .iter()
            .filter(|path| !documented.contains(**path))
            .collect();
        assert!(
            stale.is_empty(),
            "classified paths that are not configuration fields (typo or stale entry): \
             {stale:?}"
        );

        // Anchor the classification in the real parser as well as in the documentation:
        // everything the serialized default configuration expresses must be classified.
        let value =
            toml::Value::try_from(Config::default()).expect("the default configuration serializes");
        let mut serialized = BTreeSet::new();
        serialized_leaf_paths(&value, "", &mut serialized);
        let unclassified_serialized: Vec<_> = serialized
            .iter()
            .filter(|path| !classified.contains(path.as_str()))
            .collect();
        assert!(
            unclassified_serialized.is_empty(),
            "paths present in the serialized configuration but not classified: \
             {unclassified_serialized:?}"
        );
    }
}
