//! Prometheus-compatible metrics.
//!
//! Every metric name and label value used by this crate is a compile-time constant or a
//! small closed enum. Query names, client addresses, candidate addresses and certificate
//! hostnames are never used as labels: unbounded label cardinality is a denial-of-service
//! vector against the metrics pipeline and a privacy problem.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Metric name constants.
pub mod names {
    // -- ingress -----------------------------------------------------------
    /// Queries accepted, labelled by transport.
    pub const QUERIES_TOTAL: &str = "egressdns_queries_total";
    /// Responses emitted, labelled by transport and rcode.
    pub const RESPONSES_TOTAL: &str = "egressdns_responses_total";
    /// Requests refused before resolution, labelled by reason.
    pub const REJECTED_TOTAL: &str = "egressdns_rejected_total";
    /// End-to-end request latency in seconds, labelled by transport.
    pub const REQUEST_SECONDS: &str = "egressdns_request_duration_seconds";
    /// Queries answered locally from the special-use registry, labelled by registry.
    pub const SPECIAL_USE_TOTAL: &str = "egressdns_special_use_total";
    /// UDP responses that had to set TC.
    pub const UDP_TRUNCATED_TOTAL: &str = "egressdns_udp_truncated_total";
    /// Active TCP connections.
    pub const TCP_ACTIVE_CONNECTIONS: &str = "egressdns_tcp_active_connections";
    /// TCP connections refused by a limit.
    pub const TCP_REJECTED_TOTAL: &str = "egressdns_tcp_rejected_total";
    /// Queries currently in flight.
    pub const INFLIGHT_QUERIES: &str = "egressdns_inflight_queries";

    // -- cache -------------------------------------------------------------
    /// Cache lookups, labelled by outcome.
    pub const CACHE_LOOKUPS_TOTAL: &str = "egressdns_cache_lookups_total";
    /// Entries currently held, labelled by cache.
    pub const CACHE_ENTRIES: &str = "egressdns_cache_entries";
    /// Evictions, labelled by cache.
    pub const CACHE_EVICTIONS_TOTAL: &str = "egressdns_cache_evictions_total";
    /// Approximate cached bytes.
    pub const CACHE_BYTES: &str = "egressdns_cache_bytes";
    /// Requests merged into an in-flight upstream operation.
    pub const SINGLEFLIGHT_COALESCED_TOTAL: &str = "egressdns_singleflight_coalesced_total";
    /// Prefetch operations, labelled by outcome.
    pub const PREFETCH_TOTAL: &str = "egressdns_prefetch_total";

    // -- upstream ----------------------------------------------------------
    /// Upstream queries, labelled by server, transport and outcome.
    pub const UPSTREAM_QUERIES_TOTAL: &str = "egressdns_upstream_queries_total";
    /// Upstream latency in seconds, labelled by server and transport.
    pub const UPSTREAM_SECONDS: &str = "egressdns_upstream_duration_seconds";
    /// Circuit breaker state, labelled by server and transport.
    pub const UPSTREAM_CIRCUIT_STATE: &str = "egressdns_upstream_circuit_state";
    /// Hedge requests issued.
    pub const UPSTREAM_HEDGES_TOTAL: &str = "egressdns_upstream_hedges_total";
    /// Duplicate upstream queries caused by hedging or fan-out.
    pub const UPSTREAM_DUPLICATES_TOTAL: &str = "egressdns_upstream_duplicate_queries_total";
    /// Upstream queries shed because the global concurrency ceiling was reached.
    pub const UPSTREAM_SHED_TOTAL: &str = "egressdns_upstream_shed_total";
    /// Upstream exchanges currently in flight.
    pub const UPSTREAM_INFLIGHT: &str = "egressdns_upstream_inflight";
    /// Queries sent to a route whose circuit was open because no alternative existed.
    pub const UPSTREAM_LAST_RESORT_TOTAL: &str = "egressdns_upstream_last_resort_total";
    /// Queries sent to a route whose address family read as unusable because no family
    /// read as usable at all — that is, because detection, not the network, failed.
    pub const UPSTREAM_FAMILY_FALLBACK_TOTAL: &str = "egressdns_upstream_family_fallback_total";
    /// Negative answers checked against a second resolver authority, by outcome.
    pub const CORROBORATION_TOTAL: &str = "egressdns_corroboration_total";
    /// DNSSEC validations currently in flight.
    pub const DNSSEC_INFLIGHT: &str = "egressdns_dnssec_validations_inflight";
    /// DNSSEC validations shed because the concurrency ceiling was reached.
    pub const DNSSEC_SHED_TOTAL: &str = "egressdns_dnssec_validations_shed_total";
    /// Probe workers currently executing a job.
    pub const PROBE_WORKERS_ACTIVE: &str = "egressdns_probe_workers_active";
    /// UDP answers that were truncated and retried over a stream transport.
    pub const UPSTREAM_TCP_RETRY_TOTAL: &str = "egressdns_upstream_tcp_retry_total";
    /// Alternate complete answer variants observed.
    pub const VARIANTS_OBSERVED_TOTAL: &str = "egressdns_answer_variants_observed_total";
    /// Variant selection changes.
    pub const VARIANT_SWITCH_TOTAL: &str = "egressdns_answer_variant_switch_total";

    // -- dnssec ------------------------------------------------------------
    /// DNSSEC validation results, labelled by proof.
    pub const DNSSEC_RESULTS_TOTAL: &str = "egressdns_dnssec_results_total";
    /// Extended DNS Errors emitted, labelled by info code name.
    pub const EDE_EMITTED_TOTAL: &str = "egressdns_extended_errors_total";
    /// Stale answers served.
    pub const SERVE_STALE_TOTAL: &str = "egressdns_serve_stale_total";

    // -- probe -------------------------------------------------------------
    /// Probe queue depth.
    pub const PROBE_QUEUE_DEPTH: &str = "egressdns_probe_queue_depth";
    /// Probe jobs dropped because a bound was reached, labelled by reason.
    pub const PROBE_DROPPED_TOTAL: &str = "egressdns_probe_dropped_total";
    /// Probe results, labelled by stage, family and result class.
    pub const PROBE_RESULTS_TOTAL: &str = "egressdns_probe_results_total";
    /// Probe latency in seconds, labelled by stage and family.
    pub const PROBE_SECONDS: &str = "egressdns_probe_duration_seconds";
    /// Probe subsystem health, 1 when healthy.
    pub const PROBE_SUBSYSTEM_HEALTHY: &str = "egressdns_probe_subsystem_healthy";
    /// Bytes consumed from the daily throughput-measurement budget.
    pub const PROBE_BANDWIDTH_BYTES: &str = "egressdns_probe_bandwidth_bytes_total";

    // -- network -----------------------------------------------------------
    /// Address family state, 1 when usable; labelled by family.
    pub const NETWORK_FAMILY_STATE: &str = "egressdns_network_family_state";
    /// Current network generation identifier.
    pub const NETWORK_GENERATION: &str = "egressdns_network_generation";
    /// Network generation changes.
    pub const NETWORK_GENERATION_CHANGES_TOTAL: &str = "egressdns_network_generation_changes_total";

    // -- cloudflare --------------------------------------------------------
    /// Candidate pool size, labelled by family.
    pub const CF_CANDIDATES: &str = "egressdns_cloudflare_candidates";
    /// Source updates, labelled by source and outcome.
    pub const CF_SOURCE_UPDATES_TOTAL: &str = "egressdns_cloudflare_source_updates_total";
    /// Rejected external candidates, labelled by reason.
    pub const CF_CANDIDATE_REJECTED_TOTAL: &str = "egressdns_cloudflare_candidate_rejected_total";
    /// Answers processed in preserve mode.
    pub const CF_PRESERVE_TOTAL: &str = "egressdns_cloudflare_preserve_total";
    /// Answers processed in verified-augment mode.
    pub const CF_AUGMENT_TOTAL: &str = "egressdns_cloudflare_augment_total";
    /// Fallbacks from a stronger mode to a weaker one, labelled by reason.
    pub const CF_FALLBACK_TOTAL: &str = "egressdns_cloudflare_fallback_total";
    /// Number of official prefixes currently loaded, labelled by family.
    pub const CF_PREFIXES: &str = "egressdns_cloudflare_prefixes";
    /// Domain-level validations, labelled by outcome.
    pub const CF_DOMAIN_VALIDATIONS_TOTAL: &str = "egressdns_cloudflare_domain_validations_total";

    // -- ranking -----------------------------------------------------------
    /// Address ordering decisions, labelled by outcome.
    pub const RANKING_DECISIONS_TOTAL: &str = "egressdns_ranking_decisions_total";
    /// Ranking confidence class distribution.
    pub const RANKING_CONFIDENCE_TOTAL: &str = "egressdns_ranking_confidence_total";

    // -- datasets / storage ------------------------------------------------
    /// Dataset reloads, labelled by dataset and outcome.
    pub const DATASET_RELOADS_TOTAL: &str = "egressdns_dataset_reloads_total";
    /// SQLite operations, labelled by operation and outcome.
    pub const STORAGE_OPS_TOTAL: &str = "egressdns_storage_operations_total";
    /// SQLite queue depth.
    pub const STORAGE_QUEUE_DEPTH: &str = "egressdns_storage_queue_depth";
    /// 1 when the persistent store is usable.
    pub const STORAGE_HEALTHY: &str = "egressdns_storage_healthy";

    // -- process -----------------------------------------------------------
    /// Configuration reloads, labelled by outcome.
    pub const CONFIG_RELOADS_TOTAL: &str = "egressdns_config_reloads_total";
    /// 1 when the daemon is ready to answer queries.
    pub const READY: &str = "egressdns_ready";
    /// Process start timestamp in seconds since the epoch.
    pub const START_TIME_SECONDS: &str = "egressdns_start_time_seconds";
    /// Build information, carried entirely in labels with a constant value of 1.
    pub const BUILD_INFO: &str = "egressdns_build_info";
    /// Supervised background tasks that panicked and were restarted.
    pub const TASK_RESTARTS_TOTAL: &str = "egressdns_task_restarts_total";
}

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the Prometheus recorder. Safe to call more than once; later calls are ignored.
///
/// Returns the render handle, or `None` when a recorder was already installed by another
/// component (for example a test harness).
pub fn install() -> Option<PrometheusHandle> {
    if let Some(h) = HANDLE.get() {
        return Some(h.clone());
    }
    let builder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(names::REQUEST_SECONDS.to_string()),
            &[
                0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1,
                0.25, 0.5, 1.0, 2.5,
            ],
        )
        .ok()?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Prefix("egressdns_upstream".to_string()),
            &[
                0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
            ],
        )
        .ok()?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Prefix("egressdns_probe".to_string()),
            &[
                0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0,
            ],
        )
        .ok()?;
    let handle = builder.install_recorder().ok()?;
    let _ = HANDLE.set(handle.clone());
    describe();
    Some(handle)
}

/// Fetch the installed render handle.
pub fn handle() -> Option<PrometheusHandle> {
    HANDLE.get().cloned()
}

/// Register human-readable descriptions for the exported metrics.
fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};
    describe_counter!(names::QUERIES_TOTAL, "Client queries accepted");
    describe_counter!(names::RESPONSES_TOTAL, "Responses returned to clients");
    describe_counter!(names::REJECTED_TOTAL, "Requests refused before resolution");
    describe_histogram!(names::REQUEST_SECONDS, "End-to-end request latency");
    describe_counter!(names::UDP_TRUNCATED_TOTAL, "UDP responses marked truncated");
    describe_counter!(
        names::SPECIAL_USE_TOTAL,
        "Queries answered locally from the special-use domain name registry"
    );
    describe_counter!(
        names::UPSTREAM_SHED_TOTAL,
        "Upstream queries shed at the global concurrency ceiling"
    );
    describe_counter!(
        names::UPSTREAM_LAST_RESORT_TOTAL,
        "Queries sent to an open-circuit route because no alternative was available"
    );
    describe_counter!(
        names::UPSTREAM_FAMILY_FALLBACK_TOTAL,
        "Queries sent to a route whose address family read as unusable because no family \
         read as usable at all"
    );
    describe_counter!(
        names::CORROBORATION_TOTAL,
        "Unsigned negative answers checked against an independent resolver authority"
    );
    describe_gauge!(names::UPSTREAM_INFLIGHT, "Upstream exchanges in flight");
    describe_gauge!(names::DNSSEC_INFLIGHT, "DNSSEC validations in flight");
    describe_counter!(
        names::DNSSEC_SHED_TOTAL,
        "DNSSEC validations shed at the concurrency ceiling"
    );
    describe_gauge!(names::PROBE_WORKERS_ACTIVE, "Probe workers executing a job");
    describe_gauge!(
        names::TCP_ACTIVE_CONNECTIONS,
        "Active DNS-over-TCP connections"
    );
    describe_counter!(
        names::TCP_REJECTED_TOTAL,
        "TCP connections refused by a limit"
    );
    describe_gauge!(
        names::INFLIGHT_QUERIES,
        "Client queries currently in flight"
    );
    describe_counter!(names::CACHE_LOOKUPS_TOTAL, "Cache lookups by outcome");
    describe_gauge!(names::CACHE_ENTRIES, "Entries held per cache");
    describe_counter!(names::CACHE_EVICTIONS_TOTAL, "Cache evictions");
    describe_gauge!(names::CACHE_BYTES, "Approximate cached answer bytes");
    describe_counter!(
        names::SINGLEFLIGHT_COALESCED_TOTAL,
        "Requests merged into an in-flight upstream operation"
    );
    describe_counter!(names::PREFETCH_TOTAL, "Prefetch operations by outcome");
    describe_counter!(names::UPSTREAM_QUERIES_TOTAL, "Upstream queries by outcome");
    describe_histogram!(names::UPSTREAM_SECONDS, "Upstream query latency");
    describe_gauge!(
        names::UPSTREAM_CIRCUIT_STATE,
        "Circuit breaker state: 0 closed, 1 suspect, 2 open, 3 half-open"
    );
    describe_counter!(names::UPSTREAM_HEDGES_TOTAL, "Hedge requests issued");
    describe_counter!(
        names::UPSTREAM_DUPLICATES_TOTAL,
        "Duplicate upstream queries caused by hedging or fan-out"
    );
    describe_counter!(
        names::UPSTREAM_TCP_RETRY_TOTAL,
        "Truncated UDP answers retried over a stream transport"
    );
    describe_counter!(
        names::VARIANTS_OBSERVED_TOTAL,
        "Alternate answer variants observed"
    );
    describe_counter!(
        names::VARIANT_SWITCH_TOTAL,
        "Answer variant selection changes"
    );
    describe_counter!(names::DNSSEC_RESULTS_TOTAL, "DNSSEC validation results");
    describe_counter!(names::EDE_EMITTED_TOTAL, "Extended DNS Errors emitted");
    describe_counter!(names::SERVE_STALE_TOTAL, "Stale answers served");
    describe_gauge!(names::PROBE_QUEUE_DEPTH, "Probe queue depth");
    describe_counter!(names::PROBE_DROPPED_TOTAL, "Probe jobs dropped");
    describe_counter!(names::PROBE_RESULTS_TOTAL, "Probe results by class");
    describe_histogram!(names::PROBE_SECONDS, "Probe latency");
    describe_gauge!(names::PROBE_SUBSYSTEM_HEALTHY, "Probe subsystem health");
    describe_counter!(
        names::PROBE_BANDWIDTH_BYTES,
        "Throughput probe bytes consumed"
    );
    describe_gauge!(names::NETWORK_FAMILY_STATE, "Address family usability");
    describe_gauge!(names::NETWORK_GENERATION, "Current network generation");
    describe_counter!(
        names::NETWORK_GENERATION_CHANGES_TOTAL,
        "Network generation changes"
    );
    describe_gauge!(names::CF_CANDIDATES, "Cloudflare candidate pool size");
    describe_counter!(names::CF_SOURCE_UPDATES_TOTAL, "Cloudflare source updates");
    describe_counter!(
        names::CF_CANDIDATE_REJECTED_TOTAL,
        "External Cloudflare candidates rejected"
    );
    describe_counter!(
        names::CF_PRESERVE_TOTAL,
        "Answers processed in preserve mode"
    );
    describe_counter!(
        names::CF_AUGMENT_TOTAL,
        "Answers processed in verified-augment mode"
    );
    describe_counter!(names::CF_FALLBACK_TOTAL, "Cloudflare policy fallbacks");
    describe_gauge!(names::CF_PREFIXES, "Official Cloudflare prefixes loaded");
    describe_counter!(
        names::CF_DOMAIN_VALIDATIONS_TOTAL,
        "Cloudflare domain-level validations"
    );
    describe_counter!(names::RANKING_DECISIONS_TOTAL, "Address ordering decisions");
    describe_counter!(
        names::RANKING_CONFIDENCE_TOTAL,
        "Ranking confidence classes"
    );
    describe_counter!(names::DATASET_RELOADS_TOTAL, "Dataset reloads");
    describe_counter!(names::STORAGE_OPS_TOTAL, "Persistent storage operations");
    describe_gauge!(names::STORAGE_QUEUE_DEPTH, "Persistent storage queue depth");
    describe_gauge!(names::STORAGE_HEALTHY, "Persistent storage health");
    describe_counter!(names::CONFIG_RELOADS_TOTAL, "Configuration reloads");
    describe_gauge!(names::READY, "Daemon readiness");
    describe_gauge!(names::START_TIME_SECONDS, "Process start time");
    describe_gauge!(names::BUILD_INFO, "Build information");
    describe_counter!(names::TASK_RESTARTS_TOTAL, "Supervised task restarts");
}

/// Record static build information.
pub fn record_build_info() {
    metrics::gauge!(
        names::BUILD_INFO,
        "version" => crate::VERSION,
        "rustc" => env!("EGRESSDNS_RUSTC_VERSION"),
    )
    .set(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_are_prefixed_and_unique() {
        let all = [
            names::QUERIES_TOTAL,
            names::RESPONSES_TOTAL,
            names::REJECTED_TOTAL,
            names::REQUEST_SECONDS,
            names::UDP_TRUNCATED_TOTAL,
            names::SPECIAL_USE_TOTAL,
            names::UPSTREAM_SHED_TOTAL,
            names::UPSTREAM_INFLIGHT,
            names::UPSTREAM_LAST_RESORT_TOTAL,
            names::UPSTREAM_FAMILY_FALLBACK_TOTAL,
            names::CORROBORATION_TOTAL,
            names::DNSSEC_INFLIGHT,
            names::DNSSEC_SHED_TOTAL,
            names::PROBE_WORKERS_ACTIVE,
            names::TCP_ACTIVE_CONNECTIONS,
            names::TCP_REJECTED_TOTAL,
            names::INFLIGHT_QUERIES,
            names::CACHE_LOOKUPS_TOTAL,
            names::CACHE_ENTRIES,
            names::CACHE_EVICTIONS_TOTAL,
            names::CACHE_BYTES,
            names::SINGLEFLIGHT_COALESCED_TOTAL,
            names::PREFETCH_TOTAL,
            names::UPSTREAM_QUERIES_TOTAL,
            names::UPSTREAM_SECONDS,
            names::UPSTREAM_CIRCUIT_STATE,
            names::UPSTREAM_HEDGES_TOTAL,
            names::UPSTREAM_DUPLICATES_TOTAL,
            names::UPSTREAM_TCP_RETRY_TOTAL,
            names::VARIANTS_OBSERVED_TOTAL,
            names::VARIANT_SWITCH_TOTAL,
            names::DNSSEC_RESULTS_TOTAL,
            names::EDE_EMITTED_TOTAL,
            names::SERVE_STALE_TOTAL,
            names::PROBE_QUEUE_DEPTH,
            names::PROBE_DROPPED_TOTAL,
            names::PROBE_RESULTS_TOTAL,
            names::PROBE_SECONDS,
            names::PROBE_SUBSYSTEM_HEALTHY,
            names::PROBE_BANDWIDTH_BYTES,
            names::NETWORK_FAMILY_STATE,
            names::NETWORK_GENERATION,
            names::NETWORK_GENERATION_CHANGES_TOTAL,
            names::CF_CANDIDATES,
            names::CF_SOURCE_UPDATES_TOTAL,
            names::CF_CANDIDATE_REJECTED_TOTAL,
            names::CF_PRESERVE_TOTAL,
            names::CF_AUGMENT_TOTAL,
            names::CF_FALLBACK_TOTAL,
            names::CF_PREFIXES,
            names::CF_DOMAIN_VALIDATIONS_TOTAL,
            names::RANKING_DECISIONS_TOTAL,
            names::RANKING_CONFIDENCE_TOTAL,
            names::DATASET_RELOADS_TOTAL,
            names::STORAGE_OPS_TOTAL,
            names::STORAGE_QUEUE_DEPTH,
            names::STORAGE_HEALTHY,
            names::CONFIG_RELOADS_TOTAL,
            names::READY,
            names::START_TIME_SECONDS,
            names::BUILD_INFO,
            names::TASK_RESTARTS_TOTAL,
        ];
        let mut seen = std::collections::HashSet::new();
        for n in all {
            assert!(n.starts_with("egressdns_"), "{n} lacks the crate prefix");
            assert!(seen.insert(n), "duplicate metric name {n}");
        }
    }
}
