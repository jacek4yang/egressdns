//! Semantic validation of a fully deserialized configuration tree.
//!
//! Validation runs before any activation, including SIGHUP reloads, so an invalid
//! candidate configuration can never replace a working one.

use std::collections::HashSet;

use crate::error::ConfigError;
use crate::util::ipclass;

use super::{AnyPolicy, CloudflareMode, Config, DnssecMode, EcsMode, ProbeProfile, TransportKind};

fn err(path: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::invalid(path, message)
}

/// RFC 9520's ceiling on `cache.failure_max_ttl`.
///
/// The failures cache sizes its hard retention bound from this constant (see
/// `src/cache/mod.rs`), so the retention bound stays valid no matter how a reload
/// changes the configured value within the permitted range.
pub const FAILURE_MAX_TTL_CEILING: std::time::Duration = std::time::Duration::from_secs(300);

/// Validate a configuration tree. Returns the first violation encountered, with the full
/// dotted field path.
pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    validate_server(cfg)?;
    validate_cache_and_ttl(cfg)?;
    validate_upstream(cfg)?;
    validate_dnssec(cfg)?;
    validate_ecs(cfg)?;
    validate_probe(cfg)?;
    validate_cloudflare(cfg)?;
    validate_local(cfg)?;
    validate_observability(cfg)?;
    Ok(())
}

fn validate_server(cfg: &Config) -> Result<(), ConfigError> {
    let s = &cfg.server;
    if s.udp_listen.is_empty() && s.tcp_listen.is_empty() {
        return Err(err(
            "server.udp_listen",
            "at least one UDP or TCP listen address is required",
        ));
    }
    let mut seen = HashSet::new();
    for a in &s.udp_listen {
        if !seen.insert(("udp", *a)) {
            return Err(err("server.udp_listen", format!("duplicate address {a}")));
        }
    }
    for a in &s.tcp_listen {
        if !seen.insert(("tcp", *a)) {
            return Err(err("server.tcp_listen", format!("duplicate address {a}")));
        }
    }
    if s.udp.max_payload < 512 {
        return Err(err(
            "server.udp.max_payload",
            "must be at least 512 bytes (RFC 1035 minimum)",
        ));
    }
    if s.udp.max_payload > 4096 {
        return Err(err(
            "server.udp.max_payload",
            "must not exceed 4096 bytes; values above the path MTU cause IP fragmentation \
             (RFC 9715)",
        ));
    }
    if s.udp.non_edns_max_payload != 512 {
        return Err(err(
            "server.udp.non_edns_max_payload",
            "RFC 1035 fixes the non-EDNS UDP limit at 512 bytes",
        ));
    }
    if s.udp.workers_per_socket == 0 {
        return Err(err("server.udp.workers_per_socket", "must be at least 1"));
    }
    if s.udp.workers_per_socket > 1 && !s.udp.reuse_port {
        return Err(err(
            "server.udp.workers_per_socket",
            "more than one worker per socket requires server.udp.reuse_port = true",
        ));
    }
    if s.tcp.max_connections == 0 {
        return Err(err("server.tcp.max_connections", "must be at least 1"));
    }
    if s.tcp.max_connections_per_client == 0 {
        return Err(err(
            "server.tcp.max_connections_per_client",
            "must be at least 1",
        ));
    }
    if s.tcp.max_connections_per_client > s.tcp.max_connections {
        return Err(err(
            "server.tcp.max_connections_per_client",
            "must not exceed server.tcp.max_connections",
        ));
    }
    if s.tcp.max_message_bytes < 512 || s.tcp.max_message_bytes > 65_535 {
        return Err(err(
            "server.tcp.max_message_bytes",
            "must be between 512 and 65535",
        ));
    }
    if s.tcp.max_pipelined_queries == 0 {
        return Err(err(
            "server.tcp.max_pipelined_queries",
            "must be at least 1",
        ));
    }
    if s.foreground_budget.as_millis() == 0 {
        return Err(err("server.foreground_budget", "must be greater than zero"));
    }
    if s.foreground_budget.as_secs() > 30 {
        return Err(err(
            "server.foreground_budget",
            "must not exceed 30 seconds; clients give up long before that",
        ));
    }
    if s.rate_limit.enabled {
        if s.rate_limit.per_client_qps == 0 {
            return Err(err(
                "server.rate_limit.per_client_qps",
                "must be greater than zero when rate limiting is enabled",
            ));
        }
        if s.rate_limit.global_qps == 0 {
            return Err(err(
                "server.rate_limit.global_qps",
                "must be greater than zero when rate limiting is enabled",
            ));
        }
        if s.rate_limit.per_client_burst < s.rate_limit.per_client_qps {
            return Err(err(
                "server.rate_limit.per_client_burst",
                "burst must be at least the sustained rate",
            ));
        }
        if s.rate_limit.global_burst < s.rate_limit.global_qps {
            return Err(err(
                "server.rate_limit.global_burst",
                "burst must be at least the sustained rate",
            ));
        }
        if s.rate_limit.client_table_size == 0 {
            return Err(err(
                "server.rate_limit.client_table_size",
                "must be greater than zero",
            ));
        }
    }
    // A non-loopback listener with an empty ACL would be an open resolver.
    let exposed = s
        .udp_listen
        .iter()
        .chain(s.tcp_listen.iter())
        .any(|a| !a.ip().is_loopback());
    // Omission and explicit emptiness are different intentions and get different
    // answers. On loopback, omission means "the default, which is this machine". On a
    // non-loopback listener there is no safe default to infer — the operator has to say
    // who the resolver is for, because the alternative guess is an open resolver.
    match &s.allow_from {
        None if exposed => {
            return Err(err(
                "server.allow_from",
                "a non-loopback listener requires an explicit list of allowed client \
                 networks; without one this would be an open resolver. Add for example \
                 allow_from = [\"192.168.0.0/16\", \"127.0.0.0/8\", \"::1/128\"]",
            ));
        }
        // Explicitly empty is a deliberate deny-all and is respected, including on an
        // exposed listener, where it is a way to bind now and admit clients later.
        None | Some(_) => {}
    }
    for net in s.allow_from.iter().flatten() {
        if net.addr().is_multicast() {
            return Err(err(
                "server.allow_from",
                format!("{net} is a multicast range and cannot identify a client"),
            ));
        }
    }
    if matches!(s.any_policy, AnyPolicy::Forward) && exposed {
        // Not an error, but forwarding ANY from an exposed listener is an amplification
        // risk that must be a deliberate choice; require rate limiting to be on.
        if !s.rate_limit.enabled {
            return Err(err(
                "server.any_policy",
                "forwarding ANY queries from a non-loopback listener requires \
                 server.rate_limit.enabled = true (RFC 8482 amplification risk)",
            ));
        }
    }
    Ok(())
}

fn validate_cache_and_ttl(cfg: &Config) -> Result<(), ConfigError> {
    let c = &cfg.cache;
    if c.max_memory_bytes < 1024 * 1024 {
        return Err(err("cache.max_memory_bytes", "must be at least 1 MiB"));
    }
    if c.variant_max_memory_bytes < 1024 * 1024 {
        return Err(err(
            "cache.variant_max_memory_bytes",
            "must be at least 1 MiB",
        ));
    }
    if c.variant_max_memory_bytes > c.max_memory_bytes {
        return Err(err(
            "cache.variant_max_memory_bytes",
            "must not exceed cache.max_memory_bytes; alternate variants are a diagnostic \
             aid and must never outweigh the answers themselves",
        ));
    }
    if c.internal_max_ttl == 0 {
        return Err(err("cache.internal_max_ttl", "must be greater than zero"));
    }
    if c.internal_max_ttl > 604_800 {
        return Err(err(
            "cache.internal_max_ttl",
            "must not exceed 604800 seconds (7 days)",
        ));
    }
    if c.negative_max_ttl > 86_400 {
        return Err(err(
            "cache.negative_max_ttl",
            "must not exceed 86400 seconds (RFC 2308 section 5)",
        ));
    }
    if c.failure_min_ttl.as_secs() < 1 {
        return Err(err(
            "cache.failure_min_ttl",
            "RFC 9520 requires resolution failures to be cached for at least 1 second",
        ));
    }
    if c.failure_max_ttl > FAILURE_MAX_TTL_CEILING {
        return Err(err(
            "cache.failure_max_ttl",
            "RFC 9520 requires resolution failures to be cached for no more than 5 minutes",
        ));
    }
    if c.failure_max_ttl < c.failure_min_ttl {
        return Err(err(
            "cache.failure_max_ttl",
            "must not be smaller than cache.failure_min_ttl",
        ));
    }

    let t = &cfg.ttl;
    for (name, value) in [
        ("ttl.cap_default", t.cap_default),
        ("ttl.cap_optimized_multi", t.cap_optimized_multi),
        ("ttl.cap_cloudflare_preserve", t.cap_cloudflare_preserve),
        ("ttl.cap_cloudflare_augment", t.cap_cloudflare_augment),
        ("ttl.cap_network_change", t.cap_network_change),
        ("ttl.cap_serve_stale", t.cap_serve_stale),
    ] {
        if value == 0 {
            return Err(err(
                name,
                "must be greater than zero; a zero TTL cap defeats client caching entirely",
            ));
        }
        if value > 86_400 {
            return Err(err(name, "must not exceed 86400 seconds"));
        }
    }
    if t.cap_cloudflare_augment > 60 {
        return Err(err(
            "ttl.cap_cloudflare_augment",
            "augmented answers must expire quickly; the cap must not exceed 60 seconds",
        ));
    }

    let ss = &cfg.serve_stale;
    if ss.enabled {
        if ss.max_stale.as_secs() == 0 {
            return Err(err(
                "serve_stale.max_stale",
                "must be greater than zero when serve-stale is enabled",
            ));
        }
        if ss.max_stale.as_secs() > 7 * 86_400 {
            return Err(err(
                "serve_stale.max_stale",
                "must not exceed 7 days (RFC 8767 recommends 1 to 3 days)",
            ));
        }
        if ss.client_timeout >= cfg.server.foreground_budget {
            return Err(err(
                "serve_stale.client_timeout",
                "must be shorter than server.foreground_budget",
            ));
        }
        if ss.client_timeout.as_millis() > 1_800 {
            return Err(err(
                "serve_stale.client_timeout",
                "RFC 8767 section 5 recommends a client response timer below 1.8 seconds",
            ));
        }
    }

    let r = &cfg.ranking;
    if !(0.0..=1.0).contains(&r.hysteresis) {
        return Err(err("ranking.hysteresis", "must be between 0.0 and 1.0"));
    }
    if !(0.0..=0.5).contains(&r.exploration_rate) {
        return Err(err(
            "ranking.exploration_rate",
            "must be between 0.0 and 0.5",
        ));
    }
    if r.neutral_cost_ms <= 0.0 {
        return Err(err("ranking.neutral_cost_ms", "must be greater than zero"));
    }
    if r.consecutive_failure_base < 1.0 {
        return Err(err(
            "ranking.consecutive_failure_base",
            "must be at least 1.0 so repeated failures never reduce the penalty",
        ));
    }
    if r.evidence_half_life.as_secs() == 0 {
        return Err(err(
            "ranking.evidence_half_life",
            "must be greater than zero",
        ));
    }

    let p = &cfg.prefetch;
    if p.enabled {
        if !(0.01..=0.9).contains(&p.trigger_fraction) {
            return Err(err(
                "prefetch.trigger_fraction",
                "must be between 0.01 and 0.9",
            ));
        }
        if p.global_qps == 0 {
            return Err(err(
                "prefetch.global_qps",
                "must be greater than zero when prefetch is enabled",
            ));
        }
        if p.hot_set_size == 0 {
            return Err(err("prefetch.hot_set_size", "must be greater than zero"));
        }
        if p.transition_prediction && p.transition_table_size == 0 {
            return Err(err(
                "prefetch.transition_table_size",
                "must be greater than zero when transition prediction is enabled",
            ));
        }
    }
    Ok(())
}

fn validate_upstream(cfg: &Config) -> Result<(), ConfigError> {
    let u = &cfg.upstream;
    if u.groups.is_empty() {
        return Err(err("upstream.groups", "at least one group is required"));
    }
    let mut names = HashSet::new();
    for (gi, g) in u.groups.iter().enumerate() {
        let gp = format!("upstream.groups[{gi}]");
        if g.name.trim().is_empty() {
            return Err(err(format!("{gp}.name"), "must not be empty"));
        }
        if !names.insert(g.name.clone()) {
            return Err(err(
                format!("{gp}.name"),
                format!("duplicate group name `{}`", g.name),
            ));
        }
        if g.servers.iter().filter(|s| s.enabled).count() == 0 {
            return Err(err(
                format!("{gp}.servers"),
                "at least one enabled server is required",
            ));
        }
        let mut server_names = HashSet::new();
        for (si, s) in g.servers.iter().enumerate() {
            let sp = format!("{gp}.servers[{si}]");
            if s.name.trim().is_empty() {
                return Err(err(format!("{sp}.name"), "must not be empty"));
            }
            if !server_names.insert(s.name.clone()) {
                return Err(err(
                    format!("{sp}.name"),
                    format!("duplicate server name `{}` inside group", s.name),
                ));
            }
            if s.addresses.is_empty() {
                return Err(err(
                    format!("{sp}.addresses"),
                    "at least one literal address is required; encrypted upstreams need \
                     bootstrap addresses so the resolver never resolves its own upstream",
                ));
            }
            for a in &s.addresses {
                if let Some(class) = ipclass::classify(*a) {
                    // Private and loopback upstreams are legitimate: an internal
                    // forwarder, or a co-located resolver on 127.0.0.1:5353. Multicast,
                    // documentation, benchmarking and link-local ranges are not.
                    if !matches!(
                        class,
                        ipclass::SpecialUse::Private
                            | ipclass::SpecialUse::SharedAddressSpace
                            | ipclass::SpecialUse::Loopback
                    ) {
                        return Err(err(
                            format!("{sp}.addresses"),
                            format!(
                                "{a} is a {} address and cannot be an upstream",
                                class.label()
                            ),
                        ));
                    }
                }
            }
            if s.transport.is_encrypted() {
                match &s.server_name {
                    None => {
                        return Err(err(
                            format!("{sp}.server_name"),
                            "encrypted transports require a TLS server name for SNI and \
                             certificate verification",
                        ));
                    }
                    Some(name) if name.trim().is_empty() => {
                        return Err(err(format!("{sp}.server_name"), "must not be empty"));
                    }
                    Some(name) if name.parse::<std::net::IpAddr>().is_ok() => {
                        return Err(err(
                            format!("{sp}.server_name"),
                            "must be a DNS name, not an IP address",
                        ));
                    }
                    Some(_) => {}
                }
            }
            match s.transport {
                TransportKind::Doh2 | TransportKind::Doh3 => {
                    let path = s.path.as_deref().unwrap_or("/dns-query");
                    if !path.starts_with('/') {
                        return Err(err(
                            format!("{sp}.path"),
                            "DoH path must start with `/` (RFC 8484 section 4.1)",
                        ));
                    }
                }
                _ => {
                    if s.path.is_some() {
                        return Err(err(
                            format!("{sp}.path"),
                            "path is only meaningful for DoH transports",
                        ));
                    }
                }
            }
            if s.trust_ad && !s.transport.is_encrypted() {
                return Err(err(
                    format!("{sp}.trust_ad"),
                    "trusting an upstream AD bit requires an authenticated transport",
                ));
            }
            if s.enable_cookies == Some(true) && s.transport.is_encrypted() {
                // Cookies add nothing over an authenticated transport; requesting them
                // explicitly is a misunderstanding worth surfacing.
                return Err(err(
                    format!("{sp}.enable_cookies"),
                    "DNS Cookies apply to UDP and TCP transports only; omit the field or \
                     set false for encrypted transports",
                ));
            }
            if s.weight == 0 {
                return Err(err(format!("{sp}.weight"), "must be greater than zero"));
            }
        }

        let sc = &g.scheduler;
        let scp = format!("{gp}.scheduler");
        if !(0.5..=0.999).contains(&sc.hedge_percentile) {
            return Err(err(
                format!("{scp}.hedge_percentile"),
                "must be between 0.5 and 0.999",
            ));
        }
        if sc.hedge_min_delay > sc.hedge_max_delay {
            return Err(err(
                format!("{scp}.hedge_min_delay"),
                "must not exceed scheduler.hedge_max_delay",
            ));
        }
        if !(0.0..=1.0).contains(&sc.hedge_max_fraction) {
            return Err(err(
                format!("{scp}.hedge_max_fraction"),
                "must be between 0.0 and 1.0",
            ));
        }
        if sc.query_timeout.as_millis() == 0 {
            return Err(err(
                format!("{scp}.query_timeout"),
                "must be greater than zero",
            ));
        }
        if sc.query_timeout > cfg.server.foreground_budget {
            return Err(err(
                format!("{scp}.query_timeout"),
                "must not exceed server.foreground_budget",
            ));
        }
        if !(0.0..=0.5).contains(&sc.explore_rate) {
            return Err(err(
                format!("{scp}.explore_rate"),
                "must be between 0.0 and 0.5",
            ));
        }
        if sc.circuit_failure_threshold == 0 {
            return Err(err(
                format!("{scp}.circuit_failure_threshold"),
                "must be greater than zero",
            ));
        }
        if sc.circuit_half_open_successes == 0 {
            return Err(err(
                format!("{scp}.circuit_half_open_successes"),
                "must be greater than zero",
            ));
        }
        if sc.emergency_fanout && sc.emergency_fanout_max == 0 {
            return Err(err(
                format!("{scp}.emergency_fanout_max"),
                "must be greater than zero when emergency fan-out is enabled",
            ));
        }
    }
    if !names.contains(&u.default_group) {
        return Err(err(
            "upstream.default_group",
            format!("group `{}` is not defined", u.default_group),
        ));
    }
    for (i, f) in u.tls.extra_ca_files.iter().enumerate() {
        if !f.is_absolute() {
            return Err(err(
                format!("upstream.tls.extra_ca_files[{i}]"),
                "must be an absolute path",
            ));
        }
    }
    if u.tls.quic_zero_rtt {
        return Err(err(
            "upstream.tls.quic_zero_rtt",
            "QUIC 0-RTT is not supported: early data is replayable and this build refuses \
             to offer it. See docs/THREAT_MODEL.md",
        ));
    }
    Ok(())
}

fn validate_dnssec(cfg: &Config) -> Result<(), ConfigError> {
    let d = &cfg.dnssec;
    if d.max_concurrent_validations == 0 {
        return Err(err(
            "dnssec.max_concurrent_validations",
            "must be greater than zero",
        ));
    }
    if d.trust_upstream_ad && matches!(d.mode, DnssecMode::Validate) {
        return Err(err(
            "dnssec.trust_upstream_ad",
            "cannot trust an upstream AD bit while performing local validation; choose one",
        ));
    }
    if d.trust_upstream_ad {
        let any_trusted = cfg
            .upstream
            .groups
            .iter()
            .flat_map(|g| g.servers.iter())
            .any(|s| s.trust_ad);
        if !any_trusted {
            return Err(err(
                "dnssec.trust_upstream_ad",
                "no upstream server sets trust_ad = true",
            ));
        }
    }
    if let Some(p) = &d.trust_anchor_file {
        if !p.is_absolute() {
            return Err(err("dnssec.trust_anchor_file", "must be an absolute path"));
        }
    }
    Ok(())
}

fn validate_ecs(cfg: &Config) -> Result<(), ConfigError> {
    let e = &cfg.ecs;
    if matches!(e.mode, EcsMode::FixedEgress) {
        if e.egress.ipv4.is_none() && e.egress.ipv6.is_none() {
            return Err(err(
                "ecs.egress",
                "fixed-egress mode requires at least one explicit public prefix",
            ));
        }
        if let Some(net) = e.egress.ipv4 {
            if ipclass::classify_v4(net.addr()).is_some() {
                return Err(err(
                    "ecs.egress.ipv4",
                    "must be a public prefix; a private or special-use prefix must never be \
                     sent upstream",
                ));
            }
            if net.prefix_len() > 24 {
                return Err(err(
                    "ecs.egress.ipv4",
                    "prefix must not be longer than /24 (RFC 7871 privacy guidance)",
                ));
            }
        }
        if let Some(net) = e.egress.ipv6 {
            if ipclass::classify_v6(net.addr()).is_some() {
                return Err(err("ecs.egress.ipv6", "must be a public prefix"));
            }
            if net.prefix_len() > 56 {
                return Err(err(
                    "ecs.egress.ipv6",
                    "prefix must not be longer than /56 (RFC 7871 privacy guidance)",
                ));
            }
        }
    }
    for (gi, g) in cfg.upstream.groups.iter().enumerate() {
        for (si, s) in g.servers.iter().enumerate() {
            if let Some(scope) = &s.ecs {
                let p = format!("upstream.groups[{gi}].servers[{si}].ecs");
                if let Some(net) = scope.ipv4 {
                    if ipclass::classify_v4(net.addr()).is_some() {
                        return Err(err(format!("{p}.ipv4"), "must be a public prefix"));
                    }
                }
                if let Some(net) = scope.ipv6 {
                    if ipclass::classify_v6(net.addr()).is_some() {
                        return Err(err(format!("{p}.ipv6"), "must be a public prefix"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_probe(cfg: &Config) -> Result<(), ConfigError> {
    let p = &cfg.probe;
    if !p.enabled {
        return Ok(());
    }
    for (name, v) in [
        ("probe.queue_size", p.queue_size),
        ("probe.concurrency", p.concurrency),
        ("probe.max_candidates_per_rrset", p.max_candidates_per_rrset),
    ] {
        if v == 0 {
            return Err(err(name, "must be greater than zero"));
        }
    }
    if p.concurrency > 256 {
        return Err(err(
            "probe.concurrency",
            "must not exceed 256, to keep the egress footprint bounded",
        ));
    }
    if p.global_connections_per_second == 0 || p.global_connections_per_second > 10_000 {
        return Err(err(
            "probe.global_connections_per_second",
            "must be between 1 and 10000",
        ));
    }
    if p.max_response_bytes == 0 || p.max_response_bytes > 1024 * 1024 {
        return Err(err(
            "probe.max_response_bytes",
            "must be between 1 and 1048576",
        ));
    }
    if p.extra_ports.contains(&0) {
        return Err(err("probe.extra_ports", "port 0 is not valid"));
    }
    if p.extra_ports.len() > 8 {
        return Err(err(
            "probe.extra_ports",
            "at most 8 extra ports may be configured; this is not a port scanner",
        ));
    }
    for (i, net) in p.allow_special_use_targets.iter().enumerate() {
        if ipclass::classify(net.addr()).is_none() {
            return Err(err(
                format!("probe.allow_special_use_targets[{i}]"),
                "entry is already global unicast and does not need an exception",
            ));
        }
        if matches!(
            ipclass::classify(net.addr()),
            Some(ipclass::SpecialUse::CloudMetadata) | Some(ipclass::SpecialUse::LinkLocal)
        ) {
            return Err(err(
                format!("probe.allow_special_use_targets[{i}]"),
                "link-local and cloud metadata ranges can never be probe targets",
            ));
        }
    }
    let mut profile_names = HashSet::new();
    for (i, prof) in p.profiles.iter().enumerate() {
        validate_profile(&format!("probe.profiles[{i}]"), prof)?;
        if !profile_names.insert(prof.name.clone()) {
            return Err(err(
                format!("probe.profiles[{i}].name"),
                format!("duplicate profile name `{}`", prof.name),
            ));
        }
    }
    Ok(())
}

fn validate_profile(path: &str, prof: &ProbeProfile) -> Result<(), ConfigError> {
    if prof.name.trim().is_empty() {
        return Err(err(format!("{path}.name"), "must not be empty"));
    }
    if prof.domains.is_empty() {
        return Err(err(
            format!("{path}.domains"),
            "must list at least one domain",
        ));
    }
    if !prof.path.starts_with('/') {
        return Err(err(format!("{path}.path"), "must start with `/`"));
    }
    let method = prof.method.to_ascii_uppercase();
    if method != "HEAD" && method != "GET" {
        return Err(err(
            format!("{path}.method"),
            "only HEAD and GET are permitted for validation probes",
        ));
    }
    if prof.allowed_status.is_empty() {
        return Err(err(
            format!("{path}.allowed_status"),
            "must list at least one acceptable status code",
        ));
    }
    for s in &prof.allowed_status {
        if !(100..=599).contains(s) {
            return Err(err(
                format!("{path}.allowed_status"),
                format!("{s} is not a valid HTTP status code"),
            ));
        }
    }
    if let Some(h) = &prof.body_sha256 {
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(err(
                format!("{path}.body_sha256"),
                "must be a 64-character hex SHA-256 digest",
            ));
        }
    }
    for (i, s) in prof.spki_sha256.iter().enumerate() {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(err(
                format!("{path}.spki_sha256[{i}]"),
                "must be a 64-character hex SHA-256 digest",
            ));
        }
    }
    for (i, a) in prof.alpn.iter().enumerate() {
        if a.is_empty() || a.len() > 32 {
            return Err(err(
                format!("{path}.alpn[{i}]"),
                "ALPN identifiers must be between 1 and 32 bytes",
            ));
        }
    }
    Ok(())
}

fn validate_cloudflare(cfg: &Config) -> Result<(), ConfigError> {
    let c = &cfg.cloudflare;
    if !c.enabled {
        return Ok(());
    }
    if matches!(c.mode, CloudflareMode::VerifiedAugment) && !cfg.probe.enabled {
        return Err(err(
            "cloudflare.mode",
            "verified-augment requires probe.enabled = true; an address can only be added \
             after domain-level validation",
        ));
    }
    for (field, url) in [
        ("cloudflare.official.api_url", &c.official.api_url),
        ("cloudflare.official.ipv4_url", &c.official.ipv4_url),
        ("cloudflare.official.ipv6_url", &c.official.ipv6_url),
    ] {
        if !url.starts_with("https://") {
            return Err(err(field, "must be an absolute https:// URL"));
        }
    }
    if c.official.refresh_interval.as_secs() < 300 {
        return Err(err(
            "cloudflare.official.refresh_interval",
            "must be at least 300 seconds; the published prefix list changes rarely",
        ));
    }
    if c.official.max_response_bytes == 0 || c.official.max_response_bytes > 8 * 1024 * 1024 {
        return Err(err(
            "cloudflare.official.max_response_bytes",
            "must be between 1 and 8388608",
        ));
    }
    if c.official.min_ipv4_prefixes == 0 {
        return Err(err(
            "cloudflare.official.min_ipv4_prefixes",
            "must be greater than zero so an empty response cannot replace a valid snapshot",
        ));
    }
    if c.seeds.enabled {
        if c.seeds.endpoints.iter().filter(|e| e.enabled).count() == 0 {
            return Err(err(
                "cloudflare.seeds.endpoints",
                "at least one enabled endpoint is required when seeds are enabled",
            ));
        }
        let mut names = HashSet::new();
        for (i, e) in c.seeds.endpoints.iter().enumerate() {
            if e.name.trim().is_empty() {
                return Err(err(
                    format!("cloudflare.seeds.endpoints[{i}].name"),
                    "must not be empty",
                ));
            }
            if !names.insert(e.name.clone()) {
                return Err(err(
                    format!("cloudflare.seeds.endpoints[{i}].name"),
                    "duplicate endpoint name",
                ));
            }
            if !e.url.starts_with("https://") {
                return Err(err(
                    format!("cloudflare.seeds.endpoints[{i}].url"),
                    "must be an absolute https:// URL",
                ));
            }
        }
        if c.seeds.refresh_interval.as_secs() < 60 {
            return Err(err(
                "cloudflare.seeds.refresh_interval",
                "must be at least 60 seconds",
            ));
        }
        if c.seeds.max_response_bytes == 0 || c.seeds.max_response_bytes > 4 * 1024 * 1024 {
            return Err(err(
                "cloudflare.seeds.max_response_bytes",
                "must be between 1 and 4194304",
            ));
        }
        if c.seeds.max_addresses_per_response == 0 || c.seeds.max_addresses_per_response > 65_536 {
            return Err(err(
                "cloudflare.seeds.max_addresses_per_response",
                "must be between 1 and 65536",
            ));
        }
    }
    let s = &c.sampling;
    if s.enabled {
        if s.addresses_per_round == 0 || s.addresses_per_round > 4_096 {
            return Err(err(
                "cloudflare.sampling.addresses_per_round",
                "must be between 1 and 4096",
            ));
        }
        if s.max_new_candidates_per_hour == 0 {
            return Err(err(
                "cloudflare.sampling.max_new_candidates_per_hour",
                "must be greater than zero",
            ));
        }
        if s.buckets_per_prefix == 0 || s.buckets_per_prefix > 4_096 {
            return Err(err(
                "cloudflare.sampling.buckets_per_prefix",
                "must be between 1 and 4096",
            ));
        }
        if !(0.0..=1.0).contains(&s.exploit_fraction) {
            return Err(err(
                "cloudflare.sampling.exploit_fraction",
                "must be between 0.0 and 1.0",
            ));
        }
        if s.round_interval.as_secs() < 10 {
            return Err(err(
                "cloudflare.sampling.round_interval",
                "must be at least 10 seconds",
            ));
        }
    }
    let a = &c.augment;
    if a.max_added == 0 || a.max_added > 2 {
        return Err(err(
            "cloudflare.augment.max_added",
            "must be 1 or 2; verified-augment prepends at most two addresses",
        ));
    }
    if a.min_validations == 0 {
        return Err(err(
            "cloudflare.augment.min_validations",
            "must be greater than zero",
        ));
    }
    if !(0.0..=1.0).contains(&a.min_advantage) {
        return Err(err(
            "cloudflare.augment.min_advantage",
            "must be between 0.0 and 1.0",
        ));
    }
    if a.validation_ttl.as_secs() == 0 || a.validation_ttl.as_secs() > 86_400 {
        return Err(err(
            "cloudflare.augment.validation_ttl",
            "must be between 1 second and 24 hours",
        ));
    }
    if c.candidate_pool_max == 0 || c.candidate_pool_max > 1_000_000 {
        return Err(err(
            "cloudflare.candidate_pool_max",
            "must be between 1 and 1000000",
        ));
    }
    if c.probe_hosts.is_empty() {
        return Err(err(
            "cloudflare.probe_hosts",
            "at least one probe hostname is required; relying on a single undocumented \
             endpoint is not acceptable",
        ));
    }
    for (i, h) in c.probe_hosts.iter().enumerate() {
        if h.trim().is_empty() || h.contains('/') {
            return Err(err(
                format!("cloudflare.probe_hosts[{i}]"),
                "must be a bare hostname",
            ));
        }
    }
    for (i, addr) in c.static_candidates.iter().enumerate() {
        if ipclass::classify(*addr).is_some() {
            return Err(err(
                format!("cloudflare.static_candidates[{i}]"),
                "must be a global unicast address",
            ));
        }
    }
    Ok(())
}

fn validate_local(cfg: &Config) -> Result<(), ConfigError> {
    let group_names: HashSet<&str> = cfg
        .upstream
        .groups
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    for (i, r) in cfg.local.suffix_rules.iter().enumerate() {
        if r.suffix.trim().is_empty() {
            return Err(err(
                format!("local.suffix_rules[{i}].suffix"),
                "must not be empty",
            ));
        }
        if !group_names.contains(r.group.as_str()) {
            return Err(err(
                format!("local.suffix_rules[{i}].group"),
                format!("group `{}` is not defined", r.group),
            ));
        }
    }
    for (i, h) in cfg.local.hosts.iter().enumerate() {
        if h.name.trim().is_empty() {
            return Err(err(format!("local.hosts[{i}].name"), "must not be empty"));
        }
        if h.addresses.is_empty() {
            return Err(err(
                format!("local.hosts[{i}].addresses"),
                "must list at least one address",
            ));
        }
    }
    for (i, z) in cfg.local.zones.iter().enumerate() {
        if z.name.trim().is_empty() {
            return Err(err(format!("local.zones[{i}].name"), "must not be empty"));
        }
        for (j, r) in z.records.iter().enumerate() {
            if r.value.trim().is_empty() {
                return Err(err(
                    format!("local.zones[{i}].records[{j}].value"),
                    "must not be empty",
                ));
            }
        }
    }
    if cfg.local.local_ttl == 0 || cfg.local.local_ttl > 86_400 {
        return Err(err("local.local_ttl", "must be between 1 and 86400"));
    }
    if cfg.datasets.max_file_bytes == 0 {
        return Err(err("datasets.max_file_bytes", "must be greater than zero"));
    }
    if cfg.datasets.max_records == 0 {
        return Err(err("datasets.max_records", "must be greater than zero"));
    }
    Ok(())
}

fn validate_observability(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.metrics.enabled
        && !cfg.metrics.listen.ip().is_loopback()
        && !cfg.metrics.allow_non_loopback
    {
        return Err(err(
            "metrics.listen",
            "metrics must be exposed on loopback unless metrics.allow_non_loopback is set",
        ));
    }
    if !(0.0..=1.0).contains(&cfg.logging.query_log_sample) {
        return Err(err(
            "logging.query_log_sample",
            "must be between 0.0 and 1.0",
        ));
    }
    if cfg.admin.enabled {
        if !cfg.admin.socket.is_absolute() {
            return Err(err("admin.socket", "must be an absolute path"));
        }
        if cfg.admin.socket_mode & 0o007 != 0 {
            return Err(err(
                "admin.socket_mode",
                "must not grant any permission to other users",
            ));
        }
        if cfg.admin.max_request_bytes == 0 || cfg.admin.max_request_bytes > 1024 * 1024 {
            return Err(err(
                "admin.max_request_bytes",
                "must be between 1 and 1048576",
            ));
        }
    }
    if cfg.storage.enabled {
        if !cfg.storage.path.is_absolute() {
            return Err(err("storage.path", "must be an absolute path"));
        }
        if cfg.storage.queue_size == 0 {
            return Err(err("storage.queue_size", "must be greater than zero"));
        }
    }
    if let Some(w) = cfg.resources.worker_threads {
        if w == 0 || w > 512 {
            return Err(err("resources.worker_threads", "must be between 1 and 512"));
        }
    }
    if cfg.resources.max_inflight_queries == 0 {
        return Err(err(
            "resources.max_inflight_queries",
            "must be greater than zero",
        ));
    }
    if cfg.resources.max_inflight_upstream == 0 {
        return Err(err(
            "resources.max_inflight_upstream",
            "must be greater than zero",
        ));
    }
    if cfg.resources.max_blocking_threads == 0 || cfg.resources.max_blocking_threads > 128 {
        return Err(err(
            "resources.max_blocking_threads",
            "must be between 1 and 128",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TransportKind, UpstreamServerConfig};

    fn base() -> Config {
        Config::default()
    }

    fn with_server(server: UpstreamServerConfig) -> Config {
        let mut cfg = base();
        cfg.upstream.groups[0].servers = vec![server];
        cfg
    }

    #[test]
    fn the_shipped_defaults_are_valid() {
        validate(&Config::default()).expect("default configuration must validate");
    }

    #[test]
    fn loopback_and_private_upstreams_are_allowed() {
        for addr in ["127.0.0.1", "10.0.0.53", "::1"] {
            let cfg = with_server(UpstreamServerConfig {
                name: "local".into(),
                transport: TransportKind::Udp,
                addresses: vec![addr.parse().expect("ip")],
                port: Some(5_353),
                ..UpstreamServerConfig::default()
            });
            validate(&cfg).unwrap_or_else(|e| panic!("{addr} should be allowed: {e}"));
        }
    }

    #[test]
    fn nonsense_upstream_addresses_are_refused() {
        for addr in ["224.0.0.1", "192.0.2.1", "169.254.169.254", "0.0.0.0"] {
            let cfg = with_server(UpstreamServerConfig {
                name: "bad".into(),
                transport: TransportKind::Udp,
                addresses: vec![addr.parse().expect("ip")],
                ..UpstreamServerConfig::default()
            });
            assert!(validate(&cfg).is_err(), "{addr} should be refused");
        }
    }

    #[test]
    fn encrypted_upstreams_require_a_server_name() {
        let cfg = with_server(UpstreamServerConfig {
            name: "dot".into(),
            transport: TransportKind::Dot,
            addresses: vec!["9.9.9.9".parse().expect("ip")],
            server_name: None,
            ..UpstreamServerConfig::default()
        });
        let err = validate(&cfg).expect_err("must fail");
        assert!(err.to_string().contains("server_name"));
    }

    #[test]
    fn a_non_loopback_listener_requires_an_acl() {
        let mut cfg = base();
        cfg.server.udp_listen = vec!["0.0.0.0:53".parse().expect("addr")];
        cfg.server.tcp_listen = vec![];
        cfg.server.allow_from = None;
        let err = validate(&cfg).expect_err("must fail");
        assert!(err.to_string().contains("allow_from"));
    }

    #[test]
    fn quic_zero_rtt_cannot_be_enabled() {
        let mut cfg = base();
        cfg.upstream.tls.quic_zero_rtt = true;
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn verified_augment_requires_probing() {
        let mut cfg = base();
        cfg.cloudflare.enabled = true;
        cfg.cloudflare.mode = crate::config::CloudflareMode::VerifiedAugment;
        cfg.probe.enabled = false;
        let err = validate(&cfg).expect_err("must fail");
        assert!(err.to_string().contains("verified-augment"));
    }

    #[test]
    fn ecs_rejects_private_prefixes() {
        let mut cfg = base();
        cfg.ecs.mode = crate::config::EcsMode::FixedEgress;
        cfg.ecs.egress.ipv4 = Some("10.0.0.0/24".parse().expect("net"));
        assert!(validate(&cfg).is_err());
        cfg.ecs.egress.ipv4 = Some("203.0.113.0/24".parse().expect("net"));
        // 203.0.113.0/24 is documentation space, which is also refused.
        assert!(validate(&cfg).is_err());
        cfg.ecs.egress.ipv4 = Some("198.51.0.0/24".parse().expect("net"));
        validate(&cfg).expect("a public prefix is accepted");
    }

    #[test]
    fn probe_exceptions_can_never_cover_metadata_ranges() {
        let mut cfg = base();
        cfg.probe.allow_special_use_targets = vec!["169.254.0.0/16".parse().expect("net")];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn serve_stale_timer_must_stay_below_the_foreground_budget() {
        let mut cfg = base();
        cfg.serve_stale.client_timeout = cfg.server.foreground_budget;
        assert!(validate(&cfg).is_err());
    }
}
