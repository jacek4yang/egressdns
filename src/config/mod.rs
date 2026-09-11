//! Strict TOML configuration.
//!
//! Every table rejects unknown fields so that a typo in production configuration is a
//! hard error rather than a silently ignored setting. Validation is performed against a
//! fully deserialized tree before the configuration is ever activated, and activation
//! itself is an atomic pointer swap (see [`crate::runtime::App`]).

pub mod auto;
pub mod autoprobe;
pub mod builtins;
mod defaults;
pub mod endpoint;
pub mod proxy;
pub mod reload;
mod validate;

pub use validate::validate;
pub use validate::FAILURE_MAX_TTL_CEILING;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

use defaults as d;

/// Root configuration document.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct Config {
    /// Where to ask.
    ///
    /// Each entry is a bare address (`1.1.1.1`, `1.1.1.1:5353`,
    /// `2606:4700:4700::1111`, `[2606:4700:4700::1111]:5353`), a provider alias
    /// (`cloudflare`), or a URI (`https://dns.example.net/dns-query`,
    /// `tls://dns.example.net`, `quic://dns.example.net`).
    ///
    /// How to ask is not configurable, because it is not a preference: transport,
    /// HTTP version, address family, direct or proxy path, and which endpoint to
    /// prefer are all decided from measurement.
    pub upstreams: Vec<String>,

    /// The address `auto` adopted as the local forwarder, if any.
    ///
    /// Not an operator-facing setting — it is filled in at startup by gateway detection,
    /// and exists so that the route built from that address carries
    /// [`auto::ResolverRole::LocalForwarder`] and is never used as a second opinion.
    #[serde(skip)]
    pub local_forwarder: Option<IpAddr>,
    /// Egress proxies, tried when the direct path is unhealthy.
    ///
    /// `socks5://`, `socks5h://`, `http://` and `https://`. Which proxy is used, and
    /// whether one is used at all, is decided from measured path health.
    pub proxies: Vec<String>,
    /// Inbound DNS service settings.
    pub server: ServerConfig,
    /// Cache sizing and behaviour.
    pub cache: CacheConfig,
    /// Client-facing TTL policy.
    pub ttl: TtlConfig,
    /// Address quality model and ordering policy.
    pub ranking: RankingConfig,
    /// RFC 8767 serve-stale policy.
    pub serve_stale: ServeStaleConfig,
    /// Hot-name prefetching.
    pub prefetch: PrefetchConfig,
    /// TLS trust for encrypted upstreams and proxies.
    ///
    /// Operational rather than adaptive: which roots to trust is a deployment fact, not
    /// something the resolver can measure its way to.
    pub tls: UpstreamTlsConfig,
    /// Parsed egress proxies, derived from [`Config::proxies`].
    ///
    /// Never deserialized, for the same reason as [`Config::upstream`].
    #[serde(skip)]
    pub proxy: Vec<proxy::ProxyEndpoint>,
    /// Normalised upstream routes, derived from [`Config::upstreams`].
    ///
    /// Never deserialized: this is the internal shape the scheduler runs on, not a
    /// configuration surface. Declaring it in a file is refused by name.
    #[serde(skip)]
    pub upstream: UpstreamConfig,
    /// DNSSEC policy.
    pub dnssec: DnssecConfig,
    /// EDNS Client Subnet policy.
    pub ecs: EcsConfig,
    /// Active probe engine budgets and profiles.
    pub probe: ProbeConfig,
    /// IPv4/IPv6 environment detection.
    pub network: NetworkConfig,
    /// Cloudflare optimization.
    pub cloudflare: CloudflareConfig,
    /// Offline dataset files.
    pub datasets: DatasetsConfig,
    /// Static local data: hosts entries, internal zones, suffix routing.
    pub local: LocalConfig,
    /// SQLite persistence.
    pub storage: StorageConfig,
    /// Prometheus metrics exposure.
    pub metrics: MetricsConfig,
    /// Structured logging.
    pub logging: LoggingConfig,
    /// Local administration socket.
    pub admin: AdminConfig,
    /// Process-wide resource ceilings.
    pub resources: ResourceConfig,
}

impl Config {
    /// Parse and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&text, &path.display().to_string())
    }

    /// Parse and validate configuration from a TOML string.
    pub fn from_toml(text: &str, path: &str) -> Result<Self, ConfigError> {
        // Legacy syntax is detected on the raw document, before serde sees it. Left to
        // `deny_unknown_fields`, `[[upstream.groups]]` would produce "unknown field
        // `upstream`", which tells an operator holding a v1 file nothing about what to
        // do. There is no translation path: the old format is refused, by name, with a
        // pointer to the migration guide.
        let raw: toml::Value = toml::from_str(text).map_err(|source| ConfigError::Toml {
            path: path.to_string(),
            source,
        })?;
        reject_legacy(&raw)?;

        let mut cfg: Self = toml::from_str(text).map_err(|source| ConfigError::Toml {
            path: path.to_string(),
            source,
        })?;
        cfg.upstream = endpoint::build_upstreams(&cfg.upstreams)
            .map_err(|detail| ConfigError::invalid("upstreams", detail))?;
        // The derived tree carries the trust settings so every existing consumer keeps
        // reading them from one place.
        cfg.upstream.tls = cfg.tls.clone();
        cfg.proxy = proxy::parse_all(&cfg.proxies)
            .map_err(|detail| ConfigError::invalid("proxies", detail))?;
        validate(&cfg)?;
        Ok(cfg)
    }

    /// The client networks the ACL should admit.
    ///
    /// Resolves the three states of [`ServerConfig::allow_from`]; see that field for why
    /// omission and explicit emptiness cannot be the same value.
    pub fn effective_allow_from(&self) -> Vec<IpNet> {
        match &self.server.allow_from {
            Some(nets) => nets.clone(),
            None => loopback_networks(),
        }
    }

    /// Render the effective configuration as TOML with secrets redacted.
    pub fn to_redacted_toml(&self) -> String {
        let mut redacted = self.clone();
        if redacted.cloudflare.official.api_token_file.is_some() {
            redacted.cloudflare.official.api_token_file = Some(PathBuf::from("<redacted>"));
        }
        redacted.cloudflare.official.api_token_env = None;
        // `proxies` is echoed back verbatim, so a userinfo component would put the
        // password in `--dump-config`, in the admin socket's effective-config response
        // and in any support bundle built from either.
        for entry in &mut redacted.proxies {
            if let Ok(parsed) = proxy::parse(entry) {
                if parsed.credentials.is_some() {
                    *entry = format!(
                        "{}://<redacted>@{}:{}",
                        parsed.kind.label(),
                        parsed.host,
                        parsed.port
                    );
                }
            }
        }
        toml::to_string_pretty(&redacted)
            .unwrap_or_else(|e| format!("# failed to render configuration: {e}\n"))
    }

    /// Look up an upstream group by name.
    pub fn group(&self, name: &str) -> Option<&UpstreamGroupConfig> {
        self.upstream.groups.iter().find(|g| g.name == name)
    }
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

/// Inbound DNS service settings.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// UDP listen addresses.
    pub udp_listen: Vec<SocketAddr>,
    /// TCP listen addresses.
    pub tcp_listen: Vec<SocketAddr>,
    /// Client networks permitted to use the resolver.
    ///
    /// Three states, and they mean different things:
    ///
    /// * **Omitted.** With loopback-only listeners, `127.0.0.0/8` and `::1/128` are
    ///   permitted automatically, so a file naming only `upstreams` is usable from the
    ///   local host. With a non-loopback listener, omitting it is refused before
    ///   binding rather than guessed at — that is the difference between a resolver
    ///   for this machine and an open resolver.
    /// * **Explicitly empty.** A deliberate deny-all. Respected as written.
    /// * **Explicitly populated.** Exactly those networks, and nothing else.
    ///
    /// [`Config::effective_allow_from`] resolves the three into the list the ACL uses.
    pub allow_from: Option<Vec<IpNet>>,
    /// Client networks explicitly refused, evaluated before `allow_from`.
    pub deny_from: Vec<IpNet>,
    /// Maximum time the foreground path may spend before returning something to the
    /// client. Background work is never included in this budget.
    #[serde(with = "humantime_serde")]
    pub foreground_budget: Duration,
    /// Handling of `QTYPE=ANY` queries (RFC 8482).
    pub any_policy: AnyPolicy,
    /// Handling of names in the IANA Special-Use Domain Names registry (RFC 6761 and
    /// friends). Locally configured zones and hosts are always consulted first, so this
    /// only affects names the operator has not claimed.
    pub special_use: SpecialUsePolicy,
    /// UDP-specific settings.
    pub udp: UdpConfig,
    /// TCP-specific settings.
    pub tcp: TcpConfig,
    /// Inbound rate limiting.
    pub rate_limit: RateLimitConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp_listen: d::default_listen(),
            tcp_listen: d::default_listen(),
            allow_from: None,
            deny_from: Vec::new(),
            foreground_budget: Duration::from_millis(2_500),
            any_policy: AnyPolicy::Minimal,
            special_use: SpecialUsePolicy::Local,
            udp: UdpConfig::default(),
            tcp: TcpConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Handling of IANA special-use domain names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum SpecialUsePolicy {
    /// Answer registry names locally: loopback for `localhost`, NXDOMAIN for the rest.
    /// This keeps internal names such as `printer.local` and `1.168.192.in-addr.arpa` off
    /// the public Internet. This is the default.
    Local,
    /// Forward every name, including registry names, to the configured upstreams. Correct
    /// only when the upstream *is* the internal resolver for those names.
    Forward,
}

/// RFC 8482 handling for `QTYPE=ANY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum AnyPolicy {
    /// Answer with a single synthesized HINFO RRset (RFC 8482 section 4.2).
    Minimal,
    /// Forward the query upstream unchanged.
    Forward,
    /// Return REFUSED.
    Refuse,
}

/// UDP listener settings.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UdpConfig {
    /// Maximum EDNS(0) UDP payload this server will emit. Defaults to 1232, the DNS Flag
    /// Day 2020 value derived from the IPv6 minimum MTU. RFC 9715 discusses 1400 as an
    /// alternative for networks known to have a 1500-byte path MTU.
    pub max_payload: u16,
    /// Response size limit for clients that did not send an OPT record (RFC 1035).
    pub non_edns_max_payload: u16,
    /// Optional `SO_RCVBUF` override in bytes.
    pub recv_buffer_bytes: Option<usize>,
    /// Optional `SO_SNDBUF` override in bytes.
    pub send_buffer_bytes: Option<usize>,
    /// Enable `SO_REUSEPORT` and open one socket per worker. Keep disabled until
    /// benchmarked on the target host.
    pub reuse_port: bool,
    /// Number of receive workers per UDP listen address when `reuse_port` is enabled.
    pub workers_per_socket: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            max_payload: 1232,
            non_edns_max_payload: 512,
            recv_buffer_bytes: Some(4 * 1024 * 1024),
            send_buffer_bytes: Some(4 * 1024 * 1024),
            reuse_port: false,
            workers_per_socket: 1,
        }
    }
}

/// TCP listener settings.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct TcpConfig {
    /// Idle timeout for an established DNS-over-TCP connection (RFC 7766 section 6.2.3).
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Hard ceiling on connection lifetime regardless of activity.
    #[serde(with = "humantime_serde")]
    pub max_connection_lifetime: Duration,
    /// Global concurrent connection limit.
    pub max_connections: usize,
    /// Per-client-address concurrent connection limit.
    pub max_connections_per_client: usize,
    /// Maximum number of in-flight queries per connection (pipelining depth).
    pub max_pipelined_queries: usize,
    /// Maximum accepted DNS message size on TCP.
    pub max_message_bytes: usize,
    /// Advertise EDNS TCP Keepalive (RFC 7828) in responses over TCP.
    pub advertise_edns_keepalive: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(10),
            max_connection_lifetime: Duration::from_secs(300),
            max_connections: 4_096,
            max_connections_per_client: 64,
            max_pipelined_queries: 256,
            max_message_bytes: 65_535,
            advertise_edns_keepalive: true,
        }
    }
}

/// Inbound rate limiting.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
    /// Master switch.
    pub enabled: bool,
    /// Sustained queries per second permitted per client address.
    pub per_client_qps: u32,
    /// Burst allowance per client address.
    pub per_client_burst: u32,
    /// Sustained queries per second permitted across all clients.
    pub global_qps: u32,
    /// Burst allowance across all clients.
    pub global_burst: u32,
    /// Bound on the per-client rate limiter table.
    pub client_table_size: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_client_qps: 2_000,
            per_client_burst: 4_000,
            global_qps: 200_000,
            global_burst: 400_000,
            client_table_size: 65_536,
        }
    }
}

// ---------------------------------------------------------------------------
// cache
// ---------------------------------------------------------------------------

/// Cache sizing and retention.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Approximate memory ceiling for cached answers, in bytes.
    pub max_memory_bytes: u64,
    /// Maximum number of cached resolution-failure entries (RFC 9520).
    pub failure_max_entries: u64,
    /// Memory budget for retained alternate answer variants, in bytes.
    ///
    /// Weighed in bytes rather than counted, because one variant set holds up to four
    /// complete answers: an entry ceiling bounds memory only to within a factor of four,
    /// which makes the total footprint impossible to reason about.
    pub variant_max_memory_bytes: u64,
    /// Maximum number of tracked IP quality records held in memory.
    pub quality_max_entries: u64,
    /// Upper bound applied to any authoritative TTL before it is stored (RFC 2181 caps
    /// TTLs at 2^31-1; a shorter internal cap bounds memory and staleness).
    pub internal_max_ttl: u32,
    /// Upper bound applied to negative TTLs derived from the SOA (RFC 2308).
    pub negative_max_ttl: u32,
    /// Minimum resolution-failure cache duration (RFC 9520 recommends >= 1 second).
    #[serde(with = "humantime_serde")]
    pub failure_min_ttl: Duration,
    /// Maximum resolution-failure cache duration (RFC 9520 recommends <= 5 minutes).
    #[serde(with = "humantime_serde")]
    pub failure_max_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            failure_max_entries: 20_000,
            variant_max_memory_bytes: 32 * 1024 * 1024,
            quality_max_entries: 100_000,
            internal_max_ttl: 86_400,
            negative_max_ttl: 3_600,
            failure_min_ttl: Duration::from_secs(1),
            failure_max_ttl: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------
// ttl
// ---------------------------------------------------------------------------

/// Client-facing TTL caps.
///
/// Caps only ever *reduce* the TTL handed to a client. The remaining authoritative TTL is
/// always an upper bound, so no policy here can extend the lifetime of upstream data.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct TtlConfig {
    /// Cap for single-address or non-optimized answers.
    pub cap_default: u32,
    /// Cap for optimized multi-address answers that are not Cloudflare-specific.
    pub cap_optimized_multi: u32,
    /// Cap applied when a Cloudflare answer was reordered in preserve mode.
    pub cap_cloudflare_preserve: u32,
    /// Cap applied when verified Cloudflare addresses were prepended.
    pub cap_cloudflare_augment: u32,
    /// Cap applied for a period after a network-generation change.
    pub cap_network_change: u32,
    /// Cap applied to answers served from the stale cache.
    pub cap_serve_stale: u32,
    /// How long the reduced network-change cap remains in force.
    #[serde(with = "humantime_serde")]
    pub network_change_window: Duration,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            cap_default: 300,
            cap_optimized_multi: 90,
            cap_cloudflare_preserve: 60,
            cap_cloudflare_augment: 25,
            cap_network_change: 15,
            cap_serve_stale: 30,
            network_change_window: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------
// ranking
// ---------------------------------------------------------------------------

/// Address quality model and ordering policy.
///
/// The model is deliberately explainable: an expected cost in milliseconds is assembled
/// from measured latency plus explicit penalties, so an operator can always answer the
/// question "why was this address placed first?".
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct RankingConfig {
    /// Enable evidence-based ordering. When disabled the original upstream order is
    /// always preserved.
    pub enabled: bool,
    /// Neutral cost in milliseconds assigned to an address with no applicable evidence.
    /// Lack of evidence is not evidence of failure.
    pub neutral_cost_ms: f64,
    /// Penalty in milliseconds applied for a full connection failure.
    pub failure_penalty_ms: f64,
    /// Weight applied to the recent tail latency estimate.
    pub tail_weight: f64,
    /// Weight applied to observed jitter.
    pub jitter_weight: f64,
    /// Penalty in milliseconds scaled by the width of the success-probability confidence
    /// interval; a wide interval means the estimate is not yet trustworthy.
    pub uncertainty_penalty_ms: f64,
    /// Penalty in milliseconds applied when the newest sample is older than
    /// `sample_max_age`.
    pub stale_sample_penalty_ms: f64,
    /// Age beyond which samples are considered stale.
    #[serde(with = "humantime_serde")]
    pub sample_max_age: Duration,
    /// Half-life applied to the success/failure posterior.
    #[serde(with = "humantime_serde")]
    pub evidence_half_life: Duration,
    /// Required relative improvement before the leading address may be replaced.
    pub hysteresis: f64,
    /// Minimum number of successful observations before an address may be promoted to
    /// first position.
    pub min_successes_to_lead: u32,
    /// Fraction of decisions that deliberately keep a lower-ranked address first so that
    /// addresses can recover from a bad streak.
    pub exploration_rate: f64,
    /// Base penalty multiplier applied per consecutive failure, compounded.
    pub consecutive_failure_base: f64,
}

impl Default for RankingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            neutral_cost_ms: 120.0,
            failure_penalty_ms: 400.0,
            tail_weight: 0.35,
            jitter_weight: 0.25,
            uncertainty_penalty_ms: 60.0,
            stale_sample_penalty_ms: 40.0,
            sample_max_age: Duration::from_secs(1_800),
            evidence_half_life: Duration::from_secs(3_600),
            hysteresis: 0.12,
            min_successes_to_lead: 3,
            exploration_rate: 0.02,
            consecutive_failure_base: 1.8,
        }
    }
}

// ---------------------------------------------------------------------------
// serve-stale
// ---------------------------------------------------------------------------

/// RFC 8767 serve-stale policy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServeStaleConfig {
    /// Master switch.
    pub enabled: bool,
    /// Maximum age past expiry for which stale data may be served.
    #[serde(with = "humantime_serde")]
    pub max_stale: Duration,
    /// How long the resolver attempts a live refresh before falling back to stale data.
    #[serde(with = "humantime_serde")]
    pub client_timeout: Duration,
    /// Minimum interval between refresh attempts for a name currently failing.
    #[serde(with = "humantime_serde")]
    pub retry_interval: Duration,
    /// Attach RFC 8914 Extended DNS Error 3 (Stale Answer) to stale responses.
    pub include_ede: bool,
}

impl Default for ServeStaleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_stale: Duration::from_secs(86_400),
            client_timeout: Duration::from_millis(1_800),
            retry_interval: Duration::from_secs(30),
            include_ede: true,
        }
    }
}

// ---------------------------------------------------------------------------
// prefetch
// ---------------------------------------------------------------------------

/// Hot-name prefetching.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct PrefetchConfig {
    /// Master switch.
    pub enabled: bool,
    /// Refresh when the remaining TTL fraction drops below this value.
    pub trigger_fraction: f64,
    /// Minimum observed hit count before a name is eligible.
    pub min_hits: u32,
    /// Bound on the tracked hot set.
    pub hot_set_size: usize,
    /// Global prefetch query budget in queries per second.
    pub global_qps: u32,
    /// Minimum interval between prefetches of the same cache key.
    #[serde(with = "humantime_serde")]
    pub per_key_min_interval: Duration,
    /// Number of persisted hot names re-resolved at startup.
    pub warm_on_start: usize,
    /// Enable the bounded aggregate transition table (query-sequence prediction).
    /// Disabled by default; see `docs/BENCHMARKS.md` for the evidence requirement.
    pub transition_prediction: bool,
    /// Bound on the transition table.
    pub transition_table_size: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trigger_fraction: 0.15,
            min_hits: 3,
            hot_set_size: 20_000,
            global_qps: 50,
            per_key_min_interval: Duration::from_secs(5),
            warm_on_start: 200,
            transition_prediction: false,
            transition_table_size: 20_000,
        }
    }
}

// ---------------------------------------------------------------------------
// upstream
// ---------------------------------------------------------------------------

/// Upstream configuration root.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamConfig {
    /// Group used when no suffix rule matches.
    pub default_group: String,
    /// Configured upstream groups.
    pub groups: Vec<UpstreamGroupConfig>,
    /// TLS trust configuration shared by encrypted transports.
    pub tls: UpstreamTlsConfig,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            default_group: "default".to_string(),
            groups: vec![UpstreamGroupConfig::default()],
            tls: UpstreamTlsConfig::default(),
        }
    }
}

/// TLS trust settings for encrypted upstream transports.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamTlsConfig {
    /// Use the platform trust store in addition to the compiled-in Mozilla root set.
    pub use_system_roots: bool,
    /// Additional PEM bundles containing corporate roots.
    pub extra_ca_files: Vec<PathBuf>,
    /// Enable TLS session resumption for DoT/DoH/DoQ.
    pub session_resumption: bool,
    /// QUIC 0-RTT is disabled: early data is replayable and DNS queries are not
    /// idempotent from a privacy standpoint. See `docs/THREAT_MODEL.md`.
    pub quic_zero_rtt: bool,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            use_system_roots: true,
            extra_ca_files: Vec::new(),
            session_resumption: true,
            quic_zero_rtt: false,
        }
    }
}

/// A named group of upstream servers.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamGroupConfig {
    /// Group name referenced by suffix rules and by `upstream.default_group`.
    pub name: String,
    /// Members of the group.
    pub servers: Vec<UpstreamServerConfig>,
    /// Scheduling policy for this group.
    pub scheduler: SchedulerConfig,
}

impl Default for UpstreamGroupConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            servers: d::default_upstreams(),
            scheduler: SchedulerConfig::default(),
        }
    }
}

/// Upstream transport kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransportKind {
    /// Classic DNS over UDP (RFC 1035).
    Udp,
    /// Classic DNS over TCP (RFC 7766).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS carried by HTTP/2 (RFC 8484).
    Doh2,
    /// DNS over HTTPS carried by HTTP/3 (RFC 8484 over RFC 9114).
    Doh3,
    /// DNS over QUIC (RFC 9250).
    Doq,
}

impl TransportKind {
    /// Stable metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::Doh2 => "doh2",
            Self::Doh3 => "doh3",
            Self::Doq => "doq",
        }
    }

    /// True when the transport provides confidentiality and server authentication.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Dot | Self::Doh2 | Self::Doh3 | Self::Doq)
    }

    /// True when the transport is stream-oriented and therefore not subject to
    /// UDP truncation.
    pub fn is_stream(self) -> bool {
        !matches!(self, Self::Udp)
    }

    /// IANA default port for the transport.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Dot | Self::Doq => 853,
            Self::Doh2 | Self::Doh3 => 443,
        }
    }
}

/// The loopback networks admitted when no ACL is written.
pub fn loopback_networks() -> Vec<IpNet> {
    // Both are compile-time constants in disguise; `expect` is not available on a
    // production path, so a parse failure degrades to an empty list, which is
    // deny-all — the safe direction.
    ["127.0.0.0/8", "::1/128"]
        .iter()
        .filter_map(|n| n.parse::<IpNet>().ok())
        .collect()
}

/// Keys that belonged to the pre-2.0 configuration and are now refused.
///
/// Each carries the reason and the replacement, because "unknown field" is a useless
/// thing to tell somebody holding a file that used to work.
const LEGACY_KEYS: &[(&str, &str)] = &[
    (
        "version",
        "EgressDNS 2.0 has no configuration version field. Delete the line; the format \
         is identified by its contents",
    ),
    (
        "upstream",
        "the `[[upstream.groups]]` and `[[upstream.groups.servers]]` tables are removed. \
         List your resolvers in `upstreams` instead, as addresses or URIs",
    ),
];

/// Refuse a pre-2.0 document by name rather than by serde's unknown-field message.
fn reject_legacy(raw: &toml::Value) -> Result<(), ConfigError> {
    let Some(table) = raw.as_table() else {
        return Ok(());
    };
    for (key, reason) in LEGACY_KEYS {
        if table.contains_key(*key) {
            return Err(ConfigError::invalid(
                *key,
                format!("{reason}. See docs/MIGRATION-V1-TO-V2.md"),
            ));
        }
    }
    Ok(())
}

/// A single upstream server definition.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamServerConfig {
    /// Operator-facing name; also used as the bounded metrics label.
    pub name: String,
    /// What this resolver is to us: an independent authority, or the local forwarder.
    ///
    /// Set by `auto` when it adopts the gateway, and left at `Authority` otherwise. It is
    /// not an operator-facing field: whether the machine at the end of the default route
    /// is a full resolver or a forwarder is a fact about the network, not a preference.
    #[serde(skip)]
    pub role: crate::config::auto::ResolverRole,
    /// Transport used to reach the server.
    pub transport: TransportKind,
    /// Literal addresses of the server. Encrypted transports require these as bootstrap
    /// addresses so that the resolver never needs to resolve its own upstream.
    pub addresses: Vec<IpAddr>,
    /// Port override; defaults to the IANA port for the transport.
    pub port: Option<u16>,
    /// TLS server name (SNI and certificate hostname) for encrypted transports.
    pub server_name: Option<String>,
    /// HTTP path for DoH transports.
    pub path: Option<String>,
    /// Optional local source address to bind.
    pub bind_addr: Option<SocketAddr>,
    /// Static preference weight used to break ties between equally healthy routes.
    pub weight: u32,
    /// Disable without deleting.
    pub enabled: bool,
    /// Send RFC 7873 DNS Cookies. `None` means "automatic": enabled for UDP and TCP,
    /// disabled for encrypted transports where they add nothing. Setting `true`
    /// explicitly on an encrypted transport is a configuration error.
    pub enable_cookies: Option<bool>,
    /// Trust this upstream's AD bit when local validation is disabled. Requires an
    /// authenticated transport.
    pub trust_ad: bool,
    /// Per-server ECS override; `None` inherits the global policy.
    pub ecs: Option<EcsScope>,
}

impl Default for UpstreamServerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            role: crate::config::auto::ResolverRole::Authority,
            transport: TransportKind::Udp,
            addresses: Vec::new(),
            port: None,
            server_name: None,
            path: None,
            bind_addr: None,
            weight: 100,
            enabled: true,
            enable_cookies: None,
            trust_ad: false,
            ecs: None,
        }
    }
}

impl UpstreamServerConfig {
    /// Effective port for this server.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.transport.default_port())
    }

    /// Whether DNS Cookies are actually used on this server.
    ///
    /// RFC 7873 cookies protect unauthenticated UDP and TCP exchanges. Over DoT, DoH or
    /// DoQ the transport already authenticates the server, so cookies are never sent.
    pub fn cookies_effective(&self) -> bool {
        self.enable_cookies.unwrap_or(true) && !self.transport.is_encrypted()
    }
}

/// Adaptive scheduling policy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SchedulerConfig {
    /// Enable a single bounded hedge request.
    pub hedge_enabled: bool,
    /// Latency percentile of the primary route used to time the hedge.
    pub hedge_percentile: f64,
    /// Lower bound on the hedge delay.
    #[serde(with = "humantime_serde")]
    pub hedge_min_delay: Duration,
    /// Upper bound on the hedge delay.
    #[serde(with = "humantime_serde")]
    pub hedge_max_delay: Duration,
    /// Maximum fraction of queries that may be hedged, as a privacy and load control.
    pub hedge_max_fraction: f64,
    /// Per-attempt upstream timeout.
    #[serde(with = "humantime_serde")]
    pub query_timeout: Duration,
    /// Fraction of queries deliberately routed to a non-optimal healthy route so that
    /// recovered upstreams can regain rank.
    pub explore_rate: f64,
    /// Consecutive failures before the circuit opens.
    pub circuit_failure_threshold: u32,
    /// How long the circuit stays open before a half-open probe is allowed.
    #[serde(with = "humantime_serde")]
    pub circuit_open_duration: Duration,
    /// Successful half-open probes required to close the circuit.
    pub circuit_half_open_successes: u32,
    /// Permit a bounded emergency fan-out when every route is unhealthy.
    pub emergency_fanout: bool,
    /// Maximum number of routes contacted during an emergency fan-out.
    pub emergency_fanout_max: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            hedge_enabled: true,
            hedge_percentile: 0.95,
            hedge_min_delay: Duration::from_millis(20),
            hedge_max_delay: Duration::from_millis(400),
            hedge_max_fraction: 0.15,
            query_timeout: Duration::from_millis(1_500),
            explore_rate: 0.02,
            circuit_failure_threshold: 5,
            circuit_open_duration: Duration::from_secs(20),
            circuit_half_open_successes: 2,
            emergency_fanout: true,
            emergency_fanout_max: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// dnssec
// ---------------------------------------------------------------------------

/// DNSSEC validation policy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnssecConfig {
    /// Validation mode.
    pub mode: DnssecMode,
    /// Optional trust anchor file in DS/DNSKEY presentation format. When absent the
    /// compiled-in IANA root anchors are used.
    pub trust_anchor_file: Option<PathBuf>,
    /// Trust an upstream's AD bit. Only honoured for servers that also set `trust_ad`
    /// and use an authenticated transport.
    pub trust_upstream_ad: bool,
    /// Maximum concurrent validations, bounding CPU use.
    pub max_concurrent_validations: usize,
    /// Bound on the validation result cache.
    pub validation_cache_entries: usize,
    /// Maximum delegation depth the validator may chase while proving one answer. The
    /// library default is 26; a forwarder never legitimately needs anything close to that,
    /// and a low ceiling turns a hostile or misconfigured zone into a bounded cost.
    pub max_validation_depth: usize,
    /// Attach RFC 8914 Extended DNS Errors describing DNSSEC outcomes.
    pub extended_errors: bool,
    /// Ask a second, independent resolver before believing an unsigned NXDOMAIN.
    ///
    /// A forged negative is how a name is made to disappear, and unlike a forged address
    /// it leaves no evidence in the answer itself. Corroboration can only ever replace a
    /// negative with a positive, never the reverse, so it cannot be used to erase a name.
    ///
    /// Costs one extra query, on cold unsigned NXDOMAINs only.
    pub corroborate_negative: bool,

    /// How long a background proof completion may run.
    ///
    /// When a chain cannot be proved inside the foreground budget the answer is served
    /// with AD cleared, and the proof is finished afterwards so the *next* query for that
    /// zone has a warm chain and validates normally. This bounds that background work. It
    /// is deliberately far larger than the foreground budget — nothing is waiting on it —
    /// and still bounded, because nothing here is unbounded.
    #[serde(with = "humantime_serde")]
    pub proof_completion_timeout: Duration,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            mode: DnssecMode::Background,
            trust_anchor_file: None,
            trust_upstream_ad: false,
            max_concurrent_validations: 256,
            validation_cache_entries: 10_000,
            max_validation_depth: 12,
            corroborate_negative: true,
            proof_completion_timeout: Duration::from_secs(20),
            extended_errors: true,
        }
    }
}

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum DnssecMode {
    /// No local validation. DO is not set unless the client sets it, and AD is cleared
    /// unless an explicitly trusted upstream policy applies.
    Off,

    /// Validate after answering, not before. The default.
    ///
    /// A client gets the fastest admissible answer; validation runs in the evidence plane
    /// and decides what happens to that answer *next*. A variant proven Bogus is evicted
    /// and quarantined, so it is served at most once and never again; a variant proven
    /// Secure is promoted, and only then does an answer carry AD.
    ///
    /// This is the mode because synchronous validation could not keep its promise. Proving
    /// a name at the end of a four-zone CNAME chain — `www.bing.com` is the case that
    /// forced this — needs more sequential DS and DNSKEY lookups than a 2.5-second
    /// foreground budget holds. The lookups were cut off, and the library reports a
    /// cut-off lookup as `Proof::Bogus`, so the resolver refused a name it could resolve
    /// perfectly well. Availability was being spent on a check that never finished.
    Background,

    /// Validate before answering, and fail closed. For operators who require it.
    ///
    /// Honest about its cost: a name whose chain does not fit the validation deadline is
    /// refused. That is the correct trade for some deployments and the wrong one for most,
    /// which is why it is not the default.
    ///
    /// Accepts the 2.x name `validate` as an alias. Somebody who wrote that chose
    /// fail-closed deliberately, and a major version is no reason to silently give them
    /// something else — or to refuse to start over a word.
    #[serde(alias = "validate")]
    Strict,
}

impl DnssecMode {
    /// Whether a client waits for validation before being answered.
    pub fn blocks_the_client(self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Whether validation happens at all, in either plane.
    pub fn validates(self) -> bool {
        matches!(self, Self::Background | Self::Strict)
    }

    /// Whether outgoing queries should ask for DNSSEC records.
    ///
    /// True for `Background` as well as `Strict`: the evidence plane cannot validate what
    /// the foreground did not ask for, and asking costs one EDNS flag.
    pub fn wants_dnssec_records(self) -> bool {
        self.validates()
    }
}

// ---------------------------------------------------------------------------
// ecs
// ---------------------------------------------------------------------------

/// EDNS Client Subnet policy (RFC 7871).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct EcsConfig {
    /// Global mode.
    ///
    /// A client's own ECS option is never forwarded, in any mode. The outgoing query is
    /// built from the cache key rather than copied from the request, so a client subnet
    /// cannot leak upstream even by accident, and there is deliberately no switch to
    /// enable that: it would leak LAN structure to a third party and would require the
    /// cache to be keyed per client subnet.
    pub mode: EcsMode,
    /// Fixed public egress prefixes advertised upstream when `mode = "fixed-egress"`.
    pub egress: EcsScope,
}

impl Default for EcsConfig {
    fn default() -> Self {
        Self {
            mode: EcsMode::Disabled,
            egress: EcsScope::default(),
        }
    }
}

/// ECS operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum EcsMode {
    /// Never emit ECS. This is the default; a client's private LAN address is never
    /// forwarded under any mode.
    Disabled,
    /// Emit a fixed, explicitly configured public prefix.
    FixedEgress,
}

/// A configured ECS prefix pair.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct EcsScope {
    /// IPv4 prefix advertised upstream. Must be a public prefix.
    pub ipv4: Option<Ipv4Net>,
    /// IPv6 prefix advertised upstream. Must be a public prefix.
    pub ipv6: Option<Ipv6Net>,
}

// ---------------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------------

/// Active probe engine configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProbeConfig {
    /// Master switch. When disabled the resolver never opens a probe connection and all
    /// candidates keep neutral scores.
    pub enabled: bool,
    /// Bounded probe work queue.
    pub queue_size: usize,
    /// Ceiling on concurrent probe exchanges. A worker holds its slot for the whole
    /// TCP → TLS → HTTP pipeline, so one ceiling covers every stage; the default
    /// preserves the tightest of the historical per-stage defaults.
    pub concurrency: usize,
    /// Global ceiling on new probe connections per second.
    pub global_connections_per_second: u32,
    /// Stage 1 timeout.
    #[serde(with = "humantime_serde")]
    pub tcp_timeout: Duration,
    /// Stage 2 timeout.
    #[serde(with = "humantime_serde")]
    pub tls_timeout: Duration,
    /// Stage 3 timeout.
    #[serde(with = "humantime_serde")]
    pub http_timeout: Duration,
    /// Minimum interval between probes of the same address.
    #[serde(with = "humantime_serde")]
    pub per_ip_cooldown: Duration,
    /// Minimum interval between probes inside the same prefix.
    #[serde(with = "humantime_serde")]
    pub per_prefix_cooldown: Duration,
    /// Minimum interval between domain-level validations of the same hostname.
    #[serde(with = "humantime_serde")]
    pub per_domain_cooldown: Duration,
    /// Maximum number of addresses scheduled from a single observed RRset.
    pub max_candidates_per_rrset: usize,
    /// Ports probed in addition to those declared by HTTPS/SVCB or SRV records.
    pub extra_ports: Vec<u16>,
    /// Response body cap for HTTP probes.
    pub max_response_bytes: usize,
    /// Attempt QUIC/HTTP/3 handshakes where the target advertises support.
    pub enable_http3: bool,
    /// Daily budget for throughput measurement, in bytes.
    pub daily_bandwidth_budget_bytes: u64,
    /// Networks that may be probed even though they are private or otherwise special-use.
    /// Empty by default; probing special-use space is refused unless listed here.
    pub allow_special_use_targets: Vec<IpNet>,
    /// Named validation profiles.
    pub profiles: Vec<ProbeProfile>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            queue_size: 8_192,
            concurrency: 8,
            global_connections_per_second: 64,
            tcp_timeout: Duration::from_millis(1_500),
            tls_timeout: Duration::from_millis(3_000),
            http_timeout: Duration::from_millis(5_000),
            per_ip_cooldown: Duration::from_secs(300),
            per_prefix_cooldown: Duration::from_secs(30),
            per_domain_cooldown: Duration::from_secs(600),
            max_candidates_per_rrset: 4,
            extra_ports: vec![443],
            max_response_bytes: 16 * 1024,
            enable_http3: true,
            daily_bandwidth_budget_bytes: 64 * 1024 * 1024,
            allow_special_use_targets: Vec::new(),
            profiles: Vec::new(),
        }
    }
}

/// An administrator-defined validation profile for an important domain.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProbeProfile {
    /// Profile name.
    pub name: String,
    /// Domains this profile applies to. A leading `.` matches the suffix.
    pub domains: Vec<String>,
    /// Health-check path.
    pub path: String,
    /// HTTP method; only `HEAD` and `GET` are permitted.
    pub method: String,
    /// Status codes considered a successful validation.
    pub allowed_status: Vec<u16>,
    /// A response header that must be present, and optionally its exact value.
    pub required_header: Option<RequiredHeader>,
    /// Hex-encoded SHA-256 of the expected (small) response body.
    pub body_sha256: Option<String>,
    /// Permitted hex-encoded SHA-256 values of the server certificate SPKI.
    pub spki_sha256: Vec<String>,
    /// Required issuer common name substring.
    pub required_issuer_cn: Option<String>,
    /// ALPN protocols offered, in preference order.
    pub alpn: Vec<String>,
}

impl Default for ProbeProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            domains: Vec::new(),
            path: "/".to_string(),
            method: "HEAD".to_string(),
            allowed_status: vec![200, 204, 301, 302, 400, 403, 404, 405],
            required_header: None,
            body_sha256: None,
            spki_sha256: Vec::new(),
            required_issuer_cn: None,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }
}

/// A required response header for a probe profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredHeader {
    /// Header name, compared case-insensitively.
    pub name: String,
    /// Optional exact value.
    pub value: Option<String>,
}

// ---------------------------------------------------------------------------
// network
// ---------------------------------------------------------------------------

/// IPv4/IPv6 environment detection.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// Master switch for network-generation tracking.
    pub enabled: bool,
    /// Polling interval for route and address state.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Debounce window; changes must be stable for this long before a new generation is
    /// published.
    #[serde(with = "humantime_serde")]
    pub debounce: Duration,
    /// Reference IPv4 destination used only to ask the kernel which source address and
    /// route would be selected. No packets are sent.
    pub reference_v4: IpAddr,
    /// Reference IPv6 destination used the same way.
    pub reference_v6: IpAddr,
    /// Multiplier applied to historical confidence after a generation change.
    pub confidence_decay_on_change: f64,
    /// Duration of accelerated relearning after a generation change.
    #[serde(with = "humantime_serde")]
    pub relearn_window: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval: Duration::from_secs(5),
            debounce: Duration::from_secs(3),
            reference_v4: IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            reference_v6: IpAddr::V6(std::net::Ipv6Addr::new(
                0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111,
            )),
            confidence_decay_on_change: 0.25,
            relearn_window: Duration::from_secs(600),
        }
    }
}

// ---------------------------------------------------------------------------
// cloudflare
// ---------------------------------------------------------------------------

/// Cloudflare optimization configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CloudflareConfig {
    /// Master switch for the whole subsystem.
    pub enabled: bool,
    /// Response mode.
    pub mode: CloudflareMode,
    /// Official prefix sources.
    pub official: OfficialPrefixConfig,
    /// Untrusted third-party candidate seed endpoints.
    pub seeds: SeedConfig,
    /// Bounded sampling of official IPv4 prefixes.
    pub sampling: SamplingConfig,
    /// Verified-augment specific limits.
    pub augment: AugmentConfig,
    /// Hostnames used for generic Cloudflare reachability probing.
    pub probe_hosts: Vec<String>,
    /// Domains eligible for optimization; empty means "all eligible domains".
    pub allow_domains: Vec<String>,
    /// Domains never optimized, evaluated first.
    pub deny_domains: Vec<String>,
    /// Bound on the candidate pool.
    pub candidate_pool_max: usize,
    /// Administrator-supplied candidate addresses. Still filtered against the current
    /// official prefix snapshot.
    pub static_candidates: Vec<IpAddr>,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CloudflareMode::Preserve,
            official: OfficialPrefixConfig::default(),
            seeds: SeedConfig::default(),
            sampling: SamplingConfig::default(),
            augment: AugmentConfig::default(),
            probe_hosts: vec!["speed.cloudflare.com".to_string()],
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            candidate_pool_max: 4_096,
            static_candidates: Vec::new(),
        }
    }
}

/// Cloudflare response mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum CloudflareMode {
    /// No Cloudflare-specific processing at all.
    Off,
    /// Reorder addresses already present in the original RRset. Never add, never remove.
    Preserve,
    /// Additionally prepend domain-verified Cloudflare addresses for eligible,
    /// non-DNSSEC-secure HTTPS domains, retaining every original address.
    VerifiedAugment,
}

impl CloudflareMode {
    /// Stable metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Preserve => "preserve",
            Self::VerifiedAugment => "verified_augment",
        }
    }
}

/// Official Cloudflare prefix sources.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct OfficialPrefixConfig {
    /// Primary JSON API endpoint.
    pub api_url: String,
    /// Plain-text IPv4 list used as a cross-check.
    pub ipv4_url: String,
    /// Plain-text IPv6 list used as a cross-check.
    pub ipv6_url: String,
    /// Refresh interval.
    #[serde(with = "humantime_serde")]
    pub refresh_interval: Duration,
    /// Per-request timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Maximum accepted response size.
    pub max_response_bytes: usize,
    /// Minimum number of IPv4 prefixes a snapshot must contain to be accepted.
    pub min_ipv4_prefixes: usize,
    /// Minimum number of IPv6 prefixes a snapshot must contain to be accepted.
    pub min_ipv6_prefixes: usize,
    /// Optional file containing a Cloudflare API token. The token is never required:
    /// the IP endpoint is public.
    pub api_token_file: Option<PathBuf>,
    /// Optional environment variable holding a Cloudflare API token.
    pub api_token_env: Option<String>,
    /// Path where the last valid snapshot is cached on disk.
    pub cache_file: Option<PathBuf>,
}

impl Default for OfficialPrefixConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.cloudflare.com/client/v4/ips".to_string(),
            ipv4_url: "https://www.cloudflare.com/ips-v4".to_string(),
            ipv6_url: "https://www.cloudflare.com/ips-v6".to_string(),
            refresh_interval: Duration::from_secs(86_400),
            timeout: Duration::from_secs(10),
            max_response_bytes: 256 * 1024,
            min_ipv4_prefixes: 8,
            min_ipv6_prefixes: 4,
            api_token_file: None,
            api_token_env: None,
            cache_file: Some(crate::platform::default_prefix_cache_path()),
        }
    }
}

/// Untrusted candidate seed endpoints.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SeedConfig {
    /// Master switch for third-party seeds.
    pub enabled: bool,
    /// Endpoints to poll.
    pub endpoints: Vec<SeedEndpoint>,
    /// Refresh interval.
    #[serde(with = "humantime_serde")]
    pub refresh_interval: Duration,
    /// Per-request timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Maximum accepted response size for any single endpoint.
    pub max_response_bytes: usize,
    /// Maximum number of addresses accepted from a single endpoint response.
    pub max_addresses_per_response: usize,
    /// Resolve hostnames returned by a seed endpoint through the local resolver and then
    /// filter the resulting addresses against the official prefix snapshot.
    pub resolve_hostnames: bool,
}

impl Default for SeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoints: d::default_seed_endpoints(),
            refresh_interval: Duration::from_secs(2_400),
            timeout: Duration::from_secs(10),
            max_response_bytes: 128 * 1024,
            max_addresses_per_response: 256,
            resolve_hostnames: true,
        }
    }
}

/// A single untrusted seed endpoint.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SeedEndpoint {
    /// Short name used as a bounded metrics label.
    pub name: String,
    /// Absolute HTTPS URL.
    pub url: String,
    /// Enable or disable this endpoint independently.
    pub enabled: bool,
}

impl Default for SeedEndpoint {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            enabled: true,
        }
    }
}

/// Bounded sampling of official Cloudflare prefixes.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SamplingConfig {
    /// Enable stratified rotating sampling of official prefixes.
    ///
    /// Sampling covers IPv4 only, and there is deliberately no switch to extend it to
    /// IPv6: the official IPv6 space is far too large for random traversal to find
    /// anything, so such a flag could only ever be a setting that did nothing. IPv6
    /// candidates come from observed answers and from seed lists instead.
    pub enabled: bool,
    /// Interval between sampling rounds.
    #[serde(with = "humantime_serde")]
    pub round_interval: Duration,
    /// Addresses proposed per round across all prefixes.
    pub addresses_per_round: usize,
    /// Ceiling on newly proposed IPv4 candidates per hour.
    pub max_new_candidates_per_hour: usize,
    /// Number of sampling buckets each prefix is divided into.
    pub buckets_per_prefix: usize,
    /// Extra budget share given to historically productive buckets, in `[0, 1]`.
    pub exploit_fraction: f64,
    /// Deterministic seed so that a sampling schedule is reproducible.
    pub seed: u64,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            round_interval: Duration::from_secs(300),
            addresses_per_round: 32,
            max_new_candidates_per_hour: 512,
            buckets_per_prefix: 64,
            exploit_fraction: 0.3,
            seed: 0x5eed_0cf0_0000_0001,
        }
    }
}

/// Verified-augment limits.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AugmentConfig {
    /// Maximum number of verified addresses prepended to an eligible answer.
    pub max_added: usize,
    /// Minimum number of successful domain-level validations before an address may be
    /// added for that domain.
    pub min_validations: u32,
    /// Validity window of a domain-level validation result.
    #[serde(with = "humantime_serde")]
    pub validation_ttl: Duration,
    /// Required confidence-adjusted improvement over the best original address, as a
    /// fraction. Acts as hysteresis.
    pub min_advantage: f64,
    /// Minimum number of quality samples for a candidate before it may be added.
    pub min_samples: u32,
}

impl Default for AugmentConfig {
    fn default() -> Self {
        Self {
            max_added: 2,
            min_validations: 3,
            validation_ttl: Duration::from_secs(3_600),
            min_advantage: 0.12,
            min_samples: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// datasets
// ---------------------------------------------------------------------------

/// Offline dataset files.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct DatasetsConfig {
    /// Hosts-format files.
    pub hosts_files: Vec<PathBuf>,
    /// GeoSite-compatible domain category files (`category:domain` per line).
    pub domain_category_files: Vec<PathBuf>,
    /// Optional GeoIP MMDB used only as advisory diagnostic metadata.
    pub geoip_mmdb: Option<PathBuf>,
    /// Optional ASN MMDB used only as advisory diagnostic metadata.
    pub asn_mmdb: Option<PathBuf>,
    /// Reload interval; files are also reloaded on SIGHUP.
    #[serde(with = "humantime_serde")]
    pub reload_interval: Duration,
    /// Maximum accepted size of any single dataset file.
    pub max_file_bytes: u64,
    /// Maximum accepted number of records per dataset.
    pub max_records: usize,
}

impl Default for DatasetsConfig {
    fn default() -> Self {
        Self {
            hosts_files: Vec::new(),
            domain_category_files: Vec::new(),
            geoip_mmdb: None,
            asn_mmdb: None,
            reload_interval: Duration::from_secs(3_600),
            max_file_bytes: 64 * 1024 * 1024,
            max_records: 2_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// local data
// ---------------------------------------------------------------------------

/// Static local answers and routing rules.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocalConfig {
    /// Inline hosts-style entries.
    pub hosts: Vec<HostEntry>,
    /// Internal zones served authoritatively from configuration.
    pub zones: Vec<LocalZone>,
    /// Suffix-based upstream routing rules.
    pub suffix_rules: Vec<SuffixRule>,
    /// TTL used for locally served records.
    pub local_ttl: u32,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            zones: Vec::new(),
            suffix_rules: Vec::new(),
            local_ttl: 60,
        }
    }
}

/// A hosts-style static mapping.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    /// Fully qualified name.
    pub name: String,
    /// Addresses returned for A/AAAA queries.
    pub addresses: Vec<IpAddr>,
}

/// A simple internal zone.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocalZone {
    /// Zone apex.
    pub name: String,
    /// Records in presentation-like form.
    pub records: Vec<LocalRecord>,
    /// Answer NXDOMAIN for names inside the zone that have no record.
    pub authoritative: bool,
}

impl Default for LocalZone {
    fn default() -> Self {
        Self {
            name: String::new(),
            records: Vec::new(),
            authoritative: true,
        }
    }
}

/// A single record inside an internal zone.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocalRecord {
    /// Owner name, relative to the zone apex or fully qualified when ending in a dot.
    pub name: String,
    /// Record type: `A`, `AAAA`, `CNAME`, `TXT`, `PTR`, `MX`, `SRV` or `NS`.
    pub rtype: String,
    /// Presentation-format RDATA.
    pub value: String,
    /// TTL override for this record.
    pub ttl: Option<u32>,
}

impl Default for LocalRecord {
    fn default() -> Self {
        Self {
            name: "@".to_string(),
            rtype: "A".to_string(),
            value: String::new(),
            ttl: None,
        }
    }
}

/// Suffix-based routing to a named upstream group.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixRule {
    /// Domain suffix, matched on label boundaries.
    pub suffix: String,
    /// Target upstream group name.
    pub group: String,
}

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------

/// SQLite persistence.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// Master switch. When disabled the resolver runs with purely in-memory state.
    pub enabled: bool,
    /// Database path.
    pub path: PathBuf,
    /// Interval between batched flushes.
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    /// Bounded write queue.
    pub queue_size: usize,
    /// Maximum number of persisted IP quality rows.
    pub max_quality_rows: usize,
    /// Maximum number of persisted hot-domain rows.
    pub max_hot_rows: usize,
    /// Maximum number of persisted Cloudflare candidate rows.
    pub max_candidate_rows: usize,
    /// Rows unused for longer than this are pruned.
    #[serde(with = "humantime_serde")]
    pub row_max_age: Duration,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: crate::platform::default_state_db_path(),
            flush_interval: Duration::from_secs(30),
            queue_size: 8_192,
            max_quality_rows: 50_000,
            max_hot_rows: 20_000,
            max_candidate_rows: 20_000,
            row_max_age: Duration::from_secs(30 * 86_400),
        }
    }
}

// ---------------------------------------------------------------------------
// metrics / logging / admin / resources
// ---------------------------------------------------------------------------

/// Prometheus metrics exposure.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Master switch.
    pub enabled: bool,
    /// Listen address. Must be a loopback address unless `allow_non_loopback` is set.
    pub listen: SocketAddr,
    /// Permit binding a non-loopback address. Strongly discouraged.
    pub allow_non_loopback: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:9153"
                .parse()
                .unwrap_or(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9153))),
            allow_non_loopback: false,
        }
    }
}

/// Structured logging.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Log filter directive, `tracing-subscriber` syntax.
    pub level: String,
    /// Emit newline-delimited JSON instead of human-readable text.
    pub json: bool,
    /// Log one line per query. Off by default; this records client addresses and query
    /// names, which is personal data in most jurisdictions.
    pub query_log: bool,
    /// Fraction of queries logged when `query_log` is enabled.
    pub query_log_sample: f64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
            query_log: false,
            query_log_sample: 0.01,
        }
    }
}

/// Local administration socket.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// Master switch.
    pub enabled: bool,
    /// Control-plane endpoint: a Unix domain socket path on Unix, a named pipe path
    /// (`\\.\pipe\...`) on Windows.
    pub socket: PathBuf,
    /// Socket file mode (Unix; ignored on Windows, where the pipe's default security
    /// descriptor limits access to the service account and administrators).
    pub socket_mode: u32,
    /// Maximum accepted request size.
    pub max_request_bytes: usize,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: PathBuf::from(crate::platform::DEFAULT_ADMIN_ENDPOINT),
            socket_mode: 0o660,
            max_request_bytes: 64 * 1024,
        }
    }
}

/// Process-wide resource ceilings.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResourceConfig {
    /// Tokio worker threads; `None` means one per available core.
    pub worker_threads: Option<usize>,
    /// Maximum concurrent in-flight client queries.
    pub max_inflight_queries: usize,
    /// Maximum concurrent upstream operations.
    pub max_inflight_upstream: usize,
    /// Maximum number of blocking threads used for storage and dataset parsing.
    pub max_blocking_threads: usize,
    /// Enable the systemd watchdog when `WATCHDOG_USEC` is present.
    pub systemd_watchdog: bool,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_inflight_queries: 20_000,
            max_inflight_upstream: 4_000,
            max_blocking_threads: 4,
            systemd_watchdog: true,
        }
    }
}

/// Resolve a secret from an environment variable or a permission-restricted file.
pub fn read_secret(
    file: Option<&PathBuf>,
    env: Option<&String>,
) -> Result<Option<String>, ConfigError> {
    if let Some(var) = env {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed));
            }
        }
    }
    if let Some(path) = file {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Secret {
            path: path.display().to_string(),
            source,
        })?;
        let trimmed = text.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed));
        }
    }
    Ok(None)
}

/// Summary of the configuration, used by `egressdnsctl status`.
pub fn summary(cfg: &Config) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "udp_listen".into(),
        cfg.server
            .udp_listen
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    map.insert(
        "tcp_listen".into(),
        cfg.server
            .tcp_listen
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    map.insert("groups".into(), cfg.upstream.groups.len().to_string());
    map.insert("dnssec".into(), format!("{:?}", cfg.dnssec.mode));
    map.insert(
        "cloudflare".into(),
        if cfg.cloudflare.enabled {
            cfg.cloudflare.mode.label().to_string()
        } else {
            "disabled".to_string()
        },
    );
    map.insert("probe".into(), cfg.probe.enabled.to_string());
    map
}
