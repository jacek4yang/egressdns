//! The foreground resolution pipeline.
//!
//! Stages, in order:
//!
//! 1. Parse and validate the request (already done by the listener).
//! 2. Access control and rate limiting (done by the listener).
//! 3. Static local zones and hosts.
//! 4. Positive, negative, failure and stale cache state.
//! 5. Request coalescing for identical concurrent misses.
//! 6. Upstream group selection and adaptive routing.
//! 7. Response validation and DNSSEC state determination.
//! 8. Answer-variant selection.
//! 9. Standards-safe A/AAAA ordering.
//! 10. Cloudflare preserve or verified-augment policy.
//! 11. Client-facing TTL cap.
//! 12. Serialisation, performed by the listener.
//!
//! Nothing in this file performs disk I/O, database access or probing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_net::xfer::DnsHandle;
use hickory_proto::op::{DnsRequestOptions, Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, RecordType};
use rustls::RootCertStore;
use tokio::time::Instant;

use crate::cache::hotset::SharedHotSet;
use crate::cache::singleflight::{Join, SingleFlight};
use crate::cache::{
    AnswerSource, CacheEntry, CacheKey, DnsCache, DnssecMode as CacheDnssecMode, DnssecStatus,
    EntryKind, FailureEntry, Lookup, PolicyView, VariantRecord,
};
use crate::cloudflare::state::SharedCloudflare;
use crate::config::{AnyPolicy, CloudflareMode, Config, DnssecMode, EcsMode, SpecialUsePolicy};
use crate::datasets::{SharedDatasets, ZoneAnswer};
use crate::dns::handle::SchedulerHandle;
use crate::dns::message as msgutil;
use crate::dns::message::ExtendedError;
use crate::dns::specialuse;
use crate::error::ResolveError;
use crate::network::SharedNetworkState;
use crate::policy::answer::{apply_answer_policy, AnswerContext};
use crate::policy::cloudflare::Eligibility;
use crate::policy::dnssec::{dnssec_status, earliest_rrsig_expiry, may_set_ad};
use crate::probe::job::{ProbeJob, ProbeQueue};
use crate::ranking::QualityStore;
use crate::upstream::scheduler::Scheduler;

/// Transport a client used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTransport {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

impl ClientTransport {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// Where the answer came from, for metrics and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerOrigin {
    /// Served from an internal zone or hosts entry.
    Local,
    /// Fresh cache hit.
    CacheHit,
    /// Negative cache hit.
    NegativeHit,
    /// Cached resolution failure.
    FailureHit,
    /// Served stale under RFC 8767.
    Stale,
    /// Resolved upstream.
    Upstream,
    /// Coalesced onto another request's upstream operation.
    Coalesced,
    /// Refused, malformed or otherwise rejected.
    Rejected,
}

impl AnswerOrigin {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::CacheHit => "hit",
            Self::NegativeHit => "negative_hit",
            Self::FailureHit => "failure_hit",
            Self::Stale => "stale",
            Self::Upstream => "upstream",
            Self::Coalesced => "coalesced",
            Self::Rejected => "rejected",
        }
    }
}

/// A completed answer.
#[derive(Debug)]
pub struct Answer {
    /// The response message.
    pub message: Message,
    /// Where it came from.
    pub origin: AnswerOrigin,
    /// Maximum wire size the client can accept, in bytes.
    pub max_size: usize,
}

/// The foreground resolver.
pub struct Resolver {
    /// Active configuration.
    pub config: Arc<Config>,
    /// Answer, negative, failure and variant caches.
    pub cache: Arc<DnsCache>,
    /// Request coalescing.
    pub singleflight: Arc<SingleFlight<CacheKey, Arc<CacheEntry>>>,
    /// Adaptive upstream scheduler.
    pub scheduler: Arc<Scheduler>,
    /// Dataset snapshots.
    pub datasets: SharedDatasets,
    /// Network generation and family state.
    pub network: SharedNetworkState,
    /// Cloudflare optimization state.
    pub cloudflare: SharedCloudflare,
    /// Address quality evidence.
    pub quality: Arc<QualityStore>,
    /// Hot-name tracking.
    pub hotset: SharedHotSet,
    /// Probe work queue.
    pub probes: ProbeQueue,
    /// TLS roots, shared with the probe engine.
    pub roots: Arc<RootCertStore>,
    /// One DNSSEC validator per upstream group, built once so the validation cache is
    /// actually shared between queries. Building a validator per query allocated a fresh
    /// cache for every lookup and threw it away, which made
    /// `dnssec.validation_cache_entries` cost memory and buy nothing.
    validators: HashMap<Arc<str>, hickory_net::dnssec::DnssecDnsHandle<SchedulerHandle>>,
    /// Ceiling on concurrent DNSSEC validations.
    validation_slots: Arc<tokio::sync::Semaphore>,
    /// Configured value of that ceiling, for the in-flight gauge.
    validation_capacity: usize,
    /// Last stale-refresh attempt per key, enforcing `serve_stale.retry_interval`.
    stale_refresh: parking_lot::Mutex<HashMap<CacheKey, Instant>>,
    /// Monotonic counter used to derive deterministic exploration seeds.
    seq: AtomicU64,
}

impl Resolver {
    /// Assemble a resolver.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        cache: Arc<DnsCache>,
        singleflight: Arc<SingleFlight<CacheKey, Arc<CacheEntry>>>,
        scheduler: Arc<Scheduler>,
        datasets: SharedDatasets,
        network: SharedNetworkState,
        cloudflare: SharedCloudflare,
        quality: Arc<QualityStore>,
        hotset: SharedHotSet,
        probes: ProbeQueue,
        roots: Arc<RootCertStore>,
        validation_slots: Arc<tokio::sync::Semaphore>,
    ) -> Result<Self, crate::error::ConfigError> {
        // Trust anchors are security-critical: if the operator named a file it must load
        // and it must be non-empty, otherwise validation would silently fall back to the
        // compiled-in root keys and the configuration would be decorative.
        let anchors = match config.dnssec.trust_anchor_file.as_deref() {
            None => Arc::new(hickory_proto::dnssec::TrustAnchors::default()),
            Some(path) => {
                let anchors =
                    hickory_proto::dnssec::TrustAnchors::from_file(path).map_err(|e| {
                        crate::error::ConfigError::invalid(
                            "dnssec.trust_anchor_file",
                            format!("cannot load trust anchors from {}: {e}", path.display()),
                        )
                    })?;
                if anchors.is_empty() {
                    return Err(crate::error::ConfigError::invalid(
                        "dnssec.trust_anchor_file",
                        format!("{} contains no DNSKEY records", path.display()),
                    ));
                }
                tracing::info!(
                    event = "dnssec.trust_anchors_loaded",
                    path = %path.display(),
                    keys = anchors.len(),
                );
                Arc::new(anchors)
            }
        };

        let budget = config.server.foreground_budget;
        let mut validators = HashMap::new();
        for name in scheduler.registry().group_names() {
            if let Some(group) = scheduler.registry().group(&name) {
                let handle = SchedulerHandle::new(Arc::clone(&scheduler), group, budget);
                let validator = hickory_net::dnssec::DnssecDnsHandle::with_trust_anchor(
                    handle,
                    Arc::clone(&anchors),
                )
                .validation_cache_size(config.dnssec.validation_cache_entries);
                validators.insert(name, validator);
            }
        }

        let validation_capacity = validation_slots.available_permits();
        Ok(Self {
            config,
            cache,
            singleflight,
            scheduler,
            datasets,
            network,
            cloudflare,
            quality,
            hotset,
            probes,
            roots,
            validators,
            validation_slots,
            validation_capacity,
            stale_refresh: parking_lot::Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
        })
    }

    fn next_seed(&self) -> u64 {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        crate::util::fnv1a64(&n.to_le_bytes())
    }

    /// Maximum response size for a client.
    pub fn max_response_size(&self, request: &Message, transport: ClientTransport) -> usize {
        match transport {
            ClientTransport::Tcp => self.config.server.tcp.max_message_bytes,
            ClientTransport::Udp => match request.edns.as_ref() {
                None => usize::from(self.config.server.udp.non_edns_max_payload),
                Some(edns) => usize::from(
                    edns.max_payload()
                        .clamp(512, self.config.server.udp.max_payload),
                ),
            },
        }
    }

    /// Handle one client query end to end.
    pub async fn handle(self: &Arc<Self>, request: &Message, transport: ClientTransport) -> Answer {
        let max_size = self.max_response_size(request, transport);

        // ---- request validation -----------------------------------------------------
        if request.metadata.op_code != OpCode::Query {
            return self.reject(request, ResponseCode::NotImp, max_size, "opcode");
        }
        if request.queries.len() != 1 {
            return self.reject(request, ResponseCode::FormErr, max_size, "question_count");
        }
        if let Some(edns) = request.edns.as_ref() {
            if edns.version() > 0 {
                // RFC 6891 section 6.1.3.
                let mut msg = msgutil::error_response(request, ResponseCode::BADVERS, true);
                if let Some(e) = msg.edns.as_mut() {
                    e.set_version(0);
                }
                return Answer {
                    message: msg,
                    origin: AnswerOrigin::Rejected,
                    max_size,
                };
            }
        }
        let query = request.queries[0].clone();
        if !msgutil::supported_class(&query) {
            return self.reject(request, ResponseCode::Refused, max_size, "class");
        }

        let qname = query.name().to_string();
        let qtype = query.query_type();

        // ---- RFC 8482 ANY handling ---------------------------------------------------
        if qtype == RecordType::ANY {
            match self.config.server.any_policy {
                AnyPolicy::Refuse => {
                    return self.reject(request, ResponseCode::Refused, max_size, "any_refused")
                }
                AnyPolicy::Minimal => {
                    let mut msg =
                        msgutil::minimal_any_response(request, self.config.ttl.cap_default);
                    self.attach_response_edns(request, &mut msg);
                    return Answer {
                        message: msg,
                        origin: AnswerOrigin::Local,
                        max_size,
                    };
                }
                AnyPolicy::Forward => {}
            }
        }

        // ---- static local data --------------------------------------------------------
        // Operator configuration is consulted before the special-use registry, so a site
        // that genuinely serves `home.arpa.` or a private reverse zone keeps working.
        if let Some(answer) = self.local_answer(request, &qname, qtype, max_size) {
            return answer;
        }

        // ---- special-use names (RFC 6761, 6762, 7686, 8375) ----------------------------
        if self.config.server.special_use == SpecialUsePolicy::Local {
            if let Some(answer) = self.special_use_answer(request, &qname, qtype, max_size) {
                return answer;
            }
        }

        // ---- cache --------------------------------------------------------------------
        let datasets = self.datasets.load();
        let group_name = datasets
            .group_for(&qname)
            .unwrap_or_else(|| Arc::from(self.config.upstream.default_group.as_str()));
        let validating = matches!(self.config.dnssec.mode, DnssecMode::Validate);
        let client_do = request
            .edns
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);
        let key = CacheKey::new(
            &qname,
            qtype,
            query.query_class(),
            PolicyView {
                group: Arc::clone(&group_name),
                ecs_identity: self.ecs_identity(),
            },
            CacheDnssecMode {
                dnssec_ok: validating || client_do,
                checking_disabled: request.metadata.checking_disabled,
            },
        );

        let now = Instant::now();
        self.hotset.observe(&key, None, now);

        if let Some(failure) = self.cache.failure(&key, now) {
            metrics::counter!(
                crate::metrics::names::CACHE_LOOKUPS_TOTAL,
                "outcome" => "failure_hit",
            )
            .increment(1);
            let mut msg = msgutil::error_response(request, failure.rcode, true);
            if self.config.dnssec.extended_errors {
                msgutil::attach_ede(&mut msg, ExtendedError::NetworkError, failure.reason);
            }
            return Answer {
                message: msg,
                origin: AnswerOrigin::FailureHit,
                max_size,
            };
        }

        let lookup = self.cache.get(&key, now);
        metrics::counter!(
            crate::metrics::names::CACHE_LOOKUPS_TOTAL,
            "outcome" => lookup.label(),
        )
        .increment(1);

        match lookup {
            Lookup::Fresh { entry, remaining } => {
                let origin = match entry.kind {
                    EntryKind::Positive => AnswerOrigin::CacheHit,
                    _ => AnswerOrigin::NegativeHit,
                };
                let message = self.build_response(request, &entry, remaining, false, client_do);
                Answer {
                    message,
                    origin,
                    max_size,
                }
            }
            Lookup::Stale { entry, .. } => {
                self.serve_stale(request, key, entry, client_do, max_size)
                    .await
            }
            Lookup::Miss => {
                self.resolve_miss(request, key, group_name, client_do, max_size)
                    .await
            }
        }
    }

    fn reject(
        &self,
        request: &Message,
        code: ResponseCode,
        max_size: usize,
        reason: &'static str,
    ) -> Answer {
        metrics::counter!(crate::metrics::names::REJECTED_TOTAL, "reason" => reason).increment(1);
        let mut msg = msgutil::error_response(request, code, true);
        self.attach_response_edns(request, &mut msg);
        Answer {
            message: msg,
            origin: AnswerOrigin::Rejected,
            max_size,
        }
    }

    fn ecs_identity(&self) -> Option<Arc<str>> {
        match self.config.ecs.mode {
            EcsMode::Disabled => None,
            EcsMode::FixedEgress => {
                let v4 = self
                    .config
                    .ecs
                    .egress
                    .ipv4
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let v6 = self
                    .config
                    .ecs
                    .egress
                    .ipv6
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                Some(Arc::from(format!("{v4}|{v6}")))
            }
        }
    }

    /// Answer a name that falls inside the IANA Special-Use Domain Names registry.
    ///
    /// Returning `None` means the name is ordinary and resolution continues. These answers
    /// are authoritative and are deliberately *not* inserted into the shared cache: they
    /// are cheap to recompute, and keeping them out means a configuration reload that adds
    /// a local zone for `home.arpa.` takes effect on the very next query.
    fn special_use_answer(
        &self,
        request: &Message,
        qname: &str,
        qtype: RecordType,
        max_size: usize,
    ) -> Option<Answer> {
        let (registry, disposition) = specialuse::classify(qname)?;
        // An explicit suffix rule is a statement that the operator has an upstream which
        // is authoritative for this subtree, so the registry default must not shadow it.
        // This is the supported way to point `home.arpa.` or a private reverse zone at an
        // internal resolver.
        if self.datasets.load().group_for(qname).is_some() {
            return None;
        }
        metrics::counter!(
            crate::metrics::names::SPECIAL_USE_TOTAL,
            "registry" => registry.label(),
        )
        .increment(1);

        let ttl = self.config.local.local_ttl;
        let mut msg = match disposition {
            specialuse::Disposition::Forward => return None,
            specialuse::Disposition::NxDomain => {
                msgutil::error_response(request, ResponseCode::NXDomain, true)
            }
            specialuse::Disposition::Loopback => {
                let mut msg = msgutil::response_skeleton(request, true);
                if let Some(rdata) = specialuse::loopback_rdata(qtype) {
                    msg.add_answer(hickory_proto::rr::Record::from_rdata(
                        request.queries[0].name().clone(),
                        ttl,
                        rdata,
                    ));
                }
                msg
            }
        };
        msg.metadata.authoritative = true;
        self.attach_response_edns(request, &mut msg);
        Some(Answer {
            message: msg,
            origin: AnswerOrigin::Local,
            max_size,
        })
    }

    /// Answer from internal zones or hosts, when the name is covered.
    fn local_answer(
        &self,
        request: &Message,
        qname: &str,
        qtype: RecordType,
        max_size: usize,
    ) -> Option<Answer> {
        let datasets = self.datasets.load();
        let ttl = self.config.local.local_ttl;

        if matches!(qtype, RecordType::A | RecordType::AAAA) {
            let want_v4 = qtype == RecordType::A;
            let addrs = datasets.hosts.get_family(qname, want_v4);
            if !addrs.is_empty() {
                let mut msg = msgutil::response_skeleton(request, true);
                let name = request.queries[0].name().clone();
                for addr in addrs {
                    let rdata = match addr {
                        IpAddr::V4(v4) => RData::A(hickory_proto::rr::rdata::A(v4)),
                        IpAddr::V6(v6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(v6)),
                    };
                    msg.add_answer(hickory_proto::rr::Record::from_rdata(
                        name.clone(),
                        ttl,
                        rdata,
                    ));
                }
                msg.metadata.authoritative = true;
                self.attach_response_edns(request, &mut msg);
                return Some(Answer {
                    message: msg,
                    origin: AnswerOrigin::Local,
                    max_size,
                });
            }
            // A hosts entry for the other family means NODATA, not a fall-through.
            if datasets.hosts.get(qname).is_some() {
                let mut msg = msgutil::response_skeleton(request, true);
                msg.metadata.authoritative = true;
                self.attach_response_edns(request, &mut msg);
                return Some(Answer {
                    message: msg,
                    origin: AnswerOrigin::Local,
                    max_size,
                });
            }
        }

        match datasets.zones.lookup(qname, qtype) {
            ZoneAnswer::Records(records) => {
                let mut msg = msgutil::response_skeleton(request, true);
                msg.metadata.authoritative = true;
                for r in records {
                    msg.add_answer(r);
                }
                self.attach_response_edns(request, &mut msg);
                Some(Answer {
                    message: msg,
                    origin: AnswerOrigin::Local,
                    max_size,
                })
            }
            ZoneAnswer::NoData => {
                let mut msg = msgutil::response_skeleton(request, true);
                msg.metadata.authoritative = true;
                self.attach_response_edns(request, &mut msg);
                Some(Answer {
                    message: msg,
                    origin: AnswerOrigin::Local,
                    max_size,
                })
            }
            ZoneAnswer::NxDomain => {
                let mut msg = msgutil::error_response(request, ResponseCode::NXDomain, true);
                msg.metadata.authoritative = true;
                Some(Answer {
                    message: msg,
                    origin: AnswerOrigin::Local,
                    max_size,
                })
            }
            ZoneAnswer::NotInZone => None,
        }
    }

    /// Whether a stale-serving refresh may be started for this key right now.
    ///
    /// Bounded by construction: the table of last-attempt times is capped and entries
    /// older than the interval are swept, so a large working set of failing names cannot
    /// grow it without limit.
    fn stale_refresh_allowed(&self, key: &CacheKey, interval: Duration) -> bool {
        if interval.is_zero() {
            return true;
        }
        const MAX_TRACKED: usize = 8_192;
        let now = Instant::now();
        let mut table = self.stale_refresh.lock();
        if let Some(last) = table.get(key) {
            if now.saturating_duration_since(*last) < interval {
                return false;
            }
        }
        if table.len() >= MAX_TRACKED {
            table.retain(|_, last| now.saturating_duration_since(*last) < interval);
            if table.len() >= MAX_TRACKED {
                // Still full of live entries: allow the refresh rather than silently
                // suppressing it. Suppression is an optimisation; correctness is not.
                return true;
            }
        }
        table.insert(key.clone(), now);
        true
    }

    async fn serve_stale(
        self: &Arc<Self>,
        request: &Message,
        key: CacheKey,
        entry: Arc<CacheEntry>,
        client_do: bool,
        max_size: usize,
    ) -> Answer {
        let stale_cfg = &self.config.serve_stale;

        // RFC 8767: attempt a live refresh, but answer from the stale entry if the refresh
        // has not completed within the client response timer.
        //
        // `serve_stale.retry_interval` is what stops this becoming a refresh storm.
        // Without it, every query for a name whose upstream is down spawns another
        // refresh, so a popular dead name generates upstream traffic proportional to
        // client demand at precisely the moment the upstream is least able to absorb it.
        // Singleflight coalesces concurrent attempts but not sequential ones, and the
        // client is answered immediately either way.
        let refresh = if self.stale_refresh_allowed(&key, stale_cfg.retry_interval) {
            let me = Arc::clone(self);
            let refresh_key = key.clone();
            Some(tokio::spawn(async move { me.refresh(refresh_key).await }))
        } else {
            metrics::counter!(
                crate::metrics::names::SERVE_STALE_TOTAL,
                "outcome" => "refresh_suppressed",
            )
            .increment(1);
            None
        };

        if let Some(refresh) = refresh {
            if let Ok(Ok(Ok(fresh))) = tokio::time::timeout(stale_cfg.client_timeout, refresh).await
            {
                let remaining = fresh.remaining_ttl(Instant::now());
                let message = self.build_response(request, &fresh, remaining, false, client_do);
                return Answer {
                    message,
                    origin: AnswerOrigin::Upstream,
                    max_size,
                };
            }
        }

        metrics::counter!(
            crate::metrics::names::SERVE_STALE_TOTAL,
            "outcome" => "served",
        )
        .increment(1);
        let mut message = self.build_response(request, &entry, 0, true, client_do);
        if stale_cfg.include_ede && self.config.dnssec.extended_errors {
            let code = if entry.kind == EntryKind::NxDomain {
                ExtendedError::StaleNxdomain
            } else {
                ExtendedError::StaleAnswer
            };
            msgutil::attach_ede(&mut message, code, "serving expired data");
        }
        Answer {
            message,
            origin: AnswerOrigin::Stale,
            max_size,
        }
    }

    async fn resolve_miss(
        self: &Arc<Self>,
        request: &Message,
        key: CacheKey,
        _group: Arc<str>,
        client_do: bool,
        max_size: usize,
    ) -> Answer {
        let budget = self.config.server.foreground_budget;
        let result = match self.singleflight.join(key.clone()) {
            Join::Leader(leader) => {
                let outcome = self.fetch(&key).await;
                match &outcome {
                    Ok(entry) => leader.complete(Arc::clone(entry)),
                    Err(e) => leader.fail(&e.to_string()),
                }
                outcome.map_err(|e| e.to_string())
            }
            Join::Follower(follower) => {
                metrics::counter!(crate::metrics::names::SINGLEFLIGHT_COALESCED_TOTAL).increment(1);
                match tokio::time::timeout(budget, follower.wait()).await {
                    Ok(Ok(entry)) => Ok(entry),
                    Ok(Err(e)) => Err(format!("{e:?}")),
                    Err(_) => Err("coalesced request timed out".to_string()),
                }
            }
            Join::Saturated => {
                metrics::counter!(
                    crate::metrics::names::REJECTED_TOTAL,
                    "reason" => "singleflight_saturated",
                )
                .increment(1);
                Err("too many distinct queries in flight".to_string())
            }
        };

        match result {
            Ok(entry) => {
                let remaining = entry.remaining_ttl(Instant::now());
                let message = self.build_response(request, &entry, remaining, false, client_do);
                Answer {
                    message,
                    origin: AnswerOrigin::Upstream,
                    max_size,
                }
            }
            Err(detail) => {
                // Record the resolution failure so that repeated queries do not repeatedly
                // hammer a failing upstream (RFC 9520).
                let streak = self.cache.failure_streak(&key).saturating_add(1);
                let base = self.config.cache.failure_min_ttl;
                let ttl = base
                    .saturating_mul(1u32 << streak.min(6))
                    .min(self.config.cache.failure_max_ttl);
                self.cache.record_failure(
                    key,
                    FailureEntry {
                        recorded_at: Instant::now(),
                        ttl,
                        rcode: ResponseCode::ServFail,
                        reason: "upstream resolution failed",
                        consecutive: streak,
                    },
                );
                let mut msg = msgutil::error_response(request, ResponseCode::ServFail, true);
                if self.config.dnssec.extended_errors {
                    let code = if detail.contains("DNSSEC") || detail.contains("bogus") {
                        ExtendedError::DnssecBogus
                    } else {
                        ExtendedError::NoReachableAuthority
                    };
                    msgutil::attach_ede(&mut msg, code, &detail);
                }
                Answer {
                    message: msg,
                    origin: AnswerOrigin::Rejected,
                    max_size,
                }
            }
        }
    }

    /// Resolve a hostname to addresses through the normal pipeline.
    ///
    /// Used by background dataset fetches so that they inherit the same caching, DNSSEC
    /// policy and upstream health as client queries. IPv6 is preferred only when the
    /// family is known to be usable.
    pub async fn lookup_addresses(self: &Arc<Self>, host: &str) -> Vec<IpAddr> {
        let datasets = self.datasets.load();
        let group = datasets
            .group_for(host)
            .unwrap_or_else(|| Arc::from(self.config.upstream.default_group.as_str()));
        let validating = matches!(self.config.dnssec.mode, DnssecMode::Validate);
        let net = self.network.load();
        let mut families: Vec<RecordType> = Vec::with_capacity(2);
        if net.v4 != crate::network::FamilyState::Unusable {
            families.push(RecordType::A);
        }
        if net.v6 == crate::network::FamilyState::Usable {
            families.push(RecordType::AAAA);
        }
        let mut out = Vec::new();
        for qtype in families {
            let key = CacheKey::new(
                host,
                qtype,
                DNSClass::IN,
                PolicyView {
                    group: Arc::clone(&group),
                    ecs_identity: self.ecs_identity(),
                },
                CacheDnssecMode {
                    dnssec_ok: validating,
                    checking_disabled: false,
                },
            );
            let now = Instant::now();
            let entry = match self.cache.get(&key, now) {
                Lookup::Fresh { entry, .. } => Some(entry),
                _ => self.refresh(key).await.ok(),
            };
            let Some(entry) = entry else {
                continue;
            };
            for record in entry.message.answers.iter() {
                match &record.data {
                    RData::A(a) => out.push(IpAddr::V4(a.0)),
                    RData::AAAA(a) => out.push(IpAddr::V6(a.0)),
                    _ => {}
                }
            }
        }
        out.retain(|a| crate::util::ipclass::classify(*a).is_none());
        out.dedup();
        out
    }

    /// Refresh a cache key, used by serve-stale and by the prefetcher.
    pub async fn refresh(self: &Arc<Self>, key: CacheKey) -> Result<Arc<CacheEntry>, ResolveError> {
        match self.singleflight.join(key.clone()) {
            Join::Leader(leader) => {
                let outcome = self.fetch(&key).await;
                match &outcome {
                    Ok(entry) => leader.complete(Arc::clone(entry)),
                    Err(e) => leader.fail(&e.to_string()),
                }
                outcome
            }
            Join::Follower(follower) => {
                follower.wait().await.map_err(|_| ResolveError::AllFailed {
                    detail: "coalesced refresh failed".to_string(),
                })
            }
            Join::Saturated => Err(ResolveError::AllFailed {
                detail: "singleflight saturated".to_string(),
            }),
        }
    }

    /// Perform the upstream exchange for a cache key and store the result.
    async fn fetch(self: &Arc<Self>, key: &CacheKey) -> Result<Arc<CacheEntry>, ResolveError> {
        let group = self
            .scheduler
            .registry()
            .group(&key.view.group)
            .ok_or_else(|| ResolveError::NoRoute {
                group: key.view.group.to_string(),
            })?;

        let name = hickory_proto::rr::Name::from_utf8(&*key.name).map_err(|_| {
            ResolveError::InvalidResponse {
                reason: "query name could not be encoded",
            }
        })?;
        let mut query = hickory_proto::op::Query::query(name, key.qtype);
        query.set_query_class(key.qclass);

        let validating = matches!(self.config.dnssec.mode, DnssecMode::Validate);
        let mut message = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = key.mode.checking_disabled;
        message.add_query(query);

        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(self.config.server.udp.max_payload);
        edns.set_dnssec_ok(validating || key.mode.dnssec_ok);
        if let (EcsMode::FixedEgress, Some(prefix)) =
            (self.config.ecs.mode, self.config.ecs.egress.ipv4)
        {
            edns.options_mut().insert(msgutil::encode_ecs(
                IpAddr::V4(prefix.addr()),
                prefix.prefix_len(),
            ));
        }
        message.set_edns(edns);

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.edns_payload_len = self.config.server.udp.max_payload;
        options.edns_set_dnssec_ok = validating || key.mode.dnssec_ok;
        options.recursion_desired = true;
        // RFC 5452: 0x20 case randomisation adds entropy an off-path attacker must guess.
        options.case_randomization = true;

        let budget = self.config.server.foreground_budget;
        let seed = self.next_seed();

        let (response, route, trust_ad) = if validating && !key.mode.checking_disabled {
            let validator = self
                .validators
                .get(&key.view.group)
                .or_else(|| self.validators.values().next())
                .ok_or(ResolveError::NoRoute {
                    group: key.view.group.to_string(),
                })?
                .clone();

            // A validating lookup fans out into DNSKEY and DS queries whose depth hickory
            // bounds but whose *cost* it does not. Two ceilings apply and neither is
            // optional: a concurrency permit, so a burst of validating misses cannot
            // multiply into unbounded upstream work, and a wall-clock budget, so the
            // promise in `server.foreground_budget` holds for validated answers exactly as
            // it does for unvalidated ones.
            let permit = match tokio::time::timeout(
                budget,
                Arc::clone(&self.validation_slots).acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                _ => {
                    metrics::counter!(crate::metrics::names::DNSSEC_SHED_TOTAL).increment(1);
                    return Err(ResolveError::Overloaded {
                        limit: self.validation_slots.available_permits(),
                    });
                }
            };
            metrics::gauge!(crate::metrics::names::DNSSEC_INFLIGHT).set(
                self.validation_capacity
                    .saturating_sub(self.validation_slots.available_permits())
                    as f64,
            );

            let mut options = options;
            options.max_request_depth = self.config.dnssec.max_validation_depth;
            let request = hickory_proto::op::DnsRequest::new(message.clone(), options);
            use futures_util::StreamExt;
            let outcome = tokio::time::timeout(budget, async {
                let mut stream = validator.send(request);
                stream.next().await
            })
            .await;
            drop(permit);

            match outcome {
                Err(_) => {
                    return Err(ResolveError::Timeout {
                        elapsed_ms: budget.as_millis() as u64,
                    })
                }
                Ok(Some(Ok(response))) => {
                    let msg = response.into_message();
                    (msg, None, false)
                }
                Ok(Some(Err(e))) => {
                    let text = e.to_string();
                    if text.contains("Bogus") || text.contains("bogus") {
                        return Err(ResolveError::DnssecBogus);
                    }
                    return Err(ResolveError::AllFailed {
                        detail: crate::util::bounded(&text, 160),
                    });
                }
                Ok(None) => {
                    return Err(ResolveError::AllFailed {
                        detail: "validator produced no answer".to_string(),
                    })
                }
            }
        } else {
            let answer = self
                .scheduler
                .resolve(&group, message.clone(), options, budget, seed)
                .await?;
            (answer.message, Some(answer.route), answer.trust_ad)
        };

        let status = dnssec_status(&response, &self.config.dnssec, trust_ad);
        if status == DnssecStatus::Bogus {
            return Err(ResolveError::DnssecBogus);
        }

        let kind = classify(&response);
        let raw_ttl = match kind {
            EntryKind::Positive => msgutil::min_ttl(&response).unwrap_or(0),
            _ => negative_ttl(&response).unwrap_or(0),
        };
        let cap = match kind {
            EntryKind::Positive => self.cache.internal_max_ttl(),
            _ => self.cache.negative_max_ttl(),
        };
        let ttl = raw_ttl.min(cap);

        let now = Instant::now();
        let now_unix = crate::util::time::SystemClock.unix_secs_now();
        let source = AnswerSource {
            server: route
                .as_ref()
                .map(|r| Arc::clone(&r.server))
                .unwrap_or_else(|| Arc::from("validator")),
            transport: route
                .as_ref()
                .map(|r| r.transport)
                .unwrap_or(crate::config::TransportKind::Udp),
        };
        let fingerprint = msgutil::answer_fingerprint(&response);
        let entry = Arc::new(CacheEntry {
            approx_bytes: crate::cache::estimate_bytes(&response),
            fingerprint,
            received_at: now,
            received_unix: now_unix,
            ttl,
            kind,
            dnssec: status,
            source: source.clone(),
            rrsig_expiry_unix: earliest_rrsig_expiry(&response),
            message: Arc::new(response),
        });

        // Record the complete answer as a variant. Variants are never merged; this only
        // remembers that this exact complete answer was seen from this upstream.
        if kind == EntryKind::Positive {
            let is_new = self.cache.record_variant(
                key.clone(),
                VariantRecord {
                    fingerprint,
                    message: Arc::clone(&entry.message),
                    source,
                    observed_at: now,
                    ttl,
                    dnssec: status,
                },
                now,
            );
            if is_new {
                metrics::counter!(crate::metrics::names::VARIANTS_OBSERVED_TOTAL).increment(1);
            }
        }

        self.cache.clear_failure(key);
        self.cache.insert(key.clone(), Arc::clone(&entry));
        self.schedule_probes(key, &entry);
        Ok(entry)
    }

    /// Offer addresses from a fresh answer to the probe engine.
    ///
    /// This is a non-blocking hand-off. If the queue is full the observation is simply
    /// dropped: probes are optional evidence and must never slow down resolution.
    fn schedule_probes(&self, key: &CacheKey, entry: &CacheEntry) {
        if !self.probes.is_enabled() || entry.kind != EntryKind::Positive {
            return;
        }
        if !matches!(key.qtype, RecordType::A | RecordType::AAAA) {
            return;
        }
        let snapshot = self.cloudflare.prefixes();
        let generation = self.network.generation();
        let limit = self.config.probe.max_candidates_per_rrset;
        let hostname: Arc<str> = Arc::clone(&key.name);
        let mut scheduled = 0usize;
        for record in entry.message.answers.iter() {
            if scheduled >= limit {
                break;
            }
            let addr = match &record.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(a) => IpAddr::V6(a.0),
                _ => continue,
            };
            if crate::util::ipclass::classify(addr).is_some() {
                continue;
            }
            let is_cf = snapshot
                .as_ref()
                .as_ref()
                .map(|s| s.contains(addr))
                .unwrap_or(false);
            self.probes.offer(ProbeJob::Observed {
                hostname: Arc::clone(&hostname),
                addr,
                port: 443,
                cloudflare: is_cf,
                generation,
            });
            scheduled += 1;
        }
    }

    /// Build a client response from a cache entry.
    fn build_response(
        &self,
        request: &Message,
        entry: &CacheEntry,
        remaining: u32,
        is_stale: bool,
        client_do: bool,
    ) -> Message {
        let now = Instant::now();
        let mut message = (*entry.message).clone();
        message.metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
        message.metadata.response_code = entry.message.metadata.response_code;
        message.metadata.recursion_available = true;
        message.metadata.authoritative = false;
        message.queries = request.queries.clone();
        message.signature = None;
        message.edns = None;

        let elapsed = entry.age_secs(now);
        msgutil::age_ttls(&mut message, elapsed);

        let qtype = request.queries[0].query_type();
        let qname = request.queries[0].name().to_string();

        let addresses = collect_addresses(&message, qtype);
        let quality = self.quality.snapshot_for(&addresses, 443, &qname);
        let snapshot = self.cloudflare.prefixes();
        let now_unix = crate::util::time::SystemClock.unix_secs_now();
        let verified = if self.cloudflare.enabled()
            && self.cloudflare.mode() == CloudflareMode::VerifiedAugment
        {
            let store = Arc::clone(&self.quality);
            let ranking = self.config.ranking.clone();
            let host = qname.clone();
            self.cloudflare.verified_for(
                &qname,
                qtype == RecordType::A,
                self.config.cloudflare.augment.min_validations,
                self.config.cloudflare.augment.validation_ttl,
                now,
                move |addr| {
                    store
                        .get(&crate::ranking::ProbeKey::https(addr, 443, &host))
                        .map(|s| (s.expected_cost(&ranking, now), s.sample_count()))
                        // No evidence: neutral cost and zero samples, so `min_samples`
                        // can tell "measured and average" apart from "never measured".
                        .unwrap_or((ranking.neutral_cost_ms, 0))
                },
            )
        } else {
            Vec::new()
        };

        let recent_change = self
            .network
            .in_relearn_window(now_unix, self.config.ttl.network_change_window.as_secs());

        let ctx = AnswerContext {
            qtype,
            dnssec: entry.dnssec,
            cloudflare_enabled: self.cloudflare.enabled(),
            cloudflare_mode: self.cloudflare.mode(),
            snapshot: snapshot.as_ref().as_ref(),
            domain_excluded: crate::policy::cloudflare::is_excluded(
                &qname,
                &self.config.cloudflare.allow_domains,
                &self.config.cloudflare.deny_domains,
            ),
            baseline_validated: self.cloudflare.baseline(&qname),
            verified: &verified,
            can_validate_ech: false,
            quality: &quality,
            ranking: &self.config.ranking,
            augment: &self.config.cloudflare.augment,
            ttl: &self.config.ttl,
            remaining_authoritative: remaining,
            remaining_signature: entry.remaining_signature_secs(now_unix),
            is_stale,
            recent_network_change: recent_change,
            now,
            explore_seed: self.next_seed(),
        };
        let outcome = apply_answer_policy(&mut message, &ctx);
        record_policy_metrics(&outcome);

        if !client_do {
            message = message.maybe_strip_dnssec_records(false);
        }
        let client_asked_ad = client_do || request.metadata.authentic_data;
        message.metadata.authentic_data =
            may_set_ad(entry.dnssec, client_asked_ad, outcome.modified);

        self.attach_response_edns(request, &mut message);
        message
    }

    /// Attach the response OPT record, mirroring the client's DNSSEC OK bit.
    fn attach_response_edns(&self, request: &Message, message: &mut Message) {
        let Some(req_edns) = request.edns.as_ref() else {
            // RFC 6891: a client that did not send OPT must not receive one.
            message.edns = None;
            return;
        };
        let mut edns = message.edns.take().unwrap_or_default();
        edns.set_version(0);
        edns.set_max_payload(self.config.server.udp.max_payload);
        edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        edns.options_mut()
            .remove(hickory_proto::rr::rdata::opt::EdnsCode::Subnet);
        message.set_edns(edns);
    }
}

fn record_policy_metrics(outcome: &crate::policy::answer::AnswerOutcome) {
    metrics::counter!(
        crate::metrics::names::RANKING_DECISIONS_TOTAL,
        "decision" => outcome.order.label(),
    )
    .increment(1);
    match outcome.cloudflare_applied {
        Eligibility::Preserve => {
            metrics::counter!(crate::metrics::names::CF_PRESERVE_TOTAL).increment(1)
        }
        Eligibility::Augment => {
            metrics::counter!(crate::metrics::names::CF_AUGMENT_TOTAL).increment(1)
        }
        Eligibility::Off => {}
    }
    if let Some(reason) = outcome.fallback {
        metrics::counter!(
            crate::metrics::names::CF_FALLBACK_TOTAL,
            "reason" => reason.label(),
        )
        .increment(1);
    }
}

fn collect_addresses(message: &Message, qtype: RecordType) -> Vec<IpAddr> {
    message
        .answers
        .iter()
        .filter_map(|r| match (&r.data, qtype) {
            (RData::A(a), RecordType::A) => Some(IpAddr::V4(a.0)),
            (RData::AAAA(a), RecordType::AAAA) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// Classify a response as positive, NODATA or NXDOMAIN.
pub fn classify(message: &Message) -> EntryKind {
    match message.metadata.response_code {
        ResponseCode::NXDomain => EntryKind::NxDomain,
        _ => {
            let has_data = message
                .answers
                .iter()
                .any(|r| r.record_type() != RecordType::OPT && !r.record_type().is_dnssec());
            if has_data {
                EntryKind::Positive
            } else {
                EntryKind::NoData
            }
        }
    }
}

/// Negative TTL derived from the SOA minimum, per RFC 2308 section 5.
pub fn negative_ttl(message: &Message) -> Option<u32> {
    for r in &message.authorities {
        if let RData::SOA(soa) = &r.data {
            return Some(r.ttl.min(soa.minimum));
        }
    }
    None
}

/// A holder for the per-request quality snapshot type, exported for tests.
pub type QualitySnapshot = HashMap<IpAddr, crate::ranking::QualityStats>;

/// Convenience: whether a query class is servable.
pub fn class_supported(class: DNSClass) -> bool {
    matches!(class, DNSClass::IN | DNSClass::CH)
}

/// Default per-request duration used when a caller has no better information.
pub const DEFAULT_BUDGET: Duration = Duration::from_millis(2_500);
