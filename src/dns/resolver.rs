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
use crate::policy::dnssec::{
    self as policy_dnssec, dnssec_status, earliest_rrsig_expiry, may_set_ad, ValidationOutcome,
};
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

/// Background proof completions allowed to run at once.
///
/// Small on purpose, and smaller than it first looks like it should be. These share the
/// global upstream permits with client queries, so a generous ceiling here does not merely
/// use spare capacity — it makes clients queue behind background work, which is the one
/// thing this codebase does not do. Two is enough to warm a chain within a few queries.
const PROOF_COMPLETION_CONCURRENCY: usize = 2;

/// Log one `dnssec.proof_incomplete` line per this many occurrences.
const INCOMPLETE_PROOF_LOG_EVERY: u64 = 64;

/// Below this much remaining deadline, a second validation pass cannot finish, so the
/// retry is skipped rather than started and abandoned.
const MIN_REVALIDATION_BUDGET: Duration = Duration::from_millis(150);

/// Why a resolution failed, in the terms the caller needs rather than as prose.
///
/// Three separate decisions used to be re-derived by searching the error text for the
/// words "DNSSEC" and "bogus". That is fragile in the ordinary way, and it was wrong in a
/// specific way: a failure whose message reads "DNSSEC proof could not be completed"
/// contains both words and is the opposite of a bogus verdict.
struct FailureReport {
    /// Human-readable reason, used for the EDE text and the log.
    detail: String,
    /// Whether this failure may enter the failure cache.
    remember: bool,
    /// The RFC 8914 code to report.
    ede: ExtendedError,
}

impl FailureReport {
    fn from_error(e: &ResolveError) -> Self {
        let ede = match e {
            ResolveError::DnssecBogus => ExtendedError::DnssecBogus,
            _ => ExtendedError::NoReachableAuthority,
        };
        Self {
            detail: e.to_string(),
            remember: !e.is_transient(),
            ede,
        }
    }

    /// A failure of the upstream, which is worth remembering for a while (RFC 9520).
    fn upstream(detail: &str) -> Self {
        Self {
            detail: detail.to_string(),
            remember: true,
            ede: ExtendedError::NoReachableAuthority,
        }
    }
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
    /// Which names are known to be web services.
    ///
    /// Gates every use of port-443 evidence. Without it, an answer for an SSH host or a
    /// mail exchanger would be ranked by how well its addresses complete a TLS handshake
    /// on a port they do not serve, and every address in every answer would receive an
    /// unsolicited connection.
    pub services: crate::ranking::service::SharedServiceClassifier,
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
    /// How many answers have been served without a completed proof, used to sample the
    /// log rather than emit one line per query on a congested network.
    incomplete_proof_logs: AtomicU64,
    /// Ceiling on background proof completions running at once.
    proof_completion_slots: Arc<tokio::sync::Semaphore>,
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
        services: crate::ranking::service::SharedServiceClassifier,
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
            services,
            hotset,
            probes,
            roots,
            validators,
            validation_slots,
            validation_capacity,
            stale_refresh: parking_lot::Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
            incomplete_proof_logs: AtomicU64::new(0),
            proof_completion_slots: Arc::new(tokio::sync::Semaphore::new(
                PROOF_COMPLETION_CONCURRENCY,
            )),
        })
    }

    /// Fetch an answer we could not prove, if two independent authorities agree on it.
    ///
    /// Reached only when validation failed for a reason of *ours* — a deadline, an
    /// unreachable route, an authority that refuses DS queries. Never on a Bogus verdict:
    /// that path returns SERVFAIL before getting here, and must keep doing so.
    ///
    /// The corroboration requirement is what separates this from disabling DNSSEC when it
    /// is inconvenient. Stalling one resolver's chain lookups is cheap for an on-path
    /// attacker; producing the same answer from a second authority that *we* pick is not.
    /// Answers obtained this way are served with AD cleared and a short TTL, and cached as
    /// Indeterminate rather than as proof of anything.
    async fn unproved_fallback(
        &self,
        group: &Arc<crate::upstream::pool::UpstreamGroup>,
        message: &Message,
        options: DnsRequestOptions,
        seed: u64,
        outcome: ValidationOutcome,
    ) -> Option<Message> {
        let slice = crate::dns::deadline::remaining_or(self.config.server.foreground_budget);
        if slice < MIN_REVALIDATION_BUDGET {
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "unproved_no_budget",
            )
            .increment(1);
            return None;
        }

        let Some((first, second)) = self
            .scheduler
            .resolve_pair(group, message.clone(), options, slice, seed)
            .await
        else {
            // Fewer than two authorities answered. There is no entitlement to serve on
            // one authority's word, so the original failure stands.
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "unproved_unavailable",
            )
            .increment(1);
            return None;
        };

        // A negative answer is what an attacker wants from a downgrade, and the one shape
        // this must never manufacture. Unproved positives may be served; an unproved
        // negative leaves the original failure standing.
        if first.message.metadata.response_code != ResponseCode::NoError
            || first.message.answers.is_empty()
        {
            return None;
        }

        if !crate::policy::answers_are_compatible(&first.message, &second.message) {
            tracing::warn!(
                event = "dnssec.indeterminate_rejected",
                outcome = outcome.label(),
                "two authorities disagreed about an answer we could not prove"
            );
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "unproved_conflict",
            )
            .increment(1);
            return None;
        }

        metrics::counter!(
            crate::metrics::names::CORROBORATION_TOTAL,
            "outcome" => "unproved_agreed",
        )
        .increment(1);
        Some(first.message)
    }

    /// Report, at a bounded rate, that an answer is being served without a completed
    /// proof.
    ///
    /// One line per name per failure would be a flood on a congested network — which is
    /// exactly when this fires — so it is sampled. A confirmed security failure is never
    /// sampled; that is `dnssec.bogus`, and it is logged every time.
    fn note_incomplete_proof(&self, key: &CacheKey, outcome: ValidationOutcome) {
        metrics::counter!(crate::metrics::names::DNSSEC_INDETERMINATE_SERVED_TOTAL).increment(1);
        let n = self.incomplete_proof_logs.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(INCOMPLETE_PROOF_LOG_EVERY) {
            tracing::warn!(
                event = "dnssec.proof_incomplete",
                name = %key.name,
                qtype = %key.qtype,
                outcome = outcome.label(),
                suppressed = n,
                "serving without AD: the chain could not be proved inside the budget"
            );
        }
    }

    /// Finish the proof after the client has been answered.
    ///
    /// The validator caches the chain elements it fetches, so completing a proof once in
    /// the background is what lets the *next* query for the same zone validate inside the
    /// foreground budget. This is the part that makes the degradation temporary rather
    /// than permanent.
    ///
    /// Strictly background: it takes no client deadline, it is bounded by its own timeout
    /// and by a small ceiling on concurrent completions, and if that ceiling is reached
    /// the work is dropped rather than queued. A client never waits on it.
    fn spawn_proof_completion(
        self: &Arc<Self>,
        group: &Arc<str>,
        message: Message,
        options: DnsRequestOptions,
    ) {
        let Ok(permit) = Arc::clone(&self.proof_completion_slots).try_acquire_owned() else {
            // Already as many completions in flight as we allow. Dropping is correct:
            // this is an optimisation for later queries, never a debt to be queued.
            return;
        };
        let Some(validator) = self.validators.get(group).cloned() else {
            return;
        };
        metrics::counter!(crate::metrics::names::DNSSEC_PROOF_COMPLETION_TOTAL).increment(1);
        let budget = self.config.dnssec.proof_completion_timeout;
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let request = hickory_proto::op::DnsRequest::new(message, options);
            // No `deadline::with_deadline` scope here on purpose: background work is not
            // racing a client, and inheriting an expired client deadline would make every
            // completion fail instantly.
            let _ = tokio::time::timeout(budget, async {
                let mut stream = validator.send(request);
                stream.next().await
            })
            .await;
            drop(permit);
        });
    }

    /// Validate an answer the client has already been given, and act on the verdict.
    ///
    /// The evidence plane. Nothing here is on any client's critical path: it takes no
    /// foreground deadline, it is bounded by its own timeout and by a small ceiling on
    /// concurrent validations, and when that ceiling is reached the work is dropped rather
    /// than queued. Dropping is correct — this improves the *next* answer, and a debt
    /// queued behind a burst improves nothing.
    ///
    /// The four verdicts, and what each is worth:
    ///
    /// * **Bogus** — the served variant is forged. Evict and quarantine it, so it is
    ///   served at most once and never again. This is the only outcome that removes data.
    /// * **Secure** — promote, so the next client gets AD.
    /// * **ProvenInsecure** — record it, so the next client is not made to re-derive it.
    /// * **Incomplete, Timeout, TransportFailure, Indeterminate** — we learned nothing.
    ///   Leave the entry exactly as it was. Deleting an answer because we could not check
    ///   it is how a slow network becomes an outage.
    fn spawn_background_validation(
        self: &Arc<Self>,
        key: &CacheKey,
        message: Message,
        options: DnsRequestOptions,
    ) {
        let Ok(permit) = Arc::clone(&self.proof_completion_slots).try_acquire_owned() else {
            return;
        };
        let Some(validator) = self
            .validators
            .get(&key.view.group)
            .or_else(|| self.validators.values().next())
            .cloned()
        else {
            return;
        };

        metrics::counter!(crate::metrics::names::DNSSEC_PROOF_COMPLETION_TOTAL).increment(1);
        let budget = self.config.dnssec.proof_completion_timeout;
        let cache = Arc::clone(&self.cache);
        let cfg = Arc::clone(&self.config);
        let key = key.clone();
        let mut options = options;
        options.max_request_depth = cfg.dnssec.max_validation_depth;

        tokio::spawn(async move {
            use futures_util::StreamExt;
            let request = hickory_proto::op::DnsRequest::new(message, options);
            // No `deadline::with_deadline` scope: background work is not racing a client,
            // and inheriting an expired client deadline would fail every validation
            // instantly.
            let (result, observed) = crate::dns::proofwatch::watch(async {
                tokio::time::timeout(budget, async {
                    let mut stream = validator.send(request);
                    stream.next().await
                })
                .await
            })
            .await;
            drop(permit);

            let outcome = match result {
                Err(_) => ValidationOutcome::Timeout,
                Ok(Some(Ok(response))) => {
                    let msg = response.into_message();
                    policy_dnssec::classify(&msg, &cfg.dnssec, false, observed)
                }
                Ok(Some(Err(_))) => {
                    if observed == crate::dns::proofwatch::ProofFailure::None {
                        ValidationOutcome::Bogus
                    } else {
                        ValidationOutcome::IncompleteProof
                    }
                }
                Ok(None) => ValidationOutcome::TransportFailure,
            };

            metrics::counter!(
                crate::metrics::names::DNSSEC_OUTCOME_TOTAL,
                "outcome" => outcome.label(),
                "plane" => "evidence",
            )
            .increment(1);

            // The fingerprint of whatever is cached *now*, so a verdict cannot act on an
            // answer it did not examine.
            let fingerprint = match cache.get(&key, Instant::now()) {
                Lookup::Fresh { entry, .. } | Lookup::Stale { entry, .. } => entry.fingerprint,
                _ => return,
            };

            match outcome {
                ValidationOutcome::Bogus => {
                    if cache.evict_variant(&key, fingerprint) {
                        tracing::warn!(
                            event = "dnssec.bogus",
                            name = %key.name,
                            qtype = %key.qtype,
                            "a served answer failed validation and has been evicted"
                        );
                        metrics::counter!(crate::metrics::names::DNSSEC_EVICTED_TOTAL).increment(1);
                    }
                }
                ValidationOutcome::Secure => {
                    if cache.promote(&key, fingerprint, DnssecStatus::Secure) {
                        tracing::debug!(event = "dnssec.secure", name = %key.name);
                    }
                }
                ValidationOutcome::ProvenInsecure => {
                    cache.promote(&key, fingerprint, DnssecStatus::Insecure);
                }
                // Nothing was learned, so nothing changes.
                ValidationOutcome::IncompleteProof
                | ValidationOutcome::Timeout
                | ValidationOutcome::TransportFailure
                | ValidationOutcome::Indeterminate => {}
            }
        });
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
    ///
    /// The foreground deadline is established here, once, and carried on the task for
    /// everything this request goes on to await — including the DNSSEC validator's own
    /// DNSKEY and DS lookups, which come back through `SchedulerHandle` and would
    /// otherwise each start their own budget.
    pub async fn handle(self: &Arc<Self>, request: &Message, transport: ClientTransport) -> Answer {
        let deadline = Instant::now() + self.config.server.foreground_budget;
        crate::dns::deadline::with_deadline(deadline, self.handle_inner(request, transport)).await
    }

    async fn handle_inner(
        self: &Arc<Self>,
        request: &Message,
        transport: ClientTransport,
    ) -> Answer {
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
        let validating = self.config.dnssec.mode.wants_dnssec_records();
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
        // `remember` carries whether the failure may enter the failure cache. A proof we
        // could not finish is not evidence that the name is broken, and caching it as one
        // denies a working name for the whole failure TTL — long after the interruption
        // that caused it has passed.
        let result: Result<Arc<CacheEntry>, FailureReport> =
            match self.singleflight.join(key.clone()) {
                Join::Leader(leader) => {
                    let outcome = self.fetch(&key).await;
                    match &outcome {
                        Ok(entry) => leader.complete(Arc::clone(entry)),
                        Err(e) if e.is_transient() => leader.fail_uncacheable(&e.to_string()),
                        Err(e) => leader.fail(&e.to_string()),
                    }
                    outcome.map_err(|e| FailureReport::from_error(&e))
                }
                Join::Follower(follower) => {
                    metrics::counter!(crate::metrics::names::SINGLEFLIGHT_COALESCED_TOTAL)
                        .increment(1);
                    match tokio::time::timeout(budget, follower.wait()).await {
                        Ok(Ok(entry)) => Ok(entry),
                        Ok(Err(e)) => Err(FailureReport {
                            detail: e.detail().to_string(),
                            remember: e.is_cacheable(),
                            ede: ExtendedError::NoReachableAuthority,
                        }),
                        Err(_) => Err(FailureReport::upstream("coalesced request timed out")),
                    }
                }
                Join::Saturated => {
                    metrics::counter!(
                        crate::metrics::names::REJECTED_TOTAL,
                        "reason" => "singleflight_saturated",
                    )
                    .increment(1);
                    Err(FailureReport::upstream(
                        "too many distinct queries in flight",
                    ))
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
            Err(FailureReport {
                detail,
                remember,
                ede,
            }) => {
                // Record the resolution failure so that repeated queries do not repeatedly
                // hammer a failing upstream (RFC 9520) — but only when the failure was
                // about the upstream. See the `remember` flag above.
                if remember {
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
                }
                let mut msg = msgutil::error_response(request, ResponseCode::ServFail, true);
                if self.config.dnssec.extended_errors {
                    msgutil::attach_ede(&mut msg, ede, &detail);
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
        let validating = self.config.dnssec.mode.wants_dnssec_records();
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

        let validating = self.config.dnssec.mode.wants_dnssec_records();
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

        // Only Strict mode puts validation in front of the client. In Background mode —
        // the default — the foreground fetches the answer and the evidence plane decides
        // what happens to it next. See `DnssecMode::Background`.
        let synchronous =
            self.config.dnssec.mode.blocks_the_client() && !key.mode.checking_disabled;

        let (response, route, trust_ad) = if synchronous {
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
            // Waiting for a permit spends the client's time, so it is charged against the
            // same deadline. Previously the wait could consume a whole budget and
            // validation could then start a second one.
            let permit = match tokio::time::timeout(
                crate::dns::deadline::remaining_or(budget),
                Arc::clone(&self.validation_slots).acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                _ => {
                    metrics::counter!(crate::metrics::names::DNSSEC_SHED_TOTAL).increment(1);
                    return Err(ResolveError::Overloaded {
                        limit: self.validation_capacity,
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

            // Validate, watching what the transport had to say about any failure.
            //
            // A chain lookup that never completed and a signature that does not verify
            // both arrive as `Proof::Bogus`. `proofwatch` is what tells them apart; see
            // the module for why the difference is not a nicety.
            // Validation gets the whole remaining budget, and the fallback gets whatever
            // is left over rather than a reservation taken out of it.
            //
            // Reserving a share was measured to be worse on exactly the networks that
            // need help: where every lookup is slow, validation needs all the time there
            // is, and taking 45% away from it lost more answers to the reservation than
            // the fallback could win back. A validation that fails *early* — refused,
            // unreachable — still leaves time, and that is the case the fallback exists
            // for. One that runs out of time leaves none, and correctly gets none.
            let validation_deadline =
                tokio::time::Instant::now() + crate::dns::deadline::remaining_or(budget);

            let mut attempt = 0;
            let (mut response, outcome) = loop {
                attempt += 1;
                let slice = validation_deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(crate::dns::deadline::remaining_or(budget));
                let request = hickory_proto::op::DnsRequest::new(message.clone(), options);
                use futures_util::StreamExt;
                let (result, observed) = crate::dns::proofwatch::watch(async {
                    tokio::time::timeout(slice, async {
                        let mut stream = validator.send(request);
                        stream.next().await
                    })
                    .await
                })
                .await;

                let (msg, outcome) = match result {
                    Err(_) => (None, ValidationOutcome::Timeout),
                    Ok(Some(Ok(response))) => {
                        let msg = response.into_message();
                        let outcome =
                            policy_dnssec::classify(&msg, &self.config.dnssec, false, observed);
                        (Some(msg), outcome)
                    }
                    Ok(Some(Err(e))) => {
                        // The validator gave up rather than returning a message. Its own
                        // report of *why* is the only signal here, and a transport
                        // failure it saw is still a transport failure.
                        let text = e.to_string();
                        let outcome = if observed != crate::dns::proofwatch::ProofFailure::None {
                            ValidationOutcome::IncompleteProof
                        } else if text.contains("Bogus") || text.contains("bogus") {
                            ValidationOutcome::Bogus
                        } else {
                            ValidationOutcome::TransportFailure
                        };
                        (None, outcome)
                    }
                    Ok(None) => (None, ValidationOutcome::TransportFailure),
                };

                // One retry, and only for failures that are about us. Retrying Bogus
                // would be shopping for a resolver willing to say something else about
                // forged data, which is the attack rather than the defence.
                //
                // The retry is worth making because the validator caches the chain
                // elements it did manage to fetch: a second pass starts warm and usually
                // finishes what the first ran out of time for.
                let deadline_left = validation_deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    > MIN_REVALIDATION_BUDGET;
                if attempt < 2 && outcome.is_retryable() && deadline_left {
                    metrics::counter!(
                        crate::metrics::names::DNSSEC_VALIDATION_FALLBACK_TOTAL,
                        "reason" => outcome.label(),
                    )
                    .increment(1);
                    continue;
                }
                break (msg, outcome);
            };
            drop(permit);

            metrics::counter!(
                crate::metrics::names::DNSSEC_OUTCOME_TOTAL,
                "outcome" => outcome.label(),
            )
            .increment(1);

            match outcome {
                // Validation completed and the data failed it. This is the one path that
                // fails closed, and it must stay that way.
                ValidationOutcome::Bogus => {
                    tracing::warn!(
                        event = "dnssec.bogus",
                        name = %key.name,
                        qtype = %key.qtype,
                    );
                    return Err(ResolveError::DnssecBogus);
                }
                ValidationOutcome::Secure | ValidationOutcome::ProvenInsecure => {
                    let msg = response.take().ok_or(ResolveError::AllFailed {
                        detail: "validator reported success without an answer".to_string(),
                    })?;
                    (msg, None, false)
                }
                // We could not check the answer. That is not a statement about the
                // answer, and refusing to serve on it would hand anyone able to slow this
                // network the power to erase names. Serve what we have with AD cleared
                // and a short TTL, and finish the proof in the background so the next
                // query for this name has a warm chain.
                ValidationOutcome::IncompleteProof
                | ValidationOutcome::TransportFailure
                | ValidationOutcome::Timeout
                | ValidationOutcome::Indeterminate => {
                    let msg = match response.take() {
                        Some(msg) => msg,
                        // The validator gave up without producing a message, which is the
                        // common shape: it returns an error rather than a partly-proved
                        // answer. The data is still out there and still fetchable, so the
                        // question is whether we are entitled to serve it unproved.
                        //
                        // Only when the failure was ours, and only with corroboration
                        // from a second independent authority. That is what keeps this
                        // from becoming a downgrade: an attacker who can stall our chain
                        // lookups still has to produce the same answer from two
                        // authorities we chose, rather than merely breaking one.
                        None => match self
                            .unproved_fallback(&group, &message, options, seed, outcome)
                            .await
                        {
                            Some(msg) => msg,
                            None => {
                                return Err(ResolveError::ProofIncomplete {
                                    outcome: outcome.label(),
                                })
                            }
                        },
                    };
                    if outcome != ValidationOutcome::Indeterminate {
                        self.note_incomplete_proof(key, outcome);
                        self.spawn_proof_completion(&key.view.group, message.clone(), options);
                    }
                    (msg, None, false)
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
            // Reachable in Strict mode, and in Background mode only when an upstream
            // handed us records it had already marked Bogus. Either way this is a verdict
            // about the data, and the one path that fails closed.
            return Err(ResolveError::DnssecBogus);
        }

        // Background mode: the client is about to be answered, and the proof follows.
        //
        // Whatever this returns will be cached as Provisional; the evidence plane
        // promotes it to Secure, leaves it as ProvenInsecure, or evicts and quarantines
        // it if it turns out to be Bogus. A variant that fails validation is therefore
        // served at most once.
        if matches!(self.config.dnssec.mode, DnssecMode::Background) && !key.mode.checking_disabled
        {
            self.spawn_background_validation(&key, message.clone(), options);
        }

        // A negative answer nobody signed is the classic forgery: it is how censorship,
        // captive portals and on-path injection make a name disappear, and unlike a
        // forged address it leaves no evidence in the answer itself. So before an
        // unsigned NXDOMAIN is trusted, a *different resolver authority* is asked. A
        // Secure or Insecure-with-proof answer needs none of this, and neither does a
        // positive one: this is the case where a second opinion is worth the query.
        let (response, route) = self
            .corroborate_negative(&group, &message, options, &response, status, route, seed)
            .await;

        let kind = classify(&response);
        let raw_ttl = match kind {
            EntryKind::Positive => msgutil::min_ttl(&response).unwrap_or(0),
            _ => negative_ttl(&response).unwrap_or(0),
        };
        let cap = match kind {
            EntryKind::Positive => self.cache.internal_max_ttl(),
            // Read live, like failure_min_ttl below: the cache is retained across
            // reloads, so a value captured into it would silently ignore a reload.
            _ => self.config.cache.negative_max_ttl,
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

    /// Ask a second authority before believing an unsigned negative answer.
    ///
    /// Returns the answer to use and the route that produced it. When the second
    /// authority agrees, or cannot be reached, or there is no independent one, the
    /// original answer is returned unchanged — corroboration can only ever *replace a
    /// negative with a positive*, never the reverse. That asymmetry is deliberate: an
    /// attacker who can forge one resolver's answer should not be able to use this path
    /// to erase a name, only to fail at hiding one.
    #[allow(clippy::too_many_arguments)]
    async fn corroborate_negative(
        &self,
        group: &Arc<crate::upstream::pool::UpstreamGroup>,
        message: &Message,
        options: DnsRequestOptions,
        response: &Message,
        status: DnssecStatus,
        route: Option<crate::upstream::pool::RouteKey>,
        seed: u64,
    ) -> (Message, Option<crate::upstream::pool::RouteKey>) {
        let original = (response.clone(), route.clone());

        if !self.config.dnssec.corroborate_negative {
            return original;
        }
        // Only unsigned negatives. A signed answer already proves itself, and a positive
        // answer is not the shape this defends against.
        if response.metadata.response_code != ResponseCode::NXDomain
            || status == DnssecStatus::Secure
        {
            return original;
        }
        let Some(first) = route.as_ref() else {
            return original;
        };

        // Whatever is left of the client's deadline, and never more than a small slice of
        // it: the client is owed an answer, not a debate.
        let remaining = crate::dns::deadline::remaining_or(self.config.server.foreground_budget);
        let slice = remaining.mul_f64(0.5);
        if slice.is_zero() {
            return original;
        }

        let Some(second) = self
            .scheduler
            .corroborate(
                group,
                message.clone(),
                options,
                slice,
                seed ^ 0x9E37_79B9,
                &first.authority,
            )
            .await
        else {
            // No independent authority, or it did not answer. The original stands: an
            // absent second opinion is not evidence either way.
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "unavailable",
            )
            .increment(1);
            return original;
        };

        if second.message.metadata.response_code == ResponseCode::NXDomain {
            // Two independent resolvers agree the name does not exist.
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "agreed",
            )
            .increment(1);
            return original;
        }

        if second.message.metadata.response_code == ResponseCode::NoError
            && !second.message.answers.is_empty()
        {
            // One resolver says the name is gone and an independent one returns records
            // for it. The positive answer is the one that cannot be fabricated by
            // deletion, so it wins, and the disagreement is recorded.
            metrics::counter!(
                crate::metrics::names::CORROBORATION_TOTAL,
                "outcome" => "negative_conflict",
            )
            .increment(1);
            tracing::info!(
                event = "corroboration.negative_conflict",
                first = %first.authority,
                second = %second.route.authority,
                "an unsigned NXDOMAIN was contradicted by an independent resolver",
            );
            return (second.message, Some(second.route));
        }

        metrics::counter!(
            crate::metrics::names::CORROBORATION_TOTAL,
            "outcome" => "inconclusive",
        )
        .increment(1);
        original
    }

    /// Offer addresses from a fresh answer to the probe engine.
    ///
    /// This is a non-blocking hand-off. If the queue is full the observation is simply
    /// dropped: probes are optional evidence and must never slow down resolution.
    fn schedule_probes(&self, key: &CacheKey, entry: &CacheEntry) {
        // Read from the configuration published by this runtime-state generation rather
        // than from the queue's own toggle, which a reload updates separately: one query
        // must observe one coherent policy. `offer` still gates on the queue itself.
        if !self.config.probe.enabled || entry.kind != EntryKind::Positive {
            return;
        }
        // An HTTPS or SVCB answer is the protocol saying "this name is a service": note
        // it, so the A and AAAA answers for the same name become rankable.
        if crate::ranking::service::is_service_binding(key.qtype)
            && !entry.message.answers.is_empty()
        {
            self.services.note_https(&key.name);
        }
        if !matches!(key.qtype, RecordType::A | RecordType::AAAA) {
            return;
        }
        // Port 443 is probed only where there is protocol evidence that something is
        // listening on it. Otherwise the measurement is noise and the connection is
        // unsolicited.
        if !self.services.is_web_service(&key.name) {
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
        // Same rule on the read side: an answer with no service evidence is passed
        // through in the order the authority gave it, because port-443 measurements say
        // nothing about a name that is not an HTTPS service.
        let is_web = self.services.is_web_service(&qname);
        let quality = if is_web {
            self.quality.snapshot_for(&addresses, 443, &qname)
        } else {
            Default::default()
        };
        let snapshot = self.cloudflare.prefixes();
        let now_unix = crate::util::time::SystemClock.unix_secs_now();
        // One coherent policy generation for this answer: `enabled` and the configured
        // mode come from the `Config` this runtime state published, and only the live
        // operational override is read from the shared Cloudflare state.
        let cloudflare_enabled = self.config.cloudflare.enabled;
        let cloudflare_mode = self.cloudflare.effective_mode(self.config.cloudflare.mode);
        let verified = if cloudflare_enabled && cloudflare_mode == CloudflareMode::VerifiedAugment {
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
            cloudflare_enabled,
            cloudflare_mode,
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
