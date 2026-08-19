//! Reliability-aware adaptive upstream scheduling.
//!
//! The scheduler sends a query to the best healthy route, starts at most one hedge after a
//! delay derived from that route's own latency distribution, and returns the first
//! complete, acceptable, standards-valid answer. Broader fan-out happens only through an
//! explicit, bounded emergency policy.
//!
//! Everything here is on the foreground path, so it performs no disk I/O, no database
//! access and no probing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use futures_util::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{DnsRequestOptions, Message, ResponseCode};
use tokio::time::Instant;

use crate::dns::message as msgutil;
use crate::error::ResolveError;
use crate::network::{FamilyState, SharedNetworkState};
use crate::upstream::health::AttemptOutcome;
use crate::upstream::pool::{Route, RouteKey, UpstreamGroup, UpstreamRegistry};

/// A successful upstream exchange.
#[derive(Debug)]
pub struct UpstreamAnswer {
    /// The complete response message.
    pub message: Message,
    /// The route that produced it.
    pub route: RouteKey,
    /// Measured latency.
    pub latency: Duration,
    /// Whether a truncated UDP answer had to be retried over a stream transport.
    pub stream_retry: bool,
    /// Whether this server's AD bit may be trusted under the configured policy.
    pub trust_ad: bool,
}

/// Per-group counters used to bound hedging.
#[derive(Debug, Default)]
pub struct HedgeBudget {
    queries: AtomicU64,
    hedges: AtomicU64,
}

impl HedgeBudget {
    /// Record a foreground query.
    pub fn record_query(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether another hedge is permitted under the configured fraction.
    pub fn allows(&self, fraction: f64) -> bool {
        if fraction <= 0.0 {
            return false;
        }
        if fraction >= 1.0 {
            return true;
        }
        let q = self.queries.load(Ordering::Relaxed).max(1) as f64;
        let h = self.hedges.load(Ordering::Relaxed) as f64;
        h / q < fraction
    }

    /// Record that a hedge actually fired.
    pub fn record_hedge(&self) {
        self.hedges.fetch_add(1, Ordering::Relaxed);
    }

    /// Current hedge rate.
    pub fn rate(&self) -> f64 {
        let q = self.queries.load(Ordering::Relaxed).max(1) as f64;
        self.hedges.load(Ordering::Relaxed) as f64 / q
    }
}

/// The adaptive scheduler.
pub struct Scheduler {
    registry: Arc<UpstreamRegistry>,
    network: SharedNetworkState,
    budgets: parking_lot::Mutex<std::collections::HashMap<Arc<str>, Arc<HedgeBudget>>>,
    /// Global ceiling on concurrent upstream exchanges. Shared with every other scheduler
    /// generation so a configuration reload cannot transiently double the ceiling.
    slots: Arc<Semaphore>,
    capacity: usize,
    /// How long after a network generation change exploration stays elevated.
    relearn_window: Duration,
}

/// How much exploration is multiplied by during accelerated relearning.
const RELEARN_EXPLORE_MULTIPLIER: f64 = 5.0;

/// Ceiling on the boosted exploration rate. Exploration costs tail latency, so even a
/// completely changed network must not turn a fifth of queries into experiments.
const MAX_EXPLORE_RATE: f64 = 0.20;

/// A reserved half-open probe slot, released on drop.
///
/// Without this, an attempt cancelled because a hedge won the race or the foreground
/// budget expired leaks its reservation. `is_usable` requires the half-open count to be
/// zero, so a single leaked slot removes the route from ranking permanently: a recovering
/// upstream would never be allowed to recover.
struct HalfOpenSlot {
    route: Option<Arc<Route>>,
}

impl HalfOpenSlot {
    fn reserve(route: &Arc<Route>) -> Self {
        let taken = route.with_health(|h| h.begin_attempt());
        Self {
            route: taken.then(|| Arc::clone(route)),
        }
    }
}

impl Drop for HalfOpenSlot {
    fn drop(&mut self) {
        if let Some(route) = self.route.take() {
            route.with_health(|h| h.release_attempt());
        }
    }
}

/// Time left before the absolute foreground deadline.
///
/// Every nested operation derives its own timeout from this rather than inheriting a copy
/// of the original budget, so a chain of operations cannot outlive the deadline by
/// repeating it.
fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// How long a cancelled-but-sent exchange keeps its accounting slot.
///
/// Long enough to cover a plausible round trip for a datagram that is genuinely still on
/// the wire, short enough that a losing hedge cannot throttle admission of new work. Also
/// clamped by the attempt's own terminal instant, so it never outlives the timeout that
/// was already charged against the foreground deadline.
const CANCELLED_EXCHANGE_GRACE: Duration = Duration::from_millis(100);

/// Retains a physical-exchange permit until the exchange is terminal.
///
/// A datagram that has been sent stays on the wire whether or not the local future that
/// sent it is still being awaited. Releasing the permit the moment a losing hedge is
/// dropped would let the number of exchanges actually in flight exceed the configured
/// ceiling — the ceiling would bound *waiters*, not *exchanges*, which is not what it
/// claims to bound. So a cancelled-but-sent exchange keeps its slot until the point at
/// which it could no longer produce a response.
///
/// Only a cancelled exchange pays for this: one that completes locally releases its slot
/// inline, which is the overwhelmingly common case and stays free of any spawn.
///
/// The retention window is [`CANCELLED_EXCHANGE_GRACE`], not the attempt's whole
/// remaining timeout. Holding the slot for the full timeout was measured to be
/// catastrophic: on the load harness it took the truncation scenario from 15,285 queries
/// per second at 100% success to 1,187 at **0%**, and the miss-heavy scenario from 100%
/// to 85%. A losing hedge would hold a slot for up to `query_timeout` after its
/// resolution had already answered the client, so completed past work throttled admission
/// of new work until the pool was exhausted.
///
/// A short window is also the more honest model. Once the future is dropped the socket is
/// closed and the kernel discards anything that arrives, so the only interval in which the
/// exchange is meaningfully "on the wire" is about one round trip — not one timeout. The
/// grace keeps the ceiling counting exchanges rather than waiters without letting it count
/// exchanges that are over.
struct ExchangeGuard {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// The instant after which this exchange can no longer produce a response.
    terminal: Instant,
    completed: bool,
}

impl ExchangeGuard {
    fn new(permit: tokio::sync::OwnedSemaphorePermit, terminal: Instant) -> Self {
        Self {
            permit: Some(permit),
            terminal,
            completed: false,
        }
    }

    /// The exchange reached a terminal state locally, so the slot is free immediately.
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if self.completed {
            return;
        }
        let wait = self
            .terminal
            .saturating_duration_since(Instant::now())
            .min(CANCELLED_EXCHANGE_GRACE);
        if wait.is_zero() {
            return;
        }
        // Held, not leaked: the sleep is bounded by the send timeout that was already
        // charged against the foreground deadline. Outside a runtime there is nothing to
        // wait on and nothing in flight, so the slot is simply returned.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                tokio::time::sleep(wait).await;
                drop(permit);
            });
        }
    }
}

/// Outcome of a single attempt, used internally.
struct AttemptResult {
    route: Arc<Route>,
    /// `None` when the attempt was shed at the global exchange ceiling before a single
    /// packet was sent. A shed attempt carries no evidence about the route, so callers
    /// must skip health recording and outcome metrics for it.
    outcome: Option<AttemptOutcome>,
    latency: Option<Duration>,
    message: Option<Message>,
    detail: String,
}

impl AttemptResult {
    /// An attempt that never reached the route because no exchange permit was available.
    fn shed(route: Arc<Route>) -> Self {
        Self {
            route,
            outcome: None,
            latency: None,
            message: None,
            detail: String::from("shed at the upstream concurrency ceiling"),
        }
    }
}

/// How an attempt acquires its global upstream-exchange permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermitPolicy {
    /// Bounded wait: the primary attempt and a truncation retry may queue for a permit,
    /// but only within their own timeout — an overloaded resolver must shed load, not
    /// queue forever.
    Queue,
    /// No wait: a hedge or an emergency fan-out attempt that cannot start immediately
    /// has already failed its purpose, so it is shed rather than queued.
    Shed,
}

impl Scheduler {
    /// Create a scheduler.
    pub fn new(
        registry: Arc<UpstreamRegistry>,
        network: SharedNetworkState,
        slots: Arc<Semaphore>,
        relearn_window: Duration,
    ) -> Self {
        Self {
            capacity: slots.available_permits(),
            slots,
            relearn_window,
            registry,
            network,
            budgets: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The hedge budget for a group.
    pub fn budget(&self, group: &str) -> Arc<HedgeBudget> {
        let mut map = self.budgets.lock();
        map.entry(Arc::from(group))
            .or_insert_with(|| Arc::new(HedgeBudget::default()))
            .clone()
    }

    /// Physical upstream exchanges currently in flight, derived from the same semaphore
    /// every attempt acquires against.
    pub fn inflight(&self) -> usize {
        self.capacity.saturating_sub(self.slots.available_permits())
    }

    /// The configured upstream concurrency ceiling.
    pub fn upstream_capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the egress path changed recently enough to justify extra exploration.
    fn in_relearn_window(&self) -> bool {
        if self.relearn_window.is_zero() {
            return false;
        }
        self.network.in_relearn_window(
            crate::util::time::SystemClock.unix_secs_now(),
            self.relearn_window.as_secs(),
        )
    }

    /// Upstream routes.
    pub fn registry(&self) -> &Arc<UpstreamRegistry> {
        &self.registry
    }

    /// Rank the usable routes of a group, best first.
    pub fn rank(&self, group: &UpstreamGroup, seed: u64) -> Vec<Arc<Route>> {
        self.rank_inner(group, seed, false)
    }

    /// Rank routes, optionally including the TCP companions of UDP servers.
    ///
    /// Companions exist only so that a truncated UDP answer can be retried over a stream
    /// transport, per RFC 1035 §4.2.1 and RFC 7766 §5. Including them in ordinary ranking
    /// would quietly move traffic to TCP that the operator asked to send over UDP.
    fn rank_inner(
        &self,
        group: &UpstreamGroup,
        seed: u64,
        include_companions: bool,
    ) -> Vec<Arc<Route>> {
        let net = self.network.load();
        let now = Instant::now();
        /// One candidate mid-ranking.
        struct Candidate {
            score: f64,
            idx: usize,
            route: Arc<Route>,
            /// Whether `score` is real evidence or the absolute cold-start prior.
            measured: bool,
            /// Which bucket the route belongs to.
            bucket: Bucket,
        }
        #[derive(PartialEq)]
        enum Bucket {
            /// Usable family, healthy circuit.
            Ready,
            /// Usable family, open circuit.
            Degraded,
            /// Family reads as unusable.
            FamilyExcluded,
        }

        let mut candidates: Vec<Candidate> = Vec::with_capacity(group.routes.len());
        for (idx, route) in group.routes.iter().enumerate() {
            if route.stream_companion && !include_companions {
                continue;
            }
            // A family with no usable path is set aside; an undetermined family is still
            // tried, because absence of measurement is not evidence of failure.
            let family_ok = match route.key.addr {
                std::net::IpAddr::V4(_) => net.v4 != FamilyState::Unusable,
                std::net::IpAddr::V6(_) => net.v6 != FamilyState::Unusable,
            };
            let (usable, score, measured) = route.with_health(|h| {
                h.tick(now, &group.scheduler, seed ^ (idx as u64));
                (h.is_usable(), h.score(route.weight), h.is_measured())
            });
            let bucket = if !family_ok {
                Bucket::FamilyExcluded
            } else if usable {
                Bucket::Ready
            } else {
                Bucket::Degraded
            };
            candidates.push(Candidate {
                score,
                idx,
                route: Arc::clone(route),
                measured,
                bucket,
            });
        }

        // Re-price the routes that have no measurements.
        //
        // `score` has to return *something* for a route nobody has used, and any absolute
        // number is a claim about the network. Pick it too low and every unmeasured route
        // outranks every proven one — permanently, because the moment a route is measured
        // it acquires a real latency and drops back behind the untried ones. On a network
        // whose real round trip exceeds the prior, that is a scheduler that never
        // converges: it cycles through its whole route list forever, preferring whichever
        // routes it knows least about, and a configuration listing several unreachable
        // endpoints then fails to resolve anything at all. It is invisible on loopback,
        // where the real round trip is far below any sane prior, and unmissable at 250ms.
        //
        // So the prior is taken from evidence instead: an unmeasured route is priced at
        // the median of the routes that *have* been measured. "Unknown" then means
        // "typical" — better than the worst proven route, worse than the best, and still
        // reached by ordinary exploration. Absence of evidence stays neutral without
        // becoming an advantage. With nothing measured at all, every route keeps its
        // absolute prior and they tie, which is the right answer for a cold start.
        let mut measured_scores: Vec<f64> = candidates
            .iter()
            .filter(|c| c.measured)
            .map(|c| c.score)
            .collect();
        if !measured_scores.is_empty() {
            measured_scores.sort_by(|a, b| a.total_cmp(b));
            let median = measured_scores[measured_scores.len() / 2];
            for c in candidates.iter_mut().filter(|c| !c.measured) {
                // The weight bias is re-applied on top of the neutral prior so that an
                // operator's preference still orders routes nobody has measured.
                c.score =
                    median + crate::upstream::health::RouteHealth::weight_bias(c.route.weight);
            }
        }

        let mut scored: Vec<(f64, usize, Arc<Route>)> = Vec::new();
        let mut fallback: Vec<(f64, usize, Arc<Route>)> = Vec::new();
        let mut family_excluded: Vec<(f64, usize, Arc<Route>)> = Vec::new();
        for c in candidates {
            let entry = (c.score, c.idx, c.route);
            match c.bucket {
                Bucket::Ready => scored.push(entry),
                Bucket::Degraded => fallback.push(entry),
                Bucket::FamilyExcluded => family_excluded.push(entry),
            }
        }

        // A circuit breaker exists to move traffic somewhere better. When there is nowhere
        // better — every route in the group is open — refusing to send anything converts a
        // partially working upstream into a total outage: an upstream failing half its
        // queries would answer half of ours, but an empty route list answers none of them.
        // So when nothing is usable, every route is offered anyway, worst-scored last.
        // Availability outranks the breaker's own policy; the breaker still shapes the
        // *order*, and still protects a route the moment any alternative recovers.
        if scored.is_empty() && !fallback.is_empty() {
            metrics::counter!(crate::metrics::names::UPSTREAM_LAST_RESORT_TOTAL).increment(1);
            scored = fallback;
        }

        // The same argument, one level up. Address-family usability is *derived from the
        // host routing table*, so it reports on our ability to measure the network as
        // much as on the network itself: a sandbox that hides `/proc/net`, an unfamiliar
        // container, a platform whose route file moved, and every family reads
        // `Unusable` on a host whose networking is perfectly healthy. Filtering those
        // routes out then leaves nothing to rank and turns a detection failure into a
        // total outage — every query SERVFAILs while the daemon still reports ready.
        //
        // So when no family reads as usable, the filter has told us nothing we can act
        // on, and every route is offered rather than none. A genuine single-family
        // outage is unaffected: the working family still populates `scored`, and the
        // dead one is still skipped.
        if scored.is_empty() && !family_excluded.is_empty() {
            metrics::counter!(crate::metrics::names::UPSTREAM_FAMILY_FALLBACK_TOTAL).increment(1);
            scored = family_excluded;
        }
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut ranked: Vec<Arc<Route>> = scored.into_iter().map(|(_, _, r)| r).collect();
        // Low-rate exploration: occasionally promote the second-best route so that a
        // recovered upstream can regain rank without waiting for a circuit transition.
        // Immediately after a network generation change the accumulated evidence describes
        // a path that no longer exists, so exploration is boosted for `relearn_window`.
        // This is what "accelerated relearning" means in practice: without it the resolver
        // keeps preferring whichever route was best on the *previous* network until enough
        // ordinary traffic has re-measured everything.
        let explore_rate = if self.in_relearn_window() {
            (group.scheduler.explore_rate * RELEARN_EXPLORE_MULTIPLIER).min(MAX_EXPLORE_RATE)
        } else {
            group.scheduler.explore_rate
        };
        if ranked.len() > 1
            && explore_rate > 0.0
            && crate::ranking::unit_from_seed(seed) < explore_rate
        {
            ranked.swap(0, 1);
        }
        ranked
    }

    /// Resolve one query through a group.
    pub async fn resolve(
        &self,
        group: &UpstreamGroup,
        message: Message,
        options: DnsRequestOptions,
        budget: Duration,
        seed: u64,
    ) -> Result<UpstreamAnswer, ResolveError> {
        let start = Instant::now();

        // The global ceiling on upstream exchanges is enforced per physical attempt in
        // `attempt`, not here: one resolution can run a primary, a hedge and an
        // emergency fan-out at the same time, so a per-resolution permit would let the
        // real fan-out reach a multiple of the configured ceiling — and a resolution
        // holding a permit while its own attempts queue for another could starve the
        // truncation retry it is waiting on.

        let hedge_budget = self.budget(&group.name);
        hedge_budget.record_query();

        let ranked = self.rank(group, seed);
        if ranked.is_empty() {
            return Err(ResolveError::NoRoute {
                group: group.name.to_string(),
            });
        }

        let cfg = &group.scheduler;
        // One absolute deadline for the whole resolution. Every nested operation — permit
        // wait, connect, send, hedge delay, truncation retry — measures itself against
        // this instant instead of receiving a fresh copy of `budget`.
        let deadline = start + budget;
        let mut last_detail = String::from("no attempt completed");

        // Which ranked routes have actually been started. Positional accounting was wrong
        // here: it assumed the top two routes had been attempted whether or not the hedge
        // was ever admitted, so a disabled or budget-denied hedge silently consumed the
        // second route's eligibility and the emergency fallback skipped straight past the
        // one route that could still answer.
        let mut attempted = vec![false; ranked.len()];

        let mut pending: FuturesUnordered<_> = FuturesUnordered::new();
        attempted[0] = true;
        pending.push(self.attempt(
            Arc::clone(&ranked[0]),
            message.clone(),
            options,
            deadline,
            cfg.query_timeout,
            Duration::ZERO,
            None,
            PermitPolicy::Queue,
        ));

        if cfg.hedge_enabled && ranked.len() > 1 && hedge_budget.allows(cfg.hedge_max_fraction) {
            let delay = ranked[0].with_health(|h| h.hedge_delay(cfg));
            if delay < budget {
                // Marked only here, where the attempt future is actually admitted.
                attempted[1] = true;
                pending.push(self.attempt(
                    Arc::clone(&ranked[1]),
                    message.clone(),
                    options,
                    deadline,
                    cfg.query_timeout,
                    delay,
                    Some(Arc::clone(&hedge_budget)),
                    PermitPolicy::Shed,
                ));
            }
        }

        let mut fanned_out = false;
        // Whether any attempt actually reached an upstream. A resolution in which every
        // attempt was shed at the ceiling is overload, not upstream failure, and must be
        // reported as such.
        let mut any_exchange = false;

        loop {
            let left = remaining(deadline);
            if left.is_zero() {
                return Err(ResolveError::Timeout {
                    elapsed_ms: start.elapsed().as_millis() as u64,
                });
            }
            let next = match tokio::time::timeout(left, pending.next()).await {
                Err(_) => {
                    return Err(ResolveError::Timeout {
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    })
                }
                Ok(None) => None,
                Ok(Some(result)) => Some(result),
            };

            match next {
                Some(result) => {
                    // An attempt shed at the exchange ceiling never reached the route:
                    // recording it would let a local saturation event flap circuit
                    // breakers, and the outcome metrics would blame a server for load
                    // the resolver generated itself.
                    let Some(outcome) = result.outcome else {
                        if Arc::ptr_eq(&result.route, &ranked[0]) {
                            // A primary that never started is either overload or an
                            // expired deadline, and the two are different failures: only
                            // the first says anything about capacity.
                            if remaining(deadline).is_zero() {
                                return Err(ResolveError::Timeout {
                                    elapsed_ms: start.elapsed().as_millis() as u64,
                                });
                            }
                            // The primary could not start inside its own timeout, so the
                            // resolver is overloaded. Report it exactly as the old
                            // resolve-entry shed did: SERVFAIL plus the shed counter.
                            metrics::counter!(crate::metrics::names::UPSTREAM_SHED_TOTAL)
                                .increment(1);
                            return Err(ResolveError::Overloaded {
                                limit: self.capacity,
                            });
                        }
                        last_detail = result.detail;
                        continue;
                    };
                    any_exchange = true;
                    let now = Instant::now();
                    result
                        .route
                        .with_health(|h| h.record(outcome, result.latency, now, cfg));
                    metrics::counter!(
                        crate::metrics::names::UPSTREAM_QUERIES_TOTAL,
                        "server" => result.route.key.server.to_string(),
                        "transport" => result.route.key.transport.label(),
                        "outcome" => outcome.label(),
                    )
                    .increment(1);
                    if let Some(latency) = result.latency {
                        metrics::histogram!(
                            crate::metrics::names::UPSTREAM_SECONDS,
                            "server" => result.route.key.server.to_string(),
                            "transport" => result.route.key.transport.label(),
                        )
                        .record(latency.as_secs_f64());
                    }
                    if outcome == AttemptOutcome::Success {
                        if let Some(msg) = result.message {
                            let latency = result.latency.unwrap_or_default();
                            // Truncated UDP answers must be retried over a stream
                            // transport before they can be treated as complete.
                            if msg.metadata.truncation && !result.route.key.transport.is_stream() {
                                return match self
                                    .stream_retry(group, &message, options, deadline, seed)
                                    .await
                                {
                                    Some(answer) => Ok(answer),
                                    // A truncated UDP answer must never be used: its
                                    // answer section is incomplete by definition, and
                                    // returning it would hand the client a partial RRset
                                    // presented as complete. If no stream transport could
                                    // supply the full answer, this is a failure.
                                    None => Err(ResolveError::InvalidResponse {
                                        reason: "truncated UDP answer could not be \
                                                 retried over a stream transport",
                                    }),
                                };
                            }
                            return Ok(UpstreamAnswer {
                                message: msg,
                                route: result.route.key.clone(),
                                latency,
                                stream_retry: false,
                                trust_ad: result.route.trust_ad,
                            });
                        }
                    }
                    last_detail = result.detail;
                }
                None => {
                    // Every started attempt has finished without an acceptable answer.
                    // Fall back over the routes that were never started, in rank order —
                    // membership, not position, decides what is still eligible.
                    if cfg.emergency_fanout && !fanned_out {
                        fanned_out = true;
                        let mut extra = 0;
                        for idx in 0..ranked.len() {
                            if extra >= cfg.emergency_fanout_max {
                                break;
                            }
                            if attempted[idx] {
                                continue;
                            }
                            attempted[idx] = true;
                            pending.push(self.attempt(
                                Arc::clone(&ranked[idx]),
                                message.clone(),
                                options,
                                deadline,
                                cfg.query_timeout,
                                Duration::ZERO,
                                None,
                                PermitPolicy::Shed,
                            ));
                            metrics::counter!(crate::metrics::names::UPSTREAM_DUPLICATES_TOTAL)
                                .increment(1);
                            extra += 1;
                        }
                        if extra > 0 {
                            continue;
                        }
                    }
                    if !any_exchange {
                        // Every attempt was shed before reaching an upstream: overload,
                        // not upstream failure, so report it exactly as the old
                        // resolve-entry shed did.
                        metrics::counter!(crate::metrics::names::UPSTREAM_SHED_TOTAL).increment(1);
                        return Err(ResolveError::Overloaded {
                            limit: self.capacity,
                        });
                    }
                    return Err(ResolveError::AllFailed {
                        detail: crate::util::bounded(&last_detail, 160),
                    });
                }
            }
        }
    }

    /// Retry a truncated answer over a stream transport.
    async fn stream_retry(
        &self,
        group: &UpstreamGroup,
        message: &Message,
        options: DnsRequestOptions,
        deadline: Instant,
        seed: u64,
    ) -> Option<UpstreamAnswer> {
        if remaining(deadline).is_zero() {
            return None;
        }
        metrics::counter!(crate::metrics::names::UPSTREAM_TCP_RETRY_TOTAL).increment(1);
        // Companions are eligible here and nowhere else: this is the retry RFC 7766 asks
        // for, and it must work for a UDP-only configuration without the operator having
        // to declare a second server entry for the same address.
        let ranked = self.rank_inner(group, seed, true);
        let stream_routes: Vec<Arc<Route>> = ranked
            .into_iter()
            .filter(|r| r.key.transport.is_stream())
            .collect();
        // Each candidate is charged against the same absolute deadline. Handing every
        // candidate its own copy of the remaining budget is what let two hanging stream
        // routes take twice the whole foreground budget.
        for route in stream_routes.into_iter().take(2) {
            if remaining(deadline).is_zero() {
                break;
            }
            let result = self
                .attempt(
                    Arc::clone(&route),
                    message.clone(),
                    options,
                    deadline,
                    group.scheduler.query_timeout,
                    Duration::ZERO,
                    None,
                    PermitPolicy::Queue,
                )
                .await;
            // A shed retry never reached the route, so it must not move the route's
            // health: local overload is not evidence of failure.
            let Some(outcome) = result.outcome else {
                continue;
            };
            let now = Instant::now();
            result
                .route
                .with_health(|h| h.record(outcome, result.latency, now, &group.scheduler));
            if outcome == AttemptOutcome::Success {
                if let Some(msg) = result.message {
                    return Some(UpstreamAnswer {
                        message: msg,
                        route: result.route.key.clone(),
                        latency: result.latency.unwrap_or_default(),
                        stream_retry: true,
                        trust_ad: result.route.trust_ad,
                    });
                }
            }
        }
        None
    }

    /// One attempt against one route, optionally after a delay.
    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        route: Arc<Route>,
        message: Message,
        options: DnsRequestOptions,
        deadline: Instant,
        attempt_cap: Duration,
        delay: Duration,
        hedge_budget: Option<Arc<HedgeBudget>>,
        policy: PermitPolicy,
    ) -> AttemptResult {
        // A queued hedge must not hold an exchange permit while it sleeps: the delay
        // exists to give the primary a head start, and holding a global slot through it
        // would subtract that capacity from real exchanges.
        if !delay.is_zero() {
            // Sleeping past the deadline could only produce an answer nobody is waiting
            // for, at the cost of a real exchange slot.
            if delay >= remaining(deadline) {
                return AttemptResult::shed(route);
            }
            tokio::time::sleep(delay).await;
        }

        // Every physical exchange — primary, hedge, emergency fan-out and truncation
        // retry alike — funnels through here, so this is where the global ceiling binds:
        // the permit brackets connect plus send, bounding exchanges on the wire rather
        // than resolutions. Waiting is bounded by the attempt's own timeout, which
        // never exceeds the caller's remaining budget; attempts whose value depends on
        // starting immediately do not wait at all. A shed attempt reports no outcome,
        // because it carries no evidence about the route. The permit is held across the
        // send await, so a dropped attempt future — a losing hedge, a budget expiry —
        // releases it: cancellation cannot leak a slot.
        // Derived from the absolute deadline, never inherited: the permit wait and the
        // exchange it protects share one budget rather than each receiving a full copy.
        let wait_budget = attempt_cap.min(remaining(deadline));
        if wait_budget.is_zero() {
            return AttemptResult::shed(route);
        }
        let permit = match policy {
            PermitPolicy::Queue => {
                match tokio::time::timeout(wait_budget, Arc::clone(&self.slots).acquire_owned())
                    .await
                {
                    Ok(Ok(permit)) => permit,
                    _ => return AttemptResult::shed(route),
                }
            }
            PermitPolicy::Shed => match Arc::clone(&self.slots).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => return AttemptResult::shed(route),
            },
        };

        // Recomputed after the wait, which may have consumed most of the budget.
        let send_timeout = attempt_cap.min(remaining(deadline));
        if send_timeout.is_zero() {
            return AttemptResult::shed(route);
        }

        if let Some(budget) = hedge_budget {
            budget.record_hedge();
            metrics::counter!(
                crate::metrics::names::UPSTREAM_HEDGES_TOTAL,
                "server" => route.key.server.to_string(),
                "transport" => route.key.transport.label(),
            )
            .increment(1);
            metrics::counter!(crate::metrics::names::UPSTREAM_DUPLICATES_TOTAL).increment(1);
        }

        // RAII: an attempt that is dropped mid-flight — a losing hedge, or a budget
        // expiry — must give back the half-open slot it reserved.
        let _slot = HalfOpenSlot::reserve(&route);

        let mut outgoing = message.clone();
        let cookie = route.cookie();
        if route.cookies_enabled {
            if let Some(edns) = outgoing.edns.as_mut() {
                let option = match &cookie.server {
                    Some(server) if !server.is_empty() => {
                        msgutil::encode_full_cookie(cookie.client, server)
                    }
                    _ => msgutil::encode_client_cookie(cookie.client),
                };
                edns.options_mut().insert(option);
            }
        }

        // From here the exchange may reach the wire, so its accounting slot is owned by a
        // guard that survives cancellation of this future rather than by the future's own
        // stack frame.
        let mut exchange = ExchangeGuard::new(permit, Instant::now() + send_timeout);

        let sent = outgoing.clone();
        let sent_result = route
            .send(
                self.registry.provider(),
                self.registry.context(),
                outgoing,
                options,
                send_timeout,
            )
            .await;
        // Terminal locally: response, transport error or timeout. The slot is free now.
        exchange.complete();
        match sent_result {
            Err((outcome, detail)) => AttemptResult {
                route,
                outcome: Some(outcome),
                latency: None,
                message: None,
                detail,
            },
            Ok((response, latency)) => {
                let msg = response.into_message();
                match validate_response(&sent, &msg, &route, cookie.client) {
                    Ok(()) => {
                        if route.cookies_enabled {
                            let server = msgutil::extract_server_cookie(&msg, cookie.client);
                            if server.is_some() {
                                route.set_server_cookie(server);
                            }
                        }
                        AttemptResult {
                            route,
                            outcome: Some(AttemptOutcome::Success),
                            latency: Some(latency),
                            message: Some(msg),
                            detail: String::new(),
                        }
                    }
                    Err((outcome, detail)) => AttemptResult {
                        route,
                        outcome: Some(outcome),
                        latency: Some(latency),
                        message: None,
                        detail,
                    },
                }
            }
        }
    }
}

/// Validate a response against RFC 5452 and basic protocol rules.
fn validate_response(
    request: &Message,
    response: &Message,
    route: &Route,
    client_cookie: [u8; 8],
) -> Result<(), (AttemptOutcome, String)> {
    if !msgutil::question_matches(request, response) {
        return Err((
            AttemptOutcome::Malformed,
            "response question did not match the query".to_string(),
        ));
    }
    if response.metadata.message_type != hickory_proto::op::MessageType::Response {
        return Err((
            AttemptOutcome::Malformed,
            "response was not a reply".to_string(),
        ));
    }
    if response.metadata.op_code != request.metadata.op_code {
        return Err((
            AttemptOutcome::Malformed,
            "response opcode did not match".to_string(),
        ));
    }
    // A server that supports cookies must echo the client cookie. RFC 7873 section 5.3.
    if route.cookies_enabled && response.edns.is_some() {
        let has_cookie = response
            .edns
            .as_ref()
            .and_then(|e| {
                e.options()
                    .get(hickory_proto::rr::rdata::opt::EdnsCode::from(
                        msgutil::COOKIE_OPTION_CODE,
                    ))
            })
            .is_some();
        if has_cookie && msgutil::extract_server_cookie(response, client_cookie).is_none() {
            return Err((
                AttemptOutcome::Malformed,
                "DNS cookie in response did not echo the client cookie".to_string(),
            ));
        }
    }
    match response.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(()),
        ResponseCode::ServFail | ResponseCode::Refused => Err((
            AttemptOutcome::ServerFailure,
            format!("upstream returned {}", response.metadata.response_code),
        )),
        ResponseCode::BADVERS => Err((
            AttemptOutcome::ServerFailure,
            "upstream rejected the EDNS version".to_string(),
        )),
        other => Err((
            AttemptOutcome::ServerFailure,
            format!("upstream returned {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        SchedulerConfig, TransportKind, UpstreamConfig, UpstreamGroupConfig, UpstreamServerConfig,
        UpstreamTlsConfig,
    };

    fn test_group(count: usize) -> (Arc<UpstreamRegistry>, Arc<UpstreamGroup>) {
        crate::tls::install_crypto_provider();
        let servers: Vec<UpstreamServerConfig> = (0..count)
            .map(|i| UpstreamServerConfig {
                name: format!("s{i}"),
                transport: TransportKind::Udp,
                addresses: vec![format!("9.9.9.{}", i + 1).parse().expect("ip")],
                ..UpstreamServerConfig::default()
            })
            .collect();
        let cfg = UpstreamConfig {
            default_group: "default".into(),
            groups: vec![UpstreamGroupConfig {
                name: "default".into(),
                servers,
                scheduler: SchedulerConfig {
                    // Exploration is deliberately off: this asserts the ordering the
                    // score produces, not the exploration that perturbs it.
                    explore_rate: 0.0,
                    ..SchedulerConfig::default()
                },
            }],
            tls: UpstreamTlsConfig::default(),
        };
        let roots = Arc::new(crate::tls::root_store(false, &[]).expect("roots"));
        let registry = Arc::new(
            UpstreamRegistry::build(&cfg, roots, Duration::from_secs(2), 1232).expect("registry"),
        );
        let group = registry.default_group().expect("group");
        (registry, group)
    }

    fn scheduler(registry: Arc<UpstreamRegistry>) -> Scheduler {
        Scheduler::new(
            registry,
            Arc::new(crate::network::NetworkState::new()),
            Arc::new(Semaphore::new(64)),
            Duration::ZERO,
        )
    }

    /// A route that has been measured and works must not be displaced by routes nobody
    /// has tried.
    ///
    /// This is the shape of a real failure: on a network whose round trip is 250ms, the
    /// absolute cold-start prior scored *better* than any measured route, so the winner
    /// of every query was whichever route had the least evidence. With several
    /// unreachable endpoints configured, the scheduler cycled through them forever and
    /// resolution never converged. Loopback hides it completely, because a sub-millisecond
    /// round trip always beats the prior.
    #[tokio::test]
    async fn a_proven_route_outranks_routes_that_have_never_been_tried() {
        let (registry, group) = test_group(6);
        let sched = scheduler(registry);
        let cfg = &group.scheduler;

        // The first route works, at a latency typical of a real Internet path.
        let proven = Arc::clone(&group.routes[0]);
        for _ in 0..3 {
            proven.with_health(|h| {
                h.record(
                    AttemptOutcome::Success,
                    Some(Duration::from_millis(250)),
                    Instant::now(),
                    cfg,
                )
            });
        }

        let ranked = sched.rank(&group, 0);
        assert_eq!(
            ranked[0].key,
            proven.key,
            "a route measured working at 250ms must rank ahead of untried routes; \
             ranked order was {:?}",
            ranked.iter().map(|r| r.key.to_string()).collect::<Vec<_>>()
        );
    }

    /// The converse: a route measured as *bad* must fall behind untried routes, so that
    /// alternatives still get their turn.
    #[tokio::test]
    async fn a_failing_route_falls_behind_routes_that_have_never_been_tried() {
        let (registry, group) = test_group(6);
        let sched = scheduler(registry);
        let cfg = &group.scheduler;

        let bad = Arc::clone(&group.routes[0]);
        for _ in 0..4 {
            bad.with_health(|h| h.record(AttemptOutcome::Timeout, None, Instant::now(), cfg));
        }

        let ranked = sched.rank(&group, 0);
        assert_ne!(
            ranked[0].key, bad.key,
            "a route that keeps timing out must not stay first"
        );
    }

    /// With nothing measured at all, every route ties and configuration order decides.
    /// That is the correct cold start: no route has earned a preference.
    #[tokio::test]
    async fn a_cold_group_ranks_in_configuration_order() {
        let (registry, group) = test_group(4);
        let sched = scheduler(registry);
        let ranked = sched.rank(&group, 0);
        let addrs: Vec<String> = ranked.iter().map(|r| r.key.addr.to_string()).collect();
        assert_eq!(addrs, vec!["9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4"]);
    }

    /// A faster proven route must outrank a slower proven route.
    #[tokio::test]
    async fn between_two_measured_routes_the_faster_one_wins() {
        let (registry, group) = test_group(3);
        let sched = scheduler(registry);
        let cfg = &group.scheduler;

        for _ in 0..3 {
            group.routes[2].with_health(|h| {
                h.record(
                    AttemptOutcome::Success,
                    Some(Duration::from_millis(20)),
                    Instant::now(),
                    cfg,
                )
            });
            group.routes[0].with_health(|h| {
                h.record(
                    AttemptOutcome::Success,
                    Some(Duration::from_millis(400)),
                    Instant::now(),
                    cfg,
                )
            });
        }

        let ranked = sched.rank(&group, 0);
        assert_eq!(
            ranked[0].key, group.routes[2].key,
            "the 20ms route must beat the 400ms route"
        );
    }

    #[test]
    fn hedge_budget_enforces_the_fraction() {
        let b = HedgeBudget::default();
        for _ in 0..100 {
            b.record_query();
        }
        assert!(b.allows(0.1));
        for _ in 0..10 {
            b.record_hedge();
        }
        assert!(!b.allows(0.1));
        assert!(b.allows(0.5));
        assert!((b.rate() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn zero_fraction_disables_hedging() {
        let b = HedgeBudget::default();
        b.record_query();
        assert!(!b.allows(0.0));
    }

    #[test]
    fn full_fraction_always_allows() {
        let b = HedgeBudget::default();
        b.record_query();
        for _ in 0..100 {
            b.record_hedge();
        }
        assert!(b.allows(1.0));
    }
}
