//! A `DnsHandle` adapter that routes hickory's auxiliary lookups through the scheduler.
//!
//! Local DNSSEC validation needs to fetch DNSKEY and DS records while validating an
//! answer. Those lookups must obey the same health tracking, hedging and circuit breaking
//! as any other query, so they are sent through the scheduler rather than through a
//! second, independent client.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::Stream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::DnsHandle;
use hickory_net::NetError;
use hickory_proto::op::{DnsRequest, DnsResponse};

use crate::dns::proofwatch::ProofFailure;
use crate::error::ResolveError;
use crate::upstream::pool::UpstreamGroup;
use crate::upstream::scheduler::Scheduler;

/// A `DnsHandle` backed by the adaptive scheduler.
///
/// `budget` is a *ceiling*, not an allowance. Validating one answer fans out into DNSKEY
/// and DS lookups that each arrive here as a separate resolution, so handing every one of
/// them the configured budget let a four-deep chain spend four budgets while the client
/// waited. Each lookup now takes whichever is smaller: the configured per-query ceiling,
/// or the time actually left on the request's ingress deadline.
#[derive(Clone)]
pub struct SchedulerHandle {
    scheduler: Arc<Scheduler>,
    group: Arc<UpstreamGroup>,
    budget: Duration,
}

impl SchedulerHandle {
    /// Create a handle bound to one group.
    pub fn new(scheduler: Arc<Scheduler>, group: Arc<UpstreamGroup>, budget: Duration) -> Self {
        Self {
            scheduler,
            group,
            budget,
        }
    }
}

type ResponseStream = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send + 'static>>;

/// How a failed sub-lookup bears on a DNSSEC proof.
///
/// None of these are evidence about the zone being validated. A resolver that times out,
/// cannot be reached, or refuses to serve DS records has told us nothing about whether
/// the data is authentic — only that we could not check it here.
fn proof_failure_for(e: &ResolveError) -> ProofFailure {
    match e {
        ResolveError::Timeout { .. } => ProofFailure::Deadline,
        // An answering authority that refuses names a route to avoid, which is worth
        // more than a bare timeout even though neither says anything about the zone.
        ResolveError::InvalidResponse { .. } => ProofFailure::Refused,
        ResolveError::NoRoute { .. }
        | ResolveError::AllFailed { .. }
        | ResolveError::Overloaded { .. }
        | ResolveError::ShuttingDown => ProofFailure::Transport,
        // A nested Bogus is a real verdict about real data, not a failure of ours.
        ResolveError::DnssecBogus => ProofFailure::None,
        // A nested proof we could not finish is, recursively, the same problem.
        ResolveError::ProofIncomplete { .. } => ProofFailure::Transport,
    }
}

impl DnsHandle for SchedulerHandle {
    type Response = ResponseStream;
    type Runtime = TokioRuntimeProvider;

    fn is_verifying_dnssec(&self) -> bool {
        false
    }

    fn send(&self, request: DnsRequest) -> Self::Response {
        let scheduler = Arc::clone(&self.scheduler);
        let group = Arc::clone(&self.group);
        let budget = self.budget;
        let (message, options) = request.into_parts();
        Box::pin(futures_util::stream::once(async move {
            let seed = rand::random::<u64>();
            // Shared with the client request, not restarted for this sub-lookup.
            //
            // Deliberately *not* capped per step. Dividing the budget between an assumed
            // number of chain steps looks like prudence and was measured to be harmful:
            // it cut legitimate lookups short, and `www.isc.org` lost its AD flag in
            // three runs out of four — DNSSEC correctness traded for an availability gain
            // that did not materialise.
            let budget = crate::dns::deadline::remaining_or(budget);
            match scheduler
                .resolve(&group, message, options, budget, seed)
                .await
            {
                Ok(answer) => DnsResponse::from_message(answer.message)
                    .map_err(|e| NetError::from(e.to_string())),
                Err(e) => {
                    // Record *why*, while the reason still exists as a type.
                    //
                    // The validator turns any failure here into `Proof::Bogus` on the
                    // record, which is indistinguishable from a forged signature by the
                    // time we see the message. This is the last point at which the
                    // difference is knowable. See `crate::dns::proofwatch`.
                    crate::dns::proofwatch::observe(proof_failure_for(&e));
                    Err(NetError::from(crate::util::bounded(&e.to_string(), 160)))
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way a sub-lookup can fail on *our* side must be recorded as such.
    ///
    /// If any of these mapped to `ProofFailure::None`, the validator's `Proof::Bogus` for
    /// that record would be read as a cryptographic verdict, and a working name would be
    /// refused. That is the defect this release fixes.
    #[test]
    fn every_failure_of_ours_is_recorded_as_ours() {
        let cases = [
            (
                ResolveError::Timeout { elapsed_ms: 10 },
                ProofFailure::Deadline,
            ),
            (
                ResolveError::InvalidResponse { reason: "refused" },
                ProofFailure::Refused,
            ),
            (
                ResolveError::NoRoute {
                    group: String::from("default"),
                },
                ProofFailure::Transport,
            ),
            (
                ResolveError::AllFailed {
                    detail: String::from("everything is down"),
                },
                ProofFailure::Transport,
            ),
            (ResolveError::ShuttingDown, ProofFailure::Transport),
            (
                ResolveError::Overloaded { limit: 1 },
                ProofFailure::Transport,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                proof_failure_for(&error),
                expected,
                "{error} was not attributed correctly"
            );
        }
    }

    /// A nested Bogus is the one failure that is genuinely about the data, so it must not
    /// be excused as a failure of ours.
    #[test]
    fn a_nested_bogus_verdict_is_not_excused() {
        assert_eq!(
            proof_failure_for(&ResolveError::DnssecBogus),
            ProofFailure::None,
        );
    }
}
