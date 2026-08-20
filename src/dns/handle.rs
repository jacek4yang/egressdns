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
            let budget = crate::dns::deadline::remaining_or(budget);
            match scheduler
                .resolve(&group, message, options, budget, seed)
                .await
            {
                Ok(answer) => DnsResponse::from_message(answer.message)
                    .map_err(|e| NetError::from(e.to_string())),
                Err(e) => Err(NetError::from(crate::util::bounded(&e.to_string(), 160))),
            }
        }))
    }
}
