//! The foreground deadline, carried across an entire client request.
//!
//! `server.foreground_budget` promises a client an answer, or a failure, within a fixed
//! time. Keeping that promise means every nested operation measures itself against *one*
//! instant established at ingress — not against a fresh copy of the budget.
//!
//! The DNSSEC path is where a per-call `Duration` goes wrong most visibly. Validating one
//! answer means fetching a DNSKEY, a DS, the parent's DNSKEY and so on, each of which is
//! its own resolution. Hand each of them the full budget and a chain of four lookups can
//! spend four budgets; add the wait for a validation permit under congestion and the
//! client waits for something nobody promised.
//!
//! A task-local is the right carrier here rather than a parameter. The validator is
//! `hickory`'s, built once so its cache is shared, and it calls back into us through a
//! `DnsHandle` whose signature we do not control — there is nowhere to thread a deadline
//! through. One request is served on one task, so the task is exactly the scope the
//! deadline belongs to.

use std::time::Duration;

use tokio::time::Instant;

tokio::task_local! {
    /// The instant by which the request on this task must be finished.
    static FOREGROUND_DEADLINE: Instant;
}

/// Run `f` with `deadline` in force for everything it awaits.
pub async fn with_deadline<F: std::future::Future>(deadline: Instant, f: F) -> F::Output {
    FOREGROUND_DEADLINE.scope(deadline, f).await
}

/// The deadline in force, if this task is serving a client request.
///
/// Background work — prefetch, probing, maintenance — runs outside any scope and gets
/// `None`, which is correct: it is not racing a client.
pub fn current() -> Option<Instant> {
    FOREGROUND_DEADLINE.try_with(|d| *d).ok()
}

/// Time left on this task's deadline, clamped to `fallback` when there is no deadline or
/// the deadline is more generous than the caller's own limit.
///
/// This is the function nested operations call instead of using a configured duration
/// directly. It can only ever *reduce* the time an operation takes, which is what makes
/// it safe to apply everywhere.
pub fn remaining_or(fallback: Duration) -> Duration {
    match current() {
        Some(deadline) => deadline
            .saturating_duration_since(Instant::now())
            .min(fallback),
        None => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn outside_a_request_there_is_no_deadline() {
        assert!(current().is_none());
        assert_eq!(
            remaining_or(Duration::from_secs(5)),
            Duration::from_secs(5),
            "background work keeps its own budget"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_shrinks_as_the_request_ages() {
        let deadline = Instant::now() + Duration::from_secs(2);
        with_deadline(deadline, async {
            assert_eq!(remaining_or(Duration::from_secs(5)), Duration::from_secs(2));
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            assert_eq!(
                remaining_or(Duration::from_secs(5)),
                Duration::from_millis(500)
            );
        })
        .await;
    }

    /// The caller's own limit still applies: the deadline may only reduce it.
    #[tokio::test(start_paused = true)]
    async fn a_shorter_caller_limit_wins_over_a_longer_deadline() {
        let deadline = Instant::now() + Duration::from_secs(10);
        with_deadline(deadline, async {
            assert_eq!(remaining_or(Duration::from_secs(1)), Duration::from_secs(1));
        })
        .await;
    }

    /// Once the deadline has passed there is no time left to give anybody, however
    /// generous the caller's own limit is. This is what stops a chain of sub-lookups
    /// starting new work after the client has already been failed.
    #[tokio::test(start_paused = true)]
    async fn an_expired_deadline_yields_zero() {
        let deadline = Instant::now() + Duration::from_millis(100);
        with_deadline(deadline, async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(remaining_or(Duration::from_secs(5)), Duration::ZERO);
        })
        .await;
    }

    /// Every sub-lookup shares one budget rather than each receiving a copy.
    #[tokio::test(start_paused = true)]
    async fn sequential_operations_share_one_budget() {
        let budget = Duration::from_secs(2);
        let deadline = Instant::now() + budget;
        let consumed = with_deadline(deadline, async {
            let mut total = Duration::ZERO;
            // Four nested lookups, each willing to take the whole budget.
            for _ in 0..4 {
                let slice = remaining_or(budget);
                tokio::time::sleep(slice).await;
                total += slice;
            }
            total
        })
        .await;
        assert_eq!(
            consumed, budget,
            "four lookups that each asked for the full budget must share one"
        );
    }
}
