//! Why a DNSSEC proof failed, recorded where the reason still exists.
//!
//! `hickory` attaches a [`Proof`](hickory_proto::dnssec::Proof) to every record, and when
//! it cannot fetch part of a chain it attaches `Proof::Bogus`:
//!
//! ```text
//! Err(net) => return Err(ProofError::new(Proof::Bogus, ProofErrorKind::Net { query, net }))
//! ```
//!
//! By the time the validated message reaches us, `Bogus` from a forged signature and
//! `Bogus` from a lookup that timed out are the same value. Treating them the same way is
//! how `www.bing.com` came to SERVFAIL on a host that could resolve it perfectly well: a
//! four-zone CNAME chain needs more DS and DNSKEY lookups than the foreground budget
//! allowed, the last one was cut off, and a resolver reported a *cryptographic* failure
//! for what was really its own clock running out.
//!
//! The distinction matters more than the inconvenience. "This answer is forged" and "I
//! could not check this answer" call for opposite responses: the first must fail closed,
//! the second must not, because failing closed on every unfinished lookup hands anyone who
//! can slow a network the ability to erase names.
//!
//! We cannot change what `hickory` records on the record. We can record *why* our own
//! transport failed, at the moment it fails, and read it back afterwards — which is enough
//! to tell the two apart without inspecting error strings.
//!
//! The carrier is a task-local for the same reason the deadline is one: the validator
//! calls back into us through a `DnsHandle` whose signature we do not control, and one
//! request is served on one task. See [`crate::dns::deadline`].

use std::cell::Cell;

/// Why an auxiliary lookup made during validation failed.
///
/// Ordered by how much it tells us about the *answer* rather than about us. A larger
/// value wins when several are observed, so one genuine refusal is not hidden by a
/// timeout that happened alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ProofFailure {
    /// Nothing went wrong on our side.
    #[default]
    None,
    /// The lookup ran out of foreground budget. Says nothing about the zone.
    Deadline,
    /// The lookup failed to reach anybody, or the reply was unusable. Also says nothing
    /// about the zone.
    Transport,
    /// An authority answered, and refused. A resolver that will not serve DS records
    /// cannot prove a delegation either way, so this is still not evidence about the
    /// zone — but it is evidence about the *route*, and the route can be avoided.
    Refused,
}

tokio::task_local! {
    /// What the transport saw while validating the request on this task.
    ///
    /// A task-local rather than a thread-local, and the distinction is not academic: a
    /// tokio task moves between worker threads at every `await`, so the auxiliary lookup
    /// that fails and the code that reads the result routinely run on different threads.
    /// A thread-local silently reports "nothing went wrong" in exactly the cases this
    /// exists to catch — which is how the first version of this module still let
    /// `www.bing.com` SERVFAIL.
    static OBSERVED: Cell<ProofFailure>;
}

/// Record that an auxiliary lookup failed, and why.
///
/// Called from the transport, which is the only place that still knows. Safe to call from
/// anywhere: outside a validation the value is simply never read.
pub fn observe(failure: ProofFailure) {
    if failure == ProofFailure::None {
        return;
    }
    // Outside a window there is nobody to tell, which is not an error: background work
    // fails all the time and is not validating anything.
    let _ = OBSERVED.try_with(|c| {
        if failure > c.get() {
            c.set(failure);
        }
    });
}

/// Run `f` with a fresh observation window and report what was seen.
///
/// Each call gets its own cell, so nothing another request observed can leak into this
/// one, and nothing this one observes outlives it.
pub async fn watch<F: std::future::Future>(f: F) -> (F::Output, ProofFailure) {
    OBSERVED
        .scope(Cell::new(ProofFailure::None), async move {
            let out = f.await;
            let seen = OBSERVED.with(|c| c.get());
            (out, seen)
        })
        .await
}

/// What has been observed so far in the current window.
pub fn current() -> ProofFailure {
    OBSERVED.try_with(|c| c.get()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_clean_validation_observes_nothing() {
        let (out, seen) = watch(async { 7 }).await;
        assert_eq!(out, 7);
        assert_eq!(seen, ProofFailure::None);
    }

    #[tokio::test]
    async fn the_most_informative_failure_wins() {
        let (_, seen) = watch(async {
            observe(ProofFailure::Deadline);
            observe(ProofFailure::Refused);
            observe(ProofFailure::Transport);
        })
        .await;
        assert_eq!(
            seen,
            ProofFailure::Refused,
            "a refusal names a route to avoid; a timeout alongside it must not hide that"
        );
    }

    /// A previous request's failure must not be attributed to this one.
    #[tokio::test]
    async fn each_window_starts_clean() {
        let (_, first) = watch(async { observe(ProofFailure::Transport) }).await;
        assert_eq!(first, ProofFailure::Transport);
        let (_, second) = watch(async {}).await;
        assert_eq!(second, ProofFailure::None);
    }

    /// Outside a window, recording a failure must not panic. Background work fails
    /// constantly and is not validating anything.
    #[tokio::test]
    async fn observing_outside_a_window_is_harmless() {
        observe(ProofFailure::Transport);
        assert_eq!(current(), ProofFailure::None);
    }

    /// The reason this is a task-local and not a thread-local.
    ///
    /// A tokio task moves between worker threads at every await point, so the lookup that
    /// fails and the code that reads the result run on different threads as a matter of
    /// course. Under a thread-local this test reports `None` and the bug it represents —
    /// a transport failure misread as a forged signature — comes straight back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_observation_survives_moving_between_worker_threads() {
        let (_, seen) = watch(async {
            // Enough yields that work stealing has every chance to move the task.
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            observe(ProofFailure::Deadline);
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(seen, ProofFailure::Deadline);
    }

    #[tokio::test]
    async fn observing_nothing_is_not_an_observation() {
        let (_, seen) = watch(async { observe(ProofFailure::None) }).await;
        assert_eq!(seen, ProofFailure::None);
    }
}
