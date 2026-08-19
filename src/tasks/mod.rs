//! Supervised background tasks.
//!
//! Every component of the control plane runs here. Each one is:
//!
//! * **Bounded** — it uses bounded queues, explicit timeouts and semaphores.
//! * **Cancellable** — it observes a [`CancellationToken`] and stops promptly.
//! * **Panic-isolated** — a panic is caught by the supervisor, counted, and the task is
//!   restarted after a backoff. A crash in one component cannot stop DNS ingress.
//! * **Optional** — if it never runs, or fails forever, the resolver degrades to a plain
//!   caching forwarder.

pub mod cloudflare;
pub mod maintenance;
pub mod network;
pub mod prefetch;

use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::dns::resolver::Resolver;
use crate::runtime::{App, RuntimeState};
use crate::util::backoff::Backoff;

/// Everything a background task needs, without capturing any configuration.
///
/// A background task that copies configuration out of the [`App`] at startup keeps serving
/// the old configuration for the lifetime of the process, which makes a reload a lie. The
/// contract here is the opposite: a task holds only a weak reference and re-reads the
/// current state at the top of every iteration, so the very next tick after a reload uses
/// the new configuration, the new upstream registry and the new resolver.
///
/// The reference is weak so that a detached task can never keep the process state alive
/// after shutdown; `app()` returning `None` means "the daemon is gone, stop".
#[derive(Clone)]
pub struct Ctx {
    app: Weak<App>,
    /// Shutdown token for the whole control plane.
    pub cancel: CancellationToken,
}

impl Ctx {
    /// Build a context for the given process.
    pub fn new(app: &Arc<App>) -> Self {
        Self {
            app: Arc::downgrade(app),
            cancel: app.cancel.clone(),
        }
    }

    /// The process, if it is still alive.
    pub fn app(&self) -> Option<Arc<App>> {
        self.app.upgrade()
    }

    /// The configuration in force right now.
    pub fn config(&self) -> Option<Arc<Config>> {
        Some(self.app.upgrade()?.config())
    }

    /// The runtime state in force right now.
    pub fn state(&self) -> Option<Arc<RuntimeState>> {
        Some(self.app.upgrade()?.state())
    }

    /// The resolver in force right now. Never cache this across a tick: a reload replaces
    /// it, and the previous one holds a registry whose connections are about to be drained.
    pub fn resolver(&self) -> Option<Arc<Resolver>> {
        Some(self.app.upgrade()?.state().resolver.clone())
    }
}

/// Run a task under supervision until cancellation.
///
/// `factory` is called to produce a fresh future for each attempt, so a restarted task
/// starts from a clean state rather than resuming a poisoned one.
pub async fn supervise<F, Fut>(name: &'static str, cancel: CancellationToken, factory: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(60), 0.3);
    let mut attempt = 0u32;
    // A task that stayed healthy for a long time should not be punished with the maximum
    // backoff for its first panic.
    const STABLE_AFTER: Duration = Duration::from_secs(120);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let started = tokio::time::Instant::now();
        let mut handle = tokio::spawn(factory());
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                handle.abort();
                // Wait for the child to actually stop. `abort()` only schedules
                // cancellation; returning here would leave the child running after the
                // supervisor claimed to have stopped, which is exactly the class of leak
                // graceful shutdown exists to prevent.
                let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
                return;
            }
            r = &mut handle => r,
        };
        if started.elapsed() >= STABLE_AFTER {
            attempt = 0;
        }
        match outcome {
            Ok(()) => {
                // A clean return means the task decided its work is finished.
                tracing::debug!(event = "task.finished", task = name);
                return;
            }
            Err(e) if e.is_cancelled() => return,
            Err(e) => {
                metrics::counter!(
                    crate::metrics::names::TASK_RESTARTS_TOTAL,
                    "task" => name,
                )
                .increment(1);
                tracing::error!(
                    event = "task.panicked",
                    task = name,
                    error = %e,
                    "restarting supervised task"
                );
            }
        }
        let delay = backoff.delay(attempt, u64::from(attempt) ^ 0x9e37_79b9);
        attempt = attempt.saturating_add(1);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// A set of supervised background tasks that can be awaited at shutdown.
///
/// Holding the join handles is what makes "graceful shutdown" mean something: without
/// them, cancelling the token only *asks* the control plane to stop, and the process exits
/// while tasks are still running — a probe could open a new outbound connection after
/// shutdown began.
#[derive(Default)]
pub struct Supervisor {
    tasks: JoinSet<()>,
}

impl Supervisor {
    /// Create an empty set.
    pub fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
        }
    }

    /// Spawn a supervised task into the set.
    pub fn spawn<F, Fut>(&mut self, name: &'static str, cancel: CancellationToken, factory: F)
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(supervise(name, cancel, factory));
    }

    /// Number of tasks that have not yet finished.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Wait for every task to finish, up to `deadline`, then abort whatever remains.
    ///
    /// Returns the number of tasks that had to be aborted, which is zero for a clean
    /// shutdown and is worth logging when it is not.
    pub async fn join_all(&mut self, deadline: Duration) -> usize {
        let drain = async { while self.tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(deadline, drain).await.is_err() {
            let remaining = self.tasks.len();
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
            return remaining;
        }
        0
    }
}

/// Build a live [`Ctx`] backed by a real process, for tests.
///
/// Returns the app as well, because `Ctx` holds only a weak reference: dropping the app
/// would make every accessor return `None`, which is the "daemon is gone" signal.
#[cfg(test)]
pub(crate) fn test_ctx(config: crate::config::Config) -> (Arc<App>, Ctx) {
    crate::tls::install_crypto_provider();
    let app = App::from_config(Arc::new(config), std::path::PathBuf::from("/nonexistent"))
        .expect("test app builds");
    let ctx = Ctx::new(&app);
    (app, ctx)
}

/// A configuration suitable for unit tests: no persistence, no probing, no listeners.
#[cfg(test)]
pub(crate) fn test_config() -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.storage.enabled = false;
    config.probe.enabled = false;
    config.metrics.enabled = false;
    config.admin.enabled = false;
    config
}

/// Sleep for `period`, returning `false` when cancellation happened first.
pub async fn tick(period: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(period) => true,
    }
}

/// Deterministic jitter applied to a periodic interval so that a fleet of nodes does not
/// synchronise its background traffic.
pub fn jittered(period: Duration, seed: u64) -> Duration {
    let unit = crate::ranking::unit_from_seed(seed);
    let factor = 0.85 + 0.3 * unit;
    period.mul_f64(factor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn supervisor_restarts_a_panicking_task() {
        let cancel = CancellationToken::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(supervise("test", cancel2, move || {
            let c = Arc::clone(&c);
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    panic!("boom");
                }
                // Third attempt runs forever until cancelled.
                std::future::pending::<()>().await;
            }
        }));
        // Allow a few restart cycles.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            counter.load(Ordering::SeqCst) >= 3,
            "task should have restarted, ran {} times",
            counter.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn supervisor_stops_on_cancel() {
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(supervise("test", cancel2, || async {
            std::future::pending::<()>().await;
        }));
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "supervisor did not stop promptly");
    }

    #[tokio::test(start_paused = true)]
    async fn tick_reports_cancellation() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(!tick(Duration::from_secs(60), &cancel).await);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let base = Duration::from_secs(100);
        for seed in 0..64u64 {
            let d = jittered(base, seed);
            assert!(d >= Duration::from_secs(85), "{d:?}");
            assert!(d <= Duration::from_secs(115), "{d:?}");
        }
    }
}
