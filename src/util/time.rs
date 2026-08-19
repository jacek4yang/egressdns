//! Deterministic-friendly clock abstraction.
//!
//! Tests need a controllable clock so that TTL, decay and hysteresis behaviour can be
//! asserted without sleeping. Production code uses [`SystemClock`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

/// Monotonic + wall clock source.
pub trait Clock: Send + Sync + 'static {
    /// Monotonic instant, used for latency and decay computations.
    fn now(&self) -> Instant;
    /// Seconds since the UNIX epoch, used for persistence and signature lifetimes.
    fn unix_secs(&self) -> u64;
}

/// The production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// Seconds since the UNIX epoch, without needing a trait object.
    pub fn unix_secs_now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock that can be advanced manually. Used by unit and property tests.
#[derive(Debug)]
pub struct TestClock {
    base: Instant,
    offset_ms: AtomicU64,
    unix_base: AtomicU64,
}

impl TestClock {
    /// Create a test clock anchored at `unix_base` seconds.
    pub fn new(unix_base: u64) -> Self {
        Self {
            base: Instant::now(),
            offset_ms: AtomicU64::new(0),
            unix_base: AtomicU64::new(unix_base),
        }
    }

    /// Advance both the monotonic and wall clock by `d`.
    pub fn advance(&self, d: Duration) {
        self.offset_ms
            .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        self.unix_base.fetch_add(d.as_secs(), Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }

    fn unix_secs(&self) -> u64 {
        self.unix_base.load(Ordering::SeqCst)
    }
}

/// Shared clock handle.
pub type SharedClock = Arc<dyn Clock>;

/// Build the production clock handle.
pub fn system_clock() -> SharedClock {
    Arc::new(SystemClock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clock_advances() {
        let c = TestClock::new(1_000);
        let t0 = c.now();
        c.advance(Duration::from_secs(5));
        assert_eq!(c.unix_secs(), 1_005);
        assert_eq!(c.now() - t0, Duration::from_secs(5));
    }
}
