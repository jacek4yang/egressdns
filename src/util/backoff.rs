//! Deterministic exponential backoff with bounded jitter.

use std::time::Duration;

/// Exponential backoff policy with a deterministic jitter source.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    /// Jitter fraction in `[0.0, 1.0]`; the returned delay is scaled by
    /// `1 - jitter/2 .. 1 + jitter/2`.
    jitter: f64,
}

impl Backoff {
    /// Create a new backoff policy.
    pub fn new(base: Duration, max: Duration, jitter: f64) -> Self {
        Self {
            base,
            max,
            jitter: jitter.clamp(0.0, 1.0),
        }
    }

    /// Delay for attempt `n` (0-based) using `seed` for deterministic jitter.
    pub fn delay(&self, n: u32, seed: u64) -> Duration {
        let shift = n.min(20);
        let raw = self.base.saturating_mul(1u32 << shift);
        let capped = if raw > self.max { self.max } else { raw };
        if self.jitter <= f64::EPSILON {
            return capped;
        }
        // Deterministic pseudo-random in [0, 1) derived from the seed and attempt.
        let mixed =
            crate::util::fnv1a64(&[seed.to_le_bytes(), u64::from(n).to_le_bytes()].concat());
        let unit = (mixed >> 11) as f64 / ((1u64 << 53) as f64);
        let factor = 1.0 - self.jitter / 2.0 + self.jitter * unit;
        let millis = (capped.as_secs_f64() * factor * 1000.0).round().max(0.0);
        Duration::from_millis(millis as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        let b = Backoff::new(Duration::from_millis(100), Duration::from_secs(10), 0.0);
        assert_eq!(b.delay(0, 1), Duration::from_millis(100));
        assert_eq!(b.delay(1, 1), Duration::from_millis(200));
        assert_eq!(b.delay(2, 1), Duration::from_millis(400));
        assert_eq!(b.delay(30, 1), Duration::from_secs(10));
    }

    #[test]
    fn backoff_jitter_is_deterministic_and_bounded() {
        let b = Backoff::new(Duration::from_millis(1000), Duration::from_secs(60), 0.5);
        let a = b.delay(1, 42);
        let c = b.delay(1, 42);
        assert_eq!(a, c, "same seed must produce the same delay");
        assert!(a >= Duration::from_millis(1500));
        assert!(a <= Duration::from_millis(2500));
    }
}
