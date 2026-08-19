//! The per-address quality model.
//!
//! State per address is deliberately small and fixed-size so that tracking a hundred
//! thousand addresses stays bounded: a decayed Beta posterior for success probability, an
//! EWMA for recent latency, a 16-slot ring of recent samples for median and tail
//! estimates, plus a few counters.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::RankingConfig;

/// Number of recent latency samples retained per address.
pub const WINDOW: usize = 16;

/// How an observation should influence the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationClass {
    /// The probe succeeded with strong, applicable evidence.
    Success,
    /// The probe failed in a way that is applicable to the service being scored.
    ApplicableFailure,
    /// The probe failed, but the failure does not clearly indicate the address is bad
    /// (for example a middlebox reset, or a failure while the whole subsystem is sick).
    AmbiguousFailure,
    /// The endpoint does not support the capability being tested.
    Unsupported,
    /// The probe timed out.
    Timeout,
    /// Local policy prevented the probe from running at all.
    PolicyBlocked,
}

impl ObservationClass {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ApplicableFailure => "applicable_failure",
            Self::AmbiguousFailure => "ambiguous_failure",
            Self::Unsupported => "unsupported",
            Self::Timeout => "timeout",
            Self::PolicyBlocked => "policy_blocked",
        }
    }

    /// True when the observation may materially reduce a service-specific score.
    ///
    /// Ambiguous failures, unsupported capabilities and policy blocks never do: they say
    /// something about the probe, not about the address.
    pub fn is_penalising(self) -> bool {
        matches!(self, Self::ApplicableFailure | Self::Timeout)
    }
}

/// Confidence class of an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Never measured.
    Unknown,
    /// Very few or very old samples.
    Low,
    /// Enough recent samples to be useful.
    Medium,
    /// Many recent, consistent samples.
    High,
}

impl Confidence {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Decayed statistics for one probe key.
#[derive(Debug, Clone)]
pub struct QualityStats {
    /// Beta posterior successes, including the prior.
    alpha: f64,
    /// Beta posterior failures, including the prior.
    beta: f64,
    /// EWMA of recent latency in milliseconds.
    ewma_ms: f64,
    /// EWMA of absolute latency change, an inexpensive jitter estimate.
    jitter_ms: f64,
    /// Ring of the most recent latency samples in milliseconds.
    window: [f32; WINDOW],
    /// Number of valid entries in `window`.
    window_len: usize,
    /// Next write position in `window`.
    window_pos: usize,
    /// Consecutive penalising observations.
    consecutive_failures: u32,
    /// Total observations of any class.
    samples: u32,
    /// Total successful observations.
    successes: u32,
    /// Instant of the most recent observation.
    last_update: Option<Instant>,
    /// Instant of the most recent success.
    last_success: Option<Instant>,
    /// Network generation the evidence belongs to.
    generation: u64,
}

/// Prior strength. A weak prior means a handful of real samples dominates quickly, but a
/// single failure cannot drive the estimate to zero.
const PRIOR_ALPHA: f64 = 1.0;
const PRIOR_BETA: f64 = 1.0;
const EWMA_WEIGHT: f64 = 0.25;

impl QualityStats {
    /// Create empty statistics for a network generation.
    pub fn new(generation: u64) -> Self {
        Self {
            alpha: PRIOR_ALPHA,
            beta: PRIOR_BETA,
            ewma_ms: 0.0,
            jitter_ms: 0.0,
            window: [0.0; WINDOW],
            window_len: 0,
            window_pos: 0,
            consecutive_failures: 0,
            samples: 0,
            successes: 0,
            last_update: None,
            last_success: None,
            generation,
        }
    }

    /// Network generation the evidence belongs to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Total observations recorded.
    pub fn sample_count(&self) -> u32 {
        self.samples
    }

    /// Successful observations recorded.
    pub fn success_count(&self) -> u32 {
        self.successes
    }

    /// Consecutive penalising observations.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Instant of the most recent success.
    pub fn last_success(&self) -> Option<Instant> {
        self.last_success
    }

    /// True when there is at least one observation that may influence ordering.
    pub fn has_applicable_evidence(&self) -> bool {
        self.samples > 0 && (self.successes > 0 || self.consecutive_failures > 0)
    }

    /// EWMA latency in milliseconds.
    pub fn ewma_ms(&self) -> f64 {
        self.ewma_ms
    }

    /// Median of the recent window.
    pub fn p50_ms(&self) -> f64 {
        self.percentile(0.5)
    }

    /// 95th percentile of the recent window.
    pub fn p95_ms(&self) -> f64 {
        self.percentile(0.95)
    }

    /// 99th percentile of the recent window.
    pub fn p99_ms(&self) -> f64 {
        self.percentile(0.99)
    }

    /// Jitter estimate in milliseconds.
    pub fn jitter_ms(&self) -> f64 {
        self.jitter_ms
    }

    fn percentile(&self, q: f64) -> f64 {
        if self.window_len == 0 {
            return 0.0;
        }
        let mut v: Vec<f32> = self.window[..self.window_len].to_vec();
        v.sort_by(|a, b| a.total_cmp(b));
        let idx = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1;
        f64::from(v[idx])
    }

    /// Decay the posterior towards the prior, so old evidence gradually stops mattering.
    fn decay(&mut self, now: Instant, cfg: &RankingConfig) {
        let Some(last) = self.last_update else {
            return;
        };
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let half_life = cfg.evidence_half_life.as_secs_f64().max(1.0);
        let factor = 0.5f64.powf(elapsed / half_life);
        self.alpha = PRIOR_ALPHA + (self.alpha - PRIOR_ALPHA) * factor;
        self.beta = PRIOR_BETA + (self.beta - PRIOR_BETA) * factor;
    }

    /// Record a successful observation with a measured latency.
    pub fn record_success(&mut self, latency: Duration, now: Instant, cfg: &RankingConfig) {
        self.decay(now, cfg);
        let ms = latency.as_secs_f64() * 1000.0;
        if self.window_len == 0 {
            self.ewma_ms = ms;
        } else {
            self.jitter_ms =
                (1.0 - EWMA_WEIGHT) * self.jitter_ms + EWMA_WEIGHT * (ms - self.ewma_ms).abs();
            self.ewma_ms = (1.0 - EWMA_WEIGHT) * self.ewma_ms + EWMA_WEIGHT * ms;
        }
        self.window[self.window_pos] = ms as f32;
        self.window_pos = (self.window_pos + 1) % WINDOW;
        self.window_len = (self.window_len + 1).min(WINDOW);
        self.alpha += 1.0;
        self.samples = self.samples.saturating_add(1);
        self.successes = self.successes.saturating_add(1);
        self.consecutive_failures = 0;
        self.last_update = Some(now);
        self.last_success = Some(now);
    }

    /// Record a non-successful observation.
    ///
    /// Only applicable failures and timeouts move the posterior. Everything else merely
    /// refreshes the timestamp so the sample does not look stale.
    pub fn record_failure(&mut self, class: ObservationClass, now: Instant, cfg: &RankingConfig) {
        self.decay(now, cfg);
        self.samples = self.samples.saturating_add(1);
        if class.is_penalising() {
            self.beta += 1.0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        self.last_update = Some(now);
    }

    /// Record an observation of any class.
    pub fn record(
        &mut self,
        class: ObservationClass,
        latency: Option<Duration>,
        now: Instant,
        cfg: &RankingConfig,
    ) {
        match (class, latency) {
            (ObservationClass::Success, Some(d)) => self.record_success(d, now, cfg),
            (ObservationClass::Success, None) => {
                self.record_success(Duration::from_millis(0), now, cfg)
            }
            (other, _) => self.record_failure(other, now, cfg),
        }
    }

    /// Posterior mean success probability.
    pub fn success_probability(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Lower bound of the success probability, using the Beta posterior mean minus one
    /// standard deviation. This is the sample-count-aware estimate the cost model uses:
    /// with few samples the standard deviation is large, so the bound is pessimistic.
    pub fn success_probability_lower_bound(&self) -> f64 {
        let n = self.alpha + self.beta;
        let mean = self.alpha / n;
        let var = (self.alpha * self.beta) / (n * n * (n + 1.0));
        (mean - var.sqrt()).clamp(0.0, 1.0)
    }

    /// Width of the one-standard-deviation interval, used as an uncertainty measure.
    pub fn uncertainty(&self) -> f64 {
        let n = self.alpha + self.beta;
        let var = (self.alpha * self.beta) / (n * n * (n + 1.0));
        var.sqrt().clamp(0.0, 1.0)
    }

    /// Confidence class.
    pub fn confidence(&self, cfg: &RankingConfig, now: Instant) -> Confidence {
        if self.samples == 0 {
            return Confidence::Unknown;
        }
        let fresh = self
            .last_update
            .map(|t| now.saturating_duration_since(t) <= cfg.sample_max_age)
            .unwrap_or(false);
        match (self.samples, fresh) {
            (_, false) => Confidence::Low,
            (0..=2, _) => Confidence::Low,
            (3..=9, _) => Confidence::Medium,
            _ => Confidence::High,
        }
    }

    /// Expected cost in milliseconds.
    ///
    /// ```text
    /// expected_cost = ewma_latency
    ///               + tail_weight   * p95
    ///               + jitter_weight * jitter
    ///               + (1 - p_success_lower_bound) * failure_penalty
    ///               + consecutive_failure_penalty
    ///               + uncertainty_penalty
    ///               + stale_sample_penalty
    /// ```
    pub fn expected_cost(&self, cfg: &RankingConfig, now: Instant) -> f64 {
        if self.samples == 0 {
            return cfg.neutral_cost_ms;
        }
        let base = if self.successes == 0 {
            cfg.neutral_cost_ms
        } else {
            self.ewma_ms
        };
        let tail = cfg.tail_weight * self.p95_ms();
        let jitter = cfg.jitter_weight * self.jitter_ms;
        let failure = (1.0 - self.success_probability_lower_bound()) * cfg.failure_penalty_ms;
        let streak = if self.consecutive_failures == 0 {
            0.0
        } else {
            cfg.failure_penalty_ms
                * cfg
                    .consecutive_failure_base
                    .powi(self.consecutive_failures.min(8) as i32)
                / 8.0
        };
        let uncertainty = self.uncertainty() * cfg.uncertainty_penalty_ms;
        let stale = match self.last_update {
            Some(t) if now.saturating_duration_since(t) > cfg.sample_max_age => {
                cfg.stale_sample_penalty_ms
            }
            _ => 0.0,
        };
        base + tail + jitter + failure + streak + uncertainty + stale
    }

    /// Apply a network-generation change: keep the evidence as a weak prior only.
    pub fn demote_to_prior(&mut self, new_generation: u64, factor: f64) {
        let f = factor.clamp(0.0, 1.0);
        self.alpha = PRIOR_ALPHA + (self.alpha - PRIOR_ALPHA) * f;
        self.beta = PRIOR_BETA + (self.beta - PRIOR_BETA) * f;
        self.consecutive_failures = 0;
        self.samples = ((self.samples as f64) * f) as u32;
        self.successes = ((self.successes as f64) * f) as u32;
        self.generation = new_generation;
    }

    /// Rebuild statistics from persisted values.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted(
        generation: u64,
        alpha: f64,
        beta: f64,
        ewma_ms: f64,
        p95_ms: f64,
        jitter_ms: f64,
        samples: u32,
        successes: u32,
    ) -> Self {
        let mut s = Self::new(generation);
        s.alpha = alpha.max(PRIOR_ALPHA);
        s.beta = beta.max(PRIOR_BETA);
        s.ewma_ms = ewma_ms.max(0.0);
        s.jitter_ms = jitter_ms.max(0.0);
        s.samples = samples;
        s.successes = successes;
        if ewma_ms > 0.0 {
            s.window[0] = ewma_ms as f32;
            s.window[1] = p95_ms.max(ewma_ms) as f32;
            s.window_len = 2;
            s.window_pos = 2 % WINDOW;
        }
        s
    }

    /// Values to persist.
    pub fn to_persisted(&self) -> PersistedQuality {
        PersistedQuality {
            alpha: self.alpha,
            beta: self.beta,
            ewma_ms: self.ewma_ms,
            p95_ms: self.p95_ms(),
            jitter_ms: self.jitter_ms,
            samples: self.samples,
            successes: self.successes,
            generation: self.generation,
        }
    }
}

/// Flattened representation used by the persistence layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PersistedQuality {
    /// Beta posterior successes.
    pub alpha: f64,
    /// Beta posterior failures.
    pub beta: f64,
    /// EWMA latency in milliseconds.
    pub ewma_ms: f64,
    /// Tail latency estimate in milliseconds.
    pub p95_ms: f64,
    /// Jitter estimate in milliseconds.
    pub jitter_ms: f64,
    /// Observation count.
    pub samples: u32,
    /// Success count.
    pub successes: u32,
    /// Network generation.
    pub generation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RankingConfig {
        RankingConfig::default()
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_has_neutral_cost() {
        let now = Instant::now();
        let s = QualityStats::new(1);
        assert_eq!(s.expected_cost(&cfg(), now), cfg().neutral_cost_ms);
        assert_eq!(s.confidence(&cfg(), now), Confidence::Unknown);
        assert!(!s.has_applicable_evidence());
    }

    #[tokio::test(start_paused = true)]
    async fn non_penalising_failures_do_not_move_the_posterior() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        let before = s.success_probability();
        for class in [
            ObservationClass::AmbiguousFailure,
            ObservationClass::Unsupported,
            ObservationClass::PolicyBlocked,
        ] {
            s.record_failure(class, now, &c);
        }
        assert!((s.success_probability() - before).abs() < 1e-9);
        assert_eq!(s.consecutive_failures(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn applicable_failures_penalise() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        let base = s.expected_cost(&c, now);
        for _ in 0..5 {
            s.record_failure(ObservationClass::ApplicableFailure, now, &c);
        }
        assert!(s.expected_cost(&c, now) > base);
        assert_eq!(s.consecutive_failures(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_failure_does_not_eliminate_an_address() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        for _ in 0..20 {
            s.record_success(Duration::from_millis(10), now, &c);
        }
        let healthy = s.expected_cost(&c, now);
        s.record_failure(ObservationClass::ApplicableFailure, now, &c);
        let after = s.expected_cost(&c, now);
        assert!(after > healthy);
        assert!(
            s.success_probability() > 0.8,
            "one failure in twenty-one should stay above 0.8, got {}",
            s.success_probability()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn confidence_grows_with_samples() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        s.record_success(Duration::from_millis(5), now, &c);
        assert_eq!(s.confidence(&c, now), Confidence::Low);
        for _ in 0..4 {
            s.record_success(Duration::from_millis(5), now, &c);
        }
        assert_eq!(s.confidence(&c, now), Confidence::Medium);
        for _ in 0..10 {
            s.record_success(Duration::from_millis(5), now, &c);
        }
        assert_eq!(s.confidence(&c, now), Confidence::High);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_samples_are_penalised_and_downgraded() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        for _ in 0..20 {
            s.record_success(Duration::from_millis(5), now, &c);
        }
        let fresh_cost = s.expected_cost(&c, now);
        let later = now + c.sample_max_age + Duration::from_secs(60);
        assert!(s.expected_cost(&c, later) > fresh_cost);
        assert_eq!(s.confidence(&c, later), Confidence::Low);
    }

    #[tokio::test(start_paused = true)]
    async fn uncertainty_shrinks_with_evidence() {
        let now = Instant::now();
        let c = cfg();
        let mut few = QualityStats::new(1);
        few.record_success(Duration::from_millis(10), now, &c);
        let mut many = QualityStats::new(1);
        for _ in 0..50 {
            many.record_success(Duration::from_millis(10), now, &c);
        }
        assert!(many.uncertainty() < few.uncertainty());
        assert!(many.success_probability_lower_bound() > few.success_probability_lower_bound());
    }

    #[tokio::test(start_paused = true)]
    async fn window_percentiles_track_recent_samples() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        for ms in [10u64, 12, 11, 13, 200] {
            s.record_success(Duration::from_millis(ms), now, &c);
        }
        assert!(s.p50_ms() < s.p95_ms());
        assert!(s.p95_ms() >= 100.0, "p95 was {}", s.p95_ms());
    }

    #[tokio::test(start_paused = true)]
    async fn generation_change_demotes_to_weak_prior() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(1);
        for _ in 0..50 {
            s.record_success(Duration::from_millis(5), now, &c);
        }
        let strong = s.success_probability_lower_bound();
        s.demote_to_prior(2, 0.25);
        assert_eq!(s.generation(), 2);
        assert!(s.success_probability_lower_bound() < strong);
        assert!(s.uncertainty() > 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn persistence_round_trip_preserves_shape() {
        let now = Instant::now();
        let c = cfg();
        let mut s = QualityStats::new(3);
        for _ in 0..10 {
            s.record_success(Duration::from_millis(20), now, &c);
        }
        let p = s.to_persisted();
        let restored = QualityStats::from_persisted(
            p.generation,
            p.alpha,
            p.beta,
            p.ewma_ms,
            p.p95_ms,
            p.jitter_ms,
            p.samples,
            p.successes,
        );
        assert_eq!(restored.generation(), 3);
        assert_eq!(restored.sample_count(), 10);
        assert!((restored.success_probability() - s.success_probability()).abs() < 1e-9);
    }
}
