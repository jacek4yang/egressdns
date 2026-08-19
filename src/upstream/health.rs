//! Per-route health tracking and circuit breaking.
//!
//! A *route* is the triple (configured server, transport, remote address). Health is kept
//! per route rather than per server so that, for example, a broken IPv6 path to one
//! resolver does not make its IPv4 path look unhealthy.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::SchedulerConfig;

/// Number of recent latency samples retained per route.
const WINDOW: usize = 32;
/// Decay half-life applied to the outcome counters.
const HALF_LIFE: Duration = Duration::from_secs(120);

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Failures are accumulating but the route is still used.
    Suspect,
    /// The route is withdrawn until the open period elapses.
    Open,
    /// A bounded number of probe requests are permitted.
    HalfOpen,
}

impl CircuitState {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Suspect => "suspect",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }

    /// Numeric value for the gauge.
    pub fn gauge(self) -> f64 {
        match self {
            Self::Closed => 0.0,
            Self::Suspect => 1.0,
            Self::Open => 2.0,
            Self::HalfOpen => 3.0,
        }
    }
}

/// Classification of one upstream attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// A complete, acceptable answer.
    Success,
    /// No answer within the per-attempt timeout.
    Timeout,
    /// The server answered SERVFAIL or REFUSED.
    ServerFailure,
    /// The response failed structural or RFC 5452 validation.
    Malformed,
    /// The transport itself failed (connect, TLS, QUIC).
    TransportError,
}

impl AttemptOutcome {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::ServerFailure => "server_failure",
            Self::Malformed => "malformed",
            Self::TransportError => "transport_error",
        }
    }

    fn is_failure(self) -> bool {
        !matches!(self, Self::Success)
    }
}

/// Decayed health statistics for one route.
#[derive(Debug, Clone)]
pub struct RouteHealth {
    success: f64,
    timeout: f64,
    server_failure: f64,
    malformed: f64,
    transport_error: f64,
    ewma_ms: f64,
    jitter_ms: f64,
    window: [f32; WINDOW],
    window_len: usize,
    window_pos: usize,
    connect_cost_ms: f64,
    consecutive_failures: u32,
    samples: u64,
    last_update: Option<Instant>,
    last_success: Option<Instant>,
    circuit: CircuitState,
    circuit_changed_at: Option<Instant>,
    half_open_successes: u32,
    half_open_inflight: u32,
}

impl Default for RouteHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteHealth {
    /// A route with no history. Unknown routes are treated optimistically so that a fresh
    /// configuration is usable immediately.
    pub fn new() -> Self {
        Self {
            success: 0.0,
            timeout: 0.0,
            server_failure: 0.0,
            malformed: 0.0,
            transport_error: 0.0,
            ewma_ms: 0.0,
            jitter_ms: 0.0,
            window: [0.0; WINDOW],
            window_len: 0,
            window_pos: 0,
            connect_cost_ms: 0.0,
            consecutive_failures: 0,
            samples: 0,
            last_update: None,
            last_success: None,
            circuit: CircuitState::Closed,
            circuit_changed_at: None,
            half_open_successes: 0,
            half_open_inflight: 0,
        }
    }

    fn decay(&mut self, now: Instant) {
        let Some(last) = self.last_update else {
            return;
        };
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let factor = 0.5f64.powf(elapsed / HALF_LIFE.as_secs_f64());
        self.success *= factor;
        self.timeout *= factor;
        self.server_failure *= factor;
        self.malformed *= factor;
        self.transport_error *= factor;
    }

    /// Record the cost of establishing a connection.
    pub fn record_connect(&mut self, cost: Duration) {
        let ms = cost.as_secs_f64() * 1000.0;
        self.connect_cost_ms = if self.connect_cost_ms == 0.0 {
            ms
        } else {
            0.7 * self.connect_cost_ms + 0.3 * ms
        };
    }

    /// Record the outcome of one attempt.
    pub fn record(
        &mut self,
        outcome: AttemptOutcome,
        latency: Option<Duration>,
        now: Instant,
        cfg: &SchedulerConfig,
    ) {
        self.decay(now);
        self.samples = self.samples.saturating_add(1);
        match outcome {
            AttemptOutcome::Success => {
                self.success += 1.0;
                self.consecutive_failures = 0;
                self.last_success = Some(now);
                if let Some(d) = latency {
                    let ms = d.as_secs_f64() * 1000.0;
                    if self.window_len == 0 {
                        self.ewma_ms = ms;
                    } else {
                        self.jitter_ms = 0.75 * self.jitter_ms + 0.25 * (ms - self.ewma_ms).abs();
                        self.ewma_ms = 0.75 * self.ewma_ms + 0.25 * ms;
                    }
                    self.window[self.window_pos] = ms as f32;
                    self.window_pos = (self.window_pos + 1) % WINDOW;
                    self.window_len = (self.window_len + 1).min(WINDOW);
                }
            }
            AttemptOutcome::Timeout => {
                self.timeout += 1.0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
            AttemptOutcome::ServerFailure => {
                self.server_failure += 1.0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
            AttemptOutcome::Malformed => {
                self.malformed += 1.0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
            AttemptOutcome::TransportError => {
                self.transport_error += 1.0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
        }
        self.last_update = Some(now);
        self.update_circuit(outcome, now, cfg);
    }

    fn update_circuit(&mut self, outcome: AttemptOutcome, now: Instant, cfg: &SchedulerConfig) {
        match self.circuit {
            CircuitState::Closed | CircuitState::Suspect => {
                if outcome.is_failure() {
                    if self.consecutive_failures >= cfg.circuit_failure_threshold {
                        self.circuit = CircuitState::Open;
                        self.circuit_changed_at = Some(now);
                        self.half_open_successes = 0;
                        self.half_open_inflight = 0;
                    } else if self.consecutive_failures > 0 {
                        self.circuit = CircuitState::Suspect;
                    }
                } else {
                    self.circuit = CircuitState::Closed;
                }
            }
            CircuitState::Open => {}
            CircuitState::HalfOpen => {
                // The reservation is released by the caller's RAII guard, not here:
                // recording is only one of the ways an attempt can end, and the other one
                // — cancellation — used to leak the slot forever.
                if outcome.is_failure() {
                    self.circuit = CircuitState::Open;
                    self.circuit_changed_at = Some(now);
                    self.half_open_successes = 0;
                } else {
                    self.half_open_successes = self.half_open_successes.saturating_add(1);
                    if self.half_open_successes >= cfg.circuit_half_open_successes {
                        self.circuit = CircuitState::Closed;
                        self.circuit_changed_at = Some(now);
                        self.consecutive_failures = 0;
                    }
                }
            }
        }
    }

    /// Advance the circuit from Open to HalfOpen when the open period has elapsed.
    ///
    /// A deterministic jitter derived from `seed` spreads recovery probes so that a fleet
    /// of routes does not all retry at the same instant.
    pub fn tick(&mut self, now: Instant, cfg: &SchedulerConfig, seed: u64) {
        if self.circuit != CircuitState::Open {
            return;
        }
        let Some(changed) = self.circuit_changed_at else {
            self.circuit_changed_at = Some(now);
            return;
        };
        let jitter = crate::ranking::unit_from_seed(seed) * 0.5;
        let wait = cfg
            .circuit_open_duration
            .mul_f64(1.0 + jitter)
            .max(Duration::from_millis(100));
        if now.saturating_duration_since(changed) >= wait {
            self.circuit = CircuitState::HalfOpen;
            self.circuit_changed_at = Some(now);
            self.half_open_successes = 0;
            self.half_open_inflight = 0;
        }
    }

    /// Whether the route may be used for a foreground query right now.
    pub fn is_usable(&self) -> bool {
        match self.circuit {
            CircuitState::Closed | CircuitState::Suspect => true,
            CircuitState::HalfOpen => self.half_open_inflight == 0,
            CircuitState::Open => false,
        }
    }

    /// Reserve a half-open probe slot.
    ///
    /// Returns whether a slot was actually taken, so the caller can release exactly what
    /// it reserved.
    pub fn begin_attempt(&mut self) -> bool {
        if self.circuit == CircuitState::HalfOpen {
            self.half_open_inflight = self.half_open_inflight.saturating_add(1);
            return true;
        }
        false
    }

    /// Release a half-open probe slot that was reserved but never recorded.
    ///
    /// An attempt can end in two ways — recorded, or cancelled — and only the first used
    /// to release the slot. A route that lost one hedge race while recovering was then
    /// excluded from ranking for the rest of the process lifetime.
    pub fn release_attempt(&mut self) {
        self.half_open_inflight = self.half_open_inflight.saturating_sub(1);
    }

    /// Current circuit state.
    pub fn circuit(&self) -> CircuitState {
        self.circuit
    }

    /// Total attempts recorded.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Consecutive failures.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Instant of the last success.
    pub fn last_success(&self) -> Option<Instant> {
        self.last_success
    }

    /// Estimated connection establishment cost in milliseconds.
    pub fn connect_cost_ms(&self) -> f64 {
        self.connect_cost_ms
    }

    /// EWMA latency in milliseconds.
    pub fn ewma_ms(&self) -> f64 {
        self.ewma_ms
    }

    /// Jitter estimate in milliseconds.
    pub fn jitter_ms(&self) -> f64 {
        self.jitter_ms
    }

    fn total(&self) -> f64 {
        self.success + self.timeout + self.server_failure + self.malformed + self.transport_error
    }

    /// Success probability estimate.
    pub fn success_probability(&self) -> f64 {
        let n = self.total();
        if n <= 0.0 {
            return 0.5;
        }
        (self.success + 1.0) / (n + 2.0)
    }

    /// Timeout probability estimate.
    pub fn timeout_probability(&self) -> f64 {
        let n = self.total();
        if n <= 0.0 {
            return 0.0;
        }
        self.timeout / n
    }

    /// SERVFAIL/REFUSED probability estimate.
    pub fn server_failure_probability(&self) -> f64 {
        let n = self.total();
        if n <= 0.0 {
            return 0.0;
        }
        self.server_failure / n
    }

    /// Malformed-response probability estimate.
    pub fn malformed_probability(&self) -> f64 {
        let n = self.total();
        if n <= 0.0 {
            return 0.0;
        }
        self.malformed / n
    }

    /// Width of the one-standard-deviation interval on the success probability.
    pub fn uncertainty(&self) -> f64 {
        let n = self.total() + 2.0;
        let p = self.success_probability();
        ((p * (1.0 - p)) / n).sqrt()
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

    /// Median latency in milliseconds.
    pub fn p50_ms(&self) -> f64 {
        self.percentile(0.5)
    }

    /// 95th percentile latency in milliseconds.
    pub fn p95_ms(&self) -> f64 {
        self.percentile(0.95)
    }

    /// 99th percentile latency in milliseconds.
    pub fn p99_ms(&self) -> f64 {
        self.percentile(0.99)
    }

    /// Expected cost of using this route, in milliseconds. Lower is better.
    pub fn score(&self, weight: u32) -> f64 {
        let base = if self.window_len == 0 {
            // Unknown routes get an optimistic-but-not-free estimate so that a fresh route
            // is tried without immediately displacing a proven one.
            50.0
        } else {
            self.ewma_ms
        };
        let tail = 0.3 * self.p95_ms();
        let jitter = 0.2 * self.jitter_ms;
        let failure = (1.0 - self.success_probability()) * 600.0;
        let streak = if self.consecutive_failures == 0 {
            0.0
        } else {
            50.0 * f64::from(self.consecutive_failures.min(8)).powf(1.6)
        };
        let uncertainty = self.uncertainty() * 40.0;
        let connect = if self.window_len == 0 {
            self.connect_cost_ms * 0.5
        } else {
            0.0
        };
        let weight_bias = 100.0 / f64::from(weight.max(1));
        base + tail + jitter + failure + streak + uncertainty + connect + weight_bias
    }

    /// Delay before a hedge should be started, derived from the configured percentile of
    /// this route's own latency distribution and clamped to the configured bounds.
    pub fn hedge_delay(&self, cfg: &SchedulerConfig) -> Duration {
        let target = if self.window_len == 0 {
            cfg.hedge_min_delay.as_secs_f64() * 1000.0
        } else {
            self.percentile(cfg.hedge_percentile)
        };
        let ms = target.clamp(
            cfg.hedge_min_delay.as_secs_f64() * 1000.0,
            cfg.hedge_max_delay.as_secs_f64() * 1000.0,
        );
        Duration::from_millis(ms.round().max(1.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SchedulerConfig {
        SchedulerConfig::default()
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_route_is_usable() {
        let h = RouteHealth::new();
        assert!(h.is_usable());
        assert_eq!(h.circuit(), CircuitState::Closed);
        assert_eq!(h.success_probability(), 0.5);
    }

    #[tokio::test(start_paused = true)]
    async fn circuit_opens_after_threshold_and_recovers() {
        let now = Instant::now();
        let c = cfg();
        let mut h = RouteHealth::new();
        for _ in 0..c.circuit_failure_threshold {
            h.record(AttemptOutcome::Timeout, None, now, &c);
        }
        assert_eq!(h.circuit(), CircuitState::Open);
        assert!(!h.is_usable());

        // Still open before the wait elapses.
        h.tick(now + Duration::from_secs(1), &c, 1);
        assert_eq!(h.circuit(), CircuitState::Open);

        let later = now + c.circuit_open_duration.mul_f64(2.0);
        h.tick(later, &c, 1);
        assert_eq!(h.circuit(), CircuitState::HalfOpen);
        assert!(h.is_usable());

        h.begin_attempt();
        assert!(!h.is_usable(), "only one half-open probe at a time");
        for _ in 0..c.circuit_half_open_successes {
            h.begin_attempt();
            h.record(
                AttemptOutcome::Success,
                Some(Duration::from_millis(5)),
                later,
                &c,
            );
        }
        assert_eq!(h.circuit(), CircuitState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn half_open_failure_reopens_the_circuit() {
        let now = Instant::now();
        let c = cfg();
        let mut h = RouteHealth::new();
        for _ in 0..c.circuit_failure_threshold {
            h.record(AttemptOutcome::TransportError, None, now, &c);
        }
        let later = now + c.circuit_open_duration.mul_f64(2.0);
        h.tick(later, &c, 3);
        assert_eq!(h.circuit(), CircuitState::HalfOpen);
        h.begin_attempt();
        h.record(AttemptOutcome::Timeout, None, later, &c);
        assert_eq!(h.circuit(), CircuitState::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn outcome_probabilities_are_tracked_separately() {
        let now = Instant::now();
        let c = cfg();
        let mut h = RouteHealth::new();
        for _ in 0..4 {
            h.record(
                AttemptOutcome::Success,
                Some(Duration::from_millis(10)),
                now,
                &c,
            );
        }
        h.record(AttemptOutcome::Timeout, None, now, &c);
        h.record(AttemptOutcome::ServerFailure, None, now, &c);
        h.record(AttemptOutcome::Malformed, None, now, &c);
        assert!(h.timeout_probability() > 0.0);
        assert!(h.server_failure_probability() > 0.0);
        assert!(h.malformed_probability() > 0.0);
        assert!(h.success_probability() > 0.4 && h.success_probability() < 0.7);
    }

    #[tokio::test(start_paused = true)]
    async fn a_faster_route_scores_better() {
        let now = Instant::now();
        let c = cfg();
        let mut fast = RouteHealth::new();
        let mut slow = RouteHealth::new();
        for _ in 0..20 {
            fast.record(
                AttemptOutcome::Success,
                Some(Duration::from_millis(5)),
                now,
                &c,
            );
            slow.record(
                AttemptOutcome::Success,
                Some(Duration::from_millis(120)),
                now,
                &c,
            );
        }
        assert!(fast.score(100) < slow.score(100));
    }

    #[tokio::test(start_paused = true)]
    async fn hedge_delay_is_clamped() {
        let now = Instant::now();
        let c = cfg();
        let mut h = RouteHealth::new();
        assert_eq!(h.hedge_delay(&c), c.hedge_min_delay);
        for _ in 0..32 {
            h.record(
                AttemptOutcome::Success,
                Some(Duration::from_millis(5_000)),
                now,
                &c,
            );
        }
        assert_eq!(h.hedge_delay(&c), c.hedge_max_delay);
    }

    #[tokio::test(start_paused = true)]
    async fn counters_decay_over_time() {
        let now = Instant::now();
        let c = cfg();
        let mut h = RouteHealth::new();
        for _ in 0..10 {
            h.record(AttemptOutcome::Timeout, None, now, &c);
        }
        let p_before = h.success_probability();
        h.record(
            AttemptOutcome::Success,
            Some(Duration::from_millis(5)),
            now + Duration::from_secs(600),
            &c,
        );
        assert!(
            h.success_probability() > p_before + 0.2,
            "old failures should decay: {} -> {}",
            p_before,
            h.success_probability()
        );
    }
}
