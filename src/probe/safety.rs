//! Probe safety: what may be dialled, how often, and from where.
//!
//! DNS answers are attacker-influenced input. Without these checks a hostile or merely
//! misconfigured upstream could steer the probe engine at loopback services, link-local
//! metadata endpoints or internal networks — a textbook SSRF. The rules are therefore
//! deny-by-default and expressed as data, not as scattered conditionals.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use tokio::time::Instant;

use crate::config::ProbeConfig;
use crate::error::ProbeError;

/// Why a probe target was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The address is in a special-use range and not explicitly allowed.
    SpecialUse,
    /// The port is neither declared by a record nor explicitly configured.
    PortNotAllowed,
    /// The address is still inside its cooldown window.
    AddressCooldown,
    /// The covering prefix is still inside its cooldown window.
    PrefixCooldown,
    /// The hostname is still inside its cooldown window.
    DomainCooldown,
    /// The global new-connection rate limit is exhausted.
    RateLimited,
    /// The daily bandwidth budget for throughput measurement is exhausted.
    BandwidthBudget,
}

impl Refusal {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::SpecialUse => "special_use",
            Self::PortNotAllowed => "port_not_allowed",
            Self::AddressCooldown => "address_cooldown",
            Self::PrefixCooldown => "prefix_cooldown",
            Self::DomainCooldown => "domain_cooldown",
            Self::RateLimited => "rate_limited",
            Self::BandwidthBudget => "bandwidth_budget",
        }
    }

    /// Whether the refusal means "already observed recently".
    ///
    /// Cooldown refusals carry no information about the address: nothing was measured
    /// and nothing changed. Recording them as observations would fabricate evidence
    /// (`samples` grows, `last_update` refreshes, `confidence` climbs) for an address
    /// the probe engine never touched, so the engine skips the quality write for this
    /// class entirely.
    pub fn is_cooldown(self) -> bool {
        matches!(
            self,
            Self::AddressCooldown | Self::PrefixCooldown | Self::DomainCooldown
        )
    }

    /// Convert to the public error type.
    pub fn into_error(self) -> ProbeError {
        ProbeError::PolicyBlocked {
            reason: self.label(),
        }
    }
}

/// Cooldown and rate-limit bookkeeping.
pub struct ProbeGuard {
    /// Limits derived from configuration, replaced on reload so the guard follows
    /// `probe.*` changes without being rebuilt and without losing its cooldown state.
    limits: RwLock<GuardLimits>,
    state: Mutex<GuardState>,
}

#[derive(Clone)]
struct GuardLimits {
    allow_special: Vec<IpNet>,
    allowed_ports: Vec<u16>,
    per_ip: Duration,
    per_prefix: Duration,
    per_domain: Duration,
    connections_per_second: u32,
    daily_bandwidth: u64,
}

impl GuardLimits {
    fn from_config(cfg: &ProbeConfig) -> Self {
        let mut allowed_ports = cfg.extra_ports.clone();
        allowed_ports.sort_unstable();
        allowed_ports.dedup();
        Self {
            allow_special: cfg.allow_special_use_targets.clone(),
            allowed_ports,
            per_ip: cfg.per_ip_cooldown,
            per_prefix: cfg.per_prefix_cooldown,
            per_domain: cfg.per_domain_cooldown,
            connections_per_second: cfg.global_connections_per_second,
            daily_bandwidth: cfg.daily_bandwidth_budget_bytes,
        }
    }
}

struct GuardState {
    ip_seen: HashMap<IpAddr, Instant>,
    prefix_seen: HashMap<(IpAddr, u8), Instant>,
    domain_seen: HashMap<(String, IpAddr), Instant>,
    window_start: Option<Instant>,
    window_count: u32,
    bandwidth_day: Option<Instant>,
    bandwidth_used: u64,
    last_prune: Option<Instant>,
}

impl ProbeGuard {
    /// Build a guard from configuration.
    pub fn new(cfg: &ProbeConfig) -> Self {
        Self {
            limits: RwLock::new(GuardLimits::from_config(cfg)),
            state: Mutex::new(GuardState {
                ip_seen: HashMap::new(),
                prefix_seen: HashMap::new(),
                domain_seen: HashMap::new(),
                window_start: None,
                window_count: 0,
                bandwidth_day: None,
                bandwidth_used: 0,
                last_prune: None,
            }),
        }
    }

    /// Adopt new limits after a configuration reload. Accumulated cooldown and budget
    /// state is kept: a reload is not a licence to re-probe everything immediately.
    pub fn update_limits(&self, cfg: &ProbeConfig) {
        *self.limits.write() = GuardLimits::from_config(cfg);
    }

    /// Whether an address may be probed at all, ignoring cooldowns.
    pub fn address_allowed(&self, addr: IpAddr) -> bool {
        let limits = self.limits.read();
        match crate::util::ipclass::classify(addr) {
            None => true,
            Some(class) => {
                // Link-local and cloud metadata are never probeable, even with an
                // explicit exception, because the blast radius is too large.
                if matches!(
                    class,
                    crate::util::ipclass::SpecialUse::LinkLocal
                        | crate::util::ipclass::SpecialUse::CloudMetadata
                        | crate::util::ipclass::SpecialUse::Loopback
                        | crate::util::ipclass::SpecialUse::Multicast
                        | crate::util::ipclass::SpecialUse::Unspecified
                ) {
                    return false;
                }
                limits.allow_special.iter().any(|n| n.contains(&addr))
            }
        }
    }

    /// Whether a port may be probed.
    ///
    /// A port is allowed when it was declared by the service itself, for example through
    /// an HTTPS or SVCB `port` parameter or an SRV record, or when the administrator listed
    /// it. There is never a port range scan.
    pub fn port_allowed(&self, port: u16, declared: bool) -> bool {
        port != 0 && (declared || self.limits.read().allowed_ports.contains(&port))
    }

    /// Full admission check for one probe.
    pub fn admit(
        &self,
        addr: IpAddr,
        port: u16,
        declared_port: bool,
        hostname: Option<&str>,
        now: Instant,
    ) -> Result<(), Refusal> {
        if !self.address_allowed(addr) {
            return Err(Refusal::SpecialUse);
        }
        if !self.port_allowed(port, declared_port) {
            return Err(Refusal::PortNotAllowed);
        }

        let limits = self.limits.read().clone();
        let mut state = self.state.lock();

        // The daily bandwidth budget is an admission gate, not an afterthought. Checking
        // it only after a probe has run would let the budget be exceeded by the whole of
        // the last probe, and never checking it in production makes the setting
        // decorative.
        if state.bandwidth_used >= limits.daily_bandwidth {
            let expired = match state.bandwidth_day {
                None => true,
                Some(start) => now.saturating_duration_since(start) >= Duration::from_secs(86_400),
            };
            if expired {
                state.bandwidth_day = Some(now);
                state.bandwidth_used = 0;
            } else {
                return Err(Refusal::BandwidthBudget);
            }
        }

        // Global connection-rate limit, evaluated over a one-second window.
        let reset = match state.window_start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= Duration::from_secs(1),
        };
        if reset {
            state.window_start = Some(now);
            state.window_count = 0;
        }
        if state.window_count >= limits.connections_per_second {
            return Err(Refusal::RateLimited);
        }

        if let Some(last) = state.ip_seen.get(&addr) {
            if now.saturating_duration_since(*last) < limits.per_ip {
                return Err(Refusal::AddressCooldown);
            }
        }
        let prefix = covering_prefix(addr);
        if let Some(last) = state.prefix_seen.get(&prefix) {
            if now.saturating_duration_since(*last) < limits.per_prefix {
                return Err(Refusal::PrefixCooldown);
            }
        }
        if let Some(host) = hostname {
            // Keyed by (hostname, address): a multi-address name must be able to learn
            // about *each* of its addresses, which is the point of probing it. Keying by
            // hostname alone let the first address's admission block every other
            // address of the same name forever under demand-driven offers, leaving all
            // but one address permanently neutral. Abuse is still bounded: each pair is
            // gated by this cooldown, each address by the per-IP and per-prefix
            // cooldowns, and the whole engine by the global rate limit and the daily
            // bandwidth budget.
            if let Some(last) = state.domain_seen.get(&(host.to_owned(), addr)) {
                if now.saturating_duration_since(*last) < limits.per_domain {
                    return Err(Refusal::DomainCooldown);
                }
            }
        }

        state.window_count += 1;
        state.ip_seen.insert(addr, now);
        state.prefix_seen.insert(prefix, now);
        if let Some(host) = hostname {
            state.domain_seen.insert((host.to_owned(), addr), now);
        }
        prune(&mut state, now, limits.per_ip.max(limits.per_domain));
        Ok(())
    }

    /// Record bytes actually spent by a completed probe.
    ///
    /// Accounting is after the fact because the true cost is only known once the exchange
    /// has finished; the *gate* is in `admit`, which refuses new probes once the budget is
    /// spent. Returns the remaining budget.
    pub fn consume_bandwidth(&self, bytes: u64, now: Instant) -> u64 {
        let limits = self.limits.read().clone();
        let mut state = self.state.lock();
        let reset = match state.bandwidth_day {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= Duration::from_secs(86_400),
        };
        if reset {
            state.bandwidth_day = Some(now);
            state.bandwidth_used = 0;
        }
        state.bandwidth_used = state.bandwidth_used.saturating_add(bytes);
        metrics::counter!(crate::metrics::names::PROBE_BANDWIDTH_BYTES).increment(bytes);
        limits.daily_bandwidth.saturating_sub(state.bandwidth_used)
    }

    /// Bytes consumed from the daily budget.
    pub fn bandwidth_used(&self) -> u64 {
        self.state.lock().bandwidth_used
    }

    /// Number of tracked cooldown entries, for metrics.
    pub fn tracked(&self) -> usize {
        let s = self.state.lock();
        s.ip_seen.len() + s.prefix_seen.len() + s.domain_seen.len()
    }
}

/// The prefix used for per-prefix cooldowns: /24 for IPv4, /48 for IPv6.
fn covering_prefix(addr: IpAddr) -> (IpAddr, u8) {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4) & 0xffff_ff00;
            (IpAddr::V4(std::net::Ipv4Addr::from(bits)), 24)
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 80) - 1);
            (IpAddr::V6(std::net::Ipv6Addr::from(bits)), 48)
        }
    }
}

/// Drop cooldown entries that can no longer refuse anything.
///
/// Two properties matter and the previous "sweep only past 200k entries" rule had neither.
/// An entry older than its cooldown is dead weight, and `domain_seen` keys are
/// attacker-influenced hostnames of up to 253 bytes. And the sweep runs under the state
/// mutex on the probe path, so it must be bounded: sweeping the whole map on every
/// admission once the map is large turns a cheap check into an O(n) scan under a lock.
fn prune(state: &mut GuardState, now: Instant, horizon: Duration) {
    /// Hard ceiling per map. Reaching it is already pathological.
    const MAX_ENTRIES: usize = 50_000;
    /// Minimum interval between sweeps.
    const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

    let due = match state.last_prune {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= SWEEP_INTERVAL,
    };
    let over = state.ip_seen.len() > MAX_ENTRIES
        || state.prefix_seen.len() > MAX_ENTRIES
        || state.domain_seen.len() > MAX_ENTRIES;
    if !due && !over {
        return;
    }
    state.last_prune = Some(now);

    state
        .ip_seen
        .retain(|_, t| now.saturating_duration_since(*t) < horizon);
    state
        .prefix_seen
        .retain(|_, t| now.saturating_duration_since(*t) < horizon);
    state
        .domain_seen
        .retain(|_, t| now.saturating_duration_since(*t) < horizon);

    // If everything is still inside its cooldown the retain frees nothing, so a hard
    // ceiling applies: drop the oldest. Losing a cooldown record costs at most one extra
    // probe; unbounded memory is not recoverable.
    truncate_oldest(&mut state.ip_seen, MAX_ENTRIES);
    truncate_oldest(&mut state.prefix_seen, MAX_ENTRIES);
    truncate_oldest(&mut state.domain_seen, MAX_ENTRIES);
}

/// Keep only the `limit` most recent entries of a cooldown map.
fn truncate_oldest<K: Clone + std::hash::Hash + Eq>(map: &mut HashMap<K, Instant>, limit: usize) {
    if map.len() <= limit {
        return;
    }
    let mut times: Vec<Instant> = map.values().copied().collect();
    times.sort_unstable();
    let cutoff = times[map.len() - limit];
    map.retain(|_, t| *t >= cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    fn guard(cfg: ProbeConfig) -> ProbeGuard {
        ProbeGuard::new(&cfg)
    }

    fn permissive() -> ProbeConfig {
        ProbeConfig {
            per_ip_cooldown: Duration::from_secs(0),
            per_prefix_cooldown: Duration::from_secs(0),
            per_domain_cooldown: Duration::from_secs(0),
            global_connections_per_second: 1_000,
            ..ProbeConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn special_use_targets_are_refused() {
        let g = guard(permissive());
        let now = Instant::now();
        for bad in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "::1",
            "fe80::1",
            "224.0.0.1",
            "0.0.0.0",
            "fd00:ec2::254",
        ] {
            assert_eq!(
                g.admit(ip(bad), 443, false, None, now),
                Err(Refusal::SpecialUse),
                "{bad} must be refused"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_exception_allows_private_but_never_link_local() {
        let cfg = ProbeConfig {
            allow_special_use_targets: vec![
                IpNet::from_str("10.0.0.0/8").expect("net"),
                IpNet::from_str("169.254.0.0/16").expect("net"),
            ],
            ..permissive()
        };
        let g = guard(cfg);
        let now = Instant::now();
        assert!(g.admit(ip("10.1.2.3"), 443, false, None, now).is_ok());
        assert_eq!(
            g.admit(ip("169.254.169.254"), 443, false, None, now),
            Err(Refusal::SpecialUse),
            "metadata must stay unreachable even with an exception"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_declared_or_configured_ports_are_probed() {
        let g = guard(permissive());
        let now = Instant::now();
        assert!(g.admit(ip("104.16.0.1"), 443, false, None, now).is_ok());
        assert_eq!(
            g.admit(ip("104.16.0.2"), 8443, false, None, now),
            Err(Refusal::PortNotAllowed)
        );
        assert!(
            g.admit(ip("104.16.0.3"), 8443, true, None, now).is_ok(),
            "a port declared by an HTTPS/SVCB or SRV record is allowed"
        );
        assert_eq!(
            g.admit(ip("104.16.0.4"), 0, true, None, now),
            Err(Refusal::PortNotAllowed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cooldowns_are_enforced_per_address_prefix_and_domain() {
        let cfg = ProbeConfig {
            per_ip_cooldown: Duration::from_secs(60),
            per_prefix_cooldown: Duration::from_secs(30),
            per_domain_cooldown: Duration::from_secs(90),
            global_connections_per_second: 1_000,
            ..ProbeConfig::default()
        };
        let g = guard(cfg);
        let now = Instant::now();
        assert!(g
            .admit(ip("104.16.0.1"), 443, false, Some("a.example"), now)
            .is_ok());
        assert_eq!(
            g.admit(ip("104.16.0.1"), 443, false, Some("b.example"), now),
            Err(Refusal::AddressCooldown)
        );
        assert_eq!(
            g.admit(ip("104.16.0.2"), 443, false, Some("b.example"), now),
            Err(Refusal::PrefixCooldown)
        );
        let later = now + Duration::from_secs(31);
        assert!(g
            .admit(ip("104.16.0.2"), 443, false, Some("b.example"), later)
            .is_ok());
        // The domain cooldown is keyed by (hostname, address): a multi-address name
        // must be able to learn about each of its addresses, so a *different* address
        // of the same domain is admitted, while the *same* pair is refused until the
        // domain cooldown elapses.
        let much_later = now + Duration::from_secs(91);
        assert!(g
            .admit(ip("104.16.1.9"), 443, false, Some("b.example"), much_later)
            .is_ok());
        // 100s: the per-IP cooldown on 104.16.0.2 (60s from its 31s admission) has
        // elapsed, so the *domain* refusal is what this assert observes.
        assert_eq!(
            g.admit(
                ip("104.16.0.2"),
                443,
                false,
                Some("b.example"),
                now + Duration::from_secs(100)
            ),
            Err(Refusal::DomainCooldown)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn global_connection_rate_is_bounded() {
        let cfg = ProbeConfig {
            global_connections_per_second: 3,
            ..permissive()
        };
        let g = guard(cfg);
        let now = Instant::now();
        let mut allowed = 0;
        for i in 0..50u32 {
            let a = ip(&format!("104.{}.{}.1", i / 256, i % 256));
            if g.admit(a, 443, false, None, now).is_ok() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3);
        let later = now + Duration::from_secs(2);
        assert!(g.admit(ip("172.64.9.9"), 443, false, None, later).is_ok());
    }

    /// The daily bandwidth budget must gate admission, not merely be counted.
    ///
    /// Charging bytes after a probe has already run made the setting decorative: the
    /// counter grew and nothing ever consulted it, so a misconfigured deployment could
    /// exceed its budget indefinitely. `admit` now refuses once the budget is spent, and
    /// the refusal clears when the day rolls over.
    #[tokio::test(start_paused = true)]
    async fn bandwidth_budget_gates_admission_and_resets_daily() {
        let cfg = ProbeConfig {
            daily_bandwidth_budget_bytes: 1_000,
            ..permissive()
        };
        let g = guard(cfg);
        let now = Instant::now();
        let addr = ip("104.16.5.9");
        assert!(g.admit(addr, 443, false, None, now).is_ok());

        assert_eq!(g.consume_bandwidth(600, now), 400);
        assert_eq!(g.consume_bandwidth(300, now), 100);
        assert_eq!(g.bandwidth_used(), 900);
        // Still under budget, so admission continues.
        assert!(g.admit(ip("104.16.5.10"), 443, false, None, now).is_ok());

        // Spending the rest closes the gate.
        assert_eq!(g.consume_bandwidth(300, now), 0);
        assert_eq!(
            g.admit(ip("104.16.5.11"), 443, false, None, now),
            Err(Refusal::BandwidthBudget)
        );

        // A new day resets the budget and reopens admission.
        let tomorrow = now + Duration::from_secs(86_401);
        assert!(g
            .admit(ip("104.16.5.12"), 443, false, None, tomorrow)
            .is_ok());
        assert_eq!(g.bandwidth_used(), 0);
    }

    /// A reload must be able to change the budget without restarting the process.
    #[tokio::test(start_paused = true)]
    async fn updating_limits_changes_the_bandwidth_gate() {
        let g = guard(ProbeConfig {
            daily_bandwidth_budget_bytes: 1_000,
            ..permissive()
        });
        let now = Instant::now();
        let _ = g.consume_bandwidth(1_000, now);
        assert_eq!(
            g.admit(ip("104.16.5.9"), 443, false, None, now),
            Err(Refusal::BandwidthBudget)
        );
        g.update_limits(&ProbeConfig {
            daily_bandwidth_budget_bytes: 10_000,
            ..permissive()
        });
        assert!(
            g.admit(ip("104.16.5.9"), 443, false, None, now).is_ok(),
            "raising the budget by reload must reopen admission"
        );
    }

    #[test]
    fn covering_prefix_is_a_slash_24_and_slash_48() {
        assert_eq!(covering_prefix(ip("104.16.5.9")), (ip("104.16.5.0"), 24));
        let (base, len) = covering_prefix(ip("2606:4700:1234:5678::1"));
        assert_eq!(len, 48);
        assert_eq!(base, ip("2606:4700:1234::"));
    }
}
