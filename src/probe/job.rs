//! Probe work items.
//!
//! Jobs are produced by the foreground path and by background schedulers, and consumed by
//! the probe engine. The queue is bounded: when it is full, jobs are dropped and counted
//! rather than queued, because a probe is an optional observation and must never apply
//! backpressure to DNS.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A unit of probe work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeJob {
    /// An address observed in a real DNS answer for a hostname.
    Observed {
        /// Origin hostname the address was returned for.
        hostname: Arc<str>,
        /// The address.
        addr: IpAddr,
        /// Port implied by the service, defaulting to 443.
        port: u16,
        /// Whether the address is inside the official Cloudflare prefix snapshot.
        cloudflare: bool,
        /// Network generation the observation belongs to.
        generation: u64,
    },
    /// A Cloudflare candidate that needs its generic stages re-run.
    Candidate {
        /// The address.
        addr: IpAddr,
        /// Port to probe.
        port: u16,
        /// Network generation.
        generation: u64,
    },
    /// Domain-level validation of a candidate for a specific hostname.
    Validate {
        /// Origin hostname used for SNI and HTTP authority.
        hostname: Arc<str>,
        /// Candidate address.
        addr: IpAddr,
        /// Port.
        port: u16,
        /// Network generation.
        generation: u64,
    },
    /// Baseline validation of an original upstream address for a hostname.
    Baseline {
        /// Origin hostname.
        hostname: Arc<str>,
        /// Original address.
        addr: IpAddr,
        /// Port.
        port: u16,
        /// Network generation.
        generation: u64,
    },
}

impl ProbeJob {
    /// The address this job targets.
    pub fn addr(&self) -> IpAddr {
        match self {
            Self::Observed { addr, .. }
            | Self::Candidate { addr, .. }
            | Self::Validate { addr, .. }
            | Self::Baseline { addr, .. } => *addr,
        }
    }

    /// The port this job targets.
    pub fn port(&self) -> u16 {
        match self {
            Self::Observed { port, .. }
            | Self::Candidate { port, .. }
            | Self::Validate { port, .. }
            | Self::Baseline { port, .. } => *port,
        }
    }

    /// The hostname this job is about, when it is hostname-specific.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::Observed { hostname, .. }
            | Self::Validate { hostname, .. }
            | Self::Baseline { hostname, .. } => Some(hostname),
            Self::Candidate { .. } => None,
        }
    }

    /// Network generation.
    pub fn generation(&self) -> u64 {
        match self {
            Self::Observed { generation, .. }
            | Self::Candidate { generation, .. }
            | Self::Validate { generation, .. }
            | Self::Baseline { generation, .. } => *generation,
        }
    }

    /// Bounded metrics label.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Observed { .. } => "observed",
            Self::Candidate { .. } => "candidate",
            Self::Validate { .. } => "validate",
            Self::Baseline { .. } => "baseline",
        }
    }
}

/// A bounded, non-blocking probe queue handle.
///
/// The enable flag is a live `AtomicBool` rather than the presence of a channel, so that
/// `probe.enabled` can be turned on and off by a configuration reload. Building the queue
/// conditionally would silently make the setting startup-only.
#[derive(Clone)]
pub struct ProbeQueue {
    tx: Option<tokio::sync::mpsc::Sender<ProbeJob>>,
    enabled: Arc<AtomicBool>,
}

impl ProbeQueue {
    /// A queue that discards everything, used in tests and where probing can never run.
    pub fn disabled() -> Self {
        Self {
            tx: None,
            enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Wrap a sender with an initial enable state.
    pub fn new(tx: tokio::sync::mpsc::Sender<ProbeJob>, enabled: bool) -> Self {
        Self {
            tx: Some(tx),
            enabled: Arc::new(AtomicBool::new(enabled)),
        }
    }

    /// Whether probing is enabled right now.
    pub fn is_enabled(&self) -> bool {
        self.tx.is_some() && self.enabled.load(Ordering::Relaxed)
    }

    /// Turn probing on or off. Shared with every clone of this handle.
    pub fn set_enabled(&self, enabled: bool) {
        if self.enabled.swap(enabled, Ordering::Relaxed) != enabled {
            tracing::info!(event = "probe.enabled_changed", enabled);
        }
    }

    /// Offer a job. Never blocks; a full queue drops the job and counts it.
    pub fn offer(&self, job: ProbeJob) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        let Some(tx) = &self.tx else {
            return false;
        };
        let kind = job.kind();
        match tx.try_send(job) {
            Ok(()) => true,
            Err(_) => {
                metrics::counter!(
                    crate::metrics::names::PROBE_DROPPED_TOTAL,
                    "reason" => "queue_full",
                    "kind" => kind,
                )
                .increment(1);
                false
            }
        }
    }

    /// Approximate queue depth.
    pub fn depth(&self) -> usize {
        self.tx
            .as_ref()
            .map(|t| t.max_capacity() - t.capacity())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn job(n: u8) -> ProbeJob {
        ProbeJob::Candidate {
            addr: IpAddr::from_str(&format!("104.16.0.{n}")).expect("ip"),
            port: 443,
            generation: 1,
        }
    }

    #[tokio::test]
    async fn disabled_queue_drops_everything() {
        let q = ProbeQueue::disabled();
        assert!(!q.is_enabled());
        assert!(!q.offer(job(1)));
        assert_eq!(q.depth(), 0);
    }

    #[tokio::test]
    async fn full_queue_drops_without_blocking() {
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        let q = ProbeQueue::new(tx, true);
        assert!(q.offer(job(1)));
        assert!(q.offer(job(2)));
        assert!(!q.offer(job(3)), "third job must be dropped");
        assert_eq!(q.depth(), 2);
    }

    #[tokio::test]
    async fn accessors_are_consistent() {
        let j = ProbeJob::Validate {
            hostname: Arc::from("www.example.com"),
            addr: IpAddr::from_str("104.16.0.1").expect("ip"),
            port: 8443,
            generation: 3,
        };
        assert_eq!(j.port(), 8443);
        assert_eq!(j.hostname(), Some("www.example.com"));
        assert_eq!(j.generation(), 3);
        assert_eq!(j.kind(), "validate");
    }
}
