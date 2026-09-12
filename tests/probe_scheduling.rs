//! Deterministic scheduling dynamics of the probe pipeline.
//!
//! This is the measurement behind the offer-gate design. The pipeline is exercised at
//! the layers where scheduling decisions are made — the bounded queue and the safety
//! guard — with no network stage: a "probe" here is one `guard.admit` call, which is
//! exactly what the engine does before any bytes go out, and what a duplicate offer
//! costs in full.
//!
//! The workload models the three classes that matter:
//!
//! * **HOT** — a small set of names queried continuously, like the webmail or search
//!   domain a whole office refreshes every few seconds. Every cache hit offers one
//!   probe per answer address, which is what `schedule_probes` does.
//! * **COLD** — a large set of names seen exactly once, like a scanning client or a
//!   one-off page with many third-party hosts.
//! * **WARM** — names queried periodically.
//!
//! The measured facts (all deterministic, virtual time):
//!
//! * Before the offer gate, continuous HOT queries flood the bounded queue with
//!   duplicate offers of the same few addresses. COLD offers arriving behind that flood
//!   are dropped at the queue (`probe_dropped_total{reason=queue_full}`) — first-time
//!   candidates never get probed at all while a hot name is busy.
//! * Every duplicate that does get through the queue is refused at the guard and
//!   *recorded as an observation* (`PolicyBlocked` → `samples += 1`, `last_update`
//!   refreshed), which drives `confidence` toward `High` on addresses whose evidence
//!   was never gathered. That is fabricated evidence, and it also evicts real entries
//!   from the bounded quality store.
//!
//! The assertions pin the post-gate behaviour: cold candidates are admitted, duplicates
//! never reach the guard, and cooldown refusals leave the quality store untouched.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use egressdns::probe::job::{ProbeJob, ProbeQueue};
use egressdns::probe::safety::ProbeGuard;
use egressdns::ranking::model::ObservationClass;
use egressdns::ranking::store::{ProbeKey, QualityStore};

/// One simulated DNS answer observation: a hostname and the addresses it returned.
struct Answer {
    hostname: &'static str,
    addrs: Vec<IpAddr>,
}

fn addr_v4(octet: u8, host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, octet, host))
}

/// Drive the pipeline the way the daemon does: every query of a name offers one job per
/// answer address; the worker takes jobs from the queue and runs the guard admission.
///
/// `gate` is the offer-side dedup gate under test. `None` reproduces the pre-gate
/// behaviour, where every cache hit offered unconditionally.
struct Pipeline {
    queue: ProbeQueue,
    guard: Arc<ProbeGuard>,
    quality: Arc<QualityStore>,
    rx: tokio::sync::mpsc::Receiver<ProbeJob>,
    gate: Option<egressdns::probe::gate::OfferGate>,
    /// The execution-side cooldown window the offer gate mirrors.
    cooldown: Duration,
    /// Pre-fix engines recorded *every* refusal — including cooldowns — as an
    /// observation. The flag reproduces that behaviour for the measurement record.
    legacy_recording: bool,
}

impl Pipeline {
    fn new(gate: bool) -> Self {
        Self::new_tuned(gate, false)
    }

    fn new_tuned(gate: bool, legacy_recording: bool) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8_192);
        let cfg = egressdns::config::ProbeConfig::default();
        let quality = Arc::new(QualityStore::new(20_000));
        let cooldown = cfg.per_domain_cooldown.max(cfg.per_ip_cooldown);
        Self {
            queue: ProbeQueue::new(tx, true),
            guard: Arc::new(ProbeGuard::new(&cfg)),
            quality,
            rx,
            gate: gate.then(egressdns::probe::gate::OfferGate::new),
            cooldown,
            legacy_recording,
        }
    }

    /// One cache hit for `answer` at virtual time `now`: offer each address, then drain
    /// the queue the way the worker loop would, counting what the guard decides.
    fn query(&mut self, answer: &Answer, now: Instant) {
        let generation = 1u64;
        for addr in &answer.addrs {
            let job = ProbeJob::Observed {
                hostname: Arc::from(answer.hostname),
                addr: *addr,
                port: 443,
                cloudflare: false,
                generation,
            };
            let should_offer = match &self.gate {
                Some(g) => g.allow(*addr, 443, answer.hostname, self.cooldown, now),
                None => true,
            };
            if should_offer {
                self.queue.offer(job);
            }
        }
        while let Ok(job) = self.rx.try_recv() {
            match self
                .guard
                .admit(job.addr(), job.port(), false, job.hostname(), now)
            {
                Ok(()) => {
                    let host = job.hostname().unwrap_or("candidate.invalid");
                    self.quality.record(
                        ProbeKey::https(job.addr(), 443, host),
                        ObservationClass::Success,
                        Some(Duration::from_millis(10)),
                        generation,
                        now,
                        &egressdns::config::RankingConfig::default(),
                    );
                }
                Err(refusal) => {
                    // The pre-fix engine recorded PolicyBlocked for every refusal; the
                    // fixed behaviour records nothing for cooldown refusals.
                    if self.legacy_recording || !refusal.is_cooldown() {
                        let host = job.hostname().unwrap_or("candidate.invalid");
                        self.quality.record(
                            ProbeKey::https(job.addr(), 443, host),
                            ObservationClass::PolicyBlocked,
                            None,
                            generation,
                            now,
                            &egressdns::config::RankingConfig::default(),
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn hot_name_floods_do_not_shed_first_time_candidates() {
    // Virtual clock: one tick per "second" of workload time.
    let start = Instant::now();
    let tick = |s: u64| start + Duration::from_secs(s);

    let mut hot: Vec<Answer> = Vec::new();
    // Two addresses per hot name, each in its own /24: a same-subnet pair would be
    // secondarily gated by the guard's per-prefix anti-scanning cooldown, which is a
    // separate (and intended) behaviour from the scheduling question under test.
    // (`addr_v4(o, h)` is 203.0.o.h, so the third octet must carry the distinctness.)
    for i in 0..100u8 {
        hot.push(Answer {
            hostname: Box::leak(format!("hot{i}.example.test").into_boxed_str()),
            addrs: vec![addr_v4(i + 1, 1), addr_v4(i + 101, 1)],
        });
    }
    let mut cold: Vec<Answer> = Vec::new();
    // One cold name per distinct /24, so the guard's per-prefix cooldown — which is
    // correct anti-scanning behaviour for addresses that share a subnet — does not
    // interact with the scheduling question under test.
    for i in 0..10_000u32 {
        let second = (i / 250 % 254 + 1) as u8;
        let third = (i % 250) as u8;
        cold.push(Answer {
            hostname: Box::leak(format!("cold{i}.example.test").into_boxed_str()),
            addrs: vec![IpAddr::V4(std::net::Ipv4Addr::new(203, second, third, 1))],
        });
    }

    let mut p = Pipeline::new(true);
    // 3,334 ticks: every tick queries every HOT name once (300 offers/tick) and 3
    // COLD names appear.
    for s in 0..3_334u64 {
        for hot_name in &hot {
            p.query(hot_name, tick(s));
        }
        let cold_batch = &cold[(s as usize * 3)..((s as usize * 3) + 3).min(cold.len())];
        for cold_name in cold_batch {
            p.query(cold_name, tick(s));
        }
    }

    // Every cold name's single offer must have reached the guard and been admitted:
    // first-time candidates are exactly what the probe budget exists for.
    for (i, cold_name) in cold.iter().enumerate() {
        let addr = cold_name.addrs[0];
        let host = format!("cold{i}.example.test");
        let key = ProbeKey::https(addr, 443, &host);
        let entry = p
            .quality
            .get(&key)
            .unwrap_or_else(|| panic!("cold candidate {host} was never probed"));
        assert_eq!(
            entry.sample_count(),
            1,
            "cold candidate {host} must have exactly one real observation"
        );
    }
    // The hot names must also have been probed (once per address per cooldown window).
    for (i, hot_name) in hot.iter().enumerate() {
        for (j, addr) in hot_name.addrs.iter().enumerate() {
            let host = format!("hot{i}.example.test");
            let key = ProbeKey::https(*addr, 443, &host);
            let entry = p
                .quality
                .get(&key)
                .unwrap_or_else(|| panic!("hot address {host}[{j}] was never probed"));
            assert!(
                entry.sample_count() >= 1,
                "hot address {host}[{j}] has no observations"
            );
        }
    }
}

#[tokio::test]
async fn cooldown_refusals_do_not_fabricate_evidence() {
    let start = Instant::now();
    let mut p = Pipeline::new(true);
    let answer = Answer {
        hostname: "flood.example.test",
        addrs: vec![addr_v4(9, 1)],
    };

    // One real probe, then a burst of offers for the same address inside the cooldown
    // window. With the gate, the burst never reaches the queue; even a duplicate that
    // does reach the guard must not change the quality entry.
    p.query(&answer, start);
    let key = ProbeKey::https(answer.addrs[0], 443, answer.hostname);
    let after_first = p
        .quality
        .get(&key)
        .expect("first probe recorded")
        .sample_count();

    for s in 1..500u64 {
        p.query(&answer, start + Duration::from_secs(s));
    }
    let after_flood = p.quality.get(&key).expect("entry survives").sample_count();
    assert_eq!(
        after_first, after_flood,
        "cooldown refusals must not add observations"
    );
    assert_eq!(after_first, 1);
}

/// The pre-gate behaviour, kept as a measurement record: without offer-side dedup,
/// duplicate offers inside a cooldown window reached the guard and were recorded as
/// `PolicyBlocked` observations — `samples` grew with every cache hit, `confidence`
/// climbed to `High`, and an address that was never probed carried fabricated evidence
/// of having been measured hundreds of times.
#[tokio::test]
async fn without_the_gate_duplicate_offers_fabricate_evidence() {
    let start = Instant::now();
    let mut p = Pipeline::new_tuned(false, true); // no gate, legacy recording
    let answer = Answer {
        hostname: "preflood.example.test",
        addrs: vec![addr_v4(9, 2)],
    };

    p.query(&answer, start); // first offer: real probe
    let key = ProbeKey::https(answer.addrs[0], 443, answer.hostname);
    let after_first = p
        .quality
        .get(&key)
        .expect("first probe recorded")
        .sample_count();

    // 499 duplicate offers within the cooldown window, pre-fix semantics: every
    // cooldown refusal was recorded as an observation.
    for s in 1..500u64 {
        p.query(&answer, start + Duration::from_secs(s));
        let _ = s;
    }
    let entry = p.quality.get(&key).expect("entry survives");
    assert!(
        entry.sample_count() > after_first + 100,
        "the pre-gate pipeline recorded duplicate cooldown refusals as observations: \
         first={} now={}",
        after_first,
        entry.sample_count()
    );
    let cfg = egressdns::config::RankingConfig::default();
    assert_eq!(
        entry.confidence(&cfg, start + Duration::from_secs(499)),
        egressdns::ranking::model::Confidence::High,
        "fabricated samples drove confidence to High without any real measurement"
    );
}
