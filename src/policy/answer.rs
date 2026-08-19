//! Application of answer policy to a complete upstream response.
//!
//! The rules enforced here are the correctness contract:
//!
//! * Preserve mode reorders addresses inside one complete A or AAAA RRset and does nothing
//!   else. The output is always a permutation of the input.
//! * Verified-augment prepends at most `max_added` verified Cloudflare addresses and keeps
//!   every original address after de-duplication.
//! * No other record type is ever touched: CNAME, DNAME, MX, SRV, HTTPS, SVCB, DNSKEY, DS,
//!   RRSIG, NSEC, NSEC3 and unknown types pass through byte for byte.
//! * The original upstream order is the final tie-breaker everywhere.
//! * Answers from different upstreams are never combined.

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::time::Instant;

use crate::cache::DnssecStatus;
use crate::cloudflare::prefixes::PrefixSnapshot;
use crate::config::{AugmentConfig, CloudflareMode, RankingConfig, TtlConfig};
use crate::policy::cloudflare::{self as cfpolicy, Eligibility, FallbackReason};
use crate::policy::ttl::{effective_client_ttl, TtlInputs, TtlReason};
use crate::ranking::{order_addresses, OrderDecision, QualityStats};

/// A Cloudflare address that has passed domain-level validation for this exact hostname.
#[derive(Debug, Clone)]
pub struct VerifiedCandidate {
    /// The address.
    pub addr: IpAddr,
    /// Number of successful domain-level validations.
    pub successes: u32,
    /// Expected cost in milliseconds, from the quality model.
    pub cost_ms: f64,
    /// Number of quality observations behind `cost_ms`.
    ///
    /// An address with no measurements scores *neutral*, not bad — which is correct for
    /// ranking, but means an unmeasured candidate can outrank a genuinely slow original
    /// address on no evidence at all. `augment.min_samples` uses this to require real
    /// evidence before an address is added to an answer.
    pub samples: u32,
    /// Whether the validation result is still inside its validity window.
    pub fresh: bool,
}

/// Everything the policy needs to decide.
pub struct AnswerContext<'a> {
    /// Query type.
    pub qtype: RecordType,
    /// DNSSEC state of the answer.
    pub dnssec: DnssecStatus,
    /// Cloudflare subsystem enabled.
    pub cloudflare_enabled: bool,
    /// Configured Cloudflare mode.
    pub cloudflare_mode: CloudflareMode,
    /// Current official prefix snapshot.
    pub snapshot: Option<&'a PrefixSnapshot>,
    /// Domain is excluded by allow/deny policy.
    pub domain_excluded: bool,
    /// At least one original address passed a baseline TLS or HTTP validation.
    pub baseline_validated: bool,
    /// Verified candidates for this hostname, best first.
    pub verified: &'a [VerifiedCandidate],
    /// This build can validate the published ECH configuration end to end.
    pub can_validate_ech: bool,
    /// Quality statistics keyed by address.
    pub quality: &'a HashMap<IpAddr, QualityStats>,
    /// Ranking policy.
    pub ranking: &'a RankingConfig,
    /// Verified-augment limits.
    pub augment: &'a AugmentConfig,
    /// TTL policy.
    pub ttl: &'a TtlConfig,
    /// Remaining authoritative TTL of the cached entry.
    pub remaining_authoritative: u32,
    /// Remaining RRSIG lifetime, when the answer is signed.
    pub remaining_signature: Option<u32>,
    /// The answer is being served from the stale cache.
    pub is_stale: bool,
    /// The network generation changed recently.
    pub recent_network_change: bool,
    /// Monotonic now.
    pub now: Instant,
    /// Deterministic exploration seed.
    pub explore_seed: u64,
}

/// What the policy did.
#[derive(Debug, Clone, PartialEq)]
pub struct AnswerOutcome {
    /// Cloudflare mode actually applied.
    pub cloudflare_applied: Eligibility,
    /// Why a stronger mode was not used.
    pub fallback: Option<FallbackReason>,
    /// Ordering decision.
    pub order: OrderDecision,
    /// Number of verified addresses prepended.
    pub added: usize,
    /// Effective client-facing TTL.
    pub client_ttl: u32,
    /// Why that TTL was chosen.
    pub ttl_reason: TtlReason,
    /// True when the answer was modified in a way that forbids claiming AD.
    pub modified: bool,
}

/// Apply the answer policy in place.
pub fn apply_answer_policy(msg: &mut Message, ctx: &AnswerContext<'_>) -> AnswerOutcome {
    let target = match ctx.qtype {
        RecordType::A => Some(RecordType::A),
        RecordType::AAAA => Some(RecordType::AAAA),
        _ => None,
    };

    let mut outcome = AnswerOutcome {
        cloudflare_applied: Eligibility::Off,
        fallback: None,
        order: OrderDecision::Disabled,
        added: 0,
        client_ttl: 0,
        ttl_reason: TtlReason::Default,
        modified: false,
    };

    let Some(rtype) = target else {
        finish_ttl(msg, ctx, &mut outcome, false, false, false);
        return outcome;
    };

    let groups = rrset_groups(msg, rtype);
    if groups.is_empty() {
        finish_ttl(msg, ctx, &mut outcome, false, false, false);
        return outcome;
    }

    let single_rrset = groups.len() == 1;
    // The RRset that answers the query is the last one in the answer section, which is the
    // end of any CNAME chain.
    let final_group = groups.len() - 1;
    let final_addresses = addresses_of(msg, &groups[final_group].1);

    let (eligibility, fallback) = cfpolicy::evaluate(cfpolicy::EligibilityInputs {
        mode: ctx.cloudflare_mode,
        enabled: ctx.cloudflare_enabled,
        qtype: ctx.qtype,
        dnssec: ctx.dnssec,
        snapshot: ctx.snapshot,
        original: &final_addresses,
        single_rrset,
        excluded: ctx.domain_excluded,
        publishes_ech: cfpolicy::publishes_ech(msg),
        can_validate_ech: ctx.can_validate_ech,
        baseline_validated: ctx.baseline_validated,
        has_verified_candidate: ctx
            .verified
            .iter()
            .any(|v| v.fresh && v.successes >= ctx.augment.min_validations),
    });
    outcome.cloudflare_applied = eligibility;
    outcome.fallback = fallback;

    // ---- 1. Ordering, applied independently to every complete RRset -------------------
    let mut any_reorder = false;
    let mut last_decision = OrderDecision::Disabled;
    for (_, indices) in &groups {
        let original = addresses_of(msg, indices);
        if original.len() < 2 {
            continue;
        }
        let ordering = order_addresses(
            &original,
            ctx.quality,
            ctx.ranking,
            ctx.now,
            ctx.explore_seed,
        );
        last_decision = ordering.decision;
        if ordering.addresses != original {
            reorder_in_place(msg, indices, &original, &ordering.addresses);
            any_reorder = true;
        }
    }
    outcome.order = last_decision;

    // ---- 2. Verified augmentation ----------------------------------------------------
    let mut augmented = false;
    if eligibility == Eligibility::Augment {
        let snapshot = ctx.snapshot;
        let mut to_add: Vec<IpAddr> = Vec::new();
        let existing: Vec<IpAddr> = addresses_of(msg, &groups[final_group].1);
        let best_original_cost = existing
            .iter()
            .filter_map(|a| ctx.quality.get(a))
            .map(|s| s.expected_cost(ctx.ranking, ctx.now))
            .fold(f64::INFINITY, f64::min);
        for candidate in ctx.verified {
            if to_add.len() >= ctx.augment.max_added {
                break;
            }
            if !candidate.fresh || candidate.successes < ctx.augment.min_validations {
                continue;
            }
            // Adding an address to a DNS answer is a stronger action than reordering one,
            // so it requires evidence rather than the absence of counter-evidence.
            if candidate.samples < ctx.augment.min_samples {
                continue;
            }
            // Family must match the queried type.
            if candidate.addr.is_ipv4() != matches!(rtype, RecordType::A) {
                continue;
            }
            // Re-check membership against the *current* snapshot at the moment of use.
            if !snapshot
                .map(|s| s.contains(candidate.addr))
                .unwrap_or(false)
            {
                continue;
            }
            if crate::util::ipclass::classify(candidate.addr).is_some() {
                continue;
            }
            if existing.contains(&candidate.addr) || to_add.contains(&candidate.addr) {
                continue;
            }
            // Require a confidence-adjusted advantage over the best original address.
            if best_original_cost.is_finite() {
                let advantage =
                    (best_original_cost - candidate.cost_ms) / best_original_cost.max(1.0);
                if advantage < ctx.augment.min_advantage {
                    continue;
                }
            }
            to_add.push(candidate.addr);
        }
        if to_add.is_empty() {
            outcome.cloudflare_applied = Eligibility::Preserve;
            outcome.fallback = Some(FallbackReason::NoVerifiedCandidate);
        } else {
            let ttl = group_ttl(msg, &groups[final_group].1);
            let owner = groups[final_group].0.clone();
            prepend_addresses(msg, &groups[final_group].1, &owner, ttl, &to_add, rtype);
            outcome.added = to_add.len();
            augmented = true;
        }
    }

    let cloudflare_touched = matches!(
        outcome.cloudflare_applied,
        Eligibility::Preserve | Eligibility::Augment
    ) && (any_reorder || augmented);

    outcome.modified = augmented;
    finish_ttl(
        msg,
        ctx,
        &mut outcome,
        augmented,
        cloudflare_touched && !augmented,
        any_reorder && !cloudflare_touched,
    );
    outcome
}

fn finish_ttl(
    msg: &mut Message,
    ctx: &AnswerContext<'_>,
    outcome: &mut AnswerOutcome,
    augmented: bool,
    cf_preserved: bool,
    optimized_multi: bool,
) {
    let (ttl, reason) = effective_client_ttl(
        ctx.ttl,
        TtlInputs {
            remaining_authoritative: ctx.remaining_authoritative,
            remaining_signature: ctx.remaining_signature,
            is_stale: ctx.is_stale,
            recent_network_change: ctx.recent_network_change,
            cloudflare_augmented: augmented,
            cloudflare_preserved: cf_preserved,
            optimized_multi,
        },
    );
    outcome.client_ttl = ttl;
    outcome.ttl_reason = reason;
    crate::dns::message::cap_ttls(msg, ttl);
}

/// Group answer-section indices by owner name for one record type, preserving order.
fn rrset_groups(msg: &Message, rtype: RecordType) -> Vec<(Name, Vec<usize>)> {
    let mut groups: Vec<(Name, Vec<usize>)> = Vec::new();
    for (i, r) in msg.answers.iter().enumerate() {
        if r.record_type() != rtype {
            continue;
        }
        match groups.iter_mut().find(|(n, _)| *n == r.name) {
            Some((_, idx)) => idx.push(i),
            None => groups.push((r.name.clone(), vec![i])),
        }
    }
    groups
}

fn addresses_of(msg: &Message, indices: &[usize]) -> Vec<IpAddr> {
    indices
        .iter()
        .filter_map(|i| msg.answers.get(*i))
        .filter_map(record_address)
        .collect()
}

fn record_address(r: &Record) -> Option<IpAddr> {
    match &r.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

fn group_ttl(msg: &Message, indices: &[usize]) -> u32 {
    indices
        .iter()
        .filter_map(|i| msg.answers.get(*i))
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

/// Rearrange the records at `indices` so that their addresses follow `desired`.
///
/// Only the records at those exact positions are touched, so records of other types keep
/// their positions in the answer section.
fn reorder_in_place(msg: &mut Message, indices: &[usize], original: &[IpAddr], desired: &[IpAddr]) {
    debug_assert_eq!(original.len(), desired.len());
    let mut taken: Vec<Option<Record>> = indices
        .iter()
        .map(|i| msg.answers.get(*i).cloned())
        .collect();
    let mut placed: Vec<Record> = Vec::with_capacity(desired.len());
    for want in desired {
        if let Some(slot) = taken.iter_mut().find(|slot| {
            slot.as_ref()
                .and_then(record_address)
                .map(|a| a == *want)
                .unwrap_or(false)
        }) {
            if let Some(rec) = slot.take() {
                placed.push(rec);
            }
        }
    }
    // Anything not matched (which cannot happen for a permutation) is appended unchanged,
    // so no record can ever be lost by this function.
    for slot in taken.iter_mut() {
        if let Some(rec) = slot.take() {
            placed.push(rec);
        }
    }
    for (pos, rec) in indices.iter().zip(placed) {
        if let Some(target) = msg.answers.get_mut(*pos) {
            *target = rec;
        }
    }
}

/// Insert verified addresses immediately before the first member of the RRset.
fn prepend_addresses(
    msg: &mut Message,
    indices: &[usize],
    owner: &Name,
    ttl: u32,
    addrs: &[IpAddr],
    rtype: RecordType,
) {
    let Some(first) = indices.first().copied() else {
        return;
    };
    let mut new_records = Vec::with_capacity(addrs.len());
    for a in addrs {
        let rdata = match (a, rtype) {
            (IpAddr::V4(v4), RecordType::A) => RData::A(A(*v4)),
            (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA(AAAA(*v6)),
            _ => continue,
        };
        new_records.push(Record::from_rdata(owner.clone(), ttl, rdata));
    }
    for (offset, rec) in new_records.into_iter().enumerate() {
        msg.answers.insert(first + offset, rec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{CNAME, MX, SRV};
    use std::str::FromStr;
    use std::time::Duration;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("name")
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    fn a_rec(owner: &str, ttl: u32, addr: &str) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(addr.parse().expect("v4"))))
    }

    fn msg_with_addrs(owner: &str, addrs: &[&str]) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name(owner), RecordType::A));
        for a in addrs {
            m.add_answer(a_rec(owner, 300, a));
        }
        m
    }

    fn quality(now: Instant, entries: &[(&str, u64, u32)]) -> HashMap<IpAddr, QualityStats> {
        let cfg = RankingConfig::default();
        let mut map = HashMap::new();
        for (addr, ms, n) in entries {
            let mut s = QualityStats::new(1);
            for _ in 0..*n {
                s.record_success(Duration::from_millis(*ms), now, &cfg);
            }
            map.insert(ip(addr), s);
        }
        map
    }

    struct Fixture {
        snapshot: PrefixSnapshot,
        ranking: RankingConfig,
        augment: AugmentConfig,
        ttl: TtlConfig,
        quality: HashMap<IpAddr, QualityStats>,
        verified: Vec<VerifiedCandidate>,
    }

    impl Fixture {
        fn new(now: Instant) -> Self {
            let ranking = RankingConfig {
                exploration_rate: 0.0,
                ..RankingConfig::default()
            };
            Self {
                snapshot: PrefixSnapshot::builtin(),
                ranking,
                augment: AugmentConfig::default(),
                ttl: TtlConfig::default(),
                quality: quality(now, &[]),
                verified: Vec::new(),
            }
        }

        fn ctx(&self, now: Instant, qtype: RecordType, dnssec: DnssecStatus) -> AnswerContext<'_> {
            AnswerContext {
                qtype,
                dnssec,
                cloudflare_enabled: true,
                cloudflare_mode: CloudflareMode::VerifiedAugment,
                snapshot: Some(&self.snapshot),
                domain_excluded: false,
                baseline_validated: true,
                verified: &self.verified,
                can_validate_ech: false,
                quality: &self.quality,
                ranking: &self.ranking,
                augment: &self.augment,
                ttl: &self.ttl,
                remaining_authoritative: 3_600,
                remaining_signature: None,
                is_stale: false,
                recent_network_change: false,
                now,
                explore_seed: 1,
            }
        }
    }

    fn answer_addrs(m: &Message) -> Vec<IpAddr> {
        m.answers.iter().filter_map(record_address).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn preserve_mode_never_adds_or_removes() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 200, 20), ("104.16.0.2", 5, 20)]);
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1", "104.16.0.2"]);
        let before = answer_addrs(&m);
        let mut ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        ctx.cloudflare_mode = CloudflareMode::Preserve;
        let out = apply_answer_policy(&mut m, &ctx);
        let after = answer_addrs(&m);
        assert_eq!(out.added, 0);
        assert_eq!(after.len(), before.len());
        let mut a = before.clone();
        let mut b = after.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b, "preserve mode must produce a permutation");
        assert_eq!(after[0], ip("104.16.0.2"), "the fast address should lead");
    }

    #[tokio::test(start_paused = true)]
    async fn verified_augment_retains_every_original_address() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 200, 20), ("172.64.0.9", 5, 20)]);
        f.verified = vec![VerifiedCandidate {
            addr: ip("172.64.0.9"),
            successes: 5,
            cost_ms: 6.0,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1", "104.16.0.2"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.cloudflare_applied, Eligibility::Augment);
        assert_eq!(out.added, 1);
        let after = answer_addrs(&m);
        assert_eq!(after[0], ip("172.64.0.9"), "verified address must lead");
        assert!(after.contains(&ip("104.16.0.1")));
        assert!(after.contains(&ip("104.16.0.2")));
        assert_eq!(after.len(), 3);
        assert!(out.modified);
        assert!(out.client_ttl <= 30);
    }

    /// `cloudflare.augment.min_samples` must gate augmentation on real evidence.
    ///
    /// An address with no quality measurements scores *neutral*, which is the correct
    /// ranking behaviour — absence of evidence is not evidence of failure. But neutral is
    /// good enough to beat a genuinely slow original address, so without this gate a
    /// never-measured address could be added to a client's answer purely because the
    /// original was slow. The setting used to be parsed and never read.
    #[tokio::test(start_paused = true)]
    async fn augmentation_requires_the_configured_number_of_quality_samples() {
        let now = Instant::now();
        let candidate = |samples: u32| VerifiedCandidate {
            addr: ip("172.64.0.9"),
            successes: 5,
            cost_ms: 6.0,
            samples,
            fresh: true,
        };

        // Enough samples: the candidate is added.
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 200, 20)]);
        f.augment.min_samples = 8;
        f.verified = vec![candidate(8)];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let out = apply_answer_policy(&mut m, &f.ctx(now, RecordType::A, DnssecStatus::Insecure));
        assert_eq!(out.added, 1, "a well-measured candidate must be usable");

        // One sample short: refused, and the original answer is left intact.
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 200, 20)]);
        f.augment.min_samples = 8;
        f.verified = vec![candidate(7)];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let out = apply_answer_policy(&mut m, &f.ctx(now, RecordType::A, DnssecStatus::Insecure));
        assert_eq!(
            out.added, 0,
            "a candidate below min_samples must not be added"
        );
        assert_eq!(
            out.cloudflare_applied,
            Eligibility::Preserve,
            "refusing to augment degrades to preserve, never to a broken answer"
        );
        assert_eq!(answer_addrs(&m), vec![ip("104.16.0.1")]);
    }

    #[tokio::test(start_paused = true)]
    async fn dnssec_secure_never_receives_added_addresses() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.verified = vec![VerifiedCandidate {
            addr: ip("172.64.0.9"),
            successes: 5,
            cost_ms: 1.0,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Secure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
        assert!(!out.modified);
        assert_eq!(answer_addrs(&m), vec![ip("104.16.0.1")]);
    }

    #[tokio::test(start_paused = true)]
    async fn other_record_types_are_untouched() {
        let now = Instant::now();
        let f = Fixture::new(now);
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name("mail.example."), RecordType::MX));
        m.add_answer(Record::from_rdata(
            name("mail.example."),
            300,
            RData::MX(MX::new(10, name("mx1.example."))),
        ));
        m.add_answer(Record::from_rdata(
            name("mail.example."),
            300,
            RData::MX(MX::new(20, name("mx2.example."))),
        ));
        m.add_answer(Record::from_rdata(
            name("_sip._tcp.example."),
            300,
            RData::SRV(SRV::new(1, 60, 5060, name("sip1.example."))),
        ));
        let before = m.answers.clone();
        let ctx = f.ctx(now, RecordType::MX, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
        assert_eq!(
            m.answers
                .iter()
                .map(|r| r.data.to_string())
                .collect::<Vec<_>>(),
            before
                .iter()
                .map(|r| r.data.to_string())
                .collect::<Vec<_>>(),
            "MX preference and SRV priority/weight order must be preserved"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cname_chain_positions_are_preserved() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 300, 20), ("104.16.0.2", 5, 20)]);
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name("www.example."), RecordType::A));
        m.add_answer(Record::from_rdata(
            name("www.example."),
            60,
            RData::CNAME(CNAME(name("cdn.example."))),
        ));
        m.add_answer(a_rec("cdn.example.", 300, "104.16.0.1"));
        m.add_answer(a_rec("cdn.example.", 300, "104.16.0.2"));
        let mut ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        ctx.cloudflare_mode = CloudflareMode::Preserve;
        apply_answer_policy(&mut m, &ctx);
        assert!(matches!(m.answers[0].data, RData::CNAME(_)));
        assert_eq!(m.answers.len(), 3);
        assert_eq!(
            record_address(&m.answers[1]).expect("addr"),
            ip("104.16.0.2")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_never_exceeds_remaining_authoritative() {
        let now = Instant::now();
        let f = Fixture::new(now);
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        m.answers[0].ttl = 7;
        let mut ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        ctx.remaining_authoritative = 7;
        let out = apply_answer_policy(&mut m, &ctx);
        assert!(out.client_ttl <= 7);
        assert!(m.answers.iter().all(|r| r.ttl <= 7));
    }

    #[tokio::test(start_paused = true)]
    async fn augment_requires_a_meaningful_advantage() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 100, 20)]);
        // Only a 5 % improvement, below the 12 % hysteresis threshold.
        let original_cost = f
            .quality
            .get(&ip("104.16.0.1"))
            .expect("stats")
            .expected_cost(&f.ranking, now);
        f.verified = vec![VerifiedCandidate {
            addr: ip("172.64.0.9"),
            successes: 5,
            cost_ms: original_cost * 0.95,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
        assert_eq!(out.cloudflare_applied, Eligibility::Preserve);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_candidate_is_not_added() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.verified = vec![VerifiedCandidate {
            addr: ip("172.64.0.9"),
            successes: 99,
            cost_ms: 1.0,
            samples: 64,
            fresh: false,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_outside_the_snapshot_is_never_added() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.verified = vec![VerifiedCandidate {
            addr: ip("8.8.8.8"),
            successes: 99,
            cost_ms: 0.1,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
        assert_eq!(answer_addrs(&m), vec![ip("104.16.0.1")]);
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_family_candidate_is_never_added() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.verified = vec![VerifiedCandidate {
            addr: ip("2606:4700::1111"),
            successes: 99,
            cost_ms: 0.1,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_two_addresses_are_added() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 500, 20)]);
        f.verified = (1..=5)
            .map(|i| VerifiedCandidate {
                addr: ip(&format!("172.64.0.{i}")),
                successes: 9,
                cost_ms: 1.0,
                samples: 64,
                fresh: true,
            })
            .collect();
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert!(out.added <= 2, "added {}", out.added);
        assert!(answer_addrs(&m).contains(&ip("104.16.0.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_candidate_is_not_added_twice() {
        let now = Instant::now();
        let mut f = Fixture::new(now);
        f.quality = quality(now, &[("104.16.0.1", 500, 20)]);
        f.verified = vec![VerifiedCandidate {
            addr: ip("104.16.0.1"),
            successes: 9,
            cost_ms: 1.0,
            samples: 64,
            fresh: true,
        }];
        let mut m = msg_with_addrs("cdn.example.", &["104.16.0.1"]);
        let ctx = f.ctx(now, RecordType::A, DnssecStatus::Insecure);
        let out = apply_answer_policy(&mut m, &ctx);
        assert_eq!(out.added, 0);
        assert_eq!(answer_addrs(&m).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn aaaa_is_not_touched_by_an_a_query_and_vice_versa() {
        let now = Instant::now();
        let f = Fixture::new(now);
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name("dual.example."), RecordType::AAAA));
        m.add_answer(Record::from_rdata(
            name("dual.example."),
            300,
            RData::AAAA(AAAA("2606:4700::1".parse().expect("v6"))),
        ));
        m.add_answer(Record::from_rdata(
            name("dual.example."),
            300,
            RData::AAAA(AAAA("2606:4700::2".parse().expect("v6"))),
        ));
        let before = answer_addrs(&m);
        let ctx = f.ctx(now, RecordType::AAAA, DnssecStatus::Insecure);
        apply_answer_policy(&mut m, &ctx);
        let after = answer_addrs(&m);
        assert_eq!(after.len(), before.len());
        assert!(after.iter().all(|a| a.is_ipv6()));
    }
}
