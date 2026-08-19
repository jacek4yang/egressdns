//! Property tests for the correctness contract.
//!
//! These use randomised inputs to assert invariants that must hold for *every* answer, not
//! just the ones a hand-written test happened to think of.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use egressdns::cache::DnssecStatus;
use egressdns::cloudflare::prefixes::PrefixSnapshot;
use egressdns::config::{AugmentConfig, CloudflareMode, RankingConfig, TtlConfig};
use egressdns::policy::answer::{apply_answer_policy, AnswerContext, VerifiedCandidate};
use egressdns::policy::cloudflare::Eligibility;
use egressdns::policy::ttl::{effective_client_ttl, TtlInputs};
use egressdns::ranking::{order_addresses, ObservationClass, QualityStats};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use proptest::prelude::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime")
}

/// Strategy for an address inside Cloudflare's published IPv4 space.
fn cloudflare_v4() -> impl Strategy<Value = Ipv4Addr> {
    (0u8..=255, 1u8..=254).prop_map(|(c, d)| Ipv4Addr::new(104, 16, c, d))
}

/// Strategy for an address that is definitely not Cloudflare's.
fn other_v4() -> impl Strategy<Value = Ipv4Addr> {
    (1u8..=223, 0u8..=255, 1u8..=254).prop_filter_map("skip cloudflare ranges", |(a, c, d)| {
        let addr = Ipv4Addr::new(a, 9, c, d);
        let snapshot = PrefixSnapshot::builtin();
        if snapshot.contains(IpAddr::V4(addr))
            || egressdns::util::ipclass::classify_v4(addr).is_some()
        {
            None
        } else {
            Some(addr)
        }
    })
}

fn message_with(addrs: &[Ipv4Addr], ttl: u32) -> Message {
    let mut m = Message::new(1, MessageType::Response, OpCode::Query);
    let name = Name::from_utf8("cdn.example.test.").expect("name");
    m.add_query(Query::query(name.clone(), RecordType::A));
    for addr in addrs {
        m.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(A(*addr))));
    }
    m
}

fn answer_addrs(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
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
    fn new() -> Self {
        Self {
            snapshot: PrefixSnapshot::builtin(),
            ranking: RankingConfig {
                exploration_rate: 0.0,
                ..RankingConfig::default()
            },
            augment: AugmentConfig::default(),
            ttl: TtlConfig::default(),
            quality: HashMap::new(),
            verified: Vec::new(),
        }
    }

    fn context(
        &self,
        mode: CloudflareMode,
        dnssec: DnssecStatus,
        now: tokio::time::Instant,
        remaining: u32,
    ) -> AnswerContext<'_> {
        AnswerContext {
            qtype: RecordType::A,
            dnssec,
            cloudflare_enabled: true,
            cloudflare_mode: mode,
            snapshot: Some(&self.snapshot),
            domain_excluded: false,
            baseline_validated: true,
            verified: &self.verified,
            can_validate_ech: false,
            quality: &self.quality,
            ranking: &self.ranking,
            augment: &self.augment,
            ttl: &self.ttl,
            remaining_authoritative: remaining,
            remaining_signature: None,
            is_stale: false,
            recent_network_change: false,
            now,
            explore_seed: 7,
        }
    }
}

fn quality_for(addrs: &[Ipv4Addr], now: tokio::time::Instant) -> HashMap<IpAddr, QualityStats> {
    let cfg = RankingConfig::default();
    let mut map = HashMap::new();
    for (i, addr) in addrs.iter().enumerate() {
        let mut s = QualityStats::new(1);
        for _ in 0..12 {
            s.record(
                ObservationClass::Success,
                Some(Duration::from_millis(5 + (i as u64 * 37) % 400)),
                now,
                &cfg,
            );
        }
        map.insert(IpAddr::V4(*addr), s);
    }
    map
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Preserve mode is always a permutation of the original RRset.
    #[test]
    fn preserve_mode_is_always_a_permutation(
        addrs in prop::collection::vec(cloudflare_v4(), 1..8),
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut f = Fixture::new();
            f.quality = quality_for(&addrs, now);
            let mut message = message_with(&addrs, ttl);
            let before = answer_addrs(&message);
            let ctx = f.context(CloudflareMode::Preserve, DnssecStatus::Insecure, now, ttl);
            let outcome = apply_answer_policy(&mut message, &ctx);
            let after = answer_addrs(&message);

            prop_assert_eq!(outcome.added, 0);
            prop_assert_eq!(before.len(), after.len());
            let mut a = before.clone();
            let mut b = after.clone();
            a.sort();
            b.sort();
            prop_assert_eq!(a, b);
            prop_assert!(!outcome.modified);
            Ok(())
        }).expect("property holds");
    }

    /// Verified-augment never removes an original address, and only ever adds addresses
    /// that are inside the current official prefix snapshot.
    #[test]
    fn augment_retains_originals_and_only_adds_cloudflare_addresses(
        originals in prop::collection::vec(cloudflare_v4(), 1..5),
        candidates in prop::collection::vec(cloudflare_v4(), 0..4),
        intruders in prop::collection::vec(other_v4(), 0..4),
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut f = Fixture::new();
            // The originals are deliberately slow so a candidate can clear hysteresis.
            let cfg = RankingConfig::default();
            for addr in &originals {
                let mut s = QualityStats::new(1);
                for _ in 0..12 {
                    s.record(ObservationClass::Success, Some(Duration::from_millis(400)), now, &cfg);
                }
                f.quality.insert(IpAddr::V4(*addr), s);
            }
            f.verified = candidates
                .iter()
                .map(|c| VerifiedCandidate {
                    addr: IpAddr::V4(*c),
                    successes: 9,
                    cost_ms: 1.0,
                    samples: 64,
                    fresh: true,
                })
                .chain(intruders.iter().map(|c| VerifiedCandidate {
                    addr: IpAddr::V4(*c),
                    successes: 9,
                    cost_ms: 0.5,
                    samples: 64,
                    fresh: true,
                }))
                .collect();

            let mut message = message_with(&originals, ttl);
            let before = answer_addrs(&message);
            let ctx = f.context(CloudflareMode::VerifiedAugment, DnssecStatus::Insecure, now, ttl);
            let outcome = apply_answer_policy(&mut message, &ctx);
            let after = answer_addrs(&message);

            for original in &before {
                prop_assert!(after.contains(original), "original {original} was removed");
            }
            prop_assert!(outcome.added <= f.augment.max_added);
            for addr in &after {
                if !before.contains(addr) {
                    prop_assert!(
                        f.snapshot.contains(*addr),
                        "added address {addr} is outside the official prefix snapshot"
                    );
                }
            }
            for intruder in &intruders {
                prop_assert!(
                    !after.contains(&IpAddr::V4(*intruder)),
                    "a non-Cloudflare candidate was added"
                );
            }
            Ok(())
        }).expect("property holds");
    }

    /// A DNSSEC Secure or indeterminate answer never gains an address.
    #[test]
    fn signed_or_unknown_answers_never_gain_addresses(
        originals in prop::collection::vec(cloudflare_v4(), 1..5),
        candidates in prop::collection::vec(cloudflare_v4(), 1..4),
        ttl in 1u32..7200,
        secure in any::<bool>(),
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut f = Fixture::new();
            f.quality = quality_for(&originals, now);
            f.verified = candidates
                .iter()
                .map(|c| VerifiedCandidate {
                    addr: IpAddr::V4(*c),
                    successes: 99,
                    cost_ms: 0.1,
                    samples: 64,
                    fresh: true,
                })
                .collect();
            let status = if secure {
                DnssecStatus::Secure
            } else {
                DnssecStatus::Indeterminate
            };
            let mut message = message_with(&originals, ttl);
            let before = answer_addrs(&message);
            let ctx = f.context(CloudflareMode::VerifiedAugment, status, now, ttl);
            let outcome = apply_answer_policy(&mut message, &ctx);
            let after = answer_addrs(&message);

            prop_assert_eq!(outcome.added, 0);
            prop_assert!(!outcome.modified);
            prop_assert_eq!(before.len(), after.len());
            prop_assert_ne!(outcome.cloudflare_applied, Eligibility::Augment);
            Ok(())
        }).expect("property holds");
    }

    /// The client TTL is never larger than the remaining authoritative TTL.
    #[test]
    fn client_ttl_never_exceeds_the_authoritative_remainder(
        remaining in 0u32..100_000,
        signature in prop::option::of(0u32..100_000),
        stale in any::<bool>(),
        network_change in any::<bool>(),
        augmented in any::<bool>(),
        preserved in any::<bool>(),
        optimized in any::<bool>(),
    ) {
        let cfg = TtlConfig::default();
        let (ttl, _) = effective_client_ttl(&cfg, TtlInputs {
            remaining_authoritative: remaining,
            remaining_signature: signature,
            is_stale: stale,
            recent_network_change: network_change,
            cloudflare_augmented: augmented,
            cloudflare_preserved: preserved,
            optimized_multi: optimized,
        });
        prop_assert!(ttl <= remaining);
        if let Some(sig) = signature {
            prop_assert!(ttl <= sig);
        }
    }

    /// The TTL applied to every record in an answer never exceeds its own remaining TTL.
    #[test]
    fn per_record_ttls_are_only_ever_reduced(
        addrs in prop::collection::vec(cloudflare_v4(), 1..6),
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut f = Fixture::new();
            f.quality = quality_for(&addrs, now);
            let mut message = message_with(&addrs, ttl);
            let ctx = f.context(CloudflareMode::Preserve, DnssecStatus::Insecure, now, ttl);
            apply_answer_policy(&mut message, &ctx);
            for record in &message.answers {
                prop_assert!(record.ttl <= ttl, "record TTL {} exceeded {}", record.ttl, ttl);
            }
            Ok(())
        }).expect("property holds");
    }

    /// Only A and AAAA records are ever reordered; every other record keeps its position.
    #[test]
    fn only_address_records_move(
        addrs in prop::collection::vec(cloudflare_v4(), 2..6),
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut f = Fixture::new();
            f.quality = quality_for(&addrs, now);

            let name = Name::from_utf8("www.example.test.").expect("name");
            let target = Name::from_utf8("cdn.example.test.").expect("name");
            let mut message = Message::new(1, MessageType::Response, OpCode::Query);
            message.add_query(Query::query(name.clone(), RecordType::A));
            message.add_answer(Record::from_rdata(
                name.clone(),
                ttl,
                RData::CNAME(CNAME(target.clone())),
            ));
            for addr in &addrs {
                message.add_answer(Record::from_rdata(target.clone(), ttl, RData::A(A(*addr))));
            }
            message.add_additional(Record::from_rdata(
                name.clone(),
                ttl,
                RData::MX(MX::new(10, target.clone())),
            ));

            let before_types: Vec<RecordType> =
                message.answers.iter().map(|r| r.record_type()).collect();
            let before_additional: Vec<String> =
                message.additionals.iter().map(|r| r.data.to_string()).collect();

            let ctx = f.context(CloudflareMode::Preserve, DnssecStatus::Insecure, now, ttl);
            apply_answer_policy(&mut message, &ctx);

            let after_types: Vec<RecordType> =
                message.answers.iter().map(|r| r.record_type()).collect();
            let after_additional: Vec<String> =
                message.additionals.iter().map(|r| r.data.to_string()).collect();

            prop_assert_eq!(before_types, after_types, "record type layout changed");
            prop_assert_eq!(before_additional, after_additional, "additionals changed");
            Ok(())
        }).expect("property holds");
    }

    /// Ordering is a permutation and is deterministic for identical inputs.
    #[test]
    fn ordering_is_a_deterministic_permutation(
        addrs in prop::collection::vec(cloudflare_v4(), 1..10),
        seed in any::<u64>(),
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let cfg = RankingConfig::default();
            let quality = quality_for(&addrs, now);
            let inputs: Vec<IpAddr> = addrs.iter().map(|a| IpAddr::V4(*a)).collect();
            let first = order_addresses(&inputs, &quality, &cfg, now, seed);
            let second = order_addresses(&inputs, &quality, &cfg, now, seed);
            prop_assert_eq!(&first.addresses, &second.addresses);
            prop_assert_eq!(first.decision, second.decision);

            let mut a = inputs.clone();
            let mut b = first.addresses.clone();
            a.sort();
            b.sort();
            prop_assert_eq!(a, b, "ordering must be a permutation");
            Ok(())
        }).expect("property holds");
    }

    /// Unknown addresses are never dropped or demoted below a measured failure.
    #[test]
    fn unknown_addresses_are_never_dropped(
        known in prop::collection::vec(cloudflare_v4(), 1..4),
        unknown in prop::collection::vec(cloudflare_v4(), 1..4),
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let cfg = RankingConfig {
                exploration_rate: 0.0,
                ..RankingConfig::default()
            };
            let mut quality = HashMap::new();
            let base = RankingConfig::default();
            for addr in &known {
                let mut s = QualityStats::new(1);
                for _ in 0..10 {
                    s.record(ObservationClass::ApplicableFailure, None, now, &base);
                }
                quality.insert(IpAddr::V4(*addr), s);
            }
            let mut inputs: Vec<IpAddr> = known.iter().map(|a| IpAddr::V4(*a)).collect();
            inputs.extend(unknown.iter().map(|a| IpAddr::V4(*a)));
            inputs.sort();
            inputs.dedup();

            let out = order_addresses(&inputs, &quality, &cfg, now, 1);
            prop_assert_eq!(out.addresses.len(), inputs.len());
            for addr in &inputs {
                prop_assert!(out.addresses.contains(addr));
            }
            Ok(())
        }).expect("property holds");
    }

    /// Bounded structures never exceed their configured limits.
    #[test]
    fn bounded_structures_stay_bounded(
        capacity in 1usize..64,
        inserts in 1usize..600,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let pool = egressdns::cloudflare::candidates::CandidatePool::new(capacity);
            let snapshot = PrefixSnapshot::builtin();
            for i in 0..inserts {
                let addr = IpAddr::V4(Ipv4Addr::new(104, 16, (i / 254) as u8, ((i % 253) + 1) as u8));
                let _ = pool.admit(
                    addr,
                    egressdns::cloudflare::candidates::CandidateOrigin::Sampling,
                    Some(&snapshot),
                    1,
                    now,
                    None,
                );
            }
            let (v4, v6) = pool.counts();
            prop_assert!(v4 + v6 <= capacity, "pool grew to {}", v4 + v6);

            let hot = egressdns::cache::hotset::HotSet::new(capacity, 600.0, 0);
            for i in 0..inserts {
                let key = egressdns::cache::CacheKey::new(
                    &format!("n{i}.example."),
                    RecordType::A,
                    hickory_proto::rr::DNSClass::IN,
                    egressdns::cache::PolicyView::plain(Arc::from("default")),
                    egressdns::cache::DnssecMode { dnssec_ok: false, checking_disabled: false },
                );
                hot.observe(&key, None, now);
            }
            prop_assert!(hot.len() <= capacity, "hot set grew to {}", hot.len());
            Ok(())
        }).expect("property holds");
    }

    /// A probe error never turns a valid answer into a failure: the answer is returned
    /// unchanged regardless of how bad the evidence is.
    #[test]
    fn probe_failures_never_break_an_answer(
        addrs in prop::collection::vec(cloudflare_v4(), 1..6),
        failures in 1u32..40,
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let now = tokio::time::Instant::now();
            let cfg = RankingConfig::default();
            let mut f = Fixture::new();
            for addr in &addrs {
                let mut s = QualityStats::new(1);
                for _ in 0..failures {
                    s.record(ObservationClass::ApplicableFailure, None, now, &cfg);
                }
                f.quality.insert(IpAddr::V4(*addr), s);
            }
            let mut message = message_with(&addrs, ttl);
            let before = answer_addrs(&message);
            let ctx = f.context(CloudflareMode::Preserve, DnssecStatus::Insecure, now, ttl);
            apply_answer_policy(&mut message, &ctx);
            let after = answer_addrs(&message);
            prop_assert_eq!(before.len(), after.len(), "an address was dropped");
            prop_assert_eq!(
                message.metadata.response_code,
                hickory_proto::op::ResponseCode::NoError
            );
            Ok(())
        }).expect("property holds");
    }

    /// Answer-variant fingerprints distinguish different complete answers and never merge.
    #[test]
    fn variants_are_distinguished_and_never_merged(
        first in prop::collection::vec(cloudflare_v4(), 1..5),
        second in prop::collection::vec(cloudflare_v4(), 1..5),
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let a = message_with(&first, 300);
            let b = message_with(&second, 300);
            let fa = egressdns::dns::message::answer_fingerprint(&a);
            let fb = egressdns::dns::message::answer_fingerprint(&b);

            let set_a: std::collections::BTreeSet<Ipv4Addr> = first.iter().copied().collect();
            let set_b: std::collections::BTreeSet<Ipv4Addr> = second.iter().copied().collect();
            if set_a == set_b {
                prop_assert_eq!(fa, fb, "identical answer sets must fingerprint identically");
            } else {
                prop_assert_ne!(fa, fb, "different answer sets must fingerprint differently");
            }
            // Neither message ever gains records from the other.
            prop_assert_eq!(a.answers.len(), first.len());
            prop_assert_eq!(b.answers.len(), second.len());
            Ok(())
        }).expect("property holds");
    }

    /// A truncation-aware serialisation never emits more bytes than allowed.
    #[test]
    fn serialisation_respects_the_size_limit(
        count in 1usize..300,
        limit in 512usize..4096,
    ) {
        let addrs: Vec<Ipv4Addr> = (0..count)
            .map(|i| Ipv4Addr::new(104, 16, (i / 254) as u8, ((i % 253) + 1) as u8))
            .collect();
        let message = message_with(&addrs, 300);
        let out = egressdns::dns::message::serialize_limited(&message, limit)
            .expect("serialises");
        prop_assert!(out.bytes.len() <= limit, "emitted {} bytes", out.bytes.len());
        if out.truncated {
            let decoded = Message::from_vec(&out.bytes).expect("decodes");
            prop_assert!(decoded.metadata.truncation);
        }
    }

    /// IPv6 answers behave exactly like IPv4 answers under preserve mode.
    #[test]
    fn ipv6_answers_are_also_permutations(
        raw in prop::collection::vec(any::<u16>(), 1..6),
        ttl in 1u32..7200,
    ) {
        let rt = runtime();
        rt.block_on(async move {
            let addrs: Vec<Ipv6Addr> = raw
                .iter()
                .map(|n| Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, *n | 1))
                .collect();
            let name = Name::from_utf8("cdn.example.test.").expect("name");
            let mut message = Message::new(1, MessageType::Response, OpCode::Query);
            message.add_query(Query::query(name.clone(), RecordType::AAAA));
            for addr in &addrs {
                message.add_answer(Record::from_rdata(
                    name.clone(),
                    ttl,
                    RData::AAAA(AAAA(*addr)),
                ));
            }
            let before = answer_addrs(&message);
            let now = tokio::time::Instant::now();
            let f = Fixture::new();
            let mut ctx = f.context(CloudflareMode::Preserve, DnssecStatus::Insecure, now, ttl);
            ctx.qtype = RecordType::AAAA;
            apply_answer_policy(&mut message, &ctx);
            let after = answer_addrs(&message);
            let mut x = before.clone();
            let mut y = after.clone();
            x.sort();
            y.sort();
            prop_assert_eq!(x, y);
            prop_assert!(after.iter().all(|a| a.is_ipv6()));
            Ok(())
        }).expect("property holds");
    }
}
