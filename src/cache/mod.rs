//! Answer, negative, failure, variant and stale caches.
//!
//! The cache stores *complete* upstream answers exactly as they were received, together
//! with the instant of receipt. Nothing is rewritten on the way in: TTL ageing, client TTL
//! caps and address ordering all happen on the way out, so the same cached answer can be
//! served under different policies without ever losing information.

pub mod hotset;
pub mod singleflight;

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use moka::sync::Cache as MokaCache;
use tokio::time::Instant;

use crate::config::TransportKind;
use crate::config::{CacheConfig, ServeStaleConfig};

/// DNSSEC state attached to a cached answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Validated as authentic against the configured trust anchors.
    Secure,
    /// Proven to be outside any signed zone.
    Insecure,
    /// Validation failed. Bogus data must never be served as if it were valid.
    Bogus,
    /// The state could not be determined (validation disabled, missing data, or an
    /// unsupported algorithm).
    Indeterminate,
}

impl DnssecStatus {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// True when the answer may carry AD towards the client.
    pub fn is_authentic(self) -> bool {
        matches!(self, Self::Secure)
    }
}

/// Kind of cached answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A normal answer with data.
    Positive,
    /// NODATA: the name exists but has no records of the requested type.
    NoData,
    /// NXDOMAIN.
    NxDomain,
}

impl EntryKind {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::NoData => "nodata",
            Self::NxDomain => "nxdomain",
        }
    }
}

/// The policy view a cache entry belongs to.
///
/// Two clients that receive different answers because of policy must not share a cache
/// entry. The view therefore includes the upstream group and the effective ECS identity,
/// but deliberately *not* the individual client address: fragmenting the cache per LAN
/// client would destroy the hit rate for no benefit in this deployment model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyView {
    /// Name of the upstream group that produced (or would produce) the answer.
    pub group: Arc<str>,
    /// Stable identifier of the ECS prefix sent upstream, or `None` when ECS is disabled.
    pub ecs_identity: Option<Arc<str>>,
}

impl PolicyView {
    /// Construct a view with no ECS identity.
    pub fn plain(group: Arc<str>) -> Self {
        Self {
            group,
            ecs_identity: None,
        }
    }
}

/// DNSSEC-relevant request mode that changes the shape of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnssecMode {
    /// DO bit: the client asked for DNSSEC records.
    pub dnssec_ok: bool,
    /// CD bit: the client asked the resolver not to validate.
    pub checking_disabled: bool,
}

/// Cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Lower-cased, fully qualified query name.
    pub name: Arc<str>,
    /// Query type.
    pub qtype: RecordType,
    /// Query class.
    pub qclass: DNSClass,
    /// Policy view.
    pub view: PolicyView,
    /// DNSSEC-relevant mode.
    pub mode: DnssecMode,
}

impl CacheKey {
    /// Build a key from its parts, normalising the name.
    pub fn new(
        name: &str,
        qtype: RecordType,
        qclass: DNSClass,
        view: PolicyView,
        mode: DnssecMode,
    ) -> Self {
        Self {
            name: normalize_name(name),
            qtype,
            qclass,
            view,
            mode,
        }
    }
}

/// Normalise a DNS name for cache keying: lower-case, trailing dot, ASCII only.
pub fn normalize_name(name: &str) -> Arc<str> {
    let mut s = name.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    Arc::from(s.as_str())
}

/// Where a cached answer came from.
#[derive(Debug, Clone)]
pub struct AnswerSource {
    /// Configured upstream name, used as a bounded metrics label.
    pub server: Arc<str>,
    /// Transport used.
    pub transport: TransportKind,
}

/// A cached complete answer.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The complete upstream answer with the TTLs it carried when received.
    pub message: Arc<Message>,
    /// Monotonic instant of receipt.
    pub received_at: Instant,
    /// Wall-clock second of receipt, used for signature-lifetime arithmetic.
    pub received_unix: u64,
    /// Authoritative TTL that governs this entry, already bounded by policy.
    pub ttl: u32,
    /// Answer kind.
    pub kind: EntryKind,
    /// DNSSEC state established at insert time.
    pub dnssec: DnssecStatus,
    /// Upstream that produced the answer.
    pub source: AnswerSource,
    /// Canonical fingerprint of the answer section.
    pub fingerprint: u64,
    /// Earliest RRSIG expiry in the answer, when the answer is signed.
    pub rrsig_expiry_unix: Option<u64>,
    /// Approximate in-memory size, used as the cache weight.
    pub approx_bytes: u32,
}

impl CacheEntry {
    /// Seconds elapsed since receipt.
    pub fn age_secs(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.received_at).as_secs() as u32
    }

    /// Remaining authoritative TTL, zero once expired.
    pub fn remaining_ttl(&self, now: Instant) -> u32 {
        self.ttl.saturating_sub(self.age_secs(now))
    }

    /// True while the entry is within its authoritative TTL.
    pub fn is_fresh(&self, now: Instant) -> bool {
        self.remaining_ttl(now) > 0
    }

    /// Seconds past expiry, zero while fresh.
    pub fn staleness_secs(&self, now: Instant) -> u32 {
        self.age_secs(now).saturating_sub(self.ttl)
    }

    /// Remaining signature lifetime, when the answer carries RRSIGs.
    pub fn remaining_signature_secs(&self, now_unix: u64) -> Option<u32> {
        self.rrsig_expiry_unix
            .map(|exp| exp.saturating_sub(now_unix).min(u64::from(u32::MAX)) as u32)
    }
}

/// Result of a cache lookup.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// A fresh entry with the given remaining TTL.
    Fresh {
        /// The entry.
        entry: Arc<CacheEntry>,
        /// Remaining authoritative TTL in seconds.
        remaining: u32,
    },
    /// An expired entry still retained for serve-stale.
    Stale {
        /// The entry.
        entry: Arc<CacheEntry>,
        /// Seconds past expiry.
        staleness: u32,
    },
    /// Nothing usable.
    Miss,
}

impl Lookup {
    /// Bounded metrics label for the outcome.
    pub fn label(&self) -> &'static str {
        match self {
            Lookup::Fresh { entry, .. } => match entry.kind {
                EntryKind::Positive => "hit",
                EntryKind::NoData | EntryKind::NxDomain => "negative_hit",
            },
            Lookup::Stale { .. } => "stale",
            Lookup::Miss => "miss",
        }
    }
}

/// A cached resolution failure (RFC 9520).
#[derive(Debug, Clone)]
pub struct FailureEntry {
    /// Instant the failure was recorded.
    pub recorded_at: Instant,
    /// How long the failure suppresses new upstream work.
    pub ttl: Duration,
    /// Response code to return while suppressed.
    pub rcode: ResponseCode,
    /// Bounded reason for diagnostics and Extended DNS Errors.
    pub reason: &'static str,
    /// Number of consecutive failures, used for backoff.
    pub consecutive: u32,
}

impl FailureEntry {
    /// True while the failure is still suppressing upstream work.
    pub fn is_active(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.recorded_at) < self.ttl
    }
}

/// A complete alternate answer variant observed from some upstream.
#[derive(Debug, Clone)]
pub struct VariantRecord {
    /// Canonical fingerprint of the variant.
    pub fingerprint: u64,
    /// The complete answer, never merged with any other variant.
    pub message: Arc<Message>,
    /// Upstream that produced it.
    pub source: AnswerSource,
    /// Instant it was last observed.
    pub observed_at: Instant,
    /// TTL it carried.
    pub ttl: u32,
    /// DNSSEC state at observation time.
    pub dnssec: DnssecStatus,
}

impl VariantRecord {
    /// True when the variant has not yet expired.
    pub fn is_valid(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.observed_at).as_secs() < u64::from(self.ttl)
    }
}

/// The set of complete variants known for one cache key.
#[derive(Debug, Clone, Default)]
pub struct VariantSet {
    /// Known variants, bounded in length.
    pub variants: Vec<VariantRecord>,
    /// Fingerprint currently selected, for hysteresis.
    pub selected: Option<u64>,
    /// Instant the selection last changed.
    pub selected_at: Option<Instant>,
}

/// Maximum number of variants retained per key.
pub const MAX_VARIANTS_PER_KEY: usize = 4;

/// The composite DNS cache.
pub struct DnsCache {
    answers: MokaCache<CacheKey, Arc<CacheEntry>>,
    failures: MokaCache<CacheKey, Arc<FailureEntry>>,
    variants: MokaCache<CacheKey, Arc<VariantSet>>,
    serve_stale: ServeStaleConfig,
    internal_max_ttl: u32,
}

impl DnsCache {
    /// Build a cache from configuration.
    pub fn new(cfg: &CacheConfig, stale: &ServeStaleConfig) -> Self {
        // Entries are retained past their DNS TTL so that serve-stale has something to
        // serve; moka's own expiry is therefore the *retention* bound, not the DNS TTL.
        let retention = if stale.enabled {
            stale.max_stale + Duration::from_secs(u64::from(cfg.internal_max_ttl))
        } else {
            Duration::from_secs(u64::from(cfg.internal_max_ttl))
        };
        let answers = MokaCache::builder()
            .max_capacity(cfg.max_memory_bytes)
            .weigher(|_k: &CacheKey, v: &Arc<CacheEntry>| v.approx_bytes.max(1))
            .time_to_live(retention)
            .support_invalidation_closures()
            .build();
        // The per-entry failure TTL is computed from the live configuration when the
        // failure is recorded, so the moka TTL is only a retention backstop. Sizing it
        // from the configured `failure_max_ttl` would freeze that bound at construction:
        // a reload raising the value would be silently clipped by the old cache. The
        // validation ceiling is the widest any configured value can ever be, so it is
        // the strict bound that covers every legal reload.
        let failures = MokaCache::builder()
            .max_capacity(cfg.failure_max_entries)
            .time_to_live(crate::config::FAILURE_MAX_TTL_CEILING + Duration::from_secs(1))
            .support_invalidation_closures()
            .build();
        // Weighed in bytes, like the answer cache. A variant set holds up to
        // `MAX_VARIANTS_PER_KEY` complete answers, so bounding it by entry count bounds
        // memory only to within a factor of four — at the previous default that silently
        // permitted a second cache several times the size of the configured one.
        let variants = MokaCache::builder()
            .max_capacity(cfg.variant_max_memory_bytes)
            .weigher(|_k: &CacheKey, v: &Arc<VariantSet>| variant_set_bytes(v).max(1))
            .time_to_live(retention)
            .support_invalidation_closures()
            .build();
        Self {
            answers,
            failures,
            variants,
            serve_stale: stale.clone(),
            internal_max_ttl: cfg.internal_max_ttl,
        }
    }

    /// Upper bound applied to a positive TTL before storage.
    pub fn internal_max_ttl(&self) -> u32 {
        self.internal_max_ttl
    }

    /// Look up an answer.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Lookup {
        let Some(entry) = self.answers.get(key) else {
            return Lookup::Miss;
        };
        let remaining = entry.remaining_ttl(now);
        if remaining > 0 {
            return Lookup::Fresh { entry, remaining };
        }
        if !self.serve_stale.enabled {
            return Lookup::Miss;
        }
        let staleness = entry.staleness_secs(now);
        if u64::from(staleness) > self.serve_stale.max_stale.as_secs() {
            return Lookup::Miss;
        }
        // Bogus data is never served, fresh or stale.
        if entry.dnssec == DnssecStatus::Bogus {
            return Lookup::Miss;
        }
        Lookup::Stale { entry, staleness }
    }

    /// Insert or replace an answer.
    pub fn insert(&self, key: CacheKey, entry: Arc<CacheEntry>) {
        if entry.dnssec == DnssecStatus::Bogus {
            // Never cache bogus data.
            return;
        }
        self.answers.insert(key, entry);
    }

    /// Record a resolution failure.
    pub fn record_failure(&self, key: CacheKey, entry: FailureEntry) {
        self.failures.insert(key, Arc::new(entry));
    }

    /// Look up an active resolution failure.
    pub fn failure(&self, key: &CacheKey, now: Instant) -> Option<Arc<FailureEntry>> {
        let f = self.failures.get(key)?;
        if f.is_active(now) {
            Some(f)
        } else {
            self.failures.invalidate(key);
            None
        }
    }

    /// Clear any recorded failure for a key.
    pub fn clear_failure(&self, key: &CacheKey) {
        self.failures.invalidate(key);
    }

    /// Consecutive failure count for backoff purposes.
    pub fn failure_streak(&self, key: &CacheKey) -> u32 {
        self.failures.get(key).map(|f| f.consecutive).unwrap_or(0)
    }

    /// Read the variant set for a key.
    pub fn variants(&self, key: &CacheKey) -> Option<Arc<VariantSet>> {
        self.variants.get(key)
    }

    /// Record an observed complete variant, replacing an existing entry with the same
    /// fingerprint. Variants are never merged with one another.
    pub fn record_variant(&self, key: CacheKey, record: VariantRecord, now: Instant) -> bool {
        let existing = self.variants.get(&key);
        let mut set = existing.as_deref().cloned().unwrap_or_default();
        let is_new = !set
            .variants
            .iter()
            .any(|v| v.fingerprint == record.fingerprint);
        set.variants
            .retain(|v| v.fingerprint != record.fingerprint && v.is_valid(now));
        set.variants.push(record);
        if set.variants.len() > MAX_VARIANTS_PER_KEY {
            // Drop the oldest observation.
            set.variants.sort_by_key(|v| v.observed_at);
            let excess = set.variants.len() - MAX_VARIANTS_PER_KEY;
            set.variants.drain(0..excess);
        }
        self.variants.insert(key, Arc::new(set));
        is_new
    }

    /// Record which variant is currently selected, for hysteresis.
    pub fn set_selected_variant(&self, key: &CacheKey, fingerprint: u64, now: Instant) {
        let Some(existing) = self.variants.get(key) else {
            return;
        };
        let mut set = (*existing).clone();
        if set.selected == Some(fingerprint) {
            return;
        }
        set.selected = Some(fingerprint);
        set.selected_at = Some(now);
        self.variants.insert(key.clone(), Arc::new(set));
    }

    /// Invalidate every entry whose owner name equals `name` (case-insensitive).
    pub fn flush_name(&self, name: &str) {
        let target = normalize_name(name);
        let t1 = Arc::clone(&target);
        let _ = self.answers.invalidate_entries_if(move |k, _| k.name == t1);
        let t2 = Arc::clone(&target);
        let _ = self
            .failures
            .invalidate_entries_if(move |k, _| k.name == t2);
        let t3 = Arc::clone(&target);
        let _ = self
            .variants
            .invalidate_entries_if(move |k, _| k.name == t3);
    }

    /// Invalidate every entry at or beneath `suffix`.
    pub fn flush_suffix(&self, suffix: &str) {
        let target = normalize_name(suffix);
        let t1 = Arc::clone(&target);
        let _ = self
            .answers
            .invalidate_entries_if(move |k, _| name_in_suffix(&k.name, &t1));
        let t2 = Arc::clone(&target);
        let _ = self
            .failures
            .invalidate_entries_if(move |k, _| name_in_suffix(&k.name, &t2));
        let t3 = Arc::clone(&target);
        let _ = self
            .variants
            .invalidate_entries_if(move |k, _| name_in_suffix(&k.name, &t3));
    }

    /// Drop everything.
    pub fn flush_all(&self) {
        self.answers.invalidate_all();
        self.failures.invalidate_all();
        self.variants.invalidate_all();
    }

    /// Run deferred maintenance. Called from the background maintenance task so that the
    /// foreground path never pays for housekeeping.
    pub fn run_maintenance(&self) {
        self.answers.run_pending_tasks();
        self.failures.run_pending_tasks();
        self.variants.run_pending_tasks();
    }

    /// Current statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            answer_entries: self.answers.entry_count(),
            answer_bytes: self.answers.weighted_size(),
            failure_entries: self.failures.entry_count(),
            variant_entries: self.variants.entry_count(),
        }
    }
}

/// Point-in-time cache statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of cached answers.
    pub answer_entries: u64,
    /// Approximate cached answer bytes.
    pub answer_bytes: u64,
    /// Number of cached resolution failures.
    pub failure_entries: u64,
    /// Number of keys with recorded variants.
    pub variant_entries: u64,
}

fn name_in_suffix(name: &str, suffix: &str) -> bool {
    if name == suffix {
        return true;
    }
    if suffix == "." {
        return true;
    }
    name.ends_with(suffix) && name.len() > suffix.len() && {
        let boundary = name.len() - suffix.len();
        name.as_bytes()[boundary - 1] == b'.'
    }
}

/// Estimate the in-memory footprint of a message, used as the cache weight.
pub fn estimate_bytes(msg: &Message) -> u32 {
    // Wire size is a good proxy for the payload and is cheap to compute once at insert
    // time. The multiplier and the constant cover what the wire form does not: the parsed
    // `Message` with a heap-allocated `Name` per record, the `Arc<CacheEntry>` and
    // `Arc<Message>` allocations, the `CacheKey` with its interned name and policy view,
    // and moka's own per-entry bookkeeping.
    //
    // Erring high is deliberate. `cache.max_memory_bytes` is the number an operator sizes
    // a machine against, so an estimate that reads low turns a documented ceiling into a
    // surprise.
    let wire = msg.to_vec().map(|v| v.len()).unwrap_or(512);
    (wire as u32).saturating_mul(4).saturating_add(512)
}

/// Approximate memory held by one variant set.
pub fn variant_set_bytes(set: &VariantSet) -> u32 {
    set.variants
        .iter()
        .map(|v| estimate_bytes(&v.message))
        .fold(256u32, |acc, n| acc.saturating_add(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::str::FromStr;

    fn key(name: &str, qtype: RecordType) -> CacheKey {
        CacheKey::new(
            name,
            qtype,
            DNSClass::IN,
            PolicyView::plain(Arc::from("default")),
            DnssecMode {
                dnssec_ok: false,
                checking_disabled: false,
            },
        )
    }

    fn entry(ttl: u32, now: Instant, kind: EntryKind, dnssec: DnssecStatus) -> Arc<CacheEntry> {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("example.com.").expect("name"),
            RecordType::A,
        ));
        m.add_answer(Record::from_rdata(
            Name::from_str("example.com.").expect("name"),
            ttl,
            RData::A(A("1.2.3.4".parse().expect("v4"))),
        ));
        Arc::new(CacheEntry {
            approx_bytes: estimate_bytes(&m),
            fingerprint: crate::dns::message::answer_fingerprint(&m),
            message: Arc::new(m),
            received_at: now,
            received_unix: 1_000_000,
            ttl,
            kind,
            dnssec,
            source: AnswerSource {
                server: Arc::from("test"),
                transport: TransportKind::Udp,
            },
            rrsig_expiry_unix: None,
        })
    }

    fn cache() -> DnsCache {
        DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default())
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_then_stale_then_gone() {
        let c = cache();
        let now = Instant::now();
        c.insert(
            key("example.com.", RecordType::A),
            entry(10, now, EntryKind::Positive, DnssecStatus::Insecure),
        );
        match c.get(&key("EXAMPLE.com", RecordType::A), now) {
            Lookup::Fresh { remaining, .. } => assert_eq!(remaining, 10),
            other => panic!("expected fresh, got {other:?}"),
        }
        let later = now + Duration::from_secs(15);
        match c.get(&key("example.com.", RecordType::A), later) {
            Lookup::Stale { staleness, .. } => assert_eq!(staleness, 5),
            other => panic!("expected stale, got {other:?}"),
        }
        let much_later = now + Duration::from_secs(10 + 86_400 + 5);
        assert!(matches!(
            c.get(&key("example.com.", RecordType::A), much_later),
            Lookup::Miss
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn bogus_is_never_cached_or_served() {
        let c = cache();
        let now = Instant::now();
        c.insert(
            key("example.com.", RecordType::A),
            entry(300, now, EntryKind::Positive, DnssecStatus::Bogus),
        );
        assert!(matches!(
            c.get(&key("example.com.", RecordType::A), now),
            Lookup::Miss
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn keys_are_case_insensitive_but_type_sensitive() {
        let c = cache();
        let now = Instant::now();
        c.insert(
            key("Example.COM", RecordType::A),
            entry(300, now, EntryKind::Positive, DnssecStatus::Insecure),
        );
        assert!(matches!(
            c.get(&key("example.com", RecordType::A), now),
            Lookup::Fresh { .. }
        ));
        assert!(matches!(
            c.get(&key("example.com", RecordType::AAAA), now),
            Lookup::Miss
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn failure_cache_expires() {
        let c = cache();
        let now = Instant::now();
        c.record_failure(
            key("fail.example.", RecordType::A),
            FailureEntry {
                recorded_at: now,
                ttl: Duration::from_secs(5),
                rcode: ResponseCode::ServFail,
                reason: "test",
                consecutive: 1,
            },
        );
        assert!(c
            .failure(&key("fail.example.", RecordType::A), now)
            .is_some());
        assert!(c
            .failure(
                &key("fail.example.", RecordType::A),
                now + Duration::from_secs(6)
            )
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn variants_are_bounded_and_never_merged() {
        let c = cache();
        let now = Instant::now();
        let k = key("cdn.example.", RecordType::A);
        for i in 0..(MAX_VARIANTS_PER_KEY + 3) {
            let e = entry(60, now, EntryKind::Positive, DnssecStatus::Insecure);
            c.record_variant(
                k.clone(),
                VariantRecord {
                    fingerprint: i as u64,
                    message: Arc::clone(&e.message),
                    source: e.source.clone(),
                    observed_at: now + Duration::from_millis(i as u64),
                    ttl: 60,
                    dnssec: DnssecStatus::Insecure,
                },
                now,
            );
        }
        let set = c.variants(&k).expect("variants present");
        assert_eq!(set.variants.len(), MAX_VARIANTS_PER_KEY);
        // Each retained variant is a complete answer with a distinct fingerprint.
        let mut seen = std::collections::HashSet::new();
        for v in &set.variants {
            assert!(seen.insert(v.fingerprint));
            assert_eq!(v.message.answers.len(), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn flush_name_and_suffix() {
        let c = cache();
        let now = Instant::now();
        for n in ["a.example.com.", "b.example.com.", "other.net."] {
            c.insert(
                key(n, RecordType::A),
                entry(300, now, EntryKind::Positive, DnssecStatus::Insecure),
            );
        }
        c.run_maintenance();
        c.flush_name("a.example.com");
        c.run_maintenance();
        assert!(matches!(
            c.get(&key("a.example.com.", RecordType::A), now),
            Lookup::Miss
        ));
        assert!(matches!(
            c.get(&key("b.example.com.", RecordType::A), now),
            Lookup::Fresh { .. }
        ));
        c.flush_suffix("example.com");
        c.run_maintenance();
        assert!(matches!(
            c.get(&key("b.example.com.", RecordType::A), now),
            Lookup::Miss
        ));
        assert!(matches!(
            c.get(&key("other.net.", RecordType::A), now),
            Lookup::Fresh { .. }
        ));
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(name_in_suffix("a.example.com.", "example.com."));
        assert!(name_in_suffix("example.com.", "example.com."));
        assert!(!name_in_suffix("notexample.com.", "example.com."));
        assert!(name_in_suffix("anything.", "."));
    }
}
