//! Cloudflare eligibility rules.
//!
//! A domain becomes eligible for Cloudflare-specific treatment only through observation of
//! the actual DNS answer, never through its name, its NS records, GeoIP, ASN data or a
//! third-party list.

use std::net::IpAddr;

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

use crate::cache::DnssecStatus;
use crate::cloudflare::prefixes::PrefixSnapshot;
use crate::config::CloudflareMode;

/// Result of the eligibility evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    /// No Cloudflare-specific processing at all.
    Off,
    /// Reordering inside the original RRset is permitted.
    Preserve,
    /// Prepending verified Cloudflare addresses is permitted.
    Augment,
}

/// Why a stronger mode was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// The subsystem is disabled.
    Disabled,
    /// The answer contains no Cloudflare-owned address.
    NotCloudflare,
    /// The record type is not eligible.
    RecordType,
    /// Policy explicitly excludes the domain.
    DomainExcluded,
    /// DNSSEC state is Secure, so records must not be added.
    DnssecSecure,
    /// DNSSEC state could not be established.
    DnssecUnknown,
    /// The domain publishes ECH parameters this build cannot validate end to end.
    EchUnvalidatable,
    /// No original address completed a baseline TLS or HTTP validation.
    NoBaseline,
    /// No verified candidate is available for this domain.
    NoVerifiedCandidate,
    /// The answer's RRset structure is not a single simple RRset.
    ComplexAnswer,
    /// Configured mode is preserve.
    ModeIsPreserve,
}

impl FallbackReason {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NotCloudflare => "not_cloudflare",
            Self::RecordType => "record_type",
            Self::DomainExcluded => "domain_excluded",
            Self::DnssecSecure => "dnssec_secure",
            Self::DnssecUnknown => "dnssec_unknown",
            Self::EchUnvalidatable => "ech_unvalidatable",
            Self::NoBaseline => "no_baseline",
            Self::NoVerifiedCandidate => "no_verified_candidate",
            Self::ComplexAnswer => "complex_answer",
            Self::ModeIsPreserve => "mode_is_preserve",
        }
    }
}

/// Inputs for the eligibility decision.
#[derive(Debug, Clone, Copy)]
pub struct EligibilityInputs<'a> {
    /// Configured mode.
    pub mode: CloudflareMode,
    /// Whether the subsystem is enabled at all.
    pub enabled: bool,
    /// Query type.
    pub qtype: RecordType,
    /// DNSSEC state of the answer.
    pub dnssec: DnssecStatus,
    /// Current official prefix snapshot.
    pub snapshot: Option<&'a PrefixSnapshot>,
    /// Addresses in the original RRset, in upstream order.
    pub original: &'a [IpAddr],
    /// The answer contains exactly one RRset of the queried type.
    pub single_rrset: bool,
    /// The domain is excluded by allow/deny policy.
    pub excluded: bool,
    /// The domain publishes ECH parameters.
    pub publishes_ech: bool,
    /// This build can validate the published ECH configuration end to end.
    pub can_validate_ech: bool,
    /// At least one original address completed a baseline TLS or HTTP validation.
    pub baseline_validated: bool,
    /// At least one verified candidate is available for this exact hostname.
    pub has_verified_candidate: bool,
}

/// Evaluate Cloudflare eligibility.
pub fn evaluate(inputs: EligibilityInputs<'_>) -> (Eligibility, Option<FallbackReason>) {
    if !inputs.enabled || inputs.mode == CloudflareMode::Off {
        return (Eligibility::Off, Some(FallbackReason::Disabled));
    }
    if !matches!(inputs.qtype, RecordType::A | RecordType::AAAA) {
        return (Eligibility::Off, Some(FallbackReason::RecordType));
    }
    if inputs.excluded {
        return (Eligibility::Off, Some(FallbackReason::DomainExcluded));
    }
    let Some(snapshot) = inputs.snapshot else {
        return (Eligibility::Off, Some(FallbackReason::NotCloudflare));
    };
    // Condition 1: the answer must actually contain a Cloudflare-owned address.
    if !inputs.original.iter().any(|a| snapshot.contains(*a)) {
        return (Eligibility::Off, Some(FallbackReason::NotCloudflare));
    }

    if inputs.mode == CloudflareMode::Preserve {
        return (Eligibility::Preserve, Some(FallbackReason::ModeIsPreserve));
    }

    // From here the configured mode is verified-augment; every additional condition that
    // fails degrades to preserve, never to something stronger.
    if !inputs.single_rrset {
        return (Eligibility::Preserve, Some(FallbackReason::ComplexAnswer));
    }
    match inputs.dnssec {
        DnssecStatus::Secure => return (Eligibility::Preserve, Some(FallbackReason::DnssecSecure)),
        DnssecStatus::Indeterminate | DnssecStatus::Bogus => {
            return (Eligibility::Preserve, Some(FallbackReason::DnssecUnknown))
        }
        DnssecStatus::Insecure => {}
    }
    if inputs.publishes_ech && !inputs.can_validate_ech {
        return (
            Eligibility::Preserve,
            Some(FallbackReason::EchUnvalidatable),
        );
    }
    if !inputs.baseline_validated {
        return (Eligibility::Preserve, Some(FallbackReason::NoBaseline));
    }
    if !inputs.has_verified_candidate {
        return (
            Eligibility::Preserve,
            Some(FallbackReason::NoVerifiedCandidate),
        );
    }
    (Eligibility::Augment, None)
}

/// True when the answer publishes ECH parameters in an HTTPS or SVCB record.
///
/// SvcParamKey 5 is `ech` (RFC 9460 registry, defined by RFC 9849). The parameter is never
/// removed or rewritten; its presence merely means verified-augment must fall back to
/// preserve unless the TLS stack can validate the ECH path.
pub fn publishes_ech(msg: &Message) -> bool {
    for r in msg
        .answers
        .iter()
        .chain(msg.additionals.iter())
        .chain(msg.authorities.iter())
    {
        let params = match &r.data {
            RData::HTTPS(https) => &https.0.svc_params,
            RData::SVCB(svcb) => &svcb.svc_params,
            _ => continue,
        };
        for (key, _) in params.iter() {
            if *key == hickory_proto::rr::rdata::svcb::SvcParamKey::EchConfigList {
                return true;
            }
        }
    }
    false
}

/// Whether a domain is excluded by the allow/deny policy.
///
/// Deny is evaluated first. An empty allow list means "no restriction".
pub fn is_excluded(name: &str, allow: &[String], deny: &[String]) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if deny.iter().any(|d| matches_domain(&n, d)) {
        return true;
    }
    if allow.is_empty() {
        return false;
    }
    !allow.iter().any(|a| matches_domain(&n, a))
}

fn matches_domain(name: &str, pattern: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix('.') {
        return name == suffix || name.ends_with(&format!(".{suffix}"));
    }
    name == p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("ip")
    }

    fn inputs<'a>(
        snapshot: &'a PrefixSnapshot,
        original: &'a [IpAddr],
        dnssec: DnssecStatus,
    ) -> EligibilityInputs<'a> {
        EligibilityInputs {
            mode: CloudflareMode::VerifiedAugment,
            enabled: true,
            qtype: RecordType::A,
            dnssec,
            snapshot: Some(snapshot),
            original,
            single_rrset: true,
            excluded: false,
            publishes_ech: false,
            can_validate_ech: false,
            baseline_validated: true,
            has_verified_candidate: true,
        }
    }

    #[test]
    fn augment_requires_every_condition() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        assert_eq!(
            evaluate(inputs(&snap, &cf, DnssecStatus::Insecure)).0,
            Eligibility::Augment
        );
    }

    #[test]
    fn dnssec_secure_never_augments() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        let (e, r) = evaluate(inputs(&snap, &cf, DnssecStatus::Secure));
        assert_eq!(e, Eligibility::Preserve);
        assert_eq!(r, Some(FallbackReason::DnssecSecure));
    }

    #[test]
    fn indeterminate_dnssec_never_augments() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        for status in [DnssecStatus::Indeterminate, DnssecStatus::Bogus] {
            let (e, r) = evaluate(inputs(&snap, &cf, status));
            assert_eq!(e, Eligibility::Preserve);
            assert_eq!(r, Some(FallbackReason::DnssecUnknown));
        }
    }

    #[test]
    fn unvalidatable_ech_falls_back_to_preserve() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        let mut i = inputs(&snap, &cf, DnssecStatus::Insecure);
        i.publishes_ech = true;
        i.can_validate_ech = false;
        let (e, r) = evaluate(i);
        assert_eq!(e, Eligibility::Preserve);
        assert_eq!(r, Some(FallbackReason::EchUnvalidatable));
    }

    #[test]
    fn missing_baseline_falls_back_to_preserve() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        let mut i = inputs(&snap, &cf, DnssecStatus::Insecure);
        i.baseline_validated = false;
        assert_eq!(evaluate(i).1, Some(FallbackReason::NoBaseline));
    }

    #[test]
    fn non_cloudflare_answers_are_untouched() {
        let snap = PrefixSnapshot::builtin();
        let other = vec![ip("8.8.8.8"), ip("1.1.1.1")];
        let (e, r) = evaluate(inputs(&snap, &other, DnssecStatus::Insecure));
        assert_eq!(e, Eligibility::Off);
        assert_eq!(r, Some(FallbackReason::NotCloudflare));
    }

    #[test]
    fn only_a_and_aaaa_are_eligible() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        for t in [
            RecordType::MX,
            RecordType::TXT,
            RecordType::HTTPS,
            RecordType::SRV,
        ] {
            let mut i = inputs(&snap, &cf, DnssecStatus::Insecure);
            i.qtype = t;
            assert_eq!(evaluate(i).0, Eligibility::Off, "{t} must be ineligible");
        }
    }

    #[test]
    fn preserve_mode_never_upgrades() {
        let snap = PrefixSnapshot::builtin();
        let cf = vec![ip("104.16.0.1")];
        let mut i = inputs(&snap, &cf, DnssecStatus::Insecure);
        i.mode = CloudflareMode::Preserve;
        assert_eq!(evaluate(i).0, Eligibility::Preserve);
    }

    #[test]
    fn domain_matching_respects_label_boundaries() {
        let deny = vec!["bank.example".to_string(), ".internal.test".to_string()];
        assert!(is_excluded("bank.example", &[], &deny));
        assert!(!is_excluded("notbank.example", &[], &deny));
        assert!(is_excluded("a.internal.test", &[], &deny));
        assert!(is_excluded("internal.test", &[], &deny));
        assert!(!is_excluded("internal.test.evil.com", &[], &deny));
    }

    #[test]
    fn allow_list_restricts_when_present() {
        let allow = vec![".cdn.example".to_string()];
        assert!(!is_excluded("a.cdn.example", &allow, &[]));
        assert!(is_excluded("other.example", &allow, &[]));
        assert!(!is_excluded("other.example", &[], &[]));
    }
}
