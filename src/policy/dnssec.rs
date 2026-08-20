//! Deriving a single DNSSEC state for a complete answer.

use hickory_proto::dnssec::Proof;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::cache::DnssecStatus;
use crate::config::{DnssecConfig, DnssecMode};
use crate::dns::proofwatch::ProofFailure;

/// What validation concluded, and — when it failed — whether the failure was about the
/// answer or about us.
///
/// `hickory` cannot express the difference: it writes `Proof::Bogus` both for a signature
/// that does not verify and for a chain lookup that never completed. The two demand
/// opposite responses, so this type keeps them apart. See [`crate::dns::proofwatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Authentic against the configured trust anchors.
    Secure,
    /// Proven, by an authenticated denial of DS, to lie outside any signed zone.
    ProvenInsecure,
    /// Validation completed and the data failed it. Fail closed.
    Bogus,
    /// Validation could not complete: part of the chain was never fetched. Says nothing
    /// about the data. Must not be cached as Bogus, and must not fail closed on its own.
    IncompleteProof,
    /// A route used during validation could not be reached at all.
    TransportFailure,
    /// Validation ran out of the foreground budget.
    Timeout,
    /// No proof either way — validation is off, the answer carried no records, or an
    /// algorithm we do not implement.
    Indeterminate,
}

impl ValidationOutcome {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::ProvenInsecure => "proven_insecure",
            Self::Bogus => "bogus",
            Self::IncompleteProof => "incomplete_proof",
            Self::TransportFailure => "transport_failure",
            Self::Timeout => "timeout",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Whether this outcome may be retried against a different authority.
    ///
    /// Only failures that are about *us* are retryable. Retrying Bogus would be looking
    /// for a resolver willing to give a different answer about forged data, which is the
    /// whole attack.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::IncompleteProof | Self::TransportFailure | Self::Timeout
        )
    }

    /// The cache state this outcome corresponds to.
    ///
    /// Everything unproven caches as Indeterminate, never as Bogus: a cached Bogus makes
    /// one interrupted lookup deny a name for the whole failure TTL.
    pub fn cache_status(self) -> DnssecStatus {
        match self {
            Self::Secure => DnssecStatus::Secure,
            Self::ProvenInsecure => DnssecStatus::Insecure,
            Self::Bogus => DnssecStatus::Bogus,
            Self::IncompleteProof | Self::TransportFailure | Self::Timeout => {
                DnssecStatus::Indeterminate
            }
            Self::Indeterminate => DnssecStatus::Indeterminate,
        }
    }
}

/// Classify a validated response, using what the transport observed to explain a failure.
///
/// This is [`dnssec_status`] plus the one thing it cannot know on its own: whether a
/// `Bogus` record is bogus because the data is bad, or because we never managed to fetch
/// the part of the chain that would have proved it good.
pub fn classify(
    msg: &Message,
    cfg: &DnssecConfig,
    upstream_trusted_ad: bool,
    observed: ProofFailure,
) -> ValidationOutcome {
    match dnssec_status(msg, cfg, upstream_trusted_ad) {
        DnssecStatus::Secure => ValidationOutcome::Secure,
        DnssecStatus::Insecure => ValidationOutcome::ProvenInsecure,
        DnssecStatus::Indeterminate => ValidationOutcome::Indeterminate,
        DnssecStatus::Bogus => match observed {
            // Nothing went wrong on our side, so the verdict is about the data.
            ProofFailure::None => ValidationOutcome::Bogus,
            ProofFailure::Deadline => ValidationOutcome::Timeout,
            ProofFailure::Transport => ValidationOutcome::TransportFailure,
            ProofFailure::Refused => ValidationOutcome::IncompleteProof,
        },
    }
}

/// Derive the DNSSEC state of a validated response.
///
/// hickory attaches a [`Proof`] to every record after local validation. The answer as a
/// whole is only Secure when *every* record that carries data is Secure: a single Bogus or
/// Indeterminate record means the answer must not be treated as authentic.
pub fn dnssec_status(msg: &Message, cfg: &DnssecConfig, upstream_trusted_ad: bool) -> DnssecStatus {
    if matches!(cfg.mode, DnssecMode::Off) {
        if cfg.trust_upstream_ad && upstream_trusted_ad && msg.metadata.authentic_data {
            return DnssecStatus::Secure;
        }
        return DnssecStatus::Indeterminate;
    }

    let mut saw_record = false;
    let mut worst = Proof::Secure;
    for r in msg
        .answers
        .iter()
        .chain(msg.authorities.iter())
        .filter(|r| r.record_type() != RecordType::OPT)
    {
        saw_record = true;
        // `Proof` orders Indeterminate < Bogus < Insecure < Secure, so the minimum is the
        // weakest claim present.
        if r.proof < worst {
            worst = r.proof;
        }
    }

    if !saw_record {
        // An answer with no records at all carries no proof either way.
        return DnssecStatus::Indeterminate;
    }

    match worst {
        Proof::Secure => DnssecStatus::Secure,
        Proof::Insecure => DnssecStatus::Insecure,
        Proof::Bogus => DnssecStatus::Bogus,
        Proof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

/// Earliest RRSIG expiry in a message, in seconds since the epoch.
///
/// Used to guarantee that a client-facing TTL never outlives the signature that makes the
/// data verifiable.
pub fn earliest_rrsig_expiry(msg: &Message) -> Option<u64> {
    use hickory_proto::rr::RData;
    let mut earliest: Option<u64> = None;
    for r in msg
        .answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
    {
        if let RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::RRSIG(sig)) = &r.data {
            let exp = u64::from(sig.input().sig_expiration.get());
            earliest = Some(match earliest {
                Some(e) => e.min(exp),
                None => exp,
            });
        }
    }
    earliest
}

/// Whether the AD bit may be set towards the client.
///
/// RFC 4035 section 3.2.3: AD means the resolver considers every RRset in the answer and
/// authority sections authentic. Locally modified data can never claim that, so callers
/// pass `modified = true` after any augmentation.
pub fn may_set_ad(status: DnssecStatus, client_asked: bool, modified: bool) -> bool {
    client_asked && status.is_authentic() && !modified
}

#[cfg(test)]
mod outcome_tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn cfg() -> DnssecConfig {
        DnssecConfig::default()
    }

    fn message_with(proof: Proof) -> Message {
        let mut r = Record::from_rdata(
            Name::from_str("www.bing.com.").expect("name"),
            60,
            RData::A(A(Ipv4Addr::new(23, 32, 29, 8))),
        );
        r.proof = proof;
        let mut m = Message::query();
        m.answers = vec![r];
        m
    }

    /// The defect this release exists to fix.
    ///
    /// `hickory` writes `Proof::Bogus` when a chain lookup does not complete, which is the
    /// same value it writes for a signature that does not verify. Classifying the first as
    /// Bogus is what made `www.bing.com` SERVFAIL on a host that could resolve it: a
    /// four-zone CNAME chain outran the foreground budget, and the resolver reported a
    /// cryptographic failure for its own clock running out.
    #[test]
    fn a_bogus_record_caused_by_a_deadline_is_not_a_bogus_answer() {
        let msg = message_with(Proof::Bogus);
        assert_eq!(
            classify(&msg, &cfg(), false, ProofFailure::Deadline),
            ValidationOutcome::Timeout,
        );
        assert_eq!(
            classify(&msg, &cfg(), false, ProofFailure::Transport),
            ValidationOutcome::TransportFailure,
        );
        assert_eq!(
            classify(&msg, &cfg(), false, ProofFailure::Refused),
            ValidationOutcome::IncompleteProof,
        );
    }

    /// The other half, which must not regress: when nothing went wrong on our side, a
    /// Bogus record is a verdict about the data and has to fail closed.
    #[test]
    fn a_bogus_record_with_a_clean_transport_is_still_bogus() {
        assert_eq!(
            classify(
                &message_with(Proof::Bogus),
                &cfg(),
                false,
                ProofFailure::None
            ),
            ValidationOutcome::Bogus,
        );
    }

    /// A transport failure alongside a *successful* validation changes nothing. Only a
    /// Bogus verdict is ever reinterpreted, because only Bogus is ambiguous.
    #[test]
    fn a_transport_failure_does_not_downgrade_a_secure_answer() {
        assert_eq!(
            classify(
                &message_with(Proof::Secure),
                &cfg(),
                false,
                ProofFailure::Transport
            ),
            ValidationOutcome::Secure,
        );
        assert_eq!(
            classify(
                &message_with(Proof::Insecure),
                &cfg(),
                false,
                ProofFailure::Deadline
            ),
            ValidationOutcome::ProvenInsecure,
        );
    }

    /// Only failures that are about us may be retried. Retrying Bogus would be shopping
    /// for a resolver willing to say something else about forged data.
    #[test]
    fn only_our_own_failures_are_retryable() {
        assert!(ValidationOutcome::IncompleteProof.is_retryable());
        assert!(ValidationOutcome::TransportFailure.is_retryable());
        assert!(ValidationOutcome::Timeout.is_retryable());
        assert!(!ValidationOutcome::Bogus.is_retryable());
        assert!(!ValidationOutcome::Secure.is_retryable());
        assert!(!ValidationOutcome::ProvenInsecure.is_retryable());
    }

    /// Nothing unproven may be cached as Bogus: a cached Bogus makes one interrupted
    /// lookup deny a working name for the whole failure TTL.
    #[test]
    fn an_unfinished_proof_never_caches_as_bogus() {
        for outcome in [
            ValidationOutcome::IncompleteProof,
            ValidationOutcome::TransportFailure,
            ValidationOutcome::Timeout,
            ValidationOutcome::Indeterminate,
        ] {
            assert_eq!(
                outcome.cache_status(),
                DnssecStatus::Indeterminate,
                "{outcome:?} must not be remembered as a verdict"
            );
        }
        assert_eq!(ValidationOutcome::Bogus.cache_status(), DnssecStatus::Bogus);
        assert_eq!(
            ValidationOutcome::Secure.cache_status(),
            DnssecStatus::Secure
        );
        assert_eq!(
            ValidationOutcome::ProvenInsecure.cache_status(),
            DnssecStatus::Insecure
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::str::FromStr;

    fn msg_with(proofs: &[Proof]) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("example.com.").expect("name"),
            RecordType::A,
        ));
        for (i, p) in proofs.iter().enumerate() {
            let mut r = Record::from_rdata(
                Name::from_str("example.com.").expect("name"),
                300,
                RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, i as u8))),
            );
            r.proof = *p;
            m.add_answer(r);
        }
        m
    }

    fn validating() -> DnssecConfig {
        DnssecConfig {
            mode: DnssecMode::Strict,
            ..DnssecConfig::default()
        }
    }

    #[test]
    fn all_secure_is_secure() {
        let m = msg_with(&[Proof::Secure, Proof::Secure]);
        assert_eq!(
            dnssec_status(&m, &validating(), false),
            DnssecStatus::Secure
        );
    }

    #[test]
    fn one_bogus_record_makes_the_answer_bogus() {
        let m = msg_with(&[Proof::Secure, Proof::Bogus, Proof::Secure]);
        assert_eq!(dnssec_status(&m, &validating(), false), DnssecStatus::Bogus);
    }

    #[test]
    fn one_indeterminate_record_makes_the_answer_indeterminate() {
        let m = msg_with(&[Proof::Secure, Proof::Indeterminate]);
        assert_eq!(
            dnssec_status(&m, &validating(), false),
            DnssecStatus::Indeterminate
        );
    }

    #[test]
    fn insecure_is_reported_as_insecure() {
        let m = msg_with(&[Proof::Insecure, Proof::Insecure]);
        assert_eq!(
            dnssec_status(&m, &validating(), false),
            DnssecStatus::Insecure
        );
    }

    #[test]
    fn validation_disabled_is_indeterminate_not_secure() {
        let cfg = DnssecConfig {
            mode: DnssecMode::Off,
            trust_upstream_ad: false,
            ..DnssecConfig::default()
        };
        let mut m = msg_with(&[Proof::Secure]);
        m.metadata.authentic_data = true;
        assert_eq!(
            dnssec_status(&m, &cfg, false),
            DnssecStatus::Indeterminate,
            "an upstream AD bit must not be trusted by default"
        );
    }

    #[test]
    fn upstream_ad_is_only_trusted_when_explicitly_configured() {
        let cfg = DnssecConfig {
            mode: DnssecMode::Off,
            trust_upstream_ad: true,
            ..DnssecConfig::default()
        };
        let mut m = msg_with(&[Proof::Indeterminate]);
        m.metadata.authentic_data = true;
        assert_eq!(dnssec_status(&m, &cfg, true), DnssecStatus::Secure);
        assert_eq!(dnssec_status(&m, &cfg, false), DnssecStatus::Indeterminate);
        m.metadata.authentic_data = false;
        assert_eq!(dnssec_status(&m, &cfg, true), DnssecStatus::Indeterminate);
    }

    #[test]
    fn ad_is_never_claimed_for_modified_data() {
        assert!(may_set_ad(DnssecStatus::Secure, true, false));
        assert!(!may_set_ad(DnssecStatus::Secure, true, true));
        assert!(!may_set_ad(DnssecStatus::Insecure, true, false));
        assert!(!may_set_ad(DnssecStatus::Secure, false, false));
    }

    #[test]
    fn empty_answer_is_indeterminate() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("example.com.").expect("name"),
            RecordType::A,
        ));
        assert_eq!(
            dnssec_status(&m, &validating(), false),
            DnssecStatus::Indeterminate
        );
    }
}
