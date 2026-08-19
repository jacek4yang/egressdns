//! Deriving a single DNSSEC state for a complete answer.

use hickory_proto::dnssec::Proof;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::cache::DnssecStatus;
use crate::config::{DnssecConfig, DnssecMode};

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
            mode: DnssecMode::Validate,
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
