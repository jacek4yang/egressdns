//! Deciding whether two authorities said the same thing.
//!
//! Used when an answer could not be proved and we need a second opinion before serving
//! it. The question is *not* "are these byte-identical" — for anything behind a CDN they
//! never are. Two resolvers asking about `www.microsoft.com` a second apart will get
//! different Akamai edge names and different addresses, and both are correct.
//!
//! So the comparison is on the shape of the answer rather than its contents:
//!
//! * the same response code, and both actually positive;
//! * the same terminal record type;
//! * terminal owner names under the same registrable suffix.
//!
//! The last is the one doing the work. GeoDNS moves a name between
//! `e13678.dscb.akamaiedge.net` and `e15316.dsca.akamaiedge.net`, which share
//! `akamaiedge.net`; a hijack that answers `www.microsoft.com` with an address of its own
//! does not have a CNAME terminal under Akamai at all, and is rejected. It is a weaker
//! test than DNSSEC and is never used in place of it — only when validation could not
//! complete for a reason of ours.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

/// Whether two answers to the same question are compatible.
///
/// Conservative by construction: anything it cannot make sense of is incompatible, since
/// the caller's fallback is to keep the original failure rather than to serve.
pub fn answers_are_compatible(a: &Message, b: &Message) -> bool {
    if a.metadata.response_code != b.metadata.response_code {
        return false;
    }
    if a.metadata.response_code != ResponseCode::NoError {
        return false;
    }
    let (Some(ta), Some(tb)) = (terminal(a), terminal(b)) else {
        return false;
    };
    if ta.1 != tb.1 {
        return false;
    }
    registrable_suffix(&ta.0) == registrable_suffix(&tb.0)
}

/// The owner name and type of the records the answer actually terminates in.
///
/// The terminal is the last non-CNAME RRset: following the chain is the whole point, since
/// the CNAMEs themselves are what differ between CDN answers.
fn terminal(msg: &Message) -> Option<(Name, RecordType)> {
    msg.answers
        .iter()
        .filter(|r| !matches!(r.record_type(), RecordType::CNAME | RecordType::RRSIG))
        .map(|r| (r.name.clone(), r.record_type()))
        .next_back()
        .or_else(|| {
            // A chain that ends in a CNAME with nothing after it: compare on where it
            // pointed, which is still more than nothing.
            msg.answers
                .iter()
                .filter(|r| r.record_type() == RecordType::CNAME)
                .map(|r| (r.name.clone(), r.record_type()))
                .next_back()
        })
}

/// The last two labels of a name, lower-cased.
///
/// A deliberate approximation of the registrable domain. It is not a public-suffix
/// lookup, and does not need to be: the comparison is between two answers to the *same*
/// question, so the failure mode of a multi-label suffix like `co.uk` is that two answers
/// under it look compatible when a stricter test might separate them. That is the safe
/// direction for a check whose job is to notice an answer pointing somewhere else
/// entirely.
fn registrable_suffix(name: &Name) -> String {
    let text = name.to_string().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = text.split('.').collect();
    if labels.len() <= 2 {
        return text;
    }
    labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("name")
    }

    fn msg(rcode: ResponseCode, records: Vec<Record>) -> Message {
        let mut m = Message::query();
        m.metadata.response_code = rcode;
        m.answers = records;
        m
    }

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 60, RData::CNAME(CNAME(name(target))))
    }

    fn a(owner: &str, ip: &str) -> Record {
        Record::from_rdata(
            name(owner),
            60,
            RData::A(A(Ipv4Addr::from_str(ip).expect("ip"))),
        )
    }

    /// The case this exists for: one name, two CDN answers, nothing in common but shape.
    #[test]
    fn geodns_variation_of_the_same_cdn_is_compatible() {
        let first = msg(
            ResponseCode::NoError,
            vec![
                cname("www.microsoft.com.", "www.microsoft.com-c-3.edgekey.net."),
                cname(
                    "www.microsoft.com-c-3.edgekey.net.",
                    "e13678.dscb.akamaiedge.net.",
                ),
                a("e13678.dscb.akamaiedge.net.", "23.32.29.8"),
            ],
        );
        let second = msg(
            ResponseCode::NoError,
            vec![
                cname("www.microsoft.com.", "www.microsoft.com-c-3.edgekey.net."),
                cname(
                    "www.microsoft.com-c-3.edgekey.net.",
                    "e15316.dsca.akamaiedge.net.",
                ),
                a("e15316.dsca.akamaiedge.net.", "96.17.180.42"),
            ],
        );
        assert!(answers_are_compatible(&first, &second));
    }

    /// An answer that skips the CDN entirely is what a hijack looks like.
    #[test]
    fn an_answer_pointing_somewhere_else_is_not_compatible() {
        let genuine = msg(
            ResponseCode::NoError,
            vec![
                cname("www.microsoft.com.", "e13678.dscb.akamaiedge.net."),
                a("e13678.dscb.akamaiedge.net.", "23.32.29.8"),
            ],
        );
        let hijacked = msg(
            ResponseCode::NoError,
            vec![a("www.microsoft.com.", "203.0.113.7")],
        );
        assert!(!answers_are_compatible(&genuine, &hijacked));
    }

    /// Never used to agree about a name *not* existing: a forged negative is the thing
    /// this whole path must not manufacture.
    #[test]
    fn negative_answers_are_never_compatible() {
        let a1 = msg(ResponseCode::NXDomain, vec![]);
        let a2 = msg(ResponseCode::NXDomain, vec![]);
        assert!(!answers_are_compatible(&a1, &a2));

        let empty = msg(ResponseCode::NoError, vec![]);
        assert!(!answers_are_compatible(&empty, &empty));
    }

    #[test]
    fn a_different_rcode_is_not_compatible() {
        let ok = msg(ResponseCode::NoError, vec![a("example.com.", "192.0.2.1")]);
        let refused = msg(ResponseCode::Refused, vec![]);
        assert!(!answers_are_compatible(&ok, &refused));
    }

    #[test]
    fn a_different_terminal_type_is_not_compatible() {
        let with_a = msg(ResponseCode::NoError, vec![a("example.com.", "192.0.2.1")]);
        let with_cname = msg(
            ResponseCode::NoError,
            vec![cname("example.com.", "elsewhere.example.net.")],
        );
        assert!(!answers_are_compatible(&with_a, &with_cname));
    }

    #[test]
    fn the_suffix_is_the_last_two_labels() {
        assert_eq!(
            registrable_suffix(&name("e1.dscb.akamaiedge.net.")),
            "akamaiedge.net"
        );
        assert_eq!(registrable_suffix(&name("Example.COM.")), "example.com");
        assert_eq!(registrable_suffix(&name("localhost.")), "localhost");
    }

    /// Two answers for one name that land in different registrable domains are exactly
    /// what a substituted answer looks like.
    #[test]
    fn different_registrable_suffixes_are_not_compatible() {
        let first = msg(
            ResponseCode::NoError,
            vec![
                cname("www.example.com.", "edge.akamaiedge.net."),
                a("edge.akamaiedge.net.", "23.32.29.8"),
            ],
        );
        let second = msg(
            ResponseCode::NoError,
            vec![
                cname("www.example.com.", "edge.attacker.test."),
                a("edge.attacker.test.", "203.0.113.7"),
            ],
        );
        assert!(!answers_are_compatible(&first, &second));
    }
}
