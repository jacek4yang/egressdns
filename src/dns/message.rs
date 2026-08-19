//! DNS message helpers: TTL arithmetic, EDNS options, truncation-aware serialisation and
//! answer fingerprinting.
//!
//! Everything in this module is pure and synchronous so that it can be exercised by unit,
//! property and fuzz tests without any I/O.

use std::net::IpAddr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

/// RFC 8914 Extended DNS Error option code.
pub const EDE_OPTION_CODE: u16 = 15;
/// RFC 7873 DNS Cookie option code.
pub const COOKIE_OPTION_CODE: u16 = 10;
/// RFC 7828 edns-tcp-keepalive option code.
pub const KEEPALIVE_OPTION_CODE: u16 = 11;

/// The subset of RFC 8914 INFO-CODEs this resolver emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtendedError {
    /// 0 - Other.
    Other = 0,
    /// 3 - Stale Answer (RFC 8767).
    StaleAnswer = 3,
    /// 4 - Forged Answer.
    ForgedAnswer = 4,
    /// 5 - DNSSEC Indeterminate.
    DnssecIndeterminate = 5,
    /// 6 - DNSSEC Bogus.
    DnssecBogus = 6,
    /// 7 - Signature Expired.
    SignatureExpired = 7,
    /// 8 - Signature Not Yet Valid.
    SignatureNotYetValid = 8,
    /// 12 - NSEC Missing.
    NsecMissing = 12,
    /// 14 - Not Ready.
    NotReady = 14,
    /// 15 - Blocked.
    Blocked = 15,
    /// 18 - Prohibited.
    Prohibited = 18,
    /// 19 - Stale NXDOMAIN Answer.
    StaleNxdomain = 19,
    /// 22 - No Reachable Authority.
    NoReachableAuthority = 22,
    /// 23 - Network Error.
    NetworkError = 23,
}

impl ExtendedError {
    /// Numeric INFO-CODE.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::StaleAnswer => "stale_answer",
            Self::ForgedAnswer => "forged_answer",
            Self::DnssecIndeterminate => "dnssec_indeterminate",
            Self::DnssecBogus => "dnssec_bogus",
            Self::SignatureExpired => "signature_expired",
            Self::SignatureNotYetValid => "signature_not_yet_valid",
            Self::NsecMissing => "nsec_missing",
            Self::NotReady => "not_ready",
            Self::Blocked => "blocked",
            Self::Prohibited => "prohibited",
            Self::StaleNxdomain => "stale_nxdomain",
            Self::NoReachableAuthority => "no_reachable_authority",
            Self::NetworkError => "network_error",
        }
    }
}

/// Encode an RFC 8914 Extended DNS Error as a generic EDNS option.
///
/// hickory-proto models unrecognised EDNS options as `EdnsOption::Unknown`, so the two
/// octet INFO-CODE and the UTF-8 EXTRA-TEXT are assembled here. The extra text is
/// truncated so that a hostile or verbose upstream cannot inflate response size.
pub fn encode_ede(err: ExtendedError, extra_text: &str) -> EdnsOption {
    let mut buf = Vec::with_capacity(2 + extra_text.len().min(64));
    buf.extend_from_slice(&err.code().to_be_bytes());
    let text = crate::util::bounded(extra_text, 60);
    buf.extend_from_slice(text.as_bytes());
    EdnsOption::Unknown(EDE_OPTION_CODE, buf)
}

/// Decode an RFC 8914 Extended DNS Error, returning the INFO-CODE and EXTRA-TEXT.
pub fn decode_ede(option: &EdnsOption) -> Option<(u16, String)> {
    let EdnsOption::Unknown(code, bytes) = option else {
        return None;
    };
    if *code != EDE_OPTION_CODE || bytes.len() < 2 {
        return None;
    }
    let info = u16::from_be_bytes([bytes[0], bytes[1]]);
    let text = String::from_utf8_lossy(&bytes[2..]).to_string();
    Some((info, text))
}

/// Attach an Extended DNS Error to a message, creating nothing if the client did not
/// signal EDNS support (RFC 6891 forbids adding an OPT record in that case).
pub fn attach_ede(msg: &mut Message, err: ExtendedError, extra_text: &str) {
    if let Some(edns) = msg.edns.as_mut() {
        edns.options_mut().insert(encode_ede(err, extra_text));
    }
}

/// Read every Extended DNS Error present in a message.
pub fn extract_edes(msg: &Message) -> Vec<(u16, String)> {
    let Some(edns) = msg.edns.as_ref() else {
        return Vec::new();
    };
    edns.options()
        .get_all(EdnsCode::from(EDE_OPTION_CODE))
        .into_iter()
        .filter_map(decode_ede)
        .collect()
}

/// Build an RFC 7873 cookie option carrying only the 8 octet client cookie.
pub fn encode_client_cookie(client: [u8; 8]) -> EdnsOption {
    EdnsOption::Unknown(COOKIE_OPTION_CODE, client.to_vec())
}

/// Build a full RFC 7873 cookie option echoing a previously learned server cookie.
pub fn encode_full_cookie(client: [u8; 8], server: &[u8]) -> EdnsOption {
    let mut buf = Vec::with_capacity(8 + server.len().min(32));
    buf.extend_from_slice(&client);
    buf.extend_from_slice(&server[..server.len().min(32)]);
    EdnsOption::Unknown(COOKIE_OPTION_CODE, buf)
}

/// Extract the server cookie from a response, validating the echoed client cookie.
///
/// RFC 7873 section 5.3: the client MUST verify that the client cookie in the response
/// equals the one it sent. A mismatch means the response is not trustworthy.
pub fn extract_server_cookie(msg: &Message, expect_client: [u8; 8]) -> Option<Vec<u8>> {
    let edns = msg.edns.as_ref()?;
    let option = edns.options().get(EdnsCode::from(COOKIE_OPTION_CODE))?;
    let EdnsOption::Unknown(_, bytes) = option else {
        return None;
    };
    if bytes.len() < 8 || bytes[..8] != expect_client {
        return None;
    }
    let server = &bytes[8..];
    if server.is_empty() {
        return Some(Vec::new());
    }
    // A well-formed server cookie is 8 to 32 octets (RFC 7873 section 4).
    if !(8..=32).contains(&server.len()) {
        return None;
    }
    Some(server.to_vec())
}

/// Encode an RFC 7828 edns-tcp-keepalive option. Units are 100 ms.
pub fn encode_tcp_keepalive(idle: std::time::Duration) -> EdnsOption {
    let units = (idle.as_millis() / 100).min(u128::from(u16::MAX)) as u16;
    EdnsOption::Unknown(KEEPALIVE_OPTION_CODE, units.to_be_bytes().to_vec())
}

/// Build an ECS option for a fixed prefix (RFC 7871).
pub fn encode_ecs(prefix: IpAddr, source_prefix_len: u8) -> EdnsOption {
    EdnsOption::Subnet(ClientSubnet::new(prefix, source_prefix_len, 0))
}

/// Read the ECS option from a message, if present.
pub fn extract_ecs(msg: &Message) -> Option<ClientSubnet> {
    let edns = msg.edns.as_ref()?;
    match edns.options().get(EdnsCode::Subnet)? {
        EdnsOption::Subnet(cs) => Some(*cs),
        _ => None,
    }
}

/// Remove any ECS option from a message.
pub fn strip_ecs(msg: &mut Message) {
    if let Some(edns) = msg.edns.as_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

/// Apply `f` to the TTL of every resource record in every section.
pub fn map_ttls(msg: &mut Message, f: impl Fn(u32) -> u32 + Copy) {
    for r in msg
        .answers
        .iter_mut()
        .chain(msg.authorities.iter_mut())
        .chain(msg.additionals.iter_mut())
    {
        r.ttl = f(r.ttl);
    }
}

/// Cap every TTL in the message at `cap`. This can only ever reduce a TTL.
pub fn cap_ttls(msg: &mut Message, cap: u32) {
    map_ttls(msg, |ttl| ttl.min(cap));
}

/// Reduce every TTL by `elapsed` seconds, saturating at zero.
pub fn age_ttls(msg: &mut Message, elapsed: u32) {
    map_ttls(msg, |ttl| ttl.saturating_sub(elapsed));
}

/// Smallest TTL across all resource records, ignoring the OPT pseudo-record.
pub fn min_ttl(msg: &Message) -> Option<u32> {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| r.ttl)
        .min()
}

/// Largest TTL across all resource records, ignoring the OPT pseudo-record.
pub fn max_ttl(msg: &Message) -> Option<u32> {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| r.ttl)
        .max()
}

/// Outcome of a size-limited serialisation.
#[derive(Debug, Clone)]
pub struct Serialized {
    /// Wire bytes.
    pub bytes: Vec<u8>,
    /// Whether the TC bit had to be set because the message did not fit.
    pub truncated: bool,
}

/// Serialise a message, honouring a maximum wire size.
///
/// When the full message does not fit, the response is re-encoded as a header-only answer
/// with TC set, carrying the question section and the OPT record. This is what a client
/// needs in order to retry over TCP, and it avoids emitting a partially populated answer
/// section that a strict client might misinterpret.
pub fn serialize_limited(msg: &Message, max_size: usize) -> Result<Serialized, String> {
    let limit = max_size.clamp(512, 65_535) as u16;
    let mut buffer = Vec::with_capacity(limit as usize);
    let header = {
        let mut encoder = BinEncoder::new(&mut buffer);
        encoder.set_max_size(limit);
        match hickory_proto::op::emit_message_parts(
            &msg.metadata,
            &mut msg.queries.iter(),
            &mut msg.answers.iter(),
            &mut msg.authorities.iter(),
            &mut msg.additionals.iter(),
            msg.edns.as_ref(),
            msg.signature.as_deref(),
            &mut encoder,
        ) {
            Ok(h) => h,
            Err(e) => return Err(e.to_string()),
        }
    };

    if !header.truncation || msg.metadata.truncation {
        return Ok(Serialized {
            bytes: buffer,
            truncated: header.truncation,
        });
    }

    // Re-encode as a minimal truncated response.
    let minimal = msg.truncate();
    let mut small = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut small);
        encoder.set_max_size(limit);
        if let Err(e) = minimal.emit(&mut encoder) {
            return Err(e.to_string());
        }
    }
    Ok(Serialized {
        bytes: small,
        truncated: true,
    })
}

/// Build a bare error response for a request that could not be processed.
pub fn error_response(request: &Message, code: ResponseCode, recursion_available: bool) -> Message {
    let mut msg = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    msg.metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    msg.metadata.response_code = code;
    msg.metadata.recursion_available = recursion_available;
    msg.add_queries(request.queries.iter().cloned());
    if let Some(req_edns) = request.edns.as_ref() {
        let mut edns = Edns::new();
        edns.set_max_payload(req_edns.max_payload());
        edns.set_version(0);
        edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        msg.set_edns(edns);
    }
    msg
}

/// Build a response skeleton mirroring the request.
pub fn response_skeleton(request: &Message, recursion_available: bool) -> Message {
    let mut msg = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    msg.metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    msg.metadata.recursion_available = recursion_available;
    msg.add_queries(request.queries.iter().cloned());
    msg
}

/// RFC 8482: answer `QTYPE=ANY` with a single synthesised HINFO RRset.
pub fn minimal_any_response(request: &Message, ttl: u32) -> Message {
    let mut msg = response_skeleton(request, true);
    if let Some(q) = request.queries.first() {
        let hinfo = hickory_proto::rr::rdata::HINFO::new("RFC8482".to_string(), String::new());
        msg.add_answer(Record::from_rdata(
            q.name().clone(),
            ttl,
            hickory_proto::rr::RData::HINFO(hinfo),
        ));
    }
    msg
}

/// A canonical, order-independent fingerprint of a complete answer.
///
/// Used to identify *answer variants*: two upstreams may legitimately return different but
/// individually complete RRsets for a CDN name. Variants are never merged; the fingerprint
/// lets the decision cache remember which complete variants have been observed.
pub fn answer_fingerprint(msg: &Message) -> u64 {
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(msg.answers.len());
    for r in &msg.answers {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(r.name.to_string().to_ascii_lowercase().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&u16::from(r.record_type()).to_be_bytes());
        buf.extend_from_slice(&u16::from(r.dns_class).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(r.data.to_string().to_ascii_lowercase().as_bytes());
        parts.push(buf);
    }
    parts.sort_unstable();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for b in p {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Compare the question section of a response against the original query.
///
/// RFC 5452 section 9.1 requires the resolver to check that a response actually answers
/// the question that was asked. Name comparison is case-insensitive, which also makes the
/// check compatible with 0x20 case randomisation performed by the transport layer.
pub fn question_matches(request: &Message, response: &Message) -> bool {
    if request.queries.len() != response.queries.len() {
        return false;
    }
    request
        .queries
        .iter()
        .zip(response.queries.iter())
        .all(|(a, b)| {
            a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
                && a.name()
                    .to_string()
                    .eq_ignore_ascii_case(&b.name().to_string())
        })
}

/// True when the query class is one this resolver serves.
pub fn supported_class(q: &Query) -> bool {
    matches!(q.query_class(), DNSClass::IN | DNSClass::CH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData};
    use std::str::FromStr;

    fn a_record(name: &str, ttl: u32, ip: &str) -> Record {
        Record::from_rdata(
            Name::from_str(name).expect("valid name"),
            ttl,
            RData::A(A(ip.parse().expect("valid v4"))),
        )
    }

    fn sample_response() -> Message {
        let mut m = Message::new(1234, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("example.com.").expect("name"),
            RecordType::A,
        ));
        m.add_answer(a_record("example.com.", 300, "93.184.216.34"));
        m
    }

    #[test]
    fn ede_round_trip() {
        let opt = encode_ede(ExtendedError::StaleAnswer, "cache");
        let (code, text) = decode_ede(&opt).expect("decodes");
        assert_eq!(code, 3);
        assert_eq!(text, "cache");
    }

    #[test]
    fn ede_text_is_bounded() {
        let long = "x".repeat(4096);
        let opt = encode_ede(ExtendedError::Other, &long);
        let (_, text) = decode_ede(&opt).expect("decodes");
        assert!(text.chars().count() <= 61, "text was {} chars", text.len());
    }

    #[test]
    fn cookie_round_trip() {
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut m = sample_response();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(encode_full_cookie(client, &[9u8; 16]));
        m.set_edns(edns);
        let server = extract_server_cookie(&m, client).expect("server cookie");
        assert_eq!(server, vec![9u8; 16]);
        assert!(extract_server_cookie(&m, [0u8; 8]).is_none());
    }

    #[test]
    fn cookie_rejects_short_server_cookie() {
        let client = [1u8; 8];
        let mut m = sample_response();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(encode_full_cookie(client, &[9u8; 4]));
        m.set_edns(edns);
        assert!(extract_server_cookie(&m, client).is_none());
    }

    #[test]
    fn ttl_capping_only_reduces() {
        let mut m = sample_response();
        cap_ttls(&mut m, 60);
        assert_eq!(m.answers[0].ttl, 60);
        cap_ttls(&mut m, 600);
        assert_eq!(m.answers[0].ttl, 60, "cap must never increase a TTL");
    }

    #[test]
    fn ttl_aging_saturates() {
        let mut m = sample_response();
        age_ttls(&mut m, 1_000);
        assert_eq!(m.answers[0].ttl, 0);
    }

    #[test]
    fn serialize_sets_tc_when_too_large() {
        let mut m = sample_response();
        for i in 0..200u32 {
            m.add_answer(a_record(
                "example.com.",
                300,
                &format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
            ));
        }
        let out = serialize_limited(&m, 512).expect("encodes");
        assert!(out.truncated);
        assert!(out.bytes.len() <= 512);
        let decoded = Message::from_vec(&out.bytes).expect("decodes");
        assert!(decoded.metadata.truncation);
        assert!(decoded.answers.is_empty());
        assert_eq!(decoded.queries.len(), 1);
    }

    #[test]
    fn serialize_keeps_small_messages_intact() {
        let m = sample_response();
        let out = serialize_limited(&m, 1232).expect("encodes");
        assert!(!out.truncated);
        let decoded = Message::from_vec(&out.bytes).expect("decodes");
        assert_eq!(decoded.answers.len(), 1);
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let mut a = sample_response();
        a.add_answer(a_record("example.com.", 300, "93.184.216.35"));
        let mut b = Message::new(1234, MessageType::Response, OpCode::Query);
        b.add_query(Query::query(
            Name::from_str("example.com.").expect("name"),
            RecordType::A,
        ));
        b.add_answer(a_record("example.com.", 300, "93.184.216.35"));
        b.add_answer(a_record("example.com.", 300, "93.184.216.34"));
        assert_eq!(answer_fingerprint(&a), answer_fingerprint(&b));
    }

    #[test]
    fn fingerprint_distinguishes_different_sets() {
        let a = sample_response();
        let mut b = sample_response();
        b.answers.clear();
        b.add_answer(a_record("example.com.", 300, "1.2.3.4"));
        assert_ne!(answer_fingerprint(&a), answer_fingerprint(&b));
    }

    #[test]
    fn question_matching_is_case_insensitive() {
        let mut req = Message::new(1, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("ExAmPlE.CoM.").expect("name"),
            RecordType::A,
        ));
        let resp = sample_response();
        assert!(question_matches(&req, &resp));
    }

    #[test]
    fn question_mismatch_is_detected() {
        let mut req = Message::new(1, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("other.com.").expect("name"),
            RecordType::A,
        ));
        assert!(!question_matches(&req, &sample_response()));
    }
}
