//! A minimal DNS client, used by health checks rather than by resolution.
//!
//! Installation, `doctor` and the systemd health check all need to ask a real question and
//! judge a real answer. Shelling out to `dig` made that check optional — a host without
//! `bind9-dnsutils` skipped it — and `dig` reports success for SERVFAIL, REFUSED and
//! NXDOMAIN alike, because from its point of view it asked and something replied. A
//! resolver that returns SERVFAIL to every query has answered, and is broken.
//!
//! So the check lives here, in the binary that ships anyway, and reports the rcode, the
//! records and the AD bit separately, letting each caller decide what "healthy" means for
//! what it is testing.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What to ask, and of whom.
#[derive(Debug, Clone)]
pub struct Request {
    /// Name to look up.
    pub name: String,
    /// Record type, as text.
    pub rtype: String,
    /// Resolver address.
    pub server: String,
    /// Resolver port.
    pub port: u16,
    /// Use TCP rather than UDP.
    pub tcp: bool,
    /// Set DO, so the answer carries DNSSEC records and the AD bit is meaningful.
    pub dnssec: bool,
    /// How long to wait.
    pub timeout: Duration,
}

/// What came back.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum QueryOutcome {
    /// A well-formed response arrived. It may still be a failure — see `rcode`.
    Answered {
        /// Response code, as text.
        rcode: String,
        /// Addresses in the answer section, when the question was for A or AAAA.
        addresses: Vec<String>,
        /// Number of records in the answer section, whatever their type.
        answer_records: usize,
        /// Whether the responder set AD.
        authenticated: bool,
        /// Whether the responder set TC.
        truncated: bool,
        /// Round trip in milliseconds.
        elapsed_ms: u64,
    },
    /// Nothing usable arrived.
    Failed {
        /// What went wrong.
        reason: String,
    },
}

impl QueryOutcome {
    /// Whether this is a healthy answer: NOERROR, and with records if required.
    pub fn is_usable(&self, require_answer: bool) -> bool {
        match self {
            Self::Answered {
                rcode,
                answer_records,
                ..
            } => rcode == "NOERROR" && (!require_answer || *answer_records > 0),
            Self::Failed { .. } => false,
        }
    }
}

/// The canonical short name of a response code.
///
/// `Display` renders these for humans — "No Error", "Non-Existent Domain" — and the
/// mnemonics scripts and operators expect are the IANA ones, so they are produced here
/// rather than by mangling the prose.
fn rcode_name(code: hickory_proto::op::ResponseCode) -> String {
    use hickory_proto::op::ResponseCode as R;
    match code {
        R::NoError => "NOERROR",
        R::FormErr => "FORMERR",
        R::ServFail => "SERVFAIL",
        R::NXDomain => "NXDOMAIN",
        R::NotImp => "NOTIMP",
        R::Refused => "REFUSED",
        R::YXDomain => "YXDOMAIN",
        R::YXRRSet => "YXRRSET",
        R::NXRRSet => "NXRRSET",
        R::NotAuth => "NOTAUTH",
        R::NotZone => "NOTZONE",
        R::BADVERS => "BADVERS",
        R::BADSIG => "BADSIG",
        R::BADKEY => "BADKEY",
        R::BADTIME => "BADTIME",
        R::BADMODE => "BADMODE",
        R::BADNAME => "BADNAME",
        R::BADALG => "BADALG",
        R::BADTRUNC => "BADTRUNC",
        R::BADCOOKIE => "BADCOOKIE",
        // Anything the crate adds later renders as its numeric code, which is
        // unambiguous and never silently equal to NOERROR.
        other => return format!("RCODE{}", u16::from(other)),
    }
    .to_string()
}

/// A name reduced to a comparable form: lowercase, no trailing root label.
fn normalise(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

fn failed(reason: impl Into<String>) -> QueryOutcome {
    QueryOutcome::Failed {
        reason: reason.into(),
    }
}

/// Ask one question and describe the answer.
pub async fn run(request: Request) -> QueryOutcome {
    let Ok(name) = Name::from_utf8(&request.name) else {
        return failed(format!("`{}` is not a valid DNS name", request.name));
    };
    let Ok(rtype) = request.rtype.to_uppercase().parse::<RecordType>() else {
        return failed(format!("`{}` is not a record type", request.rtype));
    };
    let Ok(ip) = request.server.parse::<IpAddr>() else {
        return failed(format!("`{}` is not an IP address", request.server));
    };
    let target = SocketAddr::new(ip, request.port);

    // `Message::query` assigns a random transaction id, which is what makes an off-path
    // answer detectably wrong. Keep it so the response can be matched against it.
    let mut message = Message::query();
    let id = message.id;
    message.metadata.message_type = MessageType::Query;
    message.metadata.op_code = OpCode::Query;
    message.metadata.recursion_desired = true;
    let mut query = Query::query(name.clone(), rtype);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    if request.dnssec {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        edns.set_version(0);
        edns.set_dnssec_ok(true);
        message.edns = Some(edns);
    }

    let Ok(bytes) = message.to_vec() else {
        return failed("could not encode the query");
    };

    let started = std::time::Instant::now();
    let exchange = if request.tcp {
        exchange_tcp(target, &bytes, request.timeout).await
    } else {
        exchange_udp(target, &bytes, request.timeout).await
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let response = match exchange {
        Ok(bytes) => bytes,
        Err(e) => return failed(e),
    };
    let Ok(parsed) = Message::from_vec(&response) else {
        return failed("the response could not be parsed");
    };
    // RFC 5452: an answer to a different question, or with a different ID, is not an
    // answer to ours.
    if parsed.id != id {
        return failed("the response transaction id did not match the query");
    }
    // Compared on the normalised label sequence rather than on `Name` equality: a name
    // parsed from the command line may not carry the fully-qualified flag that the
    // responder's echo does, and that difference is not a mismatch.
    let want = normalise(&name);
    let got = parsed.queries.first().map(|q| normalise(q.name()));
    if got.as_deref() != Some(want.as_str()) {
        return failed("the response question did not match the query");
    }

    let addresses: Vec<String> = parsed
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect();

    QueryOutcome::Answered {
        rcode: rcode_name(parsed.metadata.response_code),
        addresses,
        answer_records: parsed.answers.len(),
        authenticated: parsed.metadata.authentic_data,
        truncated: parsed.metadata.truncation,
        elapsed_ms,
    }
}

async fn exchange_udp(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("could not open a local socket: {e}"))?;
    socket
        .connect(target)
        .await
        .map_err(|e| format!("no route to {target}: {e}"))?;
    socket
        .send(query)
        .await
        .map_err(|e| format!("could not send to {target}: {e}"))?;

    let mut buf = vec![0u8; 65_535];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Err(_) => Err(format!("no response from {target} within {timeout:?}")),
        Ok(Err(e)) => Err(format!("receive failed: {e}")),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
    }
}

async fn exchange_tcp(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let result = tokio::time::timeout(timeout, async {
        let mut stream = tokio::net::TcpStream::connect(target)
            .await
            .map_err(|e| format!("could not connect to {target}: {e}"))?;
        // RFC 7766: a two-octet length prefix precedes the message.
        let len = u16::try_from(query.len()).map_err(|_| String::from("query too long"))?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        stream
            .write_all(query)
            .await
            .map_err(|e| format!("write failed: {e}"))?;

        let mut header = [0u8; 2];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| format!("no length prefix from {target}: {e}"))?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(header))];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("truncated response from {target}: {e}"))?;
        Ok::<Vec<u8>, String>(body)
    })
    .await;

    match result {
        Err(_) => Err(format!("no response from {target} within {timeout:?}")),
        Ok(inner) => inner,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_malformed_name_is_reported_rather_than_sent() {
        let outcome = run(Request {
            name: String::from("not a name at all!!"),
            rtype: String::from("A"),
            server: String::from("127.0.0.1"),
            port: 53,
            tcp: false,
            dnssec: false,
            timeout: Duration::from_millis(10),
        })
        .await;
        assert!(matches!(outcome, QueryOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn an_unknown_record_type_is_reported() {
        let outcome = run(Request {
            name: String::from("example.com"),
            rtype: String::from("NOTATYPE"),
            server: String::from("127.0.0.1"),
            port: 53,
            tcp: false,
            dnssec: false,
            timeout: Duration::from_millis(10),
        })
        .await;
        match outcome {
            QueryOutcome::Failed { reason } => assert!(reason.contains("record type"), "{reason}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// The distinction the whole module exists for: a response is not a healthy answer.
    #[test]
    fn only_noerror_counts_as_usable() {
        let servfail = QueryOutcome::Answered {
            rcode: String::from("SERVFAIL"),
            addresses: Vec::new(),
            answer_records: 0,
            authenticated: false,
            truncated: false,
            elapsed_ms: 1,
        };
        assert!(!servfail.is_usable(false), "SERVFAIL is not healthy");

        let nodata = QueryOutcome::Answered {
            rcode: String::from("NOERROR"),
            addresses: Vec::new(),
            answer_records: 0,
            authenticated: false,
            truncated: false,
            elapsed_ms: 1,
        };
        assert!(nodata.is_usable(false), "NOERROR alone is a valid answer");
        assert!(
            !nodata.is_usable(true),
            "NOERROR with no records is not an answer when one was required"
        );

        let ok = QueryOutcome::Answered {
            rcode: String::from("NOERROR"),
            addresses: vec![String::from("203.0.113.1")],
            answer_records: 1,
            authenticated: true,
            truncated: false,
            elapsed_ms: 1,
        };
        assert!(ok.is_usable(true));

        assert!(!failed("nothing came back").is_usable(false));
    }
}
