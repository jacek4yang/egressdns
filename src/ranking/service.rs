//! Which names are actually web services.
//!
//! A DNS answer is a set of addresses. It is not a statement that anything is listening on
//! port 443, and treating it as one has two costs that are easy to miss:
//!
//! * **It measures the wrong thing.** An SSH host, a mail exchanger, a SIP gateway or a
//!   game server gets ranked by how well it completes a TLS handshake on a port it does
//!   not serve. Every address scores identically badly, so the ordering is noise dressed
//!   up as evidence.
//! * **It is rude, and it looks like scanning.** Every address in every answer receives an
//!   unsolicited connection to port 443. For a resolver handling arbitrary client traffic
//!   that is a lot of connections to a lot of hosts that never asked.
//!
//! So port-443 evidence is gathered, and used for ordering, only for names there is a
//! reason to believe are HTTPS services. The reason has to come from the protocol: an
//! HTTPS or SVCB record for the name, which is exactly the record that exists to say "this
//! name is a service, reachable this way".
//!
//! Everything else keeps the order the authority gave it, which is the correct default: an
//! answer nobody has evidence about should be passed through unchanged.

use std::sync::Arc;

use parking_lot::Mutex;

/// What is known about the service behind a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceClass {
    /// An HTTPS or SVCB record was seen for this name, so port 443 is meaningful.
    Https,
    /// Nothing is known. Addresses are ordered as the authority returned them.
    Unknown,
}

/// A bounded record of which names are web services.
///
/// Bounded because the key space is every name a client ever asks for, which is
/// adversarially unbounded. Names fall out of it under pressure; the consequence is that
/// a name reverts to `Unknown` and its addresses are passed through in authority order,
/// which is the safe direction.
pub struct ServiceClassifier {
    /// Names with observed HTTPS/SVCB evidence, most recent first.
    known: Mutex<Vec<Arc<str>>>,
    capacity: usize,
}

impl ServiceClassifier {
    /// Create a classifier holding at most `capacity` names.
    pub fn new(capacity: usize) -> Self {
        Self {
            known: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        }
    }

    /// Record that `name` has HTTPS or SVCB evidence.
    pub fn note_https(&self, name: &str) {
        let key = normalise(name);
        let mut known = self.known.lock();
        if let Some(pos) = known.iter().position(|n| n.as_ref() == key.as_str()) {
            // Move to front so the least recently confirmed name is the one evicted.
            let entry = known.remove(pos);
            known.insert(0, entry);
            return;
        }
        known.insert(0, Arc::from(key.as_str()));
        if known.len() > self.capacity {
            known.pop();
        }
    }

    /// What is known about `name`.
    pub fn classify(&self, name: &str) -> ServiceClass {
        let key = normalise(name);
        let known = self.known.lock();
        if known.iter().any(|n| n.as_ref() == key.as_str()) {
            ServiceClass::Https
        } else {
            ServiceClass::Unknown
        }
    }

    /// Whether port-443 evidence may be gathered and used for `name`.
    pub fn is_web_service(&self, name: &str) -> bool {
        self.classify(name) == ServiceClass::Https
    }

    /// Number of names currently classified, for diagnostics and bound tests.
    pub fn len(&self) -> usize {
        self.known.lock().len()
    }

    /// Whether anything is classified.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Names compare case-insensitively and without the root label.
fn normalise(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether a record type is evidence that a name is a service endpoint.
///
/// HTTPS (RFC 9460 type 65) and SVCB (type 64) exist precisely to say "this name is a
/// service, and here is how to reach it". Nothing else in a DNS answer does.
pub fn is_service_binding(rtype: hickory_proto::rr::RecordType) -> bool {
    matches!(
        rtype,
        hickory_proto::rr::RecordType::HTTPS | hickory_proto::rr::RecordType::SVCB
    )
}

/// Shared handle.
pub type SharedServiceClassifier = Arc<ServiceClassifier>;

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    #[test]
    fn a_name_with_no_evidence_is_unknown() {
        let c = ServiceClassifier::new(16);
        assert_eq!(c.classify("ssh.example.com"), ServiceClass::Unknown);
        assert!(!c.is_web_service("ssh.example.com"));
    }

    #[test]
    fn an_https_record_makes_a_name_a_web_service() {
        let c = ServiceClassifier::new(16);
        c.note_https("www.example.com.");
        assert_eq!(c.classify("www.example.com"), ServiceClass::Https);
        assert!(c.is_web_service("WWW.EXAMPLE.COM."));
    }

    /// Only the records that mean "this is a service" count as evidence.
    #[test]
    fn only_service_bindings_are_evidence() {
        assert!(is_service_binding(RecordType::HTTPS));
        assert!(is_service_binding(RecordType::SVCB));
        for other in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::TXT,
            RecordType::SRV,
            RecordType::CNAME,
            RecordType::NS,
        ] {
            assert!(
                !is_service_binding(other),
                "{other} must not imply an HTTPS service"
            );
        }
    }

    /// The key space is every name a client asks for, so it has to be bounded.
    #[test]
    fn the_classifier_is_bounded_under_adversarial_cardinality() {
        let c = ServiceClassifier::new(64);
        for i in 0..100_000 {
            c.note_https(&format!("n{i}.example.test"));
        }
        assert_eq!(c.len(), 64, "the classifier must not grow without bound");
        // The most recent survive; the oldest are gone and revert to Unknown, which is
        // the safe direction — an unknown name is passed through untouched.
        assert!(c.is_web_service("n99999.example.test"));
        assert!(!c.is_web_service("n0.example.test"));
    }

    #[test]
    fn re_confirming_a_name_keeps_it_from_being_evicted() {
        let c = ServiceClassifier::new(3);
        c.note_https("a.test");
        c.note_https("b.test");
        c.note_https("c.test");
        // Touch `a` so it is no longer the oldest.
        c.note_https("a.test");
        c.note_https("d.test");
        assert!(
            c.is_web_service("a.test"),
            "a was refreshed and must survive"
        );
        assert!(
            !c.is_web_service("b.test"),
            "b was the oldest and is evicted"
        );
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn duplicates_do_not_grow_the_table() {
        let c = ServiceClassifier::new(16);
        for _ in 0..1_000 {
            c.note_https("same.example.test");
        }
        assert_eq!(c.len(), 1);
    }
}
