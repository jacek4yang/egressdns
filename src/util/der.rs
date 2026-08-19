//! A deliberately minimal DER walker.
//!
//! Only two facts are extracted from an X.509 certificate that rustls has *already*
//! verified: the SHA-256 of the SubjectPublicKeyInfo, and the issuer common name. That is
//! enough to support SPKI pinning and CA constraints in probe validation profiles without
//! pulling in a general-purpose X.509 parser.
//!
//! The walker is strictly bounded: every length is checked against the remaining buffer,
//! nesting depth is capped, and any surprise returns `None` rather than panicking. It is
//! exercised by unit tests and by a dedicated fuzz target.

/// Maximum nesting depth followed while searching for the issuer name.
const MAX_DEPTH: usize = 12;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// Full encoding including the tag and length octets.
    raw: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_tlv(&mut self) -> Option<Tlv<'a>> {
        let start = self.pos;
        let tag = *self.buf.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        // High-tag-number form is not used in certificates; reject it.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let first = *self.buf.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        let len = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            // Indefinite length is not valid DER, and lengths above 4 octets are absurd
            // for a certificate.
            if n == 0 || n > 4 {
                return None;
            }
            let mut v: usize = 0;
            for _ in 0..n {
                let b = *self.buf.get(self.pos)?;
                self.pos = self.pos.checked_add(1)?;
                v = v.checked_shl(8)?.checked_add(usize::from(b))?;
            }
            v
        };
        let end = self.pos.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        let value = &self.buf[self.pos..end];
        let raw = &self.buf[start..end];
        self.pos = end;
        Some(Tlv { tag, value, raw })
    }
}

/// SHA-256 of the DER-encoded SubjectPublicKeyInfo of an X.509 certificate.
///
/// ```text
/// Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
/// TBSCertificate  ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
///                                validity, subject, subjectPublicKeyInfo, ... }
/// ```
pub fn spki_sha256(cert_der: &[u8]) -> Option<[u8; 32]> {
    let tbs = tbs_certificate(cert_der)?;
    let mut r = Reader::new(tbs);
    let mut fields: Vec<Tlv<'_>> = Vec::with_capacity(8);
    while !r.is_empty() && fields.len() < 8 {
        fields.push(r.read_tlv()?);
    }
    // With an explicit version tag ([0], 0xa0) the SPKI is field index 6, otherwise 5.
    let index = if fields.first().map(|t| t.tag) == Some(0xa0) {
        6
    } else {
        5
    };
    let spki = fields.get(index)?;
    if spki.tag != 0x30 {
        return None;
    }
    Some(crate::util::sha256(spki.raw))
}

/// Issuer common name of an X.509 certificate, if present.
pub fn issuer_common_name(cert_der: &[u8]) -> Option<String> {
    let tbs = tbs_certificate(cert_der)?;
    let mut r = Reader::new(tbs);
    let mut fields: Vec<Tlv<'_>> = Vec::with_capacity(6);
    while !r.is_empty() && fields.len() < 6 {
        fields.push(r.read_tlv()?);
    }
    let index = if fields.first().map(|t| t.tag) == Some(0xa0) {
        3
    } else {
        2
    };
    let issuer = fields.get(index)?;
    find_common_name(issuer.value, 0)
}

fn tbs_certificate(cert_der: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(cert_der);
    let outer = r.read_tlv()?;
    if outer.tag != 0x30 {
        return None;
    }
    let mut inner = Reader::new(outer.value);
    let tbs = inner.read_tlv()?;
    if tbs.tag != 0x30 {
        return None;
    }
    Some(tbs.value)
}

/// OID 2.5.4.3 (id-at-commonName) encoded as DER content octets.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

fn find_common_name(buf: &[u8], depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut r = Reader::new(buf);
    let mut last_oid_was_cn = false;
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        match tlv.tag {
            // OBJECT IDENTIFIER
            0x06 => last_oid_was_cn = tlv.value == OID_COMMON_NAME,
            // PrintableString, UTF8String, IA5String, T61String, BMPString
            0x13 | 0x0c | 0x16 | 0x14 | 0x1e if last_oid_was_cn => {
                let text = String::from_utf8_lossy(tlv.value).to_string();
                if text.is_empty() || text.len() > 256 {
                    return None;
                }
                return Some(text);
            }
            // Constructed types: SEQUENCE, SET.
            0x30 | 0x31 => {
                if let Some(found) = find_common_name(tlv.value, depth + 1) {
                    return Some(found);
                }
            }
            _ => last_oid_was_cn = false,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(cn: &str) -> Vec<u8> {
        let mut params =
            rcgen::CertificateParams::new(vec!["example.test".to_string()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("cert");
        cert.der().to_vec()
    }

    #[test]
    fn extracts_spki_and_issuer() {
        let der = self_signed("EgressDNS Test CA");
        let spki = spki_sha256(&der).expect("spki");
        assert_eq!(spki.len(), 32);
        assert_eq!(
            issuer_common_name(&der).as_deref(),
            Some("EgressDNS Test CA")
        );
    }

    #[test]
    fn spki_is_stable_for_the_same_key() {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut a = rcgen::CertificateParams::new(vec!["a.test".to_string()]).expect("params");
        a.distinguished_name = rcgen::DistinguishedName::new();
        a.distinguished_name.push(rcgen::DnType::CommonName, "A");
        let mut b = rcgen::CertificateParams::new(vec!["b.test".to_string()]).expect("params");
        b.distinguished_name = rcgen::DistinguishedName::new();
        b.distinguished_name.push(rcgen::DnType::CommonName, "B");
        let ca = a.self_signed(&key).expect("cert");
        let cb = b.self_signed(&key).expect("cert");
        assert_eq!(
            spki_sha256(ca.der()).expect("a"),
            spki_sha256(cb.der()).expect("b"),
            "the same key must produce the same SPKI hash"
        );
    }

    #[test]
    fn malformed_input_never_panics() {
        let der = self_signed("Trunc");
        for cut in 0..der.len().min(400) {
            let _ = spki_sha256(&der[..cut]);
            let _ = issuer_common_name(&der[..cut]);
        }
        for junk in [
            vec![],
            vec![0x30],
            vec![0x30, 0x80],
            vec![0x30, 0xff, 0xff, 0xff, 0xff, 0xff],
            vec![0x1f, 0x01, 0x02],
            vec![0xff; 64],
        ] {
            let _ = spki_sha256(&junk);
            let _ = issuer_common_name(&junk);
        }
    }

    #[test]
    fn deeply_nested_input_terminates() {
        // A pathological chain of nested SEQUENCEs must hit the depth cap, not recurse
        // without bound.
        let mut buf = vec![0x04, 0x00];
        for _ in 0..64 {
            let len = buf.len();
            let mut next = vec![0x30, len as u8];
            next.extend_from_slice(&buf);
            buf = next;
        }
        assert!(find_common_name(&buf, 0).is_none());
    }
}
