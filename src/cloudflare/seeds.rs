//! Untrusted third-party candidate seed parsing.
//!
//! Seed endpoints are treated as *hints only*. Their output has no authority over DNS
//! answers: every address they propose must independently pass official-prefix membership,
//! special-use filtering and local protocol validation before it can ever appear in a
//! response.
//!
//! Observation from live traffic: these endpoints regularly return addresses that do **not**
//! belong to Cloudflare (recent samples included `188.164.248.83`, `91.193.59.179` and
//! `8.35.211.212`). The captured fixtures in `tests/fixtures/` preserve that reality, and
//! the security tests assert those addresses are rejected.

use std::net::{IpAddr, SocketAddr};

use crate::error::CloudflareError;

/// One parsed item from a seed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedItem {
    /// A literal address, with an optional port hint.
    Address {
        /// The address.
        addr: IpAddr,
        /// Port hint, when the entry carried one.
        port: Option<u16>,
    },
    /// A hostname that must be resolved through the baseline resolver, after which the
    /// resulting addresses are filtered against the official prefix snapshot.
    Hostname {
        /// The hostname.
        host: String,
        /// Port hint, when the entry carried one.
        port: Option<u16>,
    },
}

/// Statistics about a parse, used for diagnostics and metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedParseStats {
    /// Lines seen.
    pub lines: usize,
    /// Entries accepted.
    pub accepted: usize,
    /// Entries skipped because they were comments or blank.
    pub skipped: usize,
    /// Entries rejected because they were malformed.
    pub malformed: usize,
    /// Entries dropped because the response cap was reached.
    pub truncated: usize,
}

/// Parse a seed response.
///
/// The parser is intentionally conservative:
///
/// * The response must be UTF-8 and must not look like HTML.
/// * At most `max_items` entries are accepted; the rest are counted and dropped.
/// * A malformed entry is skipped, never fatal, because a single bad line must not cost
///   the whole (already low-trust) list.
pub fn parse(
    body: &[u8],
    max_items: usize,
) -> Result<(Vec<SeedItem>, SeedParseStats), CloudflareError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| CloudflareError::Parse("seed response was not valid UTF-8".into()))?;
    let head = text.trim_start();
    if head.starts_with('<') || head.starts_with("{\"") || head.starts_with('[') {
        return Err(CloudflareError::Parse(
            "seed response was markup or JSON, not a candidate list".into(),
        ));
    }

    let mut items = Vec::new();
    let mut stats = SeedParseStats::default();
    for raw_line in text.lines() {
        stats.lines += 1;
        if stats.lines > 100_000 {
            return Err(CloudflareError::Parse(
                "seed response had too many lines".into(),
            ));
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            stats.skipped += 1;
            continue;
        }
        // Strip a trailing `#comment`, which the observed endpoints always append.
        let payload = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        if payload.is_empty() {
            stats.skipped += 1;
            continue;
        }
        match parse_entry(payload) {
            Some(item) => {
                if items.len() >= max_items {
                    stats.truncated += 1;
                    continue;
                }
                items.push(item);
                stats.accepted += 1;
            }
            None => stats.malformed += 1,
        }
    }
    Ok((items, stats))
}

/// Parse a single entry in any of the observed forms.
fn parse_entry(s: &str) -> Option<SeedItem> {
    if s.len() > 300 {
        return None;
    }
    // `[v6]:port`
    if s.starts_with('[') {
        let sock: SocketAddr = s.parse().ok()?;
        return Some(SeedItem::Address {
            addr: sock.ip(),
            port: Some(sock.port()),
        });
    }
    // Bare address, IPv4 or IPv6.
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Some(SeedItem::Address { addr, port: None });
    }
    // `host:port` or `v4:port`.
    if let Some((host, port_str)) = s.rsplit_once(':') {
        // A bare IPv6 literal also contains colons; the earlier `parse::<IpAddr>` already
        // handled that case, so anything reaching here with several colons is malformed.
        if host.contains(':') {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        if port == 0 {
            return None;
        }
        if let Ok(addr) = host.parse::<IpAddr>() {
            return Some(SeedItem::Address {
                addr,
                port: Some(port),
            });
        }
        let host = validate_hostname(host)?;
        return Some(SeedItem::Hostname {
            host,
            port: Some(port),
        });
    }
    let host = validate_hostname(s)?;
    Some(SeedItem::Hostname { host, port: None })
}

/// Accept only conservative DNS hostnames.
fn validate_hostname(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    // A trailing label made entirely of digits means this was a malformed address such as
    // `999.999.999.999`, not a hostname.
    let last = s.rsplit('.').next().unwrap_or("");
    if last.is_empty() || last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const CT: &[u8] = include_bytes!("../../tests/fixtures/seed_ct.txt");
    const CU: &[u8] = include_bytes!("../../tests/fixtures/seed_cu.txt");
    const CMCC: &[u8] = include_bytes!("../../tests/fixtures/seed_cmcc.txt");
    const HTML: &[u8] = include_bytes!("../../tests/fixtures/seed_html.html");
    const MIXED: &[u8] = include_bytes!("../../tests/fixtures/seed_mixed_forms.txt");

    fn addrs(items: &[SeedItem]) -> Vec<IpAddr> {
        items
            .iter()
            .filter_map(|i| match i {
                SeedItem::Address { addr, .. } => Some(*addr),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn parses_live_captured_fixtures() {
        for fixture in [CT, CU, CMCC] {
            let (items, stats) = parse(fixture, 256).expect("parses");
            assert!(!items.is_empty());
            assert_eq!(stats.malformed, 0, "live fixture should parse cleanly");
            assert!(items.iter().all(|i| matches!(i, SeedItem::Address { .. })));
        }
    }

    #[test]
    fn live_fixtures_contain_non_cloudflare_addresses() {
        // This is the whole reason the seed source is untrusted.
        let snapshot = crate::cloudflare::prefixes::PrefixSnapshot::builtin();
        let (items, _) = parse(CT, 256).expect("parses");
        let outside: Vec<_> = addrs(&items)
            .into_iter()
            .filter(|a| !snapshot.contains(*a))
            .collect();
        assert!(
            !outside.is_empty(),
            "captured fixture is expected to include addresses outside Cloudflare's \
             published prefixes; if this ever stops being true the filter still applies"
        );
    }

    #[test]
    fn html_is_rejected() {
        let err = parse(HTML, 256).expect_err("HTML must be rejected");
        assert!(matches!(err, CloudflareError::Parse(_)));
    }

    #[test]
    fn json_is_rejected() {
        assert!(parse(br#"{"ips":["104.16.0.1"]}"#, 256).is_err());
        assert!(parse(br#"[{"ip":"104.16.0.1"}]"#, 256).is_err());
    }

    #[test]
    fn all_documented_forms_are_accepted() {
        let (items, stats) = parse(MIXED, 256).expect("parses");
        assert!(stats.malformed >= 3, "malformed lines must be counted");
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("104.16.0.1").expect("ip"),
            port: None
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("104.16.0.2").expect("ip"),
            port: Some(443)
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("104.16.0.3").expect("ip"),
            port: None
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("104.16.0.4").expect("ip"),
            port: Some(2053)
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("2606:4700::1111").expect("ip"),
            port: Some(443)
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("2606:4700::2222").expect("ip"),
            port: None
        }));
        assert!(items.contains(&SeedItem::Hostname {
            host: "cf.example.test".to_string(),
            port: None
        }));
        assert!(items.contains(&SeedItem::Hostname {
            host: "edge.example.test".to_string(),
            port: Some(443)
        }));
        assert!(items.contains(&SeedItem::Address {
            addr: IpAddr::from_str("104.16.0.5").expect("ip"),
            port: None
        }));
    }

    #[test]
    fn item_count_is_capped() {
        let mut body = String::new();
        for i in 0..500 {
            body.push_str(&format!("104.16.{}.{}\n", i / 256, i % 256));
        }
        let (items, stats) = parse(body.as_bytes(), 64).expect("parses");
        assert_eq!(items.len(), 64);
        assert!(stats.truncated >= 436);
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let body = b"104.16.0.1\n999.999.999.999\nnot a host\n104.16.0.2\n";
        let (items, stats) = parse(body, 256).expect("parses");
        assert_eq!(items.len(), 2);
        assert!(stats.malformed >= 1);
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert!(parse(&[0xff, 0xfe, 0xfd], 16).is_err());
    }

    #[test]
    fn hostname_validation_is_strict() {
        assert!(validate_hostname("a.b.example").is_some());
        assert!(validate_hostname("nodots").is_none());
        assert!(validate_hostname("-bad.example").is_none());
        assert!(validate_hostname("bad-.example").is_none());
        assert!(validate_hostname("with space.example").is_none());
        assert!(validate_hostname("with/slash.example").is_none());
        assert!(validate_hostname("999.999.999.999").is_none());
        assert!(validate_hostname("1.2.3.4").is_none());
        assert!(validate_hostname(&format!("{}.example", "a".repeat(64))).is_none());
    }

    #[test]
    fn overlong_entry_is_rejected() {
        assert!(parse_entry(&"a".repeat(400)).is_none());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        for seed in 0u32..512 {
            let bytes: Vec<u8> = (0..64u32)
                .map(|i| ((seed.wrapping_mul(2_654_435_761).wrapping_add(i)) & 0xff) as u8)
                .collect();
            let _ = parse(&bytes, 32);
        }
    }
}
