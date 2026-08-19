//! Official Cloudflare prefix snapshots.
//!
//! This is the single source of truth for the question "is this address Cloudflare's?".
//! Nothing else — not a domain name, not an NS record, not GeoIP, not an ASN database, and
//! certainly not a third-party list — is allowed to answer it.
//!
//! A snapshot is only ever replaced by another snapshot that passes strict sanity checks,
//! so a truncated, empty or hostile response can never erase a working prefix set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::CloudflareError;

/// Where a snapshot came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrefixSource {
    /// The JSON API endpoint.
    Api,
    /// The plain-text list endpoints.
    TextLists,
    /// A locally cached copy of a previously valid snapshot.
    LocalCache,
    /// Compiled-in bootstrap values, used only until the first successful fetch.
    Builtin,
}

impl PrefixSource {
    /// Bounded metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::TextLists => "text_lists",
            Self::LocalCache => "local_cache",
            Self::Builtin => "builtin",
        }
    }
}

/// An immutable set of official Cloudflare prefixes with fast membership testing.
#[derive(Debug, Clone)]
pub struct PrefixSnapshot {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
    /// Precomputed `(network, mask)` pairs for constant-time IPv4 membership.
    v4_masks: Vec<(u32, u32)>,
    /// Precomputed `(network, mask)` pairs for constant-time IPv6 membership.
    v6_masks: Vec<(u128, u128)>,
    /// ETag reported by the source, when available.
    pub etag: Option<String>,
    /// Wall-clock second the snapshot was accepted.
    pub fetched_unix: u64,
    /// Origin of the snapshot.
    pub source: PrefixSource,
}

/// Serializable form used for the on-disk cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSnapshot {
    /// IPv4 prefixes in CIDR notation.
    pub ipv4_cidrs: Vec<String>,
    /// IPv6 prefixes in CIDR notation.
    pub ipv6_cidrs: Vec<String>,
    /// ETag, when the source provided one.
    pub etag: Option<String>,
    /// Wall-clock second the snapshot was accepted.
    pub fetched_unix: u64,
}

impl PrefixSnapshot {
    /// Build a snapshot from parsed prefixes.
    pub fn new(
        v4: Vec<Ipv4Net>,
        v6: Vec<Ipv6Net>,
        etag: Option<String>,
        fetched_unix: u64,
        source: PrefixSource,
    ) -> Self {
        let mut v4 = v4;
        let mut v6 = v6;
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();
        let v4_masks = v4
            .iter()
            .map(|n| (u32::from(n.network()), u32::from(n.netmask())))
            .collect();
        let v6_masks = v6
            .iter()
            .map(|n| (u128::from(n.network()), u128::from(n.netmask())))
            .collect();
        Self {
            v4,
            v6,
            v4_masks,
            v6_masks,
            etag,
            fetched_unix,
            source,
        }
    }

    /// Compiled-in bootstrap snapshot.
    ///
    /// Used only before the first successful refresh so that the optimizer is never
    /// tempted to trust an unfiltered candidate while the network is still starting up.
    /// These values are refreshed from the official sources within seconds of startup.
    pub fn builtin() -> Self {
        const V4: &[&str] = &[
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
        ];
        const V6: &[&str] = &[
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32",
        ];
        Self::new(
            V4.iter().filter_map(|s| s.parse().ok()).collect(),
            V6.iter().filter_map(|s| s.parse().ok()).collect(),
            None,
            0,
            PrefixSource::Builtin,
        )
    }

    /// IPv4 prefixes.
    pub fn ipv4(&self) -> &[Ipv4Net] {
        &self.v4
    }

    /// IPv6 prefixes.
    pub fn ipv6(&self) -> &[Ipv6Net] {
        &self.v6
    }

    /// Total prefix count.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// True when the snapshot has no prefixes at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Membership test. This runs on the foreground path and is a handful of integer
    /// comparisons over a fixed-size table.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let a = u32::from(v4);
                self.v4_masks.iter().any(|(net, mask)| a & mask == *net)
            }
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    // An IPv4-mapped address is never a legitimate Cloudflare answer.
                    let _ = mapped;
                    return false;
                }
                let a = u128::from(v6);
                self.v6_masks.iter().any(|(net, mask)| a & mask == *net)
            }
        }
    }

    /// Convert to the serializable form.
    pub fn to_stored(&self) -> StoredSnapshot {
        StoredSnapshot {
            ipv4_cidrs: self.v4.iter().map(|n| n.to_string()).collect(),
            ipv6_cidrs: self.v6.iter().map(|n| n.to_string()).collect(),
            etag: self.etag.clone(),
            fetched_unix: self.fetched_unix,
        }
    }

    /// Rebuild from the serializable form.
    pub fn from_stored(
        stored: &StoredSnapshot,
        source: PrefixSource,
    ) -> Result<Self, CloudflareError> {
        let v4 = parse_cidr_list_v4(&stored.ipv4_cidrs)?;
        let v6 = parse_cidr_list_v6(&stored.ipv6_cidrs)?;
        Ok(Self::new(
            v4,
            v6,
            stored.etag.clone(),
            stored.fetched_unix,
            source,
        ))
    }

    /// True when this snapshot and `other` describe the same prefix set.
    pub fn same_prefixes(&self, other: &Self) -> bool {
        self.v4 == other.v4 && self.v6 == other.v6
    }
}

/// Response shape of `https://api.cloudflare.com/client/v4/ips`.
#[derive(Debug, Deserialize)]
struct ApiEnvelope {
    result: Option<ApiResult>,
    success: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ApiResult {
    #[serde(default)]
    ipv4_cidrs: Vec<String>,
    #[serde(default)]
    ipv6_cidrs: Vec<String>,
    #[serde(default)]
    etag: Option<String>,
}

/// Parse the official JSON API response.
pub fn parse_api_json(body: &[u8], fetched_unix: u64) -> Result<PrefixSnapshot, CloudflareError> {
    let envelope: ApiEnvelope = serde_json::from_slice(body)
        .map_err(|e| CloudflareError::Parse(crate::util::bounded(&e.to_string(), 160)))?;
    if envelope.success == Some(false) {
        return Err(CloudflareError::Parse("API reported success=false".into()));
    }
    let result = envelope
        .result
        .ok_or_else(|| CloudflareError::Parse("API response had no result object".into()))?;
    let v4 = parse_cidr_list_v4(&result.ipv4_cidrs)?;
    let v6 = parse_cidr_list_v6(&result.ipv6_cidrs)?;
    Ok(PrefixSnapshot::new(
        v4,
        v6,
        result.etag,
        fetched_unix,
        PrefixSource::Api,
    ))
}

/// Parse one of the plain-text prefix lists.
pub fn parse_text_list(body: &[u8]) -> Result<Vec<String>, CloudflareError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| CloudflareError::Parse("prefix list was not valid UTF-8".into()))?;
    if text.trim_start().starts_with('<') {
        return Err(CloudflareError::Parse(
            "prefix list returned HTML instead of CIDRs".into(),
        ));
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() >= 4_096 {
            return Err(CloudflareError::Parse(
                "prefix list had too many lines".into(),
            ));
        }
        out.push(line.to_string());
    }
    Ok(out)
}

fn parse_cidr_list_v4(items: &[String]) -> Result<Vec<Ipv4Net>, CloudflareError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let net: Ipv4Net = item.trim().parse().map_err(|_| {
            CloudflareError::Parse(format!(
                "invalid IPv4 CIDR `{}`",
                crate::util::bounded(item, 48)
            ))
        })?;
        if net.prefix_len() < 8 || net.prefix_len() > 24 {
            return Err(CloudflareError::Parse(format!(
                "IPv4 prefix length {} outside the plausible range 8..=24",
                net.prefix_len()
            )));
        }
        if crate::util::ipclass::classify_v4(net.network()).is_some() {
            return Err(CloudflareError::Parse(format!(
                "IPv4 prefix {net} is special-use and cannot belong to Cloudflare"
            )));
        }
        out.push(net.trunc());
    }
    Ok(out)
}

fn parse_cidr_list_v6(items: &[String]) -> Result<Vec<Ipv6Net>, CloudflareError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let net: Ipv6Net = item.trim().parse().map_err(|_| {
            CloudflareError::Parse(format!(
                "invalid IPv6 CIDR `{}`",
                crate::util::bounded(item, 48)
            ))
        })?;
        if net.prefix_len() < 16 || net.prefix_len() > 64 {
            return Err(CloudflareError::Parse(format!(
                "IPv6 prefix length {} outside the plausible range 16..=64",
                net.prefix_len()
            )));
        }
        if crate::util::ipclass::classify_v6(net.network()).is_some() {
            return Err(CloudflareError::Parse(format!(
                "IPv6 prefix {net} is special-use and cannot belong to Cloudflare"
            )));
        }
        out.push(net.trunc());
    }
    Ok(out)
}

/// Reject a candidate snapshot that fails sanity checks.
///
/// A snapshot must never shrink implausibly: losing most of the prefix set would silently
/// disable optimization for large parts of the Cloudflare network, or worse, allow a
/// stale candidate to be reported as "not Cloudflare".
pub fn validate_snapshot(
    candidate: &PrefixSnapshot,
    previous: Option<&PrefixSnapshot>,
    min_v4: usize,
    min_v6: usize,
) -> Result<(), CloudflareError> {
    if candidate.v4.len() < min_v4 {
        return Err(CloudflareError::SnapshotRejected(
            "too few IPv4 prefixes to be a plausible Cloudflare snapshot",
        ));
    }
    if candidate.v6.len() < min_v6 {
        return Err(CloudflareError::SnapshotRejected(
            "too few IPv6 prefixes to be a plausible Cloudflare snapshot",
        ));
    }
    if let Some(prev) = previous {
        if candidate.v4.len() * 2 < prev.v4.len() {
            return Err(CloudflareError::SnapshotRejected(
                "IPv4 prefix count more than halved compared to the last valid snapshot",
            ));
        }
        if !prev.v6.is_empty() && candidate.v6.len() * 2 < prev.v6.len() {
            return Err(CloudflareError::SnapshotRejected(
                "IPv6 prefix count more than halved compared to the last valid snapshot",
            ));
        }
    }
    Ok(())
}

/// Cross-check an API snapshot against the plain-text lists.
///
/// Disagreement is not fatal: the endpoints are updated independently. It is reported so
/// that an operator can see it, and the API snapshot wins.
pub fn cross_check(api: &PrefixSnapshot, text_v4: &[Ipv4Net], text_v6: &[Ipv6Net]) -> Vec<String> {
    let mut notes = Vec::new();
    for n in text_v4 {
        if !api.v4.contains(n) {
            notes.push(format!("text IPv4 list has {n}, API does not"));
        }
    }
    for n in &api.v4 {
        if !text_v4.contains(n) {
            notes.push(format!("API has IPv4 {n}, text list does not"));
        }
    }
    for n in text_v6 {
        if !api.v6.contains(n) {
            notes.push(format!("text IPv6 list has {n}, API does not"));
        }
    }
    for n in &api.v6 {
        if !text_v6.contains(n) {
            notes.push(format!("API has IPv6 {n}, text list does not"));
        }
    }
    notes.truncate(16);
    notes
}

/// Parse a plain-text list into IPv4 prefixes.
pub fn text_to_v4(lines: &[String]) -> Result<Vec<Ipv4Net>, CloudflareError> {
    parse_cidr_list_v4(lines)
}

/// Parse a plain-text list into IPv6 prefixes.
pub fn text_to_v6(lines: &[String]) -> Result<Vec<Ipv6Net>, CloudflareError> {
    parse_cidr_list_v6(lines)
}

/// Convenience predicate over an optional snapshot.
pub fn is_cloudflare(snapshot: Option<&PrefixSnapshot>, addr: IpAddr) -> bool {
    snapshot.map(|s| s.contains(addr)).unwrap_or(false)
}

/// Total number of addresses in the IPv4 prefix set, used to size sampling budgets.
pub fn ipv4_address_space(snapshot: &PrefixSnapshot) -> u64 {
    snapshot
        .v4
        .iter()
        .map(|n| 1u64 << (32 - u32::from(n.prefix_len())))
        .sum()
}

/// Helper for tests and diagnostics: the first address of a prefix.
pub fn first_address(net: &Ipv4Net) -> Ipv4Addr {
    net.network()
}

/// Helper for tests and diagnostics: the first address of an IPv6 prefix.
pub fn first_address_v6(net: &Ipv6Net) -> Ipv6Addr {
    net.network()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Captured verbatim from `https://api.cloudflare.com/client/v4/ips`.
    const API_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/cloudflare_ips_api.json");

    #[test]
    fn parses_the_official_api_response() {
        let snap = parse_api_json(API_FIXTURE, 1_000).expect("parses");
        assert!(snap.ipv4().len() >= 15);
        assert!(snap.ipv6().len() >= 7);
        assert!(snap.contains(IpAddr::from_str("104.16.0.1").expect("ip")));
        assert!(snap.contains(IpAddr::from_str("2606:4700::1111").expect("ip")));
        assert!(!snap.contains(IpAddr::from_str("8.8.8.8").expect("ip")));
    }

    #[test]
    fn builtin_snapshot_is_usable() {
        let snap = PrefixSnapshot::builtin();
        assert!(snap.contains(IpAddr::from_str("172.64.1.1").expect("ip")));
        assert!(!snap.contains(IpAddr::from_str("1.1.1.1").expect("ip")));
        assert_eq!(snap.source, PrefixSource::Builtin);
    }

    #[test]
    fn ipv4_mapped_addresses_are_never_cloudflare() {
        let snap = PrefixSnapshot::builtin();
        assert!(!snap.contains(IpAddr::from_str("::ffff:104.16.0.1").expect("ip")));
    }

    #[test]
    fn html_instead_of_cidrs_is_rejected() {
        let err = parse_text_list(b"<!DOCTYPE html><html><body>hi</body></html>")
            .expect_err("must reject HTML");
        assert!(matches!(err, CloudflareError::Parse(_)));
    }

    #[test]
    fn special_use_prefixes_are_rejected() {
        let json = br#"{"result":{"ipv4_cidrs":["10.0.0.0/8"],"ipv6_cidrs":[]},"success":true}"#;
        assert!(parse_api_json(json, 0).is_err());
    }

    #[test]
    fn absurd_prefix_lengths_are_rejected() {
        let json = br#"{"result":{"ipv4_cidrs":["104.16.0.0/4"],"ipv6_cidrs":[]},"success":true}"#;
        assert!(parse_api_json(json, 0).is_err());
        let json = br#"{"result":{"ipv4_cidrs":["104.16.0.1/32"],"ipv6_cidrs":[]},"success":true}"#;
        assert!(parse_api_json(json, 0).is_err());
    }

    #[test]
    fn api_failure_envelope_is_rejected() {
        let json = br#"{"result":null,"success":false,"errors":[{"code":1,"message":"nope"}]}"#;
        assert!(parse_api_json(json, 0).is_err());
    }

    #[test]
    fn truncated_json_is_rejected() {
        let full = API_FIXTURE;
        for cut in [1, 10, 50, full.len() / 2, full.len() - 1] {
            assert!(
                parse_api_json(&full[..cut], 0).is_err(),
                "truncation at {cut} must not parse"
            );
        }
    }

    #[test]
    fn snapshot_validation_rejects_implausible_shrinkage() {
        let previous = PrefixSnapshot::builtin();
        let tiny = PrefixSnapshot::new(
            vec![Ipv4Net::from_str("104.16.0.0/13").expect("net")],
            vec![Ipv6Net::from_str("2606:4700::/32").expect("net")],
            None,
            1,
            PrefixSource::Api,
        );
        assert!(validate_snapshot(&tiny, Some(&previous), 1, 1).is_err());
        assert!(validate_snapshot(&tiny, None, 1, 1).is_ok());
        assert!(validate_snapshot(&tiny, None, 8, 4).is_err());
    }

    #[test]
    fn stored_round_trip() {
        let snap = PrefixSnapshot::builtin();
        let stored = snap.to_stored();
        let restored =
            PrefixSnapshot::from_stored(&stored, PrefixSource::LocalCache).expect("restores");
        assert!(restored.same_prefixes(&snap));
        assert_eq!(restored.source, PrefixSource::LocalCache);
    }

    #[test]
    fn cross_check_reports_disagreement() {
        let api = PrefixSnapshot::builtin();
        let text_v4 = vec![Ipv4Net::from_str("104.16.0.0/13").expect("net")];
        let notes = cross_check(&api, &text_v4, api.ipv6());
        assert!(!notes.is_empty());
        assert!(notes.len() <= 16);
    }

    #[test]
    fn address_space_is_computed() {
        let snap = PrefixSnapshot::new(
            vec![Ipv4Net::from_str("104.16.0.0/13").expect("net")],
            Vec::new(),
            None,
            0,
            PrefixSource::Api,
        );
        assert_eq!(ipv4_address_space(&snap), 1 << 19);
    }
}
