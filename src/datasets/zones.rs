//! Simple internal zones served from configuration.
//!
//! Only the record types an enterprise actually needs internally are supported. Anything
//! more elaborate belongs in a real authoritative server; this exists so that a LAN can
//! resolve its own names without a second daemon.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::LocalZone;

/// The answer a zone can produce for a query.
#[derive(Debug, Clone, PartialEq)]
pub enum ZoneAnswer {
    /// Records matching the query.
    Records(Vec<Record>),
    /// The name exists but has no records of the requested type.
    NoData,
    /// The name does not exist inside an authoritative zone.
    NxDomain,
    /// The query is not inside any configured zone.
    NotInZone,
}

/// A set of internal zones.
#[derive(Debug, Clone, Default)]
pub struct LocalZoneSet {
    zones: Vec<Zone>,
}

#[derive(Debug, Clone)]
struct Zone {
    apex: String,
    authoritative: bool,
    records: HashMap<Arc<str>, Vec<Record>>,
}

impl LocalZoneSet {
    /// A content digest of every zone and record, used to detect real dataset changes.
    pub fn digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for zone in &self.zones {
            zone.apex.hash(&mut h);
            zone.authoritative.hash(&mut h);
            let mut names: Vec<&str> = zone.records.keys().map(|k| &**k).collect();
            names.sort_unstable();
            for name in names {
                name.hash(&mut h);
                if let Some(records) = zone.records.get(name) {
                    records.len().hash(&mut h);
                    for record in records {
                        format!("{:?}", record.data).hash(&mut h);
                        record.ttl.hash(&mut h);
                    }
                }
            }
        }
        h.finish()
    }

    /// Build zones from configuration.
    pub fn build(zones: &[LocalZone], default_ttl: u32) -> Result<Self, String> {
        let mut out = Vec::with_capacity(zones.len());
        for zone in zones {
            let apex = zone.name.trim_end_matches('.').to_ascii_lowercase();
            if apex.is_empty() {
                return Err("zone name must not be empty".to_string());
            }
            let mut records: HashMap<Arc<str>, Vec<Record>> = HashMap::new();
            for rec in &zone.records {
                let owner = if rec.name == "@" || rec.name.is_empty() {
                    format!("{apex}.")
                } else if rec.name.ends_with('.') {
                    rec.name.to_ascii_lowercase()
                } else {
                    format!("{}.{apex}.", rec.name.to_ascii_lowercase())
                };
                let name = Name::from_str(&owner)
                    .map_err(|e| format!("invalid owner name `{owner}`: {e}"))?;
                let ttl = rec.ttl.unwrap_or(default_ttl);
                let record = build_record(&name, ttl, &rec.rtype, &rec.value)?;
                records
                    .entry(crate::cache::normalize_name(&owner))
                    .or_default()
                    .push(record);
            }
            out.push(Zone {
                apex,
                authoritative: zone.authoritative,
                records,
            });
        }
        // Longest apex first so that a more specific zone wins.
        out.sort_by_key(|z| std::cmp::Reverse(z.apex.len()));
        Ok(Self { zones: out })
    }

    /// Total record count.
    pub fn record_count(&self) -> usize {
        self.zones
            .iter()
            .map(|z| z.records.values().map(|v| v.len()).sum::<usize>())
            .sum()
    }

    /// Number of zones.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// True when no zone is configured.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Answer a query from the zones.
    pub fn lookup(&self, name: &str, qtype: RecordType) -> ZoneAnswer {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        for zone in &self.zones {
            if n != zone.apex && !n.ends_with(&format!(".{}", zone.apex)) {
                continue;
            }
            let key = crate::cache::normalize_name(&n);
            match zone.records.get(&key) {
                Some(records) => {
                    let matching: Vec<Record> = records
                        .iter()
                        .filter(|r| {
                            r.record_type() == qtype || r.record_type() == RecordType::CNAME
                        })
                        .cloned()
                        .collect();
                    if matching.is_empty() {
                        return ZoneAnswer::NoData;
                    }
                    return ZoneAnswer::Records(matching);
                }
                None => {
                    return if zone.authoritative {
                        ZoneAnswer::NxDomain
                    } else {
                        ZoneAnswer::NotInZone
                    };
                }
            }
        }
        ZoneAnswer::NotInZone
    }
}

fn build_record(name: &Name, ttl: u32, rtype: &str, value: &str) -> Result<Record, String> {
    let value = value.trim();
    let rdata = match rtype.to_ascii_uppercase().as_str() {
        "A" => RData::A(A(value
            .parse()
            .map_err(|_| format!("invalid IPv4 address `{value}`"))?)),
        "AAAA" => RData::AAAA(AAAA(
            value
                .parse()
                .map_err(|_| format!("invalid IPv6 address `{value}`"))?,
        )),
        "CNAME" => RData::CNAME(CNAME(parse_name(value)?)),
        "NS" => RData::NS(NS(parse_name(value)?)),
        "PTR" => RData::PTR(PTR(parse_name(value)?)),
        "TXT" => RData::TXT(TXT::new(vec![value.to_string()])),
        "MX" => {
            let (pref, host) = value
                .split_once(char::is_whitespace)
                .ok_or_else(|| format!("MX value `{value}` must be `<preference> <host>`"))?;
            let pref: u16 = pref
                .trim()
                .parse()
                .map_err(|_| format!("invalid MX preference `{pref}`"))?;
            RData::MX(MX::new(pref, parse_name(host.trim())?))
        }
        "SRV" => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() != 4 {
                return Err(format!(
                    "SRV value `{value}` must be `<priority> <weight> <port> <target>`"
                ));
            }
            let priority: u16 = parts[0].parse().map_err(|_| "invalid SRV priority")?;
            let weight: u16 = parts[1].parse().map_err(|_| "invalid SRV weight")?;
            let port: u16 = parts[2].parse().map_err(|_| "invalid SRV port")?;
            RData::SRV(SRV::new(priority, weight, port, parse_name(parts[3])?))
        }
        other => return Err(format!("unsupported local record type `{other}`")),
    };
    Ok(Record::from_rdata(name.clone(), ttl, rdata))
}

fn parse_name(value: &str) -> Result<Name, String> {
    let text = if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    };
    Name::from_str(&text).map_err(|e| format!("invalid name `{value}`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalRecord;

    fn zone() -> LocalZone {
        LocalZone {
            name: "corp.test".into(),
            authoritative: true,
            records: vec![
                LocalRecord {
                    name: "gw".into(),
                    rtype: "A".into(),
                    value: "10.0.0.1".into(),
                    ttl: Some(30),
                },
                LocalRecord {
                    name: "gw".into(),
                    rtype: "AAAA".into(),
                    value: "fd00::1".into(),
                    ttl: None,
                },
                LocalRecord {
                    name: "@".into(),
                    rtype: "MX".into(),
                    value: "10 mail.corp.test.".into(),
                    ttl: None,
                },
                LocalRecord {
                    name: "_sip._tcp".into(),
                    rtype: "SRV".into(),
                    value: "10 60 5060 sip.corp.test.".into(),
                    ttl: None,
                },
                LocalRecord {
                    name: "alias".into(),
                    rtype: "CNAME".into(),
                    value: "gw.corp.test.".into(),
                    ttl: None,
                },
            ],
        }
    }

    #[test]
    fn builds_and_answers() {
        let zones = LocalZoneSet::build(&[zone()], 60).expect("build");
        assert_eq!(zones.record_count(), 5);
        match zones.lookup("gw.corp.test.", RecordType::A) {
            ZoneAnswer::Records(r) => {
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].ttl, 30);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            zones.lookup("GW.CORP.TEST", RecordType::AAAA),
            ZoneAnswer::Records(_)
        ));
        assert!(matches!(
            zones.lookup("gw.corp.test.", RecordType::TXT),
            ZoneAnswer::NoData
        ));
        assert!(matches!(
            zones.lookup("missing.corp.test.", RecordType::A),
            ZoneAnswer::NxDomain
        ));
        assert!(matches!(
            zones.lookup("example.com.", RecordType::A),
            ZoneAnswer::NotInZone
        ));
    }

    #[test]
    fn cname_is_returned_for_any_type() {
        let zones = LocalZoneSet::build(&[zone()], 60).expect("build");
        assert!(matches!(
            zones.lookup("alias.corp.test.", RecordType::AAAA),
            ZoneAnswer::Records(_)
        ));
    }

    #[test]
    fn mx_and_srv_parse_correctly() {
        let zones = LocalZoneSet::build(&[zone()], 60).expect("build");
        match zones.lookup("corp.test.", RecordType::MX) {
            ZoneAnswer::Records(r) => assert!(r[0].data.to_string().contains("mail.corp.test")),
            other => panic!("unexpected {other:?}"),
        }
        match zones.lookup("_sip._tcp.corp.test.", RecordType::SRV) {
            ZoneAnswer::Records(r) => {
                let text = r[0].data.to_string();
                assert!(text.starts_with("10 60 5060"), "got {text}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn non_authoritative_zone_falls_through() {
        let mut z = zone();
        z.authoritative = false;
        let zones = LocalZoneSet::build(&[z], 60).expect("build");
        assert!(matches!(
            zones.lookup("missing.corp.test.", RecordType::A),
            ZoneAnswer::NotInZone
        ));
    }

    #[test]
    fn invalid_records_are_rejected_at_build_time() {
        let bad = LocalZone {
            name: "corp.test".into(),
            authoritative: true,
            records: vec![LocalRecord {
                name: "x".into(),
                rtype: "A".into(),
                value: "not-an-ip".into(),
                ttl: None,
            }],
        };
        assert!(LocalZoneSet::build(&[bad], 60).is_err());
    }

    #[test]
    fn more_specific_zone_wins() {
        let outer = LocalZone {
            name: "test".into(),
            authoritative: true,
            records: vec![LocalRecord {
                name: "a".into(),
                rtype: "A".into(),
                value: "10.0.0.2".into(),
                ttl: None,
            }],
        };
        let zones = LocalZoneSet::build(&[outer, zone()], 60).expect("build");
        match zones.lookup("gw.corp.test.", RecordType::A) {
            ZoneAnswer::Records(r) => assert_eq!(r[0].data.to_string(), "10.0.0.1"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
