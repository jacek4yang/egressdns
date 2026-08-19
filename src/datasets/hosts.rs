//! Static hosts-style mappings.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Result of loading a hosts-format file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadStats {
    /// Entries added.
    pub added: usize,
    /// Entries dropped because a limit was reached or the line was malformed.
    pub dropped: usize,
}

/// Case-insensitive name to address mapping.
#[derive(Debug, Clone, Default)]
pub struct HostsTable {
    map: HashMap<Arc<str>, Vec<IpAddr>>,
}

impl HostsTable {
    /// A content digest of every mapping, used to detect real dataset changes.
    pub fn digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut entries: Vec<(&str, &Vec<IpAddr>)> =
            self.map.iter().map(|(k, v)| (&**k, v)).collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (name, addrs) in entries {
            name.hash(&mut h);
            for addr in addrs {
                addr.hash(&mut h);
            }
        }
        h.finish()
    }

    /// Insert or extend an entry.
    pub fn insert(&mut self, name: &str, addresses: &[IpAddr]) {
        let key = crate::cache::normalize_name(name);
        let entry = self.map.entry(key).or_default();
        for a in addresses {
            if !entry.contains(a) {
                entry.push(*a);
            }
        }
    }

    /// Look up a name.
    pub fn get(&self, name: &str) -> Option<&[IpAddr]> {
        let key = crate::cache::normalize_name(name);
        self.map.get(&key).map(|v| v.as_slice())
    }

    /// Addresses of the requested family.
    pub fn get_family(&self, name: &str, ipv4: bool) -> Vec<IpAddr> {
        self.get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter(|a| a.is_ipv4() == ipv4)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of distinct names.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Parse a `/etc/hosts`-format document, bounded by `max_records`.
    pub fn load_hosts_format(&mut self, text: &str, max_records: usize) -> LoadStats {
        let mut stats = LoadStats::default();
        for line in text.lines() {
            let line = match line.split_once('#') {
                Some((before, _)) => before,
                None => line,
            }
            .trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(addr_text) = parts.next() else {
                continue;
            };
            let Ok(addr) = addr_text.parse::<IpAddr>() else {
                stats.dropped += 1;
                continue;
            };
            let mut any = false;
            for name in parts {
                if self.map.len() >= max_records {
                    stats.dropped += 1;
                    break;
                }
                if name.len() > 253 {
                    stats.dropped += 1;
                    continue;
                }
                self.insert(name, &[addr]);
                stats.added += 1;
                any = true;
            }
            if !any {
                stats.dropped += 1;
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_hosts_format() {
        let mut t = HostsTable::default();
        let stats = t.load_hosts_format(
            "# comment\n\
             10.0.0.1 gw.corp.test gateway\n\
             \n\
             2001:db8::1  v6.corp.test\n\
             not-an-address foo\n",
            1_000,
        );
        assert_eq!(stats.added, 3);
        assert_eq!(stats.dropped, 1);
        assert_eq!(
            t.get("gw.corp.test"),
            Some(&[IpAddr::from_str("10.0.0.1").expect("ip")][..])
        );
        assert_eq!(t.get("GATEWAY.").map(|v| v.len()), Some(1));
        assert_eq!(t.get_family("v6.corp.test", false).len(), 1);
        assert!(t.get_family("v6.corp.test", true).is_empty());
    }

    #[test]
    fn record_limit_is_respected() {
        let mut t = HostsTable::default();
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("10.0.0.1 host{i}.test\n"));
        }
        let stats = t.load_hosts_format(&text, 10);
        assert!(t.len() <= 10);
        assert!(stats.dropped > 0);
    }

    #[test]
    fn duplicate_addresses_are_not_repeated() {
        let mut t = HostsTable::default();
        t.insert("a.test", &[IpAddr::from_str("10.0.0.1").expect("ip")]);
        t.insert("a.test", &[IpAddr::from_str("10.0.0.1").expect("ip")]);
        t.insert("a.test", &[IpAddr::from_str("10.0.0.2").expect("ip")]);
        assert_eq!(t.get("a.test").map(|v| v.len()), Some(2));
    }
}
