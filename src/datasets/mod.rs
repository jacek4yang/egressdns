//! Offline datasets and static local data.
//!
//! Everything here is parsed in the background, bounded by explicit file-size and
//! record-count limits, and published as an immutable snapshot through [`arc_swap`]. The
//! DNS request path only ever performs an atomic pointer load; it never touches the
//! filesystem and never parses anything.
//!
//! GeoIP and ASN databases are advisory metadata only. They are exposed through
//! diagnostics and may inform probe scheduling, but they can never make a valid address
//! invalid: a disagreement between an offline database and a signed, verified DNS answer
//! is resolved in favour of the answer.

pub mod hosts;
pub mod zones;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::{DatasetsConfig, LocalConfig};

pub use hosts::HostsTable;
pub use zones::{LocalZoneSet, ZoneAnswer};

/// An immutable dataset snapshot.
pub struct DatasetSnapshot {
    /// Static host mappings.
    pub hosts: HostsTable,
    /// Internal zones.
    pub zones: LocalZoneSet,
    /// Suffix to upstream-group routing rules, longest suffix first.
    pub suffix_rules: Vec<(String, Arc<str>)>,
    /// GeoSite-style domain categories.
    pub categories: HashMap<String, Vec<String>>,
    /// Optional GeoIP reader.
    pub geoip: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    /// Optional ASN reader.
    pub asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    /// Diagnostics about the load.
    pub stats: DatasetStats,
}

/// Diagnostics about a dataset load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetStats {
    /// Number of host entries.
    pub host_entries: usize,
    /// Number of zone records.
    pub zone_records: usize,
    /// Number of suffix rules.
    pub suffix_rules: usize,
    /// Number of domain-category entries.
    pub category_entries: usize,
    /// Files skipped because they exceeded the size limit.
    pub skipped_files: usize,
    /// Records dropped because the record limit was reached.
    pub dropped_records: usize,
    /// Wall-clock second of the load.
    pub loaded_unix: u64,
}

impl DatasetSnapshot {
    /// An empty snapshot, used before the first successful load.
    pub fn empty() -> Self {
        Self {
            hosts: HostsTable::default(),
            zones: LocalZoneSet::default(),
            suffix_rules: Vec::new(),
            categories: HashMap::new(),
            geoip: None,
            asn: None,
            stats: DatasetStats::default(),
        }
    }

    /// A digest of everything this snapshot serves, used to detect real changes.
    ///
    /// Deliberately excludes `stats.loaded_unix`, which changes on every rebuild, and the
    /// memory-mapped GeoIP readers, which are compared by presence rather than content
    /// because hashing tens of megabytes on every tick would defeat the purpose.
    pub fn content_digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.hosts.digest().hash(&mut h);
        self.zones.digest().hash(&mut h);
        self.suffix_rules.hash(&mut h);
        let mut categories: Vec<(&String, usize)> =
            self.categories.iter().map(|(k, v)| (k, v.len())).collect();
        categories.sort();
        categories.hash(&mut h);
        self.geoip.is_some().hash(&mut h);
        self.asn.is_some().hash(&mut h);
        self.stats.host_entries.hash(&mut h);
        self.stats.zone_records.hash(&mut h);
        self.stats.category_entries.hash(&mut h);
        h.finish()
    }

    /// Upstream group for a query name, from the longest matching suffix rule.
    pub fn group_for(&self, name: &str) -> Option<Arc<str>> {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        for (suffix, group) in &self.suffix_rules {
            if n == *suffix || n.ends_with(&format!(".{suffix}")) {
                return Some(Arc::clone(group));
            }
        }
        None
    }

    /// Advisory ASN lookup.
    pub fn asn_of(&self, addr: IpAddr) -> Option<u32> {
        let reader = self.asn.as_ref()?;
        reader
            .lookup(addr)
            .ok()?
            .decode::<maxminddb::geoip2::Asn>()
            .ok()
            .flatten()?
            .autonomous_system_number
    }

    /// Advisory country lookup.
    pub fn country_of(&self, addr: IpAddr) -> Option<String> {
        let reader = self.geoip.as_ref()?;
        let record = reader
            .lookup(addr)
            .ok()?
            .decode::<maxminddb::geoip2::Country>()
            .ok()
            .flatten()?;
        record.country.iso_code.map(|s| s.to_string())
    }

    /// Categories a domain belongs to.
    pub fn categories_of(&self, name: &str) -> Vec<&str> {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        let mut out = Vec::new();
        for (category, domains) in &self.categories {
            if domains
                .iter()
                .any(|d| n == *d || n.ends_with(&format!(".{d}")))
            {
                out.push(category.as_str());
            }
        }
        out.sort_unstable();
        out
    }
}

/// Atomically swappable dataset holder.
pub struct DatasetStore {
    current: ArcSwap<DatasetSnapshot>,
}

impl Default for DatasetStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DatasetStore {
    /// Create a store holding the empty snapshot.
    pub fn new() -> Self {
        Self {
            current: ArcSwap::from_pointee(DatasetSnapshot::empty()),
        }
    }

    /// Load the current snapshot. One atomic pointer load.
    pub fn load(&self) -> Arc<DatasetSnapshot> {
        self.current.load_full()
    }

    /// Publish a new snapshot.
    pub fn publish(&self, snapshot: Arc<DatasetSnapshot>) {
        self.current.store(snapshot);
    }

    /// Publish only if the content differs from the current snapshot.
    ///
    /// Returns whether anything changed. Periodic reloading rebuilds from disk on every
    /// tick; swapping in an identical snapshot would invalidate nothing but would churn
    /// the `ArcSwap` and make the "reloaded" log line meaningless.
    pub fn publish_if_changed(&self, snapshot: Arc<DatasetSnapshot>) -> bool {
        if self.current.load().content_digest() == snapshot.content_digest() {
            return false;
        }
        self.current.store(snapshot);
        true
    }
}

/// Shared handle.
pub type SharedDatasets = Arc<DatasetStore>;

/// Build a snapshot from configuration. Blocking; runs on a blocking thread.
///
/// A failure to load any single file is reported but never fatal: the caller keeps the
/// previous valid snapshot.
pub fn build(
    datasets: &DatasetsConfig,
    local: &LocalConfig,
    now_unix: u64,
) -> Result<DatasetSnapshot, String> {
    let mut stats = DatasetStats {
        loaded_unix: now_unix,
        ..DatasetStats::default()
    };

    let mut hosts = HostsTable::default();
    for entry in &local.hosts {
        hosts.insert(&entry.name, &entry.addresses);
    }
    for path in &datasets.hosts_files {
        match read_bounded(path, datasets.max_file_bytes) {
            Ok(text) => {
                let added = hosts.load_hosts_format(&text, datasets.max_records);
                stats.dropped_records += added.dropped;
            }
            Err(e) => {
                stats.skipped_files += 1;
                tracing::warn!(event = "dataset.skipped", path = %path.display(), error = %e);
            }
        }
    }
    stats.host_entries = hosts.len();

    let zones = LocalZoneSet::build(&local.zones, local.local_ttl)?;
    stats.zone_records = zones.record_count();

    let mut suffix_rules: Vec<(String, Arc<str>)> = local
        .suffix_rules
        .iter()
        .map(|r| {
            (
                r.suffix
                    .trim_end_matches('.')
                    .trim_start_matches('.')
                    .to_ascii_lowercase(),
                Arc::from(r.group.as_str()),
            )
        })
        .collect();
    // Longest suffix wins, so sort by descending length.
    suffix_rules.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
    stats.suffix_rules = suffix_rules.len();

    let mut categories: HashMap<String, Vec<String>> = HashMap::new();
    let mut category_entries = 0usize;
    for path in &datasets.domain_category_files {
        match read_bounded(path, datasets.max_file_bytes) {
            Ok(text) => {
                for line in text.lines() {
                    if category_entries >= datasets.max_records {
                        stats.dropped_records += 1;
                        continue;
                    }
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let Some((category, domain)) = line.split_once(':') else {
                        continue;
                    };
                    let category = category.trim().to_ascii_lowercase();
                    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                    if category.is_empty() || domain.is_empty() || domain.len() > 253 {
                        continue;
                    }
                    categories.entry(category).or_default().push(domain);
                    category_entries += 1;
                }
            }
            Err(e) => {
                stats.skipped_files += 1;
                tracing::warn!(event = "dataset.skipped", path = %path.display(), error = %e);
            }
        }
    }
    stats.category_entries = category_entries;

    let geoip = open_mmdb(datasets.geoip_mmdb.as_ref(), &mut stats);
    let asn = open_mmdb(datasets.asn_mmdb.as_ref(), &mut stats);

    Ok(DatasetSnapshot {
        hosts,
        zones,
        suffix_rules,
        categories,
        geoip,
        asn,
        stats,
    })
}

fn open_mmdb(
    path: Option<&PathBuf>,
    stats: &mut DatasetStats,
) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
    let path = path?;
    match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => Some(Arc::new(reader)),
        Err(e) => {
            stats.skipped_files += 1;
            tracing::warn!(event = "dataset.mmdb_failed", path = %path.display(), error = %e);
            None
        }
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > max_bytes {
        return Err(format!(
            "file is {} bytes, above the {max_bytes} byte limit",
            meta.len()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostEntry, LocalZone, SuffixRule};

    fn local() -> LocalConfig {
        LocalConfig {
            hosts: vec![HostEntry {
                name: "printer.corp.test".into(),
                addresses: vec!["10.0.0.9".parse().expect("ip")],
            }],
            zones: vec![LocalZone {
                name: "corp.test".into(),
                records: vec![crate::config::LocalRecord {
                    name: "gw".into(),
                    rtype: "A".into(),
                    value: "10.0.0.1".into(),
                    ttl: Some(30),
                }],
                authoritative: true,
            }],
            suffix_rules: vec![
                SuffixRule {
                    suffix: "corp.test".into(),
                    group: "internal".into(),
                },
                SuffixRule {
                    suffix: "test".into(),
                    group: "default".into(),
                },
            ],
            local_ttl: 60,
        }
    }

    #[test]
    fn builds_from_configuration() {
        let snap = build(&DatasetsConfig::default(), &local(), 1_000).expect("build");
        assert_eq!(snap.stats.host_entries, 1);
        assert_eq!(snap.stats.zone_records, 1);
        assert_eq!(snap.stats.suffix_rules, 2);
    }

    #[test]
    fn longest_suffix_wins() {
        let snap = build(&DatasetsConfig::default(), &local(), 0).expect("build");
        assert_eq!(
            snap.group_for("host.corp.test.").as_deref(),
            Some("internal")
        );
        assert_eq!(
            snap.group_for("host.other.test.").as_deref(),
            Some("default")
        );
        assert!(snap.group_for("example.com.").is_none());
    }

    #[test]
    fn oversized_files_are_skipped_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hosts");
        std::fs::write(&path, "10.0.0.1 big.test\n".repeat(1000)).expect("write");
        let mut ds = DatasetsConfig {
            hosts_files: vec![path],
            max_file_bytes: 10,
            ..DatasetsConfig::default()
        };
        let snap = build(&ds, &LocalConfig::default(), 0).expect("build");
        assert_eq!(snap.stats.skipped_files, 1);
        ds.max_file_bytes = 1024 * 1024;
        let snap = build(&ds, &LocalConfig::default(), 0).expect("build");
        assert_eq!(snap.stats.skipped_files, 0);
        assert_eq!(snap.stats.host_entries, 1);
    }

    #[test]
    fn record_limits_are_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cats");
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("ads:tracker{i}.example\n"));
        }
        std::fs::write(&path, text).expect("write");
        let ds = DatasetsConfig {
            domain_category_files: vec![path],
            max_records: 10,
            ..DatasetsConfig::default()
        };
        let snap = build(&ds, &LocalConfig::default(), 0).expect("build");
        assert_eq!(snap.stats.category_entries, 10);
        assert!(snap.stats.dropped_records >= 90);
    }

    #[test]
    fn categories_match_on_label_boundaries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cats");
        std::fs::write(&path, "cdn:example.com\n").expect("write");
        let ds = DatasetsConfig {
            domain_category_files: vec![path],
            ..DatasetsConfig::default()
        };
        let snap = build(&ds, &LocalConfig::default(), 0).expect("build");
        assert_eq!(snap.categories_of("a.example.com."), vec!["cdn"]);
        assert_eq!(snap.categories_of("example.com"), vec!["cdn"]);
        assert!(snap.categories_of("notexample.com").is_empty());
    }

    #[test]
    fn missing_mmdb_is_not_fatal() {
        let ds = DatasetsConfig {
            geoip_mmdb: Some(PathBuf::from("/nonexistent/geoip.mmdb")),
            asn_mmdb: Some(PathBuf::from("/nonexistent/asn.mmdb")),
            ..DatasetsConfig::default()
        };
        let snap = build(&ds, &LocalConfig::default(), 0).expect("build");
        assert!(snap.geoip.is_none());
        assert!(snap.asn.is_none());
        assert_eq!(snap.stats.skipped_files, 2);
        // Advisory lookups simply return nothing.
        assert!(snap.asn_of("104.16.0.1".parse().expect("ip")).is_none());
        assert!(snap.country_of("104.16.0.1".parse().expect("ip")).is_none());
    }

    #[test]
    fn store_publishes_atomically() {
        let store = DatasetStore::new();
        assert_eq!(store.load().stats.host_entries, 0);
        let snap = build(&DatasetsConfig::default(), &local(), 5).expect("build");
        store.publish(Arc::new(snap));
        assert_eq!(store.load().stats.host_entries, 1);
        assert_eq!(store.load().stats.loaded_unix, 5);
    }
}
