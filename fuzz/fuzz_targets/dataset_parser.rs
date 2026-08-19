//! Fuzz the hosts-format and domain-category dataset parsers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut table = egressdns::datasets::HostsTable::default();
    let stats = table.load_hosts_format(text, 1_000);
    assert!(table.len() <= 1_000, "the record cap must hold");
    assert!(stats.added <= stats.added + stats.dropped);

    // Local zone construction must reject bad data rather than panicking.
    let zone = egressdns::config::LocalZone {
        name: "fuzz.test".to_string(),
        authoritative: true,
        records: text
            .lines()
            .take(32)
            .map(|line| egressdns::config::LocalRecord {
                name: line.chars().take(60).collect(),
                rtype: "A".to_string(),
                value: line.chars().rev().take(60).collect(),
                ttl: None,
            })
            .collect(),
    };
    let _ = egressdns::datasets::LocalZoneSet::build(&[zone], 60);
});
