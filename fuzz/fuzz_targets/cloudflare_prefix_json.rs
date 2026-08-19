//! Fuzz the official Cloudflare prefix parser and its snapshot validation.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(snapshot) = egressdns::cloudflare::prefixes::parse_api_json(data, 0) {
        // A snapshot that parses must contain only plausible, non-special-use prefixes.
        for net in snapshot.ipv4() {
            assert!(net.prefix_len() >= 8 && net.prefix_len() <= 24);
            assert!(egressdns::util::ipclass::classify_v4(net.network()).is_none());
        }
        for net in snapshot.ipv6() {
            assert!(net.prefix_len() >= 16 && net.prefix_len() <= 64);
        }
        let previous = egressdns::cloudflare::prefixes::PrefixSnapshot::builtin();
        let _ = egressdns::cloudflare::prefixes::validate_snapshot(
            &snapshot,
            Some(&previous),
            8,
            4,
        );
        let stored = snapshot.to_stored();
        let _ = egressdns::cloudflare::prefixes::PrefixSnapshot::from_stored(
            &stored,
            egressdns::cloudflare::prefixes::PrefixSource::LocalCache,
        );
    }
    if let Ok(lines) = egressdns::cloudflare::prefixes::parse_text_list(data) {
        let _ = egressdns::cloudflare::prefixes::text_to_v4(&lines);
        let _ = egressdns::cloudflare::prefixes::text_to_v6(&lines);
    }
});
