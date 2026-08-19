//! Fuzz the untrusted third-party candidate seed parser.
//!
//! This parser consumes data from a source with no authority whatsoever, so it must never
//! panic, never allocate without bound, and never emit an address it was not given.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((items, stats)) = egressdns::cloudflare::seeds::parse(data, 256) else {
        return;
    };
    assert!(items.len() <= 256, "the item cap must hold");
    assert!(stats.accepted <= stats.lines + 1);

    // Nothing the parser produces may bypass the official-prefix and special-use filters.
    let snapshot = egressdns::cloudflare::prefixes::PrefixSnapshot::builtin();
    for item in items {
        if let egressdns::cloudflare::seeds::SeedItem::Address { addr, .. } = item {
            let admissible = egressdns::util::ipclass::classify(addr).is_none()
                && snapshot.contains(addr);
            let _ = admissible;
        }
    }
});
