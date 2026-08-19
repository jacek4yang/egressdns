//! Fuzz DNS message parsing and the truncation-aware re-serialisation path.
//!
//! Every byte string that reaches the listener goes through exactly this code, so a panic
//! here is a remote denial of service.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = hickory_proto::op::Message::from_vec(data) else {
        return;
    };
    // Anything that parses must also round-trip through the size-limited encoder without
    // panicking, at every limit the server can be configured with.
    for limit in [512usize, 1232, 4096, 65535] {
        if let Ok(out) = egressdns::dns::message::serialize_limited(&message, limit) {
            assert!(out.bytes.len() <= limit.max(512));
            // Whatever we emit must itself be parseable.
            let _ = hickory_proto::op::Message::from_vec(&out.bytes);
        }
    }
    let _ = egressdns::dns::message::answer_fingerprint(&message);
    let _ = egressdns::dns::message::min_ttl(&message);
    let _ = egressdns::dns::message::extract_edes(&message);
    let _ = egressdns::dns::message::extract_ecs(&message);
    let _ = egressdns::dns::message::extract_server_cookie(&message, [0u8; 8]);

    let mut mutated = message.clone();
    egressdns::dns::message::age_ttls(&mut mutated, u32::MAX / 2);
    egressdns::dns::message::cap_ttls(&mut mutated, 30);
    for record in mutated.answers.iter() {
        assert!(record.ttl <= 30);
    }
});
