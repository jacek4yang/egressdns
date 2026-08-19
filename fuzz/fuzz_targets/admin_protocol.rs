//! Fuzz the administration socket request parser.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines().take(16) {
        if let Ok(request) = egressdns::admin::parse_request(line, 64 * 1024) {
            // Only documented commands may ever be accepted, and argument counts and
            // lengths are bounded.
            assert!(egressdns::admin::COMMANDS.contains(&request.command.as_str()));
            assert!(request.args.len() <= 8);
            assert!(request.args.iter().all(|a| a.len() <= 512));
        }
    }
});
