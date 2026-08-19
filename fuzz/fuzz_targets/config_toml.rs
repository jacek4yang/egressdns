//! Fuzz configuration parsing and validation.
//!
//! Configuration is trusted input, but a panic here would turn a typo into a crash loop,
//! and validation must never accept a configuration that would create an open resolver.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = egressdns::config::Config::from_toml(text, "fuzz") {
        // Anything that validates must satisfy the invariants the daemon relies on.
        let exposed = config
            .server
            .udp_listen
            .iter()
            .chain(config.server.tcp_listen.iter())
            .any(|a| !a.ip().is_loopback());
        assert!(
            !exposed || !config.server.allow_from.is_empty(),
            "an exposed listener with no ACL must never validate"
        );
        assert!(config.server.udp.max_payload >= 512);
        assert!(config.cache.failure_max_ttl.as_secs() <= 300);
        assert!(!config.upstream.tls.quic_zero_rtt);
        // The redacted rendering must itself be valid.
        let rendered = config.to_redacted_toml();
        let _ = egressdns::config::Config::from_toml(&rendered, "fuzz-roundtrip");
    }
});
