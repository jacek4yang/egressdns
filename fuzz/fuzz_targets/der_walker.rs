//! Fuzz the minimal DER walker used for SPKI pinning and issuer constraints.
//!
//! The walker only ever runs on certificates rustls has already verified, but it parses
//! attacker-influenced bytes, so it must be provably panic-free and bounded.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(spki) = egressdns::util::der::spki_sha256(data) {
        assert_eq!(spki.len(), 32);
    }
    if let Some(cn) = egressdns::util::der::issuer_common_name(data) {
        assert!(!cn.is_empty());
        assert!(cn.len() <= 256);
    }
});
