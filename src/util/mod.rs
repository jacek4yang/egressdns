//! Small shared helpers used across subsystems.

pub mod backoff;
pub mod der;
pub mod ipclass;
pub mod time;

use std::fmt::Write as _;

/// Hex-encode a byte slice into a lowercase string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// SHA-256 over a byte slice, returned as a 32-byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Truncate a string to at most `max` characters, appending an ellipsis when truncated.
///
/// Used to keep operator-visible error strings bounded so a hostile upstream cannot
/// inflate log volume.
pub fn bounded(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// A 64-bit FNV-1a hash, used for cheap, stable, non-cryptographic fingerprints.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn bounded_truncates() {
        assert_eq!(bounded("hello", 10), "hello");
        assert_eq!(bounded("hello", 3), "hel…");
    }

    #[test]
    fn fnv_is_stable() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_ne!(fnv1a64(b"a"), fnv1a64(b"b"));
    }
}
