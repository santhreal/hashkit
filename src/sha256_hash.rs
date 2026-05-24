//! SHA-256 hashing and npm integrity string support.
//!
//! This module provides standard SHA-256 via the [`sha2`] crate, plus helpers
//! for npm-style integrity strings (`sha256-<base64>`).
//!
//! # Security note
//!
//! When comparing SHA-256 digests, use [`crate::secure_compare`] instead of
//! the `==` operator to avoid timing side-channels.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Computes the one-shot SHA-256 hash of a byte slice.
///
/// # Examples
///
/// ```
/// let hash = hashkit::sha256_hash::hash(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes an npm-style integrity string: `sha256-<base64>`.
///
/// # Examples
///
/// ```
/// let integrity = hashkit::sha256_hash::integrity(b"hello world");
/// assert!(integrity.starts_with("sha256-"));
/// ```
#[inline]
#[must_use]
pub fn integrity(data: &[u8]) -> String {
    let digest = hash(data);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Parses an npm integrity string and returns the raw 32-byte digest.
///
/// Accepts strings of the form `sha256-<base64>`. Returns `None` if the
/// format is invalid or the base64 payload does not decode to exactly 32 bytes.
///
/// # Examples
///
/// ```
/// let integrity = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
/// let digest = hashkit::sha256_hash::parse_integrity(integrity);
/// assert!(digest.is_some());
/// ```
#[inline]
#[must_use]
pub fn parse_integrity(integrity: &str) -> Option<[u8; 32]> {
    let b64 = integrity.strip_prefix("sha256-")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    bytes.try_into().ok()
}

/// Verifies that `data` matches the given npm integrity string.
///
/// Compares the digest in constant time to mitigate timing attacks.
///
/// # Examples
///
/// ```
/// let integrity = hashkit::sha256_hash::integrity(b"hello world");
/// assert!(hashkit::sha256_hash::verify(b"hello world", &integrity));
/// ```
#[inline]
#[must_use]
pub fn verify(data: &[u8], integrity: &str) -> bool {
    let Some(expected) = parse_integrity(integrity) else {
        return false;
    };
    let actual = hash(data);
    crate::secure_compare(&actual, &expected)
}

#[cfg(test)]
mod tests {
    use super::{hash, integrity, parse_integrity, verify};

    #[test]
    fn empty_input_produces_known_digest() {
        let digest = hash(b"");
        // Known SHA-256 empty string digest (NIST CAVP test vector):
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn abc_input_produces_known_digest() {
        let digest = hash(b"abc");
        // NIST CAVP SHA-256 test vector for "abc":
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn nist_million_bits_input_produces_known_digest() {
        // NIST CAVP SHA-256 test vector for the 448-bit message
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        let digest = hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected: [u8; 32] = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
            0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn integrity_round_trip() {
        let data = b"npm package contents";
        let integ = integrity(data);
        let parsed = parse_integrity(&integ).expect("valid integrity string");
        assert!(crate::secure_compare(&parsed, &hash(data)));
    }

    #[test]
    fn verify_accepts_valid_integrity() {
        let data = b"hello world";
        let integ = integrity(data);
        assert!(verify(data, &integ));
    }

    #[test]
    fn verify_rejects_invalid_integrity() {
        let data = b"hello world";
        assert!(!verify(data, "sha256-invalid"));
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let data = b"hello world";
        let wrong = b"goodbye world";
        let integ = integrity(data);
        assert!(!verify(wrong, &integ));
    }

    #[test]
    fn parse_rejects_malformed_prefix() {
        assert!(parse_integrity("md5-abc").is_none());
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert!(parse_integrity("sha256-!!!").is_none());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        // Valid base64 but not 32 bytes of decoded data
        assert!(parse_integrity("sha256-dGVzdA==").is_none());
    }
}
