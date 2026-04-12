//! BLAKE3 content hashing for deduplication and stability.
//!
//! This module uses only the public API of the [`blake3`](https://docs.rs/blake3) crate:
//! standard, unkeyed BLAKE3-256 (32-byte) digests. There is no custom cryptography here.
//!
//! `ContentHash` wraps [`blake3::Hasher`] in its default configuration (same as
//! [`blake3::Hasher::new`]), which is appropriate for content addressing.
//!
//! # Cross-platform determinism
//!
//! Digest bytes are defined by the BLAKE3 specification; the reference `blake3` crate
//! produces the same output on all supported targets for the same input byte sequence.
//!
//! # Security note
//!
//! When comparing BLAKE3 digests, use [`secure_compare`] or [`crate::secure_compare`]
//! instead of the `==` operator to avoid timing side-channels.

/// A stable, streaming-capable hash for content addressing based on BLAKE3.
///
/// Streaming and one-shot digests use standard unkeyed BLAKE3-256 and match the
/// [`blake3`] crate's default [`blake3::Hasher::new`] configuration (256-bit / 32-byte output).
#[derive(Clone, Debug, Default)]
pub struct ContentHash {
    hasher: blake3::Hasher,
}

impl ContentHash {
    /// Creates a new, empty `ContentHash`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Updates the internal hash state with new data.
    ///
    /// This allows for streaming hashing of large inputs, up to arbitrary lengths.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hash, returning the resulting 32-byte hash array.
    ///
    /// # Security note
    ///
    /// Do not compare the returned array with `==` in security-sensitive contexts.
    /// Use [`secure_compare`] or [`crate::secure_compare`] instead.
    #[inline]
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    /// Finalizes the hash, returning a lowercase hex-encoded string.
    #[inline]
    #[must_use]
    pub fn finalize_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

/// Computes the one-shot BLAKE3 hash of a byte slice.
///
/// # Examples
///
/// ```
/// let hash = hashkit::blake3_hash::hash(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
///
/// # Security note
///
/// Do not compare the returned array with `==` in security-sensitive contexts.
/// Use [`secure_compare`] or [`crate::secure_compare`] instead.
#[inline]
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Compares two BLAKE3 digests in constant time.
///
/// # Examples
///
/// ```
/// let a = hashkit::blake3_hash::hash(b"hello");
/// let b = hashkit::blake3_hash::hash(b"hello");
/// assert!(hashkit::blake3_hash::secure_compare(&a, &b));
/// ```
#[inline]
#[must_use]
pub fn secure_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq::constant_time_eq(a.as_slice(), b.as_slice())
}

/// BLAKE3-256 digest of the empty byte string (spec / reference test vector).
#[cfg(test)]
const EMPTY_DIGEST: [u8; 32] = [
    0xAF, 0x13, 0x49, 0xB9, 0xF5, 0xF9, 0xA1, 0xA6, 0xA0, 0x40, 0x4D, 0xEA, 0x36, 0xDC, 0xC9, 0x49,
    0x9B, 0xCB, 0x25, 0xC9, 0xAD, 0xC1, 0x12, 0xB7, 0xCC, 0x9A, 0x93, 0xCA, 0xE4, 0x1F, 0x32, 0x62,
];

#[cfg(test)]
mod tests {
    use super::{hash, secure_compare, ContentHash, EMPTY_DIGEST};

    #[test]
    fn empty_input_matches_blake3_spec_vector() {
        assert_eq!(hash(b""), EMPTY_DIGEST);
        assert_eq!(ContentHash::new().finalize(), EMPTY_DIGEST);
    }

    #[test]
    fn abc_input_matches_blake3_spec_vector() {
        let expected: [u8; 32] = [
            0x64, 0x37, 0xB3, 0xAC, 0x38, 0x46, 0x51, 0x33, 0xFF, 0xB6, 0x3B, 0x75, 0x27, 0x3A, 0x8D, 0xB5,
            0x48, 0xC5, 0x58, 0x46, 0x5D, 0x79, 0xDB, 0x03, 0xFD, 0x35, 0x9C, 0x6C, 0xD5, 0xBD, 0x9D, 0x85,
        ];
        assert_eq!(hash(b"abc"), expected);
    }

    #[test]
    fn fox_input_matches_blake3_spec_vector() {
        let expected: [u8; 32] = [
            0x2F, 0x15, 0x14, 0x18, 0x1A, 0xAD, 0xCC, 0xD9, 0x13, 0xAB, 0xD9, 0x4C, 0xFA, 0x59, 0x27, 0x01,
            0xA5, 0x68, 0x6A, 0xB2, 0x3F, 0x8D, 0xF1, 0xDF, 0xF1, 0xB7, 0x47, 0x10, 0xFE, 0xBC, 0x6D, 0x4A,
        ];
        assert_eq!(hash(b"The quick brown fox jumps over the lazy dog"), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut h = ContentHash::new();
        h.update(b"hel");
        h.update(b"lo");
        assert_eq!(h.finalize(), hash(b"hello"));
    }

    #[test]
    fn secure_compare_detects_difference() {
        let a = hash(b"alice");
        let b = hash(b"bob");
        assert!(!secure_compare(&a, &b));
    }

    #[test]
    fn secure_compare_accepts_match() {
        let a = hash(b"same");
        let b = hash(b"same");
        assert!(secure_compare(&a, &b));
    }

    #[test]
    fn finalize_hex_matches_one_shot_hex() {
        let mut hasher = ContentHash::new();
        hasher.update(b"hello");
        let hex = hasher.finalize_hex();
        let expected = blake3::hash(b"hello").to_hex().to_string();
        assert_eq!(hex, expected);
        assert_eq!(hex.len(), 64);
    }
}
