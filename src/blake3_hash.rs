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

/// A stable, streaming-capable hash for content addressing based on BLAKE3.
///
/// Streaming and one-shot digests use standard unkeyed BLAKE3-256 and match the
/// [`blake3`] crate’s default [`blake3::Hasher::new`] configuration (256-bit / 32-byte output).
#[derive(Clone, Default)]
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
#[inline]
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// BLAKE3-256 digest of the empty byte string (spec / reference test vector).
#[cfg(test)]
const EMPTY_DIGEST: [u8; 32] = [
    0xAF, 0x13, 0x49, 0xB9, 0xF5, 0xF9, 0xA1, 0xA6, 0xA0, 0x40, 0x4D, 0xEA, 0x36, 0xDC, 0xC9,
    0x49, 0x9B, 0xCB, 0x25, 0xC9, 0xAD, 0xC1, 0x12, 0xB7, 0xCC, 0x9A, 0x93, 0xCA, 0xE4, 0x1F,
    0x32, 0x62,
];

#[cfg(test)]
mod tests {
    use super::{hash, ContentHash, EMPTY_DIGEST};

    #[test]
    fn empty_input_matches_blake3_spec_vector() {
        assert_eq!(hash(b""), EMPTY_DIGEST);
        assert_eq!(ContentHash::new().finalize(), EMPTY_DIGEST);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut h = ContentHash::new();
        h.update(b"hel");
        h.update(b"lo");
        assert_eq!(h.finalize(), hash(b"hello"));
    }
}
