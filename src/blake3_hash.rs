//! BLAKE3 content hashing for deduplication and stability.
//!
//! Provides `ContentHash`, an abstraction over `blake3::Hasher` that supports
//! streaming inputs and stable content-addressing across platforms.

/// A stable, streaming-capable hash for content addressing based on BLAKE3.
///
/// Ensures exact collision resistance and supports huge (>1GB) datasets.
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
