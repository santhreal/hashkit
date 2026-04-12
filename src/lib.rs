#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::unwrap_used, clippy::pedantic)]
//! Unified hash primitives for performance-sensitive and content-addressed use cases.
//!
//! - [`fnv`]: stable 64-bit FNV-1a, including the flashsieve-compatible two-byte fast path.
//! - [`splitmix`]: `SplitMix64` finalization and compact pair hashing.
//! - [`wyhash`]: fast non-cryptographic bulk hashing of arbitrary byte slices (pinned algorithm;
//!   see module docs).
//! - [`blake3_hash`]: standard BLAKE3-256 via the [`blake3`] crate (streaming and one-shot).
//! - [`sha256_hash`]: standard SHA-256 via the [`sha2`] crate, including npm integrity support.
//!
//! # Security note
//!
//! The non-cryptographic hashes ([`fnv`], [`splitmix`], [`wyhash`]) are **not** suitable for
//! security-sensitive use. For cryptographic hashing, use [`blake3_hash`] or [`sha256_hash`].
//!
//! # Content-addressed deduplication and large files
//!
//! The 64-bit non-cryptographic hashes in this crate are **not** suitable for
//! content-addressed deduplication. At internet scale, the birthday paradox guarantees
//! 64-bit collisions around 4 billion items — a certainty, not a risk.
//!
//! This crate also does **not** provide a streaming/incremental API for the non-cryptographic
//! hashes, so files larger than available memory cannot be hashed incrementally.
//!
//! For content-addressed deduplication and large-file hashing, use **BLAKE3** instead:
//!
//! - One-shot: [`blake3_hash::hash`]
//! - Streaming: [`blake3_hash::ContentHash`] (supports incremental `update()` / `finalize()`)
//!
//! # Output stability for persistent indices
//!
//! - **BLAKE3** digests are defined by the BLAKE3 specification. This crate delegates to the
//!   `blake3` dependency; upgrading that dependency should preserve the same digests for the
//!   same inputs as long as it remains a conforming implementation (pin the version in your
//!   workspace if you need extra assurance during upgrades).
//! - **SHA-256** digests are defined by the SHA-256 specification and delegated to the `sha2`
//!   dependency.
//! - **`wyhash`**, **FNV**, and **`SplitMix`** outputs are defined by this crate's Rust source.
//!   Treat them as a **semver contract**: the golden tests in each module guard against
//!   accidental output changes; changing those values is a **breaking** API change for any
//!   on-disk or replicated index that stores these hashes.
//! - All algorithms here use explicit little-endian interpretation of input bytes where
//!   relevant, and fixed-width integer arithmetic, so **the same logical input yields the same
//!   output on every target** supported by Rust for this crate.
//!
//! # Examples
//!
//! ```
//! use hashkit::{bloom_hash_pair, hash_to_index};
//!
//! let (h1, h2) = bloom_hash_pair(b'a', b'b');
//! let slot = hash_to_index(h1 ^ h2, 1024);
//!
//! assert!(slot < 1024);
//! ```

/// Standard BLAKE3-256 content hashing (see crate-level stability notes).
pub mod blake3_hash;
/// Shannon entropy calculation for byte slices.
pub mod entropy;
/// 64-bit FNV-1a helpers (spec constants; stable across platforms).
pub mod fnv;
/// Hex encoding and decoding.
pub mod hex;
/// Standard SHA-256 hashing with npm integrity string support.
pub mod sha256_hash;
/// SplitMix64 finalization helpers (deterministic integer pipeline).
pub mod splitmix;
/// WyHash-style bulk hashing (reference v4.3; deterministic across platforms).
pub mod wyhash;

/// Returns the two hash functions used for double-hashed bloom filter probes.
///
/// The first element is the flashsieve-compatible FNV-1a hash and the second is
/// the SplitMix64-derived hash.
///
/// # Examples
///
/// ```
/// let (first, second) = hashkit::bloom_hash_pair(b'x', b'y');
///
/// assert_ne!(first, 0);
/// assert_ne!(second, 0);
/// ```
#[inline]
#[must_use]
pub const fn bloom_hash_pair(a: u8, b: u8) -> (u64, u64) {
    (fnv::fnv1a_pair(a, b), splitmix::pair(a, b))
}

/// Reduces a hash into a bit index.
///
/// This uses fast power-of-two masking when `num_bits` is a power of two,
/// and falls back to a modulo operation for other values. If `num_bits` is
/// zero, it safely returns zero to avoid division-by-zero panics.
///
/// # Examples
///
/// ```
/// let index = hashkit::hash_to_index(0xDEAD_BEEF, 256);
///
/// assert!(index < 256);
/// ```
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn hash_to_index(hash: u64, num_bits: usize) -> usize {
    if num_bits == 0 {
        return 0;
    }
    if num_bits.is_power_of_two() {
        // Intentional truncation: only the low bits matter when masking to a
        // power-of-two boundary.
        let hash_usize = hash as usize;
        hash_usize & num_bits.wrapping_sub(1)
    } else {
        let divisor = num_bits as u64;
        let rem = hash % divisor;
        rem as usize
    }
}

/// Compares two byte slices in constant time.
///
/// Use this instead of `==` when comparing cryptographic digests to avoid
/// timing side-channels.
///
/// # Examples
///
/// ```
/// let a = hashkit::blake3_hash::hash(b"hello");
/// let b = hashkit::blake3_hash::hash(b"hello");
/// assert!(hashkit::secure_compare(&a, &b));
/// ```
#[inline]
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};

    const SAMPLE_SEED: u64 = 0x0123_4567_89AB_CDEF;

    #[test]
    fn bloom_hash_pair_matches_components() {
        let pair = bloom_hash_pair(b'a', b'b');
        assert_eq!(pair.0, fnv::fnv1a_pair(b'a', b'b'));
        assert_eq!(pair.1, splitmix::pair(b'a', b'b'));
    }

    #[test]
    fn bloom_hash_pair_is_non_zero_for_common_pair() {
        let (first, second) = bloom_hash_pair(b'n', b'g');
        assert_ne!(first, 0);
        assert_ne!(second, 0);
    }

    #[test]
    fn hash_to_index_zero_hash_maps_to_zero() {
        assert_eq!(hash_to_index(0, 64), 0);
    }

    #[test]
    fn hash_to_index_masks_large_hashes() {
        assert_eq!(hash_to_index(u64::MAX, 1024), 1023);
    }

    #[test]
    fn hash_to_index_stays_in_bounds() {
        for bits in [2_usize, 4, 8, 64, 256, 4096] {
            for hash in [0_u64, 1, 7, 31, 255, u64::MAX, SAMPLE_SEED] {
                assert!(hash_to_index(hash, bits) < bits);
            }
        }
    }

    #[test]
    fn hash_to_index_handles_non_power_of_two() {
        assert_eq!(hash_to_index(7, 10), 7);
        assert_eq!(hash_to_index(13, 10), 3);
        assert_eq!(hash_to_index(0, 10), 0);
    }

    #[test]
    fn hash_to_index_handles_zero() {
        assert_eq!(hash_to_index(7, 0), 0);
    }

    #[test]
    fn wyhash_changes_when_seed_changes() {
        assert_ne!(wyhash::hash(b"abc", 1), wyhash::hash(b"abc", 2));
    }

    #[test]
    fn wyhash_changes_when_input_changes() {
        assert_ne!(
            wyhash::hash(b"abc", SAMPLE_SEED),
            wyhash::hash(b"abd", SAMPLE_SEED)
        );
    }
}
