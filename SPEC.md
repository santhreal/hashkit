# hashkit: Specification

## Overview

`hashkit` is a Rust library that exposes unified hash primitives for fast indexing and content addressing. It provides non-cryptographic 64-bit hashes (FNV-1a, SplitMix64, WyHash) for bloom filters and hash tables, cryptographic 256-bit hashes (BLAKE3, SHA-256) for integrity verification, plus hex utilities and Shannon entropy calculation.

## Architecture

The crate is organized as a flat module tree with algorithm-specific modules and thin wrappers:

- **`fnv`**: 64-bit FNV-1a using spec constants (`OFFSET_BASIS`, `PRIME`). Includes a flashsieve-compatible two-byte fast path (`fnv1a_pair`) that avoids slice iteration.
- **`splitmix`**: `SplitMix64` finalization (`finalize`) and a two-byte pair encoder (`pair`) used as the second hash in bloom-filter probes.
- **`wyhash`**: Dependency-free WyHash v4.3 implementation using `u128` widening multiplication (`wymum`/`wymix`) and explicit little-endian byte reads. Processes inputs in 48-byte unrolled lanes for large slices and tail-calls for the final 16 bytes.
- **`blake3_hash`**: Thin safe wrapper around the `blake3` crate. Provides one-shot `hash` and a streaming `ContentHash` struct (`update` / `finalize` / `finalize_hex`).
- **`sha256_hash`**: Thin wrapper around the `sha2` crate. Provides one-shot `hash`, npm integrity string generation (`integrity`), parsing (`parse_integrity`), and verification (`verify`).
- **`hex`**: Dependency-free lowercase hex encoding (`encode`) and decoding (`decode`) with explicit error reporting.
- **`entropy`**: Shannon entropy calculation (`shannon_entropy`), streaming accumulator (`EntropyCounter`), and 8-bit quantization (`entropy_bucket`) for byte slices.

Root utilities in `lib.rs`:
- `bloom_hash_pair(a, b)`: returns `(fnv1a_pair(a, b), splitmix::pair(a, b))`.
- `bloom_probes(h1, h2, k, num_bits)`: generates `k` bit indices using Kirsch-Mitzenmacher double hashing.
- `hash_to_index(hash, num_bits)`: maps a `u64` to a bit index using power-of-two masking or modulo, with zero-safe fallback.
- `secure_compare(a, b)`: constant-time byte-slice comparison for cryptographic digests.

All modules are pure Rust with `#![forbid(unsafe_code)]`.

## Guarantees

- **Cross-platform determinism**: For the same input byte sequence, all hash functions produce identical outputs on every target supported by this crate. Non-cryptographic algorithms use explicit little-endian reads and fixed-width integer arithmetic.
- **Output stability**: Golden test vectors guard against accidental changes to hash outputs; changing them is treated as a semver-breaking change.
- **Cryptographic correctness**: BLAKE3 and SHA-256 are validated against published test vectors (empty string, `"abc"`, NIST CAVP).
- **No panics on normal use**: Hashing functions are infallible for all inputs. `hash_to_index` safely returns `0` when `num_bits == 0`.
- **Timing-attack resistance**: `secure_compare` (and `blake3_hash::secure_compare`) use `constant_time_eq` for digest comparison.

## Public API

### Types
- `blake3_hash::ContentHash`: streaming BLAKE3 hasher.
- `entropy::EntropyCounter`: streaming Shannon entropy accumulator.
- `hex::DecodeError`: `#[non_exhaustive]` enum with `OddLength` and `InvalidCharacter { byte, index }`.

### Functions
- `fnv::fnv1a_64(data: &[u8]) -> u64`
- `fnv::fnv1a_pair(a: u8, b: u8) -> u64`
- `splitmix::finalize(seed: u64) -> u64`
- `splitmix::pair(a: u8, b: u8) -> u64`
- `wyhash::hash(data: &[u8], seed: u64) -> u64`
- `blake3_hash::hash(data: &[u8]) -> [u8; 32]`
- `blake3_hash::secure_compare(a: &[u8; 32], b: &[u8; 32]) -> bool`
- `sha256_hash::hash(data: &[u8]) -> [u8; 32]`
- `sha256_hash::integrity(data: &[u8]) -> String`
- `sha256_hash::parse_integrity(integrity: &str) -> Option<[u8; 32]>`
- `sha256_hash::sha256_hex(data: &[u8]) -> String`
- `sha256_hash::verify(data: &[u8], integrity: &str) -> bool`
- `hex::encode(bytes: &[u8]) -> String`
- `hex::decode(hex: &str) -> Result<Vec<u8>, DecodeError>`
- `entropy::shannon_entropy(bytes: &[u8]) -> f64`
- `entropy::entropy_bucket(bytes: &[u8]) -> u8`
- `bloom_hash_pair(a: u8, b: u8) -> (u64, u64)`
- `bloom_probes(h1: u64, h2: u64, k: usize, num_bits: usize) -> impl Iterator<Item = usize>`
- `hash_to_index(hash: u64, num_bits: usize) -> usize`
- `secure_compare(a: &[u8], b: &[u8]) -> bool`

## Error handling

- **Hashing functions** (`fnv1a_64`, `wyhash::hash`, `blake3_hash::hash`, `sha256_hash::hash`) are infallible; they accept any `&[u8]` and return a fixed-width digest.
- **`hash_to_index`** is infallible: returns `0` when `num_bits == 0` to avoid division-by-zero.
- **`hex::decode`** returns `Result<Vec<u8>, DecodeError>`:
  - `OddLength`: input has an odd number of characters.
  - `InvalidCharacter { c, index }`: non-hex character found at the given byte index.
- **`sha256_hash::parse_integrity`** returns `Option<[u8; 32]>`, yielding `None` for missing `sha256-` prefix, invalid base64, or decoded lengths other than 32 bytes.
- **`sha256_hash::verify`** returns `false` for any malformed integrity string or digest mismatch.

## Performance characteristics

- **FNV-1a**: O(n) time, O(1) auxiliary space. Processes one byte per iteration; optimal for very short inputs.
- **SplitMix64**: O(1) time, O(1) space.
- **WyHash**: O(n) time, O(1) space. Large inputs are processed in 48-byte unrolled lanes; small inputs use branch-tailored logic.
- **BLAKE3 / SHA-256**: Performance is delegated to the underlying `blake3` and `sha2` crates; wrappers add minimal indirection.
- **Entropy**: O(n) time, O(1) space (256-byte frequency table on the stack).
- **Hex encode/decode**: O(n) time, O(n) space for the output buffer.

## Limitations

- **No `no_std` support**: Despite the crate category, `hex`, `blake3_hash`, and `sha256_hash` rely on `String` and `Vec`, so the crate currently requires `std`.
- **No streaming for 64-bit hashes**: `fnv`, `splitmix`, and `wyhash` only provide one-shot APIs; files larger than available memory cannot be hashed incrementally with them.
- **Non-cryptographic hashes are not collision-resistant**: `fnv`, `splitmix`, and `wyhash` must not be used for password hashing, MACs, or security-sensitive content addressing.
- **64-bit birthday bound**: At internet scale, 64-bit hashes collide around 4 billion items, making them unsuitable for global content-addressed deduplication.
- **WyHash is pinned to v4.3**: The reference implementation and secret constants are fixed; upgrading the algorithm would be a breaking change for stored indices.
- **No SIMD in wyhash**: The implementation uses scalar `u128` multiplication and byte-wise reads; it does not use target-specific SIMD extensions.
