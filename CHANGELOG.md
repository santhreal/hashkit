# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-04-12

### Added
- Initial release of `hashkit` with FNV-1a, SplitMix64, WyHash v4.3, BLAKE3-256, and SHA-256 primitives.
- `ContentHash` streaming BLAKE3 hasher with incremental `update()` / `finalize()` support.
- `bloom_hash_pair` and `hash_to_index` utilities for bloom-filter indexing.
- `hex` encoding/decoding with `DecodeError` reporting.
- Shannon `entropy` calculation and 8-bit bucket quantization.
- `secure_compare` constant-time comparison for cryptographic digests.
- NIST CAVP and BLAKE3 specification test vectors for cryptographic hashes.
- Golden output tests for all non-cryptographic hashes to guarantee cross-platform determinism.
