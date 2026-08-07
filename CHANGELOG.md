# Changelog


## [0.1.5] - 2026-08-07

### Fixed
- `sha256_hash::parse_integrity` now robustly parses SRI integrity strings with surrounding whitespace, option parameters (`?key=val`), and multi-token SRI strings containing a SHA-256 fallback digest.
- `entropy::EntropyCounter` frequency counting now saturates `u64` per byte rather than overflowing, maintaining consistency with `total` saturating additions.

### Added
- `blake3_hash::ContentHash::reset()` method to reset streaming hasher state without re-allocating `ContentHash`.
## [0.1.4] - 2026-08-07

- Crate `authors` set to `Santh <64453045+santhreal@users.noreply.github.com>`.
- Docs: SPEC/README mention EntropyCounter, bloom_probes, sha256_hex, DecodeError::InvalidCharacter byte field.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-07-30

### Fixed
- `cargo clippy --all-targets` now compiles clean: math identifiers in the
  `entropy` module docs are backticked (`doc_markdown`), and the crate-level
  `expect_used`/`unwrap_used`/`pedantic` denies are scoped to non-test code so
  the test suite no longer trips them. No behavioral changes.
- Removed a redundant `#[must_use]` on `bloom_probes` (its `impl Iterator`
  return type is already `#[must_use]`).

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
