# hashkit — Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
Fast hash function collection for Rust — FNV-1a, WyHash, SplitMix, BLAKE3, SHA-256.

## Purpose
Provides a single crate for all hashing needs in Santh: non-cryptographic hashes for indexes and Bloom filters, cryptographic hashes for content addressing and integrity verification.

## North Star
The hash utility crate that explains when NOT to use each algorithm — with stability guarantees for persistent indexes and constant-time comparison for security.

## Role in Ecosystem
- **Depends on:** (none internal)
- **Depended on by:** walkkit, flashsieve, trigramkit, manifestkit, netshift, vyre, yaragpu, warpscan, warpscan-coord, codewalk, authjar, provenance, threatfeed, encodex, gpudecode, ziftsieve
- **Relationship to warpscan:** Hashes content for deduplication (BLAKE3), Bloom filter indexing (FNV/SplitMix), and integrity checks (SHA-256).
- **Standalone value:** YES — any Rust project needing fast, stable, cross-platform hashing primitives.

## Invariants
- `bloom_hash_pair` never returns `(0, 0)` for common pairs.
- `hash_to_index` always returns `< num_bits` (or `0` if `num_bits == 0`).
- `wyhash`, `FNV`, and `SplitMix` outputs are semver-stable across all supported platforms.
- `secure_compare` is constant-time and suitable for digest comparison.
- BLAKE3 and SHA-256 outputs conform to their specifications.

## Boundaries
- 64-bit non-cryptographic hashes are NOT suitable for content-addressed deduplication at internet scale (birthday paradox).
- No incremental/streaming API for non-cryptographic hashes — use BLAKE3 for large files.
- Does not implement password hashing or key derivation.

## Quality State
- Tests: ~12 declared test targets including adversarial blake3, KATs, integration bloom, property invariants
- Lint preamble: yes (strictest in tree — deny expect/unwrap/pedantic)
- #![forbid(unsafe_code)]: yes
- Doc coverage: ~95%
- Known issues: None from latest audit
