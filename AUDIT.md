# hashkit Deep Audit Report

**Date:** 2026-04-11  
**Auditor:** Security Research Agent  
**Scope:** `libs/performance/indexing/hashkit/` — 902 LOC, imported by 7+ crates  
**Test Count:** 330+ tests passing (lib, integration, adversarial, property, concurrent, extreme-scale)  
**Standard:** `cargo test` + `cargo clippy -- -D warnings` enforced after every change.

---

## Executive Summary

This audit examined every source file against the eight mandated questions and the nine non-negotiable laws. One **critical algorithmic bug** was discovered and fixed: `wyhash::wymix` did not match the reference implementation, causing hash outputs to diverge from standard wyhash. All golden vectors have been corrected and verified against the official C reference. No other security-critical issues remain.

---

## 1. FNV-1a 64-bit vs. Published Specification

**Verdict: ✅ MATCHES EXACTLY**

| Aspect | Finding |
|--------|---------|
| Constants | `OFFSET_BASIS = 0xCBF2_9CE4_8422_2325` and `PRIME = 0x0000_0100_0000_01B3` match RFC 9923 / isthe.com spec |
| Algorithm | Byte-by-byte XOR-then-multiply (FNV-1a) matches pseudocode exactly |
| Vectors verified | Empty, `"a"`, `"fo"`..`"foobar"` all match published 64-bit test vectors |
| File | `src/fnv.rs:7`, `src/fnv.rs:13` |

The adversarial test suite (`tests/adversarial/adversarial_hash.rs`) already contains 7 official KATs; all pass.

---

## 2. WyHash vs. Reference Implementation

**Verdict: 🔧 CRITICAL BUG FOUND AND FIXED**

### Finding
`src/wyhash.rs:38` implemented `wymix` as:
```rust
a ^ low ^ b ^ high
```
The official wyhash C reference (`wangyi-fudan/wyhash` v4.3) defines `_wymix` as:
```c
_wymum(&A, &B); return A^B;  // i.e. low ^ high
```

Because `A` and `B` are overwritten in-place by `_wymum`, the reference returns `low ^ high`, **not** `a ^ low ^ b ^ high`. This single-line divergence meant hashkit's "wyhash" produced completely different digests from every other wyhash implementation in the ecosystem.

### Evidence
| Input | Seed | Old (buggy) | Reference C | Fixed Rust |
|-------|------|-------------|-------------|------------|
| `[0,1,2]` | 3 | `0xA595_5D2C_636A_8299` | `0x7587_3B9D_BF36_FA6B` | `0x7587_3B9D_BF36_FA6B` |
| `"abc"` | 7 | `0xBCFF_FF33_0D22_4889` | `0x6549_6750_5AB6_D52E` | `0x6549_6750_5AB6_D52E` |
| `""` | 0 | (implicit) | `0x9322_8A4D_E0EE_C5A2` | `0x9322_8A4D_E0EE_C5A2` |

### Fix Applied
- Changed `wymix` to return `low ^ high` (`src/wyhash.rs`).
- Updated all golden vectors in `src/wyhash.rs` to reference-verified values.
- Updated module docs from "2020-08-26" (a non-existent tag) to "v4.3" (the actual matching reference).

> **Severity: CRITICAL** — Any consumer attempting interoperability with standard wyhash would have received incompatible hashes, breaking content-addressed schemes or cross-language indices.

---

## 3. BLAKE3 — Re-export or Reimplementation?

**Verdict: ✅ PURE RE-EXPORT**

`src/blake3_hash.rs` contains **zero custom cryptography**. It is a thin, safe wrapper around the `blake3` crate:
- `hash(data)` → `blake3::hash(data).into()`
- `ContentHash` → wraps `blake3::Hasher::new()`
- `secure_compare` → delegates to `constant_time_eq::constant_time_eq`

There is no justification for reimplementing BLAKE3; delegating to the audited upstream crate is the correct design.

---

## 4. Const Evaluability

**Verdict: ✅ EXTENDED WHERE STABLE RUST PERMITS**

The following functions were made `const fn` because they involve only primitive arithmetic and no trait methods that are conditionally-const:

| Function | File | Const? |
|----------|------|--------|
| `fnv1a_pair` | `src/fnv.rs` | ✅ |
| `splitmix::finalize` | `src/splitmix.rs` | ✅ |
| `splitmix::pair` | `src/splitmix.rs` | ✅ |
| `bloom_hash_pair` | `src/lib.rs` | ✅ |
| `hash_to_index` | `src/lib.rs` | ✅ |
| `fnv1a_64` | `src/fnv.rs` | ❌ (requires `for` over slice) |
| `wyhash::hash` | `src/wyhash.rs` | ❌ (requires slice-range `Index`) |
| `shannon_entropy` | `src/entropy.rs` | ❌ (requires `f64` trait methods not yet const-stable) |

`blake3_hash::hash` and `sha256_hash::hash` cannot be const because they delegate to external crates.

---

## 5. Streaming / Incremental API

**Verdict: ✅ ONLY BLAKE3 HAS IT (DOCUMENTED LIMITATION)**

| Hash | Streaming API |
|------|---------------|
| FNV-1a | ❌ One-shot only |
| SplitMix64 | ❌ One-shot only |
| WyHash | ❌ One-shot only |
| BLAKE3 | ✅ `ContentHash::update()` / `finalize()` |
| SHA-256 | ❌ One-shot only (no wrapper exposed) |

The crate-level docs explicitly warn:
> "This crate also does **not** provide a streaming/incremental API for the non-cryptographic hashes, so files larger than available memory cannot be hashed incrementally."

This is an acceptable architectural boundary: bloom-filter use cases do not need streaming, and large-file deduplication is explicitly directed to BLAKE3.

---

## 6. Cross-Platform Determinism

**Verdict: ✅ DETERMINISTIC ON ALL RUST TARGETS**

| Component | Mechanism |
|-----------|-----------|
| FNV | Pure byte iteration with fixed `u64` constants |
| SplitMix64 | Pure `u64` arithmetic |
| WyHash | `u64::from_le_bytes` / `u32::from_le_bytes` for all sub-word reads; `u128` widening multiply |
| BLAKE3 | Spec-defined bytestring output |
| SHA-256 | Spec-defined bytestring output |

No conditional compilation, no target-dependent paths, no `unsafe` pointer reads. The same logical input produces the same output on 32-bit, 64-bit, little-endian, and big-endian targets.

> Note: WyHash casts `data.len() as u64`. On 32-bit targets `usize` is `u32`, so the cast is lossless. Inputs > 4 GB cannot exist on 32-bit systems anyway due to address-space limits.

---

## 7. Shannon Entropy

**Verdict: ✅ MATHEMATICALLY CORRECT**

`src/entropy.rs` computes:
```
H = -Σ p(x) · log₂(p(x))
```
with `p(x) = count(x) / len`.

- Empty input correctly returns `0.0`.
- Maximal entropy for bytes (`8.0` bits) is produced by uniformly distributed `[0..=255]`.
- `entropy_bucket` normalizes by `8.0`, clamps to `0.0..=1.0`, scales by `255.0`, and rounds — yielding `0..=255` as documented.

Precision-loss clippy warnings were suppressed with `#[allow(...)]` because:
- `len as f64` only loses precision for slices > 2⁵³ bytes (~9 PB), which is physically impossible in this API.
- The final `f64 → u8` cast is guarded by `clamp(0.0, 1.0)`.

---

## 8. Hex Encoding

**Verdict: ✅ CORRECT FOR ALL 256 BYTE VALUES**

`src/hex.rs` provides:
- `encode` → lowercase hex string
- `decode` → `Result<Vec<u8>, DecodeError>`

Audit actions taken:
- Added exhaustive round-trip test verifying every byte `0..=255` in both lowercase and uppercase.
- Added all-bytes-together test (`[0..=255]` → 512-char hex → exact decode).
- Verified odd-length rejection and invalid-character rejection.

The decoder uses `char_indices()`, which returns **byte indices**. For ASCII hex strings this is identical to character indices; for malformed multi-byte input the reported index is the byte position of the first invalid UTF-8 sequence byte — a reasonable behavior for a hex parser.

---

## 9. Findings Register

| Severity | File:Line | Description | Status |
|----------|-----------|-------------|--------|
| **CRITICAL** | `src/wyhash.rs:38` | `wymix` returned `a ^ low ^ b ^ high` instead of reference `low ^ high`, producing non-standard wyhash digests | **FIXED** |
| INFO | `src/wyhash.rs` | Module docs cited non-existent "2020-08-26" reference; updated to "v4.3" | **FIXED** |
| INFO | `src/fnv.rs:7,13` | FNV-1a constants and algorithm verified against official RFC 9923 / isthe.com vectors | VERIFIED |
| INFO | `src/blake3_hash.rs` | BLAKE3 is a safe wrapper around the audited `blake3` crate; no custom crypto | VERIFIED |
| INFO | `src/lib.rs`, `src/fnv.rs`, `src/splitmix.rs` | Added `const fn` to `hash_to_index`, `bloom_hash_pair`, `fnv1a_pair`, `splitmix::finalize`, `splitmix::pair` | **FIXED** |
| INFO | `src/hex.rs` | Added exhaustive round-trip tests for all 256 byte values | **FIXED** |
| INFO | `src/entropy.rs` | Entropy formulas are mathematically sound; clippy precision-loss warnings justified and allowed | VERIFIED |
| INFO | `src/sha256_hash.rs:81` | Pre-existing `match` rewritten to `let...else` for idiomaticity | **FIXED** |

---

## 10. Conclusion

- **FNV-1a**: Spec-compliant and well-tested.
- **WyHash**: **Critical bug fixed.** Outputs now match the official C reference implementation v4.3. This is a breaking change for any persisted hashkit-wyhash values; downstream users must re-hash or migrate.
- **BLAKE3**: Safe re-export, no custom cryptography.
- **SHA-256**: Safe re-export via `sha2` crate.
- **Entropy / Hex**: Correct, with exhaustive adversarial coverage added.
- **Const-evaluability**: Improved where stable Rust allows.
- **Determinism**: Verified across platforms.
- **Streaming**: Correctly limited to BLAKE3 only; documented limitation.

**Final status:** All 330+ tests pass. `cargo clippy -- -D warnings` is clean. The crate is approved for production use **after** the wyhash breaking change has been absorbed by downstream consumers.
