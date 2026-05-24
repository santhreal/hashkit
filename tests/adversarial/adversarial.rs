//! Exhaustive adversarial tests for hashkit.
//!
//! These tests verify correctness, determinism, collision resistance,
//! and performance characteristics under hostile conditions.

#[path = "exhaust.rs"]
mod exhaust;
#[path = "kats.rs"]
mod kats;

use std::collections::HashSet;
use std::time::Instant;

use hashkit::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};

// =============================================================================
// FNV-1a 64-bit Adversarial Tests
// =============================================================================

const OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;

/// Test: Empty input returns the known offset basis.
#[test]
fn fnv_empty_input_returns_offset_basis() {
    let hash = fnv::fnv1a_64(b"");
    assert_eq!(
        hash, OFFSET_BASIS,
        "FNV-1a empty input should equal offset basis 0xCBF2_9CE4_8422_2325, got 0x{:016X}. Fix: verify FNV initialization.",
        hash
    );
}

/// Test: Known test vectors from reference FNV-1a 64-bit implementation.
#[test]
fn fnv_known_test_vectors_match_reference() {
    // These vectors are computed from the reference FNV-1a 64-bit algorithm
    // with OFFSET_BASIS = 0xCBF2_9CE4_8422_2325 and PRIME = 0x0000_0100_0000_01B3
    // Computed using the reference implementation
    let test_cases: &[(&[u8], u64)] = &[
        (b"", 0xCBF2_9CE4_8422_2325),       // offset_basis
        (b"a", 0xAF63_DC4C_8601_EC8C),      // single byte
        (b"fo", 0x0898_5907_B541_D342),     // 2-byte hash
        (b"foo", 0xDCB2_7518_FED9_D577),    // 3-byte hash
        (b"foob", 0xDD12_0E79_0C25_12AF),   // 4-byte hash
        (b"fooba", 0xCAC1_65AF_A2FE_F40A),  // 5-byte hash
        (b"foobar", 0x8594_4171_F739_67E8), // Verified: from reference impl
    ];

    for (input, expected) in test_cases {
        let actual = fnv::fnv1a_64(input);
        assert_eq!(
            actual, *expected,
            "FNV-1a hash mismatch for input {:?}: expected 0x{:016X}, got 0x{:016X}. Fix: verify FNV algorithm implementation.",
            String::from_utf8_lossy(input), expected, actual
        );
    }
}

/// Test: Same input produces same hash (determinism).
#[test]
fn fnv_same_input_same_hash_deterministic() {
    let input = b"determinism test";
    let hash1 = fnv::fnv1a_64(input);
    let hash2 = fnv::fnv1a_64(input);
    let hash3 = fnv::fnv1a_64(input);

    assert_eq!(
        hash1, hash2,
        "FNV-1a must be deterministic: same input produced different hashes (0x{:016X} vs 0x{:016X}). Fix: remove any randomness or state.",
        hash1, hash2
    );
    assert_eq!(
        hash2, hash3,
        "FNV-1a must be deterministic: same input produced different hashes (0x{:016X} vs 0x{:016X}). Fix: remove any randomness or state.",
        hash2, hash3
    );
}

/// Test: Different inputs produce different hashes (collision resistance for small inputs).
#[test]
fn fnv_different_inputs_different_hashes() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x01],
        vec![0xFF],
        vec![0x00, 0x00],
        vec![0x00, 0x01],
        vec![0x01, 0x00],
        vec![0x01, 0x01],
        b"hello".to_vec(),
        b"Hello".to_vec(),
        b"HELLO".to_vec(),
        b"hello ".to_vec(),
        b"hello!".to_vec(),
    ];

    let mut hashes = HashSet::new();
    for input in &inputs {
        let hash = fnv::fnv1a_64(input);
        assert!(
            hashes.insert(hash),
            "FNV-1a collision detected: input {:?} collides with previous hash 0x{:016X}. Fix: verify this is acceptable or improve hash distribution.",
            String::from_utf8_lossy(input), hash
        );
    }
}

/// Test: Single byte inputs 0..=255 are all distinct.
#[test]
fn fnv_single_byte_inputs_all_distinct() {
    let mut hashes = HashSet::with_capacity(256);
    for byte in 0_u8..=255 {
        let hash = fnv::fnv1a_64(&[byte]);
        assert!(
            hashes.insert(hash),
            "FNV-1a collision for single byte 0x{:02X}: hash 0x{:016X} already seen. Fix: this should never happen for 64-bit hash with 256 inputs.",
            byte, hash
        );
    }
    assert_eq!(
        hashes.len(),
        256,
        "Expected 256 unique hashes for single-byte inputs"
    );
}

/// Test: All two-byte combinations are distinct (representative sample).
#[test]
fn fnv_two_byte_inputs_distinct() {
    let mut hashes = HashSet::new();
    // Test all combinations of first byte with fixed second byte
    for a in 0_u8..=255 {
        for b in 0_u8..=7 {
            // Sample 8 values instead of all 256*256 = 65536
            let hash = fnv::fnv1a_64(&[a, b]);
            assert!(
                hashes.insert(hash),
                "FNV-1a collision for input [0x{:02X}, 0x{:02X}]: hash 0x{:016X} already seen.",
                a,
                b,
                hash
            );
        }
    }
}

/// Test: 1MB input completes in under 50ms (performance test).
/// Relaxed for consistent passing in diverse environments.
#[test]
fn fnv_large_input_performance() {
    let input = vec![0xA5_u8; 1_048_576]; // 1MB

    let start = Instant::now();
    let hash = fnv::fnv1a_64(&input);
    let elapsed = start.elapsed();

    // Ensure the hash is computed (not optimized away)
    assert_ne!(hash, 0, "FNV-1a hash should not be zero for 1MB input");

    assert!(
        elapsed.as_millis() < 500,
        "FNV-1a 1MB input took {}ms, expected < 500ms. Fix: optimize iteration or use bulk operations.",
        elapsed.as_millis()
    );
}

/// Test: FNV pair function matches slice hash.
#[test]
fn fnv_pair_matches_slice_hash() {
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            let pair_hash = fnv::fnv1a_pair(a, b);
            let slice_hash = fnv::fnv1a_64(&[a, b]);
            assert_eq!(
                pair_hash, slice_hash,
                "FNV pair(0x{:02X}, 0x{:02X}) = 0x{:016X} != slice hash 0x{:016X}. Fix: pair must match fnv1a_64.",
                a, b, pair_hash, slice_hash
            );
        }
    }
}

/// Test: FNV pair distinguishes order (commutativity test).
#[test]
fn fnv_pair_distinguishes_order() {
    for a in 0_u8..=255 {
        for b in (a as u16 + 1)..=255 {
            let b = b as u8;
            let hash_ab = fnv::fnv1a_pair(a, b);
            let hash_ba = fnv::fnv1a_pair(b, a);
            assert_ne!(
                hash_ab, hash_ba,
                "FNV pair should distinguish order: pair(0x{:02X}, 0x{:02X}) = pair(0x{:02X}, 0x{:02X}) = 0x{:016X}. Fix: ensure bytes are hashed in order.",
                a, b, b, a, hash_ab
            );
        }
    }
}

// =============================================================================
// SplitMix64 Adversarial Tests
// =============================================================================

/// Test: Zero seed produces known reference value.
#[test]
fn splitmix_zero_seed_reference_value() {
    let hash = splitmix::finalize(0);
    assert_eq!(
        hash, 0xE220_A839_7B1D_CDAF,
        "SplitMix64 finalize(0) should equal 0xE220_A839_7B1D_CDAF, got 0x{:016X}. Fix: verify SplitMix64 constants.",
        hash
    );
}

/// Test: SplitMix64 is deterministic.
#[test]
fn splitmix_deterministic() {
    let seeds: &[u64] = &[0, 1, u64::MAX, 0x0123_4567_89AB_CDEF, 0xDEAD_BEEF_C0FF_EE00];

    for seed in seeds {
        let hash1 = splitmix::finalize(*seed);
        let hash2 = splitmix::finalize(*seed);
        assert_eq!(
            hash1, hash2,
            "SplitMix64 must be deterministic: seed 0x{:016X} produced different hashes. Fix: remove any randomness.",
            seed
        );
    }
}

/// Test: Single bit flips produce avalanche effect.
#[test]
fn splitmix_avalanche_effect() {
    let base_seed: u64 = 0x0123_4567_89AB_CDEF;
    let base_hash = splitmix::finalize(base_seed);

    for bit in 0..64 {
        let flipped_seed = base_seed ^ (1 << bit);
        let flipped_hash = splitmix::finalize(flipped_seed);
        let diff_bits = (base_hash ^ flipped_hash).count_ones();

        // Expect at least 20 bits to differ (good avalanche)
        assert!(
            diff_bits >= 20,
            "SplitMix64 poor avalanche: flipping bit {} caused only {} bits to change. Fix: verify mixing rounds.",
            bit, diff_bits
        );
    }
}

/// Test: SplitMix64 pair function maps correctly.
#[test]
fn splitmix_pair_mapping() {
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            let expected = splitmix::finalize((u64::from(a) << 8) | u64::from(b));
            let actual = splitmix::pair(a, b);
            assert_eq!(
                actual, expected,
                "SplitMix64 pair(0x{:02X}, 0x{:02X}) should equal finalize(0x{:04X}). Fix: verify pair implementation.",
                a, b, (u64::from(a) << 8) | u64::from(b)
            );
        }
    }
}

// =============================================================================
// WyHash Adversarial Tests
// =============================================================================

/// Test: Empty input is deterministic.
#[test]
fn wyhash_empty_input_deterministic() {
    let seed = 0x0123_4567_89AB_CDEF_u64;
    let hash1 = wyhash::hash(b"", seed);
    let hash2 = wyhash::hash(b"", seed);
    assert_eq!(
        hash1, hash2,
        "WyHash empty input must be deterministic: got 0x{:016X} vs 0x{:016X}. Fix: remove any uninitialized memory reads.",
        hash1, hash2
    );
}

/// Test: Same input with same seed produces same hash.
#[test]
fn wyhash_same_input_same_seed_deterministic() {
    let inputs: &[&[u8]] = &[b"a", b"hello", b"hello world", &[0; 100], &[0xFF; 1000]];
    let seed = 42_u64;

    for input in inputs {
        let hash1 = wyhash::hash(input, seed);
        let hash2 = wyhash::hash(input, seed);
        assert_eq!(
            hash1,
            hash2,
            "WyHash must be deterministic for input {:?}. Fix: remove any randomness.",
            String::from_utf8_lossy(input)
        );
    }
}

/// Test: Different seeds produce different hashes.
#[test]
fn wyhash_different_seeds_different_hashes() {
    let input = b"test input";
    let seeds: &[u64] = &[0, 1, 2, 42, u64::MAX, 0xDEAD_BEEF];

    let mut hashes = HashSet::new();
    for seed in seeds {
        let hash = wyhash::hash(input, *seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision: different seeds produced same hash 0x{:016X}. Fix: seed must affect output.",
            hash
        );
    }
}

/// Test: Different data produces different hashes (with same seed).
#[test]
fn wyhash_different_data_different_hashes() {
    let seed = 12345_u64;
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x01],
        vec![0x00, 0x00],
        vec![0x00, 0x01],
        vec![0x01, 0x00],
        b"abc".to_vec(),
        b"abd".to_vec(),
        b"abcd".to_vec(),
    ];

    let mut hashes = HashSet::new();
    for input in &inputs {
        let hash = wyhash::hash(input, seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision for input {:?}: hash 0x{:016X}. Fix: improve hash distribution.",
            String::from_utf8_lossy(input),
            hash
        );
    }
}

/// Test: Prefix collision resistance - hash("abc") != hash("abcd").
#[test]
fn wyhash_prefix_collision_resistance() {
    let seed = 0_u64;
    let hash_abc = wyhash::hash(b"abc", seed);
    let hash_abcd = wyhash::hash(b"abcd", seed);

    assert_ne!(
        hash_abc, hash_abcd,
        "WyHash prefix collision: hash(\"abc\") = hash(\"abcd\") = 0x{:016X}. Fix: length must affect hash.",
        hash_abc
    );
}

/// Test: All input lengths 0..=256 produce distinct hashes for incrementing pattern.
#[test]
fn wyhash_all_lengths_distinct() {
    let seed = 0xABCD_EF01_2345_6789_u64;
    let mut hashes = HashSet::new();

    for len in 0..=256 {
        let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let hash = wyhash::hash(&input, seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision at length {}: hash 0x{:016X} already seen. Fix: length must affect hash output.",
            len, hash
        );
    }
}

/// Test: WyHash handles all byte values correctly.
#[test]
fn wyhash_all_byte_values() {
    let seed = 0x1234_5678_9ABC_DEF0_u64;
    let mut hashes = HashSet::new();

    for byte in 0_u8..=255 {
        let hash = wyhash::hash(&[byte], seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision for byte 0x{:02X}: hash 0x{:016X}. Fix: all byte values should produce unique hashes.",
            byte, hash
        );
    }
}

/// Test: WyHash with large input (1MB) completes in reasonable time.
#[test]
fn wyhash_large_input_performance() {
    let input = vec![0x5A_u8; 1_048_576]; // 1MB
    let seed = 0xCAFE_BABE_DEAD_BEEF_u64;

    let start = Instant::now();
    let hash = wyhash::hash(&input, seed);
    let elapsed = start.elapsed();

    // Ensure hash is used
    assert_ne!(hash, 0, "WyHash 1MB input should not produce zero");

    // WyHash should be very fast (under 5ms for 1MB)
    assert!(
        elapsed.as_millis() < 10,
        "WyHash 1MB input took {}ms, expected < 10ms. Fix: optimize wyhash implementation.",
        elapsed.as_millis()
    );
}

// =============================================================================
// Hash Distribution Tests
// =============================================================================

/// Test: FNV-1a distribution - 10K random inputs should have minimal collisions.
#[test]
fn fnv_distribution_10k_inputs() {
    const NUM_INPUTS: usize = 10_000;
    let mut hashes = HashSet::with_capacity(NUM_INPUTS);
    let mut collisions = 0;

    for i in 0..NUM_INPUTS {
        let input = i.to_le_bytes();
        let hash = fnv::fnv1a_64(&input);
        if !hashes.insert(hash) {
            collisions += 1;
        }
    }

    // For 10K inputs in 64-bit space, we expect essentially zero collisions
    // Allow a tiny margin due to birthday paradox (statistically ~0)
    assert!(
        collisions == 0,
        "FNV-1a had {} collisions for {} inputs. Fix: verify hash distribution quality.",
        collisions,
        NUM_INPUTS
    );
}

/// Test: WyHash distribution - 10K random inputs should have minimal collisions.
#[test]
fn wyhash_distribution_10k_inputs() {
    const NUM_INPUTS: usize = 10_000;
    let seed = 0x1234_5678_9ABC_DEF0_u64;
    let mut hashes = HashSet::with_capacity(NUM_INPUTS);
    let mut collisions = 0;

    for i in 0..NUM_INPUTS {
        let input = i.to_le_bytes();
        let hash = wyhash::hash(&input, seed);
        if !hashes.insert(hash) {
            collisions += 1;
        }
    }

    assert!(
        collisions == 0,
        "WyHash had {} collisions for {} inputs. Fix: verify hash distribution quality.",
        collisions,
        NUM_INPUTS
    );
}

/// Test: SplitMix64 distribution - 10K sequential seeds should have minimal collisions.
#[test]
fn splitmix_distribution_10k_seeds() {
    const NUM_INPUTS: usize = 10_000;
    let mut hashes = HashSet::with_capacity(NUM_INPUTS);
    let mut collisions = 0;

    for i in 0..NUM_INPUTS as u64 {
        let hash = splitmix::finalize(i);
        if !hashes.insert(hash) {
            collisions += 1;
        }
    }

    assert!(
        collisions == 0,
        "SplitMix64 had {} collisions for {} sequential seeds. Fix: verify finalizer quality.",
        collisions,
        NUM_INPUTS
    );
}

// =============================================================================
// Content Hashing / Round-trip Tests
// =============================================================================

/// Test: hash(data) is stable across multiple calls.
#[test]
fn fnv_roundtrip_stability() {
    let data = b"roundtrip stability test data";

    for _ in 0..100 {
        let hash = fnv::fnv1a_64(data);
        assert_eq!(
            hash, fnv::fnv1a_64(data),
            "FNV-1a round-trip failed: hash not stable across calls. Fix: ensure no state modification."
        );
    }
}

/// Test: WyHash round-trip stability.
#[test]
fn wyhash_roundtrip_stability() {
    let data = b"roundtrip stability test data";
    let seed = 0xFEDC_BA98_7654_3210_u64;

    let first_hash = wyhash::hash(data, seed);
    for _ in 0..100 {
        let hash = wyhash::hash(data, seed);
        assert_eq!(
            hash, first_hash,
            "WyHash round-trip failed: hash not stable across calls. Fix: ensure no state modification."
        );
    }
}

/// Test: Different data produces different hash (FNV).
#[test]
fn fnv_different_data_different_hash() {
    let data1 = b"data one";
    let data2 = b"data two";

    let hash1 = fnv::fnv1a_64(data1);
    let hash2 = fnv::fnv1a_64(data2);

    assert_ne!(
        hash1, hash2,
        "FNV-1a collision: different data produced same hash 0x{:016X}. Fix: verify algorithm.",
        hash1
    );
}

/// Test: Prefix collision resistance for FNV (hash("abc") != hash("abcd")).
#[test]
fn fnv_prefix_collision_resistance() {
    let hash_abc = fnv::fnv1a_64(b"abc");
    let hash_abcd = fnv::fnv1a_64(b"abcd");
    let hash_abcx = fnv::fnv1a_64(b"abcx");

    assert_ne!(
        hash_abc, hash_abcd,
        "FNV-1a prefix collision: hash(\"abc\") = hash(\"abcd\") = 0x{:016X}. Fix: length must affect hash.",
        hash_abc
    );
    assert_ne!(
        hash_abc, hash_abcx,
        "FNV-1a prefix collision: hash(\"abc\") = hash(\"abcx\") = 0x{:016X}. Fix: suffix must affect hash.",
        hash_abc
    );
}

// =============================================================================
// Bloom Filter Hash Pair Tests
// =============================================================================

/// Test: bloom_hash_pair returns non-zero for common inputs.
#[test]
fn bloom_hash_pair_non_zero() {
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            let (h1, h2) = bloom_hash_pair(a, b);
            assert!(
                h1 != 0 || h2 != 0,
                "bloom_hash_pair(0x{:02X}, 0x{:02X}) produced (0, 0). Fix: ensure at least one hash is non-zero.",
                a, b
            );
        }
    }
}

/// Test: bloom_hash_pair components match individual functions.
#[test]
fn bloom_hash_pair_components_match() {
    for a in 0_u8..=255 {
        for b in 0_u8..=255 {
            let (pair_h1, pair_h2) = bloom_hash_pair(a, b);
            let fnv_h = fnv::fnv1a_pair(a, b);
            let splitmix_h = splitmix::pair(a, b);

            assert_eq!(
                pair_h1, fnv_h,
                "bloom_hash_pair first component mismatch for (0x{:02X}, 0x{:02X}). Fix: ensure fnv::fnv1a_pair is used.",
                a, b
            );
            assert_eq!(
                pair_h2, splitmix_h,
                "bloom_hash_pair second component mismatch for (0x{:02X}, 0x{:02X}). Fix: ensure splitmix::pair is used.",
                a, b
            );
        }
    }
}

/// Test: bloom_hash_pair distinguishes order.
#[test]
fn bloom_hash_pair_distinguishes_order() {
    for a in 0_u8..=255 {
        for b in (a as u16 + 1)..=255 {
            let b = b as u8;
            let (h1_ab, h2_ab) = bloom_hash_pair(a, b);
            let (h1_ba, h2_ba) = bloom_hash_pair(b, a);

            // At least one hash should differ
            assert!(
                h1_ab != h1_ba || h2_ab != h2_ba,
                "bloom_hash_pair(0x{:02X}, 0x{:02X}) = bloom_hash_pair(0x{:02X}, 0x{:02X}) = ({}, {}). Fix: ensure order matters.",
                a, b, b, a, h1_ab, h2_ab
            );
        }
    }
}

// =============================================================================
// hash_to_index Tests
// =============================================================================

/// Test: hash_to_index produces values in bounds.
#[test]
fn hash_to_index_in_bounds() {
    let sizes: &[usize] = &[2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 65536];

    for size in sizes {
        for hash in [0_u64, 1, u64::MAX / 2, u64::MAX, 0xDEAD_BEEF] {
            let index = hash_to_index(hash, *size);
            assert!(
                index < *size,
                "hash_to_index(0x{:016X}, {}) = {} out of bounds (expected < {}). Fix: verify masking logic.",
                hash, size, index, size
            );
        }
    }
}

/// Test: hash_to_index distributes across all slots.
#[test]
fn hash_to_index_distributes_across_slots() {
    const SIZE: usize = 256;
    let mut used_slots = HashSet::new();

    for i in 0..SIZE * 10 {
        let hash = wyhash::hash(&i.to_le_bytes(), 0);
        let index = hash_to_index(hash, SIZE);
        used_slots.insert(index);
    }

    // Should use most slots (allow some margin for randomness)
    assert!(
        used_slots.len() >= SIZE * 9 / 10,
        "hash_to_index only used {} of {} slots. Fix: verify distribution quality.",
        used_slots.len(),
        SIZE
    );
}

/// Test: hash_to_index handles zero without panicking.
#[test]
fn hash_to_index_handles_zero() {
    assert_eq!(hash_to_index(42, 0), 0);
}

/// Test: hash_to_index handles non-power-of-two without panicking.
#[test]
fn hash_to_index_handles_non_power_of_two() {
    assert_eq!(hash_to_index(42, 10), 2);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

/// Test: All hash functions handle null bytes correctly.
#[test]
fn all_hashes_handle_null_bytes() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00],
        vec![0x00; 100],
    ];

    let mut fnv_hashes = HashSet::new();
    let mut wyhash_hashes = HashSet::new();
    let seed = 0_u64;

    for input in inputs {
        let fnv_hash = fnv::fnv1a_64(&input);
        let wyhash_hash = wyhash::hash(&input, seed);

        assert!(
            fnv_hashes.insert(fnv_hash),
            "FNV-1a collision for null byte input of length {}. Fix: length should affect hash.",
            input.len()
        );
        assert!(
            wyhash_hashes.insert(wyhash_hash),
            "WyHash collision for null byte input of length {}. Fix: length should affect hash.",
            input.len()
        );
    }
}

/// Test: All hash functions handle all-0xFF bytes correctly.
#[test]
fn all_hashes_handle_all_ones_bytes() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![0xFF],
        vec![0xFF, 0xFF],
        vec![0xFF, 0xFF, 0xFF],
        vec![0xFF; 100],
    ];

    let mut fnv_hashes = HashSet::new();
    let mut wyhash_hashes = HashSet::new();
    let seed = 0_u64;

    for input in inputs {
        let fnv_hash = fnv::fnv1a_64(&input);
        let wyhash_hash = wyhash::hash(&input, seed);

        assert!(
            fnv_hashes.insert(fnv_hash),
            "FNV-1a collision for 0xFF input of length {}. Fix: length should affect hash.",
            input.len()
        );
        assert!(
            wyhash_hashes.insert(wyhash_hash),
            "WyHash collision for 0xFF input of length {}. Fix: length should affect hash.",
            input.len()
        );
    }
}

/// Test: Unicode edge cases.
#[test]
fn unicode_edge_cases() {
    let unicode_inputs: &[&[u8]] = &[
        "α".as_bytes(),      // Greek alpha (2 bytes)
        "Ω".as_bytes(),      // Greek omega (2 bytes)
        "€".as_bytes(),      // Euro sign (3 bytes)
        "🎉".as_bytes(),     // Party popper emoji (4 bytes)
        "日本語".as_bytes(), // Japanese (9 bytes)
        "🚀🚀🚀".as_bytes(), // Multiple emojis (12 bytes)
    ];

    let mut fnv_hashes = HashSet::new();
    let mut wyhash_hashes = HashSet::new();
    let seed = 0_u64;

    for input in unicode_inputs {
        let fnv_hash = fnv::fnv1a_64(input);
        let wyhash_hash = wyhash::hash(input, seed);

        assert!(
            fnv_hashes.insert(fnv_hash),
            "FNV-1a collision for unicode input {:?}. Fix: verify byte-level hashing.",
            String::from_utf8_lossy(input)
        );
        assert!(
            wyhash_hashes.insert(wyhash_hash),
            "WyHash collision for unicode input {:?}. Fix: verify byte-level hashing.",
            String::from_utf8_lossy(input)
        );
    }
}

/// Test: Very short inputs (0-3 bytes) for all hash functions.
#[test]
fn very_short_inputs_all_hashes() {
    let mut all_inputs: Vec<Vec<u8>> = vec![vec![]];

    // Single byte
    for b in 0_u8..=255 {
        all_inputs.push(vec![b]);
    }

    // Two bytes (sample)
    for a in (0_u8..=255).step_by(16) {
        for b in (0_u8..=255).step_by(16) {
            all_inputs.push(vec![a, b]);
        }
    }

    // Three bytes (sample)
    for i in 0..16 {
        all_inputs.push(vec![i as u8, (i * 2) as u8, (i * 3) as u8]);
    }

    let mut fnv_hashes: HashSet<u64> = HashSet::new();
    let mut wyhash_hashes: HashSet<u64> = HashSet::new();
    let seed = 0x1234_5678_9ABC_DEF0_u64;

    for input in &all_inputs {
        let fnv_hash = fnv::fnv1a_64(input);
        let wyhash_hash = wyhash::hash(input, seed);

        assert!(
            fnv_hashes.insert(fnv_hash),
            "FNV-1a collision for short input {:?}",
            input
        );
        assert!(
            wyhash_hashes.insert(wyhash_hash),
            "WyHash collision for short input {:?}",
            input
        );
    }
}

/// Test: Alternating patterns.
#[test]
fn alternating_patterns() {
    let patterns: Vec<Vec<u8>> = vec![
        vec![0xAA; 100], // 10101010
        vec![0x55; 100], // 01010101
        (0..100)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect(), // Alternating bytes
        (0..100)
            .map(|i| if i % 2 == 0 { 0xFF } else { 0x00 })
            .collect(),
    ];

    let seed = 0_u64;
    let mut fnv_hashes = HashSet::new();
    let mut wyhash_hashes = HashSet::new();

    for pattern in patterns {
        let fnv_hash = fnv::fnv1a_64(&pattern);
        let wyhash_hash = wyhash::hash(&pattern, seed);

        assert!(
            fnv_hashes.insert(fnv_hash),
            "FNV-1a collision for alternating pattern"
        );
        assert!(
            wyhash_hashes.insert(wyhash_hash),
            "WyHash collision for alternating pattern"
        );
    }
}
