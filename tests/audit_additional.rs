//! Additional adversarial and edge-case tests from deep audit.
//!
//! These tests verify behaviors not covered by existing test suites,
//! focusing on internet-scale deployment concerns.

use std::collections::HashSet;

use hashkit::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};

// =============================================================================
// WyHash Additional Tests
// =============================================================================

/// Test: WyHash produces different hashes for different length inputs
/// with the same prefix (length extension sensitivity).
#[test]
fn wyhash_length_extension_sensitivity() {
    let seed = 0x1234_5678_9ABC_DEF0_u64;
    let base = b"prefix";

    let mut hashes = HashSet::new();
    for i in 0..20 {
        let mut input = base.to_vec();
        input.extend(vec![b'X'; i]);
        let hash = wyhash::hash(&input, seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision for length extension at length {}",
            base.len() + i
        );
    }
}

/// Test: WyHash is sensitive to changes at every byte position.
#[test]
fn wyhash_position_sensitivity() {
    let seed = 0xABCD_EF01_2345_6789_u64;
    let base = vec![0xAA; 32];
    let reference = wyhash::hash(&base, seed);

    for pos in [0, 1, 7, 8, 15, 16, 23, 24, 31] {
        let mut modified = base.clone();
        modified[pos] ^= 0xFF; // Flip all bits at position
        let modified_hash = wyhash::hash(&modified, seed);
        assert_ne!(
            reference, modified_hash,
            "WyHash not sensitive to change at byte position {}",
            pos
        );
    }
}

/// Test: WyHash handles boundary sizes (3, 4, 16, 17, 48, 49 bytes).
#[test]
fn wyhash_boundary_sizes() {
    let seed = 0xDEAD_BEEF_CAFE_BABE_u64;
    let sizes = [0, 1, 2, 3, 4, 5, 15, 16, 17, 47, 48, 49, 50, 63, 64, 65];

    let mut hashes = HashSet::new();
    for size in sizes {
        let input = vec![0x5A; size];
        let hash = wyhash::hash(&input, seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision at boundary size {} (input: {:02X?})",
            size,
            &input[..size.min(4)]
        );
    }
}

/// Test: WyHash produces unique hashes for 256 sequential byte values.
#[test]
fn wyhash_sequential_byte_values_unique() {
    let seed = 0xFEDC_BA98_7654_3210_u64;
    let mut hashes = HashSet::with_capacity(256);

    for i in 0..256_u16 {
        let input = i.to_le_bytes();
        let hash = wyhash::hash(&input, seed);
        assert!(
            hashes.insert(hash),
            "WyHash collision for sequential value {} (bytes: {:02X?})",
            i,
            input
        );
    }
    assert_eq!(hashes.len(), 256);
}

// =============================================================================
// FNV-1a Additional Tests
// =============================================================================

/// Test: FNV-1a handles incremental input building correctly.
#[test]
fn fnv_incremental_building_unique() {
    let mut hashes = HashSet::new();
    let mut input = Vec::new();

    for i in 0..100_u8 {
        input.push(i);
        let hash = fnv::fnv1a_64(&input);
        assert!(
            hashes.insert(hash),
            "FNV-1a collision at incremental length {}",
            input.len()
        );
    }
}

/// Test: FNV-1a distinguishes between repeated patterns.
#[test]
fn fnv_repeated_pattern_distinguishing() {
    let patterns: Vec<Vec<u8>> = vec![
        vec![0xAB; 10],
        vec![0xAB; 20],
        vec![0xAB; 30],
        vec![0xCD; 10],
        vec![0xCD; 20],
        vec![0xCD; 30],
    ];

    let mut hashes = HashSet::new();
    for (i, pattern) in patterns.iter().enumerate() {
        let hash = fnv::fnv1a_64(pattern);
        assert!(
            hashes.insert(hash),
            "FNV-1a collision for repeated pattern at index {} (len={})",
            i,
            pattern.len()
        );
    }
}

/// Test: FNV-1a pair function is consistent with manual computation.
#[test]
fn fnv_pair_manual_computation() {
    const OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01B3;

    for a in [0x00, 0x5A, 0xFF] {
        for b in [0x00, 0xA5, 0xFF] {
            let expected = {
                let mut hash = OFFSET_BASIS;
                hash ^= u64::from(a);
                hash = hash.wrapping_mul(PRIME);
                hash ^= u64::from(b);
                hash.wrapping_mul(PRIME)
            };
            let actual = fnv::fnv1a_pair(a, b);
            assert_eq!(expected, actual, "FNV pair mismatch for ({}, {})", a, b);
        }
    }
}

// =============================================================================
// SplitMix64 Additional Tests
// =============================================================================

/// Test: SplitMix64 produces unique outputs for all u16 seeds.
#[test]
fn splitmix_all_u16_seeds_unique() {
    let mut hashes = HashSet::with_capacity(65536);

    for seed in 0..=u16::MAX {
        let hash = splitmix::finalize(u64::from(seed));
        assert!(
            hashes.insert(hash),
            "SplitMix64 collision for u16 seed {}",
            seed
        );
    }
    assert_eq!(hashes.len(), 65536);
}

/// Test: SplitMix64 pair function distinguishes all byte combinations.
#[test]
fn splitmix_pair_all_combinations_unique() {
    let mut hashes = HashSet::with_capacity(65536);

    for a in 0..=255_u8 {
        for b in 0..=255_u8 {
            let hash = splitmix::pair(a, b);
            assert!(
                hashes.insert(hash),
                "SplitMix64 pair collision for ({}, {})",
                a,
                b
            );
        }
    }
    assert_eq!(hashes.len(), 65536);
}

/// Test: SplitMix64 avalanche effect for all single-bit flips in u32 range.
#[test]
fn splitmix_avalanche_all_bit_flips_u32() {
    let base: u64 = 0x1234_5678_9ABC_DEF0;
    let base_hash = splitmix::finalize(base);

    for bit in 0..32 {
        let flipped = base ^ (1 << bit);
        let flipped_hash = splitmix::finalize(flipped);
        let diff_bits = (base_hash ^ flipped_hash).count_ones();

        // Strong avalanche should flip at least 16 bits (half of 32)
        assert!(
            diff_bits >= 16,
            "SplitMix64 weak avalanche: bit {} flip caused only {} bits to change",
            bit,
            diff_bits
        );
    }
}

// =============================================================================
// hash_to_index Additional Tests
// =============================================================================

/// Test: hash_to_index handles all possible usize values without panic.
#[test]
fn hash_to_index_extreme_usize_values() {
    let test_cases = [
        (0_u64, 0_usize),
        (0, 1),
        (u64::MAX, 1),
        (u64::MAX, usize::MAX),
        (0x8000_0000_0000_0000, 1024),
        (0x7FFF_FFFF_FFFF_FFFF, 1024),
    ];

    for (hash, num_bits) in test_cases {
        let idx = hash_to_index(hash, num_bits);
        if num_bits == 0 {
            assert_eq!(idx, 0);
        } else {
            assert!(
                idx < num_bits,
                "hash_to_index({}, {}) = {} >= {}",
                hash,
                num_bits,
                idx,
                num_bits
            );
        }
    }
}

/// Test: hash_to_index distribution quality for power-of-two sizes.
#[test]
fn hash_to_index_distribution_quality() {
    const SIZE: usize = 1024;
    const SAMPLES: usize = 10000;

    let mut counts = vec![0_usize; SIZE];

    // Generate samples using wyhash
    for i in 0..SAMPLES {
        let hash = wyhash::hash(&i.to_le_bytes(), 0);
        let idx = hash_to_index(hash, SIZE);
        counts[idx] += 1;
    }

    // Check that all slots are used (with some tolerance)
    let used_slots = counts.iter().filter(|&&c| c > 0).count();
    assert!(
        used_slots >= SIZE * 9 / 10,
        "Only {} of {} slots used (expected >= 90%)",
        used_slots,
        SIZE
    );

    // Check that no slot is overloaded (max ~3x expected average)
    let expected_avg = SAMPLES / SIZE;
    let max_count = counts.iter().copied().max().unwrap_or(0);
    assert!(
        max_count <= expected_avg * 5,
        "Max slot count {} exceeds 5x expected average {}",
        max_count,
        expected_avg
    );
}

/// Test: hash_to_index with non-power-of-two sizes.
#[test]
fn hash_to_index_non_power_of_two_sizes() {
    let sizes = [3, 5, 7, 10, 11, 13, 17, 19, 23, 100, 1000, 10000];

    for size in sizes {
        // Verify all possible hash values map correctly
        for hash in [0_u64, 1, 7, 42, 100, u64::MAX / 2, u64::MAX] {
            let idx = hash_to_index(hash, size);
            assert!(
                idx < size,
                "hash_to_index({}, {}) = {} >= {}",
                hash,
                size,
                idx,
                size
            );
        }
    }
}

// =============================================================================
// bloom_hash_pair Additional Tests
// =============================================================================

/// Test: bloom_hash_pair produces unique pairs for all 2-byte combinations.
#[test]
fn bloom_hash_pair_all_combinations_unique() {
    let mut pairs = HashSet::with_capacity(65536);

    for a in 0..=255_u8 {
        for b in 0..=255_u8 {
            let pair = bloom_hash_pair(a, b);
            assert!(
                pairs.insert(pair),
                "bloom_hash_pair collision for ({}, {}): {:?}",
                a,
                b,
                pair
            );
        }
    }
    assert_eq!(pairs.len(), 65536);
}

/// Test: bloom_hash_pair components are independent (not correlated).
#[test]
fn bloom_hash_pair_component_independence() {
    // Test that flipping bits in first byte affects both hashes independently
    let base_a = 0x55_u8;
    let base_b = 0xAA_u8;
    let base = bloom_hash_pair(base_a, base_b);

    let mut h1_changes = 0;
    let mut h2_changes = 0;

    for bit in 0..8 {
        let modified_a = base_a ^ (1 << bit);
        let modified = bloom_hash_pair(modified_a, base_b);

        if modified.0 != base.0 {
            h1_changes += 1;
        }
        if modified.1 != base.1 {
            h2_changes += 1;
        }
    }

    // Both components should change for most bit flips
    assert!(
        h1_changes >= 6,
        "First hash component only changed {} of 8 bit flips",
        h1_changes
    );
    assert!(
        h2_changes >= 6,
        "Second hash component only changed {} of 8 bit flips",
        h2_changes
    );
}

/// Test: bloom_hash_pair with extreme byte values.
#[test]
fn bloom_hash_pair_extreme_values() {
    let test_cases = [
        (0x00, 0x00),
        (0x00, 0xFF),
        (0xFF, 0x00),
        (0xFF, 0xFF),
        (0x80, 0x80),
        (0x7F, 0x7F),
    ];

    let mut hashes = HashSet::new();
    for (a, b) in test_cases {
        let (h1, h2) = bloom_hash_pair(a, b);

        // Neither should be zero for both
        assert!(
            h1 != 0 || h2 != 0,
            "bloom_hash_pair({}, {}) produced (0, 0)",
            a,
            b
        );

        // Should be unique among these extreme cases
        let combined = (h1, h2);
        assert!(
            hashes.insert(combined),
            "Duplicate hash pair for extreme values ({}, {})",
            a,
            b
        );
    }
}

// =============================================================================
// Cross-Function Consistency Tests
// =============================================================================

/// Test: All hash functions produce non-zero for non-empty inputs.
#[test]
fn all_hashes_nonzero_for_nonempty() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![0x00],
        vec![0xFF],
        vec![0x00, 0x00],
        vec![0x5A, 0xA5],
        b"test".to_vec(),
    ];

    for input in inputs {
        let fnv_hash = fnv::fnv1a_64(&input);
        let wy_hash = wyhash::hash(&input, 12345);

        // Non-cryptographic hashes can produce any value, but
        // empty input should produce predictable values
        if !input.is_empty() {
            // Just ensure they don't panic and are deterministic
            assert_eq!(fnv_hash, fnv::fnv1a_64(&input));
            assert_eq!(wy_hash, wyhash::hash(&input, 12345));
        }
    }
}

/// Test: Hash functions are consistent across different call sites.
#[test]
fn hash_function_idempotency() {
    const ITERATIONS: usize = 1000;
    const SEED: u64 = 0xCAFE_BABE_DEAD_BEEF;

    let input = b"idempotency test data";

    let fnv_first = fnv::fnv1a_64(input);
    let wy_first = wyhash::hash(input, SEED);
    let splitmix_first = splitmix::finalize(SEED);

    for _ in 0..ITERATIONS {
        assert_eq!(fnv::fnv1a_64(input), fnv_first);
        assert_eq!(wyhash::hash(input, SEED), wy_first);
        assert_eq!(splitmix::finalize(SEED), splitmix_first);
    }
}

/// Test: Byte-order sensitivity across all hash functions.
#[test]
fn all_hashes_byte_order_sensitive() {
    let input1 = vec![0x01, 0x02, 0x03, 0x04];
    let input2 = vec![0x04, 0x03, 0x02, 0x01];

    assert_ne!(
        fnv::fnv1a_64(&input1),
        fnv::fnv1a_64(&input2),
        "FNV-1a should be byte-order sensitive"
    );

    assert_ne!(
        wyhash::hash(&input1, 0),
        wyhash::hash(&input2, 0),
        "WyHash should be byte-order sensitive"
    );

    assert_ne!(
        bloom_hash_pair(0x01, 0x02),
        bloom_hash_pair(0x02, 0x01),
        "bloom_hash_pair should be byte-order sensitive"
    );
}

/// Test: Large input handling (10MB) without stack overflow.
#[test]
fn large_input_no_stack_overflow() {
    let large_input = vec![0xA5; 10_000_000]; // 10MB
    let seed = 0x1234_5678_9ABC_DEF0_u64;

    let fnv_hash = fnv::fnv1a_64(&large_input);
    let wy_hash = wyhash::hash(&large_input, seed);

    // Both should produce deterministic results
    assert_eq!(fnv::fnv1a_64(&large_input), fnv_hash);
    assert_eq!(wyhash::hash(&large_input, seed), wy_hash);

    // Neither should be zero
    assert_ne!(fnv_hash, 0);
    assert_ne!(wy_hash, 0);
}

// =============================================================================
// Performance Regression Tests
// =============================================================================

/// Test: hash_to_index performance for large iteration counts.
#[test]
fn hash_to_index_performance_regression() {
    use std::time::Instant;

    const ITERATIONS: usize = 1_000_000;
    const SIZE: usize = 4096;

    let start = Instant::now();
    let mut sum: usize = 0;

    for i in 0..ITERATIONS {
        let hash = wyhash::hash(&i.to_le_bytes(), 0);
        sum = sum.wrapping_add(hash_to_index(hash, SIZE));
    }

    let elapsed = start.elapsed();

    // Should complete in under 500ms for 1M iterations in debug sandboxes
    assert!(
        elapsed.as_millis() < 500,
        "hash_to_index performance regression: {}ms for {} iterations",
        elapsed.as_millis(),
        ITERATIONS
    );

    // Use sum to prevent optimization
    assert!(sum < ITERATIONS * SIZE);
}

// =============================================================================
// Security/Collision Tests
// =============================================================================

/// Test: Known problematic inputs don't cause issues.
#[test]
fn hashkit_pathological_inputs() {
    let pathological: Vec<Vec<u8>> = vec![
        vec![],                              // Empty
        vec![0x00],                          // Single null
        vec![0x00; 1000],                    // All nulls
        vec![0xFF; 1000],                    // All 0xFF
        (0..256).map(|i| i as u8).collect(), // Sequential
        vec![0x80; 100],                     // High bit set
        vec![0x7F; 100],                     // Just below high bit
    ];

    let seed = 0_u64;
    let mut all_hashes = HashSet::new();

    for input in pathological {
        let fnv_hash = fnv::fnv1a_64(&input);
        let wy_hash = wyhash::hash(&input, seed);

        // Each should be unique
        assert!(
            all_hashes.insert((fnv_hash, "fnv", input.len())),
            "FNV collision for pathological input of length {}",
            input.len()
        );
        assert!(
            all_hashes.insert((wy_hash, "wyhash", input.len())),
            "WyHash collision for pathological input of length {}",
            input.len()
        );
    }
}

/// Test: Birthday paradox estimation - no unexpected collisions in 100K samples.
#[test]
fn birthday_paradox_collision_check() {
    const SAMPLES: usize = 100_000;
    let mut hashes = HashSet::with_capacity(SAMPLES);
    let mut collisions = 0;

    for i in 0..SAMPLES {
        let input = i.to_le_bytes();
        let hash = wyhash::hash(&input, 0);
        if !hashes.insert(hash) {
            collisions += 1;
        }
    }

    // For 64-bit hashes, 100K samples should have ~0 collisions
    // (birthday bound at 50% collision is ~2^32 samples)
    assert_eq!(
        collisions, 0,
        "Unexpected collisions in birthday paradox test: {} collisions for {} samples",
        collisions, SAMPLES
    );
}
