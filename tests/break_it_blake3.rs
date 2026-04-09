use hashkit::{blake3_hash, fnv};
use std::collections::HashSet;

#[test]
fn test_01_fnv_empty_input() {
    let hash = fnv::fnv1a_64(&[]);
    assert_eq!(
        hash,
        fnv::OFFSET_BASIS,
        "Fix: FNV empty slice should equal OFFSET_BASIS"
    );
}

#[test]
fn test_02_fnv_distribution_quality_1() {
    let mut set = HashSet::new();
    for i in 0..10_000u32 {
        set.insert(fnv::fnv1a_64(&i.to_le_bytes()));
    }
    assert_eq!(
        set.len(),
        10_000,
        "Fix: FNV-1a distribution poor, detected collisions in first 10k ints"
    );
}

#[test]
fn test_03_fnv_distribution_quality_2_single_bytes() {
    let mut set = HashSet::new();
    for i in 0..=255u8 {
        set.insert(fnv::fnv1a_64(&[i]));
    }
    assert_eq!(set.len(), 256, "Fix: FNV-1a single byte collision detected");
}

#[test]
fn test_04_fnv_distribution_quality_3_pairs() {
    let mut set = HashSet::new();
    for i in 0..=255u8 {
        for j in 0..=255u8 {
            set.insert(fnv::fnv1a_pair(i, j));
        }
    }
    assert_eq!(set.len(), 65_536, "Fix: FNV-1a pairs collision detected");
}

#[test]
fn test_05_fnv_avalanche_like_quality() {
    // FNV isn't cryptographic but we should verify small changes affect the output
    let base = fnv::fnv1a_64(b"test data");
    let diff = fnv::fnv1a_64(b"test datb");
    assert_ne!(base, diff, "Fix: FNV failed to differentiate tiny change");
}

#[test]
fn test_06_blake3_empty_input_hash() {
    let hash = blake3_hash::hash(&[]);
    // Reference empty BLAKE3 hash:
    let expected: [u8; 32] = blake3::hash(&[]).into();
    assert_eq!(hash, expected, "Fix: BLAKE3 empty input hash mismatch");
}

#[test]
fn test_07_blake3_streaming_empty_input() {
    let hasher = blake3_hash::ContentHash::new();
    let hash = hasher.finalize();
    let expected: [u8; 32] = blake3::hash(&[]).into();
    assert_eq!(hash, expected, "Fix: BLAKE3 streaming empty hash mismatch");
}

#[test]
fn test_08_blake3_test_vector_1() {
    let input = b"abc";
    let hash = blake3_hash::hash(input);
    let expected: [u8; 32] = blake3::hash(input).into();
    assert_eq!(hash, expected, "Fix: BLAKE3 test vector 'abc' failed");
}

#[test]
fn test_09_blake3_test_vector_2() {
    let input = b"The quick brown fox jumps over the lazy dog";
    let hash = blake3_hash::hash(input);
    let expected: [u8; 32] = blake3::hash(input).into();
    assert_eq!(hash, expected, "Fix: BLAKE3 test vector fox failed");
}

#[test]
fn test_10_blake3_content_hash_stability() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"chunk1");
    hasher.update(b"chunk2");
    hasher.update(b"chunk3");
    let hash = hasher.finalize();
    let expected = blake3_hash::hash(b"chunk1chunk2chunk3");
    assert_eq!(
        hash, expected,
        "Fix: Streaming hash must match one-shot hash"
    );
}

#[test]
fn test_11_blake3_finalize_hex() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"hello");
    let hex = hasher.finalize_hex();
    let expected_hex = blake3::hash(b"hello").to_hex().to_string();
    assert_eq!(hex, expected_hex, "Fix: Finalize hex output mismatch");
}

#[test]
fn test_12_blake3_hash_length() {
    let hash = blake3_hash::hash(b"test");
    assert_eq!(hash.len(), 32, "Fix: BLAKE3 hash must be exactly 32 bytes");
}

#[test]
fn test_13_blake3_content_hash_idempotent_finalize() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"immutable");
    let hash1 = hasher.finalize();
    let hash2 = hasher.finalize();
    assert_eq!(hash1, hash2, "Fix: finalize() must be idempotent");
}

#[test]
fn test_14_blake3_stability_cross_platform_assumption() {
    let expected_hex = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    let hash = blake3_hash::hash(b"hello world");
    let hex = blake3::Hash::from(hash).to_hex().to_string();
    assert_eq!(
        hex, expected_hex,
        "Fix: BLAKE3 output shifted across versions/platforms"
    );
}

#[test]
fn test_15_blake3_streaming_small_chunks() {
    let mut hasher = blake3_hash::ContentHash::new();
    for byte in b"hello world" {
        hasher.update(&[*byte]);
    }
    let hash = hasher.finalize();
    let expected = blake3_hash::hash(b"hello world");
    assert_eq!(hash, expected, "Fix: Byte-by-byte streaming hash mismatch");
}

#[test]
fn test_16_blake3_zero_bytes() {
    let input = [0u8; 1024];
    let hash = blake3_hash::hash(&input);
    let expected: [u8; 32] = blake3::hash(&input).into();
    assert_eq!(hash, expected, "Fix: Null byte hashing mismatch");
}

#[test]
fn test_17_blake3_clone_state() {
    let mut hasher1 = blake3_hash::ContentHash::new();
    hasher1.update(b"prefix");
    let mut hasher2 = hasher1.clone();
    hasher1.update(b"suffix1");
    hasher2.update(b"suffix2");

    assert_eq!(
        hasher1.finalize(),
        blake3_hash::hash(b"prefixsuffix1"),
        "Fix: Clone state corrupted 1"
    );
    assert_eq!(
        hasher2.finalize(),
        blake3_hash::hash(b"prefixsuffix2"),
        "Fix: Clone state corrupted 2"
    );
}

#[test]
fn test_18_blake3_long_null_sequence() {
    let mut hasher = blake3_hash::ContentHash::new();
    for _ in 0..10_000 {
        hasher.update(&[0u8; 100]);
    }
    let expected = blake3_hash::hash(&[0u8; 1_000_000]);
    assert_eq!(
        hasher.finalize(),
        expected,
        "Fix: Repeated null stream hash mismatch"
    );
}

#[test]
fn test_19_blake3_1gb_streaming_input() {
    let mut hasher = blake3_hash::ContentHash::new();
    let chunk = vec![0xAB; 1024 * 1024]; // 1MB chunk
    for _ in 0..1024 {
        // 1024 * 1MB = 1GB
        hasher.update(&chunk);
    }
    let hash = hasher.finalize();
    // Deterministic check: verify it returns *something* and is stable.
    let hex = blake3::Hash::from(hash).to_hex().to_string();
    assert_ne!(hex, "", "Fix: 1GB streaming input failed to produce a hash");

    // Do it again to ensure stability
    let mut hasher2 = blake3_hash::ContentHash::new();
    for _ in 0..1024 {
        hasher2.update(&chunk);
    }
    let hash2 = hasher2.finalize();
    assert_eq!(
        hash, hash2,
        "Fix: 1GB streaming input hashing is not stable/deterministic"
    );
}

#[test]
fn test_20_blake3_streaming_vs_one_shot_10mb() {
    let mut hasher = blake3_hash::ContentHash::new();
    let chunk = vec![0x42; 1024 * 1024]; // 1MB
    let mut full_data = Vec::with_capacity(10 * 1024 * 1024);
    for _ in 0..10 {
        hasher.update(&chunk);
        full_data.extend_from_slice(&chunk);
    }
    let stream_hash = hasher.finalize();
    let oneshot_hash = blake3_hash::hash(&full_data);
    assert_eq!(
        stream_hash, oneshot_hash,
        "Fix: Streamed 10MB mismatched one-shot 10MB"
    );
}

#[test]
fn test_21_blake3_huge_single_update() {
    let mut hasher = blake3_hash::ContentHash::new();
    // 50 MB
    let data = vec![0x11; 50 * 1024 * 1024];
    hasher.update(&data);
    let stream_hash = hasher.finalize();
    let oneshot_hash = blake3_hash::hash(&data);
    assert_eq!(
        stream_hash, oneshot_hash,
        "Fix: Huge single update mismatch"
    );
}

#[test]
fn test_22_blake3_alternating_chunks() {
    let mut hasher = blake3_hash::ContentHash::new();
    let chunk_a = vec![0xAA; 1024 * 1024];
    let chunk_b = vec![0xBB; 1024 * 1024];
    for i in 0..50 {
        if i % 2 == 0 {
            hasher.update(&chunk_a);
        } else {
            hasher.update(&chunk_b);
        }
    }
    let hash1 = hasher.finalize();

    let mut hasher2 = blake3_hash::ContentHash::new();
    for i in 0..50 {
        if i % 2 == 0 {
            hasher2.update(&chunk_a);
        } else {
            hasher2.update(&chunk_b);
        }
    }
    assert_eq!(
        hash1,
        hasher2.finalize(),
        "Fix: Alternating chunks must be deterministic"
    );
}

#[test]
fn test_23_blake3_odd_sized_chunks_streaming() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"odd");
    hasher.update(&vec![0xCC; 1_000_000]);
    hasher.update(b"sized");
    hasher.update(&[0xDD; 7]);

    let mut full_data = Vec::new();
    full_data.extend_from_slice(b"odd");
    full_data.extend_from_slice(&vec![0xCC; 1_000_000]);
    full_data.extend_from_slice(b"sized");
    full_data.extend_from_slice(&[0xDD; 7]);

    assert_eq!(
        hasher.finalize(),
        blake3_hash::hash(&full_data),
        "Fix: Odd sized streaming mismatch"
    );
}

#[test]
fn test_24_blake3_state_size_and_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<blake3_hash::ContentHash>();
    // Make sure struct is relatively small (just inner blake3 state)
    assert!(
        std::mem::size_of::<blake3_hash::ContentHash>() <= 4096,
        "Fix: ContentHash is too bloated"
    );
}

#[test]
fn test_25_blake3_concurrent_hashing_same_data() {
    use std::sync::Arc;
    let data = Arc::new(vec![0xFF; 10 * 1024 * 1024]); // 10MB
    let mut threads = vec![];

    for _ in 0..8 {
        let d = Arc::clone(&data);
        threads.push(std::thread::spawn(move || {
            let mut hasher = blake3_hash::ContentHash::new();
            hasher.update(&d);
            hasher.finalize()
        }));
    }

    let expected = blake3_hash::hash(&data);
    for t in threads {
        let hash = t.join().expect("Fix: Concurrent thread panicked");
        assert_eq!(
            hash, expected,
            "Fix: Concurrent hashing produced incorrect result"
        );
    }
}

#[test]
fn test_26_blake3_concurrent_hashing_different_data() {
    let mut threads = vec![];
    for i in 0..8u8 {
        threads.push(std::thread::spawn(move || {
            let data = vec![i; 1024 * 1024]; // 1MB
            let mut hasher = blake3_hash::ContentHash::new();
            hasher.update(&data);
            (i, hasher.finalize())
        }));
    }

    for t in threads {
        let (i, hash) = t.join().expect("Fix: Thread panicked in concurrent different data test");
        let expected = blake3_hash::hash(&vec![i; 1024 * 1024]);
        assert_eq!(
            hash, expected,
            "Fix: Isolated concurrent hashing mismatch for thread {}",
            i
        );
    }
}

#[test]
fn test_27_blake3_concurrent_oneshot() {
    use std::sync::Arc;
    let data = Arc::new(vec![0x77; 5 * 1024 * 1024]);
    let mut threads = vec![];

    for _ in 0..16 {
        let d = Arc::clone(&data);
        threads.push(std::thread::spawn(move || blake3_hash::hash(&d)));
    }

    let expected = blake3_hash::hash(&data);
    for t in threads {
        let hash = t.join().expect("Fix: Thread panicked in concurrent one-shot test");
        assert_eq!(hash, expected, "Fix: Concurrent one-shot hashing mismatch");
    }
}

#[test]
fn test_28_blake3_concurrent_many_small_hashes() {
    let mut threads = vec![];
    for _ in 0..4 {
        threads.push(std::thread::spawn(move || {
            let mut hashes = Vec::new();
            for i in 0..10_000u32 {
                hashes.push(blake3_hash::hash(&i.to_le_bytes()));
            }
            hashes
        }));
    }

    for t in threads {
        let hashes = t.join().expect("Fix: Thread panicked in concurrent many small hashes test");
        assert_eq!(hashes.len(), 10_000);
        assert_eq!(hashes[0], blake3_hash::hash(&0u32.to_le_bytes()));
    }
}

#[test]
fn test_29_blake3_update_empty_slice() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"hello");
    hasher.update(&[]);
    hasher.update(b"world");
    let expected = blake3_hash::hash(b"helloworld");
    assert_eq!(
        hasher.finalize(),
        expected,
        "Fix: Updating with empty slice should be a no-op"
    );
}

#[test]
fn test_30_blake3_finalize_does_not_consume() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"test");
    let h1 = hasher.finalize();
    hasher.update(b"more");
    let h2 = hasher.finalize();
    assert_ne!(h1, h2, "Fix: Finalize should not prevent further updates");
    let expected = blake3_hash::hash(b"testmore");
    assert_eq!(
        h2, expected,
        "Fix: Subsequent updates after finalize failed"
    );
}

#[test]
fn test_31_blake3_finalize_hex_stability() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"abc");
    let hex1 = hasher.finalize_hex();
    let hex2 = hasher.finalize_hex();
    assert_eq!(hex1, hex2, "Fix: finalize_hex() must be idempotent");
}

#[test]
fn test_32_blake3_large_streaming_vs_cloned_state() {
    let mut hasher1 = blake3_hash::ContentHash::new();
    let chunk = vec![0x99; 100_000];
    for _ in 0..10 {
        hasher1.update(&chunk);
    }
    let mut hasher2 = hasher1.clone();
    hasher1.update(&chunk);
    hasher2.update(&chunk);

    assert_eq!(
        hasher1.finalize(),
        hasher2.finalize(),
        "Fix: Cloned large state mismatch"
    );
}

#[test]
fn test_33_blake3_concurrent_stress_streaming() {
    use std::sync::Arc;
    let chunk = Arc::new(vec![0xAA; 1_000_000]);
    let mut threads = vec![];

    for _ in 0..8 {
        let c = Arc::clone(&chunk);
        threads.push(std::thread::spawn(move || {
            let mut hasher = blake3_hash::ContentHash::new();
            for _ in 0..100 {
                hasher.update(&c);
            }
            hasher.finalize()
        }));
    }

    for t in threads {
        let hash = t.join().expect("Fix: Thread panicked in concurrent stress streaming test");
        // Just checking it completes without panicking and produces 32 bytes
        assert_eq!(hash.len(), 32, "Fix: Invalid hash length from stress test");
    }
}

#[test]
fn test_34_blake3_streaming_cross_platform_stability() {
    // Known hex output for BLAKE3 hash of "cross-platform stability test"
    // computed from the reference blake3 crate. Any platform-specific
    // endianness bug in the wrapper would shift this value.
    let expected_hex = "516241f5166254e92a1666491cd6fbd9db5d955cb20e4ebd3138c21cf2100022";

    let data = b"cross-platform stability test";

    // One-shot
    let one_shot_hex = blake3::Hash::from(blake3_hash::hash(data)).to_hex().to_string();
    assert_eq!(
        one_shot_hex, expected_hex,
        "Fix: BLAKE3 one-shot hash changed across platforms/versions"
    );

    // Streaming via ContentHash with arbitrary chunk boundaries
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(&data[..7]);
    hasher.update(&data[7..14]);
    hasher.update(&data[14..]);
    let stream_hex = hasher.finalize_hex();
    assert_eq!(
        stream_hex, expected_hex,
        "Fix: BLAKE3 streaming hash differs from one-shot or shifted across platforms"
    );
}
