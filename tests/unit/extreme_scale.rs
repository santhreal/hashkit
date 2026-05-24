//! Extreme scale tests for hashkit hash functions.

use hashkit::{fnv, splitmix, wyhash};

#[test]
fn fnv_empty_input() {
    let h = fnv::fnv1a_64(b"");
    assert_eq!(h, fnv::OFFSET_BASIS); // empty input = offset basis
}

#[test]
fn fnv_single_byte_all_values() {
    let mut seen = std::collections::HashSet::new();
    for b in 0u8..=255 {
        let h = fnv::fnv1a_64(&[b]);
        seen.insert(h);
    }
    // All 256 single-byte inputs should produce different hashes
    assert_eq!(seen.len(), 256);
}

#[test]
fn wyhash_deterministic() {
    let a = wyhash::hash(b"hello world", 42);
    let b = wyhash::hash(b"hello world", 42);
    assert_eq!(a, b);
}

#[test]
fn wyhash_different_seeds() {
    let a = wyhash::hash(b"data", 1);
    let b = wyhash::hash(b"data", 2);
    assert_ne!(a, b);
}

#[test]
fn wyhash_1mb_input() {
    let data = vec![0xAB_u8; 1_000_000];
    let h = wyhash::hash(&data, 0);
    assert_ne!(h, 0); // non-trivial hash
}

#[test]
fn splitmix_all_u8_values() {
    let mut seen = std::collections::HashSet::new();
    for b in 0u8..=255 {
        let h = splitmix::finalize(u64::from(b));
        seen.insert(h);
    }
    assert_eq!(seen.len(), 256); // all unique
}

#[test]
fn bloom_hash_pair_consistency() {
    let (h1a, h2a) = hashkit::bloom_hash_pair(b'x', b'y');
    let (h1b, h2b) = hashkit::bloom_hash_pair(b'x', b'y');
    assert_eq!(h1a, h1b);
    assert_eq!(h2a, h2b);
}

#[test]
fn hash_to_index_all_power_of_two_sizes() {
    for bits in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 65536] {
        let idx = hashkit::hash_to_index(u64::MAX, bits);
        assert!(idx < bits, "index {idx} >= {bits}");
    }
}
