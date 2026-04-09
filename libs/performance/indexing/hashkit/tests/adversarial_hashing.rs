#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use hashkit::{blake3_hash, wyhash};
use std::collections::HashSet;

// 1-10: BLAKE3 determinism
#[test]
fn test_blake3_determinism_empty() {
    let hash1 = blake3_hash::hash(b"");
    let hash2 = blake3_hash::hash(b"");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_determinism_small() {
    let input = b"adversarial testing payload";
    let hash1 = blake3_hash::hash(input);
    let hash2 = blake3_hash::hash(input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_determinism_large() {
    let input = vec![0x42; 1024 * 1024]; // 1MB
    let hash1 = blake3_hash::hash(&input);
    let hash2 = blake3_hash::hash(&input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_determinism_streaming_empty() {
    let hasher1 = blake3_hash::ContentHash::new();
    let hasher2 = blake3_hash::ContentHash::new();
    assert_eq!(hasher1.finalize(), hasher2.finalize());
}

#[test]
fn test_blake3_determinism_streaming_small() {
    let mut hasher1 = blake3_hash::ContentHash::new();
    hasher1.update(b"adversarial");
    hasher1.update(b" testing payload");
    
    let mut hasher2 = blake3_hash::ContentHash::new();
    hasher2.update(b"adversarial");
    hasher2.update(b" testing payload");
    
    assert_eq!(hasher1.finalize(), hasher2.finalize());
}

#[test]
fn test_blake3_determinism_hex() {
    let _hash1 = blake3_hash::hash(b"hex test");
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"hex test");
    let hex1 = hasher.finalize_hex();
    
    let mut hasher2 = blake3_hash::ContentHash::new();
    hasher2.update(b"hex test");
    assert_eq!(hex1, hasher2.finalize_hex());
}

#[test]
fn test_blake3_determinism_mixed_sizes() {
    let sizes = [1, 10, 100, 1000, 10000];
    for &size in &sizes {
        let input = vec![0xAB; size];
        let h1 = blake3_hash::hash(&input);
        let h2 = blake3_hash::hash(&input);
        assert_eq!(h1, h2);
    }
}

#[test]
fn test_blake3_determinism_unicode() {
    let input = "🚨 Adversarial 🦀".as_bytes();
    let h1 = blake3_hash::hash(input);
    let h2 = blake3_hash::hash(input);
    assert_eq!(h1, h2);
}

#[test]
fn test_blake3_determinism_clone() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"part 1");
    
    let mut hasher_cloned = hasher.clone();
    hasher.update(b" part 2");
    hasher_cloned.update(b" part 2");
    
    assert_eq!(hasher.finalize(), hasher_cloned.finalize());
}

#[test]
fn test_blake3_determinism_default() {
    let hasher1: blake3_hash::ContentHash = Default::default();
    let hasher2: blake3_hash::ContentHash = Default::default();
    assert_eq!(hasher1.finalize(), hasher2.finalize());
}

// 11-15: wyhash determinism and distribution quality
#[test]
fn test_wyhash_determinism_same_seed() {
    let input = b"determinism test";
    let seed = 0x1234567890ABCDEF;
    let h1 = wyhash::hash(input, seed);
    let h2 = wyhash::hash(input, seed);
    assert_eq!(h1, h2);
}

#[test]
fn test_wyhash_different_seeds() {
    let input = b"seed test";
    let h1 = wyhash::hash(input, 1);
    let h2 = wyhash::hash(input, 2);
    assert_ne!(h1, h2);
}

#[test]
fn test_wyhash_different_inputs() {
    let seed = 42;
    let h1 = wyhash::hash(b"input 1", seed);
    let h2 = wyhash::hash(b"input 2", seed);
    assert_ne!(h1, h2);
}

#[test]
fn test_wyhash_distribution_quality() {
    let mut hashes = HashSet::new();
    for i in 0..1000 {
        let input = format!("dist_test_{}", i);
        let h = wyhash::hash(input.as_bytes(), 0);
        assert!(hashes.insert(h), "Collision found at index {}", i);
    }
}

#[test]
fn test_wyhash_avalanche() {
    let input1 = b"avalanche1";
    let input2 = b"avalanche2"; // Only 1 bit difference conceptually in end byte
    let h1 = wyhash::hash(input1, 0);
    let h2 = wyhash::hash(input2, 0);
    
    let diff = h1 ^ h2;
    let set_bits = diff.count_ones();
    // A good hash should change roughly half the bits
    assert!(set_bits > 16 && set_bits < 48, "Poor avalanche effect: {}", set_bits);
}

// 16-20: Empty input, single byte, maximum length input hashing
#[test]
fn test_hash_empty_input() {
    let b_empty = blake3_hash::hash(b"");
    let w_empty = wyhash::hash(b"", 0);
    // Ensure they don't panic and produce consistent results
    assert_eq!(b_empty, blake3_hash::hash(b""));
    assert_eq!(w_empty, wyhash::hash(b"", 0));
}

#[test]
fn test_hash_single_byte_0() {
    let input = b"\x00";
    assert_eq!(blake3_hash::hash(input), blake3_hash::hash(input));
    assert_eq!(wyhash::hash(input, 0), wyhash::hash(input, 0));
}

#[test]
fn test_hash_single_byte_255() {
    let input = b"\xFF";
    assert_eq!(blake3_hash::hash(input), blake3_hash::hash(input));
    assert_eq!(wyhash::hash(input, 0), wyhash::hash(input, 0));
}

#[test]
fn test_hash_large_input() {
    // 100MB input
    let input = vec![0xAA; 100 * 1024 * 1024];
    let b_hash = blake3_hash::hash(&input);
    let w_hash = wyhash::hash(&input, 42);
    
    assert_eq!(b_hash, blake3_hash::hash(&input));
    assert_eq!(w_hash, wyhash::hash(&input, 42));
}

#[test]
fn test_hash_streaming_large_input() {
    let mut hasher = blake3_hash::ContentHash::new();
    let chunk = vec![0xBB; 1024 * 1024]; // 1MB
    for _ in 0..100 { // 100MB total
        hasher.update(&chunk);
    }
    
    let full_input = vec![0xBB; 100 * 1024 * 1024];
    assert_eq!(hasher.finalize(), blake3_hash::hash(&full_input));
}

// 21-25: Binary content with null bytes, 0xFF bytes
#[test]
fn test_hash_all_nulls() {
    let input = vec![0x00; 8192];
    assert_eq!(blake3_hash::hash(&input), blake3_hash::hash(&input));
    assert_eq!(wyhash::hash(&input, 123), wyhash::hash(&input, 123));
}

#[test]
fn test_hash_all_ff() {
    let input = vec![0xFF; 8192];
    assert_eq!(blake3_hash::hash(&input), blake3_hash::hash(&input));
    assert_eq!(wyhash::hash(&input, 456), wyhash::hash(&input, 456));
}

#[test]
fn test_hash_alternating_bits() {
    let input: Vec<u8> = (0..8192).map(|i| if i % 2 == 0 { 0x55 } else { 0xAA }).collect();
    assert_eq!(blake3_hash::hash(&input), blake3_hash::hash(&input));
    assert_eq!(wyhash::hash(&input, 789), wyhash::hash(&input, 789));
}

#[test]
fn test_hash_nulls_vs_ff() {
    let nulls = vec![0x00; 1024];
    let ffs = vec![0xFF; 1024];
    
    assert_ne!(blake3_hash::hash(&nulls), blake3_hash::hash(&ffs));
    assert_ne!(wyhash::hash(&nulls, 0), wyhash::hash(&ffs, 0));
}

#[test]
fn test_hash_null_padding_matters() {
    let input1 = vec![0x42; 10];
    let mut input2 = vec![0x42; 10];
    input2.push(0x00);
    
    assert_ne!(blake3_hash::hash(&input1), blake3_hash::hash(&input2));
    assert_ne!(wyhash::hash(&input1, 0), wyhash::hash(&input2, 0));
}

// 26-30: Incremental vs one-shot hashing produces same result
#[test]
fn test_incremental_vs_oneshot_small() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"hello");
    hasher.update(b" ");
    hasher.update(b"world");
    
    let oneshot = blake3_hash::hash(b"hello world");
    assert_eq!(hasher.finalize(), oneshot);
}

#[test]
fn test_incremental_vs_oneshot_medium() {
    let full = (0..10000).map(|x| (x % 256) as u8).collect::<Vec<u8>>();
    
    let mut hasher = blake3_hash::ContentHash::new();
    for chunk in full.chunks(100) {
        hasher.update(chunk);
    }
    
    let oneshot = blake3_hash::hash(&full);
    assert_eq!(hasher.finalize(), oneshot);
}

#[test]
fn test_incremental_vs_oneshot_single_bytes() {
    let full = b"single byte at a time";
    
    let mut hasher = blake3_hash::ContentHash::new();
    for &b in full.iter() {
        hasher.update(&[b]);
    }
    
    let oneshot = blake3_hash::hash(full);
    assert_eq!(hasher.finalize(), oneshot);
}

#[test]
fn test_incremental_vs_oneshot_uneven_chunks() {
    let full = b"this is a test of uneven chunks being fed to the hasher";
    
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(&full[0..4]);
    hasher.update(&full[4..20]);
    hasher.update(&full[20..21]);
    hasher.update(&full[21..]);
    
    let oneshot = blake3_hash::hash(full);
    assert_eq!(hasher.finalize(), oneshot);
}

#[test]
fn test_incremental_vs_oneshot_empty_updates() {
    let mut hasher = blake3_hash::ContentHash::new();
    hasher.update(b"hello");
    hasher.update(b"");
    hasher.update(b"world");
    hasher.update(b"");
    
    let oneshot = blake3_hash::hash(b"helloworld");
    assert_eq!(hasher.finalize(), oneshot);
}

// 31-33: Cross-platform hash stability (hash bytes should match known test vectors)
#[test]
fn test_stability_blake3_hello_world() {
    let hash = blake3_hash::hash(b"hello world");
    // BLAKE3 of "hello world"
    let expected = [215, 73, 129, 239, 167, 10, 12, 136, 11, 141, 140, 25, 133, 208, 117, 219, 203, 246, 121, 185, 154, 95, 153, 20, 229, 170, 249, 107, 131, 26, 158, 36];
    assert_eq!(hash, expected);
}

#[test]
fn test_stability_blake3_empty() {
    let hash = blake3_hash::hash(b"");
    // BLAKE3 of ""
    let expected = [175, 19, 73, 185, 245, 249, 161, 166, 160, 64, 77, 234, 54, 220, 201, 73, 155, 203, 37, 201, 173, 193, 18, 183, 204, 154, 147, 202, 228, 31, 50, 98];
    assert_eq!(hash, expected);
}

#[test]
fn test_stability_wyhash_hello_world() {
    let hash = wyhash::hash(b"hello world", 0);
    // Wyhash of "hello world" with seed 0
    let expected = 2433885997896784675;
    assert_eq!(hash, expected);
}
