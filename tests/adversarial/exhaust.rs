use hashkit::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};

#[test]
fn exhaustive_two_byte_bloom_hash_pairs() {
    let mut unique_h1 = std::collections::HashSet::new();
    let mut unique_h2 = std::collections::HashSet::new();

    // Loop through all 65,536 combinations of two bytes
    for a in 0..=255 {
        for b in 0..=255 {
            let (h1, h2) = bloom_hash_pair(a, b);
            
            // Should be deterministic
            assert_eq!(bloom_hash_pair(a, b), (h1, h2));
            
            unique_h1.insert(h1);
            unique_h2.insert(h2);
        }
    }
    
    // There are 65536 combinations. 
    // We expect a significant number of unique hashes, proving collision resistance for small inputs.
    assert!(unique_h1.len() > 65000, "Too many collisions in h1. Found: {}", unique_h1.len());
    assert!(unique_h2.len() > 65000, "Too many collisions in h2. Found: {}", unique_h2.len());
}

#[test]
fn exhaustive_wyhash_alignments() {
    // Generate an unaligned buffer
    let mut data = Vec::with_capacity(1024);
    for i in 0..1024 {
        data.push((i % 256) as u8);
    }
    
    // Test wyhash handles all 1-byte, 2-byte, 3-byte, ..., offsets correctly without panicking
    for offset in 0..16 {
        for len in 0..64 {
            let slice = &data[offset..offset+len];
            let hash = wyhash::hash(slice, offset as u64);
            
            // Determinism check
            assert_eq!(hash, wyhash::hash(slice, offset as u64));
            
            // Changing seed should change hash (for non-empty inputs)
            if len > 0 {
                assert_ne!(hash, wyhash::hash(slice, (offset + 1) as u64));
            }
        }
    }
}

#[test]
fn pathological_inputs() {
    // Empty
    assert_eq!(wyhash::hash(&[], 0), wyhash::hash(&[], 0));
    assert_eq!(fnv::fnv1a_64(&[]), fnv::fnv1a_64(&[]));
    
    // All nulls
    let zeros = vec![0; 100_000];
    let h_zeros = wyhash::hash(&zeros, 0);
    assert_ne!(h_zeros, 0);
    
    // All ones
    let ones = vec![255; 100_000];
    let h_ones = wyhash::hash(&ones, 0);
    assert_ne!(h_ones, 0);
    
    assert_ne!(h_zeros, h_ones);
}

#[test]
fn extreme_hash_to_index_values() {
    // Max values
    assert_eq!(hash_to_index(u64::MAX, usize::MAX), (u64::MAX % (usize::MAX as u64)) as usize);
    assert_eq!(hash_to_index(u64::MAX, 1), 0);
    assert_eq!(hash_to_index(0, usize::MAX), 0);
    
    // Powers of two minus 1
    assert_eq!(hash_to_index(u64::MAX, 1024), 1023);
    assert_eq!(hash_to_index(u64::MAX, 65536), 65535);
}

#[test]
fn max_wyhash_seeds() {
    let data = b"test input for wyhash seed extremes";
    let max_seed = wyhash::hash(data, u64::MAX);
    let min_seed = wyhash::hash(data, u64::MIN);
    let mid_seed = wyhash::hash(data, u64::MAX / 2);
    
    assert_ne!(max_seed, min_seed);
    assert_ne!(max_seed, mid_seed);
    assert_ne!(min_seed, mid_seed);
}

#[test]
fn adversarial_hash_to_index_with_massive_widths() {
    let hash = 0xDEADBEEF_CAFE_BABE_u64;
    let mut collision_map = std::collections::HashMap::new();

    for i in 1..=50_000 {
        let idx = hash_to_index(hash, i);
        assert!(idx < i); // Always in bounds
        
        *collision_map.entry(idx).or_insert(0) += 1;
    }

    // It should distribute and not hit the exact same index 50k times.
    assert!(collision_map.len() > 100);
}
