use hashkit::{bloom_hash_pair, hash_to_index, wyhash};
use std::collections::HashSet;

#[test]
fn bloom_filter_simulation() {
    let num_bits = 100_000;
    let mut bloom = vec![false; num_bits];
    let mut inserted = HashSet::new();

    // Insert 10k items
    for i in 0..10_000_u32 {
        let bytes = i.to_le_bytes();
        let hash1 = wyhash::hash(&bytes, 0);
        let hash2 = wyhash::hash(&bytes, 1);

        let idx1 = hash_to_index(hash1, num_bits);
        let idx2 = hash_to_index(hash2, num_bits);

        bloom[idx1] = true;
        bloom[idx2] = true;
        inserted.insert(i);
    }

    // Verify all inserted items are found
    for &i in &inserted {
        let bytes = i.to_le_bytes();
        let hash1 = wyhash::hash(&bytes, 0);
        let hash2 = wyhash::hash(&bytes, 1);

        let idx1 = hash_to_index(hash1, num_bits);
        let idx2 = hash_to_index(hash2, num_bits);

        assert!(bloom[idx1]);
        assert!(bloom[idx2]);
    }

    // Check false positive rate with 10k non-inserted items
    let mut false_positives = 0;
    for i in 10_000..20_000_u32 {
        let bytes = i.to_le_bytes();
        let hash1 = wyhash::hash(&bytes, 0);
        let hash2 = wyhash::hash(&bytes, 1);

        let idx1 = hash_to_index(hash1, num_bits);
        let idx2 = hash_to_index(hash2, num_bits);

        if bloom[idx1] && bloom[idx2] {
            false_positives += 1;
        }
    }

    // Expected FPR for 10k items in 100k bits with 2 hashes is roughly 3.6%
    // We assert it's less than 5% (500/10000)
    assert!(
        false_positives < 500,
        "False positive rate too high: {}",
        false_positives
    );
}

#[test]
fn bloom_hash_pair_simulation() {
    let num_bits = 4096;
    let mut bloom = vec![false; num_bits];

    // Insert all pairs of ASCII letters
    for a in b'a'..=b'z' {
        for b in b'a'..=b'z' {
            let (h1, h2) = bloom_hash_pair(a, b);

            // Generate 3 probe indices
            let idx1 = hash_to_index(h1, num_bits);
            let idx2 = hash_to_index(h2, num_bits);
            let idx3 = hash_to_index(h1.wrapping_add(h2), num_bits);

            bloom[idx1] = true;
            bloom[idx2] = true;
            bloom[idx3] = true;
        }
    }

    // Verify all inserted items are found
    for a in b'a'..=b'z' {
        for b in b'a'..=b'z' {
            let (h1, h2) = bloom_hash_pair(a, b);

            let idx1 = hash_to_index(h1, num_bits);
            let idx2 = hash_to_index(h2, num_bits);
            let idx3 = hash_to_index(h1.wrapping_add(h2), num_bits);

            assert!(bloom[idx1]);
            assert!(bloom[idx2]);
            assert!(bloom[idx3]);
        }
    }
}
