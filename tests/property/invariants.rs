use hashkit::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};
use proptest::prelude::*;

// Increase the number of cases to explore deep property combinations
proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn hash_to_index_never_panics_and_stays_in_bounds(
        hash in any::<u64>(),
        num_bits in any::<usize>()
    ) {
        let index = hash_to_index(hash, num_bits);
        if num_bits == 0 {
            assert_eq!(index, 0);
        } else {
            assert!(index < num_bits);
        }
    }

    #[test]
    fn fnv1a_64_is_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let hash1 = fnv::fnv1a_64(&data);
        let hash2 = fnv::fnv1a_64(&data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn fnv1a_pair_matches_slice(
        a in any::<u8>(),
        b in any::<u8>()
    ) {
        let pair = fnv::fnv1a_pair(a, b);
        let slice_hash = fnv::fnv1a_64(&[a, b]);
        assert_eq!(pair, slice_hash);
    }

    #[test]
    fn splitmix_finalize_is_deterministic(
        seed in any::<u64>()
    ) {
        let hash1 = splitmix::finalize(seed);
        let hash2 = splitmix::finalize(seed);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn splitmix_pair_is_deterministic(
        a in any::<u8>(),
        b in any::<u8>()
    ) {
        let hash1 = splitmix::pair(a, b);
        let hash2 = splitmix::pair(a, b);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn wyhash_is_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        seed in any::<u64>()
    ) {
        let hash1 = wyhash::hash(&data, seed);
        let hash2 = wyhash::hash(&data, seed);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn wyhash_single_bit_flip_avalanche(
        mut data in prop::collection::vec(any::<u8>(), 1..100),
        seed in any::<u64>(),
        bit_to_flip in 0..8_usize
    ) {
        let hash1 = wyhash::hash(&data, seed);

        // Flip exactly one bit
        let byte_idx = 0; // Flip in the first byte
        data[byte_idx] ^= 1 << bit_to_flip;

        let hash2 = wyhash::hash(&data, seed);

        // Strong hashes should avalanche and not equal the previous hash.
        // It is astronomically unlikely a 1-bit flip produces the exact same wyhash value.
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn bloom_hash_pair_is_deterministic(
        a in any::<u8>(),
        b in any::<u8>()
    ) {
        let pair1 = bloom_hash_pair(a, b);
        let pair2 = bloom_hash_pair(a, b);
        assert_eq!(pair1, pair2);
    }
}

// Further rigorous invariant testing
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn fnv_single_bit_flip_avalanche(
        mut data in prop::collection::vec(any::<u8>(), 1..100),
        bit_to_flip in 0..8_usize
    ) {
        let hash1 = fnv::fnv1a_64(&data);
        data[0] ^= 1 << bit_to_flip;
        let hash2 = fnv::fnv1a_64(&data);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn splitmix_seed_flip_avalanche(
        seed in any::<u64>(),
        bit_to_flip in 0..64_usize
    ) {
        let hash1 = splitmix::finalize(seed);
        let flipped_seed = seed ^ (1 << bit_to_flip);
        let hash2 = splitmix::finalize(flipped_seed);
        assert_ne!(hash1, hash2);

        let diff_bits = (hash1 ^ hash2).count_ones();
        // A strong avalanche should flip approximately half the bits (32).
        // A lower bound of 10 bits flipped on a single input bit flip is a safe assertion for a good mix.
        assert!(diff_bits > 10, "Weak avalanche effect observed: {} bits changed", diff_bits);
    }
}
