use hashkit::{bloom_hash_pair, fnv, hash_to_index, wyhash};
use proptest::prelude::*;

// We will test various sizes, alignments, and chunkings using proptest
proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn wyhash_never_panics_on_any_bytes_and_is_stable(
        data in prop::collection::vec(any::<u8>(), 0..5000),
        seed in any::<u64>()
    ) {
        let hash = wyhash::hash(&data, seed);
        assert_eq!(hash, wyhash::hash(&data, seed));
    }

    #[test]
    fn fnv_never_panics_on_any_bytes_and_is_stable(
        data in prop::collection::vec(any::<u8>(), 0..5000)
    ) {
        let hash = fnv::fnv1a_64(&data);
        assert_eq!(hash, fnv::fnv1a_64(&data));
    }

    #[test]
    fn hash_to_index_never_panics_and_is_stable(
        hash in any::<u64>(),
        width in any::<usize>()
    ) {
        let index = hash_to_index(hash, width);
        assert_eq!(index, hash_to_index(hash, width));
    }

    #[test]
    fn bloom_pair_never_panics_and_is_stable(
        a in any::<u8>(),
        b in any::<u8>()
    ) {
        let (h1, h2) = bloom_hash_pair(a, b);
        assert_eq!((h1, h2), bloom_hash_pair(a, b));
    }

    #[test]
    fn wyhash_concatenation_inequality(
        chunk1 in prop::collection::vec(any::<u8>(), 1..100),
        chunk2 in prop::collection::vec(any::<u8>(), 1..100),
        seed in any::<u64>()
    ) {
        let h1 = wyhash::hash(&chunk1, seed);
        let h2 = wyhash::hash(&chunk2, seed);

        let mut combined = chunk1.clone();
        combined.extend_from_slice(&chunk2);
        let h3 = wyhash::hash(&combined, seed);

        assert_ne!(h3, h1);
        assert_ne!(h3, h2);
    }
}
