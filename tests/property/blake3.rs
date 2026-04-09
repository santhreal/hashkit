use hashkit::blake3_hash::{hash, ContentHash};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn blake3_hash_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let h1 = hash(&data);
        let h2 = hash(&data);
        assert_eq!(h1, h2, "Fix: BLAKE3 one-shot hash must be deterministic");
    }

    #[test]
    fn blake3_streaming_single_split_matches_one_shot(
        data in prop::collection::vec(any::<u8>(), 0..4096),
        split in 0..=4096_usize
    ) {
        let split = split.min(data.len());
        let mut hasher = ContentHash::new();
        hasher.update(&data[..split]);
        hasher.update(&data[split..]);
        let stream_hash = hasher.finalize();
        let one_shot = hash(&data);
        assert_eq!(
            stream_hash, one_shot,
            "Fix: BLAKE3 streaming with single split must match one-shot"
        );
    }

    #[test]
    fn blake3_streaming_multiple_splits_matches_one_shot(
        data in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let mut hasher = ContentHash::new();
        for chunk in data.chunks(256) {
            hasher.update(chunk);
        }
        let stream_hash = hasher.finalize();
        let one_shot = hash(&data);
        assert_eq!(
            stream_hash, one_shot,
            "Fix: BLAKE3 streaming with multiple splits must match one-shot"
        );
    }
}
