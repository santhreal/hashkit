use hashkit::{bloom_hash_pair, fnv, hash_to_index, splitmix, wyhash};

#[test]
fn test_01_wyhash_empty_slice() {
    let hash = wyhash::hash(&[], 0);
    assert_eq!(
        hash,
        wyhash::hash(&[], 0),
        "Fix: Empty slice hashing must be deterministic"
    );
    assert_ne!(
        hash,
        wyhash::hash(&[], 1),
        "Fix: Empty slice hashing must depend on seed"
    );
}

#[test]
fn test_02_fnv_empty_slice() {
    let hash = fnv::fnv1a_64(&[]);
    assert_eq!(
        hash,
        fnv::OFFSET_BASIS,
        "Fix: FNV empty slice should equal OFFSET_BASIS"
    );
}

#[test]
fn test_03_hash_to_index_zero_bits() {
    let index = hash_to_index(12345, 0);
    assert_eq!(index, 0, "Fix: hash_to_index with 0 bits must return 0");
}

#[test]
fn test_04_wyhash_null_bytes() {
    let hash1 = wyhash::hash(&[0], 0);
    let hash2 = wyhash::hash(&[0, 0], 0);
    assert_ne!(
        hash1, hash2,
        "Fix: Null bytes of different lengths must produce different hashes"
    );
}

#[test]
fn test_05_fnv_null_bytes() {
    let hash1 = fnv::fnv1a_64(&[0]);
    let hash2 = fnv::fnv1a_64(&[0, 0]);
    assert_ne!(
        hash1, hash2,
        "Fix: FNV null bytes of different lengths must produce different hashes"
    );
}

#[test]
fn test_06_bloom_hash_pair_null_bytes() {
    let (h1, h2) = bloom_hash_pair(0, 0);
    assert_ne!(h1, 0, "Fix: bloom_hash_pair for null bytes should not be 0");
    assert_ne!(h2, 0, "Fix: bloom_hash_pair for null bytes should not be 0");
}

#[test]
fn test_07_wyhash_max_seed() {
    let hash1 = wyhash::hash(b"test", u64::MAX);
    let hash2 = wyhash::hash(b"test", u64::MAX - 1);
    assert_ne!(
        hash1, hash2,
        "Fix: wyhash should properly avalanche on extreme seed values"
    );
}

#[test]
fn test_08_splitmix_max_seed() {
    let hash = splitmix::finalize(u64::MAX);
    assert_ne!(hash, 0, "Fix: SplitMix on u64::MAX should not be 0");
}

#[test]
fn test_09_hash_to_index_max_hash_max_bits() {
    let index = hash_to_index(u64::MAX, usize::MAX);
    assert!(
        index < usize::MAX,
        "Fix: hash_to_index must safely bound u64::MAX into usize::MAX"
    );
}

#[test]
fn test_10_bloom_hash_pair_max_bytes() {
    let (h1, h2) = bloom_hash_pair(255, 255);
    assert_ne!(h1, 0, "Fix: bloom_hash_pair max bytes should not be 0");
    assert_ne!(h2, 0, "Fix: bloom_hash_pair max bytes should not be 0");
}

#[test]
fn test_11_wyhash_1mb_input() {
    // We allocate 1MB safely
    let vec = vec![0xAB; 1024 * 1024];
    let hash = wyhash::hash(&vec, 42);
    assert_eq!(
        hash,
        wyhash::hash(&vec, 42),
        "Fix: Large inputs must hash deterministically"
    );
}

#[test]
fn test_12_concurrent_access() {
    use std::sync::Arc;
    let data = Arc::new(vec![0xAA; 100_000]);
    let mut threads = vec![];
    for i in 0..8 {
        let d = Arc::clone(&data);
        threads.push(std::thread::spawn(move || {
            let hash = wyhash::hash(&d, i);
            assert_ne!(hash, 0, "Fix: Valid data hash should not be 0 in thread");
        }));
    }
    for t in threads {
        t.join()
            .expect("Fix: Threads must not panic during concurrent access");
    }
}

#[test]
fn test_13_wyhash_1_byte() {
    let hash = wyhash::hash(b"a", 0);
    assert_ne!(hash, 0, "Fix: 1 byte string must produce a non-zero hash");
}

#[test]
fn test_14_wyhash_2_bytes() {
    let hash = wyhash::hash(b"ab", 0);
    assert_ne!(hash, 0, "Fix: 2 byte string must produce a non-zero hash");
}

#[test]
fn test_15_wyhash_3_bytes() {
    let hash = wyhash::hash(b"abc", 0);
    assert_ne!(hash, 0, "Fix: 3 byte string must produce a non-zero hash");
}

#[test]
fn test_16_wyhash_4_bytes() {
    let hash = wyhash::hash(b"abcd", 0);
    assert_ne!(hash, 0, "Fix: 4 byte string must produce a non-zero hash");
}

#[test]
fn test_17_wyhash_7_bytes() {
    let hash = wyhash::hash(b"abcdefg", 0);
    assert_ne!(hash, 0, "Fix: 7 byte string must produce a non-zero hash");
}

#[test]
fn test_18_wyhash_8_bytes() {
    let hash = wyhash::hash(b"abcdefgh", 0);
    assert_ne!(hash, 0, "Fix: 8 byte string must produce a non-zero hash");
}

#[test]
fn test_19_wyhash_bom_unicode() {
    let bom = "\u{FEFF}";
    let hash = wyhash::hash(bom.as_bytes(), 0);
    assert_ne!(hash, 0, "Fix: BOM character should produce a non-zero hash");
}

#[test]
fn test_20_wyhash_overlong_utf8() {
    // Malformed sequence representing '/'
    let overlong = &[0xC0, 0xAF];
    let hash = wyhash::hash(overlong, 0);
    assert_ne!(
        hash, 0,
        "Fix: Overlong UTF-8 must be hashed consistently without panicking"
    );
}

#[test]
fn test_21_wyhash_isolated_surrogate() {
    // Isolated surrogate code points are invalid UTF-8 but valid raw bytes
    let surrogate = &[0xED, 0xA0, 0x80];
    let hash = wyhash::hash(surrogate, 0);
    assert_ne!(hash, 0, "Fix: Isolated surrogates must be hashed safely");
}

#[test]
fn test_22_fnv_unicode_characters() {
    let emojis = "🔥🦀✨";
    let hash = fnv::fnv1a_64(emojis.as_bytes());
    assert_ne!(
        hash,
        fnv::OFFSET_BASIS,
        "Fix: Emojis should shift FNV hash from offset basis"
    );
}

#[test]
fn test_23_wyhash_duplicate_entries() {
    let hash1 = wyhash::hash(b"A\0", 0);
    let hash2 = wyhash::hash(b"\0A", 0);
    assert_ne!(
        hash1, hash2,
        "Fix: Same bytes in different order must not collide"
    );
}

#[test]
fn test_24_wyhash_duplicate_entries_larger() {
    let hash1 = wyhash::hash(b"abcdefgh", 0);
    let hash2 = wyhash::hash(b"hgfedcba", 0);
    assert_ne!(hash1, hash2, "Fix: Reversed 8-byte slice must not collide");
}

#[test]
fn test_25_wyhash_off_by_one_chunk_15() {
    let data = vec![0xBB; 15];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 15 (chunk - 1) must be handled without panicking"
    );
}

#[test]
fn test_26_wyhash_off_by_one_chunk_16() {
    let data = vec![0xBB; 16];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 16 (chunk boundary) must be handled without panicking"
    );
}

#[test]
fn test_27_wyhash_off_by_one_chunk_17() {
    let data = vec![0xBB; 17];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 17 (chunk + 1) must be handled without panicking"
    );
}

#[test]
fn test_28_wyhash_off_by_one_chunk_47() {
    let data = vec![0xCC; 47];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 47 (multi-chunk - 1) must be handled without panicking"
    );
}

#[test]
fn test_29_wyhash_off_by_one_chunk_48() {
    let data = vec![0xCC; 48];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 48 (multi-chunk boundary) must be handled without panicking"
    );
}

#[test]
fn test_30_wyhash_off_by_one_chunk_49() {
    let data = vec![0xCC; 49];
    let hash = wyhash::hash(&data, 0);
    assert_ne!(
        hash, 0,
        "Fix: Length 49 (multi-chunk + 1) must be handled without panicking"
    );
}

#[test]
fn test_31_wyhash_resource_exhaustion() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for i in 0u32..100_000 {
        let hash = wyhash::hash(&i.to_le_bytes(), 0);
        set.insert(hash);
    }
    assert_eq!(
        set.len(),
        100_000,
        "Fix: 100k simple hashes must not collide or exhaust resources"
    );
}

#[test]
fn test_32_fnv_resource_exhaustion() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for i in 0u32..100_000 {
        let hash = fnv::fnv1a_64(&i.to_le_bytes());
        set.insert(hash);
    }
    assert_eq!(
        set.len(),
        100_000,
        "Fix: 100k FNV hashes must not collide or exhaust resources"
    );
}

#[test]
fn test_33_wyhash_deeply_nested_structures() {
    // A long repeating pattern of nulls and bytes to break potential recursive/chunking simplifications
    let mut data = Vec::with_capacity(1_000_000);
    for i in 0..1_000_000 {
        data.push((i % 256) as u8);
    }
    let hash = wyhash::hash(&data, 0x12345678);
    assert_ne!(
        hash, 0,
        "Fix: Deep/long iterative sequences must hash consistently"
    );
    let hash_mod = wyhash::hash(&data, 0x12345679);
    assert_ne!(
        hash, hash_mod,
        "Fix: Seed must significantly affect large structure hashing"
    );
}
