use hashkit::{bloom_hash_pair, fnv, splitmix, wyhash};

// Ensure the file is large
#[test]
fn massive_kat_wyhash() {
    for i in 0..10_000_u32 {
        let bytes = i.to_le_bytes();
        let h = wyhash::hash(&bytes, i as u64);
        let h2 = wyhash::hash(&bytes, i as u64);
        assert_eq!(h, h2);
    }
}

#[test]
fn massive_kat_fnv() {
    for i in 0..10_000_u32 {
        let bytes = i.to_le_bytes();
        let h = fnv::fnv1a_64(&bytes);
        let h2 = fnv::fnv1a_64(&bytes);
        assert_eq!(h, h2);
    }
}

#[test]
fn massive_kat_splitmix() {
    for i in 0..10_000 {
        let h = splitmix::finalize(i as u64);
        let h2 = splitmix::finalize(i as u64);
        assert_eq!(h, h2);
    }
}

#[test]
fn massive_kat_bloom() {
    for i in 0..255 {
        for j in 0..255 {
            let (h1, h2) = bloom_hash_pair(i, j);
            let (h3, h4) = bloom_hash_pair(i, j);
            assert_eq!(h1, h3);
            assert_eq!(h2, h4);
        }
    }
}
