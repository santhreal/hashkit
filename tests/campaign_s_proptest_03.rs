//! S-proptest-03 (hashkit mass proptest: hash/index invariants, no panic on arbitrary bytes).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hashkit::{
    blake3_hash, bloom_hash_pair, entropy, fnv, hash_to_index, hex, secure_compare, sha256_hash,
    splitmix, wyhash,
};
use proptest::prelude::*;

macro_rules! bytes_cases {
    ($($name:ident => |$data:ident| $body:block),+ $(,)?) => {
        $(
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(64))]
                #[test]
                fn $name($data in prop::collection::vec(any::<u8>(), 0..512)) {
                    $body
                }
            }
        )+
    };
}

bytes_cases! {
    p00_hash_to_index_pow2 => |data| {
        let bits = 64usize;
        let idx = hash_to_index(fnv::fnv1a_64(&data), bits);
        prop_assert!(idx < bits);
    },
    p01_hash_to_index_mod => |data| {
        let bits = 100usize;
        let idx = hash_to_index(wyhash::hash(&data, 0), bits);
        prop_assert!(idx < bits);
    },
    p02_hash_to_index_zero_bits => |data| {
        prop_assert_eq!(hash_to_index(splitmix::finalize(fnv::fnv1a_64(&data)), 0), 0);
    },
    p03_fnv_deterministic => |data| {
        let a = fnv::fnv1a_64(&data);
        let b = fnv::fnv1a_64(&data);
        prop_assert_eq!(a, b);
    },
    p04_fnv_pair_matches_slice => |data| {
        if data.len() >= 2 {
            let (a, b) = (data[0], data[1]);
            prop_assert_eq!(fnv::fnv1a_pair(a, b), fnv::fnv1a_64(&[a, b]));
        }
    },
    p05_splitmix_finalize_det => |data| {
        let h = fnv::fnv1a_64(&data);
        prop_assert_eq!(splitmix::finalize(h), splitmix::finalize(h));
    },
    p06_splitmix_pair_det => |data| {
        if data.len() >= 2 {
            let (a, b) = (data[0], data[1]);
            prop_assert_eq!(splitmix::pair(a, b), splitmix::pair(a, b));
        }
    },
    p07_wyhash_deterministic => |data| {
        let seed = fnv::fnv1a_64(&data);
        prop_assert_eq!(wyhash::hash(&data, seed), wyhash::hash(&data, seed));
    },
    p08_bloom_pair_components => |data| {
        if data.len() >= 2 {
            let (a, b) = (data[0], data[1]);
            let pair = bloom_hash_pair(a, b);
            prop_assert_eq!(pair.0, fnv::fnv1a_pair(a, b));
            prop_assert_eq!(pair.1, splitmix::pair(a, b));
        }
    },
    p09_hex_roundtrip => |data| {
        let encoded = hex::encode(&data);
        let decoded = hex::decode(&encoded).expect("valid hex");
        prop_assert_eq!(decoded, data);
    },
    p10_hex_encode_len => |data| {
        prop_assert_eq!(hex::encode(&data).len(), data.len() * 2);
    },
    p11_entropy_in_range => |data| {
        let e = entropy::shannon_entropy(&data);
        prop_assert!((0.0..=8.0).contains(&e));
    },
    p12_entropy_bucket_uniform_is_zero => |data| {
        // Empty or single-distinct-value input quantizes to bucket 0.
        if data.is_empty() || data.iter().all(|&x| x == data[0]) {
            prop_assert_eq!(entropy::entropy_bucket(&data), 0);
        }
    },
    p13_blake3_deterministic => |data| {
        prop_assert_eq!(blake3_hash::hash(&data), blake3_hash::hash(&data));
    },
    p14_blake3_len_32 => |data| {
        prop_assert_eq!(blake3_hash::hash(&data).len(), 32);
    },
    p15_sha256_deterministic => |data| {
        prop_assert_eq!(sha256_hash::hash(&data), sha256_hash::hash(&data));
    },
    p16_sha256_integrity_verify => |data| {
        let integrity = sha256_hash::integrity(&data);
        prop_assert!(sha256_hash::verify(&data, &integrity));
    },
    p17_secure_compare_refl => |data| {
        prop_assert!(secure_compare(&data, &data));
    },
    p18_blake3_secure_compare_refl => |data| {
        let h = blake3_hash::hash(&data);
        prop_assert!(blake3_hash::secure_compare(&h, &h));
    },
    p19_wyhash_empty_ok => |data| {
        let _ = wyhash::hash(&[], 0);
        let _ = wyhash::hash(&data, 0);
    },
    p20_fnv_empty_ok => |data| {
        let _ = fnv::fnv1a_64(&[]);
        let _ = fnv::fnv1a_64(&data);
    },
    p21_hash_to_index_mask_large => |data| {
        let bits = 1024usize;
        prop_assert!(hash_to_index(u64::MAX, bits) < bits);
        prop_assert!(hash_to_index(wyhash::hash(&data, 0), bits) < bits);
    },
    p22_bloom_indices_in_range => |data| {
        if data.len() >= 2 {
            let (h1, h2) = bloom_hash_pair(data[0], data[1]);
            let bits = 512usize;
            prop_assert!(hash_to_index(h1, bits) < bits);
            prop_assert!(hash_to_index(h2, bits) < bits);
        }
    },
    p23_parse_integrity_roundtrip => |data| {
        let integrity = sha256_hash::integrity(&data);
        let parsed = sha256_hash::parse_integrity(&integrity);
        prop_assert!(parsed.is_some());
        prop_assert_eq!(parsed.unwrap(), sha256_hash::hash(&data));
    },
    p24_entropy_empty_zero => |data| {
        if data.is_empty() {
            prop_assert_eq!(entropy::shannon_entropy(&data), 0.0);
        }
    },
    p25_entropy_bucket_empty_zero => |data| {
        if data.is_empty() {
            prop_assert_eq!(entropy::entropy_bucket(&data), 0);
        }
    },
    p26_wyhash_differs_on_append => |data| {
        if !data.is_empty() {
            let base = wyhash::hash(&data, 1);
            let mut extended = data.clone();
            extended.push(0);
            let extended_hash = wyhash::hash(&extended, 1);
            prop_assert_ne!(base, extended_hash);
        }
    },
    p27_fnv_differs_on_append => |data| {
        if !data.is_empty() {
            let base = fnv::fnv1a_64(&data);
            let mut extended = data.clone();
            extended.push(0);
            prop_assert_ne!(base, fnv::fnv1a_64(&extended));
        }
    },
    p28_splitmix_pair_symmetry_inputs => |data| {
        if data.len() >= 2 {
            let (a, b) = (data[0], data[1]);
            prop_assert_eq!(splitmix::pair(a, b), splitmix::pair(a, b));
        }
    },
    p29_hash_to_index_deterministic => |data| {
        let bits = 256usize;
        let h = wyhash::hash(&data, 99);
        prop_assert_eq!(hash_to_index(h, bits), hash_to_index(h, bits));
    },
    p30_hex_lowercase => |data| {
        let encoded = hex::encode(&data);
        prop_assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    },
    p31_blake3_differs_on_flip => |data| {
        if !data.is_empty() {
            let mut flipped = data.clone();
            flipped[0] ^= 1;
            prop_assert_ne!(blake3_hash::hash(&data), blake3_hash::hash(&flipped));
        }
    },
    p32_sha256_len_32 => |data| {
        prop_assert_eq!(sha256_hash::hash(&data).len(), 32);
    },
    p33_secure_compare_length_mismatch => |data| {
        if data.len() > 1 {
            prop_assert!(!secure_compare(&data[..data.len() - 1], &data));
        }
    },
}
