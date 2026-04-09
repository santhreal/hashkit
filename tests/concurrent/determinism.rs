use std::sync::Arc;
use std::thread;

use hashkit::{blake3_hash, fnv, splitmix, wyhash};

#[test]
fn concurrent_wyhash_same_data_same_seed() {
    let data = Arc::new(vec![0xDD_u8; 10 * 1024 * 1024]); // 10MB
    let seed = 0xABCD_EF01_2345_6789_u64;
    let expected = wyhash::hash(&data, seed);
    let mut handles = vec![];

    for _ in 0..8 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || wyhash::hash(&d, seed)));
    }

    for h in handles {
        let result = h
            .join()
            .expect("Fix: Thread panicked during wyhash concurrent test");
        assert_eq!(
            result, expected,
            "Fix: Concurrent wyhash on same data produced different results"
        );
    }
}

#[test]
fn concurrent_fnv_same_data() {
    let data = Arc::new(vec![0xDD_u8; 10 * 1024 * 1024]);
    let expected = fnv::fnv1a_64(&data);
    let mut handles = vec![];

    for _ in 0..8 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || fnv::fnv1a_64(&d)));
    }

    for h in handles {
        let result = h
            .join()
            .expect("Fix: Thread panicked during FNV concurrent test");
        assert_eq!(
            result, expected,
            "Fix: Concurrent FNV on same data produced different results"
        );
    }
}

#[test]
fn concurrent_splitmix_same_seed() {
    let seed = 0x1234_5678_9ABC_DEF0_u64;
    let expected = splitmix::finalize(seed);
    let mut handles = vec![];

    for _ in 0..8 {
        handles.push(thread::spawn(move || splitmix::finalize(seed)));
    }

    for h in handles {
        let result = h
            .join()
            .expect("Fix: Thread panicked during SplitMix concurrent test");
        assert_eq!(
            result, expected,
            "Fix: Concurrent SplitMix on same seed produced different results"
        );
    }
}

#[test]
fn concurrent_blake3_oneshot_same_data() {
    let data = Arc::new(vec![0xDD_u8; 10 * 1024 * 1024]);
    let expected = blake3_hash::hash(&data);
    let mut handles = vec![];

    for _ in 0..16 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || blake3_hash::hash(&d)));
    }

    for h in handles {
        let result = h
            .join()
            .expect("Fix: Thread panicked during BLAKE3 one-shot concurrent test");
        assert_eq!(
            result, expected,
            "Fix: Concurrent BLAKE3 one-shot on same data produced different results"
        );
    }
}

#[test]
fn concurrent_blake3_streaming_same_data() {
    let data = Arc::new(vec![0xDD_u8; 10 * 1024 * 1024]);
    let expected = blake3_hash::hash(&data);
    let mut handles = vec![];

    for _ in 0..8 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let mut hasher = blake3_hash::ContentHash::new();
            hasher.update(&d);
            hasher.finalize()
        }));
    }

    for h in handles {
        let result = h
            .join()
            .expect("Fix: Thread panicked during BLAKE3 streaming concurrent test");
        assert_eq!(
            result, expected,
            "Fix: Concurrent BLAKE3 streaming on same data produced different results"
        );
    }
}
