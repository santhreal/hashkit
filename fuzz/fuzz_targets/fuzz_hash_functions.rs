#![no_main]

use hashkit::{fnv, splitmix, wyhash};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fnv_hash = fnv::fnv1a_64(data);
    let wyhash_hash = wyhash::hash(data, fnv_hash);
    let seed = if data.len() >= 8 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&data[..8]);
        u64::from_le_bytes(bytes)
    } else {
        fnv_hash ^ wyhash_hash
    };

    let _ = splitmix::finalize(seed);
    if data.len() >= 2 {
        let _ = splitmix::pair(data[0], data[1]);
    }
    let _ = wyhash::hash(data, wyhash_hash);
});
