use std::hint::black_box;
use std::time::{Duration, Instant};

use hashkit::{blake3_hash, fnv, wyhash};

const SEED: u64 = 0xD0E1_F2A3_B4C5_9687;
const SIZES: [usize; 4] = [8, 64, 1024, 64 * 1024];

fn main() {
    println!("hashkit benchmark: wyhash vs fnv1a vs blake3");
    for size in SIZES {
        let input = make_input(size);
        let fnv = bench("fnv1a_64", size, &input, |bytes| fnv::fnv1a_64(bytes));
        let wy = bench("wyhash", size, &input, |bytes| wyhash::hash(bytes, SEED));
        let blake3 = bench("blake3", size, &input, |bytes| blake3_hash::hash(bytes));
        let ratio = fnv.as_secs_f64() / wy.as_secs_f64();
        println!("size={size:>6}B wy_speedup={ratio:>6.2}x blake3_time={blake3:?}");
    }
}

fn make_input(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9ABC_DEF0_u64;
    let mut bytes = vec![0_u8; len];
    for byte in &mut bytes {
        state = state.rotate_left(7).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        *byte = state.to_le_bytes()[0];
    }
    bytes
}

fn bench<R>(label: &str, size: usize, input: &[u8], hash_fn: impl Fn(&[u8]) -> R) -> Duration {
    let iterations = iterations_for(size);
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(hash_fn(black_box(input)));
    }
    let elapsed = start.elapsed();
    println!(
        "{label:>9} size={size:>6}B iterations={iterations:>7} total={elapsed:?}"
    );
    elapsed
}

fn iterations_for(size: usize) -> usize {
    match size {
        0..=8 => 2_000_000,
        9..=64 => 1_000_000,
        65..=1024 => 100_000,
        _ => 2_000,
    }
}
