//! Property and known-answer coverage for `hashkit::entropy`.
//!
//! `shannon_entropy` and `entropy_bucket` are relied on across the Santh
//! toolchain (walkkit, codewalk, keyhog) to classify byte payloads, so their
//! invariants are part of the published contract: bounded, finite,
//! order-independent, and exactly the textbook Shannon value on known
//! distributions.

// Exact `== 0.0` comparisons are intentional: `shannon_entropy` returns
// exactly `0.0` for empty and single-symbol input by construction, so the
// known-answer assertions are exact, not approximate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::float_cmp)]

use hashkit::entropy::{entropy_bucket, shannon_entropy};
use proptest::prelude::*;

const EPS: f64 = 1e-9;

// ---- known-answer / boundary unit tests ----

#[test]
fn empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(entropy_bucket(&[]), 0);
}

#[test]
fn single_byte_is_zero_regardless_of_length() {
    for len in [1usize, 2, 7, 1000, 65_536] {
        let data = vec![0x5Au8; len];
        assert_eq!(shannon_entropy(&data), 0.0, "len {len}");
        assert_eq!(entropy_bucket(&data), 0, "len {len}");
    }
}

#[test]
fn two_equal_symbols_is_one_bit() {
    let data = [0u8, 1, 0, 1, 0, 1];
    assert!((shannon_entropy(&data) - 1.0).abs() < EPS);
    // 1 bit -> round((1/8) * 255) = round(31.875) = 32
    assert_eq!(entropy_bucket(&data), 32);
}

#[test]
fn four_equal_symbols_is_two_bits() {
    let data = [0u8, 1, 2, 3, 0, 1, 2, 3];
    assert!((shannon_entropy(&data) - 2.0).abs() < EPS);
    // 2 bits -> round((2/8) * 255) = round(63.75) = 64
    assert_eq!(entropy_bucket(&data), 64);
}

#[test]
fn all_256_bytes_once_is_eight_bits() {
    let data: Vec<u8> = (0..=255).collect();
    assert!((shannon_entropy(&data) - 8.0).abs() < 1e-6);
    assert_eq!(entropy_bucket(&data), 255);
}

#[test]
fn imbalanced_two_symbols_is_between_zero_and_one_bit() {
    // 7:1 split -> H = -(7/8·log2 7/8 + 1/8·log2 1/8) ≈ 0.5436 bits
    let mut data = vec![0u8; 7];
    data.push(1);
    let h = shannon_entropy(&data);
    assert!(h > 0.0 && h < 1.0, "expected a fraction of a bit, got {h}");
}

// ---- properties ----

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Always finite and inside the theoretical [0, 8] range for byte data.
    #[test]
    fn bounded_and_finite(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let h = shannon_entropy(&data);
        prop_assert!(h.is_finite(), "non-finite entropy: {h}");
        prop_assert!((-EPS..=8.0 + EPS).contains(&h), "out of range: {h}");
    }

    /// Entropy depends only on the multiset of byte values, not their order.
    /// Sorting is a permutation, so it must not change the result.
    #[test]
    fn order_independent(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let mut permuted = data.clone();
        permuted.sort_unstable();
        prop_assert!((shannon_entropy(&data) - shannon_entropy(&permuted)).abs() < EPS);
    }

    /// Entropy never exceeds log2(number of distinct symbols present).
    #[test]
    fn at_most_log2_distinct(data in prop::collection::vec(any::<u8>(), 1..2048)) {
        let mut seen = [false; 256];
        for &b in &data {
            seen[usize::from(b)] = true;
        }
        let distinct = seen.iter().filter(|&&s| s).count();
        let h = shannon_entropy(&data);
        prop_assert!(
            h <= (distinct as f64).log2() + 1e-9,
            "distinct={distinct} h={h}"
        );
    }

    /// Repeating the input leaves the symbol probabilities unchanged, so the
    /// entropy is invariant under repetition.
    #[test]
    fn repetition_invariant(
        data in prop::collection::vec(any::<u8>(), 1..512),
        reps in 2usize..5,
    ) {
        let repeated: Vec<u8> = data.iter().copied().cycle().take(data.len() * reps).collect();
        prop_assert!((shannon_entropy(&data) - shannon_entropy(&repeated)).abs() < EPS);
    }

    /// A single distinct value is always zero entropy and bucket 0.
    #[test]
    fn constant_input_is_zero(byte: u8, len in 1usize..4096) {
        let data = vec![byte; len];
        prop_assert_eq!(shannon_entropy(&data), 0.0);
        prop_assert_eq!(entropy_bucket(&data), 0);
    }

    /// The bucket is exactly the documented quantization of the float entropy,
    /// and therefore always within 0..=255.
    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn bucket_matches_quantization(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let h = shannon_entropy(&data);
        let expected = ((h / 8.0).clamp(0.0, 1.0) * 255.0).round() as u8;
        prop_assert_eq!(entropy_bucket(&data), expected);
    }
}
