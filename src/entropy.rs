//! Shannon entropy calculation for byte slices.

/// Compute Shannon entropy over a byte slice.
///
/// Returns `0.0` for empty input.
///
/// # Examples
///
/// ```
/// use hashkit::entropy::shannon_entropy;
///
/// assert_eq!(shannon_entropy(&[]), 0.0);
/// assert!((shannon_entropy(&[0, 1, 2, 3]) - 2.0).abs() < 0.001);
/// ```
#[inline]
#[must_use]
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &byte in bytes {
        freq[usize::from(byte)] += 1;
    }
    entropy_from_histogram(&freq, bytes.len() as u64)
}

/// Shannon entropy (bits/byte) from a 256-lane byte histogram and its total.
///
/// ONE-PLACE owner of the entropy formula, shared by [`shannon_entropy`] (slice)
/// and [`EntropyCounter`] (streaming) so both compute bit-identically.
///
/// `H = -Σ p_i log2 p_i` with `p_i = c_i/n`. Expanding `p_i` and using `Σ c_i = n`:
///   `H = log2(n) - (1/n) Σ c_i log2(c_i)`
/// This hoists the `log2(n)` term and the division out of the 256-way loop, so the
/// loop does one `log2` (unavoidable, per distinct byte) and no division; the
/// single division happens once at the end. Returns 0.0 for an empty histogram.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn entropy_from_histogram(freq: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    let mut sum_c_log_c = 0.0f64;
    let mut distinct = 0u32;
    for &count in freq {
        if count == 0 {
            continue;
        }
        distinct += 1;
        let c = count as f64;
        sum_c_log_c += c * c.log2();
    }
    // A single distinct symbol has entropy EXACTLY 0. The closed-form
    // `log2(n) - n*log2(n)/n` leaves a tiny fp residue that can be positive OR
    // negative; the `.max(0.0)` below only clears the negative case, so return
    // the exact 0 here (matching the naive `-Σ p log2 p` form, where p=1 gives
    // `-1*log2(1) == 0`). Without this, a constant buffer reports ~1e-15 bits.
    if distinct <= 1 {
        return 0.0;
    }
    // clamp tiny negative fp residue near the low-entropy floor.
    (len.log2() - sum_c_log_c / len).max(0.0)
}

/// Incremental Shannon-entropy accumulator for streaming or very large inputs.
///
/// Feed bytes in any number of chunks with [`update`](Self::update), then read
/// [`entropy`](Self::entropy) / [`bucket`](Self::bucket) at any point. It holds
/// only a fixed 256-lane `u64` histogram (2 KiB) plus a running total, so entropy
/// over an arbitrarily large stream (a whole file read in chunks, a socket) costs
/// O(1) memory - the gap the slice-only [`shannon_entropy`] could not cover.
///
/// The result is independent of how the input is chunked, and identical to
/// [`shannon_entropy`] over the concatenation of all fed bytes.
///
/// # Examples
///
/// ```
/// use hashkit::entropy::{shannon_entropy, EntropyCounter};
///
/// let whole = b"The quick brown fox";
/// let mut c = EntropyCounter::new();
/// c.update(&whole[..5]);
/// c.update(&whole[5..]);
/// assert!((c.entropy() - shannon_entropy(whole)).abs() < 1e-9);
/// ```
#[derive(Debug, Clone)]
pub struct EntropyCounter {
    freq: [u64; 256],
    total: u64,
}

impl EntropyCounter {
    /// Create an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            freq: [0u64; 256],
            total: 0,
        }
    }

    /// Fold another chunk of bytes into the running histogram.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.freq[usize::from(byte)] = self.freq[usize::from(byte)].saturating_add(1);
        }
        self.total = self.total.saturating_add(bytes.len() as u64);
    }

    /// Total number of bytes observed so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.total
    }

    /// True if no bytes have been observed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Shannon entropy (bits/byte) of everything observed so far; `0.0` if empty.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        entropy_from_histogram(&self.freq, self.total)
    }

    /// Quantized entropy bucket `0..=255` of everything observed so far (see
    /// [`entropy_bucket`]).
    #[must_use]
    pub fn bucket(&self) -> u8 {
        bucket_from_entropy(self.entropy())
    }
}

impl Default for EntropyCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Quantize Shannon entropy to the inclusive range `0..=255`.
///
/// Empty input maps to `0`.
///
/// # Examples
///
/// ```
/// use hashkit::entropy::entropy_bucket;
///
/// assert_eq!(entropy_bucket(&[]), 0);
/// assert_eq!(entropy_bucket(&vec![0xAA; 1024]), 0);
/// ```
#[inline]
#[must_use]
pub fn entropy_bucket(bytes: &[u8]) -> u8 {
    bucket_from_entropy(shannon_entropy(bytes))
}

/// Quantize an entropy value (bits/byte) to `0..=255`. ONE-PLACE owner shared by
/// [`entropy_bucket`] and [`EntropyCounter::bucket`].
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn bucket_from_entropy(entropy: f64) -> u8 {
    let normalized = (entropy / 8.0).clamp(0.0, 1.0);
    (normalized * 255.0).round() as u8
}

#[cfg(test)]
mod tests {
    use super::{entropy_bucket, shannon_entropy, EntropyCounter};

    #[test]
    fn empty_counter_is_zero_and_empty() {
        let c = EntropyCounter::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.entropy(), 0.0);
        assert_eq!(c.bucket(), 0);
    }

    #[test]
    fn streaming_matches_slice_across_inputs_and_chunkings() {
        let inputs: [&[u8]; 4] = [
            b"The quick brown fox jumps over the lazy dog",
            b"secret_api_key=AKIA1234567890ABCDEF",
            &[0u8; 300],
            b"aabbccddeeffgghh",
        ];
        for data in inputs {
            let want = shannon_entropy(data);
            // Feed in several different chunk boundaries; every split must yield
            // the identical entropy as the whole-slice computation.
            for chunk in [1usize, 3, 7, 16] {
                let mut c = EntropyCounter::new();
                for piece in data.chunks(chunk.max(1)) {
                    c.update(piece);
                }
                assert_eq!(c.len(), data.len() as u64);
                assert!(
                    (c.entropy() - want).abs() < 1e-9,
                    "chunk={chunk} streaming {} != slice {want} for {data:?}",
                    c.entropy()
                );
                assert_eq!(c.bucket(), entropy_bucket(data));
            }
        }
    }

    #[test]
    fn uniform_stream_reaches_max_entropy() {
        // Every byte value once, fed one at a time: 8 bits/byte, bucket 255.
        let mut c = EntropyCounter::new();
        for b in 0..=255u8 {
            c.update(&[b]);
        }
        assert!((c.entropy() - 8.0).abs() < 0.01);
        assert_eq!(c.bucket(), 255);
        assert_eq!(c.len(), 256);
    }

    #[test]
    fn repeated_byte_stream_has_zero_entropy() {
        let mut c = EntropyCounter::new();
        for _ in 0..1000 {
            c.update(&[0xAA]);
        }
        assert_eq!(c.entropy(), 0.0);
        assert_eq!(c.bucket(), 0);
    }

    #[test]
    fn empty_input_is_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(entropy_bucket(&[]), 0);
    }

    #[test]
    fn uniform_distribution_hits_max_bucket() {
        let data: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
        assert_eq!(entropy_bucket(&data), 255);
    }

    #[test]
    fn repeated_byte_has_zero_entropy() {
        let data = vec![0xAA; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
        assert_eq!(entropy_bucket(&data), 0);
    }

    #[test]
    fn equal_four_symbol_distribution_has_two_bits() {
        let data = [0, 1, 2, 3];
        assert!((shannon_entropy(&data) - 2.0).abs() < 0.001);
    }

    #[test]
    fn english_text_entropy_is_approx_four_and_a_half_bits() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let entropy = shannon_entropy(data);
        assert!(
            (entropy - 4.5).abs() < 0.2,
            "Fix: Shannon entropy for English text should be approximately 4.5 bits, got {entropy}"
        );
    }

    // The count-based closed form must agree with the naive per-probability
    // definition H = -Σ p log2 p to within fp tolerance on varied inputs.
    #[test]
    fn count_form_matches_naive_probability_form() {
        #[allow(clippy::cast_precision_loss)]
        fn naive(bytes: &[u8]) -> f64 {
            if bytes.is_empty() {
                return 0.0;
            }
            let mut freq = [0u64; 256];
            for &b in bytes {
                freq[usize::from(b)] += 1;
            }
            let len = bytes.len() as f64;
            let mut h = 0.0f64;
            for c in freq {
                if c != 0 {
                    let p = c as f64 / len;
                    h -= p * p.log2();
                }
            }
            h
        }
        let inputs: [&[u8]; 5] = [
            b"The quick brown fox jumps over the lazy dog",
            b"aabbccddeeffgghh",
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            b"aaaaaaaab",
            b"secret_api_key=AKIA1234567890ABCDEF",
        ];
        for data in inputs {
            let got = shannon_entropy(data);
            let want = naive(data);
            assert!(
                (got - want).abs() < 1e-9,
                "entropy mismatch for {data:?}: closed-form {got} vs naive {want}"
            );
        }
    }
}
    #[test]
    fn saturating_frequency_counter_does_not_overflow() {
        let mut c = EntropyCounter::new();
        // Simulate near-max count
        c.freq[65] = u64::MAX;
        c.update(b"A");
        assert_eq!(c.freq[65], u64::MAX);
    }
