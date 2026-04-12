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
#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in bytes {
        freq[usize::from(byte)] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for count in freq {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
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
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn entropy_bucket(bytes: &[u8]) -> u8 {
    let entropy = shannon_entropy(bytes);
    let normalized = (entropy / 8.0).clamp(0.0, 1.0);
    (normalized * 255.0).round() as u8
}

#[cfg(test)]
mod tests {
    use super::{entropy_bucket, shannon_entropy};

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
}
