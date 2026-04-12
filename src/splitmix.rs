//! `SplitMix64` finalization helpers.

const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const MIX1: u64 = 0xBF58_476D_1CE4_E5B9;
const MIX2: u64 = 0x94D0_49BB_1331_11EB;

/// Applies the `SplitMix64` finalizer to a seed.
///
/// # Examples
///
/// ```
/// assert_eq!(hashkit::splitmix::finalize(0), 0xE220_A839_7B1D_CDAF_u64);
/// ```
#[inline]
#[must_use]
pub const fn finalize(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(GAMMA);
    z = (z ^ (z >> 30)).wrapping_mul(MIX1);
    z = (z ^ (z >> 27)).wrapping_mul(MIX2);
    z ^ (z >> 31)
}

/// Hashes a two-byte pair through the `SplitMix64` finalizer.
///
/// # Examples
///
/// ```
/// let hash = hashkit::splitmix::pair(b'a', b'b');
///
/// assert_eq!(hash, hashkit::splitmix::finalize(0x6162));
/// ```
#[inline]
#[must_use]
pub const fn pair(a: u8, b: u8) -> u64 {
    finalize(((a as u64) << 8) | (b as u64))
}

#[cfg(test)]
mod tests {
    use super::{finalize, pair};

    fn differing_bits(a: u64, b: u64) -> u32 {
        (a ^ b).count_ones()
    }

    #[test]
    fn zero_seed_matches_reference() {
        assert_eq!(finalize(0), 0xE220_A839_7B1D_CDAF);
    }

    #[test]
    fn seed_one_matches_reference() {
        assert_eq!(finalize(1), 0x910A_2DEC_8902_5CC1);
    }

    #[test]
    fn gamma_seed_matches_reference() {
        // GAMMA (0x9E3779B97F4A7C15) is a well-known seed for SplitMix64:
        assert_eq!(finalize(0x9E37_79B9_7F4A_7C15), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn pair_maps_to_seed_finalization() {
        assert_eq!(pair(b'a', b'b'), finalize(0x6162));
    }

    #[test]
    fn finalize_has_strong_single_bit_avalanche() {
        let base = finalize(0x0123_4567_89AB_CDEF);
        let flipped = finalize(0x0123_4567_89AB_CDEE);
        assert!(differing_bits(base, flipped) >= 24);
    }

    #[test]
    fn finalize_has_strong_high_bit_avalanche() {
        let base = finalize(0x0123_4567_89AB_CDEF);
        let flipped = finalize(0x8123_4567_89AB_CDEF);
        assert!(differing_bits(base, flipped) >= 24);
    }

    #[test]
    fn pair_distinguishes_order() {
        assert_ne!(pair(b'a', b'b'), pair(b'b', b'a'));
    }
}
