//! FNV-1a hashing helpers.

/// Official 64-bit FNV-1a offset basis constant.
///
/// This value is defined in the FNV-1a specification:
/// <http://www.isthe.com/chongo/tech/comp/fnv/index.html>
pub const OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;

/// Official 64-bit FNV-1a prime constant.
///
/// This value is defined in the FNV-1a specification:
/// <http://www.isthe.com/chongo/tech/comp/fnv/index.html>
pub const PRIME: u64 = 0x0000_0100_0000_01B3;

/// Computes the 64-bit FNV-1a hash of a byte slice.
///
/// This uses the exact constants already used by `flashsieve`.
///
/// # Examples
///
/// ```
/// assert_eq!(hashkit::fnv::fnv1a_64(b""), 0xCBF2_9CE4_8422_2325);
/// ```
#[inline]
#[must_use]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Computes the flashsieve-compatible 64-bit FNV-1a hash for exactly two bytes.
///
/// This avoids slice iteration overhead in the hot path for bloom-filter n-gram
/// hashing.
///
/// # Examples
///
/// ```
/// let pair = hashkit::fnv::fnv1a_pair(b'a', b'b');
///
/// assert_eq!(pair, hashkit::fnv::fnv1a_64(b"ab"));
/// ```
#[inline]
#[must_use]
pub const fn fnv1a_pair(a: u8, b: u8) -> u64 {
    let mut hash = OFFSET_BASIS;
    hash ^= a as u64;
    hash = hash.wrapping_mul(PRIME);
    hash ^= b as u64;
    hash.wrapping_mul(PRIME)
}

#[cfg(test)]
mod tests {
    use super::{fnv1a_64, fnv1a_pair, OFFSET_BASIS, PRIME};

    #[test]
    fn constants_match_flashsieve() {
        assert_eq!(OFFSET_BASIS, 0xCBF2_9CE4_8422_2325);
        assert_eq!(PRIME, 0x0000_0100_0000_01B3);
    }

    #[test]
    fn empty_input_matches_offset_basis() {
        assert_eq!(fnv1a_64(b""), OFFSET_BASIS);
    }

    #[test]
    fn known_vector_a_matches_reference() {
        assert_eq!(fnv1a_64(b"a"), 0xAF63_DC4C_8601_EC8C);
    }

    #[test]
    fn known_vector_foobar_matches_reference() {
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_F739_67E8);
    }

    #[test]
    fn pair_matches_slice_hash() {
        assert_eq!(fnv1a_pair(b'x', b'y'), fnv1a_64(b"xy"));
    }

    #[test]
    fn pair_distinguishes_order() {
        assert_ne!(fnv1a_pair(b'a', b'b'), fnv1a_pair(b'b', b'a'));
    }
}
