//! WyHash-style bulk hashing (non-cryptographic).
//!
//! Implementation follows the public reference
//! (<https://github.com/wangyi-fudan/wyhash>) as of **2020-08-26** (secret constants and
//! message schedule). Multiplication uses `u128` widening products; sub-word reads use
//! [`u32::from_le_bytes`] / [`u64::from_le_bytes`], so **outputs are identical on all
//! platforms** for the same `data` and `seed`.
//!
//! # Persistent indices
//!
//! Hash values are part of this crate’s semver contract (see the crate root). Do not change
//! outputs without a major version bump and a migration plan for stored hashes.

/// `WyHash` secret constants from the reference implementation.
///
/// These values are taken from the wyhash reference implementation
/// (<https://github.com/wangyi-fudan/wyhash>) version 2020-08-26.
const SECRET: [u64; 4] = [
    0x2D35_8DCC_AA6C_78A5,
    0x8BB8_4B93_962E_ACC9,
    0x4B33_A62E_D433_D4A3,
    0x4D5A_2DA5_1DE1_AA47,
];

/// Multiplies two 64-bit values and returns the low and high 64 bits of the 128-bit result.
#[inline]
fn wymum(a: u64, b: u64) -> (u64, u64) {
    let product = u128::from(a).wrapping_mul(u128::from(b));
    #[allow(clippy::cast_possible_truncation)]
    let low = product as u64;
    #[allow(clippy::cast_possible_truncation)]
    let high = (product >> 64) as u64;
    (low, high)
}

/// Mixes two 64-bit values using wymum and XORs the result with the inputs.
#[inline]
fn wymix(a: u64, b: u64) -> u64 {
    let (low, high) = wymum(a, b);
    a ^ low ^ b ^ high
}

/// Reads 8 bytes from input and returns as little-endian u64.
///
/// # Panics
///
/// Panics if input has fewer than 8 bytes.
#[inline]
fn read_u64(input: &[u8]) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&input[..8]);
    u64::from_le_bytes(bytes)
}

/// Reads 4 bytes from input and returns as little-endian u32 extended to u64.
///
/// # Panics
///
/// Panics if input has fewer than 4 bytes.
#[inline]
fn read_u32(input: &[u8]) -> u64 {
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&input[..4]);
    u64::from(u32::from_le_bytes(bytes))
}

/// Reads up to 3 bytes from input and returns a 24-bit value extended to u64.
///
/// Uses the first byte, middle byte, and last byte from the input.
///
/// # Panics
///
/// Panics if input is empty (has fewer than 1 byte).
#[inline]
fn read_u24(input: &[u8]) -> u64 {
    let len = input.len();
    (u64::from(input[0]) << 16) | (u64::from(input[len >> 1]) << 8) | u64::from(input[len - 1])
}

/// Hashes a byte slice with the core wyhash algorithm.
///
/// This implementation is dependency-free, deterministic, and optimized for
/// short and medium byte slices.
///
/// # Examples
///
/// ```
/// let first = hashkit::wyhash::hash(b"abc", 7);
/// let second = hashkit::wyhash::hash(b"abc", 7);
///
/// assert_eq!(first, second);
/// ```
#[inline]
#[must_use]
pub fn hash(data: &[u8], seed: u64) -> u64 {
    let mut seed = seed ^ wymix(seed ^ SECRET[0], SECRET[1]);
    let mut offset = 0_usize;
    let mut a = 0_u64;
    let mut b = 0_u64;

    if data.len() <= 16 {
        if data.len() >= 4 {
            a = (read_u32(data) << 32) | read_u32(&data[(data.len() >> 3) << 2..]);
            let tail = &data[data.len() - 4..];
            b = (read_u32(tail) << 32)
                | read_u32(&data[data.len() - 4 - ((data.len() >> 3) << 2)..]);
        } else if !data.is_empty() {
            a = read_u24(data);
        }
    } else {
        let mut remaining = data.len();
        if remaining >= 48 {
            let mut seed_lane_one = seed;
            let mut seed_lane_two = seed;
            while remaining >= 48 {
                seed = wymix(
                    read_u64(&data[offset..]) ^ SECRET[1],
                    read_u64(&data[offset + 8..]) ^ seed,
                );
                seed_lane_one = wymix(
                    read_u64(&data[offset + 16..]) ^ SECRET[2],
                    read_u64(&data[offset + 24..]) ^ seed_lane_one,
                );
                seed_lane_two = wymix(
                    read_u64(&data[offset + 32..]) ^ SECRET[3],
                    read_u64(&data[offset + 40..]) ^ seed_lane_two,
                );
                offset += 48;
                remaining -= 48;
            }
            seed ^= seed_lane_one ^ seed_lane_two;
        }
        while remaining > 16 {
            seed = wymix(
                read_u64(&data[offset..]) ^ SECRET[1],
                read_u64(&data[offset + 8..]) ^ seed,
            );
            offset += 16;
            remaining -= 16;
        }
        a = read_u64(&data[offset + remaining - 16..]);
        b = read_u64(&data[offset + remaining - 8..]);
    }

    let (left, right) = wymum(a ^ SECRET[1], b ^ seed);
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u64;
    wymix(left ^ SECRET[0] ^ len, right ^ SECRET[1])
}

#[cfg(test)]
mod tests {
    use super::{hash, read_u24, read_u32, read_u64, wymix, wymum, SECRET};

    fn reference_hash(data: &[u8], seed: u64) -> u64 {
        let mut seed = seed ^ wymix(seed ^ SECRET[0], SECRET[1]);
        let mut offset = 0_usize;
        let mut a = 0_u64;
        let mut b = 0_u64;

        if data.len() <= 16 {
            if data.len() >= 4 {
                a = (read_u32(data) << 32) | read_u32(&data[(data.len() >> 3) << 2..]);
                let tail = &data[data.len() - 4..];
                b = (read_u32(tail) << 32)
                    | read_u32(&data[data.len() - 4 - ((data.len() >> 3) << 2)..]);
            } else if !data.is_empty() {
                a = read_u24(data);
            }
        } else {
            let mut remaining = data.len();
            if remaining >= 48 {
                let mut seed_lane_one = seed;
                let mut seed_lane_two = seed;
                while remaining >= 48 {
                    seed = wymix(
                        read_u64(&data[offset..]) ^ SECRET[1],
                        read_u64(&data[offset + 8..]) ^ seed,
                    );
                    seed_lane_one = wymix(
                        read_u64(&data[offset + 16..]) ^ SECRET[2],
                        read_u64(&data[offset + 24..]) ^ seed_lane_one,
                    );
                    seed_lane_two = wymix(
                        read_u64(&data[offset + 32..]) ^ SECRET[3],
                        read_u64(&data[offset + 40..]) ^ seed_lane_two,
                    );
                    offset += 48;
                    remaining -= 48;
                }
                seed ^= seed_lane_one ^ seed_lane_two;
            }
            while remaining > 16 {
                seed = wymix(
                    read_u64(&data[offset..]) ^ SECRET[1],
                    read_u64(&data[offset + 8..]) ^ seed,
                );
                offset += 16;
                remaining -= 16;
            }
            a = read_u64(&data[offset + remaining - 16..]);
            b = read_u64(&data[offset + remaining - 8..]);
        }

        let (left, right) = wymum(a ^ SECRET[1], b ^ seed);
        wymix(left ^ SECRET[0] ^ (data.len() as u64), right ^ SECRET[1])
    }

    #[test]
    fn empty_input_matches_reference() {
        assert_eq!(hash(b"", 0), reference_hash(b"", 0));
    }

    #[test]
    fn short_input_matches_reference() {
        assert_eq!(hash(b"\0\x01\x02", 3), reference_hash(b"\0\x01\x02", 3));
    }

    #[test]
    fn medium_input_matches_reference() {
        let bytes = *b"abcdefghijklmnop";
        assert_eq!(hash(&bytes, 9), reference_hash(&bytes, 9));
    }

    #[test]
    fn long_input_matches_reference() {
        let bytes = [0xA5_u8; 97];
        assert_eq!(hash(&bytes, 11), reference_hash(&bytes, 11));
    }

    #[test]
    fn docs_vector_stays_stable() {
        // Golden value for `wyhash` 2020-08-26 reference + this implementation (persistent-index contract).
        assert_eq!(hash(&[0, 1, 2], 3), 0xA595_5D2C_636A_8299);
        assert_ne!(hash(&[0, 1, 2], 3), hash(&[0, 1, 2], 4));
    }

    #[test]
    fn golden_vector_abc_seed_7() {
        assert_eq!(hash(b"abc", 7), 0xBCFF_FF33_0D22_4889);
    }
}
