//! Hex encoding and decoding primitives.
//!
//! Provides fast, dependency-free hex encoding and decoding.

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Error during hex decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input string has an odd length.
    OddLength,
    /// The input string contains an invalid character.
    InvalidCharacter {
        /// The invalid character.
        c: char,
        /// The index of the invalid character.
        index: usize,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength => write!(f, "odd number of digits in hex string"),
            Self::InvalidCharacter { c, index } => {
                write!(f, "invalid character `{c}` at index {index}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes a byte slice into a lowercase hex string.
///
/// # Examples
///
/// ```
/// let bytes = b"hello";
/// let hex = hashkit::hex::encode(bytes);
/// assert_eq!(hex, "68656c6c6f");
/// ```
#[inline]
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    out
}

/// Decodes a hex string into a vector of bytes.
///
/// Accepts both uppercase and lowercase characters.
///
/// # Errors
///
/// Returns a [`DecodeError`] if the input string has an odd length or contains
/// invalid hexadecimal characters.
///
/// # Examples
///
/// ```
/// let hex = "68656c6c6f";
/// let bytes = hashkit::hex::decode(hex);
/// assert_eq!(bytes, Ok(b"hello".to_vec()));
/// ```
#[inline]
pub fn decode(hex: &str) -> Result<Vec<u8>, DecodeError> {
    if hex.len() % 2 != 0 {
        return Err(DecodeError::OddLength);
    }

    // Iterate over BYTES, not chars. Hex is strictly ASCII, and the odd-length
    // guard above uses byte length -- iterating chars instead would let a
    // multibyte UTF-8 string with an even byte count but fewer chars (e.g. a
    // single 4-byte emoji) slip past the loop entirely and decode to an empty/
    // truncated `Ok`, silently accepting invalid hex. Byte iteration rejects any
    // non-ASCII byte via `val`.
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = val(bytes[i], i)?;
        let lo = val(bytes[i + 1], i + 1)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

#[inline]
fn val(c: u8, index: usize) -> Result<u8, DecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DecodeError::InvalidCharacter {
            c: c as char,
            index,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encode_decode_round_trip_all_byte_values() {
        for byte in 0..=255u8 {
            let bytes = vec![byte];
            let hex = encode(&bytes);
            let decoded = decode(&hex).expect("valid hex");
            assert_eq!(decoded, bytes, "round-trip failed for byte {byte}");

            let upper_hex = hex.to_uppercase();
            let decoded_upper = decode(&upper_hex).expect("valid uppercase hex");
            assert_eq!(
                decoded_upper, bytes,
                "uppercase round-trip failed for byte {byte}"
            );
        }
    }

    #[test]
    fn encode_decode_round_trip_all_bytes_together() {
        let all_bytes: Vec<u8> = (0..=255).collect();
        let hex = encode(&all_bytes);
        assert_eq!(hex.len(), 512);
        let decoded = decode(&hex).expect("valid hex");
        assert_eq!(decoded, all_bytes);
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(decode("a").is_err());
        assert!(decode("abc").is_err());
    }

    #[test]
    fn decode_rejects_invalid_characters() {
        assert!(decode("gg").is_err());
        assert!(decode("0g").is_err());
        assert!(decode("g0").is_err());
    }

    #[test]
    fn decode_rejects_non_ascii_multibyte() {
        // Regression: a multibyte UTF-8 string can have an even *byte* length but
        // a char count that made the old char-pair loop body never run, returning
        // a silent empty `Ok` instead of rejecting invalid hex.
        assert!(decode("🦀").is_err(), "single 4-byte emoji must be rejected");
        assert!(decode("é").is_err(), "2-byte char must be rejected");
        assert!(decode("aé").is_err(), "ascii+multibyte must be rejected");
        assert!(
            decode("🦀🦀").is_err(),
            "two emoji (8 bytes) must be rejected, not decoded to empty"
        );
        // And it must never silently succeed with empty output.
        assert_ne!(decode("🦀"), Ok(Vec::new()));
    }

    #[test]
    fn encode_decode_round_trip_all_single_byte_hex_strings() {
        for byte in 0..=255u8 {
            let hex = format!("{:02x}", byte);
            let decoded = decode(&hex).expect("valid lowercase hex");
            assert_eq!(decoded, vec![byte], "decode failed for {hex}");
            let reencoded = encode(&decoded);
            assert_eq!(reencoded, hex, "encode(decode({hex})) mismatch");

            let upper_hex = format!("{:02X}", byte);
            let decoded_upper = decode(&upper_hex).expect("valid uppercase hex");
            assert_eq!(decoded_upper, vec![byte], "decode failed for {upper_hex}");
            let reencoded_upper = encode(&decoded_upper);
            assert_eq!(
                reencoded_upper, hex,
                "encode(decode({upper_hex})) should produce lowercase"
            );
        }
    }
}
