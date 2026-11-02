//! Text encoding of keys and blobs (vv-01 §3.2).

use data_encoding::{DecodeKind, Encoding};
use data_encoding_macro::new_encoding;

use crate::error::EncodingError;

/// RFC 4648 §6 alphabet in lowercase, no padding; upper case is accepted when decoding, and
/// non-zero trailing bits are rejected.
const BASE32: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz234567",
    translate_from: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    translate_to: "abcdefghijklmnopqrstuvwxyz",
};

/// Encodes bytes as lowercase unpadded base32.
pub fn encode(data: &[u8]) -> String {
    BASE32.encode(data)
}

/// Decodes base32 in any letter case, rejecting everything vv-01 §3.2 forbids.
pub fn decode(text: &str) -> Result<Vec<u8>, EncodingError> {
    BASE32.decode(text.as_bytes()).map_err(|e| match e.kind {
        DecodeKind::Length => EncodingError::InvalidLength,
        DecodeKind::Trailing => EncodingError::TrailingBits,
        DecodeKind::Symbol | DecodeKind::Padding => EncodingError::InvalidCharacter,
    })
}

/// Decodes a fixed-size value, rejecting any other length.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], EncodingError> {
    if text.len() != (N * 8).div_ceil(5) {
        return Err(EncodingError::WrongSize);
    }
    decode(text)?
        .try_into()
        .map_err(|_| EncodingError::WrongSize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_lengths() {
        for n in 0..70usize {
            let data: Vec<u8> = (0..n as u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }

    fn reference_decode(text: &str) -> Result<Vec<u8>, EncodingError> {
        let bytes = text.as_bytes();
        if matches!(bytes.len() % 8, 1 | 3 | 6) {
            return Err(EncodingError::InvalidLength);
        }
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
        for &c in bytes {
            let v = match c {
                b'a'..=b'z' => c - b'a',
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return Err(EncodingError::InvalidCharacter),
            };
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        if acc != 0 {
            return Err(EncodingError::TrailingBits);
        }
        Ok(out)
    }

    #[test]
    fn agrees_with_the_reference_on_short_strings() {
        let alphabet = ['a', 'A', 'q', 'Z', '7', '2', '=', ' ', '0', '\u{e9}'];
        let mut words = vec![String::new()];
        for _ in 0..5 {
            let longer: Vec<String> = words
                .iter()
                .flat_map(|w| alphabet.iter().map(move |c| format!("{w}{c}")))
                .collect();
            for w in &longer {
                assert_eq!(decode(w), reference_decode(w), "{w:?}");
            }
            words = longer;
        }
        for w in [
            "aaaaaaaa",
            "AAAAAAAa",
            "aaaaaaaa=",
            "me",
            "mz",
            "myyyyyyy",
            "mzzzzzzz",
        ] {
            assert_eq!(decode(w), reference_decode(w), "{w:?}");
        }
    }

    #[test]
    fn rejects_non_ascii_without_panic() {
        assert!(decode("m\u{fd}").is_err());
        assert!(decode_array::<32>("é").is_err());
    }
}
