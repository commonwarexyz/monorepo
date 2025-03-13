//! Variable-length integer encoding and decoding
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses 7 bits for the value and 1 bit to indicate if more bytes follow.

use crate::error::Error;
use bytes::{Buf, BufMut};

/// Maximum number of bytes needed to encode a 64-bit integer as a varint
pub const MAX_VARINT_LEN_U64: usize = 10;

/// Maximum number of bytes needed to encode a 32-bit integer as a varint
pub const MAX_VARINT_LEN_U32: usize = 5;

/// Encodes a unsigned 64-bit integer as a varint
pub fn encode_varint(value: u64, buf: &mut impl BufMut) {
    if value < 0x80 {
        // Fast path for small values (common case for lengths)
        buf.put_u8(value as u8);
        return;
    }

    let mut val = value;
    while val >= 0x80 {
        buf.put_u8((val as u8) | 0x80);
        val >>= 7;
    }
    buf.put_u8(val as u8);
}

/// Decodes a unsigned 64-bit integer from a varint
pub fn decode_varint(buf: &mut impl Buf) -> Result<u64, Error> {
    let mut result = 0u64;
    let mut shift = 0;

    loop {
        if !buf.has_remaining() {
            return Err(Error::EndOfBuffer);
        }

        let byte = buf.get_u8();
        if shift > 63 && byte > 1 {
            return Err(Error::InvalidVarint);
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            return Ok(result);
        }

        shift += 7;

        if shift > 63 {
            // We've read 9 bytes but still have the continuation bit set,
            // which would push our value beyond the range of u64
            if buf.has_remaining() && buf.get_u8() & 0x80 != 0 {
                return Err(Error::InvalidVarint);
            }
            return Ok(result);
        }
    }
}

/// Calculates the number of bytes needed to encode a value as a varint
pub fn varint_size(value: u64) -> usize {
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1FFFFF => 3,
        0x200000..=0xFFFFFFF => 4,
        0x10000000..=0x7FFFFFFFF => 5,
        0x800000000..=0x3FFFFFFFFFF => 6,
        0x40000000000..=0x1FFFFFFFFFFFF => 7,
        0x2000000000000..=0xFFFFFFFFFFFFFF => 8,
        0x100000000000000..=0x7FFFFFFFFFFFFFFF => 9,
        _ => 10,
    }
}

/// Encodes a unsigned 32-bit integer as a varint (more efficient than u64 version)
pub fn encode_varint_u32(value: u32, buf: &mut impl BufMut) {
    if value < 0x80 {
        // Fast path for small values
        buf.put_u8(value as u8);
        return;
    }

    let mut val = value;
    while val >= 0x80 {
        buf.put_u8((val as u8) | 0x80);
        val >>= 7;
    }
    buf.put_u8(val as u8);
}

/// Encodes a signed 64-bit integer as a varint using ZigZag encoding
pub fn encode_varint_i64(value: i64, buf: &mut impl BufMut) {
    // Convert to ZigZag encoding
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    encode_varint(zigzag, buf);
}

/// Decodes a signed 64-bit integer from a varint using ZigZag encoding
pub fn decode_varint_i64(buf: &mut impl Buf) -> Result<i64, Error> {
    let zigzag = decode_varint(buf)?;
    // Convert from ZigZag encoding
    Ok(((zigzag >> 1) as i64) ^ (-((zigzag & 1) as i64)))
}

/// Encodes a signed 32-bit integer as a varint using ZigZag encoding
pub fn encode_varint_i32(value: i32, buf: &mut impl BufMut) {
    // Convert to ZigZag encoding
    let zigzag = ((value << 1) ^ (value >> 31)) as u32;
    encode_varint_u32(zigzag, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use bytes::Bytes;

    #[test]
    fn test_varint_encoding() {
        let test_cases = [
            0u64,
            1,
            127,
            128,
            129,
            0xFF,
            0x100,
            0x3FFF,
            0x4000,
            0x1FFFFF,
            0xFFFFFF,
            0x1FFFFFFF,
            0xFFFFFFFF,
            0x1FFFFFFFFFF,
            0xFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ];

        for &value in &test_cases {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);

            assert_eq!(buf.len(), varint_size(value));

            let mut read_buf = &buf[..];
            let decoded = decode_varint(&mut read_buf).unwrap();

            assert_eq!(decoded, value, "Failed for value: {}", value);
            assert_eq!(
                read_buf.len(),
                0,
                "Not all bytes consumed for value: {}",
                value
            );
        }
    }

    #[test]
    fn test_zigzag_encoding() {
        let test_cases = [
            0i64,
            1,
            -1,
            2,
            -2,
            127,
            -127,
            128,
            -128,
            129,
            -129,
            0x7FFFFFFF,
            -0x7FFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            -0x7FFFFFFFFFFFFFFF,
        ];

        for &value in &test_cases {
            let mut buf = Vec::new();
            encode_varint_i64(value, &mut buf);

            let mut read_buf = &buf[..];
            let decoded = decode_varint_i64(&mut read_buf).unwrap();

            assert_eq!(decoded, value, "Failed for value: {}", value);
            assert_eq!(
                read_buf.len(),
                0,
                "Not all bytes consumed for value: {}",
                value
            );
        }
    }

    #[test]
    fn test_varint_small_values() {
        let values = [0u64, 1u64, 127u64];
        for value in values {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let mut read_buf = Bytes::from(buf);
            let decoded = decode_varint(&mut read_buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(read_buf.len(), 0);
        }
    }

    #[test]
    fn test_varint_multi_byte() {
        let values = [128u64, 300u64, u64::MAX];
        for value in values {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let mut read_buf = Bytes::from(buf);
            let decoded = decode_varint(&mut read_buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(read_buf.len(), 0);
        }
    }

    #[test]
    fn test_varint_insufficient_buffer() {
        let mut buf = Bytes::from_static(&[0x80]); // Incomplete varint
        assert!(matches!(decode_varint(&mut buf), Err(Error::EndOfBuffer)));
    }
}
