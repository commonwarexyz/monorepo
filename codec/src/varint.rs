//! Variable-length integer encoding and decoding
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses 7 bits for the value and 1 bit to indicate if more bytes follow.

use crate::error::Error;
use bytes::{Buf, BufMut};

fn must_u64<T: TryInto<u64>>(value: T) -> u64 {
    value
        .try_into()
        .unwrap_or_else(|_| panic!("Failed to convert to u64"))
}

fn must_i64<T: TryInto<i64>>(value: T) -> i64 {
    value
        .try_into()
        .unwrap_or_else(|_| panic!("Failed to convert to i64"))
}

/// Encodes a unsigned 64-bit integer as a varint
pub fn write<T: TryInto<u64>>(value: T, buf: &mut impl BufMut) {
    let value = must_u64(value);

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
pub fn read<T: TryFrom<u64>>(buf: &mut impl Buf) -> Result<T, Error> {
    let mut result = 0u64;
    let mut shift = 0;

    // Loop over all the bytes.
    loop {
        // Read the next byte.
        if !buf.has_remaining() {
            return Err(Error::EndOfBuffer);
        }
        let byte = buf.get_u8();

        // If we have read more than 9 bytes, the next byte must be 0 or 1.
        if shift >= (9 * 7) && byte > 1 {
            return Err(Error::InvalidVarint);
        }

        // Write the 7 bits of data to the result.
        result |= ((byte & 0x7F) as u64) << shift;

        // If the continuation bit is not set, return.
        if byte & 0x80 == 0 {
            return result.try_into().map_err(|_| Error::InvalidVarint);
        }

        // Each byte has 7 bits of data.
        shift += 7;
    }
}

/// Calculates the number of bytes needed to encode a value as a varint
pub fn size<T: TryInto<u64>>(value: T) -> usize {
    let value = must_u64(value);
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

/// Converts a signed integer to an unsigned integer using ZigZag encoding
fn to_u64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

/// Converts an unsigned integer to a signed integer using ZigZag encoding
fn to_i64(value: u64) -> i64 {
    ((value >> 1) as i64) ^ (-((value & 1) as i64))
}

/// Encodes a signed 64-bit integer as a varint using ZigZag encoding
pub fn write_i64<T: TryInto<i64>>(value: T, buf: &mut impl BufMut) {
    let value = must_i64(value);
    write(to_u64(value), buf);
}

/// Decodes a signed 64-bit integer from a varint using ZigZag encoding
pub fn read_i64<T: TryFrom<i64>>(buf: &mut impl Buf) -> Result<T, Error> {
    let zigzag = read(buf)?;
    to_i64(zigzag).try_into().map_err(|_| Error::InvalidVarint)
}

/// Calculates the number of bytes needed to encode a signed integer as a varint
pub fn size_i64(value: i64) -> usize {
    size(to_u64(value))
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
            u64::MAX,
        ];

        for &value in &test_cases {
            let mut buf = Vec::new();
            write(value, &mut buf);

            assert_eq!(buf.len(), size(value));

            let mut read_buf = &buf[..];
            let decoded: u64 = read(&mut read_buf).unwrap();

            assert_eq!(decoded, value);
            assert_eq!(read_buf.len(), 0);
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
            i64::MIN,
            i64::MAX,
        ];

        for &value in &test_cases {
            let mut buf = Vec::new();
            write_i64(value, &mut buf);

            assert_eq!(buf.len(), size_i64(value));

            let mut read_buf = &buf[..];
            let decoded = read_i64::<i64>(&mut read_buf).unwrap();

            assert_eq!(decoded, value);
            assert_eq!(read_buf.len(), 0,);
        }
    }

    #[test]
    fn test_varint_insufficient_buffer() {
        let mut buf = Bytes::from_static(&[0x80]);
        assert!(matches!(read::<u64>(&mut buf), Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_varint_invalid() {
        let mut buf =
            Bytes::from_static(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
        assert!(matches!(read::<u64>(&mut buf), Err(Error::InvalidVarint)));
    }
}
