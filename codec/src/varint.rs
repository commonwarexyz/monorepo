//! Variable-length integer encoding and decoding
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses 7 bits for the value and 1 bit to indicate if more bytes follow.

use crate::error::Error;
use bytes::{Buf, BufMut};
use std::ops::{BitOrAssign, Shl, ShrAssign};

const BITS_PER_BYTE: usize = 8;
const DATA_BITS_PER_BYTE: usize = 7;
const DATA_BITS_MASK: u8 = 0x7F;
const CONTINUATION_BIT_MASK: u8 = 0x80;

pub trait UnsignedVarint:
    Copy
    + TryFrom<u64>
    + From<u8>
    + Sized
    + ShrAssign<usize>
    + Shl<usize, Output = Self>
    + BitOrAssign<Self>
    + PartialOrd
{
    fn leading_zeros(self) -> u32;
    fn as_u8(self) -> u8;
}

macro_rules! impl_unsigned_varint {
    ($type:ty) => {
        impl UnsignedVarint for $type {
            #[inline]
            fn leading_zeros(self) -> u32 {
                self.leading_zeros()
            }

            #[inline]
            fn as_u8(self) -> u8 {
                self as u8
            }
        }
    };
}
impl_unsigned_varint!(usize);
impl_unsigned_varint!(u8);
impl_unsigned_varint!(u16);
impl_unsigned_varint!(u32);
impl_unsigned_varint!(u64);
impl_unsigned_varint!(u128);

fn must_i64<T: TryInto<i64>>(value: T) -> i64 {
    value
        .try_into()
        .unwrap_or_else(|_| panic!("Failed to convert to i64"))
}

/// Encodes a unsigned 64-bit integer as a varint
pub fn write<T: UnsignedVarint>(value: T, buf: &mut impl BufMut) {
    let bm = T::from(CONTINUATION_BIT_MASK);
    if value < bm {
        // Fast path for small values (common case for lengths)
        buf.put_u8(value.as_u8());
        return;
    }

    let mut val = value;
    while val >= bm {
        buf.put_u8((val.as_u8()) | 0x80);
        val >>= 7;
    }
    buf.put_u8(val.as_u8());
}

/// Decodes a unsigned 64-bit integer from a varint
pub fn read<T: UnsignedVarint>(buf: &mut impl Buf) -> Result<T, Error> {
    let max_bits = std::mem::size_of::<T>() * 8;
    let mut result: T = T::from(0);
    let mut shift = 0;

    // Loop over all the bytes.
    loop {
        // Read the next byte.
        if !buf.has_remaining() {
            return Err(Error::EndOfBuffer);
        }
        let byte = buf.get_u8();

        // If this must be the last byte, check for overflow.
        // This overflow check also checks for an invalid continuation bit.
        let remaining_bits = max_bits.checked_sub(shift).unwrap();
        if remaining_bits <= DATA_BITS_PER_BYTE {
            let relevant_bits = BITS_PER_BYTE - byte.leading_zeros() as usize;
            if relevant_bits > remaining_bits {
                return Err(Error::InvalidVarint);
            }
        }

        // Write the 7 bits of data to the result.
        result |= T::from(byte & DATA_BITS_MASK) << shift;

        // If the continuation bit is not set, return.
        if byte & CONTINUATION_BIT_MASK == 0 {
            return Ok(result);
        }

        // Each byte has 7 bits of data.
        shift += DATA_BITS_PER_BYTE;
    }
}

/// Calculates the number of bytes needed to encode a value as a varint
pub fn size<T: UnsignedVarint>(value: T) -> usize {
    let total_bits = std::mem::size_of::<T>() * 8;
    let leading_zeros = value.leading_zeros() as usize;
    let data_bits = total_bits - leading_zeros;
    usize::max(1, data_bits / DATA_BITS_PER_BYTE)
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
