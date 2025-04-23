//! Variable-length integer encoding and decoding
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses:
//! - 7 bits for the value
//! - 1 "continuation" bit to indicate if more bytes follow
//! 
//! `usize` and `isize` are omitted to prevent behavior from depending on the target architecture.

use crate::{EncodeSize, Error, Read, Write};
use bytes::{Buf, BufMut};
use std::ops::{BitOrAssign, Shl, ShrAssign};

const BITS_PER_BYTE: usize = 8;
const DATA_BITS_PER_BYTE: usize = 7;
const DATA_BITS_MASK: u8 = 0x7F;
const CONTINUATION_BIT_MASK: u8 = 0x80;

/// A trait for unsigned integers that can be varint encoded.
pub trait UInt:
    Copy
    + From<u8>
    + Sized
    + ShrAssign<usize>
    + Shl<usize, Output = Self>
    + BitOrAssign<Self>
    + PartialOrd
{
    /// Returns the number of leading zeros in the integer.
    fn leading_zeros(self) -> u32;

    /// Returns the least significant byte of the integer.
    fn as_u8(self) -> u8;
}

// Implements the `UInt` trait for all unsigned integer types.
macro_rules! impl_uint {
    ($type:ty) => {
        impl UInt for $type {
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
impl_uint!(u8);
impl_uint!(u16);
impl_uint!(u32);
impl_uint!(u64);
impl_uint!(u128);

/// A trait for signed integers that can be converted to and from unsigned integers of the
/// equivalent size.
///
/// When converted to unsigned integers, the encoding is done using ZigZag encoding, which moves the
/// sign bit to the least significant bit (shifting all other bits to the left by one). This allows
/// for more efficient encoding of numbers that are close to zero, even if they are negative.
pub trait SInt<UEq: UInt> {
    /// Converts the signed integer to an unsigned integer using ZigZag encoding.
    fn as_zigzag(&self) -> UEq;

    /// Converts a (ZigZag'ed) unsigned integer back to a signed integer.
    fn un_zigzag(value: UEq) -> Self;
}

// Implements the `SInt` trait for all signed integer types.
macro_rules! impl_sint {
    ($type:ty, $utype:ty) => {
        impl SInt<$utype> for $type {
            #[inline]
            fn as_zigzag(&self) -> $utype {
                let shr = std::mem::size_of::<$utype>() * 8 - 1;
                ((self << 1) ^ (self >> shr)) as $utype
            }
            #[inline]
            fn un_zigzag(value: $utype) -> Self {
                ((value >> 1) as $type) ^ (-((value & 1) as $type))
            }
        }
    };
}
impl_sint!(i8, u8);
impl_sint!(i16, u16);
impl_sint!(i32, u32);
impl_sint!(i64, u64);
impl_sint!(i128, u128);

/// Encodes a unsigned 64-bit integer as a varint
pub fn write<T: UInt>(value: T, buf: &mut impl BufMut) {
    let continuation_threshold = T::from(CONTINUATION_BIT_MASK);
    if value < continuation_threshold {
        // Fast path for small values (common case for lengths).
        // `as_u8()` does not truncate the value or leave a continuation bit.
        buf.put_u8(value.as_u8());
        return;
    }

    let mut val = value;
    while val >= continuation_threshold {
        buf.put_u8((val.as_u8()) | CONTINUATION_BIT_MASK);
        val >>= 7;
    }
    buf.put_u8(val.as_u8());
}

/// Decodes a unsigned 64-bit integer from a varint
pub fn read<T: UInt>(buf: &mut impl Buf) -> Result<T, Error> {
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

        // If this must be the last byte, check for overflow (i.e. set bits beyond the size of T).
        // Because the continuation bit is the most-significant bit, this check also happens to
        // check for an invalid continuation bit.
        // 
        // If we have reached what must be the last byte, this check prevents continuing to read
        // from the buffer by ensuring that the conditional (`if byte & CONTINUATION_BIT_MASK == 0`)
        // always evaluates to true.
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

/// Calculates the number of bytes needed to encode an unsigned integer as a varint.
pub fn size<T: UInt>(value: T) -> usize {
    let total_bits = std::mem::size_of::<T>() * 8;
    let leading_zeros = value.leading_zeros() as usize;
    let data_bits = total_bits - leading_zeros;
    usize::max(1, data_bits.div_ceil(DATA_BITS_PER_BYTE))
}

/// Encodes a signed integer as a varint using ZigZag encoding.
pub fn write_signed<U: UInt, S: SInt<U>>(value: S, buf: &mut impl BufMut) {
    write(value.as_zigzag(), buf);
}

/// Decodes a signed integer from ZigZag encoding
pub fn read_signed<U: UInt, S: SInt<U>>(buf: &mut impl Buf) -> Result<S, Error> {
    Ok(S::un_zigzag(read(buf)?))
}

/// Calculates the number of bytes needed to encode a signed integer as a varint.
pub fn size_signed<U: UInt, S: SInt<U>>(value: S) -> usize {
    size(value.as_zigzag())
}

/// An ergonomic wrapper to allow for encoding and decoding of primitive unsigned integers as
/// varints rather than the default fixed-width integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UVar<T: UInt>(pub T);

impl<T: UInt> UVar<T> {
    /// Reads a varint from the buffer and returns it as its original (primitive) type.
    pub fn read_into(buf: &mut impl Buf) -> Result<T, Error> {
        read::<T>(buf)
    }
}

impl<T: UInt> Write for UVar<T> {
    fn write(&self, buf: &mut impl BufMut) {
        write(self.0, buf);
    }
}

impl<T: UInt> Read for UVar<T> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        read(buf).map(UVar)
    }
}

impl<T: UInt> EncodeSize for UVar<T> {
    fn encode_size(&self) -> usize {
        size(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use bytes::Bytes;

    #[test]
    fn test_temp() {
        let val1 = read::<u8>(&mut &[0x81, 0x01][..]);
        assert_eq!(val1.unwrap(), 0x81);

        let val2 = read::<u8>(&mut &[0x01][..]);
        assert_eq!(val2.unwrap(), 0x01);

        let val1 = read::<u8>(&mut &[0xAC, 0x02][..]);
        assert_eq!(val1.unwrap(), 0xAC);
    }

    /// A 6-byte varint whose continuation bit never terminates:
    /// 0xFF 0xFF 0xFF 0xFF 0xFF 0x01
    const OVERLONG_U32: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn overlong_varint_panics() {
        // Wrap the test data in a `Bytes` buffer (implements `Buf`)
        let mut buf: Bytes = Bytes::from_static(&OVERLONG_U32);

        // This line panics inside `read::<u32>` due to the `unwrap()`
        let _ = read::<u32>(&mut buf);
    }

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
            write_signed(value, &mut buf);

            assert_eq!(buf.len(), size_signed(value));

            let mut read_buf = &buf[..];
            let decoded = read_signed::<u64, i64>(&mut read_buf).unwrap();

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
