//! Variable-length integer encoding and decoding
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses:
//! - 7 bits for the value
//! - 1 "continuation" bit to indicate if more bytes follow
//!
//! `u8` and `i8` are omitted since those types do not benefit from varint encoding.
//! `usize` and `isize` are omitted to prevent behavior from depending on the target architecture.

use crate::{EncodeSize, Error, FixedSize, Read, Write};
use bytes::{Buf, BufMut};
use std::{
    fmt::Debug,
    ops::{BitOrAssign, Shl, ShrAssign},
};

const BITS_PER_BYTE: usize = 8;
const DATA_BITS_PER_BYTE: usize = 7;
const DATA_BITS_MASK: u8 = 0x7F;
const CONTINUATION_BIT_MASK: u8 = 0x80;

/// A trait for unsigned integers that can be varint encoded.
pub trait UInt:
    Copy
    + From<u8>
    + Sized
    + FixedSize
    + ShrAssign<usize>
    + Shl<usize, Output = Self>
    + BitOrAssign<Self>
    + PartialOrd
    + Debug
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
pub trait SInt: Copy + Sized + FixedSize + PartialOrd + Debug {
    type UnsignedEquivalent: UInt;

    #[doc(hidden)]
    const _COMMIT_OP_ASSERT: () =
        assert!(std::mem::size_of::<Self>() == std::mem::size_of::<Self::UnsignedEquivalent>());

    /// Converts the signed integer to an unsigned integer using ZigZag encoding.
    fn as_zigzag(&self) -> Self::UnsignedEquivalent;

    /// Converts a (ZigZag'ed) unsigned integer back to a signed integer.
    fn un_zigzag(value: Self::UnsignedEquivalent) -> Self;
}

// Implements the `SInt` trait for all signed integer types.
macro_rules! impl_sint {
    ($type:ty, $utype:ty) => {
        impl SInt for $type {
            type UnsignedEquivalent = $utype;

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
impl_sint!(i16, u16);
impl_sint!(i32, u32);
impl_sint!(i64, u64);
impl_sint!(i128, u128);

/// Encodes an unsigned integer as a varint
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

/// Decodes a unsigned integer from a varint.
///
/// Returns an error if:
/// - The varint is invalid (too long or malformed)
/// - The buffer ends while reading
pub fn read<T: UInt>(buf: &mut impl Buf) -> Result<T, Error> {
    let max_bits = T::SIZE * BITS_PER_BYTE;
    let mut result: T = T::from(0);
    let mut bits_read = 0;

    // Loop over all the bytes.
    loop {
        // Read the next byte.
        if !buf.has_remaining() {
            return Err(Error::EndOfBuffer);
        }
        let byte = buf.get_u8();

        // If this is not the first byte, but the byte is completely zero, we have an invalid
        // varint. This is because this byte has no data bits and no continuation, so there was no
        // point in continuing to this byte in the first place. While the output could still result
        // in a valid value, we ensure that every value has exactly one unique, valid encoding.
        if byte == 0 && bits_read > 0 {
            return Err(Error::InvalidVarint(T::SIZE));
        }

        // If this must be the last byte, check for overflow (i.e. set bits beyond the size of T).
        // Because the continuation bit is the most-significant bit, this check also happens to
        // check for an invalid continuation bit.
        //
        // If we have reached what must be the last byte, this check prevents continuing to read
        // from the buffer by ensuring that the conditional (`if byte & CONTINUATION_BIT_MASK == 0`)
        // always evaluates to true.
        let remaining_bits = max_bits.checked_sub(bits_read).unwrap();
        if remaining_bits <= DATA_BITS_PER_BYTE {
            let relevant_bits = BITS_PER_BYTE - byte.leading_zeros() as usize;
            if relevant_bits > remaining_bits {
                return Err(Error::InvalidVarint(T::SIZE));
            }
        }

        // Write the 7 bits of data to the result.
        result |= T::from(byte & DATA_BITS_MASK) << bits_read;

        // If the continuation bit is not set, return.
        if byte & CONTINUATION_BIT_MASK == 0 {
            return Ok(result);
        }

        bits_read += DATA_BITS_PER_BYTE;
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
pub fn write_signed<S: SInt>(value: S, buf: &mut impl BufMut) {
    write(value.as_zigzag(), buf);
}

/// Decodes a signed integer from varint ZigZag encoding.
pub fn read_signed<S: SInt>(buf: &mut impl Buf) -> Result<S, Error> {
    Ok(S::un_zigzag(read(buf)?))
}

/// Calculates the number of bytes needed to encode a signed integer as a varint.
pub fn size_signed<S: SInt>(value: S) -> usize {
    size(value.as_zigzag())
}

/// An ergonomic wrapper to allow for encoding and decoding of primitive unsigned integers as
/// varints rather than the default fixed-width integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarUInt<U: UInt>(pub U);

// Implements `Into<U>` for `VarUInt<U>` for all unsigned integer types.
// This allows for easy conversion from `VarUInt<U>` to `U` using `.into()`.
macro_rules! impl_varuint_into {
    ($($type:ty),+) => {
        $(
            impl From<VarUInt<$type>> for $type {
                fn from(val: VarUInt<$type>) -> Self {
                    val.0
                }
            }
        )+
    };
}
impl_varuint_into!(u16, u32, u64, u128);

impl<U: UInt> Write for VarUInt<U> {
    fn write(&self, buf: &mut impl BufMut) {
        write(self.0, buf);
    }
}

impl<U: UInt> Read for VarUInt<U> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        read(buf).map(VarUInt)
    }
}

impl<U: UInt> EncodeSize for VarUInt<U> {
    fn encode_size(&self) -> usize {
        size(self.0)
    }
}

/// An ergonomic wrapper to allow for encoding and decoding of primitive signed integers as
/// varints rather than the default fixed-width integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarSInt<S: SInt>(pub S);

// Implements `Into<U>` for `VarSInt<U>` for all signed integer types.
// This allows for easy conversion from `VarSInt<S>` to `S` using `.into()`.
macro_rules! impl_varsint_into {
    ($($type:ty),+) => {
        $(
            impl From<VarSInt<$type>> for $type {
                fn from(val: VarSInt<$type>) -> Self {
                    val.0
                }
            }
        )+
    };
}
impl_varsint_into!(i16, i32, i64, i128);

impl<S: SInt> Write for VarSInt<S> {
    fn write(&self, buf: &mut impl BufMut) {
        write_signed::<S>(self.0, buf);
    }
}

impl<S: SInt> Read for VarSInt<S> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        read_signed::<S>(buf).map(VarSInt)
    }
}

impl<S: SInt> EncodeSize for VarSInt<S> {
    fn encode_size(&self) -> usize {
        size_signed::<S>(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::Error, DecodeExt, Encode};
    use bytes::Bytes;

    #[test]
    fn test_end_of_buffer() {
        let mut buf: Bytes = Bytes::from_static(&[]);
        assert!(matches!(read::<u32>(&mut buf), Err(Error::EndOfBuffer)));

        let mut buf: Bytes = Bytes::from_static(&[0x80, 0x8F]);
        assert!(matches!(read::<u32>(&mut buf), Err(Error::EndOfBuffer)));

        let mut buf: Bytes = Bytes::from_static(&[0x80, 0x8F]);
        assert!(matches!(read::<u32>(&mut buf), Err(Error::EndOfBuffer)));

        let mut buf: Bytes = Bytes::from_static(&[0xFF, 0x8F]);
        assert!(matches!(read::<u32>(&mut buf), Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_overflow() {
        let mut buf: Bytes = Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        assert_eq!(read::<u32>(&mut buf).unwrap(), u32::MAX);

        let mut buf: Bytes = Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        assert!(matches!(
            read::<u32>(&mut buf),
            Err(Error::InvalidVarint(u32::SIZE))
        ));

        let mut buf =
            Bytes::from_static(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
        assert!(matches!(
            read::<u64>(&mut buf),
            Err(Error::InvalidVarint(u64::SIZE))
        ));
    }

    #[test]
    fn test_overcontinuation() {
        let mut buf: Bytes = Bytes::from_static(&[0x80, 0x80, 0x80, 0x80, 0x80]);
        let result = read::<u32>(&mut buf);
        assert!(matches!(result, Err(Error::InvalidVarint(u32::SIZE))));
    }

    #[test]
    fn test_zeroed_byte() {
        let mut buf = Bytes::from_static(&[0xFF, 0x00]);
        let result = read::<u64>(&mut buf);
        assert!(matches!(result, Err(Error::InvalidVarint(u64::SIZE))));
    }

    /// Core round-trip check, generic over any UInt.
    fn varuint_round_trip<T: Copy + UInt + TryFrom<u128>>() {
        const CASES: &[u128] = &[
            0,
            1,
            127,
            128,
            129,
            0xFF,
            0x100,
            0x3FFF,
            0x4000,
            0x1_FFFF,
            0xFF_FFFF,
            0x1_FF_FF_FF_FF,
            0xFF_FF_FF_FF_FF_FF,
            0x1_FF_FF_FF_FF_FF_FF_FF_FF_FF_FF_FF_FF,
            u16::MAX as u128,
            u32::MAX as u128,
            u64::MAX as u128,
            u128::MAX,
        ];

        for &raw in CASES {
            // skip values that don't fit into T
            let Ok(value) = raw.try_into() else { continue };
            let value: T = value;

            // size matches encoding length
            let mut buf = Vec::new();
            write(value, &mut buf);
            assert_eq!(buf.len(), size(value));

            // decode matches original value
            let mut slice = &buf[..];
            let decoded: T = read(&mut slice).unwrap();
            assert_eq!(decoded, value);
            assert!(slice.is_empty());

            // VarUInt wrapper
            let encoded = VarUInt(value).encode();
            assert_eq!(VarUInt::<T>::decode(encoded).unwrap(), VarUInt(value));
        }
    }

    #[test]
    fn test_varuint() {
        varuint_round_trip::<u16>();
        varuint_round_trip::<u32>();
        varuint_round_trip::<u64>();
        varuint_round_trip::<u128>();
    }

    fn varsint_round_trip<T: Copy + SInt + TryFrom<i128>>() {
        const CASES: &[i128] = &[
            0,
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
            0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            -0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            i16::MIN as i128,
            i16::MAX as i128,
            i32::MIN as i128,
            i32::MAX as i128,
            i64::MIN as i128,
            i64::MAX as i128,
        ];

        for &raw in CASES {
            // skip values that don't fit into T
            let Ok(value) = raw.try_into() else { continue };
            let value: T = value;

            // size matches encoding length
            let mut buf = Vec::new();
            write_signed(value, &mut buf);
            assert_eq!(buf.len(), size_signed(value));

            // decode matches original value
            let mut slice = &buf[..];
            let decoded: T = read_signed(&mut slice).unwrap();
            assert_eq!(decoded, value);
            assert!(slice.is_empty());

            // VarSInt wrapper
            let encoded = VarSInt(value).encode();
            assert_eq!(VarSInt::<T>::decode(encoded).unwrap(), VarSInt(value));
        }
    }

    #[test]
    fn test_varsint() {
        varsint_round_trip::<i16>();
        varsint_round_trip::<i32>();
        varsint_round_trip::<i64>();
        varsint_round_trip::<i128>();
    }
}
