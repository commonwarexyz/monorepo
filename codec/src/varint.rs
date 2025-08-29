//! Variable-length integer encoding and decoding
//!
//! # Overview
//!
//! This module implements Google's Protocol Buffers variable-length integer encoding.
//! Each byte uses:
//! - 7 bits for the value
//! - 1 "continuation" bit to indicate if more bytes follow
//!
//! `u8` and `i8` are omitted since those types do not benefit from varint encoding.
//!
//! `usize` and `isize` are omitted to prevent behavior from depending on the target architecture.
//!
//! # Usage Example
//!
//! ```rust
//! use commonware_codec::{Encode, DecodeExt, varint::{UInt, SInt}};
//!
//! // Unsigned example
//! let one = UInt(42u128).encode();
//! assert_eq!(one.len(), 1); // 42 fits in a single byte
//! let decoded: u128 = UInt::decode(one).unwrap().into();
//! assert_eq!(decoded, 42);
//!
//! // Signed example (ZigZag)
//! let neg = SInt(-3i32).encode();
//! assert_eq!(neg.len(), 1);
//! let decoded: i32 = SInt::decode(neg).unwrap().into();
//! assert_eq!(decoded, -3);
//! ```

use crate::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use bytes::{Buf, BufMut};
use core::{fmt::Debug, mem::size_of};
use sealed::{SPrim, UPrim};

// ---------- Constants ----------

/// The number of bits in a byte.
const BITS_PER_BYTE: usize = 8;

/// The number of data-bearing bits in a byte.
/// That is, the number of bits in a byte excluding the continuation bit.
const DATA_BITS_PER_BYTE: usize = 7;

/// The mask for the data-bearing bits in a byte.
const DATA_BITS_MASK: u8 = 0x7F;

/// The mask for the continuation bit in a byte.
const CONTINUATION_BIT_MASK: u8 = 0x80;

// ---------- Traits ----------

#[doc(hidden)]
mod sealed {
    use super::*;
    use core::ops::{BitOrAssign, Shl, ShrAssign};

    /// A trait for unsigned integer primitives that can be varint encoded.
    pub trait UPrim:
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

    // Implements the `UPrim` trait for all unsigned integer types.
    macro_rules! impl_uint {
        ($type:ty) => {
            impl UPrim for $type {
                #[inline(always)]
                fn leading_zeros(self) -> u32 {
                    self.leading_zeros()
                }

                #[inline(always)]
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

    /// A trait for signed integer primitives that can be converted to and from unsigned integer
    /// primitives of the equivalent size.
    ///
    /// When converted to unsigned integers, the encoding is done using ZigZag encoding, which moves the
    /// sign bit to the least significant bit (shifting all other bits to the left by one). This allows
    /// for more efficient encoding of numbers that are close to zero, even if they are negative.
    pub trait SPrim: Copy + Sized + FixedSize + PartialOrd + Debug {
        /// The unsigned equivalent type of the signed integer.
        /// This type must be the same size as the signed integer type.
        type UnsignedEquivalent: UPrim;

        /// Compile-time assertion to ensure that the size of the signed integer is equal to the size of
        /// the unsigned integer.
        #[doc(hidden)]
        const _COMMIT_OP_ASSERT: () =
            assert!(size_of::<Self>() == size_of::<Self::UnsignedEquivalent>());

        /// Converts the signed integer to an unsigned integer using ZigZag encoding.
        fn as_zigzag(&self) -> Self::UnsignedEquivalent;

        /// Converts a (ZigZag'ed) unsigned integer back to a signed integer.
        fn un_zigzag(value: Self::UnsignedEquivalent) -> Self;
    }

    // Implements the `SPrim` trait for all signed integer types.
    macro_rules! impl_sint {
        ($type:ty, $utype:ty) => {
            impl SPrim for $type {
                type UnsignedEquivalent = $utype;

                #[inline]
                fn as_zigzag(&self) -> $utype {
                    let shr = size_of::<$utype>() * 8 - 1;
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
}

// ---------- Structs ----------

/// An ergonomic wrapper to allow for encoding and decoding of primitive unsigned integers as
/// varints rather than the default fixed-width integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt<U: UPrim>(pub U);

// Implements `Into<U>` for `UInt<U>` for all unsigned integer types.
// This allows for easy conversion from `UInt<U>` to `U` using `.into()`.
macro_rules! impl_varuint_into {
    ($($type:ty),+) => {
        $(
            impl From<UInt<$type>> for $type {
                fn from(val: UInt<$type>) -> Self {
                    val.0
                }
            }
        )+
    };
}
impl_varuint_into!(u16, u32, u64, u128);

impl<U: UPrim> Write for UInt<U> {
    fn write(&self, buf: &mut impl BufMut) {
        write(self.0, buf);
    }
}

impl<U: UPrim> Read for UInt<U> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        read(buf).map(UInt)
    }
}

impl<U: UPrim> EncodeSize for UInt<U> {
    fn encode_size(&self) -> usize {
        size(self.0)
    }
}

/// An ergonomic wrapper to allow for encoding and decoding of primitive signed integers as
/// varints rather than the default fixed-width integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SInt<S: SPrim>(pub S);

// Implements `Into<U>` for `SInt<U>` for all signed integer types.
// This allows for easy conversion from `SInt<S>` to `S` using `.into()`.
macro_rules! impl_varsint_into {
    ($($type:ty),+) => {
        $(
            impl From<SInt<$type>> for $type {
                fn from(val: SInt<$type>) -> Self {
                    val.0
                }
            }
        )+
    };
}
impl_varsint_into!(i16, i32, i64, i128);

impl<S: SPrim> Write for SInt<S> {
    fn write(&self, buf: &mut impl BufMut) {
        write_signed::<S>(self.0, buf);
    }
}

impl<S: SPrim> Read for SInt<S> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        read_signed::<S>(buf).map(SInt)
    }
}

impl<S: SPrim> EncodeSize for SInt<S> {
    fn encode_size(&self) -> usize {
        size_signed::<S>(self.0)
    }
}

// ---------- Helper Functions ----------

/// Encodes an unsigned integer as a varint
fn write<T: UPrim>(value: T, buf: &mut impl BufMut) {
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
fn read<T: UPrim>(buf: &mut impl Buf) -> Result<T, Error> {
    let max_bits = T::SIZE * BITS_PER_BYTE;
    let mut result: T = T::from(0);
    let mut bits_read = 0;

    // Loop over all the bytes.
    loop {
        // Read the next byte.
        let byte = u8::read(buf)?;

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
fn size<T: UPrim>(value: T) -> usize {
    let total_bits = size_of::<T>() * 8;
    let leading_zeros = value.leading_zeros() as usize;
    let data_bits = total_bits - leading_zeros;
    usize::max(1, data_bits.div_ceil(DATA_BITS_PER_BYTE))
}

/// Encodes a signed integer as a varint using ZigZag encoding.
fn write_signed<S: SPrim>(value: S, buf: &mut impl BufMut) {
    write(value.as_zigzag(), buf);
}

/// Decodes a signed integer from varint ZigZag encoding.
fn read_signed<S: SPrim>(buf: &mut impl Buf) -> Result<S, Error> {
    Ok(S::un_zigzag(read(buf)?))
}

/// Calculates the number of bytes needed to encode a signed integer as a varint.
fn size_signed<S: SPrim>(value: S) -> usize {
    size(value.as_zigzag())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::Error, DecodeExt, Encode};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use bytes::Bytes;

    #[test]
    fn test_end_of_buffer() {
        let mut buf: Bytes = Bytes::from_static(&[]);
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

    /// Core round-trip check, generic over any UPrim.
    fn varuint_round_trip<T: Copy + UPrim + TryFrom<u128>>() {
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

            // UInt wrapper
            let encoded = UInt(value).encode();
            assert_eq!(UInt::<T>::decode(encoded).unwrap(), UInt(value));
        }
    }

    #[test]
    fn test_varuint() {
        varuint_round_trip::<u16>();
        varuint_round_trip::<u32>();
        varuint_round_trip::<u64>();
        varuint_round_trip::<u128>();
    }

    fn varsint_round_trip<T: Copy + SPrim + TryFrom<i128>>() {
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

            // SInt wrapper
            let encoded = SInt(value).encode();
            assert_eq!(SInt::<T>::decode(encoded).unwrap(), SInt(value));
        }
    }

    #[test]
    fn test_varsint() {
        varsint_round_trip::<i16>();
        varsint_round_trip::<i32>();
        varsint_round_trip::<i64>();
        varsint_round_trip::<i128>();
    }

    #[test]
    fn test_varuint_into() {
        let v32: u32 = 0x1_FFFF;
        let out32: u32 = UInt(v32).into();
        assert_eq!(v32, out32);

        let v64: u64 = 0x1_FF_FF_FF_FF;
        let out64: u64 = UInt(v64).into();
        assert_eq!(v64, out64);
    }

    #[test]
    fn test_varsint_into() {
        let s32: i32 = -123_456;
        let out32: i32 = SInt(s32).into();
        assert_eq!(s32, out32);

        let s64: i64 = 987_654_321;
        let out64: i64 = SInt(s64).into();
        assert_eq!(s64, out64);
    }

    #[test]
    fn test_conformity() {
        assert_eq!(0usize.encode(), &[0x00][..]);
        assert_eq!(1usize.encode(), &[0x01][..]);
        assert_eq!(127usize.encode(), &[0x7F][..]);
        assert_eq!(128usize.encode(), &[0x80, 0x01][..]);
        assert_eq!(16383usize.encode(), &[0xFF, 0x7F][..]);
        assert_eq!(16384usize.encode(), &[0x80, 0x80, 0x01][..]);
        assert_eq!(2097151usize.encode(), &[0xFF, 0xFF, 0x7F][..]);
        assert_eq!(2097152usize.encode(), &[0x80, 0x80, 0x80, 0x01][..]);
        assert_eq!(
            (u32::MAX as usize).encode(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F][..]
        );
    }

    #[test]
    fn test_all_u16_values() {
        // Exhaustively test all u16 values to ensure size matches encoding
        for i in 0..=u16::MAX {
            let value = i;
            let calculated_size = size(value);

            let mut buf = Vec::new();
            write(value, &mut buf);

            assert_eq!(
                buf.len(),
                calculated_size,
                "Size mismatch for u16 value {value}",
            );

            // Also verify UInt wrapper
            let uint = UInt(value);
            assert_eq!(
                uint.encode_size(),
                buf.len(),
                "UInt encode_size mismatch for value {value}",
            );
        }
    }

    #[test]
    fn test_all_i16_values() {
        // Exhaustively test all i16 values to ensure size matches encoding
        for i in i16::MIN..=i16::MAX {
            let value = i;
            let calculated_size = size_signed(value);

            let mut buf = Vec::new();
            write_signed(value, &mut buf);

            assert_eq!(
                buf.len(),
                calculated_size,
                "Size mismatch for i16 value {value}",
            );

            // Also verify SInt wrapper
            let sint = SInt(value);
            assert_eq!(
                sint.encode_size(),
                buf.len(),
                "SInt encode_size mismatch for value {value}",
            );

            // Verify we can decode it back correctly
            let mut slice = &buf[..];
            let decoded: i16 = read_signed(&mut slice).unwrap();
            assert_eq!(decoded, value, "Decode mismatch for value {value}");
            assert!(
                slice.is_empty(),
                "Buffer not fully consumed for value {value}",
            );
        }
    }

    #[test]
    fn test_exact_bit_boundaries() {
        // Test values with exactly N bits set
        fn test_exact_bits<T: UPrim + TryFrom<u128> + core::fmt::Display>() {
            for bits in 1..=128 {
                // Create a value with exactly 'bits' bits
                // e.g., bits=3 -> 0b111 = 7
                let val = if bits == 128 {
                    u128::MAX
                } else {
                    (1u128 << bits) - 1
                };
                let Ok(value) = T::try_from(val) else {
                    continue;
                };

                // Compute expected size
                let expected_size = (bits as usize).div_ceil(DATA_BITS_PER_BYTE);
                let calculated_size = size(value);
                assert_eq!(
                    calculated_size, expected_size,
                    "Size calculation wrong for {val} with {bits} bits",
                );

                // Compare encoded size
                let mut buf = Vec::new();
                write(value, &mut buf);
                assert_eq!(
                    buf.len(),
                    expected_size,
                    "Encoded size wrong for {val} with {bits} bits",
                );
            }
        }

        test_exact_bits::<u16>();
        test_exact_bits::<u32>();
        test_exact_bits::<u64>();
        test_exact_bits::<u128>();
    }

    #[test]
    fn test_single_bit_boundaries() {
        // Test values with only a single bit set at different positions
        fn test_single_bits<T: UPrim + TryFrom<u128> + core::fmt::Display>() {
            for bit_pos in 0..128 {
                // Create a value with only a single bit set at the given position
                let val = 1u128 << bit_pos;
                let Ok(value) = T::try_from(val) else {
                    continue;
                };

                // Compute expected size
                let expected_size = ((bit_pos + 1) as usize).div_ceil(DATA_BITS_PER_BYTE);
                let calculated_size = size(value);
                assert_eq!(
                    calculated_size, expected_size,
                    "Size wrong for 1<<{bit_pos} = {val}",
                );

                // Compare encoded size
                let mut buf = Vec::new();
                write(value, &mut buf);
                assert_eq!(
                    buf.len(),
                    expected_size,
                    "Encoded size wrong for 1<<{bit_pos} = {val}",
                );
            }
        }

        test_single_bits::<u16>();
        test_single_bits::<u32>();
        test_single_bits::<u64>();
        test_single_bits::<u128>();
    }
}
