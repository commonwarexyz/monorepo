//! Binary field element trait and extension field types.

#![allow(clippy::suspicious_arithmetic_impl, clippy::suspicious_op_assign_impl)]

use commonware_codec::{Decode, Encode};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{
    fmt::{Debug, Display},
    ops::{Add, AddAssign, Deref, Mul, MulAssign},
};

/// A binary field element in `GF(2^k)`.
pub trait BinaryField:
    Sized
    + Copy
    + Clone
    + PartialEq
    + Eq
    + Debug
    + Display
    + Send
    + Sync
    + Mul<Self, Output = Self>
    + MulAssign<Self>
    + Add<Self, Output = Self>
    + AddAssign<Self>
    + Encode
    + Decode
{
    type Underlying: Into<Self> + From<Self> + Copy + Clone + PartialEq + Eq + Debug;

    /// Size of the field in bits.
    const BIT_SIZE: usize;

    /// Size of the field in bytes.
    const BYTE_SIZE: usize;

    /// The irreducible polynomial used for the field.
    const IRREDUCIBLE: Self::Underlying;

    /// The zero element of the field.
    const ZERO: Self;

    /// The one element of the field.
    const ONE: Self;

    /// Converts a little-endian byte slice to the field element.
    ///
    /// ## Panics
    ///
    /// Panics if the byte slice is not of length [`Self::BYTE_SIZE`].
    fn from_le_bytes(bytes: &[u8]) -> Self;

    /// Converts the field element to a little-endian byte array.
    ///
    /// TODO: When generic const expressions are stable, heap allocations can be avoided.
    fn to_le_bytes(&self) -> Vec<u8>;
}

macro_rules! binary_field {
    ($name:ident, $ty:ty, irreducible = $irreducible:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(transparent)]
        #[doc = concat!("A binary field element in GF(2^k), k = [", stringify!($ty), "::BITS].")]
        pub struct $name($ty);

        impl BinaryField for $name {
            type Underlying = $ty;

            const BIT_SIZE: usize = <$ty>::BITS as usize;

            const BYTE_SIZE: usize = <$ty>::BITS as usize >> 3;

            const IRREDUCIBLE: Self::Underlying = $irreducible;

            const ZERO: Self = Self(0);

            const ONE: Self = Self(1);

            fn from_le_bytes(bytes: &[u8]) -> Self {
                let mut arr = [0u8; Self::BYTE_SIZE];
                arr[..bytes.len()].copy_from_slice(bytes);

                Self(<$ty>::from_le_bytes(arr))
            }

            fn to_le_bytes(&self) -> Vec<u8> {
                self.0.to_le_bytes().to_vec()
            }
        }

        impl Mul for $name {
            type Output = Self;

            fn mul(self, other: Self) -> Self {
                let mut result: $ty = 0;
                let (mut a, mut b) = (self.0, other.0);

                // Polynomial multiplication in GF(2^n)
                while b != 0 {
                    if b & 1 == 1 {
                        result ^= a;
                    }
                    b >>= 1;
                    if a & (1 << (Self::BIT_SIZE - 1)) != 0 {
                        // If high bit is set, shift and reduce
                        a = (a << 1) ^ (Self::IRREDUCIBLE as $ty);
                    } else {
                        a <<= 1;
                    }
                }

                Self(result)
            }
        }

        impl MulAssign for $name {
            fn mul_assign(&mut self, other: Self) {
                *self = *self * other;
            }
        }

        impl Add for $name {
            type Output = Self;

            fn add(self, other: Self) -> Self {
                #[allow(clippy::suspicious_arithmetic_impl)]
                Self(self.0 ^ other.0)
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, other: Self) {
                self.0 ^= other.0;
            }
        }

        impl From<$ty> for $name {
            fn from(val: $ty) -> Self {
                Self(val)
            }
        }

        impl From<$name> for $ty {
            fn from(field: $name) -> Self {
                field.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl commonware_codec::EncodeSize for $name {
            fn encode_size(&self) -> usize {
                self.0.encode_size()
            }
        }

        impl commonware_codec::EncodeSize for &$name {
            fn encode_size(&self) -> usize {
                self.0.encode_size()
            }
        }

        impl commonware_codec::Write for $name {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl commonware_codec::Write for &$name {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl commonware_codec::Read for $name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl bytes::Buf,
                _cfg: &Self::Cfg,
            ) -> Result<Self, commonware_codec::Error> {
                let val = <$ty>::read_cfg(buf, &())?;
                Ok(Self(val))
            }
        }
    };
}

binary_field!(
    GF32,
    u32,
    irreducible = 0x8299 // x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1
);
binary_field!(
    GF128,
    u128,
    irreducible = 0x87 // x^128 + x^7 + x^2 + x + 1
);

/// A vector of [`BinaryField`] elements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct FieldVector<'a, F: BinaryField>(&'a [F]);

impl<'a, F: BinaryField> Deref for FieldVector<'a, F> {
    type Target = [F];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a, F: BinaryField> From<&'a [F]> for FieldVector<'a, F> {
    fn from(slice: &'a [F]) -> Self {
        Self(slice)
    }
}

impl<'a, F: BinaryField> Mul<&[F]> for FieldVector<'a, F> {
    type Output = F;

    fn mul(self, rhs: &[F]) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.len(),
            "Field vectors must be of the same length"
        );

        self.par_iter()
            .zip(rhs.par_iter())
            .map(|(a, b)| *a * *b)
            .reduce(|| F::ZERO, |a, b| a + b)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(1, 1, 0)]
    #[case(u32::MAX, u32::MAX, 0)]
    #[case(1, 2, 3)]
    #[case(2, 1, 3)]
    fn test_gf32_addition(#[case] lhs: u32, #[case] rhs: u32, #[case] expected: u32) {
        assert_eq!(GF32::from(lhs) + GF32::from(rhs), GF32::from(expected));
    }

    #[rstest]
    #[case(1, 1, 0)]
    #[case(u128::MAX, u128::MAX, 0)]
    #[case(1, 2, 3)]
    #[case(2, 1, 3)]
    fn test_gf128_addition(#[case] lhs: u128, #[case] rhs: u128, #[case] expected: u128) {
        assert_eq!(GF128::from(lhs) + GF128::from(rhs), GF128::from(expected));
    }

    #[rstest]
    #[case(0, 1, 0)]
    #[case(1, 1, 1)]
    #[case(2, 1, 2)]
    #[case(2, 0x800041be, 485)]
    #[case(2, 0x8000414c, 1)]
    fn test_gf32_multiplication(#[case] lhs: u32, #[case] rhs: u32, #[case] expected: u32) {
        assert_eq!(GF32::from(lhs) * GF32::from(rhs), GF32::from(expected));
    }

    #[rstest]
    #[case(0, 1, 0)]
    #[case(1, 1, 1)]
    #[case(2, 1, 2)]
    #[case(2, 0x8000000000000000000000000000008E, 411)]
    #[case(2, 0x80000000000000000000000000000043, 1)]
    fn test_gf128_multiplication(#[case] lhs: u128, #[case] rhs: u128, #[case] expected: u128) {
        assert_eq!(GF128::from(lhs) * GF128::from(rhs), GF128::from(expected));
    }

    #[rstest]
    #[case(&[1], &[1], 1)]
    #[case(&[1, 2, 3], &[4, 5, 6], 4 ^ 10 ^ 10)]
    #[should_panic(expected = "Field vectors must be of the same length")]
    #[case(&[1], &[1, 2], 0xbadc0de)]
    fn field_vector_mul(#[case] lhs: &[u32], #[case] rhs: &[u32], #[case] expected: u32) {
        let lhs = lhs.iter().copied().map(GF32::from).collect::<Vec<_>>();
        let rhs = rhs.iter().copied().map(GF32::from).collect::<Vec<_>>();

        assert_eq!(
            FieldVector::from(lhs.as_slice()) * rhs.as_slice(),
            GF32::from(expected)
        );
    }
}
