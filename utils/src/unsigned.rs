//! Unsigned integers with a fixed-width encoding.

use commonware_codec::{CodecFixedShared, Uint};
use core::{fmt::Debug, hash::Hash};

/// An unsigned integer with a fixed-width encoding.
///
/// An implementation orders values numerically and encodes each value in exactly one way, so a
/// commitment over encoded values commits to the values themselves.
pub trait Unsigned: Copy + Ord + Hash + Debug + CodecFixedShared + 'static {
    /// The value zero.
    const ZERO: Self;

    /// Returns `self + other` wrapped to the type's width, and whether the sum overflowed.
    fn overflowing_add(self, other: Self) -> (Self, bool);

    /// Returns `self - other` wrapped to the type's width, and whether the difference is negative.
    fn overflowing_sub(self, other: Self) -> (Self, bool);

    /// Returns `self + other`, or `None` if the sum overflows.
    fn checked_add(self, other: Self) -> Option<Self> {
        match self.overflowing_add(other) {
            (sum, false) => Some(sum),
            (_, true) => None,
        }
    }

    /// Returns `self - other`, or `None` if the difference is negative.
    fn checked_sub(self, other: Self) -> Option<Self> {
        match self.overflowing_sub(other) {
            (difference, false) => Some(difference),
            (_, true) => None,
        }
    }
}

macro_rules! impl_unsigned {
    ($($type:ty),*) => {
        $(
            impl Unsigned for $type {
                const ZERO: Self = 0;

                fn overflowing_add(self, other: Self) -> (Self, bool) {
                    <$type>::overflowing_add(self, other)
                }

                fn overflowing_sub(self, other: Self) -> (Self, bool) {
                    <$type>::overflowing_sub(self, other)
                }
            }
        )*
    };
}

impl_unsigned!(u8, u16, u32, u64, u128);

impl<const BITS: usize, const LIMBS: usize> Unsigned for Uint<BITS, LIMBS> {
    const ZERO: Self = Self::ZERO;

    fn overflowing_add(self, other: Self) -> (Self, bool) {
        Self::overflowing_add(self, other)
    }

    fn overflowing_sub(self, other: Self) -> (Self, bool) {
        Self::overflowing_sub(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::U256;

    #[test]
    fn test_checked_arithmetic_follows_overflow() {
        assert_eq!(Unsigned::checked_add(250u8, 5), Some(255));
        assert_eq!(Unsigned::checked_add(250u8, 6), None);
        assert_eq!(Unsigned::checked_sub(5u64, 5), Some(0));
        assert_eq!(Unsigned::checked_sub(5u64, 6), None);
        assert_eq!(<u128 as Unsigned>::ZERO, 0);
    }

    #[test]
    fn test_uint_arithmetic_follows_overflow() {
        let (five, six) = (U256::from(5), U256::from(6));
        assert_eq!(Unsigned::checked_add(U256::MAX, U256::ONE), None);
        assert_eq!(Unsigned::checked_sub(five, six), None);
        assert_eq!(Unsigned::checked_add(five, six), Some(U256::from(11)));
        assert_eq!(<U256 as Unsigned>::ZERO, U256::ZERO);
    }
}
