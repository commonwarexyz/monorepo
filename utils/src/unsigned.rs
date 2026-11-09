//! Unsigned integers with a fixed-width encoding.

use bytes::BufMut;
use commonware_codec::{
    Buf, CodecFixedShared, Error as CodecError, FixedSize, Read, Write, util::at_least,
};
use core::{
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
    ops::{Add, Mul, Sub},
};

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

/// An unsigned integer of `BITS` bits held in `LIMBS` limbs of 64 bits, such as [U256].
///
/// It encodes as its value in big-endian over the fewest bytes that hold its bits, so a 256-bit
/// integer encodes as 32 bytes. Decoding refuses an encoding with a bit set beyond the width, so
/// every value has exactly one encoding. Arithmetic through the operators wraps.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uint<const BITS: usize, const LIMBS: usize>(ruint::Uint<BITS, LIMBS>);

/// An unsigned 256-bit integer, the width of EVM token balances.
pub type U256 = Uint<256, 4>;

impl<const BITS: usize, const LIMBS: usize> Uint<BITS, LIMBS> {
    /// The value zero.
    pub const ZERO: Self = Self(ruint::Uint::ZERO);

    /// The value one.
    pub const ONE: Self = Self(ruint::Uint::ONE);

    /// The largest value.
    pub const MAX: Self = Self(ruint::Uint::MAX);

    /// Number of bytes the encoding takes.
    pub const BYTES: usize = ruint::Uint::<BITS, LIMBS>::BYTES;

    /// Number of bytes of the most significant limb the encoding takes.
    const TOP: usize = Self::BYTES - 8 * LIMBS.saturating_sub(1);

    /// Returns the value whose 64-bit limbs are `limbs`, least significant first.
    ///
    /// # Panics
    ///
    /// Panics if a bit beyond `BITS` is set.
    pub const fn from_limbs(limbs: [u64; LIMBS]) -> Self {
        Self(ruint::Uint::from_limbs(limbs))
    }

    /// Returns the 64-bit limbs of the value, least significant first.
    pub const fn as_limbs(&self) -> &[u64; LIMBS] {
        self.0.as_limbs()
    }
}

impl<const BITS: usize, const LIMBS: usize> From<u64> for Uint<BITS, LIMBS> {
    /// # Panics
    ///
    /// Panics if `value` does not fit in `BITS` bits.
    fn from(value: u64) -> Self {
        Self(ruint::Uint::from(value))
    }
}

impl<const BITS: usize, const LIMBS: usize> Debug for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<const BITS: usize, const LIMBS: usize> Display for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<const BITS: usize, const LIMBS: usize> Add for Uint<BITS, LIMBS> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Sub for Uint<BITS, LIMBS> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Mul for Uint<BITS, LIMBS> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Unsigned for Uint<BITS, LIMBS> {
    const ZERO: Self = Self::ZERO;

    fn overflowing_add(self, other: Self) -> (Self, bool) {
        let (sum, overflowed) = self.0.overflowing_add(other.0);
        (Self(sum), overflowed)
    }

    fn overflowing_sub(self, other: Self) -> (Self, bool) {
        let (difference, negative) = self.0.overflowing_sub(other.0);
        (Self(difference), negative)
    }
}

impl<const BITS: usize, const LIMBS: usize> FixedSize for Uint<BITS, LIMBS> {
    const SIZE: usize = Self::BYTES;
}

impl<const BITS: usize, const LIMBS: usize> Write for Uint<BITS, LIMBS> {
    fn write(&self, buf: &mut impl BufMut) {
        let Some((most, rest)) = self.as_limbs().split_last() else {
            return;
        };
        buf.put_slice(&most.to_be_bytes()[8 - Self::TOP..]);
        for limb in rest.iter().rev() {
            buf.put_u64(*limb);
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> Read for Uint<BITS, LIMBS> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;
        let mut limbs = [0u64; LIMBS];
        if let Some((most, rest)) = limbs.split_last_mut() {
            let mut bytes = [0u8; 8];
            buf.copy_to_slice(&mut bytes[8 - Self::TOP..]);
            *most = u64::from_be_bytes(bytes);
            for limb in rest.iter_mut().rev() {
                *limb = buf.get_u64();
            }
        }
        ruint::Uint::checked_from_limbs_slice(&limbs)
            .map(Self)
            .ok_or(CodecError::Invalid("Uint", "a bit is set beyond the width"))
    }
}

#[cfg(feature = "arbitrary")]
impl<const BITS: usize, const LIMBS: usize> arbitrary::Arbitrary<'_> for Uint<BITS, LIMBS> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        u.arbitrary().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Copying, DecodeExt as _, Encode as _};

    /// Returns the big-endian bytes of a 256-bit value.
    fn be_bytes(value: U256) -> [u8; 32] {
        value.0.to_be_bytes()
    }

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
        assert_eq!(five * six - U256::ONE, U256::from(29));
        assert_eq!(<U256 as Unsigned>::ZERO, U256::ZERO);
        assert_eq!(U256::from_limbs([0, 0, 1, 0]).as_limbs(), &[0, 0, 1, 0]);
    }

    #[test]
    fn test_uint_round_trips_as_big_endian() {
        for value in [
            U256::ZERO,
            U256::ONE,
            U256::MAX,
            U256::from_limbs([0, 0, 0, 1 << 8]),
        ] {
            let encoded = value.encode();
            assert_eq!(encoded.len(), U256::SIZE);
            assert_eq!(encoded.as_ref(), be_bytes(value));
            assert_eq!(U256::decode(encoded).unwrap(), value);
        }
        type U512 = Uint<512, 8>;
        let value = U512::MAX - U512::from(7);
        assert_eq!(value.encode().as_ref(), value.0.to_be_bytes::<64>());
        assert_eq!(U512::decode(value.encode()).unwrap(), value);
    }

    #[test]
    fn test_uint_partial_limbs_encode_their_bytes_only() {
        type U40 = Uint<40, 1>;
        assert_eq!(U40::SIZE, 5);
        assert_eq!(U40::MAX.encode().as_ref(), [0xff; 5]);
        assert_eq!(U40::decode(U40::MAX.encode()).unwrap(), U40::MAX);
        assert!(matches!(
            U40::decode(Copying(&[0xff; 6])),
            Err(CodecError::ExtraData(1))
        ));
        assert!(matches!(
            U40::decode(Copying(&[0xff; 4])),
            Err(CodecError::EndOfBuffer)
        ));
    }

    #[test]
    fn test_uint_rejects_bits_beyond_the_width() {
        type U36 = Uint<36, 1>;
        assert!(matches!(
            U36::decode(Copying(&[0xff; 5])),
            Err(CodecError::Invalid("Uint", _))
        ));
        let encoded = [0x0f, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(U36::decode(Copying(&encoded)).unwrap(), U36::MAX);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<U256>,
        }
    }
}
