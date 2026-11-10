//! Unsigned integers of any width with a fixed-width encoding.

use crate::{Buf, Error, FixedSize, Read, Write, util::at_least};
use bytes::BufMut;
use core::{
    fmt::{self, Debug, Display, Formatter},
    ops::{BitOrAssign, Shl, ShrAssign},
};

/// An unsigned integer of `BITS` bits held in `LIMBS` limbs of 64 bits, such as [U256].
///
/// It encodes as its value in big-endian over the fewest bytes that hold its bits, so a 256-bit
/// integer encodes as 32 bytes. Decoding refuses an encoding with a bit set beyond the width, so
/// every value has exactly one encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uint<const BITS: usize, const LIMBS: usize>(ruint::Uint<BITS, LIMBS>);

/// An unsigned 256-bit integer.
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

    /// Returns the number of leading zero bits within the width.
    pub const fn leading_zeros(&self) -> usize {
        self.0.leading_zeros()
    }

    /// Returns `self + other` wrapped to the width, and whether the sum overflowed.
    pub const fn overflowing_add(self, other: Self) -> (Self, bool) {
        let (sum, overflowed) = self.0.overflowing_add(other.0);
        (Self(sum), overflowed)
    }

    /// Returns `self - other` wrapped to the width, and whether the difference is negative.
    pub const fn overflowing_sub(self, other: Self) -> (Self, bool) {
        let (difference, negative) = self.0.overflowing_sub(other.0);
        (Self(difference), negative)
    }
}

impl<const BITS: usize, const LIMBS: usize> From<u64> for Uint<BITS, LIMBS> {
    /// Returns the integer holding `value`. A width below 64 bits does not compile.
    ///
    /// ```compile_fail
    /// use commonware_codec::Uint;
    ///
    /// let narrow = Uint::<40, 1>::from(1);
    /// ```
    fn from(value: u64) -> Self {
        const { assert!(BITS >= 64, "the width must hold a u64") };
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

impl<const BITS: usize, const LIMBS: usize> Shl<usize> for Uint<BITS, LIMBS> {
    type Output = Self;

    /// Shifts left, discarding the bits shifted beyond the width.
    fn shl(self, bits: usize) -> Self {
        Self(self.0 << bits)
    }
}

impl<const BITS: usize, const LIMBS: usize> ShrAssign<usize> for Uint<BITS, LIMBS> {
    fn shr_assign(&mut self, bits: usize) {
        self.0 >>= bits;
    }
}

impl<const BITS: usize, const LIMBS: usize> BitOrAssign for Uint<BITS, LIMBS> {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
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

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
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
            .ok_or(Error::Invalid("Uint", "a bit is set beyond the width"))
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
    use crate::{Copying, DecodeExt as _, Encode as _};

    /// Returns the big-endian bytes of a 256-bit value.
    fn be_bytes(value: U256) -> [u8; 32] {
        value.0.to_be_bytes()
    }

    #[test]
    fn test_arithmetic_reports_overflow() {
        let (five, six) = (U256::from(5), U256::from(6));
        assert_eq!(U256::MAX.overflowing_add(U256::ONE), (U256::ZERO, true));
        assert_eq!(five.overflowing_add(six), (U256::from(11), false));
        assert_eq!(five.overflowing_sub(six), (U256::MAX, true));
        assert_eq!(six.overflowing_sub(five), (U256::ONE, false));
        assert_eq!(U256::from_limbs([0, 0, 1, 0]).as_limbs(), &[0, 0, 1, 0]);
    }

    #[test]
    fn test_round_trips_as_big_endian() {
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
        let (value, _) = U512::MAX.overflowing_sub(U512::from(7));
        assert_eq!(value.encode().as_ref(), value.0.to_be_bytes::<64>());
        assert_eq!(U512::decode(value.encode()).unwrap(), value);
    }

    #[test]
    fn test_partial_limbs_encode_their_bytes_only() {
        type U40 = Uint<40, 1>;
        assert_eq!(U40::SIZE, 5);
        assert_eq!(U40::MAX.encode().as_ref(), [0xff; 5]);
        assert_eq!(U40::decode(U40::MAX.encode()).unwrap(), U40::MAX);
        assert!(matches!(
            U40::decode(Copying(&[0xff; 6])),
            Err(Error::ExtraData(1))
        ));
        assert!(matches!(
            U40::decode(Copying(&[0xff; 4])),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_rejects_bits_beyond_the_width() {
        type U36 = Uint<36, 1>;
        assert!(matches!(
            U36::decode(Copying(&[0xff; 5])),
            Err(Error::Invalid("Uint", _))
        ));
        let encoded = [0x0f, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(U36::decode(Copying(&encoded)).unwrap(), U36::MAX);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<U256>,
        }
    }
}
