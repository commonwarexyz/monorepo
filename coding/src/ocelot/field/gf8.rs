//! The binary field GF(2^8).

use commonware_math::algebra::{Additive, Field, Multiplicative, Object, Ring};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element of GF(2^8), represented in the AES polynomial basis.
///
/// This implements [`Field`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct GF8(u8);

impl GF8 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn add_inner(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    const fn mul_inner(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut product = 0;

        let mut i = 0;
        while i < u8::BITS {
            if b & 1 != 0 {
                product ^= a;
            }

            let high_bit = a & 0x80;
            a <<= 1;
            if high_bit != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }

        Self(product)
    }
}

impl From<u8> for GF8 {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<GF8> for u8 {
    fn from(value: GF8) -> Self {
        value.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for GF8 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

impl Object for GF8 {}

impl Add for GF8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Add<&Self> for GF8 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign<&Self> for GF8 {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl Neg for GF8 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Sub for GF8 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Sub<&Self> for GF8 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl SubAssign<&Self> for GF8 {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl Additive for GF8 {
    fn zero() -> Self {
        Self::ZERO
    }
}

impl Mul for GF8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_inner(rhs)
    }
}

impl Mul<&Self> for GF8 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl MulAssign<&Self> for GF8 {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl Multiplicative for GF8 {}

impl Ring for GF8 {
    fn one() -> Self {
        Self::ONE
    }
}

impl Field for GF8 {
    fn inv(&self) -> Self {
        self.exp(&[254])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field() {
        commonware_invariants::minifuzz::test(
            commonware_math::algebra::test_suites::fuzz_field::<GF8>,
        );
    }
}
