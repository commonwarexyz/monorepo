use crate::algebra::{Additive, CryptoGroup, Field, Multiplicative, Object, Random, Ring, Space};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;

const P: u64 = 4_611_686_018_427_389_243;
const Q: u64 = 9_223_372_036_854_778_487;

fn mul_mod(a: u64, b: u64, p: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(p)) as u64
}

/// The prime field F_p for the test modulus `p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F(u64);

impl F {
    pub const MAX: u64 = P - 1;
}

impl FixedSize for F {
    const SIZE: usize = 8;
}

impl Write for F {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for F {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let value = u64::read(buf)?;
        if value >= P {
            return Err(commonware_codec::Error::Invalid("F", "out of range"));
        }
        Ok(Self(value))
    }
}

impl From<u8> for F {
    fn from(value: u8) -> Self {
        Self::from(u64::from(value))
    }
}

impl From<u64> for F {
    fn from(value: u64) -> Self {
        Self(value % P)
    }
}

impl Object for F {}

impl Random for F {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        Self(u64::from_le_bytes(bytes) % P)
    }
}

impl<'a> Add<&'a Self> for F {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        let sum = self.0 + rhs.0;
        Self(if sum >= P { sum - P } else { sum })
    }
}

impl<'a> AddAssign<&'a Self> for F {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = *self + rhs;
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(if self.0 == 0 { 0 } else { P - self.0 })
    }
}

impl<'a> Sub<&'a Self> for F {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        self + &-*rhs
    }
}

impl<'a> SubAssign<&'a Self> for F {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = *self - rhs;
    }
}

impl Additive for F {
    fn zero() -> Self {
        Self(0)
    }
}

impl<'a> Mul<&'a Self> for F {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self::Output {
        Self(mul_mod(self.0, rhs.0, P))
    }
}

impl<'a> MulAssign<&'a Self> for F {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = *self * rhs;
    }
}

impl Multiplicative for F {}

impl Ring for F {
    fn one() -> Self {
        Self(1)
    }
}

impl Field for F {
    fn inv(&self) -> Self {
        self.exp(&[P - 2])
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary::<u64>()? % P))
    }
}

/// A prime group of order `p`.
///
/// This is constructed as a subgroup of the units in `F_q`.
///
/// `q = 2p + 1`, so the group of units has a subgroup of order `p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G(u64);

impl FixedSize for G {
    const SIZE: usize = 8;
}

impl Write for G {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for G {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let value = u64::read(buf)?;
        if value >= Q {
            return Err(commonware_codec::Error::Invalid("G", "out of range"));
        }
        let out = Self(value);
        if out.0 == 0 || out.scale(&[P]).0 != 1 {
            return Err(commonware_codec::Error::Invalid("G", "not in subgroup"));
        }
        Ok(out)
    }
}

impl Object for G {}

impl<'a> Add<&'a Self> for G {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(mul_mod(self.0, rhs.0, Q))
    }
}

impl<'a> AddAssign<&'a Self> for G {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = *self + rhs;
    }
}

impl Neg for G {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.scale(&[(Q - 2).into()])
    }
}

impl<'a> Sub<&'a Self> for G {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        self + &-*rhs
    }
}

impl<'a> SubAssign<&'a Self> for G {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = *self - rhs;
    }
}

impl Additive for G {
    fn zero() -> Self {
        Self(1)
    }
}

impl<'a> Mul<&'a F> for G {
    type Output = Self;

    fn mul(self, rhs: &'a F) -> Self::Output {
        self.scale(&[rhs.0.into()])
    }
}

impl<'a> MulAssign<&'a F> for G {
    fn mul_assign(&mut self, rhs: &'a F) {
        *self = *self * rhs;
    }
}

impl Space<F> for G {}

impl CryptoGroup for G {
    type Scalar = F;

    fn generator() -> Self {
        // 4 = 2^2 is a non-trivial quadratic residue, so it generates the
        // unique subgroup of order p because p is prime.
        Self(4)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for G {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::generator() * &u.arbitrary::<F>()?)
    }
}

commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz {
        use super::*;
        use crate::algebra::test_suites;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::Encode as _;

        #[derive(Debug, Arbitrary)]
        pub enum Plan {
            FCodec(F),
            GCodec(G),
            FuzzField,
            FuzzSpace,
        }

        impl Plan {
            pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
                match self {
                    Self::FCodec(x) => {
                        assert_eq!(&x, &F::read(&mut x.encode()).unwrap());
                    }
                    Self::GCodec(x) => {
                        assert_eq!(&x, &G::read(&mut x.encode()).unwrap());
                    }
                    Self::FuzzField => {
                        test_suites::fuzz_field::<F>(u)?;
                    }
                    Self::FuzzSpace => {
                        test_suites::fuzz_space::<F, G>(u)?;
                    }
                }
                Ok(())
            }
        }

        #[test]
        fn test_fuzz() {
            use commonware_invariants::minifuzz;
            minifuzz::test(|u| u.arbitrary::<Plan>()?.run(u));
        }
    }
});

#[allow(clippy::module_inception)]
#[cfg(test)]
mod test {
    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<F>,
            CodecConformance<G>
        }
    }
}
