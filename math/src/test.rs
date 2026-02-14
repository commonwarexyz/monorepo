use crate::algebra::{Additive, CryptoGroup, Field, Multiplicative, Object, Ring, Space};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

const P: u8 = 89;
const Q: u8 = 2 * P + 1;

fn mul_mod(a: u8, b: u8, p: u8) -> u8 {
    ((u16::from(a) * u16::from(b)) % u16::from(p)) as u8
}

/// The prime field F_89;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F(u8);

impl F {
    pub const MAX: usize = (P - 1) as usize;
}

impl FixedSize for F {
    const SIZE: usize = 1;
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
        let byte = u8::read(buf)?;
        if byte >= P {
            return Err(commonware_codec::Error::Invalid("F", "out of range"));
        }
        Ok(Self(byte))
    }
}

impl From<u8> for F {
    fn from(value: u8) -> Self {
        Self(value % P)
    }
}

impl Object for F {}

impl<'a> Add<&'a Self> for F {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self((self.0 + rhs.0) % P)
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
        Self((P - self.0) % P)
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
        self.exp(&[(P - 2).into()])
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let byte = u.arbitrary::<u8>()? % P;
        Ok(Self(byte))
    }
}

/// A prime group of order 89.
///
/// This is constructed as a subgroup of the units in F_179.
///
/// 179 = 2 * 89 + 1, so the group of units has a subgroup of order 89.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G(u8);

impl FixedSize for G {
    const SIZE: usize = 1;
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
        let byte = u8::read(buf)?;
        if byte >= Q {
            return Err(commonware_codec::Error::Invalid("G", "out of range"));
        }
        let out = Self(byte);
        if out.scale(&[(Q - 1).into()]).0 != 1 {
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
        Self(3)
    }
}

#[cfg(feature = "arbitrary")]
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
