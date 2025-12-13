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

impl<'a> Add<&'a F> for F {
    type Output = Self;

    fn add(self, rhs: &'a F) -> Self::Output {
        Self((self.0 + rhs.0) % P)
    }
}

impl<'a> AddAssign<&'a F> for F {
    fn add_assign(&mut self, rhs: &'a F) {
        *self = *self + rhs;
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self((P - self.0) % P)
    }
}

impl<'a> Sub<&'a F> for F {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        self + &-*rhs
    }
}

impl<'a> SubAssign<&'a F> for F {
    fn sub_assign(&mut self, rhs: &'a F) {
        *self = *self - rhs;
    }
}

impl Additive for F {
    fn zero() -> Self {
        Self(0)
    }
}

impl<'a> Mul<&'a F> for F {
    type Output = Self;

    fn mul(self, rhs: &'a F) -> Self::Output {
        Self(mul_mod(self.0, rhs.0, P))
    }
}

impl<'a> MulAssign<&'a F> for F {
    fn mul_assign(&mut self, rhs: &'a F) {
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

impl<'a> Add<&'a G> for G {
    type Output = Self;

    fn add(self, rhs: &'a G) -> Self::Output {
        Self(mul_mod(self.0, rhs.0, Q))
    }
}

impl<'a> AddAssign<&'a G> for G {
    fn add_assign(&mut self, rhs: &'a G) {
        *self = *self + rhs;
    }
}

impl Neg for G {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.scale(&[(Q - 2).into()])
    }
}

impl<'a> Sub<&'a G> for G {
    type Output = Self;

    fn sub(self, rhs: &'a G) -> Self::Output {
        self + &-*rhs
    }
}

impl<'a> SubAssign<&'a G> for G {
    fn sub_assign(&mut self, rhs: &'a G) {
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

#[allow(clippy::module_inception)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::algebra;
    use commonware_codec::Encode;
    use proptest::prelude::*;

    impl Arbitrary for F {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u8>().prop_map_into().boxed()
        }
    }

    impl Arbitrary for G {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<F>().prop_map(|x| G::generator() * &x).boxed()
        }
    }

    #[test]
    fn test_field() {
        algebra::test_suites::test_field(file!(), &F::arbitrary());
    }

    #[test]
    fn test_group() {
        algebra::test_suites::test_space(file!(), &F::arbitrary(), &G::arbitrary());
    }

    proptest! {
        #[test]
        fn test_f_codec(x: F) {
            assert_eq!(&x, &F::read(&mut x.encode()).unwrap());
        }

        #[test]
        fn test_g_codec(x: G) {
            assert_eq!(&x, &G::read(&mut x.encode()).unwrap());
        }
    }
}
