//! Bandersnatch curve types for use in the Golden DKG EVRF.
//!
//! Bandersnatch is a twisted Edwards curve defined over the BLS12-381 scalar
//! field. This module wraps the arkworks implementation to conform to the
//! codebase's algebra trait hierarchy.

use ark_ec::{twisted_edwards::Projective, AdditiveGroup, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, Fr};
#[cfg(any(test, feature = "arbitrary"))]
use ark_ff::PrimeField;
use ark_ff::{Field as ArkField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::{
    Additive, CryptoGroup, Field, Multiplicative, Object, Random, Ring, Space,
};
use commonware_parallel::Strategy;
use core::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;

/// A scalar in the Bandersnatch scalar field.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct F(Fr);

impl F {
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        self.0
            .serialize_compressed(&mut bytes[..])
            .expect("serialization into fixed buffer succeeds");
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, CodecError> {
        let fr = Fr::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map_err(|_| CodecError::Invalid("bandersnatch::F", "invalid"))?;
        Ok(Self(fr))
    }
}

impl Debug for F {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "bandersnatch::F([REDACTED])")
    }
}

impl Object for F {}

impl<'a> AddAssign<&'a Self> for F {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
    }
}

impl<'a> Add<&'a Self> for F {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for F {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= rhs.0;
    }
}

impl<'a> Sub<&'a Self> for F {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Additive for F {
    fn zero() -> Self {
        Self(Fr::from(0u64))
    }
}

impl<'a> MulAssign<&'a Self> for F {
    fn mul_assign(&mut self, rhs: &'a Self) {
        self.0 *= rhs.0;
    }
}

impl<'a> Mul<&'a Self> for F {
    type Output = Self;

    fn mul(mut self, rhs: &'a Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Multiplicative for F {}

impl Ring for F {
    fn one() -> Self {
        Self(Fr::from(1u64))
    }
}

impl Field for F {
    fn inv(&self) -> Self {
        if self.0.is_zero() {
            return Self::zero();
        }
        Self(self.0.inverse().expect("nonzero element has inverse"))
    }
}

impl Random for F {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        Self(Fr::rand(&mut rng))
    }
}

impl Write for F {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.to_bytes());
    }
}

impl Read for F {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        Self::from_bytes(&bytes)
    }
}

impl FixedSize for F {
    const SIZE: usize = 32;
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = u.arbitrary::<[u8; 32]>()?;
        Ok(Self(Fr::from_le_bytes_mod_order(&bytes)))
    }
}

/// A point on the Bandersnatch curve (twisted Edwards form).
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct G(Projective<BandersnatchConfig>);

impl G {
    /// Map this point into the prime-order subgroup by multiplying by the cofactor (4).
    pub fn clear_cofactor(&self) -> Self {
        let mut p = self.0;
        p.double_in_place();
        p.double_in_place();
        Self(p)
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let affine = self.0.into_affine();
        let mut bytes = [0u8; Self::SIZE];
        affine
            .serialize_compressed(&mut bytes[..])
            .expect("serialization into fixed buffer succeeds");
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, CodecError> {
        let affine = EdwardsAffine::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map_err(|_| CodecError::Invalid("bandersnatch::G", "invalid"))?;
        Ok(Self(affine.into()))
    }
}

impl Debug for G {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "bandersnatch::G({})",
            commonware_utils::hex(&self.to_bytes())
        )
    }
}

impl Object for G {}

impl<'a> AddAssign<&'a Self> for G {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
    }
}

impl<'a> Add<&'a Self> for G {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for G {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= rhs.0;
    }
}

impl<'a> Sub<&'a Self> for G {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for G {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Additive for G {
    fn zero() -> Self {
        Self(Projective::<BandersnatchConfig>::zero())
    }

    fn double(&mut self) {
        self.0.double_in_place();
    }
}

impl<'a> MulAssign<&'a F> for G {
    fn mul_assign(&mut self, rhs: &'a F) {
        self.0 *= rhs.0;
    }
}

impl<'a> Mul<&'a F> for G {
    type Output = Self;

    fn mul(mut self, rhs: &'a F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<F> for G {
    fn msm(points: &[Self], scalars: &[F], _strategy: &impl Strategy) -> Self {
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        if points.is_empty() {
            return Self::zero();
        }
        let affines: Vec<EdwardsAffine> = points.iter().map(|p| p.0.into_affine()).collect();
        let frs: Vec<Fr> = scalars.iter().map(|s| s.0).collect();
        Self(Projective::<BandersnatchConfig>::msm(&affines, &frs).expect("lengths are equal"))
    }
}

impl CryptoGroup for G {
    type Scalar = F;

    fn generator() -> Self {
        Self(Projective::<BandersnatchConfig>::generator())
    }
}

impl Write for G {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.to_bytes());
    }
}

impl Read for G {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        Self::from_bytes(&bytes)
    }
}

impl FixedSize for G {
    const SIZE: usize = 32;
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for G {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::generator() * &u.arbitrary::<F>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::test_suites;

    #[test]
    fn test_scalar_as_field() {
        minifuzz::test(test_suites::fuzz_field::<F>);
    }

    #[test]
    fn test_point_as_space() {
        minifuzz::test(test_suites::fuzz_space_ring::<F, G>);
    }
}
