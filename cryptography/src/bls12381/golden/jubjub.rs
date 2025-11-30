//! Jubjub curve primitives for Golden DKG.
//!
//! Jubjub is an embedded curve over BLS12-381's scalar field. This means:
//! - Jubjub's base field Fq == BLS12-381's scalar field Fr
//! - x-coordinates of Jubjub points are directly usable as BLS12-381 scalars
//! - Bulletproofs (which operate in Fr) can work with Jubjub coordinates NATIVELY
//!
//! This eliminates the need for expensive non-native field arithmetic in the circuit.

use super::super::primitives::group::{Element as BlsElement, Scalar as BlsScalar};
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Error as CodecError, FixedSize, Read, Write};
use commonware_utils::hex;
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
};
use ::group::{Group, GroupEncoding};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Re-export jubjub types for clarity.
pub use jubjub::{AffinePoint, ExtendedPoint, Fr as JubjubScalar};

/// Size of a compressed Jubjub point (32 bytes).
pub const POINT_SIZE: usize = 32;

/// Size of a Jubjub scalar (32 bytes).
pub const SCALAR_SIZE: usize = 32;

/// A point on the Jubjub curve.
///
/// This is used for identity keys (G_in) in the Golden DKG protocol.
/// Coordinates are in BLS12-381's scalar field Fr, making them native
/// for Bulletproofs arithmetic.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct JubjubPoint(ExtendedPoint);

impl JubjubPoint {
    /// Returns the identity (neutral) element.
    pub fn identity() -> Self {
        Self(ExtendedPoint::identity())
    }

    /// Returns the generator point.
    pub fn generator() -> Self {
        Self(ExtendedPoint::generator())
    }

    /// Creates a point from an extended point.
    pub fn from_extended(point: ExtendedPoint) -> Self {
        Self(point)
    }

    /// Returns the inner extended point.
    pub fn inner(&self) -> &ExtendedPoint {
        &self.0
    }

    /// Adds another point to this one.
    pub fn add(&mut self, other: &Self) {
        self.0 += other.0;
    }

    /// Doubles this point (P + P = 2P).
    pub fn double(&self) -> Self {
        Self(self.0.double())
    }

    /// Multiplies this point by a scalar.
    pub fn mul(&mut self, scalar: &JubjubScalarWrapper) {
        self.0 *= scalar.inner();
    }

    /// Multiplies the generator by a scalar.
    pub fn mul_generator(scalar: &JubjubScalarWrapper) -> Self {
        Self(ExtendedPoint::generator() * scalar.inner())
    }

    /// Returns the affine u-coordinate.
    ///
    /// This coordinate is in Jubjub's base field, which equals BLS12-381's scalar field.
    /// It can be directly used as a BLS12-381 scalar.
    pub fn get_u(&self) -> jubjub::Fq {
        let affine = AffinePoint::from(&self.0);
        affine.get_u()
    }

    /// Returns the affine v-coordinate.
    pub fn get_v(&self) -> jubjub::Fq {
        let affine = AffinePoint::from(&self.0);
        affine.get_v()
    }

    /// Converts the u-coordinate to a BLS12-381 scalar.
    ///
    /// Since Jubjub's base field == BLS12-381's scalar field,
    /// this is a direct byte reinterpretation.
    /// Note: We need to reverse bytes because:
    /// - `bls12_381::Scalar::to_bytes()` returns little-endian
    /// - `blst` expects big-endian for decoding
    pub fn u_as_bls_scalar(&self) -> BlsScalar {
        let u = self.get_u();
        let mut bytes = u.to_bytes();
        // Reverse from little-endian to big-endian for blst
        bytes.reverse();
        // The bytes are in the same field, so we can decode directly
        // Note: blst_sk_check requires non-zero, so we use Scalar::map as fallback
        if bytes == [0u8; 32] {
            // Zero coordinate - return zero scalar
            return <BlsScalar as BlsElement>::zero();
        }
        BlsScalar::decode(&bytes[..]).expect("valid scalar bytes")
    }

    /// Checks if this is the identity point.
    pub fn is_identity(&self) -> bool {
        bool::from(self.0.is_identity())
    }

    /// Encodes the point to bytes.
    fn as_bytes(&self) -> [u8; POINT_SIZE] {
        self.0.to_bytes()
    }

    /// Decodes a point from bytes.
    pub fn from_bytes(bytes: &[u8; POINT_SIZE]) -> Option<Self> {
        let point = ExtendedPoint::from_bytes(bytes);
        if point.is_some().into() {
            Some(Self(point.unwrap()))
        } else {
            None
        }
    }
}

impl Write for JubjubPoint {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.as_bytes());
    }
}

impl Read for JubjubPoint {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; POINT_SIZE]>::read_cfg(buf, &())?;
        Self::from_bytes(&bytes).ok_or(CodecError::Invalid("JubjubPoint", "invalid encoding"))
    }
}

impl FixedSize for JubjubPoint {
    const SIZE: usize = POINT_SIZE;
}

impl Hash for JubjubPoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl PartialOrd for JubjubPoint {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JubjubPoint {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(&other.as_bytes())
    }
}

impl Debug for JubjubPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "JubjubPoint({})", hex(&self.as_bytes()))
    }
}

impl Display for JubjubPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_bytes()))
    }
}

/// A scalar in Jubjub's scalar field.
///
/// This is used for identity secret keys in the Golden DKG protocol.
/// Note: Jubjub's scalar field Fr is different from its base field Fq.
#[derive(Clone, Eq, PartialEq)]
pub struct JubjubScalarWrapper(JubjubScalar);

impl JubjubScalarWrapper {
    /// Returns the zero scalar.
    pub fn zero() -> Self {
        Self(JubjubScalar::zero())
    }

    /// Returns the one scalar.
    pub fn one() -> Self {
        Self(JubjubScalar::one())
    }

    /// Generates a random scalar.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        use ff::Field;
        Self(JubjubScalar::random(rng))
    }

    /// Returns the inner scalar.
    pub fn inner(&self) -> &JubjubScalar {
        &self.0
    }

    /// Adds another scalar to this one.
    pub fn add(&mut self, other: &Self) {
        self.0 += other.0;
    }

    /// Subtracts another scalar from this one.
    pub fn sub(&mut self, other: &Self) {
        self.0 -= other.0;
    }

    /// Multiplies this scalar by another.
    pub fn mul(&mut self, other: &Self) {
        self.0 *= other.0;
    }

    /// Returns the multiplicative inverse, if it exists.
    pub fn inverse(&self) -> Option<Self> {
        let inv = self.0.invert();
        if inv.is_some().into() {
            Some(Self(inv.unwrap()))
        } else {
            None
        }
    }

    /// Encodes the scalar to bytes.
    fn as_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0.to_bytes()
    }

    /// Decodes a scalar from bytes.
    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> Option<Self> {
        let scalar = JubjubScalar::from_bytes(bytes);
        if scalar.is_some().into() {
            Some(Self(scalar.unwrap()))
        } else {
            None
        }
    }
}

impl Write for JubjubScalarWrapper {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.as_bytes());
    }
}

impl Read for JubjubScalarWrapper {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; SCALAR_SIZE]>::read_cfg(buf, &())?;
        Self::from_bytes(&bytes).ok_or(CodecError::Invalid("JubjubScalar", "invalid encoding"))
    }
}

impl FixedSize for JubjubScalarWrapper {
    const SIZE: usize = SCALAR_SIZE;
}

impl Hash for JubjubScalarWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl PartialOrd for JubjubScalarWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JubjubScalarWrapper {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(&other.as_bytes())
    }
}

impl Debug for JubjubScalarWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "JubjubScalar({})", hex(&self.as_bytes()))
    }
}

impl Display for JubjubScalarWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_bytes()))
    }
}

impl Zeroize for JubjubScalarWrapper {
    fn zeroize(&mut self) {
        // JubjubScalar doesn't implement Zeroize directly,
        // but we can convert to bytes, zeroize, and set to zero
        self.0 = JubjubScalar::zero();
    }
}

impl Drop for JubjubScalarWrapper {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for JubjubScalarWrapper {}

/// Identity key pair for the Golden DKG protocol.
///
/// Uses Jubjub curve for PKI, enabling native Bulletproofs arithmetic.
#[derive(Clone)]
pub struct IdentityKey {
    /// The secret key (Jubjub scalar).
    pub secret: JubjubScalarWrapper,
    /// The public key (Jubjub point).
    pub public: JubjubPoint,
}

impl IdentityKey {
    /// Generates a new random identity key pair.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let secret = JubjubScalarWrapper::random(rng);
        let public = JubjubPoint::mul_generator(&secret);
        Self { secret, public }
    }

    /// Creates an identity key from a secret scalar.
    pub fn from_secret(secret: JubjubScalarWrapper) -> Self {
        let public = JubjubPoint::mul_generator(&secret);
        Self { secret, public }
    }

    /// Computes the Diffie-Hellman shared secret with another public key.
    ///
    /// Returns the shared point on Jubjub.
    pub fn dh(&self, other_public: &JubjubPoint) -> JubjubPoint {
        let mut shared = *other_public;
        shared.mul(&self.secret);
        shared
    }

    /// Computes the encryption key alpha for eVRF.
    ///
    /// This is the u-coordinate of the DH shared secret, converted to a BLS scalar.
    /// The symmetry property holds: dh(sk_a, pk_b).u == dh(sk_b, pk_a).u
    pub fn compute_alpha(&self, other_public: &JubjubPoint) -> BlsScalar {
        let shared = self.dh(other_public);
        shared.u_as_bls_scalar()
    }
}

impl Debug for IdentityKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Element;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_point_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let scalar = JubjubScalarWrapper::random(&mut rng);
        let point = JubjubPoint::mul_generator(&scalar);

        let bytes = point.as_bytes();
        let recovered = JubjubPoint::from_bytes(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_scalar_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let scalar = JubjubScalarWrapper::random(&mut rng);

        let bytes = scalar.as_bytes();
        let recovered = JubjubScalarWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn test_identity_key_generation() {
        let mut rng = StdRng::seed_from_u64(42);
        let key = IdentityKey::generate(&mut rng);

        // Public key should be generator * secret
        let expected_public = JubjubPoint::mul_generator(&key.secret);
        assert_eq!(key.public, expected_public);
    }

    #[test]
    fn test_dh_symmetry() {
        let mut rng = StdRng::seed_from_u64(42);
        let alice = IdentityKey::generate(&mut rng);
        let bob = IdentityKey::generate(&mut rng);

        // DH should be symmetric: alice.dh(bob.public) == bob.dh(alice.public)
        let shared_alice = alice.dh(&bob.public);
        let shared_bob = bob.dh(&alice.public);

        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_alpha_symmetry() {
        let mut rng = StdRng::seed_from_u64(42);
        let alice = IdentityKey::generate(&mut rng);
        let bob = IdentityKey::generate(&mut rng);

        // Alpha should be symmetric
        let alpha_alice = alice.compute_alpha(&bob.public);
        let alpha_bob = bob.compute_alpha(&alice.public);

        assert_eq!(alpha_alice, alpha_bob);
    }

    #[test]
    fn test_u_coordinate_is_bls_scalar() {
        let mut rng = StdRng::seed_from_u64(42);
        let scalar = JubjubScalarWrapper::random(&mut rng);
        let point = JubjubPoint::mul_generator(&scalar);

        // The u-coordinate should be convertible to a BLS scalar
        let bls_scalar = point.u_as_bls_scalar();

        // Verify it's not zero (very unlikely for random point)
        assert_ne!(bls_scalar, BlsScalar::zero());
    }

    #[test]
    fn test_point_addition() {
        // Use small known scalars to verify the math
        let s1 = JubjubScalarWrapper::one();
        let mut s2 = JubjubScalarWrapper::one();
        s2.add(&JubjubScalarWrapper::one()); // s2 = 2

        let p1 = JubjubPoint::mul_generator(&s1); // G
        let p2 = JubjubPoint::mul_generator(&s2); // 2G

        // (1 + 2) * G == G + 2G == 3G
        let mut sum_scalar = s1.clone();
        sum_scalar.add(&s2); // s1 + s2 = 3
        let expected = JubjubPoint::mul_generator(&sum_scalar); // 3G

        let mut actual = p1;
        actual.add(&p2); // G + 2G

        assert_eq!(expected, actual);
    }
}
