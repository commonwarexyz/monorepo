//! The mock group: a BLS [`Variant`] whose group is the scalar field itself.
//!
//! An element is `generator * s` for a scalar `s`, stored as the canonical
//! encoding of `s`. The generator is one, scalar multiplication is field
//! multiplication, and a signature verifies when it equals the product of the
//! hashed message and the public key. The group is isomorphic to the real
//! groups as a module over the scalar field, so every algebraic check in the
//! ceremony returns the verdict it would return on the real curve, while no
//! curve arithmetic, pairing, or hash-to-curve runs.
//!
//! It offers no security: the discrete logarithm of every element is the
//! element.

use bytes::BufMut;
use commonware_codec::{Buf, Copying, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{DST, GT, SCALAR_LENGTH, Scalar, ScalarReadCfg, SmallScalar},
    variant::Variant,
};
use commonware_math::algebra::{Additive, CryptoGroup, HashToGroup, Object, Ring, Space};
use commonware_parallel::Strategy;
use core::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRng;

/// An element of the mock group.
///
/// The encoding is stored instead of the [`Scalar`] because the elements of a
/// [`Variant`] must be `Copy` and a scalar is not.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MockPoint([u8; SCALAR_LENGTH]);

impl MockPoint {
    /// The scalar this element is the generator's multiple of.
    fn scalar(&self) -> Scalar {
        Scalar::read_cfg(&mut Copying(&self.0), &ScalarReadCfg::AllowZero)
            .expect("a mock point holds a canonical scalar encoding")
    }

    /// The element `generator * scalar`.
    fn from_scalar(scalar: &Scalar) -> Self {
        let mut out = [0u8; SCALAR_LENGTH];
        scalar.write(&mut &mut out[..]);
        Self(out)
    }
}

impl Debug for MockPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "MockPoint(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl Write for MockPoint {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }
}

impl Read for MockPoint {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, (): &()) -> Result<Self, CodecError> {
        let bytes = <[u8; SCALAR_LENGTH]>::read(buf)?;

        // The real groups reject a non-canonical encoding and the identity.
        Scalar::read_cfg(&mut Copying(&bytes), &ScalarReadCfg::RejectZero)?;
        Ok(Self(bytes))
    }
}

impl FixedSize for MockPoint {
    const SIZE: usize = SCALAR_LENGTH;
}

impl Object for MockPoint {}

impl<'a> AddAssign<&'a Self> for MockPoint {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = Self::from_scalar(&(self.scalar() + &rhs.scalar()));
    }
}

impl<'a> Add<&'a Self> for MockPoint {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for MockPoint {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = Self::from_scalar(&(self.scalar() - &rhs.scalar()));
    }
}

impl<'a> Sub<&'a Self> for MockPoint {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for MockPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::from_scalar(&-self.scalar())
    }
}

impl Additive for MockPoint {
    fn zero() -> Self {
        Self([0u8; SCALAR_LENGTH])
    }
}

impl<'a> MulAssign<&'a Scalar> for MockPoint {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
        *self = Self::from_scalar(&(self.scalar() * rhs));
    }
}

impl<'a> Mul<&'a Scalar> for MockPoint {
    type Output = Self;

    fn mul(mut self, rhs: &'a Scalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a> MulAssign<&'a SmallScalar> for MockPoint {
    fn mul_assign(&mut self, rhs: &'a SmallScalar) {
        *self *= &Scalar::from(rhs.clone());
    }
}

impl<'a> Mul<&'a SmallScalar> for MockPoint {
    type Output = Self;

    fn mul(mut self, rhs: &'a SmallScalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<Scalar> for MockPoint {}

impl Space<SmallScalar> for MockPoint {}

impl CryptoGroup for MockPoint {
    type Scalar = Scalar;

    fn generator() -> Self {
        Self::from_scalar(&Scalar::one())
    }
}

impl HashToGroup for MockPoint {
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        Self::from_scalar(&Scalar::map(domain_separator, message))
    }
}

/// The mock group as a BLS [`Variant`]: public keys and signatures are both
/// [`MockPoint`]s.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct MockGroup;

impl Variant for MockGroup {
    type Public = MockPoint;
    type Signature = MockPoint;

    const PROOF_OF_POSSESSION: DST = b"GLUE_FUZZ_DKG_MOCK_GROUP_POP_";
    const MESSAGE: DST = b"GLUE_FUZZ_DKG_MOCK_GROUP_SIG_";

    /// The pairing equation `e(hm, public) == e(signature, generator)` holds
    /// exactly when `signature == hm * public` as scalars.
    fn verify(
        public: &Self::Public,
        hm: &Self::Signature,
        signature: &Self::Signature,
    ) -> Result<(), Error> {
        if signature == &Self::Signature::zero() {
            return Err(Error::InvalidSignature);
        }
        if signature.scalar() != hm.scalar() * &public.scalar() {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    fn batch_verify(
        _: &mut impl CryptoRng,
        publics: &[Self::Public],
        hms: &[Self::Signature],
        signatures: &[Self::Signature],
        _: &impl Strategy,
    ) -> Result<(), Error> {
        assert_eq!(publics.len(), hms.len());
        assert_eq!(publics.len(), signatures.len());
        if publics.is_empty() {
            return Err(Error::InvalidSignature);
        }
        for ((public, hm), signature) in publics.iter().zip(hms).zip(signatures) {
            Self::verify(public, hm, signature)?;
        }
        Ok(())
    }

    fn pairing(_: &Self::Public, _: &Self::Signature) -> GT {
        panic!("the mock group has no target group: nothing the DKG fuzzing reaches pairs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{
            ops::{self, threshold},
            sharing::Mode,
        },
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_utils::{N3f1, TestRng, ordered::Set};

    const NAMESPACE: &[u8] = b"mock";

    #[test]
    fn module_laws_hold() {
        let mut rng = TestRng::new(0);
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let g = MockPoint::generator();
        assert_eq!(g * &a + &(g * &b), g * &(a.clone() + &b));
        assert_eq!((g * &a) * &b, g * &(a.clone() * &b));
        assert_eq!(g * &a - &(g * &a), MockPoint::zero());
        assert_eq!(-(g * &a) + &(g * &a), MockPoint::zero());
    }

    #[test]
    fn codec_rejects_identity_and_roundtrips() {
        let mut rng = TestRng::new(1);
        let point = MockPoint::generator() * &Scalar::random(&mut rng);
        assert_eq!(MockPoint::decode(point.encode()).unwrap(), point);
        assert!(MockPoint::decode(MockPoint::zero().encode()).is_err());
        assert!(MockPoint::read(&mut Copying(&[0xff; SCALAR_LENGTH])).is_err());
    }

    #[test]
    fn threshold_signatures_recover_and_verify() {
        let mut rng = TestRng::new(2);
        let players: Set<u32> = Set::from_iter_dedup(0..4u32);
        let (output, shares) =
            deal::<MockGroup, _, N3f1>(&mut rng, Mode::NonZeroCounter, players).unwrap();
        let sharing = output.public();
        assert_eq!(sharing.required(), 3);
        for share in shares.values() {
            assert_eq!(
                share.public::<MockGroup>(),
                sharing.partial_public(share.index).unwrap()
            );
        }

        let message = b"message";
        let partials: Vec<_> = shares
            .values()
            .iter()
            .take(3)
            .map(|share| threshold::sign_message::<MockGroup>(share, NAMESPACE, message))
            .collect();
        let signature = threshold::recover::<MockGroup, _>(sharing, &partials, &Sequential)
            .expect("a quorum must recover");
        ops::verify_message::<MockGroup>(sharing.public(), NAMESPACE, message, &signature)
            .expect("the recovered signature must verify");
        assert!(
            ops::verify_message::<MockGroup>(sharing.public(), NAMESPACE, b"other", &signature)
                .is_err()
        );
        assert!(threshold::recover::<MockGroup, _>(sharing, &partials[..2], &Sequential).is_err());
    }
}
