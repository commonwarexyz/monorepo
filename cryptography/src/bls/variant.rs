//! Different variants of the BLS signature scheme.
//!
//! A [Variant] names the scalar field that holds private keys, the group that holds public keys,
//! and that group's [PairingGroup::Twin], which holds signatures and hashed messages.

use crate::curve::{DST, ScalarReadCfg};
use bytes::BufMut;
use commonware_codec::{
    Buf, CodecFixed, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_math::algebra::{FieldNTT, HashToGroup, PairingGroup, Random, Space};
use commonware_utils::Participant;
use core::{fmt::Debug, hash::Hash};
use ctutils::CtEq;

/// A specific instance of a signature scheme.
pub trait Variant: Clone + Send + Sync + Hash + Eq + Debug + 'static {
    /// The scalar type, which holds private keys.
    type Scalar: FieldNTT
        + Random
        + From<u64>
        + CtEq
        + Read<Cfg = ScalarReadCfg>
        + Write
        + FixedSize;

    /// The public key type.
    type Public: PairingGroup<Scalar = Self::Scalar, Twin = Self::Signature, Target: Encode>
        + HashToGroup
        + Space<Self::Challenge>
        + CodecFixed<Cfg = ()>
        + Hash
        + Copy;

    /// The signature type.
    type Signature: HashToGroup<Scalar = Self::Scalar>
        + Space<Self::Challenge>
        + CodecFixed<Cfg = ()>
        + Hash
        + Copy;

    /// The random scalars that batch verification multiplies by.
    ///
    /// Uniformly sampled values must give a soundness error of at most `2^-128` in random
    /// linear-combination checks.
    type Challenge: Random + Send + Sync;

    /// The domain separator tag (DST) for a proof of possession.
    const PROOF_OF_POSSESSION: DST;

    /// The domain separator tag (DST) for a message.
    const MESSAGE: DST;
}

/// A partial signature.
///
/// c.f. [`super::ops`] for how to manipulate these.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialSignature<V: Variant> {
    pub index: Participant,
    pub value: V::Signature,
}

impl<V: Variant> Write for PartialSignature<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.value.write(buf);
    }
}

impl<V: Variant> Read for PartialSignature<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = Participant::read(buf)?;
        let value = V::Signature::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<V: Variant> EncodeSize for PartialSignature<V> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + V::Signature::SIZE
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant> arbitrary::Arbitrary<'a> for PartialSignature<V>
where
    V::Scalar: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use commonware_math::algebra::CryptoGroup;

        Ok(Self {
            index: u.arbitrary()?,
            value: <V::Signature as CryptoGroup>::generator() * &u.arbitrary::<V::Scalar>()?,
        })
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<PartialSignature<MinPk>>,
        CodecConformance<PartialSignature<MinSig>>,
    }
}
