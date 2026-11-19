//! The variants of the BLS signature scheme over BLS12-381.
//!
//! [MinPk] puts public keys in [G1] and [MinSig] puts them in [G2], as [Twin]<[G1]>.

use super::group::{
    G1, G1_MESSAGE, G1_PROOF_OF_POSSESSION, G2, G2_MESSAGE, G2_PROOF_OF_POSSESSION, Scalar,
    SmallScalar,
};
use crate::{bls::variant::Variant, curve::DST};
use commonware_math::algebra::Twin;
use core::fmt::{Debug, Formatter};

/// The domain separation tag (DST) for the scalar that timelock encryption derives.
const TLE: DST = b"TLE_BLS12381_XMD:SHA-256_SSWU_RO_H3_";

/// The namespace of the transcripts of a distributed key generation.
const DKG: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG";

/// A [Variant] with a public key of type [G1] and a signature of type [G2].
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct MinPk {}

impl Variant for MinPk {
    type Scalar = Scalar;
    type Public = G1;
    type Signature = G2;
    type Challenge = SmallScalar;

    const PROOF_OF_POSSESSION: DST = G2_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G2_MESSAGE;
    const TLE: DST = TLE;
    const DKG: &'static [u8] = DKG;
}

impl Debug for MinPk {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinPk").finish()
    }
}

/// A [Variant] with a public key in [G2], held as [Twin]<[G1]>, and a signature of type [G1].
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct MinSig {}

impl Variant for MinSig {
    type Scalar = Scalar;
    type Public = Twin<G1>;
    type Signature = G1;
    type Challenge = SmallScalar;

    const PROOF_OF_POSSESSION: DST = G1_PROOF_OF_POSSESSION;
    const MESSAGE: DST = G1_MESSAGE;
    const TLE: DST = TLE;
    const DKG: &'static [u8] = DKG;
}

impl Debug for MinSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinSig").finish()
    }
}
