//! Authenticated evidence that crosses or makes obsolete a requested view.

use crate::{
    Viewable as _,
    multimmit::types::{Artifact, CodecConfig, Lqc, Nullification, Vqc},
    types::View,
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// Authenticated evidence that crosses or makes obsolete a requested view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewProof<V: Variant, D: Digest> {
    /// A threshold proof that the requested view was nullified.
    Nullification(Box<Nullification<V>>),
    /// A quorum certificate selecting a leader in the requested view.
    Vqc(Box<Vqc<V, D>>),
    /// An L-QC at or above the requested view.
    Lqc(Box<Lqc<V, D>>),
}

impl<V: Variant, D: Digest> ViewProof<V, D> {
    /// Returns the view authenticated by this proof.
    pub fn view(&self) -> View {
        match self {
            Self::Nullification(proof) => proof.view(),
            Self::Vqc(proof) => proof.view(),
            Self::Lqc(proof) => proof.view(),
        }
    }

    /// Returns the proof carried by `artifact`, or `None` when it is not a view proof.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_artifact(artifact: &Artifact<V, D>) -> Option<Self> {
        match artifact {
            Artifact::Nullification(proof) => Some(Self::Nullification(Box::new(proof.clone()))),
            Artifact::Vqc(proof) => Some(Self::Vqc(Box::new(proof.clone()))),
            Artifact::Lqc(proof) => Some(Self::Lqc(Box::new(proof.clone()))),
            _ => None,
        }
    }

    /// Returns whether this proof answers a request for `view`.
    ///
    /// A nullification or V-QC must name `view` itself. An L-QC at or above `view` makes the
    /// request obsolete.
    pub fn covers(&self, view: View) -> bool {
        match self {
            Self::Nullification(_) | Self::Vqc(_) => self.view() == view,
            Self::Lqc(proof) => proof.view() >= view,
        }
    }

    /// Converts this proof into the artifact it carries.
    pub fn into_artifact(self) -> Artifact<V, D> {
        match self {
            Self::Nullification(proof) => Artifact::Nullification(*proof),
            Self::Vqc(proof) => Artifact::Vqc(*proof),
            Self::Lqc(proof) => Artifact::Lqc(*proof),
        }
    }
}

impl<V: Variant, D: Digest> Write for ViewProof<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Nullification(proof) => {
                0u8.write(buf);
                proof.write(buf);
            }
            Self::Vqc(proof) => {
                1u8.write(buf);
                proof.write(buf);
            }
            Self::Lqc(proof) => {
                2u8.write(buf);
                proof.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ViewProof<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Nullification(proof) => proof.encode_size(),
            Self::Vqc(proof) => proof.encode_size(),
            Self::Lqc(proof) => proof.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for ViewProof<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Nullification(Box::new(Nullification::read(buf)?))),
            1 => Ok(Self::Vqc(Box::new(Vqc::read_cfg(buf, cfg)?))),
            2 => Ok(Self::Lqc(Box::new(Lqc::read_cfg(buf, cfg)?))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V> arbitrary::Arbitrary<'a> for ViewProof<V, commonware_cryptography::sha256::Digest>
where
    V: Variant,
    V::Signature: for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Nullification(Box::new(u.arbitrary()?))),
            1 => Ok(Self::Vqc(Box::new(u.arbitrary()?))),
            _ => Ok(Self::Lqc(Box::new(u.arbitrary()?))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::mocks::Committee;
    use commonware_codec::{Copying, Decode as _, Encode as _};
    use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};

    fn committee() -> Committee<MinPk> {
        Committee::builder(7, 6).build()
    }

    #[test]
    fn proof_codec_round_trip() {
        let committee = committee();
        let codec = committee.codec();
        let proofs = [
            ViewProof::Nullification(Box::new(committee.nullification(View::new(1)))),
            ViewProof::Vqc(Box::new(committee.vqc(View::new(2)))),
            ViewProof::Lqc(Box::new(committee.lqc(View::new(3)))),
        ];

        for proof in proofs {
            let encoded = proof.encode();
            let decoded = ViewProof::<MinPk, Digest>::decode_cfg(encoded, &codec).unwrap();
            assert_eq!(decoded, proof);
        }
    }

    #[test]
    fn proof_codec_rejects_unknown_tag() {
        let committee = committee();
        assert!(ViewProof::<MinPk, Digest>::decode_cfg(Copying(&[3]), &committee.codec()).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::bls12381::primitives::variant::MinSig;

        commonware_conformance::conformance_tests! {
            CodecConformance<ViewProof<MinPk, Digest>> => 128,
            CodecConformance<ViewProof<MinSig, Digest>> => 128,
        }
    }
}
