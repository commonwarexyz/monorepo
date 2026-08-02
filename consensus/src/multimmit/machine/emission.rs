//! Bounded resolution requests and completions.

use crate::{
    Viewable as _,
    multimmit::{
        config::CodecConfig,
        types::{Lqc, Nullification, Vqc},
    },
    types::View,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
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
impl<'a, V, D> arbitrary::Arbitrary<'a> for ViewProof<V, D>
where
    V: Variant,
    V::Signature: for<'b> arbitrary::Arbitrary<'b>,
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    commonware_cryptography::Sha256: commonware_cryptography::Hasher<Digest = D>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Nullification(Box::new(u.arbitrary()?))),
            1 => Ok(Self::Vqc(Box::new(u.arbitrary()?))),
            _ => Ok(Self::Lqc(Box::new(u.arbitrary()?))),
        }
    }
}

/// A completion correlated to one exact resolution request.
#[derive(Clone, Debug)]
pub struct ResolutionCompletion<V: Variant, D: Digest> {
    id: ResolutionId,
    generation: u64,
    view: View,
    proof: ViewProof<V, D>,
}

impl<V: Variant, D: Digest> ResolutionCompletion<V, D> {
    /// Creates a completion for one machine-issued request.
    pub const fn new(
        id: ResolutionId,
        generation: u64,
        view: View,
        proof: ViewProof<V, D>,
    ) -> Self {
        Self {
            id,
            generation,
            view,
            proof,
        }
    }

    /// Returns the request identifier.
    pub const fn id(&self) -> ResolutionId {
        self.id
    }

    /// Returns the issuing process generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the requested view.
    pub const fn view(&self) -> View {
        self.view
    }

    /// Returns the decoded proof.
    pub const fn proof(&self) -> &ViewProof<V, D> {
        &self.proof
    }

    pub(crate) fn into_proof(self) -> ViewProof<V, D> {
        self.proof
    }
}

/// Identifies one volatile resolution request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionId(u64);

impl ResolutionId {
    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded, deduplicated work for resolving one exact immutable object.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionJob {
    id: ResolutionId,
    generation: u64,
    view: View,
}

impl ResolutionJob {
    pub(crate) const fn issue(id: u64, generation: u64, view: View) -> Self {
        Self {
            id: ResolutionId(id),
            generation,
            view,
        }
    }

    /// Fabricates a job for executor tests; production jobs are machine-issued only.
    #[cfg(test)]
    pub const fn fabricate(id: u64, generation: u64, view: View) -> Self {
        Self {
            id: ResolutionId(id),
            generation,
            view,
        }
    }

    /// Returns the request identifier.
    pub const fn id(self) -> ResolutionId {
        self.id
    }

    /// Returns the process generation issuing the request.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the view to resolve.
    pub const fn view(self) -> View {
        self.view
    }
}
