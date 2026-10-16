//! Decoded Multimmit artifacts and their identities.

use crate::{
    Epochable, Viewable as _,
    multimmit::types::{
        ChainId, Floor, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteUpdate, Vqc,
    },
    types::{Attributable as _, Epoch, Height, Participant, View},
};
#[cfg(not(target_arch = "wasm32"))]
use commonware_codec::Encode;
use commonware_codec::{EncodeSize as _, Write as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

const ARTIFACT_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_ARTIFACT";

/// Evaluates `$e` with `$v` bound to the value inside whichever [`Artifact`] variant `$a` holds.
macro_rules! each_artifact {
    ($a:expr, $v:ident => $e:expr) => {
        match $a {
            Artifact::TransactionBlock($v) => $e,
            Artifact::LeaderBlock($v) => $e,
            Artifact::Update($v) => $e,
            Artifact::Vqc($v) => $e,
            Artifact::Lqc($v) => $e,
            Artifact::Floor($v) => $e,
        }
    };
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use each_artifact;

/// The decoded Multimmit wire objects accepted by the local machine.
///
/// Values in this enum have passed their bounded codec or constructor checks, but remain
/// cryptographically and contextually untrusted until the machine processes a matching verification
/// completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Artifact<V: Variant, D: Digest> {
    /// A producer-authenticated transaction-block header.
    TransactionBlock(SignedTransactionBlock<V, D>),
    /// A scheduled leader's signed proposal.
    LeaderBlock(SignedLeaderBlock<V, D>),
    /// One validator's vote update.
    Update(VoteUpdate<V, D>),
    /// A view quorum certificate.
    Vqc(Vqc<V, D>),
    /// A leader finalization quorum certificate.
    Lqc(Lqc<V, D>),
    /// A finalization certificate with the record opening its leader block's history commitment,
    /// which a node far behind its peers anchors on.
    Floor(Floor<V, D>),
}

/// An immutable atomic publication of canonical artifacts.
#[cfg(not(target_arch = "wasm32"))]
pub type ArtifactBatch<V, D> = Arc<[Arc<Artifact<V, D>>]>;

impl<V: Variant, D: Digest> Artifact<V, D> {
    /// Returns whether this artifact carries view progress.
    ///
    /// Proposals, vote updates, V-QCs, and finalization certificates sit on the path to the next
    /// view, so their verification is scheduled ahead of bulk traffic. Transaction-block headers
    /// and L-QCs do not: a view resolves from the votes the machine counts, and an L-QC is only
    /// reported, served, and installed in floors.
    pub const fn view_critical(&self) -> bool {
        !matches!(self, Self::TransactionBlock(_) | Self::Lqc(_))
    }

    /// Returns this artifact's operation class.
    pub const fn kind(&self) -> ArtifactKind {
        match self {
            Self::TransactionBlock(_) => ArtifactKind::TransactionBlock,
            Self::LeaderBlock(_) => ArtifactKind::LeaderBlock,
            Self::Update(_) => ArtifactKind::Update,
            Self::Vqc(_) => ArtifactKind::Vqc,
            Self::Lqc(_) => ArtifactKind::Lqc,
            Self::Floor(_) => ArtifactKind::Floor,
        }
    }

    /// Returns the producer chain and height for a chain-scoped artifact.
    pub const fn chain_height(&self) -> Option<(ChainId, Height)> {
        match self {
            Self::TransactionBlock(block) => {
                Some((block.header().chain(), block.header().height()))
            }
            Self::LeaderBlock(_)
            | Self::Update(_)
            | Self::Vqc(_)
            | Self::Lqc(_)
            | Self::Floor(_) => None,
        }
    }

    /// Returns the view for a view-scoped artifact.
    pub fn view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) => None,
            Self::LeaderBlock(block) => Some(block.view()),
            Self::Update(update) => Some(update.view()),
            Self::Vqc(certificate) => Some(certificate.view()),
            Self::Lqc(certificate) => Some(certificate.view()),
            Self::Floor(floor) => Some(floor.lqc().view()),
        }
    }

    /// Returns the participant for an individually attributed artifact.
    pub fn signer(&self) -> Option<Participant> {
        match self {
            Self::TransactionBlock(block) => Some(block.signer()),
            Self::LeaderBlock(block) => Some(block.signer()),
            Self::Update(update) => Some(update.signer()),
            Self::Vqc(_) | Self::Lqc(_) | Self::Floor(_) => None,
        }
    }

    /// Returns the artifact's canonical encoded length.
    pub fn encoded_len(&self) -> usize {
        each_artifact!(self, value => value.encode_size())
    }

    /// Computes the identifier an artifact of `kind` wrapping `value` would carry.
    ///
    /// Wrapping a borrowed proposal or certificate in [`Artifact`] to identify it clones the whole
    /// value first, so callers that hold only the part identify it directly.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn id_of<H: Hasher<Digest = D>, T: Encode>(
        kind: ArtifactKind,
        value: &T,
    ) -> ArtifactId<D> {
        let kind = [kind as u8];
        ArtifactId(H::hash(&[
            ARTIFACT_NAMESPACE,
            &kind,
            value.encode().as_ref(),
        ]))
    }

    /// Computes a domain-separated identifier for the encoded artifact.
    pub fn id<H: Hasher<Digest = D>>(&self) -> ArtifactId<D> {
        self.id_with_scratch::<H>(&mut Vec::new())
    }

    pub(crate) fn id_with_scratch<H: Hasher<Digest = D>>(
        &self,
        encoded: &mut Vec<u8>,
    ) -> ArtifactId<D> {
        self.write_canonical_encoding(encoded);
        self.id_from_canonical_encoding::<H>(encoded)
    }

    pub(crate) fn write_canonical_encoding(&self, encoded: &mut Vec<u8>) {
        encoded.clear();
        encoded.reserve(self.encoded_len());
        each_artifact!(self, value => value.write(encoded));
        debug_assert_eq!(encoded.len(), self.encoded_len());
    }

    /// Identifies canonical bytes already encoded for this artifact.
    pub(crate) fn id_from_canonical_encoding<H: Hasher<Digest = D>>(
        &self,
        encoded: &[u8],
    ) -> ArtifactId<D> {
        debug_assert_eq!(encoded.len(), self.encoded_len());
        let kind = [self.kind() as u8];
        ArtifactId(H::hash(&[ARTIFACT_NAMESPACE, &kind, encoded]))
    }
}

impl<V: Variant, D: Digest> Epochable for Artifact<V, D> {
    fn epoch(&self) -> Epoch {
        each_artifact!(self, value => value.epoch())
    }
}

impl<V: Variant, D: Digest> fmt::Display for Artifact<V, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind())
    }
}

/// A stable operation class used for verification grouping and diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ArtifactKind {
    /// Producer transaction-block signature.
    TransactionBlock = 0,
    /// Leader proposal signature.
    LeaderBlock = 1,
    /// Vote update.
    Update = 2,
    /// View quorum certificate.
    Vqc = 3,
    /// Leader finalization certificate.
    Lqc = 4,
    /// Finalization certificate with its opening.
    Floor = 5,
}

impl TryFrom<u8> for ArtifactKind {
    type Error = commonware_codec::Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        Ok(match tag {
            0 => Self::TransactionBlock,
            1 => Self::LeaderBlock,
            2 => Self::Update,
            3 => Self::Vqc,
            4 => Self::Lqc,
            5 => Self::Floor,
            tag => return Err(commonware_codec::Error::InvalidEnum(tag)),
        })
    }
}

/// Identifies exact artifact bytes within one epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId<D: Digest>(D);

impl<D: Digest> ArtifactId<D> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    pub const fn get(self) -> D {
        self.0
    }
}
