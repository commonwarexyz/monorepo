//! Decoded Multimmit artifacts and their identities.

use crate::{
    Epochable, Viewable as _,
    multimmit::types::{
        ChainId, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
        SignedTransactionBlock, Vote, Vqc,
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
            Artifact::DaVote($v) => $e,
            Artifact::DaCertificate($v) => $e,
            Artifact::LeaderBlock($v) => $e,
            Artifact::Vote($v) => $e,
            Artifact::NoVote($v) => $e,
            Artifact::Nullify($v) => $e,
            Artifact::Nullification($v) => $e,
            Artifact::Vqc($v) => $e,
            Artifact::Lqc($v) => $e,
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
    /// One attributed data-availability share.
    DaVote(DaVote<V, D>),
    /// A recovered data-availability certificate.
    DaCertificate(DaCertificate<V, D>),
    /// A scheduled leader's signed proposal.
    LeaderBlock(SignedLeaderBlock<V, D>),
    /// A complete consensus vote.
    Vote(Vote<V, D>),
    /// An attributed abstention.
    NoVote(NoVote<V>),
    /// An attributed nullification share.
    Nullify(Nullify<V>),
    /// A recovered nullification certificate.
    Nullification(Nullification<V>),
    /// A view quorum certificate.
    Vqc(Vqc<V, D>),
    /// A leader finalization quorum certificate.
    Lqc(Lqc<V, D>),
}

/// An immutable atomic publication of canonical artifacts.
#[cfg(not(target_arch = "wasm32"))]
pub type ArtifactBatch<V, D> = Arc<[Arc<Artifact<V, D>>]>;

impl<V: Variant, D: Digest> Artifact<V, D> {
    /// Returns whether this artifact carries view progress.
    ///
    /// Proposals, view messages, and view certificates sit on the vote-to-finality path, so
    /// their verification is scheduled ahead of bulk header and availability traffic.
    pub const fn view_critical(&self) -> bool {
        matches!(
            self,
            Self::LeaderBlock(_)
                | Self::Vote(_)
                | Self::NoVote(_)
                | Self::Nullify(_)
                | Self::Nullification(_)
                | Self::Vqc(_)
                | Self::Lqc(_)
        )
    }

    /// Returns this artifact's operation class.
    pub const fn kind(&self) -> ArtifactKind {
        match self {
            Self::TransactionBlock(_) => ArtifactKind::TransactionBlock,
            Self::DaVote(_) => ArtifactKind::DaVote,
            Self::DaCertificate(_) => ArtifactKind::DaCertificate,
            Self::LeaderBlock(_) => ArtifactKind::LeaderBlock,
            Self::Vote(_) => ArtifactKind::Vote,
            Self::NoVote(_) => ArtifactKind::NoVote,
            Self::Nullify(_) => ArtifactKind::Nullify,
            Self::Nullification(_) => ArtifactKind::Nullification,
            Self::Vqc(_) => ArtifactKind::Vqc,
            Self::Lqc(_) => ArtifactKind::Lqc,
        }
    }

    /// Returns the producer chain and height for a chain-scoped artifact.
    pub const fn chain_position(&self) -> Option<(ChainId, Height)> {
        let header = match self {
            Self::TransactionBlock(block) => block.header(),
            Self::DaVote(vote) => vote.header(),
            Self::DaCertificate(certificate) => certificate.header(),
            Self::LeaderBlock(_)
            | Self::Vote(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_)
            | Self::Vqc(_)
            | Self::Lqc(_) => return None,
        };
        Some((header.chain(), header.height()))
    }

    /// Returns the view for a view-scoped artifact.
    pub fn view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) | Self::DaVote(_) | Self::DaCertificate(_) => None,
            Self::LeaderBlock(block) => Some(block.view()),
            Self::Vote(vote) => Some(vote.view()),
            Self::NoVote(vote) => Some(vote.view()),
            Self::Nullify(nullify) => Some(nullify.view()),
            Self::Nullification(nullification) => Some(nullification.view()),
            Self::Vqc(certificate) => Some(certificate.view()),
            Self::Lqc(certificate) => Some(certificate.view()),
        }
    }

    /// Returns the participant for an individually attributed artifact.
    pub fn signer(&self) -> Option<Participant> {
        match self {
            Self::TransactionBlock(block) => Some(block.signer()),
            Self::DaVote(vote) => Some(vote.signer()),
            Self::LeaderBlock(block) => Some(block.signer()),
            Self::Vote(vote) => Some(vote.signer()),
            Self::NoVote(vote) => Some(vote.signer()),
            Self::Nullify(nullify) => Some(nullify.signer()),
            Self::DaCertificate(_) | Self::Nullification(_) | Self::Vqc(_) | Self::Lqc(_) => None,
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

    /// Returns whether this artifact may authenticate a far-future view before ancestry is resolved.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn self_certifying_view(&self) -> bool {
        matches!(self, Self::Nullification(_) | Self::Vqc(_) | Self::Lqc(_))
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
    /// Data-availability share.
    DaVote = 1,
    /// Recovered data-availability certificate.
    DaCertificate = 2,
    /// Leader proposal signature.
    LeaderBlock = 3,
    /// Complete consensus vote.
    Vote = 4,
    /// Attributed abstention.
    NoVote = 5,
    /// Nullification share.
    Nullify = 6,
    /// Recovered nullification certificate.
    Nullification = 7,
    /// View quorum certificate.
    Vqc = 8,
    /// Leader finalization certificate.
    Lqc = 9,
}

impl TryFrom<u8> for ArtifactKind {
    type Error = commonware_codec::Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        Ok(match tag {
            0 => Self::TransactionBlock,
            1 => Self::DaVote,
            2 => Self::DaCertificate,
            3 => Self::LeaderBlock,
            4 => Self::Vote,
            5 => Self::NoVote,
            6 => Self::Nullify,
            7 => Self::Nullification,
            8 => Self::Vqc,
            9 => Self::Lqc,
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
