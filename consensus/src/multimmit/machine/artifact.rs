//! Admission keys and dependencies derived from untrusted artifacts, and typed handles to
//! admitted artifacts.

use crate::{
    multimmit::types::{
        Artifact, ArtifactId, CertificateId, LeaderBlock, Nullification, Nullify,
        SignedLeaderBlock, Vote, Vqc,
    },
    types::Round,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::{fmt, marker::PhantomData};
use std::sync::Arc;

/// An immutable prerequisite for contextual admission.
///
/// Cryptographic verification is cached independently of this dependency. Arrival of the missing
/// object therefore retries contextual admission without repeating signature verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Dependency<D: Digest> {
    /// The parent V-QC named by a leader block.
    Vqc(CertificateId<D>),
    /// The complete leader block named by a vote.
    Leader {
        /// The leader's epoch and view.
        round: Round,
        /// The canonical unsigned leader-block digest.
        digest: D,
    },
}

/// An untrusted artifact with its id and dependency keys, computed once by ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdentifiedArtifact<V: Variant, D: Digest> {
    pub(crate) id: ArtifactId<D>,
    pub(crate) artifact: Artifact<V, D>,
    pub(crate) provisions: Vec<Dependency<D>>,
}

impl<V: Variant, D: Digest> Artifact<V, D> {
    /// Prepares immutable admission keys using one canonical artifact encoding.
    pub(crate) fn identify<H: Hasher<Digest = D>>(
        self,
        scratch: &mut Vec<u8>,
    ) -> IdentifiedArtifact<V, D> {
        self.write_canonical_encoding(scratch);
        self.identify_from_canonical_encoding::<H>(scratch)
    }

    pub(crate) fn identify_from_canonical_encoding<H: Hasher<Digest = D>>(
        self,
        encoded: &[u8],
    ) -> IdentifiedArtifact<V, D> {
        let id = self.id_from_canonical_encoding::<H>(encoded);
        let provisions =
            self.provisions_with_vqc_id::<H>(|_| CertificateId::from_canonical::<H>(encoded));
        IdentifiedArtifact {
            id,
            artifact: self,
            provisions,
        }
    }

    /// Returns the leader block this artifact proposes or certifies.
    pub(crate) const fn designated_leader(&self) -> Option<&LeaderBlock<V, D>> {
        match self {
            Self::LeaderBlock(block) => Some(block.block()),
            Self::Vqc(certificate) => Some(certificate.leader()),
            Self::Lqc(certificate) => Some(certificate.leader()),
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::Vote(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => None,
        }
    }

    pub(crate) const fn dependency(&self) -> Option<Dependency<D>> {
        match self {
            Self::LeaderBlock(block) => Some(Dependency::Vqc(block.block().parent())),
            Self::Vote(vote) => Some(Dependency::Leader {
                round: vote.body().round(),
                digest: vote.body().leader(),
            }),
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::Vqc(_)
            | Self::Lqc(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => None,
        }
    }

    pub(crate) fn provisions<H: Hasher<Digest = D>>(&self) -> Vec<Dependency<D>> {
        self.provisions_with_vqc_id::<H>(Vqc::id::<H>)
    }

    fn provisions_with_vqc_id<H: Hasher<Digest = D>>(
        &self,
        vqc_id: impl FnOnce(&Vqc<V, D>) -> CertificateId<D>,
    ) -> Vec<Dependency<D>> {
        match self {
            Self::LeaderBlock(block) => vec![Dependency::Leader {
                round: block.block().round(),
                digest: block.block().digest::<H>(),
            }],
            Self::Vqc(certificate) => {
                vec![
                    Dependency::Vqc(vqc_id(certificate)),
                    Dependency::Leader {
                        round: certificate.leader().round(),
                        digest: certificate.leader().digest::<H>(),
                    },
                ]
            }
            Self::Lqc(certificate) => vec![Dependency::Leader {
                round: certificate.leader().round(),
                digest: certificate.leader().digest::<H>(),
            }],
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::Vote(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => Vec::new(),
        }
    }
}

/// One artifact variant, or group of variants, that a [`Held`] handle names.
pub(crate) trait ArtifactKind<V: Variant, D: Digest> {
    /// The borrowed payload of an artifact of this kind.
    type Target<'a>;

    /// Returns the payload of `artifact` if it is of this kind.
    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>>;
}

/// Marks a kind whose artifacts are all of kind `W`.
pub(crate) trait Within<W> {}

/// A shared artifact checked once to be of kind `K`.
pub(crate) struct Held<K, V: Variant, D: Digest> {
    artifact: Arc<Artifact<V, D>>,
    kind: PhantomData<fn() -> K>,
}

impl<K: ArtifactKind<V, D>, V: Variant, D: Digest> Held<K, V, D> {
    /// Returns a handle to `artifact` if it is of kind `K`.
    pub(crate) fn try_new(artifact: &Arc<Artifact<V, D>>) -> Option<Self> {
        K::project(artifact)?;
        Some(Self {
            artifact: Arc::clone(artifact),
            kind: PhantomData,
        })
    }

    /// Returns the artifact's payload.
    pub(crate) fn get(&self) -> K::Target<'_> {
        K::project(&self.artifact).expect("held artifacts match their kind")
    }
}

impl<K, V: Variant, D: Digest> Held<K, V, D> {
    /// Returns the shared artifact.
    pub(crate) const fn arc(&self) -> &Arc<Artifact<V, D>> {
        &self.artifact
    }

    /// Returns the shared artifact, consuming the handle.
    pub(crate) fn into_arc(self) -> Arc<Artifact<V, D>> {
        self.artifact
    }

    /// Returns a handle to the same artifact as a kind that includes `K`.
    pub(crate) fn widen<W>(&self) -> Held<W, V, D>
    where
        K: Within<W>,
    {
        Held {
            artifact: Arc::clone(&self.artifact),
            kind: PhantomData,
        }
    }
}

impl<K, V: Variant, D: Digest> Clone for Held<K, V, D> {
    fn clone(&self) -> Self {
        Self {
            artifact: Arc::clone(&self.artifact),
            kind: PhantomData,
        }
    }
}

impl<K, V: Variant, D: Digest> PartialEq for Held<K, V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.artifact == other.artifact
    }
}

impl<K, V: Variant, D: Digest> Eq for Held<K, V, D> {}

impl<K, V: Variant, D: Digest> fmt::Debug for Held<K, V, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.artifact.fmt(f)
    }
}

/// A scheduled leader's signed proposal.
pub(crate) enum LeaderBlockKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for LeaderBlockKind {
    type Target<'a> = &'a SignedLeaderBlock<V, D>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::LeaderBlock(block) => Some(block),
            _ => None,
        }
    }
}

/// A proposal or certificate that designates a leader block.
pub(crate) enum DesignatingKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for DesignatingKind {
    type Target<'a> = &'a LeaderBlock<V, D>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        artifact.designated_leader()
    }
}

impl Within<DesignatingKind> for LeaderBlockKind {}

impl Within<DesignatingKind> for VqcKind {}

/// A complete consensus vote.
pub(crate) enum VoteKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for VoteKind {
    type Target<'a> = &'a Vote<V, D>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::Vote(vote) => Some(vote),
            _ => None,
        }
    }
}

/// An attributed nullification share.
pub(crate) enum NullifyKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for NullifyKind {
    type Target<'a> = &'a Nullify<V>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::Nullify(share) => Some(share),
            _ => None,
        }
    }
}

/// A recovered nullification certificate.
pub(crate) enum NullificationKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for NullificationKind {
    type Target<'a> = &'a Nullification<V>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::Nullification(certificate) => Some(certificate),
            _ => None,
        }
    }
}

/// A view quorum certificate.
pub(crate) enum VqcKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for VqcKind {
    type Target<'a> = &'a Vqc<V, D>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::Vqc(certificate) => Some(certificate),
            _ => None,
        }
    }
}

impl<V: Variant, D: Digest> Held<VqcKind, V, D> {
    /// Returns a handle to a new shared artifact holding `certificate`.
    pub(crate) fn new(certificate: Vqc<V, D>) -> Self {
        Self {
            artifact: Arc::new(Artifact::Vqc(certificate)),
            kind: PhantomData,
        }
    }
}
