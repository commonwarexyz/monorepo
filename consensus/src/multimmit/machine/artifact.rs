//! Identified untrusted artifacts and the retrieval keys they provide.

use super::{input::Now, resolution::RetrievalKey};
use crate::{
    Viewable as _,
    multimmit::types::{Artifact, ArtifactId, CertificateId},
    types::Attributable as _,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// An untrusted artifact with its identifier and the keys it provides, computed once off the
/// voter loop.
///
/// The provided keys are the [`RetrievalKey`]s that name this artifact, so its admission wakes
/// every observation and retrieval waiting on one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdentifiedArtifact<V: Variant, D: Digest> {
    pub(crate) id: ArtifactId<D>,
    pub(crate) artifact: Artifact<V, D>,
    pub(crate) provisions: Vec<RetrievalKey<D>>,
    /// When the network message carrying the artifact arrived at this node, before any local
    /// queueing, or `None` when no such reading exists (a retrieval result, for one). Admission
    /// substitutes its own clock reading for a missing receipt or one later than it.
    pub(crate) received: Option<Now>,
}

impl<V: Variant, D: Digest> Artifact<V, D> {
    /// Identifies the artifact using one canonical encoding written into `scratch`, without a
    /// receipt reading.
    pub(crate) fn identify<H: Hasher<Digest = D>>(
        self,
        scratch: &mut Vec<u8>,
    ) -> IdentifiedArtifact<V, D> {
        self.write_canonical_encoding(scratch);
        self.identify_from_canonical_encoding::<H>(scratch)
    }

    /// Identifies the artifact from its canonical encoding, without a receipt reading.
    pub(crate) fn identify_from_canonical_encoding<H: Hasher<Digest = D>>(
        self,
        encoded: &[u8],
    ) -> IdentifiedArtifact<V, D> {
        let id = self.id_from_canonical_encoding::<H>(encoded);
        let provisions = self.provisions_from_canonical_encoding::<H>(encoded);
        IdentifiedArtifact {
            id,
            artifact: self,
            provisions,
            received: None,
        }
    }

    /// Returns the retrieval keys that name this artifact.
    pub(crate) fn provisions<H: Hasher<Digest = D>>(&self) -> Vec<RetrievalKey<D>> {
        let mut encoded = Vec::new();
        if matches!(self, Self::Vqc(_) | Self::Lqc(_)) {
            self.write_canonical_encoding(&mut encoded);
        }
        self.provisions_from_canonical_encoding::<H>(&encoded)
    }

    /// Returns the provided keys. A certificate's identifier hashes its canonical encoding, which
    /// only certificates read from `encoded`.
    pub(crate) fn provisions_from_canonical_encoding<H: Hasher<Digest = D>>(
        &self,
        encoded: &[u8],
    ) -> Vec<RetrievalKey<D>> {
        match self {
            Self::TransactionBlock(block) => vec![RetrievalKey::Header {
                chain: block.header().chain(),
                digest: block.header().digest::<H>(),
            }],
            Self::LeaderBlock(block) => vec![RetrievalKey::LeaderBlock(block.view())],
            Self::Update(update) => vec![RetrievalKey::Update {
                signer: update.signer(),
                view: update.view(),
            }],
            Self::Vqc(certificate) => vec![
                RetrievalKey::Vqc(CertificateId::from_canonical::<H>(encoded)),
                RetrievalKey::VqcView(certificate.view()),
            ],
            Self::Lqc(_) => vec![RetrievalKey::Lqc(CertificateId::from_canonical::<H>(
                encoded,
            ))],
            Self::Floor(_) => vec![RetrievalKey::LatestFloor],
        }
    }
}
