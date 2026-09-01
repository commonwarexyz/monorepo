//! Best-effort activity reported to the attached [`crate::Reporter`].

use crate::{
    multimmit::types::{Artifact, ArtifactId, BlockRef, FinalityFact, TipRecord},
    types::{Epoch, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// Heap bytes an `Arc` allocation holds ahead of its value: the strong and weak reference counts.
const ARC_HEADER: usize = 2 * core::mem::size_of::<usize>();

/// Authenticated contiguous producer paths selected by local consensus extraction.
///
/// Paths include their first known parent and stop at the selected tip. They can leave gaps
/// between certificates and do not establish availability of the corresponding block bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedCommitments<D: Digest> {
    epoch: Epoch,
    paths: Arc<[Arc<[BlockRef<D>]>]>,
}

impl<D: Digest> SelectedCommitments<D> {
    /// Creates the selected paths for `epoch`.
    ///
    /// Requires every path to contain at least two references whose adjacent parent edges have
    /// been authenticated in `epoch`. The constructor does not check this.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(epoch: Epoch, paths: Vec<Arc<[BlockRef<D>]>>) -> Self {
        Self {
            epoch,
            paths: paths.into(),
        }
    }

    /// Returns the epoch whose consensus evidence authenticated the paths.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the selected paths, each ordered from its first known parent to its tip.
    pub fn paths(&self) -> &[Arc<[BlockRef<D>]>] {
        &self.paths
    }

    /// Returns the heap bytes owned by the path allocations, or `None` on overflow.
    pub fn owned_bytes(&self) -> Option<usize> {
        let mut bytes = ARC_HEADER.checked_add(core::mem::size_of_val(self.paths.as_ref()))?;
        for path in self.paths.iter() {
            bytes = bytes
                .checked_add(ARC_HEADER)?
                .checked_add(core::mem::size_of_val(path.as_ref()))?;
        }
        Some(bytes)
    }
}

/// A local proposal, contextually admitted artifact, or consensus finality observation.
///
/// Activities are idempotent, best-effort observations. They do not acknowledge delivery,
/// authorize protocol progress, or control retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// Selected producer paths reconstructed from authenticated consensus evidence.
    CommitmentsAccepted {
        /// Contiguous ranges available for local ancestry reuse.
        commitments: SelectedCommitments<D>,
    },
    /// A local transaction block has been signed, before its publication is persisted.
    ///
    /// This is not evidence of dissemination or finality. Retries may report the same block.
    TransactionProposed {
        /// Identity of the signed producer block.
        block: BlockRef<D>,
    },
    /// A leader obtained its first direct finality quorum.
    LeaderFinalized {
        /// Producer-chain tips supported by the first direct finality quorum.
        fact: FinalityFact<D>,
    },
    /// An already-finalized leader's direct finality projection advanced.
    LeaderFinalityUpdated {
        /// Producer-chain tips supported by the updated direct finality pool.
        fact: FinalityFact<D>,
    },
    /// An authenticated artifact entered the machine's contextually ready set.
    ProtocolAccepted {
        /// Stable identifier for the canonical artifact.
        artifact_id: ArtifactId<D>,
        /// Admitted artifact.
        artifact: Arc<Artifact<V, D>>,
    },
    /// An authenticated leader exposed its safe-tip history opening for peer seeding.
    HistoryAccepted {
        /// View of the leader that committed the opening.
        view: View,
        /// Commitment carried by the leader.
        commitment: D,
        /// Opening reconstructed from the retained parent state.
        record: Arc<TipRecord<D>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::ChainId, types::Height};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    #[test]
    fn selected_commitments_expose_paths_and_owned_bytes() {
        let path: Arc<[BlockRef<Sha256Digest>]> = (1..=2u8)
            .map(|height| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(u64::from(height)),
                    Sha256::hash(&[&[height]]),
                )
            })
            .collect();
        let commitments = SelectedCommitments::new(Epoch::new(3), vec![path.clone()]);
        assert_eq!(commitments.epoch(), Epoch::new(3));
        assert_eq!(commitments.paths(), core::slice::from_ref(&path));
        let expected = ARC_HEADER
            + core::mem::size_of::<Arc<[BlockRef<Sha256Digest>]>>()
            + ARC_HEADER
            + 2 * core::mem::size_of::<BlockRef<Sha256Digest>>();
        assert_eq!(commitments.owned_bytes(), Some(expected));
    }
}
