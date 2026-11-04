//! Best-effort activity reported to the attached [`crate::Reporter`].

use crate::{
    multimmit::{
        scheme::Scheme,
        types::{Artifact, ArtifactId, BlockRef, FinalityFact, FinalityId, TipRecord},
    },
    types::{Epoch, Height, View},
};
use commonware_cryptography::Digest;
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

/// A run of one producer chain's blocks whose positions in the canonical order became fixed: the
/// ancestors of [`Self::tip`] (the tip included) at heights above [`Self::above`] and at most
/// [`Self::height`].
///
/// The run says nothing about the blocks at or below [`Self::above`]. Those were placed before,
/// possibly on another branch: an anchor may jump to a rival branch, and the order then reads
/// the new blocks off the new tip's own path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement<D: Digest> {
    tip: BlockRef<D>,
    above: Height,
    height: Height,
}

impl<D: Digest> Placement<D> {
    /// Creates the run of `tip`'s ancestors at heights in `(above, height]`.
    ///
    /// Requires `above < height <= tip.height()`. The constructor does not check this.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn new(tip: BlockRef<D>, above: Height, height: Height) -> Self {
        Self { tip, above, height }
    }

    /// Returns the block whose ancestors form the run.
    pub const fn tip(&self) -> BlockRef<D> {
        self.tip
    }

    /// Returns the height of the chain's last block placed before the run.
    pub const fn above(&self) -> Height {
        self.above
    }

    /// Returns the height of the run's highest block.
    pub const fn height(&self) -> Height {
        self.height
    }
}

/// A local proposal, contextually admitted artifact, consensus finality observation, or durable
/// record.
///
/// Activities are idempotent, best-effort observations. They do not acknowledge delivery or
/// authorize protocol progress. Only [`Activity::CertificateRecorded`] bounds what an application
/// retains for the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<S: Scheme, D: Digest> {
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
    /// Local finality of a leader fixed the canonical order of producer blocks to new heights.
    ///
    /// Finality of a leader fixes a prefix of the total order: the order its tip-history record
    /// carries, extended by the final sweep toward its finalized tips. Placement only advances.
    /// It precedes the ordered output of marshal, which still delivers only from portable proofs,
    /// so it never authorizes delivery.
    ///
    /// The engine names the blocks of a history opening only when it holds every opening since
    /// the one it last placed; otherwise it advances past them silently. In particular, a
    /// restarted engine names no blocks below the history of the first leader it sees finalized.
    Placed {
        /// View of the finalized leader.
        view: View,
        /// Evidence that finalized the leader.
        evidence: FinalityId<D>,
        /// Commitment of the leader's tip-history record that the placed order extends.
        history: D,
        /// The newly placed runs: one per chain each history opening advances, oldest opening
        /// first, then one per chain the final sweep advances, each group in chain order.
        placed: Vec<Placement<D>>,
    },
    /// An authenticated artifact entered the machine's contextually ready set.
    ProtocolAccepted {
        /// Stable identifier for the canonical artifact.
        artifact_id: ArtifactId<D>,
        /// Admitted artifact.
        artifact: Arc<Artifact<S, D>>,
    },
    /// An authenticated leader exposed its safe-tip history opening for peer seeding.
    ///
    /// The engine reports the opening of every leader block it admits or finalizes, including a
    /// leader known only from its votes or certificates, as soon as the opening is
    /// reconstructible from the leader's retained parent. Each leader is reported once per engine
    /// lifetime; a restarted engine may report it once more. A leader whose parent the engine
    /// does not retain before the leader falls out of the retained view window is not reported.
    HistoryAccepted {
        /// View of the leader that committed the opening.
        view: View,
        /// Unsigned digest of the leader block that committed the opening.
        leader: D,
        /// Commitment carried by the leader.
        commitment: D,
        /// Opening reconstructed from the retained parent state.
        record: Arc<TipRecord<D>>,
    },
    /// The engine durably recorded `certified` as the newest certified block of its chain: a DA
    /// certificate for it, or the chain's genesis tip when the engine starts without one.
    ///
    /// The engine never again depends on the application's verdict for a block of that chain at
    /// or below `released`, including after a restart; a verification it already dispatched may
    /// still arrive, and its verdict is ignored. `released` trails `certified` by the pipeline
    /// depth, because the engine keeps its DA votes for blocks just below a certificate. The
    /// engine reports this once each record is durable, and for every chain's newest record when
    /// it starts, so an application can prune what the engine no longer needs.
    CertificateRecorded {
        /// The newest block of its chain whose DA certificate is durably recorded.
        certified: BlockRef<D>,
        /// The highest height of the chain that the engine no longer verifies.
        released: Height,
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
