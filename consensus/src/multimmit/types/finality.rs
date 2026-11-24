//! Leader-finality facts reported by the machine.

use crate::{
    multimmit::types::{BlockRef, CertificateId, Position},
    types::{Height, Round},
};
use commonware_cryptography::Digest;

/// Identifies the evidence underlying one leader-finality fact.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FinalityId<D: Digest> {
    /// Digest of the canonical arrival-first vote evidence in a local pool.
    Direct(D),
    /// Identifier of one independently authenticated L-QC.
    Lqc(CertificateId<D>),
}

/// The finality of one leader block: the evidence that finalized it and, for every producer
/// chain, the final block, proposed tip height, final position, and whether it is settled.
///
/// Reporters receive it in leader-finality activities, and marshal orders its output from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityFact<D: Digest> {
    id: FinalityId<D>,
    round: Round,
    leader: D,
    parent: CertificateId<D>,
    votes: usize,
    blocks: Vec<BlockRef<D>>,
    proposed: Vec<Height>,
    positions: Vec<Position>,
    settled: Vec<bool>,
}

impl<D: Digest> FinalityFact<D> {
    /// Creates a finality fact from its normalized parts.
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn new(
        id: FinalityId<D>,
        round: Round,
        leader: D,
        parent: CertificateId<D>,
        votes: usize,
        blocks: Vec<BlockRef<D>>,
        proposed: Vec<Height>,
        positions: Vec<Position>,
        settled: Vec<bool>,
    ) -> Self {
        Self {
            id,
            round,
            leader,
            parent,
            votes,
            blocks,
            proposed,
            positions,
            settled,
        }
    }

    /// Returns the evidence identifier.
    pub const fn id(&self) -> FinalityId<D> {
        self.id
    }

    /// Returns the finalized leader's epoch and view.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the finalized unsigned leader digest.
    pub const fn leader(&self) -> D {
        self.leader
    }

    /// Returns the parent V-QC named by the finalized leader.
    pub const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the number of distinct votes represented by the evidence.
    pub const fn votes(&self) -> usize {
        self.votes
    }

    /// Returns one final block per chain in canonical chain order.
    pub fn blocks(&self) -> &[BlockRef<D>] {
        &self.blocks
    }

    /// Returns one proposed tip height per chain in canonical chain order.
    pub fn proposed(&self) -> &[Height] {
        &self.proposed
    }

    /// Returns one final proposal position per chain in canonical chain order.
    pub fn positions(&self) -> &[Position] {
        &self.positions
    }

    /// Returns one settledness flag per chain in canonical chain order.
    pub fn settled(&self) -> &[bool] {
        &self.settled
    }
}

/// A normalized direct-pool summary for diagnostics and tests.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoolSummary<D: Digest> {
    round: Round,
    leader: D,
    votes: usize,
    finalized: bool,
    lqc_pending: bool,
}

impl<D: Digest> PoolSummary<D> {
    /// Creates a pool summary.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn new(
        round: Round,
        leader: D,
        votes: usize,
        finalized: bool,
        lqc_pending: bool,
    ) -> Self {
        Self {
            round,
            leader,
            votes,
            finalized,
            lqc_pending,
        }
    }

    /// Returns the pool leader's epoch and view.
    pub const fn round(self) -> Round {
        self.round
    }

    /// Returns the unsigned leader digest.
    pub const fn leader(self) -> D {
        self.leader
    }

    /// Returns the number of sticky authenticated votes.
    pub const fn votes(self) -> usize {
        self.votes
    }

    /// Returns whether the pool has reached `n-f`.
    pub const fn finalized(self) -> bool {
        self.finalized
    }

    /// Returns whether local L-QC construction remains outstanding.
    pub const fn lqc_pending(self) -> bool {
        self.lqc_pending
    }
}
