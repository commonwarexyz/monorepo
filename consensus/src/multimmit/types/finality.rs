//! Leader-finality facts reported by the machine.

use crate::{
    multimmit::types::{ArtifactId, BlockRef, CertificateId, Position},
    types::{Height, Round},
};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    multimmit::types::{ChainId, CodecConfig},
    types::Epoch,
};
use commonware_cryptography::Digest;

/// Identifies the evidence underlying one leader-finality fact.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FinalityId<D: Digest> {
    /// Digest of the canonical arrival-first vote evidence in a local pool.
    Direct(D),
    /// One independently authenticated L-QC witness.
    Lqc(ArtifactId<D>),
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

    /// Returns whether the fact is a direct-pool projection shaped for `codec` in `epoch`.
    ///
    /// A well-formed fact names a non-genesis view, carries between a view quorum and every
    /// participant's vote, lists one block per chain in chain order with a position and a
    /// settledness flag each, and keeps every position within the pipeline depth.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn is_well_formed(&self, epoch: Epoch, codec: CodecConfig) -> bool {
        let chains = codec.chains();
        matches!(self.id, FinalityId::Direct(_))
            && self.round.epoch() == epoch
            && !self.round.view().is_zero()
            && self.votes >= codec.view_quorum()
            && self.votes <= codec.participants()
            && self.blocks.len() == chains
            && self.positions.len() == chains
            && self.settled.len() == chains
            && self
                .blocks
                .iter()
                .enumerate()
                .all(|(chain, block)| u32::try_from(chain).map(ChainId::new) == Ok(block.chain()))
            && self
                .positions
                .iter()
                .all(|position| position.get() as usize <= codec.pipeline_depth())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::PathLimits, types::View};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    fn codec() -> CodecConfig {
        CodecConfig::new(6, 2, PathLimits::new(2, 1).unwrap()).unwrap()
    }

    fn fact(
        round: Round,
        votes: usize,
        chains: &[u32],
        position: u32,
    ) -> FinalityFact<Sha256Digest> {
        FinalityFact::new(
            FinalityId::Direct(Sha256::hash(&[b"pool"])),
            round,
            Sha256::hash(&[b"leader"]),
            CertificateId::new(Sha256::hash(&[b"parent"])),
            votes,
            chains
                .iter()
                .map(|chain| {
                    BlockRef::new(
                        ChainId::new(*chain),
                        Height::new(1),
                        Sha256::hash(&[b"tip"]),
                    )
                })
                .collect(),
            vec![Height::new(1); chains.len()],
            vec![Position::new(position); chains.len()],
            vec![true; chains.len()],
        )
    }

    #[test]
    fn well_formed_facts_match_the_epoch_and_codec() {
        let epoch = Epoch::new(3);
        let codec = codec();
        let round = Round::new(epoch, View::new(4));
        let quorum = codec.view_quorum();
        assert!(fact(round, quorum, &[0, 1], 2).is_well_formed(epoch, codec));

        assert!(!fact(round, quorum, &[0, 1], 2).is_well_formed(Epoch::new(4), codec));
        let genesis = Round::new(epoch, View::zero());
        assert!(!fact(genesis, quorum, &[0, 1], 2).is_well_formed(epoch, codec));
        assert!(!fact(round, quorum - 1, &[0, 1], 2).is_well_formed(epoch, codec));
        assert!(!fact(round, codec.participants() + 1, &[0, 1], 2).is_well_formed(epoch, codec));
        assert!(!fact(round, quorum, &[0], 2).is_well_formed(epoch, codec));
        assert!(!fact(round, quorum, &[1, 0], 2).is_well_formed(epoch, codec));
        assert!(!fact(round, quorum, &[0, 1], 3).is_well_formed(epoch, codec));

        let mut short_positions = fact(round, quorum, &[0, 1], 2);
        short_positions.positions.pop();
        assert!(!short_positions.is_well_formed(epoch, codec));
        let mut short_settled = fact(round, quorum, &[0, 1], 2);
        short_settled.settled.pop();
        assert!(!short_settled.is_well_formed(epoch, codec));

        let mut lqc = fact(round, quorum, &[0, 1], 2);
        lqc.id = FinalityId::Lqc(ArtifactId::new(Sha256::hash(&[b"witness"])));
        assert!(!lqc.is_well_formed(epoch, codec));
    }
}
