//! Safe and final tip extraction.

use super::{
    Error,
    path::{PathIndex, ProposalPaths, VotePaths},
};
#[cfg(any(test, feature = "mocks"))]
use crate::multimmit::types::Vqc;
use crate::{
    multimmit::types::{
        BlockRef, ChainId, CodecConfig, DigestedLeader, FinalityFact, FinalityId, LeaderBlock, Lqc,
        Position, SelectedCommitments, VoteBody,
    },
    types::Epoch,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::Participant;
use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

/// Incremental extraction state for one sticky leader vote pool.
///
/// Each authenticated participant is inserted at most once. Proposal paths are reconstructed once,
/// and each insertion updates dense position counts and branch-aware block support without
/// revisiting older vote bodies.
#[derive(Clone, Debug)]
pub(crate) struct PoolExtractor<D: Digest> {
    config: CodecConfig,
    leader: D,
    proposals: ProposalPaths<D>,
    signers_seen: Vec<bool>,
    position_counts: Vec<Vec<usize>>,
    // Extension counts are exact above the proposal tip; proposal ranks use position_counts.
    support: Vec<BTreeMap<BlockRef<D>, usize>>,
    best_supported: Vec<Option<BlockRef<D>>>,
    max_child_support: Vec<BTreeMap<BlockRef<D>, usize>>,
    ancestry: PathIndex<D>,
    len: usize,
}

impl<D: Digest> PoolExtractor<D> {
    /// Selects the known contiguous block paths ending at each final tip, using only edges this
    /// pool authenticated.
    pub(crate) fn selected(&self, epoch: Epoch, tips: &FinalTips<D>) -> SelectedCommitments<D> {
        self.ancestry.selected(epoch, tips.blocks().iter().copied())
    }

    /// Creates an empty pool for one leader block.
    pub(crate) fn new<H, V>(leader: &LeaderBlock<V, D>, config: CodecConfig) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        if leader.validate(config).is_err() {
            return Err(Error::Leader);
        }
        let proposals = ProposalPaths::new::<H, V>(leader)?;
        let mut ancestry = PathIndex::default();
        proposals.index(&mut ancestry)?;
        let position_counts = config
            .chain_ids()
            .map(|chain| proposals.chain(chain).map(|path| vec![0; path.len()]))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config,
            leader: leader.digest::<H>(),
            proposals,
            signers_seen: vec![false; config.participants()],
            position_counts,
            support: vec![BTreeMap::new(); config.chains()],
            best_supported: vec![None; config.chains()],
            max_child_support: vec![BTreeMap::new(); config.chains()],
            ancestry,
            len: 0,
        })
    }

    /// Incorporates a participant's first authenticated complete vote.
    ///
    /// Returns `false` when that participant already has a sticky pool entry.
    pub(crate) fn insert<H, V>(
        &mut self,
        leader: &LeaderBlock<V, D>,
        signer: Participant,
        body: &VoteBody<D>,
    ) -> Result<bool, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let signer_index = usize::from(signer);
        let Some(seen) = self.signers_seen.get(signer_index) else {
            return Err(Error::Signer);
        };
        if *seen {
            return Ok(false);
        }
        if body.validate(self.config).is_err() {
            return Err(Error::Vote);
        }

        let paths = VotePaths::new::<H, V>(
            DigestedLeader::with_digest(leader, self.leader),
            &self.proposals,
            body,
        )?;
        paths.validate_extensions(&self.ancestry)?;

        for chain in self.config.chain_ids() {
            let index = chain.index();
            let position = body.positions()[index].get() as usize;
            *self.position_counts[index]
                .get_mut(position)
                .ok_or(Error::Vote)? += 1;
            let path = paths.extension(chain)?;
            let proposal = self.proposals.chain(chain)?;
            let proposal_tip = *proposal.last().expect("proposal includes its anchor");
            // An extension may fork below the proposal tip or reproduce its exact suffix.
            let extends_proposal = path.get(proposal.len() - 1 - position) == Some(&proposal_tip);
            for block in &path[1..] {
                let count = self.support[index].entry(*block).or_default();
                *count += 1;
                if *count == self.config.view_quorum()
                    && extends_proposal
                    && block.height() > proposal_tip.height()
                    && self.best_supported[index].is_none_or(|best| deeper(*block, best))
                {
                    // Sticky support only grows; a qualified descendant remains qualified.
                    self.best_supported[index] = Some(*block);
                }
            }
            for pair in path.windows(2) {
                let maximum = self.max_child_support[index].entry(pair[0]).or_default();
                // Sticky votes only increase child support, so maxima never need rescanning.
                *maximum = (*maximum).max(self.support[index][&pair[1]]);
            }
        }
        paths
            .index_extensions(&mut self.ancestry)
            .expect("vote paths were prevalidated against the ancestry index");
        self.signers_seen[signer_index] = true;
        self.len += 1;
        Ok(true)
    }

    /// Returns the number of retained participants.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Extracts the current pool-final tips and settlement facts.
    pub(crate) fn final_tips(&self) -> Result<FinalTips<D>, Error> {
        if self.len < self.config.view_quorum() {
            return Err(Error::Quorum);
        }

        let rank = self.config.final_rank();
        let settlement = Settlement::new(self.config, self.len)?;
        let mut tips = FinalTips::with_capacity(self.config.chains());
        for chain in self.config.chain_ids() {
            let index = chain.index();
            let position = descending_rank(&self.position_counts[index], rank)?;
            tips.push_chain(
                &self.proposals,
                chain,
                position,
                settlement,
                |base| Ok(self.best_supported[index].unwrap_or(base)),
                |tip| {
                    Ok(self.max_child_support[index]
                        .get(&tip)
                        .copied()
                        .unwrap_or(0))
                },
            )?;
        }
        check_chain_order(tips.blocks())?;
        Ok(tips)
    }
}

#[cfg(test)]
impl<D: Digest> PoolExtractor<D> {
    pub(crate) fn retained_support_entries(&self) -> usize {
        self.support.iter().map(BTreeMap::len).sum()
    }

    pub(crate) fn final_tip_candidates(&self) -> usize {
        self.best_supported.iter().flatten().count()
    }
}

/// Per-chain tips that are safe to extend after a V-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tips<D: Digest> {
    blocks: Vec<BlockRef<D>>,
}

/// Safe V-QC tips and the authenticated ancestry used to derive them.
#[derive(Clone, Debug)]
pub(crate) struct VqcExtraction<D: Digest> {
    tips: Tips<D>,
    ancestry: PathIndex<D>,
}

impl<D: Digest> VqcExtraction<D> {
    /// Extracts ordering data from one authenticated V-QC transcript.
    ///
    /// Production extraction flows through [`super::validate_vqc`], which reuses the leader digest
    /// across derivations; this convenience wrapper serves tests and mocks.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn new<H, V>(certificate: &Vqc<V, D>, config: CodecConfig) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let leader = DigestedLeader::new::<H>(certificate.leader());
        let expanded = certificate
            .expand_votes(leader.digest(), config)
            .map_err(|_| Error::Vote)?;
        Self::from_votes::<H, V>(
            leader,
            expanded.iter().map(|(signer, body)| (*signer, body)),
            config,
        )
    }

    /// Extracts ordering data from the already expanded votes of one authenticated V-QC.
    pub(crate) fn from_votes<'a, H, V>(
        leader: DigestedLeader<'_, V, D>,
        votes: impl IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        D: 'a,
    {
        let prepared = PreparedVotes::new_digested::<H, V, _>(leader, votes, config)?;
        prepared.check_vqc_quorum(config)?;
        Ok(Self {
            tips: Tips::from_prepared(&prepared, config)?,
            ancestry: prepared.ancestry()?,
        })
    }

    /// Separates the extracted tips and ancestry without cloning either index.
    pub(crate) fn into_parts(self) -> (Tips<D>, PathIndex<D>) {
        (self.tips, self.ancestry)
    }
}

impl<D: Digest> Tips<D> {
    /// Creates one tip per chain in canonical chain order.
    pub(crate) fn new(blocks: Vec<BlockRef<D>>) -> Result<Self, Error> {
        check_chain_order(&blocks)?;
        Ok(Self { blocks })
    }

    pub(super) fn from_prepared(
        prepared: &PreparedVotes<D>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let rank = config.safe_rank();
        let mut blocks = Vec::with_capacity(config.chains());
        for chain in config.chain_ids() {
            let position = prepared.rank(chain, rank)?;
            let base = prepared.proposals.block(chain, position)?;
            blocks.push(prepared.deepest_supported(chain, base, config.designation_quorum())?);
        }
        Ok(Self { blocks })
    }

    /// Returns safe tips in ascending chain order.
    pub(crate) fn blocks(&self) -> &[BlockRef<D>] {
        &self.blocks
    }

    pub(crate) const fn owned_bytes(&self) -> Option<usize> {
        self.blocks.capacity().checked_mul(size_of::<BlockRef<D>>())
    }
}

#[cfg(test)]
impl<D: Digest> Tips<D> {
    /// Extracts safe tips from the designated votes of a V-QC transcript.
    pub(crate) fn from_votes<'a, H, V, I>(
        leader: &LeaderBlock<V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        I: IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        D: 'a,
    {
        let prepared = PreparedVotes::new::<H, V, I>(leader, votes, config)?;
        prepared.check_vqc_quorum(config)?;
        Self::from_prepared(&prepared, config)
    }

    /// Returns one chain's safe tip.
    pub(crate) fn get(&self, chain: ChainId) -> Option<BlockRef<D>> {
        self.blocks.get(chain.index()).copied()
    }
}

/// Per-chain final tips and settlement facts extracted from an L-QC or sticky vote pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalTips<D: Digest> {
    blocks: Vec<BlockRef<D>>,
    positions: Vec<Position>,
    settled: Vec<bool>,
}

impl<D: Digest> FinalTips<D> {
    /// Returns the heap bytes these tips own.
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        self.blocks
            .capacity()
            .checked_mul(size_of::<BlockRef<D>>())?
            .checked_add(
                self.positions
                    .capacity()
                    .checked_mul(size_of::<Position>())?,
            )?
            .checked_add(self.settled.capacity())
    }

    fn with_capacity(chains: usize) -> Self {
        Self {
            blocks: Vec::with_capacity(chains),
            positions: Vec::with_capacity(chains),
            settled: Vec::with_capacity(chains),
        }
    }

    /// Appends the final tip of the next chain in canonical order.
    ///
    /// `position` is the chain's final proposal position. Below the proposal tip, the final tip is
    /// the proposal block at `position`. At the proposal tip, it is the block `supported` derives
    /// from that proposal block. The chain is settled when `position` is the proposal tip and the
    /// largest support `beyond` returns for one child of the final tip stays within `settlement`.
    fn push_chain(
        &mut self,
        proposals: &ProposalPaths<D>,
        chain: ChainId,
        position: Position,
        settlement: Settlement,
        supported: impl FnOnce(BlockRef<D>) -> Result<BlockRef<D>, Error>,
        beyond: impl FnOnce(BlockRef<D>) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        let proposal = proposals.chain(chain)?;
        let proposal_tip = Position::new((proposal.len() - 1) as u32);
        let base = proposals.block(chain, position)?;
        let at_proposal_tip = position == proposal_tip;
        let tip = if at_proposal_tip {
            supported(base)?
        } else {
            base
        };
        let beyond = beyond(tip)?;
        self.blocks.push(tip);
        self.positions.push(position);
        self.settled
            .push(at_proposal_tip && settlement.settled(beyond));
        Ok(())
    }

    /// Extracts final tips from a vote set with at most one vote per participant.
    pub(crate) fn from_pool<'a, H, V, I>(
        leader: &LeaderBlock<V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        I: IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        D: 'a,
    {
        let prepared = PreparedVotes::new::<H, V, I>(leader, votes, config)?;
        Self::from_prepared(&prepared, config)
    }

    pub(super) fn from_prepared(
        prepared: &PreparedVotes<D>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        if prepared.len() < config.view_quorum() {
            return Err(Error::Quorum);
        }

        let rank = config.final_rank();
        let support = config.view_quorum();
        let settlement = Settlement::new(config, prepared.len())?;
        let mut tips = Self::with_capacity(config.chains());
        for chain in config.chain_ids() {
            let position = prepared.rank(chain, rank)?;
            tips.push_chain(
                &prepared.proposals,
                chain,
                position,
                settlement,
                |base| prepared.deepest_supported(chain, base, support),
                |tip| prepared.max_child_support(chain, tip),
            )?;
        }
        Ok(tips)
    }

    /// Extracts final tips from an authenticated L-QC transcript.
    pub(crate) fn from_lqc<H, V>(
        certificate: &Lqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let leader = DigestedLeader::new::<H>(certificate.leader());
        let votes = certificate
            .expand_votes(leader.digest(), config)
            .map_err(|_| Error::Vote)?;
        let prepared = PreparedVotes::new_digested::<H, V, _>(
            leader,
            votes.iter().map(|(signer, body)| (*signer, body)),
            config,
        )?;
        prepared.ancestry()?;
        Self::from_prepared(&prepared, config)
    }

    /// Returns final tips in ascending chain order.
    pub(crate) fn blocks(&self) -> &[BlockRef<D>] {
        &self.blocks
    }

    /// Returns the final position rank for one chain.
    pub(crate) fn position(&self, chain: ChainId) -> Option<Position> {
        self.positions.get(chain.index()).copied()
    }

    /// Returns whether the pool proves that one chain cannot grow in a same-view V-QC.
    pub(crate) fn settled(&self, chain: ChainId) -> Option<bool> {
        self.settled.get(chain.index()).copied()
    }

    /// Returns the finality fact these tips give `leader`, identified by `id` and backed by
    /// `votes` distinct votes.
    pub(crate) fn fact<V: Variant>(
        &self,
        id: FinalityId<D>,
        leader: DigestedLeader<'_, V, D>,
        votes: usize,
        config: CodecConfig,
    ) -> Result<FinalityFact<D>, Error> {
        let (leader_digest, leader) = (leader.digest(), leader.block());
        let mut positions = Vec::with_capacity(config.chains());
        let mut settled = Vec::with_capacity(config.chains());
        for chain in config.chain_ids() {
            positions.push(self.position(chain).ok_or(Error::Chain(chain))?);
            settled.push(self.settled(chain).ok_or(Error::Chain(chain))?);
        }
        Ok(FinalityFact::new(
            id,
            leader.round(),
            leader_digest,
            leader.parent(),
            votes,
            self.blocks.clone(),
            leader.proposed_heights(),
            positions,
            settled,
        ))
    }
}

#[cfg(test)]
impl<D: Digest> FinalTips<D> {
    /// Creates final-tip facts in canonical chain order.
    pub(crate) fn new(
        blocks: Vec<BlockRef<D>>,
        positions: Vec<Position>,
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        if blocks.len() != positions.len() || blocks.len() != settled.len() {
            return Err(Error::Vote);
        }
        check_chain_order(&blocks)?;
        Ok(Self {
            blocks,
            positions,
            settled,
        })
    }

    /// Returns one chain's final tip.
    pub(crate) fn get(&self, chain: ChainId) -> Option<BlockRef<D>> {
        self.blocks.get(chain.index()).copied()
    }
}

/// The pool-wide inputs to the settled rule.
#[derive(Clone, Copy, Debug)]
struct Settlement {
    /// Participants whose votes the pool has not seen.
    unseen: usize,
    /// The largest number of faulty participants, `f`.
    faults: usize,
}

impl Settlement {
    /// Derives the settled-rule inputs for a pool holding `seen` distinct votes.
    fn new(config: CodecConfig, seen: usize) -> Result<Self, Error> {
        Ok(Self {
            unseen: config
                .participants()
                .checked_sub(seen)
                .ok_or(Error::Quorum)?,
            faults: config.max_faults(),
        })
    }

    /// Returns whether one child of a final tip holding `beyond` votes stays within `f` support
    /// even if every unseen voter also supports it.
    ///
    /// Every vote that carries a chain beyond its final tip supports one immediate child of it.
    fn settled(self, beyond: usize) -> bool {
        beyond
            .checked_add(self.unseen)
            .is_some_and(|possible| possible <= self.faults)
    }
}

/// One authenticated vote reconstructed against the leader's proposal paths.
struct PreparedVote<D: Digest> {
    positions: Vec<Position>,
    paths: VotePaths<D>,
}

impl<D: Digest> PreparedVote<D> {
    fn chain<'a>(
        &'a self,
        proposals: &'a ProposalPaths<D>,
        chain: ChainId,
    ) -> Result<impl Iterator<Item = &'a BlockRef<D>>, Error> {
        let position = self.positions.get(chain.index()).ok_or(Error::Vote)?;
        let prefix = proposals
            .chain(chain)?
            .get(..position.get() as usize)
            .ok_or(Error::Vote)?;
        Ok(prefix.iter().chain(self.paths.extension(chain)?))
    }
}

/// A batch of distinct authenticated votes for one leader block, prepared for tip extraction.
///
/// Unlike [`PoolExtractor`], the batch keeps each vote's positions and paths, so every rank and
/// support query rescans the batch.
pub(super) struct PreparedVotes<D: Digest> {
    proposals: ProposalPaths<D>,
    votes: Vec<PreparedVote<D>>,
}

impl<D: Digest> PreparedVotes<D> {
    pub(super) fn new<'a, H, V, I>(
        leader: &LeaderBlock<V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        I: IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        D: 'a,
    {
        Self::new_digested::<H, V, I>(DigestedLeader::new::<H>(leader), votes, config)
    }

    pub(super) fn new_digested<'a, H, V, I>(
        digested: DigestedLeader<'_, V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        I: IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        D: 'a,
    {
        let leader = digested.block();
        if leader.validate(config).is_err() {
            return Err(Error::Leader);
        }

        let proposals = ProposalPaths::new::<H, V>(leader)?;
        let mut signers = BTreeSet::new();
        let mut prepared = Vec::new();
        for (signer, body) in votes {
            if usize::from(signer) >= config.participants() {
                return Err(Error::Signer);
            }
            if !signers.insert(signer) {
                return Err(Error::Quorum);
            }
            if prepared.len() == config.participants() {
                return Err(Error::Quorum);
            }
            if body.validate(config).is_err() {
                return Err(Error::Vote);
            }
            let paths = VotePaths::new::<H, V>(digested, &proposals, body)?;
            prepared.push(PreparedVote {
                positions: body.positions().to_vec(),
                paths,
            });
        }
        Ok(Self {
            proposals,
            votes: prepared,
        })
    }

    pub(super) const fn len(&self) -> usize {
        self.votes.len()
    }

    /// Checks that the batch holds a V-QC's vote count: at least `2f + 1`, at most `n`.
    pub(super) fn check_vqc_quorum(&self, config: CodecConfig) -> Result<(), Error> {
        if self.len() < config.designation_quorum() || self.len() > config.vqc_max_messages() {
            return Err(Error::Quorum);
        }
        Ok(())
    }

    pub(super) fn ancestry(&self) -> Result<PathIndex<D>, Error> {
        let mut ancestry = PathIndex::default();
        self.proposals.index(&mut ancestry)?;
        for vote in &self.votes {
            vote.paths.index_extensions(&mut ancestry)?;
        }
        Ok(ancestry)
    }

    fn rank(&self, chain: ChainId, rank: usize) -> Result<Position, Error> {
        if rank == 0 || rank > self.votes.len() {
            return Err(Error::Quorum);
        }
        let proposal = self.proposals.chain(chain)?;
        let mut counts = vec![0usize; proposal.len()];
        for vote in &self.votes {
            let position = vote.positions.get(chain.index()).ok_or(Error::Vote)?;
            let count = counts.get_mut(position.get() as usize).ok_or(Error::Vote)?;
            *count += 1;
        }
        descending_rank(&counts, rank)
    }

    fn deepest_supported(
        &self,
        chain: ChainId,
        base: BlockRef<D>,
        threshold: usize,
    ) -> Result<BlockRef<D>, Error> {
        let mut support = BTreeMap::<BlockRef<D>, usize>::new();
        for vote in &self.votes {
            let mut path = vote.chain(&self.proposals, chain)?;
            if !path.any(|block| *block == base) {
                continue;
            }
            for block in path {
                *support.entry(*block).or_default() += 1;
            }
        }

        let mut deepest = base;
        for (candidate, count) in support {
            if count >= threshold && deeper(candidate, deepest) {
                deepest = candidate;
            }
        }
        Ok(deepest)
    }

    fn max_child_support(&self, chain: ChainId, tip: BlockRef<D>) -> Result<usize, Error> {
        let mut children = BTreeMap::<BlockRef<D>, usize>::new();
        for vote in &self.votes {
            let mut path = vote.chain(&self.proposals, chain)?;
            if path.any(|block| *block == tip)
                && let Some(child) = path.next()
            {
                *children.entry(*child).or_default() += 1;
            }
        }
        // Every future carry beyond this tip must support one exact immediate child.
        // Unseen voters and Byzantine replacements can add at most unseen + f support.
        Ok(children.into_values().max().unwrap_or(0))
    }
}

/// Returns whether `candidate` is preferred over `current` as a deepest tip: greater height, then
/// smaller digest at equal height.
pub(super) fn deeper<D: Digest>(candidate: BlockRef<D>, current: BlockRef<D>) -> bool {
    candidate.height() > current.height()
        || candidate.height() == current.height() && candidate.digest() < current.digest()
}

/// Checks that `blocks` holds one block per chain in ascending chain order.
fn check_chain_order<D: Digest>(blocks: &[BlockRef<D>]) -> Result<(), Error> {
    if blocks
        .iter()
        .enumerate()
        .any(|(index, block)| block.chain().index() != index)
    {
        return Err(Error::ChainOrder);
    }
    Ok(())
}

/// Returns the highest position that at least `rank` votes reach or exceed.
///
/// `counts[p]` is the number of votes whose proposal position is exactly `p`. Walking positions
/// from the proposal tip down, the first position where the running total reaches `rank` is the
/// deepest position endorsed by `rank` votes, counting every vote at or beyond it.
fn descending_rank(counts: &[usize], rank: usize) -> Result<Position, Error> {
    if rank == 0 {
        return Err(Error::Quorum);
    }
    let mut seen = 0usize;
    for (position, count) in counts.iter().copied().enumerate().rev() {
        seen += count;
        if seen >= rank {
            return Ok(Position::new(position as u32));
        }
    }
    Err(Error::Quorum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        algebra::tests::{config, leader},
        types::Extension,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig};

    #[test]
    fn settlement_bounds_child_support_and_unseen_voters_by_faults() {
        // n = 6 tolerates f = 1; a pool of five votes leaves one voter unseen.
        let settlement = Settlement::new(config(6), 5).unwrap();
        assert!(settlement.settled(0));
        assert!(!settlement.settled(1));
        // Support that would overflow when unseen voters are added is never settled.
        assert!(!settlement.settled(usize::MAX));

        let complete = Settlement::new(config(6), 6).unwrap();
        assert!(complete.settled(1));
        assert!(!complete.settled(2));
        assert_eq!(Settlement::new(config(6), 7).unwrap_err(), Error::Quorum);
    }

    #[test]
    fn invalid_extension_leaves_the_entire_pool_unchanged() {
        let config = config(6);
        let leader = leader(6);
        let mut pool = PoolExtractor::new::<Sha256, MinSig>(&leader, config).unwrap();
        let positions = vec![Position::new(1); config.chains()];
        let mut extensions = vec![Extension::empty(); config.chains()];
        for extension in &mut extensions[..2] {
            *extension =
                Extension::new(vec![Sha256::hash(&[b"child"])], config.extension_bound()).unwrap();
        }
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            positions,
            extensions,
            config,
        )
        .unwrap();
        let paths = VotePaths::new::<Sha256, MinSig>(
            DigestedLeader::with_digest(&leader, pool.leader),
            &pool.proposals,
            &body,
        )
        .unwrap();
        let suffix = paths.extension(ChainId::new(1)).unwrap();
        let wrong_parent = BlockRef::new(
            suffix[0].chain(),
            suffix[0].height(),
            Sha256::hash(&[b"wrong-parent"]),
        );
        pool.ancestry
            .insert_parent(suffix[1], wrong_parent)
            .unwrap();
        let before = pool.clone();
        let signer = Participant::new(0);
        assert_eq!(
            pool.insert::<Sha256, MinSig>(&leader, signer, &body),
            Err(Error::ConflictingAncestry)
        );
        assert_eq!(pool.proposals, before.proposals);
        assert_eq!(pool.signers_seen, before.signers_seen);
        assert_eq!(pool.position_counts, before.position_counts);
        assert_eq!(pool.support, before.support);
        assert_eq!(pool.best_supported, before.best_supported);
        assert_eq!(pool.max_child_support, before.max_child_support);
        assert_eq!(pool.ancestry, before.ancestry);
        assert_eq!(pool.len, before.len);
        let valid = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            body.positions().to_vec(),
            vec![Extension::empty(); config.chains()],
            config,
        )
        .unwrap();
        assert!(
            pool.insert::<Sha256, MinSig>(&leader, signer, &valid)
                .unwrap()
        );
        assert!(
            !pool
                .insert::<Sha256, MinSig>(&leader, signer, &body)
                .unwrap()
        );
    }
}
