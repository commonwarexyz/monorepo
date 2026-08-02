//! Safe and final tip extraction.

use super::{
    Error, ProposalPaths, VotePaths,
    path::{Ancestry, PathIndex},
};
use crate::multimmit::{
    config::CodecConfig,
    types::{BlockRef, ChainId, LeaderBlock, Lqc, Position, VoteBody, Vqc},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults, N5f1, Participant};
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
    votes: Vec<Option<VotePaths<D>>>,
    position_counts: Vec<Vec<usize>>,
    support: Vec<BTreeMap<BlockRef<D>, usize>>,
    qualified: Vec<BTreeSet<BlockRef<D>>>,
    extended: Vec<BTreeMap<BlockRef<D>, usize>>,
    ancestry: PathIndex<D>,
    len: usize,
}

impl<D: Digest> Ancestry<D> for PoolExtractor<D> {
    fn parent(&self, block: BlockRef<D>) -> Option<BlockRef<D>> {
        self.ancestry.parent(block)
    }
}

impl<D: Digest> PoolExtractor<D> {
    /// Creates an empty pool for one exact leader block.
    pub(crate) fn new<H, V>(leader: &LeaderBlock<V, D>, config: CodecConfig) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        if leader.validate(config).is_err() {
            return Err(Error::Vote);
        }
        let proposals = ProposalPaths::new::<H, V>(leader)?;
        let mut ancestry = PathIndex::default();
        proposals.index(&mut ancestry)?;
        let position_counts = (0..config.chains())
            .map(|chain| {
                proposals
                    .chain(ChainId::new(chain as u32))
                    .map(|path| vec![0; path.len()])
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config,
            leader: leader.digest::<H>(),
            proposals,
            votes: vec![None; config.participants()],
            position_counts,
            support: vec![BTreeMap::new(); config.chains()],
            qualified: vec![BTreeSet::new(); config.chains()],
            extended: vec![BTreeMap::new(); config.chains()],
            ancestry,
            len: 0,
        })
    }

    /// Retains a participant's first authenticated complete vote.
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
        let index = usize::from(signer);
        let Some(slot) = self.votes.get(index) else {
            return Err(Error::Quorum);
        };
        if slot.is_some() {
            return Ok(false);
        }
        if body.validate(self.config).is_err() {
            return Err(Error::Vote);
        }

        let paths = VotePaths::new::<H, V>(leader, self.leader, &self.proposals, body)?;
        paths.validate_index(&self.ancestry)?;

        for chain in 0..self.config.chains() {
            let chain_id = ChainId::new(chain as u32);
            let position = body.positions()[chain].get() as usize;
            *self.position_counts[chain]
                .get_mut(position)
                .ok_or(Error::Vote)? += 1;
            let path = paths.chain(chain_id)?;
            for block in path {
                let count = self.support[chain].entry(*block).or_default();
                *count += 1;
                if *count == self.config.view_quorum() {
                    self.qualified[chain].insert(*block);
                }
            }
            for pair in path.windows(2) {
                *self.extended[chain].entry(pair[0]).or_default() += 1;
            }
        }
        paths
            .index(&mut self.ancestry)
            .expect("vote paths were prevalidated against the ancestry index");
        self.votes[index] = Some(paths);
        self.len += 1;
        Ok(true)
    }

    /// Returns the number of retained participants.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn retained_support_entries(&self) -> usize {
        self.support.iter().map(BTreeMap::len).sum()
    }

    #[cfg(test)]
    pub(crate) fn final_tip_candidates(&self) -> usize {
        self.qualified.iter().map(BTreeSet::len).sum()
    }

    /// Extracts the current pool-final tips and settlement facts.
    pub(crate) fn final_tips(&self) -> Result<FinalTips<D>, Error> {
        if self.len < self.config.view_quorum() {
            return Err(Error::Quorum);
        }

        let rank = N5f1::three_f_plus_one(self.config.participants()) as usize;
        let unseen = self.config.participants() - self.len;
        let faults = N5f1::max_faults(self.config.participants()) as usize;
        let mut blocks = Vec::with_capacity(self.config.chains());
        let mut positions = Vec::with_capacity(self.config.chains());
        let mut settled = Vec::with_capacity(self.config.chains());

        for chain in 0..self.config.chains() {
            let chain_id = ChainId::new(chain as u32);
            let position = descending_rank(&self.position_counts[chain], rank)?;
            let proposal = self.proposals.chain(chain_id)?;
            let proposal_tip = Position::new((proposal.len() - 1) as u32);
            let base = self.proposals.block(chain_id, position)?;
            let tip = if position == proposal_tip {
                self.deepest_supported(chain, base)?
            } else {
                base
            };
            let beyond = self.extended[chain].get(&tip).copied().unwrap_or(0);
            blocks.push(tip);
            positions.push(position);
            settled.push(position == proposal_tip && beyond + unseen <= faults);
        }

        FinalTips::new(blocks, positions, settled)
    }

    fn deepest_supported(&self, chain: usize, base: BlockRef<D>) -> Result<BlockRef<D>, Error> {
        let mut deepest = base;
        for candidate in &self.qualified[chain] {
            if candidate.height() <= base.height()
                || !self.ancestry.extends_or_equals(base, *candidate)?
            {
                continue;
            }
            if candidate.height() > deepest.height()
                || candidate.height() == deepest.height() && candidate.digest() < deepest.digest()
            {
                deepest = *candidate;
            }
        }
        Ok(deepest)
    }
}

/// Per-chain tips that are safe to extend after a V-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tips<D: Digest> {
    blocks: Vec<BlockRef<D>>,
}

/// Safe V-QC tips and the exact authenticated ancestry used to derive them.
#[derive(Clone, Debug)]
pub(crate) struct VqcExtraction<D: Digest> {
    tips: Tips<D>,
    ancestry: PathIndex<D>,
}

impl<D: Digest> VqcExtraction<D> {
    /// Extracts ordering data from one authenticated V-QC transcript.
    pub(crate) fn new<H, V>(certificate: &Vqc<V, D>, config: CodecConfig) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let leader = certificate.leader();
        let mut expanded = Vec::with_capacity(certificate.tally().signers().count());
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote::<V, H>(leader, signer, config)
                .map_err(|_| Error::Vote)?;
            expanded.push((signer, body));
        }
        let prepared = PreparedVotes::new::<H, V, _>(
            leader,
            expanded.iter().map(|(signer, body)| (*signer, body)),
            config,
        )?;
        if prepared.len() < config.designation_quorum()
            || prepared.len() > config.vqc_max_messages()
        {
            return Err(Error::Quorum);
        }
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
        if blocks
            .iter()
            .enumerate()
            .any(|(index, block)| u32::try_from(index).map(ChainId::new) != Ok(block.chain()))
        {
            return Err(Error::Vote);
        }
        Ok(Self { blocks })
    }

    /// Extracts safe tips from the designated votes of a V-QC transcript.
    #[cfg(test)]
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
        if prepared.len() < config.designation_quorum()
            || prepared.len() > config.vqc_max_messages()
        {
            return Err(Error::Quorum);
        }

        Self::from_prepared(&prepared, config)
    }

    fn from_prepared(prepared: &PreparedVotes<D>, config: CodecConfig) -> Result<Self, Error> {
        let rank = N5f1::f_plus_one(config.participants()) as usize;
        let mut blocks = Vec::with_capacity(config.chains());
        for index in 0..config.chains() {
            let chain = ChainId::new(index as u32);
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

    /// Returns one chain's safe tip.
    #[cfg(test)]
    pub(crate) fn get(&self, chain: ChainId) -> Option<BlockRef<D>> {
        self.blocks.get(chain.get() as usize).copied()
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
    /// Creates final-tip facts in canonical chain order.
    pub(crate) fn new(
        blocks: Vec<BlockRef<D>>,
        positions: Vec<Position>,
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        if blocks.len() != positions.len()
            || blocks.len() != settled.len()
            || blocks
                .iter()
                .enumerate()
                .any(|(index, block)| u32::try_from(index).map(ChainId::new) != Ok(block.chain()))
        {
            return Err(Error::Vote);
        }
        Ok(Self {
            blocks,
            positions,
            settled,
        })
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

    fn from_prepared(prepared: &PreparedVotes<D>, config: CodecConfig) -> Result<Self, Error> {
        if prepared.len() < config.view_quorum() {
            return Err(Error::Quorum);
        }

        let rank = N5f1::three_f_plus_one(config.participants()) as usize;
        let support = config.view_quorum();
        let unseen = config
            .participants()
            .checked_sub(prepared.len())
            .ok_or(Error::Quorum)?;
        let faults = N5f1::max_faults(config.participants()) as usize;

        let mut blocks = Vec::with_capacity(config.chains());
        let mut positions = Vec::with_capacity(config.chains());
        let mut settled = Vec::with_capacity(config.chains());
        for index in 0..config.chains() {
            let chain = ChainId::new(index as u32);
            let position = prepared.rank(chain, rank)?;
            let proposal = prepared.proposals.chain(chain)?;
            let proposal_tip = Position::new((proposal.len() - 1) as u32);
            let base = prepared.proposals.block(chain, position)?;
            let tip = if position == proposal_tip {
                prepared.deepest_supported(chain, base, support)?
            } else {
                base
            };
            let beyond = prepared.count_beyond(chain, tip)?;

            blocks.push(tip);
            positions.push(position);
            settled.push(
                position == proposal_tip
                    && beyond
                        .checked_add(unseen)
                        .is_some_and(|possible| possible <= faults),
            );
        }

        Ok(Self {
            blocks,
            positions,
            settled,
        })
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
        let leader = certificate.leader();
        let mut votes = Vec::with_capacity(certificate.tally().signers().count());
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote::<V, H>(leader, signer, config)
                .map_err(|_| Error::Vote)?;
            votes.push((signer, body));
        }
        let prepared = PreparedVotes::new::<H, V, _>(
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

    /// Returns one chain's final tip.
    #[cfg(test)]
    pub(crate) fn get(&self, chain: ChainId) -> Option<BlockRef<D>> {
        self.blocks.get(chain.get() as usize).copied()
    }

    /// Returns the final position rank for one chain.
    pub(crate) fn position(&self, chain: ChainId) -> Option<Position> {
        self.positions.get(chain.get() as usize).copied()
    }

    /// Returns whether the pool proves that one chain cannot grow in a same-view V-QC.
    pub(crate) fn settled(&self, chain: ChainId) -> Option<bool> {
        self.settled.get(chain.get() as usize).copied()
    }
}

struct PreparedVote<D: Digest> {
    positions: Vec<Position>,
    paths: VotePaths<D>,
}

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
        if leader.validate(config).is_err() {
            return Err(Error::Vote);
        }

        let proposals = ProposalPaths::new::<H, V>(leader)?;
        let leader_digest = leader.digest::<H>();
        let mut signers = BTreeSet::new();
        let mut prepared = Vec::new();
        for (signer, body) in votes {
            if usize::from(signer) >= config.participants() || !signers.insert(signer) {
                return Err(Error::Quorum);
            }
            if prepared.len() == config.participants() {
                return Err(Error::Quorum);
            }
            if body.validate(config).is_err() {
                return Err(Error::Vote);
            }
            let paths = VotePaths::new::<H, V>(leader, leader_digest, &proposals, body)?;
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

    pub(super) fn ancestry(&self) -> Result<PathIndex<D>, Error> {
        let mut ancestry = PathIndex::default();
        self.proposals.index(&mut ancestry)?;
        for vote in &self.votes {
            vote.paths.index(&mut ancestry)?;
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
            let position = vote
                .positions
                .get(chain.get() as usize)
                .ok_or(Error::Vote)?;
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
            let path = vote.paths.chain(chain)?;
            let Some(base_index) = path.iter().position(|block| *block == base) else {
                continue;
            };
            for block in &path[base_index + 1..] {
                *support.entry(*block).or_default() += 1;
            }
        }

        let mut deepest = base;
        for (candidate, count) in support {
            if count < threshold {
                continue;
            }
            if candidate.height() > deepest.height()
                || candidate.height() == deepest.height() && candidate.digest() < deepest.digest()
            {
                deepest = candidate;
            }
        }
        Ok(deepest)
    }

    fn count_beyond(&self, chain: ChainId, tip: BlockRef<D>) -> Result<usize, Error> {
        let mut count = 0usize;
        for vote in &self.votes {
            let path = vote.paths.chain(chain)?;
            if path
                .iter()
                .position(|block| *block == tip)
                .is_some_and(|index| index + 1 < path.len())
            {
                count += 1;
            }
        }
        Ok(count)
    }
}

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
