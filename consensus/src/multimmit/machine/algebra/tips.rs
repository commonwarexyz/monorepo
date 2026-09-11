//! Safe and final tip extraction.

use super::{
    Error, ProposalPaths, VotePaths,
    path::{Ancestry, PathIndex},
};
use crate::multimmit::{
    config::CodecConfig,
    types::{BlockRef, ChainId, LeaderBlock, Lqc, Position, VoteBody},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults, N5f1, Participant};
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
    qualified: Vec<BTreeSet<BlockRef<D>>>,
    max_child_support: Vec<BTreeMap<BlockRef<D>, usize>>,
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
            signers_seen: vec![false; config.participants()],
            position_counts,
            support: vec![BTreeMap::new(); config.chains()],
            qualified: vec![BTreeSet::new(); config.chains()],
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
        let index = usize::from(signer);
        let Some(seen) = self.signers_seen.get(index) else {
            return Err(Error::Quorum);
        };
        if *seen {
            return Ok(false);
        }
        if body.validate(self.config).is_err() {
            return Err(Error::Vote);
        }

        let paths = VotePaths::new::<H, V>(leader, self.leader, &self.proposals, body)?;
        paths.validate_extensions(&self.ancestry)?;

        for chain in 0..self.config.chains() {
            let chain_id = ChainId::new(chain as u32);
            let position = body.positions()[chain].get() as usize;
            *self.position_counts[chain]
                .get_mut(position)
                .ok_or(Error::Vote)? += 1;
            let path = paths.extension(chain_id)?;
            for block in &path[1..] {
                let count = self.support[chain].entry(*block).or_default();
                *count += 1;
                if *count == self.config.view_quorum() {
                    self.qualified[chain].insert(*block);
                }
            }
            for pair in path.windows(2) {
                let maximum = self.max_child_support[chain].entry(pair[0]).or_default();
                // Sticky votes only increase child support, so maxima never need rescanning.
                *maximum = (*maximum).max(self.support[chain][&pair[1]]);
            }
        }
        paths
            .index_extensions(&mut self.ancestry)
            .expect("vote paths were prevalidated against the ancestry index");
        self.signers_seen[index] = true;
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
            let beyond = self.max_child_support[chain]
                .get(&tip)
                .copied()
                .unwrap_or(0);
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
    ///
    /// Production extraction flows through [`super::validate_vqc`], which reuses the leader digest
    /// across derivations; this convenience wrapper serves tests and mocks.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn new<H, V>(
        certificate: &crate::multimmit::types::Vqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        Self::new_with_leader_digest::<H, V>(
            certificate,
            certificate.leader().digest::<H>(),
            config,
        )
    }

    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn new_with_leader_digest<H, V>(
        certificate: &crate::multimmit::types::Vqc<V, D>,
        leader_digest: D,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let leader = certificate.leader();
        let mut expanded = Vec::with_capacity(certificate.tally().signers().count());
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote_with_leader_digest(leader, leader_digest, signer, config)
                .map_err(|_| Error::Vote)?;
            expanded.push((signer, body));
        }
        Self::from_votes::<H, V>(
            leader,
            leader_digest,
            expanded.iter().map(|(signer, body)| (*signer, body)),
            config,
        )
    }

    /// Extracts ordering data from the already expanded votes of one authenticated V-QC.
    pub(crate) fn from_votes<'a, H, V>(
        leader: &LeaderBlock<V, D>,
        leader_digest: D,
        votes: impl IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
        D: 'a,
    {
        let prepared =
            PreparedVotes::new_with_leader_digest::<H, V, _>(leader, leader_digest, votes, config)?;
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

    pub(super) fn from_prepared(
        prepared: &PreparedVotes<D>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
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

    pub(crate) const fn owned_bytes(&self) -> Option<usize> {
        self.blocks.capacity().checked_mul(size_of::<BlockRef<D>>())
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

    pub(super) fn from_prepared(
        prepared: &PreparedVotes<D>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
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
            let beyond = prepared.max_child_support(chain, tip)?;

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
        let leader_digest = leader.digest::<H>();
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote_with_leader_digest(leader, leader_digest, signer, config)
                .map_err(|_| Error::Vote)?;
            votes.push((signer, body));
        }
        let prepared = PreparedVotes::new_with_leader_digest::<H, V, _>(
            leader,
            leader_digest,
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

impl<D: Digest> PreparedVote<D> {
    fn chain<'a>(
        &'a self,
        proposals: &'a ProposalPaths<D>,
        chain: ChainId,
    ) -> Result<impl Iterator<Item = &'a BlockRef<D>>, Error> {
        let position = self
            .positions
            .get(chain.get() as usize)
            .ok_or(Error::Vote)?;
        let prefix = proposals
            .chain(chain)?
            .get(..position.get() as usize)
            .ok_or(Error::Vote)?;
        Ok(prefix.iter().chain(self.paths.extension(chain)?))
    }
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
        Self::new_with_leader_digest::<H, V, I>(leader, leader.digest::<H>(), votes, config)
    }

    pub(super) fn new_with_leader_digest<'a, H, V, I>(
        leader: &LeaderBlock<V, D>,
        leader_digest: D,
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
        machine::algebra::tests::{config, leader},
        types::Extension,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig};

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
        let body =
            VoteBody::for_leader::<Sha256, MinSig>(&leader, positions, extensions, config).unwrap();
        let paths =
            VotePaths::new::<Sha256, MinSig>(&leader, pool.leader, &pool.proposals, &body).unwrap();
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
        assert_eq!(pool.qualified, before.qualified);
        assert_eq!(pool.max_child_support, before.max_child_support);
        assert_eq!(pool.ancestry, before.ancestry);
        assert_eq!(pool.len, before.len);
        let valid = VoteBody::for_leader::<Sha256, MinSig>(
            &leader,
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
