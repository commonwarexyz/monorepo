//! Materialized ancestry oracle shared by algebra tests and history fuzzing.

use crate::{
    multimmit::{
        config::CodecConfig,
        types::{
            Anchor, BlockRef, ChainId, LeaderBlock, Position, TransactionBlockHeader, VoteBody,
        },
    },
    types::{Height, Participant},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, sha256::Digest};
use std::collections::{BTreeMap, BTreeSet};

fn reference_child_support<'a>(
    paths: impl Iterator<Item = &'a [BlockRef<Digest>]>,
    tip: BlockRef<Digest>,
) -> usize {
    let mut counts = BTreeMap::<_, usize>::new();
    for path in paths {
        if let Some(index) = path.iter().position(|block| *block == tip)
            && let Some(child) = path.get(index + 1)
        {
            *counts.entry(*child).or_default() += 1;
        }
    }
    counts.into_values().max().unwrap_or(0)
}

#[derive(Clone)]
pub(super) struct ReferenceVote {
    pub(super) signer: Participant,
    pub(super) positions: Vec<Position>,
    pub(super) paths: Vec<Vec<BlockRef<Digest>>>,
}

pub(super) struct ReferenceFinal {
    pub(super) blocks: Vec<BlockRef<Digest>>,
    pub(super) positions: Vec<Position>,
    pub(super) settled: Vec<bool>,
}

pub(super) struct ReferenceOrdering {
    pub(super) proposals: Vec<Vec<BlockRef<Digest>>>,
    pub(super) parents: BTreeMap<BlockRef<Digest>, BlockRef<Digest>>,
    pub(super) blocks: BTreeSet<BlockRef<Digest>>,
}

impl ReferenceOrdering {
    pub(super) fn new(
        leader: &LeaderBlock<MinSig, Digest>,
        parent_tips: &[BlockRef<Digest>],
    ) -> Self {
        assert_eq!(leader.proposals().len(), parent_tips.len());
        let mut ordering = Self {
            proposals: Vec::with_capacity(leader.proposals().len()),
            parents: BTreeMap::new(),
            blocks: parent_tips.iter().copied().collect(),
        };
        for (index, proposal) in leader.proposals().iter().enumerate() {
            let anchor = proposal.anchor().block_ref::<Sha256>();
            if let Anchor::Certificate(certificate) = proposal.anchor() {
                let parent = BlockRef::new(
                    anchor.chain(),
                    Height::new(anchor.height().get() - 1),
                    certificate.header().parent(),
                );
                ordering.insert_path(&[parent, anchor]);
            };
            let mut path = vec![anchor];
            for payload in proposal.payloads() {
                let child = Self::child(leader, *path.last().unwrap(), *payload);
                path.push(child);
            }
            ordering.insert_path(&path);
            assert_eq!(path[0].chain(), ChainId::new(index as u32));
            ordering.proposals.push(path);
        }
        ordering
    }

    pub(super) fn materialize(
        &mut self,
        leader: &LeaderBlock<MinSig, Digest>,
        votes: &[(Participant, VoteBody<Digest>)],
    ) -> Vec<ReferenceVote> {
        votes
            .iter()
            .map(|(signer, vote)| {
                let paths = vote
                    .positions()
                    .iter()
                    .zip(vote.extensions())
                    .enumerate()
                    .map(|(chain, (position, extension))| {
                        let mut path = self.proposals[chain][..=position.get() as usize].to_vec();
                        for payload in extension.payloads() {
                            let child = Self::child(leader, *path.last().unwrap(), *payload);
                            path.push(child);
                        }
                        self.insert_path(&path);
                        path
                    })
                    .collect();
                ReferenceVote {
                    signer: *signer,
                    positions: vote.positions().to_vec(),
                    paths,
                }
            })
            .collect()
    }

    pub(super) fn safe(
        &self,
        votes: &[ReferenceVote],
        config: CodecConfig,
    ) -> Vec<BlockRef<Digest>> {
        let faults = (config.participants() - 1) / 5;
        let rank = faults + 1;
        (0..config.chains())
            .map(|chain| {
                let position = descending_position(votes, chain, rank);
                let base = self.proposals[chain][position.get() as usize];
                self.deepest(votes, chain, base, 2 * faults + 1)
            })
            .collect()
    }

    pub(super) fn final_tips(
        &self,
        votes: &[ReferenceVote],
        config: CodecConfig,
    ) -> ReferenceFinal {
        let faults = (config.participants() - 1) / 5;
        let rank = 3 * faults + 1;
        let unseen = config.participants() - votes.len();
        let mut blocks = Vec::with_capacity(config.chains());
        let mut positions = Vec::with_capacity(config.chains());
        let mut settled = Vec::with_capacity(config.chains());

        for chain in 0..config.chains() {
            let position = descending_position(votes, chain, rank);
            let proposal_tip = Position::new((self.proposals[chain].len() - 1) as u32);
            let base = self.proposals[chain][position.get() as usize];
            let tip = if position == proposal_tip {
                self.deepest(votes, chain, base, config.participants() - faults)
            } else {
                base
            };
            let beyond =
                reference_child_support(votes.iter().map(|vote| vote.paths[chain].as_slice()), tip);
            blocks.push(tip);
            positions.push(position);
            settled.push(position == proposal_tip && beyond + unseen <= faults);
        }

        ReferenceFinal {
            blocks,
            positions,
            settled,
        }
    }

    pub(super) fn deepest(
        &self,
        votes: &[ReferenceVote],
        chain: usize,
        base: BlockRef<Digest>,
        threshold: usize,
    ) -> BlockRef<Digest> {
        let candidates = votes
            .iter()
            .flat_map(|vote| vote.paths[chain].iter().copied())
            .collect::<BTreeSet<_>>();
        candidates.into_iter().fold(base, |deepest, candidate| {
            let support = votes
                .iter()
                .filter(|vote| vote.paths[chain].contains(&candidate))
                .count();
            if support < threshold || !self.extends(base, candidate) {
                return deepest;
            }
            if candidate.height() > deepest.height()
                || candidate.height() == deepest.height() && candidate.digest() < deepest.digest()
            {
                candidate
            } else {
                deepest
            }
        })
    }

    #[cfg(test)]
    pub(super) fn forked_producers(&self) -> BTreeSet<Participant> {
        let mut coordinates = BTreeMap::<(ChainId, Height), BlockRef<Digest>>::new();
        let mut forked = BTreeSet::new();
        for block in &self.blocks {
            let coordinate = (block.chain(), block.height());
            if coordinates
                .insert(coordinate, *block)
                .is_some_and(|existing| existing != *block)
            {
                forked.insert(Participant::new(block.chain().get()));
            }
        }
        forked
    }

    pub(super) fn extends(&self, ancestor: BlockRef<Digest>, descendant: BlockRef<Digest>) -> bool {
        if ancestor.chain() != descendant.chain() || ancestor.height() > descendant.height() {
            return false;
        }
        let mut current = descendant;
        while current.height() > ancestor.height() {
            let Some(parent) = self.parents.get(&current) else {
                return false;
            };
            current = *parent;
        }
        current == ancestor
    }

    pub(super) fn child(
        leader: &LeaderBlock<MinSig, Digest>,
        parent: BlockRef<Digest>,
        payload: Digest,
    ) -> BlockRef<Digest> {
        TransactionBlockHeader::new(
            leader.round().epoch(),
            parent.chain(),
            Height::new(parent.height().get() + 1),
            parent.digest(),
            payload,
        )
        .unwrap()
        .block_ref::<Sha256>()
    }

    pub(super) fn insert_path(&mut self, path: &[BlockRef<Digest>]) {
        self.blocks.extend(path.iter().copied());
        for pair in path.windows(2) {
            if let Some(parent) = self.parents.get(&pair[1]) {
                assert_eq!(*parent, pair[0]);
            } else {
                self.parents.insert(pair[1], pair[0]);
            }
        }
    }
}

fn descending_position(votes: &[ReferenceVote], chain: usize, rank: usize) -> Position {
    let mut positions = votes
        .iter()
        .map(|vote| vote.positions[chain])
        .collect::<Vec<_>>();
    positions.sort_unstable_by(|left, right| right.cmp(left));
    positions[rank - 1]
}
