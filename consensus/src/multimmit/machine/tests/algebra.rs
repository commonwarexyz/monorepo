use super::{
    Error, ProposalPaths, VotePaths,
    path::PathIndex,
    tips::{FinalTips, PoolExtractor, Tips},
};
use crate::{
    multimmit::{
        config::{CodecConfig, Limits},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, DaCertificate, Extension,
            LeaderBlock, Position, TransactionBlockHeader, VoteBody,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::{
            group::{Private, Scalar},
            ops::sign_message,
            variant::MinSig,
        },
    },
    sha256,
};
use commonware_utils::{Faults, N5f1, TestRng};
use proptest::{collection::vec as prop_vec, prelude::*};
use rand::seq::SliceRandom;
use std::collections::{BTreeMap, BTreeSet};

type Digest = sha256::Digest;

fn digest(label: &[u8]) -> Digest {
    Sha256::hash(&[label])
}

fn config(participants: usize) -> CodecConfig {
    CodecConfig::new(participants, participants, Limits::new(2, 2).unwrap()).unwrap()
}

fn leader(participants: usize) -> LeaderBlock<MinSig, Digest> {
    let config = config(participants);
    let proposals = (0..participants)
        .map(|index| {
            let chain = ChainId::new(index as u32);
            let anchor = Anchor::Tip(BlockRef::new(
                chain,
                Height::zero(),
                digest(format!("anchor-{index}").as_bytes()),
            ));
            let payloads = (0..2)
                .map(|position| digest(format!("proposal-{index}-{position}").as_bytes()))
                .collect();
            ChainProposal::new(chain, anchor, payloads, config.pipeline_depth()).unwrap()
        })
        .collect();
    LeaderBlock::new(
        Round::new(Epoch::new(7), View::new(1)),
        CertificateId::new(digest(b"parent")),
        digest(b"history"),
        proposals,
        config,
    )
    .unwrap()
}

fn vote(
    leader: &LeaderBlock<MinSig, Digest>,
    position: u32,
    extension: &[&[u8]],
    config: CodecConfig,
) -> VoteBody<Digest> {
    vote_with_digests(
        leader,
        position,
        extension.iter().map(|payload| digest(payload)).collect(),
        config,
    )
}

fn vote_with_digests(
    leader: &LeaderBlock<MinSig, Digest>,
    position: u32,
    extension: Vec<Digest>,
    config: CodecConfig,
) -> VoteBody<Digest> {
    let mut positions = vec![Position::new(2); config.chains()];
    positions[0] = Position::new(position);
    let mut extensions = vec![Extension::empty(); config.chains()];
    extensions[0] = Extension::new(extension, config.extension_bound()).unwrap();
    VoteBody::for_leader::<Sha256, MinSig>(leader, positions, extensions, config).unwrap()
}

fn application_digests(
    leader: &LeaderBlock<MinSig, Digest>,
    position: u32,
    payloads: Vec<u8>,
) -> Vec<Digest> {
    let chain = ChainId::new(0);
    let proposals = ProposalPaths::new::<Sha256, MinSig>(leader).unwrap();
    let mut parent = proposals.block(chain, Position::new(position)).unwrap();
    payloads
        .into_iter()
        .map(|payload| {
            let next_height = parent.height().get().checked_add(1).unwrap();
            let epoch = leader.round().epoch().get().to_be_bytes();
            let chain = chain.get().to_be_bytes();
            let height = next_height.to_be_bytes();
            let payload = [payload];
            let digest = Sha256::hash(&[
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_APPLICATION_BLOCK",
                &epoch,
                &chain,
                &height,
                parent.digest().as_ref(),
                &payload,
            ]);
            parent = BlockRef::new(parent.chain(), Height::new(next_height), digest);
            digest
        })
        .collect()
}

fn reference_safe(
    leader: &LeaderBlock<MinSig, Digest>,
    votes: &[VoteBody<Digest>],
    config: CodecConfig,
) -> Vec<BlockRef<Digest>> {
    let proposals = ProposalPaths::new::<Sha256, MinSig>(leader).unwrap();
    let paths = votes
        .iter()
        .map(|vote| {
            VotePaths::new::<Sha256, MinSig>(leader, leader.digest::<Sha256>(), &proposals, vote)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let rank = N5f1::f_plus_one(config.participants()) as usize;

    (0..config.chains())
        .map(|index| {
            let chain = ChainId::new(index as u32);
            let mut positions = votes
                .iter()
                .map(|vote| vote.positions()[index])
                .collect::<Vec<_>>();
            positions.sort_unstable_by(|left, right| right.cmp(left));
            let base = proposals.block(chain, positions[rank - 1]).unwrap();
            reference_deepest(&paths, chain, base, config.designation_quorum())
        })
        .collect()
}

fn reference_final(
    leader: &LeaderBlock<MinSig, Digest>,
    votes: &[VoteBody<Digest>],
    config: CodecConfig,
) -> (Vec<BlockRef<Digest>>, Vec<Position>, Vec<bool>) {
    let proposals = ProposalPaths::new::<Sha256, MinSig>(leader).unwrap();
    let paths = votes
        .iter()
        .map(|vote| {
            VotePaths::new::<Sha256, MinSig>(leader, leader.digest::<Sha256>(), &proposals, vote)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let rank = N5f1::three_f_plus_one(config.participants()) as usize;
    let unseen = config.participants() - votes.len();
    let faults = N5f1::max_faults(config.participants()) as usize;
    let mut blocks = Vec::with_capacity(config.chains());
    let mut final_positions = Vec::with_capacity(config.chains());
    let mut settled = Vec::with_capacity(config.chains());

    for index in 0..config.chains() {
        let chain = ChainId::new(index as u32);
        let mut positions = votes
            .iter()
            .map(|vote| vote.positions()[index])
            .collect::<Vec<_>>();
        positions.sort_unstable_by(|left, right| right.cmp(left));
        let position = positions[rank - 1];
        let proposal_tip = Position::new((proposals.chain(chain).unwrap().len() - 1) as u32);
        let base = proposals.block(chain, position).unwrap();
        let tip = if position == proposal_tip {
            reference_deepest(&paths, chain, base, config.view_quorum())
        } else {
            base
        };
        let beyond = paths
            .iter()
            .filter(|path| {
                path.chain(chain)
                    .unwrap()
                    .iter()
                    .position(|block| *block == tip)
                    .is_some_and(|tip_index| tip_index + 1 < path.chain(chain).unwrap().len())
            })
            .count();
        blocks.push(tip);
        final_positions.push(position);
        settled.push(position == proposal_tip && beyond + unseen <= faults);
    }

    (blocks, final_positions, settled)
}

fn reference_deepest(
    paths: &[VotePaths<Digest>],
    chain: ChainId,
    base: BlockRef<Digest>,
    threshold: usize,
) -> BlockRef<Digest> {
    let candidates = paths
        .iter()
        .flat_map(|path| path.chain(chain).unwrap().iter().copied())
        .collect::<BTreeSet<_>>();
    let mut deepest = base;
    for candidate in candidates {
        let support = paths
            .iter()
            .filter(|path| {
                let path = path.chain(chain).unwrap();
                let Some(base_index) = path.iter().position(|block| *block == base) else {
                    return false;
                };
                path[base_index + 1..].contains(&candidate)
            })
            .count();
        if support >= threshold
            && (candidate.height() > deepest.height()
                || candidate.height() == deepest.height() && candidate.digest() < deepest.digest())
        {
            deepest = candidate;
        }
    }
    deepest
}

fn indexed(votes: &[VoteBody<Digest>]) -> impl Iterator<Item = (Participant, &VoteBody<Digest>)> {
    votes
        .iter()
        .enumerate()
        .map(|(index, vote)| (Participant::new(index as u32), vote))
}

fn attributed(
    votes: &[(Participant, VoteBody<Digest>)],
) -> impl Iterator<Item = (Participant, &VoteBody<Digest>)> {
    votes.iter().map(|(signer, vote)| (*signer, vote))
}

#[derive(Clone)]
struct ReferenceVote {
    signer: Participant,
    positions: Vec<Position>,
    paths: Vec<Vec<BlockRef<Digest>>>,
}

struct ReferenceFinal {
    blocks: Vec<BlockRef<Digest>>,
    positions: Vec<Position>,
    settled: Vec<bool>,
}

struct ReferenceOrdering {
    proposals: Vec<Vec<BlockRef<Digest>>>,
    parents: BTreeMap<BlockRef<Digest>, BlockRef<Digest>>,
    blocks: BTreeSet<BlockRef<Digest>>,
}

impl ReferenceOrdering {
    fn new(leader: &LeaderBlock<MinSig, Digest>, parent_tips: &[BlockRef<Digest>]) -> Self {
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

    fn materialize(
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

    fn safe(&self, votes: &[ReferenceVote], config: CodecConfig) -> Vec<BlockRef<Digest>> {
        let rank = N5f1::f_plus_one(config.participants()) as usize;
        (0..config.chains())
            .map(|chain| {
                let position = descending_position(votes, chain, rank);
                let base = self.proposals[chain][position.get() as usize];
                self.deepest(votes, chain, base, config.designation_quorum())
            })
            .collect()
    }

    fn final_tips(&self, votes: &[ReferenceVote], config: CodecConfig) -> ReferenceFinal {
        let rank = N5f1::three_f_plus_one(config.participants()) as usize;
        let unseen = config.participants() - votes.len();
        let faults = N5f1::max_faults(config.participants()) as usize;
        let mut blocks = Vec::with_capacity(config.chains());
        let mut positions = Vec::with_capacity(config.chains());
        let mut settled = Vec::with_capacity(config.chains());

        for chain in 0..config.chains() {
            let position = descending_position(votes, chain, rank);
            let proposal_tip = Position::new((self.proposals[chain].len() - 1) as u32);
            let base = self.proposals[chain][position.get() as usize];
            let tip = if position == proposal_tip {
                self.deepest(votes, chain, base, config.view_quorum())
            } else {
                base
            };
            let beyond = votes
                .iter()
                .filter(|vote| {
                    vote.paths[chain]
                        .iter()
                        .position(|block| *block == tip)
                        .is_some_and(|index| index + 1 < vote.paths[chain].len())
                })
                .count();
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

    fn deepest(
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

    fn forked_producers(&self) -> BTreeSet<Participant> {
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

    fn extends(&self, ancestor: BlockRef<Digest>, descendant: BlockRef<Digest>) -> bool {
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

    fn child(
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

    fn insert_path(&mut self, path: &[BlockRef<Digest>]) {
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

#[test]
fn proposal_and_vote_paths_reconstruct_exact_headers() {
    let config = config(6);
    let leader = leader(6);
    let proposals = ProposalPaths::new::<Sha256, MinSig>(&leader).unwrap();
    let body = vote(&leader, 1, &[b"extension"], config);
    let paths =
        VotePaths::new::<Sha256, MinSig>(&leader, leader.digest::<Sha256>(), &proposals, &body)
            .unwrap();
    let mut ancestry = PathIndex::default();
    proposals.index(&mut ancestry).unwrap();
    paths.index(&mut ancestry).unwrap();
    let chain = paths.chain(ChainId::new(0)).unwrap();

    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].height(), Height::zero());
    assert_eq!(
        chain[1],
        proposals.block(ChainId::new(0), Position::new(1)).unwrap()
    );
    assert_eq!(chain[2].height(), Height::new(2));
    assert_ne!(
        chain[2],
        proposals.block(ChainId::new(0), Position::new(2)).unwrap()
    );
}

#[test]
fn safe_tips_apply_position_rank_and_branch_aware_carry() {
    let config = config(7);
    let leader = leader(7);
    let votes = [
        vote(&leader, 2, &[b"a"], config),
        vote(&leader, 2, &[b"a"], config),
        vote(&leader, 2, &[b"a"], config),
        vote(&leader, 2, &[b"b"], config),
        vote(&leader, 2, &[b"b"], config),
        vote(&leader, 2, &[b"b"], config),
    ];
    let tips = Tips::from_votes::<Sha256, MinSig, _>(&leader, indexed(&votes), config).unwrap();
    let proposals = ProposalPaths::new::<Sha256, MinSig>(&leader).unwrap();
    let leader_digest = leader.digest::<Sha256>();
    let left =
        VotePaths::new::<Sha256, MinSig>(&leader, leader_digest, &proposals, &votes[0]).unwrap();
    let right =
        VotePaths::new::<Sha256, MinSig>(&leader, leader_digest, &proposals, &votes[3]).unwrap();
    let left = *left.chain(ChainId::new(0)).unwrap().last().unwrap();
    let right = *right.chain(ChainId::new(0)).unwrap().last().unwrap();

    assert_eq!(tips.get(ChainId::new(0)), Some(left.min(right)));
    assert_eq!(tips.blocks().len(), config.chains());
}

#[test]
fn safe_tips_use_every_designated_vote_in_a_larger_vqc() {
    let config = config(6);
    let leader = leader(6);
    let votes = [
        vote(&leader, 2, &[], config),
        vote(&leader, 0, &[], config),
        vote(&leader, 0, &[], config),
        vote(&leader, 0, &[], config),
        vote(&leader, 0, &[], config),
        vote(&leader, 2, &[], config),
    ];

    let quorum = Tips::from_votes::<Sha256, MinSig, _>(
        &leader,
        indexed(&votes[..config.view_quorum()]),
        config,
    )
    .unwrap();
    let complete = Tips::from_votes::<Sha256, MinSig, _>(&leader, indexed(&votes), config).unwrap();

    assert_ne!(quorum, complete);
    assert_eq!(
        complete.get(ChainId::new(0)).unwrap().height(),
        Height::new(2)
    );
}

#[test]
fn final_tips_use_pool_support_and_generalized_settlement() {
    let config = config(7);
    let leader = leader(7);
    let votes = [
        vote(&leader, 2, &[b"x"], config),
        vote(&leader, 2, &[b"x"], config),
        vote(&leader, 2, &[b"x"], config),
        vote(&leader, 2, &[b"x"], config),
        vote(&leader, 2, &[b"x"], config),
        vote(&leader, 2, &[b"x", b"y"], config),
        vote(&leader, 2, &[b"x", b"y"], config),
    ];
    let tips = FinalTips::from_pool::<Sha256, MinSig, _>(&leader, indexed(&votes), config).unwrap();
    let proposals = ProposalPaths::new::<Sha256, MinSig>(&leader).unwrap();
    let path =
        VotePaths::new::<Sha256, MinSig>(&leader, leader.digest::<Sha256>(), &proposals, &votes[0])
            .unwrap();
    let expected = *path.chain(ChainId::new(0)).unwrap().last().unwrap();

    assert_eq!(tips.get(ChainId::new(0)), Some(expected));
    assert_eq!(tips.position(ChainId::new(0)), Some(Position::new(2)));
    assert_eq!(tips.settled(ChainId::new(0)), Some(false));
    assert_eq!(tips.blocks().len(), config.chains());
}

#[test]
fn pool_rejects_duplicate_participants() {
    let config = config(6);
    let leader = leader(6);
    let body = vote(&leader, 2, &[], config);
    let duplicate = (0..config.view_quorum()).map(|_| (Participant::new(0), &body));

    assert_eq!(
        FinalTips::from_pool::<Sha256, MinSig, _>(&leader, duplicate, config),
        Err(Error::Quorum)
    );
}

#[test]
fn incremental_pool_retains_the_first_vote_per_participant() {
    let config = config(6);
    let leader = leader(6);
    let first = vote(&leader, 2, &[b"first"], config);
    let second = vote(&leader, 1, &[b"second"], config);
    let mut pool = PoolExtractor::new::<Sha256, MinSig>(&leader, config).unwrap();

    assert!(
        pool.insert::<Sha256, MinSig>(&leader, Participant::new(0), &first)
            .unwrap()
    );
    assert!(
        !pool
            .insert::<Sha256, MinSig>(&leader, Participant::new(0), &second)
            .unwrap()
    );
    assert_eq!(pool.len(), 1);
}

#[test]
fn final_tip_index_excludes_subquorum_branches() {
    let config = config(6);
    let leader = leader(6);
    let proposals = ProposalPaths::new::<Sha256, MinSig>(&leader).unwrap();
    let mut pool = PoolExtractor::new::<Sha256, MinSig>(&leader, config).unwrap();

    for signer in 0..config.view_quorum() {
        let body = vote_with_digests(
            &leader,
            2,
            vec![
                digest(format!("branch-{signer}-1").as_bytes()),
                digest(format!("branch-{signer}-2").as_bytes()),
            ],
            config,
        );
        assert!(
            pool.insert::<Sha256, MinSig>(&leader, Participant::new(signer as u32), &body,)
                .unwrap()
        );
    }

    let proposal_entries = config.chains() * 3;
    assert_eq!(
        pool.retained_support_entries(),
        proposal_entries + config.view_quorum() * config.extension_bound()
    );
    assert_eq!(pool.final_tip_candidates(), proposal_entries);
    assert_eq!(
        pool.final_tips().unwrap().get(ChainId::new(0)),
        Some(proposals.block(ChainId::new(0), Position::new(2)).unwrap())
    );
}

fn signer_sample(rng: &mut TestRng, participants: usize, count: usize) -> Vec<Participant> {
    let mut signers = (0..participants)
        .map(|signer| Participant::new(signer as u32))
        .collect::<Vec<_>>();
    signers.shuffle(rng);
    signers.truncate(count);
    signers
}

struct ReferenceVqcMessages {
    messages: Vec<Participant>,
    designated_votes: Vec<Participant>,
}

impl ReferenceVqcMessages {
    fn new(
        messages: Vec<Participant>,
        designated_votes: Vec<Participant>,
        quorum: usize,
        designated_tally: usize,
    ) -> Self {
        let message_set = messages.iter().copied().collect::<BTreeSet<_>>();
        let designated_set = designated_votes.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(message_set.len(), quorum);
        assert_eq!(designated_set.len(), designated_tally);
        assert!(designated_set.is_subset(&message_set));
        Self {
            messages,
            designated_votes,
        }
    }

    fn message_set(&self) -> BTreeSet<Participant> {
        self.messages.iter().copied().collect()
    }

    fn designated_set(&self) -> BTreeSet<Participant> {
        self.designated_votes.iter().copied().collect()
    }

    fn non_designated_set(&self) -> BTreeSet<Participant> {
        self.message_set()
            .difference(&self.designated_set())
            .copied()
            .collect()
    }

    fn stance(&self, signer: Participant) -> Option<bool> {
        self.messages
            .contains(&signer)
            .then(|| self.designated_votes.contains(&signer))
    }
}

fn paired_vqc_messages(
    rng: &mut TestRng,
    participants: usize,
    quorum: usize,
    designated_tally: usize,
) -> [ReferenceVqcMessages; 2] {
    let first_messages = signer_sample(rng, participants, quorum);
    let first_set = first_messages.iter().copied().collect::<BTreeSet<_>>();
    let replacement = (0..participants)
        .map(|signer| Participant::new(signer as u32))
        .find(|signer| !first_set.contains(signer))
        .expect("a V-QC omits at least one participant");
    let replaced = first_messages[0];

    let mut shared = first_messages[1..].to_vec();
    shared.shuffle(rng);
    let shared_votes = shared[..designated_tally - 1].to_vec();
    let mut second_messages = first_messages.clone();
    second_messages[0] = replacement;
    let first_votes = std::iter::once(replaced)
        .chain(shared_votes.iter().copied())
        .collect();
    let second_votes = std::iter::once(replacement).chain(shared_votes).collect();

    [
        ReferenceVqcMessages::new(first_messages, first_votes, quorum, designated_tally),
        ReferenceVqcMessages::new(second_messages, second_votes, quorum, designated_tally),
    ]
}

struct CrossLeader {
    leader: LeaderBlock<MinSig, Digest>,
    parent_tips: Vec<BlockRef<Digest>>,
    certificate_history: Vec<BlockRef<Digest>>,
    certificate_chain: usize,
}

fn symbolic_threshold_certificate(marker: u64) -> ThresholdCertificate<MinSig> {
    let private = Private::new(Scalar::from_u64(marker + 1));
    ThresholdCertificate::new(sign_message::<MinSig>(
        &private,
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_ALGEBRA_TEST_CERTIFICATE",
        b"symbolic certificate",
    ))
}

fn cross_certificate_leader(
    participants: usize,
    certificate_chain: usize,
    divergent_certificate: bool,
) -> CrossLeader {
    let config = config(participants);
    let epoch = Epoch::new(7);
    let parent_tips = (0..participants)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain as u32),
                Height::zero(),
                digest(format!("parent-tip-{participants}-{chain}").as_bytes()),
            )
        })
        .collect::<Vec<_>>();
    let mut certificate_history = Vec::new();
    let proposals = parent_tips
        .iter()
        .enumerate()
        .map(|(chain, parent_tip)| {
            let chain_id = ChainId::new(chain as u32);
            let anchor = if chain == certificate_chain {
                let root = if divergent_certificate {
                    BlockRef::new(
                        chain_id,
                        Height::zero(),
                        digest(format!("certificate-root-{participants}-{chain}").as_bytes()),
                    )
                } else {
                    *parent_tip
                };
                let parent = TransactionBlockHeader::new(
                    epoch,
                    chain_id,
                    Height::new(1),
                    root.digest(),
                    digest(format!("certificate-parent-{participants}-{chain}").as_bytes()),
                )
                .unwrap()
                .block_ref::<Sha256>();
                let header = TransactionBlockHeader::new(
                    epoch,
                    chain_id,
                    Height::new(2),
                    parent.digest(),
                    digest(format!("certificate-anchor-{participants}-{chain}").as_bytes()),
                )
                .unwrap();
                let certificate = DaCertificate::new(
                    header,
                    symbolic_threshold_certificate((participants + chain) as u64),
                );
                certificate_history = vec![root, parent, certificate.block_ref::<Sha256>()];
                Anchor::Certificate(certificate)
            } else {
                Anchor::Tip(*parent_tip)
            };
            let payloads = (0..2)
                .map(|position| {
                    digest(format!("cross-proposal-{participants}-{chain}-{position}").as_bytes())
                })
                .collect();
            ChainProposal::new(chain_id, anchor, payloads, config.pipeline_depth()).unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        Round::new(epoch, View::new(1)),
        CertificateId::new(digest(b"cross-parent")),
        digest(b"cross-history"),
        proposals,
        config,
    )
    .unwrap();

    CrossLeader {
        leader,
        parent_tips,
        certificate_history,
        certificate_chain,
    }
}

#[derive(Clone, Copy)]
struct CrossPattern {
    settled_chain: usize,
    final_extension_chain: usize,
    rank_chain: usize,
    fork_chain: Option<usize>,
}

fn cross_pattern(participants: usize, certificate_chain: usize, forked: bool) -> CrossPattern {
    let regular = (0..participants)
        .filter(|chain| *chain != certificate_chain)
        .collect::<Vec<_>>();
    CrossPattern {
        settled_chain: regular[0],
        final_extension_chain: regular[1],
        rank_chain: regular[2],
        fork_chain: forked.then_some(certificate_chain),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independent axis of the cross-certificate vote matrix"
)]
fn cross_certificate_vote(
    leader: &LeaderBlock<MinSig, Digest>,
    signer: Participant,
    pool_slot: Option<usize>,
    branch: &BTreeSet<Participant>,
    high_rank: &BTreeSet<Participant>,
    alternate: bool,
    pattern: CrossPattern,
    config: CodecConfig,
) -> VoteBody<Digest> {
    let participants = config.participants();
    let faults = N5f1::max_faults(participants) as usize;
    let quorum = config.view_quorum();
    let mut positions = vec![Position::new(1); participants];
    let mut extensions = vec![Extension::empty(); participants];
    let shared = |chain: usize, side: &str| {
        digest(format!("cross-{participants}-{chain}-{side}").as_bytes())
    };

    if pool_slot.is_some_and(|slot| slot < 3 * faults + 1) {
        positions[pattern.settled_chain] = Position::new(2);
    }

    positions[pattern.final_extension_chain] = Position::new(2);
    if pool_slot.is_some_and(|slot| slot < quorum) {
        extensions[pattern.final_extension_chain] =
            Extension::new(vec![shared(pattern.final_extension_chain, "final")], 2).unwrap();
    }

    if let Some(chain) = pattern.fork_chain {
        positions[chain] = Position::new(2);
        extensions[chain] = Extension::new(
            vec![shared(
                chain,
                if branch.contains(&signer) { "a" } else { "b" },
            )],
            2,
        )
        .unwrap();
    }

    positions[pattern.rank_chain] = Position::new(if alternate {
        0
    } else if high_rank.contains(&signer) {
        2
    } else {
        1
    });

    VoteBody::for_leader::<Sha256, MinSig>(leader, positions, extensions, config).unwrap()
}

fn assert_correct_voter_uniqueness(
    participants: usize,
    pool: &BTreeSet<Participant>,
    first: &ReferenceVqcMessages,
    second: &ReferenceVqcMessages,
    faulty: &BTreeSet<Participant>,
) {
    for signer in (0..participants).map(|signer| Participant::new(signer as u32)) {
        if faulty.contains(&signer) {
            continue;
        }
        let first_stance = first.stance(signer);
        let second_stance = second.stance(signer);
        if pool.contains(&signer) {
            assert_ne!(first_stance, Some(false));
            assert_ne!(second_stance, Some(false));
        }
        if let (Some(first_stance), Some(second_stance)) = (first_stance, second_stance) {
            assert_eq!(first_stance, second_stance);
        }
    }
}

#[test]
fn cross_certificate_safe_and_final_tips_match_reference() {
    let mut rng = TestRng::new(0x5afe_e17e);

    for participants in [6, 7, 11, 12] {
        let config = config(participants);
        let faults = N5f1::max_faults(participants) as usize;
        let quorum = config.view_quorum();
        let designation = config.designation_quorum();
        let mut covered_tallies = BTreeSet::new();

        for designated_tally in designation..=quorum {
            let messages = paired_vqc_messages(&mut rng, participants, quorum, designated_tally);
            let fixture = cross_certificate_leader(participants, participants - 1, false);
            let pattern = cross_pattern(participants, fixture.certificate_chain, false);
            let branch = BTreeSet::new();
            let high_rank = BTreeSet::new();
            let votes = messages.map(|messages| {
                messages
                    .designated_votes
                    .iter()
                    .map(|signer| {
                        (
                            *signer,
                            cross_certificate_vote(
                                &fixture.leader,
                                *signer,
                                None,
                                &branch,
                                &high_rank,
                                false,
                                pattern,
                                config,
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            });
            let mut reference = ReferenceOrdering::new(&fixture.leader, &fixture.parent_tips);
            reference.insert_path(&fixture.certificate_history);
            for tally in &votes {
                let reference_votes = reference.materialize(&fixture.leader, tally);
                let expected = reference.safe(&reference_votes, config);
                let actual = Tips::from_votes::<Sha256, MinSig, _>(
                    &fixture.leader,
                    attributed(tally),
                    config,
                )
                .unwrap();
                assert_eq!(actual.blocks(), expected);
            }
            covered_tallies.insert(designated_tally);
        }

        for pool_size in quorum..=participants {
            for actual_faults in 0..=faults {
                for designated_tally in designation..=quorum {
                    let [first_messages, second_messages] =
                        paired_vqc_messages(&mut rng, participants, quorum, designated_tally);
                    let non_designated = first_messages
                        .non_designated_set()
                        .union(&second_messages.non_designated_set())
                        .copied()
                        .collect::<BTreeSet<_>>();
                    let mut preferred_faults = non_designated.iter().copied().collect::<Vec<_>>();
                    preferred_faults.shuffle(&mut rng);
                    let mut remaining_faults = (0..participants)
                        .map(|signer| Participant::new(signer as u32))
                        .filter(|signer| !non_designated.contains(signer))
                        .collect::<Vec<_>>();
                    remaining_faults.shuffle(&mut rng);
                    let faulty = preferred_faults
                        .into_iter()
                        .chain(remaining_faults)
                        .take(actual_faults)
                        .collect::<BTreeSet<_>>();
                    let allowed_pool = (0..participants)
                        .map(|signer| Participant::new(signer as u32))
                        .filter(|signer| {
                            faulty.contains(signer) || !non_designated.contains(signer)
                        })
                        .collect::<BTreeSet<_>>();
                    if allowed_pool.len() < pool_size {
                        continue;
                    }

                    let first_designated = first_messages.designated_set();
                    let second_designated = second_messages.designated_set();
                    let mut shared_designated = first_designated
                        .intersection(&second_designated)
                        .copied()
                        .collect::<Vec<_>>();
                    shared_designated.shuffle(&mut rng);
                    let mut branch = if shared_designated.len() >= designation {
                        shared_designated[..designation]
                            .iter()
                            .copied()
                            .collect::<BTreeSet<_>>()
                    } else {
                        let mut branch = shared_designated.iter().copied().collect::<BTreeSet<_>>();
                        branch.extend(first_designated.difference(&second_designated).copied());
                        branch.extend(second_designated.difference(&first_designated).copied());
                        branch
                    };
                    let branch_tally = 3 * faults + 1;
                    let mut branch_fill = allowed_pool
                        .difference(&branch)
                        .copied()
                        .collect::<Vec<_>>();
                    branch_fill.shuffle(&mut rng);
                    branch.extend(branch_fill.into_iter().take(branch_tally - branch.len()));
                    assert_eq!(branch.len(), branch_tally);
                    assert!(branch.is_subset(&allowed_pool));
                    assert!(first_designated.intersection(&branch).count() >= designation);
                    assert!(second_designated.intersection(&branch).count() >= designation);

                    let mut pool_signers = branch.iter().copied().collect::<Vec<_>>();
                    let mut pool_fill = allowed_pool
                        .difference(&branch)
                        .copied()
                        .collect::<Vec<_>>();
                    pool_fill.shuffle(&mut rng);
                    pool_signers.extend(pool_fill.into_iter().take(pool_size - branch.len()));
                    pool_signers.shuffle(&mut rng);
                    let pool_set = pool_signers.iter().copied().collect::<BTreeSet<_>>();
                    assert_correct_voter_uniqueness(
                        participants,
                        &pool_set,
                        &first_messages,
                        &second_messages,
                        &faulty,
                    );

                    let high_rank = first_messages
                        .designated_votes
                        .iter()
                        .filter(|signer| !faulty.contains(signer))
                        .take(faults + 1)
                        .copied()
                        .collect::<BTreeSet<_>>();
                    assert_eq!(high_rank.len(), faults + 1);
                    let certificate_chain = faulty
                        .iter()
                        .next()
                        .map_or(participants - 1, |signer| signer.get() as usize);
                    let fixture = cross_certificate_leader(
                        participants,
                        certificate_chain,
                        actual_faults > 0,
                    );
                    let leader = &fixture.leader;
                    let pattern =
                        cross_pattern(participants, fixture.certificate_chain, actual_faults > 0);
                    let pool_slots = pool_signers
                        .iter()
                        .enumerate()
                        .map(|(slot, signer)| (*signer, slot))
                        .collect::<BTreeMap<_, _>>();
                    let canonical = (0..participants)
                        .map(|index| {
                            let signer = Participant::new(index as u32);
                            let vote = cross_certificate_vote(
                                leader,
                                signer,
                                pool_slots.get(&signer).copied(),
                                &branch,
                                &high_rank,
                                false,
                                pattern,
                                config,
                            );
                            (signer, vote)
                        })
                        .collect::<Vec<_>>();
                    let pool = pool_signers
                        .iter()
                        .map(|signer| (*signer, canonical[signer.get() as usize].1.clone()))
                        .collect::<Vec<_>>();
                    let notarization = |signers: &[Participant]| {
                        signers
                            .iter()
                            .map(|signer| {
                                let vote = if faulty.contains(signer) {
                                    cross_certificate_vote(
                                        leader,
                                        *signer,
                                        pool_slots.get(signer).copied(),
                                        &branch,
                                        &high_rank,
                                        true,
                                        pattern,
                                        config,
                                    )
                                } else {
                                    canonical[signer.get() as usize].1.clone()
                                };
                                (*signer, vote)
                            })
                            .collect::<Vec<_>>()
                    };
                    let first = notarization(&first_messages.designated_votes);
                    let second = notarization(&second_messages.designated_votes);

                    let mut correct_votes = BTreeMap::<Participant, &VoteBody<Digest>>::new();
                    for (signer, vote) in pool.iter().chain(&first).chain(&second) {
                        if faulty.contains(signer) {
                            continue;
                        }
                        if let Some(previous) = correct_votes.insert(*signer, vote) {
                            assert_eq!(previous, vote);
                        }
                    }

                    let mut reference = ReferenceOrdering::new(leader, &fixture.parent_tips);
                    reference.insert_path(&fixture.certificate_history);
                    let reference_pool = reference.materialize(leader, &pool);
                    let reference_first = reference.materialize(leader, &first);
                    let reference_second = reference.materialize(leader, &second);
                    let expected_final = reference.final_tips(&reference_pool, config);
                    let expected_first = reference.safe(&reference_first, config);
                    let expected_second = reference.safe(&reference_second, config);
                    let final_tips = FinalTips::from_pool::<Sha256, MinSig, _>(
                        leader,
                        attributed(&pool),
                        config,
                    )
                    .unwrap();
                    let first_tips =
                        Tips::from_votes::<Sha256, MinSig, _>(leader, attributed(&first), config)
                            .unwrap();
                    let second_tips =
                        Tips::from_votes::<Sha256, MinSig, _>(leader, attributed(&second), config)
                            .unwrap();

                    assert_eq!(final_tips.blocks(), expected_final.blocks);
                    assert_eq!(first_tips.blocks(), expected_first);
                    assert_eq!(second_tips.blocks(), expected_second);
                    for chain in 0..participants {
                        let chain_id = ChainId::new(chain as u32);
                        assert_eq!(
                            final_tips.position(chain_id),
                            Some(expected_final.positions[chain])
                        );
                        assert_eq!(
                            final_tips.settled(chain_id),
                            Some(expected_final.settled[chain])
                        );
                        for safe in [&expected_first, &expected_second] {
                            assert!(reference.extends(expected_final.blocks[chain], safe[chain]));
                            if expected_final.settled[chain] {
                                assert_eq!(safe[chain], expected_final.blocks[chain]);
                            }
                        }
                    }

                    assert_eq!(
                        reference_pool
                            .iter()
                            .filter(|vote| {
                                vote.positions[pattern.settled_chain] == Position::new(2)
                            })
                            .count(),
                        3 * faults + 1
                    );
                    assert_eq!(
                        expected_final.positions[pattern.settled_chain],
                        Position::new(2)
                    );
                    assert!(expected_final.settled[pattern.settled_chain]);
                    assert_eq!(
                        reference_first
                            .iter()
                            .filter(|vote| vote.positions[pattern.rank_chain] == Position::new(2))
                            .count(),
                        faults + 1
                    );

                    let forked_producers = reference.forked_producers();
                    assert!(forked_producers.is_subset(&faulty));
                    if let Some(fork_chain) = pattern.fork_chain {
                        assert_eq!(
                            forked_producers,
                            BTreeSet::from([Participant::new(fork_chain as u32)])
                        );
                        let member = *reference_pool
                            .iter()
                            .find(|vote| branch.contains(&vote.signer))
                            .unwrap()
                            .paths[fork_chain]
                            .last()
                            .unwrap();
                        assert_eq!(
                            reference_pool
                                .iter()
                                .filter(|vote| vote.paths[fork_chain].contains(&member))
                                .count(),
                            branch_tally
                        );
                        let branch_support = reference_pool
                            .iter()
                            .map(|vote| *vote.paths[fork_chain].last().unwrap())
                            .fold(BTreeMap::<_, usize>::new(), |mut counts, block| {
                                *counts.entry(block).or_default() += 1;
                                counts
                            });
                        assert_eq!(
                            branch_support
                                .values()
                                .filter(|count| **count >= designation)
                                .count(),
                            1 + usize::from(pool_size >= 5 * faults + 2)
                        );
                        let incompatible = reference_pool
                            .iter()
                            .flat_map(|vote| vote.paths[fork_chain].iter().copied())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .filter(|candidate| {
                                !reference.extends(member, *candidate)
                                    && !reference.extends(*candidate, member)
                            })
                            .collect::<Vec<_>>();
                        assert!(!incompatible.is_empty());
                        for candidate in incompatible {
                            let correct_support = reference_pool
                                .iter()
                                .filter(|vote| {
                                    !faulty.contains(&vote.signer)
                                        && vote.paths[fork_chain].contains(&candidate)
                                })
                                .count();
                            assert!(correct_support + actual_faults < config.da_quorum());
                        }
                    } else {
                        assert!(forked_producers.is_empty());
                    }

                    assert_eq!(pool_set.len(), pool_size);
                    assert_eq!(first_messages.messages.len(), quorum);
                    assert_eq!(second_messages.messages.len(), quorum);
                    assert_eq!(first_messages.designated_votes.len(), designated_tally);
                    assert_eq!(second_messages.designated_votes.len(), designated_tally);
                    assert_ne!(first_messages.message_set(), second_messages.message_set());
                    covered_tallies.insert(designated_tally);
                }
            }
        }
        assert_eq!(
            covered_tallies,
            (designation..=quorum).collect::<BTreeSet<_>>()
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn safe_tips_match_materialized_reference(
        descriptions in prop_vec((0u32..=2, prop_vec(any::<u8>(), 0..=2)), 3..=5),
    ) {
        let config = config(6);
        let leader = leader(6);
        let votes = descriptions
            .into_iter()
            .map(|(position, extension)| {
                let extension = application_digests(&leader, position, extension);
                vote_with_digests(&leader, position, extension, config)
            })
            .collect::<Vec<_>>();
        let production = Tips::from_votes::<Sha256, MinSig, _>(
            &leader,
            indexed(&votes),
            config,
        )
        .unwrap();

        prop_assert_eq!(production.blocks(), reference_safe(&leader, &votes, config));
    }

    #[test]
    fn final_tips_match_materialized_reference(
        descriptions in prop_vec((0u32..=2, prop_vec(any::<u8>(), 0..=2)), 5..=6),
    ) {
        let config = config(6);
        let leader = leader(6);
        let votes = descriptions
            .into_iter()
            .map(|(position, extension)| {
                let extension = application_digests(&leader, position, extension);
                vote_with_digests(&leader, position, extension, config)
            })
            .collect::<Vec<_>>();
        let production = FinalTips::from_pool::<Sha256, MinSig, _>(
            &leader,
            indexed(&votes),
            config,
        )
        .unwrap();
        let (blocks, positions, settled) = reference_final(&leader, &votes, config);
        let mut incremental = PoolExtractor::new::<Sha256, MinSig>(&leader, config).unwrap();
        for (index, vote) in votes.iter().enumerate() {
            incremental
                .insert::<Sha256, MinSig>(&leader, Participant::new(index as u32), vote)
                .unwrap();
            if index + 1 >= config.view_quorum() {
                let expected = FinalTips::from_pool::<Sha256, MinSig, _>(
                    &leader,
                    indexed(&votes[..=index]),
                    config,
                )
                .unwrap();
                prop_assert_eq!(incremental.final_tips().unwrap(), expected);
            }
        }

        prop_assert_eq!(production.blocks(), blocks);
        for index in 0..config.chains() {
            let chain = ChainId::new(index as u32);
            prop_assert_eq!(production.position(chain), Some(positions[index]));
            prop_assert_eq!(production.settled(chain), Some(settled[index]));
        }
    }

}
