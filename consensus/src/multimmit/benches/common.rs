//! Shared committee fixture and strategy registration for the signature benchmarks.

use commonware_consensus::{
    Epochable as _,
    multimmit::{
        mocks,
        scheme::bls12381_threshold::Scheme,
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, CodecConfig, DigestedLeader,
            Extension, LeaderBlock, Lqc, Nullify, PathLimits, Position, SignedTransactionBlock,
            TipRecord, TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc, genesis_history,
        },
    },
    types::{Height, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256, bls12381::primitives::variant::Variant, ed25519, sha256::Digest,
};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::NZUsize;
use criterion::Criterion;

pub const PARTICIPANTS: u32 = 31;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CRYPTO_BENCH";
/// The committee seed, which also labels its epoch.
const EPOCH: u64 = 9;

pub type MultimmitScheme<V> = Scheme<ed25519::PublicKey, V>;

pub struct Fixture<V: Variant> {
    pub codec: CodecConfig,
    pub round: Round,
    pub signers: Vec<MultimmitScheme<V>>,
    pub verifier: MultimmitScheme<V>,
    parent_history: TipRecord<Digest>,
    tips: Vec<BlockRef<Digest>>,
}

impl<V: Variant> Fixture<V> {
    pub fn new() -> Self {
        Self::new_sized(PARTICIPANTS)
    }

    /// Builds one committee of `participants` validators, each producing one chain.
    pub fn new_sized(participants_count: u32) -> Self {
        let committee = mocks::Committee::<V>::builder(EPOCH, participants_count)
            .namespace(NAMESPACE)
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let epoch_config = committee.config;
        let tips = epoch_config.genesis().tips().to_vec();
        let parent_history = TipRecord::at_tips(
            genesis_history::<Sha256>(epoch_config.genesis()),
            tips.clone(),
        )
        .unwrap();

        Self {
            codec: epoch_config.codec_config(),
            round: Round::new(epoch_config.epoch(), View::new(7)),
            signers: committee.signers,
            verifier: committee.verifier,
            parent_history,
            tips,
        }
    }

    pub fn header(&self, chain: u32, marker: u64) -> TransactionBlockHeader<Digest> {
        TransactionBlockHeader::new(
            self.round.epoch(),
            ChainId::new(chain),
            Height::new(1),
            digest(b"parent", marker),
            digest(b"commitment", marker),
        )
        .unwrap()
    }

    pub fn ordinary_blocks(&self) -> Vec<SignedTransactionBlock<V, Digest>> {
        self.signers
            .iter()
            .enumerate()
            .map(|(index, signer)| {
                signer
                    .sign_transaction_block(self.header(index as u32, index as u64))
                    .unwrap()
            })
            .collect()
    }

    pub fn nullifies(&self) -> Vec<Nullify<V>> {
        self.signers
            .iter()
            .map(|signer| signer.sign_nullify(self.round).unwrap())
            .collect()
    }

    pub fn certificates(&self) -> (Vqc<V, Digest>, Lqc<V, Digest>) {
        let leader = self.leader();
        let vqc = self
            .verifier
            .assemble_vqc::<Sha256, _>(leader.clone(), &self.view_messages(&leader), &Sequential)
            .unwrap();
        let lqc = self
            .verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &self.votes(&leader), &Sequential)
            .unwrap();
        (vqc, lqc)
    }

    pub fn leader(&self) -> LeaderBlock<V, Digest> {
        let proposals = self
            .tips
            .iter()
            .enumerate()
            .map(|(index, tip)| {
                ChainProposal::new(
                    ChainId::new(index as u32),
                    Anchor::Tip(*tip),
                    vec![digest(b"proposal", index as u64)],
                    self.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            self.round,
            CertificateId::new(digest(b"parent vqc", 1)),
            self.parent_history.commitment::<Sha256>(),
            proposals,
            self.codec,
        )
        .unwrap()
    }

    pub fn vote_body(&self, leader: &LeaderBlock<V, Digest>, signer: usize) -> VoteBody<Digest> {
        let mut positions = vec![Position::new(1); self.codec.participants()];
        positions[signer] = Position::new(0);
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(leader),
            positions,
            vec![Extension::empty(); self.codec.participants()],
            self.codec,
        )
        .unwrap()
    }

    pub fn votes(&self, leader: &LeaderBlock<V, Digest>) -> Vec<Vote<V, Digest>> {
        self.signers
            .iter()
            .take(self.codec.view_quorum())
            .enumerate()
            .map(|(index, signer)| signer.sign_vote(self.vote_body(leader, index)).unwrap())
            .collect()
    }

    pub fn view_messages(&self, leader: &LeaderBlock<V, Digest>) -> Vec<ViewMessage<V, Digest>> {
        let designation = self.codec.designation_quorum();
        self.signers
            .iter()
            .take(self.codec.view_quorum())
            .enumerate()
            .map(|(index, signer)| {
                if index < designation {
                    return ViewMessage::Vote(
                        signer.sign_vote(self.vote_body(leader, index)).unwrap(),
                    );
                }

                signer
                    .sign_novote(self.round)
                    .map(ViewMessage::NoVote)
                    .unwrap()
            })
            .collect()
    }
}

pub fn rayon() -> Rayon {
    Rayon::new(NZUsize!(8)).unwrap()
}

/// A measured operation that runs under any execution strategy.
pub trait Workload {
    /// Runs the operation once under `strategy`, passing its result through [`std::hint::black_box`].
    fn run<S: Strategy>(&mut self, strategy: &S);
}

/// Registers the workload `new` builds once per execution strategy, sequential then rayon.
///
/// Each benchmark gets a fresh workload and is labeled `label` followed by `strategy=<name>`.
pub fn bench_strategies<W: Workload>(c: &mut Criterion, label: &str, mut new: impl FnMut() -> W) {
    measure(
        c,
        &format!("{label} strategy=sequential"),
        new(),
        &Sequential,
    );
    measure(c, &format!("{label} strategy=rayon"), new(), &rayon());
}

fn measure<W: Workload, S: Strategy>(
    c: &mut Criterion,
    label: &str,
    mut workload: W,
    strategy: &S,
) {
    c.bench_function(label, |b| b.iter(|| workload.run(strategy)));
}

fn digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}
