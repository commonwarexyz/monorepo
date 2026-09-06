use commonware_consensus::{
    multimmit::{
        config::{CodecConfig, Config, Limits},
        mocks,
        scheme::bls12381_threshold::Scheme,
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, EpochGenesis, Extension,
            Height, LeaderBlock, Lqc, Nullify, Position, SignedTransactionBlock, TipRecord,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc, genesis_history,
        },
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256, Signer, bls12381::primitives::variant::Variant, ed25519, sha256::Digest,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, Participant, TestRng, ordered::Set};

pub const PARTICIPANTS: u32 = 31;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CRYPTO_BENCH";

type MultimmitScheme<V> = Scheme<ed25519::PublicKey, V>;

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
        let epoch_config = test_config(participants_count);
        let codec = epoch_config.codec_config();
        let identities = Set::try_from(
            (0..participants_count)
                .map(|index| ed25519::PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let mut rng = TestRng::new(1_234);
        let (signers, verifier) = mocks::schemes(&mut rng, &epoch_config, &identities);
        let tips = epoch_config.genesis().tips().to_vec();
        let parent_history = TipRecord::at_tips(
            genesis_history::<Sha256>(epoch_config.genesis()),
            tips.clone(),
        )
        .unwrap();

        Self {
            codec,
            round: Round::new(epoch_config.epoch(), View::new(7)),
            signers,
            verifier,
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
                mocks::sign_transaction_block(signer, self.header(index as u32, index as u64))
                    .unwrap()
            })
            .collect()
    }

    pub fn nullifies(&self) -> Vec<Nullify<V>> {
        self.signers
            .iter()
            .map(|signer| mocks::sign_nullify(signer, self.round).unwrap())
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
        VoteBody::for_leader::<Sha256, V>(
            leader,
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
            .map(|(index, signer)| mocks::sign_vote(signer, self.vote_body(leader, index)).unwrap())
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
                        mocks::sign_vote(signer, self.vote_body(leader, index)).unwrap(),
                    );
                }

                mocks::sign_novote(signer, self.round)
                    .map(ViewMessage::NoVote)
                    .unwrap()
            })
            .collect()
    }
}

pub fn rayon() -> Rayon {
    Rayon::new(NZUsize!(8)).unwrap()
}

fn digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn test_config(participants: u32) -> Config<Digest> {
    let epoch = Epoch::new(9);
    let limits = Limits::new(2, 2).unwrap();
    let tips = (0..participants)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain),
                Height::zero(),
                digest(b"genesis", u64::from(chain)),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        digest(b"leader genesis", 9),
        CertificateId::new(digest(b"vqc genesis", 9)),
        CertificateId::new(digest(b"lqc genesis", 9)),
        tips,
    )
    .unwrap();
    Config::new(
        epoch,
        NAMESPACE,
        participants as usize,
        (0..participants).map(Participant::new).collect(),
        limits,
        genesis,
    )
    .unwrap()
}
