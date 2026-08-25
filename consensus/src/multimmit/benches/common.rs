use bytes::BytesMut;
use commonware_codec::{Read, Write};
use commonware_consensus::{
    multimmit::{
        config::{CodecConfig, Config, Limits},
        mocks,
        scheme::bls12381_threshold::{Roster, Scheme},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, EpochGenesis, Extension,
            Height, LeaderBlock, Lqc, Nullify, Position, SignedTransactionBlock, TipRecord,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc, genesis_history,
        },
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar, Share},
        ops,
        sharing::{Mode, ModeVersion, Sharing},
        variant::Variant,
    },
    ed25519,
    sha256::Digest,
};
use commonware_math::poly::Poly;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, Participant, TestRng, ordered::Set};
use core::num::NonZeroU32;

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
        let epoch_config = test_config();
        let codec = epoch_config.codec_config();
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| ed25519::PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let mut rng = TestRng::new(1_234);
        let mut ordinary = Vec::with_capacity(PARTICIPANTS as usize);
        let participants = identities
            .iter()
            .map(|identity| {
                let (private, public) = ops::keypair::<_, V>(&mut rng);
                let proof = Roster::<ed25519::PublicKey, V>::proof_of_possession(
                    epoch_config.namespace(),
                    &private,
                );
                ordinary.push(private);
                (identity.clone(), public, proof)
            })
            .collect();
        let roster = Roster::verify(
            epoch_config.namespace(),
            codec.participants(),
            participants,
            &Sequential,
        )
        .unwrap();
        let (da, da_shares) = sharing::<V>(&mut rng, u32::try_from(codec.da_quorum()).unwrap());
        let (nullification, nullification_shares) = sharing::<V>(
            &mut rng,
            u32::try_from(codec.nullification_quorum()).unwrap(),
        );

        let signers = ordinary
            .into_iter()
            .zip(da_shares)
            .zip(nullification_shares)
            .map(|((ordinary, da_share), nullification_share)| {
                Scheme::signer(
                    &epoch_config,
                    roster.clone(),
                    ordinary,
                    da.clone(),
                    da_share,
                    nullification.clone(),
                    nullification_share,
                )
                .unwrap()
            })
            .collect();
        let verifier = Scheme::verifier(&epoch_config, roster, da, nullification).unwrap();
        let tips = epoch_config.genesis().tips().to_vec();
        let parent_history = TipRecord::new(
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

    fn leader(&self) -> LeaderBlock<V, Digest> {
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

    fn vote_body(&self, leader: &LeaderBlock<V, Digest>, signer: usize) -> VoteBody<Digest> {
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

    fn votes(&self, leader: &LeaderBlock<V, Digest>) -> Vec<Vote<V, Digest>> {
        self.signers
            .iter()
            .take(self.codec.view_quorum())
            .enumerate()
            .map(|(index, signer)| mocks::sign_vote(signer, self.vote_body(leader, index)).unwrap())
            .collect()
    }

    fn view_messages(&self, leader: &LeaderBlock<V, Digest>) -> Vec<ViewMessage<V, Digest>> {
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

fn sharing<V: Variant>(rng: &mut TestRng, required: u32) -> (Sharing<V>, Vec<Share>) {
    let private = Poly::<Scalar>::new(rng, required - 1);
    let shares = (0..PARTICIPANTS)
        .map(|index| {
            let point = Scalar::from_u64(u64::from(index) + 1);
            Share::new(Participant::new(index), Private::new(private.eval(&point)))
        })
        .collect();
    let public = Poly::<V::Public>::commit(private);
    let mut encoded = BytesMut::new();
    Mode::NonZeroCounter.write(&mut encoded);
    PARTICIPANTS.write(&mut encoded);
    public.write(&mut encoded);
    let mut encoded = encoded.freeze();
    let total = NonZeroU32::new(PARTICIPANTS).unwrap();
    let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0())).unwrap();
    (sharing, shares)
}

fn digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn test_config() -> Config<Digest> {
    let epoch = Epoch::new(9);
    let limits = Limits::new(2, 2).unwrap();
    let tips = (0..PARTICIPANTS)
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
        PARTICIPANTS as usize,
        (0..PARTICIPANTS).map(Participant::new).collect(),
        limits,
        genesis,
    )
    .unwrap()
}
