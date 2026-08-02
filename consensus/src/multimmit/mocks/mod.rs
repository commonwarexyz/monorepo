//! Deterministic Multimmit test fixtures.
//!
//! These helpers construct one complete epoch committee with real BLS12-381 key material so
//! attached-actor and integration tests can exercise production cryptography end to end. They are
//! test support only and make no attempt to protect key material.

#[cfg(not(target_arch = "wasm32"))]
mod attached;
#[cfg(not(target_arch = "wasm32"))]
pub mod cluster;

use crate::{
    multimmit::{
        config::{CodecConfig, Config, LeaderSchedule, Limits},
        machine::algebra::VqcExtraction,
        scheme::bls12381_threshold::{Error as SchemeError, Roster, Scheme},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, DaVote, EpochGenesis,
            Extension, Height, LeaderBlock, Lqc, NoVote, Nullification, Nullify, Position,
            SignedLeaderBlock, SignedTransactionBlock, TipRecord, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Epoch, Round, View},
};
#[cfg(not(target_arch = "wasm32"))]
pub use attached::{
    MockApplication, MockApplicationLog, MockBuildGate, NoopBlocker, NoopReporter, RecordingBlocker,
};
#[cfg(all(test, not(target_arch = "wasm32")))]
pub use attached::{RecordingRelay, RecordingReporter};
use bytes::BytesMut;
use commonware_codec::{Read as _, Write as _};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar, Share},
        ops,
        sharing::{Mode, ModeVersion, Sharing},
        variant::Variant,
    },
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_math::poly::Poly;
use commonware_parallel::Sequential;
use commonware_utils::{Participant, TestRng, ordered::Set};
use core::num::NonZeroU32;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MOCKS";

/// One complete epoch committee with real cryptographic material.
pub struct Committee<V: Variant> {
    /// The validated immutable epoch configuration.
    pub config: Config<Sha256Digest>,
    /// Authenticated network identities in participant order.
    pub identities: Vec<ed25519::PublicKey>,
    /// Network private keys in participant order.
    pub network_keys: Vec<ed25519::PrivateKey>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<ed25519::PublicKey, V>>,
    /// A keyless verification scheme for observers.
    pub verifier: Scheme<ed25519::PublicKey, V>,
}

impl<V: Variant> Committee<V> {
    /// Builds a committee of `participants` with deterministic keys derived from `seed`.
    pub fn new(seed: u64, participants: u32, limits: Limits) -> Self {
        Self::new_with_namespace(seed, NAMESPACE, participants, limits)
    }

    /// Builds a committee for `namespace` with deterministic keys derived from `seed`.
    pub fn new_with_namespace(
        seed: u64,
        namespace: &[u8],
        participants: u32,
        limits: Limits,
    ) -> Self {
        Self::new_with_namespace_and_producers(
            seed,
            namespace,
            participants,
            (0..participants).map(Participant::new).collect(),
            limits,
        )
    }

    /// Builds a committee with producers assigned in chain-index order.
    pub fn new_with_namespace_and_producers(
        seed: u64,
        namespace: &[u8],
        participants: u32,
        producers: Vec<Participant>,
        limits: Limits,
    ) -> Self {
        let epoch = Epoch::new(seed);
        let chains = u32::try_from(producers.len()).expect("producer count is representable");
        let tips = (0..chains)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    digest(b"mock genesis", seed + u64::from(chain)),
                )
            })
            .collect();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"mock leader genesis", seed),
            CertificateId::new(digest(b"mock vqc genesis", seed)),
            CertificateId::new(digest(b"mock lqc genesis", seed)),
            tips,
        )
        .expect("mock genesis is valid");
        let config = Config::new(
            epoch,
            namespace,
            participants as usize,
            producers,
            limits,
            genesis,
        )
        .expect("mock configuration is valid");
        let codec = config.codec_config();

        let mut network_keys = (0..participants)
            .map(|index| ed25519::PrivateKey::from_seed(seed ^ (u64::from(index) + 1)))
            .collect::<Vec<_>>();
        network_keys.sort_by_key(|key| key.public_key());
        let identities = network_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>();
        let identity_set = Set::try_from(identities.clone()).expect("identities are unique");

        let mut rng = TestRng::new(seed);
        let mut ordinary = Vec::with_capacity(participants as usize);
        let roster_input = identity_set
            .iter()
            .map(|identity| {
                let (private, public) = ops::keypair::<_, V>(&mut rng);
                let proof = Roster::<ed25519::PublicKey, V>::proof_of_possession(
                    config.namespace(),
                    &private,
                );
                ordinary.push(private);
                (identity.clone(), public, proof)
            })
            .collect();
        let roster = Roster::verify(
            config.namespace(),
            codec.participants(),
            roster_input,
            &Sequential,
        )
        .expect("mock roster is valid");
        let (da, da_shares) = sharing::<V>(
            &mut rng,
            participants,
            u32::try_from(codec.da_quorum()).expect("quorum fits u32"),
        );
        let (nullification, nullification_shares) = sharing::<V>(
            &mut rng,
            participants,
            u32::try_from(codec.nullification_quorum()).expect("quorum fits u32"),
        );

        let signers = ordinary
            .into_iter()
            .zip(da_shares)
            .zip(nullification_shares)
            .map(|((ordinary, da_share), nullification_share)| {
                Scheme::signer(
                    &config,
                    roster.clone(),
                    ordinary,
                    da.clone(),
                    da_share,
                    nullification.clone(),
                    nullification_share,
                )
                .expect("mock signer material is consistent")
            })
            .collect();
        let verifier = Scheme::verifier(&config, roster, da, nullification)
            .expect("mock verifier material is consistent");

        Self {
            config,
            identities,
            network_keys,
            signers,
            verifier,
        }
    }

    /// Returns this committee with an explicit leader schedule.
    ///
    /// Schemes are rebuilt so the leader each scheme signs and verifies matches the machine's.
    pub fn with_leaders(self, leaders: LeaderSchedule) -> Self {
        let config = self
            .config
            .with_leaders(leaders)
            .expect("schedule matches the committee");
        let signers = self
            .signers
            .into_iter()
            .map(|scheme| scheme.with_leaders(&config))
            .collect();
        let verifier = self.verifier.with_leaders(&config);
        Self {
            config,
            signers,
            verifier,
            ..self
        }
    }

    /// Returns the bounded codec configuration for the epoch.
    pub const fn codec(&self) -> CodecConfig {
        self.config.codec_config()
    }

    /// Returns a height-one transaction-block header for `chain`.
    pub fn transaction_header(
        &self,
        chain: u32,
        commitment: Sha256Digest,
    ) -> TransactionBlockHeader<Sha256Digest> {
        let parent = self.config.genesis().tips()[chain as usize];
        TransactionBlockHeader::new(
            self.config.epoch(),
            ChainId::new(chain),
            Height::new(1),
            parent.digest(),
            commitment,
        )
        .expect("height one is a live header")
    }

    /// Returns a producer-signed height-one transaction block for `chain`.
    pub fn signed_block(
        &self,
        chain: u32,
        commitment: Sha256Digest,
    ) -> SignedTransactionBlock<V, Sha256Digest> {
        let producer = self
            .config
            .producer(ChainId::new(chain))
            .expect("producer chain is configured");
        self.signers[producer.get() as usize]
            .sign_transaction_block(self.transaction_header(chain, commitment))
            .expect("producer owns its chain")
    }

    /// Returns `signer`'s data-availability share for `header`.
    pub fn da_vote(
        &self,
        signer: usize,
        header: TransactionBlockHeader<Sha256Digest>,
    ) -> DaVote<V, Sha256Digest> {
        self.signers[signer]
            .sign_da_vote(header)
            .expect("signer holds a DA share")
    }

    /// Returns `signer`'s abstention for `view`.
    pub fn novote(&self, signer: usize, view: u64) -> NoVote<V> {
        self.signers[signer]
            .sign_novote(Round::new(self.config.epoch(), View::new(view)))
            .expect("signer holds an ordinary key")
    }

    /// Returns `signer`'s nullification share for `view`.
    pub fn nullify(&self, signer: usize, view: u64) -> Nullify<V> {
        self.signers[signer]
            .sign_nullify(Round::new(self.config.epoch(), View::new(view)))
            .expect("signer holds a nullification share")
    }

    /// Recovers a complete nullification for `view` from the first `2f+1` signers.
    pub fn nullification(&self, view: u64) -> Nullification<V> {
        let shares = (0..self.codec().nullification_quorum())
            .map(|signer| self.nullify(signer, view))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_nullification(&shares, &Sequential)
            .expect("quorum of valid shares recovers")
    }

    /// Returns the scheduled leader's signed empty proposal for `view` above `parent`.
    pub fn leader_block_with_parent(
        &self,
        view: u64,
        parent: &Vqc<V, Sha256Digest>,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let (tips, _) = VqcExtraction::new::<Sha256, V>(parent, self.codec())
            .expect("fixture parent V-QC extracts")
            .into_parts();
        let history = TipRecord::new(parent.leader().history(), tips.blocks().to_vec())
            .expect("fixture tips are canonical")
            .commitment::<Sha256>();
        self.empty_leader_block(view, parent.id::<Sha256>(), history)
    }

    /// Returns the scheduled leader's signed empty proposal for `view`, anchored at genesis.
    pub fn leader_block(&self, view: u64) -> SignedLeaderBlock<V, Sha256Digest> {
        let genesis = self.config.genesis();
        let history = genesis_tip_commitment::<Sha256>(genesis);
        self.empty_leader_block(view, genesis.vqc(), history)
    }

    /// Returns the scheduled leader's signed empty proposal for `view` above `parent`.
    fn empty_leader_block(
        &self,
        view: u64,
        parent: CertificateId<Sha256Digest>,
        history: Sha256Digest,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let codec = self.codec();
        let proposals = self
            .config
            .genesis()
            .tips()
            .iter()
            .enumerate()
            .map(|(chain, tip)| {
                ChainProposal::new(
                    ChainId::new(chain as u32),
                    Anchor::Tip(*tip),
                    Vec::new(),
                    codec.pipeline_depth(),
                )
                .expect("empty proposal is valid")
            })
            .collect();
        let block = LeaderBlock::new(
            Round::new(self.config.epoch(), View::new(view)),
            parent,
            history,
            proposals,
            codec,
        )
        .expect("anchored proposal is valid");
        let leader = (view % self.signers.len() as u64) as usize;
        self.signers[leader]
            .sign_leader_block(block)
            .expect("scheduled leader signs its proposal")
    }

    /// Returns `signer`'s complete zero-position vote for `block`.
    pub fn vote(
        &self,
        signer: usize,
        block: &SignedLeaderBlock<V, Sha256Digest>,
    ) -> Vote<V, Sha256Digest> {
        let codec = self.codec();
        let body = VoteBody::for_leader::<Sha256, V>(
            block.block(),
            vec![Position::new(0); codec.chains()],
            vec![Extension::empty(); codec.chains()],
            codec,
        )
        .expect("zero positions are valid for an empty proposal");
        self.signers[signer]
            .sign_vote(body)
            .expect("signer holds an ordinary key")
    }

    /// Assembles a real V-QC for `view` from the first `n-f` signers' votes.
    pub fn vqc(&self, view: u64) -> Vqc<V, Sha256Digest> {
        let block = self.leader_block(view);
        let messages = (0..self.codec().view_quorum())
            .map(|signer| ViewMessage::Vote(self.vote(signer, &block)))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_vqc::<Sha256, _>(block.block().clone(), &messages, &Sequential)
            .expect("quorum of valid votes aggregates")
    }

    /// Assembles a real L-QC for `view` from the first `n-f` signers' votes.
    pub fn lqc(&self, view: u64) -> Lqc<V, Sha256Digest> {
        let block = self.leader_block(view);
        let votes = (0..self.codec().view_quorum())
            .map(|signer| self.vote(signer, &block))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_lqc::<Sha256, _>(block.block().clone(), &votes, &Sequential)
            .expect("quorum of valid votes aggregates")
    }
}

/// Signs a transaction-block header with test fixture material.
#[doc(hidden)]
pub fn sign_transaction_block<P, V, D>(
    scheme: &Scheme<P, V>,
    header: TransactionBlockHeader<D>,
) -> Result<SignedTransactionBlock<V, D>, SchemeError>
where
    P: commonware_cryptography::PublicKey,
    V: Variant,
    D: commonware_cryptography::Digest,
{
    scheme.sign_transaction_block(header)
}

/// Signs a data-availability share with test fixture material.
#[doc(hidden)]
pub fn sign_da_vote<P, V, D>(
    scheme: &Scheme<P, V>,
    header: TransactionBlockHeader<D>,
) -> Result<DaVote<V, D>, SchemeError>
where
    P: commonware_cryptography::PublicKey,
    V: Variant,
    D: commonware_cryptography::Digest,
{
    scheme.sign_da_vote(header)
}

/// Signs a vote with test fixture material.
#[doc(hidden)]
pub fn sign_vote<P, V, D>(
    scheme: &Scheme<P, V>,
    body: VoteBody<D>,
) -> Result<Vote<V, D>, SchemeError>
where
    P: commonware_cryptography::PublicKey,
    V: Variant,
    D: commonware_cryptography::Digest,
{
    scheme.sign_vote(body)
}

/// Signs an abstention with test fixture material.
#[doc(hidden)]
pub fn sign_novote<P, V>(scheme: &Scheme<P, V>, round: Round) -> Result<NoVote<V>, SchemeError>
where
    P: commonware_cryptography::PublicKey,
    V: Variant,
{
    scheme.sign_novote(round)
}

/// Signs a nullification share with test fixture material.
#[doc(hidden)]
pub fn sign_nullify<P, V>(scheme: &Scheme<P, V>, round: Round) -> Result<Nullify<V>, SchemeError>
where
    P: commonware_cryptography::PublicKey,
    V: Variant,
{
    scheme.sign_nullify(round)
}

fn digest(label: &[u8], marker: u64) -> Sha256Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn sharing<V: Variant>(rng: &mut TestRng, total: u32, required: u32) -> (Sharing<V>, Vec<Share>) {
    let private = Poly::<Scalar>::new(rng, required - 1);
    let shares = (0..total)
        .map(|index| {
            let point = Scalar::from_u64(u64::from(index) + 1);
            Share::new(Participant::new(index), Private::new(private.eval(&point)))
        })
        .collect();
    let public = Poly::<V::Public>::commit(private);
    let mut encoded = BytesMut::new();
    Mode::NonZeroCounter.write(&mut encoded);
    total.write(&mut encoded);
    public.write(&mut encoded);
    let mut encoded = encoded.freeze();
    let total = NonZeroU32::new(total).expect("mock committee is non-empty");
    let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0()))
        .expect("mock sharing round-trips");
    (sharing, shares)
}

#[cfg(test)]
mod size_probe {
    use super::Committee;
    use crate::{
        Viewable as _,
        multimmit::{
            config::Limits,
            machine::{
                Artifact, BarrierAck, Capability, CoreState, CoreTurn, DurabilityCapability,
                Profile, Role, Snapshot, SnapshotCodecConfig, Tuning, VerificationCapability,
            },
        },
    };
    use commonware_codec::{EncodeSize, Read as _, Write};
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use std::{num::NonZeroUsize, time::Duration};

    fn check(label: &str, value: &(impl Write + EncodeSize)) {
        let before = value.encode_size();
        let mut buf = Vec::new();
        value.write(&mut buf);
        assert_eq!(
            buf.len(),
            before,
            "{label}: written bytes disagree with encode_size"
        );
        let mut again = Vec::new();
        value.write(&mut again);
        assert_eq!(
            (value.encode_size(), again.len()),
            (before, before),
            "{label}: size or bytes changed after the first write"
        );
    }

    #[test]
    fn snapshot_writes_exactly_encode_size_with_forwarded_vqc() {
        for n in [6u32, 7, 11] {
            let committee =
                Committee::<MinPk>::new(2000 + u64::from(n), n, Limits::new(2, 1).unwrap());
            let profile: Profile<Sha256, MinPk> = Profile::new(
                committee.config.clone(),
                Role::Observer,
                Tuning {
                    view_timeout: Duration::from_millis(500),
                    production_interval: Duration::from_millis(100),
                    ..Tuning::default()
                },
            )
            .unwrap();
            let observed = vec![
                Artifact::Vqc(committee.vqc(1)),
                Artifact::NoVote(committee.novote(0, 2)),
            ]
            .into_iter()
            .map(|artifact| {
                let id = artifact.id::<Sha256>();
                (id, artifact)
            })
            .collect::<Vec<_>>();
            let resident_bytes = observed
                .iter()
                .map(|(id, artifact)| id.encode_size() + artifact.encode_size())
                .sum();
            let mut core = CoreState::fresh(profile, NonZeroUsize::MIN).unwrap();
            core.start_fresh().unwrap();
            let mut observed = Some((observed, resident_bytes));
            loop {
                let effects = match core.next_action(NonZeroUsize::MIN).unwrap() {
                    CoreTurn::Input(serviced) => serviced.transition.into_parts().0,
                    CoreTurn::Work(work) => work.into_parts().0,
                    CoreTurn::YieldRequired => {
                        core.resume_after_yield().unwrap();
                        continue;
                    }
                    CoreTurn::Idle if observed.is_none() => break,
                    CoreTurn::Idle => panic!("Core idled before observing the fixture"),
                };
                for effect in effects {
                    match effect {
                        Capability::Durability(DurabilityCapability::Persist(job)) => {
                            core.persistence_completed(BarrierAck::new(
                                job.id(),
                                job.generation(),
                                job.last_cursor(),
                            ))
                            .unwrap();
                        }
                        Capability::Verification(VerificationCapability::Verify(job)) => {
                            let completion = job.verify::<_, ed25519::PublicKey, Sha256>(
                                &mut commonware_utils::test_rng(),
                                &committee.verifier,
                                &Sequential,
                            );
                            core.verification_completed(completion).unwrap();
                        }
                        _ => {}
                    }
                }
                if core.inspection().is_live()
                    && let Some((observed, resident_bytes)) = observed.take()
                {
                    core.observe(observed, resident_bytes).unwrap();
                }
            }
            let snapshot = core.snapshot();
            for artifact in snapshot.retained_artifacts() {
                if let Artifact::Vqc(vqc) = artifact.as_ref() {
                    check(&format!("forwarded vqc view {:?}", vqc.view()), vqc);
                    check(
                        &format!("forwarded leader view {:?}", vqc.view()),
                        vqc.leader(),
                    );
                    check(
                        &format!("forwarded tally view {:?}", vqc.view()),
                        vqc.tally(),
                    );
                }
            }
            let mut written = Vec::new();
            snapshot.write(&mut written);
            assert_eq!(
                written.len(),
                snapshot.encode_size(),
                "snapshot size mismatch at n={n}"
            );

            // The written bytes decode back to an identical snapshot.
            let cfg = SnapshotCodecConfig::from_profile(core.profile());
            let mut buf = bytes::Bytes::from(written.clone());
            let decoded = Snapshot::<MinPk, Sha256Digest>::read_cfg(&mut buf, &cfg)
                .expect("snapshot decodes");
            assert_eq!(buf.len(), 0, "snapshot decode consumed every byte");
            let mut rewritten = Vec::new();
            decoded.write(&mut rewritten);
            assert_eq!(rewritten, written, "snapshot round-trips byte-identically");
        }
    }

    #[test]
    fn every_artifact_writes_exactly_encode_size_n7() {
        for n in [6u32, 7, 11, 16] {
            let committee =
                Committee::<MinPk>::new(1000 + u64::from(n), n, Limits::new(2, 1).unwrap());
            let block = committee.leader_block(1);
            check("leader", &block);
            let vote = committee.vote(0, &block);
            check("vote", &vote);
            let vqc = committee.vqc(1);
            check("vqc", &vqc);
            let lqc = committee.lqc(1);
            check("lqc", &lqc);
            let nullification = committee.nullification(1);
            check("nullification", &nullification);
            let header = committee.transaction_header(0, Sha256::hash(&[b"x"]));
            let signed = committee.signed_block(0, header.body_digest());
            check("signed block", &signed);
            let da = committee.da_vote(1, header);
            check("da vote", &da);
            check("novote", &committee.novote(2, 1));
            check("nullify", &committee.nullify(2, 1));
        }
    }
}
