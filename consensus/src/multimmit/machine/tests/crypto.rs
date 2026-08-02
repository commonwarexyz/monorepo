use super::{algebra::VqcExtraction, tests::test_utils::cohort, *};
use crate::{
    Viewable,
    multimmit::{
        config::{CodecConfig, Config, LeaderSchedule, Limits},
        scheme::bls12381_threshold::{Roster, Scheme},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, EpochGenesis, Extension,
            Height, LeaderBlock, Position, ViewMessage, Vote, VoteBody, Vqc,
            genesis_tip_commitment,
        },
    },
    types::{Epoch, Participant, Round, View},
};
use bytes::BytesMut;
use commonware_codec::{Decode, Encode, Read, Write};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar, Share},
        ops,
        sharing::{Mode, ModeVersion, Sharing},
        variant::{MinPk, MinSig, Variant},
    },
    ed25519,
    ed25519::PrivateKey as Ed25519PrivateKey,
    sha256::Digest,
};
use commonware_math::poly::Poly;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{TestRng, ordered::Set, test_rng};
use core::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use std::sync::Arc;

const PARTICIPANTS: u32 = 6;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_CRYPTO_TEST";

struct Fixture<V: Variant> {
    protocol: Config<Digest>,
    codec: CodecConfig,
    signers: Vec<Scheme<ed25519::PublicKey, V>>,
    verifier: Scheme<ed25519::PublicKey, V>,
}

impl<V: Variant> Fixture<V> {
    fn new() -> Self {
        let protocol = protocol_config();
        let codec = protocol.codec_config();
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
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
                    protocol.namespace(),
                    &private,
                );
                ordinary.push(private);
                (identity.clone(), public, proof)
            })
            .collect();
        let roster = Roster::verify(
            protocol.namespace(),
            codec.participants(),
            participants,
            &Sequential,
        )
        .unwrap();
        let (da, da_shares) = sharing::<V>(
            &mut rng,
            PARTICIPANTS,
            u32::try_from(codec.da_quorum()).unwrap(),
        );
        let (nullification, nullification_shares) = sharing::<V>(
            &mut rng,
            PARTICIPANTS,
            u32::try_from(codec.nullification_quorum()).unwrap(),
        );

        let signers = ordinary
            .into_iter()
            .zip(da_shares)
            .zip(nullification_shares)
            .map(|((ordinary, da_share), nullification_share)| {
                Scheme::signer(
                    &protocol,
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
        let verifier = Scheme::verifier(&protocol, roster, da, nullification).unwrap();

        Self {
            protocol,
            codec,
            signers,
            verifier,
        }
    }

    fn profile(&self, role: Role) -> Profile<Sha256, V> {
        Profile::new(
            self.protocol.clone(),
            role,
            Tuning {
                view_timeout: Duration::from_secs(1),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap()
    }

    fn leader(&self, view: u64) -> LeaderBlock<V, Digest> {
        let proposals = self
            .protocol
            .genesis()
            .tips()
            .iter()
            .map(|tip| {
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Tip(*tip),
                    Vec::new(),
                    self.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            Round::new(self.protocol.epoch(), View::new(view)),
            self.protocol.genesis().vqc(),
            genesis_tip_commitment::<Sha256>(self.protocol.genesis()),
            proposals,
            self.codec,
        )
        .unwrap()
    }

    fn vote_body(&self, leader: &LeaderBlock<V, Digest>) -> VoteBody<Digest> {
        VoteBody::for_leader::<Sha256, V>(
            leader,
            vec![Position::new(0); PARTICIPANTS as usize],
            vec![Extension::empty(); PARTICIPANTS as usize],
            self.codec,
        )
        .unwrap()
    }

    fn leader_with_two_block_path(&self, view: u64) -> LeaderBlock<V, Digest> {
        let proposals = self
            .protocol
            .genesis()
            .tips()
            .iter()
            .map(|tip| {
                let blocks = if tip.chain() == ChainId::new(0) {
                    (1..=2)
                        .map(|height| digest(b"larger vqc path", height))
                        .collect()
                } else {
                    Vec::new()
                };
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Tip(*tip),
                    blocks,
                    self.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            Round::new(self.protocol.epoch(), View::new(view)),
            self.protocol.genesis().vqc(),
            genesis_tip_commitment::<Sha256>(self.protocol.genesis()),
            proposals,
            self.codec,
        )
        .unwrap()
    }

    fn vote_body_at(&self, leader: &LeaderBlock<V, Digest>, position: u32) -> VoteBody<Digest> {
        let mut positions = vec![Position::new(0); PARTICIPANTS as usize];
        positions[0] = Position::new(position);
        VoteBody::for_leader::<Sha256, V>(
            leader,
            positions,
            vec![Extension::empty(); PARTICIPANTS as usize],
            self.codec,
        )
        .unwrap()
    }

    fn sign(&self, signer: Participant, request: &SignRequest<V, Digest>) -> Artifact<V, Digest> {
        let scheme = &self.signers[signer.get() as usize];
        match request {
            SignRequest::TransactionBlock(header) => {
                Artifact::TransactionBlock(scheme.sign_transaction_block(header.clone()).unwrap())
            }
            SignRequest::DaVote(request) => {
                Artifact::DaVote(scheme.sign_da_vote(request.header().clone()).unwrap())
            }
            SignRequest::LeaderBlock(request) => {
                Artifact::LeaderBlock(scheme.sign_leader_block(request.block().clone()).unwrap())
            }
            SignRequest::Vote(request) => {
                Artifact::Vote(scheme.sign_vote(request.body().clone()).unwrap())
            }
            SignRequest::NoVote { round } => Artifact::NoVote(scheme.sign_novote(*round).unwrap()),
            SignRequest::Nullify { round } => {
                Artifact::Nullify(scheme.sign_nullify(*round).unwrap())
            }
        }
    }

    fn verify(
        &self,
        machine: &mut Machine<Sha256, V>,
        artifacts: Vec<Artifact<V, Digest>>,
    ) -> Step<V, Digest> {
        let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
        let job = observed
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
                _ => None,
            })
            .expect("real artifacts must enter production verification");
        let count = job.items().len();
        let verified = machine
            .step(Input::Verified(
                job.verify::<_, ed25519::PublicKey, Sha256>(
                    &mut test_rng(),
                    &self.verifier,
                    &Sequential,
                ),
            ))
            .unwrap();
        assert!(matches!(
            verified.status(),
            StepStatus::Verified { valid, invalid } if *valid == count && *invalid == 0
        ));
        settle(machine, verified)
    }
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
    let total = NonZeroU32::new(total).unwrap();
    let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0())).unwrap();
    (sharing, shares)
}

fn digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn protocol_config() -> Config<Digest> {
    let epoch = Epoch::new(9);
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
        Limits::new(2, 2).unwrap(),
        genesis,
    )
    .unwrap()
}

fn persist_job<V: Variant>(step: &Step<V, Digest>) -> PersistJob<V, Digest> {
    step.capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.job().clone()),
            _ => None,
        })
        .expect("a durable transition must emit a persistence job")
}

/// Folds scheduler work into a step until the machine stages a barrier or quiesces.
fn settle<V: Variant>(machine: &mut Machine<Sha256, V>, step: Step<V, Digest>) -> Step<V, Digest> {
    let status = step.status().clone();
    let (mut effects, mut activities) = step.into_parts();
    while !effects.iter().any(|effect| {
        matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        )
    }) {
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        let (emitted, accepted) = result.into_parts();
        let quiesced = emitted.is_empty() && !work_remaining;
        effects.extend(emitted);
        activities.extend(accepted);
        if quiesced {
            break;
        }
    }
    Step::for_tests(status, effects, activities)
}

fn persist<V: Variant>(
    machine: &mut Machine<Sha256, V>,
    step: &Step<V, Digest>,
) -> Step<V, Digest> {
    let job = persist_job(step);
    let step = machine
        .step(Input::Persisted(BarrierAck::new(
            job.id(),
            job.generation(),
            job.last_cursor(),
        )))
        .unwrap();
    settle(machine, step)
}

fn start<V: Variant>(profile: Profile<Sha256, V>) -> (Machine<Sha256, V>, Step<V, Digest>) {
    let mut machine = Machine::new(profile);
    let starting = machine.step(Input::Start).unwrap();
    // The view timer arms at staging; fold it into the returned step so callers keep one
    // handle to both the timer and the follow-up staging the acknowledgement emits.
    let volatile = starting
        .capabilities()
        .iter()
        .filter(|effect| {
            !matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let started = persist(&mut machine, &starting);
    let status = started.status().clone();
    let (effects, activities) = started.into_parts();
    let merged: Capabilities<V, Digest> = volatile.into_iter().chain(effects).collect();
    (machine, Step::for_tests(status, merged, activities))
}

fn assert_duplicate<V: Variant>(machine: &mut Machine<Sha256, V>, artifact: Artifact<V, Digest>) {
    let duplicate = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = duplicate.status() else {
        panic!("a repeated local artifact must follow normal observation");
    };
    assert_eq!(results[0].status(), ObservationStatus::Duplicate);
    assert!(duplicate.capabilities().iter().all(|effect| {
        !matches!(
            effect,
            Capability::Verification(VerificationCapability::Verify(_))
        )
    }));
}

fn parallel() -> Rayon {
    Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap()
}

fn execute_da_trace<V: Variant>(fixture: &Fixture<V>) {
    let producer = Participant::new(0);
    let (mut machine, _) = start(fixture.profile(Role::Validator(producer)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let build = ready
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Build(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("available work must issue a build job");
    let built = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"produced block", 1)),
        )))
        .unwrap();
    let built = settle(&mut machine, built);
    let custody = built
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a built block must request custody");
    let built = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            custody.id(),
            custody.generation(),
            custody.header().clone(),
        )))
        .unwrap();
    let built = settle(&mut machine, built);
    // Signing carries no signature out, so the request releases with the step that stages the
    // producer choice.
    let sign = built
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Sign(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("a built block must issue a signing job");
    persist(&mut machine, &built);
    let DurableEffect::Sign(SignRequest::TransactionBlock(header)) = sign.request() else {
        panic!("the producer must sign the exact built header");
    };
    let header = header.clone();
    let DurableEffect::Sign(request) = sign.request() else {
        unreachable!()
    };
    let artifact = fixture.sign(producer, request);
    assert!(matches!(
        &artifact,
        Artifact::TransactionBlock(block) if fixture.verifier.verify_transaction_block(block)
    ));
    let artifact_id = artifact.id::<Sha256>();
    let duplicate = artifact.clone();
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact),
        }))
        .unwrap();
    // The completion parks; its staging (and the self-admission the old status reported)
    // arrives when the scheduler drains it into a barrier.
    assert!(matches!(
        signed.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    let signed = settle(&mut machine, signed);
    assert!(machine.artifacts.contains_key(&artifact_id));
    let advanced = persist(&mut machine, &signed);
    if advanced.capabilities().iter().any(|capability| {
        matches!(
            capability,
            Capability::Durability(DurabilityCapability::Persist(_))
        )
    }) {
        persist(&mut machine, &advanced);
    }
    assert_duplicate(&mut machine, duplicate);

    let votes = fixture
        .signers
        .iter()
        .take(fixture.codec.da_quorum())
        .map(|signer| Artifact::DaVote(signer.sign_da_vote(header.clone()).unwrap()))
        .collect();
    let verified = fixture.verify(&mut machine, votes);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a verified DA quorum must issue recovery");
    let sequential = fixture
        .verifier
        .assemble_da_certificate(recovery.votes(), &Sequential)
        .unwrap();
    let parallel = fixture
        .verifier
        .assemble_da_certificate(recovery.votes(), &parallel())
        .unwrap();
    assert_eq!(sequential, parallel);
    assert!(fixture.verifier.verify_da_certificate(&sequential));
    let artifact = Artifact::DaCertificate(sequential.clone());
    let artifact_id = artifact.id::<Sha256>();

    let recovered = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            sequential,
        )))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging
    // barrier, and the self-admission the old status reported shows up in the artifact cache.
    assert_eq!(recovered.status(), &StepStatus::CompletionDeferred);
    let recovered = settle(&mut machine, recovered);
    assert!(machine.artifacts.contains_key(&artifact_id));
    persist(&mut machine, &recovered);
    assert_duplicate(&mut machine, artifact);
}

fn execute_sign_batch_and_nullification_trace<V: Variant>(fixture: &Fixture<V>) {
    let signer = Participant::new(0);
    let (mut machine, started) = start(fixture.profile(Role::Validator(signer)));
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .expect("a live validator must arm its view timer");
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    // Signing carries no signature out, so the batch releases with the step that stages the
    // timeout's atomic choice.
    let batch = elapsed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::SignBatch(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("a timeout must atomically issue novote and nullify signing");
    persist(&mut machine, &elapsed);
    let DurableEffect::SignBatch(requests) = batch.request() else {
        unreachable!()
    };
    assert!(matches!(
        requests.as_ref(),
        [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]
    ));
    let artifacts = requests
        .iter()
        .map(|request| fixture.sign(signer, request))
        .collect::<Vec<_>>();
    let unverified = artifacts
        .iter()
        .map(Artifact::unverified)
        .collect::<Vec<_>>();
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &unverified,
            &Sequential
        ),
        vec![true, true]
    );
    let artifact_ids = artifacts
        .iter()
        .map(|artifact| artifact.id::<Sha256>())
        .collect::<Vec<_>>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::SignedBatch {
            id: batch.id(),
            generation: batch.generation(),
            artifacts,
        }))
        .unwrap();
    // The batch completion parks; settling drains it into one staging barrier, and the two
    // admissions the old status reported show up in the artifact cache.
    assert!(matches!(
        completed.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    let completed = settle(&mut machine, completed);
    assert!(
        artifact_ids
            .iter()
            .all(|id| machine.artifacts.contains_key(id))
    );
    persist(&mut machine, &completed);

    let round = Round::new(fixture.protocol.epoch(), View::new(1));
    let shares = fixture
        .signers
        .iter()
        .skip(1)
        .take(fixture.codec.nullification_quorum())
        .map(|scheme| Artifact::Nullify(scheme.sign_nullify(round).unwrap()))
        .collect();
    let verified = fixture.verify(&mut machine, shares);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a verified nullification quorum must issue recovery");
    let sequential = fixture
        .verifier
        .assemble_nullification(recovery.shares(), &Sequential)
        .unwrap();
    let parallel = fixture
        .verifier
        .assemble_nullification(recovery.shares(), &parallel())
        .unwrap();
    assert_eq!(sequential, parallel);
    assert!(fixture.verifier.verify_nullification(&sequential));
    let artifact = Artifact::Nullification(sequential.clone());
    let artifact_id = artifact.id::<Sha256>();

    let recovered = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), sequential),
        ))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging
    // barrier, and the self-admission the old status reported shows up in the artifact cache.
    assert_eq!(recovered.status(), &StepStatus::CompletionDeferred);
    let recovered = settle(&mut machine, recovered);
    assert!(machine.artifacts.contains_key(&artifact_id));
    persist(&mut machine, &recovered);
    assert_duplicate(&mut machine, artifact);
}

fn authenticate_leader<V: Variant>(
    fixture: &Fixture<V>,
    machine: &mut Machine<Sha256, V>,
    leader: &LeaderBlock<V, Digest>,
) {
    let signer = LeaderSchedule::round_robin(fixture.codec.participants()).leader(leader.view());
    let signed = fixture.signers[signer.get() as usize]
        .sign_leader_block(leader.clone())
        .unwrap();
    fixture.verify(machine, vec![Artifact::LeaderBlock(signed)]);
}

fn execute_vqc_trace<V: Variant>(fixture: &Fixture<V>) {
    let (mut machine, _) = start(fixture.profile(Role::Observer));
    let leader = fixture.leader(1);
    authenticate_leader(fixture, &mut machine, &leader);
    let body = fixture.vote_body(&leader);
    let mut messages = fixture
        .signers
        .iter()
        .take(fixture.codec.designation_quorum())
        .map(|scheme| ViewMessage::Vote(scheme.sign_vote(body.clone()).unwrap()))
        .collect::<Vec<_>>();
    messages.extend(
        fixture
            .signers
            .iter()
            .skip(fixture.codec.designation_quorum())
            .take(fixture.codec.view_quorum() - fixture.codec.designation_quorum())
            .map(|scheme| ViewMessage::NoVote(scheme.sign_novote(leader.round()).unwrap())),
    );
    let artifacts = messages
        .iter()
        .cloned()
        .map(|message| match message {
            ViewMessage::Vote(vote) => Artifact::Vote(vote),
            ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
        })
        .collect();
    let verified = fixture.verify(&mut machine, artifacts);
    let aggregate = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a verified view quorum must issue V-QC aggregation");
    let selected = aggregate.messages().collect::<Vec<_>>();
    let sequential = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(aggregate.leader().clone(), &selected, &Sequential)
        .unwrap();
    let strategy = parallel();
    let parallel = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(aggregate.leader().clone(), &selected, &strategy)
        .unwrap();
    assert_eq!(sequential, parallel);
    assert_eq!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &sequential, &Sequential),
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &parallel, &strategy)
    );
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &sequential, &Sequential)
            .is_some()
    );
    let artifact = Artifact::Vqc(sequential.clone());
    let artifact_id = artifact.id::<Sha256>();

    let aggregated = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            sequential,
        ))))
        .unwrap();
    // Aggregation completions always park; settling drains the completion into its staging
    // barrier, and the self-admission the old status reported shows up in the artifact cache.
    assert_eq!(aggregated.status(), &StepStatus::CompletionDeferred);
    let aggregated = settle(&mut machine, aggregated);
    assert!(machine.artifacts.contains_key(&artifact_id));
    persist(&mut machine, &aggregated);
    assert_duplicate(&mut machine, artifact);
}

#[test]
fn inbound_larger_vqc_decodes_verifies_admits_and_uses_every_vote_for_tips() {
    let fixture = Fixture::<MinPk>::new();
    let leader = fixture.leader_with_two_block_path(1);
    let positions = [2, 0, 0, 0, 0, 2];
    let messages = fixture
        .signers
        .iter()
        .zip(positions)
        .map(|(scheme, position)| {
            ViewMessage::Vote(
                scheme
                    .sign_vote(fixture.vote_body_at(&leader, position))
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert!(messages.len() > fixture.codec.view_quorum());

    let quorum = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(
            leader.clone(),
            &messages[..fixture.codec.view_quorum()],
            &Sequential,
        )
        .unwrap();
    let complete = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
        .unwrap();
    let encoded = complete.encode();
    let decoded = Vqc::<MinPk, Digest>::decode_cfg(encoded.as_ref(), &fixture.codec).unwrap();
    assert_eq!(decoded, complete);
    assert_eq!(decoded.tally().signers().count(), PARTICIPANTS as usize);
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &decoded, &Sequential)
            .is_some()
    );

    let quorum_tips = VqcExtraction::new::<Sha256, MinPk>(&quorum, fixture.codec)
        .unwrap()
        .into_parts()
        .0;
    let complete_tips = VqcExtraction::new::<Sha256, MinPk>(&decoded, fixture.codec)
        .unwrap()
        .into_parts()
        .0;
    assert_ne!(quorum_tips.blocks(), complete_tips.blocks());
    assert_eq!(
        complete_tips.blocks()[0].height(),
        Height::new(2),
        "the extra designated vote changes the authenticated safe tip"
    );

    let (mut machine, _) = start(fixture.profile(Role::Observer));
    authenticate_leader(&fixture, &mut machine, &leader);
    let mut admitted = fixture.verify(&mut machine, vec![Artifact::Vqc(decoded.clone())]);
    while admitted.capabilities().iter().any(|capability| {
        matches!(
            capability,
            Capability::Durability(DurabilityCapability::Persist(_))
        )
    }) {
        admitted = persist(&mut machine, &admitted);
    }
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if anchor == &decoded));
}

fn execute_lqc_trace<V: Variant>(fixture: &Fixture<V>) {
    let (mut machine, _) = start(fixture.profile(Role::Observer));
    let leader = fixture.leader(2);
    authenticate_leader(fixture, &mut machine, &leader);
    let body = fixture.vote_body(&leader);
    let votes = fixture
        .signers
        .iter()
        .take(fixture.codec.view_quorum())
        .map(|scheme| scheme.sign_vote(body.clone()).unwrap())
        .collect::<Vec<_>>();
    let verified = fixture.verify(
        &mut machine,
        votes.iter().cloned().map(Artifact::Vote).collect(),
    );
    // The finalized pool may release its aggregation with the verifying settle or only after
    // the barriers that settle staged are acknowledged.
    let mut verified = verified;
    let aggregate = loop {
        if let Some(job) = verified
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
                _ => None,
            })
        {
            break job;
        }
        assert!(
            verified.capabilities().iter().any(|effect| {
                matches!(
                    effect,
                    Capability::Durability(DurabilityCapability::Persist(_))
                )
            }),
            "a verified vote quorum must issue L-QC aggregation"
        );
        verified = persist(&mut machine, &verified);
    };
    let selected = aggregate.votes().cloned().collect::<Vec<_>>();
    let sequential = fixture
        .verifier
        .assemble_lqc::<Sha256, _>(aggregate.leader().clone(), &selected, &Sequential)
        .unwrap();
    let strategy = parallel();
    let parallel = fixture
        .verifier
        .assemble_lqc::<Sha256, _>(aggregate.leader().clone(), &selected, &strategy)
        .unwrap();
    assert_eq!(sequential, parallel);
    assert_eq!(
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &sequential, &Sequential),
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &parallel, &strategy)
    );
    assert!(
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &sequential, &Sequential)
            .is_some()
    );
    let artifact = Artifact::Lqc(sequential.clone());
    let artifact_id = artifact.id::<Sha256>();

    let aggregated = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            sequential,
        ))))
        .unwrap();
    // Aggregation completions always park; settling drains the completion into its staging
    // barrier, and the self-admission the old status reported shows up in the artifact cache.
    assert_eq!(aggregated.status(), &StepStatus::CompletionDeferred);
    let aggregated = settle(&mut machine, aggregated);
    assert!(machine.artifacts.contains_key(&artifact_id));
    persist(&mut machine, &aggregated);
    assert_duplicate(&mut machine, artifact);
}

fn execute_real_crypto_effects<V: Variant>() {
    let fixture = Fixture::<V>::new();
    execute_da_trace(&fixture);
    execute_sign_batch_and_nullification_trace(&fixture);
    execute_vqc_trace(&fixture);
    execute_lqc_trace(&fixture);
}

fn reused_application_digest_votes(
    fixture: &Fixture<MinPk>,
    leader: &LeaderBlock<MinPk, Digest>,
) -> Vec<Vote<MinPk, Digest>> {
    let shared = digest(b"shared application child", 0);
    (0..fixture.codec.view_quorum())
        .map(|signer| {
            let mut extensions = vec![Extension::empty(); fixture.codec.chains()];
            let parent = if signer + 1 == fixture.codec.view_quorum() {
                digest(b"Byzantine application parent", 0)
            } else {
                digest(b"honest application parent", 0)
            };
            extensions[0] =
                Extension::new(vec![parent, shared], fixture.codec.extension_bound()).unwrap();
            let body = VoteBody::for_leader::<Sha256, MinPk>(
                leader,
                vec![Position::new(0); fixture.codec.chains()],
                extensions,
                fixture.codec,
            )
            .unwrap();
            fixture.signers[signer].sign_vote(body).unwrap()
        })
        .collect()
}

fn assert_reused_application_digest_is_accepted(
    fixture: &Fixture<MinPk>,
    artifact: Artifact<MinPk, Digest>,
) {
    let (mut machine, _) = start(fixture.profile(Role::Observer));
    let id = artifact.id::<Sha256>();
    let observed = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let verification = observed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verification(VerificationCapability::Verify(job)) => Some(job),
            _ => None,
        })
        .unwrap();
    let completion = verification.verify::<_, ed25519::PublicKey, Sha256>(
        &mut test_rng(),
        &fixture.verifier,
        &Sequential,
    );
    let accepted = machine.step(Input::Verified(completion)).unwrap();
    assert!(matches!(
        accepted.status(),
        StepStatus::Verified {
            valid: 1,
            invalid: 0
        }
    ));
    settle(&mut machine, accepted);
    assert!(machine.artifacts.contains_key(&id));
}

#[test]
fn vqc_accepts_a_reused_application_digest_on_distinct_ancestry() {
    let fixture = Fixture::<MinPk>::new();
    let leader = fixture.leader(1);
    let votes = reused_application_digest_votes(&fixture, &leader);
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let certificate = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader, &messages, &Sequential)
        .unwrap();
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
    assert_reused_application_digest_is_accepted(&fixture, Artifact::Vqc(certificate));
}

#[test]
fn lqc_accepts_a_reused_application_digest_on_distinct_ancestry() {
    let fixture = Fixture::<MinPk>::new();
    let leader = fixture.leader(1);
    let votes = reused_application_digest_votes(&fixture, &leader);
    let certificate = fixture
        .verifier
        .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
        .unwrap();
    assert!(
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
    assert_reused_application_digest_is_accepted(&fixture, Artifact::Lqc(certificate));
}

#[test]
fn real_crypto_effects_execute_for_min_pk() {
    execute_real_crypto_effects::<MinPk>();
}

#[test]
fn real_crypto_effects_execute_for_min_sig() {
    execute_real_crypto_effects::<MinSig>();
}
