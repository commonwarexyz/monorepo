//! Machine traces over real signatures: DA certificates, signing, certificate assembly, and
//! objective-fault attribution.

use crate::{
    Epochable as _, Viewable,
    multimmit::{
        actors::verifier::verify,
        algebra::VqcExtraction,
        config::{LeaderSchedule, Profile, Protocol, Role, Tuning},
        machine::{
            accountability::AccountabilityState,
            capability::{Capability, ChainCommand, CryptoJob, TimerCommand},
            durability::{EffectCompletion, SignRequest},
            finality::LqcAggregateCompletion,
            input::{CryptoCompletion, Input, ObservationStatus, Rejection, Step, StepStatus},
            job::{Generation, Issued},
            producer::{BuildCompletion, CustodyCompletion},
            reducer::machine::Machine,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, EffectExt, Until, cohort,
                fixtures::marked_digest, start,
            },
            view::{NullificationRecoveryCompletion, VqcAggregateCompletion},
        },
        mocks::Committee,
        scheme::bls12381_threshold::Scheme,
        types::{
            Activity, Anchor, Artifact, ChainId, ChainProposal, CodecConfig, DaVote,
            DigestedLeader, Extension, LeaderBlock, PathLimits, Position, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Height, Participant, Round, View},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519,
    sha256::Digest,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::test_rng;
use core::{mem::size_of_val, num::NonZeroUsize, time::Duration};
use std::sync::Arc;

const PARTICIPANTS: u32 = 6;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_CRYPTO_TEST";
/// The committee seed, which also labels its epoch.
const EPOCH: u64 = 9;

struct Fixture<V: Variant> {
    protocol: Protocol<Digest>,
    codec: CodecConfig,
    signers: Vec<Scheme<ed25519::PublicKey, V>>,
    verifier: Scheme<ed25519::PublicKey, V>,
}

impl<V: Variant> Fixture<V> {
    fn new() -> Self {
        let committee = Committee::<V>::builder(EPOCH, PARTICIPANTS)
            .namespace(NAMESPACE)
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        Self {
            codec: committee.config.codec_config(),
            protocol: committee.config,
            signers: committee.signers,
            verifier: committee.verifier,
        }
    }

    fn profile(&self, role: Role) -> Profile<Digest> {
        Profile::new::<MinPk>(
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
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(leader),
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
                        .map(|height| marked_digest(b"larger vqc path", height))
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
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(leader),
            positions,
            vec![Extension::empty(); PARTICIPANTS as usize],
            self.codec,
        )
        .unwrap()
    }

    /// Returns the height-one header on chain 0 whose body digest is marked by `marker`.
    fn first_header(&self, marker: &[u8]) -> TransactionBlockHeader<Digest> {
        let genesis = self.protocol.genesis().tips()[0];
        TransactionBlockHeader::new(
            self.protocol.epoch(),
            ChainId::new(0),
            Height::new(1),
            genesis.digest(),
            marked_digest(marker, 1),
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
                Artifact::Vote(scheme.sign_vote(request.clone()).unwrap())
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
        let job = observed.verify_job();
        let count = job.items().len();
        let verified = machine
            .step(Input::Verified(verify::<Sha256, _, _>(
                &job,
                &mut test_rng(),
                &self.verifier,
                &Sequential,
            )))
            .unwrap();
        assert!(matches!(
            verified.status(),
            StepStatus::Verified { valid, invalid } if *valid == count && *invalid == 0
        ));
        machine.settle(verified, Until::Persist)
    }
}

fn assert_duplicate<V: Variant>(machine: &mut Machine<Sha256, V>, artifact: Artifact<V, Digest>) {
    let duplicate = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = duplicate.status() else {
        panic!("a repeated local artifact must follow normal observation");
    };
    assert_eq!(results[0].status(), ObservationStatus::Duplicate);
    assert!(
        duplicate
            .capabilities()
            .iter()
            .all(|effect| { !matches!(effect, Capability::Verify(_)) })
    );
}

fn blocked<V: Variant>(step: &Step<V, Digest>) -> Vec<Participant> {
    step.capabilities()
        .iter()
        .filter_map(|capability| match capability {
            Capability::Quarantine(participants) => Some(participants.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[track_caller]
fn assert_objective_fault<V: Variant>(
    fixture: &Fixture<V>,
    first: Artifact<V, Digest>,
    second: Artifact<V, Digest>,
    signer: Participant,
) {
    for pair in [[first.clone(), second.clone()], [second, first]] {
        let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
        assert!(blocked(&fixture.verify(&mut machine, vec![pair[0].clone()])).is_empty());
        assert_eq!(
            blocked(&fixture.verify(&mut machine, vec![pair[1].clone()])),
            vec![signer],
        );
    }
}

#[track_caller]
fn assert_compatible<V: Variant>(
    fixture: &Fixture<V>,
    first: Artifact<V, Digest>,
    second: Artifact<V, Digest>,
) {
    for pair in [[first.clone(), second.clone()], [second, first]] {
        let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
        assert!(blocked(&fixture.verify(&mut machine, vec![pair[0].clone()])).is_empty());
        assert!(blocked(&fixture.verify(&mut machine, vec![pair[1].clone()])).is_empty());
    }
}

#[track_caller]
fn assert_objective_fault_in_one_batch<V: Variant>(
    fixture: &Fixture<V>,
    first: Artifact<V, Digest>,
    second: Artifact<V, Digest>,
    signer: Participant,
) {
    let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
    assert_eq!(
        blocked(&fixture.verify(&mut machine, vec![first, second])),
        vec![signer],
    );
}

fn parallel() -> Rayon {
    Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap()
}

fn execute_da_trace<V: Variant>(fixture: &Fixture<V>) {
    let producer = Participant::new(0);
    let (mut machine, _) = start(fixture.profile(Role::Validator(producer)), Until::Persist);
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::Persist);
    let build = ready.build_job();
    let built = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(marked_digest(b"produced block", 1)),
        )))
        .unwrap();
    let built = machine.settle(built, Until::Persist);
    let custody = built.custody_job();
    let built = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            custody.issued(),
            custody.header().clone(),
        )))
        .unwrap();
    let built = machine.settle(built, Until::Persist);
    // Signing carries no signature out, so the request releases with the step that stages the
    // producer choice.
    let sign = built
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_one().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("a built block must issue a signing job");
    machine.persist(&built.persist_job(), Until::Persist);
    let Some(SignRequest::TransactionBlock(header)) = sign.request().sign_one() else {
        panic!("the producer must sign the exact built header");
    };
    let header = header.clone();
    let Some(request) = sign.request().sign_one() else {
        unreachable!()
    };
    let artifact = fixture.sign(producer, request);
    assert!(matches!(
        &artifact,
        Artifact::TransactionBlock(block) if fixture.verifier.verify_transaction_block(block)
    ));
    let artifact_id = artifact.id::<Sha256>();
    let duplicate = artifact.clone();
    let stale = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            Issued::new(
                sign.issued().id(),
                Generation::new(sign.issued().generation().get() + 1),
            ),
            vec![Arc::new(artifact.clone())],
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.activities().is_empty());
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(artifact)],
        )))
        .unwrap();
    assert_eq!(
        signed.activities(),
        &[Activity::TransactionProposed {
            block: header.block_ref::<Sha256>(),
        }]
    );
    assert!(signed.capabilities().is_empty());
    let repeated = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(duplicate.clone())],
        )))
        .unwrap();
    assert_eq!(repeated.status(), &StepStatus::StaleCompletion);
    assert!(repeated.activities().is_empty());
    // The completion parks; its staging and self-admission arrive when the scheduler drains it
    // into a barrier.
    assert!(matches!(signed.status(), StepStatus::Accepted));
    let signed = machine.settle(signed, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&artifact_id));
    let advanced = machine.persist(&signed.persist_job(), Until::Persist);
    if advanced.has(Capability::is_journal) {
        machine.persist(&advanced.persist_job(), Until::Persist);
    }
    assert_duplicate(&mut machine, duplicate);

    let votes = fixture
        .signers
        .iter()
        .take(fixture.codec.da_quorum())
        .map(|signer| Artifact::DaVote(signer.sign_da_vote(header.clone()).unwrap()))
        .collect();
    let verified = fixture.verify(&mut machine, votes);
    // The machine forwards the authenticated shares to the own-chain DA task rather than pooling
    // them; the task assembles the certificate off-thread and returns it for the machine to admit.
    let shares = verified
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::OwnChainDa(ChainCommand::Observe(share)) => Some(share.as_ref().clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(shares.len(), fixture.codec.da_quorum());
    let sequential = fixture
        .verifier
        .assemble_da_certificate(&shares, &Sequential)
        .unwrap();
    let parallel = fixture
        .verifier
        .assemble_da_certificate(&shares, &parallel())
        .unwrap();
    assert_eq!(sequential, parallel);
    assert!(fixture.verifier.verify_da_certificate(&sequential));
    let artifact = Artifact::DaCertificate(sequential.clone());
    let artifact_id = artifact.id::<Sha256>();

    let recovered = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block: header.block_ref::<Sha256>(),
            certificate: sequential,
        }))
        .unwrap();
    // Recovered certificates park; settling drains the completion into its staging barrier and
    // the self-admission shows up in the artifact cache.
    assert_eq!(recovered.status(), &StepStatus::Accepted);
    let recovered = machine.settle(recovered, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&artifact_id));
    machine.persist(&recovered.persist_job(), Until::Persist);
    assert_duplicate(&mut machine, artifact);
}

fn execute_sign_batch_and_nullification_trace<V: Variant>(fixture: &Fixture<V>) {
    let signer = Participant::new(0);
    let (mut machine, started) = start(fixture.profile(Role::Validator(signer)), Until::Persist);
    let timer = started
        .find(|effect| match effect {
            Capability::Timer(TimerCommand::View(timer)) => Some(*timer),
            _ => None,
        })
        .expect("a live validator must arm its view timer");
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = machine.settle(elapsed, Until::Persist);
    // Signing carries no signature out, so the batch releases with the step that stages the
    // timeout's atomic choice.
    let batch = elapsed
        .find(|effect| match effect {
            Capability::Released(job) if job.request().sign_many().is_some() => Some(job.clone()),
            _ => None,
        })
        .expect("a timeout must atomically issue novote and nullify signing");
    machine.persist(&elapsed.persist_job(), Until::Persist);
    let Some(requests) = batch.request().sign_many() else {
        unreachable!()
    };
    assert!(matches!(
        requests,
        [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]
    ));
    let artifacts = requests
        .iter()
        .map(|request| fixture.sign(signer, request))
        .collect::<Vec<_>>();
    let unverified = artifacts.iter().collect::<Vec<_>>();
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &unverified,
            &[],
            &Sequential
        ),
        vec![true, true]
    );
    let artifact_ids = artifacts
        .iter()
        .map(|artifact| artifact.id::<Sha256>())
        .collect::<Vec<_>>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            batch.issued(),
            artifacts.iter().cloned().map(Arc::new).collect(),
        )))
        .unwrap();
    // The batch completion parks; settling drains it into one staging barrier, and both
    // admissions show up in the artifact cache.
    assert!(matches!(completed.status(), StepStatus::Accepted));
    let completed = machine.settle(completed, Until::Persist);
    assert!(
        artifact_ids
            .iter()
            .all(|id| machine.store.artifacts.contains_key(id))
    );
    machine.persist(&completed.persist_job(), Until::Persist);

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
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => Some(job.clone()),
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
        .step(Input::Crypto(CryptoCompletion::Nullification(
            NullificationRecoveryCompletion::new(recovery.issued(), sequential),
        )))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging
    // barrier, and the self-admission shows up in the artifact cache.
    assert_eq!(recovered.status(), &StepStatus::Accepted);
    let recovered = machine.settle(recovered, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&artifact_id));
    machine.persist(&recovered.persist_job(), Until::Persist);
    assert_duplicate(&mut machine, artifact);
}

fn authenticate_leader<V: Variant>(
    fixture: &Fixture<V>,
    machine: &mut Machine<Sha256, V>,
    leader: &LeaderBlock<V, Digest>,
) {
    let signer = LeaderSchedule::round_robin(fixture.codec.participants())
        .unwrap()
        .leader(leader.view());
    let signed = fixture.signers[signer.get() as usize]
        .sign_leader_block(leader.clone())
        .unwrap();
    fixture.verify(machine, vec![Artifact::LeaderBlock(signed)]);
}

fn execute_vqc_trace<V: Variant>(fixture: &Fixture<V>) {
    let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
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
        .find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
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
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(
            VqcAggregateCompletion::prepare::<Sha256>(
                &aggregate,
                sequential,
                machine.profile().codec(),
            )
            .unwrap(),
        ))))
        .unwrap();
    // Aggregation completions always park; settling drains the completion into its staging
    // barrier, and the self-admission shows up in the artifact cache.
    assert_eq!(aggregated.status(), &StepStatus::Accepted);
    let aggregated = machine.settle(aggregated, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&artifact_id));
    machine.persist(&aggregated.persist_job(), Until::Persist);
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
    let decoded = Vqc::<MinPk, Digest>::decode_cfg(encoded, &fixture.codec).unwrap();
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

    let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
    authenticate_leader(&fixture, &mut machine, &leader);
    let mut admitted = fixture.verify(&mut machine, vec![Artifact::Vqc(decoded.clone())]);
    while admitted.has(Capability::is_journal) {
        admitted = machine.persist(&admitted.persist_job(), Until::Persist);
    }
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if anchor == &decoded));
}

fn execute_lqc_trace<V: Variant>(fixture: &Fixture<V>) {
    let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
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
        if let Some(job) = verified.aggregate_lqc() {
            break job;
        }
        assert!(
            verified.has(|effect| { matches!(effect, Capability::Journal(_)) }),
            "a verified vote quorum must issue L-QC aggregation"
        );
        verified = machine.persist(&verified.persist_job(), Until::Persist);
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
        .step(Input::Crypto(CryptoCompletion::Lqc(Box::new(
            LqcAggregateCompletion::prepare::<Sha256>(&aggregate, sequential, fixture.codec)
                .unwrap(),
        ))))
        .unwrap();
    // Aggregation completions always park; settling drains the completion into its staging
    // barrier, and the self-admission shows up in the artifact cache.
    assert_eq!(aggregated.status(), &StepStatus::Accepted);
    let aggregated = machine.settle(aggregated, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&artifact_id));
    machine.persist(&aggregated.persist_job(), Until::Persist);
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
    let shared = marked_digest(b"shared application child", 0);
    (0..fixture.codec.view_quorum())
        .map(|signer| {
            let mut extensions = vec![Extension::empty(); fixture.codec.chains()];
            let parent = if signer + 1 == fixture.codec.view_quorum() {
                marked_digest(b"Byzantine application parent", 0)
            } else {
                marked_digest(b"honest application parent", 0)
            };
            extensions[0] =
                Extension::new(vec![parent, shared], fixture.codec.extension_bound()).unwrap();
            let body = VoteBody::for_leader(
                DigestedLeader::new::<Sha256>(leader),
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
    let (mut machine, _) = start::<Sha256, MinPk>(fixture.profile(Role::Observer), Until::Persist);
    let id = artifact.id::<Sha256>();
    let is_vqc = matches!(artifact, Artifact::Vqc(_));
    let observed = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let verification = observed
        .find(|effect| match effect {
            Capability::Verify(job) => Some(job),
            _ => None,
        })
        .unwrap();
    let completion = verify::<Sha256, _, _>(
        verification,
        &mut test_rng(),
        &fixture.verifier,
        &Sequential,
    );
    assert_eq!(completion.validated_vqc(0).is_some(), is_vqc);
    assert_eq!(completion.validated_lqc(0).is_some(), !is_vqc);
    let projection = completion
        .validated_lqc(0)
        .map(|validated| Arc::clone(validated.derived.artifact.arc()));
    // Both certificate kinds carry compute-pool derivations beyond their verdicts.
    let verdict_bytes = size_of_val(&completion) + size_of_val(completion.verdicts());
    assert!(completion.resident_bytes().unwrap() > verdict_bytes);
    let accepted = machine.step(Input::Verified(completion)).unwrap();
    assert!(matches!(
        accepted.status(),
        StepStatus::Verified {
            valid: 1,
            invalid: 0
        }
    ));
    if let Some(projection) = &projection {
        let proof = &machine.store.artifacts[&id].artifact;
        let retained = machine.finality.finality_anchor(proof).unwrap();
        assert!(Arc::ptr_eq(retained.artifact.arc(), projection));
        let copy = Arc::new(proof.as_ref().clone());
        assert!(machine.finality.finality_anchor(&copy).is_none());
    }
    machine.settle(accepted, Until::Persist);
    assert!(machine.store.artifacts.contains_key(&id));
    if let Some(projection) = projection {
        assert!(Arc::ptr_eq(
            machine.durable.state.proposal_anchor.as_ref().unwrap(),
            &projection
        ));
    }
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

fn execute_objective_equivocation_trace<V: Variant>() {
    let fixture = Fixture::<V>::new();
    execute_leader_equivocation_trace(&fixture);
    execute_vote_equivocation_trace(&fixture);
    execute_producer_equivocation_trace(&fixture);
    execute_da_vote_equivocation_trace(&fixture);
    execute_transcript_equivocation_trace(&fixture);
}

/// Two signed leader blocks for one view attribute the leader.
fn execute_leader_equivocation_trace<V: Variant>(fixture: &Fixture<V>) {
    let leader = fixture.leader_with_two_block_path(1);
    let leader_signer = fixture.protocol.leader(leader.view());
    let alternate_leader = LeaderBlock::new(
        leader.round(),
        leader.parent(),
        marked_digest(b"alternate leader history", 1),
        leader.proposals().to_vec(),
        fixture.codec,
    )
    .unwrap();
    let signed_leader = fixture.signers[leader_signer.get() as usize]
        .sign_leader_block(leader)
        .unwrap();
    let signed_alternate = fixture.signers[leader_signer.get() as usize]
        .sign_leader_block(alternate_leader)
        .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::LeaderBlock(signed_leader),
        Artifact::LeaderBlock(signed_alternate),
        leader_signer,
    );
}

/// Conflicting votes, alone or in one batch, and a vote with a novote attribute the voter; a
/// nullify or a later view's vote does not.
fn execute_vote_equivocation_trace<V: Variant>(fixture: &Fixture<V>) {
    let leader = fixture.leader_with_two_block_path(1);
    let voter = Participant::new(3);
    let first_vote = fixture.signers[voter.get() as usize]
        .sign_vote(fixture.vote_body_at(&leader, 1))
        .unwrap();
    let second_vote = fixture.signers[voter.get() as usize]
        .sign_vote(fixture.vote_body_at(&leader, 2))
        .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::Vote(first_vote.clone()),
        Artifact::Vote(second_vote.clone()),
        voter,
    );
    assert_objective_fault_in_one_batch(
        fixture,
        Artifact::Vote(first_vote.clone()),
        Artifact::Vote(second_vote),
        voter,
    );
    let (mut machine, _) = start(fixture.profile(Role::Observer), Until::Persist);
    assert!(
        blocked(&fixture.verify(&mut machine, vec![Artifact::Vote(first_vote.clone())])).is_empty()
    );
    let second = fixture.signers[voter.get() as usize]
        .sign_vote(fixture.vote_body_at(&leader, 2))
        .unwrap();
    assert_eq!(
        blocked(&fixture.verify(&mut machine, vec![Artifact::Vote(second)])),
        vec![voter],
    );
    let third = fixture.signers[voter.get() as usize]
        .sign_vote(fixture.vote_body_at(&leader, 0))
        .unwrap();
    assert!(blocked(&fixture.verify(&mut machine, vec![Artifact::Vote(third)])).is_empty());
    assert_objective_fault(
        fixture,
        Artifact::Vote(first_vote.clone()),
        Artifact::NoVote(
            fixture.signers[voter.get() as usize]
                .sign_novote(leader.round())
                .unwrap(),
        ),
        voter,
    );
    assert_compatible(
        fixture,
        Artifact::Vote(first_vote.clone()),
        Artifact::Nullify(
            fixture.signers[voter.get() as usize]
                .sign_nullify(leader.round())
                .unwrap(),
        ),
    );

    let next_leader = fixture.leader_with_two_block_path(2);
    assert_compatible(
        fixture,
        Artifact::Vote(first_vote),
        Artifact::Vote(
            fixture.signers[voter.get() as usize]
                .sign_vote(fixture.vote_body_at(&next_leader, 1))
                .unwrap(),
        ),
    );
}

/// Producer forks attribute the producer: at one height, at the maximum height, against a signed
/// parent, and under saturated accountability state.
fn execute_producer_equivocation_trace<V: Variant>(fixture: &Fixture<V>) {
    let chain = ChainId::new(0);
    let producer = fixture.protocol.producer(chain).unwrap();
    let first_header = fixture.first_header(b"producer body");
    let fork_header = fixture.first_header(b"producer fork");
    assert_objective_fault(
        fixture,
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(first_header.clone())
                .unwrap(),
        ),
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(fork_header)
                .unwrap(),
        ),
        producer,
    );

    let signed_header = |height, marker| {
        let header = TransactionBlockHeader::new(
            fixture.protocol.epoch(),
            chain,
            Height::new(height),
            marked_digest(b"saturated producer parent", height),
            marked_digest(b"saturated producer body", marker),
        )
        .unwrap();
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(header)
                .unwrap(),
        )
    };
    let mut saturated = AccountabilityState::new(2);
    for artifact in [
        signed_header(10, 10),
        signed_header(20, 20),
        signed_header(30, 30),
    ] {
        let Artifact::TransactionBlock(block) = &artifact else {
            unreachable!()
        };
        assert!(fixture.verifier.verify_transaction_block(block));
        assert!(saturated.observe::<Sha256, V>(&artifact, None).is_empty());
    }
    assert_eq!(
        saturated.observe::<Sha256, V>(&signed_header(30, 31), None),
        vec![producer],
    );

    let maximum_header = TransactionBlockHeader::new(
        fixture.protocol.epoch(),
        chain,
        Height::new(u64::MAX),
        marked_digest(b"maximum parent", 0),
        marked_digest(b"maximum body", 0),
    )
    .unwrap();
    let maximum_fork = TransactionBlockHeader::new(
        fixture.protocol.epoch(),
        chain,
        Height::new(u64::MAX),
        marked_digest(b"maximum parent", 0),
        marked_digest(b"maximum fork", 0),
    )
    .unwrap();
    // Accountability attributes a fork at the maximum height without overflowing its neighbor
    // checks. Admission never reaches it there: the height window rejects both blocks first.
    let maximum = [maximum_header, maximum_fork].map(|header| {
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(header)
                .unwrap(),
        )
    });
    for [first, second] in [
        [maximum[0].clone(), maximum[1].clone()],
        [maximum[1].clone(), maximum[0].clone()],
    ] {
        let mut accountability = AccountabilityState::new(2);
        assert!(accountability.observe::<Sha256, V>(&first, None).is_empty());
        assert_eq!(
            accountability.observe::<Sha256, V>(&second, None),
            vec![producer]
        );
    }
    let (mut machine, _) = start::<Sha256, V>(fixture.profile(Role::Observer), Until::Persist);
    let rejected = machine.step(cohort::<Sha256, _>(maximum.to_vec())).unwrap();
    assert!(matches!(
        rejected.status(),
        StepStatus::Observed(results) if results.iter().all(|result| {
            result.status() == ObservationStatus::Rejected(Rejection::FutureHeight)
        })
    ));
    let contradictory_child = TransactionBlockHeader::new(
        fixture.protocol.epoch(),
        chain,
        Height::new(2),
        marked_digest(b"wrong signed parent", 1),
        marked_digest(b"producer body", 2),
    )
    .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(first_header)
                .unwrap(),
        ),
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(contradictory_child)
                .unwrap(),
        ),
        producer,
    );
}

/// A signer's second DA vote at a height takes no slot and blames no one, whatever header it
/// names; the producer's forked blocks are what prove the fault.
fn execute_da_vote_equivocation_trace<V: Variant>(fixture: &Fixture<V>) {
    // Only a chain's producer keeps the chain's DA votes, one per signer at each height, so no DA
    // vote has to prove an equivocation.
    let producer = fixture.protocol.producer(ChainId::new(0)).unwrap();
    let first_header = fixture.first_header(b"producer body");
    let da_fork_header = fixture.first_header(b"DA fork");
    let forks = [first_header.clone(), da_fork_header.clone()].map(|header| {
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(header)
                .unwrap(),
        )
    });
    let holding_forks = || {
        let (mut machine, _) = start(fixture.profile(Role::Validator(producer)), Until::Persist);
        assert_eq!(
            blocked(&fixture.verify(&mut machine, forks.to_vec())),
            vec![producer]
        );
        machine
    };
    let da_voter = Participant::new(4);
    let first_da_vote = fixture.signers[da_voter.get() as usize]
        .sign_da_vote(first_header)
        .unwrap();
    let forged_da_vote = Artifact::DaVote(DaVote::new(
        da_fork_header.clone(),
        first_da_vote.share().clone(),
    ));
    let first_da_vote = Artifact::DaVote(first_da_vote);
    let second_da_vote = Artifact::DaVote(
        fixture.signers[da_voter.get() as usize]
            .sign_da_vote(da_fork_header)
            .unwrap(),
    );
    let position_full = |step: &Step<V, Digest>| {
        matches!(step.status(), StepStatus::Observed(results)
            if results.last().map(|result| result.status())
                == Some(ObservationStatus::Rejected(Rejection::PositionFull)))
    };
    for [first, second] in [
        [first_da_vote.clone(), second_da_vote.clone()],
        [second_da_vote.clone(), first_da_vote.clone()],
        [first_da_vote.clone(), forged_da_vote],
    ] {
        let mut machine = holding_forks();
        assert!(blocked(&fixture.verify(&mut machine, vec![first])).is_empty());
        let rejected = machine.step(cohort::<Sha256, _>(vec![second])).unwrap();
        assert!(position_full(&rejected));
        assert!(blocked(&rejected).is_empty());
    }
    let mut machine = holding_forks();
    let batch = machine
        .step(cohort::<Sha256, _>(vec![first_da_vote, second_da_vote]))
        .unwrap();
    assert!(position_full(&batch));
}

/// A vote that conflicts with a signer's certificate transcript attributes that signer.
fn execute_transcript_equivocation_trace<V: Variant>(fixture: &Fixture<V>) {
    let leader = fixture.leader_with_two_block_path(1);
    let transcript_signer = Participant::new(0);
    let transcript_body = fixture.vote_body_at(&leader, 1);
    let messages = fixture
        .signers
        .iter()
        .take(fixture.codec.view_quorum())
        .map(|scheme| ViewMessage::Vote(scheme.sign_vote(transcript_body.clone()).unwrap()))
        .collect::<Vec<_>>();
    let vqc = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
        .unwrap();
    let conflicting = fixture.signers[transcript_signer.get() as usize]
        .sign_vote(fixture.vote_body_at(&leader, 2))
        .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::Vqc(vqc),
        Artifact::Vote(conflicting.clone()),
        transcript_signer,
    );

    let lqc_votes = messages
        .into_iter()
        .map(|message| match message {
            ViewMessage::Vote(vote) => vote,
            ViewMessage::NoVote(_) => unreachable!(),
        })
        .collect::<Vec<_>>();
    let lqc = fixture
        .verifier
        .assemble_lqc::<Sha256, _>(leader.clone(), &lqc_votes, &Sequential)
        .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::Lqc(lqc),
        Artifact::Vote(conflicting),
        transcript_signer,
    );

    let mut novote_messages = fixture
        .signers
        .iter()
        .skip(1)
        .take(fixture.codec.view_quorum() - 1)
        .map(|scheme| ViewMessage::Vote(scheme.sign_vote(transcript_body.clone()).unwrap()))
        .collect::<Vec<_>>();
    novote_messages.push(ViewMessage::NoVote(
        fixture.signers[transcript_signer.get() as usize]
            .sign_novote(leader.round())
            .unwrap(),
    ));
    let vqc = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader, &novote_messages, &Sequential)
        .unwrap();
    assert_objective_fault(
        fixture,
        Artifact::Vqc(vqc),
        Artifact::Vote(
            fixture.signers[transcript_signer.get() as usize]
                .sign_vote(transcript_body)
                .unwrap(),
        ),
        transcript_signer,
    );
}

#[test]
fn objective_equivocation_is_attributed_for_min_pk() {
    execute_objective_equivocation_trace::<MinPk>();
}

#[test]
fn objective_equivocation_is_attributed_for_min_sig() {
    execute_objective_equivocation_trace::<MinSig>();
}

#[test]
fn real_crypto_effects_execute_for_min_pk() {
    execute_real_crypto_effects::<MinPk>();
}

#[test]
fn real_crypto_effects_execute_for_min_sig() {
    execute_real_crypto_effects::<MinSig>();
}

#[test]
fn a_conflicting_da_vote_takes_no_second_slot() {
    let fixture = Fixture::<MinPk>::new();
    let producer = fixture.protocol.producer(ChainId::new(0)).unwrap();
    let headers =
        [b"conflict block".as_slice(), b"conflict fork"].map(|label| fixture.first_header(label));
    let (mut machine, _) = start(fixture.profile(Role::Validator(producer)), Until::Persist);
    let blocks = headers.clone().map(|header| {
        Artifact::TransactionBlock(
            fixture.signers[producer.get() as usize]
                .sign_transaction_block(header)
                .unwrap(),
        )
    });
    // The forked blocks themselves prove the producer faulty.
    assert_eq!(
        blocked(&fixture.verify(&mut machine, blocks.to_vec())),
        vec![producer]
    );

    let voter = Participant::new(4);
    let [held, conflicting] = headers.map(|header| {
        Artifact::DaVote(
            fixture.signers[voter.get() as usize]
                .sign_da_vote(header)
                .unwrap(),
        )
    });
    assert!(blocked(&fixture.verify(&mut machine, vec![held])).is_empty());
    let cached = machine.inspect().cached_artifacts();

    // The signer's slot is taken, so a vote for the other fork is rejected unverified and blames
    // no one.
    let rejected = machine
        .step(cohort::<Sha256, _>(vec![conflicting]))
        .unwrap();
    assert!(matches!(
        rejected.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Rejected(Rejection::PositionFull)
    ));
    assert!(blocked(&rejected).is_empty());
    assert_eq!(machine.inspect().cached_artifacts(), cached);
}
