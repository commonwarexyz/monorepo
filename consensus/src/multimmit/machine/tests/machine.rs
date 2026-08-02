use self::test_utils::{Runner, SymbolicPersistence, SymbolicVerifier, cohort};
use super::{contracts::Lane, *};
use crate::{
    Epochable, Viewable as _,
    multimmit::{
        config::{Config, LeaderSchedule, Limits},
        machine::{algebra::VqcExtraction, view::ViewState},
        types::{
            Activity, Anchor, Attestation, BlockRef, CertificateId, ChainId, ChainProposal,
            ConflictingVote, Context, DaCertificate, DaVote, EpochGenesis, Extension, Height,
            LeaderBlock, Lqc, NoVote, Nullification, Nullify, Position, ProposalParent,
            SignedLeaderBlock, SignedTransactionBlock, Tally, ThresholdShare, TipRecord,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Attributable, Epoch, Participant, Round, View, ViewDelta},
};
use commonware_codec::{Decode, Encode, EncodeSize as _, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::{
            group::{Private, Scalar},
            ops::{aggregate, sign_message},
            variant::{MinPk, Variant},
        },
    },
    certificate::Signers,
    sha256::Digest,
};
use commonware_math::algebra::Additive;
use commonware_utils::N5f1;
use core::{num::NonZeroUsize, time::Duration};
use proptest::{collection::vec as prop_vec, prelude::*};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

type TestMachine = Machine<Sha256, MinPk>;
type TestDurableJob = DurableJob<DurableEffect<MinPk, Digest>>;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_TEST";

#[test]
fn capabilities_preserve_inline_storage_and_ordered_mutation() {
    let effect = |generation| {
        Capability::Leader(LeaderCapability::ArmTimer(Timer::new(
            generation,
            Round::new(Epoch::zero(), View::zero()),
            Duration::ZERO,
        )))
    };
    let generation = |effect: &Capability<MinPk, Digest>| match effect {
        Capability::Leader(LeaderCapability::ArmTimer(timer)) => timer.generation(),
        _ => unreachable!("the test constructs only timer effects"),
    };

    let mut effects = Capabilities::None;
    assert!(effects.is_empty());

    effects.push(effect(1));
    assert!(matches!(effects, Capabilities::One(_)));
    assert_eq!(effects.iter().map(generation).collect::<Vec<_>>(), [1]);

    effects.push(effect(2));
    assert!(matches!(effects, Capabilities::Two(_)));
    assert_eq!(effects.iter().map(generation).collect::<Vec<_>>(), [1, 2]);

    effects.push(effect(3));
    assert!(matches!(effects, Capabilities::Many(_)));
    assert_eq!(
        effects.iter().map(generation).collect::<Vec<_>>(),
        [1, 2, 3]
    );

    assert_eq!(generation(&effects.remove(1)), 2);
    assert_eq!(generation(&effects.pop().expect("one effect remains")), 3);
    assert!(matches!(effects, Capabilities::One(_)));

    let generations = effects.into_iter().map(|effect| generation(&effect));
    assert_eq!(generations.collect::<Vec<_>>(), [1]);

    let singleton = Capabilities::from(vec![effect(4)]);
    assert!(matches!(singleton, Capabilities::One(_)));
}

fn digest(label: &[u8]) -> Digest {
    Sha256::hash(&[label])
}

fn genesis_tip_history(protocol: &Config<Digest>) -> Digest {
    genesis_tip_commitment::<Sha256>(protocol.genesis())
}

fn config(epoch: Epoch) -> Config<Digest> {
    config_for(epoch, 1, 2)
}

fn config_for(epoch: Epoch, participants: usize, pipeline_depth: u32) -> Config<Digest> {
    config_for_producers(
        epoch,
        participants,
        (0..participants).map(Participant::from_usize).collect(),
        pipeline_depth,
    )
}

fn config_for_producers(
    epoch: Epoch,
    participants: usize,
    producers: Vec<Participant>,
    pipeline_depth: u32,
) -> Config<Digest> {
    let tips = (0..producers.len())
        .map(|chain| {
            let label = format!("genesis {chain}");
            BlockRef::new(
                ChainId::new(chain as u32),
                Height::zero(),
                digest(label.as_bytes()),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        digest(b"leader genesis"),
        CertificateId::new(digest(b"vqc genesis")),
        CertificateId::new(digest(b"lqc genesis")),
        tips,
    )
    .unwrap();
    Config::new(
        epoch,
        NAMESPACE,
        participants,
        producers,
        Limits::new(pipeline_depth, 1).unwrap(),
        genesis,
    )
    .unwrap()
}

const fn resources() -> ResourceLimits {
    resources_with_max_artifact_bytes(16 * 1024)
}

const fn resources_with_max_artifact_bytes(max_artifact_bytes: usize) -> ResourceLimits {
    ResourceLimits::new(
        NonZeroUsize::new(max_artifact_bytes).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

const fn resources_with_capacities(
    max_cached_artifacts: usize,
    max_outbox_effects: usize,
) -> ResourceLimits {
    ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(max_cached_artifacts).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(max_outbox_effects).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

const fn resources_with_validation_batch(max_verification_batch: usize) -> ResourceLimits {
    ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(max_verification_batch).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

const fn resources_with_future_views(
    max_future_view_distance: u64,
    max_future_artifacts: usize,
) -> ResourceLimits {
    ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        max_future_view_distance,
        NonZeroUsize::new(max_future_artifacts).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

const fn resources_with_dependency_waiters(max_dependency_waiters: usize) -> ResourceLimits {
    ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(max_dependency_waiters).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

fn profile(role: Role) -> Profile<Sha256, MinPk> {
    profile_for(role, 1, 2)
}

fn profile_for(role: Role, participants: usize, pipeline_depth: u32) -> Profile<Sha256, MinPk> {
    profile_with_resources(role, participants, pipeline_depth, resources())
}

fn profile_for_producers(
    role: Role,
    participants: usize,
    producers: Vec<Participant>,
    pipeline_depth: u32,
) -> Profile<Sha256, MinPk> {
    let resources = resources();
    Profile::with_limits(
        config_for_producers(Epoch::new(7), participants, producers, pipeline_depth),
        role,
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(resources, participants),
            ..Tuning::default()
        },
        resources,
    )
    .unwrap()
}

/// Derives the widest retention window the supplied bounds can carry.
///
/// Production derives the bounds from the window; these tests fix the bounds first to drive the
/// overflow paths that derivation avoids, so the window follows from them instead.
fn retention_for(resources: ResourceLimits, participants: usize) -> ViewDelta {
    let live = u64::from(N5f1::l_quorum(participants)) + 3;
    let cache = (resources.max_cached_artifacts() as u64).saturating_sub(live);
    let forwarding = (resources.max_forwarded_certificates() as u64 / 2).saturating_sub(1);
    ViewDelta::new(cache.min(forwarding))
}

fn profile_with_resources(
    role: Role,
    participants: usize,
    pipeline_depth: u32,
    resources: ResourceLimits,
) -> Profile<Sha256, MinPk> {
    profile_with_retention(
        role,
        participants,
        pipeline_depth,
        resources,
        retention_for(resources, participants),
    )
}

fn profile_with_retention(
    role: Role,
    participants: usize,
    pipeline_depth: u32,
    resources: ResourceLimits,
    view_retention: ViewDelta,
) -> Profile<Sha256, MinPk> {
    Profile::with_limits(
        config_for(Epoch::new(7), participants, pipeline_depth),
        role,
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention,
            ..Tuning::default()
        },
        resources,
    )
    .unwrap()
}

fn persist(machine: &mut TestMachine, job: &PersistJob<MinPk, Digest>) -> Step<MinPk, Digest> {
    let step = machine
        .step(Input::Persisted(BarrierAck::new(
            job.id(),
            job.generation(),
            job.last_cursor(),
        )))
        .unwrap();
    settle(machine, step)
}

/// Acknowledges a barrier without folding follow-up scheduler work into the returned step.
fn persist_raw(machine: &mut TestMachine, job: &PersistJob<MinPk, Digest>) -> Step<MinPk, Digest> {
    machine
        .step(Input::Persisted(BarrierAck::new(
            job.id(),
            job.generation(),
            job.last_cursor(),
        )))
        .unwrap()
}

fn persist_job(step: &Step<MinPk, Digest>) -> PersistJob<MinPk, Digest> {
    persist_directive(step).into_parts().0
}

fn persist_directive(step: &Step<MinPk, Digest>) -> PersistDirective<MinPk, Digest> {
    let mut directives = step
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(directive)) => Some(directive),
            _ => None,
        });
    let directive = directives
        .next()
        .expect("one durable reservation must emit a persistence job");
    assert!(directives.next().is_none());
    directive.clone()
}

fn release_after_enqueue(step: &Step<MinPk, Digest>) -> Vec<TestDurableJob> {
    persist_directive(step).into_parts().2
}

const fn durable_job(effect: &Capability<MinPk, Digest>) -> Option<&TestDurableJob> {
    let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
        return None;
    };
    Some(job)
}

fn durable_effect(effect: &Capability<MinPk, Digest>) -> Option<&DurableEffect<MinPk, Digest>> {
    Some(durable_job(effect)?.request())
}

fn sign_request(job: &TestDurableJob) -> &SignRequest<MinPk, Digest> {
    let DurableEffect::Sign(request) = job.request() else {
        unreachable!("test helper only accepts signing jobs")
    };
    request
}

fn queued_effect_id(step: &Step<MinPk, Digest>) -> EffectId {
    let job = persist_job(step);
    let Change::OutboxQueued { id, .. } = job.events()[0].change() else {
        panic!("test effect reservation must queue one outbox effect");
    };
    *id
}

fn active_machine(role: Role) -> TestMachine {
    let mut machine = Machine::new(profile(role));
    let start = machine.step(Input::Start).unwrap();
    assert_eq!(start.status(), &StepStatus::DurabilityReserved);
    // The view timer arms at staging, alongside the generation barrier.
    assert!(matches!(
        start.capabilities(),
        [
            Capability::Leader(LeaderCapability::ArmTimer(_)),
            Capability::Durability(DurabilityCapability::Persist(_))
        ]
    ));
    let started = persist(&mut machine, &persist_job(&start));
    assert_eq!(started.status(), &StepStatus::Persisted);
    match role {
        Role::Validator(_) => {
            // The producer's signing choice stages behind the generation barrier and its
            // request releases at staging.
            assert!(matches!(
                started.capabilities(),
                [Capability::Durability(DurabilityCapability::Released(job)), Capability::Durability(DurabilityCapability::Persist(_))]
                    if matches!(job.request(), DurableEffect::Sign(_))
            ));
            let proposed = persist(&mut machine, &persist_job(&started));
            assert!(
                !proposed
                    .capabilities()
                    .iter()
                    .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))),
                "the choice acknowledgement must not release signing a second time"
            );
        }
        Role::Observer => assert!(started.capabilities().is_empty()),
    }
    assert!(machine.inspect().is_live());
    machine
}

fn active_runner(role: Role) -> Runner<Sha256, MinPk> {
    let mut runner = Runner::new(profile(role));
    let start = runner.submit(Input::Start).unwrap();
    let mut persistence = SymbolicPersistence;
    let unhandled = runner
        .drain(&mut persistence, start.into_capabilities())
        .unwrap();
    match role {
        Role::Validator(_) => assert!(matches!(
            unhandled.as_slice(),
            [Capability::Leader(LeaderCapability::ArmTimer(_)), Capability::Durability(DurabilityCapability::Released(job))]
                if matches!(job.request(), DurableEffect::Sign(_))
        )),
        Role::Observer => assert!(matches!(
            unhandled.as_slice(),
            [Capability::Leader(LeaderCapability::ArmTimer(_))]
        )),
    }
    assert!(runner.inspect().is_live());
    runner
}

fn sign_job(step: &Step<MinPk, Digest>) -> TestDurableJob {
    step.capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Sign(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("a durable signing choice must release one signing job")
}

fn attestation(signer: u32) -> Attestation<MinPk> {
    Attestation::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

fn threshold_share(signer: u32) -> ThresholdShare<MinPk> {
    ThresholdShare::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

fn symbolic_threshold_certificate(marker: u64) -> ThresholdCertificate<MinPk> {
    let private = Private::new(Scalar::from_u64(marker + 1));
    ThresholdCertificate::new(sign_message::<MinPk>(
        &private,
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_CERTIFICATE",
        b"symbolic certificate",
    ))
}

fn leader(machine: &TestMachine, view: u64) -> LeaderBlock<MinPk, Digest> {
    let protocol = machine.profile().protocol().clone();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                Vec::new(),
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(view)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        proposals,
        protocol.codec_config(),
    )
    .unwrap()
}

fn leader_artifact(machine: &TestMachine, view: u64) -> Artifact<MinPk, Digest> {
    Artifact::LeaderBlock(SignedLeaderBlock::new(
        leader(machine, view),
        attestation(0),
    ))
}

const fn proposal_request(block: LeaderBlock<MinPk, Digest>) -> ProposalRequest<MinPk, Digest> {
    ProposalRequest::new(block, ProposalParent::Genesis, false)
}

fn proposal_request_with_parent(
    machine: &TestMachine,
    view: View,
    parent: Vqc<MinPk, Digest>,
) -> ProposalRequest<MinPk, Digest> {
    let base = leader(machine, view.get());
    let parent_id = Artifact::Vqc(parent.clone())
        .provisions::<Sha256>()
        .into_iter()
        .find_map(|dependency| match dependency {
            Dependency::Vqc(certificate) => Some(certificate),
            Dependency::Leader { .. } => None,
        })
        .expect("a V-QC provides its certificate identifier");
    let block = LeaderBlock::new(
        base.round(),
        parent_id,
        parent.leader().history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    ProposalRequest::new(block, ProposalParent::Exact(Arc::new(parent)), true)
}

fn vote_artifact(
    machine: &TestMachine,
    leader: &LeaderBlock<MinPk, Digest>,
) -> Artifact<MinPk, Digest> {
    let body = VoteBody::for_leader::<Sha256, MinPk>(
        leader,
        vec![Position::new(0)],
        vec![Extension::new(Vec::new(), 1).unwrap()],
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    Artifact::Vote(Vote::new(body, attestation(0)))
}

fn view_vote(
    machine: &TestMachine,
    leader: &LeaderBlock<MinPk, Digest>,
    signer: u32,
) -> Vote<MinPk, Digest> {
    let chains = machine.profile().protocol().codec_config().chains();
    let body = VoteBody::for_leader::<Sha256, MinPk>(
        leader,
        vec![Position::new(0); chains],
        (0..chains)
            .map(|_| Extension::new(Vec::new(), 1).unwrap())
            .collect(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    Vote::new(body, attestation(signer))
}

fn no_vote(machine: &TestMachine, view: View, signer: u32) -> NoVote<MinPk> {
    NoVote::new(
        Round::new(machine.profile().protocol().epoch(), view),
        attestation(signer),
    )
    .unwrap()
}

fn nullify(machine: &TestMachine, view: View, signer: u32) -> Nullify<MinPk> {
    Nullify::new(
        Round::new(machine.profile().protocol().epoch(), view),
        threshold_share(signer),
    )
    .unwrap()
}

fn symbolic_nullification(machine: &TestMachine, view: View, marker: u64) -> Nullification<MinPk> {
    let certificate = symbolic_threshold_certificate(marker);
    Nullification::new(
        Round::new(machine.profile().protocol().epoch(), view),
        certificate,
    )
    .unwrap()
}

#[test]
fn durable_effect_signature_references_cover_every_variant() {
    let machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let view = View::new(1);
    let own: Arc<Artifact<MinPk, Digest>> = Arc::new(Artifact::NoVote(no_vote(&machine, view, 0)));
    let foreign: Arc<Artifact<MinPk, Digest>> =
        Arc::new(Artifact::NoVote(no_vote(&machine, view, 1)));
    let aggregate: Arc<Artifact<MinPk, Digest>> = Arc::new(Artifact::Nullification(
        symbolic_nullification(&machine, view, 7),
    ));
    let publications = |artifact: Arc<Artifact<MinPk, Digest>>| {
        [
            ("Broadcast", DurableEffect::Broadcast(Arc::clone(&artifact))),
            (
                "BroadcastBatch",
                DurableEffect::BroadcastBatch(Arc::from([
                    Arc::clone(&foreign),
                    Arc::clone(&artifact),
                ])),
            ),
            (
                "Send",
                DurableEffect::Send(SendRequest::new(Participant::new(5), Arc::clone(&artifact))),
            ),
            (
                "SendBatch",
                DurableEffect::SendBatch(Arc::from([
                    SendRequest::new(Participant::new(5), Arc::clone(&foreign)),
                    SendRequest::new(Participant::new(5), Arc::clone(&artifact)),
                ])),
            ),
        ]
    };

    for (variant, effect) in publications(Arc::clone(&own)) {
        assert!(
            effect.references_own_signature(Some(Participant::new(0))),
            "{variant} must recognize an own signature"
        );
        assert!(
            !effect.references_own_signature(None),
            "{variant} must not attribute an individual signature to an observer"
        );
    }
    for (variant, effect) in publications(Arc::clone(&foreign)) {
        assert!(
            !effect.references_own_signature(Some(Participant::new(0))),
            "{variant} must reject a foreign signature"
        );
        assert!(
            !effect.references_own_signature(None),
            "{variant} must not attribute a foreign signature to an observer"
        );
    }
    for (variant, effect) in publications(Arc::clone(&aggregate)) {
        assert!(
            effect.references_own_signature(Some(Participant::new(0))),
            "{variant} must conservatively recognize an aggregate"
        );
        assert!(
            effect.references_own_signature(None),
            "{variant} must conservatively recognize an aggregate for an observer"
        );
    }

    let round = Round::new(machine.profile().protocol().epoch(), view);
    let signing: [DurableEffect<MinPk, Digest>; 2] = [
        DurableEffect::Sign(SignRequest::NoVote { round }),
        DurableEffect::SignBatch(Arc::from([SignRequest::NoVote { round }])),
    ];
    for effect in signing {
        assert!(!effect.references_own_signature(Some(Participant::new(0))));
        assert!(!effect.references_own_signature(None));
    }

    let proposal = DurableEffect::Propose(ProposalPublication::new(
        Arc::new(SignedLeaderBlock::new(leader(&machine, 1), attestation(1))),
        ProposalParent::Genesis,
        false,
    ));
    assert!(proposal.references_own_signature(Some(Participant::new(0))));
    assert!(proposal.references_own_signature(None));
}

fn vqc(
    machine: &TestMachine,
    leader: LeaderBlock<MinPk, Digest>,
    messages: &[ViewMessage<MinPk, Digest>],
) -> Vqc<MinPk, Digest> {
    let leader_digest = leader.digest::<Sha256>();
    let votes = messages.iter().filter_map(|message| match message {
        ViewMessage::Vote(vote) if vote.body().leader() == leader_digest => {
            Some((vote.signer(), vote.body().clone()))
        }
        _ => None,
    });
    let tally = Tally::from_votes::<MinPk, Sha256, _>(
        &leader,
        votes,
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let novoters = Signers::from(
        machine.profile().protocol().codec_config().participants(),
        messages.iter().filter_map(|message| match message {
            ViewMessage::NoVote(vote) => Some(vote.signer()),
            _ => None,
        }),
    );
    Vqc::new(
        leader,
        tally,
        novoters,
        Vec::new(),
        aggregate::Signature::<MinPk>::zero(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap()
}

fn lqc(
    machine: &TestMachine,
    leader: LeaderBlock<MinPk, Digest>,
    votes: &[Vote<MinPk, Digest>],
) -> Lqc<MinPk, Digest> {
    let tally = Tally::from_votes::<MinPk, Sha256, _>(
        &leader,
        votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    Lqc::new(
        leader,
        tally,
        aggregate::Signature::<MinPk>::zero(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap()
}

fn view_one_vqc(machine: &TestMachine) -> Vqc<MinPk, Digest> {
    let proposed = leader(machine, 1);
    let messages = [
        ViewMessage::Vote(view_vote(machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(machine, View::new(1), 4)),
    ];
    vqc(machine, proposed, &messages)
}

fn leader_extending_view_one_vqc(
    machine: &TestMachine,
    view: u64,
    parent: &Vqc<MinPk, Digest>,
) -> (LeaderBlock<MinPk, Digest>, Digest) {
    let protocol = machine.profile().protocol();
    let history = TipRecord::new(
        parent.leader().history(),
        protocol.genesis().tips().to_vec(),
    )
    .unwrap()
    .commitment::<Sha256>();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(view)),
        parent.id::<Sha256>(),
        history,
        leader(machine, view).proposals().to_vec(),
        protocol.codec_config(),
    )
    .unwrap();
    (leader, history)
}

fn start_profile(profile: Profile<Sha256, MinPk>) -> (TestMachine, Step<MinPk, Digest>) {
    let mut machine = Machine::new(profile);
    let start = machine.step(Input::Start).unwrap();
    let job = persist_job(&start);
    // The view timer arms at staging; fold it into the returned step so callers keep one
    // handle to both the timer and the follow-up staging the acknowledgement emits.
    let volatile = start
        .into_capabilities()
        .into_iter()
        .filter(|effect| {
            !matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            )
        })
        .collect::<Vec<_>>();
    let started = persist(&mut machine, &job);
    let status = started.status().clone();
    let (effects, activities) = started.into_parts();
    let merged: Capabilities<MinPk, Digest> = volatile.into_iter().chain(effects).collect();
    (machine, Step::for_tests(status, merged, activities))
}

fn observe(
    machine: &mut TestMachine,
    artifact: Artifact<MinPk, Digest>,
) -> VerifyJob<MinPk, Digest> {
    let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    assert_eq!(results[0].status(), ObservationStatus::Scheduled);
    let [Capability::Verification(VerificationCapability::Verify(job))] = step.capabilities()
    else {
        panic!("one observed artifact must emit one verification job");
    };
    job.clone()
}

fn record_view_fact(
    machine: &mut TestMachine,
    observation: Observation,
    artifact: Artifact<MinPk, Digest>,
) {
    let artifact = Arc::new(artifact);
    let profile = machine.profile.clone();
    machine
        .views
        .observe::<Sha256>(artifact.id::<Sha256>(), observation, &artifact, &profile)
        .unwrap();
}

fn record_da_recovery_candidate(machine: &mut TestMachine, label: &[u8]) {
    let chain = match machine.profile().role() {
        Role::Validator(participant) => participant,
        Role::Observer => panic!("a DA recovery candidate requires a producer role"),
    };
    let genesis = machine.profile().protocol().genesis().tips()[chain.get() as usize];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(chain.get()),
        Height::new(1),
        genesis.digest(),
        digest(label),
    )
    .unwrap();
    machine
        .chain
        .observe_producer_choice::<Sha256>(&header)
        .unwrap();
    for signer in 0..4 {
        let artifact = Artifact::DaVote(DaVote::new(header.clone(), threshold_share(signer)));
        machine
            .chain
            .observe::<Sha256>(
                artifact.id::<Sha256>(),
                Observation::new(1, signer),
                &artifact,
                machine.durable.generation,
            )
            .unwrap();
    }
}

/// Folds scheduler work into a step until the machine stages a durable event or quiesces.
///
/// Staging is application, so the stop condition is the event cursor, not the barrier: a settled
/// step carries what the old inline drive produced, namely one newly staged batch plus every
/// volatile effect derived on the way there. That batch reaches the caller as an
/// [`Capability::Durability`] wrapping a [`DurabilityCapability::Persist`] unless an earlier barrier
/// is still in flight, in which case group commit holds it open and it emits when that barrier
/// acknowledges.
fn settle(machine: &mut TestMachine, step: Step<MinPk, Digest>) -> Step<MinPk, Digest> {
    const MAX_POLLS: usize = 4_096;

    let status = step.status().clone();
    let (mut effects, mut activities) = step.into_parts();
    for _ in 0..MAX_POLLS {
        if effects.iter().any(|effect| {
            matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            )
        }) {
            return Step::for_tests(status, effects, activities);
        }
        let cursor = machine.durable.cursor;
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        let (emitted, accepted) = result.into_parts();
        let quiesced = emitted.is_empty() && !work_remaining;
        effects.extend(emitted);
        activities.extend(accepted);
        if quiesced || machine.durable.cursor != cursor {
            return Step::for_tests(status, effects, activities);
        }
    }
    panic!(
        "machine did not stage a durable event or quiesce after {MAX_POLLS} polls at view {:?}, cursor {:?}",
        machine.durable.view, machine.durable.cursor,
    );
}

/// Applies a verification completion without folding scheduler work afterward.
fn complete_raw(machine: &mut TestMachine, job: &VerifyJob<MinPk, Digest>, valid: bool) {
    let verdicts = job
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), valid))
        .collect();
    machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            verdicts,
        )))
        .unwrap();
}

fn complete(machine: &mut TestMachine, job: &VerifyJob<MinPk, Digest>, valid: bool) {
    let verdicts = job
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), valid))
        .collect();
    let step = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            verdicts,
        )))
        .unwrap();
    settle(machine, step);
}

struct RecoveredVoteSigning {
    machine: TestMachine,
    sign: TestDurableJob,
    leader: LeaderBlock<MinPk, Digest>,
    signer: Participant,
}

fn recover_vote_signing(resources: ResourceLimits) -> RecoveredVoteSigning {
    let scheduled = LeaderSchedule::round_robin(6).leader(View::new(1));
    let signer = Participant::new((scheduled.get() + 1) % 6);
    let role = Role::Validator(signer);
    let profile = profile_with_resources(role, 6, 2, resources);
    let (mut machine, _) = start_profile(profile.clone());
    let proposed = leader(&machine, 1);
    let request = SignRequest::Vote(VoteRequest::new(
        view_vote(&machine, &proposed, signer.get()).body().clone(),
    ));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(request))
        .unwrap();
    persist(&mut machine, &persist_job(&reserved));

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restored, &persist_job(&recovery));
    let sign = sign_job(&recovered);
    RecoveredVoteSigning {
        machine: restored,
        sign,
        leader: proposed,
        signer,
    }
}

fn complete_with_step(
    machine: &mut TestMachine,
    job: &VerifyJob<MinPk, Digest>,
    valid: bool,
) -> Step<MinPk, Digest> {
    let verdicts = job
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), valid))
        .collect();
    let step = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            verdicts,
        )))
        .unwrap();
    settle(machine, step)
}

fn mismatched_resolution_proof(machine: &TestMachine) -> ViewProof<MinPk, Digest> {
    ViewProof::Nullification(Box::new(symbolic_nullification(
        machine,
        View::new(u64::MAX),
        0,
    )))
}

fn drive_poll_and_persist(
    machine: &mut TestMachine,
    step: Step<MinPk, Digest>,
) -> (Capabilities<MinPk, Digest>, usize) {
    let mut effects = step.into_capabilities();
    let mut unhandled = Capabilities::None;
    let mut requeues = 0;
    for turn in 0..256 {
        if let Some(index) = effects.iter().position(|effect| {
            matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            )
        }) {
            for _ in 0..index {
                unhandled.push(effects.remove(0));
            }
            let Capability::Durability(DurabilityCapability::Persist(directive)) =
                effects.remove(0)
            else {
                unreachable!("the selected effect is a persistence job")
            };
            let (job, _, release_after_enqueue, _) = directive.into_parts();
            unhandled.extend(
                release_after_enqueue
                    .into_iter()
                    .map(|job| Capability::Durability(DurabilityCapability::Released(job))),
            );
            effects.extend(persist(machine, &job).into_capabilities());
            continue;
        }

        unhandled.extend(effects);

        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        effects = result.into_capabilities();
        requeues += usize::from(work_remaining);
        if effects.is_empty() && !work_remaining {
            return (unhandled, requeues);
        }

        assert!(turn < 255, "machine polling did not quiesce: {effects:?}");
    }

    unreachable!("the bounded polling loop returns or panics")
}

#[test]
fn pool_finality_precedes_lqc_assembly_and_grows_monotonically() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = complete_with_step(&mut machine, &vote, true);
        if signer < 4 {
            assert!(
                step.activities()
                    .iter()
                    .all(|activity| !matches!(activity, Activity::LeaderFinalized { .. }))
            );
            assert!(machine.inspect().finality().is_empty());
            assert!(step.capabilities().iter().all(|effect| !matches!(
                effect,
                Capability::Leader(LeaderCapability::AggregateLqc(_))
            )));
            continue;
        }
        assert_eq!(
            step.activities()
                .iter()
                .filter(|activity| matches!(activity, Activity::LeaderFinalized { .. }))
                .count(),
            1
        );
        // Finalization stages ordering barriers before the drive derives aggregation, so the
        // releasing completion is folded through every barrier it stages.
        let (effects, _) = drive_poll_and_persist(&mut machine, step);
        aggregate = effects.iter().find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
            _ => None,
        });
    }

    let aggregate = aggregate.expect("the n-f vote must schedule L-QC assembly");
    assert_eq!(
        aggregate
            .votes()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
    let inspection = machine.inspect();
    let [pool] = inspection.pools() else {
        panic!("one exact leader must have one direct pool");
    };
    assert_eq!(pool.votes(), 5);
    assert!(pool.finalized());
    assert!(pool.lqc_pending());
    let [fact] = inspection.finality() else {
        panic!("the direct pool must finalize before aggregation completes");
    };
    assert_eq!(fact.votes(), 5);

    let last = Artifact::Vote(view_vote(&machine, &proposed, 5));
    let last = observe(&mut machine, last);
    let grown = complete_with_step(&mut machine, &last, true);
    assert!(
        grown
            .activities()
            .iter()
            .all(|activity| !matches!(activity, Activity::LeaderFinalized { .. }))
    );
    let (effects, _) = drive_poll_and_persist(&mut machine, grown);
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateLqc(_))
    )));
    assert_eq!(machine.inspect().pools()[0].votes(), 6);
    assert_eq!(machine.inspect().finality()[0].votes(), 6);
}

#[test]
fn full_publication_outbox_does_not_block_view_certificate_assembly() {
    let limits = resources_with_capacities(32, 1);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    let filler = Arc::new(leader_artifact(&machine, 10));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(filler))
        .unwrap();
    persist(&mut machine, &persist_job(&reserved));
    assert_eq!(machine.snapshot().outbox().len(), 1);

    let proposed = leader(&machine, 1);
    let proposal = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(0),
    )));
    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        proposal.as_ref().clone(),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, artifact) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), artifact);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
    assert_eq!(machine.snapshot().outbox().len(), 1);
}

#[test]
fn batched_barriers_preserve_the_durable_event_sequence() {
    // Budget size decides how many staged facts share one barrier, and must never change the
    // durable event sequence itself: a batch is a framing choice, not a semantic one.
    let drain = |budget: usize| {
        let role = Role::Validator(Participant::new(0));
        let mut machine = active_machine(role);
        let epoch = machine.profile().protocol().epoch();

        // Three parked signing completions are the batchable class.
        let mut signings = Vec::new();
        let mut artifacts = Vec::new();
        for view in 10..13 {
            let view = View::new(view);
            let reserved = machine
                .reserve_test_effect(DurableEffect::Sign(SignRequest::Nullify {
                    round: Round::new(epoch, view),
                }))
                .unwrap();
            // The signing request carries no signature out, so it releases at staging.
            signings.push(sign_job(&reserved));
            persist_raw(&mut machine, &persist_job(&reserved));
            artifacts.push(Artifact::Nullify(nullify(&machine, view, 0)));
        }
        for (signing, artifact) in signings.iter().zip(&artifacts) {
            machine
                .step(Input::EffectCompleted(EffectCompletion::Signed {
                    id: signing.id(),
                    generation: signing.generation(),
                    artifact: Arc::new(artifact.clone()),
                }))
                .unwrap();
        }

        let budget = NonZeroUsize::new(budget).unwrap();
        let mut events = Vec::new();
        let mut barriers = 0usize;
        for _ in 0..256 {
            let result = machine.poll(budget).unwrap();
            let work_remaining = result.work_remaining();
            let mut staged = None;
            for effect in result.into_capabilities() {
                if let Capability::Durability(DurabilityCapability::Persist(job)) = effect {
                    barriers += 1;
                    events.extend(job.events().iter().cloned());
                    staged = Some(job);
                }
            }
            if let Some(job) = staged {
                persist_raw(&mut machine, &job);
            } else if !work_remaining {
                break;
            }
        }
        (events, barriers, machine.inspect())
    };

    let (serial_events, serial_barriers, serial_state) = drain(1);
    let (batched_events, batched_barriers, batched_state) = drain(16);
    assert_eq!(serial_events, batched_events);
    assert_eq!(serial_state, batched_state);
    assert!(
        batched_barriers < serial_barriers,
        "a larger budget must coalesce barriers: {batched_barriers} vs {serial_barriers}"
    );
}

#[test]
fn direct_finality_id_commits_to_the_sticky_vote_evidence() {
    let finalize = |branch: &str| {
        let profile = profile_for(Role::Observer, 6, 2);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        complete(&mut machine, &proposal, true);

        for signer in 0..5 {
            let extensions = (0..6)
                .map(|chain| {
                    let label = format!("{branch} {chain}");
                    Extension::new(vec![digest(label.as_bytes())], 1).unwrap()
                })
                .collect();
            let body = VoteBody::for_leader::<Sha256, MinPk>(
                &proposed,
                vec![Position::new(0); 6],
                extensions,
                machine.profile().protocol().codec_config(),
            )
            .unwrap();
            let vote = observe(
                &mut machine,
                Artifact::Vote(Vote::new(body, attestation(signer))),
            );
            complete(&mut machine, &vote, true);
        }

        machine.inspect().finality()[0].clone()
    };

    let left = finalize("left");
    let right = finalize("right");
    assert_eq!(left.round(), right.round());
    assert_eq!(left.leader(), right.leader());
    assert_eq!(left.votes(), right.votes());
    assert_ne!(left.blocks(), right.blocks());
    assert_ne!(left.id(), right.id());
}

#[test]
fn pool_stickiness_follows_observation_not_verification_completion() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let earlier = Artifact::Vote(view_vote(&machine, &proposed, 0));
    let earlier = observe(&mut machine, earlier);
    let mut extensions = vec![Extension::empty(); 6];
    extensions[0] = Extension::new(vec![digest(b"later extension")], 1).unwrap();
    let later_body = VoteBody::for_leader::<Sha256, MinPk>(
        &proposed,
        vec![Position::new(0); 6],
        extensions,
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let later = observe(
        &mut machine,
        Artifact::Vote(Vote::new(later_body, attestation(0))),
    );
    let others = (1..5)
        .map(|signer| {
            let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
            observe(&mut machine, artifact)
        })
        .collect::<Vec<_>>();

    complete(&mut machine, &later, true);
    for vote in &others {
        complete(&mut machine, vote, true);
    }
    assert_eq!(machine.inspect().pools()[0].votes(), 0);

    let completed = complete_with_step(&mut machine, &earlier, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, completed);
    let aggregate = effects
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job),
            _ => None,
        })
        .expect("resolving the earliest observation must release the pool");
    let selected = aggregate
        .votes()
        .find(|vote| vote.signer() == Participant::new(0))
        .unwrap();
    assert!(selected.body().extensions()[0].is_empty());
}

#[test]
fn completion_permutations_preserve_sticky_selection() {
    let run = |completion_order: [usize; 2]| {
        let (mut machine, _) = start_profile(profile_for(Role::Observer, 1, 2));
        let protocol = machine.profile().protocol();
        let genesis = protocol.genesis().tips()[0];
        let first_commitment = digest(b"sticky first");
        let second_commitment = digest(b"sticky second");
        let first_block = TransactionBlockHeader::new(
            protocol.epoch(),
            genesis.chain(),
            Height::new(1),
            genesis.digest(),
            first_commitment,
        )
        .unwrap()
        .block_ref::<Sha256>();
        let second_block = TransactionBlockHeader::new(
            protocol.epoch(),
            genesis.chain(),
            Height::new(2),
            first_block.digest(),
            second_commitment,
        )
        .unwrap()
        .block_ref::<Sha256>();
        let proposal = ChainProposal::new(
            genesis.chain(),
            Anchor::Tip(genesis),
            vec![first_commitment, second_commitment],
            protocol.codec_config().pipeline_depth(),
        )
        .unwrap();
        let proposed = LeaderBlock::new(
            Round::new(protocol.epoch(), View::new(2)),
            protocol.genesis().vqc(),
            genesis_tip_history(protocol),
            vec![proposal],
            protocol.codec_config(),
        )
        .unwrap();
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        complete(&mut machine, &verification, true);

        let earlier_body = VoteBody::for_leader::<Sha256, MinPk>(
            &proposed,
            vec![Position::new(1)],
            vec![Extension::empty()],
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        let later_body = VoteBody::for_leader::<Sha256, MinPk>(
            &proposed,
            vec![Position::new(2)],
            vec![Extension::empty()],
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        let earlier = observe(
            &mut machine,
            Artifact::Vote(Vote::new(earlier_body.clone(), attestation(0))),
        );
        let later = observe(
            &mut machine,
            Artifact::Vote(Vote::new(later_body, attestation(0))),
        );

        let jobs = [earlier, later];
        let mut aggregate = None;
        for index in completion_order {
            let step = complete_with_step(&mut machine, &jobs[index], true);
            let (effects, _) = drive_poll_and_persist(&mut machine, step);
            for effect in effects {
                if let Capability::Leader(LeaderCapability::AggregateLqc(job)) = effect {
                    assert!(
                        aggregate.replace(job).is_none(),
                        "one pool must release only one aggregation job"
                    );
                }
            }
        }

        let aggregate = aggregate.expect("settling the pool must release an aggregation job");
        let selected = aggregate.votes().collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].signer(), Participant::new(0));
        assert_eq!(selected[0].body(), &earlier_body);

        let inspection = machine.inspect();
        let [direct] = inspection.finality() else {
            panic!("one direct finality fact must select the sticky vote");
        };
        assert!(matches!(direct.id(), FinalityId::Direct(_)));
        assert_eq!(direct.votes(), 1);
        assert_eq!(direct.positions(), &[Position::new(1)]);
        assert_eq!(direct.blocks(), &[first_block]);
        assert_ne!(first_block, second_block);

        direct.clone()
    };

    assert_eq!(run([0, 1]), run([1, 0]));
}

#[test]
fn context_invalid_vote_does_not_poison_the_sticky_slot() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let invalid_body = VoteBody::new(
        proposed.round(),
        proposed.digest::<Sha256>(),
        vec![Position::new(1); 6],
        vec![Extension::empty(); 6],
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let invalid = observe(
        &mut machine,
        Artifact::Vote(Vote::new(invalid_body, attestation(0))),
    );
    let valid_body = view_vote(&machine, &proposed, 0).body().clone();
    let valid = observe(
        &mut machine,
        Artifact::Vote(Vote::new(valid_body.clone(), attestation(0))),
    );

    complete(&mut machine, &valid, true);
    assert_eq!(machine.inspect().pools()[0].votes(), 0);
    complete(&mut machine, &invalid, true);
    assert_eq!(machine.inspect().pools()[0].votes(), 1);

    for signer in 1..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let verification = observe(&mut machine, vote);
        let step = complete_with_step(&mut machine, &verification, true);
        if signer != 4 {
            continue;
        }
        let (effects, _) = drive_poll_and_persist(&mut machine, step);
        let aggregate = effects
            .iter()
            .find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job),
                _ => None,
            })
            .unwrap();
        assert_eq!(aggregate.votes().next().unwrap().body(), &valid_body);
    }
}

#[test]
fn authenticated_peer_artifact_cannot_rewrite_a_local_vote_choice() {
    let (mut machine, _) = start_profile(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let proposed = leader(&machine, 2);
    let local = view_vote(&machine, &proposed, 0).body().clone();
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::Vote(VoteRequest::new(
            local,
        ))))
        .unwrap();
    persist(&mut machine, &persist_job(&reserved));

    // A peer can relay any authenticated artifact, including an equivocation signed by this
    // process's identity in a Twins execution. Network admission must not reinterpret it as a new
    // local signing decision; only the journal can establish that decision.
    let conflicting = Artifact::NoVote(no_vote(&machine, View::new(2), 0));
    let conflicting = observe(&mut machine, conflicting);
    let completed = complete_with_step(&mut machine, &conflicting, true);
    assert!(matches!(completed.status(), StepStatus::Verified { .. }));
}

#[test]
fn independent_finality_pools_aggregate_in_parallel() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    // Same-view twins keep both pools within the retained diagnostic window, so neither
    // aggregation can be retired as moot while the other is still scheduling.
    let base = leader(&machine, 2);
    let twin = LeaderBlock::new(
        base.round(),
        machine.profile().protocol().genesis().vqc(),
        genesis_tip_history(machine.profile().protocol()),
        {
            let mut proposals = base.proposals().to_vec();
            proposals[0] = ChainProposal::new(
                proposals[0].anchor().chain(),
                proposals[0].anchor().clone(),
                vec![digest(b"twin payload")],
                machine.profile().protocol().codec_config().pipeline_depth(),
            )
            .unwrap();
            proposals
        },
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let leaders = [base, twin];
    for proposed in &leaders {
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
        );
        complete(&mut machine, &verification, true);
        for signer in 0..4 {
            let vote = Artifact::Vote(view_vote(&machine, proposed, signer));
            let verification = observe(&mut machine, vote);
            complete(&mut machine, &verification, true);
        }
    }

    let step = machine
        .step(cohort::<Sha256, _>(
            leaders
                .iter()
                .map(|proposed| Artifact::Vote(view_vote(&machine, proposed, 4)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = step.capabilities()
    else {
        panic!("the final votes must share one verification cohort");
    };
    let completed = complete_with_step(&mut machine, job, true);
    // Ordering interleaves with aggregation scheduling and may pause on header resolution, so
    // count aggregation jobs across a bounded number of scheduler turns instead of expecting
    // both in one pass.
    let mut jobs = 0;
    let mut effects = completed.into_capabilities();
    for _ in 0..32 {
        let mut staged = None;
        for effect in effects {
            match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(_)) => jobs += 1,
                Capability::Durability(DurabilityCapability::Persist(job)) => staged = Some(job),
                _ => {}
            }
        }
        if let Some(job) = staged {
            persist_raw(&mut machine, &job);
        }
        if jobs == 2 {
            break;
        }
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        effects = result.into_capabilities();
        if effects.is_empty() && !work_remaining {
            break;
        }
    }
    assert_eq!(jobs, 2);
}

#[test]
fn inbound_lqc_finalizes_without_parent_resolution() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 2);
    let proposed = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"missing parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
    let certificate_id = certificate.id::<Sha256>();
    let verification = observe(&mut machine, certificate);
    let completed = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, completed);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    let inspection = machine.inspect();
    let fact = inspection
        .finality()
        .iter()
        .find(|fact| fact.id() == FinalityId::Lqc(certificate_id))
        .expect("an authenticated L-QC must establish finality immediately");
    assert_eq!(fact.id(), FinalityId::Lqc(certificate_id));
    assert_eq!(fact.votes(), 5);
    assert_eq!(inspection.pools()[0].votes(), 5);
    assert!(inspection.pools()[0].finalized());

    let retried = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(
        retried
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_))))
    );
}

#[test]
fn inbound_lqc_votes_extend_the_arrival_first_pool() {
    let run = |raw_vote_first: bool| {
        let profile = profile_for(Role::Observer, 6, 2);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let mut votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let mut extensions = vec![Extension::empty(); 6];
        extensions[0] = Extension::new(vec![digest(b"beyond final tip")], 1).unwrap();
        let body = VoteBody::for_leader::<Sha256, MinPk>(
            &proposed,
            vec![Position::new(0); 6],
            extensions,
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        votes[0] = Vote::new(body, attestation(0));

        let raw = Artifact::Vote(view_vote(&machine, &proposed, 5));
        let certificate = Artifact::Lqc(lqc(&machine, proposed, &votes));
        let (first, second) = if raw_vote_first {
            (raw, certificate)
        } else {
            (certificate, raw)
        };
        for artifact in [first, second] {
            let verification = observe(&mut machine, artifact);
            complete(&mut machine, &verification, true);
        }

        let inspection = machine.inspect();
        let certified = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .unwrap();
        let direct = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .unwrap();
        assert_eq!(certified.votes(), 5);
        assert!(!certified.settled()[0]);
        assert_eq!(direct.votes(), 6);
        assert!(direct.settled()[0]);
        assert_eq!(inspection.pools()[0].votes(), 6);
        direct.clone()
    };

    assert_eq!(run(false), run(true));
}

#[test]
fn finality_retains_one_certificate_witness_per_pool() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);

    for signers in [0..5, 1..6] {
        let votes = signers
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let certificate = Artifact::Lqc(lqc(&machine, proposed.clone(), &votes));
        let verification = observe(&mut machine, certificate);
        complete(&mut machine, &verification, true);
    }

    let inspection = machine.inspect();
    assert_eq!(inspection.pools().len(), 1);
    assert_eq!(inspection.pools()[0].votes(), 6);
    assert_eq!(
        inspection
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .count(),
        1
    );
}

#[test]
fn inbound_lqc_reserves_its_votes_before_verification() {
    let run = |complete_raw_first: bool| {
        let profile = profile_for(Role::Observer, 6, 2);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let mut votes = (0..5)
            .map(|signer| view_vote(&machine, &proposed, signer))
            .collect::<Vec<_>>();
        let mut extensions = vec![Extension::empty(); 6];
        extensions[0] = Extension::new(vec![digest(b"certificate vote")], 1).unwrap();
        let certificate_body = VoteBody::for_leader::<Sha256, MinPk>(
            &proposed,
            vec![Position::new(0); 6],
            extensions,
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        votes[0] = Vote::new(certificate_body, attestation(0));

        let certificate = Artifact::Lqc(lqc(&machine, proposed.clone(), &votes));
        let certificate = observe(&mut machine, certificate);
        let raw = Artifact::Vote(view_vote(&machine, &proposed, 0));
        let raw = observe(&mut machine, raw);
        if complete_raw_first {
            complete(&mut machine, &raw, true);
            assert!(machine.inspect().pools().is_empty());
            complete(&mut machine, &certificate, true);
        } else {
            complete(&mut machine, &certificate, true);
            complete(&mut machine, &raw, true);
        }

        let inspection = machine.inspect();
        let direct = inspection
            .finality()
            .iter()
            .find(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .unwrap();
        assert_eq!(direct.votes(), 5);
        (inspection.pools()[0], direct.clone())
    };

    assert_eq!(run(false), run(true));
}

#[test]
fn vqc_constituents_preserve_finality_observation_order() {
    let run = |certificate_valid: bool| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            2,
            NonZeroUsize::new(64).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = profile_with_resources(Role::Observer, 6, 2, limits);
        let (mut machine, _) = start_profile(profile);
        let config = machine.profile().protocol().codec_config();
        let base = leader(&machine, 2);
        let with_payload = |label: &[u8]| {
            let mut proposals = base.proposals().to_vec();
            proposals[0] = ChainProposal::new(
                proposals[0].anchor().chain(),
                proposals[0].anchor().clone(),
                vec![digest(label)],
                config.pipeline_depth(),
            )
            .unwrap();
            LeaderBlock::new(
                base.round(),
                base.parent(),
                base.history(),
                proposals,
                config,
            )
            .unwrap()
        };
        let designated = with_payload(b"designated payload");
        let other = with_payload(b"other payload");

        let vote_at = |leader: &LeaderBlock<MinPk, Digest>, signer: u32, position: u32| {
            let mut positions = vec![Position::new(0); config.chains()];
            positions[0] = Position::new(position);
            Vote::new(
                VoteBody::for_leader::<Sha256, MinPk>(
                    leader,
                    positions,
                    vec![Extension::empty(); config.chains()],
                    config,
                )
                .unwrap(),
                attestation(signer),
            )
        };

        let designated_votes = (0..3)
            .map(|signer| vote_at(&designated, signer, 0))
            .collect::<Vec<_>>();
        let tally = Tally::from_votes::<MinPk, Sha256, _>(
            &designated,
            designated_votes
                .iter()
                .map(|vote| (vote.signer(), vote.body().clone())),
            config,
        )
        .unwrap();
        let conflicting = (3..5)
            .map(|signer| {
                let vote = vote_at(&other, signer, 0);
                ConflictingVote::new(
                    vote.signer(),
                    vote.body().leader(),
                    vote.body().positions().to_vec(),
                    vote.body().extensions().to_vec(),
                    config,
                )
                .unwrap()
            })
            .collect();
        let certificate = Vqc::new(
            designated.clone(),
            tally,
            Signers::from(config.participants(), []),
            conflicting,
            aggregate::Signature::<MinPk>::zero(),
            config,
        )
        .unwrap();
        let certificate = observe(&mut machine, Artifact::Vqc(certificate));

        for proposed in [&designated, &other] {
            let leader = observe(
                &mut machine,
                Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
            );
            complete(&mut machine, &leader, true);

            for signer in 0..5 {
                let vote = observe(&mut machine, Artifact::Vote(vote_at(proposed, signer, 1)));
                complete(&mut machine, &vote, true);
            }
        }

        assert!(
            machine.inspect().finality().is_empty(),
            "later direct votes must wait for every earlier V-QC constituent"
        );

        complete(&mut machine, &certificate, certificate_valid);
        let positions = machine
            .inspect()
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Direct(_)))
            .map(|fact| (fact.leader(), fact.positions()[0]))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(positions.len(), 2);
        (
            positions[&designated.digest::<Sha256>()],
            positions[&other.digest::<Sha256>()],
        )
    };

    assert_eq!(run(true), (Position::new(0), Position::new(0)));
    assert_eq!(run(false), (Position::new(1), Position::new(1)));
}

#[test]
fn aggregate_vote_witnesses_freeze_the_exact_finality_quorum() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        2,
        NonZeroUsize::new(64).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let signed = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &signed, true);

    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let certificate = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
    let certificate = observe(&mut machine, certificate);
    let witnesses = votes
        .iter()
        .cloned()
        .map(|vote| observe(&mut machine, Artifact::Vote(vote)))
        .collect::<Vec<_>>();
    let extra = Artifact::Vote(view_vote(&machine, &proposed, 5));
    let extra = observe(&mut machine, extra);
    complete(&mut machine, &extra, true);
    complete(&mut machine, &certificate, true);
    assert_eq!(machine.inspect().pools()[0].votes(), 6);

    let mut aggregate = None;
    for witness in witnesses {
        let completed = complete_with_step(&mut machine, &witness, true);
        let (effects, _) = drive_poll_and_persist(&mut machine, completed);
        aggregate = aggregate.or_else(|| {
            effects.into_iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job),
                _ => None,
            })
        });
    }
    let aggregate = aggregate.expect("the exact witnessed quorum must schedule L-QC assembly");
    assert_eq!(
        aggregate
            .votes()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
}

#[test]
fn matching_aggregate_witness_survives_an_earlier_mismatch() {
    let profile = profile_for(Role::Observer, 1, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let signed = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &signed, true);

    let selected = view_vote(&machine, &proposed, 0);
    let certificate = vqc(
        &machine,
        proposed.clone(),
        &[ViewMessage::Vote(selected.clone())],
    );
    let certificate = observe(&mut machine, Artifact::Vqc(certificate));
    complete(&mut machine, &certificate, true);

    let mut extensions = vec![Extension::empty(); 1];
    extensions[0] = Extension::new(vec![digest(b"mismatching witness")], 1).unwrap();
    let mismatch = Vote::new(
        VoteBody::for_leader::<Sha256, MinPk>(
            &proposed,
            vec![Position::new(0)],
            extensions,
            machine.profile().protocol().codec_config(),
        )
        .unwrap(),
        attestation(0),
    );
    let mismatch = observe(&mut machine, Artifact::Vote(mismatch));
    let matching = observe(&mut machine, Artifact::Vote(selected));

    complete(&mut machine, &matching, true);
    complete(&mut machine, &mismatch, true);
    assert!(
        machine.inspect().pools()[0].lqc_pending(),
        "the queued matching witness must make L-QC assembly ready"
    );
}

#[test]
fn finality_equivocation_detail_is_bounded_after_verification() {
    let limits = resources().with_max_finality_pools(NonZeroUsize::new(8).unwrap());
    let profile = profile_with_retention(Role::Observer, 6, 2, limits, ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 2);
    let config = machine.profile().protocol().codec_config();

    let proposal = |parent: &[u8]| {
        let block = LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(parent)),
            base.history(),
            base.proposals().to_vec(),
            config,
        )
        .unwrap();
        Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(0)))
    };
    let step = machine
        .step(cohort::<Sha256, _>(vec![
            proposal(b"first parent"),
            proposal(b"second parent"),
            proposal(b"third parent"),
        ]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("observation must report each pool reservation");
    };
    assert_eq!(results[0].status(), ObservationStatus::Scheduled);
    assert_eq!(results[1].status(), ObservationStatus::Scheduled);
    assert_eq!(results[2].status(), ObservationStatus::Scheduled);
    let [Capability::Verification(VerificationCapability::Verify(job))] = step.capabilities()
    else {
        panic!("the proposals must share one verification job");
    };
    complete(&mut machine, job, true);

    assert_eq!(machine.inspect().pools().len(), 2);
}

#[test]
fn finality_owner_reservation_waits_for_the_earliest_claim() {
    let limits = resources().with_max_finality_pools(NonZeroUsize::new(8).unwrap());
    let profile = profile_with_retention(Role::Observer, 6, 2, limits, ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    let config = machine.profile().protocol().codec_config();

    let earlier = leader(&machine, 1);
    let earlier_digest = earlier.digest::<Sha256>();
    let later = LeaderBlock::new(
        earlier.round(),
        CertificateId::new(digest(b"later claim parent")),
        earlier.history(),
        earlier.proposals().to_vec(),
        config,
    )
    .unwrap();
    let later_digest = later.digest::<Sha256>();
    let designated_votes = (0..3)
        .map(|signer| view_vote(&machine, &earlier, signer))
        .collect::<Vec<_>>();
    let tally = Tally::from_votes::<MinPk, Sha256, _>(
        &earlier,
        designated_votes
            .iter()
            .map(|vote| (vote.signer(), vote.body().clone())),
        config,
    )
    .unwrap();
    let conflicting = (3..5)
        .map(|signer| {
            let vote = view_vote(&machine, &later, signer);
            ConflictingVote::new(
                vote.signer(),
                vote.body().leader(),
                vote.body().positions().to_vec(),
                vote.body().extensions().to_vec(),
                config,
            )
            .unwrap()
        })
        .collect();
    let earlier_certificate = Artifact::Vqc(
        Vqc::new(
            earlier,
            tally,
            Signers::from(config.participants(), []),
            conflicting,
            aggregate::Signature::<MinPk>::zero(),
            config,
        )
        .unwrap(),
    );
    let earlier_claim = observe(&mut machine, earlier_certificate);

    let owner = machine.profile().protocol().leader(View::new(1));
    let later_claim = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(later, attestation(owner.get()))),
    );

    let completed = complete_with_step(&mut machine, &later_claim, true);
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 0,
        }
    );
    assert!(
        machine.inspect().pools().is_empty(),
        "a later verdict cannot consume an unresolved earlier reservation"
    );

    complete(&mut machine, &earlier_claim, true);
    let inspection = machine.inspect();
    let earlier_pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.leader() == earlier_digest)
        .expect("the aggregate's earlier leader claim must be installed first");
    assert_eq!(earlier_pool.votes(), 3);
    let later_pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.leader() == later_digest)
        .expect("the later valid detail may install only after the aggregate resolves");
    assert_eq!(later_pool.votes(), 2);
}

#[test]
fn rejected_finality_owner_reservation_releases_the_next_verdict() {
    let profile = profile_with_resources(Role::Observer, 6, 2, resources());
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 1);
    let config = machine.profile().protocol().codec_config();
    let proposal = |parent: &[u8]| {
        let block = LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(parent)),
            base.history(),
            base.proposals().to_vec(),
            config,
        )
        .unwrap();
        let digest = block.digest::<Sha256>();
        let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(1)));
        (digest, artifact)
    };
    let (_, earlier) = proposal(b"invalid earlier owner claim");
    let (later_digest, later) = proposal(b"valid later owner claim");
    let earlier = observe(&mut machine, earlier);
    let later = observe(&mut machine, later);

    complete(&mut machine, &later, true);
    assert!(machine.inspect().pools().is_empty());

    complete(&mut machine, &earlier, false);
    let inspection = machine.inspect();
    let pools = inspection.pools();
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].leader(), later_digest);
}

#[test]
fn lqc_output_waits_for_earlier_owner_claim() {
    let profile = profile_with_resources(Role::Observer, 6, 2, resources());
    let (machine, _) = start_profile(profile.clone());
    let mut finality = super::finality::FinalityState::new::<Sha256>(&profile);
    let base = leader(&machine, 1);
    let owner = machine.profile().protocol().leader(View::new(1));
    let earlier = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        base.clone(),
        attestation(owner.get()),
    )));
    let later = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"later L-QC parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, later, &votes);
    let later = Arc::new(Artifact::Lqc(certificate));
    let earlier_id = earlier.id::<Sha256>();
    let later_id = later.id::<Sha256>();
    let earlier_observation = Observation::new(1, 0);
    let later_observation = Observation::new(2, 0);
    for (artifact_id, observation, artifact) in [
        (earlier_id, earlier_observation, Arc::clone(&earlier)),
        (later_id, later_observation, Arc::clone(&later)),
    ] {
        finality
            .claim_finality::<Sha256>(artifact_id, observation, artifact, &profile)
            .unwrap();
    }

    let blocked = finality
        .validate_finality_claim::<Sha256>(later_id, later_observation, &later, &profile)
        .unwrap();
    assert!(blocked.is_empty());

    let released = finality
        .reject_finality_claim::<Sha256>(earlier_id, earlier_observation, &earlier, &profile)
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [super::finality::FinalityOutput::Finality(
            artifact_id,
            observation,
            certificate,
        )] if *artifact_id == later_id
            && *observation == later_observation
            && certificate.as_ref() == later.as_ref()
    ));
}

#[test]
fn later_duplicate_completion_preserves_an_earlier_finality_observation() {
    let profile = profile_with_resources(Role::Observer, 6, 2, resources());
    let (machine, _) = start_profile(profile.clone());
    let mut finality = super::finality::FinalityState::new::<Sha256>(&profile);
    let base = leader(&machine, 1);
    let owner = machine.profile().protocol().leader(View::new(1));
    let blocker = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        base.clone(),
        attestation(owner.get()),
    )));
    let later = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"duplicate L-QC parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later, signer))
        .collect::<Vec<_>>();
    let certificate = Arc::new(Artifact::Lqc(lqc(&machine, later, &votes)));
    let blocker_id = blocker.id::<Sha256>();
    let certificate_id = certificate.id::<Sha256>();
    let blocker_observation = Observation::new(1, 0);
    let first_observation = Observation::new(2, 0);
    let duplicate_observation = Observation::new(3, 0);

    finality
        .claim_finality::<Sha256>(
            blocker_id,
            blocker_observation,
            Arc::clone(&blocker),
            &profile,
        )
        .unwrap();
    finality
        .claim_finality::<Sha256>(
            certificate_id,
            first_observation,
            Arc::clone(&certificate),
            &profile,
        )
        .unwrap();

    let blocked = finality
        .validate_finality_claim::<Sha256>(
            certificate_id,
            first_observation,
            &certificate,
            &profile,
        )
        .unwrap();
    assert!(blocked.is_empty());
    finality
        .claim_finality::<Sha256>(
            certificate_id,
            duplicate_observation,
            Arc::clone(&certificate),
            &profile,
        )
        .unwrap();
    let duplicate = finality
        .validate_finality_claim::<Sha256>(
            certificate_id,
            duplicate_observation,
            &certificate,
            &profile,
        )
        .unwrap();
    assert!(duplicate.is_empty());

    let released = finality
        .reject_finality_claim::<Sha256>(blocker_id, blocker_observation, &blocker, &profile)
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [super::finality::FinalityOutput::Finality(
            artifact_id,
            observation,
            artifact,
        )] if *artifact_id == certificate_id
            && *observation == first_observation
            && artifact.as_ref() == certificate.as_ref()
    ));
}

#[test]
fn retiring_pending_finality_claim_releases_later_certificate() {
    let profile = profile_with_resources(Role::Observer, 6, 2, resources());
    let (machine, _) = start_profile(profile.clone());
    let mut finality = super::finality::FinalityState::new::<Sha256>(&profile);
    let earlier_leader = leader(&machine, 1);
    let later_leader = leader(&machine, 7);
    let earlier_owner = profile.protocol().leader(earlier_leader.round().view());
    assert_eq!(
        earlier_owner,
        profile.protocol().leader(later_leader.round().view())
    );
    let earlier = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        earlier_leader,
        attestation(earlier_owner.get()),
    )));
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &later_leader, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, later_leader, &votes);
    let later = Arc::new(Artifact::Lqc(certificate));
    let earlier_id = earlier.id::<Sha256>();
    let later_id = later.id::<Sha256>();
    let earlier_observation = Observation::new(1, 0);
    let later_observation = Observation::new(2, 0);
    for (artifact_id, observation, artifact) in [
        (earlier_id, earlier_observation, Arc::clone(&earlier)),
        (later_id, later_observation, Arc::clone(&later)),
    ] {
        finality
            .claim_finality::<Sha256>(artifact_id, observation, artifact, &profile)
            .unwrap();
    }
    let blocked = finality
        .validate_finality_claim::<Sha256>(later_id, later_observation, &later, &profile)
        .unwrap();
    assert!(blocked.is_empty());

    let released = finality
        .retire_through::<Sha256>(&profile, View::new(1))
        .unwrap();
    assert!(matches!(
        released.as_slice(),
        [super::finality::FinalityOutput::Finality(
            artifact_id,
            observation,
            certificate,
        )] if *artifact_id == later_id
            && *observation == later_observation
            && certificate.as_ref() == later.as_ref()
    ));
}

#[test]
fn byzantine_leader_variants_do_not_starve_a_correct_owner() {
    const MAX_POOLS: usize = 19;
    let limits = resources_with_future_views(12, 16)
        .with_max_finality_pools(NonZeroUsize::new(MAX_POOLS).unwrap());
    let profile = profile_with_retention(Role::Observer, 6, 2, limits, ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    let protocol = machine.profile().protocol().clone();

    let byzantine = protocol.leader(View::new(1));
    let mut byzantine_digests = BTreeSet::new();
    for index in 0..=MAX_POOLS {
        let view = if index == MAX_POOLS { 7 } else { 1 };
        assert_eq!(protocol.leader(View::new(view)), byzantine);
        let base = leader(&machine, view);
        let mut proposals = base.proposals().to_vec();
        proposals[0] = ChainProposal::new(
            proposals[0].anchor().chain(),
            proposals[0].anchor().clone(),
            vec![digest(&index.to_be_bytes())],
            protocol.codec_config().pipeline_depth(),
        )
        .unwrap();
        let proposed = LeaderBlock::new(
            base.round(),
            base.parent(),
            base.history(),
            proposals,
            protocol.codec_config(),
        )
        .unwrap();
        assert!(byzantine_digests.insert(proposed.digest::<Sha256>()));
        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(byzantine.get()),
            )),
        );
        let completed = complete_with_step(&mut machine, &proposal, true);
        assert_eq!(
            completed.status(),
            &StepStatus::Verified {
                valid: 1,
                invalid: 0,
            }
        );
        assert!(machine.inspect().pools().len() <= MAX_POOLS);
    }
    assert_eq!(byzantine_digests.len(), MAX_POOLS + 1);
    assert!(View::new(7) > machine.inspect().view());

    let correct = protocol.leader(View::new(2));
    assert_ne!(correct, byzantine);
    let proposed = leader(&machine, 2);
    let proposed_round = proposed.round();
    let proposed_digest = proposed.digest::<Sha256>();
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(correct.get()),
        )),
    );
    let completed = complete_with_step(&mut machine, &proposal, true);
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 0,
        }
    );
    let inspection = machine.inspect();
    let admitted = inspection
        .pools()
        .iter()
        .find(|pool| pool.round() == proposed_round && pool.leader() == proposed_digest)
        .expect("the correct owner's leader must be admitted");
    assert_eq!(admitted.votes(), 0);

    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        complete(&mut machine, &vote, true);
    }

    let inspection = machine.inspect();
    let pool = inspection
        .pools()
        .iter()
        .find(|pool| pool.round() == proposed_round && pool.leader() == proposed_digest)
        .expect("the correct owner's pool must remain exact");
    assert_eq!(pool.votes(), 5);
    assert!(pool.finalized());
    let fact = inspection
        .finality()
        .iter()
        .find(|fact| {
            fact.round() == proposed_round
                && fact.leader() == proposed_digest
                && matches!(fact.id(), FinalityId::Direct(_))
        })
        .expect("the correct owner's leader must finalize");
    assert_eq!(fact.votes(), 5);
}

#[test]
fn finality_primaries_rotate_across_correct_owners_and_views() {
    const MAX_POOLS: usize = 23;
    let limits = resources_with_future_views(16, 16)
        .with_max_finality_pools(NonZeroUsize::new(MAX_POOLS).unwrap());
    let profile = profile_with_retention(Role::Observer, 11, 2, limits, ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    let protocol = machine.profile().protocol().clone();
    let admit = |machine: &mut TestMachine, proposed: LeaderBlock<MinPk, Digest>| {
        let owner = protocol.leader(proposed.round().view());
        let digest = proposed.digest::<Sha256>();
        let proposal = observe(
            machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(owner.get()))),
        );
        let completed = complete_with_step(machine, &proposal, true);
        assert_eq!(
            completed.status(),
            &StepStatus::Verified {
                valid: 1,
                invalid: 0,
            }
        );
        digest
    };

    let first_byzantine = leader(&machine, 8);
    let mut equivocation_proposals = first_byzantine.proposals().to_vec();
    equivocation_proposals[0] = ChainProposal::new(
        equivocation_proposals[0].anchor().chain(),
        equivocation_proposals[0].anchor().clone(),
        vec![digest(b"full best effort")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let equivocation = LeaderBlock::new(
        first_byzantine.round(),
        first_byzantine.parent(),
        first_byzantine.history(),
        equivocation_proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let second_byzantine_leader = leader(&machine, 9);
    let stale_correct_leader = leader(&machine, 1);
    let first_byzantine = admit(&mut machine, first_byzantine);
    let second_byzantine = admit(&mut machine, second_byzantine_leader);
    let stale_correct = admit(&mut machine, stale_correct_leader);
    let best_effort = admit(&mut machine, equivocation);
    assert_eq!(machine.inspect().pools().len(), 4);
    assert_eq!(
        [View::new(8), View::new(9), View::new(1)]
            .map(|view| protocol.leader(view))
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );

    let later_correct_leader = leader(&machine, 2);
    let later_correct = admit(&mut machine, later_correct_leader);
    let leaders = machine
        .inspect()
        .pools()
        .iter()
        .map(|pool| pool.leader())
        .collect::<BTreeSet<_>>();
    assert!(leaders.contains(&first_byzantine));
    assert!(leaders.contains(&second_byzantine));
    assert!(leaders.contains(&best_effort));
    assert!(leaders.contains(&later_correct));
    assert!(!leaders.contains(&stale_correct));

    assert_eq!(
        protocol.leader(View::new(2)),
        protocol.leader(View::new(13))
    );
    let repeated_owner_leader = leader(&machine, 13);
    let repeated_owner = admit(&mut machine, repeated_owner_leader);
    let leaders = machine
        .inspect()
        .pools()
        .iter()
        .map(|pool| pool.leader())
        .collect::<BTreeSet<_>>();
    assert!(leaders.contains(&repeated_owner));
    assert!(!leaders.contains(&later_correct));
    assert_eq!(leaders.len(), 4);
}

#[test]
fn lqc_completion_must_match_the_selected_vote_transcript() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);
    let mut aggregate = None;
    let mut vqc_aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = complete_with_step(&mut machine, &vote, true);
        aggregate = aggregate.or_else(|| {
            step.capabilities().iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
                _ => None,
            })
        });
        vqc_aggregate = vqc_aggregate.or_else(|| {
            step.capabilities().iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
                _ => None,
            })
        });
        let (effects, _) = drive_poll_and_persist(&mut machine, step);
        aggregate = aggregate.or_else(|| {
            effects.iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
                _ => None,
            })
        });
        vqc_aggregate = vqc_aggregate.or_else(|| {
            effects.iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
                _ => None,
            })
        });
    }
    let aggregate = aggregate.unwrap();
    let vqc_aggregate = vqc_aggregate.unwrap();

    let wrong_votes = (1..=5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let wrong = lqc(&machine, proposed.clone(), &wrong_votes);
    let parked = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            wrong,
        ))))
        .unwrap();
    assert_eq!(parked.status(), &StepStatus::CompletionDeferred);
    // The mismatch surfaces exactly once when the parked completion drains; the aggregation
    // job survives for the corrected transcript.
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    // Resolve the earlier V-QC aggregation before admitting the L-QC. The observation frontier
    // intentionally prevents a later derived certificate from overtaking this crypto job.
    let view_messages = vqc_aggregate.messages().collect::<Vec<_>>();
    let view_certificate = vqc(&machine, vqc_aggregate.leader().clone(), &view_messages);
    let completed_vqc = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            vqc_aggregate.id(),
            vqc_aggregate.generation(),
            view_certificate,
        ))))
        .unwrap();
    let completed_vqc = settle(&mut machine, completed_vqc);
    let retained_vqc = persist(&mut machine, &persist_job(&completed_vqc));
    let forwarding = persist_job(&retained_vqc);
    // Fold the forwarding acknowledgement's own release here so the next window holds only
    // the L-QC staging effects.
    persist(&mut machine, &forwarding);

    let selected = aggregate.votes().cloned().collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed, &selected);
    let completed = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            certificate,
        ))))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::CompletionDeferred);
    let completed = settle(&mut machine, completed);
    let job = persist_job(&completed);
    assert!(matches!(
        job.events()[0].change(),
        Change::ArtifactCreated { .. }
    ));
    // The corrected transcript is an independently verifiable aggregate with no pending
    // local signature, so its broadcast releases with the staging step and persistence must
    // not release it a second time.
    assert!(
        completed.capabilities().iter().any(
            |effect| matches!(durable_effect(effect), Some(DurableEffect::Broadcast(artifact))
                if matches!(artifact.as_ref(), Artifact::Lqc(_)))
        ),
        "staging must release the assembled certificate"
    );
    let persisted = persist(&mut machine, &job);
    assert!(
        persisted
            .capabilities()
            .iter()
            .all(|effect| { !matches!(durable_effect(effect), Some(DurableEffect::Broadcast(_))) }),
        "persistence must not release the staged broadcast a second time"
    );
    assert!(matches!(
        machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(_))
    ));
}

#[test]
fn canceled_lqc_completion_is_not_committed_after_forwarding() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let mut vqc_aggregate = None;
    let mut lqc_aggregate = None;
    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        let completed = complete_with_step(&mut machine, &vote, true);
        let (effects, _) = drive_poll_and_persist(&mut machine, completed);
        for effect in effects {
            match effect {
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => {
                    vqc_aggregate = Some(job)
                }
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => {
                    lqc_aggregate = Some(job)
                }
                _ => {}
            }
        }
    }
    let vqc_aggregate = vqc_aggregate.unwrap();
    let lqc_aggregate = lqc_aggregate.unwrap();

    let messages = vqc_aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, proposed.clone(), &messages);
    machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            vqc_aggregate.id(),
            vqc_aggregate.generation(),
            certificate,
        ))))
        .unwrap();

    let selected = lqc_aggregate.votes().cloned().collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed.clone(), &selected);
    machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            lqc_aggregate.id(),
            lqc_aggregate.generation(),
            certificate,
        ))))
        .unwrap();

    machine.poll(NonZeroUsize::MIN).unwrap();
    machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(machine.prepared_lqc.is_some());

    let replacement_votes = (1..=5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let replacement = Artifact::Lqc(lqc(&machine, proposed, &replacement_votes));
    let replacement = observe(&mut machine, replacement);
    complete_raw(&mut machine, &replacement, true);
    assert_eq!(machine.finality.aggregate_reservations(), 0);

    let cursor = machine.durable.cursor;
    machine.poll(NonZeroUsize::MIN).unwrap();
    assert_eq!(machine.durable.cursor, cursor);
    assert!(machine.prepared_lqc.is_none());
}

fn build_job(step: &Step<MinPk, Digest>) -> BuildJob<Digest> {
    step.capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Build(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("ready work must emit a build job")
}

fn custody_job(step: &Step<MinPk, Digest>) -> CustodyJob<Digest> {
    step.capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a completed build must emit a custody job")
}

fn prepare_block(
    machine: &mut TestMachine,
    job: &BuildJob<Digest>,
    body: Digest,
) -> Step<MinPk, Digest> {
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            job.id(),
            job.generation(),
            job.parent(),
            Some(body),
        )))
        .unwrap();
    settle(machine, completed)
}

fn complete_custody(
    machine: &mut TestMachine,
    job: &CustodyJob<Digest>,
) -> Step<MinPk, Digest> {
    let completed = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            job.id(),
            job.generation(),
            job.header().clone(),
        )))
        .unwrap();
    settle(machine, completed)
}

fn authenticate_block(
    machine: &mut TestMachine,
    header: TransactionBlockHeader<Digest>,
    producer: u32,
) -> Step<MinPk, Digest> {
    let verification = observe(
        machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(producer))),
    );
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            vec![Verdict::new(verification.items()[0].ticket(), true)],
        )))
        .unwrap();
    settle(machine, verified)
}

fn validation_jobs(step: &Step<MinPk, Digest>) -> Vec<ValidationJob<MinPk, Digest>> {
    step
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
            _ => None,
        })
        .collect()
}

fn complete_validation(
    machine: &mut TestMachine,
    validation: &ValidationJob<MinPk, Digest>,
) -> Step<MinPk, Digest> {
    let validated = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            validation.id(),
            validation.generation(),
            BlockValidity::Valid,
        )))
        .unwrap();
    settle(machine, validated)
}

fn validate_block(
    machine: &mut TestMachine,
    header: TransactionBlockHeader<Digest>,
    producer: u32,
) -> Step<MinPk, Digest> {
    let authenticated = authenticate_block(machine, header, producer);
    let validations = validation_jobs(&authenticated);
    let [validation] = validations.as_slice() else {
        panic!("authenticated block must emit one validation job");
    };
    complete_validation(machine, validation)
}

fn symbolic_da_certificate(
    header: TransactionBlockHeader<Digest>,
    marker: u64,
) -> DaCertificate<MinPk, Digest> {
    DaCertificate::new(header, symbolic_threshold_certificate(marker))
}

fn drain_da_choices(
    machine: &mut TestMachine,
    mut step: Step<MinPk, Digest>,
    choices: &mut Vec<TransactionBlockHeader<Digest>>,
) {
    loop {
        let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) else {
            return;
        };
        if let Change::OutboxQueued { effect, .. } = job.events()[0].change()
            && let DurableEffect::Sign(SignRequest::DaVote(header)) = effect.as_ref()
        {
            choices.push(header.header().clone());
        }
        step = persist(machine, &job);
    }
}

fn produce_and_collect_da(
    machine: &mut TestMachine,
) -> (TransactionBlockHeader<Digest>, DaRecoveryJob<MinPk, Digest>) {
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(machine, ready);
    let build = build_job(&ready);
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"own block")),
        )))
        .unwrap();
    let completed = settle(machine, completed);
    let completed = complete_custody(machine, &custody_job(&completed));
    // The signing request releases with the step that stages the producer choice.
    let header = completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job)) => match job.request() {
                DurableEffect::Sign(SignRequest::TransactionBlock(header)) => Some(header.clone()),
                _ => None,
            },
            _ => None,
        })
        .unwrap();
    persist(machine, &persist_job(&completed));

    let votes = (0..4)
        .map(|signer| Artifact::DaVote(DaVote::new(header.clone(), threshold_share(signer))))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(votes)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("DA shares must enter cryptographic verification");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("exactly n-2f verified shares must trigger recovery");
    (header, recovery)
}

#[test]
fn profile_rejects_validator_outside_committee() {
    assert_eq!(
        Profile::<Sha256, MinPk>::new(
            config(Epoch::new(7)),
            Role::Validator(Participant::new(1)),
            Tuning {
                view_timeout: Duration::ZERO,
                production_interval: Duration::ZERO,
                view_retention: retention_for(resources(), 1),
                ..Tuning::default()
            },
        )
        .unwrap_err(),
        ProfileError::ValidatorOutOfRange(Participant::new(1))
    );
}

#[test]
fn decoded_artifact_requires_matching_verification() {
    let mut machine = active_machine(Role::Observer);
    let artifact = leader_artifact(&machine, 1);
    let id = artifact.id::<Sha256>();
    let job = observe(&mut machine, artifact.clone());

    assert!(machine.inspect().ready_artifacts().is_empty());
    assert_eq!(machine.inspect().pending_artifacts(), 1);

    let duplicate = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    assert!(matches!(
        duplicate.status(),
        StepStatus::Observed(results) if results[0].status() == ObservationStatus::Duplicate
    ));
    assert!(duplicate.capabilities().is_empty());

    let stale = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation() + 1,
            vec![Verdict::new(job.items()[0].ticket(), true)],
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(machine.inspect().ready_artifacts().is_empty());

    complete(&mut machine, &job, true);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);

    let repeated = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            vec![Verdict::new(job.items()[0].ticket(), false)],
        )))
        .unwrap();
    assert_eq!(repeated.status(), &StepStatus::StaleCompletion);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);
}

#[test]
fn invalid_artifacts_release_cache_capacity() {
    let limits = resources_with_capacities(8, 8);
    let profile = profile_with_resources(Role::Observer, 1, 2, limits);
    let (mut machine, _) = start_profile(profile);

    let first = leader(&machine, 1);
    let artifacts = [
        leader_artifact(&machine, 1),
        leader_artifact(&machine, 2),
        vote_artifact(&machine, &first),
        Artifact::NoVote(no_vote(&machine, View::new(1), 0)),
    ];
    for artifact in artifacts {
        let verification = observe(&mut machine, artifact);
        complete(&mut machine, &verification, false);
    }
    assert_eq!(machine.inspect().cached_artifacts(), 0);

    let accepted = machine
        .step(cohort::<Sha256, _>(vec![Artifact::NoVote(no_vote(
            &machine,
            View::new(2),
            0,
        ))]))
        .unwrap();
    assert!(matches!(
        accepted.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Scheduled
    ));
}

#[test]
fn mismatched_completion_does_not_consume_job() {
    let mut machine = active_machine(Role::Observer);
    let artifact = leader_artifact(&machine, 1);
    let job = observe(&mut machine, artifact);
    let wrong = VerificationTicket::new(
        job.id(),
        ArtifactId::new(digest(b"substitute")),
        job.items()[0].ticket().observation(),
    );

    assert!(matches!(
        machine.step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            vec![Verdict::new(wrong, true)],
        ))),
        Err(StepError::CompletionMismatch)
    ));
    assert_eq!(machine.inspect().verification_jobs(), &[job.id()]);

    complete(&mut machine, &job, true);
    assert!(machine.inspect().verification_jobs().is_empty());
}

#[test]
fn authenticated_vote_waits_for_exact_leader() {
    let mut machine = active_machine(Role::Observer);
    let leader = leader(&machine, 1);
    let vote = vote_artifact(&machine, &leader);
    let vote_id = vote.id::<Sha256>();
    let vote_job = observe(&mut machine, vote);
    complete(&mut machine, &vote_job, true);

    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert!(machine.inspect().ready_artifacts().is_empty());

    let leader = Artifact::LeaderBlock(SignedLeaderBlock::new(leader, attestation(0)));
    let leader_id = leader.id::<Sha256>();
    let leader_job = observe(&mut machine, leader);
    complete(&mut machine, &leader_job, true);

    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.inspect().ready_artifacts(), &[vote_id, leader_id]);
}

#[test]
fn dependency_overflow_releases_the_dropped_proposal_claim() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = Profile::with_limits(
        config_for(Epoch::new(7), 6, 2),
        Role::Validator(Participant::new(5)),
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(limits, 6),
            ..Tuning::default()
        },
        limits,
    )
    .unwrap();
    let (mut machine, _) = start_profile(profile);

    let with_parent = |machine: &TestMachine, view, label: &[u8]| {
        let base = leader(machine, view);
        LeaderBlock::new(
            base.round(),
            CertificateId::new(digest(label)),
            base.history(),
            base.proposals().to_vec(),
            machine.profile().protocol().codec_config(),
        )
        .unwrap()
    };
    let filler_artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(
        with_parent(&machine, 2, b"filler parent"),
        attestation(0),
    ));
    let filler = observe(&mut machine, filler_artifact);
    complete(&mut machine, &filler, true);
    assert_eq!(machine.waiting, 1);

    let dropped_artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(
        with_parent(&machine, 1, b"dropped parent"),
        attestation(0),
    ));
    let dropped = machine
        .step(cohort::<Sha256, _>(vec![dropped_artifact]))
        .unwrap();
    assert!(matches!(
        dropped.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(dropped.capabilities().is_empty());
    assert_eq!(machine.waiting, 1);
    assert_eq!(machine.inspect().dropped_artifacts(), 0);

    let valid_artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(leader(&machine, 1), attestation(0)));
    let valid = observe(&mut machine, valid_artifact);
    let voted = complete_with_step(&mut machine, &valid, true);
    assert!(matches!(
        persist_job(&voted).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
    ));
}

#[test]
fn dependency_overflow_cannot_leave_a_vote_in_the_vqc_pool() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);

    let base = leader(&machine, 2);
    let filler = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"missing filler parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let filler = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(filler, attestation(0))),
    );
    complete(&mut machine, &filler, true);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let proposed = leader(&machine, 1);
    let overflow = Artifact::Vote(view_vote(&machine, &proposed, 0));
    let overflow = machine.step(cohort::<Sha256, _>(vec![overflow])).unwrap();
    assert!(matches!(
        overflow.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(overflow.capabilities().is_empty());
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let messages = vec![
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let observed = machine.step(cohort::<Sha256, _>(messages)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("view messages must be verified together");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            job.items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    assert!(verified.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
}

#[test]
fn parent_rejection_precedes_child_authentication() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, parent_leader, &parent_messages));
    let dependency = parent
        .provisions::<Sha256>()
        .into_iter()
        .find_map(|dependency| match dependency {
            Dependency::Vqc(certificate) => Some(certificate),
            Dependency::Leader { .. } => None,
        })
        .unwrap();
    let base = leader(&machine, 2);
    let child = LeaderBlock::new(
        base.round(),
        dependency,
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let child = Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0)));

    let observed = machine
        .step(cohort::<Sha256, _>(vec![parent, child]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("the parent and child must share one verification job");
    };
    let completed = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            vec![
                Verdict::new(job.items()[0].ticket(), false),
                Verdict::new(job.items()[1].ticket(), true),
            ],
        )))
        .unwrap();
    assert_eq!(
        completed.status(),
        &StepStatus::Verified {
            valid: 1,
            invalid: 1,
        }
    );
    assert_eq!(machine.inspect().cached_artifacts(), 0);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
}

#[test]
fn invalid_dependency_bound_is_completion_order_independent() {
    let run = |target: usize, completion_order: [usize; 3]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(3).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = profile_with_resources(Role::Observer, 6, 2, limits);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 1);
        let message_sets = [
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
            ],
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
            ],
        ];
        let mut parents = message_sets
            .into_iter()
            .map(|messages| {
                let artifact = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
                let dependency = artifact
                    .provisions::<Sha256>()
                    .into_iter()
                    .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
                    .unwrap();
                (dependency, artifact)
            })
            .collect::<Vec<_>>();
        parents.sort_unstable_by_key(|(dependency, _)| *dependency);
        let Dependency::Vqc(parent) = parents[target].0 else {
            unreachable!("V-QC artifacts provide V-QC dependencies");
        };
        let jobs = parents
            .into_iter()
            .map(|(_, artifact)| observe(&mut machine, artifact))
            .collect::<Vec<_>>();

        let base = leader(&machine, 2);
        let child = LeaderBlock::new(
            base.round(),
            parent,
            base.history(),
            base.proposals().to_vec(),
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        let child = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0))),
        );
        for index in completion_order {
            if index == 2 {
                complete(&mut machine, &child, true);
            } else {
                complete(&mut machine, &jobs[index], false);
            }
        }
        machine.inspect()
    };

    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for target in 0..2 {
        let expected = run(target, orders[0]);
        assert_eq!(expected.waiting_artifacts(), 0);
        assert_eq!(expected.cached_artifacts(), 0);
        for order in orders.iter().skip(1) {
            assert_eq!(run(target, *order), expected);
        }
    }
}

#[test]
fn dependency_rejection_saturation_preserves_observed_valid_parents() {
    let run = |completion_order: [usize; 4]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(4).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = profile_with_resources(Role::Observer, 6, 2, limits);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let message_sets = [
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
            ],
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 5)),
            ],
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 5)),
            ],
        ];
        let mut parents = message_sets
            .into_iter()
            .map(|messages| {
                let artifact = Artifact::Vqc(vqc(&machine, proposed.clone(), &messages));
                let Dependency::Vqc(dependency) = artifact
                    .provisions::<Sha256>()
                    .into_iter()
                    .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
                    .unwrap()
                else {
                    unreachable!("V-QC artifacts provide V-QC dependencies");
                };
                (dependency, artifact)
            })
            .collect::<Vec<_>>();
        parents.sort_unstable_by_key(|(dependency, _)| *dependency);
        let (valid_parent, valid_artifact) = parents.pop().unwrap();
        let mut jobs = parents
            .into_iter()
            .map(|(_, artifact)| observe(&mut machine, artifact))
            .collect::<Vec<_>>();
        jobs.push(observe(&mut machine, valid_artifact));

        let base = leader(&machine, 3);
        let child = LeaderBlock::new(
            base.round(),
            valid_parent,
            base.history(),
            base.proposals().to_vec(),
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        jobs.push(observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(child, attestation(0))),
        ));

        for index in completion_order {
            complete(&mut machine, &jobs[index], index >= 2);
        }
        machine.inspect()
    };

    let parent_first = run([2, 3, 0, 1]);
    let saturation_first = run([0, 1, 3, 2]);
    assert_eq!(saturation_first, parent_first);
    assert_eq!(parent_first.waiting_artifacts(), 0);
    assert_eq!(parent_first.ready_artifacts().len(), 2);
}

#[test]
fn dependency_rejection_saturation_rechecks_failed_providers() {
    let run = |completion_order: [usize; 4]| {
        let limits = ResourceLimits::new(
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(4).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let profile = profile_with_resources(Role::Observer, 6, 2, limits);
        let (mut machine, _) = start_profile(profile);
        let proposed = leader(&machine, 2);
        let message_sets = [
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
            ],
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 5)),
            ],
            vec![
                ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
                ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
                ViewMessage::NoVote(no_vote(&machine, View::new(2), 5)),
            ],
        ];
        let parents = message_sets
            .into_iter()
            .map(|messages| Artifact::Vqc(vqc(&machine, proposed.clone(), &messages)))
            .collect::<Vec<_>>();
        let jobs = parents
            .iter()
            .cloned()
            .map(|artifact| observe(&mut machine, artifact))
            .collect::<Vec<_>>();
        let child = Artifact::Vote(view_vote(&machine, &proposed, 5));
        let child = observe(&mut machine, child);
        let jobs = [&jobs[0], &jobs[1], &jobs[2], &child];

        for index in completion_order {
            complete(&mut machine, jobs[index], index == 3);
        }
        machine.inspect()
    };

    let child_before_provider_failure = run([0, 3, 1, 2]);
    let provider_failure_before_child = run([0, 1, 2, 3]);
    assert_eq!(child_before_provider_failure, provider_failure_before_child);
    assert_eq!(child_before_provider_failure.waiting_artifacts(), 0);
    assert_eq!(child_before_provider_failure.cached_artifacts(), 0);
}

#[test]
fn dependency_capacity_is_reserved_by_observation_order() {
    let limits = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(4).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::MIN,
        NonZeroUsize::new(32).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, proposed, &messages));
    let Dependency::Vqc(parent_id) = parent
        .provisions::<Sha256>()
        .into_iter()
        .find(|dependency| matches!(dependency, Dependency::Vqc(_)))
        .unwrap()
    else {
        unreachable!("V-QC artifacts provide V-QC dependencies");
    };
    let parent = observe(&mut machine, parent);

    let first = leader(&machine, 3);
    let first_history = first.history();
    let first = LeaderBlock::new(
        first.round(),
        parent_id,
        first.history(),
        first.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let first = Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(0)));
    let first_id = first.id::<Sha256>();
    let first = observe(&mut machine, first);

    let mut proposals = leader(&machine, 3).proposals().to_vec();
    let proposal = &proposals[0];
    proposals[0] = ChainProposal::new(
        proposal.anchor().chain(),
        proposal.anchor().clone(),
        vec![digest(b"equivocal proposal")],
        machine.profile().protocol().codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        Round::new(machine.profile().protocol().epoch(), View::new(3)),
        parent_id,
        first_history,
        proposals,
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let second = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(second, attestation(0)),
        )]))
        .unwrap();
    assert!(matches!(
        second.status(),
        StepStatus::Observed(results)
            if matches!(results[0].status(), ObservationStatus::Rejected(_))
    ));
    assert!(second.capabilities().is_empty());

    complete(&mut machine, &first, true);
    complete(&mut machine, &parent, true);
    assert!(machine.inspect().ready_artifacts().contains(&first_id));
}

#[test]
fn recovery_does_not_apply_the_remote_dependency_ceiling_to_local_votes() {
    let role = Role::Validator(Participant::new(0));
    let profile = profile_with_resources(role, 6, 2, resources_with_dependency_waiters(1));
    let machine = Machine::new(profile.clone());
    let votes = [leader(&machine, 1), leader(&machine, 2)]
        .map(|leader| Arc::new(Artifact::Vote(view_vote(&machine, &leader, 0))));
    let mut durable = machine.durable.clone();
    for vote in votes {
        durable.local.insert(vote.id::<Sha256>(), vote);
    }
    let snapshot = Snapshot::from_state_for_test::<Sha256>(
        machine.profile().protocol().epoch(),
        role,
        durable,
    );

    let mut restored = Machine::restore(profile, snapshot).unwrap();
    restored.step(Input::RecoveryComplete).unwrap();

    assert_eq!(restored.inspect().waiting_artifacts(), 2);
    assert_eq!(restored.dependency_slots, 0);
}

#[test]
fn recovered_vote_completion_survives_remote_dependency_capacity() {
    let RecoveredVoteSigning {
        mut machine,
        sign,
        leader: proposed,
        signer,
    } = recover_vote_signing(resources_with_dependency_waiters(1));
    let base = leader(&machine, 2);
    let waiting = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"unavailable remote parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let waiting = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(waiting, attestation(0))),
    );
    complete(&mut machine, &waiting, true);
    assert_eq!(machine.dependency_slots, 1);

    let vote = Artifact::Vote(view_vote(&machine, &proposed, signer.get()));
    let vote_id = vote.id::<Sha256>();
    let parked = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(vote),
        }))
        .unwrap();
    settle(&mut machine, parked);

    assert_eq!(machine.dependency_slots, 1);
    assert_eq!(machine.inspect().waiting_artifacts(), 2);
    assert!(machine.artifacts.contains_key(&vote_id));
}

#[test]
fn recovered_vote_survives_remote_dependency_rejection_saturation() {
    let RecoveredVoteSigning {
        mut machine,
        sign,
        leader: proposed,
        signer,
    } = recover_vote_signing(resources_with_dependency_waiters(1));
    let parent_leader = leader(&machine, 2);
    let message_sets = [
        vec![
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
            ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
            ViewMessage::NoVote(no_vote(&machine, View::new(2), 4)),
        ],
        vec![
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
            ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
            ViewMessage::NoVote(no_vote(&machine, View::new(2), 3)),
            ViewMessage::NoVote(no_vote(&machine, View::new(2), 5)),
        ],
    ];
    for messages in message_sets {
        let parent = Artifact::Vqc(vqc(&machine, parent_leader.clone(), &messages));
        let verification = observe(&mut machine, parent);
        complete(&mut machine, &verification, false);
    }
    assert!(machine.dependency_rejections_saturated);

    let vote = Artifact::Vote(view_vote(&machine, &proposed, signer.get()));
    let vote_id = vote.id::<Sha256>();
    let parked = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(vote),
        }))
        .unwrap();
    settle(&mut machine, parked);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert!(machine.artifacts.contains_key(&vote_id));

    let leader = Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed,
        attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
    ));
    let verification = observe(&mut machine, leader);
    complete(&mut machine, &verification, true);
    assert!(machine.inspect().ready_artifacts().contains(&vote_id));
}

#[test]
fn invalid_parent_vqc_releases_waiting_proposal_claim() {
    let profile = profile_for(Role::Validator(Participant::new(5)), 6, 2);
    let (mut machine, _) = start_profile(profile);
    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 1)),
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Artifact::Vqc(vqc(&machine, parent_leader, &parent_messages));
    let dependency = parent
        .provisions::<Sha256>()
        .into_iter()
        .find_map(|dependency| match dependency {
            Dependency::Vqc(certificate) => Some(certificate),
            Dependency::Leader { .. } => None,
        })
        .unwrap();
    let base = leader(&machine, 1);
    let blocked = LeaderBlock::new(
        base.round(),
        dependency,
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let blocked = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(blocked, attestation(0))),
    );
    complete(&mut machine, &blocked, true);
    assert_eq!(machine.inspect().waiting_artifacts(), 1);

    let invalid_parent = observe(&mut machine, parent);
    complete(&mut machine, &invalid_parent, false);
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.inspect().dropped_artifacts(), 0);
    assert!(machine.inspect().pools().is_empty());

    let valid_artifact = leader_artifact(&machine, 1);
    let valid = observe(&mut machine, valid_artifact);
    let ready = machine
        .step(Input::Verified(VerificationCompletion::new(
            valid.id(),
            valid.generation(),
            vec![Verdict::new(valid.items()[0].ticket(), true)],
        )))
        .unwrap();
    let ready = settle(&mut machine, ready);
    assert!(matches!(
        persist_job(&ready).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
    ));
}

#[test]
fn rejected_votes_release_pending_finality_indexes() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    for index in 0..64 {
        let body = VoteBody::new(
            Round::new(machine.profile().protocol().epoch(), View::new(1)),
            digest(format!("invalid leader {index}").as_bytes()),
            vec![Position::new(0); 6],
            vec![Extension::empty(); 6],
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        let verification = observe(
            &mut machine,
            Artifact::Vote(Vote::new(body, attestation(0))),
        );
        complete(&mut machine, &verification, false);
        assert_eq!(machine.finality.pending_pools(), 0);
    }
}

#[test]
fn ingress_bounds_apply_before_verification() {
    let mut machine = active_machine(Role::Observer);
    let far = leader_artifact(&machine, 4);
    let wrong_epoch = {
        let other = Machine::new(
            Profile::new(
                config(Epoch::new(8)),
                Role::Observer,
                Tuning {
                    view_timeout: Duration::from_secs(1),
                    production_interval: Duration::from_millis(100),
                    view_retention: retention_for(resources(), 1),
                    ..Tuning::default()
                },
            )
            .unwrap(),
        );
        leader_artifact(&other, 1)
    };

    let step = machine
        .step(cohort::<Sha256, _>(vec![far, wrong_epoch]))
        .unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("observation input must be classified");
    };
    assert_eq!(
        results[0].status(),
        ObservationStatus::Rejected(Rejection::FutureView)
    );
    assert_eq!(
        results[1].status(),
        ObservationStatus::Rejected(Rejection::Context)
    );
    assert!(step.capabilities().is_empty());
    assert_eq!(machine.inspect().cached_artifacts(), 0);

    let artifacts = (0..=resources().max_verification_batch())
        .map(|_| leader_artifact(&machine, 1))
        .collect();
    let oversized = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    assert_eq!(
        oversized.status(),
        &StepStatus::CohortRejected {
            count: resources().max_verification_batch() + 1,
            rejection: Rejection::VerificationBatchTooLarge,
        }
    );
    assert!(oversized.capabilities().is_empty());

    let limits = resources_with_max_artifact_bytes(1);
    let mut limited = Machine::new(
        Profile::with_limits(
            config(Epoch::new(7)),
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_secs(1),
                production_interval: Duration::from_millis(100),
                view_retention: retention_for(limits, 1),
                ..Tuning::default()
            },
            limits,
        )
        .unwrap(),
    );
    let start = limited.step(Input::Start).unwrap();
    persist(&mut limited, &persist_job(&start));
    let artifact = leader_artifact(&limited, 1);
    let rejected = limited.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = rejected.status() else {
        panic!("individual oversized artifact must be classified");
    };
    assert_eq!(results[0].id(), None);
    assert_eq!(
        results[0].status(),
        ObservationStatus::Rejected(Rejection::ArtifactTooLarge)
    );
}

#[test]
fn inputs_are_lifecycle_gated() {
    let mut fresh = Machine::new(profile(Role::Observer));
    let artifact = leader_artifact(&fresh, 1);
    assert!(matches!(
        fresh.step(cohort::<Sha256, _>(vec![artifact])),
        Err(StepError::Lifecycle)
    ));
    assert!(matches!(
        fresh.step(Input::RecoveryComplete),
        Err(StepError::Lifecycle)
    ));

    let mut active = active_machine(Role::Observer);
    assert!(matches!(
        active.step(Input::Start),
        Err(StepError::Lifecycle)
    ));
    assert!(matches!(
        active.step(Input::RecoveryComplete),
        Err(StepError::Lifecycle)
    ));
}

#[test]
fn durable_broadcast_replays_with_stable_id() {
    let mut machine = active_machine(Role::Observer);
    let artifact = Artifact::NoVote(no_vote(&machine, View::new(1), 0));
    let before = machine.snapshot();
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(artifact.clone())))
        .unwrap();
    let job = persist_job(&reserved);

    assert_eq!(reserved.status(), &StepStatus::DurabilityReserved);
    assert!(before.outbox().is_empty());

    let id = match job.events()[0].change() {
        Change::OutboxQueued { id, .. } => *id,
        _ => panic!("expected queued outbox event"),
    };
    // Staging is application: the entry exists before its barrier acknowledges, and replaying
    // the same event over the pre-stage snapshot must rebuild it identically.
    assert_eq!(
        machine.snapshot().outbox().get(&id),
        Some(&DurableEffect::Broadcast(Arc::new(artifact.clone())))
    );
    let mut restored = Machine::restore(profile(Role::Observer), before).unwrap();
    for event in job.events() {
        restored.replay(event.clone()).unwrap();
    }
    assert!(!restored.inspect().is_live());
    assert_eq!(restored.snapshot(), machine.snapshot());

    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    // The view timer arms with the staged generation advance; the recovered outbox re-releases
    // at that barrier's acknowledgement.
    assert!(
        recovery
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Leader(LeaderCapability::ArmTimer(_)))),
        "recovery must arm the view timer at staging"
    );
    let recovered = persist(&mut restored, &persist_job(&recovery));
    let broadcast = recovered
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Durability(DurabilityCapability::Released(job)) => Some(job),
            _ => None,
        })
        .expect("recovery must reissue the durable outbox");
    let DurableEffect::Broadcast(actual) = broadcast.request() else {
        panic!("recovery must reissue the durable outbox");
    };
    assert_eq!(broadcast.id(), id);
    assert_eq!(actual.as_ref(), &artifact);

    let completion = restored
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id,
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(matches!(
        completion.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    assert!(restored.snapshot().outbox().contains_key(&id));
    assert!(completion.capabilities().is_empty());

    let mut restarted = Machine::restore(profile(Role::Observer), restored.snapshot()).unwrap();
    let recovery = restarted.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restarted, &persist_job(&recovery));
    assert!(recovered.capabilities().iter().any(
        |effect| matches!(durable_job(effect), Some(job) if job.id() == id
                && matches!(job.request(), DurableEffect::Broadcast(_)))
    ));
}

#[test]
fn restore_rejects_mismatched_publication_obligation_rows() {
    let profile = profile(Role::Observer);
    let mut machine = active_machine(Role::Observer);
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"obligation payload"),
    )
    .unwrap();
    let block = Arc::new(Artifact::TransactionBlock(SignedTransactionBlock::new(
        header,
        attestation(0),
    )));
    let queued = machine
        .reserve_test_effect(DurableEffect::Broadcast(block))
        .unwrap();
    let effect = queued_effect_id(&queued);
    persist(&mut machine, &persist_job(&queued));

    let canonical = machine.snapshot();
    let mut wrong_family = Machine::restore(profile.clone(), canonical.clone()).unwrap();
    wrong_family.durable.obligations.insert(
        effect,
        PublicationObligation::new(
            effect,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::ExitReplacedAfter {
                id: ObligationId::new(effect, 0),
                view: View::new(1),
            }],
        ),
    );
    assert!(Machine::restore(profile.clone(), wrong_family.snapshot()).is_err());

    let mut wrong_object = Machine::restore(profile.clone(), canonical).unwrap();
    wrong_object.durable.obligations.insert(
        effect,
        PublicationObligation::new(
            effect,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::BlockCertifiedAtLeast {
                id: ObligationId::new(effect, 0),
                chain: ChainId::new(1),
                height: Height::new(2),
            }],
        ),
    );
    assert!(Machine::restore(profile, wrong_object.snapshot()).is_err());
}

#[test]
fn publication_discharge_table_enforces_exact_boundaries() {
    let mut machine = active_machine(Role::Observer);
    let chain = ChainId::new(0);
    let height = Height::new(5);
    let block = EffectId::from_cursor(Cursor::new(10));
    let vote = EffectId::from_cursor(Cursor::new(11));
    let certificate = EffectId::from_cursor(Cursor::new(12));
    let exit = EffectId::from_cursor(Cursor::new(13));
    let own_message = EffectId::from_cursor(Cursor::new(14));
    let obligations = [
        PublicationObligation::new(
            block,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::BlockCertifiedAtLeast {
                id: ObligationId::new(block, 0),
                chain,
                height,
            }],
        ),
        PublicationObligation::new(
            vote,
            PublicationKind::Send,
            vec![PublicationDischarge::VoteCertifiedAtLeast {
                id: ObligationId::new(vote, 0),
                chain,
                height,
            }],
        ),
        PublicationObligation::new(
            certificate,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::CertificateSupersededAbove {
                id: ObligationId::new(certificate, 0),
                chain,
                height,
            }],
        ),
        PublicationObligation::new(
            exit,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::ExitReplacedAfter {
                id: ObligationId::new(exit, 0),
                view: View::new(8),
            }],
        ),
        PublicationObligation::new(
            own_message,
            PublicationKind::Broadcast,
            vec![PublicationDischarge::ViewRetired {
                id: ObligationId::new(own_message, 0),
                view: View::new(8),
            }],
        ),
    ];
    for obligation in obligations {
        machine
            .durable
            .obligations
            .insert(obligation.effect(), obligation);
    }

    assert!(
        machine
            .obligations_retired_by_da(chain, Height::new(4))
            .is_empty()
    );
    assert_eq!(
        machine.obligations_retired_by_da(chain, height),
        vec![block, vote]
    );
    assert_eq!(
        machine.obligations_retired_by_da(chain, Height::new(6)),
        vec![block, vote, certificate]
    );
    assert!(machine.obligations_retired_by_exit(View::new(8)).is_empty());
    assert_eq!(
        machine.obligations_retired_by_exit(View::new(9)),
        vec![exit]
    );
    assert!(
        machine
            .obligations_retired_by_floor(View::new(8))
            .is_empty()
    );
    assert_eq!(
        machine.obligations_retired_by_floor(View::new(9)),
        vec![own_message]
    );
}

#[test]
fn replayable_publication_is_exposed_before_its_obligation_barrier() {
    let mut machine = active_machine(Role::Observer);
    let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        1,
    )));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::clone(&artifact)))
        .unwrap();

    assert!(reserved.capabilities().iter().any(|effect| {
        matches!(durable_effect(effect), Some(DurableEffect::Broadcast(actual))
            if actual == &artifact)
    }));
    assert!(reserved.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));
}

#[test]
fn da_certificate_atomically_replaces_the_block_and_vote_publications() {
    let role = Role::Validator(Participant::new(0));
    let (mut machine, mut step) = start_profile(profile_for(role, 6, 2));
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        step = persist(&mut machine, &job);
    }
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(0),
        Height::new(1),
        genesis.digest(),
        digest(b"superseded block"),
    )
    .unwrap();
    let block = Arc::new(Artifact::TransactionBlock(SignedTransactionBlock::new(
        header.clone(),
        attestation(0),
    )));
    let vote = Arc::new(Artifact::DaVote(DaVote::new(
        header.clone(),
        threshold_share(0),
    )));
    let block_step = machine
        .reserve_test_effect(DurableEffect::Broadcast(block))
        .unwrap();
    let block_id = queued_effect_id(&block_step);
    persist(&mut machine, &persist_job(&block_step));
    let vote_step = machine
        .reserve_test_effect(DurableEffect::Send(SendRequest::new(
            Participant::new(0),
            vote,
        )))
        .unwrap();
    let vote_id = queued_effect_id(&vote_step);
    persist(&mut machine, &persist_job(&vote_step));

    let certificate = Artifact::DaCertificate(symbolic_da_certificate(header, 0));
    let verification = observe(&mut machine, certificate.clone());
    let replacement = complete_with_step(&mut machine, &verification, true);
    let job = persist_job(&replacement);
    let Change::DaCertificateAdvanced {
        publication,
        retired,
        artifact,
    } = job.events()[0].change()
    else {
        panic!("admitted DA certificate must replace its source publications");
    };
    assert_eq!(retired, &[block_id, vote_id]);
    assert!(publication.is_some());
    assert_eq!(artifact.as_ref(), &certificate);
    assert!(!machine.snapshot().outbox().contains_key(&block_id));
    assert!(!machine.snapshot().outbox().contains_key(&vote_id));
    let acknowledged = persist_raw(&mut machine, &job);
    let acknowledged = settle(&mut machine, acknowledged);
    assert!(acknowledged.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));
    assert!(!machine.snapshot().outbox().contains_key(&block_id));
    assert!(!machine.snapshot().outbox().contains_key(&vote_id));
}

#[test]
fn full_outbox_exit_replacement_uses_the_retired_slot() {
    let resources = resources_with_capacities(16, 1)
        .with_max_forwarded_certificates(NonZeroUsize::new(16).unwrap());
    let profile = profile_with_resources(Role::Observer, 6, 2, resources);
    let (mut machine, _) = start_profile(profile);

    for view in 1..=2 {
        let artifact =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, artifact);
        let mut step = complete_with_step(&mut machine, &verification, true);
        for _ in 0..8 {
            let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
                _ => None,
            }) else {
                break;
            };
            step = persist(&mut machine, &job);
        }
    }

    let exits = machine
        .durable
        .obligations
        .values()
        .flat_map(PublicationObligation::discharges)
        .filter_map(|discharge| match discharge {
            PublicationDischarge::ExitReplacedAfter { view, .. } => Some(*view),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exits, vec![View::new(2)]);
    assert_eq!(machine.snapshot().outbox().len(), 1);
}

#[test]
fn delayed_da_vote_signing_completion_retires_after_certification() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"certified before signing completion"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, header.clone(), genesis.chain().get());
    let sign = sign_job(&reserved);
    persist(&mut machine, &persist_job(&reserved));

    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(header.clone(), 1)),
    );
    let certified = complete_with_step(&mut machine, &certificate, true);
    persist(&mut machine, &persist_job(&certified));
    assert_eq!(
        machine.snapshot().certified_tips()[genesis.chain().get() as usize].height(),
        Height::new(1)
    );

    let vote = Artifact::DaVote(DaVote::new(header, threshold_share(0)));
    let vote_id = vote.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(vote),
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let completion_job = persist_job(&completed);
    let [event] = completion_job.events() else {
        panic!("signed completion must remain one durable transition");
    };
    let Change::SignedArtifact { publication, .. } = event.change() else {
        panic!("the delayed signing result must complete its reservation");
    };
    assert!(!machine.snapshot().outbox().contains_key(&sign.id()));
    assert!(!machine.snapshot().outbox().contains_key(publication));
    assert!(!machine.snapshot().obligations().contains_key(publication));
    assert!(machine.snapshot().local_artifacts().contains_key(&vote_id));
}

#[test]
fn typed_obligation_family_bounds_match_their_retained_state() {
    let machine = active_machine(Role::Observer);
    let bounds = machine.obligation_family_bounds();
    let participants = machine.profile().protocol().codec_config().participants();
    let depth = machine.profile().protocol().codec_config().pipeline_depth();
    let retained_views = usize::try_from(machine.profile().view_retention().get() + 1).unwrap();

    assert_eq!(bounds.own_messages, retained_views * 4);
    assert_eq!(bounds.da, participants * depth * 3);
}

#[test]
fn da_frontier_cannot_monopolize_durable_progress() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let genesis = machine.profile().protocol().genesis().tips();
    let certificates = [0, 1].map(|chain| {
        let tip = genesis[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            tip.chain(),
            Height::new(1),
            tip.digest(),
            digest(format!("certified chain {chain}").as_bytes()),
        )
        .unwrap();
        Artifact::DaCertificate(symbolic_da_certificate(header, chain as u64))
    });
    let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 2));

    let observed = machine
        .step(cohort::<Sha256, _>(
            certificates.into_iter().chain([exit]).collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("the artifact batch must be verified together");
    };
    let verdicts = verification
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), true))
        .collect();
    let first = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verdicts,
        )))
        .unwrap();
    let first = settle(&mut machine, first);
    let first_job = persist_job(&first);
    let next = persist(&mut machine, &first_job);
    let next_job = persist_job(&next);
    let mut changes = first_job
        .events()
        .iter()
        .chain(next_job.events())
        .map(|event| event.change());
    assert!(
        changes
            .clone()
            .any(|change| matches!(change, Change::DaCertificateAdvanced { .. }))
    );
    assert!(changes.any(|change| matches!(change, Change::ArtifactForwarded { .. })));
}

#[test]
fn higher_da_certificate_replacement_replays_atomically() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"first certified block"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        first.epoch(),
        first.chain(),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"retained intermediate block"),
    )
    .unwrap();
    let third = TransactionBlockHeader::new(
        second.epoch(),
        second.chain(),
        Height::new(3),
        second.block_ref::<Sha256>().digest(),
        digest(b"higher certified block"),
    )
    .unwrap();

    let first_certificate = symbolic_da_certificate(first, 1);
    let first_verification = observe(
        &mut machine,
        Artifact::DaCertificate(first_certificate.clone()),
    );
    let advanced = complete_with_step(&mut machine, &first_verification, true);
    persist(&mut machine, &persist_job(&advanced));
    let first_publication = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(Artifact::DaCertificate(
            first_certificate,
        ))))
        .unwrap();
    let first_publication_id = queued_effect_id(&first_publication);
    persist(&mut machine, &persist_job(&first_publication));

    validate_block(&mut machine, second, 0);
    let checkpoint = machine.snapshot();

    let third_certificate = symbolic_da_certificate(third, 3);
    let third_verification = observe(
        &mut machine,
        Artifact::DaCertificate(third_certificate.clone()),
    );
    let replacement = complete_with_step(&mut machine, &third_verification, true);
    let replacement_job = persist_job(&replacement);
    let Change::DaCertificateAdvanced {
        publication,
        retired,
        artifact,
    } = replacement_job.events()[0].change()
    else {
        panic!("the higher certificate must replace its certified ancestor");
    };
    assert_eq!(retired, &[first_publication_id]);
    let publication = publication.expect("the replacement needs one active retry");
    assert!(matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
        if actual == &third_certificate));

    let mut restored = Machine::restore(profile, checkpoint).unwrap();
    for event in replacement_job.events() {
        restored.replay(event.clone()).unwrap();
    }
    let snapshot = restored.snapshot();
    assert!(!snapshot.outbox().contains_key(&first_publication_id));
    assert!(matches!(snapshot.outbox().get(&publication),
        Some(DurableEffect::Broadcast(artifact))
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
                if actual == &third_certificate)));
    let recovered = restored.step(Input::RecoveryComplete).unwrap();
    let released = persist(&mut restored, &persist_job(&recovered));
    assert!(
        !restored
            .snapshot()
            .outbox()
            .contains_key(&first_publication_id)
    );
    assert!(released.capabilities().iter().any(|effect| {
        matches!(durable_job(effect), Some(job)
        if job.id() == publication
            && matches!(job.request(), DurableEffect::Broadcast(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
                if actual == &third_certificate))
            )
    }));
}

#[test]
fn vqc_does_not_supersede_a_vote_needed_for_lqc() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let vote = Arc::new(Artifact::Vote(view_vote(&machine, &proposed, 0)));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(vote))
        .unwrap();
    let vote_id = queued_effect_id(&reserved);
    persist(&mut machine, &persist_job(&reserved));

    let certificate = Artifact::Vqc(view_one_vqc(&machine));
    let verification = observe(&mut machine, certificate);
    let mut step = complete_with_step(&mut machine, &verification, true);
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        step = persist(&mut machine, &job);
    }
    assert!(machine.snapshot().outbox().contains_key(&vote_id));
}

#[test]
fn a_skipped_view_must_be_nullified_even_after_retirement() {
    // A proposal may only skip views that provably could not have finalized. Retiring a view drops
    // its live records, so the rule must still reject a gap over a view that exited with a V-QC.
    let profile = profile_for(Role::Validator(Participant::new(3)), 6, 2);
    let (machine, _) = start_profile(profile.clone());
    let mut views = ViewState::<MinPk, Digest>::new(&profile);

    // Adjacent views leave no gap.
    assert!(views.gap_is_nullified(View::new(1), View::new(2)));

    // View 1 is retired without ever being nullified: a view-3 proposal parented at view 1 skips
    // view 2, and a view-2 proposal parented at genesis skips view 1.
    views.retire_transitions_through(View::new(1));
    assert!(
        !views.gap_is_nullified(View::zero(), View::new(2)),
        "a retired view that was never nullified must not be skippable"
    );
    assert!(
        !views.gap_is_nullified(View::new(1), View::new(3)),
        "a live view that was never nullified must not be skippable"
    );

    // Once view 1's nullification is durably forwarded, skipping it is allowed even though the
    // view is retired and its live record is gone.
    views.observe_forwarded::<Sha256>(&Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        7,
    )));
    assert!(views.gap_is_nullified(View::zero(), View::new(2)));
    assert!(
        !views.gap_is_nullified(View::zero(), View::new(3)),
        "view 2 is still not nullified"
    );
}

#[test]
fn vqc_anchor_does_not_nullify_its_own_view() {
    let profile = profile_for(Role::Validator(Participant::new(3)), 6, 2);
    let (mut machine, _) = start_profile(profile);

    let certificate = view_one_vqc(&machine);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let mut step = complete_with_step(&mut machine, &verification, true);
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        step = persist(&mut machine, &job);
    }
    assert_eq!(machine.inspect().view(), View::new(2));

    let stale = leader(&machine, 2);
    let signer = machine.profile().protocol().leader(View::new(2));
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(stale, attestation(signer.get()))),
    );
    let completed = complete_with_step(&mut machine, &verification, true);

    assert!(!completed.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if job.events().iter().any(|event| {
            matches!(event.change(), Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_))))
        }))
    }));
}

#[test]
fn proposal_frontier_survives_retention_and_restart() {
    let target = View::new(6);
    let signer = LeaderSchedule::round_robin(6).leader(target);
    let profile = profile_with_retention(
        Role::Validator(signer),
        6,
        2,
        resources(),
        ViewDelta::new(2),
    );
    let (mut machine, _) = start_profile(profile.clone());
    let mut proposal_reserved = false;

    let anchor = Artifact::Vqc(view_one_vqc(&machine));
    let anchor_id = match &anchor {
        Artifact::Vqc(certificate) => certificate.id::<Sha256>(),
        _ => unreachable!(),
    };
    let verification = observe(&mut machine, anchor);
    let mut step = complete_with_step(&mut machine, &verification, true);
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        step = persist(&mut machine, &job);
    }

    for view in 2..target.get() {
        let certificate =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, certificate);
        let mut step = complete_with_step(&mut machine, &verification, true);
        while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) {
            proposal_reserved |= job.events().iter().any(|event| {
                matches!(event.change(), Change::OutboxQueued { effect, .. }
                    if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::LeaderBlock(_))))
            });
            step = persist(&mut machine, &job);
        }
    }

    assert_eq!(machine.inspect().view(), target);
    assert_eq!(machine.durable.retired_view, View::new(3));
    assert_eq!(machine.durable.proposal_nullified_through, View::new(5));
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(certificate)) if certificate.id::<Sha256>() == anchor_id));
    assert!(
        proposal_reserved,
        "the target leader never reserved its proposal"
    );

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restored, &persist_job(&recovery));
    assert!(recovered.capabilities().iter().any(|effect| {
        matches!(
            durable_effect(effect),
            Some(DurableEffect::Sign(SignRequest::LeaderBlock(_)))
        )
    }));
}

#[test]
fn retired_leader_dependencies_plateau() {
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);

    for view in 1..=32 {
        let block = leader(&machine, view);
        let signer = machine.profile().protocol().leader(block.view());
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(signer.get()))),
        );
        let admitted = complete_with_step(&mut machine, &verification, true);
        drive_poll_and_persist(&mut machine, admitted);

        let view = View::new(view);
        let exit = symbolic_nullification(&machine, view, view.get());
        let verification = observe(&mut machine, Artifact::Nullification(exit));
        let admitted = complete_with_step(&mut machine, &verification, true);
        drive_poll_and_persist(&mut machine, admitted);
    }

    let retained = machine
        .available
        .iter()
        .filter(|dependency| matches!(dependency, Dependency::Leader { .. }))
        .count();
    assert!(retained <= 4, "retained {retained} leader dependencies");
}

#[test]
fn future_lqc_durably_advances_consensus_floors() {
    let profile = profile_for(Role::Validator(Participant::new(3)), 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let before = machine.snapshot();

    let genesis = machine.profile().protocol().genesis().tips()[3];
    let transaction = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(3),
        Height::new(1),
        genesis.digest(),
        digest(b"pending transaction"),
    )
    .unwrap();
    let transaction = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::TransactionBlock(
            transaction,
        )))
        .unwrap();
    let transaction_id = queued_effect_id(&transaction);
    persist(&mut machine, &persist_job(&transaction));

    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    let pending = machine
        .reserve_test_effect(DurableEffect::SignBatch(
            vec![
                SignRequest::NoVote { round },
                SignRequest::Nullify { round },
            ]
            .into(),
        ))
        .unwrap();
    let pending_id = queued_effect_id(&pending);
    persist(&mut machine, &persist_job(&pending));

    let finalized = leader(&machine, 5);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let advanced = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, advanced);

    assert_eq!(machine.inspect().view(), View::new(6));
    assert!(
        !machine
            .snapshot()
            .signing_reservations()
            .contains_key(&pending_id)
    );
    assert!(
        machine
            .snapshot()
            .signing_reservations()
            .contains_key(&transaction_id)
    );
    assert_eq!(machine.snapshot().certified_tips(), before.certified_tips());
    assert_eq!(
        machine.snapshot().da_safety_heights(),
        before.da_safety_heights()
    );
    assert!(effects.iter().any(|effect| {
        matches!(effect, Capability::Leader(LeaderCapability::ArmTimer(timer)) if timer.round().view() == View::new(6))
    }));
    assert!(
        effects.iter().any(|effect| {
            matches!(
                durable_effect(effect),
                Some(DurableEffect::Broadcast(artifact))
                    if matches!(artifact.as_ref(), Artifact::Vqc(derived)
                        if certificate.equivalent_vqc(derived))
            )
        }),
        "an inbound L-QC must forward its derivable V-QC before leaving the view"
    );

    assert!(matches!(machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor))
            if anchor.leader() == certificate.leader()
                && anchor.tally() == certificate.tally()
                && anchor.novoters().count() == 0
                && anchor.conflicting_votes().is_empty()));
    assert_eq!(machine.inspect().finality_floor(), certificate.view());

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.inspect().finality_floor(), certificate.view());
    assert!(matches!(restored.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(restored.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
    assert_eq!(
        restored.snapshot().certified_tips(),
        before.certified_tips()
    );
    assert_eq!(
        restored.snapshot().da_safety_heights(),
        before.da_safety_heights()
    );
}

#[test]
fn future_lqc_advances_signing_and_proposal_floors_without_resolution_and_restores() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let finalized = leader(&machine, 5);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, admitted);

    assert_eq!(machine.inspect().view(), View::new(6));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_))))
    );
    assert_eq!(machine.inspect().finality_floor(), certificate.view());
    assert!(matches!(machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));

    let restored = Machine::restore(machine.profile().clone(), machine.snapshot()).unwrap();
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.inspect().finality_floor(), certificate.view());
    assert!(matches!(restored.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(restored.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
}

#[test]
fn late_lqc_advances_signing_and_proposal_floors_without_resolution_and_restores() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    for view in 1..=5 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = complete_with_step(&mut machine, &verification, true);
        drive_poll_and_persist(&mut machine, admitted);
    }

    let finalized = leader(&machine, 5);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, admitted);

    assert_eq!(machine.inspect().view(), View::new(6));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_))))
    );
    assert_eq!(machine.inspect().finality_floor(), certificate.view());
    assert!(matches!(machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));

    let restored = Machine::restore(machine.profile().clone(), machine.snapshot()).unwrap();
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.inspect().finality_floor(), certificate.view());
    assert!(matches!(restored.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(restored.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
}

#[test]
fn verified_lqc_beyond_diagnostic_retention_advances_consensus_floors() {
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    for view in 1..=8 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = complete_with_step(&mut machine, &verification, true);
        drive_poll_and_persist(&mut machine, admitted);
    }
    assert_eq!(machine.inspect().view(), View::new(9));
    assert!(machine.retention_floor() > View::new(3));

    let finalized = leader(&machine, 3);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate.clone()));
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, admitted);

    assert_eq!(machine.inspect().view(), View::new(9));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_))))
    );
    assert_eq!(machine.inspect().finality_floor(), certificate.view());
    assert!(matches!(machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
}

#[test]
fn late_finality_admissions_retain_only_the_highest_proof_without_parents() {
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), ViewDelta::new(2));
    let (mut machine, _) = start_profile(profile);
    for view in 1..=8 {
        let exit = Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, exit);
        let admitted = complete_with_step(&mut machine, &verification, true);
        drive_poll_and_persist(&mut machine, admitted);
    }
    let retained_parents = machine.views.retained_parents();

    for view in [3, 4, 5] {
        let finalized = leader(&machine, view);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &finalized, signer))
            .collect::<Vec<_>>();
        let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));
        machine
            .apply_finality(proof.id::<Sha256>(), Observation::new(view, 0), proof)
            .unwrap();
    }

    assert_eq!(machine.views.retained_finality_proofs(), 1);
    assert_eq!(machine.views.retained_parents(), retained_parents);
    assert!(matches!(
        machine.next_finality_floor_change_for_test(),
        Some(Change::FinalityFloorAdvanced { proof, .. })
            if proof.view() == Some(View::new(5))
    ));
}

#[test]
fn parent_retirement_preserves_history_for_a_retained_leader() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let parent = view_one_vqc(&machine);
    let verification = observe(&mut machine, Artifact::Vqc(parent.clone()));
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);

    let (leader, history) = leader_extending_view_one_vqc(&machine, 2, &parent);
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            leader.clone(),
            attestation(signer.get()),
        )),
    );
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);

    machine.views.retire_parents_through(View::new(2), None);
    assert_eq!(
        machine
            .views
            .leader_history::<Sha256>(&leader)
            .unwrap()
            .commitment::<Sha256>(),
        history
    );
}

#[test]
fn successive_lqc_floors_retain_only_the_latest_proposal_parent() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);

    for view in [5, 10, 15] {
        let finalized = leader(&machine, view);
        let votes = (0..5)
            .map(|signer| view_vote(&machine, &finalized, signer))
            .collect::<Vec<_>>();
        let certificate = lqc(&machine, finalized, &votes);
        let verification = observe(&mut machine, Artifact::Lqc(certificate));
        let advanced = complete_with_step(&mut machine, &verification, true);
        let (effects, _) = drive_poll_and_persist(&mut machine, advanced);
        assert!(
            effects.iter().all(|effect| !matches!(
                effect,
                Capability::Resolver(ResolverCapability::Resolve(_))
            ))
        );
        assert_eq!(machine.views.retained_finality_proofs(), 0);
    }

    assert_eq!(machine.inspect().view(), View::new(16));
    assert_eq!(machine.inspect().finality_floor(), View::new(15));
    assert_eq!(machine.views.retained_parents(), 2);
}

#[test]
fn ordinary_view_progress_does_not_arm_recovery_pulls() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let first = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &first, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, first, &votes);
    let derived = certificate
        .derive_vqc(machine.profile().protocol().codec_config())
        .unwrap();
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (mut effects, _) = drive_poll_and_persist(&mut machine, admitted);

    let template = leader(&machine, 2);
    let second = LeaderBlock::new(
        template.round(),
        derived.id::<Sha256>(),
        derived.leader().history(),
        template.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &second, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, second, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = complete_with_step(&mut machine, &verification, true);
    effects.extend(drive_poll_and_persist(&mut machine, admitted).0);

    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_)))),
        "ordinary view progress must not enter the recovery network path"
    );
}

#[test]
fn floor_pull_retries_once_per_view_until_lqc_advances_the_floor() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);

    let first = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &first, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, first, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);
    assert_eq!(machine.inspect().view(), View::new(2));
    assert!(matches!(
        machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));

    let exit = symbolic_nullification(&machine, View::new(2), 2);
    let verification = observe(&mut machine, Artifact::Nullification(exit.clone()));
    let advanced = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, advanced);
    assert_eq!(machine.inspect().view(), View::new(3));
    let pulls = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCapability::Resolve(job)) => Some(*job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(pulls.len(), 1);
    let floor_pull = pulls[0];
    assert_eq!(floor_pull.view(), View::new(2));
    assert_eq!(machine.inspect().resolution_jobs(), 1);

    let completed = machine
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            floor_pull.id(),
            floor_pull.generation(),
            floor_pull.view(),
            ViewProof::Nullification(Box::new(exit)),
        )))
        .unwrap();
    let (effects, _) = drive_poll_and_persist(&mut machine, completed);
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Capability::Resolver(ResolverCapability::Cancel(job)) if *job == floor_pull))
    );
    assert!(
        effects.iter().all(
            |effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(job)) if job.view() == floor_pull.view())
        )
    );
    assert_eq!(machine.inspect().resolution_jobs(), 0);

    let next_exit = symbolic_nullification(&machine, View::new(3), 3);
    let verification = observe(&mut machine, Artifact::Nullification(next_exit));
    let advanced = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, advanced);
    assert_eq!(machine.inspect().view(), View::new(4));
    let rearmed = effects
        .iter()
        .filter_map(|effect| match effect {
            Capability::Resolver(ResolverCapability::Resolve(job))
                if job.view() == floor_pull.view() =>
            {
                Some(*job)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rearmed.len(), 1);
    assert_ne!(rearmed[0].id(), floor_pull.id());
    assert_eq!(machine.inspect().resolution_jobs(), 1);

    let second = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &second, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, second, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, admitted);
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Capability::Resolver(ResolverCapability::Cancel(job)) if *job == rearmed[0]))
    );
    assert!(
        effects.iter().all(
            |effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(job)) if job.view() == floor_pull.view())
        )
    );
    assert!(matches!(
        machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(2)
    ));
    assert_eq!(machine.inspect().resolution_jobs(), 0);
}

#[test]
fn sign_self_admits_before_publication_attempt() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = reserved
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
        .expect("private signing must start before its reservation is acknowledged");
    let signing_barrier = persist_job(&reserved);

    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let Artifact::LeaderBlock(expected) = &artifact else {
        unreachable!("the test constructs a leader artifact")
    };
    let id = artifact.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact.clone()),
        }))
        .unwrap();
    assert!(matches!(
        completed.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    // The parked completion self-admits when the scheduler stages it, before any barrier
    // acknowledgement and before any publication attempt. Its signed transition reaches the
    // journal immediately so it can join the sync pipeline behind the signing authorization.
    let completed = settle(&mut machine, completed);
    assert_eq!(machine.inspect().ready_artifacts(), &[id]);
    assert!(completed.activities().iter().any(|activity| matches!(
        activity,
        Activity::ProtocolAccepted {
            artifact_id,
            artifact: accepted,
        } if *artifact_id == id && accepted.as_ref() == &artifact
    )));
    let signed_barrier = persist_job(&completed);
    let inspection = machine.inspect();
    let outbox = inspection.outbox();
    assert_eq!(outbox.len(), 2);
    assert_eq!(outbox[0], baseline);
    let publication = outbox[1];
    assert!(!completed.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Verification(VerificationCapability::Verify(_))
    )));
    assert!(
        !completed
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Durability(DurabilityCapability::Released(job)) if job.id() == publication))
    );
    assert!(matches!(
        machine.durable.local.get(&id),
        Some(recorded) if recorded.as_ref() == &artifact
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, publication]);

    let duplicate = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact.clone()),
        }))
        .unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    let echo = machine
        .step(cohort::<Sha256, _>(vec![artifact.clone()]))
        .unwrap();
    assert!(matches!(
        echo.status(),
        StepStatus::Observed(results) if results[0].status() == ObservationStatus::Duplicate
    ));

    let acknowledged = persist_raw(&mut machine, &signing_barrier);
    assert!(
        !acknowledged
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Sign(_))))
    );
    assert!(
        !acknowledged
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Durability(DurabilityCapability::Released(job)) if job.id() == publication))
    );
    assert!(acknowledged.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));
    let [event] = signed_barrier.events() else {
        panic!("the signed artifact must be recorded atomically");
    };
    let Change::SignedArtifact {
        sign: completed_sign,
        publication: recorded_publication,
        artifact: recorded,
    } = event.change()
    else {
        panic!("the signing completion must record its exact artifact");
    };
    assert_eq!(*completed_sign, sign.id());
    assert_eq!(*recorded_publication, publication);
    assert_eq!(recorded.as_ref(), &artifact);

    let published = persist(&mut machine, &signed_barrier);
    let mut publications = published
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if job.id() == publication =>
            {
                Some(job)
            }
            _ => None,
        });
    let broadcast = publications
        .next()
        .expect("signed proposal must publish after its barrier is acknowledged");
    assert!(publications.next().is_none());
    let DurableEffect::Propose(proposal) = broadcast.request() else {
        panic!("signed proposal must become a durable proposal publication");
    };
    assert_eq!(proposal.block().as_ref(), expected);
    assert!(proposal.parent().is_genesis());
    assert_eq!(machine.inspect().outbox(), &[baseline, broadcast.id()]);

    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert_eq!(machine.inspect().outbox(), &[baseline, broadcast.id()]);
}

#[test]
fn signed_completion_reaches_the_journal_behind_an_inflight_barrier() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    // Signing carries no signature out, so the request releases alongside its barrier.
    let [
        Capability::Durability(DurabilityCapability::Released(sign)),
        Capability::Durability(DurabilityCapability::Persist(_)),
    ] = reserved.capabilities()
    else {
        panic!("a staged signing choice must release its request");
    };
    assert!(matches!(sign.request(), DurableEffect::Sign(_)));
    persist(&mut machine, &persist_job(&reserved));

    let unrelated = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let artifact_id = artifact.id::<Sha256>();
    let buffered = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact.clone()),
        }))
        .unwrap();
    assert!(matches!(
        buffered.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    assert!(buffered.capabilities().is_empty());
    assert!(machine.inspect().ready_artifacts().is_empty());

    let duplicate = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact.clone()),
        }))
        .unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    // The poll admits the artifact and hands its signed transition to the journal immediately.
    // The active sync cannot cover the later append, but the journal can append behind it and
    // include every urgent tail event in exactly one successor sync.
    let staged = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(staged.activities().iter().any(|activity| matches!(
        activity,
        Activity::ProtocolAccepted {
            artifact_id: accepted,
            artifact: reported,
        } if *accepted == artifact_id && reported.as_ref() == &artifact
    )));
    assert_eq!(machine.inspect().ready_artifacts(), &[artifact_id]);
    assert!(
        !staged.capabilities().iter().any(|effect| matches!(
            effect,
            Capability::Verification(VerificationCapability::Verify(_))
        ) || matches!(
            durable_effect(effect),
            Some(DurableEffect::Propose(_))
        )),
        "self-admission must not loop back and the publication must wait for durability"
    );
    let mut jobs = staged
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job),
            _ => None,
        });
    let signed = jobs
        .next()
        .expect("the signed transition must reach the journal immediately")
        .clone();
    assert!(jobs.next().is_none());
    let [event] = signed.events() else {
        panic!("the signed-artifact transition must be atomic");
    };
    let Change::SignedArtifact {
        sign: completed_sign,
        artifact: recorded,
        ..
    } = event.change()
    else {
        panic!("the buffered completion must stage a signed artifact");
    };
    assert_eq!(*completed_sign, sign.id());
    assert_eq!(recorded.as_ref(), &artifact);

    // Acknowledging the older barrier neither emits the already handed-off transition again nor
    // releases its publication before the successor sync is durable.
    let resumed = persist_raw(&mut machine, &persist_job(&unrelated));
    assert!(
        resumed
            .capabilities()
            .iter()
            .all(|effect| { !matches!(durable_effect(effect), Some(DurableEffect::Propose(_))) })
    );
    assert!(
        resumed.capabilities().iter().all(|effect| !matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        )),
        "the signed transition was already handed to the journal"
    );

    let published = persist(&mut machine, &signed);
    let publication = published
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Durability(DurabilityCapability::Released(job)) => Some(job),
            _ => None,
        })
        .expect("the self-admitted artifact must publish without a network loopback");
    assert!(matches!(publication.request(), DurableEffect::Propose(_)));
}

#[test]
fn one_poll_emits_at_most_one_persistence_range() {
    let resources = resources_with_capacities(128, 128);
    let profile = Profile::with_limits(
        config_for_producers(Epoch::new(7), 2, vec![Participant::new(0)], 2),
        Role::Validator(Participant::new(1)),
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(resources, 2),
            ..Tuning::default()
        },
        resources,
    )
    .unwrap();
    let (mut machine, _) = start_profile(profile);

    let signer = Participant::new(1);
    let mut view = 2;
    for _ in 0..3 {
        while machine
            .profile()
            .protocol()
            .leaders()
            .leader(View::new(view))
            != signer
        {
            view += 1;
        }
        let proposed = leader(&machine, view);
        let reserved = machine
            .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
                proposal_request(proposed.clone()),
            )))
            .unwrap();
        let sign = sign_job(&reserved);
        let buffered = machine
            .step(Input::EffectCompleted(EffectCompletion::Signed {
                id: sign.id(),
                generation: sign.generation(),
                artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                    proposed,
                    attestation(signer.get()),
                ))),
            }))
            .unwrap();
        assert!(buffered.capabilities().is_empty());
        let emitted = settle(&mut machine, buffered);
        assert_eq!(
            emitted
                .capabilities()
                .iter()
                .filter(|effect| matches!(
                    effect,
                    Capability::Durability(DurabilityCapability::Persist(_))
                ))
                .count(),
            1,
        );
        view += 1;
    }

    for filler in 10..42 {
        let step = machine
            .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
                &machine,
                1_000 + filler,
            ))))
            .unwrap();
        assert!(step.capabilities().iter().all(|effect| !matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        )));
    }

    while machine
        .profile()
        .protocol()
        .leaders()
        .leader(View::new(view))
        != signer
    {
        view += 1;
    }
    let proposed = leader(&machine, view);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    assert!(reserved.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));
    let sign = sign_job(&reserved);
    let artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(signer.get())));
    let buffered = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact),
        }))
        .unwrap();
    assert!(buffered.capabilities().is_empty());

    let first = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(first.work_remaining());
    assert_eq!(
        first
            .capabilities()
            .iter()
            .filter(|effect| matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            ))
            .count(),
        1,
    );
    let second = machine.poll(NonZeroUsize::MIN).unwrap();
    assert_eq!(
        second
            .capabilities()
            .iter()
            .filter(|effect| matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            ))
            .count(),
        1,
    );
}

#[test]
fn late_lqc_advances_the_signing_floor_after_the_view_exits() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal_signer = LeaderSchedule::round_robin(6).leader(View::new(1));
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(proposal_signer.get()),
        )),
    );
    complete(&mut machine, &proposal, true);
    let mut vqc_job = None;
    let mut lqc_job = None;
    for signer in 0..5 {
        let vote = view_vote(&machine, &proposed, signer);
        let observed = observe(&mut machine, Artifact::Vote(vote));
        let step = complete_with_step(&mut machine, &observed, true);
        if signer == 4 {
            let (effects, _) = drive_poll_and_persist(&mut machine, step);
            for effect in effects.iter() {
                match effect {
                    Capability::Leader(LeaderCapability::AggregateVqc(job)) => {
                        vqc_job = Some(job.clone())
                    }
                    Capability::Leader(LeaderCapability::AggregateLqc(job)) => {
                        lqc_job = Some(job.clone())
                    }
                    _ => {}
                }
            }
        }
    }
    let vqc_job = vqc_job.expect("the full quorum must schedule V-QC assembly");
    let lqc_job = lqc_job.expect("the full quorum must schedule L-QC assembly");

    // The view exits through the assembled V-QC before the L-QC aggregation completes, which
    // is the ordinary order outside inline-crypto tests: the same quorum that finalizes the
    // leader also exits the view, and the finality aggregation finishes strictly later.
    let messages = vqc_job.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, vqc_job.leader().clone(), &messages);
    let exited = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            vqc_job.id(),
            vqc_job.generation(),
            certificate,
        ))))
        .unwrap();
    drive_poll_and_persist(&mut machine, exited);
    assert_eq!(machine.inspect().view(), View::new(2));

    // The late L-QC must still advance the signing floor; the view and its timer stay where
    // the ordinary exit put them.
    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let step = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            lqc_job.id(),
            lqc_job.generation(),
            assembled,
        ))))
        .unwrap();
    drive_poll_and_persist(&mut machine, step);
    assert!(
        matches!(
            machine.durable.signing_floor.as_deref(),
            Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
        ),
        "the late L-QC must set the signing floor"
    );
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn late_old_view_vote_assembles_lqc_after_view_advance() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal_signer = LeaderSchedule::round_robin(6).leader(View::new(1));
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(proposal_signer.get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let mut messages = (0..4)
        .map(|signer| ViewMessage::Vote(view_vote(&machine, &proposed, signer)))
        .collect::<Vec<_>>();
    messages.push(ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)));
    let mut effects = None;
    for (index, message) in messages.iter().enumerate() {
        let artifact = match message {
            ViewMessage::Vote(vote) => Artifact::Vote(vote.clone()),
            ViewMessage::NoVote(no_vote) => Artifact::NoVote(no_vote.clone()),
        };
        let verification = observe(&mut machine, artifact);
        let admitted = complete_with_step(&mut machine, &verification, true);
        if index + 1 == messages.len() {
            effects = Some(drive_poll_and_persist(&mut machine, admitted).0);
        }
    }

    let effects = effects.expect("the last view message must drive certificate assembly");
    let vqc_job = effects
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("four votes and one novote must assemble a V-QC");
    assert!(
        effects.iter().all(|effect| !matches!(
            effect,
            Capability::Leader(LeaderCapability::AggregateLqc(_))
        )),
        "four votes must remain below the L-QC threshold"
    );

    let certificate = vqc(&machine, proposed.clone(), &messages);
    let advanced = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            vqc_job.id(),
            vqc_job.generation(),
            certificate,
        ))))
        .unwrap();
    drive_poll_and_persist(&mut machine, advanced);
    assert_eq!(machine.inspect().view(), View::new(2));

    let late_vote = Artifact::Vote(view_vote(&machine, &proposed, 4));
    let late = observe(&mut machine, late_vote);
    let admitted = complete_with_step(&mut machine, &late, true);
    let (effects, _) = drive_poll_and_persist(&mut machine, admitted);
    let lqc_job = effects
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the late fifth vote must complete the retained finality pool");

    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let completed = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            lqc_job.id(),
            lqc_job.generation(),
            assembled,
        ))))
        .unwrap();
    drive_poll_and_persist(&mut machine, completed);

    assert!(matches!(
        machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn finality_state_retains_its_lqc_after_artifact_cache_compaction() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));
    let proof_id = proof.id::<Sha256>();

    assert!(!machine.artifacts.contains_key(&proof_id));
    machine
        .views
        .observe_finality(proof_id, &proof)
        .expect("finality admits only authenticated L-QCs to the view state");

    let change = machine
        .next_finality_floor_change_for_test()
        .expect("the admitted L-QC raises the signing floor");
    assert!(matches!(
        change,
        Change::FinalityFloorAdvanced { proof: retained, .. }
            if retained.as_ref() == proof.as_ref()
    ));
}

#[test]
fn covered_finality_update_does_not_retain_its_lqc() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let finalized = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &finalized, signer))
        .collect::<Vec<_>>();
    let proof = Arc::new(Artifact::Lqc(lqc(&machine, finalized, &votes)));
    let proof_id = proof.id::<Sha256>();

    let verification = observe(&mut machine, proof.as_ref().clone());
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);
    assert!(matches!(
        machine.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(certificate)) if certificate.view() == View::new(1)
    ));
    assert_eq!(machine.views.retained_finality_proofs(), 0);
    let retained_parents = machine.views.retained_parents();

    machine
        .apply_finality(proof_id, Observation::new(2, 0), proof)
        .expect("the covered L-QC remains valid finality evidence");

    assert_eq!(machine.views.retained_finality_proofs(), 0);
    assert_eq!(machine.views.retained_parents(), retained_parents);
}

#[test]
fn barrier_acknowledgements_are_exact_and_ordered() {
    let pending = |view| {
        let mut machine = active_machine(Role::Observer);
        let reserved = machine
            .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
                &machine, view,
            ))))
            .unwrap();
        let barrier = persist_job(&reserved);
        (machine, barrier)
    };

    let (mut machine, barrier) = pending(2);
    let stale = machine
        .step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            barrier
                .generation()
                .checked_sub(1)
                .expect("the active generation must have a predecessor"),
            barrier.last_cursor(),
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().is_empty());

    for case in 0..5 {
        let (mut machine, barrier) = pending(2);
        let acknowledgement = match case {
            0 => BarrierAck::new(
                barrier.id(),
                barrier.generation() + 1,
                barrier.last_cursor(),
            ),
            1 => BarrierAck::new(
                BarrierId::new(barrier.id().get() + 1),
                barrier.generation(),
                barrier.last_cursor(),
            ),
            2 => BarrierAck::new(
                BarrierId::new(barrier.id().get() + 2),
                barrier.generation(),
                barrier.last_cursor(),
            ),
            3 => BarrierAck::new(barrier.id(), barrier.generation(), barrier.previous()),
            4 => BarrierAck::new(
                barrier.id(),
                barrier.generation(),
                barrier
                    .last_cursor()
                    .next()
                    .expect("the test barrier cursor must have a successor"),
            ),
            _ => unreachable!(),
        };
        assert!(
            matches!(
                machine.step(Input::Persisted(acknowledgement)),
                Err(StepError::CompletionMismatch)
            ),
            "impossible acknowledgement case {case} must be fatal"
        );
    }

    let (mut machine, first) = pending(2);
    let first_ack = BarrierAck::new(first.id(), first.generation(), first.last_cursor());
    let applied = machine.step(Input::Persisted(first_ack)).unwrap();
    assert_eq!(applied.status(), &StepStatus::Persisted);

    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let second = persist_job(&reserved);
    let duplicate = machine.step(Input::Persisted(first_ack)).unwrap();
    assert_eq!(duplicate.status(), &StepStatus::StaleCompletion);
    assert!(duplicate.capabilities().is_empty());

    let second_ack = BarrierAck::new(second.id(), second.generation(), second.last_cursor());
    let applied = machine.step(Input::Persisted(second_ack)).unwrap();
    assert_eq!(applied.status(), &StepStatus::Persisted);
    assert!(matches!(
        machine.step(Input::Persisted(first_ack)),
        Err(StepError::CompletionMismatch)
    ));

    let (mut machine, first) = pending(2);
    let _ = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine, 3,
        ))))
        .unwrap();
    let queued = machine
        .staged
        .back()
        .expect("the later barrier remains queued")
        .job
        .clone();
    assert_ne!(queued.id(), first.id());
    assert!(!machine.staged.back().unwrap().emitted);
    assert!(matches!(
        machine.step(Input::Persisted(BarrierAck::new(
            queued.id(),
            queued.generation(),
            queued.last_cursor(),
        ))),
        Err(StepError::CompletionMismatch)
    ));
}

#[test]
fn signature_publication_waits_for_its_exact_barrier_acknowledgement() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = sign_job(&reserved);
    persist(&mut machine, &persist_job(&reserved));

    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            ))),
        }))
        .unwrap();
    let staged = settle(&mut machine, completed);
    let barrier = persist_job(&staged);
    assert!(
        staged
            .capabilities()
            .iter()
            .all(|effect| { !matches!(durable_effect(effect), Some(DurableEffect::Propose(_))) })
    );

    assert!(matches!(
        machine.step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            barrier.generation() + 1,
            barrier.last_cursor(),
        ))),
        Err(StepError::CompletionMismatch)
    ));

    assert!(matches!(
        machine.step(Input::Persisted(BarrierAck::new(
            barrier.id(),
            barrier.generation(),
            Cursor::zero(),
        ))),
        Err(StepError::CompletionMismatch)
    ));

    let released = persist_raw(&mut machine, &barrier);
    assert!(matches!(released.status(), StepStatus::Persisted));
    assert!(matches!(
        released.capabilities(),
        [Capability::Durability(DurabilityCapability::Released(publication))]
            if matches!(publication.request(), DurableEffect::Propose(_))
    ));
}

#[test]
fn aggregate_publication_defers_to_the_signature_exposure_floor() {
    // An aggregate certificate may embed one of our shares, so its publication must wait
    // until every fresh local signature staged before it is durable. With such a signature
    // pending, the aggregate defers; the signature's acknowledgement releases both.
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = sign_job(&reserved);
    persist(&mut machine, &persist_job(&reserved));
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            ))),
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let signature_barrier = persist_job(&completed);

    // The signature is staged but not yet acknowledged: an aggregate queued now is unsafe to
    // release, even though nothing in it is individually ours.
    let aggregate = Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 7));
    let deferred = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(aggregate.clone())))
        .unwrap();
    assert!(
        !deferred
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Broadcast(_)))),
        "an aggregate queued behind an unacknowledged signature must defer"
    );

    // Acknowledging the signature floor releases both its publication and replayable work below
    // that floor. The aggregate's own metadata may remain in the append-behind-sync tail.
    let released = persist(&mut machine, &signature_barrier);
    assert!(
        released
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Propose(_)))),
        "the durable signature must release its own publication"
    );
    assert!(released.capabilities().iter().any(|effect| {
        matches!(durable_effect(effect), Some(DurableEffect::Broadcast(artifact))
            if artifact.as_ref() == &aggregate)
    }));
}

#[test]
fn observer_cannot_reserve_signing() {
    let mut machine = active_machine(Role::Observer);
    let leader = leader(&machine, 1);
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(leader),
        ))),
        Err(StepError::UnauthorizedEffect)
    ));
}

#[test]
fn observer_replay_rejects_queued_signing_authority() {
    let machine = Machine::new(profile(Role::Observer));
    let snapshot = machine.snapshot();
    let mut restored = Machine::restore(profile(Role::Observer), snapshot).unwrap();
    let proposed = leader(&restored, 1);
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        cursor,
        Change::OutboxQueued {
            id: EffectId::from_cursor(cursor),
            effect: Box::new(DurableEffect::Sign(SignRequest::LeaderBlock(
                proposal_request(proposed),
            ))),
        },
    );

    assert_eq!(restored.replay(event), Err(ReplayError::Transition));
    assert_eq!(restored.inspect().cursor(), Cursor::zero());
    assert!(restored.inspect().outbox().is_empty());
}

#[test]
fn replay_requires_view_advance_proof_to_be_retained_and_forwarded() {
    let profile = profile_for(Role::Observer, 6, 2);
    let machine = Machine::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let proof =
        Artifact::Nullification(symbolic_nullification(&restored, View::new(1), 0)).id::<Sha256>();
    let cursor = Cursor::zero().next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        cursor,
        Change::ViewAdvanced {
            proof,
            retired: Vec::new(),
        },
    );

    assert_eq!(restored.replay(event), Err(ReplayError::Transition));
    assert_eq!(restored.inspect().view(), View::new(1));
}

#[test]
fn replay_requires_the_views_first_vqc_forwarding_before_a_current_lqc_floor() {
    let profile = profile_for(Role::Observer, 6, 2);
    let machine = Machine::new(profile.clone());
    let proposed = leader(&machine, 2);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed, &votes);
    let proof = Arc::new(Artifact::Lqc(certificate.clone()));
    let first = Cursor::zero().next().unwrap();
    let floor = DomainEvent::new(
        machine.profile().protocol().epoch(),
        first,
        Change::FinalityFloorAdvanced {
            proof: Arc::clone(&proof),
            retired: Vec::new(),
            publication_retired: Vec::new(),
        },
    );
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();

    assert_eq!(restored.replay(floor), Err(ReplayError::Transition));

    let derived = Arc::new(Artifact::Vqc(
        certificate
            .derive_vqc(machine.profile().protocol().codec_config())
            .unwrap(),
    ));
    let anchor_id = derived.id::<Sha256>();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first),
                retired: Vec::new(),
                artifact: Arc::clone(&derived),
            },
        ))
        .unwrap();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first.next().unwrap(),
            Change::FinalityFloorAdvanced {
                proof: Arc::clone(&proof),
                retired: Vec::new(),
                publication_retired: Vec::new(),
            },
        ))
        .unwrap();

    assert!(matches!(
        restored.durable.signing_floor.as_deref(),
        Some(Artifact::Lqc(actual)) if actual == &certificate
    ));

    // The forwarding duty is one V-QC per view, not one copy of every same-view transcript. A
    // different V-QC may therefore satisfy that duty, while the L-QC's exact derived V-QC becomes
    // the proposal anchor and must accompany any proposal that selects it.
    let alternate_votes = [0, 1, 2, 3, 5]
        .into_iter()
        .map(|signer| ViewMessage::Vote(view_vote(&machine, certificate.leader(), signer)))
        .collect::<Vec<_>>();
    let alternate = Arc::new(Artifact::Vqc(vqc(
        &machine,
        certificate.leader().clone(),
        &alternate_votes,
    )));
    let alternate_id = alternate.id::<Sha256>();
    assert_ne!(alternate_id, anchor_id);

    let mut restored = Machine::restore(machine.profile().clone(), machine.snapshot()).unwrap();
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first),
                retired: Vec::new(),
                artifact: Arc::clone(&alternate),
            },
        ))
        .unwrap();
    assert_eq!(
        restored
            .durable
            .forwarded_vqcs
            .get(&certificate.view())
            .map(|artifact| artifact.id::<Sha256>()),
        Some(alternate_id),
    );
    restored
        .replay(DomainEvent::new(
            machine.profile().protocol().epoch(),
            first.next().unwrap(),
            Change::FinalityFloorAdvanced {
                proof,
                retired: Vec::new(),
                publication_retired: Vec::new(),
            },
        ))
        .unwrap();
    assert_eq!(
        restored
            .durable
            .proposal_anchor
            .as_ref()
            .map(|artifact| artifact.id::<Sha256>()),
        Some(anchor_id),
    );
    Machine::restore(machine.profile().clone(), restored.snapshot()).unwrap();
}

#[test]
fn proposal_may_repeat_its_exact_parent_after_forwarding() {
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let profile = profile_for(Role::Validator(signer), 6, 2);
    let machine = Machine::new(profile.clone());
    let parent = view_one_vqc(&machine);
    let request = proposal_request_with_parent(&machine, View::new(2), parent.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();

    let forwarding_cursor = Cursor::zero().next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            forwarding_cursor,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(forwarding_cursor),
                retired: Vec::new(),
                artifact: Arc::new(Artifact::Vqc(parent)),
            },
        ))
        .unwrap();

    let proposal_cursor = forwarding_cursor.next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            proposal_cursor,
            Change::OutboxQueued {
                id: EffectId::from_cursor(proposal_cursor),
                effect: Box::new(DurableEffect::Sign(SignRequest::LeaderBlock(request))),
            },
        ))
        .unwrap();
}

#[test]
fn proposal_may_omit_an_exact_parent_after_its_forwarding_fact_retires() {
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let profile = profile_for(Role::Validator(signer), 6, 2);
    let machine = Machine::new(profile.clone());
    let proposed = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &proposed, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, proposed, &votes);
    let parent = certificate
        .derive_vqc(machine.profile().protocol().codec_config())
        .unwrap();
    let attached = proposal_request_with_parent(&machine, View::new(2), parent.clone());
    let request = ProposalRequest::new(attached.block().clone(), attached.parent().clone(), false);
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();

    let forwarding_cursor = Cursor::zero().next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            forwarding_cursor,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(forwarding_cursor),
                retired: Vec::new(),
                artifact: Arc::new(Artifact::Vqc(parent)),
            },
        ))
        .unwrap();
    let floor_cursor = forwarding_cursor.next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            floor_cursor,
            Change::FinalityFloorAdvanced {
                proof: Arc::new(Artifact::Lqc(certificate)),
                retired: Vec::new(),
                publication_retired: Vec::new(),
            },
        ))
        .unwrap();
    assert!(restored.durable.forwarded_vqcs.is_empty());

    let proposal_cursor = floor_cursor.next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            proposal_cursor,
            Change::OutboxQueued {
                id: EffectId::from_cursor(proposal_cursor),
                effect: Box::new(DurableEffect::Sign(SignRequest::LeaderBlock(request))),
            },
        ))
        .unwrap();
}

#[test]
fn replay_bounds_forwarded_certificate_outbox_growth() {
    let limits = resources_with_capacities(9, 1);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let machine = Machine::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let first = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(1),
        0,
    )));
    let second = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(2),
        0,
    )));
    let first_cursor = Cursor::zero().next().unwrap();
    restored
        .replay(DomainEvent::new(
            restored.profile().protocol().epoch(),
            first_cursor,
            Change::ArtifactForwarded {
                publication: EffectId::from_cursor(first_cursor),
                retired: Vec::new(),
                artifact: first,
            },
        ))
        .unwrap();
    let second_cursor = first_cursor.next().unwrap();
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        second_cursor,
        Change::ArtifactForwarded {
            publication: EffectId::from_cursor(second_cursor),
            retired: Vec::new(),
            artifact: second,
        },
    );
    assert_eq!(restored.replay(event), Err(ReplayError::Transition));
    assert_eq!(restored.inspect().cursor(), first_cursor);
    assert_eq!(restored.inspect().outbox().len(), 1);
}

#[test]
fn replay_accepts_reordered_future_exit_forwarding() {
    let limits = resources_with_capacities(9, 16);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let machine = Machine::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let mut cursor = Cursor::zero();

    // Future certificates can finish verification before the current view. Every publication
    // remains within the global outbox, artifact, and forwarding-history bounds.
    for view in [3, 2, 1] {
        cursor = cursor.next().unwrap();
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored,
            View::new(view),
            0,
        )));
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                cursor,
                Change::ArtifactForwarded {
                    publication: EffectId::from_cursor(cursor),
                    retired: Vec::new(),
                    artifact,
                },
            ))
            .unwrap();
    }

    assert_eq!(restored.inspect().outbox().len(), 3);
}

#[test]
fn successor_forwarding_reuses_retired_artifact_capacity() {
    let limits = resources_with_capacities(9, 16);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile.clone());

    let first = symbolic_nullification(&machine, View::new(1), 0);
    let first = observe(&mut machine, Artifact::Nullification(first));
    let forwarding = complete_with_step(&mut machine, &first, true);
    let advanced = persist(&mut machine, &persist_job(&forwarding));
    persist(&mut machine, &persist_job(&advanced));
    assert_eq!(machine.inspect().view(), View::new(2));

    let previous_vqc = Arc::new(Artifact::Vqc(view_one_vqc(&machine)));
    let previous_vqc = machine
        .reserve_test_effect(DurableEffect::Broadcast(previous_vqc))
        .unwrap();
    persist(&mut machine, &persist_job(&previous_vqc));

    // Fill the durable artifact budget. Advancing through view 2 retires the two exit
    // publications above, so forwarding its certificate must reuse their capacity atomically.
    for view in 10..17 {
        let filler = Arc::new(leader_artifact(&machine, view));
        let reserved = machine
            .reserve_test_effect(DurableEffect::Broadcast(filler))
            .unwrap();
        persist(&mut machine, &persist_job(&reserved));
    }
    assert_eq!(machine.durable_artifact_references.len(), 9);
    assert_eq!(machine.durable.outbox.len(), 9);
    assert_eq!(machine.durable.obligations.len(), 9);

    let successor = symbolic_nullification(&machine, View::new(2), 1);
    let successor = observe(&mut machine, Artifact::Nullification(successor));
    let acknowledged = machine.snapshot();
    let forwarded = complete_with_step(&mut machine, &successor, true);
    let forwarding = persist_job(&forwarded);
    assert_eq!(machine.artifacts.len(), 2);
    assert!(machine.durable.nullification_forwarded(View::new(2)));
    // Two publications retired and one replaced them. Forwarding history keeps the successor's
    // certificate referenced at the exact artifact ceiling.
    assert_eq!(machine.durable.outbox.len(), 8);
    assert_eq!(machine.durable_artifact_references.len(), 9);

    let mut restored = Machine::restore(profile.clone(), acknowledged).unwrap();
    for event in forwarding.events().iter().cloned() {
        restored.replay(event).unwrap();
    }
    assert!(restored.durable.nullification_forwarded(View::new(2)));
    assert_eq!(restored.durable.outbox.len(), 8);
    assert_eq!(restored.durable_artifact_references.len(), 9);
    Machine::restore(profile, restored.snapshot()).unwrap();
}

#[test]
fn replay_bounds_locally_created_view_certificates() {
    let limits = resources_with_capacities(9, 16);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let machine = Machine::new(profile.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let mut cursor = Cursor::zero();
    for view in 1..=9 {
        cursor = cursor.next().unwrap();
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored,
            View::new(view),
            0,
        )));
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                cursor,
                Change::ViewCertificateCreated { artifact },
            ))
            .unwrap();
    }
    let rejected_cursor = cursor.next().unwrap();
    let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
        &restored,
        View::new(10),
        0,
    )));
    let event = DomainEvent::new(
        restored.profile().protocol().epoch(),
        rejected_cursor,
        Change::ViewCertificateCreated { artifact },
    );
    assert_eq!(restored.replay(event), Err(ReplayError::Transition));
    assert_eq!(restored.inspect().cursor(), cursor);
    assert_eq!(restored.snapshot().local_artifacts().len(), 9);
}

#[test]
fn replay_and_restore_count_signing_reservations_with_retained_artifacts() {
    let limits = resources_with_capacities(9, 9);
    let profile = profile_with_resources(Role::Validator(Participant::new(0)), 6, 2, limits);
    let machine = Machine::new(profile.clone());
    let mut restored = Machine::restore(profile.clone(), machine.snapshot()).unwrap();
    let mut forwarded_cursor = Cursor::zero();
    for view in 2..=9 {
        forwarded_cursor = forwarded_cursor.next().unwrap();
        let view = View::new(view);
        let artifact = Arc::new(Artifact::Nullification(symbolic_nullification(
            &restored, view, 0,
        )));
        let retired = restored.obligations_retired_by_exit(view);
        restored
            .replay(DomainEvent::new(
                restored.profile().protocol().epoch(),
                forwarded_cursor,
                Change::ArtifactForwarded {
                    publication: EffectId::from_cursor(forwarded_cursor),
                    retired,
                    artifact,
                },
            ))
            .unwrap();
    }

    let round = Round::new(restored.profile().protocol().epoch(), View::new(1));
    let requests = Arc::from([
        SignRequest::NoVote { round },
        SignRequest::Nullify { round },
    ]);
    let sign_cursor = forwarded_cursor.next().unwrap();
    let sign = DomainEvent::new(
        restored.profile().protocol().epoch(),
        sign_cursor,
        Change::OutboxQueued {
            id: EffectId::from_cursor(sign_cursor),
            effect: Box::new(DurableEffect::SignBatch(Arc::clone(&requests))),
        },
    );
    assert_eq!(restored.replay(sign), Err(ReplayError::Transition));

    let mut durable = restored.durable.clone();
    durable.cursor = sign_cursor;
    durable.signing_reservations.insert(
        EffectId::from_cursor(sign_cursor),
        DurableEffect::SignBatch(requests),
    );
    let snapshot = Snapshot::from_state_for_test::<Sha256>(
        machine.profile().protocol().epoch(),
        Role::Validator(Participant::new(0)),
        durable,
    );
    assert!(matches!(
        Machine::restore(profile, snapshot),
        Err(ReplayError::Transition)
    ));
}

#[test]
fn recovered_timeout_publication_requires_the_exact_artifact_pair() {
    let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
    let machine = Machine::new(profile.clone());
    let view = View::new(1);
    let novote = Arc::new(Artifact::NoVote(no_vote(&machine, view, 0)));
    let other_novote = Arc::new(Artifact::NoVote(no_vote(&machine, view, 1)));
    let nullify = Arc::new(Artifact::Nullify(nullify(&machine, view, 0)));
    let mut unrelated = [Arc::clone(&novote), other_novote];
    unrelated.sort_unstable_by_key(|artifact| artifact.id::<Sha256>());
    let malformed = [
        Arc::from([Arc::clone(&novote), Arc::clone(&novote)]),
        Arc::from([Arc::clone(&nullify), Arc::clone(&nullify)]),
        Arc::from([Arc::clone(&nullify), Arc::clone(&novote)]),
        Arc::from(unrelated),
    ];

    for artifacts in malformed {
        let mut durable = machine.durable.clone();
        let cursor = Cursor::zero().next().unwrap();
        durable.cursor = cursor;
        durable.outbox.insert(
            EffectId::from_cursor(cursor),
            DurableEffect::BroadcastBatch(artifacts),
        );
        let snapshot = Snapshot::from_state_for_test::<Sha256>(
            machine.profile().protocol().epoch(),
            Role::Validator(Participant::new(0)),
            durable,
        );
        assert!(matches!(
            Machine::restore(profile.clone(), snapshot),
            Err(ReplayError::Transition)
        ));
    }
}

#[test]
fn snapshot_requires_contiguous_completed_view_exits() {
    let profile = profile_for(Role::Observer, 6, 2);
    let machine = Machine::new(profile.clone());
    let proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(1),
        0,
    )));
    let mut valid = machine.durable.clone();
    valid.view = View::new(2);
    valid
        .forwarded_nullifications
        .insert(View::new(1), Arc::clone(&proof));
    valid.exits.insert(View::new(1), proof);
    let snapshot = |state| {
        Snapshot::from_state_for_test::<Sha256>(
            machine.profile().protocol().epoch(),
            Role::Observer,
            state,
        )
    };
    Machine::restore(profile.clone(), snapshot(valid.clone())).unwrap();

    let mut zero = valid.clone();
    zero.view = View::zero();
    zero.exits.clear();
    assert!(matches!(
        Machine::restore(profile.clone(), snapshot(zero)),
        Err(ReplayError::Transition)
    ));

    let mut missing = valid.clone();
    missing.view = View::new(3);
    assert!(matches!(
        Machine::restore(profile.clone(), snapshot(missing)),
        Err(ReplayError::Transition)
    ));

    let mut sparse = valid.clone();
    sparse.exits.clear();
    assert!(matches!(
        Machine::restore(profile.clone(), snapshot(sparse)),
        Err(ReplayError::Transition)
    ));

    let future_proof = Arc::new(Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(2),
        0,
    )));
    valid
        .forwarded_nullifications
        .insert(View::new(2), Arc::clone(&future_proof));
    valid.exits.insert(View::new(2), future_proof);
    assert!(matches!(
        Machine::restore(profile, snapshot(valid)),
        Err(ReplayError::Transition)
    ));
}

#[test]
fn replay_rejects_unauthorized_local_da_certificates() {
    for role in [Role::Observer, Role::Validator(Participant::new(0))] {
        let profile = profile_for(role, 6, 2);
        let machine = Machine::new(profile.clone());
        let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
        let genesis = restored.profile().protocol().genesis().tips()[1];
        let header = TransactionBlockHeader::new(
            restored.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            digest(b"unauthorized local certificate"),
        )
        .unwrap();
        let artifact = Arc::new(Artifact::DaCertificate(symbolic_da_certificate(header, 0)));
        let cursor = Cursor::zero().next().unwrap();
        let event = DomainEvent::new(
            restored.profile().protocol().epoch(),
            cursor,
            Change::ArtifactCreated {
                publication: EffectId::from_cursor(cursor),
                artifact,
            },
        );
        assert_eq!(restored.replay(event), Err(ReplayError::Transition));
    }
}

#[test]
fn mismatched_effect_completion_preserves_outbox() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    // Signing carries no signature out, so the request releases alongside its barrier.
    let [
        Capability::Durability(DurabilityCapability::Released(sign)),
        Capability::Durability(DurabilityCapability::Persist(_)),
    ] = reserved.capabilities()
    else {
        panic!("a staged signing choice must release its request");
    };
    assert!(matches!(sign.request(), DurableEffect::Sign(_)));
    persist(&mut machine, &persist_job(&reserved));
    let wrong = leader(&machine, 3);

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                wrong,
                attestation(0),
            ))),
        })),
        Err(StepError::EffectMismatch)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.id()]);
    assert!(machine.inspect().pending_barrier().is_none());
    assert!(machine.inspect().ready_artifacts().is_empty());

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(1),
            ))),
        })),
        Err(StepError::EffectMismatch)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.id()]);
    assert!(machine.inspect().ready_artifacts().is_empty());
}

#[test]
fn publication_attempt_ignores_an_unrelated_barrier() {
    let mut machine = active_machine(Role::Observer);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine, 1,
        ))))
        .unwrap();
    let broadcast = reserved
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Broadcast(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .unwrap();
    let published = persist(&mut machine, &persist_job(&reserved));
    assert!(
        published
            .capabilities()
            .iter()
            .all(|effect| { !matches!(durable_effect(effect), Some(DurableEffect::Broadcast(_))) })
    );
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());

    machine
        .reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine, 2,
        ))))
        .unwrap();
    let stale = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(matches!(
        stale.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    assert!(stale.capabilities().is_empty());
}

#[test]
fn signed_completion_survives_crash_before_barrier_acknowledgement() {
    let mut runner = active_runner(Role::Validator(Participant::new(0)));
    let baseline = runner.inspect().outbox()[0];
    let proposed = leader(runner.machine(), 2);
    let reserved = runner
        .reserve(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    // The signing request releases at staging; the signed block's publication is what waits
    // for durability below.
    let sign = reserved
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
        .expect("a staged signing request must be released");
    let signed = runner.persist(&persist_job(&reserved)).unwrap();
    assert!(
        !signed
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))),
        "the acknowledgement must not release the signing request a second time"
    );
    let artifact = Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0)));
    let artifact_id = artifact.id::<Sha256>();
    let completed = runner
        .submit(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(artifact.clone()),
        }))
        .unwrap();
    let status = completed.status().clone();
    let (mut effects, mut activities) = completed.into_parts();
    while !effects.iter().any(|effect| {
        matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        )
    }) {
        let result = runner.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        let (emitted, accepted) = result.into_parts();
        let quiesced = emitted.is_empty() && !work_remaining;
        effects.extend(emitted);
        activities.extend(accepted);
        if quiesced {
            break;
        }
    }
    let completed = Step::for_tests(status, effects, activities);
    let job = persist_job(&completed);
    let broadcast_id = match job.events()[0].change() {
        Change::SignedArtifact {
            sign: completed_sign,
            publication,
            artifact: recorded,
        } => {
            assert_eq!(*completed_sign, sign.id());
            assert_eq!(recorded.as_ref(), &artifact);
            *publication
        }
        _ => panic!("signed completion must be one atomic durable transition"),
    };
    runner.append(&job).unwrap();

    let recovery = runner.crash_and_restore().unwrap();
    assert_eq!(runner.inspect().ready_artifacts(), &[artifact_id]);
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    assert!(
        recovery
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Leader(LeaderCapability::ArmTimer(_)))),
        "recovery must arm the view timer at staging"
    );
    let recovered = runner.persist(&persist_job(&recovery)).unwrap();
    let [
        Capability::Durability(DurabilityCapability::Released(sign)),
        Capability::Durability(DurabilityCapability::Released(broadcast)),
    ] = recovered.capabilities()
    else {
        panic!("recovery must reissue the completed signed artifact");
    };
    assert!(matches!(sign.request(), DurableEffect::Sign(_)));
    let DurableEffect::Propose(publication) = broadcast.request() else {
        panic!("recovery must reissue the completed signed artifact");
    };
    assert_eq!(broadcast.id(), broadcast_id);
    let Artifact::LeaderBlock(expected) = &artifact else {
        unreachable!();
    };
    assert_eq!(publication.block().as_ref(), expected);
    assert!(publication.parent().is_genesis());

    let delivered = runner
        .submit(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    assert_eq!(runner.inspect().local_artifacts(), 1);

    let recovery = runner.crash_and_restore().unwrap();
    assert_eq!(runner.inspect().ready_artifacts(), &[artifact_id]);
    assert_eq!(runner.inspect().local_artifacts(), 1);
    assert_eq!(runner.inspect().outbox(), &[baseline, broadcast_id]);
    runner.persist(&persist_job(&recovery)).unwrap();
}

#[test]
fn oversized_signing_completion_never_reaches_the_journal() {
    let limits = resources_with_max_artifact_bytes(1);
    let profile = Profile::with_limits(
        config(Epoch::new(7)),
        Role::Validator(Participant::new(0)),
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(limits, 1),
            ..Tuning::default()
        },
        limits,
    )
    .unwrap();
    let mut machine = Machine::new(profile);
    let start = machine.step(Input::Start).unwrap();
    let started = persist(&mut machine, &persist_job(&start));
    // The producer's signing choice stages behind the generation barrier and its request
    // releases at staging.
    assert!(matches!(
        started.capabilities(),
        [Capability::Durability(DurabilityCapability::Released(job)), Capability::Durability(DurabilityCapability::Persist(_))]
            if matches!(job.request(), DurableEffect::Sign(_))
    ));
    persist(&mut machine, &persist_job(&started));
    let baseline = machine.inspect().outbox()[0];
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let [
        Capability::Durability(DurabilityCapability::Released(sign)),
        Capability::Durability(DurabilityCapability::Persist(_)),
    ] = reserved.capabilities()
    else {
        panic!("a staged signing choice must release its request");
    };
    assert!(matches!(sign.request(), DurableEffect::Sign(_)));
    persist(&mut machine, &persist_job(&reserved));

    assert!(matches!(
        machine.step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            ))),
        })),
        Err(StepError::LocalArtifactTooLarge)
    ));
    assert_eq!(machine.inspect().outbox(), &[baseline, sign.id()]);
    assert!(machine.inspect().pending_barrier().is_none());
    assert_eq!(machine.inspect().local_artifacts(), 0);
    assert!(machine.inspect().ready_artifacts().is_empty());
}

#[test]
fn declined_build_retries_only_after_post_decline_delay() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let started = machine.step(Input::ProducerWake).unwrap();
    let started = settle(&mut machine, started);
    let [Capability::Producer(ProducerCapability::Build(build))] = started.capabilities() else {
        panic!("producer wake must issue one build without arming a production timer");
    };
    let build = build.clone();

    let coalesced = machine.step(Input::ProducerWake).unwrap();
    let coalesced = settle(&mut machine, coalesced);
    assert_eq!(coalesced.status(), &StepStatus::ProducerWake);
    assert!(coalesced.capabilities().is_empty());

    let declined = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            None,
        )))
        .unwrap();
    let declined = settle(&mut machine, declined);
    let [Capability::Producer(ProducerCapability::ArmTimer(timer))] = declined.capabilities()
    else {
        panic!("declined build must arm one retry timer without rebuilding");
    };
    assert_eq!(timer.parent(), build.parent());
    assert_eq!(timer.generation(), build.generation());

    let elapsed = machine.step(Input::ProductionTimerFired(*timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    let [Capability::Producer(ProducerCapability::Build(retry))] = elapsed.capabilities() else {
        panic!("post-decline timer must issue exactly one retry");
    };
    assert_ne!(retry.id(), build.id());
    assert_eq!(retry.parent(), build.parent());
}

#[test]
fn prepared_builds_pipeline_and_authorize_only_the_custodied_prefix() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let first = machine.step(Input::ProducerWake).unwrap();
    let first = settle(&mut machine, first);
    let first_build = build_job(&first);
    let first_prepared = prepare_block(&mut machine, &first_build, digest(b"block one"));
    assert!(first_prepared.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));
    let first_custody = first_prepared
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Producer(ProducerCapability::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a prepared block must request custody");
    let second_build = build_job(&first_prepared);
    assert_eq!(second_build.parent(), first_custody.header().block_ref::<Sha256>());

    let second_prepared = prepare_block(&mut machine, &second_build, digest(b"block two"));
    let second_custody = second_prepared
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Producer(ProducerCapability::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the second prepared block must request custody");
    assert!(second_prepared.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));
    assert!(
        machine
            .inspect()
            .producer()
            .expect("the validator owns a producer chain")
            .pipeline_blocked()
    );

    let out_of_order = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            second_custody.id(),
            second_custody.generation(),
            second_custody.header().clone(),
        )))
        .unwrap();
    let out_of_order = settle(&mut machine, out_of_order);
    assert!(out_of_order.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));

    let contiguous = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            first_custody.id(),
            first_custody.generation(),
            first_custody.header().clone(),
        )))
        .unwrap();
    let contiguous = settle(&mut machine, contiguous);
    let following = persist(&mut machine, &persist_job(&contiguous));
    let signed_heights = contiguous
        .capabilities()
        .iter()
        .chain(following.capabilities())
        .filter_map(|capability| match durable_effect(capability) {
            Some(DurableEffect::Sign(SignRequest::TransactionBlock(header))) => {
                Some(header.height())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(signed_heights, [Height::new(1), Height::new(2)]);
}

#[test]
fn matching_certificate_preserves_a_custodied_prepared_descendant() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let first_build = build_job(&settle(&mut machine, ready));
    let first = prepare_block(&mut machine, &first_build, digest(b"prepared first"));
    let first_custody = custody_job(&first);
    let second_build = build_job(&first);
    let second = prepare_block(&mut machine, &second_build, digest(b"prepared second"));
    let second_custody = custody_job(&second);
    let out_of_order = complete_custody(&mut machine, &second_custody);
    assert!(out_of_order.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));

    let certificate = Artifact::DaCertificate(symbolic_da_certificate(
        first_custody.header().clone(),
        1,
    ));
    let verification = observe(&mut machine, certificate);
    let advanced = complete_with_step(&mut machine, &verification, true);
    let late = complete_custody(&mut machine, &first_custody);
    assert_eq!(late.status(), &StepStatus::StaleCompletion);

    let persisted = persist(&mut machine, &persist_job(&advanced));
    let signing = persist_job(&persisted);
    let Change::OutboxQueued { effect, .. } = signing.events()[0].change() else {
        panic!("the retained descendant must reserve its signing subject");
    };
    assert!(matches!(
        effect.as_ref(),
        DurableEffect::Sign(SignRequest::TransactionBlock(header))
            if header == second_custody.header()
    ));
}

#[test]
fn divergent_certificate_discards_the_prepared_suffix() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let first_build = build_job(&settle(&mut machine, ready));
    let first = prepare_block(&mut machine, &first_build, digest(b"orphaned first"));
    let first_custody = custody_job(&first);
    let second_build = build_job(&first);
    let second = prepare_block(&mut machine, &second_build, digest(b"orphaned second"));
    let second_custody = custody_job(&second);
    complete_custody(&mut machine, &second_custody);

    let sibling = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        first_build.parent().chain(),
        Height::new(first_build.parent().height().get() + 1),
        first_build.parent().digest(),
        digest(b"certified sibling"),
    )
    .unwrap();
    let verification = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(sibling.clone(), 2)),
    );
    let advanced = complete_with_step(&mut machine, &verification, true);
    let persisted = persist(&mut machine, &persist_job(&advanced));
    let cancellation = persisted
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Producer(ProducerCapability::CancelCustody(cancellation)) => {
                Some(*cancellation)
            }
            _ => None,
        })
        .expect("the divergent certificate must cancel orphaned custody");
    let cancelled = machine
        .step(Input::CustodyCancelled(cancellation))
        .unwrap();
    let cancelled = settle(&mut machine, cancelled);
    let first_late = complete_custody(&mut machine, &first_custody);
    let second_late = complete_custody(&mut machine, &second_custody);
    assert_eq!(first_late.status(), &StepStatus::StaleCompletion);
    assert_eq!(second_late.status(), &StepStatus::StaleCompletion);

    let steps = [
        &advanced,
        &cancelled,
        &first_late,
        &second_late,
        &persisted,
    ];
    assert!(steps.iter().flat_map(|step| step.capabilities()).all(|capability| {
        !matches!(
            durable_effect(capability),
            Some(DurableEffect::Sign(SignRequest::TransactionBlock(header)))
                if header == first_custody.header() || header == second_custody.header()
        )
    }));
    let replacement = steps
        .iter()
        .flat_map(|step| step.capabilities())
        .find_map(|capability| match capability {
            Capability::Producer(ProducerCapability::Build(job)) => Some(job),
            _ => None,
        })
        .expect("the divergent certificate must wake production on its own tip");
    assert_eq!(replacement.parent(), sibling.block_ref::<Sha256>());
}

#[test]
fn prepared_suffix_is_discarded_across_restart_without_authority() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = active_machine(role);
    let snapshot = machine.snapshot();
    let ready = machine.step(Input::ProducerWake).unwrap();
    let build = build_job(&settle(&mut machine, ready));
    let prepared = prepare_block(&mut machine, &build, digest(b"volatile prepared block"));
    let custody = custody_job(&prepared);
    assert!(prepared.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));

    let mut restored = Machine::restore(profile(role), snapshot).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    let stale = restored
        .step(Input::BlockCustodied(CustodyCompletion::new(
            custody.id(),
            custody.generation(),
            custody.header().clone(),
        )))
        .unwrap();
    let stale = settle(&mut restored, stale);
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().iter().all(|capability| {
        !matches!(durable_effect(capability), Some(DurableEffect::Sign(_)))
    }));
}

#[test]
fn producer_builds_after_an_external_own_chain_certificate() {
    let role = Role::Validator(Participant::new(0));
    let profile = profile(role);
    let mut machine = active_machine(role);
    let before_certificate = machine.snapshot();
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"sibling producer block"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(first.clone(), 1);

    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let advanced = complete_with_step(&mut machine, &verification, true);
    let advanced_job = persist_job(&advanced);
    let Change::DaCertificateAdvanced {
        publication,
        retired,
        artifact,
    } = advanced_job.events()[0].change()
    else {
        panic!("the external certificate must advance the own-chain tip");
    };
    assert!(publication.is_none());
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::DaCertificate(actual)
        if actual == &certificate));

    let mut replayed = Machine::restore(profile, before_certificate).unwrap();
    for event in advanced_job.events() {
        replayed.replay(event.clone()).unwrap();
    }
    assert_eq!(replayed.durable.certified_tips[0].height(), Height::new(1));
    assert_eq!(replayed.durable.produced_height, Height::zero());

    let outbox_before = machine.snapshot().outbox().clone();
    let obligations_before = machine.snapshot().obligations().clone();
    let advanced = persist(&mut machine, &advanced_job);
    let build = build_job(&advanced);
    assert_eq!(build.parent(), first.block_ref::<Sha256>());

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"local successor")),
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let completed = complete_custody(&mut machine, &custody_job(&completed));
    let completed_job = persist_job(&completed);
    let Change::OutboxQueued { id, effect } = completed_job.events()[0].change() else {
        panic!("the local successor must reserve its exact signing subject");
    };
    let DurableEffect::Sign(SignRequest::TransactionBlock(successor)) = effect.as_ref() else {
        panic!("the reserved subject must be the local transaction block");
    };
    assert_eq!(successor.height(), Height::new(2));
    assert_eq!(successor.parent(), first.block_ref::<Sha256>().digest());
    assert_eq!(machine.durable.produced_blocks, 1);
    assert_eq!(machine.durable.produced_height, Height::new(2));

    let snapshot = machine.snapshot();
    assert_eq!(snapshot.outbox(), &outbox_before);
    assert_eq!(snapshot.obligations(), &obligations_before);
    assert_eq!(
        snapshot.signing_reservations().get(id),
        Some(effect.as_ref())
    );

    for event in completed_job.events() {
        replayed.replay(event.clone()).unwrap();
    }
    assert_eq!(replayed.durable.produced_blocks, 1);
    assert_eq!(replayed.durable.produced_height, Height::new(2));
    let replayed = replayed.snapshot();
    assert_eq!(replayed.outbox(), &outbox_before);
    assert_eq!(replayed.obligations(), &obligations_before);
    assert_eq!(
        replayed.signing_reservations().get(id),
        Some(effect.as_ref())
    );
}

#[test]
fn superseded_build_waits_for_completion_before_building_on_new_parent() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let first = machine.step(Input::ProducerWake).unwrap();
    let first = settle(&mut machine, first);
    let old_build = build_job(&first);
    let new_parent_header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        old_build.parent().chain(),
        Height::new(old_build.parent().height().get() + 1),
        old_build.parent().digest(),
        digest(b"twin commitment"),
    )
    .unwrap();
    let new_parent = new_parent_header.block_ref::<Sha256>();

    machine
        .chain
        .observe_producer_choice::<Sha256>(&new_parent_header)
        .unwrap();
    let advanced = machine.step(Input::ProducerWake).unwrap();
    let advanced = settle(&mut machine, advanced);
    assert!(
        advanced
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Producer(ProducerCapability::Build(_))))
    );

    let mismatched = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            old_build.id(),
            old_build.generation() + 1,
            old_build.parent(),
            Some(digest(b"mismatched commitment")),
        )))
        .unwrap();
    assert_eq!(mismatched.status(), &StepStatus::StaleCompletion);
    assert!(mismatched.capabilities().iter().all(|effect| {
        !matches!(effect, Capability::Producer(ProducerCapability::Build(_)))
            && !matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))
    }));

    let old_commitment = digest(b"old commitment");
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            old_build.id(),
            old_build.generation(),
            old_build.parent(),
            Some(old_commitment),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::StaleCompletion);
    let completed = settle(&mut machine, completed);
    let builds = completed
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Build(job)) => Some(job),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].parent(), new_parent);
    assert!(!completed.capabilities().iter().any(|effect| {
        matches!(
            durable_effect(effect),
            Some(DurableEffect::Sign(SignRequest::TransactionBlock(header)))
                if header.body_digest() == old_commitment
        )
    }));
}

#[test]
fn empty_build_waits_for_its_exact_parent_timer() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let [Capability::Producer(ProducerCapability::Build(build))] = ready.capabilities() else {
        panic!("producer wake must issue one build without arming a production timer");
    };
    let build = build.clone();

    let stale = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation() + 1,
            build.parent(),
            Some(digest(b"stale")),
        )))
        .unwrap();
    assert_eq!(stale.status(), &StepStatus::StaleCompletion);
    assert!(stale.capabilities().is_empty());

    let empty = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            None,
        )))
        .unwrap();
    assert_eq!(empty.status(), &StepStatus::BlockBuilt);
    let empty = settle(&mut machine, empty);
    let [Capability::Producer(ProducerCapability::ArmTimer(timer))] = empty.capabilities() else {
        panic!("empty build must arm one production timer");
    };
    let timer = *timer;
    assert_eq!(timer.generation(), build.generation());
    assert_eq!(timer.parent(), build.parent());

    let late = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"late")),
        )))
        .unwrap();
    assert_eq!(late.status(), &StepStatus::StaleCompletion);
    assert!(late.capabilities().is_empty());

    let elapsed = machine.step(Input::ProductionTimerFired(timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    let retry = build_job(&elapsed);
    assert_ne!(retry.id(), build.id());
    assert_eq!(retry.parent(), build.parent());
}

#[test]
fn crash_recovery_rejects_mismatched_old_resolution_completions_as_stale() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let keys = [View::new(2), View::new(3), View::new(4)];
    let old = keys.map(|key| {
        machine
            .resolution
            .request(
                machine.durable.generation,
                key,
                machine.profile().resources().max_dependency_waiters(),
            )
            .unwrap()
            .unwrap()
    });

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    let current = keys.map(|key| {
        restored
            .resolution
            .request(
                restored.durable.generation,
                key,
                restored.profile().resources().max_dependency_waiters(),
            )
            .unwrap()
            .unwrap()
    });

    for (old, current) in old.into_iter().zip(current) {
        assert_ne!(old.id(), current.id());
        assert_ne!(old.generation(), current.generation());
        let completed = restored
            .step(Input::ResolutionCompleted(ResolutionCompletion::new(
                old.id(),
                old.generation(),
                old.view(),
                mismatched_resolution_proof(&restored),
            )))
            .unwrap();
        assert_eq!(completed.status(), &StepStatus::StaleCompletion);
        assert!(completed.capabilities().is_empty());
    }
    assert_eq!(restored.inspect().resolution_jobs(), keys.len() + 1);
}

#[test]
fn invalid_block_can_be_revalidated() {
    let mut machine = active_machine(Role::Observer);
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(0),
        Height::new(1),
        genesis.digest(),
        digest(b"invalid block"),
    )
    .unwrap();
    let artifact = Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(0)));

    let verification = observe(&mut machine, artifact.clone());
    let verified = complete_with_step(&mut machine, &verification, true);
    let validation = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            validation.id(),
            validation.generation(),
            BlockValidity::Invalid,
        )))
        .unwrap();
    assert_eq!(machine.inspect().cached_artifacts(), 0);

    let repeated = observe(&mut machine, artifact);
    let verified = complete_with_step(&mut machine, &repeated, true);
    assert!(verified.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Producer(ProducerCapability::Validate(_))
    )));
}

#[test]
fn producer_window_stops_before_the_third_uncertified_block() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));

    // Preparation pipelines while custody and signing complete for earlier blocks.
    let wake = machine.step(Input::ProducerWake).unwrap();
    let mut build = build_job(&settle(&mut machine, wake));
    for height in 1..=2u64 {
        let completed = machine
            .step(Input::BlockBuilt(BuildCompletion::new(
                build.id(),
                build.generation(),
                build.parent(),
                Some(digest(format!("block {height}").as_bytes())),
            )))
            .unwrap();
        let completed = settle(&mut machine, completed);
        let next = (height < 2).then(|| build_job(&completed));
        let completed = complete_custody(&mut machine, &custody_job(&completed));
        // The signing request releases with the step that stages the producer choice.
        assert!(completed.capabilities().iter().any(|effect| {
            matches!(
                durable_effect(effect),
                Some(DurableEffect::Sign(SignRequest::TransactionBlock(_)))
            )
        }));
        persist(&mut machine, &persist_job(&completed));
        if let Some(next) = next {
            build = next;
        }
    }

    // The third block would exceed the certificate window, so no further build is issued even
    // while work remains pending.
    let blocked = machine.step(Input::ProducerWake).unwrap();
    let blocked = settle(&mut machine, blocked);
    assert_eq!(blocked.status(), &StepStatus::ProducerWake);
    assert!(
        !blocked
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Producer(ProducerCapability::Build(_))))
    );

    let second = machine
        .snapshot()
        .signing_reservations()
        .values()
        .filter_map(|effect| match effect {
            DurableEffect::Sign(SignRequest::TransactionBlock(header))
                if header.height() == Height::new(2) =>
            {
                Some(header.clone())
            }
            _ => None,
        })
        .next()
        .unwrap();
    let certificate = symbolic_da_certificate(second, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = complete_with_step(&mut machine, &verification, true);
    let admitted = persist(&mut machine, &persist_job(&advanced));
    assert_eq!(build_job(&admitted).parent().height(), Height::new(2));
}

#[test]
fn certified_chain_state_plateaus_without_ordering() {
    // Chain dissemination is independent of total ordering. Once a higher DA certificate is
    // accepted, the machine needs only that certified frontier and the bounded uncertified suffix;
    // older blocks and certificates remain retrievable from storage. Keeping them in live state
    // until ordering would let one continuously certified chain exhaust every validator.
    let resources = resources_with_capacities(512, 512);
    let profile = profile_with_resources(Role::Observer, 6, 2, resources);
    let (mut machine, _) = start_profile(profile);
    let mut parent = machine.profile().protocol().genesis().tips()[0];

    for height in 1..=100u64 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            parent.chain(),
            Height::new(height),
            parent.digest(),
            digest(format!("certified body {height}").as_bytes()),
        )
        .unwrap();
        let block = header.block_ref::<Sha256>();
        let validated = validate_block(&mut machine, header.clone(), parent.chain().get());
        assert!(validated.capabilities().is_empty());

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height)),
        );
        let certified = complete_with_step(&mut machine, &certificate, true);
        let advanced = persist(&mut machine, &persist_job(&certified));
        let _ = drive_poll_and_persist(&mut machine, advanced);
        parent = block;
    }

    assert_eq!(machine.chain.tip_heights()[0].1, Height::new(100));
    assert!(machine.chain.retained_ancestry() <= 1);
    assert!(
        machine.inspect().cached_artifacts() <= 4,
        "certified chain history remained live: {} artifacts",
        machine.inspect().cached_artifacts()
    );

    let profile = machine.profile().clone();
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    assert_eq!(restored.chain.tip_heights()[0].1, Height::new(100));
    assert!(restored.chain.retained_ancestry() <= 1);
    assert!(restored.inspect().cached_artifacts() <= 4);
}

#[test]
fn validator_da_safety_state_plateaus_across_restarts() {
    let role = Role::Validator(Participant::new(0));
    let resources = resources_with_capacities(64, 32);
    let profile = profile_with_resources(role, 6, 2, resources);
    let (mut machine, _) = start_profile(profile.clone());
    let mut parent = machine.profile().protocol().genesis().tips()[1];

    for height in 1..=40u64 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            parent.chain(),
            Height::new(height),
            parent.digest(),
            digest(format!("validator body {height}").as_bytes()),
        )
        .unwrap();
        let block = header.block_ref::<Sha256>();

        let vote_reserved = validate_block(&mut machine, header.clone(), parent.chain().get());
        // The signing request releases with the step that stages the DA choice.
        let sign = vote_reserved
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Released(job))
                    if matches!(job.request(), DurableEffect::Sign(SignRequest::DaVote(actual))
                        if actual.header() == &header) =>
                {
                    Some(job.clone())
                }
                _ => None,
            })
            .expect("the staged DA choice must be signed");
        persist(&mut machine, &persist_job(&vote_reserved));
        let signed = machine
            .step(Input::EffectCompleted(EffectCompletion::Signed {
                id: sign.id(),
                generation: sign.generation(),
                artifact: Arc::new(Artifact::DaVote(DaVote::new(
                    header.clone(),
                    threshold_share(0),
                ))),
            }))
            .unwrap();
        let signed = settle(&mut machine, signed);
        persist(&mut machine, &persist_job(&signed));

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height)),
        );
        let certified = complete_with_step(&mut machine, &certificate, true);
        let advanced = persist(&mut machine, &persist_job(&certified));
        let _ = drive_poll_and_persist(&mut machine, advanced);
        parent = block;

        assert_eq!(
            machine.snapshot().da_safety_heights()[1],
            Height::new(height)
        );
        assert!(machine.inspect().cached_artifacts() <= 4);
        assert!(machine.snapshot().local_artifacts().len() <= 1);
        assert!(machine.snapshot().outbox().len() <= 1);

        if height % 10 == 0 {
            let mut restored = Machine::restore(profile.clone(), machine.snapshot()).unwrap();
            let recovery = restored.step(Input::RecoveryComplete).unwrap();
            persist(&mut restored, &persist_job(&recovery));
            machine = restored;
        }
    }

    assert_eq!(machine.chain.tip_heights()[1].1, Height::new(40));
}

#[test]
fn recovery_reissues_the_exact_durable_producer_choice() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let build = build_job(&ready);
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"durable block")),
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let completed = complete_custody(&mut machine, &custody_job(&completed));
    persist(&mut machine, &persist_job(&completed));
    let expected = machine
        .snapshot()
        .signing_reservations()
        .values()
        .find_map(|effect| match effect {
            DurableEffect::Sign(SignRequest::TransactionBlock(header)) => Some(header.clone()),
            _ => None,
        })
        .expect("producer choice must be durable");

    let mut restored = Machine::restore(
        profile(Role::Validator(Participant::new(0))),
        machine.snapshot(),
    )
    .unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restored, &persist_job(&recovery));
    let actual = recovered
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job)) => match job.request() {
                DurableEffect::Sign(SignRequest::TransactionBlock(header)) => Some(header),
                _ => None,
            },
            _ => None,
        })
        .expect("recovery must reissue producer signing");
    assert_eq!(actual, &expected);
    let next_build = recovered
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Build(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("recovered producer choice must build on its new parent");
    assert_eq!(next_build.parent(), expected.block_ref::<Sha256>());
    assert!(recovered.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Producer(ProducerCapability::ArmTimer(_))
    )));

    let declined = restored
        .step(Input::BlockBuilt(BuildCompletion::new(
            next_build.id(),
            next_build.generation(),
            next_build.parent(),
            None,
        )))
        .unwrap();
    let declined = settle(&mut restored, declined);
    let [Capability::Producer(ProducerCapability::ArmTimer(timer))] = declined.capabilities()
    else {
        panic!("declined recovered build must arm one production timer");
    };
    assert_eq!(timer.generation(), next_build.generation());
    assert_eq!(timer.parent(), next_build.parent());
}

#[test]
fn recovered_payloads_are_the_exact_local_producer_and_da_union() {
    let role = Role::Validator(Participant::new(0));
    let recovery_profile = profile_for(role, 6, 2);
    let (mut machine, _) = start_profile(recovery_profile.clone());
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let build = build_job(&ready);
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"local recovery payload")),
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let completed = complete_custody(&mut machine, &custody_job(&completed));
    let local = completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job)) => match job.request() {
                DurableEffect::Sign(SignRequest::TransactionBlock(header)) => Some(header.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("the producer choice carries its complete recovery context");
    persist(&mut machine, &persist_job(&completed));

    let local_observation = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(local.clone(), attestation(0))),
    );
    let local_da = complete_with_step(&mut machine, &local_observation, true);
    assert!(local_da.capabilities().iter().all(|capability| !matches!(
        capability,
        Capability::Producer(ProducerCapability::Validate(_))
    )));
    persist(&mut machine, &persist_job(&local_da));

    let remote_parent = machine.profile().protocol().genesis().tips()[1];
    let remote = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        remote_parent.chain(),
        Height::new(1),
        remote_parent.digest(),
        digest(b"remote recovery payload"),
    )
    .unwrap();
    let remote_da = validate_block(&mut machine, remote.clone(), 1);
    persist(&mut machine, &persist_job(&remote_da));

    let certified_parent = machine.profile().protocol().genesis().tips()[2];
    let certified = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        certified_parent.chain(),
        Height::new(1),
        certified_parent.digest(),
        digest(b"certificate-only payload"),
    )
    .unwrap();
    let observed = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(certified, 2)),
    );
    let verified = complete_with_step(&mut machine, &observed, true);
    persist(&mut machine, &persist_job(&verified));

    let restored = Machine::restore(recovery_profile.clone(), machine.snapshot()).unwrap();
    assert_eq!(
        restored.recovered_payloads(),
        vec![
            (Context::from(&local), local.body_digest()),
            (Context::from(&remote), remote.body_digest()),
        ],
        "the duplicate local producer/DA root is verified once and certificate-only roots are excluded"
    );

    let observed = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(remote, 3)),
    );
    let verified = complete_with_step(&mut machine, &observed, true);
    persist(&mut machine, &persist_job(&verified));
    let restored = Machine::restore(recovery_profile, machine.snapshot()).unwrap();
    assert_eq!(
        restored.recovered_payloads(),
        vec![(Context::from(&local), local.body_digest())],
        "a durable certificate retires the covered DA custody root"
    );

    let observer_profile = profile_for(Role::Observer, 6, 2);
    let observer = Machine::restore(
        observer_profile.clone(),
        Machine::new(observer_profile).snapshot(),
    )
    .unwrap();
    assert!(observer.recovered_payloads().is_empty());
}

#[test]
fn validator_cannot_authorize_another_producer_chain() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        digest(b"other parent"),
        digest(b"other body"),
    )
    .unwrap();
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::Sign(SignRequest::TransactionBlock(header))),
        Err(StepError::UnauthorizedEffect)
    ));
}

#[test]
fn da_vote_choice_is_durable_and_sent_only_to_the_producer() {
    let mut machine = Machine::new(profile_for_producers(
        Role::Validator(Participant::new(3)),
        6,
        vec![Participant::new(1), Participant::new(4)],
        2,
    ));
    assert_eq!(
        machine
            .profile()
            .protocol()
            .producer_chain(Participant::new(3)),
        None
    );
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"remote body"),
    )
    .unwrap();

    let reserved = validate_block(&mut machine, header.clone(), 4);
    let choice = persist_job(&reserved);
    assert!(matches!(
        choice.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &header)
    ));
    // Signing carries no signature out of the process, so the request releases at staging;
    // only the signed vote's publication waits for its record's durability.
    let sign = reserved
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
        .expect("the staged DA choice must release signing immediately");
    assert!(matches!(sign_request(&sign), SignRequest::DaVote(actual)
        if actual.header() == &header));
    let released = persist(&mut machine, &choice);
    assert!(
        !released
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))),
        "the acknowledgement must not release the signing request a second time"
    );

    let vote = Artifact::DaVote(DaVote::new(header.clone(), threshold_share(3)));
    let vote_id = vote.id::<Sha256>();
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(vote),
        }))
        .unwrap();
    // The completion parks; settling drains it into its staging barrier, and the self-admission
    // the old status reported shows up in the artifact cache.
    assert!(matches!(
        completed.status(),
        StepStatus::EffectCompleted { admission: None }
    ));
    let completed = settle(&mut machine, completed);
    assert!(machine.artifacts.contains_key(&vote_id));
    let published = persist(&mut machine, &persist_job(&completed));
    let send = published
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Durability(DurabilityCapability::Released(job)) => Some(job),
            _ => None,
        })
        .expect("a DA vote must use directed publication");
    let DurableEffect::Send(request) = send.request() else {
        panic!("a DA vote must use directed publication");
    };
    assert_eq!(request.recipient(), Participant::new(4));
    assert!(matches!(
        request.artifact().as_ref(),
        Artifact::DaVote(vote) if vote.header() == &header
    ));
    assert_eq!(machine.inspect().local_artifacts(), 1);
}

#[test]
fn producer_subset_snapshots_restore_for_every_validator_role() {
    let producers = vec![Participant::new(4), Participant::new(1)];
    for participant in [Participant::new(3), Participant::new(4)] {
        let profile = profile_for_producers(Role::Validator(participant), 6, producers.clone(), 2);
        let machine = Machine::new(profile.clone());
        Machine::restore(profile, machine.snapshot()).expect("K<n snapshot restores");
    }
}

#[test]
fn durable_da_vote_enables_the_next_height_in_the_same_drain() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"second"),
    )
    .unwrap();

    let held = authenticate_block(&mut machine, second.clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let ready = authenticate_block(&mut machine, first.clone(), 1);
    let validations = validation_jobs(&ready);
    let child = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .expect("the anchored child enters validation");
    let held = complete_validation(&mut machine, child);
    assert!(held.capabilities().is_empty());
    let parent = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .expect("the parent enters validation");
    let first_choice = complete_validation(&mut machine, parent);
    let first_barrier = persist_job(&first_choice);
    let advanced = persist(&mut machine, &first_barrier);
    assert!(matches!(
        advanced.capabilities().first().and_then(durable_effect),
        Some(DurableEffect::Sign(_))
    ));
    let next = advanced
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job),
            _ => None,
        })
        .expect("durable height one must reserve height two without another input");
    assert!(matches!(
        next.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &second)
    ));
}

#[test]
fn certification_lag_does_not_silence_later_da_votes() {
    let (mut machine, _) = start_profile(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let epoch = machine.profile().protocol().epoch();
    let first = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"lagged floor first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"lagged floor second"),
    )
    .unwrap();
    let third = TransactionBlockHeader::new(
        epoch,
        ChainId::new(1),
        Height::new(3),
        second.block_ref::<Sha256>().digest(),
        digest(b"lagged floor third"),
    )
    .unwrap();

    // Every block finishes validation while the local certified floor still sits at genesis, so
    // the third block completes beyond the pipeline window and no vote can exist for it yet.
    let held = authenticate_block(&mut machine, third.clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let held = authenticate_block(&mut machine, second.clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let ready = authenticate_block(&mut machine, first.clone(), 1);
    let validations = validation_jobs(&ready);
    let child = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .expect("the anchored child enters validation");
    let child = complete_validation(&mut machine, child);
    let grandchild = validation_jobs(&child)
        .into_iter()
        .find(|job| job.block().header() == &third)
        .expect("released capacity admits the grandchild");
    let held = complete_validation(&mut machine, &grandchild);
    assert!(held.capabilities().is_empty());
    let parent = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .expect("the parent enters validation");
    let unlocked = complete_validation(&mut machine, parent);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, unlocked, &mut choices);
    assert_eq!(choices, vec![first.clone(), second]);

    // The cluster certifies the first height, moving the pipeline window over the third block.
    // The vote must resume even though the block was validated before the floor advanced.
    let certificate = observe(
        &mut machine,
        Artifact::DaCertificate(symbolic_da_certificate(first, 1)),
    );
    let certified = complete_with_step(&mut machine, &certificate, true);
    let mut resumed = Vec::new();
    drain_da_choices(&mut machine, certified, &mut resumed);
    assert_eq!(resumed, vec![third]);
}

#[test]
fn finalized_parent_requires_a_real_da_path_before_voting_for_its_child() {
    let role = Role::Validator(Participant::new(0));
    let (mut machine, _) = start_profile(profile_for(role, 6, 2));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"finalized unseen parent"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        first.epoch(),
        first.chain(),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"held finalized child"),
    )
    .unwrap();
    let base = leader(&machine, 5);
    let mut proposals = base.proposals().to_vec();
    proposals[1] = ChainProposal::new(
        genesis.chain(),
        Anchor::Tip(genesis),
        vec![first.body_digest()],
        machine.profile().protocol().codec_config().pipeline_depth(),
    )
    .unwrap();
    let finalized = LeaderBlock::new(
        base.round(),
        base.parent(),
        base.history(),
        proposals,
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let votes = (0..5)
        .map(|signer| {
            let mut positions = vec![Position::new(0); 6];
            positions[1] = Position::new(1);
            let body = VoteBody::for_leader::<Sha256, MinPk>(
                &finalized,
                positions,
                vec![Extension::empty(); 6],
                machine.profile().protocol().codec_config(),
            )
            .unwrap();
            Vote::new(body, attestation(signer))
        })
        .collect::<Vec<_>>();
    let certificate = lqc(&machine, finalized, &votes);
    let verification = observe(&mut machine, Artifact::Lqc(certificate));
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);

    assert_eq!(
        machine.inspect().chain_progress()[1].finalized(),
        Height::new(1)
    );
    assert_eq!(machine.snapshot().certified_tips()[1], genesis);
    assert_eq!(machine.snapshot().da_safety_heights()[1], genesis.height());

    let held = authenticate_block(&mut machine, second.clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let ready = authenticate_block(&mut machine, first.clone(), 1);
    let validations = validation_jobs(&ready);
    let child = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .expect("the anchored child enters validation");
    let held = complete_validation(&mut machine, child);
    assert!(
        held.capabilities().iter().all(|effect| {
            !matches!(durable_effect(effect), Some(DurableEffect::Sign(
                SignRequest::DaVote(request)
            )) if request.header() == &second)
        }),
        "finality must not stand in for the missing DA parent"
    );

    let parent = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .expect("the parent enters validation");
    let first_choice = complete_validation(&mut machine, parent);
    let advanced = persist(&mut machine, &persist_job(&first_choice));
    let second_choice = advanced
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job),
            _ => None,
        })
        .expect("the durable parent choice must release the held child");
    assert!(matches!(
        second_choice.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(request))
                if request.header() == &second)
    ));
}

#[test]
fn saturated_validation_chain_does_not_block_another_producer() {
    let resources = resources_with_validation_batch(1);
    let profile = profile_with_resources(Role::Observer, 2, 2, resources);
    let (mut machine, _) = start_profile(profile);
    let make = |machine: &TestMachine, chain: u32, label: &'static [u8]| {
        let genesis = machine.profile().protocol().genesis().tips()[chain as usize];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain),
            Height::new(1),
            genesis.digest(),
            digest(label),
        )
        .unwrap();
        Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(chain)))
    };
    let validations = |step: &Step<MinPk, Digest>| {
        step.capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let artifact_bytes = |artifact: &Artifact<MinPk, Digest>| match artifact {
        Artifact::TransactionBlock(block) => block.encode_size(),
        _ => unreachable!("the validation test constructs transaction blocks"),
    };

    let first_artifact = make(&machine, 0, b"validation chain zero one");
    let first_bytes = artifact_bytes(&first_artifact);
    let first = observe(&mut machine, first_artifact);
    let first = complete_with_step(&mut machine, &first, true);
    let first_validations = validations(&first);
    let [active] = first_validations.as_slice() else {
        panic!("the first producer must acquire its validation reservation")
    };
    let active = active.clone();
    assert_eq!(
        machine.chain.validation_usage(),
        (1, first_bytes, &[1, 0][..], &[first_bytes, 0][..])
    );

    let second_artifact = make(&machine, 0, b"validation chain zero two");
    let second_bytes = artifact_bytes(&second_artifact);
    let second = observe(&mut machine, second_artifact);
    let second = complete_with_step(&mut machine, &second, true);
    assert!(
        validations(&second).is_empty(),
        "the saturated producer must remain queued without a fatal transition"
    );
    assert_eq!(
        machine.chain.validation_usage(),
        (1, first_bytes, &[1, 0][..], &[first_bytes, 0][..])
    );

    let other_artifact = make(&machine, 1, b"validation chain one");
    let other_bytes = artifact_bytes(&other_artifact);
    let other = observe(&mut machine, other_artifact);
    let other = complete_with_step(&mut machine, &other, true);
    let other_validations = validations(&other);
    let [other] = other_validations.as_slice() else {
        panic!("a saturated producer must not consume another chain's reservation")
    };
    assert_eq!(other.block().header().chain(), ChainId::new(1));
    assert_eq!(
        machine.chain.validation_usage(),
        (
            2,
            first_bytes + other_bytes,
            &[1, 1][..],
            &[first_bytes, other_bytes][..],
        )
    );

    let released = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            active.id(),
            active.generation(),
            BlockValidity::Invalid,
        )))
        .unwrap();
    let released = settle(&mut machine, released);
    let resumed_validations = validations(&released);
    let [resumed] = resumed_validations.as_slice() else {
        panic!("releasing the producer reservation must resume its oldest block")
    };
    assert_eq!(resumed.block().header().chain(), ChainId::new(0));
    assert_eq!(
        machine.chain.validation_usage(),
        (
            2,
            second_bytes + other_bytes,
            &[1, 1][..],
            &[second_bytes, other_bytes][..],
        )
    );
}

#[test]
fn da_fork_selection_does_not_depend_on_validation_completion_order() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let first = make(digest(b"first fork"));
    let second = make(digest(b"second fork"));
    let observed = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::TransactionBlock(SignedTransactionBlock::new(first.clone(), attestation(1))),
            Artifact::TransactionBlock(SignedTransactionBlock::new(second.clone(), attestation(1))),
        ]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("fork cohort must be verified together");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let mut validations = verified
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let first_job = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .unwrap()
        .clone();
    let second_job = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .unwrap()
        .clone();
    validations.clear();

    let later = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            second_job.id(),
            second_job.generation(),
            BlockValidity::Valid,
        )))
        .unwrap();
    let later = settle(&mut machine, later);
    assert!(later.capabilities().is_empty());
    let earlier = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            first_job.id(),
            first_job.generation(),
            BlockValidity::Invalid,
        )))
        .unwrap();
    let earlier = settle(&mut machine, earlier);
    assert!(matches!(
        persist_job(&earlier).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &second)
    ));
}

#[test]
fn application_digest_collision_retains_distinct_header_ancestry() {
    let mut machine = Machine::new(profile_for(Role::Observer, 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make_parent = |body| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            body,
        )
        .unwrap()
    };
    let first_parent = make_parent(digest(b"first application parent"));
    let second_parent = make_parent(digest(b"second application parent"));
    validate_block(&mut machine, first_parent.clone(), 1);
    validate_block(&mut machine, second_parent.clone(), 1);

    let commitment = digest(b"shared untrusted application digest");
    let make = |parent| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(2),
            parent,
            commitment,
        )
        .unwrap()
    };
    let first = make(first_parent.block_ref::<Sha256>().digest());
    let second = make(second_parent.block_ref::<Sha256>().digest());
    let first_artifact =
        Artifact::TransactionBlock(SignedTransactionBlock::new(first.clone(), attestation(1)));
    let second_artifact =
        Artifact::TransactionBlock(SignedTransactionBlock::new(second.clone(), attestation(1)));
    let first_id = first_artifact.id::<Sha256>();
    let second_id = second_artifact.id::<Sha256>();
    let observed = machine
        .step(cohort::<Sha256, _>(vec![first_artifact, second_artifact]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("both exact headers must be verified independently");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let validations = verified
        .capabilities()
        .iter()
        .filter_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(validations.len(), 2);
    let first_job = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .unwrap();
    let second_job = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .unwrap();

    let first_valid = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            first_job.id(),
            first_job.generation(),
            BlockValidity::Valid,
        )))
        .unwrap();
    settle(&mut machine, first_valid);
    let conflicting_valid = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            second_job.id(),
            second_job.generation(),
            BlockValidity::Valid,
        )))
        .unwrap();
    settle(&mut machine, conflicting_valid);

    assert!(machine.artifacts.contains_key(&first_id));
    assert!(machine.artifacts.contains_key(&second_id));
    assert_eq!(machine.chain.retained_ancestry(), 4);
}

#[test]
fn application_digest_collision_does_not_merge_da_vote_pools() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(1)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let commitment = digest(b"shared DA digest");
    let make = |parent| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            parent,
            commitment,
        )
        .unwrap()
    };
    let first = make(genesis.digest());
    let conflicting = make(digest(b"conflicting DA parent"));
    machine
        .chain
        .observe_producer_choice::<Sha256>(&first)
        .unwrap();
    let votes = (0..3)
        .map(|signer| Artifact::DaVote(DaVote::new(first.clone(), threshold_share(signer))))
        .chain([Artifact::DaVote(DaVote::new(
            conflicting,
            threshold_share(3),
        ))])
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(votes)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("both exact DA votes must be verified independently");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    assert!(
        verified.capabilities().iter().all(|effect| !matches!(
            effect,
            Capability::Producer(ProducerCapability::RecoverDa(_))
        )),
        "shares over different exact headers must not combine into a DA quorum"
    );

    let final_vote = observe(
        &mut machine,
        Artifact::DaVote(DaVote::new(first.clone(), threshold_share(3))),
    );
    let recovered = complete_with_step(&mut machine, &final_vote, true);
    let recovered = settle(&mut machine, recovered);
    let recovery = recovered
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job)) => Some(job),
            _ => None,
        });
    let recovery = recovery.expect("one exact-header pool reaches the DA quorum");
    assert!(recovery.votes().iter().all(|vote| vote.header() == &first));
}

#[test]
fn da_fork_selection_does_not_depend_on_verification_completion_order() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let earlier = make(digest(b"earlier unverified fork"));
    let later = make(digest(b"later verified fork"));
    let earlier_job = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(earlier, attestation(1))),
    );
    let later_job = observe(
        &mut machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(later.clone(), attestation(1))),
    );

    let verified_later = machine
        .step(Input::Verified(VerificationCompletion::new(
            later_job.id(),
            later_job.generation(),
            vec![Verdict::new(later_job.items()[0].ticket(), true)],
        )))
        .unwrap();
    let verified_later = settle(&mut machine, verified_later);
    let validation = verified_later
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::Validate(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let held = machine
        .step(Input::BlockValidated(ValidationCompletion::new(
            validation.id(),
            validation.generation(),
            BlockValidity::Valid,
        )))
        .unwrap();
    let held = settle(&mut machine, held);
    assert!(held.capabilities().is_empty());

    let rejected_earlier = machine
        .step(Input::Verified(VerificationCompletion::new(
            earlier_job.id(),
            earlier_job.generation(),
            vec![Verdict::new(earlier_job.items()[0].ticket(), false)],
        )))
        .unwrap();
    let rejected_earlier = settle(&mut machine, rejected_earlier);
    assert!(matches!(
        persist_job(&rejected_earlier).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &later)
    ));
}

#[test]
fn da_worklist_rotates_between_ready_chains() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let generation = machine.durable.generation;
    let mut expected = Vec::new();
    for chain in 1..=2 {
        let genesis = machine.profile().protocol().genesis().tips()[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain as u32),
            Height::new(1),
            genesis.digest(),
            digest(format!("fair body {chain}").as_bytes()),
        )
        .unwrap();
        let artifact = Artifact::TransactionBlock(SignedTransactionBlock::new(
            header.clone(),
            attestation(chain as u32),
        ));
        machine
            .chain
            .observe::<Sha256>(
                artifact.id::<Sha256>(),
                Observation::new(1, chain as u32),
                &artifact,
                generation,
            )
            .unwrap();
        expected.push(header);
    }
    let validations = machine
        .chain
        .take_effects()
        .into_iter()
        .filter_map(|effect| match effect {
            ChainEffect::Validate(job) => Some(job),
            _ => None,
        })
        .collect::<Vec<_>>();
    for validation in validations {
        machine
            .chain
            .complete_validation::<Sha256>(
                ValidationCompletion::new(
                    validation.id(),
                    validation.generation(),
                    BlockValidity::Valid,
                ),
                generation,
            )
            .unwrap();
    }

    let profile = machine.profile().clone();
    for expected in expected {
        let selected = machine
            .chain
            .next_ready_da_vote::<Sha256>(&profile)
            .unwrap()
            .unwrap();
        assert_eq!(selected.header(), &expected);
        machine
            .chain
            .mark_da_vote_reserved(selected.header().clone());
        machine.chain.observe_da_choice(selected.header()).unwrap();
    }
}

#[test]
fn producer_recovers_the_canonical_da_quorum_and_retains_the_certificate() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let (header, recovery) = produce_and_collect_da(&mut machine);
    assert_eq!(
        recovery
            .votes()
            .iter()
            .map(|vote| vote.signer())
            .collect::<Vec<_>>(),
        (0..4).map(Participant::new).collect::<Vec<_>>()
    );
    let certificate = symbolic_da_certificate(header, 0);
    let recovered = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            certificate.clone(),
        )))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging barrier.
    assert_eq!(recovered.status(), &StepStatus::CompletionDeferred);
    let recovered = settle(&mut machine, recovered);
    assert!(matches!(
        persist_job(&recovered).events()[0].change(),
        Change::DaCertificateAdvanced {
            publication: Some(_),
            artifact,
            ..
        }
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
    assert!(
        recovered.capabilities().iter().any(|effect| {
            matches!(durable_effect(effect), Some(DurableEffect::Broadcast(artifact))
                if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate))
        }),
        "staging must release the recovered certificate"
    );
    let published = persist(&mut machine, &persist_job(&recovered));
    assert!(!matches!(
        published.capabilities().first().and_then(durable_effect),
        Some(DurableEffect::Broadcast(artifact))
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
    assert_eq!(machine.inspect().local_artifacts(), 1);
}

#[test]
fn inspection_reports_known_unfinalized_chain_tips() {
    let profile = profile_for(Role::Observer, 1, 2);
    let (mut machine, _) = start_profile(profile);
    let genesis = machine.profile().protocol().genesis().tips()[0];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        genesis.chain(),
        Height::new(1),
        genesis.digest(),
        digest(b"known but unfinalized"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(header, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    complete(&mut machine, &verification, true);

    let inspection = machine.inspect();
    let [progress] = inspection.chain_progress() else {
        panic!("the one-chain profile must report one chain");
    };
    assert_eq!(progress.chain(), genesis.chain());
    assert_eq!(progress.finalized(), Height::zero());
    assert_eq!(progress.certified(), Height::new(1));
    assert_eq!(progress.known(), Height::new(1));
}

#[test]
fn mismatched_da_recovery_does_not_consume_the_job() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let (header, recovery) = produce_and_collect_da(&mut machine);

    let mismatched_header = TransactionBlockHeader::new(
        header.epoch(),
        header.chain(),
        header.height(),
        header.parent(),
        digest(b"mismatched DA recovery subject"),
    )
    .unwrap();
    let mismatched = symbolic_da_certificate(mismatched_header, 0);
    let parked = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            mismatched,
        )))
        .unwrap();
    assert_eq!(parked.status(), &StepStatus::CompletionDeferred);
    // The mismatch surfaces exactly once when the parked completion drains; the recovery job
    // survives for the corrected certificate.
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    let certificate = symbolic_da_certificate(header, 0);
    let certificate_id = Artifact::DaCertificate(certificate.clone()).id::<Sha256>();
    let matched = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            certificate.clone(),
        )))
        .unwrap();
    assert_eq!(matched.status(), &StepStatus::CompletionDeferred);
    let matched = settle(&mut machine, matched);
    assert!(machine.artifacts.contains_key(&certificate_id));
    assert!(matches!(
        persist_job(&matched).events()[0].change(),
        Change::DaCertificateAdvanced { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
}

#[test]
fn stale_recovery_completion_releases_the_job_and_rereadies_the_block() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let (header, recovery) = produce_and_collect_da(&mut machine);
    assert_eq!(machine.chain.recovery_reservations(), 1);
    assert!(!machine.chain.has_ready_recovery());

    // A generation advance strands the dispatched job. Consuming its completion must release
    // the reservation and re-derive readiness from the surviving vote pool, not leave the
    // block parked behind a job nobody will complete.
    let stale = DaRecoveryCompletion::new(
        recovery.id(),
        recovery.generation(),
        symbolic_da_certificate(header, 0),
    );
    let released = machine
        .chain
        .prepare_recovery::<Sha256>(&stale, recovery.generation() + 1)
        .unwrap();
    assert!(released.is_none());
    assert_eq!(machine.chain.recovery_reservations(), 0);
    assert!(machine.chain.has_ready_recovery());
}

#[test]
fn stale_lqc_completion_returns_the_pool_to_the_ready_set() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);
    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = complete_with_step(&mut machine, &vote, true);
        if signer == 4 {
            let (effects, _) = drive_poll_and_persist(&mut machine, step);
            aggregate = effects.iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
                _ => None,
            });
        }
    }
    let aggregate = aggregate.expect("the n-f vote must schedule L-QC assembly");
    assert_eq!(machine.finality.lqc_aggregate_jobs.len(), 1);
    assert!(machine.finality.ready_lqcs.is_empty());

    // A generation advance strands the dispatched aggregation. Consuming its completion must
    // return the pool to the ready set, not leave it pending behind a job nobody will complete.
    let votes = aggregate.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, aggregate.leader().clone(), &votes);
    let profile = machine.profile().clone();
    let completion = LqcAggregateCompletion::new(aggregate.id(), aggregate.generation(), assembled);
    let released = machine
        .finality
        .prepare_lqc::<Sha256>(&profile, completion, aggregate.generation() + 1)
        .unwrap();
    assert!(released.is_none());
    assert!(machine.finality.lqc_aggregate_jobs.is_empty());
    assert_eq!(machine.finality.ready_lqcs.len(), 1);
}

#[test]
fn stale_vqc_completion_releases_the_pending_view() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 2);
    let view = View::new(2);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);
    let mut aggregate = None;
    for signer in 0..5 {
        let artifact = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, artifact);
        let step = complete_with_step(&mut machine, &vote, true);
        if signer == 4 {
            let (effects, _) = drive_poll_and_persist(&mut machine, step);
            aggregate = effects.iter().find_map(|effect| match effect {
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
                _ => None,
            });
        }
    }
    let aggregate = aggregate.expect("the n-f message must schedule V-QC assembly");
    assert!(machine.views.certificate_pending(view));

    // A generation advance strands the dispatched assembly. Consuming its completion must
    // clear the pending marker and re-ready the view from its retained messages.
    let messages = aggregate.messages().collect::<Vec<_>>();
    let assembled = vqc(&machine, aggregate.leader().clone(), &messages);
    let profile = machine.profile().clone();
    let completion = VqcAggregateCompletion::new(aggregate.id(), aggregate.generation(), assembled);
    let released = machine
        .views
        .prepare_vqc::<Sha256>(&profile, &completion, aggregate.generation() + 1)
        .unwrap();
    assert!(released.is_none());
    assert!(!machine.views.certificate_pending(view));
    assert!(machine.views.certificate_ready(view));
}

#[test]
fn stale_nullification_completion_releases_the_pending_view() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let view = View::new(1);
    let shares = [2, 0, 1]
        .into_iter()
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(shares)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("nullify shares must be verified");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the nullification quorum must schedule recovery");
    assert_eq!(machine.views.certificate_reservations(), 1);
    assert!(machine.views.certificate_pending(view));

    // A generation advance strands the dispatched recovery. Consuming its completion must
    // clear the pending marker and re-ready the view from its retained shares.
    let completion = NullificationRecoveryCompletion::new(
        recovery.id(),
        recovery.generation(),
        symbolic_nullification(&machine, view, 0),
    );
    let released = machine
        .views
        .prepare_nullification(&completion, recovery.generation() + 1)
        .unwrap();
    assert!(released.is_none());
    assert_eq!(machine.views.certificate_reservations(), 0);
    assert!(!machine.views.certificate_pending(view));
    assert!(machine.views.certificate_ready(view));
}

#[test]
fn local_da_certificate_promotes_an_identical_pending_artifact() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let (header, recovery) = produce_and_collect_da(&mut machine);
    let certificate = symbolic_da_certificate(header, 0);
    let certificate_id = Artifact::DaCertificate(certificate.clone()).id::<Sha256>();
    let inbound = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));

    let local = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            certificate,
        )))
        .unwrap();
    // Recovery completions always park; settling drains the completion into its staging barrier.
    assert_eq!(local.status(), &StepStatus::CompletionDeferred);
    let local = settle(&mut machine, local);
    persist(&mut machine, &persist_job(&local));
    assert!(
        machine
            .inspect()
            .ready_artifacts()
            .contains(&certificate_id)
    );

    let stale_worker = machine
        .step(Input::Verified(VerificationCompletion::new(
            inbound.id(),
            inbound.generation(),
            vec![Verdict::new(inbound.items()[0].ticket(), false)],
        )))
        .unwrap();
    assert!(matches!(
        stale_worker.status(),
        StepStatus::Verified {
            valid: 0,
            invalid: 0
        }
    ));
    assert!(
        machine
            .inspect()
            .ready_artifacts()
            .contains(&certificate_id)
    );
}

#[test]
fn an_issued_build_reserves_its_durable_completion_capacity() {
    let resources = resources_with_capacities(32, 16);
    let profile = profile_with_resources(Role::Validator(Participant::new(0)), 6, 2, resources);
    let (mut machine, _) = start_profile(profile);
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let build = build_job(&ready);
    let limit = machine.profile().resources().max_outbox_effects();
    let mut filler_view = 10;
    loop {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        match machine.reserve_test_effect(DurableEffect::Broadcast(filler)) {
            Ok(reserved) => {
                persist(&mut machine, &persist_job(&reserved));
            }
            Err(StepError::OutboxFull) => break,
            Err(error) => panic!("unexpected filler rejection: {error:?}"),
        }
    }
    assert_eq!(machine.inspect().outbox().len(), limit - 1);

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"reserved completion")),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::BlockBuilt);
    let completed = settle(&mut machine, completed);
    let completed = complete_custody(&mut machine, &custody_job(&completed));
    persist(&mut machine, &persist_job(&completed));
    assert_eq!(
        machine.inspect().outbox().len() + machine.chain.build_reservations(),
        limit
    );
}

#[test]
fn an_issued_build_reserves_its_durable_artifact_capacity() {
    let resources = resources_with_capacities(16, 64);
    let profile = profile_with_resources(Role::Validator(Participant::new(0)), 6, 2, resources);
    let (mut machine, _) = start_profile(profile);

    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = settle(&mut machine, ready);
    let build = build_job(&ready);
    let mut filler_view = 10;
    loop {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        match machine.reserve_test_effect(DurableEffect::Broadcast(filler)) {
            Ok(reserved) => {
                persist(&mut machine, &persist_job(&reserved));
            }
            Err(StepError::LocalArtifactReservation) => break,
            Err(error) => panic!("unexpected filler rejection: {error:?}"),
        }
    }

    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.id(),
            build.generation(),
            build.parent(),
            Some(digest(b"artifact-reserved completion")),
        )))
        .unwrap();
    assert_eq!(completed.status(), &StepStatus::BlockBuilt);
    let completed = settle(&mut machine, completed);
    let completed = complete_custody(&mut machine, &custody_job(&completed));
    persist(&mut machine, &persist_job(&completed));
}

#[test]
fn recovered_chain_signing_reservations_use_global_capacity() {
    let resources = resources_with_capacities(64, 64);
    let profile = profile_with_resources(Role::Validator(Participant::new(0)), 2, 1, resources);
    let chain_capacity = profile.protocol().codec_config().chains()
        * (profile.protocol().codec_config().pipeline_depth() + 1);
    let (mut machine, _) = start_profile(profile.clone());
    let chain = ChainId::new(1);
    let mut parent = machine.profile().protocol().genesis().tips()[chain.get() as usize];

    for height in 1..=chain_capacity {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            chain,
            Height::new(height as u64),
            parent.digest(),
            digest(format!("pending block {height}").as_bytes()),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>();
        let reserved = validate_block(&mut machine, header.clone(), 1);
        persist(&mut machine, &persist_job(&reserved));

        let certificate = observe(
            &mut machine,
            Artifact::DaCertificate(symbolic_da_certificate(header, height as u64)),
        );
        let certified = complete_with_step(&mut machine, &certificate, true);
        let advanced = persist(&mut machine, &persist_job(&certified));
        let _ = drive_poll_and_persist(&mut machine, advanced);
    }

    let mut recovered = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = recovered.step(Input::RecoveryComplete).unwrap();
    persist(&mut recovered, &persist_job(&recovery));

    let global_effects =
        recovered.durable.signing_reservations.len() + recovered.durable.outbox.len();
    assert_eq!(global_effects, chain_capacity);
    assert!(global_effects < recovered.profile().resources().max_outbox_effects());
    let global_artifacts = recovered.durable.artifact_occupancy::<Sha256>();
    assert!(global_artifacts < recovered.profile().resources().max_cached_artifacts());

    let header = TransactionBlockHeader::new(
        recovered.profile().protocol().epoch(),
        chain,
        Height::new(chain_capacity as u64 + 1),
        parent.digest(),
        digest(b"next pending block"),
    )
    .unwrap();
    let reserved = validate_block(&mut recovered, header, 1);
    persist(&mut recovered, &persist_job(&reserved));
    assert_eq!(
        recovered.durable.signing_reservations.len(),
        chain_capacity + 1
    );
}

#[test]
fn finality_floor_preserves_an_lqc_aggregation_reservation() {
    let resources = resources_with_capacities(32, 64);
    let profile = profile_with_resources(Role::Observer, 6, 2, resources);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 3);
    let proposal_signer = machine.profile().protocol().leader(View::new(3));
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(proposal_signer.get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let mut vqc_job = None;
    let mut lqc_job = None;
    for signer in 0..5 {
        let vote = Artifact::Vote(view_vote(&machine, &proposed, signer));
        let vote = observe(&mut machine, vote);
        let admitted = complete_with_step(&mut machine, &vote, true);
        let (effects, _) = drive_poll_and_persist(&mut machine, admitted);
        for effect in effects {
            match effect {
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => vqc_job = Some(job),
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => lqc_job = Some(job),
                _ => {}
            }
        }
    }
    let vqc_job = vqc_job.expect("the quorum must schedule V-QC assembly");
    let lqc_job = lqc_job.expect("the quorum must schedule L-QC assembly");
    machine.views.finish_vqc(vqc_job.id());
    assert_eq!(machine.inspect().view(), View::new(1));
    assert_eq!(machine.finality.aggregate_reservations(), 1);
    assert_eq!(machine.views.certificate_reservations(), 0);

    let limit = machine.profile().resources().max_cached_artifacts();
    let mut filler_view = 10;
    while machine.durable_artifact_references.len() < limit - 2 {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        let reserved = machine
            .reserve_test_effect(DurableEffect::Broadcast(filler))
            .expect("the filler must fit before the reserved boundary");
        persist(&mut machine, &persist_job(&reserved));
    }
    assert_eq!(machine.durable_artifact_references.len(), limit - 2);
    assert_eq!(
        machine.durable_artifact_references.len() + machine.finality.aggregate_reservations(),
        limit - 1
    );

    let competing = leader(&machine, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&machine, &competing, signer))
        .collect::<Vec<_>>();
    let competing = Arc::new(Artifact::Lqc(lqc(&machine, competing, &votes)));
    machine
        .views
        .observe_finality(competing.id::<Sha256>(), &competing)
        .unwrap();
    let Artifact::Lqc(certificate) = competing.as_ref() else {
        unreachable!()
    };
    let derived = Arc::new(Artifact::Vqc(
        certificate
            .derive_vqc(machine.profile().protocol().codec_config())
            .unwrap(),
    ));
    let profile = machine.profile().clone();
    machine
        .views
        .observe::<Sha256>(
            derived.id::<Sha256>(),
            Observation::new(1, 0),
            &derived,
            &profile,
        )
        .unwrap();
    assert!(matches!(
        machine.next_finality_floor_change_for_test(),
        Some(Change::FinalityFloorAdvanced {
            publication_retired,
            ..
        }) if publication_retired.is_empty()
    ));
    let wake = machine.step(Input::ProducerWake).unwrap();
    drive_poll_and_persist(&mut machine, wake);
    assert!(machine.durable.signing_floor.is_none());
    assert_eq!(machine.durable_artifact_references.len(), limit - 1);

    let votes = lqc_job.votes().cloned().collect::<Vec<_>>();
    let assembled = lqc(&machine, lqc_job.leader().clone(), &votes);
    let completed = machine
        .step(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
            lqc_job.id(),
            lqc_job.generation(),
            assembled.clone(),
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let job = persist_job(&completed);
    assert!(matches!(
        job.events()[0].change(),
        Change::ArtifactCreated { artifact, .. }
            if artifact.as_ref() == &Artifact::Lqc(assembled)
    ));
    let persisted = persist(&mut machine, &job);
    drive_poll_and_persist(&mut machine, persisted);

    assert_eq!(machine.finality.aggregate_reservations(), 0);
    assert!(
        machine.durable_artifact_references.len()
            <= machine.profile().resources().max_cached_artifacts()
    );
}

#[test]
fn da_recovery_reserves_its_publication_slot() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let (header, recovery) = produce_and_collect_da(&mut machine);
    let limit = machine.profile().resources().max_outbox_effects();
    let mut filler_view = 10;

    while machine.inspect().outbox().len()
        + machine.chain.build_reservations()
        + machine.chain.recovery_reservations()
        < limit
    {
        let filler = Arc::new(leader_artifact(&machine, filler_view));
        filler_view += 1;
        let reserved = machine
            .reserve_test_effect(DurableEffect::Broadcast(filler))
            .unwrap();
        persist(&mut machine, &persist_job(&reserved));
    }
    assert!(matches!(
        machine.reserve_test_effect(DurableEffect::Broadcast(Arc::new(leader_artifact(
            &machine,
            filler_view,
        )))),
        Err(StepError::OutboxFull)
    ));

    let certificate = symbolic_da_certificate(header, 0);
    let completed = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            certificate,
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    persist(&mut machine, &persist_job(&completed));
    assert_eq!(
        machine.inspect().outbox().len() + machine.chain.build_reservations(),
        limit
    );
}

#[test]
fn recovery_reissues_the_exact_durable_da_vote() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = Machine::new(profile_for(role, 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"recoverable DA vote"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, header.clone(), 1);
    persist(&mut machine, &persist_job(&reserved));

    let mut restored = Machine::restore(profile_for(role, 6, 2), machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restored, &persist_job(&recovery));
    let exact = recovered.capabilities().iter().any(|effect| {
        matches!(durable_effect(effect), Some(DurableEffect::Sign(
            SignRequest::DaVote(actual)
        )) if actual.header() == &header)
    });
    assert!(exact, "recovery must reissue the durable DA choice");
}

#[test]
fn invalid_da_certificate_does_not_block_the_valid_certificate() {
    let mut machine = Machine::new(profile_for(Role::Observer, 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"retry certificate"),
    )
    .unwrap();
    let forged = symbolic_da_certificate(header.clone(), 0);
    let forged = observe(&mut machine, Artifact::DaCertificate(forged));
    let recovered = symbolic_da_certificate(header, 1);
    let recovered = observe(&mut machine, Artifact::DaCertificate(recovered));
    complete(&mut machine, &recovered, true);
    let waiting = machine.chain.proposal(machine.profile(), genesis).unwrap();
    assert!(matches!(waiting.anchor(), Anchor::Tip(_)));

    let advanced = complete_with_step(&mut machine, &forged, false);
    persist(&mut machine, &persist_job(&advanced));
    let promoted = machine.chain.proposal(machine.profile(), genesis).unwrap();
    assert!(matches!(promoted.anchor(), Anchor::Certificate(_)));
    assert_eq!(machine.inspect().ready_artifacts().len(), 1);
}

#[test]
fn conflicting_da_certificates_are_rejected() {
    let mut machine = Machine::new(profile_for(Role::Observer, 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let make = |commitment| {
        TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(1),
            genesis.digest(),
            commitment,
        )
        .unwrap()
    };
    let first = symbolic_da_certificate(make(digest(b"certified first")), 0);
    let second = symbolic_da_certificate(make(digest(b"certified second")), 0);
    let first = observe(&mut machine, Artifact::DaCertificate(first));
    complete(&mut machine, &first, true);

    let second = observe(&mut machine, Artifact::DaCertificate(second));
    assert!(matches!(
        machine.step(Input::Verified(VerificationCompletion::new(
            second.id(),
            second.generation(),
            vec![Verdict::new(second.items()[0].ticket(), true)],
        ))),
        Err(StepError::ChainInvariant)
    ));
}

#[test]
fn da_voting_stops_at_the_uncertified_pipeline_boundary() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));

    let mut parent = machine.profile().protocol().genesis().tips()[1];
    let mut headers = Vec::new();
    for height in 1..=3 {
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(1),
            Height::new(height),
            parent.digest(),
            digest(format!("bounded body {height}").as_bytes()),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>();
        headers.push(header);
    }

    let held = authenticate_block(&mut machine, headers[2].clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let held = authenticate_block(&mut machine, headers[1].clone(), 1);
    assert!(validation_jobs(&held).is_empty());
    let ready = authenticate_block(&mut machine, headers[0].clone(), 1);
    let validations = validation_jobs(&ready);
    let child = validations
        .iter()
        .find(|job| job.block().header() == &headers[1])
        .expect("the anchored child enters validation");
    let child = complete_validation(&mut machine, child);
    let grandchild = validation_jobs(&child)
        .into_iter()
        .find(|job| job.block().header() == &headers[2])
        .expect("released capacity admits the grandchild");
    let held = complete_validation(&mut machine, &grandchild);
    assert!(held.capabilities().is_empty());
    let parent = validations
        .iter()
        .find(|job| job.block().header() == &headers[0])
        .expect("the parent enters validation");
    let unlocked = complete_validation(&mut machine, parent);
    let mut choices = Vec::new();
    drain_da_choices(&mut machine, unlocked, &mut choices);
    assert_eq!(choices, headers[..2]);
}

#[test]
fn a_future_certificate_retires_lower_da_work() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let lower = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"lower body"),
    )
    .unwrap();
    let future = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(3),
        digest(b"future parent"),
        digest(b"future body"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(future, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = complete_with_step(&mut machine, &verification, true);
    persist(&mut machine, &persist_job(&advanced));

    let choice = validate_block(&mut machine, lower, 1);
    assert!(choice.capabilities().is_empty());
}

#[test]
fn a_certified_base_allows_voting_for_its_child_after_a_gap() {
    let role = Role::Validator(Participant::new(0));
    let profile = profile_for(role, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let certified = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(3),
        digest(b"unheld certified parent"),
        digest(b"certified body"),
    )
    .unwrap();
    let certificate = symbolic_da_certificate(certified.clone(), 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate));
    let advanced = complete_with_step(&mut machine, &verification, true);
    persist(&mut machine, &persist_job(&advanced));

    let child = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(4),
        certified.block_ref::<Sha256>().digest(),
        digest(b"certified child body"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, child.clone(), 1);
    assert!(matches!(
        persist_job(&reserved).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &child)
    ));
    persist(&mut machine, &persist_job(&reserved));

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    assert_eq!(
        restored.snapshot().da_safety_heights()[genesis.chain().get() as usize],
        child.height()
    );
}

#[test]
fn recovery_requires_the_held_path_before_extending_a_da_vote() {
    let role = Role::Validator(Participant::new(0));
    let mut machine = Machine::new(profile_for(role, 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"restored first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"restored second"),
    )
    .unwrap();
    let reserved = validate_block(&mut machine, first.clone(), 1);
    persist(&mut machine, &persist_job(&reserved));

    let mut restored = Machine::restore(profile_for(role, 6, 2), machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    let held_second = authenticate_block(&mut restored, second.clone(), 1);
    assert!(validation_jobs(&held_second).is_empty());

    let ready = authenticate_block(&mut restored, first.clone(), 1);
    let validations = validation_jobs(&ready);
    let child = validations
        .iter()
        .find(|job| job.block().header() == &second)
        .expect("the restored path admits its child");
    let held = complete_validation(&mut restored, child);
    assert!(held.capabilities().is_empty());
    let parent = validations
        .iter()
        .find(|job| job.block().header() == &first)
        .expect("the recovered authority requires parent custody");
    let restored_path = complete_validation(&mut restored, parent);
    assert!(matches!(
        persist_job(&restored_path).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::DaVote(actual)) if actual.header() == &second)
    ));
}

#[test]
fn proposal_fact_uses_the_highest_certificate_and_voted_suffix() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let genesis = machine.profile().protocol().genesis().tips()[1];
    let first = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis.digest(),
        digest(b"proposal first"),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(1),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"proposal second"),
    )
    .unwrap();

    let first_choice = validate_block(&mut machine, first.clone(), 1);
    persist(&mut machine, &persist_job(&first_choice));
    let certificate = symbolic_da_certificate(first, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let advanced = complete_with_step(&mut machine, &verification, true);
    persist(&mut machine, &persist_job(&advanced));
    let second_choice = validate_block(&mut machine, second.clone(), 1);
    persist(&mut machine, &persist_job(&second_choice));

    let proposal = machine.chain.proposal(machine.profile(), genesis).unwrap();
    assert_eq!(proposal.anchor(), &Anchor::Certificate(certificate));
    assert_eq!(proposal.payloads(), &[second.body_digest()]);
}

#[test]
fn leader_proposal_choice_is_durable() {
    let mut machine = Machine::new(profile(Role::Validator(Participant::new(0))));
    let start = machine.step(Input::Start).unwrap();
    let started = persist(&mut machine, &persist_job(&start));
    let proposal = persist_job(&started);

    let Change::OutboxQueued { effect, .. } = proposal.events()[0].change() else {
        panic!("view entry must durably queue the proposal choice");
    };
    let DurableEffect::Sign(SignRequest::LeaderBlock(request)) = effect.as_ref() else {
        panic!("view-one leader must choose one exact proposal");
    };
    let expected = leader(&machine, 1);
    assert_eq!(request.block(), &expected);
    assert!(request.parent().is_genesis());

    // Signing carries no signature out, so the request releases in the step that staged the
    // choice; the acknowledgement must not repeat it.
    let sign = sign_job(&started);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the staged proposal must be signed verbatim");
    };
    assert_eq!(request.block(), &expected);
    assert!(request.parent().is_genesis());

    let released = persist(&mut machine, &proposal);
    assert!(
        !released
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Sign(_)))),
        "the choice acknowledgement must not release signing a second time"
    );
}

#[test]
fn oversized_proposal_pass_resumes_at_item_boundaries() {
    let participants = 130;
    let view = View::new(1);
    let signer = LeaderSchedule::round_robin(participants).leader(view);
    let profile: Profile<Sha256, MinPk> = Profile::new(
        config_for(Epoch::new(7), participants, 2),
        Role::Validator(signer),
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
            ..Tuning::default()
        },
    )
    .unwrap();
    let mut machine = Machine::new(profile.clone());
    machine.step(Input::Start).unwrap();

    let quantum = 16;
    let mut turns = 0;
    let request = loop {
        let drive = machine
            .views
            .drive_regular_sign_request::<Sha256>(&profile, view, &machine.chain, quantum)
            .unwrap();
        assert!(drive.processed <= quantum);
        turns += 1;
        if let Some(request) = drive.request {
            break request;
        }
        assert!(!drive.complete);
        assert!(turns < 64, "proposal construction failed to resume");
    };

    let SignRequest::LeaderBlock(request) = request else {
        panic!("the local leader must construct a proposal")
    };
    assert_eq!(request.block().proposals().len(), participants);
    assert!(turns > 1, "the oversized pass completed in one quantum");
}

fn enqueue_due_batch_controls(
    composer: &mut CoreState<Sha256, MinPk>,
    persistence: BarrierAck,
) -> [(InputTicket, Lane); 3] {
    let epoch = composer.machine().profile().protocol().epoch();
    let persistence = composer.enqueue(Input::Persisted(persistence), 1).unwrap();
    let timer = composer
        .enqueue(
            Input::TimerFired(Timer::new(
                0,
                Round::new(epoch, View::zero()),
                Duration::ZERO,
            )),
            1,
        )
        .unwrap();
    let view = View::new(u64::MAX);
    let job = ResolutionJob::fabricate(u64::MAX, 0, view);
    let proof = ViewProof::Nullification(Box::new(
        Nullification::new(Round::new(epoch, view), symbolic_threshold_certificate(0)).unwrap(),
    ));
    let resolver = composer
        .enqueue(
            Input::ResolutionCompleted(ResolutionCompletion::new(
                job.id(),
                job.generation(),
                job.view(),
                proof,
            )),
            1,
        )
        .unwrap();
    [
        (persistence, Lane::PersistenceCompletion),
        (timer, Lane::Timer),
        (resolver, Lane::ResolverResult),
    ]
}

fn record_protocol_acceptances(
    accepted: &mut Vec<ArtifactId<Digest>>,
    activities: &[Activity<MinPk, Digest>],
) {
    accepted.extend(activities.iter().filter_map(|activity| match activity {
        Activity::ProtocolAccepted { artifact_id, .. } => Some(*artifact_id),
        Activity::HistoryAccepted { .. } => None,
        Activity::LeaderFinalized { .. } => None,
    }));
}

#[test]
fn maximum_verified_batch_resumes_at_real_item_boundaries() {
    let batch_items = 128;
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(2).unwrap(),
        batch_items as u64,
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(batch_items).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
        NonZeroUsize::new(batch_items * 4).unwrap(),
    );
    let profile = profile_with_retention(
        Role::Observer,
        1,
        1,
        resources,
        ViewDelta::new(batch_items as u64),
    );
    let (mut machine, _) = start_profile(profile);
    let artifacts = (1..=batch_items)
        .map(|view| leader_artifact(&machine, view as u64))
        .collect::<Vec<_>>();
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("the maximum cohort must produce one verification job");
    };
    assert_eq!(verification.items().len(), batch_items);
    let expected = verification
        .items()
        .iter()
        .map(|item| item.ticket().artifact())
        .collect::<Vec<_>>();
    let completion = VerificationCompletion::new(
        verification.id(),
        verification.generation(),
        verification
            .items()
            .iter()
            .map(|item| Verdict::new(item.ticket(), true))
            .collect(),
    );
    let filler = Arc::new(leader_artifact(&machine, batch_items as u64 + 1));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Broadcast(filler))
        .unwrap();
    let persistence = persist_job(&reserved);

    let mut composer = CoreState::new(machine, NonZeroUsize::MIN).unwrap();
    let batch = composer.enqueue(Input::Verified(completion), 1).unwrap();
    let controls = enqueue_due_batch_controls(
        &mut composer,
        BarrierAck::new(
            persistence.id(),
            persistence.generation(),
            persistence.last_cursor(),
        ),
    );
    let mut control_cycles = [None; 3];
    let mut accepted = Vec::new();
    let mut resumed = false;
    let mut complete = false;

    for _ in 0..10_000 {
        match composer.next_action(NonZeroUsize::MIN).unwrap() {
            CoreTurn::Input(serviced) => {
                record_protocol_acceptances(&mut accepted, serviced.transition.activities());
                if serviced.ticket == batch {
                    resumed |= !serviced.final_chunk;
                    complete |= serviced.final_chunk;
                }
                for (index, (ticket, _)) in controls.iter().enumerate() {
                    if serviced.ticket == *ticket {
                        control_cycles[index] = Some(serviced.cycle);
                    }
                }
            }
            CoreTurn::Work(result) => {
                record_protocol_acceptances(&mut accepted, result.activities());
            }
            CoreTurn::YieldRequired => composer.resume_after_yield().unwrap(),
            CoreTurn::Idle => break,
        }
        if complete && control_cycles.iter().all(Option::is_some) {
            break;
        }
    }

    assert!(
        resumed,
        "the reducer must run before the final charged prefix"
    );
    assert!(
        complete,
        "the exact verification suffix must resume to completion"
    );
    assert_eq!(accepted, expected, "resume must preserve observation order");
    for (cycle, (_, lane)) in control_cycles.into_iter().zip(controls) {
        let cycle = cycle.unwrap_or_else(|| panic!("{lane:?} was not serviced"));
        assert!(cycle <= 1, "{lane:?} exceeded its one-cycle service bound");
    }
}

#[test]
fn maximum_signed_batch_preempts_without_partial_exposure() {
    let batch_items = contracts::CORE_BUDGET as usize;
    let profile: Profile<Sha256, MinPk> = Profile::new(
        config_for(Epoch::new(7), batch_items, 1),
        Role::Validator(Participant::new(0)),
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
            ..Tuning::default()
        },
    )
    .unwrap();
    let (mut machine, mut started) = start_profile(profile);
    while let Some(job) = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        })
    {
        started = persist(&mut machine, &job);
    }

    let mut requests = Vec::with_capacity(batch_items);
    let mut artifacts = Vec::with_capacity(batch_items);
    for chain in 0..batch_items {
        let genesis = machine.profile().protocol().genesis().tips()[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain as u32),
            Height::new(1),
            genesis.digest(),
            digest(format!("preempted signing batch {chain}").as_bytes()),
        )
        .unwrap();
        let block = Arc::new(SignedTransactionBlock::new(
            header.clone(),
            attestation(chain as u32),
        ));
        requests.push(SignRequest::DaVote(DaVoteRequest::new(block)));
        artifacts.push(Artifact::DaVote(DaVote::new(header, threshold_share(0))));
    }
    let expected = artifacts
        .iter()
        .map(Artifact::id::<Sha256>)
        .collect::<Vec<_>>();
    let reserved = machine
        .reserve_test_effect(DurableEffect::SignBatch(requests.into()))
        .unwrap();
    let persistence = persist_job(&reserved);
    let signing = reserved
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::SignBatch(requests)
                    if requests.len() == batch_items) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the exact signing batch must be issued before acknowledgement");

    let mut composer = CoreState::new(machine, NonZeroUsize::MIN).unwrap();
    let batch = composer
        .enqueue(
            Input::EffectCompleted(EffectCompletion::SignedBatch {
                id: signing.id(),
                generation: signing.generation(),
                artifacts,
            }),
            1,
        )
        .unwrap();
    let controls = enqueue_due_batch_controls(
        &mut composer,
        BarrierAck::new(
            persistence.id(),
            persistence.generation(),
            persistence.last_cursor(),
        ),
    );
    let mut control_cycles = [None; 3];
    let mut accepted = Vec::new();
    let mut resumed = false;
    let mut complete = false;
    let mut persisted_batch = false;

    for _ in 0..10_000 {
        match composer.next_action(NonZeroUsize::MIN).unwrap() {
            CoreTurn::Input(serviced) => {
                record_protocol_acceptances(&mut accepted, serviced.transition.activities());
                if serviced.ticket == batch {
                    resumed |= !serviced.final_chunk;
                    complete |= serviced.final_chunk;
                }
                for (index, (ticket, _)) in controls.iter().enumerate() {
                    if serviced.ticket == *ticket {
                        control_cycles[index] = Some(serviced.cycle);
                    }
                }
            }
            CoreTurn::Work(result) => {
                record_protocol_acceptances(&mut accepted, result.activities());
                persisted_batch |= result.capabilities().iter().any(|effect| {
                    let Capability::Durability(DurabilityCapability::Persist(job)) = effect else {
                        return false;
                    };
                    job.events().iter().any(|event| {
                        matches!(event.change(), Change::SignedArtifactBatch { sign, artifacts, .. }
                            if *sign == signing.id()
                                && artifacts.iter().map(|artifact| artifact.id::<Sha256>())
                                    .eq(expected.iter().copied()))
                    })
                });
            }
            CoreTurn::YieldRequired => composer.resume_after_yield().unwrap(),
            CoreTurn::Idle => break,
        }

        let snapshot = composer.machine().snapshot();
        let local = snapshot.local_artifacts();
        let admitted = expected.iter().filter(|id| local.contains_key(id)).count();
        assert!(
            admitted == 0 || admitted == expected.len(),
            "an atomic signing batch exposed a partial prefix"
        );
        if complete
            && persisted_batch
            && admitted == expected.len()
            && control_cycles.iter().all(Option::is_some)
        {
            break;
        }
    }

    assert!(resumed, "signing validation must stop at an item boundary");
    assert!(
        complete,
        "the exact signing suffix must resume to completion"
    );
    assert!(
        persisted_batch,
        "the exact id and ordered batch must be staged once"
    );
    assert_eq!(
        accepted, expected,
        "self-admission order changed across resume"
    );
    for (cycle, (_, lane)) in control_cycles.into_iter().zip(controls) {
        let cycle = cycle.unwrap_or_else(|| panic!("{lane:?} was not serviced"));
        assert!(cycle <= 1, "{lane:?} exceeded its one-cycle service bound");
    }
}

#[test]
fn signed_valid_proposal_durably_selects_direct_vote() {
    let mut machine = Machine::new(profile(Role::Validator(Participant::new(0))));
    let start = machine.step(Input::Start).unwrap();
    let started = persist(&mut machine, &persist_job(&start));
    // The signing request releases with the step that stages the choice; its barrier still has
    // to acknowledge before the signed proposal may publish.
    let proposal_sign = sign_job(&started);
    persist(&mut machine, &persist_job(&started));
    let SignRequest::LeaderBlock(request) = sign_request(&proposal_sign) else {
        panic!("view-one leader must sign a proposal");
    };
    let proposed = request.block().clone();

    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: proposal_sign.id(),
            generation: proposal_sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed.clone(),
                attestation(0),
            ))),
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let published = persist(&mut machine, &persist_job(&completed));
    let publication =
        published
            .capabilities()
            .iter()
            .find_map(|effect| match durable_effect(effect) {
                Some(DurableEffect::Propose(publication)) => Some(publication),
                _ => None,
            });
    let publication = publication.expect("signed proposal must carry its exact parent");
    assert_eq!(publication.block().block(), &proposed);
    assert!(publication.parent().is_genesis());

    let vote = persist_job(&published);
    let Change::OutboxQueued { effect, .. } = vote.events()[0].change() else {
        panic!("proposal admission must durably queue the direct vote");
    };
    let DurableEffect::Sign(SignRequest::Vote(request)) = effect.as_ref() else {
        panic!("a unique valid proposal must produce a vote choice");
    };
    let body = request.body();
    assert_eq!(body.leader(), proposed.digest::<Sha256>());
    assert_eq!(body.positions(), &[Position::new(0)]);
    assert!(body.extensions()[0].is_empty());
}

#[test]
fn proposal_accepts_exact_tip_history_and_rejects_an_incorrect_commitment() {
    for valid_history in [true, false] {
        let profile = profile_for(Role::Validator(Participant::new(1)), 6, 2);
        let (mut machine, _) = start_profile(profile);
        let base = leader(&machine, 1);
        let history = if valid_history {
            base.history()
        } else {
            digest(b"incorrect tip history")
        };
        let proposal = LeaderBlock::new(
            base.round(),
            base.parent(),
            history,
            base.proposals().to_vec(),
            machine.profile().protocol().codec_config(),
        )
        .unwrap();
        let signer = machine.profile().protocol().leader(proposal.view());
        let verification = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposal.clone(),
                attestation(signer.get()),
            )),
        );
        let admitted = complete_with_step(&mut machine, &verification, true);
        let histories = admitted
            .activities()
            .iter()
            .filter_map(|activity| match activity {
                Activity::HistoryAccepted {
                    commitment, record, ..
                } => Some((*commitment, record.commitment::<Sha256>())),
                Activity::ProtocolAccepted { .. } => None,
                Activity::LeaderFinalized { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            histories,
            valid_history
                .then_some((history, history))
                .into_iter()
                .collect::<Vec<_>>()
        );
        let (effects, _) = drive_poll_and_persist(&mut machine, admitted);
        let voted = effects.iter().any(|effect| {
            matches!(
                durable_effect(effect),
                Some(DurableEffect::Sign(SignRequest::Vote(request)))
                    if request.body().leader() == proposal.digest::<Sha256>()
            )
        });

        assert_eq!(voted, valid_history);
    }
}

#[test]
fn proposal_accepts_exact_lower_parent_with_complete_gap() {
    let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
    let (mut machine, _) = start_profile(profile);

    let higher_leader = leader(&machine, 3);
    let higher_votes = (0..machine.profile().protocol().codec_config().view_quorum())
        .map(|signer| view_vote(&machine, &higher_leader, signer as u32))
        .collect::<Vec<_>>();
    let higher = lqc(&machine, higher_leader, &higher_votes);
    let verification = observe(&mut machine, Artifact::Lqc(higher));
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);
    assert!(matches!(machine.durable.proposal_anchor.as_deref(),
        Some(Artifact::Vqc(anchor)) if anchor.view() == View::new(3)));
    assert_eq!(machine.inspect().view(), View::new(4));

    let parent = view_one_vqc(&machine);
    let parent_id = parent.id::<Sha256>();
    let extraction =
        VqcExtraction::new::<Sha256, MinPk>(&parent, machine.profile().protocol().codec_config())
            .unwrap();
    let (tips, _) = extraction.into_parts();
    let history = TipRecord::new(parent.leader().history(), tips.blocks().to_vec())
        .unwrap()
        .commitment::<Sha256>();
    let base = leader(&machine, 4);
    let proposal = LeaderBlock::new(
        base.round(),
        parent_id,
        history,
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();

    let verification = observe(&mut machine, Artifact::Vqc(parent));
    let admitted = complete_with_step(&mut machine, &verification, true);
    drive_poll_and_persist(&mut machine, admitted);

    let signer = machine.profile().protocol().leader(proposal.view());
    let verification = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposal.clone(),
            attestation(signer.get()),
        )),
    );
    let admitted = complete_with_step(&mut machine, &verification, true);
    let (blocked, _) = drive_poll_and_persist(&mut machine, admitted);
    assert!(
        blocked
            .iter()
            .any(|effect| matches!(effect, Capability::Resolver(ResolverCapability::Resolve(job)) if job.view() == View::new(2)))
    );
    assert!(blocked.iter().all(|effect| {
        !matches!(
            durable_effect(effect),
            Some(DurableEffect::Sign(SignRequest::Vote(_)))
        )
    }));

    let mut effects = Vec::new();
    for view in [View::new(2), View::new(3)] {
        let nullification = symbolic_nullification(&machine, view, view.get());
        let verification = observe(&mut machine, Artifact::Nullification(nullification));
        let admitted = complete_with_step(&mut machine, &verification, true);
        effects.extend(drive_poll_and_persist(&mut machine, admitted).0);
    }

    assert!(effects.iter().any(|effect| {
        matches!(
            durable_effect(effect),
            Some(DurableEffect::Sign(SignRequest::Vote(request)))
                if request.body().leader() == proposal.digest::<Sha256>()
        )
    }));
}

#[test]
fn proposal_equivocation_suppresses_direct_vote() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 2, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let first = leader(&machine, 1);
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let observed = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(1))),
            Artifact::LeaderBlock(SignedLeaderBlock::new(second, attestation(1))),
        ]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("both equivocations must share one exact verification cohort");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            job.items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    // Staging now arrives from the scheduler, so settle before asserting no vote was queued.
    let verified = settle(&mut machine, verified);
    assert!(!verified.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn pending_proposal_equivocation_blocks_direct_vote() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 2, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));
    let first = leader(&machine, 1);
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"pending equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();

    let first_observed = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(first, attestation(1)),
        )]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(first_job))] =
        first_observed.capabilities()
    else {
        panic!("the first proposal must start verification");
    };
    let second_observed = machine
        .step(cohort::<Sha256, _>(vec![Artifact::LeaderBlock(
            SignedLeaderBlock::new(second, attestation(1)),
        )]))
        .unwrap();
    let second_job = second_observed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
            _ => None,
        });

    let first_verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            first_job.id(),
            first_job.generation(),
            vec![Verdict::new(first_job.items()[0].ticket(), true)],
        )))
        .unwrap();
    let first_verified = settle(&mut machine, first_verified);
    let second_job = second_job
        .or_else(|| {
            first_verified
                .capabilities()
                .iter()
                .find_map(|effect| match effect {
                    Capability::Verification(VerificationCapability::Verify(job)) => {
                        Some(job.clone())
                    }
                    _ => None,
                })
        })
        .expect("the equivocation must eventually start verification");
    assert!(!first_verified.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
        ))
    }));

    let second_verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            second_job.id(),
            second_job.generation(),
            vec![Verdict::new(second_job.items()[0].ticket(), true)],
        )))
        .unwrap();
    let second_verified = settle(&mut machine, second_verified);
    assert!(!second_verified.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn staggered_verified_proposal_equivocation_suppresses_direct_vote() {
    let mut machine = Machine::new(profile_for(Role::Validator(Participant::new(0)), 2, 2));
    let start = machine.step(Input::Start).unwrap();
    persist(&mut machine, &persist_job(&start));

    let parent_leader = leader(&machine, 1);
    let parent_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &parent_leader, 0)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 1)),
    ];
    let parent = vqc(&machine, parent_leader, &parent_messages);
    let first = proposal_request_with_parent(&machine, View::new(2), parent.clone())
        .block()
        .clone();
    let protocol = machine.profile().protocol();
    let mut proposals = first.proposals().to_vec();
    proposals[0] = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(protocol.genesis().tips()[0]),
        vec![digest(b"staggered verified equivocation")],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let second = LeaderBlock::new(
        first.round(),
        first.parent(),
        first.history(),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();

    let first = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(first, attestation(1))),
    );
    complete(&mut machine, &first, true);
    let second = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(second, attestation(1))),
    );
    complete(&mut machine, &second, true);

    let parent = observe(&mut machine, Artifact::Vqc(parent));
    let ready = complete_with_step(&mut machine, &parent, true);
    assert!(!ready.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if matches!(
            job.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(_)))
        ))
    }));
}

#[test]
fn vote_projection_uses_voted_prefix_and_extension() {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let protocol = machine.profile().protocol().clone();
    let genesis = protocol.genesis().tips()[0];
    let first = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(0),
        Height::new(1),
        genesis.digest(),
        digest(b"first"),
    )
    .unwrap();
    let first_valid = validate_block(&mut machine, first.clone(), 0);
    persist(&mut machine, &persist_job(&first_valid));

    let second = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(0),
        Height::new(2),
        first.block_ref::<Sha256>().digest(),
        digest(b"second"),
    )
    .unwrap();
    let second_valid = validate_block(&mut machine, second.clone(), 0);
    persist(&mut machine, &persist_job(&second_valid));

    let proposal = ChainProposal::new(
        ChainId::new(0),
        Anchor::Tip(genesis),
        vec![first.body_digest()],
        protocol.codec_config().pipeline_depth(),
    )
    .unwrap();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        vec![proposal],
        protocol.codec_config(),
    )
    .unwrap();
    let body = machine
        .chain
        .vote_body::<Sha256>(&machine.profile, &leader)
        .unwrap();
    assert_eq!(body.positions(), &[Position::new(1)]);
    assert_eq!(body.extensions()[0].payloads(), &[second.body_digest()]);
}

#[test]
fn timeout_atomically_authorizes_novote_and_nullify() {
    let (mut machine, started) =
        start_profile(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    assert!(
        elapsed
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_)))),
        "a normal view timer must not enter the recovery network path"
    );
    let elapsed = settle(&mut machine, elapsed);
    let queued = persist_job(&elapsed);
    assert!(matches!(
        queued.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::SignBatch(requests)
                if matches!(requests.as_ref(),
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]))
    ));

    // Signing carries no signature out, so the batch releases with the step that stages the
    // atomic choice.
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
        .unwrap();
    persist(&mut machine, &queued);
    let view = View::new(1);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::SignedBatch {
            id: batch.id(),
            generation: batch.generation(),
            artifacts: vec![
                Artifact::NoVote(no_vote(&machine, view, 0)),
                Artifact::Nullify(nullify(&machine, view, 0)),
            ],
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    // Staging records both artifacts atomically; only their broadcast waits for durability.
    assert_eq!(machine.snapshot().local_artifacts().len(), 2);
    assert!(completed.capabilities().iter().all(|effect| !matches!(
        durable_effect(effect),
        Some(DurableEffect::BroadcastBatch(_))
    )));
    let published = persist(&mut machine, &persist_job(&completed));
    assert_eq!(machine.snapshot().local_artifacts().len(), 2);
    assert!(published.capabilities().iter().any(|capability| matches!(
        capability,
        Capability::Durability(DurabilityCapability::Released(job))
            if matches!(job.request(), DurableEffect::BroadcastBatch(_))
    )));
}

#[test]
fn post_vote_nullification_counts_existential_non_support() {
    let (mut machine, _) = start_profile(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let proposed = leader(&machine, 1);
    let signer = machine.profile().protocol().leader(View::new(1));
    let proposal = Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(signer.get()),
    ));
    let verified = observe(&mut machine, proposal);
    let selected = complete_with_step(&mut machine, &verified, true);
    // The signing request releases with the step that stages the vote choice.
    let sign = sign_job(&selected);
    persist(&mut machine, &persist_job(&selected));
    let vote = view_vote(&machine, &proposed, 0);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::Vote(vote)),
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    persist(&mut machine, &persist_job(&completed));

    let evidence = (1..=3)
        .map(|signer| Artifact::NoVote(no_vote(&machine, View::new(1), signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(evidence)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("non-support evidence must be verified together");
    };
    let nullify = machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            job.items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let nullify = settle(&mut machine, nullify);
    assert!(matches!(
        persist_job(&nullify).events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Nullify { .. }))
    ));
}

#[test]
fn nullification_recovery_uses_the_canonical_subset_and_exits() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let view = View::new(1);
    let shares = [2, 0, 1]
        .into_iter()
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(shares)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("nullify shares must be verified");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        recovery
            .shares()
            .iter()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..3).map(Participant::new).collect::<Vec<_>>()
    );
    let certificate = symbolic_nullification(&machine, view, 0);
    let proof = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), certificate),
        ))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    Machine::restore(profile, machine.snapshot()).unwrap();
    // The recovered nullification is an independently verifiable aggregate with no local
    // signature pending behind it, so its broadcast releases with the forwarding staging
    // instead of waiting for that barrier's acknowledgement.
    assert!(
        release_after_enqueue(&retained)
            .iter()
            .any(|job| matches!(job.request(), DurableEffect::Broadcast(_))),
        "the forwarding staging must release the recovered certificate"
    );
    let published = persist(&mut machine, &persist_job(&retained));
    assert!(
        published
            .capabilities()
            .iter()
            .all(|effect| { !matches!(durable_effect(effect), Some(DurableEffect::Broadcast(_))) }),
        "persistence must not release the staged broadcast a second time"
    );
    let advance = persist_job(&published);
    assert!(matches!(
        advance.events()[0].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    persist(&mut machine, &advance);
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn vqc_aggregation_retains_exact_messages_and_exits_observer() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let proposed = leader(&machine, 1);
    let proposal_signer = LeaderSchedule::round_robin(6).leader(View::new(1));
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(proposal_signer.get()),
        )),
    );
    complete(&mut machine, &proposal, true);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let artifacts = messages
        .iter()
        .cloned()
        .map(|message| match message {
            ViewMessage::Vote(vote) => Artifact::Vote(vote),
            ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
        })
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("view messages must be verified");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let aggregate = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let messages = aggregate.messages().collect::<Vec<_>>();
    assert_eq!(
        messages
            .iter()
            .map(Attributable::signer)
            .collect::<Vec<_>>(),
        (0..5).map(Participant::new).collect::<Vec<_>>()
    );
    let certificate = vqc(&machine, proposed, &messages);
    let proof = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            certificate,
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    Machine::restore(profile, machine.snapshot()).unwrap();
    let published = persist(&mut machine, &persist_job(&retained));
    let advance = persist_job(&published);
    assert!(matches!(
        advance.events()[0].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    persist(&mut machine, &advance);
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn local_vqc_emits_quorum_then_grows_to_the_full_sticky_transcript() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let observed = machine
        .step(cohort::<Sha256, _>(
            messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("view messages must be verified together");
    };
    let verified = complete_with_step(&mut machine, verification, true);
    let first = verified
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the first quorum must aggregate promptly");
    let first_messages = first.messages().collect::<Vec<_>>();
    assert_eq!(first_messages.len(), 5);
    let mut barriers = verified;
    while let Some(job) = barriers
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        })
    {
        barriers = persist(&mut machine, &job);
    }

    let full_certificate = vqc(&machine, proposed.clone(), &messages);
    let mismatch = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            first.id(),
            first.generation(),
            full_certificate.clone(),
        ))))
        .unwrap();
    assert_eq!(mismatch.status(), &StepStatus::CompletionDeferred);
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    let first_certificate = vqc(&machine, proposed, &first_messages);
    let first_id = Artifact::Vqc(first_certificate.clone()).id::<Sha256>();
    let full_id = Artifact::Vqc(full_certificate.clone()).id::<Sha256>();
    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            first.id(),
            first.generation(),
            first_certificate,
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let (effects, _) = drive_poll_and_persist(&mut machine, completed);
    let improved = effects
        .iter()
        .find_map(|capability| match capability {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the materialized quorum must schedule its strict extension");
    assert_ne!(improved.id(), first.id());
    assert_eq!(improved.messages().count(), 6);

    let improved = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            improved.id(),
            improved.generation(),
            full_certificate,
        ))))
        .unwrap();
    let improved = settle(&mut machine, improved);
    drive_poll_and_persist(&mut machine, improved);
    assert!(machine.durable.local.contains_key(&full_id));
    assert_eq!(
        machine
            .durable
            .forwarded_vqcs
            .get(&View::new(1))
            .map(|artifact| artifact.id::<Sha256>()),
        Some(first_id),
        "an improved same-view V-QC is attached to a later proposal, not forwarded twice",
    );
}

#[test]
fn invalid_earlier_message_unblocks_sticky_vqc_choice() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let earlier_artifact = Artifact::NoVote(no_vote(&machine, View::new(1), 0));
    let earlier = observe(&mut machine, earlier_artifact);
    let later = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::Vote(view_vote(&machine, &proposed, 0)),
            Artifact::Vote(view_vote(&machine, &proposed, 1)),
            Artifact::Vote(view_vote(&machine, &proposed, 2)),
            Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
            Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
        ]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(later))] = later.capabilities()
    else {
        panic!("later messages must be verified together");
    };
    let completed_later = machine
        .step(Input::Verified(VerificationCompletion::new(
            later.id(),
            later.generation(),
            later
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let completed_later = settle(&mut machine, completed_later);
    assert!(
        !completed_later.capabilities().iter().any(|effect| matches!(
            effect,
            Capability::Leader(LeaderCapability::AggregateVqc(_))
        ))
    );

    let rejected_earlier = machine
        .step(Input::Verified(VerificationCompletion::new(
            earlier.id(),
            earlier.generation(),
            vec![Verdict::new(earlier.items()[0].ticket(), false)],
        )))
        .unwrap();
    let rejected_earlier = settle(&mut machine, rejected_earlier);
    assert!(
        rejected_earlier
            .capabilities()
            .iter()
            .any(|effect| matches!(
                effect,
                Capability::Leader(LeaderCapability::AggregateVqc(_))
            ))
    );
}

#[test]
fn current_view_certificate_preempts_da_recovery_when_one_slot_is_free() {
    let limits = resources_with_capacities(32, 1);
    let profile = Profile::with_limits(
        config_for(Epoch::new(7), 6, 2),
        Role::Validator(Participant::new(5)),
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: retention_for(limits, 6),
            ..Tuning::default()
        },
        limits,
    )
    .unwrap();
    let (mut machine, _) = start_profile(profile);
    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    machine
        .views
        .observe_sign_request(&SignRequest::NoVote { round })
        .unwrap();

    record_da_recovery_candidate(&mut machine, b"certificate priority");

    let proposed = leader(&machine, 1);
    let proposal = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(0),
    )));
    let view_profile = machine.profile.clone();
    machine
        .views
        .observe::<Sha256>(
            proposal.id::<Sha256>(),
            Observation::new(2, 0),
            &proposal,
            &view_profile,
        )
        .unwrap();
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, artifact) in messages.into_iter().enumerate() {
        let artifact = Arc::new(artifact);
        machine
            .views
            .observe::<Sha256>(
                artifact.id::<Sha256>(),
                Observation::new(3, index as u32),
                &artifact,
                &view_profile,
            )
            .unwrap();
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
    assert!(!driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Producer(ProducerCapability::RecoverDa(_))
    )));
}

#[test]
fn da_recovery_preempts_noncurrent_view_certificate() {
    let limits = resources_with_capacities(32, 1);
    let profile = profile_with_resources(Role::Validator(Participant::new(5)), 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    record_da_recovery_candidate(&mut machine, b"background recovery fairness");
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(2), signer));
        record_view_fact(&mut machine, Observation::new(2, signer), share);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Producer(ProducerCapability::RecoverDa(_))
    )));
    assert!(!driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::RecoverNullification(_))
    )));
}

#[test]
fn newer_da_certificate_recovery_reuses_superseded_slot() {
    let limits = resources_with_capacities(32, 1);
    let profile = profile_with_resources(Role::Validator(Participant::new(5)), 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    record_da_recovery_candidate(&mut machine, b"first background recovery");
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(2), signer));
        record_view_fact(&mut machine, Observation::new(2, signer), share);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    let first = driven
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("DA recovery must receive the first slot");
    let first_header = first.votes()[0].header().clone();
    let certificate = symbolic_da_certificate(first_header.clone(), 0);
    let completed = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            first.id(),
            first.generation(),
            certificate,
        )))
        .unwrap();
    // Stage the recovery barrier before the second candidate appears, as the old inline
    // completion did.
    let completed = settle(&mut machine, completed);

    // The certificate is an aggregate with no local signature pending behind it, so its
    // broadcast releases with the staging step and still occupies the durable slot.
    let broadcast = completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Broadcast(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the first DA certificate must occupy the durable slot");
    let published = persist(&mut machine, &persist_job(&completed));
    assert!(
        !published
            .capabilities()
            .iter()
            .any(|effect| matches!(durable_effect(effect), Some(DurableEffect::Broadcast(_)))),
        "persistence must not release the staged broadcast a second time"
    );
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    let chain = match machine.profile().role() {
        Role::Validator(participant) => participant,
        Role::Observer => unreachable!("the test profile is a validator"),
    };
    let second_header = TransactionBlockHeader::new(
        machine.profile().protocol().epoch(),
        ChainId::new(chain.get()),
        Height::new(2),
        first_header.block_ref::<Sha256>().digest(),
        digest(b"second background recovery"),
    )
    .unwrap();
    machine
        .chain
        .observe_producer_choice::<Sha256>(&second_header)
        .unwrap();
    for signer in 0..4 {
        let artifact =
            Artifact::DaVote(DaVote::new(second_header.clone(), threshold_share(signer)));
        machine
            .chain
            .observe::<Sha256>(
                artifact.id::<Sha256>(),
                Observation::new(3, signer),
                &artifact,
                machine.durable.generation,
            )
            .unwrap();
    }

    let released = machine.step(Input::ProducerWake).unwrap();
    let released = settle(&mut machine, released);
    assert!(!released.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::RecoverNullification(_))
    )));
    let second = released
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job))
                if job.votes()[0].header() == &second_header =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the newer DA certificate reuses the superseded publication slot");
    let certificate = symbolic_da_certificate(second_header.clone(), 0);
    let completed = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            second.id(),
            second.generation(),
            certificate,
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    persist(&mut machine, &persist_job(&completed));

    assert_eq!(machine.durable.outbox.len(), 1);
    assert_eq!(
        machine.durable.certified_tips[chain.get() as usize],
        second_header.block_ref::<Sha256>()
    );
    assert!(machine.durable.outbox.values().any(|effect| {
        effect.artifacts().iter().any(|artifact| {
            matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                if certificate.header() == &second_header)
        })
    }));
}

#[test]
fn proposal_anchor_does_not_retire_the_certificate_broadcast() {
    // A leader block anchoring a chain's newest DA certificate is not a substitute for the
    // certificate broadcast: peers never admit proposal anchors into their DA state, so
    // retiring the broadcast strands every peer that missed it. Their certified tips freeze,
    // the DA-vote window (height - certified <= pipeline depth) goes permanently false, and
    // the chain halts at exactly the pipeline limit.
    let limits = resources_with_capacities(32, 4);
    let profile = profile_with_resources(Role::Validator(Participant::new(5)), 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    record_da_recovery_candidate(&mut machine, b"anchored certificate");

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    let recovery = driven
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Producer(ProducerCapability::RecoverDa(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the producer tip must schedule a DA recovery");
    let header = recovery.votes()[0].header().clone();
    let certificate = symbolic_da_certificate(header.clone(), 0);
    let completed = machine
        .step(Input::DaRecovered(DaRecoveryCompletion::new(
            recovery.id(),
            recovery.generation(),
            certificate.clone(),
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let broadcast = completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Broadcast(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the recovered certificate must broadcast");
    persist(&mut machine, &persist_job(&completed));

    // Observe the scheduled view-1 leader's block whose chain proposal anchors the
    // certificate exactly.
    let protocol = machine.profile().protocol().clone();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            let anchor = if tip.chain() == header.chain() {
                Anchor::Certificate(certificate.clone())
            } else {
                Anchor::Tip(*tip)
            };
            ChainProposal::new(
                tip.chain(),
                anchor,
                Vec::new(),
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let block = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let scheduled = protocol.leader(View::new(1));
    let artifact =
        Artifact::LeaderBlock(SignedLeaderBlock::new(block, attestation(scheduled.get())));
    let job = observe(&mut machine, artifact);
    complete(&mut machine, &job, true);

    // Fold the publication supersession sweep to a fixed point.
    for _ in 0..8 {
        let result = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = result.work_remaining();
        let (effects, _) = result.into_parts();
        if effects.is_empty() && !work_remaining {
            break;
        }
    }

    assert!(
        machine.durable.outbox.contains_key(&broadcast.id()),
        "a chain's newest certificate broadcast must outlive proposals anchoring it"
    );
}

#[test]
fn vote_quorum_assembles_a_vqc_despite_a_matching_proposal_parent() {
    // A V-QC retained only as a proposal parent cannot be forwarded, and view exit requires a
    // durably forwarded exit certificate. Holding a matching parent must therefore never
    // suppress local assembly: without it the node has no exit certificate to forward and the
    // view freezes while the process stays responsive.
    let profile = profile_for(Role::Validator(Participant::new(5)), 6, 2);
    let (mut machine, _) = start_profile(profile);
    let round = Round::new(machine.profile().protocol().epoch(), View::new(1));
    machine
        .views
        .observe_sign_request(&SignRequest::NoVote { round })
        .unwrap();

    let proposed = leader(&machine, 1);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = Arc::new(Artifact::Vqc(vqc(&machine, proposed.clone(), &messages)));
    let view_profile = machine.profile.clone();
    machine
        .views
        .retain_vqc_parent::<Sha256>(&parent, &view_profile)
        .unwrap();

    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    let facts = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, artifact) in facts.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), artifact);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(
        driven.capabilities().iter().any(|effect| matches!(
            effect,
            Capability::Leader(LeaderCapability::AggregateVqc(_))
        )),
        "a vote quorum must assemble a forwardable V-QC even when a matching parent is retained"
    );
}

#[test]
fn late_past_nullification_is_recovered_and_forwarded() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 1);
    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let forwarding = complete_with_step(&mut machine, &verification, true);
    let forwarded = persist(&mut machine, &persist_job(&forwarding));
    persist(&mut machine, &persist_job(&forwarded));
    assert_eq!(machine.inspect().view(), View::new(2));

    let shares = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(shares))] = shares.capabilities()
    else {
        panic!("past-view nullify shares must be verified together");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            shares.id(),
            shares.generation(),
            shares
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a late past-view quorum must still be recovered");
    let certificate = symbolic_nullification(&machine, View::new(1), 0);
    let completed = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), certificate),
        ))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    assert!(matches!(
        persist_job(&retained).events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                if certificate.round().view() == View::new(1))
    ));
}

#[test]
fn late_leader_cannot_preempt_an_earlier_nullification() {
    for leader_first in [false, true] {
        let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
        let proposed = leader(&machine, 1);
        let messages = machine
            .step(cohort::<Sha256, _>(vec![
                Artifact::Vote(view_vote(&machine, &proposed, 0)),
                Artifact::Vote(view_vote(&machine, &proposed, 1)),
                Artifact::Vote(view_vote(&machine, &proposed, 2)),
                Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
                Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
            ]))
            .unwrap();
        let [Capability::Verification(VerificationCapability::Verify(messages))] =
            messages.capabilities()
        else {
            panic!("view messages must be verified together");
        };
        let messages = messages.clone();
        complete(&mut machine, &messages, true);

        let nullifies = machine
            .step(cohort::<Sha256, _>(
                (0..3)
                    .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                    .collect(),
            ))
            .unwrap();
        let [Capability::Verification(VerificationCapability::Verify(nullifies))] =
            nullifies.capabilities()
        else {
            panic!("nullify shares must be verified together");
        };
        let nullifies = nullifies.clone();

        let proposal = observe(
            &mut machine,
            Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
            )),
        );

        let complete = |job: &VerifyJob<MinPk, Digest>| {
            Input::Verified(VerificationCompletion::new(
                job.id(),
                job.generation(),
                job.items()
                    .iter()
                    .map(|item| Verdict::new(item.ticket(), true))
                    .collect(),
            ))
        };
        let (first, second) = if leader_first {
            (&proposal, &nullifies)
        } else {
            (&nullifies, &proposal)
        };
        let first_complete = machine.step(complete(first)).unwrap();
        let first_complete = settle(&mut machine, first_complete);
        let second_complete = machine.step(complete(second)).unwrap();
        let second_complete = settle(&mut machine, second_complete);
        let constructions = first_complete
            .capabilities()
            .iter()
            .chain(second_complete.capabilities())
            .filter_map(|effect| match effect {
                Capability::Leader(LeaderCapability::RecoverNullification(_)) => {
                    Some("nullification")
                }
                Capability::Leader(LeaderCapability::AggregateVqc(_)) => Some("V-QC"),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(constructions, ["nullification"]);
    }
}

#[test]
fn invalid_target_vote_does_not_poison_vqc_aggregation() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    record_view_fact(
        &mut machine,
        Observation::new(1, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );

    let protocol = machine.profile().protocol();
    let chains = protocol.codec_config().chains();
    let invalid = VoteBody::new(
        proposed.round(),
        proposed.digest::<Sha256>(),
        vec![Position::new(1); chains],
        (0..chains)
            .map(|_| Extension::new(Vec::new(), 1).unwrap())
            .collect(),
        protocol.codec_config(),
    )
    .unwrap();
    assert!(!invalid.valid_for::<Sha256, MinPk>(&proposed));
    let messages = [
        Artifact::Vote(Vote::new(invalid, attestation(0))),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(2, index as u32), message);
    }

    let incomplete = machine.step(Input::ProducerWake).unwrap();
    let incomplete = settle(&mut machine, incomplete);
    assert!(incomplete.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));

    let later = Artifact::Vote(view_vote(&machine, &proposed, 3));
    record_view_fact(&mut machine, Observation::new(3, 0), later);
    let completed = machine.step(Input::ProducerWake).unwrap();
    let completed = settle(&mut machine, completed);
    let aggregate = completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job),
            _ => None,
        })
        .expect("later valid support must complete the V-QC");
    assert!(aggregate.messages().all(|message| {
        !matches!(message, ViewMessage::Vote(vote) if vote.signer() == Participant::new(0))
    }));
}

#[test]
fn current_vqc_preempts_noncurrent_nullification_recovery() {
    let limits = resources_with_capacities(32, 1);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(2), signer));
        record_view_fact(&mut machine, Observation::new(1, signer), share);
    }
    let proposed = leader(&machine, 1);
    record_view_fact(
        &mut machine,
        Observation::new(2, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(3, index as u32), message);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
    assert!(!driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::RecoverNullification(_))
    )));
}

#[test]
fn current_nullification_preempts_noncurrent_vqc_aggregation() {
    let limits = resources_with_capacities(32, 1);
    let profile = profile_with_resources(Role::Observer, 6, 2, limits);
    let (mut machine, _) = start_profile(profile);
    let proposed = leader(&machine, 2);
    record_view_fact(
        &mut machine,
        Observation::new(1, 0),
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    let messages = [
        Artifact::Vote(view_vote(&machine, &proposed, 0)),
        Artifact::Vote(view_vote(&machine, &proposed, 1)),
        Artifact::Vote(view_vote(&machine, &proposed, 2)),
        Artifact::NoVote(no_vote(&machine, View::new(2), 3)),
        Artifact::NoVote(no_vote(&machine, View::new(2), 4)),
    ];
    for (index, message) in messages.into_iter().enumerate() {
        record_view_fact(&mut machine, Observation::new(2, index as u32), message);
    }
    for signer in 0..3 {
        let share = Artifact::Nullify(nullify(&machine, View::new(1), signer));
        record_view_fact(&mut machine, Observation::new(3, signer), share);
    }

    let driven = machine.step(Input::ProducerWake).unwrap();
    let driven = settle(&mut machine, driven);
    assert!(driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::RecoverNullification(_))
    )));
    assert!(!driven.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
}

#[test]
fn inbound_vqc_requires_rescue_vote_before_view_advance() {
    let (mut machine, _) = start_profile(profile_for(Role::Validator(Participant::new(0)), 6, 2));
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let certificate = vqc(&machine, proposed.clone(), &messages);
    let proof = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let forwarding = complete_with_step(&mut machine, &verification, true);
    let forwarded = persist(&mut machine, &persist_job(&forwarding));
    let rescue = persist_job(&forwarded);
    assert!(matches!(
        rescue.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(request))
                if request.body().leader() == proposed.digest::<Sha256>())
    ));
    // The exit is staged only behind the rescue vote, so the view is still 1 while the rescue
    // barrier is the only staged work.
    assert_eq!(machine.inspect().view(), View::new(1));
    let released = persist(&mut machine, &rescue);
    // The signing request released with the step that staged the rescue choice.
    let sign = sign_job(&forwarded);
    let advance = persist_job(&released);
    assert!(matches!(
        advance.events()[0].change(),
        Change::ViewAdvanced { proof: actual, .. } if *actual == proof
    ));
    persist(&mut machine, &advance);
    assert_eq!(machine.inspect().view(), View::new(2));
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::Vote(view_vote(&machine, &proposed, 0))),
        }))
        .unwrap();
    let completed = settle(&mut machine, completed);
    persist(&mut machine, &persist_job(&completed));
    assert_eq!(machine.inspect().view(), View::new(2));
}

#[test]
fn timeout_signing_batch_survives_recovery_intact() {
    let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
    let expected_delay = profile.timers().view_timeout();
    let (mut machine, started) = start_profile(profile.clone());
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    persist(&mut machine, &persist_job(&elapsed));

    let snapshot = machine.snapshot();
    let mut restored = Machine::restore(profile, snapshot).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    assert!(recovery.capabilities().iter().any(
        |effect| matches!(effect, Capability::Leader(LeaderCapability::ArmTimer(timer)) if timer.delay() == expected_delay)
    ));
    let recovered = persist(&mut restored, &persist_job(&recovery));
    assert!(recovered.capabilities().iter().any(|effect| {
        matches!(
            durable_effect(effect),
            Some(DurableEffect::SignBatch(requests))
                if matches!(requests.as_ref(),
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));
}

#[test]
fn view_snapshot_codec_rejects_noncanonical_and_unbounded_payloads() {
    let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
    let (mut machine, started) = start_profile(profile.clone());
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    persist(&mut machine, &persist_job(&elapsed));

    let snapshot = machine.snapshot();
    let config = SnapshotCodecConfig::from_profile(&profile);
    let encoded = snapshot.encode();
    let decoded = Snapshot::<MinPk, Digest>::decode_cfg(encoded, &config).unwrap();
    Machine::restore(profile.clone(), decoded).unwrap();

    let mut missing = snapshot.clone();
    missing.clear_view_snapshot();
    assert!(matches!(
        Machine::restore(profile.clone(), missing),
        Err(ReplayError::Transition)
    ));

    let mut trailing = snapshot.clone();
    let mut payload = trailing.envelope().view().bytes().to_vec();
    payload.push(0);
    trailing.replace_view_payload(payload);
    assert!(Snapshot::<MinPk, Digest>::decode_cfg(trailing.encode(), &config).is_err());

    let mut empty = snapshot.clone();
    empty.replace_view_payload(Vec::new());
    assert!(Snapshot::<MinPk, Digest>::decode_cfg(empty.encode(), &config).is_err());

    let mut oversized = snapshot.clone();
    let oversized_slots = usize::try_from(profile.view_retention().get() + 2).unwrap();
    assert!(oversized_slots < profile.resources().max_cached_artifacts());
    oversized.replace_view_payload(oversized_slots.encode().to_vec());
    assert!(Snapshot::<MinPk, Digest>::decode_cfg(oversized.encode(), &config).is_err());

    let mut unknown_transition = snapshot.clone();
    let mut payload = 1usize.encode().to_vec();
    payload.extend_from_slice(&View::new(1).encode());
    payload.extend_from_slice(&9u8.encode());
    unknown_transition.replace_view_payload(payload);
    assert!(Snapshot::<MinPk, Digest>::decode_cfg(unknown_transition.encode(), &config).is_err());

    let mut contradictory = snapshot;
    let mut payload = 1usize.encode().to_vec();
    payload.extend_from_slice(&View::new(1).encode());
    payload.extend_from_slice(&0u8.encode());
    payload.extend_from_slice(&0u8.encode());
    payload.extend_from_slice(&1u8.encode());
    payload.extend_from_slice(&false.encode());
    contradictory.replace_view_payload(payload);
    assert!(Snapshot::<MinPk, Digest>::decode_cfg(contradictory.encode(), &config).is_err());
}

#[test]
fn timeout_choice_recovers_at_each_durable_crash_prefix() {
    let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
    let (mut machine, started) = start_profile(profile.clone());
    let before = machine.snapshot();
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    let elapsed = settle(&mut machine, elapsed);
    let timeout = persist_job(&elapsed);

    let mut without_timeout = Machine::restore(profile.clone(), before.clone()).unwrap();
    let recovery = without_timeout.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut without_timeout, &persist_job(&recovery));
    assert!(recovered.capabilities().iter().all(|effect| {
        !matches!(
            durable_effect(effect),
            Some(DurableEffect::SignBatch(requests))
                if matches!(requests.as_ref(),
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));

    let mut with_timeout = Machine::restore(profile, before).unwrap();
    for event in timeout.events() {
        with_timeout.replay(event.clone()).unwrap();
    }
    let recovery = with_timeout.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut with_timeout, &persist_job(&recovery));
    assert!(recovered.capabilities().iter().any(|effect| {
        matches!(
            durable_effect(effect),
            Some(DurableEffect::SignBatch(requests))
                if matches!(requests.as_ref(),
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }])
        )
    }));
}

#[test]
fn pending_proposal_parent_survives_recovery() {
    let role = Role::Validator(LeaderSchedule::round_robin(6).leader(View::new(2)));
    let profile = profile_for(role, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());

    let nullification = symbolic_nullification(&machine, View::new(1), 0);
    let nullification = observe(&mut machine, Artifact::Nullification(nullification));
    let forwarding = machine
        .step(Input::Verified(VerificationCompletion::new(
            nullification.id(),
            nullification.generation(),
            vec![Verdict::new(nullification.items()[0].ticket(), true)],
        )))
        .unwrap();
    // Stage the forwarding barrier before the parent certificate completes, as the old inline
    // drive did.
    let forwarding = settle(&mut machine, forwarding);

    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let parent = vqc(&machine, proposed, &messages);
    let parent_id = Artifact::Vqc(parent.clone()).id::<Sha256>();
    let parent_verification = observe(&mut machine, Artifact::Vqc(parent.clone()));
    complete(&mut machine, &parent_verification, true);

    let forwarded = persist(&mut machine, &persist_job(&forwarding));
    let entered = persist(&mut machine, &persist_job(&forwarded));
    assert_eq!(machine.inspect().view(), View::new(2));
    // Acknowledge the proposal barrier without letting the scheduler stage anything on top of
    // it, so the crash snapshot holds the reserved proposal and nothing later.
    persist_raw(&mut machine, &persist_job(&entered));
    let crashed = machine.snapshot();
    // The signing request released with the step that staged the proposal choice.
    let sign = sign_job(&entered);
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the view-two leader must reserve a proposal");
    };
    assert_eq!(request.parent().exact().map(Arc::as_ref), Some(&parent));
    assert!(request.attach_parent());
    assert!(!machine.durable.vqc_forwarded(View::new(1)));

    let mut restored = Machine::restore(profile, crashed).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let mut recovered = persist(&mut restored, &persist_job(&recovery));
    let recovered_sign = sign_job(&recovered);
    assert_eq!(recovered_sign.id(), sign.id());
    assert!(restored.inspect().ready_artifacts().contains(&parent_id));

    while let Some(job) = recovered
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        })
    {
        recovered = persist(&mut restored, &job);
    }
    let SignRequest::LeaderBlock(request) = sign_request(&recovered_sign) else {
        unreachable!("the recovered request was checked above");
    };
    assert!(request.attach_parent());
    restored
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: recovered_sign.id(),
            generation: recovered_sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                request.block().clone(),
                attestation(LeaderSchedule::round_robin(6).leader(View::new(2)).get()),
            ))),
        }))
        .unwrap();
    assert_eq!(restored.inspect().waiting_artifacts(), 0);
}

#[test]
fn outstanding_proposal_parent_survives_recovery() {
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let role = Role::Validator(signer);
    let profile = profile_for(role, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let request = proposal_request_with_parent(&machine, View::new(2), view_one_vqc(&machine));
    let parent_id = Artifact::Vqc(
        request
            .parent()
            .exact()
            .expect("the view-two proposal must carry its exact V-QC")
            .as_ref()
            .clone(),
    )
    .id::<Sha256>();

    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(
            request.clone(),
        )))
        .unwrap();
    // The signing request releases with the step that stages the choice.
    let sign = sign_job(&reserved);
    persist(&mut machine, &persist_job(&reserved));
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                request.block().clone(),
                attestation(signer.get()),
            ))),
        }))
        .unwrap();
    let signed = settle(&mut machine, signed);
    let published = persist(&mut machine, &persist_job(&signed));
    let publication = published
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Released(job))
                if matches!(job.request(), DurableEffect::Propose(_)) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the signed leader block must be published");
    let DurableEffect::Propose(proposal) = publication.request() else {
        unreachable!("the publication was selected as a proposal");
    };
    assert!(proposal.attach_parent());
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: publication.id(),
            generation: publication.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());
    assert!(machine.durable.vqc_forwarded(View::new(1)));

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    assert!(restored.inspect().ready_artifacts().contains(&parent_id));
}

#[test]
fn pending_proposal_parent_counts_against_recovery_capacity() {
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let role = Role::Validator(signer);
    let profile = profile_with_resources(role, 6, 2, resources_with_capacities(10, 16));
    let (mut machine, _) = start_profile(profile);
    let request = proposal_request_with_parent(&machine, View::new(2), view_one_vqc(&machine));
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignRequest::LeaderBlock(request)))
        .unwrap();
    persist(&mut machine, &persist_job(&reserved));

    for view in 3..=10 {
        let artifact = Arc::new(leader_artifact(&machine, view));
        let reserved = machine
            .reserve_test_effect(DurableEffect::Broadcast(artifact))
            .unwrap();
        persist(&mut machine, &persist_job(&reserved));
    }

    let constrained = profile_with_resources(role, 6, 2, resources_with_capacities(9, 16));
    assert!(matches!(
        Machine::restore(constrained, machine.snapshot()),
        Err(ReplayError::Transition)
    ));
}

#[test]
fn timeout_cutoff_rejects_a_proposal_verified_behind_an_unrelated_barrier() {
    let profile = profile_for(Role::Validator(Participant::new(5)), 6, 2);
    let (mut machine, started) = start_profile(profile);
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let filler = Arc::new(leader_artifact(&machine, 2));
    let pending = machine
        .reserve_test_effect(DurableEffect::Broadcast(filler))
        .unwrap();

    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    assert!(elapsed.capabilities().iter().all(|effect| !matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));

    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed, attestation(0))),
    );
    complete(&mut machine, &proposal, true);

    let released = persist(&mut machine, &persist_job(&pending));
    let timeout = persist_job(&released);
    assert!(timeout.events().iter().all(|event| {
        !matches!(event.change(), Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(),
                DurableEffect::Sign(SignRequest::Vote(_) | SignRequest::LeaderBlock(_))))
    }));
    assert!(matches!(
        timeout.events()[0].change(),
        Change::OutboxQueued { effect, .. }
            if matches!(effect.as_ref(), DurableEffect::SignBatch(requests)
                if matches!(requests.as_ref(),
                    [SignRequest::NoVote { .. }, SignRequest::Nullify { .. }]))
    ));
}

#[test]
fn observer_timeout_with_a_valid_proposal_never_requests_a_signature() {
    let (mut machine, started) = start_profile(profile_for(Role::Observer, 6, 2));
    let timer = started
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::ArmTimer(timer)) => Some(*timer),
            _ => None,
        })
        .unwrap();
    let proposal = leader_artifact(&machine, 1);
    let proposal = observe(&mut machine, proposal);
    complete(&mut machine, &proposal, true);

    let elapsed = machine.step(Input::TimerFired(timer)).unwrap();
    assert_eq!(elapsed.status(), &StepStatus::TimerFired);
    assert!(elapsed.capabilities().iter().all(|effect| {
        !matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        ) && !matches!(
            durable_effect(effect),
            Some(DurableEffect::Sign(_) | DurableEffect::SignBatch(_))
        )
    }));
}

#[test]
fn outstanding_future_exit_certificate_survives_recovery() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let future = Artifact::Nullification(symbolic_nullification(&machine, View::new(2), 0));
    let verification = observe(&mut machine, future);
    let forwarding = complete_with_step(&mut machine, &verification, true);
    // The independently verifiable certificate releases with the forwarding staging; only a
    // locally signed subject would wait for the barrier acknowledgement.
    let broadcast = release_after_enqueue(&forwarding)
        .into_iter()
        .find(|job| matches!(job.request(), DurableEffect::Broadcast(_)))
        .unwrap();
    persist(&mut machine, &persist_job(&forwarding));
    let delivered = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id: broadcast.id(),
            generation: broadcast.generation(),
        }))
        .unwrap();
    assert!(delivered.capabilities().is_empty());

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));

    let current = Artifact::Nullification(symbolic_nullification(&restored, View::new(1), 0));
    let verification = observe(&mut restored, current);
    let mut step = complete_with_step(&mut restored, &verification, true);
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        step = persist(&mut restored, &job);
    }
    assert_eq!(restored.inspect().view(), View::new(3));
}

#[test]
fn consecutive_exit_certificates_advance_exactly_one_view_at_a_time() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let artifacts = vec![
        Artifact::Nullification(symbolic_nullification(&machine, View::new(2), 0)),
        Artifact::Nullification(symbolic_nullification(&machine, View::new(1), 0)),
    ];
    let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("exit certificates must be verified together");
    };
    let step = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let mut step = settle(&mut machine, step);
    let mut advanced = Vec::new();
    while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
        Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
        _ => None,
    }) {
        // Staging applies the transition, so the staged view is already the new one: two
        // separate barriers stepping to view 2 then view 3 is exactly one exit per proof.
        if matches!(job.events()[0].change(), Change::ViewAdvanced { .. }) {
            advanced.push(machine.inspect().view());
        }
        step = persist(&mut machine, &job);
    }
    assert_eq!(advanced, [View::new(2), View::new(3)]);
    assert_eq!(machine.inspect().view(), View::new(3));
}

#[test]
fn retained_view_history_keeps_one_typed_exit_obligation() {
    let role = Role::Observer;
    let resources = resources_with_capacities(64, 8)
        .with_max_forwarded_certificates(NonZeroUsize::new(64).unwrap());
    let profile = profile_with_resources(role, 6, 2, resources);
    let (mut machine, _) = start_profile(profile.clone());

    for view in 1..=16 {
        let artifact =
            Artifact::Nullification(symbolic_nullification(&machine, View::new(view), view));
        let verification = observe(&mut machine, artifact);
        let mut step = complete_with_step(&mut machine, &verification, true);

        for _ in 0..8 {
            if let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
                _ => None,
            }) {
                step = persist(&mut machine, &job);
                continue;
            }
            break;
        }

        assert_eq!(machine.inspect().view(), View::new(view + 1));
        assert!(machine.inspect().cached_artifacts() < 64);
        assert!(!machine.durable.vqc_forwarded(View::new(view)));
        assert!(machine.durable.nullification_forwarded(View::new(view)));

        if view % 4 == 0 {
            let mut restored = Machine::restore(profile.clone(), machine.snapshot()).unwrap();
            let recovery = restored.step(Input::RecoveryComplete).unwrap();
            persist(&mut restored, &persist_job(&recovery));
            machine = restored;
        }
    }

    let exits = machine
        .durable
        .outbox
        .iter()
        .filter_map(|(id, effect)| match effect {
            DurableEffect::Broadcast(artifact)
                if matches!(
                    machine
                        .durable
                        .obligations
                        .get(id)
                        .map(PublicationObligation::discharges),
                    Some([PublicationDischarge::ExitReplacedAfter { .. }])
                ) =>
            {
                Some(artifact)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].view(), Some(View::new(16)));
}

#[test]
fn forwarding_history_remains_certificate_class_specific() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let old = symbolic_nullification(&machine, View::new(1), 1);

    for view in 1..=2 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = complete_with_step(&mut machine, &verification, true);

        loop {
            if let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
                _ => None,
            }) {
                step = persist(&mut machine, &job);
                continue;
            }
            break;
        }
    }

    assert_eq!(machine.inspect().view(), View::new(3));
    assert!(machine.durable.nullification_forwarded(View::new(1)));

    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    persist(&mut restored, &persist_job(&recovery));
    let duplicate = restored
        .step(cohort::<Sha256, _>(vec![Artifact::Nullification(old)]))
        .unwrap();
    assert!(matches!(
        duplicate.status(),
        StepStatus::Observed(results)
            if results[0].status() == ObservationStatus::Duplicate
    ));
    assert!(duplicate.capabilities().is_empty());

    let late_vqc = Artifact::Vqc(view_one_vqc(&restored));
    let verification = observe(&mut restored, late_vqc);
    let completed = complete_with_step(&mut restored, &verification, true);
    assert!(
        completed.capabilities().iter().any(|effect| {
            matches!(effect, Capability::Durability(DurabilityCapability::Persist(job))
                if matches!(job.events()[0].change(), Change::ArtifactForwarded {
                    artifact,
                    ..
                } if matches!(artifact.as_ref(), Artifact::Vqc(_))))
        }),
        "late V-QC status/effects: {:?} {:?}",
        completed.status(),
        completed.capabilities(),
    );
}

#[test]
fn memory_plateaus_while_finality_stalls() {
    // Perpetual operation. A node whose finality never advances still has to bound its memory, so
    // drive far more views than the retention window and require the tracked state to stop
    // growing rather than to grow slowly.
    let retention = ViewDelta::new(4);
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), retention);
    let (mut machine, _) = start_profile(profile);

    let mut samples = Vec::new();
    for view in 1..=200u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = complete_with_step(&mut machine, &verification, true);
        while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) {
            step = persist(&mut machine, &job);
        }
        if view % 20 == 0 {
            samples.push(machine.inspect().cached_artifacts());
        }
    }

    let settled = samples[1];
    assert!(
        samples[1..].iter().all(|cached| *cached == settled),
        "tracked artifacts did not plateau across 200 views: {samples:?}"
    );
}

#[test]
fn authenticated_finality_is_bounded_by_the_retained_view_window() {
    let retention = ViewDelta::new(2);
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), retention);
    let (mut machine, _) = start_profile(profile);

    // Advance beyond the retained diagnostic window without producing finality.
    for view in 1..=8u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = complete_with_step(&mut machine, &verification, true);
        while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) {
            step = persist(&mut machine, &job);
        }
        assert_eq!(machine.inspect().view(), View::new(view + 1));
    }

    assert_eq!(machine.inspect().view(), View::new(9));
    assert_eq!(machine.inspect().finality_floor(), View::zero());

    // Old L-QCs remain valid certificates, but diagnostics retain only the configured view window.
    let certificates = (1..=8u64)
        .map(|view| {
            let proposed = leader(&machine, view);
            let votes = (0..5)
                .map(|signer| view_vote(&machine, &proposed, signer))
                .collect::<Vec<_>>();
            Artifact::Lqc(lqc(&machine, proposed, &votes))
        })
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(certificates)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("the certificate cohort must emit one verification job");
    };
    let verdicts = job
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), true))
        .collect();
    machine
        .step(Input::Verified(VerificationCompletion::new(
            job.id(),
            job.generation(),
            verdicts,
        )))
        .unwrap();

    assert_eq!(machine.inspect().pools().len(), 2);
    assert_eq!(
        machine
            .inspect()
            .finality()
            .iter()
            .filter(|fact| matches!(fact.id(), FinalityId::Lqc(_)))
            .count(),
        2
    );
}

#[test]
fn omitted_parent_proposal_does_not_block_view_advance_and_retires() {
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), ViewDelta::new(1));
    let (mut machine, _) = start_profile(profile);
    let base = leader(&machine, 1);
    let orphan = LeaderBlock::new(
        base.round(),
        CertificateId::new(digest(b"omitted proposal parent")),
        base.history(),
        base.proposals().to_vec(),
        machine.profile().protocol().codec_config(),
    )
    .unwrap();
    let orphan = Artifact::LeaderBlock(SignedLeaderBlock::new(orphan, attestation(0)));
    let orphan_id = orphan.id::<Sha256>();
    let verification = observe(&mut machine, orphan);
    let waiting = complete_with_step(&mut machine, &verification, true);
    assert!(
        waiting
            .capabilities()
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_))))
    );
    assert_eq!(machine.inspect().waiting_artifacts(), 1);
    assert_eq!(machine.dependency_slots, 1);
    assert!(machine.artifacts.contains_key(&orphan_id));

    for view in 1..=2 {
        let exit = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(exit));
        let mut step = complete_with_step(&mut machine, &verification, true);
        while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) {
            step = persist(&mut machine, &job);
        }
        assert_eq!(
            machine.inspect().view(),
            View::new(view + 1),
            "the nullification for view {view} was not applied"
        );
    }

    assert_eq!(machine.inspect().view(), View::new(3));
    assert_eq!(machine.durable.retired_view, View::new(1));
    assert_eq!(machine.inspect().waiting_artifacts(), 0);
    assert_eq!(machine.dependency_slots, 0);
    assert!(!machine.artifacts.contains_key(&orphan_id));
}

#[test]
fn view_retention_retires_history_while_finality_stalls() {
    // Nullified views never advance the finality floor. Retirement is keyed off the current view
    // instead, which is what keeps a node that cannot finalize bounded.
    let retention = ViewDelta::new(2);
    let profile = profile_with_retention(Role::Observer, 6, 2, resources(), retention);
    let (mut machine, _) = start_profile(profile.clone());
    let mut resolver_prunes = Vec::new();

    for view in 1..=5u64 {
        let certificate = symbolic_nullification(&machine, View::new(view), view);
        let verification = observe(&mut machine, Artifact::Nullification(certificate));
        let mut step = complete_with_step(&mut machine, &verification, true);
        loop {
            resolver_prunes.extend(
                step.capabilities()
                    .iter()
                    .filter_map(|effect| match effect {
                        Capability::Resolver(ResolverCapability::Prune(through)) => Some(*through),
                        _ => None,
                    }),
            );
            let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
                _ => None,
            }) else {
                break;
            };
            step = persist(&mut machine, &job);
        }
    }

    assert_eq!(machine.inspect().view(), View::new(6));
    assert_eq!(machine.durable.retired_view, View::new(3));
    assert_eq!(
        resolver_prunes,
        vec![View::new(1), View::new(2), View::new(3)]
    );
    assert_eq!(
        machine
            .durable
            .forwarded_nullifications
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![View::new(4), View::new(5)]
    );
    assert_eq!(
        machine.durable.exits.keys().copied().collect::<Vec<_>>(),
        vec![View::new(4), View::new(5)]
    );
    assert!(
        machine
            .durable
            .local
            .values()
            .all(|artifact| artifact.view().is_none_or(|view| view > View::new(3)))
    );

    let expected_exits = machine.views.retained_exit_proofs();

    // The retired suffix is exactly what the snapshot carries, and it restores unchanged.
    let restored = Machine::restore(profile, machine.snapshot()).unwrap();
    assert_eq!(restored.durable, machine.durable);
    assert_eq!(restored.views.retained_exit_proofs(), expected_exits);
}

#[test]
fn invalid_resolved_exit_rearms_exact_want_and_accepts_retry() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (machine, _) = start_profile(profile.clone());
    let mut restored = Machine::restore(profile, machine.snapshot()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let exit = recovery
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Resolver(ResolverCapability::Resolve(job))
                if job.view() == restored.inspect().view() =>
            {
                Some(*job)
            }
            _ => None,
        })
        .expect("recovery requests one exact exit proof");
    persist(&mut restored, &persist_job(&recovery));

    let forged = symbolic_nullification(&restored, restored.inspect().view(), 41);
    let verifying = restored
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            exit.id(),
            exit.generation(),
            exit.view(),
            ViewProof::Nullification(Box::new(forged)),
        )))
        .unwrap();
    let verification = verifying
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the key-matching exit still requires cryptographic verification");
    let rejected = complete_with_step(&mut restored, &verification, false);
    assert!(
        rejected
            .capabilities()
            .iter()
            .any(|effect| matches!(effect, Capability::Resolver(ResolverCapability::Reject(job)) if *job == exit))
    );
    let retry = rejected
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Resolver(ResolverCapability::Resolve(job)) if job.view() == exit.view() => {
                Some(*job)
            }
            _ => None,
        })
        .expect("the still-needed exit want must be re-armed immediately");
    assert_ne!(retry.id(), exit.id());

    let authentic = symbolic_nullification(&restored, restored.inspect().view(), 42);
    let verifying = restored
        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
            retry.id(),
            retry.generation(),
            retry.view(),
            ViewProof::Nullification(Box::new(authentic)),
        )))
        .unwrap();
    let verification = verifying
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the rotated response is verified normally");
    let admitted = complete_with_step(&mut restored, &verification, true);
    drive_poll_and_persist(&mut restored, admitted);

    assert_eq!(restored.inspect().view(), View::new(2));
    assert_eq!(
        restored.inspect().resolution_jobs(),
        1,
        "the exact exit is complete while the independent finality-floor probe remains"
    );
}

#[test]
fn vqc_forwarding_waits_for_the_earliest_observation_cohort() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let early_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let later_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let early = vqc(&machine, proposed.clone(), &early_messages);
    let later = vqc(&machine, proposed, &later_messages);
    let early_job = observe(&mut machine, Artifact::Vqc(early.clone()));
    let later_job = observe(&mut machine, Artifact::Vqc(later));

    let later_first = machine
        .step(Input::Verified(VerificationCompletion::new(
            later_job.id(),
            later_job.generation(),
            vec![Verdict::new(later_job.items()[0].ticket(), true)],
        )))
        .unwrap();
    let later_first = settle(&mut machine, later_first);
    assert!(!later_first.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));

    let selected = machine
        .step(Input::Verified(VerificationCompletion::new(
            early_job.id(),
            early_job.generation(),
            vec![Verdict::new(early_job.items()[0].ticket(), true)],
        )))
        .unwrap();
    let selected = settle(&mut machine, selected);
    let forwarding = persist_job(&selected);
    let Change::ArtifactForwarded { artifact, .. } = forwarding.events()[0].change() else {
        panic!("the earliest observation cohort must determine forwarding");
    };
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(certificate) if certificate == &early));

    let [Capability::Durability(DurabilityCapability::Persist(directive))] =
        selected.capabilities()
    else {
        panic!("forwarding must be one structurally fenced persistence command");
    };
    assert_eq!(directive.id(), forwarding.id());
    let (_, _, release_after_enqueue, _) = directive.clone().into_parts();
    let [released] = release_after_enqueue.as_slice() else {
        panic!("the persistence command must carry its one post-enqueue publication");
    };
    assert!(matches!(
        released.request(),
        DurableEffect::Broadcast(forwarded) if forwarded == artifact
    ));
}

#[test]
fn cross_class_exit_selection_is_completion_order_independent() {
    for nullification_first in [false, true] {
        let profile = profile_for(Role::Validator(Participant::new(0)), 6, 2);
        let (mut machine, _) = start_profile(profile.clone());
        let proposed = leader(&machine, 1);
        let messages = vec![
            ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
            ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
            ViewMessage::Vote(view_vote(&machine, &proposed, 3)),
            ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
            ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
        ];
        let vqc = vqc(&machine, proposed.clone(), &messages);
        let vqc_job = observe(&mut machine, Artifact::Vqc(vqc));
        let certificate = symbolic_nullification(&machine, View::new(1), 0);
        let nullification_job = observe(&mut machine, Artifact::Nullification(certificate));
        let complete = |job: &VerifyJob<MinPk, Digest>| {
            Input::Verified(VerificationCompletion::new(
                job.id(),
                job.generation(),
                vec![Verdict::new(job.items()[0].ticket(), true)],
            ))
        };

        let selected = if nullification_first {
            let later = machine.step(complete(&nullification_job)).unwrap();
            let later = settle(&mut machine, later);
            assert!(later.capabilities().iter().all(|effect| !matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
            )));
            machine.step(complete(&vqc_job)).unwrap()
        } else {
            machine.step(complete(&vqc_job)).unwrap()
        };
        let selected = settle(&mut machine, selected);
        let forwarding = persist_job(&selected);
        assert!(matches!(
            forwarding.events()[0].change(),
            Change::ArtifactForwarded { artifact, .. }
                if matches!(artifact.as_ref(), Artifact::Vqc(_))
        ));
        // Snapshot the instant the forwarding barrier lands, before any follow-up staging, so
        // recovery has to re-derive the rescued vote rather than replay it.
        persist_raw(&mut machine, &forwarding);
        let crashed = machine.snapshot();

        let mut restored = Machine::restore(profile, crashed).unwrap();
        let recovery = restored.step(Input::RecoveryComplete).unwrap();
        let recovered = persist(&mut restored, &persist_job(&recovery));
        let rescue = persist_job(&recovered);
        assert!(matches!(
            rescue.events()[0].change(),
            Change::OutboxQueued { effect, .. }
                if matches!(effect.as_ref(), DurableEffect::Sign(SignRequest::Vote(request))
                    if request.body().leader() == proposed.digest::<Sha256>())
        ));
    }
}

#[test]
fn earlier_unverified_vqc_claim_blocks_later_local_nullification() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let _pending_vqc = observe(&mut machine, Artifact::Vqc(certificate));

    let shares = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(shares))] = shares.capabilities()
    else {
        panic!("nullify shares must be verified together");
    };
    let completed = machine
        .step(Input::Verified(VerificationCompletion::new(
            shares.id(),
            shares.generation(),
            shares
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let completed = settle(&mut machine, completed);
    assert!(completed.capabilities().iter().all(|effect| {
        !matches!(
            effect,
            Capability::Leader(LeaderCapability::RecoverNullification(_))
                | Capability::Durability(DurabilityCapability::Persist(_))
        )
    }));
}

#[test]
fn local_vqc_survives_a_crash_before_forwarding() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let messages = [
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let observed_messages = machine
        .step(cohort::<Sha256, _>(
            messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(observed_messages))] =
        observed_messages.capabilities()
    else {
        panic!("view messages must be verified together");
    };
    let observed_nullifies = machine
        .step(cohort::<Sha256, _>(
            (1..4)
                .map(|signer| Artifact::Nullify(nullify(&machine, View::new(1), signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(observed_nullifies))] =
        observed_nullifies.capabilities()
    else {
        panic!("nullify shares must be verified together");
    };

    let later_completed = machine
        .step(Input::Verified(VerificationCompletion::new(
            observed_nullifies.id(),
            observed_nullifies.generation(),
            observed_nullifies
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let later_completed = settle(&mut machine, later_completed);
    assert!(
        later_completed
            .capabilities()
            .iter()
            .all(|effect| !matches!(
                effect,
                Capability::Leader(LeaderCapability::RecoverNullification(_))
            ))
    );

    let earlier_completed = machine
        .step(Input::Verified(VerificationCompletion::new(
            observed_messages.id(),
            observed_messages.generation(),
            observed_messages
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let earlier_completed = settle(&mut machine, earlier_completed);
    let aggregate = earlier_completed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the earlier V-QC quorum must win the exit frontier");
    let selected = aggregate.messages().collect::<Vec<_>>();
    let certificate = vqc(&machine, proposed, &selected);
    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            certificate,
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let acknowledged = persist_raw(&mut machine, &persist_job(&completed));
    // Crash between the retention barrier and the forwarding the scheduler is about to stage.
    let crashed = machine.snapshot();
    let retained = settle(&mut machine, acknowledged);
    assert!(matches!(
        persist_job(&retained).events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(_))
    ));

    let mut restored = Machine::restore(profile, crashed).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = persist(&mut restored, &persist_job(&recovery));
    let forwarding = persist_job(&recovered);
    assert!(matches!(
        forwarding.events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(_))
    ));
}

#[test]
fn forwarding_one_certificate_class_does_not_suppress_the_other() {
    let profile = profile_for(Role::Observer, 6, 2);
    let (mut machine, _) = start_profile(profile.clone());
    let view = View::new(2);
    let certificate = symbolic_nullification(&machine, view, 0);
    let nullification_job = observe(&mut machine, Artifact::Nullification(certificate));
    let nullification_ready = complete_with_step(&mut machine, &nullification_job, true);
    let nullification_forwarding = persist_job(&nullification_ready);
    let Change::ArtifactForwarded {
        publication: nullification_publication,
        retired,
        artifact,
    } = nullification_forwarding.events()[0].change()
    else {
        panic!("the nullification must be forwarded");
    };
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::Nullification(_)));
    persist(&mut machine, &nullification_forwarding);

    let proposed = leader(&machine, 2);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, view, 3)),
        ViewMessage::NoVote(no_vote(&machine, view, 4)),
    ];
    let certificate = vqc(&machine, proposed, &messages);
    let vqc_job = observe(&mut machine, Artifact::Vqc(certificate));
    let vqc_ready = complete_with_step(&mut machine, &vqc_job, true);
    let forwarding = persist_job(&vqc_ready);
    let Change::ArtifactForwarded {
        publication: vqc_publication,
        retired,
        artifact,
    } = forwarding.events()[0].change()
    else {
        panic!("the V-QC must be forwarded");
    };
    assert!(retired.is_empty());
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(_)));
    persist(&mut machine, &forwarding);

    let snapshot = machine.snapshot();
    assert!(snapshot.outbox().contains_key(nullification_publication));
    assert!(snapshot.outbox().contains_key(vqc_publication));
    let exits = snapshot
        .obligations()
        .values()
        .flat_map(PublicationObligation::discharges)
        .filter_map(|discharge| match discharge {
            PublicationDischarge::ExitReplacedAfter { id, view: actual } if *actual == view => {
                Some(id.effect())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exits, vec![*nullification_publication, *vqc_publication]);

    let restored = Machine::restore(profile, snapshot).unwrap();
    assert!(
        restored
            .snapshot()
            .outbox()
            .contains_key(nullification_publication)
    );
    assert!(restored.snapshot().outbox().contains_key(vqc_publication));

    let successor = Artifact::Nullification(symbolic_nullification(
        &machine,
        View::new(view.get() + 1),
        1,
    ));
    let successor = observe(&mut machine, successor);
    let successor = complete_with_step(&mut machine, &successor, true);
    let successor = persist_job(&successor);
    let Change::ArtifactForwarded {
        publication: successor_publication,
        retired,
        ..
    } = successor.events()[0].change()
    else {
        panic!("the next-view exit must be forwarded");
    };
    assert_eq!(
        retired.as_slice(),
        [*nullification_publication, *vqc_publication]
    );
    persist(&mut machine, &successor);

    let snapshot = machine.snapshot();
    assert!(!snapshot.outbox().contains_key(nullification_publication));
    assert!(!snapshot.outbox().contains_key(vqc_publication));
    assert!(snapshot.outbox().contains_key(successor_publication));
}

#[test]
fn local_nullification_promotes_an_identical_pending_artifact() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let view = View::new(1);
    let observed = machine
        .step(cohort::<Sha256, _>(
            (0..3)
                .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(shares))] =
        observed.capabilities()
    else {
        panic!("nullify shares must be verified together");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            shares.id(),
            shares.generation(),
            shares
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a threshold quorum must request nullification recovery");

    let certificate = symbolic_nullification(&machine, view, 0);
    let certificate_id = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let inbound = observe(&mut machine, Artifact::Nullification(certificate.clone()));
    let local = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), certificate),
        ))
        .unwrap();
    let local = settle(&mut machine, local);
    let retained = persist(&mut machine, &persist_job(&local));
    assert!(
        machine
            .inspect()
            .ready_artifacts()
            .contains(&certificate_id)
    );

    let stale_worker = machine
        .step(Input::Verified(VerificationCompletion::new(
            inbound.id(),
            inbound.generation(),
            vec![Verdict::new(inbound.items()[0].ticket(), false)],
        )))
        .unwrap();
    assert!(matches!(
        stale_worker.status(),
        StepStatus::Verified {
            valid: 0,
            invalid: 0
        }
    ));
    assert!(matches!(
        persist_job(&retained).events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if artifact.id::<Sha256>() == certificate_id
    ));
}

#[test]
fn local_vqc_origin_reconciles_identical_pending_later_ingress() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let local_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let messages = machine
        .step(cohort::<Sha256, _>(
            local_messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(messages))] =
        messages.capabilities()
    else {
        panic!("view messages must be verified together");
    };

    let local = vqc(&machine, proposed, &local_messages);
    let inbound = observe(&mut machine, Artifact::Vqc(local.clone()));

    let ready = machine
        .step(Input::Verified(VerificationCompletion::new(
            messages.id(),
            messages.generation(),
            messages
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let ready = settle(&mut machine, ready);
    let aggregate = ready
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("the local quorum must issue V-QC aggregation");

    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            local.clone(),
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    let forwarding = persist_job(&retained);
    assert!(matches!(
        forwarding.events()[0].change(),
        Change::ArtifactForwarded { artifact, .. }
            if matches!(artifact.as_ref(), Artifact::Vqc(actual) if actual == &local)
    ));

    let stale = machine
        .step(Input::Verified(VerificationCompletion::new(
            inbound.id(),
            inbound.generation(),
            vec![Verdict::new(inbound.items()[0].ticket(), true)],
        )))
        .unwrap();
    assert_eq!(
        stale.status(),
        &StepStatus::Verified {
            valid: 0,
            invalid: 0,
        }
    );
}

#[test]
fn local_vqc_origin_precedes_identical_later_ingress() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);
    let local_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let messages = machine
        .step(cohort::<Sha256, _>(
            local_messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(messages))] =
        messages.capabilities()
    else {
        panic!("view messages must be verified together");
    };
    let competing_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let local = vqc(&machine, proposed.clone(), &local_messages);
    let competing = vqc(&machine, proposed, &competing_messages);
    let certificates = machine
        .step(cohort::<Sha256, _>(vec![
            Artifact::Vqc(competing),
            Artifact::Vqc(local.clone()),
        ]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(certificates))] =
        certificates.capabilities()
    else {
        panic!("V-QCs must be verified together");
    };
    complete(&mut machine, certificates, true);

    let ready = machine
        .step(Input::Verified(VerificationCompletion::new(
            messages.id(),
            messages.generation(),
            messages
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let ready = settle(&mut machine, ready);
    let aggregate = ready
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            local.clone(),
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    let forwarding = persist_job(&retained);
    let Change::ArtifactForwarded { artifact, .. } = forwarding.events()[0].change() else {
        panic!("the local origin must re-enter representative selection");
    };
    assert!(matches!(artifact.as_ref(), Artifact::Vqc(actual) if actual == &local));
}

#[test]
fn proposal_parent_suppresses_identical_local_assembly() {
    let signer = LeaderSchedule::round_robin(6).leader(View::new(2));
    let profile = profile_for(Role::Validator(signer), 6, 2);
    let (mut machine, _) = start_profile(profile);

    // View one nullifies before its view messages arrive.
    let exit = symbolic_nullification(&machine, View::new(1), 0);
    let nullification = observe(&mut machine, Artifact::Nullification(exit));

    // The view-one messages arrive late and sit in verification.
    let proposed = leader(&machine, 1);
    let messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let pending = machine
        .step(cohort::<Sha256, _>(
            messages
                .iter()
                .cloned()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(pending))] =
        pending.capabilities()
    else {
        panic!("view messages must be verified together");
    };
    let pending = pending.clone();

    // The nullification verifies and becomes the exit proof for view one. Settling stages its
    // forwarding barrier before the peer's certificate finishes verification, as the old inline
    // drive did.
    let forwarding = machine
        .step(Input::Verified(VerificationCompletion::new(
            nullification.id(),
            nullification.generation(),
            vec![Verdict::new(nullification.items()[0].ticket(), true)],
        )))
        .unwrap();
    let forwarding = settle(&mut machine, forwarding);

    // A peer assembled the same V-QC from the same messages and it verifies first.
    let parent = vqc(&machine, proposed, &messages);
    let certificate = observe(&mut machine, Artifact::Vqc(parent.clone()));
    complete(&mut machine, &certificate, true);

    // Exit view one on the nullification and propose view two anchored on the inbound V-QC.
    let forwarded = persist(&mut machine, &persist_job(&forwarding));
    let entered = persist(&mut machine, &persist_job(&forwarded));
    assert_eq!(machine.inspect().view(), View::new(2));
    // The signing request releases with the step that stages the proposal choice.
    let sign = sign_job(&entered);
    persist(&mut machine, &persist_job(&entered));
    let SignRequest::LeaderBlock(request) = sign_request(&sign) else {
        panic!("the view-two leader must reserve a proposal");
    };
    assert_eq!(request.parent().exact().map(Arc::as_ref), Some(&parent));
    assert!(request.attach_parent());
    let signed = machine
        .step(Input::EffectCompleted(EffectCompletion::Signed {
            id: sign.id(),
            generation: sign.generation(),
            artifact: Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                request.block().clone(),
                attestation(signer.get()),
            ))),
        }))
        .unwrap();
    let signed = settle(&mut machine, signed);
    let published = persist(&mut machine, &persist_job(&signed));

    // The view messages finish verification with the publication barrier still in flight. The
    // proposal already disseminates their V-QC, so the machine must not assemble and broadcast it
    // again.
    let ready = machine
        .step(Input::Verified(VerificationCompletion::new(
            pending.id(),
            pending.generation(),
            pending
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let ready = settle(&mut machine, ready);
    assert!(!ready.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )));
    persist(&mut machine, &persist_job(&published));
    let assembled = Artifact::Vqc(parent);
    assert!(
        machine
            .durable
            .local
            .contains_key(&assembled.id::<Sha256>())
    );
    assert!(machine.inspect().pending_barrier().is_none());
    let cursor = machine.inspect().cursor();
    let drained = machine.poll(NonZeroUsize::MIN).unwrap();
    assert!(drained.capabilities().is_empty());
    assert_eq!(machine.inspect().cursor(), cursor);
    assert!(machine.inspect().is_live());
}

#[test]
fn forwarded_vqc_does_not_suppress_different_local_assembly() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let proposed = leader(&machine, 1);
    let proposal = observe(
        &mut machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(
            proposed.clone(),
            attestation(LeaderSchedule::round_robin(6).leader(View::new(1)).get()),
        )),
    );
    complete(&mut machine, &proposal, true);

    let first_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 4)),
    ];
    let first = vqc(&machine, proposed.clone(), &first_messages);
    let first = Arc::new(Artifact::Vqc(first));
    let profile = machine.profile().clone();
    machine
        .views
        .retain_vqc_parent::<Sha256>(&first, &profile)
        .unwrap();
    machine.views.observe_forwarded::<Sha256>(&first);

    let second_messages = vec![
        ViewMessage::Vote(view_vote(&machine, &proposed, 0)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 1)),
        ViewMessage::Vote(view_vote(&machine, &proposed, 2)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 3)),
        ViewMessage::NoVote(no_vote(&machine, View::new(1), 5)),
    ];
    let second = vqc(&machine, proposed, &second_messages);
    let messages = machine
        .step(cohort::<Sha256, _>(
            second_messages
                .into_iter()
                .map(|message| match message {
                    ViewMessage::Vote(vote) => Artifact::Vote(vote),
                    ViewMessage::NoVote(vote) => Artifact::NoVote(vote),
                })
                .collect(),
        ))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(messages))] =
        messages.capabilities()
    else {
        panic!("the different V-QC transcript must be verified together");
    };
    let ready = complete_with_step(&mut machine, messages, true);
    let aggregate = ready
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::AggregateVqc(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a different transcript must still be aggregated locally");
    let completed = machine
        .step(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
            aggregate.id(),
            aggregate.generation(),
            second,
        ))))
        .unwrap();
    let completed = settle(&mut machine, completed);
    let retained = persist(&mut machine, &persist_job(&completed));
    assert!(!retained.capabilities().iter().any(|effect| {
        matches!(effect, Capability::Durability(DurabilityCapability::Persist(job)) if matches!(
            job.events()[0].change(),
            Change::ArtifactForwarded { artifact, .. } if matches!(artifact.as_ref(), Artifact::Vqc(_))
        ))
    }));
    assert_eq!(machine.views.retained_parents(), 3);
}

#[test]
fn mismatched_nullification_recovery_preserves_the_job() {
    let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
    let view = View::new(1);
    let shares = (0..3)
        .map(|signer| Artifact::Nullify(nullify(&machine, view, signer)))
        .collect();
    let observed = machine.step(cohort::<Sha256, _>(shares)).unwrap();
    let [Capability::Verification(VerificationCapability::Verify(verification))] =
        observed.capabilities()
    else {
        panic!("nullify shares must be verified");
    };
    let verified = machine
        .step(Input::Verified(VerificationCompletion::new(
            verification.id(),
            verification.generation(),
            verification
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect(),
        )))
        .unwrap();
    let verified = settle(&mut machine, verified);
    let recovery = verified
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Leader(LeaderCapability::RecoverNullification(job)) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    let mismatch = symbolic_nullification(&machine, View::new(view.get() + 1), 0);
    let parked = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), mismatch),
        ))
        .unwrap();
    assert_eq!(parked.status(), &StepStatus::CompletionDeferred);
    // The mismatch surfaces exactly once when the parked completion drains; the recovery job
    // survives for the corrected certificate.
    assert!(matches!(
        machine.poll(NonZeroUsize::MIN),
        Err(StepError::CompletionMismatch)
    ));

    let certificate = symbolic_nullification(&machine, view, 0);
    let certificate_id = Artifact::Nullification(certificate.clone()).id::<Sha256>();
    let matched = machine
        .step(Input::NullificationRecovered(
            NullificationRecoveryCompletion::new(recovery.id(), recovery.generation(), certificate),
        ))
        .unwrap();
    assert_eq!(matched.status(), &StepStatus::CompletionDeferred);
    let matched = settle(&mut machine, matched);
    assert!(machine.artifacts.contains_key(&certificate_id));
    assert!(
        matched.capabilities().iter().any(|effect| matches!(
            effect,
            Capability::Durability(DurabilityCapability::Persist(_))
        )),
        "the corrected recovery must stage its durable transition"
    );
}

proptest! {
    #[test]
    fn send_batch_assigns_stable_distinct_vote_obligation_ids(count in 1usize..=8) {
        let machine = active_machine(Role::Observer);
        let genesis = machine.profile().protocol().genesis().tips()[0];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(0),
            Height::new(1),
            genesis.digest(),
            digest(b"batched vote obligation"),
        )
        .unwrap();
        let vote = Arc::new(Artifact::DaVote(DaVote::new(
            header,
            threshold_share(0),
        )));
        let requests = (0..count)
            .map(|_| SendRequest::new(Participant::new(0), Arc::clone(&vote)))
            .collect::<Vec<_>>();
        let effect = DurableEffect::SendBatch(requests.into());
        let id = EffectId::from_cursor(Cursor::new(100));
        let first = machine.publication_obligation(id, &effect).unwrap();
        let second = machine.publication_obligation(id, &effect).unwrap();

        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.kind(), PublicationKind::SendBatch);
        prop_assert_eq!(first.discharges().len(), count);
        for (item, discharge) in first.discharges().iter().copied().enumerate() {
            let stable = matches!(
                discharge,
                PublicationDischarge::VoteCertifiedAtLeast { id: obligation, .. }
                    if obligation.effect() == id && obligation.item() == item as u32
            );
            prop_assert!(stable);
        }
    }

    #[test]
    fn held_chain_is_da_voted_in_height_order(
        priorities in prop_vec(any::<u8>(), 1..=4),
    ) {
        let depth = priorities.len() as u32;
        let mut machine = Machine::new(profile_for(
            Role::Validator(Participant::new(0)),
            6,
            depth,
        ));
        let start = machine.step(Input::Start).unwrap();
        persist(&mut machine, &persist_job(&start));

        let mut parent = machine.profile().protocol().genesis().tips()[1];
        let mut headers = Vec::with_capacity(priorities.len());
        for height in 1..=priorities.len() {
            let header = TransactionBlockHeader::new(
                machine.profile().protocol().epoch(),
                ChainId::new(1),
                Height::new(height as u64),
                parent.digest(),
                digest(format!("property body {height}").as_bytes()),
            )
            .unwrap();
            parent = header.block_ref::<Sha256>();
            headers.push(header);
        }
        let mut order = (0..headers.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|index| (priorities[*index], *index));

        let mut validations = BTreeMap::new();
        for &index in &order {
            let authenticated = authenticate_block(&mut machine, headers[index].clone(), 1);
            for job in validation_jobs(&authenticated) {
                validations.insert(job.block().header().height(), job);
            }
        }
        prop_assert_eq!(validations.len(), headers.len());

        let mut choices = Vec::new();
        for index in order {
            let height = headers[index].height();
            let validation = validations.remove(&height).unwrap();
            let step = complete_validation(&mut machine, &validation);
            drain_da_choices(&mut machine, step, &mut choices);
        }
        prop_assert_eq!(
            choices.iter().map(|header| header.height()).collect::<Vec<_>>(),
            (1..=headers.len()).map(|height| Height::new(height as u64)).collect::<Vec<_>>(),
        );
        for (choice, expected) in choices.iter().zip(headers) {
            prop_assert_eq!(choice, &expected);
        }
    }

    #[test]
    fn generated_nullification_suffix_advances_in_order(
        priorities in prop_vec(any::<u8>(), 1..=5),
    ) {
        let (mut machine, _) = start_profile(profile_for(Role::Observer, 6, 2));
        let mut views = (1..=priorities.len())
            .map(|view| View::new(view as u64))
            .collect::<Vec<_>>();
        views.sort_unstable_by_key(|view| (priorities[view.get() as usize - 1], view.get()));
        let artifacts = views
            .into_iter()
            .map(|view| Artifact::Nullification(symbolic_nullification(&machine, view, 0)))
            .collect();
        let observed = machine.step(cohort::<Sha256, _>(artifacts)).unwrap();
        let [Capability::Verification(VerificationCapability::Verify(verification))] = observed.capabilities() else {
            return Err(TestCaseError::fail("missing verification job"));
        };
        let step = machine
            .step(Input::Verified(VerificationCompletion::new(
                verification.id(),
                verification.generation(),
                verification
                    .items()
                    .iter()
                    .map(|item| Verdict::new(item.ticket(), true))
                    .collect(),
            )))
            .unwrap();
        let mut step = settle(&mut machine, step);
        let mut advanced = Vec::new();
        while let Some(job) = step.capabilities().iter().find_map(|effect| match effect {
            Capability::Durability(DurabilityCapability::Persist(job)) => Some(job.clone()),
            _ => None,
        }) {
            // Staging applies the transition, so each staged exit reports the view it entered.
            if matches!(job.events()[0].change(), Change::ViewAdvanced { .. }) {
                advanced.push(machine.inspect().view());
            }
            step = persist(&mut machine, &job);
        }
        prop_assert_eq!(
            advanced,
            (2..=priorities.len() + 1)
                .map(|view| View::new(view as u64))
                .collect::<Vec<_>>()
        );
        prop_assert_eq!(
            machine.inspect().view(),
            View::new(priorities.len() as u64 + 1)
        );
    }
}

#[test]
fn symbolic_verifier_uses_exact_production_tickets() {
    let mut runner = active_runner(Role::Observer);
    let accepted = leader_artifact(runner.machine(), 1);
    let rejected = leader_artifact(runner.machine(), 2);
    let accepted_id = accepted.id::<Sha256>();
    let rejected_id = rejected.id::<Sha256>();
    let observed = runner
        .submit(cohort::<Sha256, _>(vec![accepted, rejected]))
        .unwrap();
    let [Capability::Verification(VerificationCapability::Verify(job))] = observed.capabilities()
    else {
        panic!("both observations must share one verification job");
    };
    let mut verifier = SymbolicVerifier::new(false);
    verifier.set(accepted_id, true);

    let completed = runner
        .execute(
            &mut verifier,
            &Capability::Verification(VerificationCapability::Verify(job.clone())),
        )
        .unwrap();
    assert!(matches!(
        completed.as_ref().map(Step::status),
        Some(StepStatus::Verified {
            valid: 1,
            invalid: 1
        })
    ));
    assert_eq!(runner.inspect().ready_artifacts(), &[accepted_id]);
    assert_eq!(runner.inspect().cached_artifacts(), 1);
    assert_ne!(accepted_id, rejected_id);
}

#[test]
fn runner_models_before_and_after_append_crash_cuts() {
    let mut runner = active_runner(Role::Observer);
    let artifact = Artifact::NoVote(no_vote(runner.machine(), View::new(1), 0));

    // A relayed third-party artifact is independently verifiable, so its broadcast releases
    // with the staging step; only locally signed subjects wait for their barrier.
    let unpersisted = runner
        .reserve(DurableEffect::Broadcast(Arc::new(artifact.clone())))
        .unwrap();
    assert!(unpersisted.capabilities().iter().any(|effect| matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )));
    assert!(unpersisted.capabilities().iter().any(|effect| {
        matches!(durable_effect(effect), Some(DurableEffect::Broadcast(actual))
            if actual.as_ref() == &artifact)
    }));
    let recovery = runner.crash_and_restore().unwrap();
    // The reservation was never appended, so recovery forgets it; voiding the replayable
    // relay cannot equivocate this node.
    assert!(runner.inspect().outbox().is_empty());
    runner.persist(&persist_job(&recovery)).unwrap();

    let reserved = runner
        .reserve(DurableEffect::Broadcast(Arc::new(artifact.clone())))
        .unwrap();
    let job = persist_job(&reserved);
    let id = match job.events()[0].change() {
        Change::OutboxQueued { id, .. } => *id,
        _ => panic!("expected durable outbox reservation"),
    };
    runner.append(&job).unwrap();

    let recovery = runner.crash_and_restore().unwrap();
    assert_eq!(runner.inspect().outbox(), &[id]);
    let recovered = runner.persist(&persist_job(&recovery)).unwrap();
    let broadcast = recovered
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Durability(DurabilityCapability::Released(job)) => Some(job),
            _ => None,
        })
        .expect("durable broadcast must be reissued after recovery");
    assert_eq!(broadcast.id(), id);
    let DurableEffect::Broadcast(actual) = broadcast.request() else {
        panic!("durable broadcast must be reissued after recovery");
    };
    assert_eq!(actual.as_ref(), &artifact);
}
