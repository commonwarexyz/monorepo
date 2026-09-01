//! Shared fixtures for the machine unit tests: profiles, symbolic artifacts, and drivers.

pub(super) use crate::multimmit::machine::testing::fixtures::{
    CountingHasher, Harness, TEST_RESOURCES, TestConfig, attestation, digest, genesis_tip_history,
    retention_for, threshold_share,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::voter::validation_parallelism,
        algebra::VqcExtraction,
        config::{LeaderSchedule, Profile, ResourceLimits, Role},
        machine::{
            artifact::Dependency,
            capability::{
                Capabilities, Capability, CryptoJob, ObservedBlock, ResolverCommand, TimerCommand,
                ValidatorCommand,
            },
            core_state::{CoreState, InputTicket},
            durability::{
                BarrierAck, Change, ChangeKind, DurableEffect, DurableJob, EffectCompletion,
                EffectId, PersistDirective, PersistJob, ProposalParent, ProposalRequest,
                ReplayError, SignRequest, SnapshotReason, TransitionReason,
            },
            eligibility::{BlockValidity, ChainEligibility, ValidationCompletion},
            finality::LqcAggregateJob,
            input::{DaVotesOffer, Input, ObservationStatus, Step, StepStatus},
            job::Generation,
            producer::{BuildCompletion, BuildJob, CustodyCompletion, CustodyJob},
            reducer::machine::Machine,
            resolution::{ResolutionCompletion, ResolutionJob},
            scheduler::Lane,
            testing::{
                CapabilitiesExt as _, Drive as _, Driver, EffectExt, MachineExt as _, StepExt as _,
                SymbolicPersistence, Until, VerifyJobExt as _, cohort,
                fixtures::{genesis_leader, symbolic_lqc, symbolic_vqc, vote},
                start,
            },
            verification::{Observation, VerifyJob},
            view::{ViewTimer, VqcAggregateCompletion, VqcAggregateJob},
        },
        types::{
            Activity, Artifact, ArtifactId, ChainId, CodecConfig, DaCertificate, DigestedLeader,
            Extension, LeaderBlock, Lqc, NoVote, Nullification, Nullify, Position,
            SignedLeaderBlock, SignedTransactionBlock, TipRecord, TransactionBlockHeader,
            ViewMessage, ViewProof, Vote, VoteBody, Vqc,
        },
    },
    types::{Height, Participant, Round, View},
};
use commonware_cryptography::{
    Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::{
            group::{Private, Scalar},
            ops::sign_message,
            variant::MinPk,
        },
    },
    sha256::Digest,
};
use core::{num::NonZeroUsize, time::Duration};
use std::sync::Arc;

pub(super) type TestMachine = Machine<Sha256, MinPk>;

type TestDurableJob = DurableJob<MinPk, Digest>;

/// Returns the check a rejected replay or restore failed.
pub(super) fn transition_reason<T>(result: Result<T, ReplayError>) -> TransitionReason {
    match result {
        Err(ReplayError::Transition(reason)) => reason,
        Err(other) => panic!("expected a transition failure, got {other:?}"),
        Ok(_) => panic!("expected a transition failure, got success"),
    }
}

/// Returns the check a rejected snapshot failed.
pub(super) fn snapshot_reason<T>(result: Result<T, ReplayError>) -> SnapshotReason {
    match result {
        Err(ReplayError::Snapshot(reason)) => reason,
        Err(other) => panic!("expected a snapshot failure, got {other:?}"),
        Ok(_) => panic!("expected a snapshot failure, got success"),
    }
}

pub(super) fn release_after_enqueue(step: &Step<MinPk, Digest>) -> Vec<TestDurableJob> {
    step.persist_directive().release_after_enqueue
}

pub(super) const fn durable_job(effect: &Capability<MinPk, Digest>) -> Option<&TestDurableJob> {
    let Capability::Released(job) = effect else {
        return None;
    };
    Some(job)
}

pub(in crate::multimmit::machine) fn durable_effect(
    effect: &Capability<MinPk, Digest>,
) -> Option<&DurableEffect<MinPk, Digest>> {
    Some(durable_job(effect)?.request())
}

pub(super) fn sign_request(job: &TestDurableJob) -> &SignRequest<MinPk, Digest> {
    let Some(request) = job.request().sign_one() else {
        unreachable!("test helper only accepts signing jobs")
    };
    request
}

pub(super) fn queued_effect_id(step: &Step<MinPk, Digest>) -> EffectId {
    let job = step.persist_job();
    let Change::OutboxQueued { id, .. } = job.events()[0].change() else {
        panic!("test effect reservation must queue one outbox effect");
    };
    *id
}

pub(super) fn active_machine(role: Role) -> TestMachine {
    let mut machine = Machine::new(Harness::builder(role).profile());
    let start = machine.step(Input::Start).unwrap();
    assert_eq!(start.status(), &StepStatus::Accepted);
    // The view timer arms at staging, alongside the generation barrier.
    assert!(matches!(
        start.capabilities(),
        [
            Capability::Timer(TimerCommand::View(_)),
            Capability::Journal(_)
        ]
    ));
    let started = machine.persist(&start.persist_job(), Until::CursorAdvance);
    assert_eq!(started.status(), &StepStatus::Accepted);
    match role {
        Role::Validator(_) => {
            // The producer's signing choice stages behind the generation barrier and its
            // request releases at staging.
            assert!(matches!(
                started.capabilities(),
                [Capability::Released(job), Capability::Journal(_)]
                    if job.request().sign_one().is_some()
            ));
            let proposed = machine.persist(&started.persist_job(), Until::CursorAdvance);
            assert!(
                !proposed.has(|effect| durable_effect(effect)
                    .and_then(EffectExt::sign_one)
                    .is_some()),
                "the choice acknowledgement must not release signing a second time"
            );
        }
        Role::Observer => assert!(started.capabilities().is_empty()),
    }
    assert!(machine.inspect().is_live());
    machine
}

pub(in crate::multimmit::machine) fn active_driver(role: Role) -> Driver<Sha256, MinPk> {
    let mut driver = Driver::new(Harness::builder(role).profile());
    let start = driver.submit(Input::Start).unwrap();
    let unhandled = driver.drain(
        &mut SymbolicPersistence,
        start.into_capabilities(),
        Until::Step,
    );
    match role {
        Role::Validator(_) => assert!(matches!(
            unhandled.as_slice(),
            [Capability::Timer(TimerCommand::View(_)), Capability::Released(job)]
                if job.request().sign_one().is_some()
        )),
        Role::Observer => assert!(matches!(
            unhandled.as_slice(),
            [Capability::Timer(TimerCommand::View(_))]
        )),
    }
    assert!(driver.inspect().is_live());
    driver
}

pub(super) fn sign_job(step: &Step<MinPk, Digest>) -> TestDurableJob {
    step.find(|effect| match effect {
        Capability::Released(job) if job.request().sign_one().is_some() => Some(job.clone()),
        _ => None,
    })
    .expect("a durable signing choice must release one signing job")
}

fn symbolic_threshold_certificate(marker: u64) -> ThresholdCertificate<MinPk> {
    let private = Private::new(Scalar::from_u64(marker + 1));
    ThresholdCertificate::new(sign_message::<MinPk>(
        &private,
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_CERTIFICATE",
        b"symbolic certificate",
    ))
}

pub(in crate::multimmit::machine) fn leader(
    machine: &TestMachine,
    view: u64,
) -> LeaderBlock<MinPk, Digest> {
    genesis_leader(machine.profile().protocol(), View::new(view))
}

pub(in crate::multimmit::machine) fn leader_artifact(
    machine: &TestMachine,
    view: u64,
) -> Artifact<MinPk, Digest> {
    Artifact::LeaderBlock(SignedLeaderBlock::new(
        leader(machine, view),
        attestation(0),
    ))
}

pub(super) const fn proposal_request(
    block: LeaderBlock<MinPk, Digest>,
) -> ProposalRequest<MinPk, Digest> {
    ProposalRequest::new(block, ProposalParent::Genesis, false)
}

pub(super) fn proposal_request_with_parent(
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
        machine.profile().codec(),
    )
    .unwrap();
    ProposalRequest::new(block, ProposalParent::Exact(Arc::new(parent)), true)
}

pub(super) fn vote_artifact(
    machine: &TestMachine,
    leader: &LeaderBlock<MinPk, Digest>,
) -> Artifact<MinPk, Digest> {
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(leader),
        vec![Position::new(0)],
        vec![Extension::new(Vec::new(), 1).unwrap()],
        machine.profile().codec(),
    )
    .unwrap();
    Artifact::Vote(Vote::new(body, attestation(0)))
}

pub(in crate::multimmit::machine) fn view_vote(
    machine: &TestMachine,
    leader: &LeaderBlock<MinPk, Digest>,
    signer: u32,
) -> Vote<MinPk, Digest> {
    let codec = machine.profile().codec();
    vote(leader, signer, &vec![0; codec.chains()], codec)
}

pub(super) fn view_messages(
    machine: &TestMachine,
    leader: &LeaderBlock<MinPk, Digest>,
    voters: &[u32],
    nonvoters: &[u32],
) -> Vec<ViewMessage<MinPk, Digest>> {
    let mut messages = Vec::with_capacity(voters.len() + nonvoters.len());
    messages.extend(
        voters
            .iter()
            .map(|&signer| ViewMessage::Vote(view_vote(machine, leader, signer))),
    );
    messages.extend(
        nonvoters
            .iter()
            .map(|&signer| ViewMessage::NoVote(no_vote(machine, leader.round().view(), signer))),
    );
    messages
}

pub(in crate::multimmit::machine) fn no_vote(
    machine: &TestMachine,
    view: View,
    signer: u32,
) -> NoVote<MinPk> {
    NoVote::new(
        Round::new(machine.profile().protocol().epoch(), view),
        attestation(signer),
    )
    .unwrap()
}

pub(super) fn nullify(machine: &TestMachine, view: View, signer: u32) -> Nullify<MinPk> {
    Nullify::new(
        Round::new(machine.profile().protocol().epoch(), view),
        threshold_share(signer),
    )
    .unwrap()
}

pub(super) fn symbolic_nullification(
    machine: &TestMachine,
    view: View,
    marker: u64,
) -> Nullification<MinPk> {
    let certificate = symbolic_threshold_certificate(marker);
    Nullification::new(
        Round::new(machine.profile().protocol().epoch(), view),
        certificate,
    )
    .unwrap()
}

pub(super) fn vqc(
    machine: &TestMachine,
    leader: LeaderBlock<MinPk, Digest>,
    messages: &[ViewMessage<MinPk, Digest>],
) -> Vqc<MinPk, Digest> {
    symbolic_vqc(leader, messages, machine.profile().codec())
}

pub(super) fn vqc_completion(
    aggregate: &VqcAggregateJob<MinPk, Digest>,
    certificate: Vqc<MinPk, Digest>,
    codec: CodecConfig,
) -> VqcAggregateCompletion<MinPk, Digest> {
    VqcAggregateCompletion::prepare::<Sha256>(aggregate, certificate, codec).unwrap()
}

pub(super) fn lqc(
    machine: &TestMachine,
    leader: LeaderBlock<MinPk, Digest>,
    votes: &[Vote<MinPk, Digest>],
) -> Lqc<MinPk, Digest> {
    symbolic_lqc(leader, votes, machine.profile().codec())
}

pub(super) fn self_certifying_view_proofs(
    machine: &TestMachine,
    view: View,
) -> [Artifact<MinPk, Digest>; 3] {
    let proposed = leader(machine, view.get());
    let votes = (0..5)
        .map(|signer| view_vote(machine, &proposed, signer))
        .collect::<Vec<_>>();
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    [
        Artifact::Nullification(symbolic_nullification(machine, view, view.get())),
        Artifact::Vqc(vqc(machine, proposed.clone(), &messages)),
        Artifact::Lqc(lqc(machine, proposed, &votes)),
    ]
}

pub(super) fn view_one_vqc(machine: &TestMachine) -> Vqc<MinPk, Digest> {
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

pub(super) fn leader_extending_view_one_vqc(
    machine: &TestMachine,
    view: u64,
    parent: &Vqc<MinPk, Digest>,
) -> (LeaderBlock<MinPk, Digest>, Digest) {
    let protocol = machine.profile().protocol();
    let (tips, _) = VqcExtraction::new::<Sha256, MinPk>(parent, protocol.codec_config())
        .unwrap()
        .into_parts();
    let history = TipRecord::new(
        parent.leader().history(),
        tips.blocks().to_vec(),
        parent.leader().proposed_heights(),
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

pub(in crate::multimmit::machine) fn start_profile(
    profile: Profile<Digest>,
) -> (TestMachine, Step<MinPk, Digest>) {
    start(profile, Until::CursorAdvance)
}

pub(super) fn observe(
    machine: &mut TestMachine,
    artifact: Artifact<MinPk, Digest>,
) -> VerifyJob<MinPk, Digest> {
    let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    assert_eq!(results[0].status(), ObservationStatus::Scheduled);
    // Retirement and anchor advances emit their own chain-plane routing capabilities, so the
    // verification job is one capability among possibly several.
    step.verify_job()
}

pub(super) fn record_view_fact(
    machine: &mut TestMachine,
    observation: Observation,
    artifact: Artifact<MinPk, Digest>,
) {
    let artifact = Arc::new(artifact);
    machine
        .views
        .observe::<Sha256>(artifact.id::<Sha256>(), observation, &artifact, None)
        .unwrap();
}

pub(super) struct RecoveredVoteSigning {
    pub(super) machine: TestMachine,
    pub(super) sign: TestDurableJob,
    pub(super) leader: LeaderBlock<MinPk, Digest>,
    pub(super) signer: Participant,
}

pub(super) fn recover_vote_signing(resources: ResourceLimits) -> RecoveredVoteSigning {
    let scheduled = LeaderSchedule::round_robin(6).unwrap().leader(View::new(1));
    let signer = Participant::new((scheduled.get() + 1) % 6);
    let role = Role::Validator(signer);
    let profile = Harness::builder(role)
        .participants(6)
        .resources(resources)
        .profile();
    let (mut machine, _) = start_profile(profile.clone());
    let proposed = leader(&machine, 1);
    let request = SignRequest::Vote(view_vote(&machine, &proposed, signer.get()).body().clone());
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(request))
        .unwrap();
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);

    let mut restored = Machine::restore(profile, machine.live_snapshot_for_test()).unwrap();
    let recovery = restored.step(Input::RecoveryComplete).unwrap();
    let recovered = restored.persist(&recovery.persist_job(), Until::CursorAdvance);
    let sign = sign_job(&recovered);
    RecoveredVoteSigning {
        machine: restored,
        sign,
        leader: proposed,
        signer,
    }
}

pub(super) fn mismatched_resolution_proof(machine: &TestMachine) -> ViewProof<MinPk, Digest> {
    ViewProof::Nullification(Box::new(symbolic_nullification(
        machine,
        View::new(u64::MAX),
        0,
    )))
}

/// Machine work quanta and journal barrier acknowledgements spent leaving one view.
pub(super) struct ExitDrive {
    pub(super) quanta: usize,
    pub(super) barriers: usize,
    /// Ordered event kinds of the persistence range that carries the exit.
    pub(super) exit: Vec<ChangeKind>,
}

/// Drives machine-owned work until the machine leaves `from`, acknowledging a barrier only
/// when the machine reports no remaining work.
pub(super) fn drive_to_exit(
    machine: &mut TestMachine,
    staged: Step<MinPk, Digest>,
    from: View,
) -> ExitDrive {
    const MAX_QUANTA: usize = 64;

    let mut effects = staged.into_capabilities();
    let mut quanta = 0;
    let mut barriers = 0;
    let mut work = true;
    while machine.view() == from {
        if work {
            assert!(
                quanta < MAX_QUANTA,
                "the machine held {from:?} for {MAX_QUANTA} work quanta"
            );
            let result = machine.poll(NonZeroUsize::MIN).unwrap();
            quanta += 1;
            work = machine.work_remaining();
            effects.extend(result.into_capabilities());
            continue;
        }
        let index = effects
            .iter()
            .position(|effect| matches!(effect, Capability::Journal(_)))
            .unwrap_or_else(|| panic!("the machine quiesced in {from:?}"));
        let Capability::Journal(directive) = effects.remove(index) else {
            unreachable!("the selected effect is a persistence job")
        };
        let job = directive.job;
        barriers += 1;
        effects.extend(machine.persist(&job, Until::Step).into_capabilities());
        work = true;
    }
    // Group commit holds the exit's range while the certificate's barrier is in flight, so
    // drain what remains to observe how the exit was journalled.
    let mut ranges = Vec::new();
    while let Some(index) = effects
        .iter()
        .position(|effect| matches!(effect, Capability::Journal(_)))
    {
        let Capability::Journal(directive) = effects.remove(index) else {
            unreachable!("the selected effect is a persistence job")
        };
        let job = directive.job;
        ranges.push(
            job.events()
                .iter()
                .map(|event| event.change().kind())
                .collect::<Vec<_>>(),
        );
        effects.extend(machine.persist(&job, Until::Step).into_capabilities());
    }
    let exit = ranges
        .into_iter()
        .find(|kinds| kinds.contains(&ChangeKind::ViewAdvanced))
        .unwrap_or_default();
    ExitDrive {
        quanta,
        barriers,
        exit,
    }
}

pub(super) fn prepare_block(
    machine: &mut TestMachine,
    job: &BuildJob<Digest>,
    body: Digest,
) -> Step<MinPk, Digest> {
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            job.issued(),
            job.parent(),
            Some(body),
        )))
        .unwrap();
    machine.settle(completed, Until::CursorAdvance)
}

pub(super) fn complete_custody(
    machine: &mut TestMachine,
    job: &CustodyJob<Digest>,
) -> Step<MinPk, Digest> {
    let completed = machine
        .step(Input::BlockCustodied(CustodyCompletion::new(
            job.issued(),
            job.header().clone(),
        )))
        .unwrap();
    machine.settle(completed, Until::CursorAdvance)
}

pub(super) fn authenticate_block(
    machine: &mut TestMachine,
    header: TransactionBlockHeader<Digest>,
    producer: u32,
) -> Step<MinPk, Digest> {
    let verification = observe(
        machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(producer))),
    );
    let verified = machine
        .step(Input::Verified(verification.all_valid()))
        .unwrap();
    machine.settle(verified, Until::CursorAdvance)
}

/// Drives one authenticated block through its chain plane and offers whatever it makes eligible.
///
/// The block store, validation, and DA-vote eligibility live in the chain plane the runtime task
/// owns. This routes the block to that plane and offers the contiguous eligible run it computes
/// for the machine's current state, so the machine reserves and self-admits exactly as it would
/// from a task's offer. A block that is not yet eligible (its held path is absent, or
/// it is beyond the pipeline window or below a retirement floor) offers nothing, matching the
/// plane. For a run spanning several heights on one chain, route them all with [`route_blocks`] and
/// offer the run together with [`offer_eligible`], since a plane offers its whole eligible run at
/// once.
pub(super) fn validate_block(
    machine: &mut TestMachine,
    header: TransactionBlockHeader<Digest>,
    producer: u32,
) -> Step<MinPk, Digest> {
    let chain = header.chain().get();
    let routed = route_blocks(machine, producer, std::slice::from_ref(&header));
    offer_eligible(machine, chain, &routed)
}

/// One block the machine routed to a producer chain's remote chain plane.
type RoutedBlock = (
    ArtifactId<Digest>,
    Observation,
    Arc<SignedTransactionBlock<MinPk, Digest>>,
    bool,
);

/// A benign settled step to seed [`settle`] when driving the machine outside an input.
pub(super) fn poll_seed() -> Step<MinPk, Digest> {
    Step::for_tests(StepStatus::Accepted, Capabilities::new(), Vec::new())
}

/// Authenticates each header through the machine and returns the blocks the machine routes to its
/// chain plane.
///
/// The machine still mints each observation identity, records producer ancestry, and rejects forks
/// here, exactly as in production; only the routed blocks' storage, validation, and DA-vote
/// eligibility moved to the per-chain plane. A test drives that plane over these blocks with
/// [`plane_eligible_run`].
pub(super) fn route_blocks(
    machine: &mut TestMachine,
    producer: u32,
    headers: &[TransactionBlockHeader<Digest>],
) -> Vec<RoutedBlock> {
    headers
        .iter()
        .map(|header| {
            let authenticated = authenticate_block(machine, header.clone(), producer);
            authenticated
                .find(|effect| match effect {
                    Capability::Validator(
                        _,
                        ValidatorCommand::Observe(ObservedBlock {
                            id,
                            observation,
                            block,
                            custodied,
                        }),
                    ) => Some((*id, *observation, block.clone(), *custodied)),
                    _ => None,
                })
                .expect("an authenticated block routes to its chain plane")
        })
        .collect()
}

/// Builds a per-chain validator seeded from the machine's current certified anchor and durable DA
/// choices, drives it over `routed` with an always-valid application verdict, and returns the
/// contiguous eligible DA-vote run it offers the machine.
///
/// This is exactly the plane a chain's validator task owns, run inline so a machine test can offer
/// the machine the run it would receive for the machine's current state. Rebuilt per call, it
/// reflects each anchor and choice advance the machine has since made.
pub(super) fn plane_eligible_run(
    machine: &TestMachine,
    chain: u32,
    routed: &[RoutedBlock],
) -> (Vec<Arc<SignedTransactionBlock<MinPk, Digest>>>, Height) {
    let chain_id = ChainId::new(chain);
    let codec = machine.profile().codec();
    let items_limit = validation_parallelism(machine.profile());
    let bytes_limit =
        items_limit.saturating_mul(machine.profile().resources().max_artifact_bytes());
    let mut validator = ChainEligibility::<MinPk, Digest>::new(
        chain_id,
        codec.pipeline_depth() as u64,
        items_limit,
        bytes_limit,
        machine.certified_anchor(chain_id),
        machine.generation(),
    );
    validator.note_chosen(machine.chosen_choices(chain_id));
    for (id, observation, block, custodied) in routed {
        if block.header().chain() == chain_id {
            validator.observe::<Sha256>(*id, *observation, Arc::clone(block), *custodied);
        }
    }
    while let Some(job) = validator.ready_validation() {
        validator.complete_validation(ValidationCompletion::new(
            job.issued(),
            BlockValidity::Valid,
        ));
    }
    let run = validator.eligible_run(codec.pipeline_depth());
    (run.run, run.ready_through)
}

/// Offers the machine the eligible DA-vote run its chain's validator task would from `routed`, then
/// settles the resulting reservation.
pub(super) fn offer_eligible(
    machine: &mut TestMachine,
    chain: u32,
    routed: &[RoutedBlock],
) -> Step<MinPk, Digest> {
    stage_eligible(machine, chain, routed);
    machine.settle(poll_seed(), Until::CursorAdvance)
}

/// Stages one chain's eligible DA-vote run into the machine's frontier shadow without draining it,
/// so a test can arm several chains and capture the whole frontier atomically in one later drain.
pub(super) fn stage_eligible(machine: &mut TestMachine, chain: u32, routed: &[RoutedBlock]) {
    let (candidates, ready_through) = plane_eligible_run(machine, chain, routed);
    let offered = machine.offer_da_votes(DaVotesOffer {
        generation: machine.generation(),
        chain: ChainId::new(chain),
        candidates,
        ready_through,
    });
    assert_eq!(offered, StepStatus::Accepted);
}

pub(super) fn symbolic_da_certificate(
    header: TransactionBlockHeader<Digest>,
    marker: u64,
) -> DaCertificate<MinPk, Digest> {
    DaCertificate::new(header, symbolic_threshold_certificate(marker))
}

pub(super) fn drain_da_choices(
    machine: &mut TestMachine,
    mut step: Step<MinPk, Digest>,
    choices: &mut Vec<TransactionBlockHeader<Digest>>,
) {
    loop {
        let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) else {
            return;
        };
        for event in job.events() {
            let Change::OutboxQueued { effect, .. } = event.change() else {
                continue;
            };
            for request in effect.sign_requests().unwrap_or_default() {
                if let SignRequest::DaVote(request) = request {
                    choices.push(request.header().clone());
                }
            }
        }
        step = machine.persist(&job, Until::CursorAdvance);
    }
}

/// Produces, custodies, and signs one own-chain block, returning its recorded producer header.
///
/// The own-chain data-availability plane runs on its own task, so the machine neither pools shares
/// nor issues recovery. Certificate-admission tests supply a certificate directly through
/// `CryptoCompletion::DaCertificate`, exactly as the task returns one.
pub(super) fn produce_own_header(machine: &mut TestMachine) -> TransactionBlockHeader<Digest> {
    let ready = machine.step(Input::ProducerWake).unwrap();
    let ready = machine.settle(ready, Until::CursorAdvance);
    let build = ready.build_job();
    let completed = machine
        .step(Input::BlockBuilt(BuildCompletion::new(
            build.issued(),
            build.parent(),
            Some(digest(b"own block")),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let completed = complete_custody(machine, &completed.custody_job());
    // The signing request releases with the step that stages the producer choice.
    let header = completed
        .find(|effect| match effect {
            Capability::Released(job) => match job.request().sign_one() {
                Some(SignRequest::TransactionBlock(header)) => Some(header.clone()),
                _ => None,
            },
            _ => None,
        })
        .unwrap();
    machine.persist(&completed.persist_job(), Until::CursorAdvance);
    header
}

pub(super) fn assert_lqc_floors_restore(machine: &mut TestMachine) {
    let finalized = leader(machine, 5);
    let votes = (0..5)
        .map(|signer| view_vote(machine, &finalized, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(machine, finalized, &votes);
    let verification = observe(machine, Artifact::Lqc(certificate.clone()));
    let admitted = machine.verify(&verification, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(admitted);

    assert_eq!(machine.inspect().view(), View::new(6));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Capability::Resolver(ResolverCommand::Resolve(_))))
    );
    assert_eq!(machine.inspect().finality_floor(), certificate.view());
    assert!(matches!(machine.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(machine.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));

    let restored = Machine::<Sha256, MinPk>::restore(
        machine.profile().clone(),
        machine.live_snapshot_for_test(),
    )
    .unwrap();
    assert_eq!(restored.inspect().view(), View::new(6));
    assert_eq!(restored.inspect().finality_floor(), certificate.view());
    assert!(matches!(restored.signing_floor(),
        Some(Artifact::Lqc(actual)) if actual == &certificate));
    assert!(matches!(restored.anchor_vqc(),
        Some(Artifact::Vqc(anchor)) if certificate.equivalent_vqc(anchor)));
}

/// Drives one leader block and a unanimous vote transcript into the local finality pools.
///
/// Returns the aggregation jobs the pools reserve for the view certificate and the certificate
/// of local finality.
pub(super) fn drive_unanimous_votes(
    machine: &mut TestMachine,
    proposed: &LeaderBlock<MinPk, Digest>,
) -> (
    VqcAggregateJob<MinPk, Digest>,
    LqcAggregateJob<MinPk, Digest>,
) {
    let proposal = observe(
        machine,
        Artifact::LeaderBlock(SignedLeaderBlock::new(proposed.clone(), attestation(0))),
    );
    machine.verify(&proposal, true, Until::CursorAdvance);
    let mut vqc_aggregate = None;
    let mut lqc_aggregate = None;
    fn collect<'a>(
        effects: impl IntoIterator<Item = &'a Capability<MinPk, Digest>>,
        vqc: &mut Option<VqcAggregateJob<MinPk, Digest>>,
        lqc: &mut Option<LqcAggregateJob<MinPk, Digest>>,
    ) {
        for effect in effects {
            match effect {
                Capability::Crypto(CryptoJob::AggregateVqc(job)) => {
                    let retained = vqc.get_or_insert_with(|| job.clone());
                    assert_eq!(retained.issued().id(), job.issued().id());
                    assert_eq!(retained.issued().generation(), job.issued().generation());
                }
                Capability::Crypto(CryptoJob::AggregateLqc(job)) => {
                    let retained = lqc.get_or_insert_with(|| job.clone());
                    assert_eq!(retained.issued().id(), job.issued().id());
                    assert_eq!(retained.issued().generation(), job.issued().generation());
                }
                _ => {}
            }
        }
    }
    for signer in 0..5 {
        let vote = observe(
            machine,
            Artifact::Vote(view_vote(machine, proposed, signer)),
        );
        let step = machine.verify(&vote, true, Until::CursorAdvance);
        collect(step.capabilities(), &mut vqc_aggregate, &mut lqc_aggregate);
        let effects = machine.drain_persisting(step);
        collect(effects.iter(), &mut vqc_aggregate, &mut lqc_aggregate);
    }
    (
        vqc_aggregate.expect("a unanimous transcript reserves a view certificate"),
        lqc_aggregate.expect("a unanimous transcript reaches local finality"),
    )
}

pub(super) fn unacknowledged_proposal() -> (TestMachine, Step<MinPk, Digest>) {
    let mut machine = active_machine(Role::Validator(Participant::new(0)));
    let proposed = leader(&machine, 2);
    let reserved = machine
        .reserve_test_effect(DurableEffect::sign(SignRequest::LeaderBlock(
            proposal_request(proposed.clone()),
        )))
        .unwrap();
    let sign = sign_job(&reserved);
    machine.persist(&reserved.persist_job(), Until::CursorAdvance);
    let completed = machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            sign.issued(),
            vec![Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                proposed,
                attestation(0),
            )))],
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    (machine, completed)
}

/// Builds `count` consecutive headers on `chain`, anchored at that chain's epoch genesis tip.
pub(super) fn da_run_headers(
    machine: &TestMachine,
    chain: u32,
    count: u64,
    label: &str,
) -> Vec<TransactionBlockHeader<Digest>> {
    let epoch = machine.profile().protocol().epoch();
    let mut parent = machine.profile().protocol().genesis().tips()[chain as usize];
    let mut headers = Vec::with_capacity(count as usize);
    for height in 1..=count {
        let header = TransactionBlockHeader::new(
            epoch,
            ChainId::new(chain),
            Height::new(height),
            parent.digest(),
            digest(format!("{label} {chain} {height}").as_bytes()),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>();
        headers.push(header);
    }
    headers
}

/// Returns the data-availability vote run staged by each signing reservation in `job`.
pub(super) fn reserved_da_runs(
    job: &PersistJob<MinPk, Digest>,
) -> Vec<Vec<TransactionBlockHeader<Digest>>> {
    job.events()
        .iter()
        .filter_map(|event| {
            let Change::OutboxQueued { effect, .. } = event.change() else {
                return None;
            };
            let run = effect
                .sign_requests()?
                .iter()
                .filter_map(|request| match request {
                    SignRequest::DaVote(request) => Some(request.header().clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!run.is_empty()).then_some(run)
        })
        .collect()
}

pub(super) fn frontier_chain(
    machine: &TestMachine,
    count: u64,
) -> Vec<TransactionBlockHeader<Digest>> {
    let mut parent = machine.profile().protocol().genesis().tips()[1];
    (1..=count)
        .map(|height| {
            let header = TransactionBlockHeader::new(
                machine.profile().protocol().epoch(),
                ChainId::new(1),
                Height::new(height),
                parent.digest(),
                digest(format!("frontier body {height}").as_bytes()),
            )
            .unwrap();
            parent = header.block_ref::<Sha256>();
            header
        })
        .collect()
}

pub(super) fn enqueue_due_batch_controls(
    composer: &mut CoreState<Sha256, MinPk>,
    persistence: BarrierAck,
) -> [(InputTicket, Lane); 3] {
    let epoch = composer.machine().profile().protocol().epoch();
    let persistence = composer.enqueue(Input::Persisted(persistence)).unwrap();
    let timer = composer
        .enqueue(Input::TimerFired(ViewTimer::new(
            Generation::new(0),
            Round::new(epoch, View::zero()),
            Duration::ZERO,
        )))
        .unwrap();
    let view = View::new(u64::MAX);
    let job = ResolutionJob::issue(u64::MAX, Generation::new(0), view);
    let proof = ViewProof::Nullification(Box::new(
        Nullification::new(Round::new(epoch, view), symbolic_threshold_certificate(0)).unwrap(),
    ));
    let resolver = composer
        .enqueue(Input::ResolutionCompleted(ResolutionCompletion::new(
            job.issued(),
            job.view(),
            proof,
        )))
        .unwrap();
    [
        (persistence, Lane::PersistenceCompletion),
        (timer, Lane::Timer),
        (resolver, Lane::ResolverResult),
    ]
}

pub(super) fn record_protocol_acceptances(
    accepted: &mut Vec<ArtifactId<Digest>>,
    activities: &[Activity<MinPk, Digest>],
) {
    accepted.extend(activities.iter().filter_map(|activity| match activity {
        Activity::ProtocolAccepted { artifact_id, .. } => Some(*artifact_id),
        Activity::CommitmentsAccepted { .. }
        | Activity::HistoryAccepted { .. }
        | Activity::TransactionProposed { .. } => None,
        Activity::LeaderFinalized { .. } | Activity::LeaderFinalityUpdated { .. } => None,
    }));
}
