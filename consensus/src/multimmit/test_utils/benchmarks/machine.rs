use super::fabric::{self, BenchArtifact};
use crate::{
    multimmit::{
        config::Config,
        machine::{
            Artifact, BarrierAck, BlockValidity, Capabilities, Capability, DurabilityCapability,
            DurableEffect, EffectCompletion, EffectId, Input, LeaderCapability, Machine,
            ObservationStatus, PersistJob, ProducerCapability, Profile, PublicationDischarge, Role,
            SignRequest, Snapshot, StepStatus, Tuning, ValidationCompletion, Verdict,
            VerificationCapability, VerificationCompletion,
        },
        types::{
            Anchor, ChainId, ChainProposal, DaCertificate, DaVote, SignedLeaderBlock,
            SignedTransactionBlock, ThresholdShare, TransactionBlockHeader, Vote,
        },
    },
    types::{Height, Participant, View},
};
use bytes::BytesMut;
use commonware_codec::{Read, Write, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::variant::{MinPk, Variant},
    },
    sha256::Digest,
};
use commonware_math::algebra::Additive;
use std::{
    cell::Cell,
    collections::VecDeque,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

const PARTICIPANTS: usize = 50;
const PIPELINE_DEPTH: u32 = 64;

thread_local! {
    static HASH_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Default)]
struct CountedSha256(Sha256);

impl Hasher for CountedSha256 {
    type Digest = Digest;

    fn hash(parts: &[&[u8]]) -> Self::Digest {
        record_hashes(1);
        Sha256::hash(parts)
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        record_hashes(2);
        Sha256::hash_pair(left, right)
    }

    fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    fn finalize(self) -> (Self, Self::Digest) {
        record_hashes(1);
        let (hasher, digest) = self.0.finalize();
        (Self(hasher), digest)
    }
}

fn record_hashes(count: usize) {
    HASH_CALLS.with(|calls| calls.set(calls.get() + count));
}

fn take_hash_calls() -> usize {
    HASH_CALLS.with(|calls| calls.replace(0))
}

fn start_counted(protocol: Config<Digest>) -> Machine<CountedSha256, MinPk> {
    let profile = Profile::new(protocol, Role::Observer, Tuning::default()).unwrap();
    let mut machine = Machine::new(profile);
    let mut capabilities = VecDeque::new();
    capabilities.extend(machine.step(Input::Start).unwrap().into_capabilities());

    loop {
        while let Some(capability) = capabilities.pop_front() {
            match capability {
                Capability::Durability(DurabilityCapability::Persist(job)) => {
                    let step = machine
                        .step(Input::Persisted(BarrierAck::new(
                            job.id(),
                            job.generation(),
                            job.last_cursor(),
                        )))
                        .unwrap();
                    capabilities.extend(step.into_capabilities());
                }
                Capability::Leader(LeaderCapability::ArmTimer(_)) => {}
                other => panic!("unexpected counted-machine startup capability: {other:?}"),
            }
        }

        let polled = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = polled.work_remaining();
        capabilities.extend(polled.into_capabilities());
        if capabilities.is_empty() && !work_remaining {
            return machine;
        }
    }
}

fn empty_leader(protocol: &Config<Digest>) -> SignedLeaderBlock<MinPk, Digest> {
    let genesis = protocol.genesis().tips();
    let history = fabric::genesis_anchor(protocol);
    let proposals = genesis
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
    fabric::leader_block(protocol, 1, protocol.genesis().vqc(), history, proposals)
}

fn threshold_share(signer: u32) -> ThresholdShare<MinPk> {
    ThresholdShare::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

fn da_certificate(header: TransactionBlockHeader<Digest>) -> DaCertificate<MinPk, Digest> {
    let certificate = ThresholdCertificate::<MinPk>::new(<MinPk as Variant>::Signature::zero());
    let mut encoded = BytesMut::new();
    header.write(&mut encoded);
    certificate.write(&mut encoded);
    DaCertificate::read_cfg(&mut encoded.freeze(), &()).unwrap()
}

fn drain_validator(machine: &mut fabric::BenchMachine, effects: fabric::BenchCapabilities) {
    let mut queue = VecDeque::new();
    queue.extend(effects);
    let mut effects = queue;
    loop {
        while let Some(effect) = effects.pop_front() {
            let step = match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => machine
                    .step(Input::Persisted(BarrierAck::new(
                        job.id(),
                        job.generation(),
                        job.last_cursor(),
                    )))
                    .unwrap(),
                Capability::Verification(VerificationCapability::Verify(job)) => {
                    effects.extend(fabric::verify_all_true(machine, &job));
                    continue;
                }
                Capability::Producer(ProducerCapability::Validate(job)) => machine
                    .step(Input::BlockValidated(ValidationCompletion::new(
                        job.id(),
                        job.generation(),
                        BlockValidity::Valid,
                    )))
                    .unwrap(),
                Capability::Durability(DurabilityCapability::Released(job)) => {
                    match job.request() {
                        DurableEffect::Sign(SignRequest::DaVote(request)) => machine
                            .step(Input::EffectCompleted(EffectCompletion::Signed {
                                id: job.id(),
                                generation: job.generation(),
                                artifact: Arc::new(Artifact::DaVote(DaVote::new(
                                    request.header().clone(),
                                    threshold_share(0),
                                ))),
                            }))
                            .unwrap(),
                        DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {
                            panic!("unexpected signing request in discharge setup")
                        }
                        _ => machine
                            .step(Input::EffectCompleted(EffectCompletion::Delivered {
                                id: job.id(),
                                generation: job.generation(),
                            }))
                            .unwrap(),
                    }
                }
                Capability::Leader(LeaderCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::RecoverDa(_))
                | Capability::Leader(LeaderCapability::RecoverNullification(_))
                | Capability::Leader(LeaderCapability::AggregateVqc(_))
                | Capability::Leader(LeaderCapability::AggregateLqc(_)) => continue,
                other => panic!("unexpected discharge-setup effect: {other:?}"),
            };
            effects.extend(step.into_capabilities());
        }

        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        let work_remaining = polled.work_remaining();
        effects.extend(polled.into_capabilities());
        if effects.is_empty() && !work_remaining {
            return;
        }
    }
}

fn add_vote_obligation(machine: &mut fabric::BenchMachine, header: TransactionBlockHeader<Digest>) {
    let producer = header.chain().get();
    let artifact = Artifact::TransactionBlock(SignedTransactionBlock::new(
        header,
        fabric::attestation(producer),
    ));
    let effects = fabric::absorb(machine, vec![artifact]);
    drain_validator(machine, effects);
}

fn local_sign_completion_fixture() -> (fabric::BenchMachine, EffectCompletion<MinPk, Digest>) {
    let protocol = fabric::protocol(6, 64);
    let profile = Profile::new(
        protocol.clone(),
        Role::Validator(Participant::new(0)),
        Tuning::default(),
    )
    .unwrap();
    let mut machine = fabric::start(profile);
    let genesis = protocol.genesis().tips();
    let header = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis[1].digest(),
        fabric::digest(b"allocation sign completion", 0),
    )
    .unwrap();
    let artifact =
        Artifact::TransactionBlock(SignedTransactionBlock::new(header, fabric::attestation(1)));
    let mut effects = VecDeque::new();
    effects.extend(fabric::absorb(&mut machine, vec![artifact]));
    let mut completion = None;

    loop {
        while let Some(effect) = effects.pop_front() {
            let step = match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => machine
                    .step(Input::Persisted(BarrierAck::new(
                        job.id(),
                        job.generation(),
                        job.last_cursor(),
                    )))
                    .unwrap(),
                Capability::Verification(VerificationCapability::Verify(job)) => {
                    effects.extend(fabric::verify_all_true(&mut machine, &job));
                    continue;
                }
                Capability::Producer(ProducerCapability::Validate(job)) => machine
                    .step(Input::BlockValidated(ValidationCompletion::new(
                        job.id(),
                        job.generation(),
                        BlockValidity::Valid,
                    )))
                    .unwrap(),
                Capability::Durability(DurabilityCapability::Released(job)) => {
                    match job.request() {
                        DurableEffect::Sign(SignRequest::DaVote(request)) => {
                            assert!(completion.is_none(), "fixture issued one DA-vote signature");
                            completion = Some(EffectCompletion::Signed {
                                id: job.id(),
                                generation: job.generation(),
                                artifact: Arc::new(Artifact::DaVote(DaVote::new(
                                    request.header().clone(),
                                    threshold_share(0),
                                ))),
                            });
                            continue;
                        }
                        DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {
                            panic!("unexpected signing request in allocation corpus")
                        }
                        _ => machine
                            .step(Input::EffectCompleted(EffectCompletion::Delivered {
                                id: job.id(),
                                generation: job.generation(),
                            }))
                            .unwrap(),
                    }
                }
                Capability::Leader(LeaderCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::RecoverDa(_))
                | Capability::Leader(LeaderCapability::RecoverNullification(_))
                | Capability::Leader(LeaderCapability::AggregateVqc(_))
                | Capability::Leader(LeaderCapability::AggregateLqc(_)) => continue,
                other => panic!("unexpected allocation-corpus effect: {other:?}"),
            };
            effects.extend(step.into_capabilities());
        }

        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        let work_remaining = polled.work_remaining();
        effects.extend(polled.into_capabilities());
        if effects.is_empty() && !work_remaining {
            return (
                machine,
                completion.expect("fixture reaches one DA-vote signing request"),
            );
        }
        assert!(
            work_remaining || !effects.is_empty(),
            "sign request disappeared"
        );
    }
}

fn next_persist(
    machine: &mut fabric::BenchMachine,
    effects: fabric::BenchCapabilities,
) -> PersistJob<MinPk, Digest> {
    let mut queue = VecDeque::new();
    queue.extend(effects);
    let mut effects = queue;
    loop {
        while let Some(effect) = effects.pop_front() {
            match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => {
                    return job.job().clone();
                }
                Capability::Leader(LeaderCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::ArmTimer(_)) => {}
                other => panic!("unexpected pre-publication effect: {other:?}"),
            }
        }
        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        let work_remaining = polled.work_remaining();
        effects.extend(polled.into_capabilities());
        assert!(
            work_remaining || !effects.is_empty(),
            "signed completion did not stage persistence"
        );
    }
}

struct DischargeFixture {
    profile: Profile<Sha256, MinPk>,
    snapshot: Snapshot<MinPk, Digest>,
    certificate: Artifact<MinPk, Digest>,
    retired: EffectId,
}

fn discharge_fixture(obligations: usize) -> DischargeFixture {
    let protocol = fabric::protocol(6, 64);
    let profile = Profile::new(
        protocol.clone(),
        Role::Validator(Participant::new(0)),
        Tuning::default(),
    )
    .unwrap();
    let mut machine = fabric::start(profile.clone());
    let genesis = protocol.genesis().tips();
    let target = TransactionBlockHeader::new(
        protocol.epoch(),
        ChainId::new(1),
        Height::new(1),
        genesis[1].digest(),
        fabric::digest(b"discharge target", 0),
    )
    .unwrap();
    add_vote_obligation(&mut machine, target.clone());

    let mut parent = genesis[2].digest();
    for height in 1..obligations {
        let header = TransactionBlockHeader::new(
            protocol.epoch(),
            ChainId::new(2),
            Height::new(height as u64),
            parent,
            fabric::digest(b"unrelated obligation", height as u64),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>().digest();
        add_vote_obligation(&mut machine, header);
    }

    let snapshot = machine.snapshot();
    assert_eq!(snapshot.obligations().len(), obligations);
    let retired = snapshot
        .obligations()
        .values()
        .find_map(|obligation| {
            obligation
                .discharges()
                .iter()
                .find_map(|discharge| match discharge {
                    PublicationDischarge::VoteCertifiedAtLeast { chain, height, .. }
                        if *chain == target.chain() && *height == target.height() =>
                    {
                        Some(obligation.effect())
                    }
                    _ => None,
                })
        })
        .expect("target vote has a typed obligation");

    DischargeFixture {
        profile,
        snapshot,
        certificate: Artifact::DaCertificate(da_certificate(target)),
        retired,
    }
}

fn stage_discharge(
    fixture: &DischargeFixture,
) -> (fabric::BenchMachine, Capabilities<MinPk, Digest>, Duration) {
    let mut machine = Machine::restore(fixture.profile.clone(), fixture.snapshot.clone()).unwrap();
    let recovery = machine.step(Input::RecoveryComplete).unwrap();
    drain_validator(&mut machine, recovery.into_capabilities());

    let artifact = fixture.certificate.clone();
    let id = artifact.id::<Sha256>();
    let observed = machine.step(Input::Observe(vec![(id, artifact)])).unwrap();
    let verification = observed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("certificate enters verification");
    let verdicts = verification
        .items()
        .iter()
        .map(|item| Verdict::new(item.ticket(), true))
        .collect();
    let completion =
        VerificationCompletion::new(verification.id(), verification.generation(), verdicts);

    let start = Instant::now();
    let mut effects = machine
        .step(Input::Verified(completion))
        .unwrap()
        .into_capabilities();
    for _ in 0..8 {
        if effects.iter().any(|capability| {
            matches!(
                capability,
                Capability::Durability(DurabilityCapability::Persist(_))
            )
        }) {
            break;
        }
        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        effects.extend(polled.into_capabilities());
    }
    let elapsed = start.elapsed();
    assert!(
        effects.iter().any(|capability| matches!(
            capability,
            Capability::Durability(DurabilityCapability::Persist(_))
        )),
        "certificate must stage its durable successor"
    );
    (machine, effects, elapsed)
}

/// Fixed private-core benchmark workloads.
#[derive(Clone, Copy, Debug)]
pub enum MachineScenario {
    Poll64Budget1,
    Poll64Budget1024,
    Poll256Budget1,
    Poll256Budget1024,
    Obligation1,
    Obligation64,
    IngressAdmission,
    ObserveDuplicates,
}

/// Four independent zero-allocation protocol operations.
pub struct AllocationCases {
    duplicate_machine: fabric::BenchMachine,
    duplicate_input: Option<Input<MinPk, Digest>>,
    sign_machine: fabric::BenchMachine,
    sign_completion: Option<EffectCompletion<MinPk, Digest>>,
    release_machine: fabric::BenchMachine,
    release_acknowledgement: Option<BarrierAck>,
    reference_effect: DurableEffect<MinPk, Digest>,
}

impl AllocationCases {
    /// Builds all fixtures outside the measured allocation regions.
    pub fn new() -> Self {
        let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
        let profile = fabric::observer(protocol.clone());
        let leader = empty_leader(&protocol);
        let vote = Artifact::Vote(fabric::vote(&protocol, leader.block(), 0, 0));
        let reference_effect = DurableEffect::Broadcast(Arc::new(vote.clone()));
        let mut duplicate_machine = fabric::start(profile);
        fabric::absorb(&mut duplicate_machine, vec![Artifact::LeaderBlock(leader)]);
        fabric::absorb(&mut duplicate_machine, vec![vote.clone()]);
        let duplicate_input = Input::Observe(vec![(vote.id::<Sha256>(), vote)]);

        let (sign_machine, sign_completion) = local_sign_completion_fixture();
        let (mut release_machine, release_completion) = local_sign_completion_fixture();
        let signed = release_machine
            .step(Input::EffectCompleted(release_completion))
            .unwrap();
        let persist = next_persist(&mut release_machine, signed.into_capabilities());
        let release_acknowledgement =
            BarrierAck::new(persist.id(), persist.generation(), persist.last_cursor());

        Self {
            duplicate_machine,
            duplicate_input: Some(duplicate_input),
            sign_machine,
            sign_completion: Some(sign_completion),
            release_machine,
            release_acknowledgement: Some(release_acknowledgement),
            reference_effect,
        }
    }

    /// Executes duplicate ingress exactly once.
    pub fn duplicate_ingress(&mut self) {
        let input = self
            .duplicate_input
            .take()
            .expect("duplicate ingress is measured once");
        self.duplicate_machine.step(input).unwrap();
    }

    /// Executes local signing completion exactly once.
    pub fn sign_completion(&mut self) {
        let completion = self
            .sign_completion
            .take()
            .expect("sign completion is measured once");
        self.sign_machine
            .step(Input::EffectCompleted(completion))
            .unwrap();
    }

    /// Executes durable publication release exactly once.
    pub fn publication_release(&mut self) {
        let acknowledgement = self
            .release_acknowledgement
            .take()
            .expect("publication release is measured once");
        self.release_machine
            .step(Input::Persisted(acknowledgement))
            .unwrap();
    }

    /// Checks whether one publication carries the validator's signature.
    pub fn signature_reference(&mut self) {
        assert!(
            std::hint::black_box(&self.reference_effect)
                .references_own_signature(Some(Participant::new(0)))
        );
    }
}

impl Default for AllocationCases {
    fn default() -> Self {
        Self::new()
    }
}

/// Two independent idle transitions used by the allocation sanity check.
pub struct IdleAllocationCase {
    coalesced: fabric::BenchMachine,
    idle: fabric::BenchMachine,
}

impl IdleAllocationCase {
    /// Executes and checks the two idle operations.
    pub fn run(&mut self) {
        let wake = self.coalesced.step(Input::ProducerWake).unwrap();
        let poll = self.idle.poll(NonZeroUsize::MIN).unwrap();
        assert_eq!(wake.status(), &StepStatus::ProducerWake);
        assert!(wake.capabilities().is_empty());
        assert!(poll.capabilities().is_empty());
        assert!(!poll.work_remaining());
    }
}

/// Builds the idle fixtures outside the measured allocation region.
pub fn idle_allocation_case() -> IdleAllocationCase {
    let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
    let profile = fabric::observer(protocol);
    let mut coalesced = fabric::start(profile.clone());
    coalesced.step(Input::ProducerWake).unwrap();
    IdleAllocationCase {
        coalesced,
        idle: fabric::start(profile),
    }
}

/// Executes one fixed workload and returns only its measured region.
pub fn run_machine(scenario: MachineScenario) -> Duration {
    match scenario {
        MachineScenario::Poll64Budget1 => run_poll(64, 1),
        MachineScenario::Poll64Budget1024 => run_poll(64, 1_024),
        MachineScenario::Poll256Budget1 => run_poll(256, 1),
        MachineScenario::Poll256Budget1024 => run_poll(256, 1_024),
        MachineScenario::Obligation1 => run_obligation_discharge(1),
        MachineScenario::Obligation64 => run_obligation_discharge(64),
        MachineScenario::IngressAdmission => run_ingress_admission(),
        MachineScenario::ObserveDuplicates => run_observe_duplicates(),
    }
}

fn run_poll(artifacts: usize, budget: usize) -> Duration {
    let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
    let profile = fabric::observer(protocol.clone());
    let genesis = protocol.genesis().tips().to_vec();
    let mut headers: Vec<Vec<TransactionBlockHeader<Digest>>> = vec![Vec::new(); PARTICIPANTS];
    let mut cohorts: Vec<Vec<BenchArtifact>> = Vec::new();
    let mut remaining = artifacts;
    let mut height = 1u64;
    while remaining > 0 {
        let mut cohort = Vec::new();
        for chain in 0..PARTICIPANTS {
            if remaining == 0 {
                break;
            }
            let parent = match height {
                1 => genesis[chain].digest(),
                _ => headers[chain][height as usize - 2]
                    .block_ref::<Sha256>()
                    .digest(),
            };
            let header = TransactionBlockHeader::new(
                protocol.epoch(),
                genesis[chain].chain(),
                Height::new(height),
                parent,
                fabric::digest(b"block commitment", (chain as u64) << 32 | height),
            )
            .unwrap();
            cohort.push(Artifact::TransactionBlock(SignedTransactionBlock::new(
                header.clone(),
                fabric::attestation(chain as u32),
            )));
            headers[chain].push(header);
            remaining -= 1;
        }
        cohorts.push(cohort);
        height += 1;
    }

    let anchor = fabric::genesis_anchor(&protocol);
    let proposals = genesis
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                vec![headers[chain][0].commitment()],
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let leader = fabric::leader_block(&protocol, 1, protocol.genesis().vqc(), anchor, proposals);
    let votes = (0..protocol.codec_config().view_quorum())
        .map(|signer| fabric::vote(&protocol, leader.block(), signer as u32, 1))
        .collect::<Vec<_>>();
    let mut machine = fabric::start(profile);
    let mut staged = Capabilities::None;
    for cohort in cohorts {
        staged.extend(fabric::absorb(&mut machine, cohort));
    }
    staged.extend(fabric::absorb(
        &mut machine,
        vec![Artifact::LeaderBlock(leader)],
    ));
    staged.extend(fabric::absorb(
        &mut machine,
        votes.into_iter().map(Artifact::Vote).collect(),
    ));

    let started = Instant::now();
    fabric::drain(
        &mut machine,
        staged,
        NonZeroUsize::new(budget).unwrap(),
        &mut |job| panic!("unexpected resolution: {:?}", job.view()),
    );
    let elapsed = started.elapsed();
    let inspection = machine.inspect();
    assert_eq!(inspection.finality_floor(), View::zero());
    assert!(
        inspection
            .chain_progress()
            .iter()
            .all(|progress| progress.finalized() == Height::zero())
    );
    elapsed
}

fn run_obligation_discharge(obligations: usize) -> Duration {
    let fixture = discharge_fixture(obligations);
    let (mut machine, effects, elapsed) = stage_discharge(&fixture);
    drain_validator(&mut machine, effects);
    assert!(
        !machine
            .snapshot()
            .obligations()
            .contains_key(&fixture.retired),
        "the indexed successor must retire its exact vote"
    );
    elapsed
}

fn run_ingress_admission() -> Duration {
    let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
    let leader = empty_leader(&protocol);
    let vote = Artifact::Vote(fabric::vote(&protocol, leader.block(), 0, 0));
    let mut machine = start_counted(protocol);
    take_hash_calls();
    let probe = vote.clone();
    let _ = probe.id::<CountedSha256>();
    let identifier_hashes = take_hash_calls();
    let started = Instant::now();
    let id = vote.id::<CountedSha256>();
    let step = machine.step(Input::Observe(vec![(id, vote)])).unwrap();
    let elapsed = started.elapsed();
    let actual_hashes = take_hash_calls();
    assert!(matches!(
        step.status(),
        StepStatus::Observed(results)
            if results.len() == 1 && results[0].status() == ObservationStatus::Scheduled
    ));
    assert!(matches!(
        step.capabilities(),
        [Capability::Verification(VerificationCapability::Verify(_))]
    ));
    let machine_rehashes = usize::from(cfg!(debug_assertions));
    assert_eq!(actual_hashes, identifier_hashes * (1 + machine_rehashes));
    elapsed
}

fn run_observe_duplicates() -> Duration {
    let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
    let profile = fabric::observer(protocol.clone());
    let leader = empty_leader(&protocol);
    let votes = (0..protocol.codec_config().view_quorum())
        .map(|signer| {
            let vote = fabric::vote(&protocol, leader.block(), signer as u32, 0);
            Vote::new(
                vote.body().clone(),
                fabric::deferred_attestation(signer as u32),
            )
        })
        .collect::<Vec<_>>();
    let mut machine = fabric::start(profile);
    fabric::absorb(&mut machine, vec![Artifact::LeaderBlock(leader)]);
    fabric::absorb(
        &mut machine,
        votes.iter().cloned().map(Artifact::Vote).collect(),
    );
    let duplicates = votes
        .iter()
        .enumerate()
        .map(|(signer, vote)| {
            let copy = Vote::new(
                vote.body().clone(),
                fabric::deferred_attestation(signer as u32),
            );
            let artifact = Artifact::Vote(copy);
            (artifact.id::<Sha256>(), artifact)
        })
        .collect::<Vec<_>>();
    let started = Instant::now();
    let step = machine.step(Input::Observe(duplicates)).unwrap();
    let elapsed = started.elapsed();
    assert!(
        step.into_capabilities().is_empty(),
        "duplicates stage nothing"
    );
    elapsed
}
