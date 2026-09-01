//! Machine benchmarks: work polls, obligation discharge, ingress admission, and V-QC completion on
//! a 50-participant committee.

use super::fabric::{self, BenchArtifact};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Protocol, Role, Tuning},
        machine::{
            BarrierAck, Capabilities, Capability, CryptoCompletion, CryptoJob, DaVotesOffer,
            DischargeKind, DurableEffect, EffectCompletion, EffectId, Input, Machine,
            ObservationStatus, ObservedBlock, PersistDirective, PersistJob, ResolverCommand,
            SignRequest, Snapshot, StepStatus, TimerCommand, ValidatorCommand,
            VqcAggregateCompletion, VqcAggregateJob,
            testing::{
                VerifyJobExt as _,
                fixtures::{
                    CountingHasher, TestConfig, attestation, genesis_leader, genesis_tip_history,
                    marked_digest, symbolic_vqc, threshold_share, unsigned_da_certificate,
                },
            },
        },
        types::{
            Anchor, Artifact, ChainId, ChainProposal, DaVote, DigestedLeader, Extension,
            LeaderBlock, Position, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, Vote, VoteBody,
        },
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::{Faults as _, N5f1};
use core::fmt;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

const PARTICIPANTS: usize = 50;
const PIPELINE_DEPTH: u32 = 64;
/// Committee size of the obligation-discharge fixture.
const DISCHARGE_PARTICIPANTS: usize = 6;

fn empty_leader(protocol: &Protocol<Digest>) -> SignedLeaderBlock<MinPk, Digest> {
    let view = View::new(1);
    SignedLeaderBlock::new(
        genesis_leader(protocol, view),
        attestation(protocol.leader(view).get()),
    )
}

fn drain_validator(
    machine: &mut fabric::BenchMachine,
    effects: fabric::BenchCapabilities,
    mut signed: impl FnMut(EffectCompletion<MinPk, Digest>) -> Option<EffectCompletion<MinPk, Digest>>,
) {
    let mut effects: VecDeque<_> = effects.into_iter().collect();
    loop {
        while let Some(effect) = effects.pop_front() {
            let step = match effect {
                Capability::Journal(directive) => {
                    machine.step(Input::Persisted(directive.job.ack())).unwrap()
                }
                Capability::Verify(job) => {
                    effects.extend(fabric::verify_all_true(machine, &job));
                    continue;
                }
                // Drive the chain plane inline: the routed block is valid, so offer it
                // as the chain's eligible run for the machine to reserve, exactly as a task would.
                Capability::Validator(
                    _,
                    ValidatorCommand::Observe(ObservedBlock { block, .. }),
                ) => {
                    machine.offer_da_votes(DaVotesOffer {
                        generation: machine.generation(),
                        chain: block.header().chain(),
                        ready_through: block.header().height(),
                        candidates: vec![block],
                    });
                    continue;
                }
                Capability::Released(job) => match job.request().sign_requests() {
                    Some([SignRequest::DaVote(request)]) => {
                        let completion = EffectCompletion::signed(
                            job.issued(),
                            vec![Arc::new(Artifact::DaVote(DaVote::new(
                                request.header().clone(),
                                threshold_share(0),
                            )))],
                        );
                        let Some(completion) = signed(completion) else {
                            continue;
                        };
                        machine.step(Input::EffectCompleted(completion)).unwrap()
                    }
                    Some(_) => panic!("unexpected signing request in discharge setup"),
                    None => machine
                        .step(Input::EffectCompleted(EffectCompletion::delivered(
                            job.issued(),
                        )))
                        .unwrap(),
                },
                Capability::Resolver(ResolverCommand::Resolve(_)) => continue,
                effect if fabric::inert(&effect) => continue,
                other => panic!("unexpected discharge-setup effect: {other:?}"),
            };
            effects.extend(step.into_capabilities());
        }

        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        let work_remaining = machine.work_remaining();
        effects.extend(polled.into_capabilities());
        if effects.is_empty() && !work_remaining {
            return;
        }
    }
}

fn add_vote_obligation(machine: &mut fabric::BenchMachine, header: TransactionBlockHeader<Digest>) {
    let producer = header.chain().get();
    let artifact =
        Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(producer)));
    let effects = fabric::absorb(machine, vec![artifact]);
    drain_validator(machine, effects, Some);
}

fn local_sign_completion_fixture() -> (fabric::BenchMachine, EffectCompletion<MinPk, Digest>) {
    let protocol = fabric::protocol(DISCHARGE_PARTICIPANTS, PIPELINE_DEPTH);
    let profile = Profile::new::<MinPk>(
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
        marked_digest(b"allocation sign completion", 0),
    )
    .unwrap();
    let artifact = Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(1)));
    let effects = fabric::absorb(&mut machine, vec![artifact]);
    let mut completion = None;
    drain_validator(&mut machine, effects, |signed| {
        assert!(completion.is_none(), "fixture issued one DA-vote signature");
        completion = Some(signed);
        None
    });
    (
        machine,
        completion.expect("fixture reaches one DA-vote signing request"),
    )
}

fn next_persist(
    machine: &mut fabric::BenchMachine,
    effects: fabric::BenchCapabilities,
) -> PersistJob<MinPk, Digest> {
    let mut effects: VecDeque<_> = effects.into_iter().collect();
    loop {
        while let Some(effect) = effects.pop_front() {
            match effect {
                Capability::Journal(PersistDirective { job, .. }) => {
                    return job;
                }
                Capability::Timer(TimerCommand::View(_))
                | Capability::Timer(TimerCommand::Production(_))
                | Capability::Acknowledged { .. }
                | Capability::Retain(_)
                | Capability::Retire(_)
                | Capability::Resolver(_) => {}
                other => panic!("unexpected pre-publication effect: {other:?}"),
            }
        }
        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        let work_remaining = machine.work_remaining();
        effects.extend(polled.into_capabilities());
        assert!(
            work_remaining || !effects.is_empty(),
            "signed completion did not stage persistence"
        );
    }
}

struct DischargeFixture {
    profile: Profile<Digest>,
    snapshot: Snapshot<MinPk, Digest>,
    certificate: Artifact<MinPk, Digest>,
    retired: EffectId,
}

fn discharge_fixture(obligations: usize) -> DischargeFixture {
    let protocol = fabric::protocol(DISCHARGE_PARTICIPANTS, PIPELINE_DEPTH);
    let profile = Profile::new::<MinPk>(
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
        marked_digest(b"discharge target", 0),
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
            marked_digest(b"unrelated obligation", height as u64),
        )
        .unwrap();
        parent = header.block_ref::<Sha256>().digest();
        add_vote_obligation(&mut machine, header);
    }

    let snapshot = machine.live_snapshot_for_test();
    assert_eq!(snapshot.outbox().len(), obligations);
    let retired = snapshot
        .outbox()
        .iter()
        .find_map(|(id, entry)| {
            entry.discharges().iter().find_map(|discharge| {
                matches!(discharge.until(), DischargeKind::VoteCertifiedAtLeast { chain, height }
                    if chain == target.chain() && height == target.height())
                .then_some(*id)
            })
        })
        .expect("target vote has a typed obligation");

    DischargeFixture {
        profile,
        snapshot,
        certificate: Artifact::DaCertificate(unsigned_da_certificate(target)),
        retired,
    }
}

fn stage_discharge(
    fixture: &DischargeFixture,
) -> (fabric::BenchMachine, Capabilities<MinPk, Digest>, Duration) {
    let mut machine = Machine::restore(fixture.profile.clone(), fixture.snapshot.clone()).unwrap();
    let recovery = machine.step(Input::RecoveryComplete).unwrap();
    drain_validator(&mut machine, recovery.into_capabilities(), Some);

    let artifact = fixture.certificate.clone();
    let observed = machine
        .step(Input::Observe(vec![
            artifact.identify::<Sha256>(&mut Vec::new()),
        ]))
        .unwrap();
    let verification = observed
        .capabilities()
        .iter()
        .find_map(|effect| match effect {
            Capability::Verify(job) => Some(job.clone()),
            _ => None,
        })
        .expect("certificate enters verification");
    let completion = verification.all_valid();

    let start = Instant::now();
    let mut effects = machine
        .step(Input::Verified(completion))
        .unwrap()
        .into_capabilities();
    for _ in 0..8 {
        if effects
            .iter()
            .any(|capability| matches!(capability, Capability::Journal(_)))
        {
            break;
        }
        let polled = machine.poll(NonZeroUsize::new(1_024).unwrap()).unwrap();
        effects.extend(polled.into_capabilities());
    }
    let elapsed = start.elapsed();
    assert!(
        effects
            .iter()
            .any(|capability| matches!(capability, Capability::Journal(_))),
        "certificate must stage its durable successor"
    );
    (machine, effects, elapsed)
}

/// Fixed private-core benchmark workloads.
///
/// Each workload's [`Display`](fmt::Display) form is its `operation/key=value` benchmark label.
#[derive(Clone, Copy, Debug)]
pub enum MachineScenario {
    /// Drains `artifacts` producer headers, a leader block, and a view quorum of votes, spending at
    /// most `budget` work keys per poll.
    Poll {
        /// Producer headers observed before the leader block.
        artifacts: usize,
        /// Work keys one poll may spend.
        budget: usize,
    },
    /// Retires one DA-vote publication with a certificate while `obligations` publications are
    /// outstanding.
    ObligationDischarge {
        /// Publications outstanding when the certificate arrives.
        obligations: usize,
    },
    /// Admits one vote into a started machine.
    IngressAdmission,
    /// Observes a view quorum of votes the machine already holds.
    ObserveDuplicates,
    /// Completes one locally aggregated V-QC whose votes carry `payloads` proposed and `extensions`
    /// extended blocks across the chains, through its durable staging.
    VqcCompletion {
        /// Proposed blocks across every chain.
        payloads: u32,
        /// Extension blocks across every chain.
        extensions: u32,
    },
}

impl MachineScenario {
    /// Every workload the benchmark target measures.
    pub const ALL: [Self; 12] = [
        Self::Poll {
            artifacts: 64,
            budget: 1,
        },
        Self::Poll {
            artifacts: 64,
            budget: 1_024,
        },
        Self::Poll {
            artifacts: 256,
            budget: 1,
        },
        Self::Poll {
            artifacts: 256,
            budget: 1_024,
        },
        Self::ObligationDischarge { obligations: 1 },
        Self::ObligationDischarge { obligations: 64 },
        Self::IngressAdmission,
        Self::ObserveDuplicates,
        Self::VqcCompletion {
            payloads: 20,
            extensions: 12,
        },
        Self::VqcCompletion {
            payloads: 20,
            extensions: 72,
        },
        Self::VqcCompletion {
            payloads: 84,
            extensions: 12,
        },
        Self::VqcCompletion {
            payloads: 84,
            extensions: 72,
        },
    ];
}

impl fmt::Display for MachineScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poll { artifacts, budget } => write!(
                f,
                "poll/n={PARTICIPANTS} artifacts={artifacts} budget={budget}"
            ),
            Self::ObligationDischarge { obligations } => write!(
                f,
                "obligation_discharge/n={DISCHARGE_PARTICIPANTS} obligations={obligations} retired=1"
            ),
            Self::IngressAdmission => write!(f, "ingress_admission/n={PARTICIPANTS} artifacts=1"),
            Self::ObserveDuplicates => write!(
                f,
                "observe_duplicates/n={PARTICIPANTS} artifacts={}",
                N5f1::quorum(PARTICIPANTS)
            ),
            Self::VqcCompletion {
                payloads,
                extensions,
            } => write!(
                f,
                "vqc_completion/n={PARTICIPANTS} payloads={payloads} extensions={extensions}"
            ),
        }
    }
}

/// Hot-path machine operations, each prepared to run once, whose allocations a test counts.
pub struct HotPathOperations {
    duplicate_machine: fabric::BenchMachine,
    duplicate_input: Option<Input<MinPk, Digest>>,
    sign_machine: fabric::BenchMachine,
    sign_completion: Option<EffectCompletion<MinPk, Digest>>,
    release_machine: fabric::BenchMachine,
    release_acknowledgement: Option<BarrierAck>,
    reference_effect: DurableEffect<MinPk, Digest>,
}

impl HotPathOperations {
    /// Prepares every operation.
    pub fn new() -> Self {
        let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
        let profile = fabric::observer(protocol.clone());
        let leader = empty_leader(&protocol);
        let vote = Artifact::Vote(fabric::vote(&protocol, leader.block(), 0, 0));
        let reference_effect = DurableEffect::broadcast(Arc::new(vote.clone()));
        let mut duplicate_machine = fabric::start(profile);
        fabric::absorb(&mut duplicate_machine, vec![Artifact::LeaderBlock(leader)]);
        fabric::absorb(&mut duplicate_machine, vec![vote.clone()]);
        let duplicate_input = Input::Observe(vec![vote.identify::<Sha256>(&mut Vec::new())]);

        let (sign_machine, sign_completion) = local_sign_completion_fixture();
        let (mut release_machine, release_completion) = local_sign_completion_fixture();
        let signed = release_machine
            .step(Input::EffectCompleted(release_completion))
            .unwrap();
        let persist = next_persist(&mut release_machine, signed.into_capabilities());
        let release_acknowledgement = persist.ack();

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

    /// Observes a vote the machine already holds.
    pub fn duplicate_ingress(&mut self) {
        let input = self
            .duplicate_input
            .take()
            .expect("duplicate ingress is counted once");
        self.duplicate_machine.step(input).unwrap();
    }

    /// Completes a local DA-vote signature.
    pub fn sign_completion(&mut self) {
        let completion = self
            .sign_completion
            .take()
            .expect("sign completion is counted once");
        self.sign_machine
            .step(Input::EffectCompleted(completion))
            .unwrap();
    }

    /// Acknowledges the barrier that releases a signed publication.
    pub fn publication_release(&mut self) {
        let acknowledgement = self
            .release_acknowledgement
            .take()
            .expect("publication release is counted once");
        self.release_machine
            .step(Input::Persisted(acknowledgement))
            .unwrap();
    }

    /// Returns whether a relayed vote's publication references this validator's own signature.
    pub fn signature_reference(&self) -> bool {
        std::hint::black_box(&self.reference_effect)
            .publication()
            .is_some_and(|publication| {
                publication.references_own_signature(Some(Participant::new(0)))
            })
    }
}

impl Default for HotPathOperations {
    fn default() -> Self {
        Self::new()
    }
}

/// Machine operations that find no work, whose allocations a test counts.
pub struct IdleOperations {
    coalesced: fabric::BenchMachine,
    idle: fabric::BenchMachine,
}

impl IdleOperations {
    /// Prepares a machine whose producer wake is already pending and a quiescent machine.
    pub fn new() -> Self {
        let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
        let profile = fabric::observer(protocol);
        let mut coalesced = fabric::start(profile.clone());
        coalesced.step(Input::ProducerWake).unwrap();
        Self {
            coalesced,
            idle: fabric::start(profile),
        }
    }

    /// Wakes the producer again and returns whether the wake coalesced without new work.
    pub fn coalesced_wake(&mut self) -> bool {
        let wake = self.coalesced.step(Input::ProducerWake).unwrap();
        wake.status() == &StepStatus::Accepted && wake.capabilities().is_empty()
    }

    /// Polls the quiescent machine and returns whether it found no work.
    pub fn idle_poll(&mut self) -> bool {
        let poll = self.idle.poll(NonZeroUsize::MIN).unwrap();
        poll.capabilities().is_empty() && !self.idle.work_remaining()
    }
}

impl Default for IdleOperations {
    fn default() -> Self {
        Self::new()
    }
}

/// Executes one fixed workload and returns only its measured region.
pub fn run_machine(scenario: MachineScenario) -> Duration {
    match scenario {
        MachineScenario::Poll { artifacts, budget } => run_poll(artifacts, budget),
        MachineScenario::ObligationDischarge { obligations } => {
            run_obligation_discharge(obligations)
        }
        MachineScenario::IngressAdmission => run_ingress_admission(),
        MachineScenario::ObserveDuplicates => run_observe_duplicates(),
        MachineScenario::VqcCompletion {
            payloads,
            extensions,
        } => run_vqc_completion(payloads, extensions),
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
                marked_digest(b"block commitment", (chain as u64) << 32 | height),
            )
            .unwrap();
            cohort.push(Artifact::TransactionBlock(SignedTransactionBlock::new(
                header.clone(),
                attestation(chain as u32),
            )));
            headers[chain].push(header);
            remaining -= 1;
        }
        cohorts.push(cohort);
        height += 1;
    }

    let anchor = genesis_tip_history(&protocol);
    let proposals = genesis
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                vec![headers[chain][0].body_digest()],
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
    let mut staged = Capabilities::new();
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
    // The vote quorum finalizes each chain's one proposed block in the leader's pool. Without an
    // L-QC the finality floor stays at genesis.
    let inspection = machine.inspect();
    assert_eq!(inspection.finality_floor(), View::zero());
    assert!(
        inspection
            .chain_progress()
            .iter()
            .all(|progress| progress.finalized() == Height::new(1))
    );
    elapsed
}

fn run_obligation_discharge(obligations: usize) -> Duration {
    let fixture = discharge_fixture(obligations);
    let (mut machine, effects, elapsed) = stage_discharge(&fixture);
    drain_validator(&mut machine, effects, Some);
    assert!(
        !machine
            .live_snapshot_for_test()
            .outbox()
            .contains_key(&fixture.retired),
        "the indexed successor must retire its exact vote"
    );
    elapsed
}

fn run_ingress_admission() -> Duration {
    let protocol = fabric::protocol(PARTICIPANTS, PIPELINE_DEPTH);
    let leader = empty_leader(&protocol);
    let vote = Artifact::Vote(fabric::vote(&protocol, leader.block(), 0, 0));
    let mut machine = fabric::start::<CountingHasher>(fabric::observer(protocol));
    CountingHasher::take();
    let probe = vote.clone();
    let _ = probe.id::<CountingHasher>();
    let identifier_hashes = CountingHasher::take();
    let started = Instant::now();
    let step = machine
        .step(Input::Observe(vec![
            vote.identify::<CountingHasher>(&mut Vec::new()),
        ]))
        .unwrap();
    let elapsed = started.elapsed();
    let actual_hashes = CountingHasher::take();
    assert!(matches!(
        step.status(),
        StepStatus::Observed(results)
            if results.len() == 1 && results[0].status() == ObservationStatus::Scheduled
    ));
    assert!(matches!(step.capabilities(), [Capability::Verify(_)]));
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
            artifact.identify::<Sha256>(&mut Vec::new())
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

fn run_vqc_completion(payloads: u32, extensions: u32) -> Duration {
    let participants = u32::try_from(PARTICIPANTS).expect("the committee size is representable");
    let protocol = TestConfig::new(PARTICIPANTS)
        .depth(payloads.div_ceil(participants).max(2))
        .extensions(extensions.div_ceil(participants).max(1))
        .build();
    let codec = protocol.codec_config();
    let view = View::new(1);
    let empty = genesis_leader(&protocol, view);
    let proposed = LeaderBlock::new(
        empty.round(),
        empty.parent(),
        empty.history(),
        empty
            .proposals()
            .iter()
            .map(|proposal| {
                let chain = proposal.anchor().chain().get();
                ChainProposal::new(
                    proposal.anchor().chain(),
                    proposal.anchor().clone(),
                    (0..payloads)
                        .filter(|index| index % participants == chain)
                        .map(|index| marked_digest(b"vqc completion proposal", u64::from(index)))
                        .collect(),
                    codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect(),
        codec,
    )
    .unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&proposed),
        proposed
            .proposals()
            .iter()
            .map(|proposal| Position::new(u32::try_from(proposal.len()).unwrap()))
            .collect(),
        (0..participants)
            .map(|chain| {
                Extension::new(
                    (0..extensions)
                        .filter(|index| index % participants == chain)
                        .map(|index| marked_digest(b"vqc completion extension", u64::from(index)))
                        .collect(),
                    codec.extension_bound(),
                )
                .unwrap()
            })
            .collect(),
        codec,
    )
    .unwrap();

    let mut machine = fabric::start(fabric::observer(protocol.clone()));
    let leader = SignedLeaderBlock::new(proposed.clone(), attestation(protocol.leader(view).get()));
    let mut aggregation = None;
    let votes = (0..codec.view_quorum()).map(|signer| {
        Artifact::Vote(Vote::new(
            body.clone(),
            attestation(u32::try_from(signer).unwrap()),
        ))
    });
    for artifact in std::iter::once(Artifact::LeaderBlock(leader)).chain(votes) {
        let effects = fabric::absorb(&mut machine, vec![artifact]);
        if let Some(job) = drain_to_aggregation(&mut machine, effects) {
            assert!(aggregation.replace(job).is_none());
        }
    }
    let job = aggregation.expect("a unanimous transcript reserves a view certificate");
    let certificate = symbolic_vqc(proposed, &job.messages().collect::<Vec<_>>(), codec);
    let completion = VqcAggregateCompletion::prepare::<Sha256>(&job, certificate, codec).unwrap();

    let started = Instant::now();
    let mut effects = machine
        .step(Input::Crypto(CryptoCompletion::Vqc(Box::new(completion))))
        .unwrap()
        .into_capabilities();
    loop {
        let polled = machine.poll(NonZeroUsize::MAX).unwrap();
        let work_remaining = machine.work_remaining();
        effects.extend(polled.into_capabilities());
        if !work_remaining {
            break;
        }
    }
    let elapsed = started.elapsed();
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Capability::Journal(_))),
        "the completed certificate stages its durable retention"
    );
    elapsed
}

/// Acknowledges every barrier `effects` lead to and returns the V-QC aggregation they issue, if any.
fn drain_to_aggregation(
    machine: &mut fabric::BenchMachine,
    effects: fabric::BenchCapabilities,
) -> Option<VqcAggregateJob<MinPk, Digest>> {
    let mut aggregation = None;
    let mut effects: VecDeque<_> = effects.into_iter().collect();
    loop {
        while let Some(effect) = effects.pop_front() {
            match effect {
                Capability::Journal(directive) => {
                    let step = machine.step(Input::Persisted(directive.job.ack())).unwrap();
                    effects.extend(step.into_capabilities());
                }
                Capability::Crypto(CryptoJob::AggregateVqc(job)) => {
                    assert!(aggregation.replace(job).is_none());
                }
                Capability::Released(job) => {
                    let step = machine
                        .step(Input::EffectCompleted(EffectCompletion::delivered(
                            job.issued(),
                        )))
                        .unwrap();
                    effects.extend(step.into_capabilities());
                }
                Capability::Resolver(ResolverCommand::Resolve(_)) => {}
                effect if fabric::inert(&effect) => {}
                other => panic!("unexpected V-QC completion setup effect: {other:?}"),
            }
        }
        let polled = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = machine.work_remaining();
        effects.extend(polled.into_capabilities());
        if effects.is_empty() && !work_remaining {
            return aggregation;
        }
    }
}

#[cfg(test)]
mod scenario_tests {
    use super::*;

    #[test]
    fn every_machine_scenario_runs() {
        for scenario in MachineScenario::ALL {
            run_machine(scenario);
        }
    }

    #[test]
    fn scenario_labels_are_stable() {
        let labels = MachineScenario::ALL.map(|scenario| scenario.to_string());
        assert_eq!(
            labels,
            [
                "poll/n=50 artifacts=64 budget=1",
                "poll/n=50 artifacts=64 budget=1024",
                "poll/n=50 artifacts=256 budget=1",
                "poll/n=50 artifacts=256 budget=1024",
                "obligation_discharge/n=6 obligations=1 retired=1",
                "obligation_discharge/n=6 obligations=64 retired=1",
                "ingress_admission/n=50 artifacts=1",
                "observe_duplicates/n=50 artifacts=41",
                "vqc_completion/n=50 payloads=20 extensions=12",
                "vqc_completion/n=50 payloads=20 extensions=72",
                "vqc_completion/n=50 payloads=84 extensions=12",
                "vqc_completion/n=50 payloads=84 extensions=72",
            ]
        );
    }
}
