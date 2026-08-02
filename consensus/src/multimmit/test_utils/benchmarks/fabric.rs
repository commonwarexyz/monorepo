//! Shared fixtures for fixed private-core benchmark scenarios.
//!
//! Artifacts are fabricated with zero-valued signatures and admitted through all-true
//! verification verdicts, so machine-driving benches measure scheduling, staging, and
//! ordering rather than cryptography.

use crate::{
    multimmit::{
        config::{Config, Limits},
        machine::{
            Artifact, BarrierAck, BlockValidity, Capabilities, Capability, DurabilityCapability,
            DurableEffect, EffectCompletion, EffectId, Input, LeaderCapability, Machine,
            PersistJob, ProducerCapability, Profile, ResolutionCompletion, ResolutionJob,
            ResolverCapability, Role, Tuning, ValidationCompletion, Verdict,
            VerificationCapability, VerificationCompletion, VerifyJob, ViewProof,
        },
        mocks::Committee,
        types::{
            Anchor, Attestation, BlockRef, CertificateId, ChainId, ChainProposal, EpochGenesis,
            Extension, Height, LeaderBlock, Position, SignedLeaderBlock, SignedTransactionBlock,
            TipRecord, TransactionBlockHeader, Vote, VoteBody, genesis_history,
        },
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_codec::{Encode, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, Variant},
    sha256::Digest,
};
use commonware_math::algebra::{Additive, HashToGroup};
use std::{collections::VecDeque, num::NonZeroUsize};

pub(super) type BenchMachine = Machine<Sha256, MinPk>;
pub(super) type BenchCapability = Capability<MinPk, Digest>;
pub(super) type BenchCapabilities = Capabilities<MinPk, Digest>;
pub(super) type BenchArtifact = Artifact<MinPk, Digest>;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_BENCH";

pub const MACHINE_SCALE_PARTICIPANTS: usize = 6;
pub const MACHINE_SCALE_BLOCKS_PER_CHAIN: u64 = 16;
pub const MACHINE_SCALE_VIEWS: u64 = 256;

/// Fixed logical completion costs for the machine-scale workload.
#[derive(Clone, Copy, Debug)]
pub struct CompletionProfile {
    pub cpu_ticks: u64,
    pub storage_ticks: u64,
    pub network_ticks: u64,
}

pub const MACHINE_SCALE_COMPLETION_PROFILE: CompletionProfile = CompletionProfile {
    cpu_ticks: 2,
    storage_ticks: 8,
    network_ticks: 3,
};

/// Deterministic measurements from the fixed machine-scale workload.
#[derive(Clone, Copy, Debug)]
pub struct MachineScaleReport {
    pub blocks: u64,
    pub views: u64,
    pub block_machine_calls: u64,
    pub view_machine_calls: u64,
    pub block_logical_ticks: u64,
    pub view_logical_ticks: u64,
    pub blocks_per_1k_ticks: u64,
    pub views_per_1k_ticks: u64,
    pub completion_p95_ticks: u64,
    pub completion_p99_ticks: u64,
}

impl MachineScaleReport {
    pub const fn checksum(&self) -> u64 {
        self.blocks
            .wrapping_add(self.views)
            .wrapping_add(self.block_machine_calls)
            .wrapping_add(self.view_machine_calls)
            .wrapping_add(self.block_logical_ticks)
            .wrapping_add(self.view_logical_ticks)
            .wrapping_add(self.blocks_per_1k_ticks)
            .wrapping_add(self.views_per_1k_ticks)
            .wrapping_add(self.completion_p95_ticks)
            .wrapping_add(self.completion_p99_ticks)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LogicalRun {
    machine_calls: u64,
    logical_ticks: u64,
}

impl LogicalRun {
    const fn add(&mut self, other: Self) {
        self.machine_calls += other.machine_calls;
        self.logical_ticks += other.logical_ticks;
    }
}

struct ScheduledCapability {
    ready_at: u64,
    sequence: u64,
    capability: BenchCapability,
}

pub(super) fn digest(label: &[u8], marker: u64) -> Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

/// Builds a validated protocol configuration with fabricated genesis facts.
pub(super) fn protocol(participants: usize, pipeline_depth: u32) -> Config<Digest> {
    let epoch = Epoch::new(7);
    let tips = (0..participants)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain as u32),
                Height::zero(),
                digest(b"bench genesis", chain as u64),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        digest(b"bench leader genesis", 0),
        CertificateId::new(digest(b"bench vqc genesis", 0)),
        CertificateId::new(digest(b"bench lqc genesis", 0)),
        tips,
    )
    .unwrap();
    Config::new(
        epoch,
        NAMESPACE,
        participants,
        (0..participants).map(Participant::from_usize).collect(),
        Limits::new(pipeline_depth, 1).unwrap(),
        genesis,
    )
    .unwrap()
}

/// Builds an observer profile with production-derived resource bounds.
pub(super) fn observer(protocol: Config<Digest>) -> Profile<Sha256, MinPk> {
    Profile::new(protocol, Role::Observer, Tuning::default()).unwrap()
}

/// Returns the commitment to the synthetic genesis history and tips.
pub(super) fn genesis_anchor(protocol: &Config<Digest>) -> Digest {
    TipRecord::new(
        genesis_history::<Sha256>(protocol.genesis()),
        protocol.genesis().tips().to_vec(),
    )
    .unwrap()
    .commitment::<Sha256>()
}

/// Fabricates an attributed signature; verdicts are fabricated, so it is never verified.
pub(super) fn attestation(signer: u32) -> Attestation<MinPk> {
    Attestation::new(
        Participant::new(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

/// Fabricates an undecoded attributed signature whose encoding is a real group element.
///
/// Forcing it pays the full point decompression and subgroup check, so a bench observing
/// such an artifact measures what decoding a gossiped copy actually costs.
pub(super) fn deferred_attestation(signer: u32) -> Attestation<MinPk> {
    let point = <MinPk as Variant>::Signature::hash_to_group(NAMESPACE, &signer.to_be_bytes());
    Attestation::new(
        Participant::new(signer),
        Lazy::deferred(&mut point.encode(), ()),
    )
}

/// Fabricates the scheduled leader's signed proposal for `view`.
pub(super) fn leader_block(
    protocol: &Config<Digest>,
    view: u64,
    parent: CertificateId<Digest>,
    history: Digest,
    proposals: Vec<ChainProposal<MinPk, Digest>>,
) -> SignedLeaderBlock<MinPk, Digest> {
    let block = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(view)),
        parent,
        history,
        proposals,
        protocol.codec_config(),
    )
    .unwrap();
    let leader = protocol.leader(View::new(view));
    SignedLeaderBlock::new(block, attestation(leader.get()))
}

/// Fabricates `signer`'s complete vote at `position` on every chain.
pub(super) fn vote(
    protocol: &Config<Digest>,
    leader: &LeaderBlock<MinPk, Digest>,
    signer: u32,
    position: u32,
) -> Vote<MinPk, Digest> {
    let chains = protocol.codec_config().chains();
    let body = VoteBody::for_leader::<Sha256, MinPk>(
        leader,
        vec![Position::new(position); chains],
        vec![Extension::empty(); chains],
        protocol.codec_config(),
    )
    .unwrap();
    Vote::new(body, attestation(signer))
}

/// Starts a fresh live machine, acknowledging its generation barrier.
pub(super) fn start(profile: Profile<Sha256, MinPk>) -> BenchMachine {
    let mut machine = Machine::new(profile);
    let step = machine.step(Input::Start).unwrap();
    drain(
        &mut machine,
        step.into_capabilities(),
        NonZeroUsize::MIN,
        &mut |_| panic!("startup requires no resolution"),
    );
    machine
}

/// Observes one cohort and applies an all-true verification completion without polling.
///
/// Returns capabilities staged by the two steps so callers can carry them into a drain.
pub(super) fn absorb(machine: &mut BenchMachine, cohort: Vec<BenchArtifact>) -> BenchCapabilities {
    let identified = cohort
        .into_iter()
        .map(|artifact| (artifact.id::<Sha256>(), artifact))
        .collect();
    let step = machine.step(Input::Observe(identified)).unwrap();
    let mut capabilities = BenchCapabilities::None;
    for capability in step.into_capabilities() {
        match capability {
            Capability::Verification(VerificationCapability::Verify(job)) => {
                capabilities.extend(verify_all_true(machine, &job));
            }
            other => capabilities.push(other),
        }
    }
    capabilities
}

/// Completes one verification job with fabricated all-true verdicts.
pub(super) fn verify_all_true(
    machine: &mut BenchMachine,
    job: &VerifyJob<MinPk, Digest>,
) -> BenchCapabilities {
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
        .unwrap()
        .into_capabilities()
}

/// Drains queued machine work to idle with the given poll budget.
///
/// Persistence barriers are acknowledged inline, resolved verification jobs receive
/// all-true verdicts, resolutions are answered by `resolve`, publications receive volatile
/// delivery feedback, and timers are dropped. Signing, building, validation, recovery, and
/// aggregation must not appear for the observer machines these benches drive.
pub(super) fn drain<F>(
    machine: &mut BenchMachine,
    capabilities: BenchCapabilities,
    budget: NonZeroUsize,
    resolve: &mut F,
) where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
{
    drain_with(machine, capabilities, budget, resolve, &mut |_| {});
}

/// [`drain`] with a sink observing every acknowledged persistence job.
pub(super) fn drain_with<F, P>(
    machine: &mut BenchMachine,
    capabilities: BenchCapabilities,
    budget: NonZeroUsize,
    resolve: &mut F,
    on_persist: &mut P,
) where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
    P: FnMut(&PersistJob<MinPk, Digest>),
{
    let mut idle_polls = 0usize;
    let mut queue = VecDeque::new();
    queue.extend(capabilities);
    loop {
        while let Some(capability) = queue.pop_front() {
            match capability {
                Capability::Durability(DurabilityCapability::Persist(job)) => {
                    on_persist(&job);
                    let step = machine
                        .step(Input::Persisted(BarrierAck::new(
                            job.id(),
                            job.generation(),
                            job.last_cursor(),
                        )))
                        .unwrap();
                    queue.extend(step.into_capabilities());
                }
                Capability::Verification(VerificationCapability::Verify(job)) => {
                    queue.extend(verify_all_true(machine, &job));
                }
                Capability::Resolver(ResolverCapability::Resolve(job)) => {
                    let step = machine
                        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
                            job.id(),
                            job.generation(),
                            job.view(),
                            resolve(&job),
                        )))
                        .unwrap();
                    queue.extend(step.into_capabilities());
                }
                Capability::Durability(DurabilityCapability::Released(job)) => {
                    match job.request() {
                        DurableEffect::Broadcast(_)
                        | DurableEffect::BroadcastBatch(_)
                        | DurableEffect::Propose(_)
                        | DurableEffect::Send(_)
                        | DurableEffect::SendBatch(_) => {
                            delivered(machine, &mut queue, job.id(), job.generation())
                        }
                        DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {
                            unreachable!("observers never sign")
                        }
                    }
                }
                Capability::Producer(ProducerCapability::Validate(job)) => {
                    let step = machine
                        .step(Input::BlockValidated(ValidationCompletion::new(
                            job.id(),
                            job.generation(),
                            BlockValidity::Valid,
                        )))
                        .unwrap();
                    queue.extend(step.into_capabilities());
                }
                Capability::Leader(LeaderCapability::ArmTimer(_))
                | Capability::Producer(ProducerCapability::ArmTimer(_)) => {}
                Capability::Resolver(
                    ResolverCapability::Cancel(_) | ResolverCapability::Reject(_),
                ) => {}
                // Observers never sign or build; recoveries and aggregations stay unanswered
                // because their completions are not constructible outside the crate. Both jobs
                // are bounded and dangling them does not block the scheduler.
                Capability::Leader(
                    LeaderCapability::AggregateVqc(_) | LeaderCapability::AggregateLqc(_),
                ) => {}
                Capability::Producer(ProducerCapability::RecoverDa(_))
                | Capability::Leader(LeaderCapability::RecoverNullification(_)) => {}
                other => panic!("unexpected capability in bench drive: {other:?}"),
            }
        }
        let polled = machine.poll(budget).unwrap();
        let work_remaining = polled.work_remaining();
        queue.extend(polled.into_capabilities());
        if queue.is_empty() {
            if !work_remaining {
                return;
            }
            idle_polls += 1;
            assert!(
                idle_polls < 1_000_000,
                "machine reports ready work but emits no capabilities"
            );
        } else {
            idle_polls = 0;
        }
    }
}

/// Runs fixed logical block/view work through one production machine.
///
/// This isolates reducer scaling. It is not a six-engine actor, storage, or network benchmark.
pub fn machine_scale_report() -> MachineScaleReport {
    let profile = MACHINE_SCALE_COMPLETION_PROFILE;
    let (block_run, mut completion_tails, blocks) = block_soak(profile);
    let (view_run, view_tails) = view_soak(profile);
    completion_tails.extend(view_tails);

    MachineScaleReport {
        blocks,
        views: MACHINE_SCALE_VIEWS,
        block_machine_calls: block_run.machine_calls,
        view_machine_calls: view_run.machine_calls,
        block_logical_ticks: block_run.logical_ticks,
        view_logical_ticks: view_run.logical_ticks,
        blocks_per_1k_ticks: rate_per_1k(blocks, block_run.logical_ticks),
        views_per_1k_ticks: rate_per_1k(MACHINE_SCALE_VIEWS, view_run.logical_ticks),
        completion_p95_ticks: percentile(&mut completion_tails, 95),
        completion_p99_ticks: percentile(&mut completion_tails, 99),
    }
}

fn block_soak(profile: CompletionProfile) -> (LogicalRun, Vec<u64>, u64) {
    let protocol = protocol(
        MACHINE_SCALE_PARTICIPANTS,
        MACHINE_SCALE_BLOCKS_PER_CHAIN as u32,
    );
    let genesis = protocol.genesis().tips().to_vec();
    let mut headers: Vec<Vec<TransactionBlockHeader<Digest>>> =
        vec![Vec::new(); MACHINE_SCALE_PARTICIPANTS];
    let mut cohorts = Vec::new();

    for height in 1..=MACHINE_SCALE_BLOCKS_PER_CHAIN {
        let mut cohort = Vec::with_capacity(MACHINE_SCALE_PARTICIPANTS);
        for chain in 0..MACHINE_SCALE_PARTICIPANTS {
            let parent = headers[chain]
                .last()
                .map_or(genesis[chain].digest(), |header| {
                    header.block_ref::<Sha256>().digest()
                });
            let marker = (chain as u64) << 32 | height;
            let header = TransactionBlockHeader::new(
                protocol.epoch(),
                genesis[chain].chain(),
                Height::new(height),
                parent,
                digest(b"machine scale block", marker),
            )
            .unwrap();
            cohort.push(Artifact::TransactionBlock(SignedTransactionBlock::new(
                header.clone(),
                attestation(chain as u32),
            )));
            headers[chain].push(header);
        }
        cohorts.push(cohort);
    }

    let anchor = genesis_anchor(&protocol);
    let history = anchor;
    let proposals = genesis
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                headers[chain]
                    .iter()
                    .map(TransactionBlockHeader::body_digest)
                    .collect(),
                protocol.codec_config().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let leader = leader_block(&protocol, 1, protocol.genesis().vqc(), history, proposals);
    let votes = (0..protocol.codec_config().view_quorum())
        .map(|signer| {
            Artifact::Vote(vote(
                &protocol,
                leader.block(),
                signer as u32,
                MACHINE_SCALE_BLOCKS_PER_CHAIN as u32,
            ))
        })
        .collect::<Vec<_>>();
    let mut machine = start(observer(protocol));
    let mut total = LogicalRun::default();
    let mut completion_tails = Vec::with_capacity(cohorts.len() + 2);
    let mut resolve = |job: &ResolutionJob| {
        panic!(
            "unexpected machine-scale block resolution: {:?}",
            job.view()
        )
    };

    for cohort in cohorts {
        let run = observe_profiled(&mut machine, cohort, profile, &mut resolve);
        completion_tails.push(run.logical_ticks);
        total.add(run);
    }
    let run = observe_profiled(
        &mut machine,
        vec![Artifact::LeaderBlock(leader)],
        profile,
        &mut resolve,
    );
    completion_tails.push(run.logical_ticks);
    total.add(run);
    let run = observe_profiled(&mut machine, votes, profile, &mut resolve);
    completion_tails.push(run.logical_ticks);
    total.add(run);
    let blocks = MACHINE_SCALE_PARTICIPANTS as u64 * MACHINE_SCALE_BLOCKS_PER_CHAIN;
    assert!(
        machine.inspect().finality().iter().any(|fact| {
            fact.blocks()
                .iter()
                .map(|block| block.height().get())
                .sum::<u64>()
                == blocks
        }),
        "the fixed block workload must establish local finality for every producer block"
    );
    (total, completion_tails, blocks)
}

fn view_soak(profile: CompletionProfile) -> (LogicalRun, Vec<u64>) {
    let committee = Committee::<MinPk>::new(
        91,
        MACHINE_SCALE_PARTICIPANTS as u32,
        Limits::new(2, 1).unwrap(),
    );
    let certificates = (1..=MACHINE_SCALE_VIEWS)
        .map(|view| Artifact::Nullification(committee.nullification(view)))
        .collect::<Vec<_>>();
    let machine_profile =
        Profile::new(committee.config, Role::Observer, Tuning::default()).unwrap();
    let mut machine = start(machine_profile);
    let mut total = LogicalRun::default();
    let mut completion_tails = Vec::with_capacity(certificates.len());

    for certificate in certificates {
        let run = observe_profiled(&mut machine, vec![certificate], profile, &mut |job| {
            panic!("unexpected machine-scale view resolution: {job:?}")
        });
        completion_tails.push(run.logical_ticks);
        total.add(run);
    }

    assert_eq!(
        machine.inspect().view(),
        View::new(MACHINE_SCALE_VIEWS + 1),
        "every nullification must complete its view"
    );
    (total, completion_tails)
}

fn observe_profiled<F>(
    machine: &mut BenchMachine,
    cohort: Vec<BenchArtifact>,
    profile: CompletionProfile,
    resolve: &mut F,
) -> LogicalRun
where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
{
    let identified = cohort
        .into_iter()
        .map(|artifact| (artifact.id::<Sha256>(), artifact))
        .collect();
    let step = machine.step(Input::Observe(identified)).unwrap();
    let mut run = LogicalRun {
        machine_calls: 1,
        logical_ticks: profile.cpu_ticks,
    };
    drain_profiled(
        machine,
        step.into_capabilities(),
        profile,
        resolve,
        &mut run,
    );
    run
}

fn drain_profiled<F>(
    machine: &mut BenchMachine,
    capabilities: BenchCapabilities,
    profile: CompletionProfile,
    resolve: &mut F,
    run: &mut LogicalRun,
) where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
{
    let mut pending = Vec::new();
    let mut sequence = 0;
    schedule_capabilities(
        capabilities,
        run.logical_ticks,
        profile,
        &mut sequence,
        &mut pending,
    );

    loop {
        charge_machine_call(run, profile);
        let polled = machine.poll(NonZeroUsize::MIN).unwrap();
        let work_remaining = polled.work_remaining();
        schedule_capabilities(
            polled.into_capabilities(),
            run.logical_ticks,
            profile,
            &mut sequence,
            &mut pending,
        );
        if work_remaining {
            assert!(
                run.machine_calls < 1_000_000,
                "machine-scale workload did not drain internal machine work"
            );
            continue;
        }
        let Some(ready_at) = pending.iter().map(|capability| capability.ready_at).min() else {
            return;
        };
        run.logical_ticks = run.logical_ticks.max(ready_at);

        let mut ready = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            if pending[index].ready_at > run.logical_ticks {
                index += 1;
                continue;
            }
            ready.push(pending.remove(index));
        }
        ready.sort_by_key(|capability| capability.sequence);

        for scheduled in ready {
            charge_machine_call(run, profile);
            let capabilities = complete_profiled_capability(machine, scheduled.capability, resolve);
            schedule_capabilities(
                capabilities,
                run.logical_ticks,
                profile,
                &mut sequence,
                &mut pending,
            );
        }
    }
}

fn schedule_capabilities(
    capabilities: BenchCapabilities,
    now: u64,
    profile: CompletionProfile,
    sequence: &mut u64,
    pending: &mut Vec<ScheduledCapability>,
) {
    for capability in capabilities {
        let delay = match &capability {
            Capability::Durability(DurabilityCapability::Persist(_)) => profile.storage_ticks,
            Capability::Verification(VerificationCapability::Verify(_))
            | Capability::Producer(ProducerCapability::Validate(_)) => profile.cpu_ticks,
            Capability::Resolver(ResolverCapability::Resolve(_)) => profile.network_ticks,
            Capability::Durability(DurabilityCapability::Released(job)) => match job.request() {
                DurableEffect::Broadcast(_)
                | DurableEffect::BroadcastBatch(_)
                | DurableEffect::Propose(_)
                | DurableEffect::Send(_)
                | DurableEffect::SendBatch(_) => profile.network_ticks,
                DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {
                    unreachable!("machine-scale observer workload never signs")
                }
            },
            Capability::Leader(
                LeaderCapability::ArmTimer(_)
                | LeaderCapability::AggregateVqc(_)
                | LeaderCapability::AggregateLqc(_)
                | LeaderCapability::RecoverNullification(_),
            )
            | Capability::Producer(
                ProducerCapability::ArmTimer(_) | ProducerCapability::RecoverDa(_),
            ) => continue,
            other => panic!("unexpected profiled capability: {other:?}"),
        };
        pending.push(ScheduledCapability {
            ready_at: now + delay,
            sequence: *sequence,
            capability,
        });
        *sequence += 1;
    }
}

fn complete_profiled_capability<F>(
    machine: &mut BenchMachine,
    capability: BenchCapability,
    resolve: &mut F,
) -> BenchCapabilities
where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
{
    let step = match capability {
        Capability::Durability(DurabilityCapability::Persist(job)) => {
            machine.step(Input::Persisted(BarrierAck::new(
                job.id(),
                job.generation(),
                job.last_cursor(),
            )))
        }
        Capability::Verification(VerificationCapability::Verify(job)) => {
            let verdicts = job
                .items()
                .iter()
                .map(|item| Verdict::new(item.ticket(), true))
                .collect();
            machine.step(Input::Verified(VerificationCompletion::new(
                job.id(),
                job.generation(),
                verdicts,
            )))
        }
        Capability::Resolver(ResolverCapability::Resolve(job)) => {
            machine.step(Input::ResolutionCompleted(ResolutionCompletion::new(
                job.id(),
                job.generation(),
                job.view(),
                resolve(&job),
            )))
        }
        Capability::Durability(DurabilityCapability::Released(job)) => {
            machine.step(Input::EffectCompleted(EffectCompletion::Delivered {
                id: job.id(),
                generation: job.generation(),
            }))
        }
        Capability::Producer(ProducerCapability::Validate(job)) => {
            machine.step(Input::BlockValidated(ValidationCompletion::new(
                job.id(),
                job.generation(),
                BlockValidity::Valid,
            )))
        }
        other => unreachable!("unscheduled capability reached completion: {other:?}"),
    }
    .unwrap();
    step.into_capabilities()
}

const fn charge_machine_call(run: &mut LogicalRun, profile: CompletionProfile) {
    run.machine_calls += 1;
    run.logical_ticks += profile.cpu_ticks;
}

const fn rate_per_1k(completions: u64, logical_ticks: u64) -> u64 {
    completions * 1_000 / logical_ticks
}

fn percentile(samples: &mut [u64], percent: usize) -> u64 {
    assert!(!samples.is_empty(), "percentile requires samples");
    samples.sort_unstable();
    let rank = (samples.len() * percent).div_ceil(100);
    samples[rank - 1]
}

fn delivered(
    machine: &mut BenchMachine,
    queue: &mut VecDeque<BenchCapability>,
    id: EffectId,
    generation: u64,
) {
    let step = machine
        .step(Input::EffectCompleted(EffectCompletion::Delivered {
            id,
            generation,
        }))
        .unwrap();
    queue.extend(step.into_capabilities());
}
