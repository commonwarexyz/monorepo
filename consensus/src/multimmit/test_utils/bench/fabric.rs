//! Shared fixtures for fixed private-core benchmark scenarios.
//!
//! Artifacts are fabricated with zero-valued signatures and admitted through all-true
//! verification verdicts, so machine-driving benches measure scheduling, staging, and
//! ordering rather than cryptography.

use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Protocol, Role, Tuning},
        machine::{
            Capabilities, Capability, DurableEffect, EffectCompletion, EffectId, Input, Issued,
            Machine, PersistJob, ResolutionCompletion, ResolutionJob, ResolverCommand, VerifyJob,
            testing::{
                VerifyJobExt as _,
                fixtures::{self, TestConfig, attestation, genesis_tip_history, marked_digest},
            },
        },
        mocks::Committee,
        types::{
            Anchor, Artifact, Attestation, BlockRef, CertificateId, ChainId, ChainProposal,
            EpochGenesis, LeaderBlock, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, ViewProof, Vote,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_codec::{Encode, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, Variant},
    sha256::Digest,
};
use commonware_math::algebra::HashToGroup;
use std::{collections::VecDeque, num::NonZeroUsize};

pub(super) type BenchMachine = Machine<Sha256, MinPk>;
pub(super) type BenchCapability = Capability<MinPk, Digest>;
pub(super) type BenchCapabilities = Capabilities<MinPk, Digest>;
pub(super) type BenchArtifact = Artifact<MinPk, Digest>;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_BENCH";

/// Committee size of the machine-scale workload.
pub const MACHINE_SCALE_PARTICIPANTS: usize = 6;
/// Blocks each producer chain builds in the machine-scale block phase.
pub const MACHINE_SCALE_BLOCKS_PER_CHAIN: u64 = 16;
/// Views the machine-scale view phase advances.
pub const MACHINE_SCALE_VIEWS: u64 = 256;

/// Fixed logical completion costs for the machine-scale workload.
#[derive(Clone, Copy, Debug)]
pub struct CompletionProfile {
    /// Logical ticks one verification job or machine input takes.
    pub cpu_ticks: u64,
    /// Logical ticks one persistence barrier takes to be acknowledged.
    pub storage_ticks: u64,
    /// Logical ticks one resolution or publication takes.
    pub network_ticks: u64,
}

/// The completion costs the machine-scale benchmark uses.
pub const MACHINE_SCALE_COMPLETION_PROFILE: CompletionProfile = CompletionProfile {
    cpu_ticks: 2,
    storage_ticks: 8,
    network_ticks: 3,
};

/// Deterministic measurements from the fixed machine-scale workload.
#[derive(Clone, Copy, Debug)]
pub struct MachineScaleReport {
    /// Producer blocks the block phase finalizes.
    pub blocks: u64,
    /// Views advanced in the view phase.
    pub views: u64,
    /// Machine steps and polls the block phase made.
    pub block_machine_calls: u64,
    /// Machine steps and polls the view phase made.
    pub view_machine_calls: u64,
    /// Logical ticks the block phase took.
    pub block_logical_ticks: u64,
    /// Logical ticks the view phase took.
    pub view_logical_ticks: u64,
    /// Blocks finalized per thousand logical ticks.
    pub blocks_per_1k_ticks: u64,
    /// Views advanced per thousand logical ticks.
    pub views_per_1k_ticks: u64,
    /// 95th percentile completion latency, in logical ticks.
    pub completion_p95_ticks: u64,
    /// 99th percentile completion latency, in logical ticks.
    pub completion_p99_ticks: u64,
}

impl MachineScaleReport {
    /// Folds every field into one value, so a benchmark can keep the report alive and a change
    /// in any field is visible.
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

/// Builds a validated protocol configuration with fabricated genesis facts.
pub(super) fn protocol(participants: usize, pipeline_depth: u32) -> Protocol<Digest> {
    let epoch = Epoch::new(7);
    let tips = (0..participants)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain as u32),
                Height::zero(),
                marked_digest(b"bench genesis", chain as u64),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        marked_digest(b"bench leader genesis", 0),
        CertificateId::new(marked_digest(b"bench vqc genesis", 0)),
        CertificateId::new(marked_digest(b"bench lqc genesis", 0)),
        tips,
    )
    .unwrap();
    TestConfig::new(participants)
        .depth(pipeline_depth)
        .namespace(NAMESPACE)
        .genesis(genesis)
        .build()
}

/// Builds an observer profile with production-derived resource bounds.
pub(super) fn observer(protocol: Protocol<Digest>) -> Profile<Digest> {
    Profile::new::<MinPk>(protocol, Role::Observer, Tuning::default()).unwrap()
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
    protocol: &Protocol<Digest>,
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
    protocol: &Protocol<Digest>,
    leader: &LeaderBlock<MinPk, Digest>,
    signer: u32,
    position: u32,
) -> Vote<MinPk, Digest> {
    let codec = protocol.codec_config();
    fixtures::vote(leader, signer, &vec![position; codec.chains()], codec)
}

/// Starts a fresh live machine, acknowledging its generation barrier.
pub(super) fn start<H: Hasher<Digest = Digest>>(profile: Profile<H::Digest>) -> Machine<H, MinPk> {
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
pub(crate) fn absorb(machine: &mut BenchMachine, cohort: Vec<BenchArtifact>) -> BenchCapabilities {
    let identified = cohort
        .into_iter()
        .map(|artifact| artifact.identify::<Sha256>(&mut Vec::new()))
        .collect();
    let step = machine.step(Input::Observe(identified)).unwrap();
    let mut capabilities = BenchCapabilities::new();
    for capability in step.into_capabilities() {
        match capability {
            Capability::Verify(job) => {
                capabilities.extend(verify_all_true(machine, &job));
            }
            other => capabilities.push(other),
        }
    }
    capabilities
}

/// Completes one verification job with fabricated all-true verdicts.
pub(super) fn verify_all_true<H: Hasher<Digest = Digest>>(
    machine: &mut Machine<H, MinPk>,
    job: &VerifyJob<MinPk, Digest>,
) -> BenchCapabilities {
    machine
        .step(Input::Verified(job.all_valid()))
        .unwrap()
        .into_capabilities()
}

/// Returns whether the bench workloads leave `capability` unanswered.
///
/// Observers never run a chain plane, cast DA votes, or sign, so chain-plane commands and own-chain
/// DA commands are inert. Recoveries and aggregations stay unanswered because their completions
/// are not constructible outside the crate; both jobs are bounded and dangling them does not block
/// the scheduler. Timers, durability notices, and resolver controls need no completion.
pub(super) const fn inert(capability: &BenchCapability) -> bool {
    matches!(
        capability,
        Capability::Validator(..)
            | Capability::OwnChainDa(_)
            | Capability::Crypto(_)
            | Capability::Timer(_)
            | Capability::Acknowledged { .. }
            | Capability::Retain(_)
            | Capability::Retire(_)
            | Capability::Resolver(
                ResolverCommand::Cancel(_) | ResolverCommand::Reject(_) | ResolverCommand::Prune(_)
            )
    )
}

/// Drains queued machine work to idle with the given poll budget.
///
/// Persistence barriers are acknowledged inline, resolved verification jobs receive
/// all-true verdicts, resolutions are answered by `resolve`, publications receive volatile
/// delivery feedback, and timers are dropped. Signing, building, validation, recovery, and
/// aggregation must not appear for the observer machines these benches drive.
pub(super) fn drain<H: Hasher<Digest = Digest>, F>(
    machine: &mut Machine<H, MinPk>,
    capabilities: BenchCapabilities,
    budget: NonZeroUsize,
    resolve: &mut F,
) where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
{
    drain_with(machine, capabilities, budget, resolve, &mut |_| {});
}

/// [`drain`] with a sink observing every acknowledged persistence job.
pub(crate) fn drain_with<H: Hasher<Digest = Digest>, F, P>(
    machine: &mut Machine<H, MinPk>,
    capabilities: BenchCapabilities,
    budget: NonZeroUsize,
    resolve: &mut F,
    on_persist: &mut P,
) where
    F: FnMut(&ResolutionJob) -> ViewProof<MinPk, Digest>,
    P: FnMut(&PersistJob<MinPk, Digest>),
{
    let mut idle_polls = 0usize;
    let mut queue: VecDeque<_> = capabilities.into_iter().collect();
    loop {
        while let Some(capability) = queue.pop_front() {
            match capability {
                Capability::Journal(directive) => {
                    on_persist(&directive.job);
                    let step = machine.step(Input::Persisted(directive.job.ack())).unwrap();
                    queue.extend(step.into_capabilities());
                }
                Capability::Verify(job) => {
                    queue.extend(verify_all_true(machine, &job));
                }
                Capability::Resolver(ResolverCommand::Resolve(job)) => {
                    let step = machine
                        .step(Input::ResolutionCompleted(ResolutionCompletion::new(
                            job.issued(),
                            job.view(),
                            resolve(&job),
                        )))
                        .unwrap();
                    queue.extend(step.into_capabilities());
                }
                Capability::Released(job) => match job.request() {
                    DurableEffect::Publish(_) => delivered(machine, &mut queue, job.issued()),
                    DurableEffect::Sign(_) => unreachable!("observers never sign"),
                },
                capability if inert(&capability) => {}
                other => panic!("unexpected capability in bench drive: {other:?}"),
            }
        }
        let polled = machine.poll(budget).unwrap();
        let work_remaining = machine.work_remaining();
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
                marked_digest(b"machine scale block", marker),
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

    let anchor = genesis_tip_history(&protocol);
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
    let committee = Committee::<MinPk>::builder(91, MACHINE_SCALE_PARTICIPANTS as u32).build();
    let nullifications = (1..=MACHINE_SCALE_VIEWS)
        .map(|view| committee.nullification(View::new(view)))
        .collect::<Vec<_>>();
    let certificates = nullifications
        .iter()
        .cloned()
        .map(Artifact::Nullification)
        .collect::<Vec<_>>();
    let machine_profile =
        Profile::new::<MinPk>(committee.config, Role::Observer, Tuning::default()).unwrap();
    let mut machine = start(machine_profile);
    let mut total = LogicalRun::default();
    let mut completion_tails = Vec::with_capacity(certificates.len());

    for certificate in certificates {
        let run = observe_profiled(&mut machine, vec![certificate], profile, &mut |job| {
            let index = usize::try_from(job.view().get())
                .unwrap()
                .checked_sub(1)
                .expect("genesis requires no resolution");
            ViewProof::Nullification(Box::new(nullifications[index].clone()))
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
        .map(|artifact| artifact.identify::<Sha256>(&mut Vec::new()))
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
        let work_remaining = machine.work_remaining();
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
            Capability::Journal(_) => profile.storage_ticks,
            Capability::Verify(_) => profile.cpu_ticks,
            Capability::Resolver(ResolverCommand::Resolve(_)) => profile.network_ticks,
            Capability::Released(job) => match job.request() {
                DurableEffect::Publish(_) => profile.network_ticks,
                DurableEffect::Sign(_) => {
                    unreachable!("machine-scale observer workload never signs")
                }
            },
            capability if inert(capability) => continue,
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
        Capability::Journal(directive) => machine.step(Input::Persisted(directive.job.ack())),
        Capability::Verify(job) => machine.step(Input::Verified(job.all_valid())),
        Capability::Resolver(ResolverCommand::Resolve(job)) => {
            machine.step(Input::ResolutionCompleted(ResolutionCompletion::new(
                job.issued(),
                job.view(),
                resolve(&job),
            )))
        }
        Capability::Released(job) => machine.step(Input::EffectCompleted(
            EffectCompletion::delivered(job.issued()),
        )),
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

fn delivered<H: Hasher<Digest = Digest>>(
    machine: &mut Machine<H, MinPk>,
    queue: &mut VecDeque<BenchCapability>,
    issued: Issued<EffectId>,
) {
    let step = machine
        .step(Input::EffectCompleted(EffectCompletion::delivered(issued)))
        .unwrap();
    queue.extend(step.into_capabilities());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_scale_workload_runs() {
        let report = machine_scale_report();
        assert_eq!(report.views, MACHINE_SCALE_VIEWS);
        assert_eq!(
            report.blocks,
            MACHINE_SCALE_PARTICIPANTS as u64 * MACHINE_SCALE_BLOCKS_PER_CHAIN
        );
    }
}
