//! Deterministic drivers, symbolic effect executors, and capability queries for tests of the
//! production machine.

use super::super::{
    capability::{AppJob, Capability, CryptoJob, ResolverCommand},
    durability::{BatchId, Cursor, DomainEvent, DurableEffect, PersistJob, ReplayError, Snapshot},
    input::{DaVotesOffer, Input, PollResult, Step, StepError, StepStatus},
    job::Generation,
    reducer::machine::{Inspection, Machine},
    verification::{Verdict, VerificationCompletion, VerifyJob},
};
#[cfg(test)]
use super::{
    super::capability::Capabilities,
    executors::{Execution, Executor, SymbolicPersistence},
    extensions::{MachineExt as _, StepExt},
};
use crate::multimmit::{
    config::Profile,
    types::{Artifact, ArtifactId},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
#[cfg(test)]
use std::collections::VecDeque;
use std::{collections::BTreeMap, num::NonZeroUsize};

/// Builds one observation input, pairing artifacts with the identifiers ingress computes.
pub(in crate::multimmit::machine) fn cohort<H: Hasher, V: Variant>(
    artifacts: Vec<Artifact<V, H::Digest>>,
) -> Input<V, H::Digest> {
    Input::Observe(
        artifacts
            .into_iter()
            .map(|artifact| artifact.identify::<H>(&mut Vec::new()))
            .collect(),
    )
}

/// Failure reported by a deterministic driver or one of its symbolic executors.
#[derive(Debug, thiserror::Error)]
pub(in crate::multimmit::machine) enum DriverError {
    /// The production machine rejected an input.
    #[error("machine step failed: {0}")]
    Step(#[from] StepError),
    /// Recovery rejected a checkpoint or journal entry.
    #[error("machine replay failed: {0}")]
    Replay(#[from] ReplayError),
    /// A persistence job is not the next symbolic journal batch.
    #[error("persistence job is not contiguous with the symbolic journal")]
    JournalOrder,
    /// A persistence acknowledgement precedes its symbolic durable append.
    #[error("persistence acknowledgement precedes the durable append")]
    NotDurable,
}

/// How far a driver folds machine-owned work into the step it returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::machine) enum Until {
    /// Return the input's own step without polling.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only unit tests fold one input at a time")
    )]
    Step,
    /// Poll one work quantum at a time until the step carries a persistence barrier or the machine
    /// has no work left.
    Persist,
    /// Poll one work quantum at a time until the step carries a persistence barrier, the applied
    /// cursor advances, or the machine has no work left.
    ///
    /// Staging applies a change, so a staged batch that group commit holds behind an in-flight
    /// barrier still ends the fold.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only unit tests fold one input at a time")
    )]
    CursorAdvance,
    /// Poll with an unbounded budget until the machine has no work left.
    Quiesce,
}

/// Most polls or drain turns a driver spends before it reports that the machine never settles.
pub(in crate::multimmit::machine) const MAX_DRAIN_TURNS: usize = 4_096;

/// Per-artifact symbolic verification policy keyed by artifact ID.
#[derive(Clone, Debug)]
pub(in crate::multimmit::machine) struct SymbolicVerifier<D: Digest> {
    default: bool,
    verdicts: BTreeMap<ArtifactId<D>, bool>,
}

impl<D: Digest> SymbolicVerifier<D> {
    /// Creates a verifier with the given fallback verdict.
    pub const fn new(default: bool) -> Self {
        Self {
            default,
            verdicts: BTreeMap::new(),
        }
    }

    /// Overrides the verdict for one artifact.
    #[cfg(test)]
    pub fn set(&mut self, artifact: ArtifactId<D>, valid: bool) {
        self.verdicts.insert(artifact, valid);
    }

    /// Builds a completion without bypassing production tickets.
    pub fn complete<V: Variant>(&self, job: &VerifyJob<V, D>) -> VerificationCompletion<V, D> {
        let verdicts = job
            .items()
            .iter()
            .map(|item| {
                let ticket = item.ticket();
                let valid = self
                    .verdicts
                    .get(&ticket.artifact())
                    .copied()
                    .unwrap_or(self.default);
                Verdict::new(ticket, valid)
            })
            .collect();
        VerificationCompletion::new(job.issued(), verdicts)
    }
}

/// Completion of a verification job without real cryptography.
pub(crate) trait VerifyJobExt<V: Variant, D: Digest> {
    /// Completes every item of the job as valid.
    fn all_valid(&self) -> VerificationCompletion<V, D>;
}

impl<V: Variant, D: Digest> VerifyJobExt<V, D> for VerifyJob<V, D> {
    fn all_valid(&self) -> VerificationCompletion<V, D> {
        SymbolicVerifier::new(true).complete(self)
    }
}

/// A production machine, or a wrapper around one, that a deterministic test can drive.
pub(in crate::multimmit::machine) trait Drive<V: Variant, D: Digest> {
    /// Submits one input through the production reducer.
    fn submit(&mut self, input: Input<V, D>) -> Result<Step<V, D>, DriverError>;

    /// Runs one bounded machine-owned work turn.
    fn poll_with(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, D>, DriverError>;

    /// Returns whether another machine-owned quantum is ready.
    #[cfg(test)]
    fn work_remaining(&self) -> bool;

    /// Returns the cursor of the newest applied durable change.
    #[cfg(test)]
    fn applied_cursor(&self) -> Cursor;

    /// Makes `job` durable and returns the machine's step for its acknowledgement.
    #[cfg(test)]
    fn make_durable(&mut self, job: &PersistJob<V, D>) -> Result<Step<V, D>, DriverError>;

    /// Folds machine-owned work into `step` as far as `until` asks.
    ///
    /// # Panics
    ///
    /// Panics if the machine rejects a poll or does not settle within [`MAX_DRAIN_TURNS`] polls.
    #[cfg(test)]
    fn settle(&mut self, step: Step<V, D>, until: Until) -> Step<V, D> {
        let budget = match until {
            Until::Step => return step,
            Until::Persist | Until::CursorAdvance => NonZeroUsize::MIN,
            Until::Quiesce => NonZeroUsize::MAX,
        };
        let status = step.status().clone();
        let (mut effects, mut activities) = step.into_parts();
        for _ in 0..MAX_DRAIN_TURNS {
            if until != Until::Quiesce
                && effects
                    .iter()
                    .any(|effect| matches!(effect, Capability::Journal(_)))
            {
                return Step::for_tests(status, effects, activities);
            }
            let cursor = self.applied_cursor();
            let result = self
                .poll_with(budget)
                .unwrap_or_else(|error| panic!("machine poll failed: {error}"));
            let work_remaining = self.work_remaining();
            let (emitted, accepted) = result.into_parts();
            let quiesced = if until == Until::Quiesce {
                !work_remaining
            } else {
                emitted.is_empty() && !work_remaining
            };
            effects.extend(emitted);
            activities.extend(accepted);
            if quiesced || (until == Until::CursorAdvance && self.applied_cursor() != cursor) {
                return Step::for_tests(status, effects, activities);
            }
        }
        panic!("the machine did not settle within {MAX_DRAIN_TURNS} polls ({until:?})");
    }

    /// Makes `job` durable and folds the acknowledgement's follow-up work as far as `until` asks.
    ///
    /// # Panics
    ///
    /// Panics if the job is not the next durable batch or the machine rejects it.
    #[cfg(test)]
    fn persist(&mut self, job: &PersistJob<V, D>, until: Until) -> Step<V, D> {
        let step = self
            .make_durable(job)
            .unwrap_or_else(|error| panic!("persisting barrier {:?} failed: {error}", job.id()));
        self.settle(step, until)
    }

    /// Completes `job` with one verdict for every item and folds the follow-up work as far as
    /// `until` asks.
    ///
    /// # Panics
    ///
    /// Panics if the machine rejects the completion.
    #[cfg(test)]
    fn verify(&mut self, job: &VerifyJob<V, D>, valid: bool, until: Until) -> Step<V, D> {
        let step = self
            .submit(Input::Verified(SymbolicVerifier::new(valid).complete(job)))
            .unwrap_or_else(|error| panic!("verification completion failed: {error}"));
        self.settle(step, until)
    }

    /// Executes one effect when `executor` handles it.
    #[cfg(test)]
    fn execute(
        &mut self,
        executor: &mut impl Executor<V, D>,
        effect: &Capability<V, D>,
    ) -> Result<Option<Step<V, D>>, DriverError> {
        let Some(execution) = executor.execute(effect) else {
            return Ok(None);
        };
        match execution {
            Execution::Input(input) => self.submit(input).map(Some),
            Execution::Persist(job) => self.make_durable(&job).map(Some),
        }
    }

    /// Drives the effects `executor` handles in FIFO order and returns those left unhandled.
    ///
    /// Each handled effect's step is folded as far as `until` asks, and machine-owned work is
    /// polled one quantum at a time between inputs, mirroring the production driver. Releases a
    /// persistence directive carries ahead of its acknowledgement are returned unhandled.
    ///
    /// # Panics
    ///
    /// Panics if an execution fails or the machine does not quiesce within [`MAX_DRAIN_TURNS`]
    /// turns.
    #[cfg(test)]
    fn drain(
        &mut self,
        executor: &mut impl Executor<V, D>,
        effects: impl IntoIterator<Item = Capability<V, D>>,
        until: Until,
    ) -> Capabilities<V, D> {
        let mut pending = VecDeque::from_iter(effects);
        let mut unhandled = Capabilities::new();
        for _ in 0..MAX_DRAIN_TURNS {
            while let Some(effect) = pending.pop_front() {
                let Some(step) = self
                    .execute(executor, &effect)
                    .unwrap_or_else(|error| panic!("executing {effect:?} failed: {error}"))
                else {
                    unhandled.push(effect);
                    continue;
                };
                if let Capability::Journal(directive) = effect {
                    unhandled.extend(
                        directive
                            .release_after_enqueue
                            .into_iter()
                            .map(Capability::Released),
                    );
                }
                pending.extend(self.settle(step, until).into_capabilities());
            }
            let result = self
                .poll_with(NonZeroUsize::MIN)
                .unwrap_or_else(|error| panic!("machine poll failed: {error}"));
            let work_remaining = self.work_remaining();
            pending.extend(result.into_capabilities());
            if pending.is_empty() && !work_remaining {
                return unhandled;
            }
        }
        panic!("draining did not quiesce within {MAX_DRAIN_TURNS} turns: {unhandled:?}");
    }

    /// Persists every barrier `step` leads to, folding each acknowledgement until the cursor
    /// advances, and returns the other effects in issuance order.
    #[cfg(test)]
    fn drain_persisting(&mut self, step: Step<V, D>) -> Capabilities<V, D> {
        self.drain(
            &mut SymbolicPersistence,
            step.into_capabilities(),
            Until::CursorAdvance,
        )
    }
}

impl<H: Hasher, V: Variant> Drive<V, H::Digest> for Machine<H, V> {
    fn submit(&mut self, input: Input<V, H::Digest>) -> Result<Step<V, H::Digest>, DriverError> {
        Ok(self.step(input)?)
    }

    fn poll_with(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, H::Digest>, DriverError> {
        Ok(self.poll(budget)?)
    }

    #[cfg(test)]
    fn work_remaining(&self) -> bool {
        Self::work_remaining(self)
    }

    #[cfg(test)]
    fn applied_cursor(&self) -> Cursor {
        self.durable.state.cursor
    }

    #[cfg(test)]
    fn make_durable(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        Ok(self.step(Input::Persisted(job.ack()))?)
    }
}

/// Starts a fresh machine and acknowledges its generation barrier.
///
/// The view timer arms when the start stages, so the returned step merges the start's volatile
/// effects with the acknowledgement's follow-up work, folded as far as `until` asks.
#[cfg(test)]
pub(in crate::multimmit::machine) fn start<H: Hasher, V: Variant>(
    profile: Profile<H::Digest>,
    until: Until,
) -> (Machine<H, V>, Step<V, H::Digest>) {
    let mut machine = Machine::new(profile);
    let starting = machine.step(Input::Start).expect("a fresh machine starts");
    let (effects, _) = starting.into_parts();
    let mut volatile = Capabilities::new();
    let mut barrier = None;
    for effect in effects {
        match effect {
            Capability::Journal(directive) => barrier = Some(directive.job),
            effect => volatile.push(effect),
        }
    }
    let barrier = barrier.expect("starting stages the generation barrier");
    let started = machine.persist(&barrier, until);
    let status = started.status().clone();
    let (effects, activities) = started.into_parts();
    volatile.extend(effects);
    (machine, Step::for_tests(status, volatile, activities))
}

/// Single-machine deterministic driver backed by an in-memory symbolic journal.
pub(in crate::multimmit::machine) struct Driver<H: Hasher, V: Variant> {
    profile: Profile<H::Digest>,
    machine: Machine<H, V>,
    checkpoint: Snapshot<V, H::Digest>,
    journal: Vec<DomainEvent<V, H::Digest>>,
    persistence: BTreeMap<BatchId, PersistJob<V, H::Digest>>,
}

impl<H: Hasher, V: Variant> Driver<H, V> {
    /// Creates a driver for a fresh, not-yet-started machine.
    pub fn new(profile: Profile<H::Digest>) -> Self {
        let machine = Machine::new(profile.clone());
        let checkpoint = machine.live_snapshot_for_test();
        Self {
            profile,
            machine,
            checkpoint,
            journal: Vec::new(),
            persistence: BTreeMap::new(),
        }
    }

    /// Returns the production machine's normalized state.
    pub fn inspect(&self) -> Inspection<H::Digest> {
        self.machine.inspect()
    }

    /// Returns the production machine for read-only assertions.
    pub(in crate::multimmit::machine) const fn machine(&self) -> &Machine<H, V> {
        &self.machine
    }

    /// Returns the profile the machine runs with.
    pub(in crate::multimmit::machine) const fn profile(&self) -> &Profile<H::Digest> {
        &self.profile
    }

    /// Returns the checkpoint the symbolic journal starts from.
    pub(in crate::multimmit::machine) const fn checkpoint(&self) -> &Snapshot<V, H::Digest> {
        &self.checkpoint
    }

    /// Returns the durably appended events after the checkpoint, in cursor order.
    pub(in crate::multimmit::machine) fn journal(&self) -> &[DomainEvent<V, H::Digest>] {
        &self.journal
    }

    /// Returns the machine's process generation.
    pub const fn generation(&self) -> Generation {
        self.machine.generation()
    }

    /// Returns whether the next poll begins this node's vote pass for the current view.
    pub fn vote_build_due(&self) -> bool {
        self.machine.vote_build_due()
    }

    /// Applies a chain plane's DA-vote offer, as the core does outside its lanes.
    pub fn offer_da_votes(&mut self, offer: DaVotesOffer<V, H::Digest>) -> StepStatus<H::Digest> {
        self.machine.offer_da_votes(offer)
    }

    /// Appends a persistence job without returning its completion to the machine.
    pub fn append(&mut self, job: &PersistJob<V, H::Digest>) -> Result<(), DriverError> {
        if self.persistence.get(&job.id()) != Some(job)
            || job.previous() != self.journal_cursor()
            || job.events().is_empty()
        {
            return Err(DriverError::JournalOrder);
        }
        let mut expected = job.previous();
        for event in job.events() {
            expected = expected.next().ok_or(DriverError::JournalOrder)?;
            if event.cursor() != expected {
                return Err(DriverError::JournalOrder);
            }
        }
        self.journal.extend_from_slice(job.events());
        Ok(())
    }

    /// Acknowledges an already appended persistence job.
    pub fn acknowledge(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        if self.journal_cursor() != job.last_cursor() {
            return Err(DriverError::NotDurable);
        }
        let step = self.submit(Input::Persisted(job.ack()))?;
        self.persistence.remove(&job.id());
        Ok(step)
    }

    /// Discards volatile state, silently replays durable state, and requests recovery completion.
    pub fn crash_and_restore(&mut self) -> Result<Step<V, H::Digest>, DriverError> {
        let mut machine = Machine::restore(self.profile.clone(), self.checkpoint.clone())?;
        for event in &self.journal {
            machine.replay(event.clone())?;
        }
        self.machine = machine;
        self.persistence.clear();
        self.submit(Input::RecoveryComplete)
    }

    /// Reserves a synthetic durable action through the production durability path.
    #[cfg(test)]
    pub fn reserve(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        let step = self.machine.reserve_test_effect(effect)?;
        self.record_effects(step.capabilities());
        Ok(step)
    }

    fn journal_cursor(&self) -> Cursor {
        self.journal
            .last()
            .map_or(self.checkpoint.cursor(), DomainEvent::cursor)
    }

    fn record_effects(&mut self, effects: &[Capability<V, H::Digest>]) {
        for effect in effects {
            if let Capability::Journal(directive) = effect {
                self.persistence
                    .insert(directive.job.id(), directive.job.clone());
            }
        }
    }
}

impl<H: Hasher, V: Variant> Drive<V, H::Digest> for Driver<H, V> {
    fn submit(&mut self, input: Input<V, H::Digest>) -> Result<Step<V, H::Digest>, DriverError> {
        let step = self.machine.step(input)?;
        self.record_effects(step.capabilities());
        Ok(step)
    }

    fn poll_with(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, H::Digest>, DriverError> {
        let result = self.machine.poll(budget)?;
        self.record_effects(result.capabilities());
        Ok(result)
    }

    #[cfg(test)]
    fn work_remaining(&self) -> bool {
        self.machine.work_remaining()
    }

    #[cfg(test)]
    fn applied_cursor(&self) -> Cursor {
        self.machine.durable.state.cursor
    }

    #[cfg(test)]
    fn make_durable(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        self.append(job)?;
        self.acknowledge(job)
    }
}

/// Predicates over one capability, named by the job it carries.
pub(in crate::multimmit::machine) trait CapabilityExt {
    /// Returns whether this is a batch of artifacts to verify.
    fn is_verify(&self) -> bool;
    /// Returns whether this quarantines equivocating participants.
    fn is_quarantine(&self) -> bool;
    /// Returns whether this is a persistence barrier.
    fn is_journal(&self) -> bool;
    /// Returns whether this is an application build.
    fn is_build(&self) -> bool;
    /// Returns whether this is an application custody request.
    fn is_custody(&self) -> bool;
    /// Returns whether this is a view-proof fetch.
    fn is_resolve(&self) -> bool;
    /// Returns whether this cancels, rejects, or prunes resolver work.
    fn is_resolver_control(&self) -> bool;
    /// Returns whether this is a V-QC aggregation.
    fn is_aggregate_vqc(&self) -> bool;
    /// Returns whether this is an L-QC aggregation.
    fn is_aggregate_lqc(&self) -> bool;
    /// Returns whether this releases a signing choice of one request.
    fn is_sign(&self) -> bool;
    /// Returns whether this releases a signing choice of several requests.
    fn is_sign_batch(&self) -> bool;
    /// Returns whether this releases a publication.
    fn is_publish(&self) -> bool;
}

impl<V: Variant, D: Digest> CapabilityExt for Capability<V, D> {
    fn is_verify(&self) -> bool {
        matches!(self, Self::Verify(_))
    }

    fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine(_))
    }

    fn is_journal(&self) -> bool {
        matches!(self, Self::Journal(_))
    }

    fn is_build(&self) -> bool {
        matches!(self, Self::Application(AppJob::Build(_)))
    }

    fn is_custody(&self) -> bool {
        matches!(self, Self::Application(AppJob::Custody(_)))
    }

    fn is_resolve(&self) -> bool {
        matches!(self, Self::Resolver(ResolverCommand::Resolve(_)))
    }

    fn is_resolver_control(&self) -> bool {
        matches!(
            self,
            Self::Resolver(
                ResolverCommand::Cancel(_) | ResolverCommand::Reject(_) | ResolverCommand::Prune(_)
            )
        )
    }

    fn is_aggregate_vqc(&self) -> bool {
        matches!(self, Self::Crypto(CryptoJob::AggregateVqc(_)))
    }

    fn is_aggregate_lqc(&self) -> bool {
        matches!(self, Self::Crypto(CryptoJob::AggregateLqc(_)))
    }

    fn is_sign(&self) -> bool {
        matches!(
            self,
            Self::Released(job) if matches!(job.request().sign_requests(), Some([_]))
        )
    }

    fn is_sign_batch(&self) -> bool {
        matches!(
            self,
            Self::Released(job) if matches!(job.request().sign_requests(), Some([_, _, ..]))
        )
    }

    fn is_publish(&self) -> bool {
        matches!(
            self,
            Self::Released(job) if matches!(job.request(), DurableEffect::Publish(_))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Role,
            machine::{
                durability::{Change, DurableEffect},
                testing::{CapabilitiesExt as _, EffectExt},
                tests::fixtures::{active_driver, durable_effect, leader_artifact, no_vote},
            },
        },
        types::View,
    };
    use commonware_cryptography::Sha256;
    use std::sync::Arc;

    #[test]
    fn symbolic_verifier_uses_exact_production_tickets() {
        let mut runner = active_driver(Role::Observer);
        let accepted = leader_artifact(runner.machine(), 1);
        let rejected = leader_artifact(runner.machine(), 2);
        let accepted_id = accepted.id::<Sha256>();
        let rejected_id = rejected.id::<Sha256>();
        let observed = runner
            .submit(cohort::<Sha256, _>(vec![accepted, rejected]))
            .unwrap();
        let [Capability::Verify(job)] = observed.capabilities() else {
            panic!("both observations must share one verification job");
        };
        let mut verifier = SymbolicVerifier::new(false);
        verifier.set(accepted_id, true);

        let completed = runner
            .execute(&mut verifier, &Capability::Verify(job.clone()))
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
        let mut runner = active_driver(Role::Observer);
        let artifact = Artifact::NoVote(no_vote(runner.machine(), View::new(1), 0));

        // A relayed third-party artifact is independently verifiable, so its broadcast releases
        // with the staging step; only locally signed subjects wait for their barrier.
        let unpersisted = runner
            .reserve(DurableEffect::broadcast(Arc::new(artifact.clone())))
            .unwrap();
        assert!(
            unpersisted
                .capabilities()
                .iter()
                .any(|effect| matches!(effect, Capability::Journal(_)))
        );
        assert!(unpersisted.capabilities().iter().any(|effect| {
            matches!(durable_effect(effect).and_then(EffectExt::broadcast_one), Some(actual)
                if actual.as_ref() == &artifact)
        }));
        let recovery = runner.crash_and_restore().unwrap();
        // The reservation was never appended, so recovery forgets it; voiding the replayable
        // relay cannot equivocate this node.
        assert!(runner.inspect().outbox().is_empty());
        runner.persist(&recovery.persist_job(), Until::Step);

        let reserved = runner
            .reserve(DurableEffect::broadcast(Arc::new(artifact.clone())))
            .unwrap();
        let job = reserved.persist_job();
        let id = match job.events()[0].change() {
            Change::OutboxQueued { id, .. } => *id,
            _ => panic!("expected durable outbox reservation"),
        };
        runner.append(&job).unwrap();

        let recovery = runner.crash_and_restore().unwrap();
        assert_eq!(runner.inspect().outbox(), &[id]);
        let recovered = runner.persist(&recovery.persist_job(), Until::Step);
        let broadcast = recovered
            .capabilities()
            .iter()
            .find_map(|capability| match capability {
                Capability::Released(job) => Some(job),
                _ => None,
            })
            .expect("durable broadcast must be reissued after recovery");
        assert_eq!(broadcast.issued().id(), id);
        let Some(actual) = broadcast.request().broadcast_one() else {
            panic!("durable broadcast must be reissued after recovery");
        };
        assert_eq!(actual.as_ref(), &artifact);
    }
}
