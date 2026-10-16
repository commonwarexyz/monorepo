//! A deterministic driver over the production machine and its symbolic journal.

use super::{
    executors::{Execution, Executor, ManualClock, SymbolicPersistence, SymbolicVerifier},
    extensions::StepExt as _,
};
use crate::{
    multimmit::{
        config::Profile,
        machine::{
            capability::{Capabilities, Capability, ResolverCommand},
            durability::{BatchId, Cursor, DomainEvent, PersistJob, ReplayError, Snapshot},
            input::{Input, Now, PollResult, Step, StepError},
            job::Generation,
            reducer::machine::{Inspection, Machine},
            verification::VerifyJob,
        },
        types::{Artifact, ChainId},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
};

/// Builds one observation input, identifying each artifact as ingress does.
pub(crate) fn cohort<H: Hasher, V: Variant>(
    artifacts: Vec<Artifact<V, H::Digest>>,
) -> Input<V, H::Digest> {
    Input::Observe(
        artifacts
            .into_iter()
            .map(|artifact| artifact.identify::<H>(&mut Vec::new()))
            .collect(),
    )
}

/// A failure reported by a driver.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DriverError {
    /// The machine rejected an input.
    #[error("machine step failed: {0}")]
    Step(#[from] StepError),
    /// Recovery rejected the checkpoint or a journal entry.
    #[error("machine replay failed: {0}")]
    Replay(#[from] ReplayError),
    /// A barrier is not the next batch of the symbolic journal.
    #[error("persistence job is not contiguous with the symbolic journal")]
    JournalOrder,
    /// An acknowledgement precedes its durable append.
    #[error("persistence acknowledgement precedes the durable append")]
    NotDurable,
}

/// How far a driver folds machine-owned work into the step it returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Until {
    /// Return the input's own step.
    Step,
    /// Poll one quantum at a time until the step carries a barrier or no work is left.
    Persist,
    /// Poll until no work is left.
    Quiesce,
}

/// The most polls or drain turns a driver spends before it reports that the machine never settles.
pub(crate) const MAX_DRAIN_TURNS: usize = 4_096;

/// A production machine, or a wrapper around one, that a deterministic test can drive.
pub(crate) trait Drive<V: Variant, D: Digest> {
    /// Submits one input through the production reducer.
    fn submit(&mut self, input: Input<V, D>) -> Result<Step<V, D>, DriverError>;

    /// Runs one bounded machine-owned work turn.
    fn poll_with(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, D>, DriverError>;

    /// Returns whether machine-owned work is ready.
    fn work_remaining(&self) -> bool;

    /// Returns the machine's process generation.
    fn current_generation(&self) -> Generation;

    /// Makes `job` durable and returns the machine's step for its acknowledgement.
    fn make_durable(&mut self, job: &PersistJob<V, D>) -> Result<Step<V, D>, DriverError>;

    /// Folds machine-owned work into `step` as far as `until` asks.
    ///
    /// # Panics
    ///
    /// Panics if the machine rejects a poll or does not settle within [`MAX_DRAIN_TURNS`] polls.
    fn settle(&mut self, step: Step<V, D>, until: Until) -> Step<V, D> {
        if until == Until::Step {
            return step;
        }
        let status = step.status().clone();
        let (mut capabilities, mut activities) = step.into_parts();
        for _ in 0..MAX_DRAIN_TURNS {
            if until == Until::Persist
                && capabilities
                    .iter()
                    .any(|c| matches!(c, Capability::Journal(_)))
            {
                return Step::for_tests(status, capabilities, activities);
            }
            if !self.work_remaining() {
                return Step::for_tests(status, capabilities, activities);
            }
            let (emitted, accepted) = self
                .poll_with(NonZeroUsize::MIN)
                .unwrap_or_else(|error| panic!("machine poll failed: {error}"))
                .into_parts();
            capabilities.extend(emitted);
            activities.extend(accepted);
        }
        panic!("the machine did not settle within {MAX_DRAIN_TURNS} polls ({until:?})");
    }

    /// Makes `job` durable and folds the acknowledgement's follow-up work as far as `until`
    /// asks.
    ///
    /// # Panics
    ///
    /// Panics if the job is not the next durable batch or the machine rejects it.
    fn persist(&mut self, job: &PersistJob<V, D>, until: Until) -> Step<V, D> {
        let step = self
            .make_durable(job)
            .unwrap_or_else(|error| panic!("persisting barrier {:?} failed: {error}", job.id()));
        self.settle(step, until)
    }

    /// Completes `job` with `valid` for every item.
    ///
    /// # Panics
    ///
    /// Panics if the machine rejects the completion.
    fn verify(&mut self, job: &VerifyJob<V, D>, valid: bool, until: Until) -> Step<V, D> {
        let step = self
            .submit(Input::Verified(SymbolicVerifier::new(valid).complete(job)))
            .unwrap_or_else(|error| panic!("verification completion failed: {error}"));
        self.settle(step, until)
    }

    /// Executes `capability` when `executor` handles it, returning the step its completion
    /// produced, if any.
    fn execute(
        &mut self,
        executor: &mut impl Executor<V, D>,
        capability: &Capability<V, D>,
    ) -> Result<Option<Option<Step<V, D>>>, DriverError> {
        let Some(execution) = executor.execute(capability, self.current_generation()) else {
            return Ok(None);
        };
        Ok(Some(match execution {
            Execution::Input(input) => Some(self.submit(input)?),
            Execution::Persist(job) => Some(self.make_durable(&job)?),
            Execution::Absorbed => None,
        }))
    }

    /// Executes the capabilities `executor` handles in FIFO order, polling machine-owned work
    /// between inputs, and returns the capabilities left unhandled in issuance order.
    ///
    /// Publications a barrier releases once the journal accepts it are returned unhandled
    /// alongside it.
    ///
    /// # Panics
    ///
    /// Panics if an execution fails or the machine does not quiesce within
    /// [`MAX_DRAIN_TURNS`] turns.
    fn drain(
        &mut self,
        executor: &mut impl Executor<V, D>,
        capabilities: impl IntoIterator<Item = Capability<V, D>>,
    ) -> Capabilities<V, D> {
        let mut pending = VecDeque::from_iter(capabilities);
        let mut unhandled = Capabilities::new();
        for _ in 0..MAX_DRAIN_TURNS {
            while let Some(capability) = pending.pop_front() {
                let executed = self
                    .execute(executor, &capability)
                    .unwrap_or_else(|error| panic!("executing {capability:?} failed: {error}"));
                let Some(step) = executed else {
                    unhandled.push(capability);
                    continue;
                };
                if let Capability::Journal(directive) = capability {
                    unhandled.extend(
                        directive
                            .release_after_enqueue
                            .into_iter()
                            .map(Capability::Released),
                    );
                }
                if let Some(step) = step {
                    pending.extend(step.into_capabilities());
                }
            }
            if !self.work_remaining() {
                return unhandled;
            }
            let result = self
                .poll_with(NonZeroUsize::MIN)
                .unwrap_or_else(|error| panic!("machine poll failed: {error}"));
            pending.extend(result.into_parts().0);
        }
        panic!("draining did not quiesce within {MAX_DRAIN_TURNS} turns: {unhandled:?}");
    }

    /// Persists every barrier `step` leads to and returns the other capabilities.
    fn drain_persisting(&mut self, step: Step<V, D>) -> Capabilities<V, D> {
        self.drain(&mut SymbolicPersistence, step.into_capabilities())
    }
}

/// One machine with an in-memory symbolic journal and a manual clock.
///
/// The journal starts at a checkpoint, takes barriers only in cursor order, and acknowledges a
/// barrier only once it is appended, so a crash between append and acknowledgement can be scripted.
pub(crate) struct Driver<H: Hasher, V: Variant> {
    profile: Profile<H::Digest>,
    machine: Machine<H, V>,
    checkpoint: Snapshot<V, H::Digest>,
    journal: Vec<DomainEvent<V, H::Digest>>,
    issued: BTreeMap<BatchId, PersistJob<V, H::Digest>>,
    clock: ManualClock,
    /// Every header floor the machine told the resolver, in issue order.
    settled_headers: Vec<(ChainId, Height)>,
}

impl<H: Hasher, V: Variant> Driver<H, V> {
    /// Creates a driver for a fresh, not yet started machine.
    pub(crate) fn new(profile: Profile<H::Digest>) -> Self {
        let machine = Machine::new(profile.clone());
        let checkpoint = machine.live_snapshot_for_test();
        Self {
            profile,
            machine,
            checkpoint,
            journal: Vec::new(),
            issued: BTreeMap::new(),
            clock: ManualClock::default(),
            settled_headers: Vec::new(),
        }
    }

    /// Returns every header floor the machine told the resolver, in issue order.
    pub(crate) fn settled_headers(&self) -> &[(ChainId, Height)] {
        &self.settled_headers
    }

    /// Returns the machine's normalized state.
    pub(crate) fn inspect(&self) -> Inspection<H::Digest> {
        self.machine.inspect()
    }

    /// Returns the machine for read-only assertions.
    pub(crate) const fn machine(&self) -> &Machine<H, V> {
        &self.machine
    }

    /// Returns the machine for test entry points into its durability path.
    pub(crate) const fn machine_mut(&mut self) -> &mut Machine<H, V> {
        &mut self.machine
    }

    /// Returns the checkpoint the symbolic journal starts from.
    pub(crate) const fn checkpoint(&self) -> &Snapshot<V, H::Digest> {
        &self.checkpoint
    }

    /// Returns the durably appended events after the checkpoint, in cursor order.
    pub(crate) fn journal(&self) -> &[DomainEvent<V, H::Digest>] {
        &self.journal
    }

    /// Returns the driver's clock.
    pub(crate) const fn clock(&self) -> &ManualClock {
        &self.clock
    }

    /// Returns the current clock reading.
    pub(crate) const fn now(&self) -> Now {
        self.clock.now()
    }

    /// Records the barriers among `capabilities` so they can be appended later, and applies
    /// their timer commands to the clock.
    pub(crate) fn record(&mut self, capabilities: &[Capability<V, H::Digest>]) {
        let generation = self.machine.generation();
        for capability in capabilities {
            match capability {
                Capability::Journal(directive) => {
                    self.issued
                        .insert(directive.job.id(), directive.job.clone());
                }
                Capability::Timer(_) => {
                    Executor::<V, H::Digest>::execute(&mut self.clock, capability, generation);
                }
                Capability::Resolver(ResolverCommand::SettleHeaders { chain, height }) => {
                    self.settled_headers.push((*chain, *height));
                }
                _ => {}
            }
        }
    }

    /// Appends `job` to the symbolic journal without acknowledging it.
    pub(crate) fn append(&mut self, job: &PersistJob<V, H::Digest>) -> Result<(), DriverError> {
        if self.issued.get(&job.id()) != Some(job)
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

    /// Acknowledges an appended barrier.
    pub(crate) fn acknowledge(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        if self.journal_cursor() < job.last_cursor() {
            return Err(DriverError::NotDurable);
        }
        let step = self.submit(Input::Persisted(job.ack()))?;
        self.issued.remove(&job.id());
        Ok(step)
    }

    /// Takes the checkpoint the machine cuts now, discarding the journal prefix it covers.
    ///
    /// Returns whether the machine could cut one.
    pub(crate) fn checkpoint_now(&mut self) -> bool {
        let Some(cut) = self.machine.checkpoint_cut() else {
            return false;
        };
        let cursor = cut.cursor();
        self.journal.retain(|event| event.cursor() > cursor);
        self.checkpoint = cut;
        true
    }

    /// Discards volatile state, restores the checkpoint, and replays the journal.
    pub(crate) fn crash(&mut self) -> Result<(), DriverError> {
        let mut machine = Machine::restore(self.profile.clone(), self.checkpoint.clone())?;
        for event in &self.journal {
            machine.replay(event.clone())?;
        }
        self.machine = machine;
        self.issued.clear();
        Ok(())
    }

    /// Crashes, recovers, and requests recovery completion.
    pub(crate) fn crash_and_restore(&mut self) -> Result<Step<V, H::Digest>, DriverError> {
        self.crash()?;
        self.submit(Input::RecoveryComplete)
    }

    /// Advances the clock by `millis` and submits a tick for every deadline the clock reached.
    pub(crate) fn advance(&mut self, millis: u64) -> Result<Vec<Step<V, H::Digest>>, DriverError> {
        self.elapse(millis)
            .into_iter()
            .map(|tick| self.submit(tick))
            .collect()
    }

    /// Advances the clock by `millis` and returns, unsubmitted, a tick for every deadline the
    /// clock reached, in deadline order.
    pub(in crate::multimmit::machine) fn elapse(
        &mut self,
        millis: u64,
    ) -> Vec<Input<V, H::Digest>> {
        self.clock.advance(millis)
    }

    fn journal_cursor(&self) -> Cursor {
        self.journal
            .last()
            .map_or(self.checkpoint.cursor(), DomainEvent::cursor)
    }
}

impl<H: Hasher, V: Variant> Drive<V, H::Digest> for Driver<H, V> {
    fn submit(&mut self, input: Input<V, H::Digest>) -> Result<Step<V, H::Digest>, DriverError> {
        let step = self.machine.step(input, self.clock.now())?;
        self.record(step.capabilities());
        Ok(step)
    }

    fn poll_with(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, H::Digest>, DriverError> {
        let result = self.machine.poll(budget, self.clock.now())?;
        self.record(result.capabilities());
        Ok(result)
    }

    fn work_remaining(&self) -> bool {
        self.machine.has_component_work()
    }

    fn current_generation(&self) -> Generation {
        self.machine.generation()
    }

    fn make_durable(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, DriverError> {
        self.append(job)?;
        self.acknowledge(job)
    }
}
