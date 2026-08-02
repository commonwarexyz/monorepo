//! Deterministic support for driving the production machine in tests and fuzz targets.

use super::super::{
    Artifact, ArtifactId, BarrierAck, BarrierId, Capability, Cursor, DomainEvent,
    DurabilityCapability, Input, Inspection, Machine, PersistJob, PollResult, Profile, ReplayError,
    Snapshot, Step, StepError, Verdict, VerificationCompletion, VerifyJob,
};
#[cfg(test)]
use super::super::{DurableEffect, VerificationCapability};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
#[cfg(test)]
use std::collections::VecDeque;
use std::{collections::BTreeMap, num::NonZeroUsize};

mod world;

/// Builds one observation input, pairing artifacts with the identifiers the batcher computes.
pub(in crate::multimmit::machine) fn cohort<H: Hasher, V: Variant>(
    artifacts: Vec<Artifact<V, H::Digest>>,
) -> Input<V, H::Digest> {
    Input::Observe(
        artifacts
            .into_iter()
            .map(|artifact| (artifact.id::<H>(), artifact))
            .collect(),
    )
}

/// Exercises a bounded three-replica production-machine schedule derived from arbitrary bytes.
///
/// Bytes 0 through 7 select the convergent historical schedule. The remaining input is at most 40
/// four-byte actions: ASCII opcode, replica selector, artifact/case selector, and ordering flags.
/// The stateful opcodes are `dDq` (artifact/cohort/duplicate), `vxm` (valid, invalid, malformed
/// verification), `sack` (acknowledge or crash at barrier cuts), `ptTw` (poll and timers), `bBV`
/// (build and validate), `rC` (resolution and cancellation), `gG` (aggregate), `iI` (sign), and
/// `lo` (delivery and obligation-successor acknowledgement). Inapplicable actions are skipped.
///
/// The same interpreter backs the generated unit property and the cargo-fuzz entry point. Every
/// applied action checks exact journal-prefix replay, finality state, publication oracles,
/// signature exposure, and production resource ceilings. The historical suffix then checks
/// convergence.
pub(crate) fn exercise_world(input: &[u8]) {
    world::exercise(input);
}

/// Failure reported by the deterministic runner or one of its symbolic executors.
#[derive(Debug, thiserror::Error)]
pub(super) enum RunnerError {
    /// The production machine rejected an input.
    #[error("machine step failed: {0}")]
    Step(#[from] StepError),
    /// Recovery rejected a checkpoint or journal entry.
    #[error("machine replay failed: {0}")]
    Replay(#[from] ReplayError),
    /// A persistence job is not the exact next symbolic journal batch.
    #[error("persistence job is not contiguous with the symbolic journal")]
    JournalOrder,
    /// A persistence acknowledgement precedes its symbolic durable append.
    #[error("persistence acknowledgement precedes the durable append")]
    NotDurable,
}

/// A completion chosen by a pluggable symbolic effect executor.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) enum Execution<V: Variant, D: Digest> {
    /// Submit a normal completion through the production input path.
    Input(Input<V, D>),
    /// Durably append and acknowledge an exact persistence job.
    Persist(PersistJob<V, D>),
}

/// Pluggable policy for completing immutable machine effects.
#[cfg(test)]
pub(super) trait Executor<V: Variant, D: Digest> {
    /// Returns a completion when this executor handles `effect`.
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>>;
}

/// Per-artifact symbolic verification policy keyed by exact artifact ID.
#[derive(Clone, Debug)]
pub(super) struct SymbolicVerifier<D: Digest> {
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

    /// Overrides the verdict for one exact artifact.
    #[cfg(test)]
    pub fn set(&mut self, artifact: ArtifactId<D>, valid: bool) {
        self.verdicts.insert(artifact, valid);
    }

    /// Builds an exact completion without bypassing production tickets.
    pub fn complete<V: Variant>(&self, job: &VerifyJob<V, D>) -> VerificationCompletion<D> {
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
        VerificationCompletion::new(job.id(), job.generation(), verdicts)
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> Executor<V, D> for SymbolicVerifier<D> {
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>> {
        let Capability::Verification(VerificationCapability::Verify(job)) = effect else {
            return None;
        };
        Some(Execution::Input(Input::Verified(self.complete(job))))
    }
}

/// Executor that synchronously makes persistence effects durable.
#[cfg(test)]
#[derive(Copy, Clone, Debug, Default)]
pub(super) struct SymbolicPersistence;

#[cfg(test)]
impl<V: Variant, D: Digest> Executor<V, D> for SymbolicPersistence {
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>> {
        let Capability::Durability(DurabilityCapability::Persist(job)) = effect else {
            return None;
        };
        Some(Execution::Persist(job.job().clone()))
    }
}

/// Single-machine deterministic runner backed by an in-memory symbolic journal.
pub(super) struct Runner<H: Hasher, V: Variant> {
    profile: Profile<H, V>,
    machine: Machine<H, V>,
    checkpoint: Snapshot<V, H::Digest>,
    journal: Vec<DomainEvent<V, H::Digest>>,
    persistence: BTreeMap<BarrierId, PersistJob<V, H::Digest>>,
}

impl<H: Hasher, V: Variant> Runner<H, V> {
    /// Creates a runner for a fresh, not-yet-started machine.
    pub fn new(profile: Profile<H, V>) -> Self {
        let machine = Machine::new(profile.clone());
        let checkpoint = machine.snapshot();
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

    /// Returns the production machine for read-only test assertions.
    #[cfg(test)]
    pub(super) const fn machine(&self) -> &Machine<H, V> {
        &self.machine
    }

    /// Submits one input through the production reducer.
    pub fn submit(
        &mut self,
        input: Input<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, RunnerError> {
        let step = self.machine.step(input)?;
        self.record_step(&step);
        Ok(step)
    }

    /// Runs one bounded machine-owned work turn and records its persistence effects.
    pub fn poll(&mut self, budget: NonZeroUsize) -> Result<PollResult<V, H::Digest>, RunnerError> {
        let result = self.machine.poll(budget)?;
        self.record_effects(result.capabilities());
        Ok(result)
    }

    /// Drains machine-owned work without executing the effects it emits.
    #[cfg(test)]
    pub fn settle(&mut self, step: Step<V, H::Digest>) -> Result<Step<V, H::Digest>, RunnerError> {
        let status = step.status().clone();
        let (mut effects, mut activities) = step.into_parts();
        loop {
            let polled = self.poll(NonZeroUsize::MAX)?;
            let work_remaining = polled.work_remaining();
            let (polled_effects, polled_activities) = polled.into_parts();
            effects.extend(polled_effects);
            activities.extend(polled_activities);
            if !work_remaining {
                return Ok(Step::for_tests(status, effects, activities));
            }
        }
    }

    /// Executes one effect when `executor` handles it.
    #[cfg(test)]
    pub fn execute(
        &mut self,
        executor: &mut impl Executor<V, H::Digest>,
        effect: &Capability<V, H::Digest>,
    ) -> Result<Option<Step<V, H::Digest>>, RunnerError> {
        let Some(execution) = executor.execute(effect) else {
            return Ok(None);
        };
        match execution {
            Execution::Input(input) => self.submit(input).map(Some),
            Execution::Persist(job) => self.persist(&job).map(Some),
        }
    }

    /// Drives handled effects in FIFO order and returns those left unhandled.
    ///
    /// Machine-owned work is polled between inputs, mirroring the production driver, so staging
    /// that the scheduler derives from an input is drained through the same executor.
    #[cfg(test)]
    pub fn drain(
        &mut self,
        executor: &mut impl Executor<V, H::Digest>,
        effects: impl IntoIterator<Item = Capability<V, H::Digest>>,
    ) -> Result<Vec<Capability<V, H::Digest>>, RunnerError> {
        let mut pending = VecDeque::from_iter(effects);
        let mut unhandled = Vec::new();
        for _ in 0..4_000 {
            while let Some(effect) = pending.pop_front() {
                let Some(step) = self.execute(executor, &effect)? else {
                    unhandled.push(effect);
                    continue;
                };
                pending.extend(step.into_capabilities());
            }
            let result = self.poll(NonZeroUsize::MIN)?;
            let work_remaining = result.work_remaining();
            pending.extend(result.into_capabilities());
            if pending.is_empty() && !work_remaining {
                return Ok(unhandled);
            }
        }
        panic!("draining did not quiesce: {unhandled:?}");
    }

    /// Appends a persistence job without returning its completion to the machine.
    pub fn append(&mut self, job: &PersistJob<V, H::Digest>) -> Result<(), RunnerError> {
        if self.persistence.get(&job.id()) != Some(job)
            || job.previous() != self.journal_cursor()
            || job.events().is_empty()
        {
            return Err(RunnerError::JournalOrder);
        }
        let mut expected = job.previous();
        for event in job.events() {
            expected = expected.next().ok_or(RunnerError::JournalOrder)?;
            if event.cursor() != expected {
                return Err(RunnerError::JournalOrder);
            }
        }
        self.journal.extend_from_slice(job.events());
        Ok(())
    }

    /// Acknowledges an already appended persistence job.
    pub fn acknowledge(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, RunnerError> {
        if self.journal_cursor() != job.last_cursor() {
            return Err(RunnerError::NotDurable);
        }
        let step = self.submit(Input::Persisted(BarrierAck::new(
            job.id(),
            job.generation(),
            job.last_cursor(),
        )))?;
        self.persistence.remove(&job.id());
        Ok(step)
    }

    /// Appends and acknowledges one exact persistence job.
    #[cfg(test)]
    pub fn persist(
        &mut self,
        job: &PersistJob<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, RunnerError> {
        self.append(job)?;
        self.acknowledge(job)
    }

    /// Discards volatile state, silently replays durable state, and requests recovery completion.
    pub fn crash_and_restore(&mut self) -> Result<Step<V, H::Digest>, RunnerError> {
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
    ) -> Result<Step<V, H::Digest>, RunnerError> {
        let step = self.machine.reserve_test_effect(effect)?;
        self.record_step(&step);
        Ok(step)
    }

    fn journal_cursor(&self) -> Cursor {
        self.journal
            .last()
            .map_or(self.checkpoint.cursor(), DomainEvent::cursor)
    }

    fn record_step(&mut self, step: &Step<V, H::Digest>) {
        self.record_effects(step.capabilities());
    }

    fn record_effects(&mut self, effects: &[Capability<V, H::Digest>]) {
        for effect in effects {
            if let Capability::Durability(DurabilityCapability::Persist(job)) = effect {
                self.persistence.insert(job.id(), job.job().clone());
            }
        }
    }
}
