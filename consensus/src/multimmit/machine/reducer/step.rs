//! Entry points: input steps, resumable passes, work polls, and replay.

use super::{
    InputPass, PassKind,
    completions::Completions,
    components::WorkStatus,
    machine::{Lifecycle, Machine},
    store::ArtifactStore,
};
use crate::multimmit::machine::{
    capability::{Capabilities, Capability, ResolverCommand},
    durability::{Change, DomainEvent, ReplayError},
    input::{Input, Now, PollResult, Step, StepError, StepStatus},
    scheduler::{Budget, WorkKey},
    util::Drive,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::num::NonZeroUsize;

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Advances one queued input by at most `budget` units at clock reading `now`.
    ///
    /// An observation prefix also stops at the verification batch bound, so one pass issues at
    /// most one verification job.
    pub(crate) fn advance(
        &mut self,
        pass: &mut InputPass<V, H::Digest>,
        budget: usize,
        now: Now,
    ) -> Result<Drive<Step<V, H::Digest>>, StepError> {
        match &mut pass.kind {
            PassKind::Atomic(input) => {
                let input = input
                    .take()
                    .expect("an applied input is not advanced again");
                Ok(Drive::done(1, self.step(input, now)?))
            }
            PassKind::Observe(artifacts) => {
                self.ensure_live()?;
                let items = artifacts
                    .len()
                    .min(budget)
                    .min(self.profile.resources().max_verification_batch());
                let mut step = self.observe_artifacts(artifacts.by_ref().take(items), now)?;
                step.activities.append(&mut self.activities);
                Ok(Drive {
                    processed: items,
                    complete: artifacts.len() == 0,
                    output: step,
                })
            }
        }
    }

    /// Applies one serialized input at clock reading `now`.
    pub(crate) fn step(
        &mut self,
        input: Input<V, H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        // Only lifecycle inputs and persistence acknowledgements arrive before the machine is live.
        if !matches!(
            input,
            Input::Start | Input::RecoveryComplete | Input::Persisted(_)
        ) {
            self.ensure_live()?;
        }
        let mut step = match input {
            Input::Start => self.start(Lifecycle::Fresh, now),
            Input::RecoveryComplete => self.start(Lifecycle::Recovering, now),
            Input::Persisted(ack) => self.complete_persistence(ack),
            Input::Observe(artifacts) => self.observe_artifacts(artifacts.into_iter(), now),
            Input::Verified(completion) => self.complete_verification(completion, now),
            Input::EffectCompleted(completion) => self.complete_effect(completion),
            Input::Tick(family) => self.tick(family, now),
            Input::BlockBuilt(completion) => self.complete_block_build(completion, now),
            Input::BlockCustodied(completion) => self.complete_block_custody(completion, now),
            Input::Validated(completion) => self.complete_validation(completion, now),
            Input::ResolutionCompleted(completion) => self.complete_resolution(completion, now),
            Input::Crypto(completion) => Ok(self.park_crypto(completion)),
        }?;
        step.capabilities.extend(self.take_quarantine());
        step.capabilities.extend(self.request_starved()?);
        step.activities.append(&mut self.activities);
        Ok(step)
    }

    /// Performs at most `budget` machine-owned work quanta at clock reading `now`.
    ///
    /// A component quantum ends the poll, so the caller yields before another one begins. The poll
    /// hands one eligible batch to the journal on exit.
    pub(crate) fn poll(
        &mut self,
        budget: NonZeroUsize,
        now: Now,
    ) -> Result<PollResult<V, H::Digest>, StepError> {
        self.ensure_live()?;
        let mut capabilities = Capabilities::new();
        let mut driven = None;
        for _ in 0..budget.get() {
            let Some(key) = self.scheduler.pop() else {
                break;
            };
            match key {
                WorkKey::CompleteEffect(id) => {
                    capabilities.extend(self.drive_signing_completion(id, now)?);
                }
                WorkKey::CompleteCrypto => capabilities.extend(self.drive_crypto_completion(now)?),
                WorkKey::Drive(component) => {
                    driven = Some(component);
                    let (status, emitted) =
                        self.drive_component(component, &mut Budget::quantum(), now)?;
                    capabilities.extend(emitted);
                    match status {
                        WorkStatus::Complete => {}
                        WorkStatus::Requeue => self.scheduler.enqueue(key),
                        WorkStatus::Blocked => self.scheduler.block(component),
                    }
                    break;
                }
            }
        }
        capabilities.extend(self.take_quarantine());
        capabilities.extend(self.request_starved()?);
        capabilities.extend(self.emit_staged());
        Ok(PollResult {
            capabilities,
            activities: core::mem::take(&mut self.activities),
            driven,
        })
    }

    /// Replays one contiguous durable event without emitting capabilities.
    pub(crate) fn replay(&mut self, event: DomainEvent<V, H::Digest>) -> Result<(), ReplayError> {
        if self.lifecycle != Lifecycle::Recovering || !self.pipeline.staged.is_empty() {
            return Err(ReplayError::Lifecycle);
        }
        self.apply_event(&event)?;
        self.pipeline.acked = self.durable.state.cursor;
        self.activities.clear();
        Ok(())
    }

    pub(super) fn ensure_live(&self) -> Result<(), StepError> {
        if self.lifecycle != Lifecycle::Live {
            return Err(StepError::Lifecycle);
        }
        Ok(())
    }

    /// Leaves the `from` lifecycle by staging the next process generation, then rebuilds the
    /// protocol components from durable state at clock reading `now`.
    ///
    /// The machine serves live inputs at once, but nothing it releases leaves the process before
    /// the generation is durable: the generation barrier is urgent, and its acknowledgement
    /// re-releases every outstanding signing reservation and publication under the new
    /// generation.
    fn start(&mut self, from: Lifecycle, now: Now) -> Result<Step<V, H::Digest>, StepError> {
        if self.lifecycle != from
            || !self.pipeline.staged.is_empty()
            || self.pipeline.acked != self.durable.state.cursor
        {
            return Err(StepError::Lifecycle);
        }
        let mut capabilities = self.advance_generation()?;
        self.lifecycle = Lifecycle::Live;
        capabilities.extend(self.start_components(now)?);
        capabilities.extend(self.emit_staged());
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    /// Stages the next process generation.
    fn advance_generation(&mut self) -> Result<Capabilities<V, H::Digest>, StepError> {
        let generation = self
            .durable
            .state
            .generation
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        self.reserve_change(Change::GenerationAdvanced(generation))
    }

    /// Restarts the live machine in process at clock reading `now`, after a durable change moved
    /// its state past the work in flight (an anchor).
    ///
    /// As a process restart does, it stages the next generation, so every completion of earlier
    /// work is stale and the outstanding effects are released again once the generation is
    /// durable, and rebuilds the components from durable state. It also cancels every retrieval
    /// and drops the peer artifacts held, which the rebuilt components no longer account for.
    ///
    /// # Errors
    ///
    /// Fails like [`Machine::reserve_change`] when no batch can take the generation.
    pub(in crate::multimmit::machine) fn restart_in_process(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let mut capabilities = self.advance_generation()?;
        capabilities.extend(
            self.resolution
                .take_all()
                .into_iter()
                .map(|job| Capability::Resolver(ResolverCommand::Cancel(job))),
        );
        self.store = ArtifactStore::new();
        self.completions = Completions::new();
        capabilities.extend(self.start_components(now)?);
        Ok(capabilities)
    }
}
