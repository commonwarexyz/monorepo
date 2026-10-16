//! Completions of work the machine issued.
//!
//! Every completion carries the [`Generation`](crate::multimmit::machine::Generation) of the
//! work it completes, and a completion from an earlier generation is stale. Completions that stage
//! a durable change park here and drain through the scheduler, so one queue orders every durable
//! transition the pipeline admits.

use super::{machine::Machine, store::ArtifactState};
use crate::multimmit::{
    config::Role,
    machine::{
        capability::{Capabilities, Capability, ResolverCommand},
        chain::producer::Producer,
        durability::{
            Change, DurableEffect, EffectCompletion, EffectId, EffectResult, SignRequest,
        },
        input::{
            BuildCompletion, CryptoCompletion, CustodyCompletion, Now, ObservationStatus,
            Rejection, Step, StepError, StepStatus, TimerFamily, ValidationCompletion,
        },
        resolution::ResolutionCompletion,
        scheduler::WorkKey,
        verification::{JobId, VerificationTicket},
    },
    types::{Activity, Artifact, ArtifactBatch, ArtifactId},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

/// Issued work whose completions are outstanding or parked.
pub(crate) struct Completions<V: Variant, D: Digest> {
    /// Outstanding verification jobs with their tickets, in verdict order.
    pub(in crate::multimmit::machine) verification_jobs:
        BTreeMap<JobId, Vec<VerificationTicket<D>>>,
    /// The identifier of the next verification job.
    pub(in crate::multimmit::machine) next_job: u64,
    /// Parked artifacts whose content became checkable while every verification job slot was
    /// taken. They stay parked and are settled again when a verification completes.
    pub(in crate::multimmit::machine) awaiting_job: BTreeSet<ArtifactId<D>>,
    /// Validated signing results awaiting their staging turn, by signing effect.
    pub(in crate::multimmit::machine) pending_signing: BTreeMap<EffectId, ArtifactBatch<V, D>>,
    /// Aggregation completions awaiting their staging turn, in arrival order.
    pub(in crate::multimmit::machine) pending_crypto: VecDeque<CryptoCompletion<V, D>>,
}

impl<V: Variant, D: Digest> Completions<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            verification_jobs: BTreeMap::new(),
            next_job: 0,
            awaiting_job: BTreeSet::new(),
            pending_signing: BTreeMap::new(),
            pending_crypto: VecDeque::new(),
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Applies the completion of one released outbox effect.
    ///
    /// A signing result must be the local validator's signature over exactly the reserved
    /// requests; it parks until the scheduler stages it. A delivery report is volatile feedback.
    pub(super) fn complete_effect(
        &mut self,
        completion: EffectCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let issued = completion.issued;
        let id = issued.id();
        if !self.is_current(issued) || self.completions.pending_signing.contains_key(&id) {
            return Ok(Step::stale());
        }
        let Some(effect) = self.durable_effect(id) else {
            return Ok(Step::stale());
        };
        let (sign, artifacts) = match (effect, completion.result) {
            (DurableEffect::Publish(_), EffectResult::Delivered) => {
                return Ok(Step::from(StepStatus::Accepted));
            }
            (DurableEffect::Sign(sign), EffectResult::Signed(artifacts)) => (sign, artifacts),
            _ => return Err(StepError::EffectMismatch),
        };
        let Role::Validator(signer) = self.profile.role() else {
            return Err(StepError::UnauthorizedEffect);
        };
        if self.signing_issued.get(&id) != Some(&issued.generation())
            || sign.requests().len() != artifacts.len()
            || !sign
                .requests()
                .iter()
                .zip(&artifacts)
                .all(|(request, artifact)| request.matches(signer, artifact))
        {
            return Err(StepError::EffectMismatch);
        }
        let max_bytes = self.profile.resources().max_artifact_bytes();
        if artifacts
            .iter()
            .any(|artifact| artifact.encoded_len() > max_bytes)
        {
            return Err(StepError::LocalArtifactTooLarge);
        }
        let mut step = Step::from(StepStatus::Accepted);
        let view = self.view();
        step.activities.extend(
            artifacts
                .iter()
                .filter_map(|artifact| match artifact.as_ref() {
                    Artifact::TransactionBlock(block) => Some(Activity::TransactionProposed {
                        block: block.header().block_ref::<H>(),
                        view,
                    }),
                    _ => None,
                }),
        );
        self.completions
            .pending_signing
            .insert(id, ArtifactBatch::from(artifacts));
        self.scheduler.enqueue(WorkKey::CompleteEffect(id));
        Ok(step)
    }

    /// Stages the parked signing result of effect `id`, replacing its reservation with the
    /// publication of the signed artifacts, and hands the artifacts to their components.
    pub(super) fn drive_signing_completion(
        &mut self,
        id: EffectId,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let Some(artifacts) = self.completions.pending_signing.remove(&id) else {
            return Ok(Capabilities::new());
        };
        if self.durable.state.signing(&id).is_none() {
            return Ok(Capabilities::new());
        }
        let served = self.served_updates(id, &artifacts)?;
        let publication = self.next_effect_id()?;
        let capabilities = self.reserve_change(Change::SignedArtifacts {
            sign: id,
            publication,
            artifacts: artifacts.clone(),
        })?;
        self.serve_when_durable(served.into_iter().map(Arc::new));
        self.signed(&artifacts, now)?;
        Ok(capabilities)
    }

    /// Returns the signed vote updates among `artifacts`, the result of signing effect `id`, in
    /// the form naming every chain that the resolver serves for this node's vote of their tag.
    fn served_updates(
        &self,
        id: EffectId,
        artifacts: &ArtifactBatch<V, H::Digest>,
    ) -> Result<Vec<Artifact<V, H::Digest>>, StepError> {
        let Some(sign) = self.durable.state.signing(&id) else {
            return Ok(Vec::new());
        };
        sign.requests()
            .iter()
            .zip(artifacts.iter())
            .filter_map(|(request, artifact)| match (request, artifact.as_ref()) {
                (SignRequest::Update(request), Artifact::Update(update)) => Some(
                    self.complete_update(request.content(), update.seq(), update.attestation())
                        .map(Artifact::Update),
                ),
                _ => None,
            })
            .collect()
    }

    /// Parks one aggregation completion of the current generation for staging.
    pub(super) fn park_crypto(
        &mut self,
        completion: CryptoCompletion<V, H::Digest>,
    ) -> Step<V, H::Digest> {
        if !self.is_current(completion.issued()) {
            return Step::stale();
        }
        self.completions.pending_crypto.push_back(completion);
        self.scheduler.enqueue(WorkKey::CompleteCrypto);
        Step::from(StepStatus::Accepted)
    }

    /// Hands the oldest parked aggregation completion to its component.
    pub(super) fn drive_crypto_completion(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let Some(completion) = self.completions.pending_crypto.pop_front() else {
            return Ok(Capabilities::new());
        };
        if !self.completions.pending_crypto.is_empty() {
            self.scheduler.enqueue(WorkKey::CompleteCrypto);
        }
        self.complete_crypto(completion, now)
    }

    /// Applies one application build completion for the producer's outstanding build.
    pub(super) fn complete_block_build(
        &mut self,
        completion: BuildCompletion<H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.is_current(completion.issued())
            || self
                .components
                .producer
                .as_ref()
                .and_then(Producer::building)
                != Some(completion.issued())
        {
            return Ok(Step::stale());
        }
        let capabilities = self.producer_built(completion, now)?;
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    /// Applies one custody completion for one of the producer's outstanding custody requests.
    pub(super) fn complete_block_custody(
        &mut self,
        completion: CustodyCompletion<H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.is_current(completion.issued())
            || self
                .components
                .producer
                .as_ref()
                .is_none_or(|producer| !producer.awaits_custody(completion.issued()))
        {
            return Ok(Step::stale());
        }
        let capabilities = self.producer_custodied(completion, now)?;
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    /// Applies one chain plane's verdict from the current generation.
    pub(super) fn complete_validation(
        &mut self,
        completion: ValidationCompletion<H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if completion.generation() != self.durable.state.generation {
            return Ok(Step::stale());
        }
        let capabilities = self.chain_validated(completion, now)?;
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    /// Admits one retrieved artifact through the observation path.
    ///
    /// A result that does not provide the requested key is rejected; one that admission refuses
    /// ends the attempt. Either way the key is requested again while an artifact waits on it. A
    /// refusal first settles the key's waiters at `now`: admission refuses deterministically what
    /// the node can no longer hold or read, and a waiter that no longer needs the key then stops
    /// waiting for it rather than having it fetched again.
    pub(super) fn complete_resolution(
        &mut self,
        completion: ResolutionCompletion<V, H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let job = completion.job();
        if !self.resolution.matches(job) {
            return Ok(Step::stale());
        }
        let key = job.key();
        let artifact = completion.into_artifact();
        let id = artifact.id;
        if !artifact.provisions.contains(&key) {
            self.resolution.resolved(key);
            let capabilities = self.retry_retrieval(job, ResolverCommand::Reject(job))?;
            return Ok(Step::new(
                StepStatus::ResolutionCompleted {
                    admission: ObservationStatus::Rejected(Rejection::Context),
                },
                capabilities,
            ));
        }
        let step = self.observe_artifacts(core::iter::once(artifact), now)?;
        let admission = match step.status() {
            StepStatus::Observed(results) => match results.as_slice() {
                [result] => result.status(),
                _ => return Err(StepError::CompletionMismatch),
            },
            _ => return Err(StepError::CompletionMismatch),
        };
        let pending = self
            .store
            .get(&id)
            .is_some_and(|entry| entry.state != ArtifactState::Ready);
        let mut capabilities = step.into_capabilities();
        match admission {
            ObservationStatus::Scheduled => self.resolution.begin_verification(key, id),
            ObservationStatus::Duplicate if pending => self.resolution.begin_verification(key, id),
            ObservationStatus::Duplicate => {
                self.resolution.resolved(key);
                capabilities.push(Capability::Resolver(ResolverCommand::Cancel(job)));
            }
            ObservationStatus::Rejected(_) => {
                self.resolution.resolved(key);
                capabilities.extend(self.settle(self.store.waiters(&key), now)?);
                capabilities.extend(self.retry_retrieval(job, ResolverCommand::Cancel(job))?);
            }
        }
        Ok(Step::new(
            StepStatus::ResolutionCompleted { admission },
            capabilities,
        ))
    }

    /// Fires the deadline of `family` once the clock reaches it.
    ///
    /// A tick carries no deadline: an early tick, or one for a deadline that was cancelled or
    /// replaced, is stale.
    pub(super) fn tick(
        &mut self,
        family: TimerFamily,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let deadline = &mut self.timers[family as usize];
        if deadline.is_none_or(|at| now < at) {
            return Ok(Step::stale());
        }
        *deadline = None;
        let capabilities = self.fire_timer(family, now)?;
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }
}
