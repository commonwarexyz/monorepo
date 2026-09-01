//! Completion handlers for work the machine issued.

use super::{
    dependencies::{DerivedIdentity, ValidatedCertificate},
    drive::{WorkResult, WorkStatus},
    machine::Machine,
    store::ArtifactState,
};
use crate::{
    Epochable as _, Viewable,
    multimmit::{
        algebra::ValidatedLqc,
        config::Role,
        machine::{
            capability::{Capabilities, Capability, ChainCommand},
            durability::{Change, DurableEffect, EffectCompletion, EffectId, EffectResult},
            finality::PreparedLqc,
            input::{CryptoCompletion, ObservationStatus, Step, StepError, StepStatus},
            producer::{
                BuildCompletion, BuildOutcome, CustodyCancellation, CustodyCompletion,
                ProductionTimer,
            },
            resolution::ResolutionCompletion,
            scheduler::WorkKey,
            verification::{JobId, Observation, VerificationTicket},
            view::{NullificationRecoveryCompletion, ViewTimer, VqcAggregateCompletion},
        },
        types::{Activity, Artifact, ArtifactBatch, ArtifactId, BlockRef, DaCertificate},
    },
    types::{Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// A validated local signing completion awaiting its durability turn.
#[derive(Clone, Debug)]
pub(crate) enum PendingSigningCompletion<V: Variant, D: Digest> {
    One {
        artifact: Arc<Artifact<V, D>>,
        id: ArtifactId<D>,
    },
    Batch {
        artifacts: ArtifactBatch<V, D>,
        ids: Vec<ArtifactId<D>>,
    },
}

/// Work the machine issued whose completions are outstanding or parked.
pub(crate) struct Completions<V: Variant, D: Digest> {
    /// Outstanding verification jobs with their tickets, in verdict order.
    pub(in crate::multimmit::machine) verification_jobs:
        BTreeMap<JobId, Vec<VerificationTicket<D>>>,
    /// The identifier of the next verification job.
    pub(in crate::multimmit::machine) next_job: u64,
    /// Signing completions awaiting their durability turn, by effect.
    pub(in crate::multimmit::machine) pending_signing:
        BTreeMap<EffectId, PendingSigningCompletion<V, D>>,
    /// Recovery and aggregation completions parked while a persistence barrier is outstanding.
    ///
    /// Together with `prepared_lqc`, these entries are bounded by the machine's own crypto-task
    /// reservations, so retained completions never exceed the in-flight jobs.
    pub(in crate::multimmit::machine) pending_crypto: VecDeque<CryptoCompletion<V, D>>,
    /// The validated head L-QC completion moved out of the FIFO across its forwarding yield.
    pub(in crate::multimmit::machine) prepared_lqc: Option<PreparedLqc<V, D>>,
}

impl<V: Variant, D: Digest> Completions<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            verification_jobs: BTreeMap::new(),
            next_job: 0,
            pending_signing: BTreeMap::new(),
            pending_crypto: VecDeque::new(),
            prepared_lqc: None,
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    pub(super) fn wake_producer(&mut self) -> Result<Step<V, H::Digest>, StepError> {
        self.chain.wake_producer();
        self.wake_components();
        Ok(Step::from(StepStatus::Accepted))
    }

    pub(super) fn complete_block_build(
        &mut self,
        completion: BuildCompletion<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let outcome = self.chain.complete_build::<H>(completion)?;
        let status = match outcome {
            BuildOutcome::Stale => return Ok(Step::stale()),
            BuildOutcome::Superseded => StepStatus::StaleCompletion,
            // The chain retains the pending build sign request, so the drive quantum derives
            // and stages it when the barrier pipeline has room.
            BuildOutcome::Empty | BuildOutcome::Prepared => StepStatus::Accepted,
        };
        self.wake_components();
        Ok(Step::from(status))
    }

    pub(super) fn complete_block_custody(
        &mut self,
        completion: CustodyCompletion<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.chain.complete_custody(completion)? {
            return Ok(Step::stale());
        }
        self.wake_components();
        Ok(Step::from(StepStatus::Accepted))
    }

    pub(super) fn complete_custody_cancellation(
        &mut self,
        cancellation: CustodyCancellation,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self
            .chain
            .complete_custody_cancellation(cancellation, self.durable.state.generation)?
        {
            return Ok(Step::stale());
        }
        self.wake_components();
        Ok(Step::from(StepStatus::Accepted))
    }

    pub(super) fn complete_resolution(
        &mut self,
        completion: ResolutionCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.resolution.matches(&completion) {
            return Ok(Step::stale());
        }

        let view = completion.view();
        if !completion.proof().covers(view) {
            return Err(StepError::CompletionMismatch);
        }
        self.observe_resolution(view, completion.into_proof().into_artifact())
    }

    fn observe_resolution(
        &mut self,
        view: View,
        artifact: Artifact<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let artifact = artifact.identify::<H>(&mut self.store.id_scratch);
        let id = artifact.id;
        let step = self.observe_artifacts([artifact].into_iter())?;
        let status = match step.status() {
            StepStatus::Observed(results) => match results.as_slice() {
                [result] => result.status(),
                _ => return Err(StepError::CompletionMismatch),
            },
            _ => {
                self.cancel_resolution(view);
                return Ok(step);
            }
        };
        match status {
            ObservationStatus::Scheduled => {
                self.resolution.begin_verification(view, id);
            }
            ObservationStatus::Duplicate => {
                let entry = self
                    .store
                    .artifacts
                    .get(&id)
                    .ok_or(StepError::CompletionMismatch)?;
                if !matches!(entry.state, ArtifactState::Ready) {
                    self.resolution.begin_verification(view, id);
                } else {
                    self.cancel_resolution(view);
                    self.wake_components();
                }
            }
            ObservationStatus::Rejected(_) => {
                self.cancel_resolution(view);
                self.wake_components();
            }
        }
        Ok(Step::new(
            StepStatus::ResolutionCompleted { admission: status },
            step.into_capabilities(),
        ))
    }

    pub(super) fn fire_production_timer(
        &mut self,
        timer: ProductionTimer<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.chain.fire_timer(timer) {
            return Ok(Step::stale());
        }
        self.wake_components();
        Ok(Step::from(StepStatus::Accepted))
    }

    /// Durably admits and publishes a certificate the own-chain DA task recovered.
    ///
    /// The task assembles the certificate from admitted shares, so its cryptography is valid;
    /// the machine still owns the subject. A certificate whose block is no longer the current
    /// uncertified producer header (already certified, or retired while the recovery was in
    /// flight) is stale rather than fatal.
    pub(super) fn recovered_certificate(
        &mut self,
        block: BlockRef<H::Digest>,
        certificate: &DaCertificate<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let chain = block.chain().get() as usize;
        let above_tip = self
            .durable
            .state
            .certified_tips
            .get(chain)
            .is_some_and(|tip| block.height() > tip.height());
        if certificate.block_ref::<H>() != block
            || !above_tip
            || !self.chain.is_producer_header(certificate.header())
        {
            return Ok(Capabilities::new());
        }
        let artifact = Arc::new(Artifact::DaCertificate(certificate.clone()));
        let id = self.validate_self_admission(&artifact, None)?;
        if self.already_held(id) {
            return Ok(Capabilities::new());
        }
        let publication = self.next_effect_id()?;
        let height = certificate.header().height();
        let retired = self
            .obligations_retired_by_da(certificate.header().chain(), certificate.header().height());
        let remaining = self.durable_effect_count().saturating_sub(retired.len());
        if remaining >= self.profile.resources().max_outbox_effects() {
            return Err(StepError::OutboxFull);
        }
        let mut capabilities = self.reserve_change(Change::DaCertificateAdvanced {
            publication: Some(publication),
            retired_publications: retired,
            artifact: Arc::clone(&artifact),
        })?;
        self.self_admit(artifact, id)?;
        // Confirm the advanced anchor to the task so it prunes the settled pool.
        capabilities.push(Capability::OwnChainDa(ChainCommand::AnchorAdvanced(height)));
        Ok(capabilities)
    }

    fn complete_nullification_recovery(
        &mut self,
        completion: &NullificationRecoveryCompletion<V>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let Some(prepared) = self
            .views
            .prepare_nullification(completion, self.durable.state.generation)?
        else {
            return Ok(Capabilities::new());
        };
        let id = self.validate_self_admission(&prepared.artifact, None)?;
        if self.already_held(id) {
            self.views.finish_nullification(completion.issued().id());
            return Ok(Capabilities::new());
        }
        let capabilities = self.reserve_view_certificate(
            Arc::clone(&prepared.artifact),
            id,
            prepared.observation,
            None,
        )?;
        self.views.finish_nullification(completion.issued().id());
        Ok(capabilities)
    }

    fn complete_vqc_aggregation(
        &mut self,
        completion: &mut VqcAggregateCompletion<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let Some(prepared) = self
            .views
            .prepare_vqc(completion, self.durable.state.generation)?
        else {
            return Ok(Capabilities::new());
        };
        let derived = DerivedIdentity {
            id: completion.derived().artifact_id,
            encoded_len: prepared.artifact.encoded_len(),
        };
        let id = self.validate_self_admission(&prepared.artifact, Some(derived))?;
        if self.already_held(id) {
            self.views.finish_vqc(completion.issued().id());
            return Ok(Capabilities::new());
        }
        let capabilities = self.reserve_change(Change::ViewCertificateCreated {
            artifact: Arc::clone(&prepared.artifact),
        })?;
        // Capacity failures above leave the completion intact at the FIFO head. Once the event is
        // staged the completion is consumed, so admission takes its validation.
        self.self_admit_at(
            prepared.artifact,
            id,
            prepared.observation,
            Some(ValidatedCertificate::Vqc(completion.take_validated())),
        )?;
        self.wake_components();
        self.views.finish_vqc(completion.issued().id());
        Ok(capabilities)
    }

    fn complete_lqc_aggregation(
        &mut self,
        prepared: &mut PreparedLqc<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.validate_self_admission(
            &prepared.artifact,
            Some(DerivedIdentity {
                id: prepared.artifact_id,
                encoded_len: prepared.encoded_len,
            }),
        )?;
        if self.already_held(prepared.artifact_id) {
            self.finality.finish_lqc(prepared.issued.id());
            return Ok(Capabilities::new());
        }
        // An L-QC is durable local finality evidence, not a message this node owes its peers.
        // Peers that miss finality for a leader fetch a covering L-QC through resolution.
        let capabilities = self.reserve_view_certificate(
            Arc::clone(&prepared.artifact),
            prepared.artifact_id,
            prepared.observation,
            prepared.validated.take(),
        )?;
        self.finality.finish_lqc(prepared.issued.id());
        Ok(capabilities)
    }

    fn reserve_view_certificate(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
        observation: Observation,
        validated: Option<ValidatedLqc<V, H::Digest>>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let capabilities = self.reserve_change(Change::ViewCertificateCreated {
            artifact: Arc::clone(&artifact),
        })?;
        self.self_admit_at(
            artifact,
            id,
            observation,
            validated.map(ValidatedCertificate::Lqc),
        )?;
        self.wake_components();
        Ok(capabilities)
    }

    pub(super) fn complete_effect(
        &mut self,
        completion: EffectCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let id = completion.issued.id();
        if !self.is_current(completion.issued)
            || self.completions.pending_signing.contains_key(&id)
            || !self.contains_durable_effect(id)
        {
            return Ok(Step::stale());
        }
        let effect = self
            .durable_effect(id)
            .expect("live durable effect was checked above");
        if !effect.authorized::<H>(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }
        if let DurableEffect::Sign(sign) = &effect
            && !self.chain.signing_issued(completion.issued, sign)
        {
            return Err(StepError::EffectMismatch);
        }

        if matches!(
            (&effect, &completion.result),
            (DurableEffect::Publish(_), EffectResult::Delivered)
        ) {
            return Ok(Step::from(StepStatus::Accepted));
        }

        let completion = self.prepare_signing_completion(effect, completion)?;
        let mut step = Step::from(StepStatus::Accepted);
        if let PendingSigningCompletion::One { artifact, .. } = &completion
            && let Artifact::TransactionBlock(block) = artifact.as_ref()
        {
            step.activities.push(Activity::TransactionProposed {
                block: block.header().block_ref::<H>(),
            });
        }
        let replaced = self.completions.pending_signing.insert(id, completion);
        debug_assert!(replaced.is_none(), "one completion is prepared per effect");
        self.scheduler.enqueue(WorkKey::CompleteEffect(id));
        Ok(step)
    }

    fn prepare_signing_completion(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
        completion: EffectCompletion<V, H::Digest>,
    ) -> Result<PendingSigningCompletion<V, H::Digest>, StepError> {
        let (DurableEffect::Sign(effect), EffectResult::Signed(artifacts)) =
            (effect, completion.result)
        else {
            return Err(StepError::EffectMismatch);
        };
        let ([request], [artifact]) = (effect.requests(), artifacts.as_slice()) else {
            return Err(StepError::EffectMismatch);
        };
        let Role::Validator(signer) = self.profile.role() else {
            return Err(StepError::UnauthorizedEffect);
        };
        if !request.matches(signer, artifact) {
            return Err(StepError::EffectMismatch);
        }
        let id = self.validate_self_admission(artifact, None)?;
        Ok(PendingSigningCompletion::One {
            artifact: Arc::clone(artifact),
            id,
        })
    }

    fn stage_signing_completion(
        &mut self,
        id: EffectId,
        completion: PendingSigningCompletion<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        if !self.durable.state.signing_reservations.contains_key(&id) {
            return Ok(Capabilities::new());
        }

        let publication = self.next_effect_id()?;
        let change = match &completion {
            PendingSigningCompletion::One { artifact, .. } => Change::SignedArtifacts {
                sign: id,
                publication,
                artifacts: Arc::from([Arc::clone(artifact)]),
            },
            PendingSigningCompletion::Batch { artifacts, .. } => Change::SignedArtifacts {
                sign: id,
                publication,
                artifacts: Arc::clone(artifacts),
            },
        };
        let capabilities = self.reserve_change(change)?;
        match completion {
            PendingSigningCompletion::One { artifact, id } => self.self_admit(artifact, id)?,
            PendingSigningCompletion::Batch { artifacts, ids } => {
                for (artifact, id) in artifacts.iter().cloned().zip(ids) {
                    self.self_admit(artifact, id)?;
                }
            }
        }
        Ok(capabilities)
    }

    pub(super) fn drive_signing_completion(&mut self, id: EffectId) -> WorkResult<V, H::Digest> {
        let Some(completion) = self.completions.pending_signing.get(&id).cloned() else {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        };
        let capabilities = self.stage_signing_completion(id, completion)?;
        self.completions.pending_signing.remove(&id);
        Ok((WorkStatus::Complete, capabilities))
    }

    pub(super) fn drive_crypto_completion(&mut self) -> WorkResult<V, H::Digest> {
        if let Some(prepared) = self.completions.prepared_lqc.take() {
            return self.drive_prepared_lqc(prepared);
        }
        let Some(completion) = self.completions.pending_crypto.pop_front() else {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        };
        // Each arm hands back the completion it borrowed so transient pressure can repark it; an
        // L-QC is consumed into its prepared form instead.
        let (step, completion) = match completion {
            CryptoCompletion::DaCertificate { block, certificate } => (
                self.recovered_certificate(block, &certificate),
                CryptoCompletion::DaCertificate { block, certificate },
            ),
            CryptoCompletion::Nullification(completion) => (
                self.complete_nullification_recovery(&completion),
                CryptoCompletion::Nullification(completion),
            ),
            CryptoCompletion::Vqc(mut completion) => (
                self.complete_vqc_aggregation(&mut completion),
                CryptoCompletion::Vqc(completion),
            ),
            CryptoCompletion::Lqc(completion) => {
                let prepared = match self.finality.prepare_lqc::<H>(
                    &self.profile,
                    *completion,
                    self.durable.state.generation,
                ) {
                    Ok(Some(prepared)) => prepared,
                    Ok(None) => return Ok((self.pending_crypto_status(), Capabilities::new())),
                    Err(error) => return Err(error.into()),
                };
                return self.drive_prepared_lqc(prepared);
            }
        };
        let capabilities = match step {
            Ok(capabilities) => capabilities,
            // Capacity is released by later barrier acknowledgements, so transient pressure
            // reparks the completion at the queue head instead of failing the machine.
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.completions.pending_crypto.push_front(completion);
                return Ok((WorkStatus::Blocked, Capabilities::new()));
            }
            // A rejected completion is consumed: the underlying recovery or aggregation job
            // survives for a corrected completion, and the error surfaces exactly once rather
            // than poisoning every later drain of the queue.
            Err(error) => return Err(error),
        };
        let status = if self.completions.pending_crypto.is_empty() {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        };
        Ok((status, capabilities))
    }

    fn drive_prepared_lqc(
        &mut self,
        mut prepared: PreparedLqc<V, H::Digest>,
    ) -> WorkResult<V, H::Digest> {
        if !self.finality.lqc_aggregation_is_current(prepared.issued) {
            // The prepared certificate can no longer commit; return the reservation to its pool
            // so aggregation re-derives instead of waiting behind a consumed completion.
            self.finality.abandon_lqc(prepared.issued.id());
            return Ok((self.pending_crypto_status(), Capabilities::new()));
        }
        let Artifact::Lqc(certificate) = prepared.artifact.as_ref() else {
            unreachable!("L-QC preparation returns an L-QC")
        };
        if self.effective_retention_floor() > certificate.view() {
            // The view aged out while aggregation was in flight, so its publication obligation
            // is already discharged and the completion cannot affect live consensus state.
            self.finality.finish_lqc(prepared.issued.id());
            return Ok((self.pending_crypto_status(), Capabilities::new()));
        }

        match self.forward_before_lqc_completion(&prepared) {
            Ok(Some(capabilities)) => {
                self.completions.prepared_lqc = Some(prepared);
                self.scheduler.enqueue_front(WorkKey::CompleteCrypto);
                return Ok((WorkStatus::Complete, capabilities));
            }
            Ok(None) => {}
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.completions.prepared_lqc = Some(prepared);
                return Ok((WorkStatus::Blocked, Capabilities::new()));
            }
            Err(error) => return Err(error),
        }

        let capabilities = match self.complete_lqc_aggregation(&mut prepared) {
            Ok(capabilities) => capabilities,
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.completions.prepared_lqc = Some(prepared);
                return Ok((WorkStatus::Blocked, Capabilities::new()));
            }
            Err(error) => return Err(error),
        };
        Ok((self.pending_crypto_status(), capabilities))
    }

    fn pending_crypto_status(&self) -> WorkStatus {
        if self.completions.pending_crypto.is_empty() {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        }
    }

    fn forward_before_lqc_completion(
        &mut self,
        prepared: &PreparedLqc<V, H::Digest>,
    ) -> Result<Option<Capabilities<V, H::Digest>>, StepError> {
        let Artifact::Lqc(certificate) = prepared.artifact.as_ref() else {
            unreachable!("L-QC preparation returns an L-QC")
        };
        let Some(change) = self.next_artifact_forwarding(Some(certificate))? else {
            return Ok(None);
        };
        self.reserve_change(change).map(Some)
    }

    pub(super) fn fire_timer(&mut self, timer: ViewTimer) -> Result<Step<V, H::Digest>, StepError> {
        let current = timer.generation() == self.durable.state.generation
            && timer.round()
                == Round::new(self.profile.protocol().epoch(), self.durable.state.view);
        if !current {
            return Ok(Step::stale());
        }
        self.views
            .fire_timer::<H>(self.durable.state.view, &self.chain)?;
        self.wake_components();
        Ok(Step::from(StepStatus::Accepted))
    }
}
