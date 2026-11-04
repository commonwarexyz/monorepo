//! Entry points: input steps, resumable passes, work polls, and replay.

use super::{
    completions::PendingSigningCompletion,
    dependencies::ValidatedCertificate,
    drive::{WorkResult, WorkStatus},
    machine::{Lifecycle, Machine},
    store::ArtifactState,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            artifact::{Dependency, IdentifiedArtifact},
            capability::{Capabilities, Capability, ResolverCommand},
            durability::{
                Change, DomainEvent, DurableEffect, EffectCompletion, EffectId, EffectResult,
                ReplayError, SignRequest,
            },
            finality::FinalityUpdate,
            input::{Input, PollResult, Step, StepError, StepStatus},
            job::Issued,
            scheduler::{Budget, ProtocolComponent, WorkKey},
            util::Drive,
            verification::VerificationCompletion,
            view::{HistoryRecord, LeaderHistory},
        },
        scheme::Scheme,
        types::{Activity, Artifact, ArtifactId, ChainId},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Digest, Hasher};
use core::mem::take;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};

/// Reports one reconstructed leader history record.
pub(super) fn history_accepted<S: Scheme, D: Digest>(
    (source, record): HistoryRecord<D>,
) -> Activity<S, D> {
    Activity::HistoryAccepted {
        view: source.view,
        leader: source.leader,
        commitment: source.history,
        record,
    }
}

/// Where a verification pass is, with the verdict it resumes at.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum VerificationPassPhase {
    /// The completion has not been matched to its job.
    Start,
    /// Verdicts before this one matched their tickets.
    Validate(usize),
    /// Verdicts before this one were applied.
    Apply(usize),
    Complete,
}

/// Owned verification input and item cursor retained across core cycles.
pub(crate) struct VerificationPass<S: Scheme, D: Digest> {
    completion: VerificationCompletion<S, D>,
    phase: VerificationPassPhase,
}

impl<S: Scheme, D: Digest> VerificationPass<S, D> {
    pub(crate) const fn new(completion: VerificationCompletion<S, D>) -> Self {
        Self {
            completion,
            phase: VerificationPassPhase::Start,
        }
    }
}

/// Where a signing batch pass is.
enum SigningBatchPassPhase<S: Scheme, D: Digest> {
    /// The completion has not been matched to its reservation.
    Start,
    /// Artifacts are prepared against the reservation's requests, signed by `signer`.
    Prepare {
        requests: Arc<[SignRequest<S, D>]>,
        signer: Participant,
    },
    Complete,
}

/// Owned signing completion and private preparation cursor retained across core cycles.
pub(crate) struct SigningBatchPass<S: Scheme, D: Digest> {
    issued: Issued<EffectId>,
    artifacts: std::vec::IntoIter<Arc<Artifact<S, D>>>,
    total: usize,
    phase: SigningBatchPassPhase<S, D>,
    prepared: Vec<Arc<Artifact<S, D>>>,
    ids: Vec<ArtifactId<D>>,
    unique: BTreeSet<ArtifactId<D>>,
    /// The last DA-vote height accepted per chain, enforcing consecutive runs.
    da_runs: BTreeMap<ChainId, Height>,
    /// DA-vote requests observed so far.
    da_seen: usize,
    da_reservation_matches: bool,
    all_da_votes: bool,
}

impl<S: Scheme, D: Digest> SigningBatchPass<S, D> {
    pub(crate) fn new(issued: Issued<EffectId>, artifacts: Vec<Arc<Artifact<S, D>>>) -> Self {
        let total = artifacts.len();
        Self {
            issued,
            artifacts: artifacts.into_iter(),
            total,
            phase: SigningBatchPassPhase::Start,
            prepared: Vec::new(),
            ids: Vec::new(),
            unique: BTreeSet::new(),
            da_runs: BTreeMap::new(),
            da_seen: 0,
            da_reservation_matches: true,
            all_da_votes: true,
        }
    }

    /// Records the DA-vote shape of the request at `index`: a batch may carry several chains
    /// and, per chain, one run of strictly consecutive heights, since each DA vote counts as
    /// sent for the next one's eligibility within the same authorization.
    fn note_request(
        &mut self,
        request: &SignRequest<S, D>,
        chains: usize,
        reserved: Option<&SignRequest<S, D>>,
    ) {
        let SignRequest::DaVote(da_request) = request else {
            self.all_da_votes = false;
            return;
        };
        let header = da_request.header();
        let chain = header.chain();
        let in_committee = (chain.get() as usize) < chains;
        let run_ordered = self
            .da_runs
            .get(&chain)
            .is_none_or(|last| header.height() == last.next());
        self.da_runs.insert(chain, header.height());
        self.da_seen += 1;
        self.all_da_votes &= in_committee && run_ordered;
        self.da_reservation_matches &= reserved == Some(request);
    }
}

/// One queued input and its progress across core cycles.
///
/// Observation cohorts, verification completions and signing batches resume where the last
/// budget ran out; every other input applies atomically in one unit.
pub(crate) struct InputPass<S: Scheme, D: Digest>(PassKind<S, D>);

enum PassKind<S: Scheme, D: Digest> {
    /// An input not yet applied; taken when it applies.
    Atomic(Option<Input<S, D>>),
    /// The artifacts of an observation cohort not yet observed, in observation order.
    Observe(std::vec::IntoIter<IdentifiedArtifact<S, D>>),
    Verified(VerificationPass<S, D>),
    SignedBatch(SigningBatchPass<S, D>),
}

impl<S: Scheme, D: Digest> InputPass<S, D> {
    pub(crate) fn new(input: Input<S, D>) -> Self {
        Self(match input {
            Input::Observe(artifacts) => PassKind::Observe(artifacts.into_iter()),
            Input::Verified(completion) => PassKind::Verified(VerificationPass::new(completion)),
            // A signing choice of several requests prepares its artifacts in one resumable pass.
            Input::EffectCompleted(EffectCompletion {
                issued,
                result: EffectResult::Signed(artifacts),
            }) if artifacts.len() > 1 => {
                PassKind::SignedBatch(SigningBatchPass::new(issued, artifacts))
            }
            input => PassKind::Atomic(Some(input)),
        })
    }

    /// Returns whether the pass observes a cohort, whose units are artifacts.
    pub(crate) const fn observes(&self) -> bool {
        matches!(self.0, PassKind::Observe(_))
    }

    /// Returns the input of an atomic pass that has not applied yet.
    #[cfg(test)]
    pub(crate) const fn pending_input(&self) -> Option<&Input<S, D>> {
        match &self.0 {
            PassKind::Atomic(input) => input.as_ref(),
            PassKind::Observe(_) | PassKind::Verified(_) | PassKind::SignedBatch(_) => None,
        }
    }
}

impl<H: Hasher, S: Scheme> Machine<H, S> {
    /// Advances one queued input by at most `budget` units.
    ///
    /// An observation prefix also stops at the verification batch bound, so one pass never
    /// schedules more than one verification job.
    pub(crate) fn advance(
        &mut self,
        pass: &mut InputPass<S, H::Digest>,
        budget: usize,
    ) -> Result<Drive<Step<S, H::Digest>>, StepError> {
        match &mut pass.0 {
            PassKind::Atomic(input) => {
                let input = input
                    .take()
                    .expect("an applied input is not advanced again");
                Ok(Drive::done(1, self.step(input)?))
            }
            PassKind::Observe(artifacts) => {
                let items = artifacts
                    .len()
                    .min(budget)
                    .min(self.profile.resources().max_verification_batch());
                let report_admissions = self.lifecycle == Lifecycle::Live;
                self.ensure_live()?;
                let mut step = self.observe_artifacts(artifacts.by_ref().take(items))?;
                if report_admissions {
                    step.activities.extend(self.drain_activities());
                } else {
                    self.discard_activities();
                }
                Ok(Drive {
                    processed: items,
                    complete: artifacts.len() == 0,
                    output: step,
                })
            }
            PassKind::Verified(pass) => self.advance_verification_pass(pass, budget),
            PassKind::SignedBatch(pass) => self.advance_signing_batch_pass(pass, budget),
        }
    }

    /// Applies one serialized input and returns deterministic immutable capabilities.
    pub(crate) fn step(
        &mut self,
        input: Input<S, H::Digest>,
    ) -> Result<Step<S, H::Digest>, StepError> {
        let report_admissions = self.lifecycle == Lifecycle::Live;

        // Only lifecycle inputs and persistence acknowledgements arrive before the machine is live.
        if !matches!(
            input,
            Input::Start | Input::RecoveryComplete | Input::Persisted(_)
        ) {
            self.ensure_live()?;
        }
        let mut step = match input {
            Input::Start => self.start(false),
            Input::RecoveryComplete => self.start(true),
            Input::Persisted(completion) => self.complete_persistence(completion),
            Input::Observe(artifacts) => self.observe(artifacts),
            Input::Verified(completion) => {
                let mut pass = VerificationPass::new(completion);
                let advanced = self.advance_verification_pass(&mut pass, usize::MAX)?;
                debug_assert!(advanced.complete);
                Ok(advanced.output)
            }
            // A signing choice of several requests prepares its artifacts in one resumable pass.
            Input::EffectCompleted(EffectCompletion {
                issued,
                result: EffectResult::Signed(artifacts),
            }) if artifacts.len() > 1 => {
                let mut pass = SigningBatchPass::new(issued, artifacts);
                let advanced = self.advance_signing_batch_pass(&mut pass, usize::MAX)?;
                debug_assert!(advanced.complete);
                Ok(advanced.output)
            }
            Input::EffectCompleted(completion) => self.complete_effect(completion),
            Input::TimerFired(timer) => self.fire_timer(timer),
            Input::ProducerWake => self.wake_producer(),
            Input::BlockBuilt(completion) => self.complete_block_build(completion),
            Input::BlockCustodied(completion) => self.complete_block_custody(completion),
            Input::CustodyCancelled(cancellation) => {
                self.complete_custody_cancellation(cancellation)
            }
            Input::ResolutionCompleted(completion) => self.complete_resolution(completion),
            Input::ProductionTimerFired(timer) => self.fire_production_timer(timer),
            // Recovery and aggregation completions stage a durable change, so they always park
            // and drain through the scheduler: one FIFO decides staging order for every durable
            // transition, whether or not a barrier sync happens to be in flight.
            Input::Crypto(completion) => {
                self.completions.pending_crypto.push_back(completion);
                self.scheduler.enqueue(WorkKey::CompleteCrypto);
                return Ok(Step::from(StepStatus::Accepted));
            }
        }?;

        // Recovery and replay promotions are never externalized, but they must still be drained
        // so they cannot leak into the first reporting step.
        if report_admissions {
            let accepted = self.drain_activities();
            step.activities.extend(accepted);
        } else {
            self.discard_activities();
        }
        step.capabilities
            .extend(self.resolution.take_capabilities());

        Ok(step)
    }

    /// Applies at most `budget` real verification items and retains the suffix cursor.
    fn advance_verification_pass(
        &mut self,
        pass: &mut VerificationPass<S, H::Digest>,
        budget: usize,
    ) -> Result<Drive<Step<S, H::Digest>>, StepError> {
        self.ensure_live()?;
        debug_assert!(budget > 0);

        let mut processed = 0;
        let mut applied = 0;
        let mut valid = 0;
        let mut invalid = 0;
        while processed < budget && pass.phase != VerificationPassPhase::Complete {
            let id = pass.completion.issued().id();
            let verdicts = pass.completion.verdicts().len();
            match pass.phase {
                VerificationPassPhase::Start => {
                    processed += 1;
                    if !self.is_current(pass.completion.issued())
                        || !self.completions.verification_jobs.contains_key(&id)
                    {
                        pass.phase = VerificationPassPhase::Complete;
                        return Ok(Drive::done(processed, Step::stale()));
                    }
                    if self.completions.verification_jobs[&id].len() != verdicts {
                        return Err(StepError::CompletionMismatch);
                    }
                    if verdicts == 0 {
                        self.completions
                            .verification_jobs
                            .remove(&id)
                            .expect("the empty verification job remains retained");
                        pass.phase = VerificationPassPhase::Complete;
                    } else {
                        pass.phase = VerificationPassPhase::Validate(0);
                    }
                }
                VerificationPassPhase::Validate(position) => {
                    let expected = self.completions.verification_jobs[&id][position];
                    let actual = pass.completion.verdicts()[position].ticket();
                    if expected != actual {
                        return Err(StepError::CompletionMismatch);
                    }
                    processed += 1;
                    pass.phase = if position + 1 == verdicts {
                        self.completions
                            .verification_jobs
                            .remove(&id)
                            .expect("the validated verification job remains retained");
                        VerificationPassPhase::Apply(0)
                    } else {
                        VerificationPassPhase::Validate(position + 1)
                    };
                }
                VerificationPassPhase::Apply(position) => {
                    let verdict = pass.completion.verdicts()[position];
                    let vqc = pass
                        .completion
                        .take_validated_vqc(position)
                        .map(ValidatedCertificate::Vqc);
                    let lqc = pass
                        .completion
                        .take_validated_lqc(position)
                        .map(ValidatedCertificate::Lqc);
                    let da_equivocator = pass.completion.take_da_equivocator(position);
                    if let Some(verdict_valid) =
                        self.apply_verification_verdict(verdict, vqc.or(lqc), da_equivocator)?
                    {
                        valid += usize::from(verdict_valid);
                        invalid += usize::from(!verdict_valid);
                    }
                    processed += 1;
                    applied += 1;
                    pass.phase = if position + 1 == verdicts {
                        VerificationPassPhase::Complete
                    } else {
                        VerificationPassPhase::Apply(position + 1)
                    };
                }
                VerificationPassPhase::Complete => unreachable!("the loop excludes completion"),
            }
        }

        let complete = pass.phase == VerificationPassPhase::Complete;
        let mut step = if applied > 0 || complete {
            self.finish_verification_prefix(valid, invalid)?
        } else {
            Step::from(StepStatus::Verified {
                valid: 0,
                invalid: 0,
            })
        };
        step.activities.extend(self.drain_activities());
        step.capabilities
            .extend(self.resolution.take_capabilities());
        Ok(Drive {
            processed,
            complete,
            output: step,
        })
    }

    /// Privately prepares at most `budget` signed artifacts before one atomic admission.
    fn advance_signing_batch_pass(
        &mut self,
        pass: &mut SigningBatchPass<S, H::Digest>,
        budget: usize,
    ) -> Result<Drive<Step<S, H::Digest>>, StepError> {
        self.ensure_live()?;
        debug_assert!(budget > 0);

        let mut processed = 0;
        while processed < budget && !matches!(pass.phase, SigningBatchPassPhase::Complete) {
            let (requests, signer) = match &pass.phase {
                SigningBatchPassPhase::Start => {
                    processed += 1;
                    if !self.is_current(pass.issued)
                        || self
                            .completions
                            .pending_signing
                            .contains_key(&pass.issued.id())
                        || !self.contains_durable_effect(pass.issued.id())
                    {
                        pass.phase = SigningBatchPassPhase::Complete;
                        return Ok(Drive::done(processed, Step::stale()));
                    }
                    let effect = self
                        .durable_effect(pass.issued.id())
                        .expect("the signing reservation was checked above");
                    let DurableEffect::Sign(effect) = effect else {
                        return Err(StepError::EffectMismatch);
                    };
                    let requests = Arc::clone(effect.shared());
                    let Role::Validator(signer) = self.profile.role() else {
                        return Err(StepError::UnauthorizedEffect);
                    };
                    if requests.is_empty() {
                        return Err(StepError::UnauthorizedEffect);
                    }
                    if requests.len() != pass.total {
                        return Err(StepError::EffectMismatch);
                    }
                    pass.prepared.reserve_exact(pass.total);
                    pass.ids.reserve_exact(pass.total);
                    pass.phase = SigningBatchPassPhase::Prepare { requests, signer };
                    continue;
                }
                SigningBatchPassPhase::Prepare { requests, signer } => {
                    (Arc::clone(requests), *signer)
                }
                SigningBatchPassPhase::Complete => unreachable!("the loop excludes completion"),
            };
            let artifact = pass
                .artifacts
                .next()
                .expect("the signing cursor remains below its exact batch length");
            let index = pass.ids.len();
            let request = &requests[index];
            if !request.matches_context(self.profile.protocol().epoch()) {
                return Err(StepError::UnauthorizedEffect);
            }
            pass.note_request(
                request,
                self.profile.codec().chains(),
                self.chain.issued_signing_request(pass.issued, index),
            );
            if !request.matches(signer, &artifact) {
                return Err(StepError::EffectMismatch);
            }
            let id = self.validate_self_admission(&artifact, None)?;
            if !pass.unique.insert(id) {
                return Err(StepError::LocalArtifactReservation);
            }
            pass.prepared.push(artifact);
            pass.ids.push(id);
            processed += 1;
            if pass.ids.len() < pass.total {
                continue;
            }
            let current = self
                .durable_effect(pass.issued.id())
                .filter(|_| self.is_current(pass.issued));
            let Some(effect) = current else {
                pass.phase = SigningBatchPassPhase::Complete;
                return Ok(Drive::done(processed, Step::stale()));
            };
            let DurableEffect::Sign(effect) = &effect else {
                return Err(StepError::EffectMismatch);
            };
            if !Arc::ptr_eq(effect.shared(), &requests) {
                return Err(StepError::EffectMismatch);
            }
            let timeout_pair = matches!(requests.as_ref(), [
                SignRequest::NoVote { round: left },
                SignRequest::Nullify { round: right },
            ] if left == right);
            let da_votes = pass.all_da_votes && pass.da_seen == pass.total;
            if !timeout_pair && !da_votes {
                return Err(StepError::UnauthorizedEffect);
            }
            if da_votes
                && (!pass.da_reservation_matches
                    || self.chain.issued_signing_batch_len(pass.issued) != Some(pass.total))
            {
                return Err(StepError::EffectMismatch);
            }
            if self.store.artifacts.len() + pass.ids.len()
                > self.profile.resources().max_cached_artifacts()
            {
                return Err(StepError::LocalArtifactReservation);
            }
            let artifacts = Arc::from(take(&mut pass.prepared));
            let ids = take(&mut pass.ids);
            self.completions.pending_signing.insert(
                pass.issued.id(),
                PendingSigningCompletion::Batch { artifacts, ids },
            );
            self.scheduler
                .enqueue(WorkKey::CompleteEffect(pass.issued.id()));
            pass.phase = SigningBatchPassPhase::Complete;
        }

        Ok(Drive {
            processed,
            complete: matches!(pass.phase, SigningBatchPassPhase::Complete),
            output: Step::from(StepStatus::Accepted),
        })
    }

    /// Performs at most `budget` machine-owned semantic work quanta.
    ///
    /// Staged changes apply immediately and accumulate into group-commit batches; the poll
    /// hands ready batches to the driver on exit. Work blocked on resolution is not reported
    /// as ready; the matching completion wakes it.
    pub(crate) fn poll(
        &mut self,
        budget: NonZeroUsize,
    ) -> Result<PollResult<S, H::Digest>, StepError> {
        self.ensure_live()?;
        let mut capabilities = Capabilities::new();

        for _ in 0..budget.get() {
            let Some(key) = self.scheduler.pop() else {
                break;
            };
            let (status, emitted) = match key {
                WorkKey::CompleteEffect(id) => self.drive_signing_completion(id)?,
                WorkKey::CompleteCrypto => self.drive_crypto_completion()?,
                WorkKey::Drive(component) => {
                    self.drive_component_quantum(component, &mut Budget::quantum())?
                }
            };
            capabilities.extend(emitted);

            if status == WorkStatus::Requeue {
                self.scheduler.enqueue(key);
            }
            // One component key owns one finite service cycle. Returning here ensures an actor
            // observes ready work and yields before beginning another component quantum.
            if matches!(key, WorkKey::Drive(_)) {
                break;
            }
        }

        // Hand one ready group-commit batch to the driver.
        capabilities.extend(self.emit_staged());
        capabilities.extend(self.resolution.take_capabilities());
        let activities = self.drain_activities();
        Ok(PollResult {
            capabilities,
            activities,
            vote_builds: self.views.drain_vote_builds(),
        })
    }

    /// Reports direct-finality updates, every artifact promoted to ready, and every leader
    /// history record reconstructed since the last drain.
    ///
    /// A promotion that the same drain window also discarded is not an admission: the artifact
    /// is no longer retained, so it is filtered out exactly as a before-and-after comparison of
    /// the retained map would have. A history record is reported regardless: it was
    /// reconstructed when its leader was offered, and a leader whose view retires in the same
    /// window (an L-QC raises the retired view to its own) remains authenticated.
    fn drain_activities(&mut self) -> Vec<Activity<S, H::Digest>> {
        let finalized = self.finality.drain_updates();
        self.report_finality_histories();
        let histories = self.views.take_histories();
        if self.store.newly_ready.is_empty() && finalized.is_empty() && histories.is_empty() {
            return Vec::new();
        }
        let mut accepted = take(&mut self.store.newly_ready);
        accepted.retain(|(_, id, _)| {
            self.store
                .artifacts
                .get(id)
                .is_some_and(|entry| matches!(entry.state, ArtifactState::Ready))
        });
        accepted.sort_unstable_by_key(|(observation, id, _)| (*observation, *id));
        let mut activities =
            Vec::with_capacity(accepted.len() + 2 * finalized.len() + histories.len());
        activities.extend(finalized.into_iter().flat_map(|update| match update {
            FinalityUpdate::Finalized(fact, commitments) => [
                Activity::CommitmentsAccepted { commitments },
                Activity::LeaderFinalized { fact },
            ],
            FinalityUpdate::Advanced(fact, commitments) => [
                Activity::CommitmentsAccepted { commitments },
                Activity::LeaderFinalityUpdated { fact },
            ],
        }));
        for (_, artifact_id, artifact) in accepted {
            self.push_acceptance(artifact_id, artifact, &mut activities);
        }
        activities.extend(histories.into_iter().map(history_accepted));
        activities
    }

    /// Offers `source` for history reporting while the machine is live.
    ///
    /// Replay and recovery never report, so they record nothing either.
    pub(super) fn report_history(&mut self, source: LeaderHistory<H::Digest>) {
        if self.lifecycle == Lifecycle::Live {
            self.views.report_history(source);
        }
    }

    /// Offers the leader of every pool whose finality fact changed for history reporting.
    pub(super) fn report_finality_histories(&mut self) {
        let live = self.lifecycle == Lifecycle::Live;
        let views = &mut self.views;
        self.finality.drain_histories(|source| {
            if live {
                views.report_history(source);
            }
        });
    }

    /// Offers an admitted leader block for history reporting, reusing the digest its
    /// provisions carry.
    pub(super) fn report_leader_history(
        &mut self,
        artifact: &Artifact<S, H::Digest>,
        provisions: &[Dependency<H::Digest>],
    ) {
        let Artifact::LeaderBlock(block) = artifact else {
            return;
        };
        let leader = provisions.iter().find_map(|provision| match provision {
            Dependency::Leader { digest, .. } => Some(*digest),
            Dependency::Vqc(_) => None,
        });
        if let Some(leader) = leader {
            self.report_history(LeaderHistory::new(block.block(), leader));
        }
    }

    /// Offers the leader of a verified L-QC for history reporting.
    ///
    /// `leader` is the leader digest when verification already derived it.
    pub(super) fn report_certificate_history(
        &mut self,
        certificate: &Artifact<S, H::Digest>,
        leader: Option<H::Digest>,
    ) {
        let Artifact::Lqc(certificate) = certificate else {
            return;
        };
        if self.lifecycle != Lifecycle::Live {
            return;
        }
        let block = certificate.leader();
        let leader = leader.unwrap_or_else(|| block.digest::<H>());
        self.views.report_history(LeaderHistory::new(block, leader));
    }

    /// Appends the activities reporting one accepted artifact: its selected commitments and the
    /// acceptance itself.
    pub(super) fn push_acceptance(
        &self,
        artifact_id: ArtifactId<H::Digest>,
        artifact: Arc<Artifact<S, H::Digest>>,
        activities: &mut Vec<Activity<S, H::Digest>>,
    ) {
        if let Some(commitments) = self
            .views
            .selected_commitments(&artifact)
            .or_else(|| self.finality.selected_commitments(&artifact))
        {
            activities.push(Activity::CommitmentsAccepted {
                commitments: commitments.clone(),
            });
        }
        activities.push(Activity::ProtocolAccepted {
            artifact_id,
            artifact,
        });
    }

    fn discard_activities(&mut self) {
        self.store.newly_ready.clear();
        self.finality.clear_updates();
        self.views.discard_histories();
    }

    /// Replays one contiguous durable event without emitting live capabilities.
    pub(crate) fn replay(&mut self, event: DomainEvent<S, H::Digest>) -> Result<(), ReplayError> {
        if self.lifecycle != Lifecycle::Recovering || !self.pipeline.staged.is_empty() {
            return Err(ReplayError::Lifecycle);
        }
        self.apply_event(&event)?;
        self.pipeline.acked = self.durable.state.cursor;
        // Replay never externalizes admissions, and the boundary step that follows must not
        // inherit them.
        self.discard_activities();
        Ok(())
    }

    pub(super) fn ensure_live(&self) -> Result<(), StepError> {
        if self.lifecycle != Lifecycle::Live {
            return Err(StepError::Lifecycle);
        }
        Ok(())
    }

    pub(super) fn start(&mut self, recovery: bool) -> Result<Step<S, H::Digest>, StepError> {
        let expected = if recovery {
            Lifecycle::Recovering
        } else {
            Lifecycle::Fresh
        };
        if self.lifecycle != expected || !self.pipeline.staged.is_empty() {
            return Err(StepError::Lifecycle);
        }
        if recovery {
            self.restore_durable_artifacts()?;
        }
        let generation = self
            .durable
            .state
            .generation
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        if self.pipeline.acked != self.durable.state.cursor {
            return Err(StepError::Lifecycle);
        }
        // Every recovered event was replayed from the synced journal, so any recovered signature
        // exposure is acknowledged already.
        self.pipeline.own_exposure = self.durable.state.cursor;
        // Every recovered certificate is durable, so the application learns each chain's release
        // before the engine verifies anything new; recovery verified what it retained already.
        let recorded = self
            .durable
            .state
            .certified_tips
            .iter()
            .map(|block| self.certificate_recorded(*block))
            .collect::<Vec<_>>();
        let mut step = Step::new(
            StepStatus::Accepted,
            self.reserve_change(Change::GenerationAdvanced(generation))?,
        );
        // State transitions happen at staging; the acknowledgement releases the recovered
        // outbox once the new generation is durable.
        self.lifecycle = Lifecycle::Live;
        step.activities.extend(recorded);
        step.activities.extend(self.restore_ready_artifacts()?);
        if recovery {
            // Retained exits advance startup without peer input. Resolve the first remaining
            // proof requirement, including a finality-floor probe at the current view.
            let mut view = self.durable.state.view;
            while !self.resolution_needed(view) {
                view = View::new(
                    view.get()
                        .checked_add(1)
                        .ok_or(StepError::IdentifierExhausted)?,
                );
            }
            if let Some(job) = self.request_resolution(view)? {
                step.capabilities
                    .push(Capability::Resolver(ResolverCommand::Resolve(job)));
            }
        }
        step.capabilities.extend(self.emit_staged());
        Ok(step)
    }

    pub(super) fn observe(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<S, H::Digest>>,
    ) -> Result<Step<S, H::Digest>, StepError> {
        self.observe_artifacts(artifacts.into_iter())
    }

    fn drive_component_quantum(
        &mut self,
        component: ProtocolComponent,
        budget: &mut Budget,
    ) -> WorkResult<S, H::Digest> {
        let before = self.durable.state.cursor;
        let (status, capabilities) = match component {
            ProtocolComponent::Finality => self.drive_finality_component()?,
            ProtocolComponent::View => self.drive_view_component(budget)?,
            ProtocolComponent::Da => self.drive_da_component(budget)?,
        };
        // Queued sources are serviced only through this component key, so completing the
        // quantum while any remain would strand them until an unrelated wake.
        let status = if status == WorkStatus::Requeue || self.durable.state.cursor != before {
            WorkStatus::Requeue
        } else {
            WorkStatus::Complete
        };
        Ok((status, capabilities))
    }

    /// Wakes every protocol component, exactly as servicing an external input does.
    pub(super) fn wake_components(&mut self) {
        self.scheduler.enqueue_components();
    }
}
