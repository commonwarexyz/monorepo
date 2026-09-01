//! Staging durable changes and the journal barrier pipeline.

use super::{machine::Machine, store::ArtifactState};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::{Capabilities, Capability, ResolverCommand, TimerCommand},
            durability::{
                BarrierAck, BatchId, Change, Cursor, DomainEvent, DurableEffect, DurableJob,
                EffectId, PersistDirective, PersistJob, Publication, ReplayError, TransitionReason,
            },
            input::{Step, StepError, StepStatus},
            job::{Generation, Issued},
            view::ViewTimer,
        },
        types::{Activity, Artifact, ArtifactId},
    },
    types::{Round, View},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::VecDeque, sync::Arc};

/// Emitted-but-unacknowledged barriers allowed before ordinary batches stop entering the
/// journal pipeline. The journal must flush by this limit to release the core's capacity.
pub(crate) const MAX_INFLIGHT_BARRIERS: usize = 4;

/// The most events one barrier may carry. The journal derives its record limits from this and
/// [`MAX_BATCH_BYTES`].
pub(crate) const MAX_BATCH_EVENTS: usize = 32;

/// The byte target that closes a barrier's batch. One indivisible event may exceed it, and the
/// journal's record limit leaves room for that event.
pub(crate) const MAX_BATCH_BYTES: usize = 1 << 20;

/// Total unacknowledged batches retained by the synchronous owner: the journal pipeline, one
/// coalescing batch, and one successor whose external release requires journal admission.
pub(crate) const MAX_STAGED_BARRIERS: usize = MAX_INFLIGHT_BARRIERS + 2;

/// Process-local publication released once its own-signature exposure floor is durable.
#[derive(Clone, Debug)]
pub(crate) enum DeferredRelease<V: Variant, D: Digest> {
    Outbox(EffectId),
    Retain(Arc<Artifact<V, D>>),
}

/// Acknowledgement work frozen when a batch enters the journal pipeline.
///
/// The work is derived before later transitions can retire the outbox entries it references, and
/// runs once the batch is durable: resolver retention to install, publication attempts to retire,
/// and forwarded nullifications to count.
#[derive(Clone, Debug)]
pub(crate) struct FrozenAcknowledgement<V: Variant, D: Digest> {
    pub(crate) retention: Vec<Arc<Artifact<V, D>>>,
    pub(crate) retirements: Vec<EffectId>,
    pub(crate) forwarded_nullifications: usize,
}

/// One group-commit batch of staged events awaiting durability.
///
/// Staged events are already applied to machine state; the batch exists only to make them
/// durable and to release their external effects once the journal sync acknowledges. While a
/// barrier is in flight, new events absorb into the open batch at the back of the staging
/// queue, so batch sizes scale with storage latency instead of forcing one sync per event.
#[derive(Clone, Debug)]
pub(crate) struct PendingPersistence<V: Variant, D: Digest> {
    pub(crate) job: PersistJob<V, D>,
    /// Independently verifiable publications released only after this batch enters the journal.
    pub(crate) release_after_enqueue: Vec<DurableJob<V, D>>,
    /// Whether the batch has been handed to the driver as a [`Capability::Journal`].
    pub(crate) emitted: bool,
    /// Acknowledgement work derived before later transitions can retire referenced outbox entries.
    pub(crate) acknowledgement: Option<FrozenAcknowledgement<V, D>>,
    /// Encoded bytes accumulated by the batch, for the journal's record-size bound.
    pub(crate) bytes: usize,
}

impl<V: Variant, D: Digest> PendingPersistence<V, D> {
    pub(crate) fn starts_generation(&self) -> bool {
        self.job
            .events()
            .iter()
            .any(|event| matches!(event.change(), Change::GenerationAdvanced(_)))
    }
}

/// The journal pipeline: staged batches, acknowledgement, and release ordering.
pub(crate) struct Pipeline<V: Variant, D: Digest> {
    /// Group-commit batches of staged, already-applied events awaiting durability, in cursor
    /// order. The back batch stays open for absorption until it fills or the pipeline drains.
    pub(in crate::multimmit::machine) staged: VecDeque<PendingPersistence<V, D>>,
    /// Cursor of the last acknowledged (synced) journal event; the durable state's cursor leads
    /// it by the staged pipeline, since application happens at staging.
    pub(in crate::multimmit::machine) acked: Cursor,
    /// Identity of the most recently applied persistence boundary.
    ///
    /// Only that boundary may be duplicated at the acknowledgement frontier. An older id is an
    /// out-of-order completion and remains fatal, so one retained identity keeps this state
    /// bounded while preventing a forged cursor from being classified as stale.
    pub(in crate::multimmit::machine) last_barrier: Option<BarrierAck>,
    /// Cursor of the latest event that records a fresh local signature.
    ///
    /// Capabilities that reference one of our signatures (directly or inside an aggregate) release
    /// only once `acked` reaches this floor, so no fresh signature leaves the process before
    /// its record is durable. Capabilities free of such references release at staging.
    pub(in crate::multimmit::machine) own_exposure: Cursor,
    /// Publications awaiting their exposure floor, in cursor order.
    pub(in crate::multimmit::machine) deferred_releases: VecDeque<(Cursor, DeferredRelease<V, D>)>,
    /// The identifier of the next batch.
    pub(in crate::multimmit::machine) next_barrier: u64,
    /// Cursor of the newest staged data-availability vote reservation.
    ///
    /// The DA component keeps at most one unacknowledged reservation, so blocks that become
    /// eligible while that barrier is in flight join the next one instead of each reserving
    /// its own signing action, durable event, and barrier. A reservation therefore waits at
    /// most one barrier, and a cursor at or below `acked` never defers.
    pub(in crate::multimmit::machine) da_vote_reserved_through: Cursor,
}

impl<V: Variant, D: Digest> Pipeline<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            staged: VecDeque::new(),
            acked: Cursor::zero(),
            last_barrier: None,
            own_exposure: Cursor::zero(),
            deferred_releases: VecDeque::new(),
            next_barrier: 0,
            da_vote_reserved_through: Cursor::zero(),
        }
    }
}

/// Which staged batch one event joins.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BatchTarget {
    /// The open batch at the back, which is not yet emitted and still has room.
    Open,
    /// A new batch behind every staged one.
    New,
}

/// How the batch that stages one event releases its work.
struct StagedRelease<V: Variant, D: Digest> {
    /// Whether the batch must reach the journal without waiting for more events.
    urgent: bool,
    /// A publication released once the batch enters the journal.
    release_after_enqueue: Option<DurableJob<V, D>>,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Stages one durable change: applies it immediately and queues it for group commit.
    ///
    /// Staging is application. Every event mutates machine state through [`Self::apply_event`],
    /// the same transition function recovery replays, exactly once and in cursor order, so all
    /// later derivations see every staged event.
    ///
    /// External release splits by what durability protects. An effect referencing one of our
    /// signatures releases only once [`Pipeline::acked`] reaches its exposure floor: for the
    /// publication of a fresh signature that floor is this very event, so the record is always
    /// durable before the signature leaves. Forwarded certificates release after their own batch
    /// enters the journal; other independently verifiable work can release in the returned step.
    /// A crash that forgets either publication is indistinguishable from network reordering.
    pub(super) fn reserve_change(
        &mut self,
        change: Change<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let cursor = self
            .durable
            .state
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        let previous = self.durable.state.cursor;
        let generation = self.durable.state.generation;
        let event = DomainEvent::new(self.profile.protocol().epoch(), cursor, change);
        let view_before = self.durable.state.view;
        let retired_before = self.durable.state.retired_view;
        let bytes = event.encode_size();
        let target = if self.pipeline.staged.back().is_some_and(|open| {
            !open.emitted
                && open.job.events().len() < MAX_BATCH_EVENTS
                && open.bytes.saturating_add(bytes) <= MAX_BATCH_BYTES
        }) {
            BatchTarget::Open
        } else {
            BatchTarget::New
        };
        if target == BatchTarget::New && self.pipeline.staged.len() >= MAX_STAGED_BARRIERS {
            return Err(StepError::PersistenceCapacity);
        }
        if let Err(source) = self.apply_event(&event) {
            // The machine derived a change its own validator rejects: internal corruption.
            return Err(StepError::DurableTransition {
                change: event.change().kind(),
                source,
            });
        }

        let mut capabilities = Capabilities::new();
        if self.durable.state.retired_view > retired_before {
            capabilities.push(Capability::Resolver(ResolverCommand::Prune(
                self.durable.state.retired_view,
            )));
        }
        let release = self.release_policy(&event, cursor, &mut capabilities);
        self.retain_or_defer_aggregate(&event, &mut capabilities);
        self.rearm_view_timer(&event, view_before, &mut capabilities);
        self.stage_event(event, release, bytes, target, generation, previous)?;
        Ok(capabilities)
    }

    /// Decides when the outbox action an applied event queues may leave the process.
    ///
    /// Returns whether the event's batch is urgent and the publication to release only once the
    /// batch enters the journal; every other released action is pushed to `capabilities` or
    /// deferred behind the own-signature exposure floor.
    fn release_policy(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
        cursor: Cursor,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> StagedRelease<V, H::Digest> {
        // The recovered outbox re-releases at the generation barrier's acknowledgement, when
        // every recovered record is durable again under the new generation.
        let urgent = matches!(event.change(), Change::GenerationAdvanced(_));
        let release = |release_after_enqueue| StagedRelease {
            urgent,
            release_after_enqueue,
        };
        let Some(id) = event.change().queued_effect() else {
            return release(None);
        };
        if event.change().records_local_signature() {
            self.pipeline.own_exposure = cursor;
            self.pipeline
                .deferred_releases
                .push_back((cursor, DeferredRelease::Outbox(id)));
            return StagedRelease {
                urgent: true,
                release_after_enqueue: None,
            };
        }
        let me = match self.profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        let referenced = self
            .durable
            .state
            .outbox
            .get(&id)
            .is_some_and(|entry| entry.publication().references_own_signature(me));
        if referenced && self.pipeline.own_exposure > self.pipeline.acked {
            self.pipeline
                .deferred_releases
                .push_back((self.pipeline.own_exposure, DeferredRelease::Outbox(id)));
            release(None)
        } else if matches!(event.change(), Change::ArtifactForwarded { .. }) {
            release(self.release_outbox_job(id))
        } else {
            self.release_outbox([id], capabilities);
            release(None)
        }
    }

    /// Retains a created aggregate or new finality proof for the resolver, or defers it behind the
    /// own-signature exposure floor.
    fn retain_or_defer_aggregate(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) {
        let (Change::ViewCertificateCreated { artifact }
        | Change::FinalityFloorAdvanced {
            proof: artifact, ..
        }) = event.change()
        else {
            return;
        };
        // Aggregates may contain our shares. Their metadata is reconstructible, but exposing the
        // proof still requires durability of every fresh local signature it could carry.
        if self.pipeline.own_exposure > self.pipeline.acked {
            self.pipeline.deferred_releases.push_back((
                self.pipeline.own_exposure,
                DeferredRelease::Retain(Arc::clone(artifact)),
            ));
        } else {
            capabilities.push(Capability::Retain(Arc::clone(artifact)));
        }
    }

    /// Arms the view timer for the view an applied event entered.
    fn rearm_view_timer(
        &self,
        event: &DomainEvent<V, H::Digest>,
        view_before: View,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) {
        // A late finality floor leaves the view where the ordinary exit put it; re-arming the
        // timer for it would push out the deadline the running view already earned.
        let entered = matches!(
            event.change(),
            Change::ViewAdvanced { .. } | Change::GenerationAdvanced(_)
        ) || (matches!(event.change(), Change::FinalityFloorAdvanced { .. })
            && self.durable.state.view != view_before);
        if entered {
            capabilities.push(Capability::Timer(TimerCommand::View(ViewTimer::new(
                self.durable.state.generation,
                Round::new(self.profile.protocol().epoch(), self.durable.state.view),
                self.profile.tuning().view_timeout,
            ))));
        }
    }

    /// Appends an applied event to the open batch, or opens a new batch for it.
    fn stage_event(
        &mut self,
        event: DomainEvent<V, H::Digest>,
        release: StagedRelease<V, H::Digest>,
        bytes: usize,
        target: BatchTarget,
        generation: Generation,
        previous: Cursor,
    ) -> Result<(), StepError> {
        let StagedRelease {
            urgent,
            release_after_enqueue,
        } = release;
        if target == BatchTarget::Open {
            let open = self
                .pipeline
                .staged
                .back_mut()
                .expect("an appendable persistence batch remains staged");
            open.job.push_event(event, urgent);
            if let Some(job) = release_after_enqueue {
                open.release_after_enqueue.push(job);
            }
            open.bytes = open.bytes.saturating_add(bytes);
            return Ok(());
        }
        let id = BatchId::new(self.pipeline.next_barrier);
        self.pipeline.next_barrier = self
            .pipeline
            .next_barrier
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;
        let job = PersistJob::new(id, generation, previous, vec![event], urgent);
        self.pipeline.staged.push_back(PendingPersistence {
            job,
            release_after_enqueue: release_after_enqueue.into_iter().collect(),
            emitted: false,
            acknowledgement: None,
            bytes,
        });
        Ok(())
    }

    /// Hands one cut batch to the driver while keeping the group-commit window open.
    ///
    /// Eligible batches emit in cursor order, one per poll, so the caller needs exactly one journal
    /// command slot before entering the reducer. The open batch at the back emits only when it is
    /// the sole staged batch: while any barrier is in flight it keeps absorbing background events,
    /// so batch sizes scale with storage latency and an idle machine still emits immediately.
    /// Urgent work and publications awaiting enqueue make every earlier batch eligible; repeated
    /// polls hand that prefix to the journal without allowing a later range to overtake it.
    pub(super) fn next_staged_index(&self) -> Option<usize> {
        let staged = self.pipeline.staged.len();
        let inflight = self
            .pipeline
            .staged
            .iter()
            .filter(|batch| batch.emitted)
            .count();
        let force_through = self
            .pipeline
            .staged
            .iter()
            .enumerate()
            .rev()
            .find(|(_, batch)| {
                !batch.emitted && (batch.job.urgent() || !batch.release_after_enqueue.is_empty())
            })
            .map(|(index, _)| index);
        for (index, batch) in self.pipeline.staged.iter().enumerate() {
            if batch.emitted {
                continue;
            }
            let forced = force_through.is_some_and(|through| index <= through);
            if inflight >= MAX_INFLIGHT_BARRIERS && !forced {
                break;
            }
            let last = index + 1 == staged;
            let full =
                batch.job.events().len() >= MAX_BATCH_EVENTS || batch.bytes >= MAX_BATCH_BYTES;
            if last && staged > 1 && !full && !forced {
                return None;
            }
            return Some(index);
        }
        None
    }

    fn freeze_persistence(
        &self,
        job: PersistJob<V, H::Digest>,
        release_after_enqueue: Vec<DurableJob<V, H::Digest>>,
    ) -> (
        PersistDirective<V, H::Digest>,
        FrozenAcknowledgement<V, H::Digest>,
    ) {
        let mut staged_retention = Vec::new();
        let mut retention = Vec::new();
        let mut retirements = Vec::new();
        let mut forwarded_nullifications = 0usize;

        for event in job.events() {
            match event.change() {
                Change::SignedArtifacts { publication, .. } => {
                    if let Some(publication) = self.durable.state.publication(publication) {
                        Self::extend_publication(publication, &mut retention);
                    }
                }
                Change::OutboxQueued { effect, .. } => {
                    if let Some(publication) = effect.publication() {
                        Self::extend_publication(publication, &mut retention);
                    }
                }
                Change::DaCertificateAdvanced {
                    artifact,
                    retired_publications: retired,
                    ..
                } => {
                    retention.push(Arc::clone(artifact));
                    retirements.extend(retired);
                }
                Change::ViewCertificateCreated { .. } => {}
                Change::ArtifactForwarded {
                    retired_publications: retired,
                    artifact,
                    ..
                } => {
                    staged_retention.push(Arc::clone(artifact));
                    retirements.extend(retired);
                    forwarded_nullifications +=
                        usize::from(matches!(artifact.as_ref(), Artifact::Nullification(_)));
                }
                Change::ViewAdvanced {
                    retired_publications: retired,
                    ..
                } => retirements.extend(retired),
                Change::FinalityFloorAdvanced {
                    retired_publications,
                    ..
                } => {
                    retirements.extend(retired_publications);
                }
                Change::GenerationAdvanced(_) => {}
            }
        }
        retirements.sort_unstable();
        retirements.dedup();
        (
            PersistDirective {
                job,
                staged_retention,
                release_after_enqueue,
            },
            FrozenAcknowledgement {
                retention,
                retirements,
                forwarded_nullifications,
            },
        )
    }

    /// Stages a publication's artifacts for resolver custody.
    ///
    /// A proposal's block and parent are not staged.
    fn extend_publication(
        publication: &Publication<V, H::Digest>,
        retention: &mut Vec<Arc<Artifact<V, H::Digest>>>,
    ) {
        retention.extend(publication.artifacts().cloned());
    }

    pub(crate) fn emit_staged(&mut self) -> Capabilities<V, H::Digest> {
        let Some(index) = self.next_staged_index() else {
            return Capabilities::new();
        };
        let batch = &self.pipeline.staged[index];
        let job = batch.job.clone();
        let release_after_enqueue = batch.release_after_enqueue.clone();
        let (persist, acknowledgement) = self.freeze_persistence(job, release_after_enqueue);
        let batch = &mut self.pipeline.staged[index];
        batch.emitted = true;
        debug_assert!(batch.acknowledgement.is_none());
        batch.acknowledgement = Some(acknowledgement);
        vec![Capability::Journal(persist)]
    }

    /// Acknowledges the oldest in-flight barrier and releases its external effects.
    ///
    /// The barrier's events were applied at staging; durability only opens the gate for the
    /// actions they authorized to leave the process.
    pub(super) fn complete_persistence(
        &mut self,
        completion: BarrierAck,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if self.pipeline.last_barrier == Some(completion) {
            return Ok(Step::stale());
        }
        let Some(pending) = self.pipeline.staged.front() else {
            if self
                .pipeline
                .last_barrier
                .is_some_and(|applied| completion.generation() < applied.generation())
            {
                return Ok(Step::stale());
            }
            return Err(StepError::CompletionMismatch);
        };
        if completion.generation() < pending.job.generation() {
            return Ok(Step::stale());
        }
        if !pending.emitted
            || completion.barrier() != pending.job.id()
            || completion.generation() != pending.job.generation()
            || completion.cursor() != pending.job.last_cursor()
        {
            return Err(StepError::CompletionMismatch);
        }

        let pending = self
            .pipeline
            .staged
            .pop_front()
            .expect("persistence job was just matched");
        let starts_generation = pending.starts_generation();
        let acknowledgement = pending
            .acknowledgement
            .expect("an emitted persistence job freezes its acknowledgement directives");
        self.pipeline.acked = completion.cursor();
        self.pipeline.last_barrier = Some(completion);
        let FrozenAcknowledgement {
            retention,
            retirements,
            forwarded_nullifications,
        } = acknowledgement;
        let mut capabilities = Capabilities::new();
        if !retention.is_empty() || forwarded_nullifications != 0 {
            capabilities.push(Capability::Acknowledged {
                retention,
                forwarded_nullifications,
            });
        }
        if starts_generation {
            // Re-releasing the recovered outbox subsumes its deferred entries. Process-local
            // resolver proofs keep their individual signature floors across this boundary.
            self.pipeline
                .deferred_releases
                .retain(|(_, release)| matches!(release, DeferredRelease::Retain(_)));
            let mut released = self
                .durable
                .state
                .signing_reservations
                .keys()
                .copied()
                .chain(self.durable.state.outbox.keys().copied())
                .collect::<Vec<_>>();
            released.sort_unstable();
            self.release_outbox(released, &mut capabilities);
        }
        while let Some((floor, _)) = self.pipeline.deferred_releases.front() {
            if *floor > self.pipeline.acked {
                break;
            }
            let (_, release) = self
                .pipeline
                .deferred_releases
                .pop_front()
                .expect("the deferred front was just inspected");
            match release {
                DeferredRelease::Outbox(id) => self.release_outbox([id], &mut capabilities),
                DeferredRelease::Retain(artifact) => {
                    capabilities.push(Capability::Retain(artifact))
                }
            }
        }
        self.sync_signing_completions();
        self.wake_components();
        // Acknowledgement may unblock the next batch in the pipeline.
        capabilities.extend(self.emit_staged());
        if !retirements.is_empty() {
            capabilities.push(Capability::Retire(retirements));
        }
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    pub(super) fn restore_ready_artifacts(
        &mut self,
    ) -> Result<Vec<Activity<V, H::Digest>>, StepError> {
        let mut ready = self
            .store
            .artifacts
            .iter()
            .filter_map(|(id, entry)| {
                matches!(entry.state, ArtifactState::Ready).then_some((
                    entry.observation,
                    *id,
                    Arc::clone(&entry.artifact),
                ))
            })
            .collect::<Vec<_>>();
        ready.sort_unstable_by_key(|(observation, id, _)| (*observation, *id));
        for (observation, id, artifact) in &ready {
            self.claim_finality(*id, *observation, Arc::clone(artifact))?;
            self.validate_finality(*id, *observation, artifact, None)?;
            self.chain.observe::<H>(*id, *observation, artifact)?;
            self.views.observe::<H>(*id, *observation, artifact, None)?;
        }
        let mut activities = Vec::with_capacity(ready.len());
        for (_, artifact_id, artifact) in ready {
            self.push_acceptance(artifact_id, artifact, &mut activities);
        }
        Ok(activities)
    }

    pub(crate) fn retain_durable_artifact(
        &mut self,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), ReplayError> {
        let references = self.durable.artifact_references.entry(id).or_default();
        *references = references
            .checked_add(1)
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        Ok(())
    }

    pub(crate) fn release_durable_artifact(
        &mut self,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), ReplayError> {
        let Some(references) = self.durable.artifact_references.get_mut(&id) else {
            return Err(ReplayError::Transition(TransitionReason::References));
        };
        *references = references
            .checked_sub(1)
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        if *references == 0 {
            self.durable.artifact_references.remove(&id);
            self.note_retirement_candidate(id);
        }
        Ok(())
    }

    /// Returns the artifact identifiers an effect carries, hashing each artifact once.
    pub(crate) fn effect_artifact_ids(
        effect: &DurableEffect<V, H::Digest>,
    ) -> Vec<ArtifactId<H::Digest>> {
        let mut ids = Vec::new();
        effect.visit_references::<H>(|id| ids.push(id));
        ids
    }

    /// Retains an effect's artifacts and signing reservations and caches its identifiers for
    /// later release.
    ///
    /// `ids` must be the effect's own visited identifiers; callers that already computed them
    /// for validation pass them through so each artifact is hashed exactly once.
    pub(crate) fn admit_durable_effect(
        &mut self,
        id: EffectId,
        reservations: usize,
        ids: Vec<ArtifactId<H::Digest>>,
    ) -> Result<(), ReplayError> {
        for artifact in ids.iter().copied() {
            self.retain_durable_artifact(artifact)?;
        }
        self.durable.signing_reservations = self
            .durable
            .signing_reservations
            .checked_add(reservations)
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        self.durable.effect_ids.insert(id, ids);
        Ok(())
    }

    /// Releases an effect's artifacts using its cached identifiers.
    pub(crate) fn release_durable_effect(
        &mut self,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        let ids = self
            .durable
            .effect_ids
            .remove(&id)
            .unwrap_or_else(|| Self::effect_artifact_ids(effect));
        for artifact in ids {
            self.release_durable_artifact(artifact)?;
        }
        self.durable.signing_reservations = self
            .durable
            .signing_reservations
            .checked_sub(effect.reservations())
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        Ok(())
    }

    fn release_outbox(
        &mut self,
        ids: impl IntoIterator<Item = EffectId>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) {
        for id in ids {
            if let Some(job) = self.release_outbox_job(id) {
                capabilities.push(Capability::Released(job));
            }
        }
    }

    fn release_outbox_job(&mut self, id: EffectId) -> Option<DurableJob<V, H::Digest>> {
        let effect = self.durable_effect(id)?;
        if !effect.authorized::<H>(&self.profile) {
            return None;
        }
        if let DurableEffect::Sign(sign) = &effect {
            self.chain
                .issue_signing(Issued::new(id, self.durable.state.generation), sign)
                .expect("a released DA signing effect has an exact durable reservation");
        }
        Some(DurableJob::new(
            Issued::new(id, self.durable.state.generation),
            effect,
        ))
    }

    pub(crate) fn reserve_effect(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.check_effect_capacity(&effect, 0, &[])?;
        self.reserve_effect_prechecked(effect)
    }

    /// Stages one capacity-checked effect.
    ///
    /// Callers that consume a volatile reservation (build or vote slots) check capacity while
    /// the reservation is still outstanding, consume it, and only then stage: application runs
    /// at staging and expects the consumed slot to exist.
    pub(super) fn reserve_effect_prechecked(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let id = self.next_effect_id()?;
        self.reserve_change(Change::OutboxQueued {
            id,
            effect: Box::new(effect),
        })
    }

    /// Returns the effect identifier the next staged event will mint.
    ///
    /// An effect is identified by the cursor of the event that queues it.
    pub(super) fn next_effect_id(&self) -> Result<EffectId, StepError> {
        self.durable
            .state
            .cursor
            .next()
            .map(EffectId::from_cursor)
            .ok_or(StepError::IdentifierExhausted)
    }

    /// Returns whether the durable set already holds this locally created artifact.
    ///
    /// Artifact creation is unique by identifier, and staging applies the same transition replay
    /// does, so creating a held artifact again would journal an event no restart could re-derive.
    /// A completion that rediscovers a held artifact is redundant, not a fault.
    pub(super) fn already_held(&self, id: ArtifactId<H::Digest>) -> bool {
        self.durable.state.local.contains_key(&id)
    }
}
