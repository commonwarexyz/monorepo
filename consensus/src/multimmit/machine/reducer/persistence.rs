//! Staging durable changes and the journal barrier pipeline.
//!
//! Staging is application: [`Machine::reserve_change`] applies an event through the same
//! transition replay uses, then queues it for group commit. Durability only opens the gate for the
//! external actions the event authorized.

use super::{
    MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_INFLIGHT_BARRIERS, MAX_STAGED_BARRIERS, machine::Machine,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::{Capabilities, Capability, ResolverCommand},
            durability::{
                BarrierAck, BatchId, Change, Cursor, DomainEvent, DurableEffect, DurableJob,
                EffectId, PersistDirective, PersistJob,
            },
            input::{Step, StepError, StepStatus},
            job::Issued,
        },
        types::{Activity, Artifact},
    },
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::VecDeque, sync::Arc};

/// Artifacts to install in resolver custody.
type Retention<V, D> = Vec<Arc<Artifact<V, D>>>;

/// A process-local release held until the journal acknowledges the own-signature exposure floor.
#[derive(Clone, Debug)]
pub(crate) enum DeferredRelease<V: Variant, D: Digest> {
    /// Release the outbox effect.
    Outbox(EffectId),
    /// Install the certificate in resolver custody.
    Retain(Arc<Artifact<V, D>>),
}

/// One group-commit batch of staged events awaiting durability.
///
/// Staged events are already applied to machine state; the batch exists to make them durable and
/// to release their external work once the journal acknowledges it. While a barrier is in flight,
/// new events absorb into the open batch at the back of the queue, so batch sizes scale with
/// storage latency instead of forcing one sync per event.
#[derive(Clone, Debug)]
pub(crate) struct PendingPersistence<V: Variant, D: Digest> {
    pub(crate) job: PersistJob<V, D>,
    /// Independently verifiable publications released once the batch enters the journal.
    pub(crate) release_after_enqueue: Vec<DurableJob<V, D>>,
    /// Artifacts installed in resolver custody once the batch enters the journal.
    pub(crate) staged_retention: Vec<Arc<Artifact<V, D>>>,
    /// Artifacts installed in resolver custody once the batch is durable.
    pub(crate) retention: Vec<Arc<Artifact<V, D>>>,
    /// Publications whose attempts retire once the batch is durable.
    pub(crate) retirements: Vec<EffectId>,
    /// Activities reported once the batch is durable.
    pub(crate) reports: Vec<Activity<V, D>>,
    /// Whether the batch was handed to the journal.
    pub(crate) emitted: bool,
    /// Encoded bytes of the batch's events.
    pub(crate) bytes: usize,
}

impl<V: Variant, D: Digest> PendingPersistence<V, D> {
    fn starts_generation(&self) -> bool {
        self.job
            .events()
            .iter()
            .any(|event| matches!(event.change(), Change::GenerationAdvanced(_)))
    }
}

/// The journal pipeline: staged batches, acknowledgements, and release ordering.
pub(crate) struct Pipeline<V: Variant, D: Digest> {
    /// Batches of staged, already-applied events awaiting durability, in cursor order. The back
    /// batch stays open for absorption until it fills or is emitted.
    pub(in crate::multimmit::machine) staged: VecDeque<PendingPersistence<V, D>>,
    /// Cursor of the last acknowledged event. The durable state's cursor leads it by the staged
    /// batches.
    pub(in crate::multimmit::machine) acked: Cursor,
    /// The most recently applied acknowledgement, which may be delivered again.
    last_barrier: Option<BarrierAck>,
    /// Cursor of the latest event that records a fresh local signature.
    ///
    /// Work that may carry one of this node's signatures releases only once `acked` reaches
    /// this floor, so no signature leaves the process before its record is durable.
    own_exposure: Cursor,
    /// Cursor of the event that started the current generation.
    ///
    /// Nothing leaves the process before the generation is durable, so every release waits for
    /// `acked` to reach this floor.
    generation_floor: Cursor,
    /// Releases awaiting their floor, in floor order.
    deferred: VecDeque<(Cursor, DeferredRelease<V, D>)>,
    next_barrier: u64,
}

impl<V: Variant, D: Digest> Pipeline<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            staged: VecDeque::new(),
            acked: Cursor::zero(),
            last_barrier: None,
            own_exposure: Cursor::zero(),
            generation_floor: Cursor::zero(),
            deferred: VecDeque::new(),
            next_barrier: 0,
        }
    }

    /// Returns the floor a release that may carry one of this node's signatures waits for.
    fn exposure_floor(&self) -> Cursor {
        self.own_exposure.max(self.generation_floor)
    }

    /// Holds `release` until `floor` is acknowledged, keeping the queue in floor order.
    fn defer(&mut self, floor: Cursor, release: DeferredRelease<V, D>) {
        let index = self.deferred.partition_point(|(held, _)| *held <= floor);
        self.deferred.insert(index, (floor, release));
    }

    /// Returns the identifier of the oldest unacknowledged batch.
    pub(crate) fn pending_barrier(&self) -> Option<BatchId> {
        self.staged.front().map(|pending| pending.job.id())
    }

    /// Returns the index of the next batch to hand to the journal.
    ///
    /// Batches emit in cursor order, one per call. The open batch at the back emits only when it
    /// is the sole staged batch, so it keeps absorbing events while barriers are in flight. An
    /// urgent batch, or one with publications awaiting enqueue, forces every batch up to it out,
    /// even past [`MAX_INFLIGHT_BARRIERS`].
    pub(super) fn next_staged_index(&self) -> Option<usize> {
        let staged = self.staged.len();
        let inflight = self.staged.iter().filter(|batch| batch.emitted).count();
        let force_through = self.staged.iter().rposition(|batch| {
            !batch.emitted && (batch.job.urgent() || !batch.release_after_enqueue.is_empty())
        });
        let (index, batch) = self
            .staged
            .iter()
            .enumerate()
            .find(|(_, batch)| !batch.emitted)?;
        let forced = force_through.is_some_and(|through| index <= through);
        if inflight >= MAX_INFLIGHT_BARRIERS && !forced {
            return None;
        }
        let full = batch.job.events().len() >= MAX_BATCH_EVENTS || batch.bytes >= MAX_BATCH_BYTES;
        if index + 1 == staged && staged > 1 && !full && !forced {
            return None;
        }
        Some(index)
    }
}

/// How the batch that stages one event releases its work.
struct StagedRelease<V: Variant, D: Digest> {
    urgent: bool,
    release_after_enqueue: Option<DurableJob<V, D>>,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Stages one durable change: applies it and queues it for group commit.
    ///
    /// An effect that may carry one of this node's signatures releases only once the journal
    /// acknowledges its exposure floor; for a fresh signature that floor is the event itself.
    /// Forwarded certificates release once their batch enters the journal; other independently
    /// verifiable work releases in the returned capabilities.
    pub(in crate::multimmit::machine) fn reserve_change(
        &mut self,
        change: Change<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let previous = self.durable.state.cursor;
        let cursor = previous.next().ok_or(StepError::IdentifierExhausted)?;
        let event = DomainEvent::new(self.profile.protocol().epoch(), cursor, change);
        let bytes = event.encode_size();
        let open = self.pipeline.staged.back().is_some_and(|open| {
            !open.emitted
                && open.job.events().len() < MAX_BATCH_EVENTS
                && open.bytes.saturating_add(bytes) <= MAX_BATCH_BYTES
        });
        if !open && self.pipeline.staged.len() >= MAX_STAGED_BARRIERS {
            return Err(StepError::PersistenceCapacity);
        }
        let retired_before = self.durable.state.retired_view;
        let retirements =
            self.apply_event(&event)
                .map_err(|source| StepError::DurableTransition {
                    change: event.change().kind(),
                    source,
                })?;

        let mut capabilities = Capabilities::new();
        let retired = self.durable.state.retired_view;
        if retired > retired_before {
            self.resolution.prune(retired);
            capabilities.push(Capability::Resolver(ResolverCommand::Prune(retired)));
        }
        let release = self.release_policy(&event, &mut capabilities);
        let (staged_retention, retention) = self.event_retention(&event, &mut capabilities);
        let StagedRelease {
            urgent,
            release_after_enqueue,
        } = release;
        if open {
            let batch = self
                .pipeline
                .staged
                .back_mut()
                .expect("the open batch is staged");
            batch.job.push_event(event, urgent);
            batch.release_after_enqueue.extend(release_after_enqueue);
            batch.staged_retention.extend(staged_retention);
            batch.retention.extend(retention);
            batch.retirements.extend(retirements);
            batch.bytes = batch.bytes.saturating_add(bytes);
            return Ok(capabilities);
        }
        let id = BatchId::new(self.pipeline.next_barrier);
        self.pipeline.next_barrier = self
            .pipeline
            .next_barrier
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;
        self.pipeline.staged.push_back(PendingPersistence {
            job: PersistJob::new(
                id,
                self.durable.state.generation,
                previous,
                vec![event],
                urgent,
            ),
            release_after_enqueue: release_after_enqueue.into_iter().collect(),
            staged_retention,
            retention,
            retirements,
            reports: Vec::new(),
            emitted: false,
            bytes,
        });
        Ok(capabilities)
    }

    /// Reports `activities` once the batch holding the newest staged event is durable.
    ///
    /// # Panics
    ///
    /// Panics unless an event is staged.
    pub(in crate::multimmit::machine) fn report_when_durable(
        &mut self,
        activities: impl IntoIterator<Item = Activity<V, H::Digest>>,
    ) {
        self.pipeline
            .staged
            .back_mut()
            .expect("an event is staged")
            .reports
            .extend(activities);
    }

    /// Installs `artifacts` in resolver custody once the batch holding the newest staged event is
    /// durable.
    ///
    /// # Panics
    ///
    /// Panics unless an event is staged.
    pub(in crate::multimmit::machine) fn serve_when_durable(
        &mut self,
        artifacts: impl IntoIterator<Item = Arc<Artifact<V, H::Digest>>>,
    ) {
        self.pipeline
            .staged
            .back_mut()
            .expect("an event is staged")
            .retention
            .extend(artifacts);
    }

    /// Reports `activities` after every activity reported before: once the newest staged batch is
    /// durable, or at once when nothing is staged.
    pub(in crate::multimmit::machine) fn report_in_order(
        &mut self,
        activities: impl IntoIterator<Item = Activity<V, H::Digest>>,
    ) {
        match self.pipeline.staged.back_mut() {
            Some(batch) => batch.reports.extend(activities),
            None => self.activities.extend(activities),
        }
    }

    /// Returns whether `count` more batches can be staged.
    pub(in crate::multimmit::machine) fn has_batch_room(&self, count: usize) -> bool {
        self.pipeline.staged.len().saturating_add(count) <= MAX_STAGED_BARRIERS
    }

    /// Serves `artifact` once every staged batch is durable, or at once when nothing is staged.
    pub(in crate::multimmit::machine) fn serve_in_order(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) {
        match self.pipeline.staged.back_mut() {
            Some(batch) => batch.retention.push(artifact),
            None => capabilities.push(Capability::Retain(artifact)),
        }
    }

    /// Decides when the outbox effect an applied event queues may leave the process.
    fn release_policy(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> StagedRelease<V, H::Digest> {
        let change = event.change();
        // A new generation re-releases the recovered outbox at its acknowledgement.
        let urgent = matches!(change, Change::GenerationAdvanced(_));
        if urgent {
            self.pipeline.generation_floor = event.cursor();
        }
        let Some(id) = change.queued_effect() else {
            return StagedRelease {
                urgent,
                release_after_enqueue: None,
            };
        };
        if change.records_local_signature() {
            self.pipeline.own_exposure = event.cursor();
            self.pipeline
                .defer(event.cursor(), DeferredRelease::Outbox(id));
            return StagedRelease {
                urgent: true,
                release_after_enqueue: None,
            };
        }
        let me = match self.profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        let exposes = self
            .durable
            .state
            .publication(&id)
            .is_some_and(|publication| publication.references_own_signature(me));
        let floor = if exposes {
            self.pipeline.exposure_floor()
        } else {
            self.pipeline.generation_floor
        };
        let mut release_after_enqueue = None;
        if floor > self.pipeline.acked {
            self.pipeline.defer(floor, DeferredRelease::Outbox(id));
        } else if matches!(change, Change::ArtifactForwarded { .. }) {
            release_after_enqueue = self.release_outbox_job(id);
        } else {
            capabilities.extend(self.release_outbox_job(id).map(Capability::Released));
        }
        StagedRelease {
            urgent,
            release_after_enqueue,
        }
    }

    /// Returns the artifacts an applied event makes servable once its batch enters the journal and
    /// once it is durable, and retains a certificate behind the exposure floor while it is
    /// unacknowledged.
    fn event_retention(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> (Retention<V, H::Digest>, Retention<V, H::Digest>) {
        match event.change() {
            Change::SignedArtifacts {
                publication: id, ..
            }
            | Change::OutboxQueued { id, .. } => {
                // This node's vote updates are served in the form naming every chain, which
                // signing completion stages beside the record.
                let retention = self
                    .durable
                    .state
                    .publication(id)
                    .map(|publication| {
                        publication
                            .artifacts()
                            .iter()
                            .filter(|artifact| !matches!(artifact.as_ref(), Artifact::Update(_)))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                (Vec::new(), retention)
            }
            Change::ArtifactForwarded { artifact, .. }
            | Change::CertificateCreated { artifact } => {
                // A certificate may aggregate this node's votes, so it is served only once every
                // fresh local signature it could carry is durable: a forwarded one from its batch,
                // a created one at once.
                let floor = self.pipeline.exposure_floor();
                if floor > self.pipeline.acked {
                    self.pipeline
                        .defer(floor, DeferredRelease::Retain(Arc::clone(artifact)));
                } else if matches!(event.change(), Change::ArtifactForwarded { .. }) {
                    return (vec![Arc::clone(artifact)], Vec::new());
                } else {
                    capabilities.push(Capability::Retain(Arc::clone(artifact)));
                }
                (Vec::new(), Vec::new())
            }
            Change::GenerationAdvanced(_)
            | Change::Accepted { .. }
            | Change::EmissionResolved { .. }
            | Change::ViewEntered { .. }
            | Change::RetentionAdvanced { .. }
            | Change::Anchored { .. } => (Vec::new(), Vec::new()),
        }
    }

    /// Hands the next eligible batch to the journal.
    pub(in crate::multimmit::machine) fn emit_staged(&mut self) -> Capabilities<V, H::Digest> {
        let Some(index) = self.pipeline.next_staged_index() else {
            return Capabilities::new();
        };
        let batch = &mut self.pipeline.staged[index];
        batch.emitted = true;
        vec![Capability::Journal(PersistDirective {
            job: batch.job.clone(),
            staged_retention: core::mem::take(&mut batch.staged_retention),
            release_after_enqueue: core::mem::take(&mut batch.release_after_enqueue),
        })]
    }

    /// Acknowledges the oldest in-flight barrier and releases the external work it gated.
    pub(super) fn complete_persistence(
        &mut self,
        ack: BarrierAck,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if self.pipeline.last_barrier == Some(ack) {
            return Ok(Step::stale());
        }
        let Some(pending) = self.pipeline.staged.front() else {
            if self
                .pipeline
                .last_barrier
                .is_some_and(|applied| ack.generation() < applied.generation())
            {
                return Ok(Step::stale());
            }
            return Err(StepError::CompletionMismatch);
        };
        if ack.generation() < pending.job.generation() {
            return Ok(Step::stale());
        }
        if !pending.emitted
            || ack.barrier() != pending.job.id()
            || ack.generation() != pending.job.generation()
            || ack.cursor() != pending.job.last_cursor()
        {
            return Err(StepError::CompletionMismatch);
        }
        let mut pending = self
            .pipeline
            .staged
            .pop_front()
            .expect("the acknowledged batch is staged");
        self.pipeline.acked = ack.cursor();
        self.pipeline.last_barrier = Some(ack);
        self.activities.append(&mut pending.reports);
        self.scheduler.wake_blocked();

        let mut capabilities = Capabilities::new();
        if !pending.retention.is_empty() {
            capabilities.push(Capability::Acknowledged {
                retention: pending.retention.clone(),
            });
        }
        if pending.starts_generation() {
            // Every effect queued at or below the acknowledged cursor is durable and releases
            // under the new generation, which subsumes its deferred entry. An effect queued later
            // keeps its own floor.
            let acked = self.pipeline.acked;
            self.pipeline.deferred.retain(|(_, release)| match release {
                DeferredRelease::Outbox(id) => id.get() > acked.get(),
                DeferredRelease::Retain(_) => true,
            });
            let mut released = self
                .durable
                .state
                .effect_ids()
                .filter(|id| id.get() <= acked.get())
                .collect::<Vec<_>>();
            released.sort_unstable();
            for id in released {
                capabilities.extend(self.release_outbox_job(id).map(Capability::Released));
            }
        }
        while self
            .pipeline
            .deferred
            .front()
            .is_some_and(|(floor, _)| *floor <= self.pipeline.acked)
        {
            let (_, release) = self
                .pipeline
                .deferred
                .pop_front()
                .expect("the deferred front was inspected");
            match release {
                DeferredRelease::Outbox(id) => {
                    capabilities.extend(self.release_outbox_job(id).map(Capability::Released));
                }
                DeferredRelease::Retain(artifact) => {
                    capabilities.push(Capability::Retain(artifact));
                }
            }
        }
        capabilities.extend(self.emit_staged());
        if !pending.retirements.is_empty() {
            capabilities.push(Capability::Retire(pending.retirements));
        }
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    /// Returns the job releasing the outstanding effect `id`, or `None` once it retired or
    /// when the profile cannot authorize it.
    fn release_outbox_job(&mut self, id: EffectId) -> Option<DurableJob<V, H::Digest>> {
        let effect = self.durable_effect(id)?;
        if !effect.authorized::<H>(&self.profile) {
            return None;
        }
        let issued = Issued::new(id, self.durable.state.generation);
        if matches!(effect, DurableEffect::Sign(_)) {
            self.signing_issued.entry(id).or_insert(issued.generation());
        }
        Some(DurableJob::new(issued, effect))
    }

    /// Returns an owned copy of the outstanding effect `id`.
    pub(in crate::multimmit::machine) fn durable_effect(
        &self,
        id: EffectId,
    ) -> Option<DurableEffect<V, H::Digest>> {
        let state = &self.durable.state;
        state
            .signing(&id)
            .cloned()
            .map(DurableEffect::Sign)
            .or_else(|| state.publication(&id).cloned().map(DurableEffect::Publish))
    }

    /// Returns the identifier the next staged event mints for an effect it queues.
    pub(in crate::multimmit::machine) fn next_effect_id(&self) -> Result<EffectId, StepError> {
        self.durable
            .state
            .cursor
            .next()
            .map(EffectId::from_cursor)
            .ok_or(StepError::IdentifierExhausted)
    }

    /// Stages `effect` in the outbox after checking that it fits its bounds.
    ///
    /// Capacity pressure is reported as [`StepError::OutboxFull`] or
    /// [`StepError::LocalArtifactReservation`] without staging anything, so a component can
    /// retry once an acknowledgement releases capacity.
    pub(in crate::multimmit::machine) fn reserve_effect(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let resources = self.profile.resources();
        if self.durable.state.effect_count() >= resources.max_outbox_effects() {
            return Err(StepError::OutboxFull);
        }
        if !effect.authorized::<H>(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }
        let mut ids = Vec::new();
        effect.visit_retained(|retained| ids.push(retained.id::<H>()));
        let occupancy = self
            .durable
            .occupancy_after(&ids, &[], effect.reservations(), 0)
            .and_then(|durable| durable.checked_add(self.store.len()));
        if occupancy.is_none_or(|occupancy| occupancy > resources.max_cached_artifacts()) {
            return Err(StepError::LocalArtifactReservation);
        }
        let id = self.next_effect_id()?;
        self.reserve_change(Change::OutboxQueued {
            id,
            effect: Box::new(effect),
        })
    }
}
