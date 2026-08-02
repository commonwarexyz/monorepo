//! State ownership and normalized inspection.

use super::{
    Artifact, ArtifactBatch, ArtifactId, BarrierAck, BarrierId, Capability, ChainState, Change,
    Cursor, Dependency, DurableEffect, DurableJob, DurableState, EffectId, FinalityFact, Input,
    JobId, Observation, PersistJob, PoolSummary, Profile, ReplayError, ResolutionCompletion,
    ResolutionJob, Role, Scheduler, SignRequest, Snapshot, VerificationTicket,
    finality::{FinalityState, PreparedLqc},
    view::ViewState,
};
use crate::{
    Viewable as _,
    multimmit::types::{CertificateId, ChainId, Context, Height},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub(crate) enum ArtifactState<D: Digest> {
    Pending(VerificationTicket<D>),
    Waiting(BTreeSet<Dependency<D>>),
    Ready,
    Dropped,
}

#[derive(Clone, Debug)]
pub(crate) struct ArtifactEntry<V: Variant, D: Digest> {
    pub artifact: Arc<Artifact<V, D>>,
    pub provisions: Arc<[Dependency<D>]>,
    pub observation: Observation,
    pub state: ArtifactState<D>,
    pub dependency_protected: bool,
    pub future: bool,
    pub view_observed: bool,
    pub dependency_slot: bool,
}

/// One artifact promoted to [`ArtifactState::Ready`], as admission telemetry needs it.
pub(crate) type ReadyPromotion<V, D> = (Observation, ArtifactId<D>, Arc<Artifact<V, D>>);

/// An acknowledged checkpoint cut whose derived projections can be built off the voter task.
pub(crate) struct CheckpointCut<H: Hasher, V: Variant> {
    epoch: Epoch,
    role: Role,
    state: DurableState<V, H::Digest>,
}

impl<H: Hasher, V: Variant> CheckpointCut<H, V> {
    pub(crate) const fn cursor(&self) -> Cursor {
        self.state.cursor
    }

    pub(crate) const fn retired_view(&self) -> View {
        self.state.retired_view
    }

    pub(crate) fn materialize(self) -> Snapshot<V, H::Digest> {
        Snapshot::new::<H>(self.epoch, self.role, self.state)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResolutionStatus<D: Digest> {
    InFlight,
    Verifying(ArtifactId<D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ResolutionRecord<D: Digest> {
    job: ResolutionJob,
    status: ResolutionStatus<D>,
}

/// Machine-wide ownership of bounded immutable-object resolution work.
///
/// Jobs remain keyed by view while an attempt is in flight or its decoded artifact is undergoing
/// ordinary verification. Removing a failed attempt permits the same view to be
/// retried with a fresh identifier while retaining the process generation.
pub(crate) struct ResolutionState<D: Digest> {
    records: BTreeMap<View, ResolutionRecord<D>>,
    next_id: u64,
}

impl<D: Digest> ResolutionState<D> {
    const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// Issues one deduplicated job without exceeding the shared dependency-work bound.
    pub(crate) fn request(
        &mut self,
        generation: u64,
        view: View,
        limit: usize,
    ) -> Result<Option<ResolutionJob>, ()> {
        if self.records.contains_key(&view) || self.records.len() >= limit {
            return Ok(None);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(())?;
        let job = ResolutionJob::issue(id, generation, view);
        self.records.insert(
            view,
            ResolutionRecord {
                job,
                status: ResolutionStatus::InFlight,
            },
        );
        Ok(Some(job))
    }

    pub(crate) fn matches<V: Variant>(&self, completion: &ResolutionCompletion<V, D>) -> bool {
        self.records.get(&completion.view()).is_some_and(|record| {
            record.status == ResolutionStatus::InFlight
                && record.job.id() == completion.id()
                && record.job.generation() == completion.generation()
        })
    }

    pub(crate) fn begin_verification(&mut self, view: View, artifact: ArtifactId<D>) {
        if let Some(record) = self.records.get_mut(&view) {
            record.status = ResolutionStatus::Verifying(artifact);
        }
    }

    pub(crate) fn verification_ready(&mut self, artifact: ArtifactId<D>) -> Vec<View> {
        self.records
            .iter()
            .filter_map(|(key, record)| {
                matches!(record.status, ResolutionStatus::Verifying(verifying) if verifying == artifact)
                    .then_some(*key)
            })
            .collect()
    }

    pub(crate) fn verification_failed(&mut self, artifact: ArtifactId<D>) -> Vec<ResolutionJob> {
        let failed = self
            .records
            .iter()
            .filter_map(|(key, record)| match record.status {
                ResolutionStatus::Verifying(verifying) if verifying == artifact => {
                    Some((*key, record.job))
                }
                ResolutionStatus::InFlight | ResolutionStatus::Verifying(_) => None,
            })
            .collect::<Vec<_>>();
        for (key, _) in &failed {
            self.records.remove(key);
        }
        failed.into_iter().map(|(_, job)| job).collect()
    }

    pub(crate) fn resolved(&mut self, view: View) -> Option<ResolutionJob> {
        self.records.remove(&view).map(|record| record.job)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = View> + '_ {
        self.records.keys().copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
}

/// One producer chain's local progress for diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChainProgress {
    chain: ChainId,
    finalized: Height,
    certified: Height,
    known: Height,
}

impl ChainProgress {
    /// Returns the producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the greatest height established by retained local finality.
    pub const fn finalized(self) -> Height {
        self.finalized
    }

    /// Returns the greatest height backed by a retained DA certificate.
    pub const fn certified(self) -> Height {
        self.certified
    }

    /// Returns the greatest locally usable, certified, or finalized height.
    pub const fn known(self) -> Height {
        self.known
    }
}

/// The local producer's current build and DA-certificate state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProducerProgress {
    chain: ChainId,
    produced: Height,
    certified: Height,
    vote_shares: usize,
    da_quorum: usize,
    pipeline_depth: u64,
    ready_recovery: bool,
    pending_recovery: bool,
    active_recovery: bool,
    wake: bool,
    timer_armed: bool,
    build_pending: bool,
    production_credit: bool,
}

impl ProducerProgress {
    /// Returns the local producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }
    /// Returns the latest locally produced height.
    pub const fn produced(self) -> Height {
        self.produced
    }
    /// Returns the latest locally held DA-certified height.
    pub const fn certified(self) -> Height {
        self.certified
    }
    /// Returns distinct DA shares held for the produced tip.
    pub const fn vote_shares(self) -> usize {
        self.vote_shares
    }
    /// Returns the DA share quorum.
    pub const fn da_quorum(self) -> usize {
        self.da_quorum
    }
    /// Returns the configured producer pipeline depth.
    pub const fn pipeline_depth(self) -> u64 {
        self.pipeline_depth
    }
    /// Returns whether the produced tip is ready to schedule DA recovery.
    pub const fn ready_recovery(self) -> bool {
        self.ready_recovery
    }
    /// Returns whether recovery is reserved for the produced tip.
    pub const fn pending_recovery(self) -> bool {
        self.pending_recovery
    }
    /// Returns whether recovery is executing for the produced tip.
    pub const fn active_recovery(self) -> bool {
        self.active_recovery
    }
    /// Returns whether production has a pending wake.
    pub const fn wake(self) -> bool {
        self.wake
    }
    /// Returns whether the production delay timer is armed.
    pub const fn timer_armed(self) -> bool {
        self.timer_armed
    }
    /// Returns whether an application build is pending.
    pub const fn build_pending(self) -> bool {
        self.build_pending
    }
    /// Returns whether durable-effect capacity permits another build.
    pub const fn production_credit(self) -> bool {
        self.production_credit
    }

    /// Returns whether another build is blocked by the DA pipeline window.
    pub const fn pipeline_blocked(self) -> bool {
        self.produced.get().saturating_sub(self.certified.get()) >= self.pipeline_depth
    }
}

/// Read-only normalized state intended for tests, metrics, and diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection<D: Digest> {
    epoch: Epoch,
    view: View,
    generation: u64,
    cursor: Cursor,
    live: bool,
    recovering: bool,
    cached_artifacts: usize,
    pending_artifacts: usize,
    waiting_artifacts: usize,
    ready_artifacts: Vec<ArtifactId<D>>,
    dropped_artifacts: usize,
    future_artifacts: usize,
    verification_jobs: Vec<JobId>,
    pending_barrier: Option<BarrierId>,
    local_artifacts: usize,
    outbox: Vec<EffectId>,
    produced_blocks: u64,
    producer: Option<ProducerProgress>,
    resolution_jobs: usize,
    chain_progress: Vec<ChainProgress>,
    pools: Vec<PoolSummary<D>>,
    finality: Vec<FinalityFact<D>>,
    retained_artifact_references: usize,
    nullification_suffix: u64,
    retired_view: View,
    finality_floor: View,
}

/// Lightweight operational projection for actor-owned metrics.
pub(crate) struct Progress {
    pub view: View,
    pub retired_view: View,
    pub finality_floor: View,
    pub proposal_anchor_view: View,
    pub produced_blocks: u64,
    pub producer: Option<ProducerProgress>,
}

impl<D: Digest> Inspection<D> {
    /// Returns the machine's immutable epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the current local view.
    pub const fn view(&self) -> View {
        self.view
    }

    /// Returns the local producer's build and DA-certificate state.
    pub const fn producer(&self) -> Option<ProducerProgress> {
        self.producer
    }

    /// Returns the number of artifacts pinned by durable safety state.
    pub const fn retained_artifact_references(&self) -> usize {
        self.retained_artifact_references
    }

    /// Returns the length of the exact nullification suffix above the proposal anchor.
    pub const fn nullification_suffix(&self) -> u64 {
        self.nullification_suffix
    }

    /// Returns the durable transition floor.
    pub const fn retired_view(&self) -> View {
        self.retired_view
    }

    /// Returns the durable consensus signing floor.
    pub const fn finality_floor(&self) -> View {
        self.finality_floor
    }

    /// Returns the current completion-correlation generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the last acknowledged durable journal cursor.
    pub const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns whether normal live inputs may be processed.
    pub const fn is_live(&self) -> bool {
        self.live
    }

    /// Returns whether silent journal replay is still permitted.
    pub const fn is_recovering(&self) -> bool {
        self.recovering
    }

    /// Returns the number of retained exact artifact records.
    pub const fn cached_artifacts(&self) -> usize {
        self.cached_artifacts
    }

    /// Returns the number of artifacts awaiting cryptographic verification.
    pub const fn pending_artifacts(&self) -> usize {
        self.pending_artifacts
    }

    /// Returns the number of authenticated artifacts waiting on immutable dependencies.
    pub const fn waiting_artifacts(&self) -> usize {
        self.waiting_artifacts
    }

    /// Returns authenticated artifacts whose immutable dependencies are available.
    pub fn ready_artifacts(&self) -> &[ArtifactId<D>] {
        &self.ready_artifacts
    }

    /// Returns the number of authenticated artifacts dropped from contextual admission by a bound.
    pub const fn dropped_artifacts(&self) -> usize {
        self.dropped_artifacts
    }

    /// Returns the number of retained future-view artifacts.
    pub const fn future_artifacts(&self) -> usize {
        self.future_artifacts
    }

    /// Returns outstanding verification jobs in deterministic identifier order.
    pub fn verification_jobs(&self) -> &[JobId] {
        &self.verification_jobs
    }

    /// Returns the exact pending persistence barrier, if any.
    pub const fn pending_barrier(&self) -> Option<BarrierId> {
        self.pending_barrier
    }

    /// Returns the number of locally created artifacts retained durably.
    pub const fn local_artifacts(&self) -> usize {
        self.local_artifacts
    }

    /// Returns durable unacknowledged external actions in stable ID order.
    pub fn outbox(&self) -> &[EffectId] {
        &self.outbox
    }

    /// Returns the number of locally authorized producer blocks.
    pub const fn produced_blocks(&self) -> u64 {
        self.produced_blocks
    }

    /// Returns the number of deduplicated immutable-object resolution requests.
    pub const fn resolution_jobs(&self) -> usize {
        self.resolution_jobs
    }

    /// Returns local progress for every producer chain in canonical chain order.
    pub fn chain_progress(&self) -> &[ChainProgress] {
        &self.chain_progress
    }

    /// Returns arrival-first direct vote pools in leader order.
    pub fn pools(&self) -> &[PoolSummary<D>] {
        &self.pools
    }

    /// Returns the latest direct and certificate-backed finality facts.
    pub fn finality(&self) -> &[FinalityFact<D>] {
        &self.finality
    }
}

/// One group-commit batch of staged events awaiting durability.
///
/// Staged events are already applied to machine state; the batch exists only to make them
/// durable and to release their external effects once the journal sync acknowledges. While a
/// barrier is in flight, new events absorb into the open batch at the back of the staging
/// queue, so batch sizes scale with storage latency instead of forcing one sync per event.
#[derive(Clone, Debug)]
pub(crate) struct FrozenAcknowledgement<V: Variant, D: Digest> {
    pub(crate) retention: Vec<Arc<Artifact<V, D>>>,
    pub(crate) retirements: Vec<EffectId>,
    pub(crate) forwarded_nullifications: usize,
}

/// One group-commit batch and the runtime directives frozen when it enters the journal pipeline.
#[derive(Clone, Debug)]
pub(crate) struct PendingPersistence<V: Variant, D: Digest> {
    pub job: PersistJob<V, D>,
    /// Independently verifiable publications released only after this batch enters the journal.
    pub release_after_enqueue: Vec<DurableJob<DurableEffect<V, D>>>,
    /// Whether the batch has been handed to the driver as an [`super::DurabilityCapability::Persist`].
    pub emitted: bool,
    /// Acknowledgement work derived before later transitions can retire referenced outbox entries.
    pub acknowledgement: Option<FrozenAcknowledgement<V, D>>,
    /// Encoded bytes accumulated by the batch, for the journal's record-size bound.
    pub bytes: usize,
}

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

/// Signing completions awaiting their durability turn.
///
/// The lowest effect identifier stays inline. Concurrent completions spill into the ordered map,
/// preserving sorted recovery wakeups without allocating for the common singleton.
pub(crate) struct PendingSigningCompletions<V: Variant, D: Digest> {
    first: Option<(EffectId, PendingSigningCompletion<V, D>)>,
    overflow: BTreeMap<EffectId, PendingSigningCompletion<V, D>>,
}

impl<V: Variant, D: Digest> PendingSigningCompletions<V, D> {
    const fn new() -> Self {
        Self {
            first: None,
            overflow: BTreeMap::new(),
        }
    }

    pub(crate) fn contains_key(&self, id: &EffectId) -> bool {
        self.first.as_ref().is_some_and(|(first, _)| first == id) || self.overflow.contains_key(id)
    }

    pub(crate) fn insert(&mut self, id: EffectId, completion: PendingSigningCompletion<V, D>) {
        let Some((first_id, first_completion)) = self.first.take() else {
            self.first = Some((id, completion));
            return;
        };

        if id == first_id {
            debug_assert_ne!(
                id, first_id,
                "pending signing completion identifiers are unique"
            );
            self.first = Some((first_id, first_completion));
            return;
        }

        if id < first_id {
            self.overflow.insert(first_id, first_completion);
            self.first = Some((id, completion));
            return;
        }

        self.first = Some((first_id, first_completion));
        let replaced = self.overflow.insert(id, completion);
        debug_assert!(
            replaced.is_none(),
            "pending signing completion identifiers are unique"
        );
    }

    pub(crate) fn get(&self, id: &EffectId) -> Option<&PendingSigningCompletion<V, D>> {
        match &self.first {
            Some((first, completion)) if first == id => Some(completion),
            _ => self.overflow.get(id),
        }
    }

    pub(crate) fn remove(&mut self, id: &EffectId) {
        if self.first.as_ref().is_some_and(|(first, _)| first == id) {
            self.first = self.overflow.pop_first();
            return;
        }
        self.overflow.remove(id);
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &EffectId> {
        self.first
            .iter()
            .map(|(id, _)| id)
            .chain(self.overflow.keys())
    }
}

impl<V: Variant, D: Digest> PendingPersistence<V, D> {
    pub fn starts_generation(&self) -> bool {
        self.job
            .events()
            .iter()
            .any(|event| matches!(event.change(), Change::GenerationAdvanced(_)))
    }
}

/// Startup phase governing which machine inputs may be reduced.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Fresh,
    Recovering,
    Live,
}

/// The single owner of all Multimmit protocol state for one epoch.
pub(super) struct Machine<H: Hasher, V: Variant> {
    pub(crate) profile: Profile<H, V>,
    pub(crate) durable: DurableState<V, H::Digest>,
    pub(crate) durable_artifact_references: BTreeMap<ArtifactId<H::Digest>, usize>,
    /// Artifact identifiers carried by every live outbox effect.
    ///
    /// An identifier hashes the full encoded artifact, so each effect's set is computed once at
    /// admission and reused for release and occupancy accounting instead of re-hashing multi-
    /// kilobyte certificates on every durable transition.
    pub(crate) durable_effect_ids: BTreeMap<EffectId, Vec<ArtifactId<H::Digest>>>,
    pub(crate) durable_signing_reservations: usize,
    pub(crate) lifecycle: Lifecycle,
    pub(crate) next_cohort: u64,
    pub(crate) next_job: u64,
    pub(crate) next_barrier: u64,
    pub(crate) artifacts: BTreeMap<ArtifactId<H::Digest>, ArtifactEntry<V, H::Digest>>,
    pub(crate) vqcs: BTreeMap<CertificateId<H::Digest>, ArtifactId<H::Digest>>,
    pub(crate) jobs: BTreeMap<JobId, Vec<VerificationTicket<H::Digest>>>,
    pub(crate) future: BTreeSet<(View, ArtifactId<H::Digest>)>,
    /// Future L-QCs whose signing floor must survive an independent view advance.
    pub(crate) available: BTreeSet<Dependency<H::Digest>>,
    pub(crate) providers: BTreeMap<Dependency<H::Digest>, BTreeSet<ArtifactId<H::Digest>>>,
    pub(crate) invalid_dependencies: BTreeSet<Dependency<H::Digest>>,
    pub(crate) dependency_rejections_saturated: bool,
    pub(crate) waiters: BTreeMap<Dependency<H::Digest>, BTreeSet<ArtifactId<H::Digest>>>,
    pub(crate) dependency_slots: usize,
    pub(crate) waiting: usize,
    /// Artifacts promoted to [`ArtifactState::Ready`] since the last drain, in promotion order.
    ///
    /// Admission telemetry needs the set of newly ready artifacts, and the retained map holds
    /// hundreds of entries: tracking promotions as they happen keeps every step and poll off a
    /// full scan. Entries are drained by both, so a promotion is never reported twice.
    pub(crate) newly_ready: Vec<ReadyPromotion<V, H::Digest>>,
    /// Group-commit batches of staged, already-applied events awaiting durability, in cursor
    /// order. The back batch stays open for absorption until it fills or the pipeline drains.
    pub(crate) staged: VecDeque<PendingPersistence<V, H::Digest>>,
    /// Cursor of the last acknowledged (synced) journal event; `durable.cursor` leads it by
    /// the staged pipeline, since application happens at staging.
    pub(crate) acked: Cursor,
    /// Exact identity of the most recently applied persistence boundary.
    ///
    /// Only that boundary may be duplicated at the acknowledgement frontier. An older id is an
    /// out-of-order completion and remains fatal, so one retained identity keeps this state
    /// bounded while preventing a forged cursor from being classified as stale.
    pub(crate) applied_barrier: Option<BarrierAck>,
    /// Cursor of the latest event that records a fresh local signature.
    ///
    /// Capabilities that reference one of our signatures (directly or inside an aggregate) release
    /// only once `acked` reaches this floor, so no fresh signature leaves the process before
    /// its record is durable. Capabilities free of such references release at staging.
    pub(crate) own_exposure: Cursor,
    /// Outbox effects awaiting their exposure floor, as `(floor, effect)` in cursor order.
    pub(crate) deferred_releases: VecDeque<(Cursor, EffectId)>,
    pub(crate) pending_signing: PendingSigningCompletions<V, H::Digest>,
    /// Reused canonical encoding buffer for machine-validated local artifacts.
    pub(crate) artifact_id_scratch: Vec<u8>,
    /// Recovery and aggregation completions parked while a persistence barrier is outstanding.
    ///
    /// Together with `prepared_lqc`, these entries are bounded by the machine's own crypto-task
    /// reservations, so retained completions never exceed the in-flight jobs.
    pub(super) pending_crypto: VecDeque<Input<V, H::Digest>>,
    /// The validated head L-QC completion moved out of the FIFO across its forwarding yield.
    pub(crate) prepared_lqc: Option<PreparedLqc<V, H::Digest>>,
    pub(crate) defer_da_certificate: bool,
    pub(crate) prefer_deferred_view_certificate: bool,
    pub(crate) chain: ChainState<V, H::Digest>,
    pub(crate) views: ViewState<V, H::Digest>,
    pub(crate) finality: FinalityState<V, H::Digest>,
    pub(crate) resolution: ResolutionState<H::Digest>,
    /// Current view in which finality-floor recovery was last probed.
    pub(crate) floor_probe_view: View,
    /// Serving objects already handed to the resolver during this process generation.
    pub(crate) resolution_effects: Vec<Capability<V, H::Digest>>,
    pub(crate) scheduler: Scheduler,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns application payloads that must be reverified before recovered authority is released.
    pub(crate) fn recovered_payloads(&self) -> Vec<(Context<H::Digest>, H::Digest)> {
        self.chain.recovered_payloads()
    }

    /// Creates an empty machine at live view one for the configured epoch.
    pub fn new(profile: Profile<H, V>) -> Self {
        let resources = profile.resources();
        let genesis = profile.protocol().genesis();
        let available = BTreeSet::from([
            Dependency::Vqc(genesis.vqc()),
            Dependency::Leader {
                round: Round::new(genesis.epoch(), View::zero()),
                digest: genesis.leader(),
            },
        ]);

        let chain = ChainState::new(&profile);
        let views = ViewState::new(&profile);
        let finality = FinalityState::new(&profile);
        let resolution = ResolutionState::new();
        let produced_height = match profile.role() {
            Role::Validator(participant) => profile
                .protocol()
                .producer_chain(participant)
                .map_or_else(Height::zero, |chain| {
                    profile.protocol().genesis().tips()[chain.get() as usize].height()
                }),
            Role::Observer => Height::zero(),
        };
        let genesis_tips = genesis.tips().to_vec();
        Self {
            profile,
            durable: DurableState::new(genesis_tips, produced_height),
            durable_artifact_references: BTreeMap::new(),
            durable_effect_ids: BTreeMap::new(),
            durable_signing_reservations: 0,
            lifecycle: Lifecycle::Fresh,
            next_cohort: 0,
            next_job: 0,
            next_barrier: 0,
            artifacts: BTreeMap::new(),
            vqcs: BTreeMap::new(),
            jobs: BTreeMap::new(),
            future: BTreeSet::new(),
            available,
            providers: BTreeMap::new(),
            invalid_dependencies: BTreeSet::new(),
            dependency_rejections_saturated: false,
            waiters: BTreeMap::new(),
            dependency_slots: 0,
            waiting: 0,
            newly_ready: Vec::new(),
            staged: VecDeque::new(),
            acked: Cursor::zero(),
            applied_barrier: None,
            own_exposure: Cursor::zero(),
            deferred_releases: VecDeque::new(),
            pending_signing: PendingSigningCompletions::new(),
            artifact_id_scratch: Vec::new(),
            pending_crypto: VecDeque::new(),
            prepared_lqc: None,
            defer_da_certificate: false,
            prefer_deferred_view_certificate: false,
            chain,
            views,
            finality,
            resolution,
            floor_probe_view: View::zero(),
            resolution_effects: Vec::new(),
            scheduler: Scheduler::new(resources.max_outbox_effects()),
        }
    }

    /// Restores the last acknowledged snapshot and enters silent replay mode.
    pub fn restore(
        profile: Profile<H, V>,
        snapshot: Snapshot<V, H::Digest>,
    ) -> Result<Self, ReplayError> {
        snapshot.validate(&profile)?;
        let mut machine = Self::new(profile);
        machine.durable = snapshot.state().clone();
        machine.views.restore_snapshot(snapshot.view_snapshot());
        machine
            .chain
            .restore_da_state(
                &machine.durable.certified_tips,
                &machine.durable.da_safety_heights,
            )
            .map_err(|_| ReplayError::Transition)?;
        machine.durable_artifact_references = machine.durable.artifact_references::<H>();
        machine.durable_effect_ids = machine
            .durable
            .effect_ids()
            .map(|id| {
                let effect = machine
                    .durable
                    .effect(&id)
                    .expect("durable effect identifier came from its owner");
                let mut ids = Vec::new();
                DurableState::visit_effect_artifacts::<H>(&effect, |artifact| ids.push(artifact));
                (id, ids)
            })
            .collect();
        for (id, effect) in machine.durable.signing_reservations.iter() {
            machine
                .chain
                .reserve_signing(*id, effect)
                .map_err(|_| ReplayError::Transition)?;
        }
        machine.durable_signing_reservations = machine.durable.signing_reservations();
        let proposal_anchor = machine.proposal_anchor_view();
        machine
            .views
            .restore_proposal_frontier(proposal_anchor, machine.durable.proposal_nullified_through);
        let mut headers = Vec::new();
        headers.extend(machine.durable.local.values().filter_map(|artifact| {
            let Artifact::TransactionBlock(block) = artifact.as_ref() else {
                return None;
            };
            Some(block.header().clone())
        }));
        headers.extend(
            machine
                .durable
                .signing_reservations
                .values()
                .flat_map(|effect| match effect {
                    DurableEffect::Sign(request) => core::slice::from_ref(request),
                    DurableEffect::SignBatch(requests) => requests,
                    _ => &[],
                })
                .filter_map(|request| {
                    let SignRequest::TransactionBlock(header) = request else {
                        return None;
                    };
                    Some(header.clone())
                }),
        );
        machine
            .chain
            .reconcile::<H>(headers)
            .map_err(|_| ReplayError::Transition)?;
        let mut da_headers = Vec::new();
        da_headers.extend(machine.durable.local.values().filter_map(|artifact| {
            let Artifact::DaVote(vote) = artifact.as_ref() else {
                return None;
            };
            Some(vote.header().clone())
        }));
        da_headers.extend(
            machine
                .durable
                .signing_reservations
                .values()
                .flat_map(|effect| match effect {
                    DurableEffect::Sign(request) => core::slice::from_ref(request),
                    DurableEffect::SignBatch(requests) => requests,
                    _ => &[],
                })
                .filter_map(|request| {
                    let SignRequest::DaVote(request) = request else {
                        return None;
                    };
                    Some(request.header().clone())
                }),
        );
        machine
            .chain
            .reconcile_da_choices(da_headers)
            .map_err(|_| ReplayError::Transition)?;
        for effect in machine.durable.signing_reservations.values() {
            let requests: &[SignRequest<V, H::Digest>] = match effect {
                DurableEffect::Sign(request) => core::slice::from_ref(request),
                DurableEffect::SignBatch(requests) => requests,
                _ => return Err(ReplayError::Transition),
            };
            for request in requests {
                machine
                    .views
                    .observe_sign_request(request)
                    .map_err(|_| ReplayError::Transition)?;
            }
        }
        for artifact in machine.durable.local.values() {
            if matches!(artifact.as_ref(), Artifact::Vqc(_)) {
                machine
                    .views
                    .retain_vqc_parent::<H>(artifact, &machine.profile)
                    .map_err(|_| ReplayError::Transition)?;
            }
            machine
                .views
                .observe_durable_artifact(artifact, machine.profile.role())
                .map_err(|_| ReplayError::Transition)?;
        }
        for artifact in machine
            .durable
            .forwarded_vqcs
            .values()
            .chain(machine.durable.forwarded_nullifications.values())
        {
            machine.views.observe_forwarded::<H>(artifact);
        }
        machine.retire_view_history()?;
        machine.lifecycle = Lifecycle::Recovering;
        Ok(machine)
    }

    /// Returns the immutable local construction profile.
    pub const fn profile(&self) -> &Profile<H, V> {
        &self.profile
    }

    /// Projects state at the last acknowledged durable cursor.
    pub fn snapshot(&self) -> Snapshot<V, H::Digest> {
        Snapshot::new::<H>(
            self.profile.protocol().epoch(),
            self.profile.role(),
            self.durable.clone(),
        )
    }

    /// Freezes the acknowledged state while leaving projection construction to its consumer.
    pub(crate) fn checkpoint_cut(&self) -> CheckpointCut<H, V> {
        CheckpointCut {
            epoch: self.profile.protocol().epoch(),
            role: self.profile.role(),
            state: self.durable.clone(),
        }
    }

    /// Returns a normalized read-only projection without exposing internal maps.
    /// Returns the number of exact nullifications retained above the proposal anchor.
    pub fn nullification_suffix(&self) -> u64 {
        let anchor = self.proposal_anchor_view();
        self.durable
            .proposal_nullified_through
            .get()
            .saturating_sub(anchor.get())
    }

    fn proposal_anchor_view(&self) -> View {
        match self.durable.proposal_anchor.as_deref() {
            Some(Artifact::Vqc(anchor)) => anchor.view(),
            _ => View::zero(),
        }
    }

    /// Returns the number of artifacts pinned by durable safety state.
    pub fn retained_artifact_references(&self) -> usize {
        self.durable_artifact_references.len()
    }

    /// Returns the number of staged group-commit batches not yet acknowledged as durable.
    pub fn staged_barriers(&self) -> usize {
        self.staged.len()
    }

    /// Returns whether another protocol turn may reserve durable state.
    pub(crate) fn has_persistence_capacity(&self) -> bool {
        self.staged.len() < Self::MAX_STAGED_BARRIERS
    }

    fn project_chain_progress(&self, finality: &[FinalityFact<H::Digest>]) -> Vec<ChainProgress> {
        let mut finalized = self
            .profile
            .protocol()
            .genesis()
            .tips()
            .iter()
            .map(|tip| tip.height())
            .collect::<Vec<_>>();
        for fact in finality {
            for block in fact.blocks() {
                let height = &mut finalized[block.chain().get() as usize];
                *height = (*height).max(block.height());
            }
        }
        self.chain
            .tip_heights()
            .into_iter()
            .enumerate()
            .map(|(index, (known, certified))| {
                let finalized = finalized[index];
                ChainProgress {
                    chain: ChainId::new(index as u32),
                    finalized,
                    certified,
                    known: known.max(finalized),
                }
            })
            .collect()
    }

    fn producer_progress(&self) -> Option<ProducerProgress> {
        let status = self.chain.producer_status::<H>()?;
        Some(ProducerProgress {
            chain: status.chain,
            produced: status.produced,
            certified: status.certified,
            vote_shares: status.vote_shares,
            da_quorum: status.da_quorum,
            pipeline_depth: status.pipeline_depth,
            ready_recovery: status.ready_recovery,
            pending_recovery: status.pending_recovery,
            active_recovery: status.active_recovery,
            wake: status.wake,
            timer_armed: status.timer_armed,
            build_pending: status.build_pending,
            production_credit: status.production_credit,
        })
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.durable.generation
    }

    pub(crate) fn progress(&self) -> Progress {
        Progress {
            view: self.durable.view,
            retired_view: self.durable.retired_view,
            finality_floor: self.signing_floor_view(),
            proposal_anchor_view: self.proposal_anchor_view(),
            produced_blocks: self.durable.produced_blocks,
            producer: self.producer_progress(),
        }
    }

    pub(crate) fn chain_progress(&self) -> Vec<ChainProgress> {
        let finality = self.finality.facts();
        self.project_chain_progress(&finality)
    }

    pub fn inspect(&self) -> Inspection<H::Digest> {
        let mut pending_artifacts = 0;
        let mut waiting_artifacts = 0;
        let mut ready_artifacts = Vec::new();
        let mut dropped_artifacts = 0;

        for (id, entry) in &self.artifacts {
            match entry.state {
                ArtifactState::Pending(_) => pending_artifacts += 1,
                ArtifactState::Waiting(_) => waiting_artifacts += 1,
                ArtifactState::Ready => ready_artifacts.push((entry.observation, *id)),
                ArtifactState::Dropped => dropped_artifacts += 1,
            }
        }

        ready_artifacts.sort_unstable();
        let finality = self.finality.facts();
        let chain_progress = self.project_chain_progress(&finality);
        let mut outbox = self.durable.effect_ids().collect::<Vec<_>>();
        outbox.sort_unstable();

        Inspection {
            epoch: self.profile.protocol().epoch(),
            view: self.durable.view,
            generation: self.durable.generation,
            cursor: self.durable.cursor,
            live: self.lifecycle == Lifecycle::Live,
            recovering: self.lifecycle == Lifecycle::Recovering,
            cached_artifacts: self.artifacts.len(),
            pending_artifacts,
            waiting_artifacts,
            ready_artifacts: ready_artifacts.into_iter().map(|(_, id)| id).collect(),
            dropped_artifacts,
            future_artifacts: self.future.len(),
            verification_jobs: self.jobs.keys().copied().collect(),
            pending_barrier: self.staged.front().map(|pending| pending.job.id()),
            local_artifacts: self.durable.local.len(),
            outbox,
            retained_artifact_references: self.durable_artifact_references.len(),
            nullification_suffix: self.nullification_suffix(),
            retired_view: self.durable.retired_view,
            finality_floor: self.signing_floor_view(),
            produced_blocks: self.durable.produced_blocks,
            producer: self.producer_progress(),
            resolution_jobs: self.resolution.len(),
            chain_progress,
            pools: self.finality.pools(),
            finality,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::machine::Cursor;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };

    fn effect_id(value: u64) -> EffectId {
        EffectId::from_cursor(Cursor::new(value))
    }

    fn completion() -> PendingSigningCompletion<MinPk, Sha256Digest> {
        PendingSigningCompletion::Batch {
            artifacts: Arc::from(Vec::<Arc<Artifact<MinPk, Sha256Digest>>>::new()),
            ids: Vec::new(),
        }
    }

    #[test]
    fn pending_signing_keeps_effect_order_across_inline_and_overflow_storage() {
        let mut pending = PendingSigningCompletions::new();
        pending.insert(effect_id(3), completion());
        pending.insert(effect_id(1), completion());
        pending.insert(effect_id(2), completion());

        assert_eq!(
            pending.keys().copied().collect::<Vec<_>>(),
            vec![effect_id(1), effect_id(2), effect_id(3)]
        );

        pending.remove(&effect_id(1));
        assert_eq!(
            pending.keys().copied().collect::<Vec<_>>(),
            vec![effect_id(2), effect_id(3)]
        );
        assert!(pending.get(&effect_id(2)).is_some());

        pending.remove(&effect_id(3));
        pending.remove(&effect_id(2));
        assert!(pending.keys().next().is_none());
    }
}
