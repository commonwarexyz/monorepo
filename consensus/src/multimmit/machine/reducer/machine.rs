//! The [`Machine`] struct, its construction and restore, and normalized inspection.
//!
//! `Machine` owns every piece of protocol state in named parts:
//!
//! - [`DurableLedger`]: applied durable state and the artifact references it holds.
//! - [`ArtifactStore`]: retained peer artifacts, their admission progress, and dependency waits.
//! - [`Pipeline`]: staged journal batches and the releases ordered behind them.
//! - [`Completions`], [`ResolutionState`], and the generations signing capabilities were
//!   issued in: issued work awaiting completion.
//! - [`Components`]: the volatile state of the protocol components, serviced through the
//!   [`Scheduler`] and the hooks in [`components`](super::components).

use super::{
    completions::Completions,
    components::Components,
    ledger::DurableLedger,
    persistence::Pipeline,
    store::{ArtifactState, ArtifactStore},
};
use crate::{
    Epochable as _,
    multimmit::{
        config::Profile,
        machine::{
            chain::{accept::Refusals, producer::ProductionHolds},
            durability::{BatchId, Cursor, DurableState, EffectId, ReplayError, Snapshot},
            emit::PinnedUndetermined,
            input::{Now, TimerFamily},
            job::{Generation, Issued},
            resolution::ResolutionState,
            scheduler::Scheduler,
            verification::JobId,
            view::declare::{DeclarationContexts, DeclarationCounts, ViewEnds},
        },
        types::{Activity, Artifact, ArtifactId, ChainId, ViewProof},
    },
    types::{Epoch, Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// One producer chain's local progress for diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChainProgress {
    chain: ChainId,
    accepted: Height,
    quorum: Height,
    finalized: Height,
}

impl ChainProgress {
    /// Returns the producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the height of the chain's locally accepted tip.
    pub const fn accepted(self) -> Height {
        self.accepted
    }

    /// Returns the chain's height-quorum height `h*`: the greatest height at least `n - 2f`
    /// validators endorse.
    pub const fn quorum(self) -> Height {
        self.quorum
    }

    /// Returns the greatest height of the chain this node knows to be final.
    pub const fn finalized(self) -> Height {
        self.finalized
    }
}

/// The local producer's progress for diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProducerProgress {
    chain: ChainId,
    produced: Height,
    building: bool,
    custody_pending: bool,
}

impl ProducerProgress {
    /// Returns the local producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the height of the newest header this node signed for its chain.
    pub const fn produced(self) -> Height {
        self.produced
    }

    /// Returns whether an application build is outstanding.
    pub const fn building(self) -> bool {
        self.building
    }

    /// Returns whether a built block awaits durable custody before its header is signed.
    pub const fn custody_pending(self) -> bool {
        self.custody_pending
    }
}

/// Read-only normalized state intended for tests, metrics, and diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection<D: Digest> {
    epoch: Epoch,
    progress: CoreProgress,
    generation: Generation,
    cursor: Cursor,
    lifecycle: Lifecycle,
    cached_artifacts: usize,
    pending_artifacts: usize,
    waiting_artifacts: usize,
    ready_artifacts: Vec<ArtifactId<D>>,
    verification_jobs: Vec<JobId>,
    pending_barrier: Option<BatchId>,
    local_artifacts: usize,
    outbox: Vec<EffectId>,
    resolution_jobs: usize,
    chain_progress: Vec<ChainProgress>,
}

impl<D: Digest> Inspection<D> {
    /// Returns the bound epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the current view.
    pub const fn view(&self) -> View {
        self.progress.view
    }

    /// Returns the newest view whose resolution facts were reported.
    pub const fn last_resolved(&self) -> View {
        self.progress.last_resolved
    }

    /// Returns the highest retired view.
    pub const fn retired_view(&self) -> View {
        self.progress.retired_view
    }

    /// Returns the local producer's progress, if this node produces a chain.
    pub const fn producer(&self) -> Option<ProducerProgress> {
        self.progress.producer
    }

    /// Returns the process generation.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the newest applied journal cursor.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns whether the machine serves live inputs.
    pub const fn is_live(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Live)
    }

    /// Returns whether the machine is replaying its journal.
    pub const fn is_recovering(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Recovering)
    }

    /// Returns the number of retained artifacts.
    pub const fn cached_artifacts(&self) -> usize {
        self.cached_artifacts
    }

    /// Returns the number of artifacts awaiting verification.
    pub const fn pending_artifacts(&self) -> usize {
        self.pending_artifacts
    }

    /// Returns the number of verified artifacts awaiting a dependency.
    pub const fn waiting_artifacts(&self) -> usize {
        self.waiting_artifacts
    }

    /// Returns the admitted artifacts in observation order.
    pub fn ready_artifacts(&self) -> &[ArtifactId<D>] {
        &self.ready_artifacts
    }

    /// Returns the number of in-flight verification jobs.
    pub const fn verification_jobs_len(&self) -> usize {
        self.verification_jobs.len()
    }

    /// Returns whether a journal barrier awaits acknowledgement.
    pub const fn persistence_pending(&self) -> bool {
        self.pending_barrier.is_some()
    }

    /// Returns the number of locally created artifacts durable state retains.
    pub const fn local_artifacts(&self) -> usize {
        self.local_artifacts
    }

    /// Returns the number of outstanding durable effects.
    pub const fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Returns the outstanding durable effects in identifier order.
    #[cfg(test)]
    pub(crate) fn outbox(&self) -> &[EffectId] {
        &self.outbox
    }

    /// Returns the number of outstanding retrievals.
    pub const fn resolution_jobs(&self) -> usize {
        self.resolution_jobs
    }

    /// Returns each producer chain's local progress.
    pub fn chain_progress(&self) -> &[ChainProgress] {
        &self.chain_progress
    }

    /// Returns the delay estimate `delta_hat` the current view's timers derive from, in
    /// milliseconds.
    pub const fn delay_millis(&self) -> u64 {
        self.progress.delay
    }

    /// Returns the production interval estimate `theta_hat` the current view's timers derive
    /// from, in milliseconds.
    pub const fn production_millis(&self) -> u64 {
        self.progress.production
    }

    /// Returns the current view's grace `t_grace`, in milliseconds.
    pub const fn grace_millis(&self) -> u64 {
        self.progress.grace
    }

    /// Returns the number of vote updates parked until an earlier update of their sender is read.
    pub const fn parked_updates(&self) -> usize {
        self.progress.parked_updates
    }

    /// Returns the chains declared final per rule since the process started.
    pub const fn declarations(&self) -> DeclarationCounts {
        self.progress.declarations
    }

    /// Returns why each view this node sent a final vote for ended, and their total length, since
    /// the process started.
    pub const fn view_ends(&self) -> ViewEnds {
        self.progress.view_ends
    }
}

/// Lightweight operational projection for actor-owned metrics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreProgress {
    pub(crate) view: View,
    pub(crate) retired_view: View,
    pub(crate) last_resolved: View,
    pub(crate) producer: Option<ProducerProgress>,
    pub(crate) artifact_cache_occupancy: usize,
    pub(crate) artifact_cache_capacity: usize,
    pub(crate) remote_artifact_capacity: usize,
    pub(crate) local_artifact_capacity: usize,
    pub(crate) verification_jobs: usize,
    pub(crate) verification_job_capacity: usize,
    pub(crate) future_artifacts: usize,
    /// Vote updates parked until an earlier update of their sender is read.
    pub(crate) parked_updates: usize,
    /// The delay estimate `delta_hat` the current view's timers derive from, in milliseconds.
    pub(crate) delay: u64,
    /// The production interval estimate `theta_hat` the current view's timers derive from, in
    /// milliseconds.
    pub(crate) production: u64,
    /// The current view's grace `t_grace`, in milliseconds.
    pub(crate) grace: u64,
    /// The chains declared final per rule since the process started.
    pub(crate) declarations: DeclarationCounts,
    /// Why each view this node sent a final vote for ended since the process started.
    pub(crate) view_ends: ViewEnds,
    /// The ready peer headers a bound refused since the process started.
    pub(crate) refusals: Refusals,
    /// What this node knew about each chain it declared final since the process started.
    pub(crate) declaration_contexts: DeclarationContexts,
    /// View boundaries pinned after their final votes failed to determine them.
    pub(crate) pinned_undetermined: PinnedUndetermined,
    /// Time the local producer spent held by the flow bound since the process started.
    pub(crate) production_holds: ProductionHolds,
}

/// Startup phase governing which machine inputs may be reduced.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Fresh,
    Recovering,
    Live,
}

/// The single owner of all Multimmit protocol state for one epoch.
pub(crate) struct Machine<H: Hasher, V: Variant> {
    pub(in crate::multimmit::machine) profile: Profile<H::Digest>,
    pub(in crate::multimmit::machine) lifecycle: Lifecycle,
    /// Applied durable state and its references.
    pub(in crate::multimmit::machine) durable: DurableLedger<V, H::Digest>,
    /// Retained peer artifacts.
    pub(in crate::multimmit::machine) store: ArtifactStore<V, H::Digest>,
    /// Staged batches and release ordering.
    pub(in crate::multimmit::machine) pipeline: Pipeline<V, H::Digest>,
    /// Issued work whose completions are outstanding or parked.
    pub(in crate::multimmit::machine) completions: Completions<V, H::Digest>,
    /// Outstanding retrievals.
    pub(in crate::multimmit::machine) resolution: ResolutionState<H::Digest>,
    /// The generation each durable signing reservation's capability was first issued in. A
    /// signature completes its reservation only under that generation; the reservation itself is
    /// durable state.
    pub(in crate::multimmit::machine) signing_issued: BTreeMap<EffectId, Generation>,
    /// The deadline held per timer family.
    pub(in crate::multimmit::machine) timers: [Option<Now>; TimerFamily::COUNT],
    /// Volatile protocol component state.
    pub(in crate::multimmit::machine) components: Components<V, H::Digest>,
    /// Which components and completions have work ready.
    pub(in crate::multimmit::machine) scheduler: Scheduler,
    /// Activities reported since the last step or poll.
    pub(in crate::multimmit::machine) activities: Vec<Activity<V, H::Digest>>,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Creates an empty machine at view one for the configured epoch, with every chain at its
    /// genesis tip.
    pub(crate) fn new(profile: Profile<H::Digest>) -> Self {
        let genesis = profile.protocol().genesis();
        let state = DurableState::new(genesis.tips().to_vec(), Height::zero());
        let resources = profile.resources();
        Self {
            durable: DurableLedger::new::<H>(state),
            store: ArtifactStore::new(),
            pipeline: Pipeline::new(),
            completions: Completions::new(),
            resolution: ResolutionState::new(),
            signing_issued: BTreeMap::new(),
            timers: [None; TimerFamily::COUNT],
            components: Components::new(&profile),
            scheduler: Scheduler::new(resources.max_outbox_effects()),
            activities: Vec::new(),
            lifecycle: Lifecycle::Fresh,
            profile,
        }
    }

    /// Restores the last acknowledged snapshot and enters silent replay mode.
    pub(crate) fn restore(
        profile: Profile<H::Digest>,
        snapshot: Snapshot<V, H::Digest>,
    ) -> Result<Self, ReplayError> {
        snapshot.validate::<H>(&profile)?;
        let mut machine = Self::new(profile);
        machine.durable = DurableLedger::new::<H>(snapshot.into_state());
        machine.pipeline.acked = machine.durable.state.cursor;
        machine.lifecycle = Lifecycle::Recovering;
        Ok(machine)
    }

    /// Returns a snapshot of acknowledged state, or `None` while staged changes await durability.
    pub(crate) fn checkpoint_cut(&self) -> Option<Snapshot<V, H::Digest>> {
        (self.pipeline.staged.is_empty() && self.durable.state.cursor == self.pipeline.acked)
            .then(|| self.snapshot())
    }

    /// Projects current state, including staged changes, for deterministic tests.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn live_snapshot_for_test(&self) -> Snapshot<V, H::Digest> {
        self.snapshot()
    }

    fn snapshot(&self) -> Snapshot<V, H::Digest> {
        Snapshot::new(
            self.profile.protocol().epoch(),
            self.profile.role(),
            self.durable.state.clone(),
        )
    }

    /// Returns a normalized read-only projection without exposing internal maps.
    pub(crate) fn inspect(&self) -> Inspection<H::Digest> {
        let mut pending_artifacts = 0;
        let mut waiting_artifacts = 0;
        let mut ready = Vec::new();
        for (id, entry) in self.store.iter() {
            match entry.state {
                ArtifactState::Parked(_) | ArtifactState::Pending(_) => pending_artifacts += 1,
                ArtifactState::Waiting(_) => waiting_artifacts += 1,
                ArtifactState::Ready => ready.push((entry.observation, *id)),
            }
        }
        ready.sort_unstable();
        let state = &self.durable.state;
        Inspection {
            epoch: self.profile.protocol().epoch(),
            progress: self.progress(),
            generation: state.generation,
            cursor: state.cursor,
            lifecycle: self.lifecycle,
            cached_artifacts: self.store.len(),
            pending_artifacts,
            waiting_artifacts,
            ready_artifacts: ready.into_iter().map(|(_, id)| id).collect(),
            verification_jobs: self.completions.verification_jobs.keys().copied().collect(),
            pending_barrier: self.pipeline.pending_barrier(),
            local_artifacts: state.local.len(),
            outbox: {
                let mut outbox = state.effect_ids().collect::<Vec<_>>();
                outbox.sort_unstable();
                outbox
            },
            resolution_jobs: self.resolution.len(),
            chain_progress: self.chain_progress(),
        }
    }

    /// Projects compact protocol progress for metrics and retention coordination.
    pub(crate) fn progress(&self) -> CoreProgress {
        let resources = self.profile.resources();
        let state = &self.durable.state;
        let durable = self.durable.occupancy();
        let timers = self.current_timers();
        CoreProgress {
            view: state.view,
            retired_view: state.retired_view,
            last_resolved: state
                .emission
                .last_key_value()
                .map_or(state.retired_view, |(view, _)| *view),
            producer: self
                .components
                .producer
                .as_ref()
                .map(|producer| ProducerProgress {
                    chain: producer.chain(),
                    produced: state.produced,
                    building: producer.building().is_some(),
                    custody_pending: producer.custody_pending(),
                }),
            artifact_cache_occupancy: self.store.len() + durable,
            artifact_cache_capacity: resources.max_cached_artifacts(),
            remote_artifact_capacity: resources.max_cached_artifacts().saturating_sub(durable),
            local_artifact_capacity: resources.max_cached_artifacts(),
            verification_jobs: self.completions.verification_jobs.len(),
            verification_job_capacity: resources.max_inflight_verifications(),
            future_artifacts: self.store.future_len(),
            parked_updates: self.store.parked_len(),
            delay: timers.delta,
            production: timers.production,
            grace: timers.grace,
            declarations: self.declaration_counts(),
            view_ends: self.view_ends(),
            refusals: self.components.chain.refusals(),
            declaration_contexts: self.declaration_contexts(),
            pinned_undetermined: self.components.emitter.pinned_undetermined,
            production_holds: self
                .components
                .producer
                .as_ref()
                .map_or_else(ProductionHolds::default, |producer| producer.holds()),
        }
    }

    /// Returns each producer chain's local progress.
    pub(crate) fn chain_progress(&self) -> Vec<ChainProgress> {
        let layer = &self.components.chain;
        self.profile
            .codec()
            .chain_ids()
            .map(|chain| ChainProgress {
                chain,
                accepted: layer.tip(chain).height(),
                quorum: layer.quorum(chain),
                finalized: layer.finalized(chain),
            })
            .collect()
    }

    /// Returns whether another protocol turn may stage durable state.
    pub(crate) fn has_persistence_capacity(&self) -> bool {
        self.pipeline.staged.len() < super::MAX_STAGED_BARRIERS
    }

    /// Returns whether machine-owned work is ready: a scheduled work key or a staged batch the
    /// journal may take.
    pub(crate) fn has_component_work(&self) -> bool {
        self.scheduler.has_work() || self.pipeline.next_staged_index().is_some()
    }

    /// Returns the immutable profile.
    pub(crate) const fn profile(&self) -> &Profile<H::Digest> {
        &self.profile
    }

    /// Returns the process generation that issues volatile work.
    pub(crate) const fn generation(&self) -> Generation {
        self.durable.state.generation
    }

    /// Returns the current view.
    pub(crate) const fn view(&self) -> View {
        self.durable.state.view
    }

    /// Returns whether work issued as `issued` belongs to the current process generation.
    pub(crate) fn is_current<Id: Copy>(&self, issued: Issued<Id>) -> bool {
        issued.generation() == self.durable.state.generation
    }

    /// Returns the durable retired view, the retained view proofs, and this node's latest vote of
    /// every tag the pool reads, from which the resolver rebuilds its volatile custody after
    /// startup.
    pub(crate) fn resolver_seed(&self) -> (View, Vec<Artifact<V, H::Digest>>) {
        let mut artifacts = self
            .durable
            .state
            .resolver_proofs()
            .into_iter()
            .map(|proof| match proof {
                ViewProof::Vqc(vqc) => Artifact::Vqc(*vqc),
                ViewProof::Lqc(lqc) => Artifact::Lqc(*lqc),
            })
            .collect::<Vec<_>>();
        artifacts.extend(self.served_votes());
        (self.durable.state.retired_view, artifacts)
    }
}
