//! The [`Machine`] struct, its construction and restore, and normalized inspection.
//!
//! `Machine` owns every piece of protocol state in named parts:
//!
//! - [`DurableLedger`]: applied durable state and the artifact references it holds.
//! - [`ArtifactStore`]: retained artifacts and their retirement and future indexes.
//! - [`DependencyIndex`]: which dependencies are available, who provides them, and who waits.
//! - [`Pipeline`]: staged journal batches and the ordering of releases behind them.
//! - [`Completions`]: issued verification and signing work awaiting completion.
//! - Protocol partitions: [`ChainState`], [`ViewState`], [`FinalityState`],
//!   [`ResolutionState`], and accountability.
//! - [`Scheduler`]: which components have work ready.

#[cfg(any(test, feature = "mocks"))]
use super::store::vote_slot_key;
use super::{
    completions::Completions,
    dependencies::DependencyIndex,
    ledger::DurableLedger,
    persistence::Pipeline,
    store::{ArtifactState, ArtifactStore},
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role},
        machine::{
            accountability::AccountabilityState,
            artifact::Dependency,
            chain::ChainState,
            da::DaChoice,
            durability::{
                BatchId, Cursor, DurableState, EffectId, ReplayError, SignRequest, Snapshot,
                TransitionReason,
            },
            finality::FinalityState,
            input::{DaVotesOffer, StepStatus},
            job::{Generation, Issued},
            producer::ProducerProgress,
            reducer::MAX_STAGED_BARRIERS,
            resolution::ResolutionState,
            scheduler::{ProtocolComponent, Scheduler, WorkKey},
            verification::JobId,
            view::{TimeoutCutoff, ViewState},
        },
        types::{
            Artifact, ArtifactId, BlockRef, ChainId, Context, FinalityFact, PoolSummary, ViewProof,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeSet;

/// One producer chain's local progress for diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChainProgress {
    chain: ChainId,
    finalized: Height,
    certified: Height,
    da_voted: Height,
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

    /// Returns the greatest height covered by a retained local DA vote.
    pub const fn da_voted(self) -> Height {
        self.da_voted
    }

    /// Returns the greatest locally usable, certified, or finalized height.
    pub const fn known(self) -> Height {
        self.known
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
    dropped_artifacts: usize,
    verification_jobs: Vec<JobId>,
    pending_barrier: Option<BatchId>,
    local_artifacts: usize,
    outbox: Vec<EffectId>,
    resolution_jobs: usize,
    chain_progress: Vec<ChainProgress>,
    pools: Vec<PoolSummary<D>>,
    finality: Vec<FinalityFact<D>>,
    retained_artifact_references: usize,
    nullification_suffix: u64,
}

/// Lightweight operational projection for actor-owned metrics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreProgress {
    pub(crate) view: View,
    pub(crate) retired_view: View,
    pub(crate) finality_floor: View,
    pub(crate) proposal_anchor_view: View,
    pub(crate) produced_blocks: u64,
    pub(crate) producer: Option<ProducerProgress>,
    pub(crate) artifact_cache_occupancy: usize,
    pub(crate) artifact_cache_capacity: usize,
    pub(crate) remote_artifact_capacity: usize,
    pub(crate) local_artifact_capacity: usize,
    pub(crate) verification_jobs: usize,
    pub(crate) verification_job_capacity: usize,
    pub(crate) future_artifacts: usize,
    pub(crate) timeout_cutoff_vote: bool,
    pub(crate) timeout_cutoff_timeout: bool,
}

impl<D: Digest> Inspection<D> {
    /// Returns the machine's immutable epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the current local view.
    pub const fn view(&self) -> View {
        self.progress.view
    }

    /// Returns the local producer's build and DA-certificate state.
    pub const fn producer(&self) -> Option<ProducerProgress> {
        self.progress.producer
    }

    /// Returns the number of artifacts pinned by durable safety state.
    pub const fn retained_artifact_references(&self) -> usize {
        self.retained_artifact_references
    }

    /// Returns the length of the nullification suffix above the proposal anchor.
    pub const fn nullification_suffix(&self) -> u64 {
        self.nullification_suffix
    }

    /// Returns the durable transition floor.
    pub const fn retired_view(&self) -> View {
        self.progress.retired_view
    }

    /// Returns the durable consensus signing floor.
    pub const fn finality_floor(&self) -> View {
        self.progress.finality_floor
    }

    /// Returns the current completion-correlation generation.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the last acknowledged durable journal cursor.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns whether normal live inputs may be processed.
    pub const fn is_live(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Live)
    }

    /// Returns whether silent journal replay is still permitted.
    pub const fn is_recovering(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Recovering)
    }

    /// Returns the number of retained artifact records.
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
        self.progress.future_artifacts
    }

    /// Returns the number of outstanding verification jobs.
    pub const fn verification_jobs_len(&self) -> usize {
        self.verification_jobs.len()
    }

    /// Returns outstanding verification jobs in deterministic identifier order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn verification_jobs(&self) -> &[JobId] {
        &self.verification_jobs
    }

    /// Returns whether a persistence barrier is awaiting its journal sync.
    pub const fn persistence_pending(&self) -> bool {
        self.pending_barrier.is_some()
    }

    /// Returns the exact pending persistence barrier, if any.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn pending_barrier(&self) -> Option<BatchId> {
        self.pending_barrier
    }

    /// Returns the number of locally created artifacts retained durably.
    pub const fn local_artifacts(&self) -> usize {
        self.local_artifacts
    }

    /// Returns the number of durable unacknowledged external actions.
    pub const fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Returns durable unacknowledged external actions in stable ID order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn outbox(&self) -> &[EffectId] {
        &self.outbox
    }

    /// Returns the number of locally authorized producer blocks.
    pub const fn produced_blocks(&self) -> u64 {
        self.progress.produced_blocks
    }

    /// Returns the number of deduplicated view-proof requests.
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

/// Which DA work the DA component tries before driving its producer chain.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum DaOrder {
    /// Advance a DA certificate first.
    #[default]
    CertificateFirst,
    /// Drive the chain first: the previous quantum just advanced a certificate.
    ChainFirst,
}

/// Which views the view component assembles certificates for.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewCertificates {
    /// Only the current view.
    #[default]
    CurrentOnly,
    /// The current view, then a deferred view the DA component found room for.
    WithDeferred,
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
    /// Applied durable state and its reference ledgers.
    pub(in crate::multimmit::machine) durable: DurableLedger<V, H::Digest>,
    /// Retained artifacts and their indexes.
    pub(in crate::multimmit::machine) store: ArtifactStore<V, H::Digest>,
    /// Dependency availability, providers, and waiters.
    pub(in crate::multimmit::machine) dependencies: DependencyIndex<H::Digest>,
    /// Staged batches and release ordering.
    pub(in crate::multimmit::machine) pipeline: Pipeline<V, H::Digest>,
    /// Issued work whose completions are outstanding or parked.
    pub(in crate::multimmit::machine) completions: Completions<V, H::Digest>,
    pub(in crate::multimmit::machine) accountability: AccountabilityState<H::Digest>,
    pub(in crate::multimmit::machine) quarantine: Vec<Participant>,
    pub(in crate::multimmit::machine) da_order: DaOrder,
    pub(in crate::multimmit::machine) view_certificates: ViewCertificates,
    pub(in crate::multimmit::machine) chain: ChainState<V, H::Digest>,
    pub(in crate::multimmit::machine) views: ViewState<V, H::Digest>,
    pub(in crate::multimmit::machine) finality: FinalityState<V, H::Digest>,
    pub(in crate::multimmit::machine) resolution: ResolutionState<V, H::Digest>,
    pub(in crate::multimmit::machine) scheduler: Scheduler,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns application payloads that must be reverified before recovered authority is released.
    pub(crate) fn recovered_payloads(&self) -> Vec<(Context<H::Digest>, H::Digest)> {
        self.chain.recovered_payloads()
    }

    /// Creates an empty machine at live view one for the configured epoch.
    pub(crate) fn new(profile: Profile<H::Digest>) -> Self {
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
        let views = ViewState::new::<H>(&profile);
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
            lifecycle: Lifecycle::Fresh,
            durable: DurableLedger::new(DurableState::new(genesis_tips, produced_height)),
            store: ArtifactStore::new(),
            dependencies: DependencyIndex::new(available),
            pipeline: Pipeline::new(),
            completions: Completions::new(),
            accountability: AccountabilityState::new(resources.max_cached_artifacts()),
            quarantine: Vec::new(),
            da_order: DaOrder::CertificateFirst,
            view_certificates: ViewCertificates::CurrentOnly,
            chain,
            views,
            finality,
            resolution,
            scheduler: Scheduler::new(resources.max_outbox_effects()),
        }
    }

    /// Restores the last acknowledged snapshot and enters silent replay mode.
    pub(crate) fn restore(
        profile: Profile<H::Digest>,
        snapshot: Snapshot<V, H::Digest>,
    ) -> Result<Self, ReplayError> {
        let view = snapshot.validate::<H>(&profile)?;
        let mut machine = Self::new(profile);
        machine.durable.state = snapshot.into_state();
        machine.pipeline.acked = machine.durable.state.cursor;
        machine.views.restore_slots(view.slots);
        machine
            .chain
            .da
            .restore(
                &machine.durable.state.certified_tips,
                &machine.durable.state.da_safety_heights,
            )
            .map_err(|_| ReplayError::Transition(TransitionReason::ChainState))?;
        machine.durable.artifact_references = machine.durable.state.artifact_references::<H>();
        machine.durable.effect_ids = machine
            .durable
            .state
            .effect_ids()
            .map(|id| {
                let effect = machine
                    .durable_effect(id)
                    .expect("durable effect identifier came from its owner");
                (id, Self::effect_artifact_ids(&effect))
            })
            .collect();
        for (id, effect) in machine.durable.state.signing_reservations.iter() {
            machine
                .chain
                .reserve_signing(*id, effect)
                .map_err(|_| ReplayError::Transition(TransitionReason::ChainState))?;
        }
        machine.durable.signing_reservations = machine.durable.state.signing_reservations();
        let proposal_anchor = machine.durable.state.proposal_anchor_view();
        machine.views.restore_proposal_frontier(
            proposal_anchor,
            machine.durable.state.proposal_nullified_through,
        );
        // Producer headers and DA choices are held by local artifacts and by pending signing
        // requests alike.
        let local = machine
            .durable
            .state
            .local
            .values()
            .map(|artifact| artifact.as_ref());
        let headers: Vec<_> = local
            .clone()
            .filter_map(|artifact| match artifact {
                Artifact::TransactionBlock(block) => Some(block.header().clone()),
                _ => None,
            })
            .chain(
                machine
                    .durable
                    .state
                    .sign_requests()
                    .filter_map(|request| match request {
                        SignRequest::TransactionBlock(header) => Some(header.clone()),
                        _ => None,
                    }),
            )
            .collect();
        machine
            .chain
            .reconcile::<H>(headers)
            .map_err(|_| ReplayError::Transition(TransitionReason::ChainState))?;
        let da_headers: Vec<_> = local
            .filter_map(|artifact| match artifact {
                Artifact::DaVote(vote) => Some(vote.header().clone()),
                _ => None,
            })
            .chain(
                machine
                    .durable
                    .state
                    .sign_requests()
                    .filter_map(|request| match request {
                        SignRequest::DaVote(request) => Some(request.header().clone()),
                        _ => None,
                    }),
            )
            .collect();
        machine
            .chain
            .da
            .reconcile_choices::<H>(da_headers)
            .map_err(|_| ReplayError::Transition(TransitionReason::ChainState))?;
        for request in machine.durable.state.sign_requests() {
            machine
                .views
                .observe_sign_request(request)
                .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;
        }
        for artifact in machine.durable.state.local.values() {
            if matches!(artifact.as_ref(), Artifact::Vqc(_)) {
                machine
                    .views
                    .retain_vqc_parent::<H>(artifact)
                    .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;
            }
            machine
                .views
                .observe_durable_artifact(artifact)
                .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;
        }
        for artifact in machine
            .durable
            .state
            .forwarded_vqcs
            .values()
            .chain(machine.durable.state.forwarded_nullifications.values())
        {
            machine.views.observe_forwarded::<H>(artifact);
        }
        machine.retire_view_history()?;
        machine.lifecycle = Lifecycle::Recovering;
        Ok(machine)
    }

    /// Returns the immutable local construction profile.
    pub(crate) const fn profile(&self) -> &Profile<H::Digest> {
        &self.profile
    }

    /// Checks that the retirement indices mirror the retained artifact map exactly.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn assert_artifact_indices(&self) {
        let mut by_view = 0usize;
        for (view, ids) in &self.store.by_view {
            assert!(!ids.is_empty(), "empty view index bucket at {view:?}");
            for id in ids {
                let entry = self
                    .store
                    .artifacts
                    .get(id)
                    .expect("indexed artifact is retained");
                assert_eq!(entry.artifact.view(), Some(*view), "view index disagrees");
                by_view += 1;
            }
        }
        let mut by_position = 0usize;
        for (position, ids) in &self.store.by_position {
            assert!(
                !ids.is_empty(),
                "empty position index bucket at {position:?}"
            );
            for id in ids {
                let entry = self
                    .store
                    .artifacts
                    .get(id)
                    .expect("indexed artifact is retained");
                let indexed = entry
                    .artifact
                    .chain_position()
                    .unwrap_or_else(|| panic!("position index holds a view artifact: {entry:?}"));
                assert_eq!(indexed, *position);
                by_position += 1;
            }
        }
        let expected_views = self
            .store
            .artifacts
            .values()
            .filter(|entry| entry.artifact.view().is_some())
            .count();
        let expected_positions = self
            .store
            .artifacts
            .values()
            .filter(|entry| {
                matches!(
                    entry.artifact.as_ref(),
                    Artifact::TransactionBlock(_)
                        | Artifact::DaVote(_)
                        | Artifact::DaCertificate(_)
                )
            })
            .count();
        assert_eq!(by_view, expected_views, "view index size");
        assert_eq!(by_position, expected_positions, "position index size");

        // The verified-block index lists exactly the ready producer blocks at each position, and
        // the vote-slot index exactly the network votes retained above the durable certified tip.
        for (position, blocks) in &self.store.verified_blocks {
            assert!(
                blocks.iter().any(Option::is_some),
                "empty verified-block bucket at {position:?}"
            );
            for id in blocks.iter().flatten() {
                let entry = self
                    .store
                    .artifacts
                    .get(id)
                    .expect("indexed verified block is retained");
                assert!(
                    matches!(entry.state, ArtifactState::Ready),
                    "indexed verified block {id:?} is not ready"
                );
                assert!(
                    matches!(entry.artifact.as_ref(), Artifact::TransactionBlock(block)
                        if (block.header().chain(), block.header().height()) == *position),
                    "verified-block index disagrees at {position:?}"
                );
            }
        }
        for (key, id) in &self.store.vote_slots {
            let entry = self
                .store
                .artifacts
                .get(id)
                .expect("slotted vote is retained");
            assert!(
                matches!(entry.artifact.as_ref(), Artifact::DaVote(vote) if vote_slot_key(vote) == *key),
                "vote-slot index disagrees at {key:?}"
            );
        }
        for (id, entry) in &self.store.artifacts {
            match entry.artifact.as_ref() {
                Artifact::TransactionBlock(block)
                    if matches!(entry.state, ArtifactState::Ready) =>
                {
                    let position = (block.header().chain(), block.header().height());
                    assert!(
                        self.store
                            .verified_blocks
                            .get(&position)
                            .is_some_and(|blocks| blocks.contains(&Some(*id))),
                        "ready producer block {id:?} is missing from the verified-block index"
                    );
                }
                Artifact::DaVote(vote)
                    if !entry.dependency_protected
                        && vote.header().height()
                            > self.durable.state.certified_tips[vote.header().chain().index()]
                                .height() =>
                {
                    assert_eq!(
                        self.store.vote_slots.get(&vote_slot_key(vote)),
                        Some(id),
                        "network vote {id:?} above the durable tip is missing from its slot"
                    );
                }
                _ => {}
            }
        }

        // Dependency-waiter slots are held exactly by the entries flagged for one, and the waiter
        // index lists exactly the entries waiting on each dependency.
        let slots = self
            .store
            .artifacts
            .values()
            .filter(|entry| entry.dependency_slot)
            .count();
        assert_eq!(slots, self.dependencies.slots, "dependency slot count");
        for (id, entry) in &self.store.artifacts {
            if let ArtifactState::Waiting(missing) = &entry.state {
                assert!(
                    self.dependencies
                        .waiters
                        .get(missing)
                        .is_some_and(|waiters| waiters.contains(id)),
                    "waiting artifact {id:?} is missing from the waiter index"
                );
            }
        }
        for (dependency, waiters) in &self.dependencies.waiters {
            assert!(
                !waiters.is_empty(),
                "empty waiter bucket for {dependency:?}"
            );
            for id in waiters {
                assert!(
                    matches!(
                        self.store.artifacts.get(id).map(|entry| &entry.state),
                        Some(ArtifactState::Waiting(missing)) if missing == dependency
                    ),
                    "waiter {id:?} does not wait on {dependency:?}"
                );
            }
        }

        // Every retained artifact retirement could forget right now is either queued for the
        // next pass or sits in a retired range the sweep has not reached yet.
        for (id, entry) in &self.store.artifacts {
            if entry.future || self.durable.artifact_references.contains_key(id) {
                continue;
            }
            let view = entry.artifact.view();
            let view_retired = view.is_some_and(|view| view <= self.durable.state.retired_view);
            let view_unswept =
                view.is_some_and(|view| self.store.swept_view.is_none_or(|swept| swept < view));
            let position = match entry.artifact.as_ref() {
                Artifact::TransactionBlock(block) => Some(block.header()),
                Artifact::DaVote(vote) => Some(vote.header()),
                Artifact::DaCertificate(certificate) => Some(certificate.header()),
                _ => None,
            }
            .map(|header| (header.chain().get() as usize, header.height()));
            let position_retired = position.is_some_and(|(chain, height)| {
                height <= self.durable.state.certified_tips[chain].height()
            });
            let position_unswept = position.is_some_and(|(chain, height)| {
                self.store
                    .swept_floors
                    .get(chain)
                    .copied()
                    .flatten()
                    .is_none_or(|swept| swept < height)
            });
            let forgettable = match entry.state {
                ArtifactState::Ready => view_retired || position_retired,
                ArtifactState::Waiting(_) => view_retired,
                _ => false,
            };
            if !forgettable {
                continue;
            }
            assert!(
                self.store.retirement_pending.contains(id)
                    || (view_retired && view_unswept)
                    || (position_retired && position_unswept),
                "retirable artifact {id:?} escaped the incremental retirement sweep"
            );
        }
    }

    /// Returns whether another machine-owned quantum is ready: scheduled work or a staged batch
    /// awaiting hand-off.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn work_remaining(&self) -> bool {
        self.scheduler.has_work() || self.next_staged_index().is_some()
    }

    /// Projects current state for deterministic tests, including staged changes.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn live_snapshot_for_test(&self) -> Snapshot<V, H::Digest> {
        Snapshot::new(
            self.profile.protocol().epoch(),
            self.profile.role(),
            self.durable.state.clone(),
        )
    }

    /// Returns a snapshot of acknowledged state, or `None` while staged changes await durability.
    pub(crate) fn checkpoint_cut(&self) -> Option<Snapshot<V, H::Digest>> {
        (self.pipeline.staged.is_empty() && self.durable.state.cursor == self.pipeline.acked).then(
            || {
                Snapshot::new(
                    self.profile.protocol().epoch(),
                    self.profile.role(),
                    self.durable.state.clone(),
                )
            },
        )
    }

    /// Returns the durable transition floor and the retained view proofs, from which the resolver
    /// rebuilds its volatile custody after startup.
    pub(crate) fn resolver_seed(&self) -> (View, Vec<ViewProof<V, H::Digest>>) {
        (
            self.durable.state.retired_view,
            self.durable.state.resolver_proofs(),
        )
    }

    /// Returns the number of nullifications retained above the proposal anchor.
    pub(crate) fn nullification_suffix(&self) -> u64 {
        let anchor = self.durable.state.proposal_anchor_view();
        self.durable
            .state
            .proposal_nullified_through
            .get()
            .saturating_sub(anchor.get())
    }

    /// Returns the number of artifacts pinned by durable safety state.
    pub(crate) fn retained_artifact_references(&self) -> usize {
        self.durable.artifact_references.len()
    }

    /// Returns the number of staged group-commit batches not yet acknowledged as durable.
    pub(crate) fn staged_barriers(&self) -> usize {
        self.pipeline.staged.len()
    }

    /// Returns whether another protocol turn may reserve durable state.
    pub(crate) fn has_persistence_capacity(&self) -> bool {
        self.pipeline.staged.len() < MAX_STAGED_BARRIERS
    }

    /// Returns whether any protocol component has scheduled work.
    pub(crate) fn has_component_work(&self) -> bool {
        self.scheduler.has_work()
    }

    /// Returns whether the next poll begins this node's vote pass for the current view.
    ///
    /// A poll drives the view component when it is the first ready key, and that drive begins the
    /// pass when the view's timer has not fired (a fired timer can take the cutoff path first) and
    /// the view state would begin a vote pass. A pass begun after its view's timer fired is
    /// therefore not reported here. It allocates nothing: the proposal validity check compares the
    /// proposal against its parent's cached commitment, and runs only once the cheaper conditions
    /// hold.
    pub(crate) fn vote_build_due(&self) -> bool {
        let view = self.durable.state.view;
        self.scheduler.peek() == Some(WorkKey::Drive(ProtocolComponent::View))
            && self.views.timeout_cutoff(view).is_none()
            && self.views.vote_pass_begins(view).unwrap_or(false)
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
            .map(|(index, heights)| {
                let finalized = finalized[index];
                ChainProgress {
                    chain: ChainId::new(index as u32),
                    finalized,
                    certified: heights.certified,
                    da_voted: heights.da_voted,
                    known: heights.known.max(finalized),
                }
            })
            .collect()
    }

    /// Returns whether work issued as `issued` belongs to the current process generation.
    pub(crate) fn is_current<Id: Copy>(&self, issued: Issued<Id>) -> bool {
        issued.generation() == self.durable.state.generation
    }

    /// Returns the process generation that issues volatile work.
    pub(crate) const fn generation(&self) -> Generation {
        self.durable.state.generation
    }

    /// Returns the current view.
    pub(crate) const fn view(&self) -> View {
        self.durable.state.view
    }

    /// Returns the durable retired view: views at or below it hold no retained state.
    #[cfg(test)]
    pub(crate) const fn retired_view(&self) -> View {
        self.durable.state.retired_view
    }

    /// Returns the L-QC that proves finality through the signing floor, if one was admitted.
    #[cfg(test)]
    pub(crate) fn signing_floor(&self) -> Option<&Artifact<V, H::Digest>> {
        self.durable.state.signing_floor.as_deref()
    }

    /// Returns the V-QC the next proposal builds on, if one was selected.
    #[cfg(test)]
    pub(crate) fn anchor_vqc(&self) -> Option<&Artifact<V, H::Digest>> {
        self.durable.state.proposal_anchor.as_deref()
    }

    /// Returns the own producer chain's certified tip height, if this validator produces one.
    pub(crate) fn own_certified_height(&self) -> Option<Height> {
        let Role::Validator(participant) = self.profile.role() else {
            return None;
        };
        let chain = self.profile.protocol().producer_chain(participant)?;
        self.durable.state.certified_height(chain)
    }

    /// Returns one producer chain's certified anchor, for re-seeding its chain plane.
    pub(crate) fn certified_anchor(&self, chain: ChainId) -> BlockRef<H::Digest> {
        self.chain.da.certified_anchor(chain)
    }

    /// Returns one producer chain's durable DA choices, for re-seeding its chain plane.
    pub(crate) fn chosen_choices(&self, chain: ChainId) -> Vec<DaChoice<H::Digest>> {
        self.chain.da.chosen_choices(chain)
    }

    /// Records one chain's offered eligible run and frontier reach from its chain plane.
    ///
    /// An offer from a plane of an earlier process generation is stale.
    pub(crate) fn offer_da_votes(
        &mut self,
        offer: DaVotesOffer<V, H::Digest>,
    ) -> StepStatus<H::Digest> {
        let DaVotesOffer {
            generation,
            chain,
            candidates,
            ready_through,
        } = offer;
        if generation != self.durable.state.generation {
            return StepStatus::StaleCompletion;
        }
        self.chain
            .da
            .note_da_vote_ready(chain, candidates, ready_through);
        // Schedule the drain so the reservation does not wait for the next unrelated input.
        self.wake_components();
        StepStatus::Accepted
    }

    /// Projects compact protocol progress for metrics and retention coordination.
    pub(crate) fn progress(&self) -> CoreProgress {
        let resources = self.profile.resources();
        let cutoff = self.views.timeout_cutoff(self.durable.state.view);
        CoreProgress {
            view: self.durable.state.view,
            retired_view: self.durable.state.retired_view,
            finality_floor: self.signing_floor_view(),
            proposal_anchor_view: self.durable.state.proposal_anchor_view(),
            produced_blocks: self.durable.state.produced_blocks,
            producer: self.chain.producer_status::<H>(),
            artifact_cache_occupancy: self.store.artifacts.len()
                + self.local_artifact_reservations(),
            artifact_cache_capacity: resources.max_cached_artifacts(),
            remote_artifact_capacity: resources.remote_artifact_capacity(),
            local_artifact_capacity: resources.local_artifact_capacity(),
            verification_jobs: self.completions.verification_jobs.len(),
            verification_job_capacity: resources.max_inflight_verifications(),
            future_artifacts: self.store.future.len(),
            timeout_cutoff_vote: matches!(cutoff, Some(TimeoutCutoff::Vote(_))),
            timeout_cutoff_timeout: matches!(cutoff, Some(TimeoutCutoff::Timeout)),
        }
    }

    /// Returns each producer chain's local progress.
    pub(crate) fn chain_progress(&self) -> Vec<ChainProgress> {
        let finality = self.finality.facts();
        self.project_chain_progress(&finality)
    }

    /// Returns the verified headers admitted after this leader sealed its proposal, while that
    /// proposal's view was still current.
    pub(crate) const fn headers_after_seal(&self) -> u64 {
        self.views.headers_after_seal()
    }

    /// Returns the proposal-pass restarts verified header admissions triggered.
    pub(crate) const fn header_restarts(&self) -> u64 {
        self.views.header_restarts()
    }

    /// Returns a normalized read-only projection without exposing internal maps.
    pub(crate) fn inspect(&self) -> Inspection<H::Digest> {
        let mut pending_artifacts = 0;
        let mut waiting_artifacts = 0;
        let mut ready_artifacts = Vec::new();
        let mut dropped_artifacts = 0;

        for (id, entry) in &self.store.artifacts {
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
        let mut outbox = self.durable.state.effect_ids().collect::<Vec<_>>();
        outbox.sort_unstable();

        Inspection {
            epoch: self.profile.protocol().epoch(),
            progress: self.progress(),
            generation: self.durable.state.generation,
            cursor: self.durable.state.cursor,
            lifecycle: self.lifecycle,
            cached_artifacts: self.store.artifacts.len(),
            pending_artifacts,
            waiting_artifacts,
            ready_artifacts: ready_artifacts.into_iter().map(|(_, id)| id).collect(),
            dropped_artifacts,
            verification_jobs: self.completions.verification_jobs.keys().copied().collect(),
            pending_barrier: self.pipeline.staged.front().map(|pending| pending.job.id()),
            local_artifacts: self.durable.state.local.len(),
            outbox,
            retained_artifact_references: self.durable.artifact_references.len(),
            nullification_suffix: self.nullification_suffix(),
            resolution_jobs: self.resolution.len(),
            chain_progress,
            pools: self.finality.pools(),
            finality,
        }
    }
}
