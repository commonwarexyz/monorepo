//! Speculative execution engine for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] owns the in-memory pending-tip DAG and the applied
//! database set. It is the workhorse behind the actor's `Processing` mode,
//! handling three operations:
//!
//! - Propose/Verify: fork unmerkleized batches from a parent's pending
//!   state (or from applied state), delegate to the [`Application`], and
//!   cache the resulting merkleized batches keyed by block digest.
//!
//! - Lazy recovery: when a parent's pending state is missing (e.g. after
//!   restart), the processor walks the block DAG backward via marshal to the
//!   nearest known anchor, then replays forward via [`Application::apply`],
//!   inserting each intermediate result into the pending map.
//!
//! - Finalization: apply the winning fork's merkleized batches to the
//!   databases, retaining only pending descendants of the finalized winner.
//!   The actor coordinates durability separately so multiple finalizations
//!   can be covered by one storage sync.
//!
//! Verification jobs are polled independently and scoped to their callers.
//! Verification-owned lazy recovery shares [`Application::apply`] by block
//! digest. Proposal recovery remains actor-owned.

use crate::stateful::{
    Application, Finalized, Input, Proposed, PruneConfig,
    actor::{core::Verification, metrics::Metrics as StatefulMetrics},
    db::{Anchor, Barrier, DatabaseSet},
};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable, Roundable,
    marshal::{
        Identifier,
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::{Height, Round},
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::{metrics::GaugeExt, traces::TracedExt as _},
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use futures::{Stream, StreamExt};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
    hash::Hash,
    sync::Arc,
};
use tracing::{debug, warn};

mod verifier;
pub(super) use verifier::Verifier;

pub(super) type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;
type PendingMap<A, E> = BTreeMap<PendingDigest<A, E>, PendingEntry<A, E>>;
pub(super) type PendingSyncTargets<A, E> =
    <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type DeferredPrune<T> = Option<Prune<T>>;
type ReplayResult = Result<(), PrepareBatchesError>;
type ReplayWaiterSlots = Vec<Option<oneshot::Sender<ReplayResult>>>;
type ReplayRegistry<D> = Arc<Mutex<BTreeMap<D, ReplayFlight>>>;

/// Identity that prevents stale handles from modifying a replacement replay.
struct ReplayGeneration;

/// One in-progress replay and the requests waiting for its result.
struct ReplayFlight {
    generation: Arc<ReplayGeneration>,
    waiters: ReplayWaiterSlots,
    vacant_slots: Vec<usize>,
}

/// Last observed phase used to classify live verification across finalization.
#[derive(Clone, Copy)]
enum VerificationPhase<D> {
    Acquiring,
    Replaying { digest: D, parent: D, round: Round },
    Verifying { digest: D, parent: D, round: Round },
}

/// How tracked verification work crosses an incoming finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Disposition {
    /// Continue polling work proven to descend from the finalized block.
    Retain,
    /// Restart the same request when its branch is unknown or its active phase
    /// cannot cross finalization.
    Retry,
    /// Return false for work already proven to use an incompatible parent.
    Reject,
}

/// Progress used to classify an active verification attempt across an incoming
/// finalization.
#[derive(Clone)]
pub(super) struct VerificationProgress<D: Copy>(Arc<Mutex<VerificationPhase<D>>>);

impl<D: Copy> Default for VerificationProgress<D> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(VerificationPhase::Acquiring)))
    }
}

impl<D: Copy> VerificationProgress<D> {
    fn replaying(&self, digest: D, parent: D, round: Round) {
        *self.0.lock() = VerificationPhase::Replaying {
            digest,
            parent,
            round,
        };
    }

    fn verifying(&self, digest: D, parent: D, round: Round) {
        *self.0.lock() = VerificationPhase::Verifying {
            digest,
            parent,
            round,
        };
    }

    fn phase(&self) -> VerificationPhase<D> {
        *self.0.lock()
    }
}

/// Pending parents whose branch-scoped batches remain valid after one
/// finalized block is applied.
///
/// Marshal delivers finalized blocks in height order. Canonical older blocks
/// are therefore already covered by the processed anchor and resolve while
/// their verification is still acquiring. The exact processed phase is the
/// only older replay or verification phase that can survive from the preceding
/// finalization.
pub(super) struct FinalizationBoundary<D> {
    digest: D,
    round: Round,
    processed_digest: D,
    processed_round: Round,
    compatible: HashSet<D>,
}

impl<D: Copy + Eq + Hash> FinalizationBoundary<D> {
    pub(super) fn disposition(&self, progress: &VerificationProgress<D>) -> Disposition {
        match progress.phase() {
            VerificationPhase::Acquiring => Disposition::Retry,
            VerificationPhase::Replaying {
                digest,
                parent,
                round,
            } => {
                if digest == self.processed_digest && round == self.processed_round {
                    return Disposition::Retry;
                }
                match digest == self.digest {
                    true => Disposition::Retain,
                    false if round > self.round && self.compatible.contains(&parent) => {
                        Disposition::Retain
                    }
                    false => Disposition::Reject,
                }
            }
            VerificationPhase::Verifying {
                digest,
                parent,
                round,
            } => {
                if digest == self.digest
                    || (digest == self.processed_digest && round == self.processed_round)
                {
                    Disposition::Retry
                } else if round > self.round && self.compatible.contains(&parent) {
                    Disposition::Retain
                } else {
                    Disposition::Reject
                }
            }
        }
    }
}

/// Cached speculative state for a block digest.
struct PendingEntry<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    round: Round,
    parent: PendingDigest<A, E>,
    merkleized: PendingBatches<A, E>,
}

/// Speculative state shared by independently-polled verification jobs.
///
/// During finalization, the winning batch remains available as a branch parent
/// while a clone is applied. `finalizing_compatible` admits late state only
/// when its recorded parent already belongs to that branch.
struct ExecutionState<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Merkleized state for unfinalized blocks.
    pending: PendingMap<A, E>,
    /// Latest canonical anchor whose finalization hook has completed.
    last_processed: Anchor<PendingDigest<A, E>>,
    /// Winner currently being applied, if finalization is active.
    finalizing: Option<Anchor<PendingDigest<A, E>>>,
    /// Winner batch retained while a clone is applied to the databases.
    finalizing_batch: Option<PendingBatches<A, E>>,
    /// Winner and descendants allowed in pending state during finalization.
    finalizing_compatible: HashSet<PendingDigest<A, E>>,
}

/// Returns the winner and pending descendants whose state survives finalization.
fn compatible_pending<A, E>(
    state: &ExecutionState<A, E>,
    finalized_digest: PendingDigest<A, E>,
    finalized_round: Round,
) -> HashSet<PendingDigest<A, E>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let mut children_by_parent = BTreeMap::new();
    for (candidate_digest, entry) in &state.pending {
        if entry.round <= finalized_round {
            continue;
        }
        children_by_parent
            .entry(entry.parent)
            .or_insert_with(Vec::new)
            .push(*candidate_digest);
    }

    let mut compatible = HashSet::new();
    compatible.insert(finalized_digest);

    let mut to_visit = VecDeque::new();
    to_visit.push_back(finalized_digest);
    while let Some(parent) = to_visit.pop_front() {
        let Some(children) = children_by_parent.get(&parent) else {
            continue;
        };
        for &child in children {
            if compatible.insert(child) {
                to_visit.push_back(child);
            }
        }
    }
    compatible
}

/// Shared execution inputs and actor-owned speculative state.
struct Execution<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    databases: A::Databases,
    state: Arc<Mutex<ExecutionState<A, E>>>,
    metrics: StatefulMetrics,
}

impl<E, A> Clone for Execution<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            databases: self.databases.clone(),
            state: self.state.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// In-progress verification replays keyed by acquired block digest.
///
/// Each key identifies a [`CertifiableBlock`] and its embedded context.
#[derive(Clone)]
struct ReplayFlights<D: Copy + Ord> {
    entries: ReplayRegistry<D>,
}

#[derive(Clone, Copy)]
struct ReplayTracking<'a, D: Copy + Ord> {
    flights: &'a ReplayFlights<D>,
    progress: &'a VerificationProgress<D>,
}

impl<D: Copy + Ord> Default for ReplayFlights<D> {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl<D: Copy + Ord> ReplayFlights<D> {
    fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    fn waiter(&self, digest: D, flight: &mut ReplayFlight) -> ReplayWaiter<D> {
        let (sender, completion) = oneshot::channel();
        let waiters = &mut flight.waiters;
        let slot = if let Some(slot) = flight.vacant_slots.pop() {
            assert!(
                waiters
                    .get_mut(slot)
                    .expect("vacant replay waiter slot must exist")
                    .replace(sender)
                    .is_none(),
                "vacant replay waiter slot must be empty",
            );
            slot
        } else {
            let slot = waiters.len();
            waiters.push(Some(sender));
            slot
        };
        ReplayWaiter {
            flights: self.clone(),
            digest,
            generation: Arc::clone(&flight.generation),
            slot,
            completion,
        }
    }

    /// Registers an owner through the caller-held registry guard, keeping the
    /// existing-flight check and insertion in one critical section.
    fn register_owner(&self, digest: D, entries: &mut BTreeMap<D, ReplayFlight>) -> ReplayOwner<D> {
        let generation = Arc::new(ReplayGeneration);
        assert!(
            entries
                .insert(
                    digest,
                    ReplayFlight {
                        generation: Arc::clone(&generation),
                        waiters: Vec::new(),
                        vacant_slots: Vec::new(),
                    },
                )
                .is_none(),
        );
        ReplayOwner {
            flights: self.clone(),
            digest,
            generation,
            result: None,
        }
    }
}

/// Outcome of requesting shared replay work for one block digest.
enum ReplayClaim<D: Copy + Ord> {
    /// State for the digest is already available.
    Ready,
    /// The caller owns the new replay flight.
    Owner(ReplayOwner<D>),
    /// Another caller owns the replay flight.
    Wait(ReplayWaiter<D>),
}

/// Claim on the finalizing winner's batch construction.
enum FinalizationClaim<D: Copy + Ord> {
    Cached,
    Wait(ReplayWaiter<D>),
    Reconstruct(ReplayOwner<D>),
}

/// Registration that removes its own waiter slot when dropped.
struct ReplayWaiter<D: Copy + Ord> {
    flights: ReplayFlights<D>,
    digest: D,
    generation: Arc<ReplayGeneration>,
    slot: usize,
    completion: oneshot::Receiver<ReplayResult>,
}

impl<D: Copy + Ord> Drop for ReplayWaiter<D> {
    fn drop(&mut self) {
        let mut entries = self.flights.entries.lock();
        let Some(flight) = entries.get_mut(&self.digest) else {
            return;
        };
        if !Arc::ptr_eq(&flight.generation, &self.generation) {
            return;
        }

        let waiters = &mut flight.waiters;
        let waiter = waiters
            .get_mut(self.slot)
            .expect("live replay waiter must have a slot");
        assert!(
            waiter.take().is_some(),
            "live replay waiter slot must hold its sender",
        );
        flight.vacant_slots.push(self.slot);
    }
}

/// Replay owner that removes its generation and notifies waiters when dropped.
struct ReplayOwner<D: Copy + Ord> {
    flights: ReplayFlights<D>,
    digest: D,
    generation: Arc<ReplayGeneration>,
    result: Option<ReplayResult>,
}

impl<D: Copy + Ord> ReplayOwner<D> {
    fn finish(mut self, result: ReplayResult) {
        assert_ne!(
            result,
            Err(PrepareBatchesError::Cancelled),
            "cancellation must drop the replay owner without a result",
        );
        self.result = Some(result);
    }
}

impl<D: Copy + Ord> Drop for ReplayOwner<D> {
    fn drop(&mut self) {
        let flight = self
            .flights
            .entries
            .lock()
            .remove(&self.digest)
            .expect("replay owner must have an in-flight entry");
        assert!(
            Arc::ptr_eq(&flight.generation, &self.generation),
            "replay owner must match its in-flight generation",
        );
        if let Some(result) = self.result {
            for waiter in flight.waiters.into_iter().flatten() {
                waiter.send_lossy(result);
            }
        }
    }
}

/// Errors while preparing parent-relative batches for propose/verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrepareBatchesError {
    /// Parent ancestry is provably invalid.
    Invalid,
    /// Parent ancestry ended before validity could be proven.
    Incomplete,
    /// The attempt was cancelled while waiting.
    Cancelled,
}

/// Provides a cancellation signal for speculative actor work.
trait Cancellation {
    fn cancelled(&mut self) -> impl Future<Output = ()> + Send;
}

impl<T: Send> Cancellation for oneshot::Sender<T> {
    async fn cancelled(&mut self) {
        self.closed().await;
    }
}

impl Cancellation for Verification {
    async fn cancelled(&mut self) {
        self.wait_for_cancellation().await;
    }
}

/// State applied for a newly finalized block.
pub(super) struct Applied<T> {
    /// Durability started for this block, when no earlier sync was active.
    pub(super) barrier: Option<Barrier>,

    /// Prune made due by this finalization.
    pub(super) prune: DeferredPrune<T>,
}

/// Marshal and database prune targets selected from finalized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prune<T> {
    marshal_height: Height,
    pub(super) barrier_height: Height,
    qmdb_target: T,
}

impl<T> Prune<T> {
    /// Run database and marshal pruning.
    ///
    /// A completed database sync covers `barrier_height`, and no database sync remains active,
    /// before this runs. The marshal prune that follows retains every later block a restart could
    /// replay.
    pub(super) async fn run<E, DBs, S, V>(self, databases: &DBs, marshal: &MarshalMailbox<S, V>)
    where
        E: Rng + Spawner + Metrics + Clock,
        DBs: DatabaseSet<E, SyncTargets = T>,
        S: Scheme,
        V: MarshalVariant,
    {
        databases.prune(&self.qmdb_target).await;
        marshal.prune(self.marshal_height);
    }
}

/// Tracks the configured prune cadence and finalized sync targets needed to
/// make pruning safe.
pub(super) struct Pruning<T> {
    maintenance_interval: u64,
    maintenance_offset: u64,
    marshal_retention_window: usize,
    qmdb_retention_window: usize,
    retained_targets: VecDeque<(Height, T)>,
}

impl<T: Clone> Pruning<T> {
    pub(super) fn random(config: PruneConfig, max_pending_acks: usize, rng: &mut impl Rng) -> Self {
        let interval = u64::try_from(config.maintenance_interval.get())
            .expect("prune interval should fit in u64");
        let offset = rng.next_u64() % interval;
        Self::build(config, max_pending_acks, offset)
    }

    pub(super) fn build(
        config: PruneConfig,
        max_pending_acks: usize,
        maintenance_offset: u64,
    ) -> Self {
        config.assert_valid();
        let maintenance_interval = u64::try_from(config.maintenance_interval.get())
            .expect("prune interval should fit in u64");
        assert!(
            maintenance_offset < maintenance_interval,
            "prune maintenance offset must be within the interval",
        );
        let base_retention_window = max_pending_acks
            .checked_add(1)
            .expect("max_pending_acks retention window overflowed");
        let marshal_retention_window = base_retention_window
            .checked_add(config.retained_marshal_blocks)
            .expect("marshal prune retention window overflowed");
        let qmdb_retention_window = base_retention_window
            .checked_add(config.retained_qmdb_blocks)
            .expect("qmdb prune retention window overflowed");
        Self {
            maintenance_interval,
            maintenance_offset,
            marshal_retention_window,
            qmdb_retention_window,
            retained_targets: VecDeque::new(),
        }
    }

    /// Observe a newly finalized block and decide whether pruning should run.
    ///
    /// Pruning first retains the last `max_pending_acks + 1` finalized targets
    /// plus the configured retained block windows. It then prunes only when the
    /// largest required window is populated and the current finalized height
    /// matches the selected phase of the configured maintenance interval.
    fn observe_finalized(&mut self, height: Height, targets: T) -> DeferredPrune<T> {
        self.retained_targets.push_back((height, targets));
        if self.retained_targets.len() > self.marshal_retention_window {
            self.retained_targets.pop_front();
        }

        if height.get() % self.maintenance_interval != self.maintenance_offset {
            return None;
        }

        // Do not prune until we've observed the full rewind-safe marshal
        // window after startup.
        if self.retained_targets.len() < self.marshal_retention_window {
            return None;
        }

        let marshal_height = self
            .retained_targets
            .front()
            .expect("retained prune targets must exist")
            .0;
        let qmdb_index = self
            .retained_targets
            .len()
            .checked_sub(self.qmdb_retention_window)
            .expect("qmdb retention window must not exceed marshal window");
        let (barrier_height, qmdb_target) = self
            .retained_targets
            .get(qmdb_index)
            .expect("qmdb prune target must exist");

        Some(Prune {
            marshal_height,
            barrier_height: *barrier_height,
            qmdb_target: qmdb_target.clone(),
        })
    }
}

/// Owns speculative execution and state persistence for a running stateful actor.
pub(super) struct Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    app: A,
    execution: Execution<E, A>,
    replays: ReplayFlights<PendingDigest<A, E>>,
    pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a new processor with the given application, databases, and
    /// the last finalized block's anchor.
    pub(super) fn new(
        app: A,
        databases: A::Databases,
        last_processed: Anchor<PendingDigest<A, E>>,
        metrics: StatefulMetrics,
        pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
    ) -> Self {
        Self {
            app,
            execution: Execution {
                databases,
                state: Arc::new(Mutex::new(ExecutionState {
                    pending: BTreeMap::new(),
                    last_processed,
                    finalizing: None,
                    finalizing_batch: None,
                    finalizing_compatible: HashSet::new(),
                })),
                metrics,
            },
            replays: ReplayFlights::default(),
            pruning,
        }
    }

    /// Creates a verifier for an independently-polled request.
    pub(super) fn verifier(&self) -> Verifier<E, A> {
        Verifier {
            app: self.app.clone(),
            execution: self.execution.clone(),
            replays: self.replays.clone(),
        }
    }

    /// Returns whether every verification-owned replay has released its owner.
    pub(super) fn replays_idle(&self) -> bool {
        self.replays.is_empty()
    }

    /// Snapshot the pending bases that remain branch-valid after `block` is
    /// finalized.
    pub(super) fn finalization_boundary(
        &self,
        block: &A::Block,
    ) -> FinalizationBoundary<PendingDigest<A, E>> {
        let digest = block.digest();
        let round = block.context().round();
        let state = self.execution.state.lock();
        FinalizationBoundary {
            digest,
            round,
            processed_digest: state.last_processed.digest,
            processed_round: state.last_processed.round,
            compatible: compatible_pending(&state, digest, round),
        }
    }

    /// Returns a reference to the database set.
    pub(super) const fn databases(&self) -> &A::Databases {
        &self.execution.databases
    }

    pub(super) fn last_processed(&self) -> Anchor<PendingDigest<A, E>> {
        self.execution.last_processed()
    }

    #[cfg(test)]
    fn pending_contains(&self, digest: &PendingDigest<A, E>) -> bool {
        self.execution.pending_contains(digest)
    }

    #[cfg(test)]
    fn clear_pending(&self) {
        self.execution.state.lock().pending.clear();
        self.execution.update_pending_metric();
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// build a new block proposal. The resulting block and its merkleized
    /// state are cached in `pending`. Sends `None` on `response` if the
    /// ancestry is invalid or the application declines to propose.
    pub(super) async fn propose<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        (runtime_context, consensus_context): (E, A::Context),
        mut ancestry: impl Ancestry<A::Block>,
        input: Input<A::Input, A::Provider>,
        mut response: oneshot::Sender<Option<A::Block>>,
    ) where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let timer = self.execution.metrics.propose_duration.timer(context);

        let parent = match fetch_ancestor(&mut response, &mut ancestry).await {
            Some(Some(parent)) => parent,
            Some(None) => {
                response.send_lossy(None);
                return;
            }
            None => {
                debug!("proposal request cancelled before initial ancestry arrived");
                return;
            }
        };
        let parent_digest = parent.digest();
        let ancestry = marshal_ancestry::with_prefix([Arc::clone(&parent)], ancestry);

        let round = consensus_context.round();
        let batches = match self
            .prepare_batches(context, marshal, parent, &mut response)
            .await
        {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                response.send_lossy(None);
                return;
            }
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    ?parent_digest,
                    "proposal request waiting on incomplete ancestry during prepare_batches"
                );
                response.closed().await;
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?parent_digest,
                    "proposal request cancelled during prepare_batches"
                );
                return;
            }
        };

        let proposed = match await_or_cancel(
            &mut response,
            self.app.propose(
                (runtime_context, consensus_context),
                ancestry,
                batches,
                input,
            ),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(?parent_digest, "proposal request cancelled during propose");
                return;
            }
        };

        let Some(Proposed { block, merkleized }) = proposed else {
            response.send_lossy(None);
            return;
        };
        assert!(
            A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)),
            "proposed state must match block commitments",
        );
        assert!(
            self.cache_pending(block.digest(), parent_digest, round, merkleized),
            "proposal parent must remain compatible until the proposal completes",
        );
        self.execution.update_pending_metric();
        timer.observe(context);
        response.send_lossy(Some(block));
    }

    /// Ensure parent state exists, then prepare unmerkleized batches for execution.
    #[tracing::instrument(
        name = "stateful.processor.prepare_batches",
        level = "info",
        skip_all,
        fields(parent = %parent.digest())
    )]
    async fn prepare_batches<S, V, C>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        parent: Arc<A::Block>,
        cancellation: &mut C,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
        C: Cancellation,
    {
        self.execution
            .prepare_batches(&mut self.app, context, marshal, parent, cancellation, None)
            .await
    }

    /// Fork unmerkleized batches from known parent state.
    #[cfg(test)]
    async fn fork_batches(
        &self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError> {
        self.execution.fork_batches(parent).await
    }

    /// Rebuild missing pending ancestry up to `target` lazily from a block provider.
    #[cfg(test)]
    async fn rebuild_pending<P, C>(
        &mut self,
        context: &E,
        provider: P,
        target: Arc<A::Block>,
        cancellation: &mut C,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
        C: Cancellation,
    {
        self.execution
            .rebuild_pending(&mut self.app, context, provider, target, cancellation, None)
            .await
    }

    /// Apply finalized state and prune dead in-memory forks.
    ///
    /// Returns [`None`] when the block was already processed (a duplicate
    /// report).
    pub(super) async fn finalize(
        &mut self,
        context: &E,
        block: &A::Block,
        start_sync: bool,
    ) -> Option<Applied<PendingSyncTargets<A, E>>> {
        let finalized = Anchor::from(block);
        let (height, digest) = (finalized.height, finalized.digest);
        let last_processed = self.execution.last_processed();
        if height < last_processed.height {
            panic!(
                "received finalized block below processed height: finalized={} processed={}",
                height.get(),
                last_processed.height.get(),
            );
        }
        if height == last_processed.height {
            assert_eq!(
                digest, last_processed.digest,
                "received conflicting finalized block at processed height",
            );
            self.notify_finalized(context, block, Finalized::Synchronized)
                .await;
            return None;
        }

        let timer = self.execution.metrics.finalize_duration.timer(context);
        let block_context = block.context();
        let sync_targets = A::sync_targets(block);
        self.execution.begin_finalization(finalized);

        // Marshal finalization is ordered. If the winner is not cached,
        // reconstruct its batch from the current finalized database state.
        //
        // Safety contract: reconstructed `Application::apply` output must
        // match the block commitments previously enforced by `Application::verify`.
        let reconstruction = loop {
            match self
                .execution
                .claim_finalization_batch(&self.replays, digest)
            {
                FinalizationClaim::Cached => break None,
                FinalizationClaim::Reconstruct(owner) => break Some(owner),
                FinalizationClaim::Wait(mut waiter) => match (&mut waiter.completion).await {
                    Ok(Ok(())) | Err(_) => continue,
                    Ok(Err(error)) => {
                        warn!(
                            ?digest,
                            ?error,
                            "finalization could not reuse active verification replay"
                        );
                        continue;
                    }
                },
            }
        };
        let reconstructed = if reconstruction.is_none() {
            None
        } else {
            let batches = self.execution.databases.new_batches().await;
            let batch = self
                .app
                .apply(
                    (context.child("finalize_reconstruct"), block_context),
                    block,
                    batches,
                )
                .await;
            assert!(
                A::Databases::matches_sync_targets(&batch, &sync_targets),
                "finalize reconstruction must match block commitments",
            );
            Some(batch)
        };

        let batch = self
            .execution
            .secure_finalization_batch(digest, reconstructed);
        if let Some(owner) = reconstruction {
            owner.finish(Ok(()));
        }
        let artifact = self
            .app
            .capture_finalized(
                (context.child("capture_finalized"), block.context()),
                block,
                &batch,
                self.execution.databases.readers(),
            )
            .await;
        self.execution.databases.apply(batch).await;
        let barrier = if start_sync {
            Some(self.execution.databases.finalize().await)
        } else {
            None
        };
        self.notify_finalized(context, block, Finalized::Applied(artifact))
            .await;
        let prune = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe_finalized(height, sync_targets));
        self.execution.finish_finalization(finalized);
        timer.observe(context);

        Some(Applied { barrier, prune })
    }

    /// Notify the application after a finalized block is reflected in the
    /// database set.
    pub(super) async fn notify_finalized(
        &mut self,
        context: &E,
        block: &A::Block,
        provenance: Finalized<A::FinalizedArtifact>,
    ) {
        self.app
            .finalized(
                (context.child("finalized"), block.context()),
                block,
                provenance,
                self.execution.databases.readers(),
            )
            .await;
    }

    /// Cache merkleized pending state for a block digest.
    fn cache_pending(
        &self,
        digest: PendingDigest<A, E>,
        parent: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
    ) -> bool {
        self.execution
            .cache_pending(digest, parent, round, merkleized)
    }
}

impl<E, A> Execution<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn last_processed(&self) -> Anchor<PendingDigest<A, E>> {
        self.state.lock().last_processed
    }

    /// Records the compatible pending state for a serialized finalization.
    fn begin_finalization(&self, anchor: Anchor<PendingDigest<A, E>>) {
        let mut state = self.state.lock();
        let compatible = compatible_pending(&state, anchor.digest, anchor.round);
        assert!(
            state.finalizing.replace(anchor).is_none(),
            "finalization must be serialized",
        );
        assert!(state.finalizing_batch.is_none());
        assert!(state.finalizing_compatible.is_empty());
        state.finalizing_compatible = compatible;
    }

    /// Retain the winner as a branch parent and discard incompatible state.
    fn secure_finalization_batch(
        &self,
        digest: PendingDigest<A, E>,
        reconstructed: Option<PendingBatches<A, E>>,
    ) -> PendingBatches<A, E> {
        let mut state = self.state.lock();
        assert_eq!(
            state.finalizing.map(|anchor| anchor.digest),
            Some(digest),
            "secured batch must match active finalization",
        );
        assert!(state.finalizing_batch.is_none());
        let ExecutionState {
            pending,
            finalizing_batch,
            finalizing_compatible,
            ..
        } = &mut *state;
        let batch = pending
            .remove(&digest)
            .map(|entry| entry.merkleized)
            .or(reconstructed)
            .expect("finalization must have a cached or reconstructed batch");
        *finalizing_batch = Some(batch.clone());
        let before = pending.len();
        pending.retain(|candidate_digest, _| finalizing_compatible.contains(candidate_digest));
        let pruned = before - pending.len();
        let pending = pending.len();
        drop(state);
        self.metrics.pruned_forks.inc_by(pruned as u64);
        let _ = self.metrics.pending_blocks.try_set(pending);
        batch
    }

    /// Publish the finalized anchor after its application hook completes.
    fn finish_finalization(&self, finalized: Anchor<PendingDigest<A, E>>) {
        let mut state = self.state.lock();
        assert_eq!(state.finalizing.take(), Some(finalized));
        assert!(state.finalizing_batch.take().is_some());
        state.finalizing_compatible.clear();
        state.last_processed = finalized;
    }

    fn summary(&self) -> (Anchor<PendingDigest<A, E>>, usize) {
        let state = self.state.lock();
        (state.last_processed, state.pending.len())
    }

    fn pending_contains(&self, digest: &PendingDigest<A, E>) -> bool {
        self.state.lock().pending.contains_key(digest)
    }

    fn pending_len(&self) -> usize {
        self.state.lock().pending.len()
    }

    fn update_pending_metric(&self) {
        let _ = self.metrics.pending_blocks.try_set(self.pending_len());
    }

    fn cache_pending(
        &self,
        digest: PendingDigest<A, E>,
        parent: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
    ) -> bool {
        let mut state = self.state.lock();
        if let Some(existing) = state.pending.get(&digest) {
            debug_assert_eq!(existing.parent, parent, "pending parent changed for digest");
            debug_assert_eq!(existing.round, round, "pending round changed for digest");
            return true;
        }

        // A replay can finish after another copy supplied the batch consumed by finalization.
        // Treat it as cached without reinserting the finalized batch.
        let winner_already_retained = state.finalizing.is_some_and(|finalizing| {
            state.finalizing_batch.is_some()
                && finalizing.digest == digest
                && finalizing.round == round
        });
        if winner_already_retained
            || (state.last_processed.digest == digest && state.last_processed.round == round)
        {
            return true;
        }

        // The processed anchor is not advanced until the application hook returns. Retained
        // descendants may cache state during that interval, but new work on the old anchor may not.
        let compatible = state.finalizing.map_or_else(
            || {
                round > state.last_processed.round
                    && (parent == state.last_processed.digest
                        || state.pending.contains_key(&parent))
            },
            |finalizing| {
                (digest == finalizing.digest
                    && round == finalizing.round
                    && (parent == state.last_processed.digest
                        || state.pending.contains_key(&parent)))
                    || (round > finalizing.round && state.finalizing_compatible.contains(&parent))
            },
        );
        if !compatible {
            return false;
        }
        state.pending.insert(
            digest,
            PendingEntry {
                round,
                parent,
                merkleized,
            },
        );
        if state.finalizing.is_some() {
            state.finalizing_compatible.insert(digest);
        }
        true
    }

    /// Finds, joins, or reserves construction of the finalizing winner batch.
    ///
    /// Replay completion only tells the caller to check the cache again: the
    /// owner caches the batch before notifying its waiters. Execution state is
    /// always locked before the replay registry when both are inspected.
    fn claim_finalization_batch(
        &self,
        replays: &ReplayFlights<PendingDigest<A, E>>,
        digest: PendingDigest<A, E>,
    ) -> FinalizationClaim<PendingDigest<A, E>> {
        let state = self.state.lock();
        let mut entries = replays.entries.lock();
        if let Some(flight) = entries.get_mut(&digest) {
            return FinalizationClaim::Wait(replays.waiter(digest, flight));
        }
        if state.pending.contains_key(&digest) {
            FinalizationClaim::Cached
        } else {
            FinalizationClaim::Reconstruct(replays.register_owner(digest, &mut entries))
        }
    }

    /// Reuses known state, joins an active replay, or claims replay ownership.
    ///
    /// The state-before-registry lock order prevents a replay registration from
    /// racing insertion of the same digest.
    fn claim_replay(
        &self,
        replays: &ReplayFlights<PendingDigest<A, E>>,
        digest: PendingDigest<A, E>,
    ) -> ReplayClaim<PendingDigest<A, E>> {
        let state = self.state.lock();
        if state.last_processed.digest == digest
            || state.pending.contains_key(&digest)
            || (state.finalizing_batch.is_some()
                && state
                    .finalizing
                    .is_some_and(|finalizing| finalizing.digest == digest))
        {
            return ReplayClaim::Ready;
        }

        let mut entries = replays.entries.lock();
        if let Some(flight) = entries.get_mut(&digest) {
            return ReplayClaim::Wait(replays.waiter(digest, flight));
        }

        ReplayClaim::Owner(replays.register_owner(digest, &mut entries))
    }

    /// Whether finalization supersedes a winner replay's terminal failure.
    fn finalization_recovers_replay(&self, digest: PendingDigest<A, E>) -> bool {
        let state = self.state.lock();
        state.last_processed.digest == digest
            || state
                .finalizing
                .is_some_and(|finalizing| finalizing.digest == digest)
    }

    /// Forks batches from a known parent.
    async fn fork_batches(
        &self,
        parent: &PendingDigest<A, E>,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError> {
        {
            let state = self.state.lock();
            if let Some(entry) = state.pending.get(parent) {
                return Ok(A::Databases::fork_batches(&entry.merkleized));
            }
            if state
                .finalizing
                .is_some_and(|finalizing| finalizing.digest == *parent)
            {
                let batch = state
                    .finalizing_batch
                    .as_ref()
                    .ok_or(PrepareBatchesError::Invalid)?;
                return Ok(A::Databases::fork_batches(batch));
            }
            if state.last_processed.digest != *parent {
                return Err(PrepareBatchesError::Invalid);
            }
        }

        Ok(self.databases.new_batches().await)
    }

    /// Replays one certified block and caches its commitment-matching state.
    ///
    /// Cancellation caches nothing. A commitment mismatch or state that cannot
    /// be cached across active finalization makes the ancestry invalid.
    async fn replay_block<C>(
        &self,
        app: &mut A,
        context: &E,
        target_digest: PendingDigest<A, E>,
        block: Arc<A::Block>,
        cancellation: &mut C,
    ) -> ReplayResult
    where
        C: Cancellation,
    {
        let (digest, parent_digest) = (block.digest(), block.parent());
        let consensus_context = block.context();
        let round = consensus_context.round();

        let Some(batches) = await_or_cancel(cancellation, self.fork_batches(&parent_digest)).await
        else {
            return Err(PrepareBatchesError::Cancelled);
        };
        let batches = batches?;

        let Some(merkleized) = await_or_cancel(
            cancellation,
            app.apply(
                (context.child("rebuild_pending_apply"), consensus_context),
                &block,
                batches,
            ),
        )
        .await
        else {
            return Err(PrepareBatchesError::Cancelled);
        };

        if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
            warn!(
                ?target_digest,
                block = ?digest,
                "rebuild replay state root must match block commitments"
            );
            return Err(PrepareBatchesError::Invalid);
        }

        self.cache_pending(digest, parent_digest, round, merkleized)
            .then_some(())
            .ok_or(PrepareBatchesError::Invalid)
    }

    /// Replays one block while sharing completed work with concurrent requests.
    ///
    /// One owner executes the block and broadcasts each terminal result. A
    /// cancelled owner drops the flight without a result, closing its waiter
    /// channels so live requests loop and claim a new generation.
    async fn replay_block_shared<C>(
        &self,
        app: &mut A,
        context: &E,
        target_digest: PendingDigest<A, E>,
        block: Arc<A::Block>,
        cancellation: &mut C,
        replay: ReplayTracking<'_, PendingDigest<A, E>>,
    ) -> ReplayResult
    where
        C: Cancellation,
    {
        let (digest, parent, round) = (block.digest(), block.parent(), block.context().round());
        loop {
            match self.claim_replay(replay.flights, digest) {
                ReplayClaim::Ready => return Ok(()),
                ReplayClaim::Owner(owner) => {
                    replay.progress.replaying(digest, parent, round);
                    let result = self
                        .replay_block(
                            app,
                            context,
                            target_digest,
                            Arc::clone(&block),
                            cancellation,
                        )
                        .await;
                    if result != Err(PrepareBatchesError::Cancelled) {
                        owner.finish(result);
                    }
                    return result;
                }
                ReplayClaim::Wait(mut waiter) => {
                    replay.progress.replaying(digest, parent, round);
                    let Some(completion) =
                        await_or_cancel(cancellation, &mut waiter.completion).await
                    else {
                        return Err(PrepareBatchesError::Cancelled);
                    };
                    match completion {
                        Ok(Ok(())) | Err(_) => continue,
                        Ok(Err(error)) => {
                            if self.finalization_recovers_replay(digest) {
                                continue;
                            }
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    /// Ensures parent state exists and forks batches for speculative execution.
    ///
    /// Verification supplies replay tracking to share reconstruction by block
    /// digest, while proposals reconstruct independently. `fork_batches`
    /// revalidates the parent after reconstruction in case finalization
    /// advanced meanwhile.
    async fn prepare_batches<S, V, C>(
        &self,
        app: &mut A,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        parent: Arc<A::Block>,
        cancellation: &mut C,
        replay: Option<ReplayTracking<'_, PendingDigest<A, E>>>,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
        C: Cancellation,
    {
        let parent_digest = parent.digest();
        let known = {
            let state = self.state.lock();
            state.last_processed.digest == parent_digest
                || state.pending.contains_key(&parent_digest)
        };
        if !known {
            self.rebuild_pending(app, context, marshal, parent, cancellation, replay)
                .await?;
        }

        await_or_cancel(cancellation, self.fork_batches(&parent_digest))
            .await
            .ok_or(PrepareBatchesError::Cancelled)?
    }

    /// Rebuilds missing ancestry through `target`.
    ///
    /// The backward walk stops only at pending state or the applied anchor and
    /// rejects stale or non-contiguous ancestry. Blocks are then replayed in
    /// ancestor order, with commitments checked before each cache insertion.
    async fn rebuild_pending<P, C>(
        &self,
        app: &mut A,
        context: &E,
        provider: P,
        target: Arc<A::Block>,
        cancellation: &mut C,
        replay: Option<ReplayTracking<'_, PendingDigest<A, E>>>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
        C: Cancellation,
    {
        let timer = self.metrics.rebuild_pending_duration.timer(context);
        let target_digest = target.digest();

        let mut replay_path = Vec::new();
        let mut cursor = target;
        loop {
            let (known, last_processed) = {
                let state = self.state.lock();
                (
                    cursor.digest() == state.last_processed.digest
                        || state.pending.contains_key(&cursor.digest()),
                    state.last_processed,
                )
            };
            if known {
                break;
            }

            let cursor_height = cursor.height();
            if cursor_height <= last_processed.height {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    current_height = cursor_height.get(),
                    last_processed_height = last_processed.height.get(),
                    last_processed = ?last_processed.digest,
                    "rebuild_pending reached stale ancestry at or below processed height"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            let Some(parent) =
                await_or_cancel(cancellation, provider.clone().subscribe_parent(&cursor)).await
            else {
                return Err(PrepareBatchesError::Cancelled);
            };

            let Some(parent) = parent else {
                debug!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    "ancestor subscription ended before delivery"
                );
                return Err(PrepareBatchesError::Incomplete);
            };

            if parent.digest() != cursor.parent() || parent.height().next() != cursor_height {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    parent = ?parent.digest(),
                    cursor_height = cursor_height.get(),
                    parent_height = parent.height().get(),
                    expected_parent = ?cursor.parent(),
                    "rebuild_pending received non-contiguous ancestry"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            replay_path.push(cursor);
            cursor = parent;
        }

        let depth = replay_path.len();
        for block in replay_path.into_iter().rev() {
            if let Some(replay) = replay {
                self.replay_block_shared(app, context, target_digest, block, cancellation, replay)
                    .await?;
            } else {
                self.replay_block(app, context, target_digest, block, cancellation)
                    .await?;
            }
        }

        self.update_pending_metric();
        let _ = self.metrics.rebuild_pending_depth.try_set(depth);
        timer.observe(context);
        Ok(())
    }
}

/// Returns true when `block` is already covered by applied state.
#[tracing::instrument(
    name = "stateful.processor.is_already_processed",
    level = "info",
    skip_all,
    fields(height = block.height().traced(), digest = %block.digest())
)]
async fn is_already_processed<S, V, C>(
    last_processed: Anchor<<V::ApplicationBlock as Digestible>::Digest>,
    marshal: MarshalMailbox<S, V>,
    block: &V::ApplicationBlock,
    cancellation: &mut C,
) -> Result<bool, PrepareBatchesError>
where
    S: Scheme,
    V: MarshalVariant,
    V::ApplicationBlock: Block + Clone,
    C: Cancellation,
{
    let target_height = block.height();
    if target_height > last_processed.height {
        return Ok(false);
    }
    if target_height == last_processed.height {
        return Ok(block.digest() == last_processed.digest);
    }

    let Some(canonical) = await_or_cancel(
        cancellation,
        marshal.get_block(Identifier::Height(target_height)),
    )
    .await
    else {
        return Err(PrepareBatchesError::Cancelled);
    };
    let Some(canonical) = canonical else {
        warn!(
            target_height = target_height.get(),
            processed_height = last_processed.height.get(),
            "failed to fetch canonical processed block for stale-block check"
        );
        return Err(PrepareBatchesError::Incomplete);
    };

    Ok(canonical.digest() == block.digest())
}

/// Read the next ancestry item unless the request is cancelled.
#[tracing::instrument(name = "stateful.processor.fetch_ancestor", level = "info", skip_all)]
async fn fetch_ancestor<C, T, S>(cancellation: &mut C, stream: &mut S) -> Option<Option<T>>
where
    S: Stream<Item = T> + Unpin,
    C: Cancellation,
{
    await_or_cancel(cancellation, stream.next()).await
}

/// Wait for `future` unless the request is cancelled.
async fn await_or_cancel<C, T, F>(cancellation: &mut C, future: F) -> Option<T>
where
    F: Future<Output = T>,
    C: Cancellation,
{
    select! {
        _ = cancellation.cancelled() => None,
        output = future => Some(output),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Applied, Disposition, FinalizationBoundary, PrepareBatchesError, Processor, Prune, Pruning,
        ReplayClaim, ReplayFlights, ReplayTracking, VerificationProgress, fetch_ancestor,
    };
    use crate::stateful::{
        Application, Finalized, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{Anchor, Barrier, DatabaseSet, Merkleized as _, Shared, Unmerkleized as _},
    };
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        Block as ConsensusBlock, CertifiableBlock, Heightable,
        marshal::ancestry::{Ancestry, BlockProvider},
        simplex::{mocks::scheme::Scheme as MockScheme, types::Context as ConsensusContext},
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Digestible, Hasher, Sha256, Signer as _, ed25519, sha256::Digest,
    };
    use commonware_macros::{boxed, select};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, ContextCell, Runner as _, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, Location, full::Config as MmrJournalConfig},
        qmdb::{any, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, channel::oneshot, non_empty_range, range::NonEmptyRange, sync::Mutex,
    };
    use futures::StreamExt;
    use std::{
        collections::{BTreeMap, HashSet, VecDeque},
        future::Future,
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    async fn assert_durable(barrier: Option<Barrier>) {
        assert!(
            barrier
                .expect("finalization must start durability")
                .durable()
                .await,
            "database sync must complete",
        );
    }

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;

    const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
    const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

    type Qmdb<E> =
        any::unordered::fixed::Db<mmr::Family, E, Digest, Digest, Sha256, TwoCap, Sequential>;
    type DbSet<E> = Shared<Qmdb<E>>;
    type TestMerkleized =
        <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized;

    #[test]
    fn finalization_dispositions_preserve_winner_and_descendant_work() {
        let boundary = FinalizationBoundary {
            digest: 10,
            round: Round::new(Epoch::zero(), View::new(10)),
            processed_digest: 9,
            processed_round: Round::new(Epoch::zero(), View::new(9)),
            compatible: HashSet::from([10, 11]),
        };
        let progress = VerificationProgress::default();
        assert_eq!(boundary.disposition(&progress), Disposition::Retry,);

        progress.replaying(9, 8, Round::new(Epoch::zero(), View::new(9)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retry,);

        progress.replaying(10, 1, Round::new(Epoch::zero(), View::new(10)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retain,);
        progress.replaying(12, 11, Round::new(Epoch::zero(), View::new(11)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retain,);
        progress.replaying(20, 19, Round::new(Epoch::zero(), View::new(11)));
        assert_eq!(boundary.disposition(&progress), Disposition::Reject,);

        progress.verifying(9, 8, Round::new(Epoch::zero(), View::new(9)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retry,);
        progress.verifying(10, 1, Round::new(Epoch::zero(), View::new(10)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retry,);
        progress.verifying(12, 11, Round::new(Epoch::zero(), View::new(11)));
        assert_eq!(boundary.disposition(&progress), Disposition::Retain,);
        progress.verifying(20, 19, Round::new(Epoch::zero(), View::new(11)));
        assert_eq!(boundary.disposition(&progress), Disposition::Reject,);
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Block {
        context: TestContext,
        parent: Digest,
        height: Height,
        state_root: Digest,
        range: NonEmptyRange<Location>,
    }

    impl Write for Block {
        fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
            self.context.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.state_root.write(buf);
            self.range.write(buf);
        }
    }

    impl EncodeSize for Block {
        fn encode_size(&self) -> usize {
            self.context.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.state_root.encode_size()
                + self.range.encode_size()
        }
    }

    impl Read for Block {
        type Cfg = ();

        fn read_cfg(
            buf: &mut impl commonware_runtime::Buf,
            _: &Self::Cfg,
        ) -> Result<Self, CodecError> {
            Ok(Self {
                context: TestContext::read(buf)?,
                parent: Digest::read(buf)?,
                height: Height::read(buf)?,
                state_root: Digest::read(buf)?,
                range: commonware_utils::range::NonEmptyRange::read(buf)?,
            })
        }
    }

    impl Digestible for Block {
        type Digest = Digest;

        fn digest(&self) -> Digest {
            Sha256::hash(&[&self.encode()])
        }
    }

    impl Heightable for Block {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl ConsensusBlock for Block {
        fn parent(&self) -> Digest {
            self.parent
        }
    }

    impl CertifiableBlock for Block {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    impl Block {
        fn genesis() -> Self {
            Self {
                context: consensus_context(Digest::EMPTY, View::zero()),
                parent: Digest::EMPTY,
                height: Height::zero(),
                state_root: Digest::EMPTY,
                range: non_empty_range!(Location::new(0), Location::new(1)),
            }
        }
    }

    fn consensus_context(parent: Digest, view: View) -> TestContext {
        TestContext {
            round: Round::new(Epoch::zero(), view),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (
                if view.is_zero() {
                    View::zero()
                } else {
                    View::new(view.get() - 1)
                },
                parent,
            ),
        }
    }

    fn u64_to_digest(value: u64) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Digest::from(bytes)
    }

    fn digest_to_u64(value: &Digest) -> u64 {
        let bytes: &[u8] = value.as_ref();
        u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .expect("digest prefix should be 8 bytes"),
        )
    }

    fn height_key(height: Height) -> Digest {
        Sha256::hash(&[&height.get().to_be_bytes()])
    }

    fn counter_key() -> Digest {
        Sha256::hash(&[b"processor_harness_counter"])
    }

    struct ApplyGate {
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    }

    #[derive(Clone)]
    struct ApplicationProbe {
        target: Digest,
        calls: Arc<AtomicUsize>,
        gates: Arc<Mutex<VecDeque<ApplyGate>>>,
    }

    impl ApplicationProbe {
        fn new(target: Digest, gates: impl IntoIterator<Item = ApplyGate>) -> Self {
            Self {
                target,
                calls: Arc::new(AtomicUsize::new(0)),
                gates: Arc::new(Mutex::new(gates.into_iter().collect())),
            }
        }

        async fn call(&self, digest: Digest) {
            if digest != self.target {
                return;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let Some(mut gate) = self.gates.lock().pop_front() else {
                return;
            };
            gate.started.send(()).expect("test must await replay");
            let _ = (&mut gate.release).await;
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn apply_gate() -> (ApplyGate, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        (
            ApplyGate {
                started,
                release: release_rx,
            },
            started_rx,
            release,
        )
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CapturedArtifact {
        prior_counter: Option<u64>,
        batch_counter: u64,
        batch_height: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum FinalizedObservation {
        Applied {
            artifact: CapturedArtifact,
            post_counter: u64,
            post_height: u64,
        },
        Synchronized {
            post_counter: u64,
            post_height: u64,
        },
    }

    #[derive(Clone)]
    struct ExecutionApp {
        genesis: Block,
        finalized_observer: Option<Arc<Mutex<Vec<FinalizedObservation>>>>,
        apply_probe: Option<ApplicationProbe>,
        finalized_probe: Option<ApplicationProbe>,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
                finalized_observer: None,
                apply_probe: None,
                finalized_probe: None,
            }
        }

        fn with_finalized_observer() -> (Self, Arc<Mutex<Vec<FinalizedObservation>>>) {
            let observations = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    genesis: Block::genesis(),
                    finalized_observer: Some(observations.clone()),
                    apply_probe: None,
                    finalized_probe: None,
                },
                observations,
            )
        }

        async fn execute(
            height: Height,
            view: View,
            mut batches: <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized
        {
            let current_counter = batches
                .get(&counter_key())
                .await
                .expect("counter read should succeed")
                .map_or(0, |digest| digest_to_u64(&digest));
            batches = batches.write(counter_key(), Some(u64_to_digest(current_counter + 1)));
            batches = batches.write(height_key(height), Some(u64_to_digest(view.get())));
            batches.merkleize().await.expect("merkleize should succeed")
        }
    }

    impl Application<deterministic::Context> for ExecutionApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = Block;
        type Databases = DbSet<deterministic::Context>;
        type FinalizedArtifact = CapturedArtifact;
        type Provider = ();
        type Input = ();

        async fn genesis(&mut self) -> Self::Block {
            self.genesis.clone()
        }

        async fn propose(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            let mut ancestry = Box::pin(ancestry);
            let parent = ancestry.next().await?;
            let context = context.1.clone();
            let view = context.round.view();
            let height = parent.height().next();
            let merkleized = Self::execute(height, view, batches).await;
            let block = Block {
                context,
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            };
            Some(Proposed { block, merkleized })
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            let mut ancestry = Box::pin(ancestry);
            let block = ancestry.next().await?;
            let merkleized =
                Self::execute(block.height(), block.context.round.view(), batches).await;
            if merkleized.root() != block.state_root {
                return None;
            }
            Some(merkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            if let Some(probe) = &self.apply_probe {
                probe.call(block.digest()).await;
            }
            Self::execute(block.height(), block.context.round.view(), batches).await
        }

        async fn capture_finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: &TestMerkleized,
            readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) -> Self::FinalizedArtifact {
            let prior_counter = readers
                .read()
                .await
                .get(&counter_key())
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value));
            let pending = batches.new_batch();
            let batch_counter = pending
                .get(&counter_key())
                .await
                .expect("batch read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("winning batch should contain a counter");
            let batch_height = pending
                .get(&height_key(block.height()))
                .await
                .expect("batch read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("winning batch should contain its height");
            CapturedArtifact {
                prior_counter,
                batch_counter,
                batch_height,
            }
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            provenance: Finalized<Self::FinalizedArtifact>,
            readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
            if let Some(probe) = &self.finalized_probe {
                probe.call(block.digest()).await;
            }
            let Some(observer) = &self.finalized_observer else {
                return;
            };
            let db = readers.read().await;
            let post_height = db
                .get(&height_key(block.height()))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("finalized height should be reflected in the database set");
            let post_counter = db
                .get(&counter_key())
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("finalized counter should be reflected in the database set");
            drop(db);
            let observation = match provenance {
                Finalized::Applied(artifact) => FinalizedObservation::Applied {
                    artifact,
                    post_counter,
                    post_height,
                },
                Finalized::Synchronized => FinalizedObservation::Synchronized {
                    post_counter,
                    post_height,
                },
            };
            observer.lock().push(observation);
        }

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            Target::new(block.state_root, block.range.clone())
        }
    }

    #[derive(Clone, Default)]
    struct MapProvider {
        blocks: Arc<Mutex<BTreeMap<Digest, Block>>>,
        fetches: Arc<AtomicUsize>,
    }

    impl MapProvider {
        fn insert(&self, block: Block) {
            self.blocks.lock().insert(block.digest(), block);
        }

        fn fetch_by_digest(&self, digest: Digest) -> Option<Block> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.blocks.lock().get(&digest).cloned()
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl BlockProvider for MapProvider {
        type Block = Block;

        fn subscribe_parent(
            &self,
            block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let provider = self.clone();
            let parent = block.parent();
            async move { provider.fetch_by_digest(parent).map(Arc::new) }
        }
    }

    #[derive(Clone, Default)]
    struct ScriptedParentProvider {
        responses: Arc<Mutex<BTreeMap<Digest, VecDeque<Option<Block>>>>>,
        fetches: Arc<AtomicUsize>,
    }

    impl ScriptedParentProvider {
        fn push(&self, child: &Block, responses: impl IntoIterator<Item = Option<Block>>) {
            self.responses
                .lock()
                .insert(child.digest(), responses.into_iter().collect());
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl BlockProvider for ScriptedParentProvider {
        type Block = Block;

        fn subscribe_parent(
            &self,
            block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let provider = self.clone();
            let child = block.digest();
            async move {
                provider.fetches.fetch_add(1, Ordering::SeqCst);
                provider
                    .responses
                    .lock()
                    .get_mut(&child)
                    .and_then(VecDeque::pop_front)
                    .flatten()
                    .map(Arc::new)
            }
        }
    }

    struct Harness {
        context_cell: ContextCell<deterministic::Context>,
        processor: Processor<deterministic::Context, ExecutionApp>,
        provider: MapProvider,
        db_config: any::FixedConfig<TwoCap, Sequential>,
    }

    impl Harness {
        async fn new(context: deterministic::Context) -> Self {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix(), &context);
            Self::with_app(context, provider, config.clone(), ExecutionApp::new()).await
        }

        async fn new_with_finalized_observer(
            context: deterministic::Context,
        ) -> (Self, Arc<Mutex<Vec<FinalizedObservation>>>) {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix(), &context);
            let (app, observations) = ExecutionApp::with_finalized_observer();
            (
                Self::with_app(context, provider, config, app).await,
                observations,
            )
        }

        async fn with_app(
            context: deterministic::Context,
            provider: MapProvider,
            config: any::FixedConfig<TwoCap, Sequential>,
            app: ExecutionApp,
        ) -> Self {
            let databases = <DbSet<deterministic::Context> as DatabaseSet<
                deterministic::Context,
            >>::init(context.child("db_set"), config.clone())
            .await;
            let metrics = StatefulMetrics::new(&context);
            Self {
                context_cell: ContextCell::new(context),
                processor: Processor::new(
                    app,
                    databases,
                    Anchor {
                        height: Height::zero(),
                        round: Block::genesis().context().round,
                        digest: Block::genesis().digest(),
                    },
                    metrics,
                    None,
                ),
                provider,
                db_config: config,
            }
        }

        async fn build_child(&self, parent: &Block, view: View) -> (Block, TestMerkleized) {
            let context = consensus_context(parent.digest(), view);
            let height = Height::new(parent.height().get() + 1);
            let batches = self
                .processor
                .fork_batches(&parent.digest())
                .await
                .expect("parent should be available");
            let merkleized = ExecutionApp::execute(height, view, batches).await;
            let block = Block {
                context,
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            };
            (block, merkleized)
        }

        async fn stage_pending_child(&mut self, parent: &Block, view: View) -> Block {
            let (block, merkleized) = self.build_child(parent, view).await;
            let round = Round::new(Epoch::zero(), view);
            assert!(self.processor.cache_pending(
                block.digest(),
                parent.digest(),
                round,
                merkleized
            ));
            self.provider.insert(block.clone());
            block
        }

        /// Finalize `block` and wait for its database sync.
        /// Returns whether the block was newly applied (`false` for a
        /// duplicate report).
        #[boxed]
        async fn finalize(&mut self, block: Block) -> bool {
            let Some(Applied { barrier, .. }) = self
                .processor
                .finalize(self.context_cell.as_present(), &block, true)
                .await
            else {
                return false;
            };
            assert_durable(barrier).await;
            true
        }

        #[boxed]
        async fn finalize_with_prune(
            &mut self,
            block: Block,
        ) -> Option<
            Prune<
                <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::SyncTargets,
            >,
        > {
            let Applied { barrier, prune } = self
                .processor
                .finalize(self.context_cell.as_present(), &block, true)
                .await
                .expect("finalized block must apply");
            assert_durable(barrier).await;
            prune
        }

        async fn height_value(&self, height: Height) -> Option<u64> {
            let db = self.processor.databases().read().await;
            db.get(&height_key(height))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn counter_value(&self) -> Option<u64> {
            let db = self.processor.databases().read().await;
            db.get(&counter_key())
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn reopen_height_value(
            &self,
            context: deterministic::Context,
            height: Height,
        ) -> Option<u64> {
            let reopened: Qmdb<deterministic::Context> =
                Qmdb::init(context.child("reopen_db"), self.db_config.clone())
                    .await
                    .expect("database reopen should succeed");
            reopened
                .get(&height_key(height))
                .await
                .expect("reopened db read should succeed")
                .map(|value| digest_to_u64(&value))
        }
    }

    fn next_partition_prefix() -> String {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        format!("processor_harness_{id}")
    }

    fn qmdb_config(
        prefix: &str,
        context: &deterministic::Context,
    ) -> any::FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        any::FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{prefix}_mmr_journal"),
                metadata_partition: format!("{prefix}_mmr_metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: IO_BUFFER_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{prefix}_log_journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: IO_BUFFER_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    #[test]
    fn pruning_waits_for_full_retention_window() {
        let config = PruneConfig {
            maintenance_interval: NZUsize!(1),
            retained_marshal_blocks: 1,
            retained_qmdb_blocks: 1,
        };
        let mut pruning = Pruning::build(config, 2, 0);

        assert_eq!(pruning.observe_finalized(Height::new(1), 10_u64), None,);
        assert_eq!(pruning.observe_finalized(Height::new(2), 20_u64), None,);
        assert_eq!(pruning.observe_finalized(Height::new(3), 30_u64), None,);
        assert_eq!(
            pruning.observe_finalized(Height::new(4), 40_u64),
            Some(Prune {
                marshal_height: Height::new(1),
                barrier_height: Height::new(1),
                qmdb_target: 10,
            }),
        );
    }

    #[test]
    fn pruning_uses_oldest_retained_target() {
        let config = PruneConfig {
            maintenance_interval: NZUsize!(1),
            retained_marshal_blocks: 1,
            retained_qmdb_blocks: 1,
        };
        let mut pruning = Pruning::build(config, 1, 0);

        assert_eq!(pruning.observe_finalized(Height::new(1), 10_u64), None,);
        assert_eq!(pruning.observe_finalized(Height::new(2), 20_u64), None,);
        assert_eq!(
            pruning.observe_finalized(Height::new(3), 30_u64),
            Some(Prune {
                marshal_height: Height::new(1),
                barrier_height: Height::new(1),
                qmdb_target: 10,
            }),
        );
        assert_eq!(
            pruning.observe_finalized(Height::new(4), 40_u64),
            Some(Prune {
                marshal_height: Height::new(2),
                barrier_height: Height::new(2),
                qmdb_target: 20,
            }),
        );
    }

    #[test]
    fn pruning_can_retain_more_marshal_history_than_qmdb() {
        let config = PruneConfig {
            maintenance_interval: NZUsize!(3),
            retained_marshal_blocks: 3,
            retained_qmdb_blocks: 1,
        };
        let mut pruning = Pruning::build(config, 1, 0);

        assert_eq!(pruning.observe_finalized(Height::new(1), 10_u64), None);
        assert_eq!(pruning.observe_finalized(Height::new(2), 20_u64), None);
        assert_eq!(pruning.observe_finalized(Height::new(3), 30_u64), None);
        assert_eq!(pruning.observe_finalized(Height::new(4), 40_u64), None);
        assert_eq!(pruning.observe_finalized(Height::new(5), 50_u64), None);
        assert_eq!(
            pruning.observe_finalized(Height::new(6), 60_u64),
            Some(Prune {
                marshal_height: Height::new(2),
                barrier_height: Height::new(4),
                qmdb_target: 40,
            }),
        );
    }

    #[test]
    fn pruning_uses_maintenance_phase() {
        let config = PruneConfig {
            maintenance_interval: NZUsize!(5),
            retained_marshal_blocks: 1,
            retained_qmdb_blocks: 0,
        };
        let mut pruning = Pruning::build(config, 1, 2);

        for height in 1..=6 {
            assert_eq!(
                pruning.observe_finalized(Height::new(height), height * 10),
                None,
            );
        }
        assert_eq!(
            pruning.observe_finalized(Height::new(7), 70),
            Some(Prune {
                marshal_height: Height::new(5),
                barrier_height: Height::new(6),
                qmdb_target: 60,
            }),
        );
        for height in 8..=11 {
            assert_eq!(
                pruning.observe_finalized(Height::new(height), height * 10),
                None,
            );
        }
        assert_eq!(
            pruning.observe_finalized(Height::new(12), 120),
            Some(Prune {
                marshal_height: Height::new(10),
                barrier_height: Height::new(11),
                qmdb_target: 110,
            }),
        );
    }

    #[test]
    #[should_panic(expected = "marshal must retain at least as many blocks as QMDB")]
    fn prune_config_rejects_less_marshal_retention_than_qmdb() {
        PruneConfig {
            maintenance_interval: NZUsize!(1),
            retained_marshal_blocks: 1,
            retained_qmdb_blocks: 2,
        }
        .assert_valid();
    }

    #[test]
    fn prune_config_accepts_zero_retention() {
        PruneConfig {
            maintenance_interval: NZUsize!(1),
            retained_marshal_blocks: 0,
            retained_qmdb_blocks: 0,
        }
        .assert_valid();
    }

    #[test]
    fn execution_finalization_returns_deferred_prune() {
        deterministic::Runner::default().start(|context| async move {
            let provider = MapProvider::default();
            let config = qmdb_config("db_config", &context);
            let app = ExecutionApp::new();
            let mut harness = Harness::with_app(context, provider, config, app).await;
            harness.processor = Processor::new(
                ExecutionApp::new(),
                harness.processor.databases().clone(),
                Anchor {
                    height: Height::zero(),
                    round: Block::genesis().context().round,
                    digest: Block::genesis().digest(),
                },
                StatefulMetrics::new(harness.context_cell.as_present()),
                Some(Pruning::build(
                    PruneConfig {
                        maintenance_interval: NZUsize!(1),
                        retained_marshal_blocks: 1,
                        retained_qmdb_blocks: 1,
                    },
                    1,
                    0,
                )),
            );

            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            let prune = harness.finalize_with_prune(block1).await;
            assert_eq!(
                prune, None,
                "pruning should wait for the full retention window",
            );
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;

            assert!(harness.processor.pending_contains(&winner.digest()));
            assert!(harness.processor.pending_contains(&loser.digest()));

            assert!(
                harness.finalize(winner.clone()).await,
                "finalization should persist winner state",
            );
            assert!(
                !harness.processor.pending_contains(&loser.digest()),
                "losing fork at finalized round should be pruned",
            );
            assert_eq!(harness.processor.last_processed().digest, winner.digest());
            assert_eq!(harness.height_value(Height::new(2)).await, Some(3));
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork_descendants() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let loser_child = harness.stage_pending_child(&loser, View::new(4)).await;

            assert!(harness.processor.pending_contains(&winner.digest()));
            assert!(harness.processor.pending_contains(&loser.digest()));
            assert!(harness.processor.pending_contains(&loser_child.digest()));

            assert!(
                harness.finalize(winner.clone()).await,
                "finalization should persist winner state",
            );
            assert!(
                !harness.processor.pending_contains(&loser.digest()),
                "losing fork at finalized round should be pruned",
            );
            assert!(
                !harness.processor.pending_contains(&loser_child.digest()),
                "descendants of the losing fork should also be pruned",
            );
        });
    }

    #[test]
    fn execution_finalization_prunes_before_finalized_hook_completes() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let winner_child = harness.stage_pending_child(&winner, View::new(4)).await;
            let (gate, started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let execution = harness.processor.execution.clone();

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            started.await.expect("finalized hook should start");

            assert!(execution.pending_contains(&winner_child.digest()));
            assert!(!execution.pending_contains(&block1.digest()));
            assert!(!execution.pending_contains(&loser.digest()));

            release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn execution_forks_from_finalizing_winner_before_database_apply() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;
            let databases = harness.processor.databases().clone();
            let read = databases.read().await;
            let execution = harness.processor.execution.clone();

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());

            let winner_digest = winner.digest();
            let mut fork = Box::pin(execution.fork_batches(&winner_digest));
            let forked = match futures::poll!(&mut fork) {
                std::task::Poll::Ready(forked) => forked,
                std::task::Poll::Pending => {
                    panic!("finalizing winner should remain available for child batches")
                }
            };
            assert!(forked.is_ok(), "finalizing winner should remain forkable");

            drop(read);
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn execution_late_winner_publication_is_a_noop() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let view = View::new(1);
            let round = Round::new(Epoch::zero(), view);
            let (winner, initial_batch) = harness.build_child(&genesis, view).await;
            let (_, during_finalization_batch) = harness.build_child(&genesis, view).await;
            let (_, after_finalization_batch) = harness.build_child(&genesis, view).await;
            assert!(harness.processor.cache_pending(
                winner.digest(),
                genesis.digest(),
                round,
                initial_batch,
            ));

            let (gate, started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let execution = harness.processor.execution.clone();
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            started.await.expect("finalized hook should start");

            assert!(execution.cache_pending(
                winner.digest(),
                genesis.digest(),
                round,
                during_finalization_batch,
            ));
            assert!(!execution.pending_contains(&winner.digest()));

            release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;

            assert!(execution.cache_pending(
                winner.digest(),
                genesis.digest(),
                round,
                after_finalization_batch,
            ));
            assert!(!execution.pending_contains(&winner.digest()));
        });
    }

    #[test]
    fn execution_descendant_replay_survives_finalized_parent_removal() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let parent = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (child, _) = harness.build_child(&parent, View::new(2)).await;

            let (owner_gate, owner_started, mut owner_release) = apply_gate();
            let (retry_gate, retry_started, retry_release) = apply_gate();
            harness.processor.app.apply_probe = Some(ApplicationProbe::new(
                child.digest(),
                [owner_gate, retry_gate],
            ));
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(parent.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();
            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();
            let owner_progress = VerificationProgress::default();
            let waiter_progress = VerificationProgress::default();
            let (mut owner_cancellation, owner_alive) = oneshot::channel::<()>();
            let (mut waiter_cancellation, _waiter_alive) = oneshot::channel::<()>();

            let mut owner = Box::pin(execution.replay_block_shared(
                &mut owner_app,
                replay_context,
                child.digest(),
                Arc::new(child.clone()),
                &mut owner_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &owner_progress,
                },
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            owner_started.await.expect("replay owner should start");

            let mut waiter = Box::pin(execution.replay_block_shared(
                &mut waiter_app,
                replay_context,
                child.digest(),
                Arc::new(child.clone()),
                &mut waiter_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &waiter_progress,
                },
            ));
            assert!(futures::poll!(&mut waiter).is_pending());
            let boundary = harness.processor.finalization_boundary(&parent);
            assert_eq!(boundary.disposition(&owner_progress), Disposition::Retain,);
            assert_eq!(boundary.disposition(&waiter_progress), Disposition::Retain,);

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &parent,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            finalized_started
                .await
                .expect("finalized hook should start");

            drop(owner_alive);
            assert_eq!(owner.await, Err(PrepareBatchesError::Cancelled));
            owner_release.closed().await;

            select! {
                result = &mut waiter => {
                    panic!("retained replay failed after owner cancellation: {result:?}");
                },
                result = retry_started => {
                    result.expect("retained replay should restart from finalized state");
                },
            }
            retry_release
                .send(())
                .expect("retried replay should remain active");
            assert_eq!(waiter.await, Ok(()));

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn finalized_reader_preserves_retained_replay_base() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut harness, observations) = Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let parent = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (child, _) = harness.build_child(&parent, View::new(2)).await;

            let (owner_gate, owner_started, mut owner_release) = apply_gate();
            let (retry_gate, retry_started, retry_release) = apply_gate();
            harness.processor.app.apply_probe = Some(ApplicationProbe::new(
                child.digest(),
                [owner_gate, retry_gate],
            ));
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(parent.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();
            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();
            let owner_progress = VerificationProgress::default();
            let waiter_progress = VerificationProgress::default();
            let (mut owner_cancellation, owner_alive) = oneshot::channel::<()>();
            let (mut waiter_cancellation, _waiter_alive) = oneshot::channel::<()>();

            let mut owner = Box::pin(execution.replay_block_shared(
                &mut owner_app,
                replay_context,
                child.digest(),
                Arc::new(child.clone()),
                &mut owner_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &owner_progress,
                },
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            owner_started.await.expect("replay owner should start");

            let mut waiter = Box::pin(execution.replay_block_shared(
                &mut waiter_app,
                replay_context,
                child.digest(),
                Arc::new(child),
                &mut waiter_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &waiter_progress,
                },
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &parent,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            finalized_started
                .await
                .expect("finalized hook should start");

            drop(owner_alive);
            assert_eq!(owner.await, Err(PrepareBatchesError::Cancelled));
            owner_release.closed().await;
            select! {
                result = &mut waiter => {
                    panic!("retained replay failed after owner cancellation: {result:?}");
                },
                result = retry_started => {
                    result.expect("retained replay should restart from finalized state");
                },
            }

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
            assert!(matches!(
                observations.lock().as_slice(),
                [FinalizedObservation::Applied { post_height: 1, .. }]
            ));

            retry_release
                .send(())
                .expect("retried replay should remain active");
            assert_eq!(waiter.await, Ok(()));
        });
    }

    #[test]
    fn execution_finalize_self_applies_after_cancelled_winner_replay() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;

            let (owner_gate, owner_started, mut owner_release) = apply_gate();
            let probe = ApplicationProbe::new(winner.digest(), [owner_gate]);
            harness.processor.app.apply_probe = Some(probe.clone());

            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();
            let mut owner_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();
            let (mut owner_cancellation, owner_alive) = oneshot::channel::<()>();
            let owner_progress = VerificationProgress::default();

            let mut owner = Box::pin(execution.replay_block_shared(
                &mut owner_app,
                replay_context,
                winner.digest(),
                Arc::new(winner.clone()),
                &mut owner_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &owner_progress,
                },
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            owner_started.await.expect("winner replay should start");

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(
                futures::poll!(&mut finalize).is_pending(),
                "finalization should wait on the active winner replay",
            );

            drop(owner_alive);
            assert_eq!(owner.await, Err(PrepareBatchesError::Cancelled));
            owner_release.closed().await;

            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
            assert_eq!(
                probe.calls(),
                2,
                "finalization must reconstruct the winner after the owner cancels",
            );
            assert_eq!(harness.processor.last_processed().digest, winner.digest());
            assert!(harness.processor.replays_idle());
        });
    }

    #[test]
    fn execution_replay_waiter_recovers_from_invalid_finalizing_winner() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;
            let probe = ApplicationProbe::new(winner.digest(), std::iter::empty());
            harness.processor.app.apply_probe = Some(probe.clone());

            let owner = match harness
                .processor
                .execution
                .claim_replay(&harness.processor.replays, winner.digest())
            {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("winner replay claim should own the flight"),
            };

            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();
            let waiter_progress = VerificationProgress::default();
            let (mut waiter_cancellation, _waiter_alive) = oneshot::channel::<()>();
            let mut waiter = Box::pin(execution.replay_block_shared(
                &mut waiter_app,
                replay_context,
                winner.digest(),
                Arc::new(winner.clone()),
                &mut waiter_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &waiter_progress,
                },
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(
                futures::poll!(&mut finalize).is_pending(),
                "finalization should wait on the active winner replay",
            );

            owner.finish(Err(PrepareBatchesError::Invalid));
            assert_eq!(
                waiter.await,
                Ok(()),
                "retained waiter should join recovery of the finalizing winner",
            );
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
            assert_eq!(probe.calls(), 1, "winner should be reconstructed once");
            assert_eq!(harness.processor.last_processed().digest, winner.digest());
            assert!(harness.processor.replays_idle());
        });
    }

    #[test]
    fn execution_finalization_waits_for_active_cached_winner_replay() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, merkleized) = harness.build_child(&genesis, View::new(1)).await;

            let owner = match harness
                .processor
                .execution
                .claim_replay(&harness.processor.replays, winner.digest())
            {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("winner replay should own the flight"),
            };
            assert!(harness.processor.cache_pending(
                winner.digest(),
                genesis.digest(),
                winner.context().round,
                merkleized,
            ));

            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));

            select! {
                _ = &mut finalize => {
                    panic!("finalization bypassed active winner replay");
                },
                result = &mut started => {
                    result.expect("finalized hook should remain reachable");
                    panic!("finalization reached the application hook before replay completed");
                },
                _ = harness.context_cell.as_present().sleep(Duration::from_millis(10)) => {},
            }

            owner.finish(Ok(()));
            select! {
                result = &mut started => {
                    result.expect("finalized hook should start after replay completes");
                },
                _ = &mut finalize => {
                    panic!("finalization completed before its application hook");
                },
            }
            release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn execution_replay_waiter_reuses_retained_finalizing_winner() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;

            let (replay_gate, replay_started, replay_release) = apply_gate();
            let probe = ApplicationProbe::new(winner.digest(), [replay_gate]);
            harness.processor.app.apply_probe = Some(probe.clone());
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();
            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();
            let owner_progress = VerificationProgress::default();
            let waiter_progress = VerificationProgress::default();
            let (mut owner_cancellation, _owner_alive) = oneshot::channel::<()>();
            let (mut waiter_cancellation, _waiter_alive) = oneshot::channel::<()>();

            let mut owner = Box::pin(execution.replay_block_shared(
                &mut owner_app,
                replay_context,
                winner.digest(),
                Arc::new(winner.clone()),
                &mut owner_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &owner_progress,
                },
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            replay_started.await.expect("winner replay should start");

            let mut waiter = Box::pin(execution.replay_block_shared(
                &mut waiter_app,
                replay_context,
                winner.digest(),
                Arc::new(winner.clone()),
                &mut waiter_cancellation,
                ReplayTracking {
                    flights: &replays,
                    progress: &waiter_progress,
                },
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());

            replay_release
                .send(())
                .expect("winner replay should remain active");
            assert_eq!(owner.await, Ok(()));
            select! {
                result = finalized_started => {
                    result.expect("finalized hook should start");
                },
                _ = &mut finalize => {
                    panic!("finalization completed before its application hook");
                },
            }

            assert_eq!(
                waiter.await,
                Ok(()),
                "waiter should reuse the retained winner batch",
            );
            assert_eq!(probe.calls(), 1, "winner should be reconstructed once");

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize
                .await
                .expect("finalized block should be newly applied");
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn execution_finalization_reserves_missing_winner_reconstruction() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;
            let execution = harness.processor.execution.clone();
            let replays = harness.processor.replays.clone();

            execution.begin_finalization(Anchor::from(&winner));
            let finalization = execution.claim_finalization_batch(&replays, winner.digest());
            assert!(
                matches!(
                    execution.claim_replay(&replays, winner.digest()),
                    ReplayClaim::Wait(_),
                ),
                "missing winner reconstruction must remain single-flight",
            );
            drop(finalization);
        });
    }

    #[test]
    fn execution_rejects_late_losing_fork_publication() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let late_view = View::new(4);
            let (late_child, merkleized) = harness.build_child(&loser, late_view).await;

            assert!(harness.finalize(winner).await);
            assert!(
                !harness.processor.cache_pending(
                    late_child.digest(),
                    loser.digest(),
                    Round::new(Epoch::zero(), late_view),
                    merkleized,
                ),
                "completed work on a losing fork must not publish after finalization",
            );
            assert!(!harness.processor.pending_contains(&late_child.digest()));
        });
    }

    #[test]
    fn execution_rebuild_pending_restores_missing_chain() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
            harness.processor.clear_pending();
            harness.provider.insert(block2.clone());
            harness.provider.insert(block3.clone());

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    harness.provider.clone(),
                    Arc::new(block3.clone()),
                    &mut response,
                )
                .await;
            assert_eq!(result, Ok(()), "rebuild should succeed");
            assert!(
                harness.processor.pending_contains(&block2.digest()),
                "first missing descendant should be reconstructed",
            );
            assert!(
                harness.processor.pending_contains(&block3.digest()),
                "target block should be reconstructed",
            );
        });
    }

    #[test]
    fn execution_fork_batches_rejects_unknown_parent() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            assert!(matches!(
                harness.processor.fork_batches(&u64_to_digest(999)).await,
                Err(PrepareBatchesError::Invalid),
            ));
        });
    }

    #[test]
    fn dropped_replay_waiter_releases_registration() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let replays = ReplayFlights::default();
            let digest = u64_to_digest(999);

            assert!(matches!(
                harness
                    .processor
                    .execution
                    .claim_replay(&replays, harness.processor.last_processed().digest),
                ReplayClaim::Ready,
            ));
            assert!(replays.is_empty());

            let owner = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("first replay claim should own the flight"),
            };
            let first = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            let second = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            assert_eq!((first.slot, second.slot), (0, 1));

            drop(first);
            assert!(
                replays.entries.lock().get(&digest).is_some_and(|flight| {
                    let waiters = &flight.waiters;
                    waiters.len() == 2 && waiters[0].is_none() && waiters[1].is_some()
                }),
                "dropping a non-tail waiter must release its slot",
            );
            let replacement = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            assert_eq!(replacement.slot, 0);
            assert!(
                replays
                    .entries
                    .lock()
                    .get(&digest)
                    .is_some_and(|flight| flight.waiters.len() == 2
                        && flight.waiters.iter().all(Option::is_some)),
                "replacement waiter must reuse the released slot",
            );

            drop(second);
            drop(replacement);
            assert!(
                replays
                    .entries
                    .lock()
                    .get(&digest)
                    .is_some_and(|flight| flight.waiters.iter().all(Option::is_none)
                        && flight.vacant_slots.len() == 2),
                "dropped replay waiters must leave reusable vacant slots",
            );
            drop(owner);
            assert!(replays.is_empty());
        });
    }

    #[test]
    fn replay_waiter_reuses_most_recent_vacant_slot() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let replays = ReplayFlights::default();
            let digest = u64_to_digest(999);

            let owner = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("first replay claim should own the flight"),
            };
            let first = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            let second = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            let third = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            assert_eq!((first.slot, second.slot, third.slot), (0, 1, 2));

            drop(first);
            drop(third);
            let replacement = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            assert_eq!(replacement.slot, 2);

            drop(second);
            drop(replacement);
            drop(owner);
            assert!(replays.is_empty());
        });
    }

    #[test]
    fn stale_replay_waiter_does_not_clear_new_flight() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let replays = ReplayFlights::default();
            let digest = u64_to_digest(999);

            let first_owner = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("first replay claim should own the flight"),
            };
            let stale_waiter = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Wait(waiter) => waiter,
                _ => panic!("duplicate replay claim should wait for the owner"),
            };
            drop(first_owner);

            let second_owner = match harness.processor.execution.claim_replay(&replays, digest) {
                ReplayClaim::Owner(owner) => owner,
                _ => panic!("new replay claim should own the replacement flight"),
            };
            let mut current_waiter =
                match harness.processor.execution.claim_replay(&replays, digest) {
                    ReplayClaim::Wait(waiter) => waiter,
                    _ => panic!("duplicate replay claim should wait for the replacement owner"),
                };

            drop(stale_waiter);
            assert!(
                futures::poll!(&mut current_waiter.completion).is_pending(),
                "stale waiter cleanup must not unregister a newer flight's waiter",
            );

            drop(current_waiter);
            drop(second_owner);
            assert!(replays.is_empty());
        });
    }

    #[test]
    fn overlapping_rebuilds_share_replay_after_owner_cancellation() {
        deterministic::Runner::timed(std::time::Duration::from_secs(5)).start(
            |context| async move {
                let mut harness = Harness::new(context.child("harness")).await;
                let genesis = Block::genesis();
                let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
                let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
                let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
                harness.processor.clear_pending();
                harness.provider.insert(genesis);

                let (first_gate, first_started, mut first_release) = apply_gate();
                let (retry_gate, retry_started, retry_release) = apply_gate();
                let (duplicate_gate, mut duplicate_started, _duplicate_release) = apply_gate();
                let probe = ApplicationProbe::new(
                    block1.digest(),
                    [first_gate, retry_gate, duplicate_gate],
                );
                harness.processor.app.apply_probe = Some(probe.clone());

                let first_execution = harness.processor.execution.clone();
                let second_execution = harness.processor.execution.clone();
                let third_execution = harness.processor.execution.clone();
                let fourth_execution = harness.processor.execution.clone();
                let mut first_app = harness.processor.app.clone();
                let mut second_app = harness.processor.app.clone();
                let mut third_app = harness.processor.app.clone();
                let mut fourth_app = harness.processor.app.clone();
                let first_provider = harness.provider.clone();
                let second_provider = harness.provider.clone();
                let third_provider = harness.provider.clone();
                let fourth_provider = harness.provider.clone();
                let first_replays = harness.processor.replays.clone();
                let second_replays = harness.processor.replays.clone();
                let third_replays = harness.processor.replays.clone();
                let fourth_replays = harness.processor.replays.clone();
                let (mut first_cancellation, first_live) = oneshot::channel::<bool>();
                let (mut second_cancellation, second_live) = oneshot::channel::<bool>();
                let (mut third_cancellation, third_live) = oneshot::channel::<bool>();
                let (mut fourth_cancellation, fourth_live) = oneshot::channel::<bool>();
                let first_progress = VerificationProgress::default();
                let second_progress = VerificationProgress::default();
                let third_progress = VerificationProgress::default();
                let fourth_progress = VerificationProgress::default();

                let mut first = Box::pin(first_execution.rebuild_pending(
                    &mut first_app,
                    &context,
                    first_provider,
                    Arc::new(block2.clone()),
                    &mut first_cancellation,
                    Some(ReplayTracking {
                        flights: &first_replays,
                        progress: &first_progress,
                    }),
                ));
                select! {
                    result = &mut first => panic!("first rebuild completed before replay gate: {result:?}"),
                    result = first_started => result.expect("first replay should start"),
                }

                let mut second = Box::pin(second_execution.rebuild_pending(
                    &mut second_app,
                    &context,
                    second_provider,
                    Arc::new(block2.clone()),
                    &mut second_cancellation,
                    Some(ReplayTracking {
                        flights: &second_replays,
                        progress: &second_progress,
                    }),
                ));
                let mut third = Box::pin(third_execution.rebuild_pending(
                    &mut third_app,
                    &context,
                    third_provider,
                    Arc::new(block3),
                    &mut third_cancellation,
                    Some(ReplayTracking {
                        flights: &third_replays,
                        progress: &third_progress,
                    }),
                ));
                let mut fourth = Box::pin(fourth_execution.rebuild_pending(
                    &mut fourth_app,
                    &context,
                    fourth_provider,
                    Arc::new(block2),
                    &mut fourth_cancellation,
                    Some(ReplayTracking {
                        flights: &fourth_replays,
                        progress: &fourth_progress,
                    }),
                ));
                let mut waiters_registered = false;
                for _ in 0..100 {
                    waiters_registered = harness
                        .processor
                        .replays
                        .entries
                        .lock()
                        .get(&block1.digest())
                        .is_some_and(|flight| flight.waiters.len() == 3);
                    if waiters_registered {
                        break;
                    }
                    select! {
                        result = &mut first => panic!("first rebuild completed before cancellation: {result:?}"),
                        result = &mut second => panic!("second rebuild completed before cancellation: {result:?}"),
                        result = &mut third => panic!("third rebuild completed before cancellation: {result:?}"),
                        result = &mut fourth => panic!("fourth rebuild completed before cancellation: {result:?}"),
                        result = &mut duplicate_started => {
                            result.expect("duplicate replay signal should remain available");
                            panic!("overlapping rebuilds executed the same ancestor concurrently");
                        },
                        _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                    }
                }
                assert!(
                    waiters_registered,
                    "overlapping replays should wait for the current owner"
                );
                assert_eq!(probe.calls(), 1);

                drop(fourth_live);
                let fourth_result = select! {
                    result = &mut fourth => result,
                    result = &mut first => panic!("owner completed while cancelling waiter: {result:?}"),
                    result = &mut second => panic!("live waiter completed while cancelling peer: {result:?}"),
                    result = &mut third => panic!("live waiter completed while cancelling peer: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_secs(1)) => {
                        panic!("cancelled replay waiter did not stop");
                    },
                };
                assert_eq!(fourth_result, Err(PrepareBatchesError::Cancelled));
                assert!(
                    harness
                        .processor
                        .replays
                        .entries
                        .lock()
                        .get(&block1.digest())
                        .is_some_and(|flight| {
                            flight.waiters.iter().flatten().count() == 2
                                && flight.vacant_slots.len() == 1
                        }),
                    "cancelled waiter must unregister while the owner remains active",
                );

                drop(first_live);
                let first_result = select! {
                    result = &mut first => result,
                    result = &mut second => panic!("waiter completed before owner cancellation: {result:?}"),
                    result = &mut third => panic!("waiter completed before owner cancellation: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_secs(1)) => {
                        panic!("cancelled replay owner did not stop");
                    },
                };
                assert_eq!(first_result, Err(PrepareBatchesError::Cancelled));
                first_release.closed().await;
                select! {
                    result = &mut second => panic!("waiter completed before retry gate: {result:?}"),
                    result = &mut third => panic!("waiter completed before retry gate: {result:?}"),
                    result = retry_started => result.expect("live waiter should acquire replay ownership"),
                    result = &mut duplicate_started => {
                        result.expect("duplicate replay signal should remain available");
                        panic!("multiple waiters acquired replay ownership");
                    },
                    _ = context.sleep(std::time::Duration::from_secs(1)) => {
                        panic!("live waiter did not retry cancelled replay");
                    },
                }

                retry_release
                    .send(())
                    .expect("retried replay should still be running");
                let completed = futures::future::join(second, third);
                let (second_result, third_result) = select! {
                    result = &mut duplicate_started => {
                        result.expect("duplicate replay signal should remain available");
                        panic!("successful replay was not shared with every waiter");
                    },
                    result = completed => result,
                    _ = context.sleep(std::time::Duration::from_secs(1)) => {
                        panic!("waiting rebuilds did not complete");
                    },
                };
                assert_eq!(second_result, Ok(()));
                assert_eq!(third_result, Ok(()));
                assert_eq!(probe.calls(), 2);
                assert!(harness.processor.replays_idle());
                drop((second_live, third_live));
            },
        );
    }

    #[test]
    fn execution_rebuild_pending_rejects_stale_ancestor_quickly() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let mut chain = Vec::new();
            let mut parent = genesis;
            for view in 1..=5 {
                let block = harness.stage_pending_child(&parent, View::new(view)).await;
                assert!(harness.finalize(block.clone()).await);
                parent = block.clone();
                chain.push(block);
            }

            harness.processor.clear_pending();
            let stale = chain[1].clone(); // height 2, below processed height 5
            let fetches_before = harness.provider.fetches();

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    harness.provider.clone(),
                    Arc::new(stale),
                    &mut response,
                )
                .await;
            assert_eq!(
                result,
                Err(PrepareBatchesError::Invalid),
                "stale ancestry should be rejected",
            );

            let fetches_after = harness.provider.fetches();
            assert_eq!(
                fetches_after.saturating_sub(fetches_before),
                0,
                "stale ancestry should be rejected before fetching its parent",
            );
        });
    }

    #[test]
    fn execution_rebuild_pending_rejects_sync_target_mismatch_before_caching() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let mut block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            harness.processor.clear_pending();

            block2.range = non_empty_range!(Location::new(1), Location::new(2));
            harness.provider.insert(block2.clone());

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    harness.provider.clone(),
                    Arc::new(block2.clone()),
                    &mut response,
                )
                .await;
            assert_eq!(
                result,
                Err(PrepareBatchesError::Invalid),
                "rebuild should reject a replayed batch whose sync target does not match the block",
            );
            assert!(
                !harness.processor.pending_contains(&block2.digest()),
                "rejected replay must not be inserted into the pending cache",
            );
        });
    }

    #[test]
    fn execution_rebuild_pending_rejects_height_gap_to_processed_anchor() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();

            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let gap_height = Height::new(3);
            let gap_view = View::new(3);
            let batches = harness
                .processor
                .fork_batches(&block1.digest())
                .await
                .expect("processed anchor should be available");
            let merkleized = ExecutionApp::execute(gap_height, gap_view, batches).await;
            let gap_block = Block {
                context: consensus_context(block1.digest(), gap_view),
                parent: block1.digest(),
                height: gap_height,
                state_root: merkleized.root(),
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            };

            let provider = ScriptedParentProvider::default();
            provider.push(&gap_block, [Some(block1)]);

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    provider,
                    Arc::new(gap_block.clone()),
                    &mut response,
                )
                .await;

            assert_eq!(
                result,
                Err(PrepareBatchesError::Invalid),
                "rebuild must reject non-contiguous ancestry above the processed anchor",
            );
            assert!(
                !harness.processor.pending_contains(&gap_block.digest()),
                "height-gap block must not be cached as pending",
            );
        });
    }

    #[test]
    fn execution_rebuild_pending_rejects_wrong_parent_digest() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
            let mut wrong_parent = block2;
            wrong_parent.state_root = u64_to_digest(999);
            assert_ne!(wrong_parent.digest(), block3.parent());
            harness.processor.clear_pending();

            let provider = ScriptedParentProvider::default();
            provider.push(&block3, [Some(wrong_parent)]);
            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    provider.clone(),
                    Arc::new(block3.clone()),
                    &mut response,
                )
                .await;

            assert_eq!(result, Err(PrepareBatchesError::Invalid));
            assert_eq!(provider.fetches(), 1);
            assert!(!harness.processor.pending_contains(&block3.digest()));
        });
    }

    #[test]
    #[should_panic(expected = "received conflicting finalized block at processed height")]
    fn execution_finalize_panics_on_conflicting_duplicate_height() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let canonical = harness.stage_pending_child(&genesis, View::new(1)).await;
            let conflicting = harness.stage_pending_child(&genesis, View::new(2)).await;

            assert!(harness.finalize(canonical).await);

            let _ = harness.finalize(conflicting).await;
        });
    }

    #[test]
    fn execution_finalize_identical_duplicate_returns_false() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let canonical = harness.stage_pending_child(&genesis, View::new(1)).await;

            assert!(harness.finalize(canonical.clone()).await);
            assert!(!harness.finalize(canonical).await);
            assert_eq!(harness.counter_value().await, Some(1));
        });
    }

    #[test]
    fn execution_finalization_persists_state_to_db() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            assert!(harness.finalize(block1).await);
            assert_eq!(harness.counter_value().await, Some(1));
            assert_eq!(
                harness
                    .reopen_height_value(context.child("reopen"), Height::new(1))
                    .await,
                Some(1),
                "height state should survive reopen after finalization",
            );
        });
    }

    #[test]
    fn execution_finalized_handoff_preserves_cached_and_reconstructed_artifacts() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, observations) =
                Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;

            assert!(harness.finalize(block1).await);
            harness.processor.clear_pending();
            let probe = ApplicationProbe::new(block2.digest(), []);
            harness.processor.app.apply_probe = Some(probe.clone());
            assert!(harness.finalize(block2).await);
            assert_eq!(
                probe.calls(),
                1,
                "block2 should be reconstructed through Application::apply",
            );

            assert_eq!(
                observations.lock().as_slice(),
                [
                    FinalizedObservation::Applied {
                        artifact: CapturedArtifact {
                            prior_counter: None,
                            batch_counter: 1,
                            batch_height: 1,
                        },
                        post_counter: 1,
                        post_height: 1,
                    },
                    FinalizedObservation::Applied {
                        artifact: CapturedArtifact {
                            prior_counter: Some(1),
                            batch_counter: 2,
                            batch_height: 2,
                        },
                        post_counter: 2,
                        post_height: 2,
                    },
                ],
                "capture should see pre-apply state and finalized should receive the artifact after apply",
            );
        });
    }

    #[test]
    fn execution_duplicate_finalization_is_synchronized() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, observations) = Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block = harness.stage_pending_child(&genesis, View::new(1)).await;

            assert!(harness.finalize(block.clone()).await);
            observations.lock().clear();
            assert!(!harness.finalize(block).await);

            assert_eq!(
                observations.lock().as_slice(),
                [FinalizedObservation::Synchronized {
                    post_counter: 1,
                    post_height: 1,
                }],
            );
        });
    }

    #[test]
    #[should_panic(expected = "finalize reconstruction must match block commitments")]
    fn execution_finalize_reconstruction_rejects_state_root_mismatch() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let mut block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            block1.state_root = u64_to_digest(999);
            harness.processor.clear_pending();

            let _ = harness.finalize(block1.clone()).await;
        });
    }

    #[test]
    fn initial_ancestry_read_cancels_when_response_dropped() {
        deterministic::Runner::default().start(|_context| async move {
            let (mut response, receiver) = oneshot::channel::<bool>();
            let mut ancestry = Box::pin(futures::stream::pending::<Block>());
            drop(receiver);

            assert_eq!(fetch_ancestor(&mut response, &mut ancestry).await, None);
        });
    }

    #[test]
    fn execution_rebuild_pending_returns_incomplete_when_parent_subscription_ends() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            harness.processor.clear_pending();

            let provider = ScriptedParentProvider::default();
            provider.push(&block2, [None]);

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    provider,
                    Arc::new(block2),
                    &mut response,
                )
                .await;

            assert_eq!(result, Err(PrepareBatchesError::Incomplete));
        });
    }

    #[test]
    fn execution_rebuild_pending_does_not_retry_closed_provider_forever() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            harness.processor.clear_pending();

            let provider = ScriptedParentProvider::default();
            provider.push(&block2, [None, Some(block1.clone())]);

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    provider.clone(),
                    Arc::new(block2),
                    &mut response,
                )
                .await;

            assert_eq!(result, Err(PrepareBatchesError::Incomplete));
            assert_eq!(
                provider.fetches(),
                1,
                "closed ancestry should not be retried"
            );
        });
    }
}
