//! Speculative execution engine for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] owns the in-memory pending-tip DAG and the applied
//! database set, and does the work behind the actor's `Processing` mode:
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
//!   databases, start flushing them (durability is reported via [`Barrier`]),
//!   capture a snapshot of the database set for publication (returned in
//!   [`Applied`]), then retain only pending descendants of the finalized
//!   winner.
//!
//! - Maintenance: [`Processor::prune`] runs due prunes and
//!   [`Processor::publish_snapshot`] publishes a fresh capture afterwards.
//!
use crate::stateful::{
    Application, ExecutionError, Input, Proposed, PruneConfig,
    actor::{core::Verification, metrics::Metrics as StatefulMetrics},
    db::{
        Anchor, Barrier, DatabaseSet, MerkleizedOf, Publisher, ReadersOf, SnapshotsOf,
        SyncTargetsOf, UnmerkleizedOf,
    },
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
    sync::Arc,
};
use tracing::{Instrument as _, debug, info_span, warn};

mod verifier;
pub(super) use verifier::Verifier;

pub(super) type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = MerkleizedOf<<A as Application<E>>::Databases, E>;
type PendingMap<A, E> = BTreeMap<PendingDigest<A, E>, PendingEntry<A, E>>;
pub(super) type PendingSyncTargets<A, E> = SyncTargetsOf<<A as Application<E>>::Databases, E>;
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

/// What one verification attempt concluded.
pub(in crate::stateful::actor) enum VerificationResult {
    /// A verdict to return to the caller.
    Decided(bool),
    /// The caller left, so there is nothing left to answer.
    Cancelled,
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
struct ExecutionState<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Merkleized state for unfinalized blocks.
    pending: PendingMap<A, E>,
    /// Latest canonical anchor whose finalization hook has completed.
    last_processed: Anchor<PendingDigest<A, E>>,
    /// Set while a finalization sits between its first database mutation and
    /// the anchor move. Forks from the anchor during that window would take
    /// post-apply state under the pre-apply anchor, so they refuse.
    finalizing: bool,
    /// Woken when the anchor moves and the finalizing window closes.
    anchor_waiters: Vec<oneshot::Sender<()>>,
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

/// Read capability and speculative state, shared by every verification job.
///
/// Deliberately carries no authority to mutate the database set. Jobs holding
/// one are therefore `'static` and can outlive any number of applies.
struct Execution<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    readers: ReadersOf<A::Databases, E>,
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
            readers: self.readers.clone(),
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

impl<D: Copy + Ord> Default for ReplayFlights<D> {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl<D: Copy + Ord> ReplayFlights<D> {
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

/// Result of requesting shared replay work for one block digest.
enum ReplayClaim<D: Copy + Ord> {
    /// State for the digest is already available.
    Ready,
    /// The caller owns the new replay flight.
    Owner(ReplayOwner<D>),
    /// Another caller owns the replay flight.
    Wait(ReplayWaiter<D>),
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
    /// A competing finalization landed mid-preparation. The caller re-checks
    /// against the new canonical state.
    Stale,
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
pub(super) struct Applied<T, S> {
    /// A snapshot of the database set, captured at the apply boundary.
    pub(super) snapshots: S,

    /// Proves the snapshot durable. Resolves once every database flush completes.
    pub(super) barrier: Barrier,

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
    databases: A::Databases,
    execution: Execution<E, A>,
    replays: ReplayFlights<PendingDigest<A, E>>,
    pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a new processor with the given application, databases, and the
    /// last finalized block's anchor.
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
                readers: databases.readers(),
                state: Arc::new(Mutex::new(ExecutionState {
                    pending: BTreeMap::new(),
                    last_processed,
                    finalizing: false,
                    anchor_waiters: Vec::new(),
                })),
                metrics,
            },
            databases,
            replays: ReplayFlights::default(),
            pruning,
        }
    }

    /// The height of the last finalized block applied to the databases.
    pub(super) fn processed_height(&self) -> Height {
        self.execution.last_processed().height
    }

    /// Prune `self.databases` and `marshal` to the `prune` target.
    ///
    /// # Invariant
    ///
    /// Databases must be durable through `prune.barrier_height`.
    pub(super) async fn prune<S, V>(
        mut self,
        prune: Prune<PendingSyncTargets<A, E>>,
        marshal: &MarshalMailbox<S, V>,
    ) -> Self
    where
        S: Scheme,
        V: MarshalVariant,
    {
        self.databases = self.databases.prune(&prune.qmdb_target).await;
        marshal.prune(prune.marshal_height);
        self
    }

    /// Capture a snapshot of the database set's applied state and publish it
    /// at the processed height.
    pub(super) async fn publish_snapshot(
        mut self,
        publisher: &mut Publisher<SnapshotsOf<A::Databases, E>>,
    ) -> Self {
        let snapshots;
        (self.databases, snapshots) = self.databases.snapshot().await;
        publisher.publish_now(self.processed_height(), snapshots);
        self
    }

    #[cfg(test)]
    fn readers(&self) -> ReadersOf<A::Databases, E> {
        self.execution.readers.clone()
    }

    #[cfg(test)]
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

    #[cfg(test)]
    fn last_processed(&self) -> Anchor<PendingDigest<A, E>> {
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

    /// Fork unmerkleized batches from known parent state.
    #[cfg(test)]
    async fn fork_batches(
        &self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<UnmerkleizedOf<A::Databases, E>, PrepareBatchesError> {
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

    /// Apply finalized state, start persisting it, and prune dead in-memory forks.
    ///
    /// Returns the processor, the snapshot to publish, the barrier proving that
    /// snapshot durable, and any prune now due. [`None`] means the block was
    /// already applied, which happens when marshal reports it twice.
    ///
    /// The block's state comes from its verification when that is cached, and is
    /// replayed here otherwise. Verification jobs keep running throughout, so
    /// this leaves the block reachable as a parent until the anchor moves.
    pub(super) async fn finalize(
        mut self,
        context: &E,
        block: &A::Block,
    ) -> (
        Self,
        Option<Applied<PendingSyncTargets<A, E>, SnapshotsOf<A::Databases, E>>>,
    ) {
        let (height, digest) = (block.height(), block.digest());
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
            return (self, None);
        }

        let timer = self.execution.metrics.finalize_duration.timer(context);
        let block_context = block.context();
        let round = block_context.round();
        let sync_targets = A::sync_targets(block);

        // Marshal finalization is ordered. A pending miss means we can replay
        // this block on top of finalized state.
        //
        // The entry stays in the pending map until the retention sweep below.
        // Verification jobs run throughout this call, and one that forks from
        // this block must find it rather than rebuild it on top of itself.
        //
        // Safety contract: replayed `Application::apply` output must match the
        // block commitments previously enforced by `Application::verify`.
        self.execution.state.lock().finalizing = true;
        let batch = match self.execution.pending_batch(&digest) {
            Some(merkleized) => merkleized,
            None => {
                let batches = A::Databases::new_batches(&self.execution.readers).await;
                let batch = match self
                    .app
                    .apply(
                        (context.child("finalize_replay"), block_context),
                        block,
                        batches,
                    )
                    .await
                {
                    Ok(batch) => batch,
                    // The runtime is tearing the actor down; park until this
                    // task is dropped with it.
                    Err(ExecutionError::Shutdown) => std::future::pending().await,
                    // Impossible on a correct node: the batches were just forked
                    // from applied state, mutation authority is unique, and
                    // there is no caller to answer with a refusal.
                    Err(err) => panic!("finalize replay failed: {err}"),
                };
                assert!(
                    A::Databases::matches_sync_targets(&batch, &sync_targets),
                    "finalize replay state root must match block commitments",
                );
                batch
            }
        };

        let (snapshots, barrier);
        (self.databases, snapshots, barrier) = self.databases.finalize(batch).await;
        self.notify_finalized(context, block).await;
        let prune = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe_finalized(height, sync_targets));
        self.execution.advance_to_finalized(Anchor {
            height,
            round,
            digest,
        });
        timer.observe(context);

        (
            self,
            Some(Applied {
                snapshots,
                barrier,
                prune,
            }),
        )
    }

    /// Notify the application that marshal delivered a finalized block already
    /// reflected in the database set.
    pub(super) fn notify_finalized(
        &self,
        context: &E,
        block: &A::Block,
    ) -> impl Future<Output = ()> + Send {
        let mut app = self.app.clone();
        let readers = self.execution.readers.clone();
        async move {
            app.finalized(
                (context.child("finalized"), block.context()),
                block,
                readers,
            )
            .await;
        }
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

        // A replay of the block the anchor now sits on is already reflected in
        // applied state.
        if state.last_processed.digest == digest && state.last_processed.round == round {
            return true;
        }

        // Verification runs across finalizations, so a verdict can land against
        // a newer anchor and pending set than the one it started from. This is
        // where such a result is refused: its branch is no longer reachable.
        let compatible = round > state.last_processed.round
            && (parent == state.last_processed.digest || state.pending.contains_key(&parent));
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
        true
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
        if state.last_processed.digest == digest || state.pending.contains_key(&digest) {
            return ReplayClaim::Ready;
        }

        let mut entries = replays.entries.lock();
        if let Some(flight) = entries.get_mut(&digest) {
            return ReplayClaim::Wait(replays.waiter(digest, flight));
        }

        ReplayClaim::Owner(replays.register_owner(digest, &mut entries))
    }

    /// Forks batches from a known parent.
    async fn fork_batches(
        &self,
        parent: &PendingDigest<A, E>,
    ) -> Result<UnmerkleizedOf<A::Databases, E>, PrepareBatchesError> {
        {
            let state = self.state.lock();
            if let Some(entry) = state.pending.get(parent) {
                return Ok(A::Databases::fork_batches(&entry.merkleized));
            }
            if state.last_processed.digest != *parent {
                return Err(PrepareBatchesError::Invalid);
            }
        }

        let batches = A::Databases::new_batches(&self.readers).await;

        // A finalization mutates the databases before the anchor moves, so a
        // fork taken meanwhile can hold post-apply state under the pre-apply
        // anchor. Refuse whenever one overlapped this fork: either its window
        // is still open, or its anchor move already landed. The caller waits
        // out the window and re-checks canonical state.
        let state = self.state.lock();
        if state.finalizing || state.last_processed.digest != *parent {
            return Err(PrepareBatchesError::Stale);
        }
        drop(state);
        Ok(batches)
    }

    /// Wait until no finalization is mid-flight and the anchor differs from `seen`.
    ///
    /// Returns immediately when that already holds. Used by stale verification
    /// attempts, whose staleness proves a finalization at least reached its
    /// database mutation; parking here (instead of retrying immediately) lets
    /// that finalization finish moving the anchor.
    async fn anchor_past(&self, seen: &Anchor<PendingDigest<A, E>>) {
        loop {
            let waiter = {
                let mut state = self.state.lock();
                if !state.finalizing && state.last_processed.digest != seen.digest {
                    return;
                }
                let (sender, receiver) = oneshot::channel();
                state.anchor_waiters.push(sender);
                receiver
            };
            let _ = waiter.await;
        }
    }

    /// Replays one certified block and caches its commitment-matching state.
    ///
    /// Cancellation caches nothing. A commitment mismatch, or state that the
    /// applied anchor has already moved past, makes the ancestry invalid.
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

        let batches = self.fork_batches(&parent_digest).await?;

        let Some(applied) = await_or_cancel(
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
        let merkleized = match applied {
            Ok(merkleized) => merkleized,
            // A block finalized while this replay executed. The requester
            // re-checks canonical state; this replay never panics on it.
            Err(ExecutionError::Stale) => return Err(PrepareBatchesError::Stale),
            Err(ExecutionError::Shutdown) => return Err(PrepareBatchesError::Cancelled),
            Err(err @ ExecutionError::Fatal(_)) => panic!("application replay failed: {err}"),
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
        replays: &ReplayFlights<PendingDigest<A, E>>,
    ) -> ReplayResult
    where
        C: Cancellation,
    {
        let digest = block.digest();
        loop {
            match self.claim_replay(replays, digest) {
                ReplayClaim::Ready => return Ok(()),
                ReplayClaim::Owner(owner) => {
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
                    let Some(completion) =
                        await_or_cancel(cancellation, &mut waiter.completion).await
                    else {
                        return Err(PrepareBatchesError::Cancelled);
                    };
                    match completion {
                        Ok(Ok(())) | Err(_) => continue,
                        Ok(Err(error)) => return Err(error),
                    }
                }
            }
        }
    }

    /// Ensures parent state exists and forks batches for speculative execution.
    ///
    /// Verification supplies the replay registry to share reconstruction by block
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
        replays: Option<&ReplayFlights<PendingDigest<A, E>>>,
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
            self.rebuild_pending(app, context, marshal, parent, cancellation, replays)
                .await?;
        }

        self.fork_batches(&parent_digest).await
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
        replays: Option<&ReplayFlights<PendingDigest<A, E>>>,
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
            if let Some(replays) = replays {
                self.replay_block_shared(app, context, target_digest, block, cancellation, replays)
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

    /// Take the cached merkleized batch for `digest`, if it was executed.
    fn pending_batch(&self, digest: &PendingDigest<A, E>) -> Option<PendingBatches<A, E>> {
        self.state
            .lock()
            .pending
            .get(digest)
            .map(|entry| entry.merkleized.clone())
    }

    /// Move the anchor to a finalized block and drop the pending state that
    /// block invalidates. A pending block survives only when it descends from
    /// the anchor and was created after its round.
    ///
    /// Both halves happen under one lock. Verification jobs read this state
    /// while a block applies, and a job that saw the pending set already swept
    /// but the anchor not yet moved would reject work that is still valid.
    fn advance_to_finalized(&self, anchor: Anchor<PendingDigest<A, E>>) {
        let mut state = self.state.lock();
        let compatible = compatible_pending(&state, anchor.digest, anchor.round);
        let before = state.pending.len();
        state
            .pending
            .retain(|digest, entry| entry.round > anchor.round && compatible.contains(digest));
        let pruned = before - state.pending.len();
        let remaining = state.pending.len();
        state.last_processed = anchor;
        state.finalizing = false;
        for waiter in state.anchor_waiters.drain(..) {
            waiter.send_lossy(());
        }
        drop(state);
        self.metrics.pruned_forks.inc_by(pruned as u64);
        let _ = self.metrics.pending_blocks.try_set(remaining);
    }
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Creates a verifier for an independently-polled request.
    pub(super) fn verifier(&self) -> Verifier<E, A> {
        Verifier {
            app: self.app.clone(),
            execution: self.execution.clone(),
            replays: self.replays.clone(),
        }
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// build a new block proposal. The resulting block and its merkleized
    /// state are cached in `pending`. Sends `None` on `response` if the
    /// ancestry is invalid or the application declines to propose.
    pub(super) fn propose<S, V>(
        &self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        (runtime_context, consensus_context): (E, A::Context),
        mut ancestry: impl Ancestry<A::Block>,
        input: Input<A::Input, A::Provider>,
        mut response: oneshot::Sender<Option<A::Block>>,
    ) -> impl Future<Output = ()> + Send
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let mut app = self.app.clone();
        let execution = &self.execution;
        async move {
            let timer = execution.metrics.propose_duration.timer(context);

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
            let prepare = info_span!(
                "stateful.processor.prepare_batches",
                parent = %parent_digest,
            );
            let ancestry = marshal_ancestry::with_prefix([Arc::clone(&parent)], ancestry);

            let round = consensus_context.round();
            let batches = match execution
                .prepare_batches(&mut app, context, marshal, parent, &mut response, None)
                .instrument(prepare)
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
                // Unreachable: the actor admits no finalization while a
                // proposal runs (it becomes the FIFO barrier), so nothing can
                // go stale. Decline loudly rather than hide a broken barrier.
                Err(PrepareBatchesError::Stale) => {
                    warn!(?parent_digest, "proposal went stale during prepare_batches");
                    debug_assert!(false, "no finalization can interleave a proposal");
                    response.send_lossy(None);
                    return;
                }
            };

            let proposed = match await_or_cancel(
                &mut response,
                app.propose(
                    (runtime_context, consensus_context),
                    ancestry,
                    batches,
                    input,
                ),
            )
            .await
            {
                Some(Ok(result)) => result,
                Some(Err(err)) => {
                    // Stale is unreachable for the same reason as above;
                    // Shutdown and everything else also just decline.
                    warn!(?parent_digest, ?err, "proposal failed");
                    debug_assert!(
                        !matches!(err, ExecutionError::Stale),
                        "no finalization can interleave a proposal",
                    );
                    response.send_lossy(None);
                    return;
                }
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
                execution.cache_pending(block.digest(), parent_digest, round, merkleized),
                "proposal parent must remain compatible until the proposal completes",
            );
            execution.update_pending_metric();
            timer.observe(context);
            response.send_lossy(Some(block));
        }
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
        Applied, PrepareBatchesError, Processor, Prune, Pruning, ReplayClaim, ReplayFlights,
        fetch_ancestor,
    };
    use crate::stateful::{
        Application, ExecutionError, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{
            Anchor, DatabaseSet, Merkleized as _, MerkleizedOf, ReadersOf, SyncTargetsOf,
            UnmerkleizedOf,
        },
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
        ContextCell, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
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
        collections::{BTreeMap, VecDeque},
        future::Future,
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;

    const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
    const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

    type Qmdb<E> =
        any::unordered::fixed::Db<mmr::Family, E, Digest, Digest, Sha256, TwoCap, Sequential>;
    type TestSet<E> = crate::stateful::db::Single<Qmdb<E>>;
    type TestMerkleized =
        <TestSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized;
    type TestUnmerkleized =
        <TestSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Unmerkleized;

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

    #[derive(Clone)]
    struct ExecutionApp {
        genesis: Block,
        finalized_observer: Option<Arc<Mutex<Vec<u64>>>>,
        finalized_probe: Option<ApplicationProbe>,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
                finalized_observer: None,
                finalized_probe: None,
            }
        }

        fn with_finalized_observer() -> (Self, Arc<Mutex<Vec<u64>>>) {
            let finalized_values = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    genesis: Block::genesis(),
                    finalized_observer: Some(finalized_values.clone()),
                    finalized_probe: None,
                },
                finalized_values,
            )
        }

        async fn execute(
            height: Height,
            view: View,
            mut batches: UnmerkleizedOf<TestSet<deterministic::Context>, deterministic::Context>,
        ) -> Result<
            MerkleizedOf<TestSet<deterministic::Context>, deterministic::Context>,
            ExecutionError,
        > {
            let current_counter = batches
                .get(&counter_key())
                .await?
                .map_or(0, |digest| digest_to_u64(&digest));
            batches = batches.write(counter_key(), Some(u64_to_digest(current_counter + 1)));
            batches = batches.write(height_key(height), Some(u64_to_digest(view.get())));
            Ok(crate::stateful::db::Unmerkleized::merkleize(batches).await?)
        }
    }

    impl Application<deterministic::Context> for ExecutionApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = Block;
        type Databases = TestSet<deterministic::Context>;
        type Provider = ();
        type Input = ();

        async fn genesis(&mut self) -> Self::Block {
            self.genesis.clone()
        }

        async fn propose(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            batches: UnmerkleizedOf<Self::Databases, deterministic::Context>,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            let mut ancestry = Box::pin(ancestry);
            let Some(parent) = ancestry.next().await else {
                return Ok(None);
            };
            let context = context.1.clone();
            let view = context.round.view();
            let height = parent.height().next();
            let merkleized = Self::execute(height, view, batches).await?;
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
            Ok(Some(Proposed { block, merkleized }))
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            batches: UnmerkleizedOf<Self::Databases, deterministic::Context>,
        ) -> Result<Option<MerkleizedOf<Self::Databases, deterministic::Context>>, ExecutionError>
        {
            let mut ancestry = Box::pin(ancestry);
            let Some(block) = ancestry.next().await else {
                return Ok(None);
            };
            let merkleized =
                Self::execute(block.height(), block.context.round.view(), batches).await?;
            if merkleized.root() != block.state_root {
                return Ok(None);
            }
            Ok(Some(merkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: UnmerkleizedOf<Self::Databases, deterministic::Context>,
        ) -> Result<MerkleizedOf<Self::Databases, deterministic::Context>, ExecutionError> {
            Self::execute(block.height(), block.context.round.view(), batches).await
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
            if let Some(probe) = &self.finalized_probe {
                probe.call(block.digest()).await;
            }
            let Some(observer) = &self.finalized_observer else {
                return;
            };
            let value = readers
                .read()
                .await
                .get(&height_key(block.height()))
                .await
                .expect("database read should succeed")
                .expect("finalized height should be reflected in the database set");
            observer.lock().push(digest_to_u64(&value));
        }

        fn sync_targets(
            block: &Self::Block,
        ) -> SyncTargetsOf<Self::Databases, deterministic::Context> {
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
        ) -> (Self, Arc<Mutex<Vec<u64>>>) {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix(), &context);
            let (app, finalized_values) = ExecutionApp::with_finalized_observer();
            (
                Self::with_app(context, provider, config, app).await,
                finalized_values,
            )
        }

        async fn with_app(
            context: deterministic::Context,
            provider: MapProvider,
            config: any::FixedConfig<TwoCap, Sequential>,
            app: ExecutionApp,
        ) -> Self {
            Self::with_app_pruned(context, provider, config, app, None).await
        }

        async fn with_app_pruned(
            context: deterministic::Context,
            provider: MapProvider,
            config: any::FixedConfig<TwoCap, Sequential>,
            app: ExecutionApp,
            prune_config: Option<PruneConfig>,
        ) -> Self {
            let databases =
                TestSet::<deterministic::Context>::init(context.child("db_set"), config.clone())
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
                    prune_config.map(|config| Pruning::build(config, 1, 0)),
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
            let merkleized = ExecutionApp::execute(height, view, batches).await.unwrap();
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

        async fn fork_from(&self, parent: &Block) -> TestUnmerkleized {
            self.processor
                .fork_batches(&parent.digest())
                .await
                .expect("parent must be forkable")
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

        /// Finalize `block` and wait for its deferred flush.
        /// Returns whether the block was newly applied (`false` for a
        /// duplicate report).
        #[boxed]
        async fn finalize(mut self, block: Block) -> (Self, bool) {
            let applied;
            (self.processor, applied) = self
                .processor
                .finalize(self.context_cell.as_present(), &block)
                .await;
            let Some(Applied { barrier, .. }) = applied else {
                return (self, false);
            };
            assert!(barrier.durable().await, "finalize flush must complete");
            (self, true)
        }

        #[boxed]
        async fn finalize_with_prune(
            mut self,
            block: Block,
        ) -> (
            Self,
            Option<Prune<SyncTargetsOf<TestSet<deterministic::Context>, deterministic::Context>>>,
        ) {
            let applied;
            (self.processor, applied) = self
                .processor
                .finalize(self.context_cell.as_present(), &block)
                .await;
            let Applied { barrier, prune, .. } = applied.expect("finalized block must apply");
            assert!(barrier.durable().await, "finalize flush must complete");
            (self, prune)
        }

        async fn height_value(&self, height: Height) -> Option<u64> {
            self.processor
                .readers()
                .read()
                .await
                .get(&height_key(height))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn counter_value(&self) -> Option<u64> {
            self.processor
                .readers()
                .read()
                .await
                .get(&counter_key())
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
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{prefix}_log_journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: IO_BUFFER_SIZE,
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
            let mut harness = Harness::with_app_pruned(
                context,
                provider,
                config,
                app,
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 1,
                    retained_qmdb_blocks: 1,
                }),
            )
            .await;

            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            let (_, prune) = harness.finalize_with_prune(block1).await;
            assert_eq!(
                prune, None,
                "pruning should wait for the full retention window",
            );
        });
    }

    /// A fork taken from the anchor while a finalization is mid-flight (databases
    /// applied, anchor not yet advanced) refuses instead of handing out the winner's
    /// state under the loser's anchor.
    #[test]
    fn fork_refuses_inside_the_finalize_window() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;

            // Park the finalize between its database apply and its anchor move.
            let (gate, started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let verifier = harness.processor.verifier();
            let processor = harness.processor;
            let finalize = processor.finalize(harness.context_cell.as_present(), &winner);
            futures::pin_mut!(finalize);
            select! {
                _ = &mut finalize => panic!("finalize must park on the probe"),
                result = started => result.expect("finalize must reach the probe"),
            }

            // Inside the window, a fork from the anchor must refuse: the databases
            // are already at the winner, but the anchor still names genesis.
            assert!(matches!(
                verifier.execution.fork_batches(&genesis.digest()).await,
                Err(PrepareBatchesError::Stale)
            ));

            release.send(()).expect("finalize is parked");
            let (processor, applied) = finalize.await;
            assert!(applied.is_some());
            drop(processor);
        });
    }

    /// A batch forked before a competing finalization refuses its next operation with
    /// the typed stale error, end to end through the set wrapper, the database cell,
    /// and the storage checks.
    #[test]
    fn stale_fork_refuses_through_the_set() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Fork from the applied anchor, then finalize a competing child.
            let stale = harness.fork_from(&genesis).await;
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied;
            (harness, applied) = harness.finalize(winner).await;
            assert!(applied);

            assert!(matches!(
                ExecutionApp::execute(Height::new(1), View::new(1), stale).await,
                Err(ExecutionError::Stale)
            ));
            drop(harness);
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

            let applied;
            (harness, applied) = harness.finalize(winner.clone()).await;
            assert!(applied, "finalization should persist winner state");
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

            let applied;
            (harness, applied) = harness.finalize(winner.clone()).await;
            assert!(applied, "finalization should persist winner state");
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

    /// A verification job holds an [`Execution`] and keeps running while a
    /// block is applied. The block being finalized must stay reachable as a
    /// parent for that whole window, otherwise a job that forks from it
    /// mid-apply rebuilds it on top of itself and rejects a valid descendant.
    #[test]
    fn finalized_block_stays_forkable_while_it_applies() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;

            // A job's view of the world, taken before the apply starts.
            let execution = harness.processor.execution.clone();

            // Park the finalization inside its `finalized` hook: the database
            // apply is done, and the anchor has not moved yet.
            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let mut finalize = Box::pin(
                harness
                    .processor
                    .finalize(harness.context_cell.as_present(), &winner),
            );
            select! {
                _ = &mut finalize => panic!("finalize completed before its hook returned"),
                result = &mut started => result.expect("finalized hook should start"),
            }

            assert!(
                execution.fork_batches(&winner.digest()).await.is_ok(),
                "the applying block must stay forkable for jobs that are still running",
            );

            release
                .send(())
                .expect("finalized hook should remain active");
            let (_processor, applied) = finalize.await;
            let Applied { barrier, .. } = applied.expect("finalized block should be newly applied");
            assert!(barrier.durable().await, "finalize flush must complete");
        });
    }

    #[test]
    fn execution_finalize_awaits_its_finalized_hook() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block = harness.stage_pending_child(&genesis, View::new(1)).await;

            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(block.digest(), [gate]));
            let mut finalize = Box::pin(
                harness
                    .processor
                    .finalize(harness.context_cell.as_present(), &block),
            );
            select! {
                _ = &mut finalize => {
                    panic!("finalize completed before its finalized hook returned");
                },
                result = &mut started => {
                    result.expect("finalized hook should start");
                },
            }

            release
                .send(())
                .expect("finalized hook should remain active");
            let (_processor, applied) = finalize.await;
            let Applied { barrier, .. } = applied.expect("finalized block should be newly applied");
            assert!(barrier.durable().await, "finalize flush must complete");
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

            let applied;
            (harness, applied) = harness.finalize(winner).await;
            assert!(applied);
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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

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
            assert!(replays.entries.lock().is_empty());

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
            assert!(replays.entries.lock().is_empty());
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
            assert!(replays.entries.lock().is_empty());
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
            assert!(replays.entries.lock().is_empty());
        });
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
                let applied;
                (harness, applied) = harness.finalize(block.clone()).await;
                assert!(applied);
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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

            let gap_height = Height::new(3);
            let gap_view = View::new(3);
            let batches = harness
                .processor
                .fork_batches(&block1.digest())
                .await
                .expect("processed anchor should be available");
            let merkleized = ExecutionApp::execute(gap_height, gap_view, batches)
                .await
                .unwrap();
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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

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

            let applied;
            (harness, applied) = harness.finalize(canonical).await;
            assert!(applied);

            let _ = harness.finalize(conflicting).await;
        });
    }

    #[test]
    fn execution_finalize_identical_duplicate_returns_false() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let canonical = harness.stage_pending_child(&genesis, View::new(1)).await;

            let applied;
            (harness, applied) = harness.finalize(canonical.clone()).await;
            assert!(applied);
            let applied;
            (harness, applied) = harness.finalize(canonical).await;
            assert!(!applied);
            assert_eq!(harness.counter_value().await, Some(1));
        });
    }

    #[test]
    fn execution_finalization_persists_state_to_db() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            let applied;
            (harness, applied) = harness.finalize(block1).await;
            assert!(applied);
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
    fn execution_finalized_hook_runs_for_each_applied_block() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, finalized_values) =
                Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;

            let applied;
            (harness, applied) = harness.finalize(block1).await;
            assert!(applied);
            let (_, applied) = harness.finalize(block2).await;
            assert!(applied);
            assert_eq!(
                finalized_values.lock().clone(),
                vec![1, 2],
                "finalized hook should observe every applied block",
            );
        });
    }

    #[test]
    fn execution_finalized_hook_runs_for_already_reflected_block() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, finalized_values) =
                Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

            finalized_values.lock().clear();
            harness
                .processor
                .notify_finalized(harness.context_cell.as_present(), &block1)
                .await;
            assert_eq!(
                finalized_values.lock().clone(),
                vec![1],
                "finalized hook should run for blocks already reflected in the database set",
            );
        });
    }

    #[test]
    #[should_panic(expected = "finalize replay state root must match block commitments")]
    fn execution_finalize_replay_rejects_state_root_mismatch() {
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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

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
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);

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
