//! Speculative execution for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] owns the in-memory pending-tip DAG and the applied
//! database set, and does the work behind the actor's `Processing` mode.
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
//!   databases (durability is reported via [`Barrier`]), capture a snapshot
//!   of the database set for publication when durability starts (returned in
//!   [`Applied`]), then retain only pending descendants of the finalized
//!   winner. The actor coordinates durability separately so multiple
//!   finalizations can be covered by one storage sync.
//!
//! - Maintenance -- [`Processor::prune`] runs due prunes and
//!   [`Processor::publish_snapshot`] publishes fresh snapshots afterwards.
//!
//! # How verification races finalization
//!
//! Finalization never waits for verification. The actor applies a finalized
//! block immediately, and verification jobs keep running through the apply.
//!
//! Jobs share an [`Execution`], which holds readers over the databases and,
//! under one lock, the pending map of executed blocks (proposed, verified, or
//! replayed), the applied anchor, and the finalizing flag.
//!
//! A job on the losing side of an apply is refused at its next database read
//! ([`ExecutionError::Stale`]). It waits out the anchor move
//! ([`Execution::anchor_past`]) and re-checks the candidate against the new
//! canonical chain. A candidate that itself finalized is true, one whose
//! branch lost is false, and one still undecided executes again (the loop in
//! `verifier::Verifier::run`).
//!
//! An apply changes the databases before the anchor moves. A fork taken from
//! the anchor in between could mix the two states, so forks refuse while the
//! flag is set, and dropping dead forks, the anchor move, and the flag clear
//! happen under one lock ([`Execution::advance_to_finalized`]).
//!
//! When its verification was cached, the finalized block stays in the pending
//! map until the anchor moves, so a job forking from it mid-apply finds it
//! instead of rebuilding it on top of itself. A replayed miss caches nothing,
//! and the flag alone protects forks in that window.

use crate::stateful::{
    Application, ExecutionError, Input, Proposed, PruneConfig,
    actor::{BlockDigest, SyncTargets, core::Verification, metrics::Metrics as StatefulMetrics},
    db::{
        Anchor, Barrier, DatabaseSet, MerkleizedOf, Publisher, ReadersOf, SnapshotsOf,
        UnmerkleizedOf,
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
use futures::{FutureExt as _, Stream, StreamExt, future};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
    sync::Arc,
};
use tracing::{Instrument as _, debug, info_span, warn};

mod verifier;
pub(super) use verifier::Verifier;

type PendingBatches<A, E> = MerkleizedOf<<A as Application<E>>::Databases, E>;
type PendingMap<A, E> = BTreeMap<BlockDigest<A, E>, PendingEntry<A, E>>;
type ReplayResult = Result<(), PrepareBatchesError>;
type ReplayWaiterSlots = Vec<Option<oneshot::Sender<ReplayResult>>>;
type ReplayRegistry<D> = Arc<Mutex<BTreeMap<D, ReplayFlight>>>;

/// Identity that prevents stale handles from modifying a replacement replay.
struct ReplayGeneration;

/// One in-progress replay and the requests waiting for its result.
struct ReplayFlight {
    generation: Arc<ReplayGeneration>,
    waiters: ReplayWaiterSlots,
    vacant: Vec<usize>,
}

/// The verification's final answer.
pub(in crate::stateful::actor) enum VerificationResult {
    /// A verdict to return to the caller.
    Decided(bool),
    /// The request future was dropped, so there is nothing left to answer.
    Cancelled,
}

/// How a [`PendingEntry`]'s state was produced.
///
/// `Applied` state is reconstructed by [`Application::apply`], which executes a
/// block's transitions unconditionally to serve as a speculative parent for a
/// descendant. It is not a verification verdict, so it must never fast-answer a
/// verification (and thus certification) request for its own digest. `Verified`
/// state completed [`Application::verify`] for that exact digest, or is our own
/// proposal, and may.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// Reconstructed by `apply` as speculative parent state.
    Applied,
    /// Accepted by `verify`, or produced by a local proposal.
    Verified,
}

/// Cached speculative state for a block digest.
struct PendingEntry<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    round: Round,
    parent: BlockDigest<A, E>,
    merkleized: PendingBatches<A, E>,
    provenance: Provenance,
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
    processed: Anchor<BlockDigest<A, E>>,
    /// Set from the start of a finalization's apply phase (before its replay
    /// and database mutations) until the anchor move. Forks from the anchor
    /// during that window could take post-apply state under the pre-apply
    /// anchor, so they refuse.
    finalizing: bool,
    /// Woken when the anchor moves and the finalizing window closes. A cancelled waiter's
    /// sender stays until the next registration or anchor move.
    anchor_waiters: Vec<oneshot::Sender<()>>,
}

impl<A, E> ExecutionState<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Returns `digest` and its pending descendants in later rounds.
    fn descendants(&self, digest: BlockDigest<A, E>, round: Round) -> HashSet<BlockDigest<A, E>> {
        let mut children_by_parent = BTreeMap::new();
        for (candidate_digest, entry) in &self.pending {
            if entry.round <= round {
                continue;
            }
            children_by_parent
                .entry(entry.parent)
                .or_insert_with(Vec::new)
                .push(*candidate_digest);
        }

        let mut descendants = HashSet::new();
        descendants.insert(digest);

        let mut to_visit = VecDeque::new();
        to_visit.push_back(digest);
        while let Some(parent) = to_visit.pop_front() {
            let Some(children) = children_by_parent.get(&parent) else {
                continue;
            };
            for &child in children {
                if descendants.insert(child) {
                    to_visit.push_back(child);
                }
            }
        }
        descendants
    }
}

/// Readers and speculative state shared by every verification job.
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

/// In-progress replays shared by verifications, keyed by block digest.
///
/// Keying by digest is sound because a digest identifies a [`CertifiableBlock`] together with its
/// embedded context. Execution state is locked before the registry whenever both are held, so a
/// registration cannot race the caching of the same digest.
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
        let slot = if let Some(slot) = flight.vacant.pop() {
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

    /// Registers a new flight for `digest` in the caller-held `entries` and returns its owner.
    ///
    /// Panics if a flight for `digest` exists. Callers check under the same guard.
    fn owner(&self, digest: D, entries: &mut BTreeMap<D, ReplayFlight>) -> ReplayOwner<D> {
        let generation = Arc::new(ReplayGeneration);
        assert!(
            entries
                .insert(
                    digest,
                    ReplayFlight {
                        generation: Arc::clone(&generation),
                        waiters: Vec::new(),
                        vacant: Vec::new(),
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
        flight.vacant.push(self.slot);
    }
}

/// Owner of a replay flight.
///
/// Dropping the owner removes its flight. Waiters receive the result recorded by
/// [`ReplayOwner::finish`], or see their channel close if none was recorded.
struct ReplayOwner<D: Copy + Ord> {
    flights: ReplayFlights<D>,
    digest: D,
    generation: Arc<ReplayGeneration>,
    result: Option<ReplayResult>,
}

impl<D: Copy + Ord> ReplayOwner<D> {
    /// Records `result` for the flight's waiters and drops the owner.
    ///
    /// Panics if `result` is a cancellation. A cancelled owner is dropped without a result.
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
    /// The request future was dropped while waiting.
    Cancelled,
    /// A competing finalization landed mid-preparation. The caller re-checks
    /// against the new canonical state.
    Stale,
}

/// Cancellation signal for speculative work.
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

/// What serving receives from one finalization.
pub(super) enum Publication<S> {
    /// Nothing new: no barrier was requested, and the set's snapshots are not cheap.
    None,
    /// A snapshot of the applied state, captured without a barrier because the set's snapshots
    /// are cheap (see [`DatabaseSet::CHEAP_SNAPSHOT`]).
    Snapshot(S),
    /// A snapshot of the applied state and the barrier started with it, which covers the block
    /// and every earlier applied block.
    WithBarrier(S, Barrier),
}

/// Result of applying a newly finalized block.
pub(super) struct Applied<T, S> {
    /// Snapshots to serve, with the barrier covering the block when the caller requested one.
    pub(super) publication: Publication<S>,

    /// Prune that became due with this finalization.
    pub(super) prune: Option<Prune<T>>,
}

/// Marshal and database prune targets selected from finalized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prune<T> {
    marshal_height: Height,
    /// Finalized height whose sync targets are the database prune target.
    pub(super) barrier_height: Height,
    qmdb_target: T,
}

/// Prune schedule and the finalized sync targets retained for it.
///
/// See [`Config::prune_config`](crate::stateful::Config::prune_config) for the retained windows.
pub(super) struct Pruning<T> {
    interval: u64,
    offset: u64,
    marshal_window: usize,
    qmdb_window: usize,
    retained: VecDeque<(Height, T)>,
}

impl<T: Clone> Pruning<T> {
    /// Creates a schedule whose phase is chosen at random within the maintenance interval.
    pub(super) fn random(config: PruneConfig, max_pending_acks: usize, rng: &mut impl Rng) -> Self {
        let interval = u64::try_from(config.maintenance_interval.get())
            .expect("prune interval should fit in u64");
        let offset = rng.next_u64() % interval;
        Self::new(config, max_pending_acks, offset)
    }

    /// Creates a schedule that prunes at heights congruent to `offset` modulo the maintenance
    /// interval.
    ///
    /// Panics if `config` is invalid, `offset` is not below the interval, or a window overflows.
    pub(super) fn new(config: PruneConfig, max_pending_acks: usize, offset: u64) -> Self {
        config.assert_valid();
        let interval = u64::try_from(config.maintenance_interval.get())
            .expect("prune interval should fit in u64");
        assert!(
            offset < interval,
            "prune maintenance offset must be within the interval",
        );
        let base_retention_window = max_pending_acks
            .checked_add(1)
            .expect("max_pending_acks retention window overflowed");
        let marshal_window = base_retention_window
            .checked_add(config.retained_marshal_blocks)
            .expect("marshal prune retention window overflowed");
        let qmdb_window = base_retention_window
            .checked_add(config.retained_qmdb_blocks)
            .expect("qmdb prune retention window overflowed");
        Self {
            interval,
            offset,
            marshal_window,
            qmdb_window,
            retained: VecDeque::new(),
        }
    }

    /// Records the sync targets of the finalized block at `height` and returns a prune if one is
    /// due.
    ///
    /// A prune is due when `height` matches the schedule's phase and a full marshal retention
    /// window has been recorded since startup. Marshal is pruned to the oldest retained height,
    /// and the databases to the oldest sync targets in the database retention window.
    fn observe(&mut self, height: Height, targets: T) -> Option<Prune<T>> {
        self.retained.push_back((height, targets));
        if self.retained.len() > self.marshal_window {
            self.retained.pop_front();
        }

        if height.get() % self.interval != self.offset {
            return None;
        }

        if self.retained.len() < self.marshal_window {
            return None;
        }

        let marshal_height = self
            .retained
            .front()
            .expect("retained prune targets must exist")
            .0;
        let qmdb_index = self
            .retained
            .len()
            .checked_sub(self.qmdb_window)
            .expect("qmdb retention window must not exceed marshal window");
        let (barrier_height, qmdb_target) = self
            .retained
            .get(qmdb_index)
            .expect("qmdb prune target must exist");

        Some(Prune {
            marshal_height,
            barrier_height: *barrier_height,
            qmdb_target: qmdb_target.clone(),
        })
    }
}

/// Speculative execution and finalized-state application for a running stateful actor.
pub(super) struct Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    app: A,
    databases: A::Databases,
    execution: Execution<E, A>,
    replays: ReplayFlights<BlockDigest<A, E>>,
    pruning: Option<Pruning<SyncTargets<A, E>>>,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Creates a processor whose `databases` hold the applied state of `processed`.
    pub(super) fn new(
        app: A,
        databases: A::Databases,
        processed: Anchor<BlockDigest<A, E>>,
        metrics: StatefulMetrics,
        pruning: Option<Pruning<SyncTargets<A, E>>>,
    ) -> Self {
        Self {
            app,
            execution: Execution {
                readers: databases.readers(),
                state: Arc::new(Mutex::new(ExecutionState {
                    pending: BTreeMap::new(),
                    processed,
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

    /// Returns a verifier that shares this processor's speculative state.
    pub(super) fn verifier(&self) -> Verifier<E, A> {
        Verifier {
            app: self.app.clone(),
            execution: self.execution.clone(),
            replays: self.replays.clone(),
        }
    }

    /// The height of the last finalized block applied to the databases.
    pub(super) fn processed_height(&self) -> Height {
        self.execution.processed().height
    }

    /// Prune `self.databases` and `marshal` to the `prune` target.
    ///
    /// # Invariant
    ///
    /// Databases must be durable through `prune.barrier_height`.
    pub(super) async fn prune<S, V>(
        mut self,
        prune: Prune<SyncTargets<A, E>>,
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
        publisher.publish(self.processed_height(), snapshots);
        self
    }

    /// Capture snapshots of every applied batch and start one durability
    /// barrier covering them.
    pub(super) async fn sync(mut self) -> (Self, SnapshotsOf<A::Databases, E>, Barrier) {
        let (snapshots, barrier);
        (self.databases, snapshots, barrier) = self.databases.finalize().await;
        (self, snapshots, barrier)
    }

    #[cfg(test)]
    fn processed(&self) -> Anchor<BlockDigest<A, E>> {
        self.execution.processed()
    }

    #[cfg(test)]
    fn pending_contains(&self, digest: &BlockDigest<A, E>) -> bool {
        self.execution.pending_contains(digest)
    }

    #[cfg(test)]
    fn pending_verified(&self, digest: &BlockDigest<A, E>) -> bool {
        self.execution.pending_verified(digest)
    }

    #[cfg(test)]
    fn clear_pending(&self) {
        self.execution.state.lock().pending.clear();
        self.execution.update_pending_metric();
    }

    #[cfg(test)]
    async fn fork_batches(
        &self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<UnmerkleizedOf<A::Databases, E>, PrepareBatchesError> {
        let (mut never, _live) = oneshot::channel::<()>();
        self.execution.fork_batches(parent, &mut never).await
    }

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

    /// Returns whether `block` is at or below the processed height.
    ///
    /// Panics if `block` conflicts with the processed anchor at the same height.
    pub(super) fn redelivered(&self, block: &A::Block) -> bool {
        let processed = self.execution.processed();
        if block.height() == processed.height {
            assert_eq!(
                block.digest(),
                processed.digest,
                "received conflicting finalized block at processed height",
            );
        }
        block.height() <= processed.height
    }

    /// Applies the next finalized `block` and discards cached state that does not descend from it.
    ///
    /// Returns the processor, the prune that became due, if any, and the [`Publication`] for
    /// serving, which carries a barrier covering `block` and every earlier applied block if
    /// `start_barrier` is set. The processed anchor advances to `block` after the application's
    /// `finalized` hook returns.
    ///
    /// The block's state comes from its verification when that is cached, and
    /// a cached block stays reachable as a parent until the anchor moves. A
    /// miss is replayed here without caching, and forks from the anchor refuse
    /// until the anchor moves. Verification jobs keep running throughout.
    ///
    /// Panics if `block` does not have the next height and the processed anchor as its parent,
    /// or if an uncached block fails to execute or match its commitments.
    pub(super) async fn finalize(
        mut self,
        context: &E,
        block: &A::Block,
        start_barrier: bool,
    ) -> (
        Self,
        Applied<SyncTargets<A, E>, SnapshotsOf<A::Databases, E>>,
    ) {
        let (height, digest) = (block.height(), block.digest());
        let processed = self.execution.processed();
        assert_eq!(
            height,
            processed.height.next(),
            "finalized block skips unapplied heights",
        );
        assert_eq!(
            block.parent(),
            processed.digest,
            "finalized block does not extend the applied tip",
        );

        let timer = self.execution.metrics.finalize_duration.timer(context);
        let block_context = block.context();
        let round = block_context.round();
        let sync_targets = A::sync_targets(block);

        // Marshal finalization is ordered. A pending miss means we can replay
        // this block on top of finalized state.
        //
        // A cached entry stays in the pending map until the anchor move below
        // drops dead forks, so a job forking from this block finds it instead
        // of rebuilding it on top of itself. A replayed miss caches nothing,
        // and replayed `apply` output must match the block's commitments.
        // Every path from here must reach `advance_to_finalized` or take the
        // actor down -- a stranded window parks every later verification
        // forever.
        {
            let mut state = self.execution.state.lock();
            assert!(!state.finalizing, "finalization must be serialized");
            state.finalizing = true;
        }
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
                    Ok(Some(batch)) => batch,
                    // A finalized block was certified by a quorum whose honest voters
                    // verified it, so it always executes.
                    Ok(None) => panic!("finalize replay could not execute a finalized block"),
                    // Impossible on a correct node, since the batches were just forked
                    // from applied state, mutation authority is unique, and
                    // there is no caller to answer with a refusal. Parking leaves the
                    // block unapplied and unacknowledged.
                    Err(err) => {
                        panic_unless_stopping(context, "finalize replay", &err);
                        future::pending().await
                    }
                };
                assert!(
                    A::Databases::matches_sync_targets(&batch, &sync_targets),
                    "finalize replay state root must match block commitments",
                );
                batch
            }
        };

        let captured = self
            .app
            .capture(
                (context.child("capture"), block.context()),
                block,
                &batch,
                self.execution.readers.clone(),
            )
            .await;
        self.databases = self.databases.apply(batch).await;
        let publication = if start_barrier {
            let (snapshots, barrier);
            (self.databases, snapshots, barrier) = self.databases.finalize().await;
            Publication::WithBarrier(snapshots, barrier)
        } else if A::Databases::CHEAP_SNAPSHOT {
            let snapshots;
            (self.databases, snapshots) = self.databases.snapshot().await;
            Publication::Snapshot(snapshots)
        } else {
            Publication::None
        };
        self.app
            .finalized(
                (context.child("finalized"), block.context()),
                block,
                captured,
                self.execution.readers.clone(),
            )
            .await;
        let prune = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe(height, sync_targets));
        self.execution.advance_to_finalized(Anchor {
            height,
            round,
            digest,
        });
        timer.observe(context);

        (self, Applied { publication, prune })
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// build a new block proposal. The resulting block and its merkleized
    /// state are cached in `pending`. Sends `None` on `response` if the
    /// ancestry is invalid, the application declines to propose, or the
    /// proposal goes stale (debug-asserted unreachable, since no finalization
    /// can interleave a proposal). A fatal application error panics unless shutdown has fired.
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
                // Unreachable, since the actor admits no finalization while
                // a proposal runs (it becomes the FIFO barrier).
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
                Some(Err(err @ ExecutionError::Fatal(_))) => {
                    panic_unless_stopping(context, "application proposal", &err);
                    return future::pending().await;
                }
                Some(Err(err)) => {
                    // An invalid execution declines. Stale is unreachable for the same reason as
                    // above.
                    warn!(?parent_digest, ?err, "proposal declined by error");
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
            // The cache keys the entry by the requested parent and round, which verification
            // and replay later read back from the block itself.
            assert_eq!(
                block.parent(),
                parent_digest,
                "proposed block must extend the requested parent",
            );
            assert_eq!(
                block.context().round(),
                round,
                "proposed block must carry the requested round",
            );
            assert!(
                execution.cache_pending(
                    block.digest(),
                    PendingEntry {
                        round,
                        parent: parent_digest,
                        merkleized,
                        provenance: Provenance::Verified,
                    },
                ),
                "proposal parent must remain compatible until the proposal completes",
            );
            execution.update_pending_metric();
            timer.observe(context);
            response.send_lossy(Some(block));
        }
    }
}

impl<E, A> Execution<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn processed(&self) -> Anchor<BlockDigest<A, E>> {
        self.state.lock().processed
    }

    fn summary(&self) -> (Anchor<BlockDigest<A, E>>, usize) {
        let state = self.state.lock();
        (state.processed, state.pending.len())
    }

    /// Whether `digest` has cached state that completed `verify` (or a local
    /// proposal). Speculative `apply` replay state does not count, so a
    /// certification that reconstructed an ancestor cannot fast-answer without
    /// a real verification verdict for that ancestor's own digest.
    fn pending_verified(&self, digest: &BlockDigest<A, E>) -> bool {
        self.state
            .lock()
            .pending
            .get(digest)
            .is_some_and(|entry| entry.provenance == Provenance::Verified)
    }

    #[cfg(test)]
    fn pending_contains(&self, digest: &BlockDigest<A, E>) -> bool {
        self.state.lock().pending.contains_key(digest)
    }

    fn pending_len(&self) -> usize {
        self.state.lock().pending.len()
    }

    fn update_pending_metric(&self) {
        let _ = self.metrics.pending_blocks.try_set(self.pending_len());
    }

    /// Caches `entry` as the speculative state of `digest`.
    ///
    /// Returns `true` if the state is cached or already held: by an existing entry (which keeps
    /// its state and only upgrades its provenance), or by the processed anchor. Otherwise returns
    /// `false` unless `entry` is at a later round than the processed anchor, with the processed
    /// anchor or a cached block as its parent.
    ///
    /// Panics if `digest` is already cached with a different parent or round.
    fn cache_pending(&self, digest: BlockDigest<A, E>, entry: PendingEntry<A, E>) -> bool {
        let (round, parent) = (entry.round, entry.parent);
        let mut state = self.state.lock();
        if let Some(existing) = state.pending.get_mut(&digest) {
            assert_eq!(existing.parent, parent, "pending parent changed for digest");
            assert_eq!(existing.round, round, "pending round changed for digest");
            // A real verification verdict promotes speculative replay state, so
            // a later certification of this digest fast-answers honestly.
            // `Applied` never demotes an entry that already verified.
            if entry.provenance == Provenance::Verified {
                existing.provenance = Provenance::Verified;
            }
            return true;
        }

        // A replay of the block the anchor now sits on is already reflected in
        // applied state.
        if state.processed.digest == digest && state.processed.round == round {
            return true;
        }

        // A verdict can land after the anchor moved past its branch. This is
        // where it is refused.
        let compatible = round > state.processed.round
            && (parent == state.processed.digest || state.pending.contains_key(&parent));
        if !compatible {
            return false;
        }
        state.pending.insert(digest, entry);
        true
    }

    /// Claims replay of `digest` for a verification.
    ///
    /// Returns [`ReplayClaim::Ready`] if `digest` is the processed anchor or is cached,
    /// [`ReplayClaim::Wait`] if a replay of `digest` is in flight, and [`ReplayClaim::Owner`]
    /// otherwise.
    fn claim_replay(
        &self,
        replays: &ReplayFlights<BlockDigest<A, E>>,
        digest: BlockDigest<A, E>,
    ) -> ReplayClaim<BlockDigest<A, E>> {
        let state = self.state.lock();
        if state.processed.digest == digest || state.pending.contains_key(&digest) {
            return ReplayClaim::Ready;
        }

        let mut entries = replays.entries.lock();
        if let Some(flight) = entries.get_mut(&digest) {
            return ReplayClaim::Wait(replays.waiter(digest, flight));
        }

        ReplayClaim::Owner(replays.owner(digest, &mut entries))
    }

    /// Forks batches from a known parent.
    ///
    /// Forking from the processed anchor takes read access, which waits while a finalization
    /// applies. That wait ends early with [`PrepareBatchesError::Cancelled`] if `cancellation`
    /// fires, and a fork that would overlap a finalization refuses with
    /// [`PrepareBatchesError::Stale`] without waiting.
    async fn fork_batches<C: Cancellation>(
        &self,
        parent: &BlockDigest<A, E>,
        cancellation: &mut C,
    ) -> Result<UnmerkleizedOf<A::Databases, E>, PrepareBatchesError> {
        {
            let state = self.state.lock();
            if let Some(entry) = state.pending.get(parent) {
                return Ok(A::Databases::fork_batches(&entry.merkleized));
            }
            if state.processed.digest != *parent {
                return Err(PrepareBatchesError::Invalid);
            }
            if state.finalizing {
                return Err(PrepareBatchesError::Stale);
            }
        }

        let Some(batches) =
            await_or_cancel(cancellation, A::Databases::new_batches(&self.readers)).await
        else {
            return Err(PrepareBatchesError::Cancelled);
        };

        // A finalization mutates the databases before the anchor moves, so a
        // fork taken meanwhile can hold post-apply state under the pre-apply
        // anchor. Refuse whenever one overlapped this fork -- either its window
        // is still open, or its anchor move already landed. The caller waits
        // out the window and re-checks canonical state.
        let state = self.state.lock();
        if state.finalizing || state.processed.digest != *parent {
            return Err(PrepareBatchesError::Stale);
        }
        drop(state);
        Ok(batches)
    }

    /// Wait until no finalization is mid-flight and the anchor differs from `seen`.
    ///
    /// Returns immediately when that already holds. A stale attempt parks
    /// here until the in-flight finalization moves the anchor or takes the
    /// actor down.
    async fn anchor_past(&self, seen: &Anchor<BlockDigest<A, E>>) {
        loop {
            let waiter = {
                let mut state = self.state.lock();
                if !state.finalizing && state.processed.digest != seen.digest {
                    return;
                }
                let (sender, receiver) = oneshot::channel();
                state.anchor_waiters.retain(|waiter| !waiter.is_closed());
                state.anchor_waiters.push(sender);
                receiver
            };
            let _ = waiter.await;
        }
    }

    /// Replays `block` on its parent's state and caches the result as unverified.
    ///
    /// Cancellation caches nothing. A block that cannot be executed, a
    /// commitment mismatch, or state that the applied anchor has already moved
    /// past, makes the ancestry invalid.
    async fn replay<C>(
        &self,
        app: &mut A,
        context: &E,
        target_digest: BlockDigest<A, E>,
        block: Arc<A::Block>,
        cancellation: &mut C,
    ) -> ReplayResult
    where
        C: Cancellation,
    {
        let (digest, parent_digest) = (block.digest(), block.parent());
        let consensus_context = block.context();
        let round = consensus_context.round();

        let batches = self.fork_batches(&parent_digest, cancellation).await?;

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
            Ok(Some(merkleized)) => merkleized,
            Ok(None) => {
                warn!(?target_digest, block = ?digest, "rebuild replay could not execute block");
                return Err(PrepareBatchesError::Invalid);
            }
            // A block finalized while this replay executed. The requester
            // re-checks canonical state, so this replay never panics on it.
            Err(ExecutionError::Stale) => return Err(PrepareBatchesError::Stale),
            Err(ExecutionError::Invalid(reason)) => {
                warn!(?target_digest, block = ?digest, reason, "rebuild replay execution invalid");
                return Err(PrepareBatchesError::Invalid);
            }
            // Parking keeps the flight, so live waiters stay parked instead of re-claiming.
            Err(err @ ExecutionError::Fatal(_)) => {
                panic_unless_stopping(context, "application replay", &err);
                return future::pending().await;
            }
        };

        if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
            warn!(
                ?target_digest,
                block = ?digest,
                "rebuild replay state root must match block commitments"
            );
            return Err(PrepareBatchesError::Invalid);
        }

        self.cache_pending(
            digest,
            PendingEntry {
                round,
                parent: parent_digest,
                merkleized,
                provenance: Provenance::Applied,
            },
        )
        .then_some(())
        .ok_or(PrepareBatchesError::Invalid)
    }

    /// Replays `block` as [`Self::replay`] does, sharing the work with concurrent verifications.
    ///
    /// One request executes the replay and the others wait for its result. If the executing
    /// request is cancelled, a remaining request takes over. A waiter adopts the executing
    /// request's failure.
    async fn replay_shared<C>(
        &self,
        app: &mut A,
        context: &E,
        target_digest: BlockDigest<A, E>,
        block: Arc<A::Block>,
        cancellation: &mut C,
        replays: &ReplayFlights<BlockDigest<A, E>>,
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
                        .replay(
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
                    // Staleness is judged against each request's own view of the anchor, so an
                    // inherited `Stale` re-claims like a finished or abandoned flight.
                    match completion {
                        Ok(Ok(())) | Ok(Err(PrepareBatchesError::Stale)) | Err(_) => continue,
                        Ok(Err(error)) => return Err(error),
                    }
                }
            }
        }
    }

    /// Replays `parent` and its uncached ancestors if `parent` is neither cached nor the processed
    /// anchor, then forks batches from its state.
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
        replays: Option<&ReplayFlights<BlockDigest<A, E>>>,
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
            state.processed.digest == parent_digest || state.pending.contains_key(&parent_digest)
        };
        if !known {
            self.rebuild_pending(app, context, marshal, parent, cancellation, replays)
                .await?;
        }

        self.fork_batches(&parent_digest, cancellation).await
    }

    /// Walks back from `target` to the nearest cached block or the processed anchor, then replays
    /// the uncached blocks in height order.
    ///
    /// Returns [`PrepareBatchesError::Invalid`] if the walk reaches the processed height without
    /// meeting the processed anchor, if `provider` returns a block that is not the parent at the
    /// preceding height, or if a replay fails. Returns [`PrepareBatchesError::Incomplete`] if
    /// `provider` stops before delivering a parent, and [`PrepareBatchesError::Cancelled`] if
    /// `cancellation` fires first.
    async fn rebuild_pending<P, C>(
        &self,
        app: &mut A,
        context: &E,
        provider: P,
        target: Arc<A::Block>,
        cancellation: &mut C,
        replays: Option<&ReplayFlights<BlockDigest<A, E>>>,
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
            let (known, processed) = {
                let state = self.state.lock();
                (
                    cursor.digest() == state.processed.digest
                        || state.pending.contains_key(&cursor.digest()),
                    state.processed,
                )
            };
            if known {
                break;
            }

            let cursor_height = cursor.height();
            if cursor_height <= processed.height {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    current_height = cursor_height.get(),
                    last_processed_height = processed.height.get(),
                    last_processed = ?processed.digest,
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
            let result = if let Some(replays) = replays {
                self.replay_shared(app, context, target_digest, block, cancellation, replays)
                    .await
            } else {
                self.replay(app, context, target_digest, block, cancellation)
                    .await
            };
            // Replays before a failure stay cached.
            if result.is_err() {
                self.update_pending_metric();
            }
            result?;
        }

        self.update_pending_metric();
        let _ = self.metrics.rebuild_pending_depth.try_set(depth);
        timer.observe(context);
        Ok(())
    }

    /// Take the cached merkleized batch for `digest`, if it was executed.
    fn pending_batch(&self, digest: &BlockDigest<A, E>) -> Option<PendingBatches<A, E>> {
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
    /// Dropping dead forks, the anchor move, and the finalizing-window close
    /// happen under one lock. Verification jobs read this state while a block
    /// applies, and a job that saw dead forks already dropped but the anchor
    /// not yet moved would reject work that is still valid.
    fn advance_to_finalized(&self, anchor: Anchor<BlockDigest<A, E>>) {
        let mut state = self.state.lock();
        let compatible = state.descendants(anchor.digest, anchor.round);
        // The finalized block becomes the anchor, so its own entry is not a pruned fork.
        state.pending.remove(&anchor.digest);
        let before = state.pending.len();
        state
            .pending
            .retain(|digest, entry| entry.round > anchor.round && compatible.contains(digest));
        let pruned = before - state.pending.len();
        let remaining = state.pending.len();
        state.processed = anchor;
        state.finalizing = false;
        for waiter in state.anchor_waiters.drain(..) {
            waiter.send_lossy(());
        }
        drop(state);
        self.metrics.pruned_forks.inc_by(pruned as u64);
        let _ = self.metrics.pending_blocks.try_set(remaining);
    }
}

/// Returns whether `block` is the canonical block at its height, at or below the processed height.
///
/// Returns [`PrepareBatchesError::Incomplete`] if marshal lacks the finalized block at a lower
/// height, and [`PrepareBatchesError::Cancelled`] if `cancellation` fires first.
#[tracing::instrument(
    name = "stateful.processor.is_already_processed",
    level = "info",
    skip_all,
    fields(height = block.height().traced(), digest = %block.digest())
)]
async fn is_already_processed<S, V, C>(
    processed: Anchor<<V::ApplicationBlock as Digestible>::Digest>,
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
    if target_height > processed.height {
        return Ok(false);
    }
    if target_height == processed.height {
        return Ok(block.digest() == processed.digest);
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
            processed_height = processed.height.get(),
            "failed to fetch canonical processed block for stale-block check"
        );
        return Err(PrepareBatchesError::Incomplete);
    };

    Ok(canonical.digest() == block.digest())
}

/// Returns the next item of `stream`: `None` if `cancellation` fires first, and `Some(None)` if
/// the stream has ended.
#[tracing::instrument(name = "stateful.processor.fetch_ancestor", level = "info", skip_all)]
async fn fetch_ancestor<C, T, S>(cancellation: &mut C, stream: &mut S) -> Option<Option<T>>
where
    S: Stream<Item = T> + Unpin,
    C: Cancellation,
{
    await_or_cancel(cancellation, stream.next()).await
}

/// Panics with `err` unless shutdown has fired.
///
/// A stopping runtime can fail an application dependency mid-operation, so once shutdown is
/// observed the caller parks instead of reporting a crash.
fn panic_unless_stopping(context: &impl Spawner, operation: &str, err: &ExecutionError) {
    if context.stopped().now_or_never().is_none() {
        panic!("{operation} failed: {err}");
    }
    warn!(%err, "{operation} failed during shutdown");
}

/// Returns the output of `future`, or `None` if `cancellation` fires first.
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
        Applied, BlockDigest, Clock, Metrics, PendingBatches, PendingEntry, PrepareBatchesError,
        Processor, Provenance, Prune, Pruning, Publication, ReplayClaim, ReplayFlights, Rng,
        Spawner, fetch_ancestor,
    };

    impl<D: Copy + Ord> ReplayFlights<D> {
        /// Whether no replay is in flight.
        fn is_empty(&self) -> bool {
            self.entries.lock().is_empty()
        }
    }

    impl<E, A> Processor<E, A>
    where
        E: Rng + Spawner + Metrics + Clock,
        A: Application<E>,
    {
        fn readers(&self) -> ReadersOf<A::Databases, E> {
            self.execution.readers.clone()
        }

        fn cache_pending(
            &self,
            digest: BlockDigest<A, E>,
            parent: BlockDigest<A, E>,
            round: Round,
            merkleized: PendingBatches<A, E>,
            provenance: Provenance,
        ) -> bool {
            self.execution.cache_pending(
                digest,
                PendingEntry {
                    round,
                    parent,
                    merkleized,
                    provenance,
                },
            )
        }
    }
    use crate::stateful::{
        Application, ExecutionError, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{
            Anchor, Barrier, DatabaseSet, Merkleized as _, MerkleizedOf, ReadersOf, Single,
            SyncTargetsOf, UnmerkleizedOf,
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
    use futures::{FutureExt as _, StreamExt};
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

    impl<S> Publication<S> {
        /// The barrier this publication started, if any.
        fn into_barrier(self) -> Option<Barrier> {
            match self {
                Self::WithBarrier(_, barrier) => Some(barrier),
                Self::None | Self::Snapshot(_) => None,
            }
        }
    }

    async fn assert_durable(barrier: Option<Barrier>) {
        assert!(
            barrier
                .expect("finalization must start durability")
                .durable()
                .await,
            "database barrier must complete",
        );
    }

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;

    const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
    const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

    type Qmdb<E> =
        any::unordered::fixed::Db<mmr::Family, E, Digest, Digest, Sha256, TwoCap, Sequential>;
    type DbSet<E> = Single<Qmdb<E>>;
    type TestMerkleized =
        <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized;
    type TestUnmerkleized =
        <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Unmerkleized;

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
            buf: &mut impl commonware_codec::Buf,
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

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
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

    /// Makes `apply` of `target` fail with fatal storage, firing shutdown first if `stop` is set.
    #[derive(Clone, Copy)]
    struct FatalApply {
        target: Digest,
        stop: bool,
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
    struct Captured {
        prior_counter: Option<u64>,
        batch_counter: u64,
        batch_view: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FinalizedObservation {
        captured: Captured,
        post_counter: u64,
        post_view: u64,
    }

    #[derive(Clone)]
    struct ExecutionApp {
        genesis: Block,
        finalized_observer: Option<Arc<Mutex<Vec<FinalizedObservation>>>>,
        apply_probe: Option<ApplicationProbe>,
        finalized_probe: Option<ApplicationProbe>,
        fatal_apply: Option<FatalApply>,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
                finalized_observer: None,
                apply_probe: None,
                finalized_probe: None,
                fatal_apply: None,
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
                    fatal_apply: None,
                },
                observations,
            )
        }

        async fn execute(
            height: Height,
            view: View,
            mut batches: UnmerkleizedOf<DbSet<deterministic::Context>, deterministic::Context>,
        ) -> Result<
            MerkleizedOf<DbSet<deterministic::Context>, deterministic::Context>,
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
        type Databases = DbSet<deterministic::Context>;
        type Captured = Captured;
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
            context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: UnmerkleizedOf<Self::Databases, deterministic::Context>,
        ) -> Result<Option<MerkleizedOf<Self::Databases, deterministic::Context>>, ExecutionError>
        {
            if let Some(probe) = &self.apply_probe {
                probe.call(block.digest()).await;
            }
            if let Some(fatal) = self.fatal_apply
                && fatal.target == block.digest()
            {
                if fatal.stop {
                    // Polling `stop` once fires the signal.
                    let _ = context.0.stop(0, None).now_or_never();
                }
                return Err(ExecutionError::Fatal("disk failed".into()));
            }
            Self::execute(block.height(), block.context.round.view(), batches)
                .await
                .map(Some)
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: &TestMerkleized,
            readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) -> Self::Captured {
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
            let batch_view = pending
                .get(&height_key(block.height()))
                .await
                .expect("batch read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("winning batch should contain its view");
            Captured {
                prior_counter,
                batch_counter,
                batch_view,
            }
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            captured: Self::Captured,
            readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
            if let Some(probe) = &self.finalized_probe {
                probe.call(block.digest()).await;
            }
            let Some(observer) = &self.finalized_observer else {
                return;
            };
            let db = readers.read().await;
            let post_view = db
                .get(&height_key(block.height()))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("finalized view should be reflected in the database set");
            let post_counter = db
                .get(&counter_key())
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
                .expect("finalized counter should be reflected in the database set");
            drop(db);
            let observation = FinalizedObservation {
                captured,
                post_counter,
                post_view,
            };
            observer.lock().push(observation);
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
            Self::with_app_pruned(context, provider, config, app, None).await
        }

        async fn with_app_pruned(
            context: deterministic::Context,
            provider: MapProvider,
            config: any::FixedConfig<TwoCap, Sequential>,
            app: ExecutionApp,
            prune_config: Option<PruneConfig>,
        ) -> Self {
            let databases = DbSet::<deterministic::Context>::init(
                context.child("databases"),
                config.clone(),
                None,
            )
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
                    prune_config.map(|config| Pruning::new(config, 1, 0)),
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
            self.stage_pending_child_with_state(parent, view, view)
                .await
        }

        /// Stages a child at `view` whose execution writes `state_view`, so siblings built with
        /// the same `state_view` commit to identical state.
        async fn stage_pending_child_with_state(
            &mut self,
            parent: &Block,
            view: View,
            state_view: View,
        ) -> Block {
            let context = consensus_context(parent.digest(), view);
            let height = parent.height().next();
            let batches = self.fork_from(parent).await;
            let merkleized = ExecutionApp::execute(height, state_view, batches)
                .await
                .unwrap();
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
            let round = Round::new(Epoch::zero(), view);
            assert!(self.processor.cache_pending(
                block.digest(),
                parent.digest(),
                round,
                merkleized,
                Provenance::Verified,
            ));
            self.provider.insert(block.clone());
            block
        }

        /// Applies `block` and waits for its database barrier.
        ///
        /// Returns `false` without applying redelivered blocks.
        #[boxed]
        async fn finalize(mut self, block: Block) -> (Self, bool) {
            if self.processor.redelivered(&block) {
                return (self, false);
            }
            let applied;
            (self.processor, applied) = self
                .processor
                .finalize(self.context_cell.as_present(), &block, true)
                .await;
            assert_durable(applied.publication.into_barrier()).await;
            (self, true)
        }

        #[boxed]
        async fn finalize_with_prune(
            mut self,
            block: Block,
        ) -> (
            Self,
            Option<Prune<SyncTargetsOf<DbSet<deterministic::Context>, deterministic::Context>>>,
        ) {
            let applied;
            (self.processor, applied) = self
                .processor
                .finalize(self.context_cell.as_present(), &block, true)
                .await;
            let Applied { publication, prune } = applied;
            let barrier = publication.into_barrier();
            assert_durable(barrier).await;
            (self, prune)
        }

        async fn view_at_height(&self, height: Height) -> Option<u64> {
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

        async fn reopen_view_at_height(
            self,
            context: deterministic::Context,
            height: Height,
        ) -> Option<u64> {
            let Self {
                processor,
                db_config,
                ..
            } = self;
            drop(processor);
            let reopened: Qmdb<deterministic::Context> =
                Qmdb::init(context.child("reopen_db"), db_config, None)
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
            init_cache: Some(NZUsize!(1024)),
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
        let mut pruning = Pruning::new(config, 2, 0);

        assert_eq!(pruning.observe(Height::new(1), 10_u64), None,);
        assert_eq!(pruning.observe(Height::new(2), 20_u64), None,);
        assert_eq!(pruning.observe(Height::new(3), 30_u64), None,);
        assert_eq!(
            pruning.observe(Height::new(4), 40_u64),
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
        let mut pruning = Pruning::new(config, 1, 0);

        assert_eq!(pruning.observe(Height::new(1), 10_u64), None,);
        assert_eq!(pruning.observe(Height::new(2), 20_u64), None,);
        assert_eq!(
            pruning.observe(Height::new(3), 30_u64),
            Some(Prune {
                marshal_height: Height::new(1),
                barrier_height: Height::new(1),
                qmdb_target: 10,
            }),
        );
        assert_eq!(
            pruning.observe(Height::new(4), 40_u64),
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
        let mut pruning = Pruning::new(config, 1, 0);

        assert_eq!(pruning.observe(Height::new(1), 10_u64), None);
        assert_eq!(pruning.observe(Height::new(2), 20_u64), None);
        assert_eq!(pruning.observe(Height::new(3), 30_u64), None);
        assert_eq!(pruning.observe(Height::new(4), 40_u64), None);
        assert_eq!(pruning.observe(Height::new(5), 50_u64), None);
        assert_eq!(
            pruning.observe(Height::new(6), 60_u64),
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
        let mut pruning = Pruning::new(config, 1, 2);

        for height in 1..=6 {
            assert_eq!(pruning.observe(Height::new(height), height * 10), None);
        }
        assert_eq!(
            pruning.observe(Height::new(7), 70),
            Some(Prune {
                marshal_height: Height::new(5),
                barrier_height: Height::new(6),
                qmdb_target: 60,
            }),
        );
        for height in 8..=11 {
            assert_eq!(pruning.observe(Height::new(height), height * 10), None);
        }
        assert_eq!(
            pruning.observe(Height::new(12), 120),
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

    /// A replay cancelled while its fork waits for read access behind a busy writer returns at
    /// once and releases its replay flight, instead of waiting for the writer.
    #[test]
    fn cancelled_replay_releases_flight_while_writer_is_busy() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            let cfg = qmdb_config("held-writer", &context);
            let db = Qmdb::init(context.child("held_db"), cfg, None)
                .await
                .unwrap();
            let writer = crate::stateful::db::Writer::new("held-writer", db);
            harness.processor.execution.readers = writer.reader();
            let (release, released) = oneshot::channel::<()>();
            let mut mutation = Box::pin(writer.mutate(|db| async move {
                let _ = released.await;
                (db, ())
            }));
            assert!(futures::poll!(&mut mutation).is_pending());

            let replays = ReplayFlights::default();
            let (mut cancellation, cancelled) = oneshot::channel::<()>();
            let execution = &harness.processor.execution;
            let mut replay = Box::pin(execution.replay_shared(
                &mut harness.processor.app,
                &context,
                block.digest(),
                Arc::new(block),
                &mut cancellation,
                &replays,
            ));
            assert!(futures::poll!(&mut replay).is_pending());
            assert!(!replays.is_empty());
            drop(cancelled);
            assert!(
                matches!(
                    futures::poll!(&mut replay),
                    std::task::Poll::Ready(Err(PrepareBatchesError::Cancelled))
                ),
                "caller cancellation must not wait for the database writer"
            );
            assert!(
                replays.is_empty(),
                "cancelled owner must release its replay flight"
            );
            release.send(()).unwrap();
            let (_writer, ()) = mutation.await;
        });
    }

    /// Fatal storage in an ancestor replay without shutdown panics.
    #[test]
    #[should_panic(expected = "application replay failed")]
    fn fatal_replay_panics() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            harness.processor.app.fatal_apply = Some(FatalApply {
                target: block.digest(),
                stop: false,
            });
            let replays = ReplayFlights::default();
            let (mut live, _cancelled) = oneshot::channel::<()>();
            let _ = harness
                .processor
                .execution
                .replay_shared(
                    &mut harness.processor.app,
                    &context,
                    block.digest(),
                    Arc::new(block),
                    &mut live,
                    &replays,
                )
                .await;
        });
    }

    /// Fatal storage in an ancestor replay after shutdown fired in the same poll parks the
    /// owner with its flight, so a live waiter stays parked instead of re-claiming it.
    #[test]
    fn fatal_replay_during_shutdown_parks_owner_and_waiter() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            let (gate, started, release) = apply_gate();
            let probe = ApplicationProbe::new(block.digest(), [gate]);
            harness.processor.app.apply_probe = Some(probe.clone());
            harness.processor.app.fatal_apply = Some(FatalApply {
                target: block.digest(),
                stop: true,
            });
            let replays = ReplayFlights::default();
            let execution = &harness.processor.execution;
            let block = Arc::new(block);

            // The owner parks on the apply gate while a second request waits on its flight.
            let mut owner_app = harness.processor.app.clone();
            let (mut owner_live, _owner_cancelled) = oneshot::channel::<()>();
            let mut owner = Box::pin(execution.replay_shared(
                &mut owner_app,
                &context,
                block.digest(),
                block.clone(),
                &mut owner_live,
                &replays,
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            started.await.expect("owner must reach apply");
            let mut waiter_app = harness.processor.app.clone();
            let (mut waiter_live, _waiter_cancelled) = oneshot::channel::<()>();
            let mut waiter = Box::pin(execution.replay_shared(
                &mut waiter_app,
                &context,
                block.digest(),
                block.clone(),
                &mut waiter_live,
                &replays,
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            // Releasing the gate fires shutdown and fails the apply in the owner's next poll.
            release.send(()).expect("owner is parked");
            for _ in 0..8 {
                assert!(futures::poll!(&mut owner).is_pending());
                assert!(futures::poll!(&mut waiter).is_pending());
            }
            assert!(context.stopped().now_or_never().is_some());
            assert_eq!(probe.calls(), 1, "the waiter must not re-claim the replay");
            assert!(!replays.is_empty(), "the parked owner keeps its flight");
        });
    }

    /// Cancelled anchor waiters are dropped at the next registration, so churn inside one
    /// finalizing window keeps at most one dead sender, and the anchor move wakes every live one.
    #[test]
    fn anchor_waiters_drop_cancelled_registrations() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;

            // Park the finalize inside its window.
            let (gate, started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let verifier = harness.processor.verifier();
            let execution = &verifier.execution;
            let processor = harness.processor;
            let finalize = processor.finalize(harness.context_cell.as_present(), &winner, true);
            futures::pin_mut!(finalize);
            select! {
                _ = &mut finalize => panic!("finalize must park on the probe"),
                result = started => result.expect("finalize must reach the probe"),
            }
            let seen = execution.processed();
            let waiters = || execution.state.lock().anchor_waiters.len();

            // Sequential churn: each registration drops the previous cancelled one.
            for _ in 0..8 {
                let mut waiter = Box::pin(execution.anchor_past(&seen));
                assert!(futures::poll!(&mut waiter).is_pending());
                drop(waiter);
                assert_eq!(waiters(), 1);
            }

            // A burst of cancellations stays until the next registration.
            let mut burst = Vec::new();
            for _ in 0..4 {
                let mut waiter = Box::pin(execution.anchor_past(&seen));
                assert!(futures::poll!(&mut waiter).is_pending());
                burst.push(waiter);
            }
            drop(burst);
            assert_eq!(waiters(), 4);
            let mut live = Box::pin(execution.anchor_past(&seen));
            assert!(futures::poll!(&mut live).is_pending());
            assert_eq!(waiters(), 1);

            // The anchor move wakes the live waiter and empties the list.
            release.send(()).expect("finalize is parked");
            let (processor, applied) = finalize.await;
            assert_eq!(waiters(), 0);
            live.await;
            assert_durable(applied.publication.into_barrier()).await;
            drop(processor);
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
            let finalize = processor.finalize(harness.context_cell.as_present(), &winner, true);
            futures::pin_mut!(finalize);
            select! {
                _ = &mut finalize => panic!("finalize must park on the probe"),
                result = started => result.expect("finalize must reach the probe"),
            }

            // Inside the window, a fork from the anchor must refuse, since the databases
            // are already at the winner, but the anchor still names genesis.
            let (mut never, _live) = oneshot::channel::<()>();
            assert!(matches!(
                verifier
                    .execution
                    .fork_batches(&genesis.digest(), &mut never)
                    .await,
                Err(PrepareBatchesError::Stale)
            ));

            release.send(()).expect("finalize is parked");
            let (processor, applied) = finalize.await;
            assert_durable(applied.publication.into_barrier()).await;
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

    /// A verification batch forked from a branch that a finalization dropped refuses as stale,
    /// so the verifier re-checks the candidate against the canonical chain instead of answering
    /// from dead state. A losing branch with the winner's exact state (`identical`) is the same
    /// state by commitment, so its execution proceeds and matches the winner's branch.
    #[rstest::rstest]
    #[case::distinct_parent(1, false)]
    #[case::identical_parent(1, true)]
    #[case::distinct_grandparent(2, false)]
    #[case::identical_grandparent(2, true)]
    fn finalized_away_fork_refuses_unless_state_matches(
        #[case] depth: u64,
        #[case] identical: bool,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // The losing branch starts at the winner's height. Every block on it shares the
            // winner's state view when `identical` is set.
            let state_view = |view: u64| View::new(if identical { 1 } else { view });
            let mut losing = harness
                .stage_pending_child_with_state(&genesis, View::new(2), state_view(2))
                .await;
            for view in 3..2 + depth {
                losing = harness
                    .stage_pending_child_with_state(&losing, View::new(view), state_view(view))
                    .await;
            }
            let candidate = harness.fork_from(&losing).await;
            let winner = harness
                .stage_pending_child_with_state(&genesis, View::new(1), View::new(1))
                .await;

            let applied;
            (harness, applied) = harness.finalize(winner.clone()).await;
            assert!(applied);
            assert!(!harness.processor.pending_contains(&losing.digest()));

            let height = Height::new(depth + 1);
            let result = ExecutionApp::execute(height, state_view(2 + depth), candidate).await;
            if identical {
                let mut expected = harness.fork_from(&winner).await;
                for level in 2..=depth {
                    let merkleized =
                        ExecutionApp::execute(Height::new(level), state_view(level), expected)
                            .await
                            .expect("the winner's branch executes");
                    expected = merkleized.new_batch();
                }
                let expected = ExecutionApp::execute(height, state_view(2 + depth), expected)
                    .await
                    .expect("the winner's branch executes");
                let result = result.expect("identical state is not stale");
                assert_eq!(result.root(), expected.root());
            } else {
                assert!(matches!(result, Err(ExecutionError::Stale)));
            }
            drop(harness);
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);
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
            assert_eq!(harness.processor.processed().digest, winner.digest());
            assert_eq!(harness.view_at_height(Height::new(2)).await, Some(3));
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork_descendants() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);
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
            assert_eq!(
                harness.processor.execution.metrics.pruned_forks.get(),
                2,
                "finalized blocks are not counted as pruned forks",
            );
        });
    }

    /// The block being finalized stays reachable as a parent while it
    /// applies, so a job forking from it mid-apply does not rebuild it on top
    /// of itself.
    #[test]
    fn finalized_block_stays_forkable_while_it_applies() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;

            // A job's view of the world, taken before the apply starts.
            let execution = harness.processor.execution.clone();

            // Park the finalization inside its `finalized` hook. The database
            // apply is done, and the anchor has not moved yet.
            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &winner,
                true,
            ));
            select! {
                _ = &mut finalize => panic!("finalize completed before its finalized hook returned"),
                result = &mut started => result.expect("finalized hook should start"),
            }

            let (mut never, _live) = oneshot::channel::<()>();
            assert!(
                execution
                    .fork_batches(&winner.digest(), &mut never)
                    .await
                    .is_ok(),
                "the applying block must stay forkable for jobs that are still running",
            );

            release
                .send(())
                .expect("finalized hook should remain active");
            let (_processor, applied) = finalize.await;
            let barrier = applied.publication.into_barrier();
            assert_durable(barrier).await;
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
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &block,
                true,
            ));
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
            let barrier = applied.publication.into_barrier();
            assert_durable(barrier).await;
        });
    }

    #[test]
    fn execution_rejects_late_losing_fork_publication() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied;
            (harness, applied) = harness.finalize(block1.clone()).await;
            assert!(applied);
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
                    Provenance::Verified,
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

            // Reconstruction runs `apply`, not `verify`, so the rebuilt state is
            // available as a speculative parent but is not a verification verdict.
            // A later verification of these digests must not be short-circuited.
            assert!(
                !harness.processor.pending_verified(&block2.digest()),
                "replayed ancestor must not count as verified",
            );
            assert!(
                !harness.processor.pending_verified(&block3.digest()),
                "replayed target must not count as verified",
            );
        });
    }

    /// A real `verify` verdict promotes speculative replay state to verified so a
    /// later certification of that digest can fast-answer honestly, and `apply`
    /// replay never demotes an entry that already verified.
    #[test]
    fn cache_pending_provenance_promotes_but_never_demotes() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Stage a replayed (apply-provenance) child of the applied anchor.
            let (replayed, replayed_merkleized) = harness.build_child(&genesis, View::new(1)).await;
            let replayed_round = Round::new(Epoch::zero(), View::new(1));
            assert!(harness.processor.cache_pending(
                replayed.digest(),
                genesis.digest(),
                replayed_round,
                replayed_merkleized,
                Provenance::Applied,
            ));
            assert!(harness.processor.pending_contains(&replayed.digest()));
            assert!(
                !harness.processor.pending_verified(&replayed.digest()),
                "apply-provenance state must not read as verified",
            );

            // A genuine verification of the same digest promotes it.
            let (_, verified_merkleized) = harness.build_child(&genesis, View::new(1)).await;
            assert!(harness.processor.cache_pending(
                replayed.digest(),
                genesis.digest(),
                replayed_round,
                verified_merkleized,
                Provenance::Verified,
            ));
            assert!(
                harness.processor.pending_verified(&replayed.digest()),
                "a real verify verdict must promote replayed state",
            );

            // A later replay of the same digest must not demote it back.
            let (_, replay_again) = harness.build_child(&genesis, View::new(1)).await;
            assert!(harness.processor.cache_pending(
                replayed.digest(),
                genesis.digest(),
                replayed_round,
                replay_again,
                Provenance::Applied,
            ));
            assert!(
                harness.processor.pending_verified(&replayed.digest()),
                "apply replay must not demote already-verified state",
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
                    .claim_replay(&replays, harness.processor.processed().digest),
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
                        && flight.vacant.len() == 2),
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

    /// Marshal delivers a finalized chain, so a block at the next height whose parent is not the
    /// processed anchor is a contract violation. Its commitments can still match the applied
    /// state, so finalization panics instead of applying it to a state it does not extend.
    #[test]
    #[should_panic(expected = "finalized block does not extend the applied tip")]
    fn execution_finalize_panics_on_unlinked_successor() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Finalize one of two siblings at height 1.
            let canonical = harness.stage_pending_child(&genesis, View::new(1)).await;
            let sibling = harness.stage_pending_child(&genesis, View::new(2)).await;
            let applied;
            (harness, applied) = harness.finalize(canonical.clone()).await;
            assert!(applied);

            // Build a height 2 block on the canonical state, then point it at the sibling.
            let (child, _) = harness.build_child(&canonical, View::new(3)).await;
            let unlinked = Block {
                context: consensus_context(sibling.digest(), View::new(3)),
                parent: sibling.digest(),
                ..child
            };
            let _ = harness.finalize(unlinked).await;
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
                    .reopen_view_at_height(context.child("reopen"), Height::new(1))
                    .await,
                Some(1),
                "height state should survive reopen after finalization",
            );
        });
    }

    #[test]
    fn execution_finalized_handoff_preserves_cached_and_reconstructed_captures() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, observations) =
                Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(7)).await;
            let block2 = harness.stage_pending_child(&block1, View::new(11)).await;

            let cached_probe = ApplicationProbe::new(block1.digest(), []);
            harness.processor.app.apply_probe = Some(cached_probe.clone());
            let applied;
            (harness, applied) = harness.finalize(block1).await;
            assert!(applied);
            assert_eq!(
                cached_probe.calls(),
                0,
                "block1 should use its cached merkleized batch",
            );
            harness.processor.clear_pending();
            let reconstructed_probe = ApplicationProbe::new(block2.digest(), []);
            harness.processor.app.apply_probe = Some(reconstructed_probe.clone());
            let (_, applied) = harness.finalize(block2).await;
            assert!(applied);
            assert_eq!(
                reconstructed_probe.calls(),
                1,
                "block2 should be reconstructed through Application::apply",
            );

            assert_eq!(
                observations.lock().as_slice(),
                [
                    FinalizedObservation {
                        captured: Captured {
                            prior_counter: None,
                            batch_counter: 1,
                            batch_view: 7,
                        },
                        post_counter: 1,
                        post_view: 7,
                    },
                    FinalizedObservation {
                        captured: Captured {
                            prior_counter: Some(1),
                            batch_counter: 2,
                            batch_view: 11,
                        },
                        post_counter: 2,
                        post_view: 11,
                    },
                ],
                "capture should see pre-apply state and finalized should receive the captured value after apply",
            );
        });
    }

    #[test]
    fn execution_duplicate_finalization_skips_hooks() {
        deterministic::Runner::default().start(|context| async move {
            let (mut harness, observations) = Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let block = harness.stage_pending_child(&genesis, View::new(1)).await;

            let applied;
            (harness, applied) = harness.finalize(block.clone()).await;
            assert!(applied);
            observations.lock().clear();
            let (_, applied) = harness.finalize(block).await;
            assert!(!applied);

            assert!(observations.lock().is_empty());
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
