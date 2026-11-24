//! Speculative execution for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] executes blocks on the applied database set and caches the resulting state
//! of unfinalized blocks by block digest. Outside finalization, the _branch anchor_ is the last
//! block the processor finalized, and the databases hold its state. Finalization advances the
//! anchor once the finalized block's merkleized state is ready and keeps that state cached until
//! the application's `finalized` hook returns, so descendants can fork from it while the
//! databases change.
//!
//! - Prepare and propose: the [`Application`] builds on batches forked from the parent's cached
//!   state, or from the applied databases when the parent is the branch anchor. The built state
//!   must match the block's commitments, and it is cached.
//! - Verify: [`Application::process`] processes the block on its parent's state as a
//!   [`Finality::Candidate`]. The block is valid if the application accepts it and the result
//!   matches its commitments. A cached state answers later verifications of its block.
//! - Recovery: when a parent's state is not cached (for example after a restart), the parent and
//!   its missing ancestors are processed in height order as candidates, starting above the
//!   nearest cached ancestor or the branch anchor. A recovered state is cached only if it matches
//!   its block's commitments. Concurrent requests that need the same block's state, including a
//!   verification of that block, share one processing call.
//! - Finalization: if the finalized block is still processing, its finalization joins that
//!   processing and reuses the result. Processing on competing branches is not awaited. It fails
//!   at its next storage call once the block applies, and its requests start over. The processor
//!   publishes snapshots after the finalization hook completes. The caller coordinates
//!   durability, so one database barrier can cover several finalizations.

use crate::stateful::{
    Application, ExecutionError, Finality, Input, Proposed, PruneConfig,
    actor::{BlockDigest, SyncTargets, core::Proposal, metrics::Metrics as StatefulMetrics},
    db::{Anchor, Barrier, DatabaseSet, Publisher, SnapshotsOf},
};
use commonware_consensus::{
    Block, CertifiableBlock, Handoff, Heightable, Roundable,
    marshal::{
        ancestry::{AncestorStream, Ancestry, BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::{Height, Round},
};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_macros::{boxed, select};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Spawner,
    signal::Signal,
    telemetry::metrics::{GaugeExt, histogram::Timer},
};
use commonware_utils::{Widen, channel::fallible::OneshotExt, sync::Mutex};
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared, WeakShared},
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::{Future, poll_fn},
    sync::Arc,
};
use tracing::{Instrument as _, debug, info_span, warn};

mod verifier;
pub(super) use verifier::{Prepared, Verifier};

type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;
type Unmerkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Unmerkleized;
type Readers<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Readers;

const DATABASES_LOST: &str =
    "database set used after an interrupted mutation, which must have stopped the actor";
type PendingMap<A, E> = BTreeMap<BlockDigest<A, E>, PendingEntry<A, E>>;
type FlightResult = Result<(), PrepareBatchesError>;

/// Candidate processing of one block, awaited by every request that needs the block's state.
///
/// The processing stays alive while any handle does, and dropping the last handle cancels it.
/// Every handle that awaits a completed flight receives its result.
type Flight = Shared<BoxFuture<'static, FlightResult>>;

/// Missing blocks between cached or applied state and a requested block, processed oldest first.
struct ReplayPath<B: Block> {
    /// Missing blocks, newest first, so the next block to process is at the end.
    blocks: Vec<Digested<B>>,

    /// Parent of the next block to process.
    parent: Digested<B>,

    /// Round of the block the path leads to. Every request for the path's ancestry carries it
    /// as its bound.
    bound: Round,

    /// Recovery timer and path depth, recorded once the path is exhausted.
    measurement: Option<(Timer, usize)>,
}

/// Cached speculative state for a block digest.
struct PendingEntry<A, E>
where
    A: Application<E>,
{
    round: Round,
    parent: BlockDigest<A, E>,
    merkleized: PendingBatches<A, E>,
}

/// Speculative state shared by the processor and its verifiers.
struct ExecutionState<A, E>
where
    A: Application<E>,
{
    /// Merkleized state for unfinalized blocks and the root of an active finalization.
    pending: PendingMap<A, E>,
    /// Candidate processing in flight, at most one per block digest. Requests can share a call
    /// because the digest commits to the block's embedded context. Each flight removes its own
    /// entry when it completes or is cancelled, so the map holds only live flights.
    flights: BTreeMap<BlockDigest<A, E>, WeakShared<BoxFuture<'static, FlightResult>>>,
    /// The branch anchor. During finalization its batch also stays in `pending`.
    branch: Anchor<BlockDigest<A, E>>,
}

impl<A, E> ExecutionState<A, E>
where
    A: Application<E>,
{
    fn speculative_len(&self) -> usize {
        self.pending.len() - usize::from(self.pending.contains_key(&self.branch.digest))
    }

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

/// Database readers, speculative state, and metrics shared by the processor and its verifiers.
struct Execution<E, A>
where
    A: Application<E>,
{
    readers: Readers<A, E>,
    state: Arc<Mutex<ExecutionState<A, E>>>,
    metrics: StatefulMetrics,
}

impl<E, A> Clone for Execution<E, A>
where
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

/// Removes a flight's registry entry once its processing completes or is cancelled.
///
/// The request handler serializes flight admission and destruction. Cleanup finishes
/// before another flight for the same digest can be registered.
struct FlightGuard<A, E>
where
    A: Application<E>,
{
    state: Arc<Mutex<ExecutionState<A, E>>>,
    digest: BlockDigest<A, E>,
}

impl<A, E> Drop for FlightGuard<A, E>
where
    A: Application<E>,
{
    fn drop(&mut self) {
        self.state.lock().flights.remove(&self.digest);
    }
}

/// Failures while acquiring or processing state for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrepareBatchesError {
    /// The block or its ancestry is invalid.
    Invalid,
    /// Ancestry ended before the required state could be recovered.
    Incomplete,
    /// A finalization moved the branch anchor past the state the request built on. The request
    /// acquires its blocks again against the new anchor.
    Stale,
}

/// Result of applying a newly finalized block.
pub(super) struct Applied<T> {
    /// Barrier covering the block, present only when the caller requested one.
    pub(super) barrier: Option<Barrier>,

    /// Prune that became due with this finalization.
    pub(super) prune: Option<Prune<T>>,
}

/// Panics with `failure`, unless `stopped` has fired. A stopping runtime can fail storage
/// mid-operation, so a failure during shutdown is logged instead and the operation never
/// completes.
async fn fail_unless_stopped<T>(stopped: Signal, failure: String) -> T {
    if stopped.now_or_never().is_some() {
        warn!(failure, "abandoning a failed operation during shutdown");
        return std::future::pending().await;
    }
    panic!("{failure}");
}

/// Marshal and database prune targets selected from finalized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prune<T> {
    marshal_height: Height,
    /// Finalized height whose sync targets are the database prune target.
    pub(super) barrier_height: Height,
    qmdb_target: T,
}

impl<T> Prune<T> {
    /// Prunes the databases to the sync targets at `barrier_height`, then prunes marshal.
    ///
    /// The caller must ensure a completed database barrier covers `barrier_height` and that no
    /// database barrier is active.
    async fn run<E, DBs, S, V>(self, databases: DBs, marshal: &MarshalMailbox<S, V>) -> DBs
    where
        DBs: DatabaseSet<E, SyncTargets = T>,
        S: Scheme,
        V: MarshalVariant,
    {
        let databases = databases.prune(&self.qmdb_target).await;
        marshal.prune(self.marshal_height);
        databases
    }
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
        let interval: u64 = Widen::widen(config.maintenance_interval.get());
        let offset = rng.next_u64() % interval;
        Self::new(config, max_pending_acks, offset)
    }

    /// Creates a schedule that prunes at heights congruent to `offset` modulo the maintenance
    /// interval.
    ///
    /// Panics if `config` is invalid, `offset` is not below the interval, or a window overflows.
    pub(super) fn new(config: PruneConfig, max_pending_acks: usize, offset: u64) -> Self {
        config.assert_valid();
        let interval: u64 = Widen::widen(config.maintenance_interval.get());
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
pub(super) struct Processor<E, A, T>
where
    A: Application<E>,
{
    app: A,
    /// The database set, absent once a mutation was interrupted.
    databases: Option<A::Databases>,
    execution: Execution<E, A>,
    pruning: Option<Pruning<SyncTargets<A, E>>>,
    publisher: Publisher<SnapshotsOf<A::Databases, E>>,
    strategy: T,
}

impl<E, A, T> Processor<E, A, T>
where
    E: Spawner + Clock,
    A: Application<E>,
    T: Strategy,
{
    /// Creates a processor whose `databases` hold the applied state of `anchor`.
    pub(super) fn new(
        app: A,
        databases: A::Databases,
        anchor: Anchor<BlockDigest<A, E>>,
        metrics: StatefulMetrics,
        pruning: Option<Pruning<SyncTargets<A, E>>>,
        publisher: Publisher<SnapshotsOf<A::Databases, E>>,
        strategy: T,
    ) -> Self {
        const {
            assert!(
                !A::Databases::CHEAP_SNAPSHOT || A::Databases::ANY_CHEAP_SNAPSHOT,
                "CHEAP_SNAPSHOT requires ANY_CHEAP_SNAPSHOT"
            );
        }
        Self {
            app,
            execution: Execution {
                readers: databases.readers(),
                state: Arc::new(Mutex::new(ExecutionState {
                    pending: BTreeMap::new(),
                    flights: BTreeMap::new(),
                    branch: anchor,
                })),
                metrics,
            },
            databases: Some(databases),
            pruning,
            publisher: publisher.with_merge(A::Databases::merge_snapshots),
            strategy,
        }
    }

    /// Returns a verifier that shares this processor's speculative state.
    pub(super) fn verifier(&self) -> Verifier<E, A> {
        Verifier {
            app: self.app.clone(),
            execution: self.execution.clone(),
        }
    }

    /// Returns read-only handles to the database set.
    pub(super) fn readers(&self) -> Readers<A, E> {
        self.execution.readers.clone()
    }

    /// Takes the database set for a by-value mutation. Until the caller restores it, the set
    /// counts as lost.
    const fn take_databases(&mut self) -> A::Databases {
        self.databases.take().expect(DATABASES_LOST)
    }

    /// Prunes the databases and marshal to `prune`'s targets (see [`Prune::run`]).
    #[boxed]
    pub(super) async fn prune<S, V>(
        &mut self,
        prune: Prune<SyncTargets<A, E>>,
        marshal: &MarshalMailbox<S, V>,
    ) where
        S: Scheme,
        V: MarshalVariant,
    {
        let databases = self.take_databases();
        self.databases = Some(prune.run(databases, marshal).await);
    }

    /// Returns the current branch anchor.
    pub(super) fn branch_anchor(&self) -> Anchor<BlockDigest<A, E>> {
        self.execution.branch_anchor()
    }

    /// Capture a snapshot of the database set's applied state and publish it at the branch
    /// anchor's height.
    #[boxed]
    pub(super) async fn publish_snapshot(&mut self) {
        let (databases, snapshots) = self.take_databases().snapshot().await;
        self.databases = Some(databases);
        self.publisher
            .publish(self.execution.branch_anchor().height, snapshots);
    }

    /// Capture and publish applied state, and start the barrier that makes it durable.
    ///
    /// The caller must await the previous barrier before starting another.
    #[boxed]
    pub(super) async fn start_sync(&mut self) -> Barrier {
        let (databases, snapshots, barrier) = self.take_databases().finalize().await;
        self.databases = Some(databases);
        self.publisher
            .publish(self.execution.branch_anchor().height, snapshots);
        barrier
    }

    /// Refresh a mixed set's cheap members at `height`, retaining its other served snapshots.
    /// Does nothing before the first publish.
    async fn refresh_snapshot(&mut self, height: Height) {
        let Some(served) = self.publisher.served() else {
            return;
        };
        let (databases, snapshots) = self.take_databases().refresh_cheap(&served).await;
        self.databases = Some(databases);
        // Drop our reference before replacement releases the old served set.
        drop(served);
        self.publisher.refresh(height, snapshots);
    }

    #[cfg(test)]
    fn pending_contains(&self, digest: &BlockDigest<A, E>) -> bool {
        self.execution.pending_contains(digest)
    }

    #[cfg(test)]
    fn clear_pending(&self) {
        self.execution.state.lock().pending.clear();
        let _ = self.execution.metrics.pending_blocks.try_set(0);
    }

    /// Builds a proposal on the first block of `ancestry` and answers `proposal`.
    ///
    /// The caller must recover the parent, place it at the front of `ancestry`, and run no
    /// finalization until this call returns. A built block's state is cached before the response
    /// is sent. Declines if the application builds nothing or the parent is neither cached nor
    /// the branch anchor, and returns without answering if `proposal` is cancelled first.
    ///
    /// Panics if the application proposes state that does not match the block's commitments.
    #[boxed]
    pub(super) async fn propose(
        &mut self,
        context: &E,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: impl Ancestry<A::Block>,
        input: Input<A::Input, A::Provider>,
        mut proposal: Proposal<Digested<A::Block>>,
    ) {
        let timer = self.execution.metrics.propose_duration.timer(context);

        let parent_digest = ancestry
            .peek()
            .expect("recovered ancestry must begin with the proposal's parent")
            .digest();

        let round = consensus_context.round();
        let batches = match await_or_cancel(
            poll_fn(|cx| proposal.poll_cancelled(cx)),
            self.execution.fork_batches(&parent_digest),
        )
        .await
        {
            Some(Ok(batches)) => batches,
            Some(Err(_)) => {
                debug!(
                    ?parent_digest,
                    "proposal declined: parent state is no longer compatible"
                );
                proposal.decline();
                return;
            }
            None => {
                debug!(
                    ?parent_digest,
                    "proposal request cancelled while forking batches"
                );
                return;
            }
        };

        // Only a build that yields a block is timed.
        let application_context = (runtime_context, consensus_context);
        match proposal {
            Proposal::Prepare(mut response) => {
                let Some(prepared) = await_or_cancel(
                    response.closed(),
                    self.app
                        .prepare(application_context, ancestry, batches, input),
                )
                .await
                else {
                    debug!(?parent_digest, "proposal request cancelled during prepare");
                    return;
                };
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(ExecutionError::Invalid(reason)) => {
                        debug!(
                            ?parent_digest,
                            reason, "prepare declined: invalid execution"
                        );
                        Handoff::Wait
                    }
                    Err(err) => {
                        fail_unless_stopped(context.stopped(), format!("prepare failed: {err}"))
                            .await
                    }
                };
                let prepared = match prepared {
                    Handoff::Vote(proposed) => {
                        Handoff::Vote(self.cache_proposed(round, parent_digest, proposed).await)
                    }
                    Handoff::Stage(proposed) => {
                        Handoff::Stage(self.cache_proposed(round, parent_digest, proposed).await)
                    }
                    Handoff::Wait => Handoff::Wait,
                };
                if !prepared.is_wait() {
                    timer.observe(context);
                }
                response.send_lossy(prepared);
            }
            Proposal::Propose(mut response) => {
                let Some(proposed) = await_or_cancel(
                    response.closed(),
                    self.app
                        .propose(application_context, ancestry, batches, input),
                )
                .await
                else {
                    debug!(?parent_digest, "proposal request cancelled during propose");
                    return;
                };
                let block = match proposed {
                    Ok(Some(proposed)) => {
                        Some(self.cache_proposed(round, parent_digest, proposed).await)
                    }
                    Ok(None) => None,
                    Err(ExecutionError::Invalid(reason)) => {
                        debug!(
                            ?parent_digest,
                            reason, "propose declined: invalid execution"
                        );
                        None
                    }
                    Err(err) => {
                        fail_unless_stopped(context.stopped(), format!("propose failed: {err}"))
                            .await
                    }
                };
                if block.is_some() {
                    timer.observe(context);
                }
                response.send_lossy(block);
            }
        }
    }

    /// Caches the state of a block the application built on `parent` and returns the block
    /// with its digest.
    ///
    /// Panics if the state does not match the block's commitments, or if `parent`'s state has
    /// been discarded. Only a finalization discards it, and none runs during a build.
    async fn cache_proposed(
        &mut self,
        round: Round,
        parent: BlockDigest<A, E>,
        Proposed { block, merkleized }: Proposed<A, E>,
    ) -> Digested<A::Block> {
        assert!(
            A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)),
            "proposed state must match block commitments",
        );
        let block = Digested::compute(block, &self.strategy).await;
        assert!(
            self.cache_pending(
                block.digest(),
                PendingEntry {
                    round,
                    parent,
                    merkleized,
                },
            )
            .is_ok(),
            "proposal parent must remain compatible until the proposal completes",
        );
        block
    }

    #[cfg(test)]
    async fn fork_batches(
        &self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<Unmerkleized<A, E>, PrepareBatchesError> {
        self.execution.fork_batches(parent).await
    }

    #[cfg(test)]
    async fn rebuild_pending<P>(
        &self,
        context: &E,
        provider: &P,
        target: Digested<A::Block>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        self.execution
            .rebuild_pending(&self.app, context, provider, target)
            .await
    }

    /// Returns whether `block` is at or below the branch anchor's height.
    ///
    /// Panics if `block` conflicts with the branch anchor at the same height.
    pub(super) fn redelivered(&self, block: &Digested<A::Block>) -> bool {
        let anchor = self.execution.branch_anchor();
        if block.height() == anchor.height {
            assert_eq!(
                block.digest(),
                anchor.digest,
                "received conflicting finalized block at anchor height",
            );
        }
        block.height() <= anchor.height
    }

    /// Applies the next finalized `block` and discards cached state that does not descend from it.
    ///
    /// Requests keep running throughout. If `block` is still processing, this joins its flight
    /// and uses its result. A flight on a competing branch ends with
    /// [`PrepareBatchesError::Stale`] at its next batch read once `block` is applied, and its
    /// requests start over against the new branch anchor.
    ///
    /// Publishes snapshots and returns the prune that became due, if any. If `start_barrier` is
    /// set, it also returns a barrier covering `block` and every earlier applied block. The branch anchor advances once
    /// `block`'s merkleized state is ready, and that state remains cached through the
    /// application's `finalized` hook.
    ///
    /// Panics if `block` does not have the next height and the branch anchor as its parent, or if
    /// an uncached block fails to process or match its commitments.
    #[boxed]
    pub(super) async fn finalize<P>(
        &mut self,
        context: &E,
        provider: &P,
        block: &Digested<A::Block>,
        start_barrier: bool,
    ) -> Applied<SyncTargets<A, E>>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let finalized = Anchor::from_block(block);
        let (height, digest) = (finalized.height, finalized.digest);
        let anchor = self.execution.branch_anchor();
        assert_eq!(
            height,
            anchor.height.next(),
            "finalized block skips unapplied heights",
        );
        assert_eq!(
            block.parent(),
            anchor.digest,
            "finalized block does not extend the applied tip",
        );

        let timer = self.execution.metrics.finalize_duration.timer(context);
        let block_context = block.context();
        let sync_targets = A::sync_targets(block.inner());
        // A flight already processing the block finishes it once rather than twice. A flight
        // that rejects the block as a candidate leaves it uncached, and it is reconstructed below.
        let flight = {
            let state = self.execution.state.lock();
            state.flights.get(&digest).and_then(WeakShared::upgrade)
        };
        if let Some(flight) = flight {
            let _ = flight.await;
        }
        let cached = self
            .execution
            .state
            .lock()
            .pending
            .get(&digest)
            .map(|entry| entry.merkleized.clone());

        // Marshal delivers finalized blocks in height order, so the winner's parent state is the
        // applied state.
        let batch = if let Some(batch) = cached {
            batch
        } else {
            let batches = A::Databases::new_batches(&self.execution.readers).await;

            // The finalized block must reproduce its committed state.
            let ancestry = self.execution.ancestry(
                context,
                provider.clone(),
                [block.clone()],
                block_context.round(),
            );
            match self
                .app
                .process(
                    (context.child("finalize_reconstruct"), block_context),
                    ancestry,
                    batches,
                    Finality::Finalized,
                )
                .await
            {
                Ok(Some(batch)) if A::Databases::matches_sync_targets(&batch, &sync_targets) => {
                    batch
                }
                Ok(Some(_)) => {
                    fail_unless_stopped(
                        context.stopped(),
                        "finalize reconstruction must match block commitments".into(),
                    )
                    .await
                }
                Ok(None) => {
                    fail_unless_stopped(
                        context.stopped(),
                        "finalize reconstruction must process the block".into(),
                    )
                    .await
                }
                Err(err) => {
                    fail_unless_stopped(
                        context.stopped(),
                        format!("finalize reconstruction failed: {err}"),
                    )
                    .await
                }
            }
        };

        self.execution
            .retain_branch(finalized, block.parent(), &batch);
        let captured = self
            .app
            .capture(
                (context.child("capture"), block.context()),
                block.inner(),
                &batch,
                self.execution.readers.clone(),
            )
            .await;
        let databases = self.take_databases().apply(batch).await;
        let (databases, snapshots, barrier) = if start_barrier {
            let (databases, snapshots, barrier) = databases.finalize().await;
            (databases, Some(snapshots), Some(barrier))
        } else if A::Databases::CHEAP_SNAPSHOT {
            let (databases, snapshots) = databases.snapshot().await;
            (databases, Some(snapshots), None)
        } else {
            (databases, None, None)
        };
        self.databases = Some(databases);
        self.app
            .finalized(
                (context.child("finalized"), block.context()),
                block.inner(),
                captured,
                self.execution.readers.clone(),
            )
            .await;

        // Publish only after the hook completes. Compact members must serve every applied block,
        // including blocks applied while a barrier is pending.
        if let Some(snapshots) = snapshots {
            self.publisher.publish(height, snapshots);
        } else if A::Databases::ANY_CHEAP_SNAPSHOT {
            self.refresh_snapshot(height).await;
        }

        let prune = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe(height, sync_targets));
        let retained = self.execution.state.lock().pending.remove(&digest);
        assert!(
            retained.is_some(),
            "finalized root must remain cached through its hook"
        );
        timer.observe(context);

        Applied { barrier, prune }
    }

    fn cache_pending(
        &self,
        digest: BlockDigest<A, E>,
        entry: PendingEntry<A, E>,
    ) -> Result<(), PrepareBatchesError> {
        self.execution.cache_pending(digest, entry)
    }
}

impl<E, A> Execution<E, A>
where
    E: Spawner + Clock,
    A: Application<E>,
{
    fn branch_anchor(&self) -> Anchor<BlockDigest<A, E>> {
        self.state.lock().branch
    }

    /// Caches `batch` as the state of `anchor`, discards cached state that does not descend from
    /// it, and makes `anchor` the branch anchor.
    ///
    /// Requests outside this branch may still be running. They go stale at their next batch read
    /// or cache attempt. The caller must keep the root cached until its finalization completes
    /// so requests on this branch can fork from it while the databases change.
    fn retain_branch(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        parent: BlockDigest<A, E>,
        batch: &PendingBatches<A, E>,
    ) {
        // Requests may have cached descendants since this finalization began, so descendants come
        // from the current cache.
        let mut state = self.state.lock();
        let compatible = state.descendants(anchor.digest, anchor.round);
        let before = state.pending.len();
        state
            .pending
            .retain(|digest, _| compatible.contains(digest));
        let pruned = before - state.pending.len();
        state
            .pending
            .entry(anchor.digest)
            .or_insert_with(|| PendingEntry {
                round: anchor.round,
                parent,
                merkleized: batch.clone(),
            });
        state.branch = anchor;
        let pending = state.speculative_len();
        drop(state);
        self.metrics.pruned_forks.inc_by(pruned as u64);
        let _ = self.metrics.pending_blocks.try_set(pending);
    }

    fn pending_contains(&self, digest: &BlockDigest<A, E>) -> bool {
        self.state.lock().pending.contains_key(digest)
    }

    /// Returns the ancestry the application reads while processing the newest of `blocks`:
    /// `blocks` themselves, then earlier ancestors fetched from `provider` on demand. `bound` is
    /// the round that ends the need for those ancestors.
    fn ancestry<P, I>(
        &self,
        context: &E,
        provider: P,
        blocks: I,
        bound: Round,
    ) -> impl Ancestry<A::Block> + use<E, A, P, I>
    where
        P: BlockProvider<Block = A::Block> + Clone,
        I: IntoIterator<Item = Digested<A::Block>>,
    {
        AncestorStream::new(
            Arc::new(context.child("ancestry")),
            provider,
            blocks,
            Some(bound),
            self.metrics.ancestor_fetch_duration.clone(),
        )
    }

    /// Caches `entry` as the speculative state of `digest`.
    ///
    /// An existing entry keeps its state. A new entry is cached only if it is at a later round
    /// than the branch anchor and its parent is the anchor or another cached block, and caching
    /// it updates the pending-state gauge. The anchor itself counts as cached. Returns
    /// [`PrepareBatchesError::Stale`] if a finalization overtook the entry while it processed:
    /// its round is at or before the anchor's, or its parent was discarded.
    ///
    /// Panics if `digest` is already cached with a different parent or round.
    fn cache_pending(
        &self,
        digest: BlockDigest<A, E>,
        entry: PendingEntry<A, E>,
    ) -> Result<(), PrepareBatchesError> {
        let (round, parent) = (entry.round, entry.parent);
        let mut state = self.state.lock();
        if let Some(existing) = state.pending.get(&digest) {
            assert_eq!(existing.parent, parent, "pending parent changed for digest");
            assert_eq!(existing.round, round, "pending round changed for digest");
            return Ok(());
        }
        if digest == state.branch.digest {
            return Ok(());
        }
        if round <= state.branch.round {
            return Err(PrepareBatchesError::Stale);
        }
        if parent != state.branch.digest && !state.pending.contains_key(&parent) {
            return Err(PrepareBatchesError::Stale);
        }
        state.pending.insert(digest, entry);
        let pending = state.speculative_len();
        drop(state);
        let _ = self.metrics.pending_blocks.try_set(pending);
        Ok(())
    }

    /// Returns a handle to the candidate processing of the first block of `ancestry`, or
    /// [`None`] if the block's state is cached or is the branch anchor.
    ///
    /// Joins the block's live flight if there is one. Otherwise starts a flight with its own
    /// application clone, `context`, and `ancestry` and caches a valid result before completing.
    fn join_flight(
        &self,
        app: &A,
        context: E,
        ancestry: BoxedAncestry<A::Block>,
    ) -> Option<Flight> {
        let digest = ancestry
            .peek()
            .expect("candidate ancestry must start with its block")
            .digest();
        let mut state = self.state.lock();
        if state.branch.digest == digest || state.pending.contains_key(&digest) {
            return None;
        }
        if let Some(flight) = state.flights.get(&digest).and_then(WeakShared::upgrade) {
            return Some(flight);
        }

        // The flight removes its entry before `Shared` stores its result, so the registry never
        // hands out a completed flight. It is traced under its own span, since no single request
        // owns it.
        let app = app.clone();
        let execution = self.clone();
        let guard = FlightGuard {
            state: self.state.clone(),
            digest,
        };
        let flight = async move {
            let result = execution.process_candidate(app, context, ancestry).await;
            drop(guard);
            result
        }
        .instrument(info_span!(
            parent: None,
            "stateful.processor.process",
            block = %digest,
        ))
        .boxed()
        .shared();
        let registered = flight
            .downgrade()
            .expect("a new flight must not have completed");
        state.flights.insert(digest, registered);
        Some(flight)
    }

    /// Forks batches from the state of `parent`.
    ///
    /// Forks from `parent`'s cached state, or from the applied databases if `parent` is the branch
    /// anchor. During finalization the new branch anchor is still cached, so forks use its cached
    /// state until its `finalized` hook completes. Returns [`PrepareBatchesError::Stale`] if
    /// `parent` is neither cached nor the branch anchor, since only a finalization discards
    /// cached state.
    ///
    /// A finalization moves the branch anchor before it applies, so a fork from the applied
    /// databases checks the anchor again once its batches exist. If it moved, the batches may
    /// include the newly applied block, and this returns [`PrepareBatchesError::Stale`].
    async fn fork_batches(
        &self,
        parent: &BlockDigest<A, E>,
    ) -> Result<Unmerkleized<A, E>, PrepareBatchesError> {
        {
            let state = self.state.lock();
            if let Some(entry) = state.pending.get(parent) {
                return Ok(A::Databases::fork_batches(&entry.merkleized));
            }
            if state.branch.digest != *parent {
                return Err(PrepareBatchesError::Stale);
            }
        }

        let batches = A::Databases::new_batches(&self.readers).await;
        if self.state.lock().branch.digest != *parent {
            return Err(PrepareBatchesError::Stale);
        }
        Ok(batches)
    }

    /// Processes the first block of `ancestry` on its parent's state as a candidate and caches the
    /// result.
    ///
    /// Returns immediately if the block is the branch anchor. Returns
    /// [`PrepareBatchesError::Invalid`] if the block is above the anchor's height with a round
    /// not after the anchor's, if the application rejects the block, or if the result does not
    /// match the block's commitments. Returns [`PrepareBatchesError::Stale`] if a finalization
    /// overtook the block or its parent, before or while it processed.
    async fn process_candidate(
        &self,
        mut app: A,
        context: E,
        ancestry: BoxedAncestry<A::Block>,
    ) -> FlightResult {
        let block = ancestry
            .peek()
            .expect("candidate ancestry must start with its block");
        let (digest, parent_digest, height) = (block.digest(), block.parent(), block.height());
        let consensus_context = block.context();
        let round = consensus_context.round();
        let sync_targets = A::sync_targets(block.inner());

        // A finalization may have overtaken the block since the request chose it. The anchor
        // itself is valid. Any other block at or below the anchor's height is answered from the
        // canonical chain once the request acquires again. Above it, no descendant of the anchor
        // has a round at or before the anchor's.
        let anchor = self.branch_anchor();
        if digest == anchor.digest {
            return Ok(());
        }
        if height <= anchor.height {
            return Err(PrepareBatchesError::Stale);
        }
        if round <= anchor.round {
            return Err(PrepareBatchesError::Invalid);
        }
        let batches = self.fork_batches(&parent_digest).await?;
        let stopped = context.stopped();
        let merkleized = match app
            .process(
                (context, consensus_context),
                ancestry,
                batches,
                Finality::Candidate,
            )
            .await
        {
            Ok(Some(merkleized)) => merkleized,
            Ok(None) => {
                warn!(block = ?digest, "application rejected block");
                return Err(PrepareBatchesError::Invalid);
            }
            Err(ExecutionError::Invalid(reason)) => {
                warn!(block = ?digest, reason, "block execution is invalid");
                return Err(PrepareBatchesError::Invalid);
            }
            Err(ExecutionError::Stale) => {
                debug!(block = ?digest, "block execution went stale");
                return Err(PrepareBatchesError::Stale);
            }
            Err(err @ ExecutionError::Fatal(_)) => {
                fail_unless_stopped(stopped, format!("process failed: {err}")).await
            }
        };

        if !A::Databases::matches_sync_targets(&merkleized, &sync_targets) {
            warn!(block = ?digest, "processed state must match block commitments");
            return Err(PrepareBatchesError::Invalid);
        }

        self.cache_pending(
            digest,
            PendingEntry {
                round,
                parent: parent_digest,
                merkleized,
            },
        )
    }

    /// Collects the missing blocks between `target` and cached or applied state without forking
    /// database batches.
    ///
    /// Returns [`PrepareBatchesError::Invalid`] if the walk reaches the anchor height without
    /// meeting the branch anchor, or if `provider` returns a block that is not the parent at the
    /// preceding height. Returns [`PrepareBatchesError::Incomplete`] if `provider` stops before
    /// delivering a parent. Returns [`PrepareBatchesError::Stale`] if a finalization moves the
    /// branch anchor during the walk, since a block the walk passed may have become the anchor.
    ///
    /// Each parent is requested under `target`'s round. Once marshal's processed round floor
    /// covers that round, every ancestor of `target` is processed or can never be finalized.
    async fn prepare_replay<P>(
        &self,
        context: &E,
        provider: &P,
        target: Digested<A::Block>,
    ) -> Result<ReplayPath<A::Block>, PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let timer = self.metrics.rebuild_pending_duration.timer(context);
        let target_digest = target.digest();
        let bound = target.context().round();

        let mut replay_path = Vec::new();
        let mut cursor = target;
        let start = self.branch_anchor().digest;
        loop {
            let (known, anchor) = {
                let state = self.state.lock();
                (
                    cursor.digest() == state.branch.digest
                        || state.pending.contains_key(&cursor.digest()),
                    state.branch,
                )
            };
            if known {
                break;
            }
            if anchor.digest != start {
                debug!(
                    ?target_digest,
                    "branch anchor moved during the ancestry walk"
                );
                return Err(PrepareBatchesError::Stale);
            }

            let cursor_height = cursor.height();
            if cursor_height <= anchor.height {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    current_height = cursor_height.get(),
                    branch_height = anchor.height.get(),
                    branch_anchor = ?anchor.digest,
                    "ancestry reached stale state at or below anchor height"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            let Some(parent) = provider.subscribe_parent(&cursor, Some(bound)).await else {
                debug!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    "ancestor subscription ended before delivery"
                );
                return Err(PrepareBatchesError::Incomplete);
            };

            if parent.digest() != cursor.parent()
                || cursor_height.previous() != Some(parent.height())
            {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    parent = ?parent.digest(),
                    cursor_height = cursor_height.get(),
                    parent_height = parent.height().get(),
                    expected_parent = ?cursor.parent(),
                    "received non-contiguous ancestry"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            replay_path.push(cursor);
            cursor = parent;
        }

        let depth = replay_path.len();
        Ok(ReplayPath {
            blocks: replay_path,
            parent: cursor,
            bound,
            measurement: Some((timer, depth)),
        })
    }

    /// Returns the ancestry for the next block on `path`, starting with the block and its parent,
    /// or [`None`] once the path is exhausted.
    ///
    /// Each block forks from the state of the one before it, so the caller processes a block
    /// before requesting the next.
    fn next_replay<P>(
        &self,
        context: &E,
        provider: &P,
        path: &mut ReplayPath<A::Block>,
    ) -> Option<BoxedAncestry<A::Block>>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let Some(block) = path.blocks.pop() else {
            if let Some((timer, depth)) = path.measurement.take() {
                let _ = self.metrics.rebuild_pending_depth.try_set(depth);
                timer.observe(context);
            }
            return None;
        };
        let parent = std::mem::replace(&mut path.parent, block.clone());
        Some(BoxedAncestry::new(self.ancestry(
            context,
            provider.clone(),
            [block, parent],
            path.bound,
        )))
    }

    #[cfg(test)]
    async fn rebuild_pending<P>(
        &self,
        app: &A,
        context: &E,
        provider: &P,
        target: Digested<A::Block>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let mut path = self.prepare_replay(context, provider, target).await?;
        while let Some(ancestry) = self.next_replay(context, provider, &mut path) {
            if let Some(flight) = self.join_flight(app, context.child("replay"), ancestry) {
                flight.await?;
            }
        }
        Ok(())
    }
}

/// Returns the output of `future`, or `None` if `cancelled` resolves first.
async fn await_or_cancel<T>(
    cancelled: impl Future<Output = ()>,
    future: impl Future<Output = T>,
) -> Option<T> {
    select! {
        _ = cancelled => None,
        output = future => Some(output),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Applied, Execution, Flight, FlightResult, PendingEntry, PrepareBatchesError, Processor,
        Prune, Pruning, fail_unless_stopped,
    };
    use crate::stateful::{
        Application, ExecutionError, Finality, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{Anchor, Barrier, DatabaseSet, Merkleized as _, Single, Unmerkleized as _},
        tests::mocks::digested,
    };
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        Block as ConsensusBlock, CertifiableBlock, Heightable,
        marshal::ancestry::{self as marshal_ancestry, Ancestry, BlockProvider, BoxedAncestry},
        simplex::{mocks::scheme::Scheme as MockScheme, types::Context as ConsensusContext},
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Digested, Digestible, Hasher, Sha256, Signer as _, ed25519, sha256::Digest,
    };
    use commonware_macros::{boxed, select};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        ContextCell, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::{
            authenticated::Config as MerkleConfig, contiguous::fixed::Config as FixedLogConfig,
        },
        mmr::{self, Location},
        qmdb::{any, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, channel::oneshot, non_empty_range, range::NonEmptyRange, sync::Mutex,
    };
    use futures::{StreamExt, task::ArcWake};
    use std::{
        collections::{BTreeMap, VecDeque},
        future::Future,
        num::NonZeroUsize,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Context,
        time::Duration,
    };

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
    type QmdbConfig = any::unordered::fixed::Config<TwoCap, Sequential>;
    type DbSet<E> = Single<Qmdb<E>>;
    type TestMerkleized =
        <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized;

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

    /// Awaits the shared candidate processing of the first block of `ancestry`, or returns
    /// `Ok(())` at once if the block's state is cached or is the branch anchor.
    async fn process_shared(
        execution: &Execution<deterministic::Context, ExecutionApp>,
        app: &ExecutionApp,
        context: &deterministic::Context,
        ancestry: impl Ancestry<Block>,
    ) -> FlightResult {
        let ancestry = BoxedAncestry::new(ancestry);
        match execution.join_flight(app, context.child("replay"), ancestry) {
            Some(flight) => flight.await,
            None => Ok(()),
        }
    }

    /// Returns a handle to the candidate processing of the first block of `ancestry`, starting
    /// the processing if none is in flight. Panics if the block already has state.
    fn join_flight(
        execution: &Execution<deterministic::Context, ExecutionApp>,
        app: &ExecutionApp,
        context: &deterministic::Context,
        ancestry: impl Ancestry<Block>,
    ) -> Flight {
        let ancestry = BoxedAncestry::new(ancestry);
        execution
            .join_flight(app, context.child("replay"), ancestry)
            .expect("block must not have state yet")
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

    type ProcessAncestry = Arc<Mutex<Vec<(Finality, [Digest; 3])>>>;

    #[derive(Clone)]
    struct ExecutionApp {
        genesis: Block,
        finalized_observer: Option<Arc<Mutex<Vec<FinalizedObservation>>>>,
        process_probe: Option<ApplicationProbe>,
        capture_probe: Option<ApplicationProbe>,
        finalized_probe: Option<ApplicationProbe>,
        process_ancestry: Option<ProcessAncestry>,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
                finalized_observer: None,
                process_probe: None,
                capture_probe: None,
                finalized_probe: None,
                process_ancestry: None,
            }
        }

        fn with_finalized_observer() -> (Self, Arc<Mutex<Vec<FinalizedObservation>>>) {
            let observations = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    finalized_observer: Some(observations.clone()),
                    ..Self::new()
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
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            let mut ancestry = Box::pin(ancestry);
            let Some(parent) = ancestry.next().await else {
                return Ok(None);
            };
            let context = context.1.clone();
            let view = context.round.view();
            let height = parent.height().next();
            let merkleized = Self::execute(height, view, batches).await;
            let block = Block {
                context,
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: merkleized.target().range,
            };
            Ok(Some(Proposed { block, merkleized }))
        }

        async fn process(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            finality: Finality,
        ) -> Result<
            Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized>,
            ExecutionError,
        > {
            let Some(block) = ancestry.next().await else {
                return Ok(None);
            };
            if let Some(observations) = &self.process_ancestry {
                let parent = ancestry
                    .next()
                    .await
                    .expect("process must expose the parent");
                let ancestor = ancestry
                    .next()
                    .await
                    .expect("process must fetch earlier ancestors");
                observations.lock().push((
                    finality,
                    [block.digest(), parent.digest(), ancestor.digest()],
                ));
            }
            if let Some(probe) = &self.process_probe {
                probe.call(block.digest()).await;
            }
            Ok(Some(
                Self::execute(block.height(), block.inner().context.round.view(), batches).await,
            ))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: &TestMerkleized,
            readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) -> Self::Captured {
            if let Some(probe) = &self.capture_probe {
                probe.call(block.digest()).await;
            }
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
            readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
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
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            Target {
                root: block.state_root,
                range: block.range.clone(),
            }
        }
    }

    #[derive(Clone, Default)]
    struct MapProvider {
        blocks: Arc<Mutex<BTreeMap<Digest, Block>>>,
        fetches: Arc<AtomicUsize>,
        /// The bound of each parent request, in order.
        bounds: Arc<Mutex<Vec<Option<Round>>>>,
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

        fn bounds(&self) -> Vec<Option<Round>> {
            self.bounds.lock().clone()
        }
    }

    impl BlockProvider for MapProvider {
        type Block = Block;

        fn subscribe_parent(
            &self,
            block: &Digested<Self::Block>,
            bound: Option<Round>,
        ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
            self.bounds.lock().push(bound);
            let provider = self.clone();
            let parent = block.parent();
            async move { provider.fetch_by_digest(parent).map(digested) }
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
            block: &Digested<Self::Block>,
            _bound: Option<Round>,
        ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
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
                    .map(digested)
            }
        }
    }

    /// A [MapProvider] that holds the parent request of one child until released.
    #[derive(Clone)]
    struct GatedParentProvider {
        inner: MapProvider,
        child: Digest,
        gate: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    impl BlockProvider for GatedParentProvider {
        type Block = Block;

        fn subscribe_parent(
            &self,
            block: &Digested<Self::Block>,
            bound: Option<Round>,
        ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
            let gate = (block.digest() == self.child)
                .then(|| self.gate.lock().take())
                .flatten();
            let parent = self.inner.subscribe_parent(block, bound);
            async move {
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
                parent.await
            }
        }
    }

    struct Harness {
        context_cell: ContextCell<deterministic::Context>,
        processor: Processor<deterministic::Context, ExecutionApp, Sequential>,
        provider: MapProvider,
        db_config: QmdbConfig,
    }

    impl Harness {
        async fn new(context: deterministic::Context) -> Self {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix());
            Self::with_app(context, provider, config.clone(), ExecutionApp::new()).await
        }

        async fn new_with_finalized_observer(
            context: deterministic::Context,
        ) -> (Self, Arc<Mutex<Vec<FinalizedObservation>>>) {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix());
            let (app, observations) = ExecutionApp::with_finalized_observer();
            (
                Self::with_app(context, provider, config, app).await,
                observations,
            )
        }

        async fn with_app(
            context: deterministic::Context,
            provider: MapProvider,
            config: QmdbConfig,
            app: ExecutionApp,
        ) -> Self {
            let databases = <DbSet<deterministic::Context> as DatabaseSet<
                deterministic::Context,
            >>::init(context.child("databases"), config.clone(), None)
            .await;
            let metrics = StatefulMetrics::new(&context);
            let (publisher, _) = crate::stateful::db::Publisher::new(&context);
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
                    publisher,
                    Sequential,
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
                range: merkleized.target().range,
            };
            (block, merkleized)
        }

        async fn stage_pending_child(&mut self, parent: &Block, view: View) -> Block {
            let (block, merkleized) = self.build_child(parent, view).await;
            let round = Round::new(Epoch::zero(), view);
            assert!(
                self.processor
                    .cache_pending(
                        block.digest(),
                        PendingEntry {
                            round,
                            parent: parent.digest(),
                            merkleized,
                        },
                    )
                    .is_ok()
            );
            self.provider.insert(block.clone());
            block
        }

        /// Applies `block` and waits for its database barrier.
        ///
        /// Returns `false` without applying redelivered blocks.
        #[boxed]
        async fn finalize(&mut self, block: Block) -> bool {
            let block = digested(block);
            if self.processor.redelivered(&block) {
                return false;
            }
            let Applied { barrier, .. } = self
                .processor
                .finalize(self.context_cell.as_present(), &self.provider, &block, true)
                .await;
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
            let block = digested(block);
            let Applied { barrier, prune } = self
                .processor
                .finalize(self.context_cell.as_present(), &self.provider, &block, true)
                .await;
            assert_durable(barrier).await;
            prune
        }

        async fn view_at_height(&self, height: Height) -> Option<u64> {
            let readers = self.processor.readers();
            let db = readers.read().await;
            db.get(&height_key(height))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn counter_value(&self) -> Option<u64> {
            let readers = self.processor.readers();
            let db = readers.read().await;
            db.get(&counter_key())
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

    fn qmdb_config(prefix: &str) -> QmdbConfig {
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        QmdbConfig {
            merkle: MerkleConfig {
                partition: format!("{prefix}_mmr_metadata"),
                replay_buffer: IO_BUFFER_SIZE,
                strategy: Sequential,
                resident_height: Default::default(),
            },
            log: FixedLogConfig {
                partition: format!("{prefix}_log_journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: IO_BUFFER_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
            },
            translator: TwoCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: NZUsize!(2),
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
            let config = qmdb_config("db_config");
            let app = ExecutionApp::new();
            let mut harness = Harness::with_app(context, provider, config, app).await;
            harness.processor = Processor::new(
                ExecutionApp::new(),
                harness
                    .processor
                    .databases
                    .take()
                    .expect("harness holds its databases"),
                Anchor {
                    height: Height::zero(),
                    round: Block::genesis().context().round,
                    digest: Block::genesis().digest(),
                },
                StatefulMetrics::new(harness.context_cell.as_present()),
                Some(Pruning::new(
                    PruneConfig {
                        maintenance_interval: NZUsize!(1),
                        retained_marshal_blocks: 1,
                        retained_qmdb_blocks: 1,
                    },
                    1,
                    0,
                )),
                crate::stateful::db::Publisher::new(harness.context_cell.as_present()).0,
                Sequential,
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
            assert!(harness.finalize(block1.clone()).await);
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
            assert_eq!(harness.processor.branch_anchor().digest, winner.digest());
            assert_eq!(harness.view_at_height(Height::new(2)).await, Some(3));
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork_descendants() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);
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
            assert!(harness.finalize(block1.clone()).await);
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let winner_child = harness.stage_pending_child(&winner, View::new(4)).await;
            let (gate, started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [gate]));
            let execution = harness.processor.execution.clone();

            let finalized_block = digested(winner.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &finalized_block,
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
            let Applied { barrier, .. } = finalize.await;
            assert_durable(barrier).await;
        });
    }

    #[rstest::rstest]
    #[case::cached(true)]
    #[case::reconstructed(false)]
    fn finalization_retains_sealed_root_through_hook(#[case] cached: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let winner = harness
                .stage_pending_child(&Block::genesis(), View::new(7))
                .await;
            if !cached {
                harness.processor.clear_pending();
            }

            // Hold the winner's finalization at its capture and finalized hooks.
            let (capture_gate, capture_started, capture_release) = apply_gate();
            let (hook_gate, hook_started, hook_release) = apply_gate();
            harness.processor.app.capture_probe =
                Some(ApplicationProbe::new(winner.digest(), [capture_gate]));
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(winner.digest(), [hook_gate]));
            let execution = harness.processor.execution.clone();
            let databases = harness.processor.readers();
            let block = digested(winner.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &block,
                true,
            ));
            select! {
                _ = &mut finalize => panic!("finalization must wait at the capture gate"),
                result = capture_started => result.unwrap(),
            }

            // Before the state is applied, the winner is the branch anchor and its state is cached
            // for forks without counting as speculative, while the databases lack it.
            assert_eq!(execution.branch_anchor().digest, winner.digest());
            assert!(execution.pending_contains(&winner.digest()));
            assert_eq!(execution.metrics.pending_blocks.get(), 0);
            assert!(<DbSet<deterministic::Context> as DatabaseSet<
                deterministic::Context,
            >>::matches_sync_targets(
                &execution.state.lock().pending[&winner.digest()].merkleized,
                &ExecutionApp::sync_targets(&winner),
            ));
            let fork = execution.fork_batches(&winner.digest()).await.unwrap();
            assert_eq!(
                fork.get(&counter_key())
                    .await
                    .unwrap()
                    .map(|v| digest_to_u64(&v)),
                Some(1)
            );
            assert_eq!(
                fork.get(&height_key(winner.height()))
                    .await
                    .unwrap()
                    .map(|v| digest_to_u64(&v)),
                Some(7)
            );
            assert!(
                databases
                    .read()
                    .await
                    .get(&counter_key())
                    .await
                    .unwrap()
                    .is_none()
            );
            drop(fork);

            // Once capture returns, the databases hold the state and the root stays cached through
            // the finalized hook.
            capture_release.send(()).unwrap();
            select! {
                _ = &mut finalize => panic!("finalization must wait at the finalized hook gate"),
                result = hook_started => result.unwrap(),
            }
            assert!(execution.pending_contains(&winner.digest()));
            assert_eq!(
                databases
                    .read()
                    .await
                    .get(&counter_key())
                    .await
                    .unwrap()
                    .map(|v| digest_to_u64(&v)),
                Some(1)
            );

            // The root leaves the cache once the hook returns.
            hook_release.send(()).unwrap();
            let Applied { barrier, .. } = finalize.await;
            assert_durable(barrier).await;
            assert!(!execution.pending_contains(&winner.digest()));
            assert_eq!(execution.metrics.pending_blocks.get(), 0);
        });
    }

    #[test]
    fn finalization_keeps_replay_published_after_boundary() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let parent = harness
                .stage_pending_child(&Block::genesis(), View::new(1))
                .await;
            let (child, _) = harness.build_child(&parent, View::new(2)).await;

            // Hold the child's processing with a second request joined to it.
            let (gate, started, release) = apply_gate();
            harness.processor.app.process_probe =
                Some(ApplicationProbe::new(child.digest(), [gate]));
            let execution = harness.processor.execution.clone();
            let app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present().child("replay");
            let mut first = Box::pin(process_shared(
                &execution,
                &app,
                &replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut first).is_pending());
            started.await.unwrap();
            let mut second = Box::pin(process_shared(
                &execution,
                &app,
                &replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut second).is_pending());

            // A retained replay can cache its state while other requests finish, and a request
            // joined to it can observe that success after the parent's finalization.
            release.send(()).unwrap();
            assert_eq!(first.await, Ok(()));
            assert!(harness.finalize(parent.clone()).await);
            assert!(!execution.pending_contains(&parent.digest()));
            assert!(execution.pending_contains(&child.digest()));
            assert_eq!(second.await, Ok(()));
            let fork = execution.fork_batches(&child.digest()).await.unwrap();
            assert_eq!(
                fork.get(&counter_key())
                    .await
                    .unwrap()
                    .map(|v| digest_to_u64(&v)),
                Some(2)
            );
            assert_eq!(
                fork.get(&height_key(child.height()))
                    .await
                    .unwrap()
                    .map(|v| digest_to_u64(&v)),
                Some(2)
            );
        });
    }

    #[test]
    fn execution_forks_from_finalizing_winner_before_database_apply() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;
            let databases = harness.processor.readers();
            let read = databases.read().await;
            let execution = harness.processor.execution.clone();

            let finalized_block = digested(winner.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &finalized_block,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());

            let winner_digest = winner.digest();
            let mut fork = Box::pin(execution.fork_batches(&winner_digest));
            let forked = match futures::poll!(&mut fork) {
                std::task::Poll::Ready(forked) => forked,
                std::task::Poll::Pending => {
                    panic!("finalizing winner must remain available for child batches")
                }
            };
            assert!(forked.is_ok(), "finalizing winner must remain forkable");

            drop(read);
            let Applied { barrier, .. } = finalize.await;
            assert_durable(barrier).await;
        });
    }

    /// A descendant's processing that forked from its parent's cached state still completes and
    /// caches its result after the parent's finalization removes the parent's root from the cache,
    /// even when the request that started it is dropped during the finalization. The finalized
    /// hook reads the applied state while that processing runs.
    #[test]
    fn execution_descendant_replay_survives_finalized_parent_removal() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut harness, observations) = Harness::new_with_finalized_observer(context).await;
            let genesis = Block::genesis();
            let parent = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (child, _) = harness.build_child(&parent, View::new(2)).await;

            let (gate, started, release) = apply_gate();
            harness.processor.app.process_probe =
                Some(ApplicationProbe::new(child.digest(), [gate]));
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(parent.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();
            let app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();

            // Two requests share the child's processing. The gate holds it.
            let mut first = Box::pin(process_shared(
                &execution,
                &app,
                replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut first).is_pending());
            started.await.expect("replay must start");

            let mut second = Box::pin(process_shared(
                &execution,
                &app,
                replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut second).is_pending());

            let finalized_block = digested(parent.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &finalized_block,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            finalized_started.await.expect("finalized hook must start");

            // Dropping the first request leaves the processing running for the second while the
            // finalized hook reads the applied state, and the processing completes once the
            // parent's root has left the cache.
            drop(first);
            assert!(futures::poll!(&mut second).is_pending());
            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize.await;
            assert_durable(barrier).await;
            assert!(matches!(
                observations.lock().as_slice(),
                [FinalizedObservation { post_view: 1, .. }]
            ));
            assert!(!execution.pending_contains(&parent.digest()));
            release.send(()).expect("replay must remain active");
            assert_eq!(second.await, Ok(()));
            assert!(execution.pending_contains(&child.digest()));
        });
    }

    /// Finalizing a block whose processing is in flight joins that processing and reuses its
    /// result instead of processing the block again.
    #[test]
    fn execution_finalization_joins_in_flight_winner() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;
            let execution = harness.processor.execution.clone();

            // The gate keeps the winner's processing in flight.
            let (gate, started, release) = apply_gate();
            let probe = ApplicationProbe::new(winner.digest(), [gate]);
            harness.processor.app.process_probe = Some(probe.clone());
            let mut flight = join_flight(
                &execution,
                &harness.processor.app,
                harness.context_cell.as_present(),
                marshal_ancestry::from_iter([digested(winner.clone())]),
            );
            assert!(futures::poll!(&mut flight).is_pending());
            started.await.unwrap();

            // Finalization waits for the flight, then applies its cached result.
            let mut finalize = Box::pin(harness.finalize(winner.clone()));
            assert!(futures::poll!(&mut finalize).is_pending());
            release.send(()).unwrap();
            assert!(finalize.await);
            assert_eq!(flight.await, Ok(()));
            assert_eq!(probe.calls(), 1);
            assert_eq!(harness.processor.branch_anchor().digest, winner.digest());
        });
    }

    /// A flight for a block created while that block's finalization reconstructs it, and first
    /// polled after the block became the anchor, succeeds without processing the block again.
    #[test]
    fn flight_for_block_finalized_before_its_first_poll_succeeds() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            harness.provider.insert(block.clone());

            // The gate holds the finalization's reconstruction of the block.
            let (gate, started, release) = apply_gate();
            let probe = ApplicationProbe::new(block.digest(), [gate]);
            harness.processor.app.process_probe = Some(probe.clone());
            let execution = harness.processor.execution.clone();
            let app = harness.processor.app.clone();
            let flight_context = harness.context_cell.as_present().child("flight");
            let mut finalize = Box::pin(harness.finalize(block.clone()));
            assert!(futures::poll!(&mut finalize).is_pending());
            started.await.unwrap();

            // A request joins the block while it reconstructs, and the finalization completes
            // before the request's flight is first polled.
            let flight = join_flight(
                &execution,
                &app,
                &flight_context,
                marshal_ancestry::from_iter([digested(block.clone())]),
            );
            release.send(()).unwrap();
            assert!(finalize.await);
            assert_eq!(flight.await, Ok(()));
            assert_eq!(probe.calls(), 1);
        });
    }

    #[test]
    fn execution_rejects_late_losing_fork_publication() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let late_view = View::new(4);
            let (late_child, merkleized) = harness.build_child(&loser, late_view).await;

            assert!(harness.finalize(winner).await);
            assert_eq!(
                harness.processor.cache_pending(
                    late_child.digest(),
                    PendingEntry {
                        round: Round::new(Epoch::zero(), late_view),
                        parent: loser.digest(),
                        merkleized,
                    },
                ),
                Err(PrepareBatchesError::Stale),
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

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.provider,
                    digested(block3.clone()),
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
    fn execution_rebuild_pending_bounds_parent_requests_by_round() {
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
            let requested_before = harness.provider.bounds().len();

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.provider,
                    digested(block3.clone()),
                )
                .await;
            assert_eq!(result, Ok(()), "rebuild must succeed");

            // The walk requests the parents of block3 and block2. Both serve block3, so both carry
            // its round.
            let bounds = harness.provider.bounds().split_off(requested_before);
            let bound = Some(Round::new(Epoch::zero(), View::new(3)));
            assert!(bounds.len() >= 2, "the walk must request both parents");
            assert!(
                bounds.iter().all(|requested| *requested == bound),
                "every parent request must carry the requested block's round: {bounds:?}"
            );
        });
    }

    #[test]
    fn execution_process_ancestry_survives_recovery_and_finalization() {
        deterministic::Runner::timed(std::time::Duration::from_secs(5)).start(
            |context| async move {
                let mut harness = Harness::new(context).await;
                let genesis = Block::genesis();
                let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
                assert!(harness.finalize(block1.clone()).await);
                let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
                assert!(harness.finalize(block2.clone()).await);
                let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
                harness.processor.clear_pending();
                let bound = Some(block3.context.round);
                let requested_before = harness.provider.bounds().len();

                // Recovery processes block3 as a candidate, and its ancestry reaches past the
                // parent to an earlier ancestor.
                let observations = Arc::new(Mutex::new(Vec::new()));
                harness.processor.app.process_ancestry = Some(observations.clone());
                assert_eq!(
                    harness
                        .processor
                        .rebuild_pending(
                            harness.context_cell.as_present(),
                            &harness.provider,
                            digested(block3.clone()),
                        )
                        .await,
                    Ok(()),
                );
                let expected = [block3.digest(), block2.digest(), block1.digest()];
                assert_eq!(*observations.lock(), [(Finality::Candidate, expected)]);
                assert!(harness.processor.pending_contains(&block3.digest()));
                let recovery_requests = harness.provider.bounds().len() - requested_before;
                assert!(
                    recovery_requests >= 2,
                    "recovery must request block3's parent and an earlier ancestor"
                );

                // The cached state answers a later request without processing block3 again.
                assert_eq!(
                    process_shared(
                        &harness.processor.execution,
                        &harness.processor.app,
                        harness.context_cell.as_present(),
                        marshal_ancestry::from_iter([digested(block3.clone())]),
                    )
                    .await,
                    Ok(()),
                );
                assert_eq!(observations.lock().len(), 1);

                // Finalizing the uncached block processes it as finalized with the same ancestry.
                harness.processor.clear_pending();
                assert!(harness.finalize(block3).await);
                assert_eq!(
                    *observations.lock(),
                    [
                        (Finality::Candidate, expected),
                        (Finality::Finalized, expected),
                    ]
                );
                assert_eq!(harness.counter_value().await, Some(3));
                assert_eq!(harness.view_at_height(Height::new(3)).await, Some(3));

                // The recovery and the finalization read past block3 for block3 alone, so every
                // parent they requested carries block3's round.
                let bounds = harness.provider.bounds().split_off(requested_before);
                assert!(
                    bounds.len() > recovery_requests,
                    "finalization must request block3's ancestors"
                );
                assert!(
                    bounds.iter().all(|requested| *requested == bound),
                    "every parent request must carry block3's round: {bounds:?}"
                );
            },
        );
    }

    /// A parent that is neither cached nor the anchor can only have been discarded by a
    /// finalization, so a fork from it is stale and its request acquires again.
    #[test]
    fn execution_fork_batches_reports_unknown_parent_as_stale() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            assert!(matches!(
                harness.processor.fork_batches(&u64_to_digest(999)).await,
                Err(PrepareBatchesError::Stale),
            ));
        });
    }

    struct WakeCheck<F>(F);

    impl<F: Fn() + Send + Sync> ArcWake for WakeCheck<F> {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            (arc_self.0)();
        }
    }

    /// A completing flight removes its entry, caches the block only after a success, and answers
    /// every joined request with the same result.
    #[rstest::rstest]
    #[case::success(true)]
    #[case::invalid_commitment(false)]
    fn flight_completion_removes_entry_and_shares_result(#[case] valid: bool) {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (mut block, _) = harness.build_child(&genesis, View::new(1)).await;
            if !valid {
                block.state_root = u64_to_digest(999);
            }
            let digest = block.digest();
            let ancestry = marshal_ancestry::from_iter([digested(block), digested(genesis)]);

            // The gate holds the processing with a second request joined to it.
            let (gate, started, release) = apply_gate();
            let mut app = harness.processor.app.clone();
            app.process_probe = Some(ApplicationProbe::new(digest, [gate]));
            let execution = &harness.processor.execution;
            let mut first = join_flight(execution, &app, &context, ancestry.clone());
            assert!(futures::poll!(&mut first).is_pending());
            started.await.expect("processing must start");
            let mut second = join_flight(execution, &app, &context, ancestry);
            assert!(futures::poll!(&mut second).is_pending());

            // Completing the processing removes the flight, caches a valid result, and answers
            // both requests with the same result.
            release.send(()).expect("processing must remain held");
            let expected = if valid {
                Ok(())
            } else {
                Err(PrepareBatchesError::Invalid)
            };
            assert_eq!(first.await, expected);
            {
                let state = execution.state.lock();
                assert!(!state.flights.contains_key(&digest));
                assert_eq!(state.pending.contains_key(&digest), valid);
            }
            assert_eq!(second.await, expected);
            assert!(harness.processor.execution.state.lock().flights.is_empty());
        });
    }

    /// Dropping one request's handle leaves the shared processing running for the others and
    /// releases the dropped request's waker, so that waker never fires.
    #[test]
    fn dropped_flight_handle_releases_waker() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            let digest = block.digest();
            let ancestry = marshal_ancestry::from_iter([digested(block), digested(genesis)]);

            // Three requests share one processing. The gate holds it.
            let (gate, started, release) = apply_gate();
            let mut app = harness.processor.app.clone();
            app.process_probe = Some(ApplicationProbe::new(digest, [gate]));
            let execution = &harness.processor.execution;
            let mut first = join_flight(execution, &app, &context, ancestry.clone());
            assert!(futures::poll!(&mut first).is_pending());
            started.await.expect("processing must start");
            let mut second = join_flight(execution, &app, &context, ancestry.clone());
            let third = join_flight(execution, &app, &context, ancestry);

            // Dropping the polled second request releases its waker while the flight stays active.
            let wakes = Arc::new(AtomicUsize::new(0));
            let observed = wakes.clone();
            let callback = Arc::new(WakeCheck(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }));
            let weak = Arc::downgrade(&callback);
            let waker = futures::task::waker(callback);
            assert!(
                Pin::new(&mut second)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop(waker);
            assert!(weak.upgrade().is_some());
            drop(second);
            assert!(weak.upgrade().is_none());
            assert!(!harness.processor.execution.state.lock().flights.is_empty());

            // The remaining requests receive the result, and the dropped waker never fires.
            release.send(()).expect("processing must remain held");
            assert_eq!(first.await, Ok(()));
            assert_eq!(third.await, Ok(()));
            assert_eq!(wakes.load(Ordering::SeqCst), 0);
            assert!(harness.processor.execution.state.lock().flights.is_empty());
        });
    }

    /// A request that is dropped after a wakeup, without polling again, leaves the processing to
    /// the other requests. They drive it to completion.
    #[test]
    fn woken_request_dropped_before_polling_hands_processing_on() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            let digest = block.digest();
            let ancestry = marshal_ancestry::from_iter([digested(block), digested(genesis)]);

            // Both requests have polled the processing. The gate holds it.
            let (gate, started, release) = apply_gate();
            let mut app = harness.processor.app.clone();
            app.process_probe = Some(ApplicationProbe::new(digest, [gate]));
            let execution = &harness.processor.execution;
            let mut first = join_flight(execution, &app, &context, ancestry.clone());
            assert!(futures::poll!(&mut first).is_pending());
            started.await.expect("processing must start");
            let mut second = join_flight(execution, &app, &context, ancestry);
            assert!(futures::poll!(&mut second).is_pending());

            // Releasing the gate wakes both requests. Dropping the first before it polls again
            // leaves the second to complete the processing.
            release.send(()).expect("processing must remain held");
            drop(first);
            assert_eq!(second.await, Ok(()));
            assert!(execution.pending_contains(&digest));
            assert!(harness.processor.execution.state.lock().flights.is_empty());
        });
    }

    /// A flight stays registered while any request holds it, admits later requests, and is
    /// cancelled when the last request drops it. A request after that starts a new flight.
    #[test]
    fn flight_ends_with_its_last_request() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let (block, _) = harness.build_child(&genesis, View::new(1)).await;
            let digest = block.digest();
            let ancestry = marshal_ancestry::from_iter([digested(block), digested(genesis)]);

            // The first gate holds the processing started by the first request, and the second
            // holds the processing a later request starts after the first is cancelled.
            let (gate, started, release) = apply_gate();
            let (fresh_gate, fresh_started, _fresh_release) = apply_gate();
            let mut app = harness.processor.app.clone();
            app.process_probe = Some(ApplicationProbe::new(digest, [gate, fresh_gate]));
            let execution = &harness.processor.execution;
            let mut first = join_flight(execution, &app, &context, ancestry.clone());
            assert!(futures::poll!(&mut first).is_pending());
            started.await.expect("processing must start");

            // Dropping other requests, polled or not, leaves the flight active.
            let mut polled = join_flight(execution, &app, &context, ancestry.clone());
            assert!(futures::poll!(&mut polled).is_pending());
            let unpolled = join_flight(execution, &app, &context, ancestry.clone());
            drop(polled);
            drop(unpolled);
            assert!(!harness.processor.execution.state.lock().flights.is_empty());

            // A later request joins the same flight and keeps it alive once the first request
            // drops it.
            let late = join_flight(execution, &app, &context, ancestry.clone());
            assert!(first.ptr_eq(&late));
            drop(first);
            assert!(!harness.processor.execution.state.lock().flights.is_empty());
            assert!(!release.is_closed());

            // The last request to drop the flight cancels the processing and removes the entry.
            drop(late);
            assert!(harness.processor.execution.state.lock().flights.is_empty());
            assert!(release.is_closed());

            // A new request starts a new flight and processes the block again.
            let mut fresh = join_flight(execution, &app, &context, ancestry);
            assert!(futures::poll!(&mut fresh).is_pending());
            fresh_started.await.expect("new processing must start");
            assert!(!harness.processor.execution.state.lock().flights.is_empty());
        });
    }

    #[rstest::rstest]
    #[case::uncontended(true, 0)]
    #[case::shared_success(true, 16)]
    #[case::shared_invalid_commitment(false, 16)]
    fn flight_shares_terminal_result(#[case] valid: bool, #[case] joiner_count: usize) {
        deterministic::Runner::timed(std::time::Duration::from_secs(5)).start(
            |context| async move {
                let harness = Harness::new(context.child("harness")).await;
                let genesis = Block::genesis();
                let (mut block, _) = harness.build_child(&genesis, View::new(1)).await;
                if !valid {
                    block.state_root = u64_to_digest(999);
                }
                let digest = block.digest();
                let ancestry = marshal_ancestry::from_iter([digested(block), digested(genesis)]);

                // Hold the processing started by the first request inside the application's
                // process call.
                let (gate, started, release) = apply_gate();
                let probe = ApplicationProbe::new(digest, [gate]);
                let mut app = harness.processor.app.clone();
                app.process_probe = Some(probe.clone());
                let execution = &harness.processor.execution;
                let mut first = Box::pin(process_shared(
                    execution,
                    &app,
                    &context,
                    ancestry.clone(),
                ));
                select! {
                    result = &mut first => panic!("processing must reach the execution gate: {result:?}"),
                    result = started => result.expect("processing must start"),
                }

                // Polled requests and an unpolled one join the processing without another call.
                let mut joiners = Vec::new();
                for _ in 0..joiner_count {
                    let mut joiner =
                        Box::pin(process_shared(execution, &app, &context, ancestry.clone()));
                    assert!(futures::poll!(&mut joiner).is_pending());
                    joiners.push(joiner);
                }
                let unpolled = (joiner_count != 0)
                    .then(|| join_flight(execution, &app, &context, ancestry.clone()));
                assert_eq!(probe.calls(), 1);

                // Every request receives the result of the single call.
                release.send(()).expect("processing must remain held");

                let expected = if valid {
                    Ok(())
                } else {
                    Err(PrepareBatchesError::Invalid)
                };
                assert_eq!(first.await, expected);
                for result in futures::future::join_all(joiners).await {
                    assert_eq!(result, expected);
                }
                if let Some(joiner) = unpolled {
                    assert_eq!(joiner.await, expected);
                }
                assert_eq!(probe.calls(), 1);
                assert!(harness.processor.execution.state.lock().flights.is_empty());

                // A cached success answers a later request without another call.
                if valid {
                    assert_eq!(
                        process_shared(execution, &app, &context, ancestry).await,
                        Ok(()),
                    );
                    assert_eq!(probe.calls(), 1);
                }
            },
        );
    }

    /// Recoveries that need the same missing ancestor share its processing. The processing keeps
    /// running when the request that started it is dropped and answers every remaining request
    /// from one call.
    #[test]
    fn overlapping_rebuilds_share_processing_across_cancellation() {
        deterministic::Runner::timed(std::time::Duration::from_secs(5)).start(
            |context| async move {
                let mut harness = Harness::new(context.child("harness")).await;
                let genesis = Block::genesis();
                let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
                let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
                let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
                harness.processor.clear_pending();
                harness.provider.insert(genesis);

                // The gate holds block1's processing, and a second gate detects any repeated
                // processing of block1.
                let (gate, started, release) = apply_gate();
                let (duplicate_gate, mut duplicate_started, _duplicate_release) = apply_gate();
                let probe = ApplicationProbe::new(block1.digest(), [gate, duplicate_gate]);
                harness.processor.app.process_probe = Some(probe.clone());
                let execution = harness.processor.execution.clone();
                let app = harness.processor.app.clone();

                let mut first = Box::pin(execution.rebuild_pending(
                    &app,
                    &context,
                    &harness.provider,
                    digested(block2.clone()),
                ));
                select! {
                    result = &mut first => panic!("first rebuild must reach the replay gate: {result:?}"),
                    result = started => result.expect("first replay must start"),
                }

                // Later rebuilds join block1's processing, so the duplicate gate stays unused.
                let mut second = Box::pin(execution.rebuild_pending(
                    &app,
                    &context,
                    &harness.provider,
                    digested(block2.clone()),
                ));
                let mut third = Box::pin(execution.rebuild_pending(
                    &app,
                    &context,
                    &harness.provider,
                    digested(block3),
                ));
                let mut fourth = Box::pin(execution.rebuild_pending(
                    &app,
                    &context,
                    &harness.provider,
                    digested(block2),
                ));
                assert!(futures::poll!(&mut second).is_pending());
                assert!(futures::poll!(&mut third).is_pending());
                assert!(futures::poll!(&mut fourth).is_pending());
                assert!(futures::poll!(&mut duplicate_started).is_pending());
                assert_eq!(probe.calls(), 1);

                // Dropping requests, including the one that started the processing, leaves it
                // running for the rest.
                drop(fourth);
                drop(first);
                assert!(futures::poll!(&mut second).is_pending());
                assert!(futures::poll!(&mut third).is_pending());
                assert!(!release.is_closed());
                assert!(futures::poll!(&mut duplicate_started).is_pending());

                // Releasing the processing completes every remaining rebuild from one call.
                release.send(()).expect("shared processing must remain active");
                let (second_result, third_result) = select! {
                    result = &mut duplicate_started => {
                        result.expect("duplicate replay signal must remain available");
                        panic!("block1 must be processed once");
                    },
                    result = futures::future::join(second, third) => result,
                };
                assert_eq!(second_result, Ok(()));
                assert_eq!(third_result, Ok(()));
                assert_eq!(probe.calls(), 1);
                assert!(harness.processor.execution.state.lock().flights.is_empty());
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
            let stale = chain[1].clone(); // height 2, below anchor height 5
            let fetches_before = harness.provider.fetches();

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.provider,
                    digested(stale),
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

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.provider,
                    digested(block2.clone()),
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
                .expect("branch anchor must be available");
            let merkleized = ExecutionApp::execute(gap_height, gap_view, batches).await;
            let gap_block = Block {
                context: consensus_context(block1.digest(), gap_view),
                parent: block1.digest(),
                height: gap_height,
                state_root: merkleized.root(),
                range: merkleized.target().range,
            };

            let provider = ScriptedParentProvider::default();
            provider.push(&gap_block, [Some(block1)]);

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &provider,
                    digested(gap_block.clone()),
                )
                .await;

            assert_eq!(
                result,
                Err(PrepareBatchesError::Invalid),
                "rebuild must reject non-contiguous ancestry above the branch anchor",
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
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &provider,
                    digested(block3.clone()),
                )
                .await;

            assert_eq!(result, Err(PrepareBatchesError::Invalid));
            assert_eq!(provider.fetches(), 1);
            assert!(!harness.processor.pending_contains(&block3.digest()));
        });
    }

    /// An unverified ancestor can claim any height, including `u64::MAX`, which has no
    /// successor. An ancestor whose height is not contiguous with the cursor is rejected.
    #[test]
    fn execution_rebuild_pending_rejects_parent_at_max_height() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.child("harness")).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            assert!(harness.finalize(block1.clone()).await);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
            let parent = Block {
                height: Height::new(u64::MAX),
                ..block2
            };
            let child = Block {
                parent: parent.digest(),
                ..block3
            };
            harness.processor.clear_pending();

            let provider = ScriptedParentProvider::default();
            provider.push(&child, [Some(parent)]);
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &provider,
                    digested(child.clone()),
                )
                .await;

            assert_eq!(result, Err(PrepareBatchesError::Invalid));
            assert_eq!(provider.fetches(), 1);
            assert!(!harness.processor.pending_contains(&child.digest()));
        });
    }

    #[test]
    #[should_panic(expected = "received conflicting finalized block at anchor height")]
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

    /// Marshal delivers a finalized chain, so a block at the next height whose parent is not the
    /// branch anchor is a contract violation. Its commitments can still match the applied state,
    /// so finalization panics instead of applying it to a state it does not extend.
    #[test]
    #[should_panic(expected = "finalized block does not extend the applied tip")]
    fn execution_finalize_panics_on_unlinked_successor() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Finalize one of two siblings at height 1.
            let canonical = harness.stage_pending_child(&genesis, View::new(1)).await;
            let sibling = harness.stage_pending_child(&genesis, View::new(2)).await;
            assert!(harness.finalize(canonical.clone()).await);

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
            harness.processor.app.process_probe = Some(cached_probe.clone());
            assert!(harness.finalize(block1).await);
            assert_eq!(
                cached_probe.calls(),
                0,
                "block1 should use its cached merkleized batch",
            );
            harness.processor.clear_pending();
            let reconstructed_probe = ApplicationProbe::new(block2.digest(), []);
            harness.processor.app.process_probe = Some(reconstructed_probe.clone());
            assert!(harness.finalize(block2).await);
            assert_eq!(
                reconstructed_probe.calls(),
                1,
                "block2 must be reconstructed through Application::process",
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

            assert!(harness.finalize(block.clone()).await);
            observations.lock().clear();
            assert!(!harness.finalize(block).await);

            assert!(observations.lock().is_empty());
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

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &provider,
                    digested(block2),
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

            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &provider,
                    digested(block2),
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

    /// A walk that passes a block before that block is finalized, and then reaches the old
    /// anchor, is stale rather than invalid.
    #[test]
    fn replay_walk_is_stale_when_the_anchor_moves_past_it() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let parent = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (target, _) = harness.build_child(&parent, View::new(2)).await;
            harness.provider.insert(genesis.clone());
            harness.provider.insert(target.clone());
            harness
                .processor
                .execution
                .state
                .lock()
                .pending
                .remove(&parent.digest());

            // The walk passes `parent` while genesis is the anchor, then waits for its parent.
            let (release, gate) = oneshot::channel();
            let provider = GatedParentProvider {
                inner: harness.provider.clone(),
                child: parent.digest(),
                gate: Arc::new(Mutex::new(Some(gate))),
            };
            let execution = harness.processor.execution.clone();
            let walk_context = harness.context_cell.as_present().child("walk");
            let mut walk = Box::pin(execution.prepare_replay(
                &walk_context,
                &provider,
                digested(target.clone()),
            ));
            assert!(futures::poll!(&mut walk).is_pending());

            // `parent` becomes the anchor before the walk reaches genesis.
            assert!(harness.finalize(parent.clone()).await);
            release.send(()).unwrap();
            assert!(matches!(walk.await, Err(PrepareBatchesError::Stale)));

            // Walking again from the new anchor finds `target` alone.
            let path = execution
                .prepare_replay(&walk_context, &harness.provider, digested(target))
                .await
                .expect("the walk must reach the new anchor");
            assert_eq!(path.blocks.len(), 1);
        });
    }

    /// A failed operation panics while the actor runs.
    #[test]
    #[should_panic(expected = "process failed: injected")]
    fn failure_panics_while_running() {
        use commonware_runtime::Spawner as _;
        deterministic::Runner::default().start(|context| async move {
            let () =
                fail_unless_stopped(context.stopped(), "process failed: injected".into()).await;
        });
    }

    /// A failed operation after shutdown fired is abandoned: it never completes and does not
    /// panic.
    #[test]
    fn failure_is_abandoned_after_shutdown() {
        use commonware_runtime::Spawner as _;
        deterministic::Runner::default().start(|context| async move {
            let stopped = context.stopped();
            let stopper = context.child("stopper");
            let stop = context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });
            let _ = context.stopped().await;
            let mut failed = Box::pin(fail_unless_stopped::<()>(
                stopped,
                "process failed: injected".into(),
            ));
            assert!(futures::poll!(&mut failed).is_pending());
            drop(failed);
            stop.await.expect("stop task should finish");
        });
    }
}
