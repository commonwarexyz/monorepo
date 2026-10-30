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
//! - Finalization: processing of the finalized block and of competing branches finishes before
//!   the block's state is applied, while processing of its descendants may continue. The caller
//!   coordinates durability, so one database barrier can cover several finalizations.

use crate::stateful::{
    Application, Finality, Input, Proposed, PruneConfig,
    actor::{BlockDigest, SyncTargets, core::Proposal, metrics::Metrics as StatefulMetrics},
    db::{Anchor, Barrier, DatabaseSet},
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
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Supervisor,
    telemetry::metrics::{GaugeExt, histogram::Timer},
};
use commonware_utils::{
    Widen,
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use futures::{FutureExt as _, future::Shared};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::{Future, poll_fn},
    hash::Hash,
    sync::Arc,
};
use tracing::{debug, warn};

mod verifier;
pub(super) use verifier::{Prepared, Verifier};

type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;
type Unmerkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Unmerkleized;
type PendingMap<A, E> = BTreeMap<BlockDigest<A, E>, PendingEntry<A, E>>;
type ReplayResult = Result<(), PrepareBatchesError>;
type ReplayWaiter = Shared<oneshot::Receiver<ReplayResult>>;

/// One in-flight processing call. Its completion channel is allocated when the first waiter
/// joins, so `None` means no request has joined the owner yet.
type ReplayFlight = Option<(oneshot::Sender<ReplayResult>, ReplayWaiter)>;

/// The block whose shared execution a request is running or awaiting.
#[derive(Clone, Copy)]
pub(super) struct ExecutionStep<D> {
    pub(super) digest: D,
    pub(super) parent: D,
    pub(super) round: Round,
}

/// How an execution step crosses an incoming finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Disposition {
    /// Continue polling work proven to descend from the finalized block.
    Retain,
    /// Finish this step and hold its request until maintenance completes.
    Park,
    /// Reject work whose parent or round is incompatible with the finalized branch.
    Reject,
}

/// Snapshot of the cached state that remains valid once one finalized block is applied.
pub(super) struct FinalizationBoundary<D> {
    digest: D,
    round: Round,
    compatible: HashSet<D>,
}

impl<D: Copy + Eq + Hash> FinalizationBoundary<D> {
    /// Classifies one execution step against the incoming finalized branch.
    pub(super) fn disposition(&self, step: &ExecutionStep<D>) -> Disposition {
        if step.digest == self.digest {
            Disposition::Park
        } else if step.round > self.round && self.compatible.contains(&step.parent) {
            Disposition::Retain
        } else {
            Disposition::Reject
        }
    }

    /// Allows a completed descendant to become the parent of another retained step.
    pub(super) fn completed(&mut self, step: &ExecutionStep<D>) {
        assert_eq!(self.disposition(step), Disposition::Retain);
        self.compatible.insert(step.digest);
    }
}

/// Missing blocks between cached or applied state and a requested block, processed oldest first.
struct ReplayPath<B: Block> {
    /// Missing blocks, newest first, so the next block to process is at the end.
    blocks: Vec<Digested<B>>,

    /// Parent of the next block to process.
    parent: Digested<B>,

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
    /// In-flight candidate processing, at most one per block digest. Requests can share a call
    /// because the digest commits to the block's embedded context.
    flights: BTreeMap<BlockDigest<A, E>, ReplayFlight>,
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

/// Databases, speculative state, and metrics shared by the processor and its verifiers.
struct Execution<E, A>
where
    A: Application<E>,
{
    databases: A::Databases,
    state: Arc<Mutex<ExecutionState<A, E>>>,
    metrics: StatefulMetrics,
}

impl<E, A> Clone for Execution<E, A>
where
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

/// Outcome of requesting shared replay work for one block digest.
enum ReplayClaim<E, A>
where
    A: Application<E>,
{
    /// State for the digest is already available.
    Ready,
    /// The caller owns the new replay flight.
    Owner(ReplayOwner<E, A>),
    /// Another caller owns the replay flight.
    Wait(ReplayWaiter),
}

/// Owner of a replay flight.
///
/// Dropping the owner removes its flight. Waiters receive the result recorded by
/// [`ReplayOwner::finish`], or see their channel close if none was recorded.
struct ReplayOwner<E, A>
where
    A: Application<E>,
{
    state: Arc<Mutex<ExecutionState<A, E>>>,
    digest: BlockDigest<A, E>,
    result: Option<ReplayResult>,
}

impl<E, A> ReplayOwner<E, A>
where
    A: Application<E>,
{
    /// Records `result` for the flight's waiters and drops the owner.
    fn finish(mut self, result: ReplayResult) {
        self.result = Some(result);
    }
}

impl<E, A> Drop for ReplayOwner<E, A>
where
    A: Application<E>,
{
    fn drop(&mut self) {
        let flight = self
            .state
            .lock()
            .flights
            .remove(&self.digest)
            .expect("replay owner must have an in-flight entry");
        if let Some((sender, completion)) = flight {
            match self.result {
                Some(result) => {
                    sender.send_lossy(result);
                }
                None => drop(sender),
            }
            drop(completion);
        }
    }
}

/// Errors while preparing parent-relative batches for propose/verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrepareBatchesError {
    /// Parent ancestry is provably invalid.
    Invalid,
    /// Parent ancestry ended before validity could be proven.
    Incomplete,
}

/// Result of applying a newly finalized block.
pub(super) struct Applied<T> {
    /// Barrier covering the block, present only when the caller requested one.
    pub(super) barrier: Option<Barrier>,

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

impl<T> Prune<T> {
    /// Prunes the databases to the sync targets at `barrier_height`, then prunes marshal.
    ///
    /// The caller must ensure a completed database barrier covers `barrier_height` and that no
    /// database barrier is active.
    pub(super) async fn run<E, DBs, S, V>(self, databases: &DBs, marshal: &MarshalMailbox<S, V>)
    where
        DBs: DatabaseSet<E, SyncTargets = T>,
        S: Scheme,
        V: MarshalVariant,
    {
        databases.prune(&self.qmdb_target).await;
        marshal.prune(self.marshal_height);
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
    execution: Execution<E, A>,
    pruning: Option<Pruning<SyncTargets<A, E>>>,
    strategy: T,
}

impl<E, A, T> Processor<E, A, T>
where
    E: Supervisor + Clock,
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
        strategy: T,
    ) -> Self {
        Self {
            app,
            execution: Execution {
                databases,
                state: Arc::new(Mutex::new(ExecutionState {
                    pending: BTreeMap::new(),
                    flights: BTreeMap::new(),
                    branch: anchor,
                })),
                metrics,
            },
            pruning,
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

    /// Returns whether no replay is in flight.
    pub(super) fn replays_idle(&self) -> bool {
        self.execution.state.lock().flights.is_empty()
    }

    /// Snapshots the cached state that remains valid once `block` is finalized.
    pub(super) fn boundary(
        &self,
        block: &Digested<A::Block>,
    ) -> FinalizationBoundary<BlockDigest<A, E>> {
        let digest = block.digest();
        let round = block.context().round();
        let state = self.execution.state.lock();
        FinalizationBoundary {
            digest,
            round,
            compatible: state.descendants(digest, round),
        }
    }

    /// Returns a reference to the database set.
    pub(super) const fn databases(&self) -> &A::Databases {
        &self.execution.databases
    }

    /// Returns the current branch anchor.
    pub(super) fn branch_anchor(&self) -> Anchor<BlockDigest<A, E>> {
        self.execution.branch_anchor()
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
                    Some(proposed) => {
                        Some(self.cache_proposed(round, parent_digest, proposed).await)
                    }
                    None => None,
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
            ),
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
        &mut self,
        context: &E,
        provider: &P,
        target: Digested<A::Block>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        self.execution
            .rebuild_pending(&mut self.app, context, provider, target)
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
    /// The caller must let every execution step that [`Self::boundary`] does not retain finish
    /// before entering, and must admit no new requests until this call returns. Retained
    /// descendants may continue.
    ///
    /// Returns the prune that became due, if any. If `start_barrier` is set, it also returns a
    /// barrier covering `block` and every earlier applied block. The branch anchor advances once
    /// `block`'s merkleized state is ready, and that state remains cached through the
    /// application's `finalized` hook.
    ///
    /// Panics if `block` does not have the next height and the branch anchor as its parent, if a
    /// request is still processing `block`, or if an uncached block fails to process or match its
    /// commitments.
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
        let cached = {
            let state = self.execution.state.lock();
            assert!(
                !state.flights.contains_key(&digest),
                "finalized block must not be processed when its finalization starts",
            );
            state
                .pending
                .get(&digest)
                .map(|entry| entry.merkleized.clone())
        };

        // Marshal delivers finalizations in height order, so the winner's parent state is the
        // applied state.
        let batch = if let Some(batch) = cached {
            batch
        } else {
            let batches = self.execution.databases.new_batches().await;

            // The finalized block must reproduce its committed state.
            let ancestry = self
                .execution
                .ancestry(context, provider.clone(), [block.clone()]);
            let batch = self
                .app
                .process(
                    (context.child("finalize_reconstruct"), block_context),
                    ancestry,
                    batches,
                    Finality::Finalized,
                )
                .await
                .expect("finalize reconstruction must process the block");
            assert!(
                A::Databases::matches_sync_targets(&batch, &sync_targets),
                "finalize reconstruction must match block commitments",
            );
            batch
        };

        self.execution
            .retain_branch(finalized, block.parent(), &batch);
        let captured = self
            .app
            .capture(
                (context.child("capture"), block.context()),
                block.inner(),
                &batch,
                self.execution.databases.readers(),
            )
            .await;
        self.execution.databases.apply(batch).await;
        let barrier = if start_barrier {
            Some(self.execution.databases.finalize().await)
        } else {
            None
        };
        self.app
            .finalized(
                (context.child("finalized"), block.context()),
                block.inner(),
                captured,
                self.execution.databases.readers(),
            )
            .await;
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

    fn cache_pending(&self, digest: BlockDigest<A, E>, entry: PendingEntry<A, E>) -> bool {
        self.execution.cache_pending(digest, entry)
    }
}

impl<E, A> Execution<E, A>
where
    E: Supervisor + Clock,
    A: Application<E>,
{
    fn branch_anchor(&self) -> Anchor<BlockDigest<A, E>> {
        self.state.lock().branch
    }

    /// Caches `batch` as the state of `anchor`, discards cached state that does not descend from
    /// it, and makes `anchor` the branch anchor.
    ///
    /// The caller must have let every request outside this branch finish, and must keep the root
    /// cached until its finalization completes so retained requests can fork from it while the
    /// databases change.
    fn retain_branch(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        parent: BlockDigest<A, E>,
        batch: &PendingBatches<A, E>,
    ) {
        // Retained requests may have cached descendants since the finalization boundary was
        // taken, so descendants come from the current cache.
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
    /// `blocks` themselves, then earlier ancestors fetched from `provider` on demand.
    fn ancestry<P, I>(
        &self,
        context: &E,
        provider: P,
        blocks: I,
    ) -> impl Ancestry<A::Block> + use<E, A, P, I>
    where
        P: BlockProvider<Block = A::Block> + Clone,
        I: IntoIterator<Item = Digested<A::Block>>,
    {
        AncestorStream::new(
            Arc::new(context.child("ancestry")),
            provider,
            blocks,
            self.metrics.ancestor_fetch_duration.clone(),
        )
    }

    /// Caches `entry` as the speculative state of `digest` and returns whether `digest` is cached.
    ///
    /// An existing entry keeps its state. A new entry is cached only if it is at a later round
    /// than the branch anchor and its parent is the anchor or another cached block, and caching
    /// it updates the pending-state gauge.
    ///
    /// Panics if `digest` is already cached with a different parent or round.
    fn cache_pending(&self, digest: BlockDigest<A, E>, entry: PendingEntry<A, E>) -> bool {
        let (round, parent) = (entry.round, entry.parent);
        let mut state = self.state.lock();
        if let Some(existing) = state.pending.get(&digest) {
            assert_eq!(existing.parent, parent, "pending parent changed for digest");
            assert_eq!(existing.round, round, "pending round changed for digest");
            return true;
        }

        let compatible = round > state.branch.round
            && (parent == state.branch.digest || state.pending.contains_key(&parent));
        if !compatible {
            return false;
        }
        state.pending.insert(digest, entry);
        let pending = state.speculative_len();
        drop(state);
        let _ = self.metrics.pending_blocks.try_set(pending);
        true
    }

    /// Claims replay of `digest` for a request.
    ///
    /// Returns [`ReplayClaim::Ready`] if `digest` is the branch anchor or is cached,
    /// [`ReplayClaim::Wait`] if a replay of `digest` is in flight, and [`ReplayClaim::Owner`]
    /// otherwise.
    fn claim_replay(&self, digest: BlockDigest<A, E>) -> ReplayClaim<E, A> {
        let mut state = self.state.lock();
        if state.branch.digest == digest || state.pending.contains_key(&digest) {
            return ReplayClaim::Ready;
        }

        if let Some(flight) = state.flights.get_mut(&digest) {
            let (_, completion) = flight.get_or_insert_with(|| {
                let (sender, receiver) = oneshot::channel();
                (sender, receiver.shared())
            });
            return ReplayClaim::Wait(completion.clone());
        }

        state.flights.insert(digest, None);
        ReplayClaim::Owner(ReplayOwner {
            state: self.state.clone(),
            digest,
            result: None,
        })
    }

    /// Forks batches from the state of `parent`.
    ///
    /// Forks from `parent`'s cached state, or from the applied databases if `parent` is the branch
    /// anchor. During finalization the new branch anchor is still cached, so forks use its cached
    /// state until its `finalized` hook completes. Returns [`PrepareBatchesError::Invalid`] if
    /// `parent` is neither cached nor the branch anchor.
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
                return Err(PrepareBatchesError::Invalid);
            }
        }

        Ok(self.databases.new_batches().await)
    }

    /// Processes the first block of `ancestry` on its parent's state as a candidate and caches the
    /// result.
    ///
    /// Returns [`PrepareBatchesError::Invalid`] if the parent's state cannot be forked, if the
    /// application rejects the block, if the result does not match the block's commitments, or
    /// if the result can no longer be cached.
    async fn replay(
        &self,
        app: &mut A,
        context: &E,
        ancestry: impl Ancestry<A::Block>,
    ) -> ReplayResult {
        let block = ancestry
            .peek()
            .expect("replayed ancestry must start with its block");
        let (digest, parent_digest) = (block.digest(), block.parent());
        let consensus_context = block.context();
        let round = consensus_context.round();
        let sync_targets = A::sync_targets(block.inner());

        let batches = self.fork_batches(&parent_digest).await?;
        let Some(merkleized) = app
            .process(
                (context.child("process"), consensus_context),
                ancestry,
                batches,
                Finality::Candidate,
            )
            .await
        else {
            warn!(block = ?digest, "application rejected block");
            return Err(PrepareBatchesError::Invalid);
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
        .then_some(())
        .ok_or(PrepareBatchesError::Invalid)
    }

    /// Processes the first block of `ancestry` as [`Self::replay`] does, sharing the call with
    /// concurrent requests for the same block.
    ///
    /// Returns immediately if the block is cached or is the branch anchor. Otherwise one request
    /// processes the block and the others receive its result, including a failure. If the
    /// processing request is dropped before it finishes, a waiting request processes the block
    /// again.
    async fn replay_shared(
        &self,
        app: &mut A,
        context: &E,
        ancestry: impl Ancestry<A::Block>,
    ) -> ReplayResult {
        let block = ancestry
            .peek()
            .expect("replayed ancestry must start with its block");
        let digest = block.digest();
        loop {
            match self.claim_replay(digest) {
                ReplayClaim::Ready => return Ok(()),
                ReplayClaim::Owner(owner) => {
                    let result = self.replay(app, context, ancestry).await;
                    owner.finish(result);
                    return result;
                }
                ReplayClaim::Wait(waiter) => match waiter.await {
                    Ok(result) => return result,
                    Err(_) => continue,
                },
            }
        }
    }

    /// Collects the missing blocks between `target` and cached or applied state without forking
    /// database batches.
    ///
    /// Returns [`PrepareBatchesError::Invalid`] if the walk reaches the anchor height without
    /// meeting the branch anchor, or if `provider` returns a block that is not the parent at the
    /// preceding height. Returns [`PrepareBatchesError::Incomplete`] if `provider` stops before
    /// delivering a parent.
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

        let mut replay_path = Vec::new();
        let mut cursor = target;
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

            let cursor_height = cursor.height();
            if cursor_height <= anchor.height {
                warn!(
                    ?target_digest,
                    cursor = ?cursor.digest(),
                    current_height = cursor_height.get(),
                    branch_height = anchor.height.get(),
                    branch_anchor = ?anchor.digest,
                    "rebuild_pending reached stale ancestry at or below anchor height"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            let Some(parent) = provider.subscribe_parent(&cursor).await else {
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
                    "rebuild_pending received non-contiguous ancestry"
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
        )))
    }

    #[cfg(test)]
    async fn rebuild_pending<P>(
        &self,
        app: &mut A,
        context: &E,
        provider: &P,
        target: Digested<A::Block>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let mut path = self.prepare_replay(context, provider, target).await?;
        while let Some(ancestry) = self.next_replay(context, provider, &mut path) {
            self.replay_shared(app, context, ancestry).await?;
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
        Applied, Disposition, ExecutionStep, FinalizationBoundary, PendingEntry,
        PrepareBatchesError, Processor, Prune, Pruning, ReplayClaim, ReplayResult,
    };
    use crate::stateful::{
        Application, Finality, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{Anchor, Barrier, DatabaseSet, Merkleized as _, Shared, Unmerkleized as _},
        tests::mocks::digested,
    };
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        Block as ConsensusBlock, CertifiableBlock, Heightable,
        marshal::ancestry::{self as marshal_ancestry, Ancestry, BlockProvider},
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
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, Location, full::Config as MmrJournalConfig},
        qmdb::{any, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, channel::oneshot, non_empty_range, range::NonEmptyRange, sync::Mutex,
    };
    use futures::{StreamExt, task::ArcWake};
    use std::{
        collections::{BTreeMap, HashSet, VecDeque},
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
    type DbSet<E> = Shared<Qmdb<E>>;
    type TestMerkleized =
        <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized;

    #[test]
    fn finalization_boundary_follows_completed_descendants() {
        let round = |view| Round::new(Epoch::zero(), View::new(view));
        let step = |digest, parent, view| ExecutionStep {
            digest,
            parent,
            round: round(view),
        };
        let mut boundary = FinalizationBoundary {
            digest: 10,
            round: round(10),
            compatible: HashSet::from([10, 11]),
        };

        // The finalized block parks, a later step on a cached descendant continues, and a step
        // on an uncached parent is rejected.
        assert_eq!(boundary.disposition(&step(10, 1, 10)), Disposition::Park);
        assert_eq!(boundary.disposition(&step(12, 11, 12)), Disposition::Retain);
        assert_eq!(boundary.disposition(&step(13, 12, 13)), Disposition::Reject);

        // A completed retained step can parent later steps. A step that is not in a later round
        // than the finalized block, or whose parent is unknown, stays rejected.
        boundary.completed(&step(12, 11, 12));
        assert_eq!(boundary.disposition(&step(13, 12, 13)), Disposition::Retain);
        assert_eq!(boundary.disposition(&step(14, 12, 10)), Disposition::Reject);
        assert_eq!(boundary.disposition(&step(20, 19, 11)), Disposition::Reject);
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

        async fn process(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            finality: Finality,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            let block = ancestry.next().await?;
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
            Some(Self::execute(block.height(), block.inner().context.round.view(), batches).await)
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
            block: &Digested<Self::Block>,
        ) -> impl Future<Output = Option<Digested<Self::Block>>> + Send + 'static {
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

    struct Harness {
        context_cell: ContextCell<deterministic::Context>,
        processor: Processor<deterministic::Context, ExecutionApp, Sequential>,
        provider: MapProvider,
        db_config: any::FixedConfig<TwoCap, Sequential>,
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
            config: any::FixedConfig<TwoCap, Sequential>,
            app: ExecutionApp,
        ) -> Self {
            let databases = <DbSet<deterministic::Context> as DatabaseSet<
                deterministic::Context,
            >>::init(context.child("databases"), config.clone(), None)
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
                PendingEntry {
                    round,
                    parent: parent.digest(),
                    merkleized,
                },
            ));
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

    fn qmdb_config(prefix: &str) -> any::FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
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
            let config = qmdb_config("db_config");
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
                Some(Pruning::new(
                    PruneConfig {
                        maintenance_interval: NZUsize!(1),
                        retained_marshal_blocks: 1,
                        retained_qmdb_blocks: 1,
                    },
                    1,
                    0,
                )),
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
            let databases = harness.processor.databases().clone();
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

            // Hold the child's processing with a second request waiting on it.
            let (gate, started, release) = apply_gate();
            harness.processor.app.process_probe =
                Some(ApplicationProbe::new(child.digest(), [gate]));
            let execution = harness.processor.execution.clone();
            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = owner_app.clone();
            let replay_context = harness.context_cell.as_present().child("replay");
            let mut owner = Box::pin(execution.replay_shared(
                &mut owner_app,
                &replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            started.await.unwrap();
            let mut waiter = Box::pin(execution.replay_shared(
                &mut waiter_app,
                &replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            // The parent's boundary retains the child's step before the child is cached.
            let boundary = harness.processor.boundary(&digested(parent.clone()));
            assert_eq!(
                boundary.disposition(&ExecutionStep {
                    digest: child.digest(),
                    parent: child.parent(),
                    round: child.context.round,
                }),
                Disposition::Retain,
            );
            assert!(!boundary.compatible.contains(&child.digest()));

            // A retained replay can cache its state while other requests finish, and its waiter
            // can observe that success after the parent's finalization.
            release.send(()).unwrap();
            assert_eq!(owner.await, Ok(()));
            assert!(harness.finalize(parent.clone()).await);
            assert!(!execution.pending_contains(&parent.digest()));
            assert!(execution.pending_contains(&child.digest()));
            assert_eq!(waiter.await, Ok(()));
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
            let databases = harness.processor.databases().clone();
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

    #[test]
    fn execution_descendant_replay_survives_finalized_parent_removal() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let parent = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (child, _) = harness.build_child(&parent, View::new(2)).await;

            let (owner_gate, owner_started, mut owner_release) = apply_gate();
            let (retry_gate, retry_started, retry_release) = apply_gate();
            harness.processor.app.process_probe = Some(ApplicationProbe::new(
                child.digest(),
                [owner_gate, retry_gate],
            ));
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(parent.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();

            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();

            let mut owner = Box::pin(execution.replay_shared(
                &mut owner_app,
                replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            owner_started.await.expect("replay owner must start");

            let mut waiter = Box::pin(execution.replay_shared(
                &mut waiter_app,
                replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut waiter).is_pending());
            let boundary = harness.processor.boundary(&digested(parent.clone()));
            assert_eq!(
                boundary.disposition(&ExecutionStep {
                    digest: child.digest(),
                    parent: child.parent(),
                    round: child.context.round,
                }),
                Disposition::Retain,
            );

            let finalized_block = digested(parent.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &finalized_block,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            finalized_started.await.expect("finalized hook must start");

            drop(owner);
            owner_release.closed().await;

            select! {
                result = &mut waiter => {
                    panic!("retained replay must restart before completing: {result:?}");
                },
                result = retry_started => {
                    result.expect("retained replay must restart from finalized state");
                },
            }
            retry_release
                .send(())
                .expect("retried replay must remain active");
            assert_eq!(waiter.await, Ok(()));

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize.await;
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
            harness.processor.app.process_probe = Some(ApplicationProbe::new(
                child.digest(),
                [owner_gate, retry_gate],
            ));
            let (finalized_gate, finalized_started, finalized_release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(parent.digest(), [finalized_gate]));

            let execution = harness.processor.execution.clone();

            let mut owner_app = harness.processor.app.clone();
            let mut waiter_app = harness.processor.app.clone();
            let replay_context = harness.context_cell.as_present();

            let mut owner = Box::pin(execution.replay_shared(
                &mut owner_app,
                replay_context,
                marshal_ancestry::from_iter([digested(child.clone())]),
            ));
            assert!(futures::poll!(&mut owner).is_pending());
            owner_started.await.expect("replay owner must start");

            let mut waiter = Box::pin(execution.replay_shared(
                &mut waiter_app,
                replay_context,
                marshal_ancestry::from_iter([digested(child)]),
            ));
            assert!(futures::poll!(&mut waiter).is_pending());

            let finalized_block = digested(parent.clone());
            let mut finalize = Box::pin(harness.processor.finalize(
                harness.context_cell.as_present(),
                &harness.provider,
                &finalized_block,
                true,
            ));
            assert!(futures::poll!(&mut finalize).is_pending());
            finalized_started.await.expect("finalized hook must start");

            drop(owner);
            owner_release.closed().await;
            select! {
                result = &mut waiter => {
                    panic!("retained replay must restart before completing: {result:?}");
                },
                result = retry_started => {
                    result.expect("retained replay must restart from finalized state");
                },
            }

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            let Applied { barrier, .. } = finalize.await;
            assert_durable(barrier).await;
            assert!(matches!(
                observations.lock().as_slice(),
                [FinalizedObservation { post_view: 1, .. }]
            ));

            retry_release
                .send(())
                .expect("retried replay must remain active");
            assert_eq!(waiter.await, Ok(()));
        });
    }

    /// The caller must finish every execution of the finalized block before its finalization
    /// starts, so finalization panics on an in-flight replay of the block.
    #[test]
    #[should_panic(expected = "finalized block must not be processed when its finalization starts")]
    fn execution_finalization_rejects_in_flight_winner() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let (winner, _) = harness.build_child(&genesis, View::new(1)).await;
            let execution = harness.processor.execution.clone();

            let ReplayClaim::Owner(_replay) = execution.claim_replay(winner.digest()) else {
                panic!("uncached winner must be claimable");
            };
            harness.finalize(winner).await;
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
            assert!(
                !harness.processor.cache_pending(
                    late_child.digest(),
                    PendingEntry {
                        round: Round::new(Epoch::zero(), late_view),
                        parent: loser.digest(),
                        merkleized,
                    },
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

                // The cached state answers a later request without processing block3 again.
                assert_eq!(
                    harness
                        .processor
                        .execution
                        .replay_shared(
                            &mut harness.processor.app,
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
            },
        );
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

    struct WakeCheck<F>(F);

    impl<F: Fn() + Send + Sync> ArcWake for WakeCheck<F> {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            (arc_self.0)();
        }
    }

    #[rstest::rstest]
    #[case::success(Some(Ok(())), false)]
    #[case::invalid(Some(Err(PrepareBatchesError::Invalid)), false)]
    #[case::owner_cancelled(None, false)]
    #[case::waiter_cancelled(None, true)]
    fn replay_notifications_release_state_lock(
        #[case] result: Option<ReplayResult>,
        #[case] cancel_waiter: bool,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let (block, merkleized) = harness.build_child(&Block::genesis(), View::new(1)).await;
            let digest = block.digest();
            let execution = &harness.processor.execution;

            // When the waiter is woken, the state lock must be free, the flight removed, and the
            // block cached only after a success.
            let ReplayClaim::Owner(owner) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let ReplayClaim::Wait(mut waiter) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let state = execution.state.clone();
            let wakes = Arc::new(AtomicUsize::new(0));
            let observed = wakes.clone();
            let waker = futures::task::waker(Arc::new(WakeCheck(move || {
                let state = state
                    .try_lock()
                    .expect("notification must release execution state");
                assert!(!state.flights.contains_key(&digest));
                assert_eq!(state.pending.contains_key(&digest), result == Some(Ok(())));
                observed.fetch_add(1, Ordering::SeqCst);
            })));
            assert!(
                Pin::new(&mut waiter)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );

            // Resolve the flight with the case's outcome.
            if cancel_waiter {
                drop(waiter);
                drop(owner);
            } else if let Some(result) = result {
                if result.is_ok() {
                    assert!(execution.cache_pending(
                        digest,
                        PendingEntry {
                            round: Round::new(Epoch::zero(), View::new(1)),
                            parent: block.parent(),
                            merkleized,
                        }
                    ));
                }
                owner.finish(result);
                assert_eq!(waiter.await, Ok(result));
            } else {
                drop(owner);
                assert!(waiter.await.is_err());
            }

            // Every outcome except a cancelled waiter wakes the waiter, and none leaves a flight.
            assert_eq!(wakes.load(Ordering::SeqCst) == 0, cancel_waiter);
            assert!(harness.processor.replays_idle());
        });
    }

    #[test]
    fn dropped_replay_waiter_releases_waker() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let execution = &harness.processor.execution;
            let digest = u64_to_digest(999);
            let ReplayClaim::Owner(owner) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let ReplayClaim::Wait(mut waiter) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let ReplayClaim::Wait(survivor) = execution.claim_replay(digest) else {
                unreachable!()
            };

            // Dropping a polled waiter releases its waker while the flight stays active.
            let wakes = Arc::new(AtomicUsize::new(0));
            let observed = wakes.clone();
            let callback = Arc::new(WakeCheck(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }));
            let weak = Arc::downgrade(&callback);
            let waker = futures::task::waker(callback);
            assert!(
                Pin::new(&mut waiter)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop(waker);
            assert!(weak.upgrade().is_some());
            drop(waiter);
            assert!(weak.upgrade().is_none());
            assert!(!harness.processor.replays_idle());

            // The surviving waiter receives the owner's result, and the dropped waker never fires.
            owner.finish(Err(PrepareBatchesError::Invalid));
            assert_eq!(survivor.await, Ok(Err(PrepareBatchesError::Invalid)));
            assert_eq!(wakes.load(Ordering::SeqCst), 0);
            assert!(harness.processor.replays_idle());
        });
    }

    #[test]
    fn replay_owner_remains_active_without_waiters() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            let execution = &harness.processor.execution;
            let digest = u64_to_digest(999);

            // An owner without waiters holds its flight until it is dropped.
            let ReplayClaim::Owner(owner) = execution.claim_replay(digest) else {
                unreachable!()
            };
            assert!(!harness.processor.replays_idle());
            drop(owner);
            assert!(harness.processor.replays_idle());

            // Dropping every waiter, polled or not, leaves the owner's flight active.
            let ReplayClaim::Owner(owner) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let ReplayClaim::Wait(mut polled) = execution.claim_replay(digest) else {
                unreachable!()
            };
            let ReplayClaim::Wait(unpolled) = execution.claim_replay(digest) else {
                unreachable!()
            };
            assert!(futures::poll!(&mut polled).is_pending());
            drop(polled);
            drop(unpolled);
            assert!(!harness.processor.replays_idle());

            // A later waiter joins the same flight and receives the owner's result.
            let ReplayClaim::Wait(late) = execution.claim_replay(digest) else {
                panic!("a late waiter must join the original owner")
            };
            owner.finish(Err(PrepareBatchesError::Invalid));
            assert_eq!(late.await, Ok(Err(PrepareBatchesError::Invalid)));
            assert!(harness.processor.replays_idle());
        });
    }

    #[rstest::rstest]
    #[case::uncontended(true, 0)]
    #[case::shared_success(true, 16)]
    #[case::shared_invalid_commitment(false, 16)]
    fn replay_shares_terminal_result(#[case] valid: bool, #[case] waiter_count: usize) {
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

                // Hold the owner inside the application's process call.
                let (gate, started, release) = apply_gate();
                let probe = ApplicationProbe::new(digest, [gate]);
                let mut app = harness.processor.app.clone();
                app.process_probe = Some(probe.clone());
                let execution = &harness.processor.execution;
                let mut owner_app = app.clone();
                let mut owner = Box::pin(execution.replay_shared(
                    &mut owner_app,
                    &context,
                    ancestry.clone(),
                ));
                select! {
                    result = &mut owner => panic!("owner must reach the execution gate: {result:?}"),
                    result = started => result.expect("owner must enter execution"),
                }

                // Polled waiters and an unpolled claim join the owner without another call.
                let mut waiters = Vec::new();
                for _ in 0..waiter_count {
                    let mut app = app.clone();
                    let context = &context;
                    let ancestry = ancestry.clone();
                    let mut waiter = Box::pin(async move {
                        execution.replay_shared(&mut app, context, ancestry).await
                    });
                    assert!(futures::poll!(&mut waiter).is_pending());
                    waiters.push(waiter);
                }
                let unpolled = (waiter_count != 0).then(|| {
                    let ReplayClaim::Wait(waiter) = execution.claim_replay(digest) else {
                        panic!("an unpolled waiter must join the owner")
                    };
                    waiter
                });
                assert_eq!(probe.calls(), 1);

                // Every request receives the owner's result from its single call.
                release.send(()).expect("owner must still be executing");

                let expected = if valid {
                    Ok(())
                } else {
                    Err(PrepareBatchesError::Invalid)
                };
                assert_eq!(owner.await, expected);
                for result in futures::future::join_all(waiters).await {
                    assert_eq!(result, expected);
                }
                if let Some(waiter) = unpolled {
                    assert_eq!(waiter.await, Ok(expected));
                }
                assert_eq!(probe.calls(), 1);
                assert!(harness.processor.replays_idle());

                // A cached success answers a later request without another call.
                if valid {
                    assert_eq!(
                        execution.replay_shared(&mut app, &context, ancestry).await,
                        Ok(()),
                    );
                    assert_eq!(probe.calls(), 1);
                }
            },
        );
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
                harness.processor.app.process_probe = Some(probe.clone());

                let first_execution = harness.processor.execution.clone();
                let second_execution = harness.processor.execution.clone();
                let third_execution = harness.processor.execution.clone();
                let fourth_execution = harness.processor.execution.clone();
                let mut first_app = harness.processor.app.clone();
                let mut second_app = harness.processor.app.clone();
                let mut third_app = harness.processor.app.clone();
                let mut fourth_app = harness.processor.app.clone();

                let mut first = Box::pin(first_execution.rebuild_pending(
                    &mut first_app,
                    &context,
                    &harness.provider,
                    digested(block2.clone()),
                ));
                select! {
                    result = &mut first => panic!("first rebuild completed before replay gate: {result:?}"),
                    result = first_started => result.expect("first replay should start"),
                }

                let mut second = Box::pin(second_execution.rebuild_pending(
                    &mut second_app,
                    &context,
                    &harness.provider,
                    digested(block2.clone()),
                ));
                let mut third = Box::pin(third_execution.rebuild_pending(
                    &mut third_app,
                    &context,
                    &harness.provider,
                    digested(block3),
                ));
                let mut fourth = Box::pin(fourth_execution.rebuild_pending(
                    &mut fourth_app,
                    &context,
                    &harness.provider,
                    digested(block2),
                ));
                assert!(futures::poll!(&mut second).is_pending());
                assert!(futures::poll!(&mut third).is_pending());
                assert!(futures::poll!(&mut fourth).is_pending());
                assert!(futures::poll!(&mut duplicate_started).is_pending());
                assert_eq!(probe.calls(), 1);

                drop(fourth);
                assert!(futures::poll!(&mut first).is_pending());
                assert!(futures::poll!(&mut second).is_pending());
                assert!(futures::poll!(&mut third).is_pending());

                drop(first);
                first_release.closed().await;
                select! {
                    result = &mut second => panic!("waiter completed before retry gate: {result:?}"),
                    result = &mut third => panic!("waiter completed before retry gate: {result:?}"),
                    result = retry_started => result.expect("live waiter should acquire replay ownership"),
                    result = &mut duplicate_started => {
                        result.expect("duplicate replay signal should remain available");
                        panic!("multiple waiters acquired replay ownership");
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
                };
                assert_eq!(second_result, Ok(()));
                assert_eq!(third_result, Ok(()));
                assert_eq!(probe.calls(), 2);
                assert!(harness.processor.replays_idle());
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
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
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
}
