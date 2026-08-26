//! Speculative execution engine for the [`Stateful`](super::Stateful) actor.
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
//! A job is a chain of stages ([`stages`]): futures over owned inputs that
//! the actor polls in a pool ([`Handler`]). Between stages the actor runs
//! [`Processor::step`]; jobs never touch the pending map, the anchor, or the
//! replay table themselves, and every fork a job executes on is taken inside
//! a step.
//!
//! The databases live outside the [`Processor`] and every mutation takes them
//! by value. The one step that needs them, a fork from the applied anchor,
//! waits until the mutation returns them ([`Processor::settle`] retries it);
//! every other step runs while the mutation is in flight. So no fork can
//! straddle an apply. Storage alone could not enforce this: a fork taken
//! after an apply but before the anchor moved would record the new commitment
//! and pass its stale-read checks while the job believed its parent was the
//! old anchor.
//!
//! A job on the losing side of an apply is refused at its next database read
//! ([`Stale`](crate::stateful::ExecutionError::Stale)). By the time that
//! outcome reaches a step the finalization has moved the anchor, so the step
//! re-checks the candidate against the new canonical chain: a candidate that
//! itself finalized is true, one whose branch lost is false, and one still
//! undecided executes again.

use crate::stateful::{
    Application, Input, Proposed, PruneConfig,
    actor::metrics::Metrics as StatefulMetrics,
    db::{
        Anchor, Barrier, DatabaseSet, MerkleizedOf, ReadersOf, SnapshotsOf, SyncTargetsOf,
        UnmerkleizedOf,
    },
};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable, Roundable,
    marshal::{
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::{Height, Round},
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::metrics::{GaugeExt, histogram::Timer},
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand_core::Rng;
use std::collections::{BTreeMap, HashSet, VecDeque};
use tracing::{Instrument as _, Span, debug, info_span, warn};

mod jobs;
mod stages;
use jobs::{Acquired, Caller, Carry, Failure, Fetched, Insert, Interrupted, Outcome, ReplayResult};
pub(super) use jobs::{Handler, Request};

pub(super) type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = MerkleizedOf<<A as Application<E>>::Databases, E>;
type PendingMap<A, E> = BTreeMap<PendingDigest<A, E>, PendingEntry<A, E>>;
pub(super) type PendingSyncTargets<A, E> = SyncTargetsOf<<A as Application<E>>::Databases, E>;
type DeferredPrune<T> = Option<Prune<T>>;

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
    parent: PendingDigest<A, E>,
    merkleized: PendingBatches<A, E>,
    provenance: Provenance,
}

/// Returns the winner and pending descendants whose state survives finalization.
fn compatible_pending<A, E>(
    pending: &PendingMap<A, E>,
    finalized_digest: PendingDigest<A, E>,
    finalized_round: Round,
) -> HashSet<PendingDigest<A, E>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let mut children_by_parent = BTreeMap::new();
    for (candidate_digest, entry) in pending {
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

/// Runs `stage` over `carry` in the job pool, returning the carry with its
/// outcome.
macro_rules! dispatch {
    ($jobs:expr, $carry:ident, $stage:expr) => {{
        let span = $carry.span.clone();
        $jobs.push(
            async move {
                let outcome = $stage.await;
                ($carry, outcome)
            }
            .instrument(span),
        );
    }};
}

/// Marshal and database prune targets selected from finalized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prune<T> {
    marshal_height: Height,
    pub(super) barrier_height: Height,
    qmdb_target: T,
}

impl<T> Prune<T> {
    /// Prune `databases` and `marshal` to this target.
    ///
    /// # Invariant
    ///
    /// Databases must be durable through `barrier_height`.
    pub(super) async fn run<E, D, S, V>(self, databases: D, marshal: &MarshalMailbox<S, V>) -> D
    where
        D: DatabaseSet<E, SyncTargets = T>,
        S: Scheme,
        V: MarshalVariant,
    {
        let databases = databases.prune(&self.qmdb_target).await;
        marshal.prune(self.marshal_height);
        databases
    }
}

/// A finalization between its bookkeeping and its apply.
pub(super) struct Finalizing<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    batch: Option<PendingBatches<A, E>>,
    timer: Timer,
}

impl<A, E> Finalizing<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The block's cached state, or `None` when it has to be replayed.
    pub(super) fn batch(&self) -> Option<PendingBatches<A, E>> {
        self.batch.clone()
    }
}

/// Where a job's next batches come from.
enum Fork<U> {
    Batches(U),
    /// The parent is the anchor and the databases are inside a mutation.
    Deferred,
    Unknown,
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
    /// Merkleized state for unfinalized blocks.
    pending: PendingMap<A, E>,
    /// Latest canonical anchor whose finalization hook has completed.
    last_processed: Anchor<PendingDigest<A, E>>,
    /// Replays in flight, keyed by the block being replayed, with the jobs
    /// waiting for each.
    replays: BTreeMap<PendingDigest<A, E>, Vec<oneshot::Sender<ReplayResult>>>,
    /// Jobs whose next fork is from the anchor, waiting for the databases to
    /// return from a mutation.
    deferred: Vec<Carry<E, A>>,
    metrics: StatefulMetrics,
    pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a new processor with the given application and the last
    /// finalized block's anchor.
    pub(super) const fn new(
        app: A,
        last_processed: Anchor<PendingDigest<A, E>>,
        metrics: StatefulMetrics,
        pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
    ) -> Self {
        Self {
            app,
            pending: BTreeMap::new(),
            last_processed,
            replays: BTreeMap::new(),
            deferred: Vec::new(),
            metrics,
            pruning,
        }
    }

    pub(super) fn app(&self) -> A {
        self.app.clone()
    }

    /// The height of the last finalized block applied to the databases.
    pub(super) const fn processed_height(&self) -> Height {
        self.last_processed.height
    }

    /// Start finalizing `block`: its bookkeeping before the apply.
    ///
    /// Returns [`None`] when the block was already applied, which happens when
    /// marshal reports it twice.
    pub(super) fn begin_finalize(&self, context: &E, block: &A::Block) -> Option<Finalizing<A, E>> {
        let (height, digest) = (block.height(), block.digest());
        let last_processed = self.last_processed;
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
            return None;
        }

        // Marshal finalization is ordered. A pending miss means the block can
        // be replayed on top of finalized state.
        Some(Finalizing {
            batch: self
                .pending
                .get(&digest)
                .map(|entry| entry.merkleized.clone()),
            timer: self.metrics.finalize_duration.timer(context),
        })
    }

    /// Apply a finalized block to `databases`, replaying it when `batch` is
    /// `None`, and report it to the application.
    ///
    /// Returns the databases and, only when `start_sync` is set, the snapshot
    /// to publish and the barrier proving that snapshot durable.
    pub(super) async fn apply_finalized(
        mut app: A,
        databases: A::Databases,
        context: &E,
        block: &A::Block,
        batch: Option<PendingBatches<A, E>>,
        sync_targets: &PendingSyncTargets<A, E>,
        start_sync: bool,
    ) -> (
        A::Databases,
        Option<SnapshotsOf<A::Databases, E>>,
        Option<Barrier>,
    ) {
        let batch = match batch {
            Some(batch) => batch,
            None => {
                let batches = A::Databases::new_batches(&databases);
                let batch = match app
                    .apply(
                        (context.child("finalize_replay"), block.context()),
                        block,
                        batches,
                    )
                    .await
                {
                    Ok(batch) => batch,
                    // Impossible on a correct node, since the batches were just forked
                    // from applied state, mutation authority is unique, and
                    // there is no caller to answer with a refusal.
                    Err(err) => panic!("finalize replay failed: {err}"),
                };
                assert!(
                    A::Databases::matches_sync_targets(&batch, sync_targets),
                    "finalize replay state root must match block commitments",
                );
                batch
            }
        };

        let mut databases = databases.apply(batch).await;
        let (snapshots, barrier) = if start_sync {
            let (snapshots, barrier);
            (databases, snapshots, barrier) = databases.finalize().await;
            (Some(snapshots), Some(barrier))
        } else {
            (None, None)
        };
        Self::notify_finalized(app, databases.readers(), context, block).await;
        (databases, snapshots, barrier)
    }

    /// Finish finalizing `block` once it is applied: record it for pruning and
    /// move the anchor. Returns any prune now due.
    pub(super) fn finish_finalize(
        &mut self,
        context: &E,
        block: &A::Block,
        sync_targets: PendingSyncTargets<A, E>,
        finalizing: Finalizing<A, E>,
    ) -> DeferredPrune<PendingSyncTargets<A, E>> {
        let height = block.height();
        let prune = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe_finalized(height, sync_targets));
        self.advance_to_finalized(Anchor {
            height,
            round: block.context().round(),
            digest: block.digest(),
        });
        finalizing.timer.observe(context);
        prune
    }

    /// Notify the application that marshal delivered a finalized block already
    /// reflected in the database set.
    pub(super) async fn notify_finalized(
        mut app: A,
        readers: ReadersOf<A::Databases, E>,
        context: &E,
        block: &A::Block,
    ) {
        app.finalized(
            (context.child("finalized"), block.context()),
            block,
            readers,
        )
        .await;
    }

    /// Move the anchor to a finalized block and drop the pending state that
    /// block invalidates. A pending block survives only when it descends from
    /// the anchor and was created after its round.
    fn advance_to_finalized(&mut self, anchor: Anchor<PendingDigest<A, E>>) {
        let compatible = compatible_pending(&self.pending, anchor.digest, anchor.round);
        let before = self.pending.len();
        self.pending
            .retain(|digest, entry| entry.round > anchor.round && compatible.contains(digest));
        let pruned = before - self.pending.len();
        self.last_processed = anchor;
        self.metrics.pruned_forks.inc_by(pruned as u64);
        self.update_pending_metric();
    }

    fn known(&self, digest: &PendingDigest<A, E>) -> bool {
        self.last_processed.digest == *digest || self.pending.contains_key(digest)
    }

    /// Whether `digest` has cached state that completed `verify` (or a local
    /// proposal). Speculative `apply` replay state does not count, so a
    /// certification that reconstructed an ancestor cannot fast-answer without
    /// a real verification verdict for that ancestor's own digest.
    fn pending_verified(&self, digest: &PendingDigest<A, E>) -> bool {
        self.pending
            .get(digest)
            .is_some_and(|entry| entry.provenance == Provenance::Verified)
    }

    fn update_pending_metric(&self) {
        let _ = self.metrics.pending_blocks.try_set(self.pending.len());
    }

    /// Fork batches from a known parent: its pending state, or the applied
    /// databases when it is the anchor.
    fn fork_from(
        &self,
        parent: &PendingDigest<A, E>,
        databases: Option<&A::Databases>,
    ) -> Fork<UnmerkleizedOf<A::Databases, E>> {
        if let Some(entry) = self.pending.get(parent) {
            return Fork::Batches(A::Databases::fork_batches(&entry.merkleized));
        }
        if self.last_processed.digest != *parent {
            return Fork::Unknown;
        }
        databases.map_or(Fork::Deferred, |databases| {
            Fork::Batches(A::Databases::new_batches(databases))
        })
    }

    /// Cache `merkleized` for `digest` unless the anchor already moved past its
    /// branch.
    fn insert(
        &mut self,
        digest: PendingDigest<A, E>,
        parent: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
        provenance: Provenance,
    ) -> bool {
        if let Some(existing) = self.pending.get_mut(&digest) {
            debug_assert_eq!(existing.parent, parent, "pending parent changed for digest");
            debug_assert_eq!(existing.round, round, "pending round changed for digest");
            // A real verification verdict promotes speculative replay state, so
            // a later certification of this digest fast-answers honestly.
            // `Applied` never demotes an entry that already verified.
            if provenance == Provenance::Verified {
                existing.provenance = Provenance::Verified;
            }
            return true;
        }

        // A replay of the block the anchor now sits on is already reflected in
        // applied state.
        if self.last_processed.digest == digest && self.last_processed.round == round {
            return true;
        }

        // A verdict can land after the anchor moved past its branch. This is
        // where it is refused.
        let compatible = round > self.last_processed.round
            && (parent == self.last_processed.digest || self.pending.contains_key(&parent));
        if !compatible {
            return false;
        }
        self.pending.insert(
            digest,
            PendingEntry {
                round,
                parent,
                merkleized,
                provenance,
            },
        );
        true
    }
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E>,
{
    /// Start a verification job.
    pub(super) fn schedule<S, V>(&self, jobs: &mut Handler<E, A, S, V>, request: Request<E, A>)
    where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        // Upgrade to an independent cursor. A cancelled caller cannot provide
        // one, so the request is dropped and its response channel closes.
        let Some(ancestry) = request.ancestry.upgrade() else {
            return;
        };
        let span = info_span!(parent: &request.span, "stateful.actor.verify");
        let timer = self.metrics.verify_duration.timer(&request.context.0);
        let mut carry = Carry {
            span,
            context: request.context,
            ancestry,
            caller: Caller::Verify(request.verification),
            candidate: None,
            parent: None,
            anchor: self.last_processed,
            path: VecDeque::new(),
            timer,
            rebuild: None,
        };
        dispatch!(jobs, carry, stages::candidate(&mut carry));
    }

    /// Start a proposal job. The block and its merkleized state are cached in
    /// `pending`; `response` gets `None` if the ancestry is invalid or the
    /// application declines to propose.
    pub(super) fn propose<S, V>(
        &self,
        jobs: &mut Handler<E, A, S, V>,
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        input: Input<A::Input, A::Provider>,
        response: oneshot::Sender<Option<A::Block>>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        jobs.start_proposal();
        let timer = self.metrics.propose_duration.timer(&context.0);
        let mut carry = Carry {
            span,
            context,
            ancestry,
            caller: Caller::Propose {
                response,
                input: Some(input),
            },
            candidate: None,
            parent: None,
            anchor: self.last_processed,
            path: VecDeque::new(),
            timer,
            rebuild: None,
        };
        dispatch!(jobs, carry, stages::parent(&mut carry));
    }

    /// Retain verified state and step every job that finished since the last
    /// call. With the databases in hand, also retry the jobs whose fork from
    /// the anchor waited for them.
    pub(super) fn settle<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        for Insert {
            digest,
            parent,
            round,
            merkleized,
        } in jobs.take_inserts()
        {
            if !self.insert(digest, parent, round, merkleized, Provenance::Verified) {
                debug!(
                    parent_digest = ?parent,
                    block_digest = ?digest,
                    "verified state not cached, overtaken by finalization"
                );
            }
            self.update_pending_metric();
        }
        if databases.is_some() {
            for carry in std::mem::take(&mut self.deferred) {
                self.continue_path(jobs, databases, carry);
            }
        }
        for (carry, outcome) in jobs.take_steps() {
            self.step(jobs, databases, carry, outcome);
        }
    }

    /// Advance one job past a completed stage.
    fn step<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        mut carry: Carry<E, A>,
        outcome: Outcome<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        match outcome {
            Outcome::Candidate(Fetched::Ready) => self.classify(jobs, databases, carry),
            Outcome::Parent(Acquired::Ready) => self.lookup(jobs, databases, carry),
            Outcome::Parent(Acquired::Declined) => jobs.deliver(carry, None),
            Outcome::Candidate(Fetched::Cancelled)
            | Outcome::Parent(Acquired::Cancelled)
            | Outcome::Classified(None)
            | Outcome::Walked(Err(Failure::Cancelled))
            | Outcome::Verified(Err(Interrupted::Cancelled))
            | Outcome::Proposed(Err(Interrupted::Cancelled))
            | Outcome::Woken(None) => jobs.release(carry),
            Outcome::Classified(Some(_)) | Outcome::Verified(Ok(_)) => {
                unreachable!("verdicts are answered on admission")
            }
            Outcome::Walked(Ok(path)) => {
                let _ = self.metrics.rebuild_pending_depth.try_set(path.len());
                carry.path = path.into();
                self.continue_path(jobs, databases, carry);
            }
            Outcome::Walked(Err(Failure::Invalid)) => self.invalid(jobs, databases, carry),
            Outcome::Walked(Err(Failure::Stale)) => unreachable!("walking reads no database"),
            Outcome::Replayed(result) => self.replayed(jobs, databases, carry, result),
            Outcome::Verified(Err(Interrupted::Stale)) => self.stale(jobs, databases, carry),
            Outcome::Proposed(Ok(Some(Proposed { block, merkleized }))) => {
                assert!(
                    A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)),
                    "proposed state must match block commitments",
                );
                let round = carry.context.1.round();
                assert!(
                    self.insert(
                        block.digest(),
                        carry.parent().digest(),
                        round,
                        merkleized,
                        Provenance::Verified,
                    ),
                    "proposal parent must remain compatible until the proposal completes",
                );
                self.update_pending_metric();
                jobs.deliver(carry, Some(block));
            }
            Outcome::Proposed(Ok(None)) => jobs.deliver(carry, None),
            Outcome::Proposed(Err(Interrupted::Stale)) => self.stale(jobs, databases, carry),
            Outcome::Woken(Some(Ok(()))) | Outcome::Woken(Some(Err(Failure::Cancelled))) => {
                self.continue_path(jobs, databases, carry)
            }
            Outcome::Woken(Some(Err(Failure::Invalid))) => self.invalid(jobs, databases, carry),
            Outcome::Woken(Some(Err(Failure::Stale))) => self.stale(jobs, databases, carry),
        }
    }

    /// Decide a verification from the canonical chain, or go on to its parent.
    fn classify<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        mut carry: Carry<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        carry.anchor = self.last_processed;
        let (height, digest) = (carry.candidate().height(), carry.candidate().digest());

        // A finalized candidate cannot be re-executed against newer database
        // state. Prove it belongs to the canonical chain before accepting it.
        if height < carry.anchor.height {
            let marshal = jobs.marshal();
            return dispatch!(jobs, carry, stages::classify(&mut carry, marshal));
        }
        if height == carry.anchor.height {
            let canonical = digest == carry.anchor.digest;
            return carry.answer(canonical);
        }
        if self.pending_verified(&digest) {
            return carry.answer(true);
        }
        if carry.parent.is_some() {
            return self.lookup(jobs, databases, carry);
        }
        dispatch!(jobs, carry, stages::parent(&mut carry));
    }

    /// Fork the parent's state, or start rebuilding it.
    fn lookup<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        mut carry: Carry<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        carry.anchor = self.last_processed;
        carry.path.clear();
        if self.known(&carry.parent().digest()) {
            return self.continue_path(jobs, databases, carry);
        }
        carry.rebuild = Some(
            self.metrics
                .rebuild_pending_duration
                .timer(&carry.context.0),
        );
        let known = self.pending.keys().copied().collect();
        let marshal = jobs.marshal();
        dispatch!(jobs, carry, stages::walk(&mut carry, marshal, known));
    }

    /// Replay the next missing block of the path, or fork the parent once none
    /// are left.
    fn continue_path<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        mut carry: Carry<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        while let Some(block) = carry.path.front() {
            let (digest, parent) = (block.digest(), block.parent());
            if self.known(&digest) {
                carry.path.pop_front();
                continue;
            }

            // One job replays each block. The rest wait for its result.
            if let Some(waiters) = self.replays.get_mut(&digest) {
                let (sender, completion) = oneshot::channel();
                waiters.push(sender);
                return dispatch!(jobs, carry, stages::wait(&mut carry, completion));
            }
            let batches = match self.fork_from(&parent, databases) {
                Fork::Batches(batches) => batches,
                Fork::Deferred => return self.deferred.push(carry),
                Fork::Unknown => return self.invalid(jobs, databases, carry),
            };
            self.replays.insert(digest, Vec::new());
            let app = self.app.clone();
            return dispatch!(jobs, carry, stages::replay(&mut carry, app, batches));
        }

        if let Some(timer) = carry.rebuild.take() {
            timer.observe(&carry.context.0);
        }
        let batches = match self.fork_from(&carry.parent().digest(), databases) {
            Fork::Batches(batches) => batches,
            Fork::Deferred => return self.deferred.push(carry),
            Fork::Unknown => return self.invalid(jobs, databases, carry),
        };
        let app = self.app.clone();
        match carry.caller {
            Caller::Verify(_) => dispatch!(jobs, carry, stages::verify(&mut carry, app, batches)),
            Caller::Propose { .. } => {
                dispatch!(jobs, carry, stages::propose(&mut carry, app, batches))
            }
        }
    }

    /// Retain a replayed block and release the jobs waiting on it.
    fn replayed<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        mut carry: Carry<E, A>,
        result: Result<PendingBatches<A, E>, Failure>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let block = carry
            .path
            .front()
            .expect("a replay stage has a block to replay");
        let (digest, parent, round) = (block.digest(), block.parent(), block.context().round());
        let result = result.and_then(|merkleized| {
            // Replayed state that the anchor already moved past is refused here.
            self.insert(digest, parent, round, merkleized, Provenance::Applied)
                .then_some(())
                .ok_or(Failure::Invalid)
        });
        let waiters = self
            .replays
            .remove(&digest)
            .expect("a replay owner has an entry");
        for waiter in waiters {
            waiter.send_lossy(result);
        }
        match result {
            Ok(()) => {
                carry.path.pop_front();
                self.update_pending_metric();
                self.continue_path(jobs, databases, carry);
            }
            Err(Failure::Invalid) => self.invalid(jobs, databases, carry),
            Err(Failure::Stale) => self.stale(jobs, databases, carry),
            Err(Failure::Cancelled) => jobs.release(carry),
        }
    }

    /// The job's ancestry proved invalid against the anchor it was looked up
    /// under.
    fn invalid<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        carry: Carry<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        match carry.caller {
            Caller::Propose { .. } => jobs.deliver(carry, None),
            // An anchor that moved during the attempt can make valid ancestry
            // look invalid (the finalization dropped the parent from the
            // pending map), so re-classify. A stable anchor means the ancestry
            // is genuinely invalid.
            Caller::Verify(_) if carry.anchor != self.last_processed => {
                self.classify(jobs, databases, carry)
            }
            Caller::Verify(_) => {
                warn!(
                    parent_digest = ?carry.parent().digest(),
                    block_digest = ?carry.candidate().digest(),
                    pending_keys = self.pending.len(),
                    last_processed = ?self.last_processed.digest,
                    "verification rejected: ancestry invalid against the applied anchor"
                );
                carry.answer(false);
            }
        }
    }

    /// A finalization invalidated the job's batches. It has moved the anchor,
    /// so re-classify.
    fn stale<S, V>(
        &mut self,
        jobs: &mut Handler<E, A, S, V>,
        databases: Option<&A::Databases>,
        carry: Carry<E, A>,
    ) where
        S: Scheme + 'static,
        V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        match carry.caller {
            Caller::Verify(_) => {
                debug_assert_ne!(
                    carry.anchor, self.last_processed,
                    "a stale batch implies an apply, which moves the anchor before any step",
                );
                self.classify(jobs, databases, carry);
            }
            // Unreachable, since the actor admits no finalization while a
            // proposal runs (it becomes the FIFO barrier).
            Caller::Propose { .. } => {
                warn!(parent_digest = ?carry.parent().digest(), "proposal went stale");
                debug_assert!(false, "no finalization can interleave a proposal");
                jobs.deliver(carry, None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clock, Fork, Metrics, PendingDigest, Processor, Provenance, Prune, Pruning, Rng, Spawner,
        jobs::{Caller, Carry, Failure, Outcome},
        stages,
    };

    impl<E, A> Processor<E, A>
    where
        E: Rng + Spawner + Metrics + Clock,
        A: Application<E>,
    {
        fn fork(
            &self,
            parent: &PendingDigest<A, E>,
            databases: &A::Databases,
        ) -> Option<UnmerkleizedOf<A::Databases, E>> {
            match self.fork_from(parent, Some(databases)) {
                Fork::Batches(batches) => Some(batches),
                Fork::Deferred | Fork::Unknown => None,
            }
        }

        fn last_processed(&self) -> Anchor<PendingDigest<A, E>> {
            self.last_processed
        }

        fn pending_contains(&self, digest: &PendingDigest<A, E>) -> bool {
            self.pending.contains_key(digest)
        }

        fn clear_pending(&mut self) {
            self.pending.clear();
        }
    }

    impl Processor<deterministic::Context, ExecutionApp> {
        /// Rebuild `target`'s missing ancestry through `provider`, running the
        /// walk and replay stages a job would and retaining each replayed block.
        async fn rebuild_pending(
            &mut self,
            context: &deterministic::Context,
            databases: &DbSet<deterministic::Context>,
            provider: impl BlockProvider<Block = Block> + Clone,
            target: Arc<Block>,
            response: oneshot::Sender<Option<Block>>,
        ) -> Result<(), Failure> {
            let mut carry: Carry<deterministic::Context, ExecutionApp> = Carry {
                span: tracing::Span::none(),
                context: (context.child("rebuild_pending"), target.context()),
                ancestry: BoxedAncestry::new(from_iter(std::iter::empty::<Arc<Block>>())),
                caller: Caller::Propose {
                    response,
                    input: None,
                },
                candidate: None,
                parent: Some(target),
                anchor: self.last_processed,
                path: VecDeque::new(),
                timer: self.metrics.verify_duration.timer(context),
                rebuild: None,
            };
            let known = self.pending.keys().copied().collect();
            let path = match stages::walk(&mut carry, provider, known).await {
                Outcome::Walked(path) => path?,
                _ => unreachable!("walk resolves to Walked"),
            };
            carry.path = path.into();
            while let Some(block) = carry.path.front().cloned() {
                let batches = self
                    .fork(&block.parent(), databases)
                    .ok_or(Failure::Invalid)?;
                let merkleized = match stages::replay(&mut carry, self.app.clone(), batches).await {
                    Outcome::Replayed(replayed) => replayed?,
                    _ => unreachable!("replay resolves to Replayed"),
                };
                if !self.insert(
                    block.digest(),
                    block.parent(),
                    block.context().round,
                    merkleized,
                    Provenance::Applied,
                ) {
                    return Err(Failure::Invalid);
                }
                carry.path.pop_front();
            }
            Ok(())
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
        marshal::ancestry::{Ancestry, BlockProvider, BoxedAncestry, from_iter},
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
        databases: DbSet<deterministic::Context>,
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
                DbSet::<deterministic::Context>::init(context.child("db_set"), config.clone())
                    .await;
            let metrics = StatefulMetrics::new(&context);
            Self {
                context_cell: ContextCell::new(context),
                processor: Processor::new(
                    app,
                    Anchor {
                        height: Height::zero(),
                        round: Block::genesis().context().round,
                        digest: Block::genesis().digest(),
                    },
                    metrics,
                    prune_config.map(|config| Pruning::build(config, 1, 0)),
                ),
                databases,
                provider,
                db_config: config,
            }
        }

        async fn build_child(&self, parent: &Block, view: View) -> (Block, TestMerkleized) {
            let context = consensus_context(parent.digest(), view);
            let height = Height::new(parent.height().get() + 1);
            let batches = self
                .processor
                .fork(&parent.digest(), &self.databases)
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

        fn fork_from(&self, parent: &Block) -> TestUnmerkleized {
            self.processor
                .fork(&parent.digest(), &self.databases)
                .expect("parent must be forkable")
        }

        async fn stage_pending_child(&mut self, parent: &Block, view: View) -> Block {
            let (block, merkleized) = self.build_child(parent, view).await;
            let round = Round::new(Epoch::zero(), view);
            assert!(self.processor.insert(
                block.digest(),
                parent.digest(),
                round,
                merkleized,
                Provenance::Verified,
            ));
            self.provider.insert(block.clone());
            block
        }

        /// Finalize `block` and wait for its database sync.
        /// Returns whether the block was newly applied (`false` for a
        /// duplicate report).
        #[boxed]
        async fn finalize(self, block: Block) -> (Self, bool) {
            let (harness, prune) = self.finalize_steps(&block).await;
            (harness, prune.is_some())
        }

        #[boxed]
        async fn finalize_with_prune(
            self,
            block: Block,
        ) -> (
            Self,
            Option<Prune<SyncTargetsOf<DbSet<deterministic::Context>, deterministic::Context>>>,
        ) {
            let (harness, prune) = self.finalize_steps(&block).await;
            (harness, prune.expect("finalized block must apply"))
        }

        /// Run the three finalization steps for `block` and wait for its
        /// database sync. Returns the prune made due, or `None` for a duplicate
        /// report.
        async fn finalize_steps(
            mut self,
            block: &Block,
        ) -> (
            Self,
            Option<
                Option<Prune<SyncTargetsOf<DbSet<deterministic::Context>, deterministic::Context>>>,
            >,
        ) {
            let context = self.context_cell.as_present();
            let Some(finalizing) = self.processor.begin_finalize(context, block) else {
                return (self, None);
            };
            let sync_targets = ExecutionApp::sync_targets(block);
            let (databases, _, barrier) = Processor::apply_finalized(
                self.processor.app(),
                self.databases,
                context,
                block,
                finalizing.batch(),
                &sync_targets,
                true,
            )
            .await;
            self.databases = databases;
            let prune = self
                .processor
                .finish_finalize(context, block, sync_targets, finalizing);
            assert_durable(barrier).await;
            (self, Some(prune))
        }

        async fn height_value(&self, height: Height) -> Option<u64> {
            self.databases
                .readers()
                .read()
                .await
                .get(&height_key(height))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn counter_value(&self) -> Option<u64> {
            self.databases
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

    /// A batch forked before a competing finalization refuses its next operation with
    /// the typed stale error, end to end through the set wrapper, the database cell,
    /// and the storage checks.
    #[test]
    fn stale_fork_refuses_through_the_set() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Fork from the applied anchor, then finalize a competing child.
            let stale = harness.fork_from(&genesis);
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

    #[test]
    fn execution_finalize_awaits_its_finalized_hook() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block = harness.stage_pending_child(&genesis, View::new(1)).await;

            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(block.digest(), [gate]));
            let context = harness.context_cell.as_present();
            let finalizing = harness
                .processor
                .begin_finalize(context, &block)
                .expect("finalized block should be newly applied");
            let sync_targets = ExecutionApp::sync_targets(&block);
            let mut finalize = Box::pin(Processor::apply_finalized(
                harness.processor.app(),
                harness.databases,
                context,
                &block,
                finalizing.batch(),
                &sync_targets,
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
            let (_databases, _, barrier) = finalize.await;
            assert_durable(barrier).await;
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
                !harness.processor.insert(
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

            let (response, _rx) = oneshot::channel::<Option<Block>>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.databases,
                    harness.provider.clone(),
                    Arc::new(block3.clone()),
                    response,
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
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            // Stage a replayed (apply-provenance) child of the applied anchor.
            let (replayed, replayed_merkleized) = harness.build_child(&genesis, View::new(1)).await;
            let replayed_round = Round::new(Epoch::zero(), View::new(1));
            assert!(harness.processor.insert(
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
            assert!(harness.processor.insert(
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
            assert!(harness.processor.insert(
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
            assert!(
                harness
                    .processor
                    .fork(&u64_to_digest(999), &harness.databases)
                    .is_none()
            );
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

            let (response, _rx) = oneshot::channel::<Option<Block>>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.databases,
                    harness.provider.clone(),
                    Arc::new(stale),
                    response,
                )
                .await;
            assert_eq!(
                result,
                Err(Failure::Invalid),
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

            let (response, _rx) = oneshot::channel::<Option<Block>>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.databases,
                    harness.provider.clone(),
                    Arc::new(block2.clone()),
                    response,
                )
                .await;
            assert_eq!(
                result,
                Err(Failure::Invalid),
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
                .fork(&block1.digest(), &harness.databases)
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

            let (response, _rx) = oneshot::channel::<Option<Block>>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.databases,
                    provider,
                    Arc::new(gap_block.clone()),
                    response,
                )
                .await;

            assert_eq!(
                result,
                Err(Failure::Invalid),
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
            let (response, _rx) = oneshot::channel::<Option<Block>>();
            let result = harness
                .processor
                .rebuild_pending(
                    harness.context_cell.as_present(),
                    &harness.databases,
                    provider.clone(),
                    Arc::new(block3.clone()),
                    response,
                )
                .await;

            assert_eq!(result, Err(Failure::Invalid));
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
            Processor::notify_finalized(
                harness.processor.app(),
                harness.databases.readers(),
                harness.context_cell.as_present(),
                &block1,
            )
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
            let (response, receiver) = oneshot::channel::<Option<Block>>();
            let mut caller = Caller::<Block, (), ()>::Propose {
                response,
                input: None,
            };
            let mut ancestry = Box::pin(futures::stream::pending::<Block>());
            drop(receiver);

            assert!(
                stages::fetch_ancestor(&mut caller, &mut ancestry)
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn execution_rebuild_pending_parks_when_parent_subscription_ends() {
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

            // Incomplete ancestry is not a verdict. The walk parks until the
            // caller drops its request.
            let (response, rx) = oneshot::channel::<Option<Block>>();
            let mut rebuild = Box::pin(harness.processor.rebuild_pending(
                harness.context_cell.as_present(),
                &harness.databases,
                provider,
                Arc::new(block2),
                response,
            ));
            select! {
                _ = &mut rebuild => panic!("incomplete ancestry must park the rebuild"),
                _ = harness.context_cell.as_present().sleep(Duration::from_millis(10)) => {},
            }

            drop(rx);
            assert_eq!(rebuild.await, Err(Failure::Cancelled));
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

            let (response, rx) = oneshot::channel::<Option<Block>>();
            let mut rebuild = Box::pin(harness.processor.rebuild_pending(
                harness.context_cell.as_present(),
                &harness.databases,
                provider.clone(),
                Arc::new(block2),
                response,
            ));
            select! {
                _ = &mut rebuild => panic!("incomplete ancestry must park the rebuild"),
                _ = harness.context_cell.as_present().sleep(Duration::from_millis(10)) => {},
            }
            assert_eq!(
                provider.fetches(),
                1,
                "closed ancestry should not be retried"
            );

            drop(rx);
            assert_eq!(rebuild.await, Err(Failure::Cancelled));
        });
    }
}
