//! Speculative execution engine for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] owns the applied database set, the in-memory pending-tip
//! DAG, and the verification and proposal jobs, and does the work behind the
//! actor's `Processing` mode.
//!
//! - Propose/Verify: fork unmerkleized batches from a parent's pending state
//!   (or from applied state), delegate to the [`Application`], and cache the
//!   resulting merkleized batches keyed by block digest.
//!
//! - Lazy recovery: when a parent's pending state is missing (e.g. after
//!   restart), a job walks the block DAG backward via marshal to the nearest
//!   known anchor, then replays forward via [`Application::apply`], caching
//!   each intermediate result. Jobs that need the same replay share it.
//!
//! - Finalization: apply the winning fork's merkleized batches to the
//!   databases, move the anchor, then retain only pending descendants of the
//!   winner. The actor starts durability separately ([`Processor::sync`]) so
//!   multiple finalizations can be covered by one storage sync.
//!
//! - Maintenance: [`Processor::prune`] runs due prunes and
//!   [`Processor::publish_snapshot`] publishes fresh snapshots afterwards.
//!
//! # How verification races finalization
//!
//! Finalization never waits for verification. The processor applies a
//! finalized block immediately, and jobs keep running through the apply.
//!
//! A job is a chain of stages ([`stages`]): futures over owned inputs that the
//! processor polls in a pool. Between stages the processor steps the job
//! synchronously. That step is the only code that reads or writes the pending
//! map, the anchor, or the replay table, and every fork a job executes on is
//! taken in a step.
//!
//! Every database mutation takes the databases out of the processor and puts
//! them back only after the anchor reflects it. Steps run while the mutation is
//! in flight, except two that defer until the databases are back: a fork from
//! the applied anchor, and a job whose batch storage refused
//! ([`Stale`](crate::stateful::ExecutionError::Stale)) because it sat on the
//! losing side of the apply. So no fork can straddle an apply, and a stale job
//! is always re-checked against the new canonical chain: a candidate that
//! itself finalized is true, one whose branch lost is false, and one still
//! undecided executes again. Storage alone could not enforce the first part: a
//! fork taken after an apply but before the anchor moved would record the new
//! commitment and pass its stale-read checks while the job believed its parent
//! was the old anchor.
//!
//! A job waiting on another job's replay or deferred on the databases notices
//! its caller's cancellation when it is resumed, bounded by one block apply or
//! one mutation.

use crate::stateful::{
    Application, Input, Proposed, PruneConfig,
    actor::{core::Request, metrics::Metrics as StatefulMetrics},
    db::{
        Anchor, Barrier, DatabaseSet, MerkleizedOf, Publisher, SnapshotsOf, SyncTargetsOf,
        UnmerkleizedOf,
    },
};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable, Roundable,
    marshal::ancestry::BoxedAncestry,
    types::{Height, Round},
};
use commonware_cryptography::Digestible;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::GaugeExt};
use commonware_utils::{channel::oneshot, futures::Pool};
use futures::{FutureExt as _, future};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
    iter::once,
    sync::Arc,
};
use tracing::{Instrument as _, Span, debug, info_span, warn};

mod jobs;
mod stages;
use jobs::{Caller, Job, Outcome, Stale};
pub(super) use stages::Marshal;

pub(super) type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = MerkleizedOf<<A as Application<E>>::Databases, E>;
type PendingMap<A, E> = BTreeMap<PendingDigest<A, E>, PendingEntry<A, E>>;
pub(super) type PendingSyncTargets<A, E> = SyncTargetsOf<<A as Application<E>>::Databases, E>;

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

/// Runs `stage` over `job` in the processor's pool unless the caller drops its
/// request, returning the job with its outcome.
///
/// `stage` may borrow fields of `job` but must not call `Job` methods: the
/// cancellation arm holds `job.caller` while `stage` is built.
macro_rules! dispatch {
    ($processor:expr, $job:ident, $stage:expr) => {{
        let span = $job.span.clone();
        $processor.jobs.push(
            async move {
                let outcome = select! {
                    _ = $job.caller.cancelled() => {
                        debug!("caller dropped its request");
                        Outcome::Cancelled
                    },
                    outcome = $stage => outcome,
                };
                ($job, outcome)
            }
            .instrument(span),
        );
    }};
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
    fn observe_finalized(&mut self, height: Height, targets: T) -> Option<Prune<T>> {
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

/// Marshal and database prune targets selected from finalized history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prune<T> {
    marshal_height: Height,
    pub(super) barrier_height: Height,
    qmdb_target: T,
}

/// Where a job's next batches come from.
enum Fork<U> {
    Batches(U),
    /// The parent is the anchor and the databases are inside a mutation.
    Deferred,
    Unknown,
}

/// Owns speculative execution and the applied databases for a running
/// stateful actor.
pub(super) struct Processor<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    app: A,
    /// The applied databases, taken out while a mutation runs.
    databases: Option<A::Databases>,
    marshal: P,
    /// Serves the latest snapshots of the applied state.
    publisher: Publisher<SnapshotsOf<A::Databases, E>>,
    /// The stage each live job is running.
    jobs: Pool<(Job<E, A>, Outcome<E, A>)>,
    /// Whether a proposal job is live.
    proposing: bool,
    /// Merkleized state for unfinalized blocks.
    pending: PendingMap<A, E>,
    /// Latest canonical anchor applied to the databases.
    last_processed: Anchor<PendingDigest<A, E>>,
    /// Replays in flight, keyed by the block being replayed, with the jobs
    /// waiting on each.
    replays: BTreeMap<PendingDigest<A, E>, Vec<Job<E, A>>>,
    /// Jobs deferred until the databases are back from a mutation.
    deferred: Vec<Job<E, A>>,
    metrics: StatefulMetrics,
    pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
}

impl<E, A, P> Processor<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E>,
    P: Marshal<Block = A::Block>,
{
    /// Create a processor over `databases`, applied through the anchor
    /// `last_processed`.
    pub(super) fn new(
        app: A,
        databases: A::Databases,
        marshal: P,
        publisher: Publisher<SnapshotsOf<A::Databases, E>>,
        last_processed: Anchor<PendingDigest<A, E>>,
        metrics: StatefulMetrics,
        pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
    ) -> Self {
        Self {
            app,
            databases: Some(databases),
            marshal,
            publisher,
            jobs: Pool::default(),
            proposing: false,
            pending: BTreeMap::new(),
            last_processed,
            replays: BTreeMap::new(),
            deferred: Vec::new(),
            metrics,
            pruning,
        }
    }

    /// The height of the last finalized block applied to the databases.
    pub(super) const fn processed_height(&self) -> Height {
        self.last_processed.height
    }

    /// Whether a proposal job is live.
    pub(super) const fn proposing(&self) -> bool {
        self.proposing
    }

    const fn databases(&self) -> &A::Databases {
        self.databases
            .as_ref()
            .expect("a mutation owns the databases only inside a processor method")
    }

    /// Run `operation` while stepping the jobs that finish meanwhile.
    async fn drive<T>(&mut self, operation: impl Future<Output = T>) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => return output,
                _ = self.step_next() => {},
            }
        }
    }

    /// Run one mutation of the databases, stepping jobs meanwhile. Forks from
    /// the anchor and stale jobs defer until it returns.
    async fn mutate<T, F>(&mut self, mutation: impl FnOnce(A::Databases) -> F) -> T
    where
        F: Future<Output = (A::Databases, T)>,
    {
        let databases = self.take_databases();
        let (databases, output) = self.drive(mutation(databases)).await;
        self.restore(databases);
        output
    }

    /// Take the databases for a mutation.
    fn take_databases(&mut self) -> A::Databases {
        assert!(!self.proposing, "no mutation runs while a proposal is live");
        self.databases.take().expect("one mutation at a time")
    }

    /// Put the databases back and resume the jobs deferred on them.
    fn restore(&mut self, databases: A::Databases) {
        self.databases = Some(databases);
        // Only verifications defer on the databases: no mutation overlaps a
        // proposal.
        for job in std::mem::take(&mut self.deferred) {
            self.classify(job);
        }
    }

    /// Capture snapshots of the applied state, serve them, and start
    /// persisting them. Returns the height they were captured at and its
    /// durability barrier.
    pub(super) async fn sync(&mut self) -> (Height, Barrier) {
        let (snapshots, barrier) = self
            .mutate(|databases| async move {
                let (databases, snapshots, barrier) = databases.finalize().await;
                (databases, (snapshots, barrier))
            })
            .await;
        // The snapshots serve immediately; peers verify what they fetch against
        // a finalized root, so serving safely runs ahead of disk.
        let height = self.last_processed.height;
        self.publisher.publish(height, snapshots);
        (height, barrier)
    }

    /// Serve a fresh snapshot of the applied state.
    pub(super) async fn publish_snapshot(&mut self) {
        let snapshots = self.mutate(DatabaseSet::snapshot).await;
        self.publisher
            .publish(self.last_processed.height, snapshots);
    }

    /// Prune the databases and marshal to `prune`'s targets.
    ///
    /// # Invariant
    ///
    /// The databases must be durable through `prune.barrier_height`.
    pub(super) async fn prune(&mut self, prune: Prune<PendingSyncTargets<A, E>>) {
        let Prune {
            marshal_height,
            qmdb_target,
            ..
        } = prune;
        self.mutate(|databases| async move { (databases.prune(&qmdb_target).await, ()) })
            .await;
        self.marshal.prune(marshal_height);
    }

    /// Whether `block` is already reflected in the databases, which happens
    /// when marshal reports it twice.
    ///
    /// Panics on a block below the anchor or a conflicting digest at its
    /// height.
    pub(super) fn processed(&self, block: &A::Block) -> bool {
        let (height, digest) = (block.height(), block.digest());
        let anchor = self.last_processed;
        if height < anchor.height {
            panic!(
                "received finalized block below processed height: finalized={} processed={}",
                height.get(),
                anchor.height.get(),
            );
        }
        if height == anchor.height {
            assert_eq!(
                digest, anchor.digest,
                "received conflicting finalized block at processed height",
            );
            return true;
        }
        false
    }

    /// Apply `block`, replaying it when its state is not cached, and move the
    /// anchor. Returns any prune now due.
    pub(super) async fn finalize(
        &mut self,
        context: &E,
        block: &A::Block,
    ) -> Option<Prune<PendingSyncTargets<A, E>>> {
        assert!(
            !self.processed(block),
            "finalize called on a processed block"
        );
        let timer = self.metrics.finalize_duration.timer(context);
        let sync_targets = A::sync_targets(block);
        // Marshal finalization is ordered. A pending miss means the block can
        // be replayed on top of finalized state.
        let batch = self
            .pending
            .get(&block.digest())
            .map(|entry| entry.merkleized.clone());
        let mut app = self.app.clone();
        let databases = self.take_databases();
        let apply = async {
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
                        A::Databases::matches_sync_targets(&batch, &sync_targets),
                        "finalize replay state root must match block commitments",
                    );
                    batch
                }
            };
            databases.apply(batch).await
        };
        let databases = self.drive(apply).await;

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
        self.restore(databases);
        timer.observe(context);
        prune
    }

    /// Notify the application that marshal delivered a finalized block already
    /// reflected in the database set, stepping jobs meanwhile.
    pub(super) async fn notify_finalized(&mut self, context: &E, block: &A::Block) {
        let mut app = self.app.clone();
        let readers = self.databases().readers();
        let notify = app.finalized(
            (context.child("finalized"), block.context()),
            block,
            readers,
        );
        self.drive(notify).await;
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
    fn fork_from(&self, parent: &PendingDigest<A, E>) -> Fork<UnmerkleizedOf<A::Databases, E>> {
        if let Some(entry) = self.pending.get(parent) {
            return Fork::Batches(A::Databases::fork_batches(&entry.merkleized));
        }
        if self.last_processed.digest != *parent {
            return Fork::Unknown;
        }
        self.databases.as_ref().map_or(Fork::Deferred, |databases| {
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
        self.update_pending_metric();
        true
    }

    /// Start a verification job.
    pub(super) fn schedule(&mut self, request: Request<E, A>) {
        // Upgrade to an independent cursor. A cancelled caller cannot provide
        // one, so the request is dropped and its response channel closes.
        let Some(ancestry) = request.ancestry.upgrade() else {
            return;
        };
        let span = info_span!(parent: &request.span, "stateful.actor.verify");
        let timer = self.metrics.verify_duration.timer(&request.context.0);
        let mut job = Job {
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
        dispatch!(
            self,
            job,
            stages::fetch(&mut job.ancestry).map(Outcome::Candidate)
        );
    }

    /// Start a proposal job. The block and its merkleized state are cached in
    /// `pending`; `response` gets `None` if the ancestry is invalid or the
    /// application declines to propose.
    pub(super) fn propose(
        &mut self,
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        input: Input<A::Input, A::Provider>,
        response: oneshot::Sender<Option<A::Block>>,
    ) {
        assert!(!self.proposing, "the actor runs one proposal at a time");
        assert!(
            self.databases.is_some(),
            "no proposal starts while a mutation runs"
        );
        self.proposing = true;
        let timer = self.metrics.propose_duration.timer(&context.0);
        let mut job = Job {
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
        dispatch!(
            self,
            job,
            stages::fetch(&mut job.ancestry).map(Outcome::Parent)
        );
    }

    /// Wait for the next job to finish a stage, and step it.
    pub(super) async fn step_next(&mut self) {
        let (job, outcome) = self.jobs.next_completed().await;
        self.step(job, outcome);
    }

    /// Step every job that has already finished a stage, without waiting.
    pub(super) fn step_ready(&mut self) {
        while let Some((job, outcome)) = self.jobs.next_completed().now_or_never() {
            self.step(job, outcome);
        }
    }

    /// Advance one job past a completed stage.
    fn step(&mut self, mut job: Job<E, A>, outcome: Outcome<E, A>) {
        match outcome {
            Outcome::Cancelled => self.retire(job),
            Outcome::Candidate(Some(block)) => {
                job.candidate = Some(block);
                self.classify(job);
            }
            Outcome::Parent(Some(block)) => {
                job.parent = Some(block);
                self.lookup(job);
            }
            Outcome::Parent(None) if job.is_proposal() => self.deliver(job, None),
            // Incomplete ancestry is not a verdict.
            Outcome::Candidate(None) | Outcome::Parent(None) => {
                debug!("verification request waiting on incomplete ancestry");
                self.park(job);
            }
            Outcome::Canonical(None) => {
                warn!(
                    target_height = job.candidate().height().get(),
                    processed_height = job.anchor.height.get(),
                    "failed to fetch canonical block for a candidate below the processed height"
                );
                self.park(job);
            }
            Outcome::Canonical(Some(canonical)) => {
                let canonical = canonical == job.candidate().digest();
                job.answer(canonical);
            }
            Outcome::Walked(Some(path)) => {
                let _ = self.metrics.rebuild_pending_depth.try_set(path.len());
                job.path = path.into();
                self.advance(job);
            }
            Outcome::Walked(None) => self.invalid(job),
            Outcome::Replayed(result) => self.replayed(job, result),
            Outcome::Verified(Ok(None)) => {
                warn!(
                    parent_digest = ?job.parent().digest(),
                    block_digest = ?job.candidate().digest(),
                    "verification rejected: app.verify returned None"
                );
                job.answer(false);
            }
            Outcome::Verified(Ok(Some(merkleized))) => {
                let _job_span = job.span.clone().entered();
                let (digest, parent) = (job.candidate().digest(), job.parent().digest());
                let _span = info_span!(
                    "stateful.processor.match_commitments",
                    block = %digest,
                    parent = %parent,
                )
                .entered();

                // Application output is adversarial until it matches the
                // commitments carried by the candidate block. Never retain it
                // before this check.
                if !A::Databases::matches_sync_targets(
                    &merkleized,
                    &A::sync_targets(job.candidate()),
                ) {
                    warn!(
                        parent_digest = ?parent,
                        block_digest = ?digest,
                        "verification rejected: verified state must match block commitments"
                    );
                    return job.answer(false);
                }

                // Caching is retention, not part of the verdict. The execution
                // matched the block's commitments on its own branch.
                if !self.insert(
                    digest,
                    parent,
                    job.context.1.round(),
                    merkleized,
                    Provenance::Verified,
                ) {
                    debug!(
                        parent_digest = ?parent,
                        block_digest = ?digest,
                        "verified state not cached, overtaken by finalization"
                    );
                }
                job.answer(true);
            }
            Outcome::Verified(Err(Stale)) | Outcome::Proposed(Err(Stale)) => self.stale(job),
            Outcome::Proposed(Ok(None)) => self.deliver(job, None),
            Outcome::Proposed(Ok(Some(Proposed { block, merkleized }))) => {
                assert!(
                    A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)),
                    "proposed state must match block commitments",
                );
                assert!(
                    self.insert(
                        block.digest(),
                        job.parent().digest(),
                        job.context.1.round(),
                        merkleized,
                        Provenance::Verified,
                    ),
                    "proposal parent must remain compatible until the proposal completes",
                );
                self.deliver(job, Some(block));
            }
        }
    }

    /// Retire a job whose caller dropped its request. A replay owner hands its
    /// replay to the jobs waiting on it.
    fn retire(&mut self, job: Job<E, A>) {
        if job.is_proposal() {
            self.proposing = false;
        }
        if let Some(block) = job.path.front() {
            let waiters = self
                .replays
                .remove(&block.digest())
                .expect("a cancelled replay owner has an entry");
            for waiter in waiters {
                self.advance(waiter);
            }
        }
    }

    /// Hold a job on incomplete ancestry until its caller drops the request.
    fn park(&mut self, mut job: Job<E, A>) {
        debug_assert!(job.path.is_empty(), "only a replay owner carries a path");
        dispatch!(self, job, future::pending::<Outcome<E, A>>());
    }

    /// Answer a proposal and retire its job.
    fn deliver(&mut self, job: Job<E, A>, block: Option<A::Block>) {
        self.proposing = false;
        job.deliver(block);
    }

    /// Decide a verification from the canonical chain, or go on to its parent.
    fn classify(&mut self, mut job: Job<E, A>) {
        job.anchor = self.last_processed;
        job.path.clear();
        let (height, digest) = (job.candidate().height(), job.candidate().digest());

        // A finalized candidate cannot be re-executed against newer database
        // state. Prove it belongs to the canonical chain before accepting it.
        if height < job.anchor.height {
            let provider = self.marshal.clone();
            return dispatch!(
                self,
                job,
                stages::canonical(provider, height).map(Outcome::Canonical)
            );
        }
        if height == job.anchor.height {
            let canonical = digest == job.anchor.digest;
            return job.answer(canonical);
        }
        if self.pending_verified(&digest) {
            return job.answer(true);
        }
        if job.parent.is_some() {
            return self.lookup(job);
        }
        dispatch!(
            self,
            job,
            stages::fetch(&mut job.ancestry).map(Outcome::Parent)
        );
    }

    /// Fork the parent's state, or start rebuilding it.
    fn lookup(&mut self, mut job: Job<E, A>) {
        debug_assert!(job.path.is_empty(), "only a replay owner carries a path");
        job.anchor = self.last_processed;
        if self.known(&job.parent().digest()) {
            return self.advance(job);
        }
        job.rebuild = Some(self.metrics.rebuild_pending_duration.timer(&job.context.0));
        let known = self.pending.keys().copied().collect();
        let provider = self.marshal.clone();
        let (parent, anchor) = (Arc::clone(job.parent()), job.anchor);
        dispatch!(
            self,
            job,
            stages::walk(provider, parent, anchor, known).map(Outcome::Walked)
        );
    }

    /// Replay the next missing block of the path, or execute on the parent
    /// once none are left.
    fn advance(&mut self, mut job: Job<E, A>) {
        // Another job may have replayed the front of the path meanwhile.
        while job
            .path
            .front()
            .is_some_and(|block| self.known(&block.digest()))
        {
            job.path.pop_front();
        }
        let replaying = job.path.front().map(Arc::clone);
        let parent = match &replaying {
            Some(block) => block.parent(),
            None => {
                if let Some(timer) = job.rebuild.take() {
                    timer.observe(&job.context.0);
                }
                job.parent().digest()
            }
        };

        // One job replays each block. The rest wait on it.
        if let Some(waiters) = replaying
            .as_ref()
            .and_then(|block| self.replays.get_mut(&block.digest()))
        {
            return waiters.push(job);
        }
        let batches = match self.fork_from(&parent) {
            Fork::Batches(batches) => batches,
            Fork::Deferred => return self.deferred.push(job),
            Fork::Unknown => return self.invalid(job),
        };
        let app = self.app.clone();
        match replaying {
            Some(block) => {
                self.replays.insert(block.digest(), Vec::new());
                let context = job.context.0.child("replay_apply");
                dispatch!(
                    self,
                    job,
                    stages::replay(app, context, block, batches).map(Outcome::Replayed)
                );
            }
            None if job.is_proposal() => {
                let Caller::Propose { input, .. } = &mut job.caller else {
                    unreachable!("only proposals reach the propose stage")
                };
                let input = input.take().expect("a proposal builds once");
                // The application takes the caller's runtime context by value.
                // Keep a child as the clock for the proposal timer.
                let clock = job.context.0.child("propose_timer");
                let runtime_context = std::mem::replace(&mut job.context.0, clock);
                let context = (runtime_context, job.context.1.clone());
                let (parent, ancestry) = (Arc::clone(job.parent()), job.ancestry.clone());
                dispatch!(
                    self,
                    job,
                    stages::propose(app, context, parent, ancestry, batches, input)
                        .map(Outcome::Proposed)
                );
            }
            None => {
                let context = (
                    job.context.0.child("application").child("verify_attempt"),
                    job.context.1.clone(),
                );
                let (candidate, parent) = (Arc::clone(job.candidate()), Arc::clone(job.parent()));
                let ancestry = job.ancestry.clone();
                dispatch!(
                    self,
                    job,
                    stages::verify(app, context, candidate, parent, ancestry, batches)
                        .map(Outcome::Verified)
                );
            }
        }
    }

    /// Retain a replayed block and resume the jobs waiting on its replay.
    fn replayed(&mut self, job: Job<E, A>, result: Result<PendingBatches<A, E>, Stale>) {
        let block = job
            .path
            .front()
            .expect("a replay stage has a block to replay");
        let digest = block.digest();
        let retained = result.map(|merkleized| {
            // Application output is adversarial until it matches the block's
            // commitments. Never retain it before this check.
            if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(block)) {
                warn!(block = ?digest, "replayed state root must match block commitments");
                return false;
            }
            // Replayed state that the anchor already moved past is refused here.
            self.insert(
                digest,
                block.parent(),
                block.context().round(),
                merkleized,
                Provenance::Applied,
            )
        });
        let waiters = self
            .replays
            .remove(&digest)
            .expect("a replay owner has an entry");

        // The owner goes first, so it registers the next replay before the
        // waiters can wait on it.
        for job in once(job).chain(waiters) {
            match retained {
                Ok(true) => self.advance(job),
                Ok(false) => self.invalid(job),
                Err(Stale) => self.stale(job),
            }
        }
    }

    /// The job's ancestry proved invalid against the anchor it was looked up
    /// under.
    fn invalid(&mut self, job: Job<E, A>) {
        match job.caller {
            Caller::Propose { .. } => self.deliver(job, None),
            // An anchor that moved during the attempt can make valid ancestry
            // look invalid (the finalization dropped the parent from the
            // pending map), so re-classify. A stable anchor means the ancestry
            // is genuinely invalid.
            Caller::Verify(_) if job.anchor != self.last_processed => self.classify(job),
            Caller::Verify(_) => {
                warn!(
                    parent_digest = ?job.parent().digest(),
                    block_digest = ?job.candidate().digest(),
                    pending_keys = self.pending.len(),
                    last_processed = ?self.last_processed.digest,
                    "verification rejected: ancestry invalid against the applied anchor"
                );
                job.answer(false);
            }
        }
    }

    /// A finalization invalidated the job's batches. Re-classify once the
    /// anchor reflects it.
    fn stale(&mut self, job: Job<E, A>) {
        assert!(
            !job.is_proposal(),
            "no mutation runs while a proposal is live"
        );
        debug!(
            parent_digest = ?job.parent().digest(),
            block_digest = ?job.candidate().digest(),
            "verification went stale during execution"
        );
        // The apply that refused the job has not returned the databases yet,
        // so the anchor has not moved. Defer until it has.
        if self.databases.is_none() {
            return self.deferred.push(job);
        }
        debug_assert_ne!(
            job.anchor, self.last_processed,
            "an apply moves the anchor before it returns the databases",
        );
        self.classify(job);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clock, Fork, Marshal, Metrics, PendingDigest, Processor, Provenance, Prune, Pruning, Rng,
        Spawner, stages,
    };
    use crate::stateful::{
        Application, ExecutionError, Input, Proposed, PruneConfig,
        actor::metrics::Metrics as StatefulMetrics,
        db::{
            Anchor, Barrier, DatabaseSet, Merkleized as _, MerkleizedOf, Publisher, ReadersOf,
            Single, SyncTargetsOf, UnmerkleizedOf,
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
    use futures::{Stream, StreamExt, poll};
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        future::Future,
        num::NonZeroUsize,
        pin::{Pin, pin},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{self, Poll},
        time::Duration,
    };

    impl<E, A, P> Processor<E, A, P>
    where
        E: Rng + Spawner + Metrics + Clock + 'static,
        A: Application<E>,
        P: Marshal<Block = A::Block>,
    {
        fn fork(&self, parent: &PendingDigest<A, E>) -> Option<UnmerkleizedOf<A::Databases, E>> {
            match self.fork_from(parent) {
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

    async fn assert_durable(barrier: Barrier) {
        assert!(barrier.durable().await, "database sync must complete");
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

    /// A block after `parent` with placeholder state. The walk reads only
    /// heights and parent links.
    fn linked_block(parent: &Block, view: View) -> Block {
        Block {
            context: consensus_context(parent.digest(), view),
            parent: parent.digest(),
            height: parent.height().next(),
            state_root: Digest::EMPTY,
            range: non_empty_range!(Location::new(0), Location::new(1)),
        }
    }

    fn anchor_at(block: &Block) -> Anchor<Digest> {
        Anchor {
            height: block.height(),
            round: block.context().round,
            digest: block.digest(),
        }
    }

    /// An ancestry that never yields, for requests cancelled before their
    /// first read.
    #[derive(Clone)]
    struct PendingAncestry;

    impl Stream for PendingAncestry {
        type Item = Arc<Block>;

        fn poll_next(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Ancestry<Block> for PendingAncestry {
        fn peek(&self) -> Option<&Block> {
            None
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
        verify_probe: Option<ApplicationProbe>,
        apply_probe: Option<ApplicationProbe>,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
                finalized_observer: None,
                finalized_probe: None,
                verify_probe: None,
                apply_probe: None,
            }
        }

        fn with_finalized_observer() -> (Self, Arc<Mutex<Vec<u64>>>) {
            let finalized_values = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    genesis: Block::genesis(),
                    finalized_observer: Some(finalized_values.clone()),
                    finalized_probe: None,
                    verify_probe: None,
                    apply_probe: None,
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
            if let Some(probe) = &self.verify_probe {
                probe.call(block.digest()).await;
            }
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
            if let Some(probe) = &self.apply_probe {
                probe.call(block.digest()).await;
            }
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

    impl Marshal for MapProvider {
        async fn canonical(&self, height: Height) -> Option<Digest> {
            self.blocks
                .lock()
                .values()
                .find(|block| block.height() == height)
                .map(Digestible::digest)
        }

        fn prune(&self, _: Height) {}
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
        processor: Processor<deterministic::Context, ExecutionApp, MapProvider>,
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
            provider.insert(Block::genesis());
            let databases =
                DbSet::<deterministic::Context>::init(context.child("db_set"), config.clone())
                    .await;
            let metrics = StatefulMetrics::new(&context);
            let (publisher, _) = Publisher::new(&context);
            Self {
                context_cell: ContextCell::new(context),
                processor: Processor::new(
                    app,
                    databases,
                    provider.clone(),
                    publisher,
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
                .fork(&parent.digest())
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
                .fork(&parent.digest())
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
        async fn finalize(&mut self, block: Block) -> bool {
            self.finalize_steps(&block).await.is_some()
        }

        #[boxed]
        async fn finalize_with_prune(
            &mut self,
            block: Block,
        ) -> Option<Prune<SyncTargetsOf<DbSet<deterministic::Context>, deterministic::Context>>>
        {
            self.finalize_steps(&block)
                .await
                .expect("finalized block must apply")
        }

        /// Run the finalization sequence the actor runs for `block` and wait
        /// for its database sync. Returns the prune made due, or `None` for a
        /// duplicate report.
        async fn finalize_steps(
            &mut self,
            block: &Block,
        ) -> Option<
            Option<Prune<SyncTargetsOf<DbSet<deterministic::Context>, deterministic::Context>>>,
        > {
            let context = self.context_cell.as_present();
            if self.processor.processed(block) {
                return None;
            }
            let prune = self.processor.finalize(context, block).await;
            let (_, barrier) = self.processor.sync().await;
            assert_durable(barrier).await;
            self.processor.notify_finalized(context, block).await;
            Some(prune)
        }

        /// Run a proposal on `parent` through the processor until it answers.
        async fn propose(&mut self, parent: &Block, view: View) -> Option<Block> {
            let (response, receiver) = oneshot::channel();
            let context = self.context_cell.as_present();
            self.processor.propose(
                tracing::Span::none(),
                (
                    context.child("propose"),
                    consensus_context(parent.digest(), view),
                ),
                BoxedAncestry::new(from_iter([Arc::new(parent.clone())])),
                Input {
                    upstream: (),
                    provider: (),
                },
                response,
            );
            self.run_until(receiver).await
        }

        /// Schedule a verification of `candidate` on `parent`, returning its verdict channel.
        fn verify(&mut self, candidate: &Block, parent: &Block) -> oneshot::Receiver<bool> {
            let (response, receiver) = oneshot::channel();
            let context = self.context_cell.as_present();
            let (_owner, request) = super::Request::new(
                tracing::Span::none(),
                (context.child("verify"), candidate.context()),
                from_iter([Arc::new(candidate.clone()), Arc::new(parent.clone())]),
                response,
            );
            self.processor.schedule(request);
            receiver
        }

        /// Step jobs until `receiver` resolves.
        async fn run_until<T>(&mut self, mut receiver: oneshot::Receiver<T>) -> T {
            loop {
                select! {
                    result = &mut receiver => return result.expect("job answers before dropping"),
                    _ = self.processor.step_next() => {},
                }
            }
        }

        async fn height_value(&self, height: Height) -> Option<u64> {
            self.processor
                .databases()
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
                .databases()
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

            let prune = harness.finalize_with_prune(block1).await;
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
            let applied = harness.finalize(winner).await;
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

            let applied = harness.finalize(winner.clone()).await;
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

            let applied = harness.finalize(winner.clone()).await;
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
    fn notify_finalized_awaits_the_application_hook() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block = harness.stage_pending_child(&genesis, View::new(1)).await;

            let (gate, mut started, release) = apply_gate();
            harness.processor.app.finalized_probe =
                Some(ApplicationProbe::new(block.digest(), [gate]));
            let context = harness.context_cell.as_present();
            harness.processor.finalize(context, &block).await;
            let mut notify = Box::pin(harness.processor.notify_finalized(context, &block));
            select! {
                _ = &mut notify => {
                    panic!("notification completed before its finalized hook returned");
                },
                result = &mut started => {
                    result.expect("finalized hook should start");
                },
            }

            release
                .send(())
                .expect("finalized hook should remain active");
            notify.await;
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

            let applied = harness.finalize(winner).await;
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
    fn rebuild_restores_missing_chain() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied = harness.finalize(block1.clone()).await;
            assert!(applied);

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
            harness.processor.clear_pending();

            let proposed = harness
                .propose(&block3, View::new(4))
                .await
                .expect("proposal should rebuild its parent state");
            assert_eq!(proposed.parent(), block3.digest());
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
            assert!(
                harness.processor.pending_verified(&proposed.digest()),
                "a local proposal counts as verified",
            );
        });
    }

    /// A real `verify` verdict promotes speculative replay state to verified so a
    /// later certification of that digest can fast-answer honestly, and `apply`
    /// replay never demotes an entry that already verified.
    #[test]
    fn insert_provenance_promotes_but_never_demotes() {
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
    fn fork_rejects_unknown_parent() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(context).await;
            assert!(matches!(
                harness.processor.fork_from(&u64_to_digest(999)),
                Fork::Unknown
            ));
        });
    }

    #[test]
    fn rebuild_rejects_stale_ancestor_quickly() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let mut chain = Vec::new();
            let mut parent = genesis;
            for view in 1..=5 {
                let block = harness.stage_pending_child(&parent, View::new(view)).await;
                let applied = harness.finalize(block.clone()).await;
                assert!(applied);
                parent = block.clone();
                chain.push(block);
            }

            harness.processor.clear_pending();
            let stale = chain[1].clone(); // height 2, below processed height 5
            let fetches_before = harness.provider.fetches();

            assert!(
                harness.propose(&stale, View::new(6)).await.is_none(),
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
    fn rebuild_rejects_sync_target_mismatch_before_caching() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let applied = harness.finalize(block1.clone()).await;
            assert!(applied);

            let mut block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            harness.processor.clear_pending();

            block2.range = non_empty_range!(Location::new(1), Location::new(2));
            harness.provider.insert(block2.clone());

            assert!(
                harness.propose(&block2, View::new(3)).await.is_none(),
                "rebuild should reject a replayed batch whose sync target does not match the block",
            );
            assert!(
                !harness.processor.pending_contains(&block2.digest()),
                "rejected replay must not be inserted into the pending cache",
            );
        });
    }

    #[test]
    fn walk_rejects_height_gap_to_processed_anchor() {
        deterministic::Runner::default().start(|_| async move {
            let block1 = linked_block(&Block::genesis(), View::new(1));
            let mut gap_block = linked_block(&block1, View::new(3));
            gap_block.height = Height::new(3);
            let provider = ScriptedParentProvider::default();
            provider.push(&gap_block, [Some(block1.clone())]);

            let path = stages::walk(
                provider,
                Arc::new(gap_block),
                anchor_at(&block1),
                BTreeSet::new(),
            )
            .await;
            assert!(
                path.is_none(),
                "the walk must reject non-contiguous ancestry above the processed anchor",
            );
        });
    }

    #[test]
    fn walk_rejects_wrong_parent_digest() {
        deterministic::Runner::default().start(|_| async move {
            let block1 = linked_block(&Block::genesis(), View::new(1));
            let block2 = linked_block(&block1, View::new(2));
            let block3 = linked_block(&block2, View::new(3));
            let mut wrong_parent = block2;
            wrong_parent.state_root = u64_to_digest(999);
            assert_ne!(wrong_parent.digest(), block3.parent());
            let provider = ScriptedParentProvider::default();
            provider.push(&block3, [Some(wrong_parent)]);

            let path = stages::walk(
                provider.clone(),
                Arc::new(block3),
                anchor_at(&block1),
                BTreeSet::new(),
            )
            .await;
            assert!(path.is_none());
            assert_eq!(provider.fetches(), 1);
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

            let applied = harness.finalize(canonical).await;
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

            let applied = harness.finalize(canonical.clone()).await;
            assert!(applied);
            let applied = harness.finalize(canonical).await;
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

            let applied = harness.finalize(block1).await;
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

            let applied = harness.finalize(block1).await;
            assert!(applied);
            let applied = harness.finalize(block2).await;
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

            let applied = harness.finalize(block1.clone()).await;
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
    fn proposal_cancelled_before_its_ancestry_arrives_is_retired() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let (response, receiver) = oneshot::channel();
            let context = harness.context_cell.as_present();
            harness.processor.propose(
                tracing::Span::none(),
                (
                    context.child("propose"),
                    consensus_context(Block::genesis().digest(), View::new(1)),
                ),
                BoxedAncestry::new(PendingAncestry),
                Input {
                    upstream: (),
                    provider: (),
                },
                response,
            );
            drop(receiver);

            harness.processor.step_next().await;
            assert!(!harness.processor.proposing());
            assert!(harness.processor.jobs.is_empty());
        });
    }

    #[test]
    fn walk_parks_when_parent_subscription_ends() {
        deterministic::Runner::default().start(|_| async move {
            let block1 = linked_block(&Block::genesis(), View::new(1));
            let block2 = linked_block(&block1, View::new(2));
            let provider = ScriptedParentProvider::default();
            provider.push(&block2, [None]);

            // Incomplete ancestry is not a verdict. The walk parks until its
            // caller drops the request.
            let mut walk = pin!(stages::walk(
                provider,
                Arc::new(block2),
                anchor_at(&block1),
                BTreeSet::new(),
            ));
            assert!(
                poll!(&mut walk).is_pending(),
                "incomplete ancestry must park the walk"
            );
        });
    }

    #[test]
    fn walk_does_not_retry_closed_provider_forever() {
        deterministic::Runner::default().start(|_| async move {
            let block1 = linked_block(&Block::genesis(), View::new(1));
            let block2 = linked_block(&block1, View::new(2));
            let provider = ScriptedParentProvider::default();
            provider.push(&block2, [None, Some(block1.clone())]);

            let mut walk = pin!(stages::walk(
                provider.clone(),
                Arc::new(block2),
                anchor_at(&block1),
                BTreeSet::new(),
            ));
            assert!(poll!(&mut walk).is_pending());
            assert!(poll!(&mut walk).is_pending());
            assert_eq!(
                provider.fetches(),
                1,
                "closed ancestry should not be retried"
            );
        });
    }

    /// While a mutation holds the databases, a fork from the anchor waits for
    /// them and a fork from pending state, including the block being
    /// finalized, does not.
    #[test]
    fn anchor_fork_defers_while_the_databases_are_out() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;

            let databases = harness
                .processor
                .databases
                .take()
                .expect("databases start in the processor");
            assert!(matches!(
                harness.processor.fork_from(&genesis.digest()),
                Fork::Deferred
            ));
            assert!(matches!(
                harness.processor.fork_from(&winner.digest()),
                Fork::Batches(_)
            ));
            harness.processor.databases = Some(databases);
            assert!(matches!(
                harness.processor.fork_from(&genesis.digest()),
                Fork::Batches(_)
            ));
        });
    }

    /// A job whose parent is the anchor defers while a finalization holds the
    /// databases, then forks from the new anchor once they return.
    #[test]
    fn anchor_fork_defers_until_the_databases_return() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (candidate, _) = harness.build_child(&winner, View::new(2)).await;
            // Uncached, so the finalization replays the winner and holds there.
            harness.processor.clear_pending();
            let (gate, started, release) = apply_gate();
            let probe = ApplicationProbe::new(winner.digest(), [gate]);
            harness.processor.app.apply_probe = Some(probe.clone());

            let mut verdict = harness.verify(&candidate, &winner);
            {
                let context = harness.context_cell.as_present();
                let mut finalize = pin!(harness.processor.finalize(context, &winner));
                assert!(poll!(&mut finalize).is_pending());
                started.await.expect("the replay should start");

                // The job walked to the anchor while the databases were out and
                // deferred on its fork.
                assert_eq!(harness.provider.fetches(), 1);
                assert!(poll!(&mut verdict).is_pending());

                release.send(()).expect("the replay should be held");
                finalize.await;
            }
            assert!(harness.run_until(verdict).await);
            assert_eq!(
                probe.calls.load(Ordering::SeqCst),
                1,
                "the job never replays the applied winner"
            );
        });
    }

    /// A waiter whose caller dropped its request is retired when the replay it
    /// waits on finishes, without executing.
    #[test]
    fn cancelled_waiter_is_retired_when_the_replay_finishes() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let (first, _) = harness.build_child(&block1, View::new(2)).await;
            let (second, _) = harness.build_child(&block1, View::new(3)).await;
            let (third, _) = harness.build_child(&block1, View::new(4)).await;
            harness.processor.clear_pending();
            let (gate, started, release) = apply_gate();
            harness.processor.app.apply_probe =
                Some(ApplicationProbe::new(block1.digest(), [gate]));
            let verify_probe = ApplicationProbe::new(second.digest(), []);
            harness.processor.app.verify_probe = Some(verify_probe.clone());

            let owner = harness.verify(&first, &block1);
            harness.run_until(started).await;
            let cancelled = harness.verify(&second, &block1);
            let live = harness.verify(&third, &block1);
            harness.processor.step_ready();
            assert_eq!(
                harness.processor.replays[&block1.digest()].len(),
                2,
                "the siblings wait on the live replay"
            );

            drop(cancelled);
            release.send(()).expect("the replay should be held");
            assert!(harness.run_until(owner).await);
            assert!(harness.run_until(live).await);
            harness.processor.step_ready();
            assert!(harness.processor.replays.is_empty());
            assert!(
                harness.processor.jobs.is_empty(),
                "the cancelled waiter is retired"
            );
            assert_eq!(
                verify_probe.calls.load(Ordering::SeqCst),
                0,
                "a cancelled waiter never executes"
            );
        });
    }

    /// A verification refused by storage while a mutation holds the databases
    /// defers until they return, then answers from the canonical chain.
    #[test]
    fn stale_verification_defers_while_the_databases_are_out() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let winner = harness.stage_pending_child(&genesis, View::new(1)).await;
            let loser = harness.stage_pending_child(&genesis, View::new(2)).await;
            let (candidate, _) = harness.build_child(&loser, View::new(3)).await;

            // Park the verification inside the application, forked from the loser.
            let (gate, started, release) = apply_gate();
            harness.processor.app.verify_probe =
                Some(ApplicationProbe::new(candidate.digest(), [gate]));
            let mut verdict = harness.verify(&candidate, &loser);
            harness.run_until(started).await;
            assert!(harness.finalize(winner).await);

            // Take the databases out as a mutation would, then let the
            // verification read its stale fork while they are out.
            let (finish, finished) = oneshot::channel::<()>();
            let mut mutation = Box::pin(harness.processor.mutate(|databases| async move {
                let _ = finished.await;
                (databases, ())
            }));
            assert!(poll!(&mut mutation).is_pending());
            release.send(()).expect("verification should be parked");
            select! {
                _ = &mut mutation => panic!("the mutation must wait to be finished"),
                _ = harness.context_cell.as_present().sleep(Duration::from_millis(10)) => {},
            }
            assert!(
                poll!(&mut verdict).is_pending(),
                "a stale verification must defer while the databases are out",
            );

            finish.send(()).expect("the mutation should be pending");
            mutation.await;
            assert!(
                !harness.run_until(verdict).await,
                "the losing branch is refused once the anchor moved",
            );
        });
    }
}
