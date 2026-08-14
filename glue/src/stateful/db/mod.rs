//! Traits for database batch lifecycle and state sync in [`Stateful`](super::Stateful).
//!
//! This module defines the boundary between stateful application logic and
//! storage backends (QMDB variants).
//!
//! # Batch Lifecycle
//!
//! Normal execution has three stages:
//! 1. [`Unmerkleized`]: mutable, in-progress batch (concrete types expose reads and writes).
//! 2. [`Merkleized`]: a sealed batch with a computed root.
//! 3. Finalization: apply the sealed batch and start persisting it via
//!    [`ManagedDb::finalize`], observing durability via [`Barrier`]. Finalize also
//!    captures each database's serving snapshot, published for resolver serving (see
//!    [`Reader`]) once the barrier proves the capture durable.
//!
//! [`DatabaseSet`] groups one or more [`ManagedDb`] instances into one logical
//! unit for execution and commit.
//!
//! # Read access and mutation
//!
//! Each database sits behind a [`Writer`] that owns it. The set holds the only
//! [`Writer`], which is not [`Clone`], so mutation is uniquely permitted.
//! Batches hold a [`Reader`], which is freely cloned and grants a read guard
//! covering exactly one storage call.
//!
//! Because a guard never spans application code, a mutation waits at most one
//! storage call to start, and work holding a reader is never cancelled: it
//! pauses at its next read and resumes once the mutation completes. A mutation
//! that is interrupted poisons the writer and destroys it, which is reachable
//! only while the mutating task is being torn down.
//!
//! Two invariants keep this sound. A batch handed to [`ManagedDb::finalize`]
//! must not read through its own reader, because that call runs while the
//! write side is held. And the set must outlive every batch, because dropping
//! the [`Writer`] closes it and parks later reads. Both hold structurally today,
//! because the set holds the [`Writer`] and every reader lives in a batch the
//! set outlives.
//!
//! # State Sync
//!
//! State sync orchestration is expressed by two traits:
//! - [`StateSyncDb`]: per-database sync entrypoint.
//! - [`StateSyncSet`]: set-level orchestration.
//!
//! ## Anchors
//!
//! Each set of sync targets is paired with an anchor `(Height, Round, D)` where
//! `D` is the block digest. The db layer never interprets the anchor; it
//! only tracks which anchor each database converged on.
//!
//! On completion, [`StateSyncSet::sync`] returns the anchor that all databases
//! agreed on. The caller uses this to set the marshal floor and the
//! last-processed digest, ensuring they match the actual convergence point
//! rather than whatever marshal's head happens to be (which may have advanced
//! during sync).
//!
//! ## Convergence Algorithm (tuple sets)
//!
//! Tuple [`StateSyncSet`] implementations assign each `(anchor, targets)`
//! pair a *generation* number and use this algorithm:
//!
//! 1. Forward tip updates only to databases that have not yet reported
//!    "reached target". Reached databases are frozen to prevent them from
//!    running ahead to a newer anchor.
//! 2. When all databases report reached, compare the generation each was
//!    assigned when it reported.
//! 3. If all generations match, every database synced to targets from the
//!    same anchor. Return that anchor.
//! 4. If generations differ, *regroup*: re-send the highest-reached
//!    generation's targets to the behind databases, clear their reached
//!    state, and repeat from step 1.
//!
//! ### Chasing a moving tip
//!
//! ```text
//! time -------------------------------------------------------------->
//!
//! marshal finalized tip:   A0 ------ A1 ------ A2 ------ A3
//! generation:              g0        g1        g2        g3
//!
//! db0 (slow):              g0 ------------------> g1 -----------------> g3 reached
//! db1 (fast):              g0 ----> g1 reached -- frozen -- regroup --> g3 reached
//! db2 (fast):              g0 ----> g1 reached -- frozen -- regroup --> g3 reached
//!
//! coordinator queue while db0 is still catching up:
//!                          [A2] [A3] -- drain --> keep only A3
//!
//! finish only when:
//! - every database has reported the same generation
//! - no newer tip update is still queued behind it
//! ```
//!
//! The coordinator continuously drains tip updates and keeps only the latest
//! value before forwarding, which avoids target-channel backpressure buildup.
//! The `generation_state` map is pruned after every dispatch to only retain
//! generations currently assigned to at least one database, so memory usage
//! is bounded by the number of databases regardless of how long sync runs.

use commonware_codec::Encode;
use commonware_consensus::{
    CertifiableBlock, Epochable, Roundable, Viewable,
    types::{Height, Round},
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{Error as RuntimeError, Handle, Metrics, Spawner, reschedule};
use commonware_storage::{
    journal::{authenticated, contiguous::Snapshottable},
    merkle::Family,
    qmdb::{self, sync},
};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot, ring};
use futures::{
    future::{Either, pending, try_join_all},
    join,
};
use live::{Closed, Reader, Writer};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tracing::debug;

const MAX_CHANNEL_DRAIN_PER_TICK: usize = 32;

pub mod any;
pub mod current;
pub mod immutable;
pub mod keyless;
pub mod live;
pub mod p2p;
pub mod snapshot;

impl Closed {
    /// The storage-facing rendering of a closed writer.
    pub(crate) const fn storage<F: Family>(self) -> qmdb::Error<F> {
        qmdb::Error::Runtime(commonware_runtime::Error::Closed)
    }
}

/// Mutable batch state before merkleization.
///
/// Concrete types provide key-value operations (`get`, `write`, `set`,
/// `append`, etc.) as inherent methods; the generic wrapper only needs
/// [`merkleize`](Self::merkleize). Batches carry a [`Reader`] to the
/// database they were created from, so every operation reads the right
/// database and no operation can delay a mutation by more than one call.
pub trait Unmerkleized: Sized + Send {
    /// The merkleized batch produced by [`merkleize`](Self::merkleize).
    type Merkleized: Merkleized;

    /// The error type returned by fallible operations.
    type Error: Send;

    /// Resolve all mutations, compute the new state root, and produce a
    /// merkleized batch.
    fn merkleize(self) -> impl Future<Output = Result<Self::Merkleized, Self::Error>> + Send;
}

/// Sealed batch state with a computed root.
///
/// The application uses [`root`](Self::root) in block headers, and the wrapper
/// later finalizes this batch.
///
/// Implementations are handles over shared batch state, so [`Clone`] is cheap.
/// The wrapper relies on it to keep a block forkable while that same block is
/// being applied.
pub trait Merkleized: Clone + Sized + Send + Sync {
    /// The digest type used for the state root.
    type Digest: Digest;

    /// The unmerkleized batch type produced by [`new_batch`](Self::new_batch).
    type Unmerkleized: Send;

    /// The canonical state root committed in block headers.
    fn root(&self) -> Self::Digest;

    /// Create a child unmerkleized batch that reads through this batch's
    /// pending changes before falling back to the applied database state.
    fn new_batch(&self) -> Self::Unmerkleized;
}

/// One database managed by the [`Stateful`](super::Stateful) wrapper.
///
/// Implementations create new batches from applied state and apply finalized
/// batches back to storage, deferring each batch's flush to a returned handle.
///
/// Batches carry a [`Reader`] to their database. Reads acquire a short
/// lease per call and fall back from pending batch state to applied state.
///
/// `E` is a trait generic (not an associated type), so one database type can
/// work across runtimes that satisfy the bounds.
///
/// # Ownership
///
/// Mutating methods take the database by value and return it on success. If a mutating
/// method returns an error, or its future is dropped before it finishes, the database is
/// gone: state that was not yet durable is discarded, but everything already on disk stays
/// recoverable. Behind a writer that leaves the database poisoned, so later reads park
/// rather than observe a database that is missing.
pub trait ManagedDb<E>: Send + Sync + Sized {
    /// An in-progress batch of mutations that has not yet been merkleized.
    type Unmerkleized: Unmerkleized<Merkleized = Self::Merkleized>;

    /// A batch whose root has been computed but has not yet been applied to
    /// the underlying database.
    ///
    /// Constrained so that [`Merkleized::new_batch`] produces the same
    /// [`Unmerkleized`] type as [`ManagedDb::new_batch`](Self::new_batch).
    type Merkleized: Merkleized<Unmerkleized = Self::Unmerkleized>;

    /// The error type returned by fallible operations.
    type Error: Debug + Send;

    /// Configuration needed to construct a new database instance.
    type Config: Send;

    /// Sync target type for state sync of this database.
    ///
    /// Typically a database-specific state commitment plus the operation range needed to reach it.
    type SyncTarget: Clone + PartialEq + Send + Sync;

    /// Owned immutable snapshot of applied state.
    type Snapshot: Clone + Send + Sync + 'static;

    /// Construct a new database from its configuration.
    fn init(
        context: E,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Return the sync target produced by a newly initialized database.
    ///
    /// This must match [`sync_target`](Self::sync_target) after opening an empty partition.
    fn initial_sync_target() -> Self::SyncTarget;

    /// Create a new unmerkleized batch rooted at the database's applied
    /// state.
    ///
    /// The batch keeps `handle` and leases the database through it on every
    /// read, so it stays valid across applies of compatible batches.
    fn new_batch(
        handle: Reader<Self>,
    ) -> impl Future<Output = Result<Self::Unmerkleized, Closed>> + Send;

    /// Return true if a merkleized batch matches a sync target.
    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool;

    /// Apply a merkleized batch's changeset to the underlying database, capture a snapshot
    /// of the applied state, and begin persisting it.
    ///
    /// The returned database reflects the batch immediately, while the flush may still
    /// be running. The returned handle resolves once the batch is durable. Flush
    /// failures surface only through the handle, so callers must await every handle and
    /// must not serve the snapshot before its handle resolves successfully. When the
    /// handle resolves with an error, the snapshot may prove earlier state than the
    /// returned database, and neither may be used further. Databases
    /// without deferred persistence flush before returning and yield a ready handle.
    fn finalize(
        self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<(Self, Self::Snapshot, Handle<()>), Self::Error>> + Send;

    /// Capture a snapshot of the current applied state.
    ///
    /// The snapshot reflects every batch applied before this call and nothing
    /// applied after it, including state that may not yet be durably persisted.
    fn snapshot(self) -> impl Future<Output = Result<(Self, Self::Snapshot), Self::Error>> + Send;

    /// Prune the database to a previously finalized sync target.
    ///
    /// Handles returned while finalizing later state may still be pending. Implementations that
    /// discard history must coordinate pruning with those in-flight writes. Databases that do not
    /// retain pruneable operation history can rely on the default no-op. Any pruning effects must
    /// be durable before returning.
    fn prune(
        self,
        _target: &Self::SyncTarget,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send {
        async { Ok(self) }
    }

    /// Return the sync target for this database's current applied state.
    fn sync_target(&self) -> Self::SyncTarget;

    /// Rewind applied state to `target`.
    ///
    /// Implementations must ensure rewind effects are durable before returning
    /// the database (for example by committing after rewind).
    fn rewind_to_target(
        self,
        target: Self::SyncTarget,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

/// Durability barrier for batches applied by [`DatabaseSet::finalize`].
///
/// Holds one [`ManagedDb::finalize`] handle per database in the set. Deferred
/// flush failures surface only here, so every barrier must be awaited via
/// [`durable`](Self::durable), typically on a futures pool. Before
/// [`DatabaseSet::prune`] runs, every barrier through its target must resolve.
/// Barriers for later state may remain pending.
///
/// # Examples
///
/// ```
/// use commonware_glue::stateful::db::Barrier;
/// use commonware_runtime::Handle;
///
/// struct CustomDatabaseSet;
///
/// # async fn example() {
/// let barrier = Barrier::from_handles::<CustomDatabaseSet>([
///     Handle::ready(Ok(())),
/// ]);
/// assert!(barrier.durable().await);
/// # }
/// ```
#[must_use = "await `durable` to surface deferred flush failures"]
pub struct Barrier {
    syncs: Vec<(&'static str, Option<usize>, Handle<()>)>,
}

impl Barrier {
    /// Construct a barrier from deferred flush handles owned by `T`.
    ///
    /// Failures identify `T` and the handle's zero-based position in the
    /// provided iteration. An empty barrier is immediately durable.
    pub fn from_handles<T: ?Sized>(handles: impl IntoIterator<Item = Handle<()>>) -> Self {
        let db_type = std::any::type_name::<T>();
        Self {
            syncs: handles
                .into_iter()
                .enumerate()
                .map(|(index, handle)| (db_type, Some(index), handle))
                .collect(),
        }
    }

    /// Resolves `true` once every deferred flush is durable.
    ///
    /// A flush failure panics because the database has already advanced past
    /// the unflushed batch. Returns `false` only when runtime shutdown aborts
    /// or closes a flush handle.
    pub async fn durable(self) -> bool {
        let syncs = self
            .syncs
            .into_iter()
            .map(|(db_type, index, handle)| async move {
                match handle.await {
                    Ok(()) => Ok(true),
                    Err(RuntimeError::Closed | RuntimeError::Aborted) => {
                        debug!(db_type, "runtime shutdown before finalize flush completed");
                        Ok(false)
                    }
                    Err(err) => Err((db_type, index, err)),
                }
            });

        match try_join_all(syncs).await {
            Ok(results) => results.into_iter().all(|durable| durable),
            Err((db_type, index, err)) => {
                let index = index.map_or(String::new(), |i| format!("index {i}, "));
                panic!("database finalize flush failed ({index}type {db_type}): {err}");
            }
        }
    }
}

/// A collection of [`ManagedDb`] instances.
///
/// Every method treats a database error as fatal and panics. Deferred flush
/// failures surface later, through [`Barrier`].
pub trait DatabaseSet<E>: Send + Sync + Sized + 'static {
    /// One [`ManagedDb::Unmerkleized`] per database: scalar under [`Single`], a tuple
    /// for tuple sets.
    type Unmerkleized: Send;

    /// One [`ManagedDb::Merkleized`] per database, shaped like [`Self::Unmerkleized`].
    ///
    /// [`Clone`] is cheap (see [`Merkleized`]) and the wrapper uses it to keep a
    /// block forkable while that block is being applied.
    type Merkleized: Clone + Send + Sync;

    /// One [`ManagedDb::Snapshot`] per database, shaped like [`Self::Unmerkleized`].
    type Snapshots: Send + Sync + 'static;

    /// Configuration needed to construct every database in the set: the database's
    /// [`ManagedDb::Config`] under [`Single`], a tuple of per-database configs for
    /// tuple sets.
    type Config: Send;

    /// Per-database sync targets extracted from a finalized block, shaped like
    /// [`Self::Config`].
    type SyncTargets: Clone + PartialEq + Send + Sync;

    /// One [`Reader`] per database, shaped like [`Self::Unmerkleized`].
    ///
    /// Handles are cloned into batches, and hooks that read applied state
    /// directly acquire leases through them.
    type Handles: Clone + Send + Sync + 'static;

    /// Construct the database set from its configuration.
    fn init(context: E, config: Self::Config) -> impl Future<Output = Self> + Send;

    /// Return the sync targets produced by a newly initialized database set.
    fn initial_sync_targets() -> Self::SyncTargets;

    /// Read handles over the set's databases.
    fn handles(&self) -> Self::Handles;

    /// Create unmerkleized batches from each database's applied state.
    ///
    /// Takes handles rather than `&self` because verification jobs build
    /// batches without holding the set. Methods that do take the set are the
    /// ones only its owner calls.
    fn new_batches(
        handles: &Self::Handles,
    ) -> impl Future<Output = Result<Self::Unmerkleized, Closed>> + Send;

    /// Create child unmerkleized batches from a pending merkleized parent.
    ///
    /// Reads come from the in-memory merkleized state.
    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized;

    /// Return true if merkleized batches match the given sync targets.
    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool;

    /// Return sync targets for the set's currently applied state.
    ///
    /// Applied state may be ahead of durable state while a flush is pending.
    fn applied_targets(&self) -> impl Future<Output = Self::SyncTargets> + Send;

    /// Apply each merkleized batch's changeset to its underlying database, capture each
    /// database's snapshot, and begin persisting them.
    ///
    /// Returns once every database reflects its batch. The captured set snapshot must
    /// not be served before the returned [`Barrier`] proves it durable, and every
    /// barrier must be awaited (see [`Barrier`]).
    fn finalize(
        self,
        batches: Self::Merkleized,
    ) -> impl Future<Output = (Self, Self::Snapshots, Barrier)> + Send;

    /// Capture a snapshot of every database's current applied state.
    ///
    /// A snapshot can include state that is not yet durably persisted.
    fn snapshot(self) -> impl Future<Output = (Self, Self::Snapshots)> + Send;

    /// Prune each database to the provided per-database targets (see
    /// [`ManagedDb::prune`] for the durability contract).
    fn prune(self, targets: &Self::SyncTargets) -> impl Future<Output = Self> + Send;

    /// Rewind the set to the provided per-database targets.
    fn rewind_to_targets(self, targets: Self::SyncTargets) -> impl Future<Output = Self> + Send;
}

/// The snapshot a log-backed QMDB database produces, shared for serving.
///
/// `C` is the database's operations log. Every full QMDB variant returns this
/// shape from [`ManagedDb::snapshot`]; naming it here keeps the projection out
/// of each variant's associated-type definition.
pub type LogSnapshot<F, E, C, H> =
    Arc<authenticated::Snapshot<F, E, <C as Snapshottable>::Reader, H>>;

/// Syntactic sugar for the type of unmerkleized batches used by a given [DatabaseSet] D.
pub type UnmerkleizedOf<D, E> = <D as DatabaseSet<E>>::Unmerkleized;

/// Syntactic sugar for the type of merkleized batches used by a given [DatabaseSet] D.
pub type MerkleizedOf<D, E> = <D as DatabaseSet<E>>::Merkleized;

/// Syntactic sugar for the type of published snapshot used by a given [DatabaseSet] D.
pub type SnapshotsOf<D, E> = <D as DatabaseSet<E>>::Snapshots;

/// Syntactic sugar for the type of sync targets used by a given [DatabaseSet] D.
pub type SyncTargetsOf<D, E> = <D as DatabaseSet<E>>::SyncTargets;

/// Syntactic sugar for the type of read handles used by a given [DatabaseSet] D.
pub type HandlesOf<D, E> = <D as DatabaseSet<E>>::Handles;

/// A one-database set.
///
/// The set holds the sole [`Writer`], cloning [`Reader`]s into batches.
pub struct Single<T> {
    writer: Writer<T>,
}

impl<T> From<T> for Single<T> {
    fn from(database: T) -> Self {
        Self {
            writer: Writer::new(database),
        }
    }
}

impl<T> Single<T> {
    /// A reader of the set's database.
    ///
    /// Same reader as [`DatabaseSet::handles`], reachable without naming the
    /// runtime the set is used with.
    pub fn handle(&self) -> Reader<T> {
        self.writer.reader()
    }
}

impl<E, T> DatabaseSet<E> for Single<T>
where
    E: Send + Sync + Metrics,
    T: ManagedDb<E> + 'static,
{
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;
    type Config = T::Config;
    type SyncTargets = T::SyncTarget;
    type Snapshots = T::Snapshot;
    type Handles = Reader<T>;

    async fn init(context: E, config: Self::Config) -> Self {
        match T::init(context.child("db"), config).await {
            Ok(database) => Self::from(database),
            Err(err) => panic!(
                "database init failed (type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
        }
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        T::initial_sync_target()
    }

    fn handles(&self) -> Self::Handles {
        self.handle()
    }

    async fn new_batches(handles: &Self::Handles) -> Result<Self::Unmerkleized, Closed> {
        T::new_batch(handles.clone()).await
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        parent.new_batch()
    }

    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
        T::matches_sync_target(batches, targets)
    }

    async fn applied_targets(&self) -> Self::SyncTargets {
        self.writer.read().await.sync_target()
    }

    async fn finalize(self, batches: Self::Merkleized) -> (Self, Self::Snapshots, Barrier) {
        let (member, snapshot, sync) = finalize_or_panic(self, batches, None).await;
        let barrier = Barrier {
            syncs: vec![(core::any::type_name::<T>(), None, sync)],
        };
        (member, snapshot, barrier)
    }

    async fn snapshot(self) -> (Self, Self::Snapshots) {
        snapshot_or_panic(self, None).await
    }

    async fn prune(self, targets: &Self::SyncTargets) -> Self {
        prune_or_panic(self, targets, None).await
    }

    async fn rewind_to_targets(self, targets: Self::SyncTargets) -> Self {
        rewind_or_panic(self, targets, None).await
    }
}

/// Parameters for a one-time state-sync pass.
#[derive(Clone, Copy, Debug)]
pub struct SyncEngineConfig {
    /// Maximum operations fetched per source request.
    pub fetch_batch_size: NonZeroU64,

    /// Number of operations applied per local apply step.
    pub apply_batch_size: NonZeroU64,

    /// Maximum number of outstanding source requests.
    pub max_outstanding_requests: usize,

    /// Capacity of per-database target-update channels.
    pub update_channel_size: NonZeroUsize,

    /// Number of historical roots to retain for proof verification across
    /// target updates.
    pub max_retained_roots: usize,
}

/// A [`ManagedDb`] with a state-sync entrypoint.
pub trait StateSyncDb<E, S>: ManagedDb<E> {
    /// Error returned by the state-sync engine for this database.
    type SyncError: Debug + Send;

    /// Run state-sync for this database and return a fully-initialized instance.
    #[allow(clippy::too_many_arguments)]
    fn sync_db(
        context: E,
        config: Self::Config,
        source: S,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send;
}

/// Block metadata identifying the block that produced a set
/// of sync targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor<D: Digest> {
    /// Height of the anchoring block.
    pub height: Height,
    /// Consensus round of the anchoring block.
    pub round: Round,
    /// Digest of the anchoring block.
    pub digest: D,
}

impl<B, D> From<&B> for Anchor<D>
where
    B: CertifiableBlock<Digest = D>,
    B::Context: Epochable + Viewable,
    D: Digest,
{
    fn from(block: &B) -> Self {
        Self {
            height: block.height(),
            round: block.context().round(),
            digest: block.digest(),
        }
    }
}

/// Tip update delivered to a live state-sync session.
///
/// The optional observation barrier is used by the stateful actor to delay
/// marshal acknowledgement until the sync coordinator has recorded the new
/// anchor and targets.
pub struct TipUpdate<D: Digest, T> {
    anchor: Anchor<D>,
    targets: T,
    observed: Option<oneshot::Sender<()>>,
}

impl<D: Digest, T> TipUpdate<D, T> {
    pub const fn new(anchor: Anchor<D>, targets: T) -> Self {
        Self {
            anchor,
            targets,
            observed: None,
        }
    }

    pub(crate) fn with_observation(anchor: Anchor<D>, targets: T) -> (Self, oneshot::Receiver<()>) {
        let (observed, receiver) = oneshot::channel();
        (
            Self {
                anchor,
                targets,
                observed: Some(observed),
            },
            receiver,
        )
    }

    /// Record the update before releasing its observation barrier.
    pub(crate) fn record<R>(self, record: impl FnOnce(Anchor<D>, T) -> R) -> R {
        let result = record(self.anchor, self.targets);
        if let Some(observed) = self.observed {
            let _ = observed.send(());
        }
        result
    }
}

/// A [`DatabaseSet`] that can run one-time state sync.
///
/// `D` is the block digest type. Each set of sync targets is paired
/// with an [`Anchor`] identifying the block that produced those targets.
/// On convergence, `sync` returns the anchor that all databases agreed on.
pub trait StateSyncSet<E, S, D>: DatabaseSet<E>
where
    D: Digest,
{
    /// Error returned if any database in the set fails state sync.
    type Error: Debug + Send;

    /// Run one-time state sync and return the initialized set
    /// together with the anchor all databases converged on.
    #[allow(clippy::too_many_arguments)]
    fn sync(
        context: E,
        config: Self::Config,
        sources: S,
        anchor: Anchor<D>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<D, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<(Self, Anchor<D>), Self::Error>> + Send;
}

impl<E, T, S, D> StateSyncSet<E, S, D> for Single<T>
where
    E: Send + Sync + Metrics,
    T: StateSyncDb<E, S> + 'static,
    S: Send + 'static,
    D: Digest,
{
    type Error = T::SyncError;

    #[allow(clippy::too_many_arguments)]
    async fn sync(
        context: E,
        config: Self::Config,
        source: S,
        anchor: Anchor<D>,
        target: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<D, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<D>), Self::Error> {
        let (target_tx, target_rx) = mpsc::channel(sync_config.update_channel_size.get());
        let (finish_tx, finish_rx) = mpsc::channel(1);
        let (reached_tx, mut reached_rx) = mpsc::channel(1);
        let mut current_target = target.clone();
        let sync = T::sync_db(
            context,
            config,
            source,
            target,
            target_rx,
            Some(finish_rx),
            Some(reached_tx),
            sync_config,
        );

        let coordinator = async {
            let mut current_anchor = anchor;
            let mut tip_updates = Some(tip_updates);
            loop {
                if !drain_single_tip_updates(
                    &mut tip_updates,
                    &target_tx,
                    &mut current_anchor,
                    &mut current_target,
                )
                .await
                {
                    return (current_anchor, current_target);
                }

                let update_future = tip_updates.as_mut().map_or_else(
                    || Either::Right(pending()),
                    |updates| Either::Left(updates.recv()),
                );
                select! {
                    reached = reached_rx.recv() => {
                        let Some(reached) = reached else {
                            return (current_anchor, current_target);
                        };
                        if !drain_single_tip_updates(
                            &mut tip_updates,
                            &target_tx,
                            &mut current_anchor,
                            &mut current_target,
                        )
                        .await
                        {
                            return (current_anchor, current_target);
                        };
                        if reached != current_target {
                            continue;
                        }
                        let _ = finish_tx.send_lossy(()).await;
                        return (current_anchor, current_target);
                    },
                    update = update_future => {
                        let Some(update) = update else {
                            tip_updates = None;
                            continue;
                        };
                        let target = update.record(|new_anchor, new_target| {
                            if new_anchor.height <= current_anchor.height {
                                return None;
                            }
                            current_anchor = new_anchor;
                            if new_target == current_target {
                                return None;
                            }
                            current_target = new_target.clone();
                            Some(new_target)
                        });
                        let Some(new_target) = target else {
                            continue;
                        };
                        if !target_tx.send_lossy(new_target).await {
                            return (current_anchor, current_target);
                        }
                    },
                }
            }
        };

        let (db_result, (converged_anchor, converged_target)) = join!(sync, coordinator);
        let database = db_result?;
        assert!(
            T::sync_target(&database) == converged_target,
            "state sync database target does not match the coordinator target",
        );
        Ok((Self::from(database), converged_anchor))
    }
}

async fn drain_single_tip_updates<D, T>(
    tip_updates: &mut Option<ring::Receiver<TipUpdate<D, T>>>,
    target_tx: &mpsc::Sender<T>,
    current_anchor: &mut Anchor<D>,
    current_target: &mut T,
) -> bool
where
    D: Digest,
    T: Clone + PartialEq + Send + Sync,
{
    let mut drained = 0usize;
    let mut latest = None;
    loop {
        let update = match tip_updates.as_mut().map(ring::Receiver::try_recv) {
            Some(Ok(update)) => update,
            Some(Err(ring::TryRecvError::Empty)) => break,
            Some(Err(ring::TryRecvError::Disconnected)) => {
                *tip_updates = None;
                break;
            }
            None => break,
        };
        drained += 1;

        update.record(|new_anchor, new_target| {
            let latest_height = latest
                .as_ref()
                .map_or(current_anchor.height, |(anchor, _): &(Anchor<D>, T)| {
                    anchor.height
                });
            if new_anchor.height > latest_height {
                latest = Some((new_anchor, new_target));
            }
        });
        if drained.is_multiple_of(MAX_CHANNEL_DRAIN_PER_TICK) {
            reschedule().await;
        }
    }

    let Some((new_anchor, new_target)) = latest else {
        return true;
    };
    *current_anchor = new_anchor;
    if new_target == *current_target {
        return true;
    }
    *current_target = new_target.clone();
    target_tx.send_lossy(new_target).await
}

/// Implement [`DatabaseSet`] for a tuple of gated one-database sets.
macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<E: Send + Sync + Metrics, $($T: ManagedDb<E> + 'static),+> DatabaseSet<E>
            for ($(Single<$T>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);
            type Config = ($($T::Config,)+);
            type SyncTargets = ($($T::SyncTarget,)+);
            type Snapshots = ($($T::Snapshot,)+);
            type Handles = ($(Reader<$T>,)+);

            async fn init(context: E, config: Self::Config) -> Self {
                join!($(
                    async {
                        Single::from(
                            $T::init(
                                context.child(concat!("db_", stringify!($idx))),
                                config.$idx,
                            )
                            .await
                            .expect(concat!(
                                "database init failed (index ",
                                stringify!($idx),
                                ", type ",
                                stringify!($T),
                                ")",
                            )),
                        )
                    },
                )+)
            }

            fn initial_sync_targets() -> Self::SyncTargets {
                ($($T::initial_sync_target(),)+)
            }

            fn handles(&self) -> Self::Handles {
                ($(self.$idx.handle(),)+)
            }

            async fn new_batches(handles: &Self::Handles) -> Result<Self::Unmerkleized, Closed> {
                let batches = join!($(
                    $T::new_batch(handles.$idx.clone()),
                )+);
                Ok(($(batches.$idx?,)+))
            }

            fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
                ($(parent.$idx.new_batch(),)+)
            }

            fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
                $($T::matches_sync_target(&batches.$idx, &targets.$idx))&&+
            }

            async fn applied_targets(&self) -> Self::SyncTargets {
                join!($(
                    async { self.$idx.writer.read().await.sync_target() },
                )+)
            }

            async fn finalize(self, batches: Self::Merkleized) -> (Self, Self::Snapshots, Barrier) {
                // Every database captures at its own apply boundary inside this call, so the
                // captured snapshots form one capture.
                let results = join!($(
                    finalize_or_panic(self.$idx, batches.$idx, Some($idx)),
                )+);
                let barrier = Barrier {
                    syncs: vec![$(
                        (core::any::type_name::<$T>(), Some($idx), results.$idx.2),
                    )+],
                };
                (
                    ($(results.$idx.0,)+),
                    ($(results.$idx.1,)+),
                    barrier,
                )
            }

            async fn snapshot(self) -> (Self, Self::Snapshots) {
                let results = join!($(
                    snapshot_or_panic(self.$idx, Some($idx)),
                )+);
                (($(results.$idx.0,)+), ($(results.$idx.1,)+))
            }

            async fn prune(self, targets: &Self::SyncTargets) -> Self {
                join!($(
                    prune_or_panic(self.$idx, &targets.$idx, Some($idx)),
                )+)
            }

            async fn rewind_to_targets(self, targets: Self::SyncTargets) -> Self {
                join!($(
                    rewind_or_panic(self.$idx, targets.$idx, Some($idx)),
                )+)
            }
        }
    };
}

impl_database_set!(DB1: 0, DB2: 1);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6, DB8: 7);

struct DbSyncChannels<T> {
    target_tx: mpsc::Sender<T>,
    target_rx: mpsc::Receiver<T>,
    finish_tx: mpsc::Sender<()>,
    finish_rx: mpsc::Receiver<()>,
    generation_tx: mpsc::Sender<(usize, T)>,
    generation_rx: mpsc::Receiver<(usize, T)>,
    reached_tx: mpsc::Sender<T>,
    reached_rx: mpsc::Receiver<T>,
}

impl<T> DbSyncChannels<T> {
    fn new(update_channel_size: usize) -> Self {
        let (target_tx, target_rx) = mpsc::channel(update_channel_size);
        let (finish_tx, finish_rx) = mpsc::channel(1);
        let (generation_tx, generation_rx) = mpsc::channel(update_channel_size);
        let (reached_tx, reached_rx) = mpsc::channel(1);
        Self {
            target_tx,
            target_rx,
            finish_tx,
            finish_rx,
            generation_tx,
            generation_rx,
            reached_tx,
            reached_rx,
        }
    }
}

struct CoordinatorSyncSenders<T> {
    target_tx: mpsc::Sender<T>,
    finish_tx: mpsc::Sender<()>,
    generation_tx: mpsc::Sender<(usize, T)>,
}

macro_rules! impl_state_sync_set {
    ($($T:ident : $S:ident : $idx:tt),+) => {
        impl<E, D, $($T, $S),+> StateSyncSet<E, ($($S,)+), D> for ($(Single<$T>,)+)
        where
            E: Send + Sync + Spawner + Metrics + 'static,
            D: Digest + 'static,
            $(
                $T: StateSyncDb<E, $S> + 'static,
                $S: Send + 'static,
            )+
        {
            type Error = String;

            #[allow(clippy::too_many_arguments)]
            async fn sync(
                context: E,
                config: Self::Config,
                sources: ($($S,)+),
                anchor: Anchor<D>,
                targets: Self::SyncTargets,
                tip_updates: ring::Receiver<TipUpdate<D, Self::SyncTargets>>,
                sync_config: SyncEngineConfig,
            ) -> Result<(Self, Anchor<D>), Self::Error> {
                let db_channels = ($(
                    DbSyncChannels::<<$T as ManagedDb<E>>::SyncTarget>::new(
                        sync_config.update_channel_size.get(),
                    ),
                )+);
                let coordinator_senders = ($(
                    CoordinatorSyncSenders {
                        target_tx: db_channels.$idx.target_tx,
                        finish_tx: db_channels.$idx.finish_tx,
                        generation_tx: db_channels.$idx.generation_tx,
                    },
                )+);
                let (reached_event_tx, mut reached_event_rx) = mpsc::channel(16);
                let (completion_tx, mut completion_rx) = mpsc::channel(1);
                let db_count = [$($idx,)+].len();
                let coordinator_targets = targets.clone();
                let initial_targets = targets.clone();
                let first_db_error: Arc<commonware_utils::sync::Mutex<Option<String>>> =
                    Arc::new(commonware_utils::sync::Mutex::new(None));
                let coordinator_handle = context.child("coordinator").spawn({
                    move |_context| async move {
                        let mut tip_updates = Some(tip_updates);
                        let mut state = CoordinatorState::new(db_count, anchor, coordinator_targets);
                        let mut last_dispatched_targets = initial_targets;

                        loop {
                            loop {
                                match reached_event_rx.try_recv() {
                                    Ok((idx, generation)) => state.record_reached(idx, generation),
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => return None,
                                }
                            }

                            if let Some(updates) = tip_updates.as_mut() {
                                loop {
                                    match updates.try_recv() {
                                        Ok(update) => {
                                            update.record(|anchor, targets| {
                                                state.record_tip_update(anchor, targets);
                                            });
                                        }
                                        Err(ring::TryRecvError::Empty) => break,
                                        Err(ring::TryRecvError::Disconnected) => {
                                            tip_updates = None;
                                            break;
                                        }
                                    }
                                }
                            }

                            match state.next_action() {
                                CoordinatorAction::Converged { anchor, targets } => {
                                    $(
                                        let _ = coordinator_senders.$idx.finish_tx.send_lossy(()).await;
                                    )+
                                    return Some((anchor, targets));
                                }
                                CoordinatorAction::Dispatch {
                                    generation,
                                    targets: dispatch_targets,
                                } => {
                                    $(
                                        let dispatch_target = dispatch_targets.$idx.clone();
                                        if !coordinator_senders.$idx
                                            .generation_tx
                                            .send_lossy((generation, dispatch_target.clone()))
                                            .await
                                        {
                                            return None;
                                        }
                                        if state.should_dispatch($idx) {
                                            if dispatch_target != last_dispatched_targets.$idx {
                                                if !coordinator_senders.$idx
                                                    .target_tx
                                                    .send_lossy(dispatch_target.clone())
                                                    .await
                                                {
                                                    return None;
                                                }
                                                last_dispatched_targets.$idx = dispatch_target;
                                            }
                                        } else if dispatch_target == last_dispatched_targets.$idx {
                                            state.mark_reached_same_target($idx, generation);
                                        }
                                    )+
                                    continue;
                                }
                                CoordinatorAction::Wait => {}
                            }

                            let update_future = tip_updates.as_mut().map_or_else(
                                || Either::Right(pending()),
                                |updates| Either::Left(updates.recv()),
                            );
                            select! {
                                reached_event = reached_event_rx.recv() => {
                                    let (idx, generation) = reached_event?;
                                    state.record_reached(idx, generation);
                                },
                                _ = completion_rx.recv() => {
                                    return None;
                                },
                                update = update_future => {
                                    let Some(update) = update else {
                                        tip_updates = None;
                                        continue;
                                    };
                                    update.record(|anchor, targets| {
                                        state.record_tip_update(anchor, targets);
                                    });
                                },
                            };
                        }
                    }
                });
                let db_handles = (
                    $(
                        context.child(concat!("db_", stringify!($idx))).spawn({
                            let first_db_error = first_db_error.clone();
                            let mut reached_target_rx = db_channels.$idx.reached_rx;
                            let mut generation_rx = Some(db_channels.$idx.generation_rx);
                            let mut current_generation = 0usize;
                            let mut current_target = targets.$idx.clone();
                            let mut last_reached_target = None;
                            let mut last_reported_generation = None;
                            let reached_event_sender = reached_event_tx.clone();
                            let completion_signal = completion_tx.clone();
                            let config = config.$idx;
                            let source = sources.$idx;
                            let target = targets.$idx;
                            let target_rx = db_channels.$idx.target_rx;
                            let finish_rx = db_channels.$idx.finish_rx;
                            let reached_tx = db_channels.$idx.reached_tx;
                            move |context| async move {
                                let sync = $T::sync_db(
                                    context,
                                    config,
                                    source,
                                    target,
                                    target_rx,
                                    Some(finish_rx),
                                    Some(reached_tx),
                                    sync_config,
                                );
                                let forward_reached = async move {
                                    loop {
                                        drain_generation_updates(
                                            &mut generation_rx,
                                            &mut current_generation,
                                            &mut current_target,
                                            &last_reached_target,
                                            &mut last_reported_generation,
                                            &reached_event_sender,
                                            $idx,
                                        )
                                        .await;

                                        let update_future = generation_rx.as_mut().map_or_else(
                                            || Either::Right(pending()),
                                            |updates| Either::Left(updates.recv()),
                                        );
                                        select! {
                                            reached_target = reached_target_rx.recv() => {
                                                let Some(reached_target) = reached_target else {
                                                    return;
                                                };

                                                last_reached_target = Some(reached_target.clone());
                                                drain_generation_updates(
                                                    &mut generation_rx,
                                                    &mut current_generation,
                                                    &mut current_target,
                                                    &last_reached_target,
                                                    &mut last_reported_generation,
                                                    &reached_event_sender,
                                                    $idx,
                                                )
                                                .await;

                                                if reached_target != current_target {
                                                    continue;
                                                }

                                                if last_reported_generation != Some(current_generation) {
                                                    if !reached_event_sender
                                                        .send_lossy(($idx, current_generation))
                                                        .await
                                                    {
                                                        return;
                                                    }
                                                    last_reported_generation = Some(current_generation);
                                                }
                                            },
                                            update = update_future => {
                                                let Some((generation, target)) = update else {
                                                    generation_rx = None;
                                                    continue;
                                                };
                                                current_generation = generation;
                                                current_target = target;
                                                if last_reached_target.as_ref() == Some(&current_target)
                                                    && last_reported_generation != Some(current_generation)
                                                {
                                                    if !reached_event_sender
                                                        .send_lossy(($idx, current_generation))
                                                        .await
                                                    {
                                                        return;
                                                    }
                                                    last_reported_generation = Some(current_generation);
                                                }
                                            },
                                        };
                                    }
                                };
                                let (sync_result, _) = join!(sync, forward_reached);
                                let result = sync_result.map_err(|err| {
                                    format!(
                                        "state sync failed (index {}, db {}): {err:?}",
                                        $idx,
                                        core::any::type_name::<$T>(),
                                    )
                                });
                                if let Err(err) = &result {
                                    let mut first = first_db_error.lock();
                                    if first.is_none() {
                                        *first = Some(err.clone());
                                    }
                                }
                                let _ = completion_signal.send_lossy(()).await;
                                result
                            }
                        }),
                    )+
                );

                let synced = join!(
                    $(
                        async {
                            db_handles.$idx
                                .await
                                .expect("state sync database task exited")
                        },
                    )+
                );
                let converged_anchor = coordinator_handle
                    .await
                    .expect("state sync coordinator task exited");

                if let Some(err) = first_db_error.lock().take() {
                    return Err(err);
                }

                let synced = ($(Single::from(synced.$idx?),)+);
                let Some((converged_anchor, converged_targets)) = converged_anchor else {
                    return Err("state sync coordinator did not report a converged anchor".into());
                };
                if <Self as DatabaseSet<E>>::applied_targets(&synced).await != converged_targets {
                    return Err(
                        "state sync database targets do not match the coordinator target set"
                            .into(),
                    );
                }

                Ok((synced, converged_anchor))
            }
        }
    };
}

impl_state_sync_set!(DB1: S1: 0, DB2: S2: 1);
impl_state_sync_set!(DB1: S1: 0, DB2: S2: 1, DB3: S3: 2);
impl_state_sync_set!(DB1: S1: 0, DB2: S2: 1, DB3: S3: 2, DB4: S4: 3);
impl_state_sync_set!(DB1: S1: 0, DB2: S2: 1, DB3: S3: 2, DB4: S4: 3, DB5: S5: 4);
impl_state_sync_set!(DB1: S1: 0, DB2: S2: 1, DB3: S3: 2, DB4: S4: 3, DB5: S5: 4, DB6: S6: 5);
impl_state_sync_set!(
    DB1: S1: 0,
    DB2: S2: 1,
    DB3: S3: 2,
    DB4: S4: 3,
    DB5: S5: 4,
    DB6: S6: 5,
    DB7: S7: 6
);
impl_state_sync_set!(
    DB1: S1: 0,
    DB2: S2: 1,
    DB3: S3: 2,
    DB4: S4: 3,
    DB5: S5: 4,
    DB6: S6: 5,
    DB7: S7: 6,
    DB8: S8: 7
);

async fn drain_generation_updates<T>(
    generation_rx: &mut Option<mpsc::Receiver<(usize, T)>>,
    current_generation: &mut usize,
    current_target: &mut T,
    last_reached_target: &Option<T>,
    last_reported_generation: &mut Option<usize>,
    reached_event_sender: &mpsc::Sender<(usize, usize)>,
    idx: usize,
) where
    T: Clone + PartialEq,
{
    if let Some(updates) = generation_rx.as_mut() {
        let mut drained = 0usize;
        loop {
            match updates.try_recv() {
                Ok((generation, target)) => {
                    drained += 1;
                    *current_generation = generation;
                    *current_target = target;

                    if last_reached_target.as_ref() == Some(current_target)
                        && *last_reported_generation != Some(*current_generation)
                    {
                        if !reached_event_sender
                            .send_lossy((idx, *current_generation))
                            .await
                        {
                            return;
                        }
                        *last_reported_generation = Some(*current_generation);
                    }
                    if drained.is_multiple_of(MAX_CHANNEL_DRAIN_PER_TICK) {
                        reschedule().await;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    *generation_rx = None;
                    break;
                }
            }
        }
    }
}

/// Per-database sync tracking state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbSyncState {
    /// Database is still syncing toward its assigned generation's targets.
    Seeking { generation: usize },
    /// Database reported it reached its assigned generation's targets.
    Reached { generation: usize },
}

impl DbSyncState {
    const fn generation(self) -> usize {
        match self {
            Self::Seeking { generation } | Self::Reached { generation } => generation,
        }
    }

    const fn is_reached(self) -> bool {
        matches!(self, Self::Reached { .. })
    }
}

/// What the coordinator should do after processing events.
enum CoordinatorAction<D: Digest, T> {
    /// Nothing to do; wait for the next event.
    Wait,
    /// Dispatch targets to non-reached databases for `generation`.
    Dispatch { generation: usize, targets: T },
    /// All databases converged on the same generation.
    Converged { anchor: Anchor<D>, targets: T },
}

/// Pure state machine for multi-database sync convergence.
///
/// Tracks which generation each database is assigned to, which have
/// reported "reached", and decides when to regroup or declare
/// convergence.
struct CoordinatorState<D: Digest, T> {
    dbs: Vec<DbSyncState>,
    generation_state: BTreeMap<usize, (Anchor<D>, T)>,
    current_generation: usize,
    latest_tip: Option<(Anchor<D>, T)>,
    last_dispatched_anchor: Anchor<D>,
}

impl<D: Digest, T: Clone> CoordinatorState<D, T> {
    fn new(db_count: usize, anchor: Anchor<D>, targets: T) -> Self {
        let dbs = vec![DbSyncState::Seeking { generation: 0 }; db_count];
        let mut generation_state = BTreeMap::new();
        generation_state.insert(0, (anchor, targets));
        Self {
            dbs,
            generation_state,
            current_generation: 0,
            latest_tip: None,
            last_dispatched_anchor: anchor,
        }
    }

    /// Record that database `idx` reached `generation`.
    ///
    /// Reached events can arrive late. If the database has already been
    /// re-assigned to a newer generation, stale events are ignored.
    fn record_reached(&mut self, idx: usize, generation: usize) {
        if self.dbs[idx].generation() != generation {
            return;
        }
        if self.dbs[idx].is_reached() {
            return;
        }
        self.dbs[idx] = DbSyncState::Reached { generation };
    }

    /// Record a new tip update.
    ///
    /// Sync targets must move strictly forward. Ignore stale and duplicate
    /// anchors to avoid dispatching backward targets.
    fn record_tip_update(&mut self, anchor: Anchor<D>, targets: T) {
        let current_height = self
            .latest_tip
            .as_ref()
            .map_or(self.last_dispatched_anchor.height, |(latest_anchor, _)| {
                latest_anchor.height
            });
        if anchor.height <= current_height {
            return;
        }
        self.latest_tip = Some((anchor, targets));
    }

    /// Determine the next action. Mutates internal state for regroup/dispatch.
    ///
    /// Returns which database indices should receive targets via
    /// `dbs[idx].is_reached() == false` after a `Dispatch` action.
    fn next_action(&mut self) -> CoordinatorAction<D, T> {
        let all_reached = self.dbs.iter().all(|db| db.is_reached());

        if all_reached {
            let min_gen = self.dbs.iter().map(|db| db.generation()).min().unwrap();
            let max_gen = self.dbs.iter().map(|db| db.generation()).max().unwrap();

            if min_gen == max_gen {
                if let Some((anchor, targets)) = self.latest_tip.take() {
                    let generation = self.current_generation + 1;
                    self.current_generation = generation;
                    for db in &mut self.dbs {
                        *db = DbSyncState::Seeking { generation };
                    }
                    self.generation_state
                        .insert(generation, (anchor, targets.clone()));
                    self.last_dispatched_anchor = anchor;
                    self.prune_generations();
                    return CoordinatorAction::Dispatch {
                        generation,
                        targets,
                    };
                }

                let (anchor, targets) = self
                    .generation_state
                    .get(&min_gen)
                    .expect("missing state for converged generation")
                    .clone();
                return CoordinatorAction::Converged { anchor, targets };
            }

            // Regroup: reset behind databases to seek the highest generation.
            let (_anchor, targets) = self
                .generation_state
                .get(&max_gen)
                .expect("missing state for regroup generation")
                .clone();
            for db in &mut self.dbs {
                if db.generation() != max_gen {
                    *db = DbSyncState::Seeking {
                        generation: max_gen,
                    };
                }
            }
            self.prune_generations();
            return CoordinatorAction::Dispatch {
                generation: max_gen,
                targets,
            };
        }

        // Not all reached. If there's a pending tip, dispatch it.
        let Some((anchor, targets)) = self.latest_tip.take() else {
            return CoordinatorAction::Wait;
        };

        let generation = self.current_generation + 1;
        self.current_generation = generation;
        for db in &mut self.dbs {
            if !db.is_reached() {
                *db = DbSyncState::Seeking { generation };
            }
        }
        self.generation_state
            .insert(generation, (anchor, targets.clone()));
        self.last_dispatched_anchor = anchor;

        self.prune_generations();
        CoordinatorAction::Dispatch {
            generation,
            targets,
        }
    }

    /// Retain only generations referenced by at least one database.
    fn prune_generations(&mut self) {
        self.generation_state
            .retain(|r#gen, _| self.dbs.iter().any(|db| db.generation() == *r#gen));
    }

    /// Whether database `idx` is a non-reached recipient for dispatch.
    fn should_dispatch(&self, idx: usize) -> bool {
        !self.dbs[idx].is_reached()
    }

    /// Advance a reached database to `generation` when its target is unchanged.
    fn mark_reached_same_target(&mut self, idx: usize, generation: usize) {
        if !self.dbs[idx].is_reached() {
            return;
        }
        self.dbs[idx] = DbSyncState::Reached { generation };
    }
}

/// Sync a database that durably persists an operation log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_standard_db<E, DB, S>(
    context: E,
    config: DB::Config,
    source: S,
    target: sync::Target<DB::Family, DB::Digest>,
    tip_updates: mpsc::Receiver<sync::Target<DB::Family, DB::Digest>>,
    finish: Option<mpsc::Receiver<()>>,
    reached_target: Option<mpsc::Sender<sync::Target<DB::Family, DB::Digest>>>,
    sync_config: SyncEngineConfig,
) -> Result<DB, sync::Error<DB::Family, S::Error, DB::Digest>>
where
    DB: sync::Database<Context = E>,
    DB::Op: Encode,
    S: sync::SourceFor<DB>,
{
    sync::sync(sync::engine::Config {
        context,
        source,
        target,
        max_outstanding_requests: sync_config.max_outstanding_requests,
        fetch_batch_size: sync_config.fetch_batch_size,
        apply_batch_size: sync_config.apply_batch_size,
        db_config: config,
        update_rx: Some(tip_updates),
        finish_rx: finish,
        reached_target_tx: reached_target,
        max_retained_roots: sync_config.max_retained_roots,
    })
    .await
}

/// Aborts an adapter task when its owning sync future completes or is cancelled.
struct Forwarder(Handle<()>);

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sync a database that does not durably persist an operation log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_compact_db<E, DB, S>(
    context: E,
    config: DB::Config,
    source: S,
    target: sync::CompactTarget<DB::Family, DB::Digest>,
    mut tip_updates: mpsc::Receiver<sync::CompactTarget<DB::Family, DB::Digest>>,
    finish: Option<mpsc::Receiver<()>>,
    reached_target: Option<mpsc::Sender<sync::CompactTarget<DB::Family, DB::Digest>>>,
    sync_config: SyncEngineConfig,
) -> Result<DB, sync::Error<DB::Family, S::Error, DB::Digest>>
where
    E: Metrics + Spawner,
    DB: sync::Database<Context = E>,
    DB::Op: Encode,
    S: sync::SourceFor<DB>,
{
    let mut initial = sync::Target::try_from(&target).map_err(sync::Error::Engine)?;
    // Start at the newest target already queued.
    while let Ok(update) = tip_updates.try_recv() {
        let Ok(update) = sync::Target::try_from(&update) else {
            continue;
        };
        if update.advances(&initial) {
            initial = update;
        }
    }

    let (update_tx, update_rx) = mpsc::channel(sync_config.update_channel_size.get());
    // Retain the handle until the engine exits so the adapter is aborted on completion or cancel.
    let update_forwarder = Forwarder(context.child("compact_updates").spawn(move |_| async move {
        while let Some(update) = tip_updates.recv().await {
            // Ignore malformed updates.
            let Ok(update) = sync::Target::try_from(&update) else {
                continue;
            };
            if update_tx.send(update).await.is_err() {
                break;
            }
        }
    }));

    let reached_target_tx = reached_target.map(|reached| {
        let (tx, mut rx) = mpsc::channel::<sync::Target<DB::Family, DB::Digest>>(1);
        context.child("compact_reached").spawn(move |_| async move {
            while let Some(reached_engine_target) = rx.recv().await {
                let target = sync::CompactTarget {
                    root: reached_engine_target.root,
                    size: reached_engine_target.range.end(),
                };
                if reached.send(target).await.is_err() {
                    break;
                }
            }
        });
        tx
    });

    let result = sync::sync(sync::engine::Config {
        context,
        source,
        target: initial,
        db_config: config,
        fetch_batch_size: sync_config.fetch_batch_size,
        apply_batch_size: sync_config.apply_batch_size,
        max_outstanding_requests: sync_config.max_outstanding_requests,
        max_retained_roots: sync_config.max_retained_roots,
        update_rx: Some(update_rx),
        finish_rx: finish,
        reached_target_tx,
    })
    .await;
    drop(update_forwarder);
    result
}

#[tracing::instrument(name = "stateful.db.snapshot_or_panic", level = "info", skip_all, fields(index = index))]
async fn snapshot_or_panic<E, T: ManagedDb<E>>(
    member: Single<T>,
    index: Option<usize>,
) -> (Single<T>, T::Snapshot) {
    // Capture failures are fatal by design: a set that cannot snapshot its applied
    // state cannot publish, and other members may already have captured.
    let Single { writer } = member;
    let (writer, snapshot) = writer
        .mutate(|database| async move {
            match database.snapshot().await {
                Ok(result) => result,
                Err(err) => {
                    let index = index.map_or(String::new(), |i| format!("index {i}, "));
                    panic!(
                        "database snapshot capture failed ({index}type {}): {err:?}",
                        core::any::type_name::<T>(),
                    );
                }
            }
        })
        .await;
    (Single { writer }, snapshot)
}

#[tracing::instrument(name = "stateful.db.finalize_or_panic", level = "info", skip_all, fields(index = index))]
async fn finalize_or_panic<E, T: ManagedDb<E>>(
    member: Single<T>,
    batch: T::Merkleized,
    index: Option<usize>,
) -> (Single<T>, T::Snapshot, Handle<()>) {
    // Mutable finalize failures are fatal by design because the batch may already have been
    // applied to other databases in the same set, leaving partially applied state.
    let Single { writer } = member;
    let (writer, (snapshot, sync)) = writer
        .mutate(|database| async move {
            match database.finalize(batch).await {
                Ok((database, snapshot, sync)) => (database, (snapshot, sync)),
                Err(err) => {
                    let index = index.map_or(String::new(), |i| format!("index {i}, "));
                    panic!(
                        "database finalize failed ({index}type {}): {err:?}",
                        core::any::type_name::<T>(),
                    );
                }
            }
        })
        .await;
    (Single { writer }, snapshot, sync)
}

#[tracing::instrument(name = "stateful.db.rewind_or_panic", level = "info", skip_all, fields(index = index))]
async fn rewind_or_panic<E, T: ManagedDb<E>>(
    member: Single<T>,
    target: T::SyncTarget,
    index: Option<usize>,
) -> Single<T> {
    // Mutable rewind failures are fatal by design because the database handle
    // may be internally diverged after a failed rewind.
    let Single { writer } = member;
    let (writer, ()) = writer
        .mutate(|database| async move {
            if T::sync_target(&database) == target {
                return (database, ());
            }
            match database.rewind_to_target(target).await {
                Ok(database) => (database, ()),
                Err(err) => {
                    let index = index.map_or(String::new(), |i| format!("index {i}, "));
                    panic!(
                        "database rewind failed ({index}type {}): {err:?}",
                        core::any::type_name::<T>(),
                    );
                }
            }
        })
        .await;
    Single { writer }
}

#[tracing::instrument(name = "stateful.db.prune_or_panic", level = "info", skip_all, fields(index = index))]
async fn prune_or_panic<E, T: ManagedDb<E>>(
    member: Single<T>,
    target: &T::SyncTarget,
    index: Option<usize>,
) -> Single<T> {
    // Prune failures are fatal because pruning may already have discarded part
    // of the retained history before the error surfaced.
    let Single { writer } = member;
    let (writer, ()) = writer
        .mutate(|database| async move {
            match database.prune(target).await {
                Ok(database) => (database, ()),
                Err(err) => {
                    let index = index.map_or(String::new(), |i| format!("index {i}, "));
                    panic!(
                        "database prune failed ({index}type {}): {err:?}",
                        core::any::type_name::<T>(),
                    );
                }
            }
        })
        .await;
    Single { writer }
}

#[cfg(test)]
mod tests {
    use super::{
        Anchor, Barrier, Closed, CoordinatorAction, CoordinatorState, DatabaseSet,
        MAX_CHANNEL_DRAIN_PER_TICK, ManagedDb, Reader, Single, StateSyncDb, StateSyncSet,
        SyncEngineConfig, TipUpdate, Writer, drain_single_tip_updates,
    };
    use crate::stateful::tests::mocks::{TestMerkleized, TestUnmerkleized, anchor as mock_anchor};
    use commonware_cryptography::sha256;
    use commonware_macros::select;
    use commonware_runtime::{
        Clock, Error as RuntimeError, Handle, Runner as _, Spawner as _, Supervisor as _,
        deterministic, reschedule,
    };
    use commonware_utils::{
        NZU64,
        channel::{mpsc, oneshot, ring},
    };
    use futures::{FutureExt, SinkExt, pin_mut};
    use std::{
        convert::Infallible,
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    mod managed_db_lifecycle {
        use super::{ManagedDb, Writer};
        use crate::stateful::db::Unmerkleized;
        use commonware_cryptography::{Sha256, sha256::Digest};
        use commonware_parallel::Sequential;
        use commonware_runtime::{
            Handle, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
        };
        use commonware_storage::{
            journal::contiguous::{
                fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
            },
            merkle::{full::Config as MerkleConfig, mmr},
            qmdb::{
                any as storage_any, current as storage_current, immutable as storage_immutable,
                keyless as storage_keyless,
            },
            translator::TwoCap,
        };
        use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};
        use rstest::rstest;
        use std::{fmt::Debug, marker::PhantomData};

        type Context = deterministic::Context;

        type AnyFixed = storage_any::unordered::fixed::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            Sequential,
        >;
        type AnyVariable = storage_any::unordered::variable::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            Sequential,
        >;

        type CurrentUnorderedFixed = storage_current::unordered::fixed::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            64,
            Sequential,
        >;
        type CurrentOrderedFixed = storage_current::ordered::fixed::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            64,
            Sequential,
        >;
        type CurrentUnorderedVariable = storage_current::unordered::variable::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            64,
            Sequential,
        >;
        type CurrentOrderedVariable = storage_current::ordered::variable::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            64,
            Sequential,
        >;

        type ImmutableFixed = storage_immutable::fixed::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            Sequential,
        >;
        type ImmutableVariable = storage_immutable::variable::Db<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            TwoCap,
            Sequential,
        >;
        type ImmutableCompactFixed = storage_immutable::fixed::CompactDb<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            Sequential,
        >;
        type ImmutableCompactVariable = storage_immutable::variable::CompactDb<
            mmr::Family,
            Context,
            Digest,
            U64,
            Sha256,
            ((), ()),
            Sequential,
        >;

        type KeylessFixed =
            storage_keyless::fixed::Db<mmr::Family, Context, U64, Sha256, Sequential>;
        type KeylessVariable =
            storage_keyless::variable::Db<mmr::Family, Context, U64, Sha256, Sequential>;
        type KeylessCompactFixed =
            storage_keyless::fixed::CompactDb<mmr::Family, Context, U64, Sha256, Sequential>;
        type KeylessCompactVariable =
            storage_keyless::variable::CompactDb<mmr::Family, Context, U64, Sha256, (), Sequential>;

        fn page_cache(context: &Context) -> CacheRef {
            CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11))
        }

        fn merkle_config(context: &Context, suffix: &str) -> MerkleConfig<Sequential> {
            MerkleConfig {
                journal_partition: format!("initial-target-{suffix}-merkle-journal"),
                metadata_partition: format!("initial-target-{suffix}-merkle-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache(context),
            }
        }

        fn fixed_journal_config(context: &Context, suffix: &str) -> FixedJournalConfig {
            FixedJournalConfig {
                partition: format!("initial-target-{suffix}-log"),
                items_per_blob: NZU64!(7),
                page_cache: page_cache(context),
                write_buffer: NZUsize!(1024),
            }
        }

        fn variable_journal_config<C>(
            context: &Context,
            suffix: &str,
            codec_config: C,
        ) -> VariableJournalConfig<C> {
            VariableJournalConfig {
                partition: format!("initial-target-{suffix}-log"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config,
                page_cache: page_cache(context),
                write_buffer: NZUsize!(1024),
            }
        }

        fn any_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_any::FixedConfig<TwoCap, Sequential> {
            storage_any::Config {
                merkle_config: merkle_config(context, suffix),
                journal_config: fixed_journal_config(context, suffix),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            }
        }

        fn any_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_any::VariableConfig<TwoCap, ((), ()), Sequential> {
            storage_any::Config {
                merkle_config: merkle_config(context, suffix),
                journal_config: variable_journal_config(context, suffix, ((), ())),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            }
        }

        fn current_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_current::FixedConfig<TwoCap, Sequential> {
            storage_current::Config {
                merkle_config: merkle_config(context, suffix),
                journal_config: fixed_journal_config(context, suffix),
                grafted_metadata_partition: format!("initial-target-{suffix}-grafted-metadata"),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            }
        }

        fn current_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_current::VariableConfig<TwoCap, ((), ()), Sequential> {
            storage_current::Config {
                merkle_config: merkle_config(context, suffix),
                journal_config: variable_journal_config(context, suffix, ((), ())),
                grafted_metadata_partition: format!("initial-target-{suffix}-grafted-metadata"),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            }
        }

        fn immutable_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_immutable::fixed::Config<TwoCap, Sequential> {
            storage_immutable::Config {
                merkle_config: merkle_config(context, suffix),
                log: fixed_journal_config(context, suffix),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
            }
        }

        fn immutable_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_immutable::variable::Config<TwoCap, ((), ()), Sequential> {
            storage_immutable::Config {
                merkle_config: merkle_config(context, suffix),
                log: variable_journal_config(context, suffix, ((), ())),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
            }
        }

        fn keyless_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_keyless::fixed::Config<Sequential> {
            storage_keyless::Config {
                merkle: merkle_config(context, suffix),
                log: fixed_journal_config(context, suffix),
            }
        }

        fn keyless_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_keyless::variable::Config<(), Sequential> {
            storage_keyless::Config {
                merkle: merkle_config(context, suffix),
                log: variable_journal_config(context, suffix, ()),
            }
        }

        fn immutable_compact_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_immutable::fixed::CompactConfig<Sequential> {
            storage_immutable::CompactConfig {
                strategy: Sequential,
                witness: variable_journal_config(context, suffix, ()),
                commit_codec_config: (),
            }
        }

        fn immutable_compact_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_immutable::variable::CompactConfig<((), ()), Sequential> {
            storage_immutable::CompactConfig {
                strategy: Sequential,
                witness: variable_journal_config(context, suffix, ()),
                commit_codec_config: ((), ()),
            }
        }

        fn keyless_compact_fixed_config(
            context: &Context,
            suffix: &str,
        ) -> storage_keyless::fixed::CompactConfig<Sequential> {
            storage_keyless::CompactConfig {
                strategy: Sequential,
                witness: variable_journal_config(context, suffix, ()),
                commit_codec_config: (),
            }
        }

        fn keyless_compact_variable_config(
            context: &Context,
            suffix: &str,
        ) -> storage_keyless::variable::CompactConfig<(), Sequential> {
            storage_keyless::CompactConfig {
                strategy: Sequential,
                witness: variable_journal_config(context, suffix, ()),
                commit_codec_config: (),
            }
        }

        /// Finalize `batch` through the writer, returning the snapshot and flush handle.
        async fn finalize<T: ManagedDb<Context>>(
            writer: Writer<T>,
            batch: T::Merkleized,
        ) -> (Writer<T>, T::Snapshot, Handle<()>) {
            let (writer, (snapshot, sync)) = writer
                .mutate(|db| async move {
                    let (db, snapshot, sync) = T::finalize(db, batch).await.unwrap_or_else(|err| {
                        panic!("finalize failed: {err:?}");
                    });
                    (db, (snapshot, sync))
                })
                .await;
            (writer, snapshot, sync)
        }

        async fn assert_initial_sync_target_and_finalize<T>(context: Context, config: T::Config)
        where
            T: ManagedDb<Context> + 'static,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
            T::SyncTarget: Debug,
        {
            let initial = T::initial_sync_target();
            let db = T::init(context, config).await.unwrap();
            assert_eq!(initial, db.sync_target());
            let writer = Writer::new(db);
            let handle = writer.reader();
            let batch = T::new_batch(handle)
                .await
                .expect("writer is live")
                .merkleize()
                .await
                .expect("empty batch must merkleize");
            let (_writer, snapshot, sync) = finalize(writer, batch).await;
            drop(snapshot);
            sync.await.expect("empty batch finalize flush failed");
        }

        #[rstest]
        #[case::any_fixed(PhantomData::<AnyFixed>, any_fixed_config)]
        #[case::any_variable(PhantomData::<AnyVariable>, any_variable_config)]
        #[case::current_unordered_fixed(
            PhantomData::<CurrentUnorderedFixed>,
            current_fixed_config
        )]
        #[case::current_ordered_fixed(
            PhantomData::<CurrentOrderedFixed>,
            current_fixed_config
        )]
        #[case::current_unordered_variable(
            PhantomData::<CurrentUnorderedVariable>,
            current_variable_config
        )]
        #[case::current_ordered_variable(
            PhantomData::<CurrentOrderedVariable>,
            current_variable_config
        )]
        #[case::immutable_fixed(PhantomData::<ImmutableFixed>, immutable_fixed_config)]
        #[case::immutable_variable(
            PhantomData::<ImmutableVariable>,
            immutable_variable_config
        )]
        #[case::immutable_compact_fixed(
            PhantomData::<ImmutableCompactFixed>,
            immutable_compact_fixed_config
        )]
        #[case::immutable_compact_variable(
            PhantomData::<ImmutableCompactVariable>,
            immutable_compact_variable_config
        )]
        #[case::keyless_fixed(PhantomData::<KeylessFixed>, keyless_fixed_config)]
        #[case::keyless_variable(PhantomData::<KeylessVariable>, keyless_variable_config)]
        #[case::keyless_compact_fixed(
            PhantomData::<KeylessCompactFixed>,
            keyless_compact_fixed_config
        )]
        #[case::keyless_compact_variable(
            PhantomData::<KeylessCompactVariable>,
            keyless_compact_variable_config
        )]
        fn initial_sync_target_and_empty_finalize_match_initialized_database<T>(
            #[case] _db: PhantomData<T>,
            #[case] config: fn(&Context, &str) -> T::Config,
        ) where
            T: ManagedDb<Context> + 'static,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
            T::SyncTarget: Debug,
        {
            deterministic::Runner::default().start(|context| async move {
                let config = config(&context, "db");
                assert_initial_sync_target_and_finalize::<T>(context.child("db"), config).await;
            });
        }

        async fn assert_rewind_restores_finalized_target<T>(context: Context, config: T::Config)
        where
            T: ManagedDb<Context> + 'static,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
            T::SyncTarget: Debug,
        {
            let db = T::init(context, config).await.unwrap();
            let writer = Writer::new(db);
            let handle = writer.reader();
            let batch = T::new_batch(handle.clone())
                .await
                .expect("writer is live")
                .merkleize()
                .await
                .expect("first batch must merkleize");
            let (writer, snapshot, sync) = finalize(writer, batch).await;
            drop(snapshot);
            sync.await.expect("first finalize flush failed");
            let target = handle.read().await.expect("writer is live").sync_target();

            let batch = T::new_batch(handle.clone())
                .await
                .expect("writer is live")
                .merkleize()
                .await
                .expect("second batch must merkleize");
            let (writer, snapshot, sync) = finalize(writer, batch).await;
            drop(snapshot);
            sync.await.expect("second finalize flush failed");

            let (_writer, ()) = writer
                .mutate(|db| {
                    let target = target.clone();
                    async move {
                        let db = db
                            .rewind_to_target(target)
                            .await
                            .unwrap_or_else(|_| panic!("rewind to finalized target failed"));
                        (db, ())
                    }
                })
                .await;
            assert_eq!(
                handle.read().await.expect("writer is live").sync_target(),
                target
            );
        }

        #[rstest]
        #[case::any_fixed(PhantomData::<AnyFixed>, any_fixed_config)]
        #[case::any_variable(PhantomData::<AnyVariable>, any_variable_config)]
        #[case::current_unordered_fixed(
            PhantomData::<CurrentUnorderedFixed>,
            current_fixed_config
        )]
        #[case::current_ordered_fixed(
            PhantomData::<CurrentOrderedFixed>,
            current_fixed_config
        )]
        #[case::current_unordered_variable(
            PhantomData::<CurrentUnorderedVariable>,
            current_variable_config
        )]
        #[case::current_ordered_variable(
            PhantomData::<CurrentOrderedVariable>,
            current_variable_config
        )]
        #[case::immutable_fixed(PhantomData::<ImmutableFixed>, immutable_fixed_config)]
        #[case::immutable_variable(
            PhantomData::<ImmutableVariable>,
            immutable_variable_config
        )]
        #[case::immutable_compact_fixed(
            PhantomData::<ImmutableCompactFixed>,
            immutable_compact_fixed_config
        )]
        #[case::immutable_compact_variable(
            PhantomData::<ImmutableCompactVariable>,
            immutable_compact_variable_config
        )]
        #[case::keyless_fixed(PhantomData::<KeylessFixed>, keyless_fixed_config)]
        #[case::keyless_variable(PhantomData::<KeylessVariable>, keyless_variable_config)]
        #[case::keyless_compact_fixed(
            PhantomData::<KeylessCompactFixed>,
            keyless_compact_fixed_config
        )]
        #[case::keyless_compact_variable(
            PhantomData::<KeylessCompactVariable>,
            keyless_compact_variable_config
        )]
        fn rewind_restores_earlier_finalized_sync_target<T>(
            #[case] _db: PhantomData<T>,
            #[case] config: fn(&Context, &str) -> T::Config,
        ) where
            T: ManagedDb<Context> + 'static,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
            T::SyncTarget: Debug,
        {
            deterministic::Runner::default().start(|context| async move {
                let config = config(&context, "db");
                assert_rewind_restores_finalized_target::<T>(context.child("db"), config).await;
            });
        }
    }

    macro_rules! ready_finalize {
        () => {
            async fn finalize(
                self,
                _batch: Self::Merkleized,
            ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
                Ok((self, (), Handle::ready(Ok(()))))
            }
        };
    }

    #[derive(Default)]
    struct TestDb;

    struct CountingRewindDb {
        current_target: u64,
        rewind_count: usize,
    }

    struct PruneCountingDb {
        prune_count: Arc<AtomicUsize>,
    }

    impl<E: Send> ManagedDb<E> for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for CountingRewindDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("CountingRewindDb is constructed directly in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("CountingRewindDb is constructed directly in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.current_target
        }

        async fn rewind_to_target(mut self, target: Self::SyncTarget) -> Result<Self, Self::Error> {
            self.current_target = target;
            self.rewind_count += 1;
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for PruneCountingDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = Arc<AtomicUsize>;
        type SyncTarget = ();
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(_context: E, prune_count: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self { prune_count })
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        async fn prune(self, _target: &Self::SyncTarget) -> Result<Self, Self::Error> {
            self.prune_count.fetch_add(1, Ordering::SeqCst);
            Ok(self)
        }

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    struct BlockingFinalizeDb {
        started: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }

    impl BlockingFinalizeDb {
        fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
            Self {
                started: Some(started),
                release: Some(release),
            }
        }
    }

    #[derive(Debug)]
    struct TestFinalizeError;

    struct FailingFinalizeDb;

    struct SlowSyncDb {
        final_target: u64,
    }

    struct RejectDuplicateTargetSyncDb {
        final_target: u64,
    }

    struct StaleReachedSyncDb {
        final_target: u64,
    }

    struct FastSyncDb {
        final_target: u64,
    }

    struct ImmediateStateSyncDb;

    struct FailingStateSyncDb;

    struct MismatchedTargetSyncDb {
        final_target: u64,
    }

    struct FinishClosedSyncDb {
        final_target: u64,
    }

    struct ObservedSlowSyncDb {
        final_target: u64,
    }

    struct ObservedFastSyncDb {
        final_target: u64,
    }

    struct DistinctObservedFastSyncDb {
        final_target: u64,
    }

    #[derive(Clone)]
    struct SlowSyncController {
        release: Arc<AtomicBool>,
    }

    #[derive(Clone)]
    struct FastSyncObserver {
        ready: Arc<AtomicBool>,
        update_count: Arc<AtomicUsize>,
    }

    impl<E: Send> ManagedDb<E> for FailingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = TestFinalizeError;
        type Config = ();
        type SyncTarget = ();
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(
            self,
            _batch: Self::Merkleized,
        ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
            Err(TestFinalizeError)
        }

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    struct FailingSnapshotDb;

    impl<E: Send> ManagedDb<E> for FailingSnapshotDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = TestFinalizeError;
        type Config = ();
        type SyncTarget = ();
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Err(TestFinalizeError)
        }

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(
            self,
            _batch: Self::Merkleized,
        ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
            Ok((self, (), Handle::ready(Ok(()))))
        }

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    #[test]
    fn tuple_rewind_to_targets_skips_already_aligned_databases() {
        deterministic::Runner::default().start(|_context| async move {
            type RewindPair = (Single<CountingRewindDb>, Single<CountingRewindDb>);

            let left = CountingRewindDb {
                current_target: 2,
                rewind_count: 0,
            };
            let right = CountingRewindDb {
                current_target: 1,
                rewind_count: 0,
            };

            let databases: RewindPair = (Single::from(left), Single::from(right));
            let databases = <RewindPair as DatabaseSet<deterministic::Context>>::rewind_to_targets(
                databases,
                (1, 1),
            )
            .await;

            let (left, right) = (databases.0.handle(), databases.1.handle());
            assert_eq!(left.read().await.expect("writer is live").current_target, 1);
            assert_eq!(left.read().await.expect("writer is live").rewind_count, 1);

            assert_eq!(
                right.read().await.expect("writer is live").current_target,
                1
            );
            assert_eq!(right.read().await.expect("writer is live").rewind_count, 0);
        });
    }

    #[test]
    fn database_set_prune_calls_managed_db_prune() {
        deterministic::Runner::default().start(|_context| async move {
            let prune_count = Arc::new(AtomicUsize::new(0));
            let database = Single::from(PruneCountingDb {
                prune_count: prune_count.clone(),
            });

            let _database = DatabaseSet::<deterministic::Context>::prune(database, &()).await;

            assert_eq!(prune_count.load(Ordering::SeqCst), 1);
        });
    }

    impl<E: Send> ManagedDb<E> for BlockingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("BlockingFinalizeDb is constructed directly in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(
            mut self,
            _batch: Self::Merkleized,
        ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.await;
            }
            Ok((self, (), Handle::ready(Ok(()))))
        }

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for SlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("SlowSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("SlowSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for RejectDuplicateTargetSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!(
                "RejectDuplicateTargetSyncDb is only constructed through state sync in tests"
            )
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!(
                "RejectDuplicateTargetSyncDb is only constructed through state sync in tests"
            )
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for FastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FastSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FastSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for FailingStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FailingStateSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FailingStateSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for MismatchedTargetSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("MismatchedTargetSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("MismatchedTargetSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for ImmediateStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ImmediateStateSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ImmediateStateSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for FinishClosedSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FinishClosedSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FinishClosedSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedSlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ObservedSlowSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ObservedSlowSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ObservedFastSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ObservedFastSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E: Send> ManagedDb<E> for DistinctObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!(
                "DistinctObservedFastSyncDb is only constructed through state sync in tests"
            )
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!(
                "DistinctObservedFastSyncDb is only constructed through state sync in tests"
            )
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E> StateSyncDb<E, Arc<AtomicBool>> for SlowSyncDb
    where
        E: Send + Clock,
    {
        type SyncError = Infallible;

        async fn sync_db(
            context: E,
            _config: Self::Config,
            release: Arc<AtomicBool>,
            target: Self::SyncTarget,
            tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            while !release.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);

            loop {
                if let Some(reached_target) = reached_target.as_ref()
                    && reached_target.send(final_target).await.is_err()
                {
                    break;
                }

                context.sleep(Duration::from_millis(1)).await;

                if finish.is_none() && tip_updates.is_none() {
                    break;
                }

                let finish_signal = finish.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |finish_rx| futures::future::Either::Left(finish_rx.recv()),
                );
                let update_signal = tip_updates.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |update_rx| futures::future::Either::Left(update_rx.recv()),
                );

                select! {
                    _ = finish_signal => {
                        break;
                    },
                    update = update_signal => match update {
                        Some(update) => {
                            final_target = update;
                        }
                        None => {
                            tip_updates = None;
                            if finish.is_none() {
                                break;
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
        }
    }

    impl<E> StateSyncDb<E, Arc<AtomicBool>> for RejectDuplicateTargetSyncDb
    where
        E: Send + Clock,
    {
        type SyncError = Infallible;

        async fn sync_db(
            context: E,
            _config: Self::Config,
            release: Arc<AtomicBool>,
            target: Self::SyncTarget,
            mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = target;
            while !release.load(Ordering::SeqCst) {
                match tip_updates.try_recv() {
                    Ok(update) => {
                        assert_ne!(
                            update, final_target,
                            "state sync must not send duplicate target updates"
                        );
                        final_target = update;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            if let Some(reached_target) = reached_target.as_ref() {
                let _ = reached_target.send(final_target).await;
            }
            if let Some(finish_rx) = finish.as_mut() {
                let _ = finish_rx.recv().await;
            }

            Ok(Self { final_target })
        }
    }

    impl<E: Send> ManagedDb<E> for StaleReachedSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("StaleReachedSyncDb is only constructed through state sync in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("StaleReachedSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_handle: Reader<Self>) -> Result<Self::Unmerkleized, Closed> {
            Ok(TestUnmerkleized)
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_finalize!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    impl<E> StateSyncDb<E, ()> for StaleReachedSyncDb
    where
        E: Send + Clock,
    {
        type SyncError = Infallible;

        async fn sync_db(
            context: E,
            _config: Self::Config,
            _resolver: (),
            target: Self::SyncTarget,
            mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let update = tip_updates.recv().await.expect("expected forwarded tip");
            if let Some(reached_target) = reached_target.as_ref() {
                let _ = reached_target.send(target).await;
            }

            let finish_signal = finish.as_mut().map_or_else(
                || futures::future::Either::Right(futures::future::pending()),
                |finish_rx| futures::future::Either::Left(finish_rx.recv()),
            );
            select! {
                _ = finish_signal => Ok(Self {
                    final_target: target
                }),
                _ = context.sleep(Duration::from_millis(10)) => {
                    if let Some(reached_target) = reached_target.as_ref() {
                        let _ = reached_target.send(update).await;
                    }
                    if let Some(finish_rx) = finish.as_mut() {
                        let _ = finish_rx.recv().await;
                    }
                    Ok(Self {
                        final_target: update,
                    })
                },
            }
        }
    }

    impl<E: Send> StateSyncDb<E, Arc<AtomicBool>> for FastSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            done: Arc<AtomicBool>,
            target: Self::SyncTarget,
            tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            done.store(true, Ordering::SeqCst);
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);

            loop {
                if let Some(reached_target) = reached_target.as_ref()
                    && reached_target.send(final_target).await.is_err()
                {
                    break;
                }

                if finish.is_none() && tip_updates.is_none() {
                    break;
                }

                let finish_signal = finish.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |finish_rx| futures::future::Either::Left(finish_rx.recv()),
                );
                let update_signal = tip_updates.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |update_rx| futures::future::Either::Left(update_rx.recv()),
                );

                select! {
                    _ = finish_signal => {
                        break;
                    },
                    update = update_signal => match update {
                        Some(update) => {
                            final_target = update;
                        }
                        None => {
                            tip_updates = None;
                            if finish.is_none() {
                                break;
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
        }
    }

    #[derive(Debug)]
    struct TestSyncError;

    #[derive(Debug)]
    struct FinishClosedSyncError;

    impl<E: Send> StateSyncDb<E, ()> for FailingStateSyncDb {
        type SyncError = TestSyncError;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            _resolver: (),
            _target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            _finish: Option<mpsc::Receiver<()>>,
            _reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            Err(TestSyncError)
        }
    }

    impl<E: Send> StateSyncDb<E, ()> for ImmediateStateSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            _resolver: (),
            _target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            _finish: Option<mpsc::Receiver<()>>,
            _reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            Ok(Self)
        }
    }

    impl<E: Send> StateSyncDb<E, ()> for MismatchedTargetSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            _resolver: (),
            target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            if let Some(reached_target) = reached_target.as_ref() {
                let _ = reached_target.send(target).await;
            }
            if let Some(finish_rx) = finish.as_mut() {
                let _ = finish_rx.recv().await;
            }
            Ok(Self {
                final_target: target + 1,
            })
        }
    }

    impl<E: Send> StateSyncDb<E, ()> for FinishClosedSyncDb {
        type SyncError = FinishClosedSyncError;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            _resolver: (),
            target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            _reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let Some(finish_rx) = finish.as_mut() else {
                panic!("finish receiver should be provided");
            };
            match finish_rx.recv().await {
                Some(()) => Ok(Self {
                    final_target: target,
                }),
                None => Err(FinishClosedSyncError),
            }
        }
    }

    impl<E> StateSyncDb<E, SlowSyncController> for ObservedSlowSyncDb
    where
        E: Send + Clock,
    {
        type SyncError = Infallible;

        async fn sync_db(
            context: E,
            _config: Self::Config,
            controller: SlowSyncController,
            target: Self::SyncTarget,
            tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            while !controller.release.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);
            let mut reported_target = None;
            let mut observed_update = false;
            loop {
                if let Some(update_rx) = tip_updates.as_mut() {
                    let mut drained = 0usize;
                    loop {
                        match update_rx.try_recv() {
                            Ok(update) => {
                                drained += 1;
                                final_target = update;
                                observed_update = true;
                                reported_target = None;
                                if drained.is_multiple_of(MAX_CHANNEL_DRAIN_PER_TICK) {
                                    reschedule().await;
                                }
                            }
                            Err(mpsc::error::TryRecvError::Empty) => {
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                tip_updates = None;
                                break;
                            }
                        }
                    }
                }

                if observed_update && reported_target != Some(final_target) {
                    if let Some(reached_target) = reached_target.as_ref()
                        && reached_target.send(final_target).await.is_err()
                    {
                        break;
                    }
                    reported_target = Some(final_target);
                }

                if finish.is_none() && tip_updates.is_none() {
                    break;
                }

                let finish_signal = finish.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |finish_rx| futures::future::Either::Left(finish_rx.recv()),
                );
                let update_signal = tip_updates.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |update_rx| futures::future::Either::Left(update_rx.recv()),
                );

                select! {
                    _ = finish_signal => {
                        break;
                    },
                    update = update_signal => match update {
                        Some(update) => {
                            final_target = update;
                            observed_update = true;
                            reported_target = None;
                        }
                        None => {
                            tip_updates = None;
                            if finish.is_none() {
                                break;
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
        }
    }

    impl<E: Send> StateSyncDb<E, FastSyncObserver> for ObservedFastSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            observer: FastSyncObserver,
            target: Self::SyncTarget,
            tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);
            let mut reported_target = None;
            observer.ready.store(true, Ordering::SeqCst);

            loop {
                if reported_target != Some(final_target) {
                    if let Some(reached_target) = reached_target.as_ref()
                        && reached_target.send(final_target).await.is_err()
                    {
                        break;
                    }
                    reported_target = Some(final_target);
                }

                if finish.is_none() && tip_updates.is_none() {
                    break;
                }

                let finish_signal = finish.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |finish_rx| futures::future::Either::Left(finish_rx.recv()),
                );
                let update_signal = tip_updates.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |update_rx| futures::future::Either::Left(update_rx.recv()),
                );

                select! {
                    _ = finish_signal => {
                        break;
                    },
                    update = update_signal => match update {
                        Some(update) => {
                            observer.update_count.fetch_add(1, Ordering::SeqCst);
                            final_target = update;
                            reported_target = None;
                        }
                        None => {
                            tip_updates = None;
                            if finish.is_none() {
                                break;
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
        }
    }

    impl<E: Send> StateSyncDb<E, FastSyncObserver> for DistinctObservedFastSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            observer: FastSyncObserver,
            target: Self::SyncTarget,
            tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);
            let mut reported_target = None;
            observer.ready.store(true, Ordering::SeqCst);

            loop {
                if reported_target != Some(final_target) {
                    if let Some(reached_target) = reached_target.as_ref()
                        && reached_target.send(final_target).await.is_err()
                    {
                        break;
                    }
                    reported_target = Some(final_target);
                }

                if finish.is_none() && tip_updates.is_none() {
                    break;
                }

                let finish_signal = finish.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |finish_rx| futures::future::Either::Left(finish_rx.recv()),
                );
                let update_signal = tip_updates.as_mut().map_or_else(
                    || futures::future::Either::Right(futures::future::pending()),
                    |update_rx| futures::future::Either::Left(update_rx.recv()),
                );

                select! {
                    _ = finish_signal => {
                        break;
                    },
                    update = update_signal => match update {
                        Some(update) => {
                            observer.update_count.fetch_add(1, Ordering::SeqCst);
                            if update != final_target {
                                final_target = update;
                                reported_target = None;
                            }
                        }
                        None => {
                            tip_updates = None;
                            if finish.is_none() {
                                break;
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
        }
    }

    #[test]
    fn tuple_finalize_runs_databases_in_parallel() {
        deterministic::Runner::default().start(|_context| async move {
            let (started1_tx, started1_rx) = oneshot::channel();
            let (started2_tx, started2_rx) = oneshot::channel();
            let (release1_tx, release1_rx) = oneshot::channel();
            let (release2_tx, release2_rx) = oneshot::channel();

            let databases = (
                Single::from(BlockingFinalizeDb::new(started1_tx, release1_rx)),
                Single::from(BlockingFinalizeDb::new(started2_tx, release2_rx)),
            );

            let finalize = DatabaseSet::<deterministic::Context>::finalize(
                databases,
                (TestMerkleized, TestMerkleized),
            );
            pin_mut!(finalize);
            assert!(finalize.as_mut().now_or_never().is_none());

            let started1 = started1_rx;
            let started2 = started2_rx;
            pin_mut!(started1);
            pin_mut!(started2);
            assert!(matches!(started1.as_mut().now_or_never(), Some(Ok(()))));
            assert!(
                matches!(started2.as_mut().now_or_never(), Some(Ok(()))),
                "tuple finalize should start all database finalizations concurrently"
            );

            let _ = release1_tx.send(());
            let _ = release2_tx.send(());
            let (_, _, barrier) = finalize.await;
            assert!(barrier.durable().await);
        });
    }

    #[test]
    #[should_panic(
        expected = "database finalize failed (index 1, type commonware_glue::stateful::db::tests::FailingFinalizeDb)"
    )]
    fn tuple_finalize_panic_identifies_failing_database() {
        deterministic::Runner::default().start(|_context| async move {
            let databases = (Single::from(TestDb), Single::from(FailingFinalizeDb));
            let _ = DatabaseSet::<deterministic::Context>::finalize(
                databases,
                (TestMerkleized, TestMerkleized),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(
        expected = "database snapshot capture failed (index 1, type commonware_glue::stateful::db::tests::FailingSnapshotDb)"
    )]
    fn tuple_snapshot_panic_identifies_failing_database() {
        deterministic::Runner::default().start(|_context| async move {
            let databases = (Single::from(TestDb), Single::from(FailingSnapshotDb));
            let _ = DatabaseSet::<deterministic::Context>::snapshot(databases).await;
        });
    }

    #[test]
    #[should_panic(
        expected = "database finalize flush failed (index 1, type commonware_glue::stateful::db::tests::TestDb)"
    )]
    fn barrier_panics_on_flush_failure() {
        deterministic::Runner::default().start(|_context| async move {
            let barrier = Barrier::from_handles::<TestDb>([
                Handle::ready(Ok(())),
                Handle::ready(Err(RuntimeError::WriteFailed)),
            ]);
            let _ = barrier.durable().await;
        });
    }

    #[test]
    fn barrier_reports_shutdown_as_not_durable() {
        deterministic::Runner::default().start(|_context| async move {
            let barrier = Barrier {
                syncs: vec![
                    ("db0", Some(0), Handle::ready(Ok(()))),
                    ("db1", Some(1), Handle::ready(Err(RuntimeError::Closed))),
                ],
            };
            assert!(!barrier.durable().await);

            let barrier = Barrier {
                syncs: vec![("db0", None, Handle::ready(Err(RuntimeError::Aborted)))],
            };
            assert!(!barrier.durable().await);
        });
    }

    type TestAnchor = Anchor<sha256::Digest>;

    fn anchor(n: u64) -> TestAnchor {
        mock_anchor(n, n as u8)
    }

    #[test]
    fn tip_update_observation_follows_recording() {
        deterministic::Runner::default().start(|_context| async move {
            let (update, mut observed) = TipUpdate::with_observation(anchor(1), 7u64);
            let mut recorded = None;

            update.record(|new_anchor, new_target| {
                assert!((&mut observed).now_or_never().is_none());
                recorded = Some((new_anchor, new_target));
            });

            assert_eq!(recorded, Some((anchor(1), 7)));
            observed.await.expect("recorded update should be observed");
        });
    }

    #[test]
    fn single_tip_update_drain_keeps_highest_recorded_target() {
        deterministic::Runner::default().start(|_context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (target_tx, mut target_rx) = mpsc::channel(4);
            let (newer_update, newer_observed) = TipUpdate::with_observation(anchor(2), 2u64);
            let (older_update, older_observed) = TipUpdate::with_observation(anchor(1), 1u64);

            let _ = tip_tx.send(newer_update).await;
            let _ = tip_tx.send(older_update).await;

            let mut tip_updates = Some(tip_rx);
            let mut current_anchor = anchor(0);
            let mut current_target = 0u64;
            assert!(
                drain_single_tip_updates(
                    &mut tip_updates,
                    &target_tx,
                    &mut current_anchor,
                    &mut current_target,
                )
                .await
            );

            newer_observed
                .await
                .expect("newer update should be observed");
            older_observed
                .await
                .expect("older update should also be observed");
            assert_eq!(current_anchor, anchor(2));
            assert_eq!(current_target, 2);
            assert_eq!(target_rx.recv().await, Some(2));
            assert!(matches!(
                target_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn single_tip_update_drain_advances_anchor_without_duplicate_target() {
        deterministic::Runner::default().start(|_context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let (target_tx, mut target_rx) = mpsc::channel(1);
            let (update, observed) = TipUpdate::with_observation(anchor(3), 7u64);

            let _ = tip_tx.send(update).await;

            let mut tip_updates = Some(tip_rx);
            let mut current_anchor = anchor(2);
            let mut current_target = 7u64;
            assert!(
                drain_single_tip_updates(
                    &mut tip_updates,
                    &target_tx,
                    &mut current_anchor,
                    &mut current_target,
                )
                .await
            );

            observed.await.expect("update should be observed");
            assert_eq!(current_anchor, anchor(3));
            assert_eq!(current_target, 7);
            assert!(matches!(
                target_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn single_state_sync_handles_closed_tip_updates_channel() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let release = Arc::new(AtomicBool::new(false));
            let release_for_sync = release.clone();

            let sync = context.child("single_state_sync_closed_tip_updates").spawn(
                move |context| async move {
                    <Single<SlowSyncDb> as StateSyncSet<
                        deterministic::Context,
                        Arc<AtomicBool>,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        release_for_sync,
                        anchor(0),
                        0,
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                },
            );

            drop(tip_tx);
            context.sleep(Duration::from_millis(1)).await;
            release.store(true, Ordering::SeqCst);

            let (_database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(converged_anchor, anchor(0));
        });
    }

    #[test]
    fn single_state_sync_preserves_db_error_when_target_channel_closes() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let _ = tip_tx.send(TipUpdate::new(anchor(1), 1u64)).await;

            let result = <Single<FailingStateSyncDb> as StateSyncSet<
                deterministic::Context,
                (),
                sha256::Digest,
            >>::sync(
                context,
                (),
                (),
                anchor(0),
                0,
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NonZeroU64::new(1).unwrap(),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
                    max_retained_roots: 0,
                },
            )
            .await;

            assert!(matches!(result, Err(TestSyncError)));
        });
    }

    #[test]
    fn single_state_sync_ignores_backward_tip_updates() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let release = Arc::new(AtomicBool::new(true));
            let source = SlowSyncController {
                release: release.clone(),
            };

            let sync = context
                .child("single_state_sync_ignores_backward_tip_updates")
                .spawn(move |context| async move {
                    <Single<ObservedSlowSyncDb> as StateSyncSet<
                        deterministic::Context,
                        SlowSyncController,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        source,
                        anchor(0),
                        0,
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                });

            let _ = tip_tx.send(TipUpdate::new(anchor(2), 2)).await;
            let _ = tip_tx.send(TipUpdate::new(anchor(1), 1)).await;
            drop(tip_tx);

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            let final_target = database
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            assert_eq!(
                final_target, 2,
                "single-db sync target must never move backward"
            );
            assert_eq!(
                converged_anchor,
                anchor(2),
                "converged anchor must remain on the highest seen tip"
            );
        });
    }

    #[test]
    fn single_state_sync_advances_anchor_without_duplicate_target_update() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let release = Arc::new(AtomicBool::new(false));
            let release_for_sync = release.clone();

            let sync = context.child("single_state_sync_noop_target_update").spawn(
                move |context| async move {
                    <Single<RejectDuplicateTargetSyncDb> as StateSyncSet<
                        deterministic::Context,
                        Arc<AtomicBool>,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        release_for_sync,
                        anchor(7),
                        7,
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                },
            );

            // Let the coordinator finish its initial queue drain so the update
            // below exercises the live select arm.
            context.sleep(Duration::from_millis(10)).await;
            let (update, observed) = TipUpdate::with_observation(anchor(9), 7);
            let _ = tip_tx.send(update).await;
            observed
                .await
                .expect("single-db coordinator should record noop target update");
            release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(
                database
                    .handle()
                    .read()
                    .await
                    .expect("writer is live")
                    .final_target,
                7
            );
            assert_eq!(converged_anchor, anchor(9));
        });
    }

    #[test]
    fn single_state_sync_ignores_stale_reached_after_forwarded_tip() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());

            let sync =
                context
                    .child("single_state_sync_stale_reached")
                    .spawn(move |context| async move {
                        <Single<StaleReachedSyncDb> as StateSyncSet<
                            deterministic::Context,
                            (),
                            sha256::Digest,
                        >>::sync(
                            context,
                            (),
                            (),
                            anchor(0),
                            0,
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: NZU64!(1),
                                max_outstanding_requests: 1,
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                                max_retained_roots: 0,
                            },
                        )
                        .await
                        .expect("single state sync should succeed")
                    });

            let _ = tip_tx.send(TipUpdate::new(anchor(2), 2)).await;

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            let final_target = database
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            assert_eq!(
                final_target, 2,
                "single-db sync must not finish on a stale reached target",
            );
            assert_eq!(
                converged_anchor,
                anchor(2),
                "converged anchor must match the target the database reached",
            );
        });
    }

    #[test]
    fn tuple_state_sync_converges_before_finish() {
        deterministic::Runner::default().start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_done = Arc::new(AtomicBool::new(false));

            let slow_release_for_sync = slow_release.clone();
            let fast_done_for_sync = fast_done.clone();
            let sync = context
                .child("tuple_state_sync")
                .spawn(move |context| async move {
                    <(Single<SlowSyncDb>, Single<FastSyncDb>) as StateSyncSet<
                        deterministic::Context,
                        (Arc<AtomicBool>, Arc<AtomicBool>),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_release_for_sync, fast_done_for_sync),
                        anchor(0),
                        (0, 0),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                });

            while !fast_done.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
            let _ = tip_tx.send(TipUpdate::new(anchor(1), (1, 1))).await;
            let _ = tip_tx.send(TipUpdate::new(anchor(2), (2, 2))).await;
            slow_release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced
                .0
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            let fast_target = synced
                .1
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;

            assert_eq!(
                slow_target, fast_target,
                "all databases should finish on the same converged target set"
            );
            assert_eq!(
                converged_anchor.height.get(),
                slow_target,
                "returned anchor height should match the converged generation"
            );
        });
    }

    #[test]
    fn tuple_state_sync_ignores_backward_tip_updates() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(8).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_done = Arc::new(AtomicBool::new(false));

            let slow_release_for_sync = slow_release.clone();
            let fast_done_for_sync = fast_done.clone();
            let sync = context
                .child("tuple_state_sync_ignores_backward_tip_updates")
                .spawn(move |context| async move {
                    <(Single<SlowSyncDb>, Single<FastSyncDb>) as StateSyncSet<
                        deterministic::Context,
                        (Arc<AtomicBool>, Arc<AtomicBool>),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_release_for_sync, fast_done_for_sync),
                        anchor(0),
                        (0, 0),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(8).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                });

            while !fast_done.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            let _ = tip_tx.send(TipUpdate::new(anchor(2), (2, 2))).await;
            let _ = tip_tx.send(TipUpdate::new(anchor(1), (1, 1))).await;
            drop(tip_tx);
            context.sleep(Duration::from_millis(1)).await;
            slow_release.store(true, Ordering::SeqCst);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced
                .0
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            let fast_target = synced
                .1
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            assert_eq!(
                slow_target, 2,
                "slow database target must never move backward"
            );
            assert_eq!(
                fast_target, 2,
                "fast database target must never move backward"
            );
            assert_eq!(
                converged_anchor,
                anchor(2),
                "converged anchor must remain on the highest seen tip"
            );
        });
    }

    #[test]
    fn tuple_state_sync_rejects_database_target_mismatch() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (_tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let fast_done = Arc::new(AtomicBool::new(false));

            let result = <(Single<MismatchedTargetSyncDb>, Single<FastSyncDb>) as StateSyncSet<
                deterministic::Context,
                ((), Arc<AtomicBool>),
                sha256::Digest,
            >>::sync(
                context,
                ((), ()),
                ((), fast_done),
                anchor(7),
                (7, 7),
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NonZeroU64::new(1).unwrap(),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
                    max_retained_roots: 0,
                },
            )
            .await;

            let err = match result {
                Ok(_) => panic!("tuple state sync should reject a mismatched database target"),
                Err(err) => err,
            };
            assert!(
                err.contains("database targets do not match"),
                "error should identify the target mismatch, got: {err}"
            );
        });
    }

    #[test]
    fn tuple_state_sync_returns_db_error_instead_of_panicking_when_anchor_missing() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (_tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());

            let result =
                <(Single<ImmediateStateSyncDb>, Single<FailingStateSyncDb>) as StateSyncSet<
                    deterministic::Context,
                    ((), ()),
                    sha256::Digest,
                >>::sync(
                    context,
                    ((), ()),
                    ((), ()),
                    anchor(0),
                    (0, 0),
                    tip_rx,
                    SyncEngineConfig {
                        fetch_batch_size: NonZeroU64::new(1).unwrap(),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NonZeroUsize::new(1).unwrap(),
                        max_retained_roots: 0,
                    },
                )
                .await;

            let err = match result {
                Ok(_) => panic!("tuple state sync should return the database sync error"),
                Err(err) => err,
            };
            assert!(
                err.contains("state sync failed (index 1, db"),
                "error should include failing database index: {err}"
            );
            assert!(
                err.contains("FailingStateSyncDb"),
                "error should include failing database type: {err}"
            );
        });
    }

    #[test]
    fn tuple_state_sync_returns_db_error_when_other_database_waits_for_finish() {
        deterministic::Runner::timed(Duration::from_secs(1)).start(|context| async move {
            let (_tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let release = Arc::new(AtomicBool::new(true));

            let result = <(Single<SlowSyncDb>, Single<FailingStateSyncDb>) as StateSyncSet<
                deterministic::Context,
                (Arc<AtomicBool>, ()),
                sha256::Digest,
            >>::sync(
                context,
                ((), ()),
                (release, ()),
                anchor(0),
                (0, 0),
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NonZeroU64::new(1).unwrap(),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
                    max_retained_roots: 0,
                },
            )
            .await;

            let err = match result {
                Ok(_) => panic!("tuple state sync should return the database sync error"),
                Err(err) => err,
            };
            assert!(
                err.contains("state sync failed (index 1, db"),
                "error should include failing database index: {err}"
            );
            assert!(
                err.contains("FailingStateSyncDb"),
                "error should include failing database type: {err}"
            );
        });
    }

    #[test]
    fn tuple_state_sync_preserves_original_failure_when_peer_finish_channel_closes() {
        deterministic::Runner::timed(Duration::from_secs(1)).start(|context| async move {
            let (_tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());

            let result =
                <(Single<FinishClosedSyncDb>, Single<FailingStateSyncDb>) as StateSyncSet<
                    deterministic::Context,
                    ((), ()),
                    sha256::Digest,
                >>::sync(
                    context,
                    ((), ()),
                    ((), ()),
                    anchor(0),
                    (0, 0),
                    tip_rx,
                    SyncEngineConfig {
                        fetch_batch_size: NonZeroU64::new(1).unwrap(),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NonZeroUsize::new(1).unwrap(),
                        max_retained_roots: 0,
                    },
                )
                .await;

            let err = match result {
                Ok(_) => panic!("tuple state sync should return the database sync error"),
                Err(err) => err,
            };
            assert!(
                err.contains("state sync failed (index 1, db"),
                "error should include failing database index: {err}"
            );
            assert!(
                err.contains("FailingStateSyncDb"),
                "error should include failing database type: {err}"
            );
        });
    }

    #[test]
    fn coordinator_rejects_stale_reached_event_from_older_generation() {
        let mut state = CoordinatorState::new(2, anchor(0), (0u64, 0u64));

        state.record_tip_update(anchor(1), (1, 1));
        match state.next_action() {
            CoordinatorAction::Dispatch {
                generation,
                targets: (left, right),
            } => {
                assert_eq!(generation, 1, "coordinator should dispatch generation 1");
                assert_eq!((left, right), (1, 1));
            }
            CoordinatorAction::Wait => panic!("coordinator should dispatch the newer tip"),
            CoordinatorAction::Converged { anchor, .. } => {
                panic!("coordinator converged too early at {anchor:?}")
            }
        }

        // This reached event belongs to generation 0 but arrives after the
        // coordinator has already advanced the database to generation 1.
        state.record_reached(1, 0);

        // Only database 0 has actually reached generation 1 so far.
        state.record_reached(0, 1);

        match state.next_action() {
            CoordinatorAction::Wait => {}
            CoordinatorAction::Dispatch { targets, .. } => {
                panic!(
                    "coordinator should wait for a fresh reached event, got dispatch {targets:?}"
                )
            }
            CoordinatorAction::Converged { anchor, .. } => {
                panic!("stale reached event must not allow convergence at {anchor:?}")
            }
        }
    }

    #[test]
    fn coordinator_dispatches_pending_tip_before_converging() {
        let mut state = CoordinatorState::new(2, anchor(0), (0u64, 0u64));

        state.record_tip_update(anchor(1), (1, 1));
        match state.next_action() {
            CoordinatorAction::Dispatch {
                generation,
                targets: (left, right),
            } => {
                assert_eq!(generation, 1, "coordinator should dispatch generation 1");
                assert_eq!((left, right), (1, 1));
            }
            CoordinatorAction::Wait => panic!("coordinator should dispatch the newer tip"),
            CoordinatorAction::Converged { anchor, .. } => {
                panic!("coordinator converged too early at {anchor:?}")
            }
        }

        state.record_reached(0, 1);
        state.record_reached(1, 1);
        state.record_tip_update(anchor(2), (2, 2));

        match state.next_action() {
            CoordinatorAction::Dispatch {
                generation,
                targets: (left, right),
            } => {
                assert_eq!(generation, 2, "coordinator should advance to generation 2");
                assert_eq!((left, right), (2, 2));
            }
            CoordinatorAction::Wait => panic!("coordinator should dispatch the pending tip"),
            CoordinatorAction::Converged { anchor, .. } => {
                panic!("coordinator should not converge with a pending tip: {anchor:?}")
            }
        }
    }

    #[test]
    fn tuple_state_sync_stops_updates_after_reached_until_regroup() {
        deterministic::Runner::default().start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(32).unwrap());
            let slow_release = Arc::new(AtomicBool::new(true));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let slow_source = SlowSyncController {
                release: slow_release.clone(),
            };
            let fast_source = FastSyncObserver {
                ready: fast_ready.clone(),
                update_count: fast_update_count.clone(),
            };
            let sync = context.child("tuple_state_sync_algorithm").spawn(
                move |context| async move {
                    <(
                        Single<ObservedSlowSyncDb>,
                        Single<ObservedFastSyncDb>,
                    ) as StateSyncSet<
                        deterministic::Context,
                        (SlowSyncController, FastSyncObserver),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_source, fast_source),
                        anchor(0),
                        (0, 0),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                },
            );

            while !fast_ready.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            for target in 1..=16u64 {
                let _ = tip_tx.send(TipUpdate::new(anchor(target), (target, target))).await;
            }
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced.0.handle().read().await.expect("writer is live").final_target;
            let fast_target = synced.1.handle().read().await.expect("writer is live").final_target;

            assert_eq!(
                slow_target, fast_target,
                "all databases should finish on the same converged target set"
            );
            assert_eq!(
                converged_anchor.height.get(), slow_target,
                "returned anchor height should match the converged generation"
            );
            assert_eq!(
                fast_update_count.load(Ordering::SeqCst),
                1,
                "a reached database must not receive tip updates before regroup; only regroup retarget should be observed"
            );
        });
    }

    #[test]
    fn tuple_state_sync_allows_noop_database_while_other_catches_up() {
        deterministic::Runner::default().start(|context| async move {
            let (tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));
            let target = 7u64;

            let sync = context.child("tuple_state_sync_noop").spawn({
                let slow_source = slow_release.clone();
                let fast_source = FastSyncObserver {
                    ready: fast_ready.clone(),
                    update_count: fast_update_count.clone(),
                };
                move |context| async move {
                    <(Single<SlowSyncDb>, Single<ObservedFastSyncDb>) as StateSyncSet<
                        deterministic::Context,
                        (Arc<AtomicBool>, FastSyncObserver),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_source, fast_source),
                        anchor(target),
                        (target, target),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                }
            });

            while !fast_ready.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            drop(tip_tx);
            slow_release.store(true, Ordering::SeqCst);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced
                .0
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            let fast_target = synced
                .1
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;

            assert_eq!(slow_target, target);
            assert_eq!(fast_target, target);
            assert_eq!(converged_anchor, anchor(target));
            assert_eq!(
                fast_update_count.load(Ordering::SeqCst),
                0,
                "already-at-target database should not receive tip updates"
            );
        });
    }

    #[test]
    fn tuple_state_sync_regroup_completes_when_database_target_is_unchanged() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let sync = context
                .child("tuple_state_sync_regroup_unchanged_target")
                .spawn({
                    let slow_source = slow_release.clone();
                    let fast_source = FastSyncObserver {
                        ready: fast_ready.clone(),
                        update_count: fast_update_count.clone(),
                    };
                    move |context| async move {
                        <(Single<SlowSyncDb>, Single<DistinctObservedFastSyncDb>) as StateSyncSet<
                            deterministic::Context,
                            (Arc<AtomicBool>, FastSyncObserver),
                            sha256::Digest,
                        >>::sync(
                            context,
                            ((), ()),
                            (slow_source, fast_source),
                            anchor(0),
                            (0, 7),
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: NZU64!(1),
                                max_outstanding_requests: 1,
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                                max_retained_roots: 0,
                            },
                        )
                        .await
                        .expect("tuple state sync should succeed")
                    }
                });

            while !fast_ready.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            let _ = tip_tx.send(TipUpdate::new(anchor(9), (9, 7))).await;
            context.sleep(Duration::from_millis(1)).await;
            slow_release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced
                .0
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;
            let fast_target = synced
                .1
                .handle()
                .read()
                .await
                .expect("writer is live")
                .final_target;

            assert_eq!(slow_target, 9);
            assert_eq!(fast_target, 7);
            assert_eq!(converged_anchor, anchor(9));
            assert_eq!(
                fast_update_count.load(Ordering::SeqCst),
                0,
                "the unchanged-target database should not receive duplicate target updates",
            );
        });
    }
}
