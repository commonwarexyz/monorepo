//! Database batch lifecycle and state sync for [`Stateful`](super::Stateful).
//!
//! `db` defines the traits a storage backend implements to be driven by
//! [`Stateful`](super::Stateful) and implements them for QMDB databases ([`any`], [`current`],
//! [`immutable`], [`keyless`]). [`p2p`] fetches and serves state sync data over the network.
//!
//! # Batch Lifecycle
//!
//! A block's state changes pass through three stages:
//! 1. [`Unmerkleized`]: a mutable batch (concrete types expose reads and writes).
//! 2. [`Merkleized`]: a sealed batch with a computed state root.
//! 3. Applied: [`ManagedDb::apply`] exposes the batch as a recoverable checkpoint.
//!    [`ManagedDb::finalize`] then starts persisting it, and a [`Barrier`] observes completion.
//!    A barrier covers the state applied before it was requested. Later batches may be applied
//!    while it is pending.
//!
//! [`DatabaseSet`] groups one or more [`ManagedDb`] instances into one unit for execution and
//! commit. [`Shared`] implements it for one database, and tuples of up to eight [`Shared`]
//! databases implement it for several.
//!
//! # State Sync
//!
//! [`StateSyncDb`] builds one database by syncing it from peers. [`StateSyncSet`] syncs every
//! database in a set to the targets carried by a finalized block, following newer tips until the
//! databases converge.
//!
//! ## Anchors
//!
//! Each set of sync targets is paired with an [`Anchor`], the finalized block that carries them. A
//! running sync handles each tip update as follows:
//!
//! - Upon a tip at or below the height of the most recently adopted anchor (initially the one
//!   passed to [`StateSyncSet::sync`]): ignore it.
//! - Upon a tip at a greater height: adopt its anchor. If its targets differ from the current
//!   targets, send them to the databases (tuple sets follow the
//!   [convergence rules](#convergence-tuple-sets)).
//! - Upon every database reporting its current target: converge, leaving queued tips unobserved.
//! - Upon every database having reached a target: hold. A holding sync refuses every later tip
//!   and finishes at the most recently adopted anchor.
//! - Upon a forced tip: end any hold and handle the tip as above. The sync holds again once every
//!   database reaches a target.
//!
//! Queued tips are coalesced: a tip superseded by a newer one before the sync dispatches it may
//! never reach the databases. [`StateSyncSet::sync`] returns an anchor whose targets every database
//! reached. Refused tips and tips delivered after convergence never reach the databases. The
//! returned anchor can trail the latest tip sent.
//!
//! ## Convergence (tuple sets)
//!
//! A tuple set assigns a _generation_ each time it dispatches a tip to its databases, and tracks
//! whether each database has reached the current generation's targets.
//!
//! - Upon dispatching a recorded tip: start a new generation and send its targets to every
//!   database whose target changed. A database that already reached an unchanged target counts
//!   as reached for the new generation.
//! - Upon every database reaching the current generation with no tip pending: finish at that
//!   generation's anchor.
//! - Upon every database having reached a target since the sync started or the last forced tip:
//!   refuse every later tip until a forced tip.
//!
//! The coordinator retains the current generation's anchor and targets and the latest recorded tip
//! not yet dispatched.
//!
//! ### Chasing a moving tip
//!
//! ```text
//! time ---------------------------------------------------------------------------->
//!
//! tips:           A0              A1              A2  A3              A4
//! generation:     g0              g1                  g2 (A2 is superseded before dispatch)
//!
//! db0 (slow):     g0 ------------ g1 ---------------- g2  reached g1 ---- reached g2
//! db1 (fast):     g0  reached g0  g1  reached g1 ---- g2  reached g2
//!
//! - A4 arrives after every database has reached a target and is refused
//! - finish at A3 once every database has reached g2
//! ```
//!
//! # Failures
//!
//! Database failures are fatal. [`DatabaseSet`] implementations panic when a database fails to
//! open, apply, finalize, or prune, and [`Barrier::durable`] panics when a deferred sync fails. A
//! mutation that is cancelled also loses its database until restart (see [`Shared`]). A database
//! that fails state sync is reported through the error returned by [`StateSyncSet::sync`].

use commonware_codec::Encode;
use commonware_consensus::{
    CertifiableBlock, Epochable, Roundable, Viewable,
    types::{Height, Round},
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{Error as RuntimeError, Handle, Metrics, Spawner, reschedule};
use commonware_storage::qmdb::sync::{self, Request, Source, source};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot, ring},
    sync::{AsyncRwLockReadGuard, AsyncRwLockWriteGuard, TracedAsyncRwLock},
};
use futures::{
    future::{Either, pending, try_join_all},
    join,
};
use std::{
    fmt::Debug,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    ops::Deref,
    sync::Arc,
};
use tracing::debug;

const MAX_CHANNEL_DRAIN_PER_TICK: usize = 32;

pub mod any;
pub mod current;
pub mod immutable;
pub mod keyless;
pub mod p2p;

/// A database shared across tasks.
///
/// By-value mutations take the database out with [`Self::write`] and restore it with
/// [`WriteSlot::put`]. A mutation that fails, panics, or is cancelled before the put leaves the
/// database _lost_: every later [`Self::read`] or [`Self::write`] panics, and only a restart
/// recovers it.
/// [`Source::serve`] on a lost database returns an error instead of panicking.
pub struct Shared<DB>(Inner<DB>);

/// The lock behind [`Shared`], for which storage implements [`Source`].
type Inner<DB> = Arc<TracedAsyncRwLock<Option<DB>>>;

impl<DB> Clone for Shared<DB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

const DB_LOST_MSG: &str =
    "database was lost by an earlier failed or interrupted operation; restart to recover";

impl<DB> Shared<DB> {
    /// Creates a shared database identified by `label` in lock traces.
    pub fn new(label: &'static str, db: DB) -> Self {
        Self(Arc::new(TracedAsyncRwLock::new(label, Some(db))))
    }

    /// Acquires shared read access to the database.
    ///
    /// The lock is write-preferring: once a writer is queued, new readers wait
    /// behind it. Holding a guard across an await that acquires this cell
    /// again therefore deadlocks once a writer arrives in between.
    ///
    /// # Panics
    ///
    /// Panics if the database was lost by an earlier failed or interrupted mutation.
    pub async fn read(&self) -> ReadGuard<'_, DB> {
        ReadGuard(AsyncRwLockReadGuard::map(self.0.read().await, |db| {
            db.as_ref().expect(DB_LOST_MSG)
        }))
    }

    /// Takes the database out for a by-value mutation.
    ///
    /// The returned [`WriteSlot`] holds the cell locked and empty until
    /// [`WriteSlot::put`] restores the database. Dropping the slot without a put
    /// leaves the database lost.
    ///
    /// # Panics
    ///
    /// Panics if the database was lost by an earlier failed or interrupted mutation.
    pub async fn write(&self) -> (WriteSlot<'_, DB>, DB) {
        let mut guard = self.0.write().await;
        let db = guard.take().expect(DB_LOST_MSG);
        (WriteSlot(guard), db)
    }

    async fn read_locked(&self) -> ReadLocked<'_, DB> {
        ReadLocked {
            database: self.0.read().await,
            shared: self,
        }
    }

    #[cfg(test)]
    async fn new_batch_for_test<E>(&self) -> <DB as ManagedDb<E>>::Unmerkleized
    where
        DB: ManagedDb<E>,
    {
        let database = self.read_locked().await;
        DB::new_batch(database.batch_context())
    }
}

/// Read-only access to a database managed by [`Stateful`](super::Stateful).
///
/// Unlike [`Shared`], this handle cannot acquire a write slot, construct or
/// apply batches, finalize database state, or prune. Applications receive readers in
/// [`Application::capture`](super::Application::capture) and
/// [`Application::finalized`](super::Application::finalized) so observing
/// finalized state cannot invalidate concurrent speculative batches.
///
/// ```compile_fail
/// use commonware_glue::stateful::db::Reader;
///
/// async fn mutate<DB>(reader: Reader<DB>) {
///     let _ = reader.write().await;
/// }
/// ```
pub struct Reader<DB>(Shared<DB>);

impl<DB> Reader<DB> {
    /// Acquires shared read access to the database.
    ///
    /// The guard follows the same write-preferring lock discipline as
    /// [`Shared::read`].
    ///
    /// # Panics
    ///
    /// Panics if the database was lost by an earlier failed or interrupted mutation.
    pub async fn read(&self) -> ReadGuard<'_, DB> {
        self.0.read().await
    }
}

/// Shared read access to a [`Shared`] database.
pub struct ReadGuard<'a, DB>(AsyncRwLockReadGuard<'a, DB>);

impl<DB> Deref for ReadGuard<'_, DB> {
    type Target = DB;

    fn deref(&self) -> &DB {
        &self.0
    }
}

/// An exclusively locked [`Shared`] cell whose database has been taken out.
pub struct WriteSlot<'a, DB>(AsyncRwLockWriteGuard<'a, Option<DB>>);

impl<DB> WriteSlot<'_, DB> {
    /// Restores the database and releases the write lock.
    pub fn put(mut self, db: DB) {
        *self.0 = Some(db);
    }
}

/// Origin-bound read access used to construct a database batch.
struct ReadLocked<'a, DB> {
    database: AsyncRwLockReadGuard<'a, Option<DB>>,
    shared: &'a Shared<DB>,
}

impl<DB> ReadLocked<'_, DB> {
    fn batch_context(&self) -> BatchContext<'_, DB> {
        BatchContext {
            database: self.database.as_ref().expect(DB_LOST_MSG),
            shared: Shared::clone(self.shared),
        }
    }
}

/// Origin-bound database access for synchronous batch construction.
///
/// Only the [`DatabaseSet`] implementations in this module construct it. Its borrow prevents a
/// [`ManagedDb`] implementation from retaining the set's read lock in the returned batch.
pub struct BatchContext<'a, DB> {
    database: &'a DB,
    shared: Shared<DB>,
}

impl<'a, DB> BatchContext<'a, DB> {
    /// Splits the capability into the read-locked database and its [`Shared`] handle.
    pub fn into_parts(self) -> (&'a DB, Shared<DB>) {
        (self.database, self.shared)
    }
}

impl<DB> Source for Shared<DB>
where
    DB: Send + Sync + 'static,
    Inner<DB>: Source,
{
    type Family = <Inner<DB> as Source>::Family;
    type Digest = <Inner<DB> as Source>::Digest;
    type Op = <Inner<DB> as Source>::Op;
    type Error = <Inner<DB> as Source>::Error;

    fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> impl Future<Output = source::Result<Self>> + Send {
        self.0.serve(request)
    }
}

/// A batch of speculative mutations that has not been merkleized.
///
/// Concrete types expose reads and writes (`get`, `write`, `set`, `append`, and so on) as
/// inherent methods.
pub trait Unmerkleized: Sized + Send {
    /// The sealed batch returned by [`Self::merkleize`].
    type Merkleized: Merkleized;

    /// Error returned by [`Self::merkleize`].
    type Error: Send;

    /// Computes the state root over every mutation and seals the batch.
    fn merkleize(self) -> impl Future<Output = Result<Self::Merkleized, Self::Error>> + Send;
}

/// A sealed batch with a computed state root.
pub trait Merkleized: Sized + Send + Sync {
    /// Digest type of the state root returned by [`Self::root`].
    type Digest: Digest;

    /// The child batch returned by [`Self::new_batch`].
    type Unmerkleized: Unmerkleized;

    /// Returns the state root of the database with this batch applied.
    fn root(&self) -> Self::Digest;

    /// Creates a child batch whose reads see this batch's pending changes before the applied
    /// database state.
    fn new_batch(&self) -> Self::Unmerkleized;
}

/// A database whose batches [`Stateful`](super::Stateful) builds, applies, persists, and prunes.
///
/// Applying a batch and persisting it are separate steps: [`Self::apply`] exposes a batch as a
/// recoverable checkpoint, and [`Self::finalize`] starts making applied checkpoints durable.
///
/// # Ownership
///
/// Mutating methods take the database by value and return it on success. If a mutating method
/// returns an error or its future is dropped, the instance is lost. Durable state remains
/// recoverable on restart. State that was not yet durable may or may not be recovered.
pub trait ManagedDb<E>: Send + Sync + Sized {
    /// A batch of mutations that has not been merkleized.
    type Unmerkleized: Unmerkleized;

    /// A merkleized batch that has not been applied.
    ///
    /// Cloning must preserve the same sealed branch state and should be cheap.
    type Merkleized: Clone + Merkleized<Unmerkleized = Self::Unmerkleized>;

    /// Error returned by [`Self::apply`], [`Self::finalize`], and [`Self::prune`], and carried by
    /// [`InitError::Database`] from [`Self::init`].
    type Error: Debug + Send;

    /// Configuration passed to [`Self::init`].
    type Config: Send;

    /// Recovery and state sync target for this database.
    ///
    /// Typically a database-specific state commitment plus the operation range needed to reach it.
    type SyncTarget: Clone + Debug + PartialEq + Send + Sync;

    /// Opens the database at `expected`, or at its latest checkpoint when `expected` is `None`.
    ///
    /// State beyond the selected checkpoint must be durably discarded before this returns.
    /// Returns [`InitError::TargetMismatch`] if the recovered target is not `expected`.
    fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> impl Future<Output = Result<Self, InitError<Self::Error, Self::SyncTarget>>> + Send;

    /// Returns the sync target of a new, empty database.
    ///
    /// It must equal [`Self::sync_target`] after [`Self::init`] opens an empty partition.
    fn initial_sync_target() -> Self::SyncTarget;

    /// Creates a batch over the applied state of `database`.
    ///
    /// The batch may keep the [`Shared`] handle from [`BatchContext::into_parts`] for later reads.
    /// It cannot keep the borrowed database, so the batch never holds the set's read lock.
    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized;

    /// Returns whether applying `batch` yields a database whose [`Self::sync_target`] is
    /// `target`.
    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool;

    /// Applies `batch` to the database.
    ///
    /// The returned database must expose `batch` as an independently recoverable checkpoint. The
    /// checkpoint need not be durable until the handle returned by [`Self::finalize`] resolves.
    fn apply(
        self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Starts persisting every checkpoint applied before this call.
    ///
    /// The returned handle resolves once that state is durable. Batches applied while it is
    /// pending are not covered and need a later finalization. Callers must await the handle before
    /// finalizing again.
    fn finalize(self) -> impl Future<Output = Result<(Self, Handle<()>), Self::Error>> + Send;

    /// Prunes the database to a previously finalized sync target.
    ///
    /// Callers must await every handle returned by [`Self::finalize`] before pruning. Pruning
    /// effects must be durable before this returns. The default implementation does nothing, for
    /// databases without prunable history.
    fn prune(
        self,
        _target: &Self::SyncTarget,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send {
        async { Ok(self) }
    }

    /// Returns the target of the latest applied checkpoint (which need not be durable yet).
    fn sync_target(&self) -> Self::SyncTarget;
}

/// A durability barrier returned by [`DatabaseSet::finalize`].
///
/// Deferred sync failures surface only through [`Self::durable`], so every barrier must be
/// awaited. A barrier must resolve before [`DatabaseSet::prune`] runs.
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
#[must_use = "await `durable` to surface deferred sync failures"]
pub struct Barrier {
    syncs: Vec<(&'static str, Option<usize>, Handle<()>)>,
}

impl Barrier {
    /// Builds a barrier from deferred sync handles owned by `T`.
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

    /// Resolves `true` once every deferred sync completes, or `false` if runtime shutdown aborts
    /// or closes a sync handle.
    ///
    /// # Panics
    ///
    /// Panics if a sync fails, because the database has already advanced past the state that
    /// failed to persist.
    pub async fn durable(self) -> bool {
        let syncs = self
            .syncs
            .into_iter()
            .map(|(db_type, index, handle)| async move {
                match handle.await {
                    Ok(()) => Ok(true),
                    Err(RuntimeError::Closed | RuntimeError::Aborted) => {
                        debug!(db_type, "runtime shutdown before database sync completed");
                        Ok(false)
                    }
                    Err(err) => Err((db_type, index, err)),
                }
            });

        match try_join_all(syncs).await {
            Ok(results) => results.into_iter().all(|durable| durable),
            Err((db_type, index, err)) => {
                let index = index.map_or(String::new(), |i| format!("index {i}, "));
                panic!("database sync failed ({index}type {db_type}): {err}");
            }
        }
    }
}

/// A group of [`ManagedDb`] instances executed and committed as one unit.
///
/// Read access may span several members at once, so a mutation must not hold one member's write
/// access while waiting for another's.
///
/// # Mutation Safety
///
/// Calls to [`Self::apply`], [`Self::finalize`], and [`Self::prune`] must not overlap.
/// Implementations panic if a database mutation fails (see
/// [Failures](crate::stateful::db#failures)).
pub trait DatabaseSet<E>: Clone + Send + Sync + 'static {
    /// One [`ManagedDb::Unmerkleized`] per database in the set.
    type Unmerkleized: Send;

    /// One [`ManagedDb::Merkleized`] per database in the set.
    ///
    /// Cloning must preserve the same sealed branch state and should be cheap.
    type Merkleized: Clone + Send + Sync;

    /// Read-only handles for observing the applied database state.
    ///
    /// Implementations must not expose mutation capabilities through this
    /// type. In particular, readers must not construct or apply batches,
    /// finalize database state, or prune.
    type Readers: Send;

    /// Configuration needed to construct every database in the set.
    ///
    /// - Single database sets use that database's [`ManagedDb::Config`].
    /// - Multi-database tuple sets use a tuple of per-database configs
    ///   `(Db1::Config, Db2::Config, ...)`.
    type Config: Send;

    /// Per-database sync targets carried by a finalized block.
    ///
    /// For a single-database set this is one target. For multi-database sets it is a tuple of
    /// targets, one per database.
    type SyncTargets: Clone + PartialEq + Send + Sync;

    /// Opens every database in the set, each at its target in `expected` when supplied.
    ///
    /// # Panics
    ///
    /// Panics if a database fails to open, including when it does not match its expected target.
    fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTargets>,
    ) -> impl Future<Output = Self> + Send;

    /// Returns the sync targets of a new, empty set.
    fn initial_sync_targets() -> Self::SyncTargets;

    /// Creates a batch over each database's applied state.
    ///
    /// Implementations must release every read lock before returning.
    fn new_batches(&self) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Creates child batches of a pending merkleized parent.
    ///
    /// Construction takes no lock. Reads see `parent`'s pending changes before falling back to the
    /// applied state.
    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized;

    /// Returns whether applying `batches` yields `targets` (see
    /// [`ManagedDb::matches_sync_target`]).
    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool;

    /// Returns read-only handles for every database in the set.
    fn readers(&self) -> Self::Readers;

    /// Applies each batch to its database.
    ///
    /// Returns once every database exposes its batch as an independently recoverable checkpoint.
    /// Durability starts separately with [`Self::finalize`].
    fn apply(&self, batches: Self::Merkleized) -> impl Future<Output = ()> + Send;

    /// Starts persisting every checkpoint applied before this call.
    ///
    /// The returned [`Barrier`] resolves once that state is durable in every database. Batches
    /// applied while it is pending are not covered and need a later finalization. The barrier
    /// must be awaited before finalizing again.
    fn finalize(&self) -> impl Future<Output = Barrier> + Send;

    /// Prunes each database to its target in `targets`.
    ///
    /// The state represented by `targets` must already be durable, and no barrier may be pending.
    /// Pruning effects must be durable before this returns.
    fn prune(&self, targets: &Self::SyncTargets) -> impl Future<Output = ()> + Send;

    /// Returns the targets of the latest applied checkpoints (which need not be durable yet).
    fn committed_targets(&self) -> impl Future<Output = Self::SyncTargets> + Send;
}

/// Parameters for a one-time state-sync pass.
#[derive(Clone, Copy, Debug)]
pub struct SyncEngineConfig {
    /// Maximum operations fetched per source request.
    ///
    /// Peers ignore requests larger than their `max_serve_ops` (see [`p2p::Config`]), so a larger
    /// value stalls sync. Keep this at or below the `max_serve_ops` every peer uses.
    pub fetch_batch_size: NonZeroU64,

    /// Number of operations applied per local apply step.
    pub apply_batch_size: NonZeroU64,

    /// Maximum number of outstanding requests for operations. Requests for pinned nodes are
    /// outstanding beyond it: one for the current target and, while target updates are deferred,
    /// up to two for deferred targets.
    pub max_outstanding_requests: NonZeroUsize,

    /// Capacity of per-database target-update channels.
    pub update_channel_size: NonZeroUsize,
}

/// A [`ManagedDb`] that can be built by syncing it from peers.
pub trait StateSyncDb<E, R>: ManagedDb<E> {
    /// Error returned by [`Self::sync_db`].
    type SyncError: Debug + Send;

    /// Syncs a new database from `source` to `target` and returns it.
    ///
    /// Implementations must follow these rules:
    /// - Adopt a target from `tip_updates` only if it advances the current target.
    /// - When `finish` is `Some`, complete only once it has signaled and the current target is
    ///   reached. When `finish` is `None`, complete as soon as the current target is reached.
    /// - When `reached_target` is `Some`, report each reached target on it at most once, before
    ///   adopting a newer target. A report may wait for channel capacity, so callers must drain
    ///   the receiver.
    /// - Keep receiving from `tip_updates` until completing, pausing only while a report waits for
    ///   `reached_target` capacity. Callers may wait for capacity to send a target.
    #[allow(clippy::too_many_arguments)]
    fn sync_db(
        context: E,
        config: Self::Config,
        source: R,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send;
}

/// The finalized block that carries a set of sync targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor<D: Digest> {
    /// Height of the block.
    pub height: Height,
    /// Consensus round of the block.
    pub round: Round,
    /// Digest of the block.
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

/// A finalized tip delivered to a running [`StateSyncSet::sync`].
///
/// See [Anchors](crate::stateful::db#anchors) for how a sync handles each update.
pub struct TipUpdate<D: Digest, T> {
    anchor: Anchor<D>,
    targets: T,
    forced: bool,
    observed: Option<oneshot::Sender<Observation>>,
}

/// How a running sync handled a [`TipUpdate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// The sync recorded the update, whether or not it adopted its targets.
    Recorded,
    /// The sync refused the update. It finishes at an earlier recorded tip, unless a later forced
    /// update is recorded first.
    Refused,
}

impl<D: Digest, T> TipUpdate<D, T> {
    /// Creates an update for the block identified by `anchor`, which carries `targets`.
    pub const fn new(anchor: Anchor<D>, targets: T) -> Self {
        Self {
            anchor,
            targets,
            forced: false,
            observed: None,
        }
    }

    /// Creates an update and a receiver that resolves with how a sync handled it.
    ///
    /// The receiver errors if the update is dropped unhandled.
    pub(crate) fn with_observation(
        anchor: Anchor<D>,
        targets: T,
    ) -> (Self, oneshot::Receiver<Observation>) {
        let (observed, receiver) = oneshot::channel();
        (
            Self {
                anchor,
                targets,
                forced: false,
                observed: Some(observed),
            },
            receiver,
        )
    }

    /// Creates an update that a holding sync records instead of refusing, which releases the
    /// hold, and a receiver that resolves with how the sync handled it.
    ///
    /// The receiver errors if the update is dropped unhandled.
    pub(crate) fn forced_with_observation(
        anchor: Anchor<D>,
        targets: T,
    ) -> (Self, oneshot::Receiver<Observation>) {
        let (mut update, receiver) = Self::with_observation(anchor, targets);
        update.forced = true;
        (update, receiver)
    }

    /// Returns whether the update releases a holding sync.
    pub(crate) const fn forced(&self) -> bool {
        self.forced
    }

    /// Passes the update to `record`, then resolves its observer.
    pub(crate) fn record<R>(self, record: impl FnOnce(Anchor<D>, T) -> R) -> R {
        let result = record(self.anchor, self.targets);
        if let Some(observed) = self.observed {
            let _ = observed.send(Observation::Recorded);
        }
        result
    }

    /// Resolves the observer without recording the update.
    pub(crate) fn refuse(self) {
        if let Some(observed) = self.observed {
            let _ = observed.send(Observation::Refused);
        }
    }
}

/// A [`DatabaseSet`] that can be built by one-time state sync.
///
/// `D` is the block digest type of each [`Anchor`].
pub trait StateSyncSet<E, R, D>: DatabaseSet<E>
where
    D: Digest,
{
    /// Error returned if any database in the set fails state sync.
    type Error: Debug + Send;

    /// Syncs every database from `sources` to `targets`, carried by `anchor`, and returns the
    /// synced set with an anchor whose targets every database reached.
    ///
    /// Updates on `tip_updates` follow the [module rules](crate::stateful::db#anchors). The
    /// returned anchor, not the latest tip delivered, identifies the synced state.
    #[allow(clippy::too_many_arguments)]
    fn sync(
        context: E,
        config: Self::Config,
        sources: R,
        anchor: Anchor<D>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<D, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<(Self, Anchor<D>), Self::Error>> + Send;
}

/// An error opening a [`ManagedDb`].
#[derive(Debug, thiserror::Error)]
pub enum InitError<E: Debug, T: Debug> {
    /// The database failed to open or recover.
    #[error("database initialization failed: {0:?}")]
    Database(E),
    /// The opened database's [`ManagedDb::sync_target`] is not the expected target.
    #[error("database target mismatch: expected {expected:?}, recovered {recovered:?}")]
    TargetMismatch {
        /// The target requested by the caller.
        expected: T,
        /// The target recovered from storage.
        recovered: T,
    },
}

/// Validates the requested sync target before returning the database.
fn validate_initialization<E, T>(
    db: T,
    expected: Option<T::SyncTarget>,
) -> Result<T, InitError<T::Error, T::SyncTarget>>
where
    T: ManagedDb<E>,
{
    let Some(expected) = expected else {
        return Ok(db);
    };
    let recovered = db.sync_target();
    if recovered != expected {
        return Err(InitError::TargetMismatch {
            expected,
            recovered,
        });
    }
    Ok(db)
}

impl<E: Send + Sync, T: ManagedDb<E> + 'static> DatabaseSet<E> for Shared<T> {
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;
    type Readers = Reader<T>;
    type Config = T::Config;
    type SyncTargets = T::SyncTarget;

    async fn init(context: E, config: Self::Config, expected: Option<Self::SyncTargets>) -> Self {
        let db = T::init(context, config, expected)
            .await
            .expect("database init failed");
        Self::new("stateful.db", db)
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        T::initial_sync_target()
    }

    async fn new_batches(&self) -> Self::Unmerkleized {
        let database = self.read_locked().await;
        T::new_batch(database.batch_context())
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        parent.new_batch()
    }

    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
        T::matches_sync_target(batches, targets)
    }

    fn readers(&self) -> Self::Readers {
        Reader(self.clone())
    }

    async fn apply(&self, batches: Self::Merkleized) {
        apply_shared::<E, T>(self, batches, None).await;
    }

    async fn finalize(&self) -> Barrier {
        let handle = finalize_shared::<E, T>(self, None).await;
        Barrier {
            syncs: vec![(core::any::type_name::<T>(), None, handle)],
        }
    }

    async fn prune(&self, target: &Self::SyncTargets) {
        prune_shared::<E, T>(self, target, None).await;
    }

    async fn committed_targets(&self) -> Self::SyncTargets {
        let database = self.read().await;
        T::sync_target(&database)
    }
}

impl<E, T, R, D> StateSyncSet<E, R, D> for Shared<T>
where
    E: Metrics,
    T: StateSyncDb<E, R> + 'static,
    R: Send + 'static,
    D: Digest,
{
    type Error = T::SyncError;

    #[allow(clippy::too_many_arguments)]
    async fn sync(
        context: E,
        config: Self::Config,
        source: R,
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
            let mut held = false;
            // The newest recorded target not yet sent to the database. It waits for channel
            // capacity alongside reached reports, so the database never waits to report while the
            // coordinator waits to send it a target.
            let mut unsent = None;
            loop {
                let update_future = tip_updates.as_mut().map_or_else(
                    || Either::Right(pending()),
                    |updates| Either::Left(updates.recv()),
                );
                let send_future = if unsent.is_some() {
                    Either::Left(target_tx.reserve())
                } else {
                    Either::Right(pending())
                };
                select! {
                    reached = reached_rx.recv() => {
                        let Some(reached) = reached else {
                            return (current_anchor, current_target);
                        };
                        // A report of the newest recorded target converges, leaving queued tips
                        // unhandled, so a queued forced tip cannot discard a finished sync.
                        if reached == current_target {
                            let _ = finish_tx.send_lossy(()).await;
                            return (current_anchor, current_target);
                        }
                        // Once the database reaches an earlier target, the sync refuses every
                        // later tip, including those already queued, until a forced update
                        // releases it.
                        held = true;
                    },
                    update = update_future => {
                        let Some(update) = update else {
                            tip_updates = None;
                            continue;
                        };
                        if update.forced() {
                            held = false;
                        }
                        if held {
                            update.refuse();
                            continue;
                        }
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
                        if target.is_some() {
                            unsent = target;
                        }
                    },
                    permit = send_future => {
                        let Ok(permit) = permit else {
                            return (current_anchor, current_target);
                        };
                        permit.send(unsent.take().expect("a send waits only for an unsent target"));
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
        Ok((Self::new("stateful.db", database), converged_anchor))
    }
}

macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<E: Send + Sync + Metrics, $($T: ManagedDb<E> + 'static),+> DatabaseSet<E>
            for ($(Shared<$T>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);
            type Readers = ($(Reader<$T>,)+);
            type Config = ($($T::Config,)+);
            type SyncTargets = ($($T::SyncTarget,)+);

            async fn init(
                context: E,
                config: Self::Config,
                expected: Option<Self::SyncTargets>,
            ) -> Self {
                let result = join!($(
                    async {
                        let db = $T::init(
                                context.child(concat!("db_", stringify!($idx))),
                                config.$idx,
                                expected.as_ref().map(|targets| targets.$idx.clone()),
                            )
                            .await
                            .expect(concat!(
                                "database init failed (index ",
                                stringify!($idx),
                                ", type ",
                                stringify!($T),
                                ")",
                            ));
                        Shared::new(concat!("stateful.db.", stringify!($idx)), db)
                    },
                )+);
                result
            }

            fn initial_sync_targets() -> Self::SyncTargets {
                ($($T::initial_sync_target(),)+)
            }

            async fn new_batches(&self) -> Self::Unmerkleized {
                let databases = join!($(self.$idx.read_locked(),)+);
                ($($T::new_batch(databases.$idx.batch_context()),)+)
            }

            fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
                ($(parent.$idx.new_batch(),)+)
            }

            fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
                $($T::matches_sync_target(&batches.$idx, &targets.$idx))&&+
            }

            fn readers(&self) -> Self::Readers {
                ($(Reader(self.$idx.clone()),)+)
            }

            async fn apply(
                &self,
                batches: Self::Merkleized,
            ) {
                // Each member completes its own write-lock lifecycle. Holding
                // a partial tuple of writers can deadlock cross-database reads.
                join!($(apply_shared::<E, $T>(
                    &self.$idx,
                    batches.$idx,
                    Some($idx),
                ),)+);
            }

            async fn finalize(&self) -> Barrier {
                let handles = join!($(finalize_shared::<E, $T>(
                    &self.$idx,
                    Some($idx),
                ),)+);
                Barrier {
                    syncs: vec![$((
                        core::any::type_name::<$T>(),
                        Some($idx),
                        handles.$idx,
                    ),)+],
                }
            }

            async fn prune(
                &self,
                targets: &Self::SyncTargets,
            ) {
                join!($(prune_shared::<E, $T>(
                    &self.$idx,
                    &targets.$idx,
                    Some($idx),
                ),)+);
            }

            async fn committed_targets(&self) -> Self::SyncTargets {
                let databases = join!($(self.$idx.read(),)+);
                ($($T::sync_target(&databases.$idx),)+)
            }

        }
    };
}

impl_database_set!(DB1: 0);
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

/// A database's report that it reached a sync target.
///
/// Coalescing keeps the greatest report. A generation report also counts toward the hold, and
/// only a report of the current generation, the highest, counts as reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Reached {
    /// The database reached a target older than its current one.
    Earlier,
    /// The database reached the target of this generation.
    Generation(usize),
}

/// Per-database reached reports not yet taken by the tuple coordinator.
type ReachedReports = Arc<commonware_utils::sync::Mutex<Vec<Option<Reached>>>>;

/// Records reached reports for the tuple coordinator without waiting for it.
#[derive(Clone)]
struct ReachedSender {
    reports: ReachedReports,
    wake: mpsc::Sender<()>,
}

impl ReachedSender {
    /// Records that database `idx` reached a target, keeping its greatest untaken report, and
    /// wakes the coordinator.
    ///
    /// Returns `false` if the coordinator stopped.
    fn send(&self, idx: usize, report: Reached) -> bool {
        {
            let mut reports = self.reports.lock();
            reports[idx] = reports[idx].max(Some(report));
        }
        !matches!(
            self.wake.try_send(()),
            Err(mpsc::error::TrySendError::Closed(()))
        )
    }
}

/// Takes the reached reports recorded by [`ReachedSender`]s.
struct ReachedReceiver {
    reports: ReachedReports,
    wake: mpsc::Receiver<()>,
}

impl ReachedReceiver {
    /// Takes every report recorded since the last call, in database order.
    fn take(&self) -> Vec<(usize, Reached)> {
        self.reports
            .lock()
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, report)| report.take().map(|report| (idx, report)))
            .collect()
    }

    /// Waits until a report may have been recorded. Returns `false` once every sender is dropped.
    async fn wait(&mut self) -> bool {
        self.wake.recv().await.is_some()
    }
}

/// Creates a reached report channel for `db_count` databases.
fn reached_channel(db_count: usize) -> (ReachedSender, ReachedReceiver) {
    let reports: ReachedReports =
        Arc::new(commonware_utils::sync::Mutex::new(vec![None; db_count]));
    let (wake_tx, wake_rx) = mpsc::channel(1);
    (
        ReachedSender {
            reports: reports.clone(),
            wake: wake_tx,
        },
        ReachedReceiver {
            reports,
            wake: wake_rx,
        },
    )
}

struct CoordinatorSyncSenders<T> {
    target_tx: mpsc::Sender<T>,
    finish_tx: mpsc::Sender<()>,
    generation_tx: mpsc::Sender<(usize, T)>,
}

macro_rules! impl_state_sync_set {
    ($($T:ident : $R:ident : $idx:tt),+) => {
        impl<E, D, $($T, $R),+> StateSyncSet<E, ($($R,)+), D> for ($(Shared<$T>,)+)
        where
            E: Send + Sync + Spawner + Metrics + 'static,
            D: Digest + 'static,
            $(
                $T: StateSyncDb<E, $R> + 'static,
                $R: Send + 'static,
            )+
        {
            type Error = String;

            #[allow(clippy::too_many_arguments)]
            async fn sync(
                context: E,
                config: Self::Config,
                sources: ($($R,)+),
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
                        target_tx: db_channels.$idx.target_tx.clone(),
                        finish_tx: db_channels.$idx.finish_tx.clone(),
                        generation_tx: db_channels.$idx.generation_tx.clone(),
                    },
                )+);
                let coordinator_owned_senders = ($(
                    CoordinatorSyncSenders {
                        target_tx: db_channels.$idx.target_tx,
                        finish_tx: db_channels.$idx.finish_tx,
                        generation_tx: db_channels.$idx.generation_tx,
                    },
                )+);
                let db_count = [$($idx,)+].len();
                let (reached_event_tx, mut reached_event_rx) = reached_channel(db_count);
                let (completion_tx, mut completion_rx) = mpsc::channel(1);
                let coordinator_targets = targets.clone();
                let initial_targets = targets.clone();
                let first_db_error: Arc<commonware_utils::sync::Mutex<Option<String>>> =
                    Arc::new(commonware_utils::sync::Mutex::new(None));

                // The coordinator applies the convergence rules and dispatches each generation.
                let coordinator_handle = context.child("coordinator").spawn({
                    move |_context| async move {
                        let coordinator_owned_senders = coordinator_owned_senders;
                        let mut tip_updates = Some(tip_updates);
                        let mut state = CoordinatorState::new(db_count, anchor, coordinator_targets);
                        let mut last_dispatched_targets = initial_targets;

                        loop {
                            for (idx, report) in reached_event_rx.take() {
                                state.record_reached(idx, report);
                            }

                            // Convergence is checked before queued tips are handled, so a queued
                            // forced tip cannot discard a finished sync.
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
                                    // These sends wait only while a database task is busy. Each
                                    // task keeps taking generation updates, and each database
                                    // keeps taking targets as `StateSyncDb::sync_db` requires,
                                    // since its reached reports go to a task that never waits on
                                    // this coordinator.
                                    $(
                                        let dispatch_target = dispatch_targets.$idx.clone();
                                        if !coordinator_senders.$idx
                                            .generation_tx
                                            .send_lossy((generation, dispatch_target.clone()))
                                            .await
                                        {
                                            return None;
                                        }
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
                                    )+
                                    continue;
                                }
                                CoordinatorAction::Wait => {}
                            }

                            // Once every database reaches a target, the set refuses every later
                            // tip until a forced one ends the hold.
                            let mut drained = 0usize;
                            if let Some(updates) = tip_updates.as_mut() {
                                loop {
                                    match updates.try_recv() {
                                        Ok(update) => {
                                            drained += 1;
                                            state.handle_tip(update);
                                            if drained.is_multiple_of(MAX_CHANNEL_DRAIN_PER_TICK) {
                                                reschedule().await;
                                            }
                                        }
                                        Err(ring::TryRecvError::Empty) => break,
                                        Err(ring::TryRecvError::Disconnected) => {
                                            tip_updates = None;
                                            break;
                                        }
                                    }
                                }
                            }
                            if drained > 0 {
                                continue;
                            }

                            let update_future = tip_updates.as_mut().map_or_else(
                                || Either::Right(pending()),
                                |updates| Either::Left(updates.recv()),
                            );
                            select! {
                                woken = reached_event_rx.wait() => {
                                    if !woken {
                                        return None;
                                    }
                                },
                                _ = completion_rx.recv() => {
                                    drop(coordinator_owned_senders);
                                    return None;
                                },
                                update = update_future => {
                                    let Some(update) = update else {
                                        tip_updates = None;
                                        continue;
                                    };
                                    state.handle_tip(update);
                                },
                            };
                        }
                    }
                });

                // Each database task runs its sync and reports each target it reaches, and each
                // new generation whose target it already reached.
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

                                                // A target of an earlier generation counts only
                                                // toward the hold.
                                                if reached_target != current_target {
                                                    if !reached_event_sender
                                                        .send($idx, Reached::Earlier)
                                                    {
                                                        return;
                                                    }
                                                    continue;
                                                }

                                                if last_reported_generation != Some(current_generation) {
                                                    if !reached_event_sender.send(
                                                        $idx,
                                                        Reached::Generation(current_generation),
                                                    ) {
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
                                                    if !reached_event_sender.send(
                                                        $idx,
                                                        Reached::Generation(current_generation),
                                                    ) {
                                                        return;
                                                    }
                                                    last_reported_generation = Some(current_generation);
                                                }
                                            },
                                        };
                                    }
                                };
                                let (sync_result, _) = join!(sync, forward_reached);
                                let result = sync_result
                                    .map(|database| {
                                        Shared::new(
                                            concat!("stateful.db.", stringify!($idx)),
                                            database,
                                        )
                                    })
                                    .map_err(|err| {
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
                drop(reached_event_tx);

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

                let synced = ($(synced.$idx?,)+);
                let Some((converged_anchor, converged_targets)) = converged_anchor else {
                    return Err("state sync coordinator did not report a converged anchor".into());
                };
                let committed_targets =
                    <Self as DatabaseSet<E>>::committed_targets(&synced).await;
                if committed_targets != converged_targets {
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

impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3, DB5: R5: 4);
impl_state_sync_set!(DB1: R1: 0, DB2: R2: 1, DB3: R3: 2, DB4: R4: 3, DB5: R5: 4, DB6: R6: 5);
impl_state_sync_set!(
    DB1: R1: 0,
    DB2: R2: 1,
    DB3: R3: 2,
    DB4: R4: 3,
    DB5: R5: 4,
    DB6: R6: 5,
    DB7: R7: 6
);
impl_state_sync_set!(
    DB1: R1: 0,
    DB2: R2: 1,
    DB3: R3: 2,
    DB4: R4: 3,
    DB5: R5: 4,
    DB6: R6: 5,
    DB7: R7: 6,
    DB8: R8: 7
);

/// Applies the queued generation assignments for database `idx`, reporting each one whose target
/// the database has already reached.
async fn drain_generation_updates<T>(
    generation_rx: &mut Option<mpsc::Receiver<(usize, T)>>,
    current_generation: &mut usize,
    current_target: &mut T,
    last_reached_target: &Option<T>,
    last_reported_generation: &mut Option<usize>,
    reached_event_sender: &ReachedSender,
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
                        if !reached_event_sender.send(idx, Reached::Generation(*current_generation))
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

/// What the coordinator should do after processing events.
enum CoordinatorAction<D: Digest, T> {
    /// Nothing to do until the next event.
    Wait,
    /// Dispatch `targets` as `generation` to every database.
    Dispatch { generation: usize, targets: T },
    /// Every database reached the targets of one generation, carried by `anchor`.
    Converged { anchor: Anchor<D>, targets: T },
}

/// State machine for tuple-set sync convergence (see the
/// [module docs](crate::stateful::db#convergence-tuple-sets)).
///
/// Tracks whether each database has reached the current generation and whether it has reached a
/// target of any generation. Holds the current generation's anchor and targets and the latest
/// recorded tip not yet dispatched. Decides when to dispatch or finish.
struct CoordinatorState<D: Digest, T> {
    /// Whether each database reached the current generation's targets.
    reached: Vec<bool>,
    /// Whether each database has reached a target of any generation since the last release.
    reported: Vec<bool>,
    /// The current generation, which increments on each dispatch.
    generation: usize,
    /// Anchor and targets of the current generation.
    current: (Anchor<D>, T),
    /// Anchor and targets of the latest recorded tip, pending dispatch as the next generation.
    latest_tip: Option<(Anchor<D>, T)>,
}

impl<D: Digest, T: Clone> CoordinatorState<D, T> {
    fn new(db_count: usize, anchor: Anchor<D>, targets: T) -> Self {
        Self {
            reached: vec![false; db_count],
            reported: vec![false; db_count],
            generation: 0,
            current: (anchor, targets),
            latest_tip: None,
        }
    }

    /// Records that database `idx` reached a target.
    ///
    /// Reached events can arrive late. An event for an earlier generation counts only toward the
    /// hold.
    fn record_reached(&mut self, idx: usize, report: Reached) {
        self.reported[idx] = true;
        if report == Reached::Generation(self.generation) {
            self.reached[idx] = true;
        }
    }

    /// Returns whether every database has reached a target of any generation since the last
    /// release.
    ///
    /// A holding coordinator refuses every later tip until [`Self::release`].
    fn held(&self) -> bool {
        self.reported.iter().all(|reported| *reported)
    }

    /// Ends a hold. The coordinator holds again once every database reports reaching a target
    /// again.
    fn release(&mut self) {
        self.reported.fill(false);
    }

    /// Handles a tip update. A forced tip ends any hold. A holding coordinator refuses the tip,
    /// and otherwise records it.
    fn handle_tip(&mut self, update: TipUpdate<D, T>) {
        if update.forced() {
            self.release();
        }
        if self.held() {
            update.refuse();
        } else {
            update.record(|anchor, targets| self.record_tip_update(anchor, targets));
        }
    }

    /// Records a tip as the pending dispatch, replacing any earlier pending tip.
    ///
    /// A tip at or below the height of the pending or current anchor is ignored. Targets are not
    /// compared.
    fn record_tip_update(&mut self, anchor: Anchor<D>, targets: T) {
        let current_height = self
            .latest_tip
            .as_ref()
            .map_or(self.current.0.height, |(latest_anchor, _)| {
                latest_anchor.height
            });
        if anchor.height <= current_height {
            return;
        }
        self.latest_tip = Some((anchor, targets));
    }

    /// Returns the next coordinator action.
    ///
    /// Returns `Dispatch` for a pending tip (a new generation), `Converged` when every database
    /// reached the current generation, and `Wait` otherwise.
    fn next_action(&mut self) -> CoordinatorAction<D, T> {
        if let Some((anchor, targets)) = self.latest_tip.take() {
            self.generation += 1;
            self.reached.fill(false);
            self.current = (anchor, targets.clone());
            return CoordinatorAction::Dispatch {
                generation: self.generation,
                targets,
            };
        }
        if self.reached.iter().all(|reached| *reached) {
            let (anchor, targets) = self.current.clone();
            return CoordinatorAction::Converged { anchor, targets };
        }
        CoordinatorAction::Wait
    }
}

/// Syncs a database that durably persists its operation log.
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

/// Syncs a compact database, which does not persist its operation log.
///
/// A compact target that does not convert to an engine target fails the sync when passed as
/// `target` and is ignored when it arrives on `tip_updates`.
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
    let update_forwarder = Forwarder(context.child("compact_updates").spawn(move |_| async move {
        while let Some(update) = tip_updates.recv().await {
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
        update_rx: Some(update_rx),
        finish_rx: finish,
        reached_target_tx,
    })
    .await;
    drop(update_forwarder);
    result
}

#[tracing::instrument(name = "stateful.db.apply", level = "info", skip_all, fields(index = index))]
async fn apply<E, T: ManagedDb<E>>(database: T, batch: T::Merkleized, index: Option<usize>) -> T {
    // Mutable apply failures are fatal because the batch may already have been
    // applied to other databases in the same set, leaving partially applied state.
    match database.apply(batch).await {
        Ok(result) => result,
        Err(err) => {
            let index = index.map_or(String::new(), |i| format!("index {i}, "));
            panic!(
                "database apply failed ({index}type {}): {err:?}",
                core::any::type_name::<T>(),
            );
        }
    }
}

/// Applies `batch` to one database while holding only that database's write lock.
async fn apply_shared<E, T: ManagedDb<E>>(
    shared: &Shared<T>,
    batch: T::Merkleized,
    index: Option<usize>,
) {
    let (slot, database) = shared.write().await;
    slot.put(apply(database, batch, index).await);
}

#[tracing::instrument(name = "stateful.db.finalize", level = "info", skip_all, fields(index = index))]
async fn finalize<E, T: ManagedDb<E>>(database: T, index: Option<usize>) -> (T, Handle<()>) {
    match database.finalize().await {
        Ok(result) => result,
        Err(err) => {
            let index = index.map_or(String::new(), |i| format!("index {i}, "));
            panic!(
                "database finalize failed ({index}type {}): {err:?}",
                core::any::type_name::<T>(),
            );
        }
    }
}

/// Starts persisting one database and returns the handle that resolves once it is durable.
async fn finalize_shared<E, T: ManagedDb<E>>(
    shared: &Shared<T>,
    index: Option<usize>,
) -> Handle<()> {
    let (slot, database) = shared.write().await;
    let (database, handle) = finalize(database, index).await;
    slot.put(database);
    handle
}

async fn prune_shared<E, T: ManagedDb<E>>(
    shared: &Shared<T>,
    target: &T::SyncTarget,
    index: Option<usize>,
) {
    let (slot, database) = shared.write().await;
    slot.put(prune(database, target, index).await);
}

#[tracing::instrument(name = "stateful.db.prune", level = "info", skip_all, fields(index = index))]
async fn prune<E, T: ManagedDb<E>>(database: T, target: &T::SyncTarget, index: Option<usize>) -> T {
    // Prune failures are fatal because pruning may already have discarded part
    // of the retained history before the error surfaced.
    match database.prune(target).await {
        Ok(database) => database,
        Err(err) => {
            let index = index.map_or(String::new(), |i| format!("index {i}, "));
            panic!(
                "database prune failed ({index}type {}): {err:?}",
                core::any::type_name::<T>(),
            );
        }
    }
}

/// A resolver that serves sync requests from a database attached after startup.
pub trait AttachableResolver<DB>: Clone + Send + Sync + 'static {
    /// Attaches `db` for serving incoming requests.
    fn attach_database(&self, db: Shared<DB>) -> impl Future<Output = ()> + Send;
}

/// A set of resolvers with the same shape as a database set.
pub trait AttachableResolverSet<DBs>: Clone + Send + Sync + 'static {
    /// Attaches each database to its resolver.
    fn attach_databases(&self, databases: DBs) -> impl Future<Output = ()> + Send;
}

impl<R, DB> AttachableResolverSet<Shared<DB>> for R
where
    R: AttachableResolver<DB>,
    DB: Send + Sync + 'static,
{
    async fn attach_databases(&self, db: Shared<DB>) {
        self.attach_database(db).await;
    }
}

macro_rules! impl_attachable_resolver_set {
    ($($R:ident : $DB:ident : $idx:tt),+) => {
        impl<$($R, $DB),+> AttachableResolverSet<($(Shared<$DB>,)+)> for ($($R,)+)
        where
            $(
                $R: AttachableResolver<$DB>,
                $DB: Send + Sync + 'static,
            )+
        {
            async fn attach_databases(&self, databases: ($(Shared<$DB>,)+)) {
                futures::join!($(
                    self.$idx.attach_database(databases.$idx),
                )+);
            }
        }
    };
}

impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2, R4: DB4: 3);
impl_attachable_resolver_set!(R1: DB1: 0, R2: DB2: 1, R3: DB3: 2, R4: DB4: 3, R5: DB5: 4);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5
);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5,
    R7: DB7: 6
);
impl_attachable_resolver_set!(
    R1: DB1: 0,
    R2: DB2: 1,
    R3: DB3: 2,
    R4: DB4: 3,
    R5: DB5: 4,
    R6: DB6: 5,
    R7: DB7: 6,
    R8: DB8: 7
);

#[cfg(test)]
mod tests {
    use super::{
        Anchor, AttachableResolver, AttachableResolverSet, Barrier, BatchContext,
        CoordinatorAction, CoordinatorState, DatabaseSet, InitError, MAX_CHANNEL_DRAIN_PER_TICK,
        ManagedDb, Observation, Reached, Shared, StateSyncDb, StateSyncSet, SyncEngineConfig,
        TipUpdate, reached_channel,
    };
    use crate::stateful::tests::mocks::{TestMerkleized, TestUnmerkleized, anchor as mock_anchor};
    use commonware_cryptography::sha256;
    use commonware_macros::select;
    use commonware_runtime::{
        Clock, Error as RuntimeError, Handle, Runner as _, Spawner as _, Supervisor as _,
        deterministic, reschedule,
    };
    use commonware_utils::{
        NZU64, NZUsize,
        channel::{mpsc, oneshot, ring},
    };
    use futures::{FutureExt, SinkExt, pin_mut};
    use std::{
        convert::Infallible,
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    mod managed_db_lifecycle {
        use super::{ManagedDb, Shared};
        use crate::stateful::db::Unmerkleized;
        use commonware_cryptography::{Sha256, sha256::Digest};
        use commonware_parallel::Sequential;
        use commonware_runtime::{
            Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
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
                init_cache: Some(NZUsize!(1024)),
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
                init_cache: Some(NZUsize!(1024)),
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
                init_cache: Some(NZUsize!(1024)),
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
                init_cache: Some(NZUsize!(1024)),
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

        async fn assert_initial_sync_target_and_apply<T>(context: Context, config: T::Config)
        where
            T: ManagedDb<Context> + 'static,
            T::Unmerkleized: Unmerkleized<Merkleized = T::Merkleized>,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
        {
            let initial = T::initial_sync_target();
            let db = T::init(context, config, None).await.unwrap();
            assert_eq!(initial, db.sync_target());
            let db = Shared::new("test", db);
            let batch = db
                .new_batch_for_test::<Context>()
                .await
                .merkleize()
                .await
                .expect("empty batch must merkleize");
            let (slot, database) = db.write().await;
            let database = T::apply(database, batch).await.unwrap();
            let (database, sync) = T::finalize(database).await.unwrap();
            slot.put(database);
            sync.await.expect("empty batch database sync failed");
        }

        #[rstest]
        #[case::any(PhantomData::<AnyFixed>, any_fixed_config)]
        #[case::current(PhantomData::<CurrentUnorderedFixed>, current_fixed_config)]
        #[case::immutable(PhantomData::<ImmutableFixed>, immutable_fixed_config)]
        #[case::immutable_compact(
            PhantomData::<ImmutableCompactFixed>, immutable_compact_fixed_config
        )]
        #[case::keyless(PhantomData::<KeylessFixed>, keyless_fixed_config)]
        #[case::keyless_compact(
            PhantomData::<KeylessCompactFixed>, keyless_compact_fixed_config
        )]
        fn merkleize_stale_batch_returns_error<T>(
            #[case] _db: PhantomData<T>,
            #[case] config: fn(&Context, &str) -> T::Config,
        ) where
            T: ManagedDb<Context> + 'static,
            T::Unmerkleized: Unmerkleized<
                    Merkleized = T::Merkleized,
                    Error = commonware_storage::qmdb::Error<mmr::Family>,
                >,
            T::SyncTarget: Debug,
        {
            deterministic::Runner::default().start(|context| async move {
                let config = config(&context, "db");
                let database = T::init(context.child("db"), config, None).await.unwrap();
                let db = Shared::new("test", database);
                let stale = db.new_batch_for_test::<Context>().await;
                let winner = db
                    .new_batch_for_test::<Context>()
                    .await
                    .merkleize()
                    .await
                    .unwrap();

                // Batch creation releases the read lock, permitting a sibling to be applied.
                let (slot, database) = db.write().await;
                let database = T::apply(database, winner).await.unwrap();
                slot.put(database);

                assert!(matches!(
                    stale.merkleize().await,
                    Err(commonware_storage::qmdb::Error::StaleBatch)
                ));
                assert!(
                    db.new_batch_for_test::<Context>()
                        .await
                        .merkleize()
                        .await
                        .is_ok()
                );
            });
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
        fn initial_sync_target_and_empty_apply_match_initialized_database<T>(
            #[case] _db: PhantomData<T>,
            #[case] config: fn(&Context, &str) -> T::Config,
        ) where
            T: ManagedDb<Context> + 'static,
            T::Unmerkleized: Unmerkleized<Merkleized = T::Merkleized>,
            <T::Unmerkleized as Unmerkleized>::Error: Debug,
            T::SyncTarget: Debug,
        {
            deterministic::Runner::default().start(|context| async move {
                let config = config(&context, "db");
                assert_initial_sync_target_and_apply::<T>(context.child("db"), config).await;
            });
        }
    }

    macro_rules! ready_apply {
        () => {
            async fn apply(self, _batch: Self::Merkleized) -> Result<Self, Self::Error> {
                Ok(self)
            }

            async fn finalize(self) -> Result<(Self, Handle<()>), Self::Error> {
                Ok((self, Handle::ready(Ok(()))))
            }
        };
    }

    #[derive(Default)]
    struct TestDb;

    struct InitializationDb {
        /// Restart target selected during initialization.
        current_target: u64,
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

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            Ok(Self)
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {}
    }

    impl<E: Send> ManagedDb<E> for InitializationDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = u64;
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            0
        }

        async fn init(
            _context: E,
            config: Self::Config,
            expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            let target = expected.unwrap_or(config);
            assert!(
                target <= config,
                "database is behind its initialization target"
            );
            Ok(Self {
                current_target: target,
            })
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.current_target
        }
    }

    impl<E: Send> ManagedDb<E> for PruneCountingDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = Arc<AtomicUsize>;
        type SyncTarget = ();

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(
            _context: E,
            prune_count: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            Ok(Self { prune_count })
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        async fn prune(self, _target: &Self::SyncTarget) -> Result<Self, Self::Error> {
            self.prune_count.fetch_add(1, Ordering::SeqCst);
            Ok(self)
        }

        fn sync_target(&self) -> Self::SyncTarget {}
    }

    struct BlockingApplyDb {
        started: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }

    impl BlockingApplyDb {
        fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
            Self {
                started: Some(started),
                release: Some(release),
            }
        }
    }

    #[derive(Debug)]
    struct TestApplyError;

    struct FailingApplyDb;

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

    impl<E: Send> ManagedDb<E> for FailingApplyDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = TestApplyError;
        type Config = ();
        type SyncTarget = ();

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            Ok(Self)
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn apply(self, _batch: Self::Merkleized) -> Result<Self, Self::Error> {
            Err(TestApplyError)
        }

        async fn finalize(self) -> Result<(Self, Handle<()>), Self::Error> {
            Ok((self, Handle::ready(Ok(()))))
        }

        fn sync_target(&self) -> Self::SyncTarget {}
    }

    /// Database mock that can fail after recording its selected restart target.
    struct RecoverableStartupDb(u64);

    impl<E: Send> ManagedDb<E> for RecoverableStartupDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = &'static str;
        type Config = (Arc<AtomicU64>, bool);
        type SyncTarget = u64;

        fn initial_sync_target() -> u64 {
            0
        }

        async fn init(
            _context: E,
            (state, fail): Self::Config,
            expected: Option<u64>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            let retained = state.load(Ordering::Relaxed);
            let selected = expected.unwrap_or(retained);
            if selected > retained {
                return Err(InitError::Database("database is behind"));
            }
            state.store(selected, Ordering::Relaxed);
            if fail {
                return Err(InitError::Database(
                    "initialization interrupted after durable repair",
                ));
            }
            Ok(Self(selected))
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &u64) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn tuple_initialization_retries_partial_failure_and_rejects_behind() {
        deterministic::Runner::default().start(|context| async move {
            type DbSet = (Shared<RecoverableStartupDb>, Shared<RecoverableStartupDb>);
            let left = Arc::new(AtomicU64::new(3));
            let right = Arc::new(AtomicU64::new(2));
            let result = std::panic::AssertUnwindSafe(<DbSet as DatabaseSet<_>>::init(
                context.child("interrupted"),
                ((left.clone(), false), (right.clone(), true)),
                Some((1, 1)),
            ))
            .catch_unwind()
            .await;
            assert!(result.is_err());
            assert_eq!(left.load(Ordering::Relaxed), 1);
            assert_eq!(right.load(Ordering::Relaxed), 1);
            let recovered = <DbSet as DatabaseSet<_>>::init(
                context.child("retry"),
                ((left.clone(), false), (right.clone(), false)),
                Some((1, 1)),
            )
            .await;
            assert_eq!((*recovered.0.read().await).0, 1);
            assert_eq!((*recovered.1.read().await).0, 1);
            drop(recovered);
            let result = std::panic::AssertUnwindSafe(<DbSet as DatabaseSet<_>>::init(
                context.child("behind"),
                ((left, false), (right, false)),
                Some((1, 2)),
            ))
            .catch_unwind()
            .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn tuple_initialization_validates_ahead_and_aligned_databases() {
        deterministic::Runner::default().start(|context| async move {
            type DbSet = (Shared<InitializationDb>, Shared<InitializationDb>);
            let (left, right) =
                <DbSet as DatabaseSet<_>>::init(context, (2, 1), Some((1, 1))).await;
            for database in [left, right] {
                let db = database.read().await;
                assert_eq!(db.current_target, 1);
            }
        });
    }

    #[test]
    fn database_set_prune_calls_managed_db_prune() {
        deterministic::Runner::default().start(|_context| async move {
            let prune_count = Arc::new(AtomicUsize::new(0));
            let database = Shared::new(
                "test",
                PruneCountingDb {
                    prune_count: prune_count.clone(),
                },
            );

            <Shared<PruneCountingDb> as DatabaseSet<deterministic::Context>>::prune(&database, &())
                .await;

            assert_eq!(prune_count.load(Ordering::SeqCst), 1);
        });
    }

    impl<E: Send> ManagedDb<E> for BlockingApplyDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();

        fn initial_sync_target() -> Self::SyncTarget {}

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("BlockingApplyDb is constructed directly in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn apply(mut self, _batch: Self::Merkleized) -> Result<Self, Self::Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.await;
            }
            Ok(self)
        }

        async fn finalize(self) -> Result<(Self, Handle<()>), Self::Error> {
            Ok((self, Handle::ready(Ok(()))))
        }

        fn sync_target(&self) -> Self::SyncTarget {}
    }

    impl<E: Send> ManagedDb<E> for SlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("SlowSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("SlowSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for RejectDuplicateTargetSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!(
                "RejectDuplicateTargetSyncDb is only constructed through state sync in tests"
            )
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!(
                "RejectDuplicateTargetSyncDb is only constructed through state sync in tests"
            )
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for FastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FastSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("FastSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for FailingStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FailingStateSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("FailingStateSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }
    }

    impl<E: Send> ManagedDb<E> for MismatchedTargetSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("MismatchedTargetSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("MismatchedTargetSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for ImmediateStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ImmediateStateSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("ImmediateStateSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }
    }

    impl<E: Send> ManagedDb<E> for FinishClosedSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("FinishClosedSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("FinishClosedSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedSlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ObservedSlowSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("ObservedSlowSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("ObservedFastSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("ObservedFastSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E: Send> ManagedDb<E> for DistinctObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!(
                "DistinctObservedFastSyncDb is only constructed through state sync in tests"
            )
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!(
                "DistinctObservedFastSyncDb is only constructed through state sync in tests"
            )
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E> StateSyncDb<E, Arc<AtomicBool>> for SlowSyncDb
    where
        E: Clock,
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
        E: Clock,
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

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("StaleReachedSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("StaleReachedSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    impl<E> StateSyncDb<E, ()> for StaleReachedSyncDb
    where
        E: Clock,
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
        E: Clock,
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
    fn tuple_new_batches_queues_reads_concurrently() {
        deterministic::Runner::default().start(|_context| async move {
            let db1 = Shared::new("test", TestDb);
            let db2 = Shared::new("test", TestDb);
            let databases = (db1.clone(), db2.clone());

            let (slot1, taken1) = db1.write().await;
            let (slot2, taken2) = db2.write().await;

            let new_batches = <(Shared<TestDb>, Shared<TestDb>) as DatabaseSet<
                deterministic::Context,
            >>::new_batches(&databases);
            pin_mut!(new_batches);
            assert!(new_batches.as_mut().now_or_never().is_none());

            slot2.put(taken2);
            {
                let writer2_again = db2.write();
                pin_mut!(writer2_again);
                assert!(
                    writer2_again.as_mut().now_or_never().is_none(),
                    "tuple new_batches should queue reads for all databases concurrently"
                );
            }

            slot1.put(taken1);
            let _ = new_batches.await;
        });
    }

    #[test]
    fn new_batches_releases_read_lock_before_returning() {
        deterministic::Runner::default().start(|_context| async move {
            let database = Shared::new("test", TestDb);
            let _ = <Shared<TestDb> as DatabaseSet<deterministic::Context>>::new_batches(&database)
                .await;

            let writer = database.write();
            pin_mut!(writer);
            assert!(
                writer.as_mut().now_or_never().is_some(),
                "batch construction must release its read lock before returning",
            );
        });
    }

    #[test]
    fn tuple_apply_does_not_hold_ready_writer_while_waiting_for_reader() {
        deterministic::Runner::default().start(|_context| async move {
            type DbSet = (Shared<TestDb>, Shared<TestDb>);

            let db1 = Shared::new("test", TestDb);
            let db2 = Shared::new("test", TestDb);
            let databases = (db1.clone(), db2.clone());
            let reader1 = db1.read().await;

            let apply = async {
                <DbSet as DatabaseSet<deterministic::Context>>::apply(
                    &databases,
                    (TestMerkleized, TestMerkleized),
                )
                .await
            };
            pin_mut!(apply);
            assert!(apply.as_mut().now_or_never().is_none());

            let reader2 = db2.read();
            pin_mut!(reader2);
            assert!(
                reader2.as_mut().now_or_never().is_some(),
                "tuple apply must not hold one writer while waiting for another database's reader",
            );

            drop(reader1);
            apply.await;
        });
    }

    #[test]
    fn tuple_apply_runs_databases_in_parallel() {
        deterministic::Runner::default().start(|_context| async move {
            let (started1_tx, started1_rx) = oneshot::channel();
            let (started2_tx, started2_rx) = oneshot::channel();
            let (release1_tx, release1_rx) = oneshot::channel();
            let (release2_tx, release2_rx) = oneshot::channel();

            let databases = (
                Shared::new("test", BlockingApplyDb::new(started1_tx, release1_rx)),
                Shared::new("test", BlockingApplyDb::new(started2_tx, release2_rx)),
            );

            let apply = <(Shared<BlockingApplyDb>, Shared<BlockingApplyDb>) as DatabaseSet<
                deterministic::Context,
            >>::apply(&databases, (TestMerkleized, TestMerkleized));
            pin_mut!(apply);
            assert!(apply.as_mut().now_or_never().is_none());

            let started1 = started1_rx;
            let started2 = started2_rx;
            pin_mut!(started1);
            pin_mut!(started2);
            assert!(matches!(started1.as_mut().now_or_never(), Some(Ok(()))));
            assert!(
                matches!(started2.as_mut().now_or_never(), Some(Ok(()))),
                "tuple apply should start on all databases concurrently"
            );

            let _ = release1_tx.send(());
            let _ = release2_tx.send(());
            apply.await;
        });
    }

    #[test]
    #[should_panic(
        expected = "database apply failed (index 1, type commonware_glue::stateful::db::tests::FailingApplyDb)"
    )]
    fn tuple_apply_panic_identifies_failing_database() {
        deterministic::Runner::default().start(|_context| async move {
            let databases = (
                Shared::new("test", TestDb),
                Shared::new("test", FailingApplyDb),
            );
            let _ = <(Shared<TestDb>, Shared<FailingApplyDb>) as DatabaseSet<
                deterministic::Context,
            >>::apply(&databases, (TestMerkleized, TestMerkleized))
            .await;
        });
    }

    #[test]
    #[should_panic(
        expected = "database sync failed (index 1, type commonware_glue::stateful::db::tests::TestDb)"
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

    struct LaggingSyncDb {
        final_target: u64,
    }

    /// Signals that a [`LaggingSyncDb`] reported its initial target, and releases it.
    type LagGate = (oneshot::Sender<()>, oneshot::Receiver<()>);

    impl<E: Send> ManagedDb<E> for LaggingSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("LaggingSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("LaggingSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    /// Reports its initial target once the first tip arrives, waits for release, then reports
    /// and finishes at the newest forwarded target.
    impl<E: Send> StateSyncDb<E, LagGate> for LaggingSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            (reported, release): LagGate,
            target: Self::SyncTarget,
            mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
            mut finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = tip_updates.recv().await.expect("expected forwarded tip");
            if let Some(reached_target) = reached_target.as_ref() {
                let _ = reached_target.send(target).await;
            }
            let _ = reported.send(());

            let _ = release.await;
            while let Ok(update) = tip_updates.try_recv() {
                final_target = update;
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

    fn lagging_sync_config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: NZU64!(1),
            max_outstanding_requests: NZUsize!(1),
            update_channel_size: NonZeroUsize::new(4).unwrap(),
        }
    }

    /// Once the database reaches an earlier target, the sync refuses later tips and finishes at
    /// the newest recorded tip.
    #[test]
    fn single_state_sync_refuses_tips_after_reaching_earlier_target() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (reported_tx, reported_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let sync =
                context
                    .child("single_state_sync_refuses_tips")
                    .spawn(move |context| async move {
                        <Shared<LaggingSyncDb> as StateSyncSet<
                            deterministic::Context,
                            LagGate,
                            sha256::Digest,
                        >>::sync(
                            context,
                            (),
                            (reported_tx, release_rx),
                            anchor(0),
                            0,
                            tip_rx,
                            lagging_sync_config(),
                        )
                        .await
                        .expect("single state sync should succeed")
                    });

            // The first tip is recorded and forwarded.
            let (update, observed) = TipUpdate::with_observation(anchor(1), 1);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));

            // The database reports its initial target. A later tip is refused.
            reported_rx
                .await
                .expect("database should report its initial target");
            let (update, observed) = TipUpdate::with_observation(anchor(2), 2);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Refused));

            // Once released, the database reaches the newest recorded tip and the sync finishes
            // there.
            release_tx.send(()).unwrap();
            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(database.read().await.final_target, 1);
            assert_eq!(converged_anchor, anchor(1));
        });
    }

    /// A forced tip releases a holding sync: it is recorded and forwarded, and the sync finishes
    /// at it.
    #[test]
    fn single_state_sync_forced_tip_releases_hold() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (reported_tx, reported_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let sync =
                context
                    .child("single_state_sync_forced_tip")
                    .spawn(move |context| async move {
                        <Shared<LaggingSyncDb> as StateSyncSet<
                            deterministic::Context,
                            LagGate,
                            sha256::Digest,
                        >>::sync(
                            context,
                            (),
                            (reported_tx, release_rx),
                            anchor(0),
                            0,
                            tip_rx,
                            lagging_sync_config(),
                        )
                        .await
                        .expect("single state sync should succeed")
                    });

            // The first tip is recorded. The database reports its initial target, which starts
            // the hold, and a later tip is refused.
            let (update, observed) = TipUpdate::with_observation(anchor(1), 1);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            reported_rx
                .await
                .expect("database should report its initial target");
            let (update, observed) = TipUpdate::with_observation(anchor(2), 2);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Refused));

            // A forced tip is recorded and forwarded, and the sync finishes there.
            let (update, observed) = TipUpdate::forced_with_observation(anchor(3), 3);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            release_tx.send(()).unwrap();
            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(database.read().await.final_target, 3);
            assert_eq!(converged_anchor, anchor(3));
        });
    }

    /// A holding sync whose database reaches the recorded target while a forced tip is queued
    /// finishes at the recorded target.
    #[test]
    fn single_state_sync_converges_before_queued_forced_tip() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (reported_tx, reported_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let sync = context.child("single_state_sync_queued_forced_tip").spawn(
                move |context| async move {
                    <Shared<LaggingSyncDb> as StateSyncSet<
                        deterministic::Context,
                        LagGate,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        (reported_tx, release_rx),
                        anchor(0),
                        0,
                        tip_rx,
                        lagging_sync_config(),
                    )
                    .await
                    .expect("single state sync should succeed")
                },
            );

            // The first tip is recorded, and the database's report of its initial target starts
            // the hold.
            let (update, observed) = TipUpdate::with_observation(anchor(1), 1);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            reported_rx
                .await
                .expect("database should report its initial target");
            let (update, observed) = TipUpdate::with_observation(anchor(2), 2);
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Refused));

            // A forced tip is queued as the database reaches the recorded target. The sync polls
            // the database before the coordinator, which takes reports before tips, so it
            // converges before taking the forced tip.
            let (update, _observed) = TipUpdate::forced_with_observation(anchor(3), 3);
            let _ = tip_tx.send(update).await;
            release_tx.send(()).unwrap();
            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(database.read().await.final_target, 1);
            assert_eq!(converged_anchor, anchor(1));
        });
    }

    struct EagerSyncDb {
        final_target: u64,
    }

    impl<E: Send> ManagedDb<E> for EagerSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("EagerSyncDb is only constructed through state sync in tests")
        }

        async fn init(
            _context: E,
            _config: Self::Config,
            _expected: Option<Self::SyncTarget>,
        ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
            unreachable!("EagerSyncDb is only constructed through state sync in tests")
        }

        fn new_batch(_database: BatchContext<'_, Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        ready_apply!();

        fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }
    }

    /// Once released, reports its initial target and then each forwarded target as soon as it
    /// arrives, waiting for report capacity as the sync engine does, and finishes when asked.
    impl<E: Send> StateSyncDb<E, oneshot::Receiver<()>> for EagerSyncDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: E,
            _config: Self::Config,
            release: oneshot::Receiver<()>,
            target: Self::SyncTarget,
            mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
            finish: Option<mpsc::Receiver<()>>,
            reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            let mut finish = finish.expect("single state sync requests a finish");
            let reached_target = reached_target.expect("single state sync observes reports");
            let _ = release.await;
            let mut final_target = target;
            let _ = reached_target.send(final_target).await;
            loop {
                select! {
                    _ = finish.recv() => return Ok(Self { final_target }),
                    update = tip_updates.recv() => {
                        let Some(update) = update else {
                            let _ = finish.recv().await;
                            return Ok(Self { final_target });
                        };
                        final_target = update;
                        let _ = reached_target.send(final_target).await;
                    },
                }
            }
        }
    }

    /// The coordinator keeps draining reached reports while it waits to forward a target, so a
    /// database that reports each target before taking the next one cannot deadlock it.
    #[test]
    fn single_state_sync_drains_reports_while_forwarding_targets() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (release_tx, release_rx) = oneshot::channel();
            let sync = context.child("single_state_sync_drains_reports").spawn(
                move |context| async move {
                    <Shared<EagerSyncDb> as StateSyncSet<
                        deterministic::Context,
                        oneshot::Receiver<()>,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        release_rx,
                        anchor(0),
                        0,
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NZU64!(1),
                            apply_batch_size: NZU64!(1),
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                },
            );

            // Before the database reports its initial target, the first tip fills the target
            // channel, the second is recorded and waits to be forwarded, and the third waits in
            // the tip ring.
            for height in 1..=2 {
                let (update, observed) = TipUpdate::with_observation(anchor(height), height);
                let _ = tip_tx.send(update).await;
                assert_eq!(observed.await, Ok(Observation::Recorded));
            }
            let (update, third) = TipUpdate::with_observation(anchor(3), 3);
            let _ = tip_tx.send(update).await;

            // The database reports every target as it arrives. The sync polls the database before
            // the coordinator, which takes reports before tips, so the first report, of an earlier
            // target, starts the hold before the third tip is taken. The third tip is refused and
            // the sync finishes at the second.
            release_tx.send(()).unwrap();
            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(third.await, Ok(Observation::Refused));
            assert_eq!(database.read().await.final_target, 2);
            assert_eq!(converged_anchor, anchor(2));
        });
    }

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
    fn single_state_sync_handles_closed_tip_updates_channel() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let release = Arc::new(AtomicBool::new(false));
            let release_for_sync = release.clone();

            let sync = context.child("single_state_sync_closed_tip_updates").spawn(
                move |context| async move {
                    <Shared<SlowSyncDb> as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
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

            let result = <Shared<FailingStateSyncDb> as StateSyncSet<
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
                    max_outstanding_requests: NZUsize!(1),
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
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
                    <Shared<ObservedSlowSyncDb> as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                });

            let _ = tip_tx.send(TipUpdate::new(anchor(2), 2)).await;
            let _ = tip_tx.send(TipUpdate::new(anchor(1), 1)).await;
            drop(tip_tx);

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            let final_target = database.read().await.final_target;
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
                    <Shared<RejectDuplicateTargetSyncDb> as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                },
            );

            // Let the coordinator start waiting before the update below arrives.
            context.sleep(Duration::from_millis(10)).await;
            let (update, observed) = TipUpdate::with_observation(anchor(9), 7);
            let _ = tip_tx.send(update).await;
            observed
                .await
                .expect("single-db coordinator should record noop target update");
            release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(database.read().await.final_target, 7);
            assert_eq!(converged_anchor, anchor(9));
        });
    }

    #[test]
    fn single_state_sync_finishes_at_forwarded_tip_after_stale_reached() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());

            let sync =
                context
                    .child("single_state_sync_stale_reached")
                    .spawn(move |context| async move {
                        <Shared<StaleReachedSyncDb> as StateSyncSet<
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
                                max_outstanding_requests: NZUsize!(1),
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                            },
                        )
                        .await
                        .expect("single state sync should succeed")
                    });

            let _ = tip_tx.send(TipUpdate::new(anchor(2), 2)).await;

            let (database, converged_anchor) = sync.await.expect("sync task should complete");
            let final_target = database.read().await.final_target;
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

    /// The set records tips and sends them to every database until every database reaches a
    /// target. It then refuses later tips and finishes at the newest recorded tip.
    #[test]
    fn tuple_state_sync_refuses_tips_once_every_database_reaches_a_target() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (reported_tx, reported_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));
            let fast_source = FastSyncObserver {
                ready: fast_ready.clone(),
                update_count: fast_update_count.clone(),
            };
            let sync =
                context
                    .child("tuple_state_sync_refuses_tips")
                    .spawn(move |context| async move {
                        <(Shared<LaggingSyncDb>, Shared<ObservedFastSyncDb>) as StateSyncSet<
                            deterministic::Context,
                            (LagGate, FastSyncObserver),
                            sha256::Digest,
                        >>::sync(
                            context,
                            ((), ()),
                            ((reported_tx, release_rx), fast_source),
                            anchor(0),
                            (0, 0),
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: NZU64!(1),
                                max_outstanding_requests: NZUsize!(1),
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                            },
                        )
                        .await
                        .expect("tuple state sync should succeed")
                    });

            // The fast database reaches its initial target first. The next tip is still recorded
            // and reaches both databases.
            while !fast_ready.load(Ordering::SeqCst) {
                reschedule().await;
            }
            let (update, observed) = TipUpdate::with_observation(anchor(1), (1, 1));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            while fast_update_count.load(Ordering::SeqCst) == 0 {
                reschedule().await;
            }

            // The lagging database reports its initial target. Every database has reached a
            // target, and a later tip is refused.
            reported_rx
                .await
                .expect("lagging database should report its initial target");
            let (update, observed) = TipUpdate::with_observation(anchor(2), (2, 2));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Refused));

            // Once released, both databases finish at the newest recorded tip.
            release_tx.send(()).unwrap();
            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(synced.0.read().await.final_target, 1);
            assert_eq!(synced.1.read().await.final_target, 1);
            assert_eq!(converged_anchor, anchor(1));
            assert_eq!(fast_update_count.load(Ordering::SeqCst), 1);
        });
    }

    /// A forced tip releases a holding set: it is recorded and sent to every database, and the set
    /// finishes there.
    #[test]
    fn tuple_state_sync_forced_tip_releases_hold() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let (reported_tx, reported_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));
            let fast_source = FastSyncObserver {
                ready: fast_ready.clone(),
                update_count: fast_update_count.clone(),
            };
            let sync =
                context
                    .child("tuple_state_sync_forced_tip")
                    .spawn(move |context| async move {
                        <(Shared<LaggingSyncDb>, Shared<ObservedFastSyncDb>) as StateSyncSet<
                            deterministic::Context,
                            (LagGate, FastSyncObserver),
                            sha256::Digest,
                        >>::sync(
                            context,
                            ((), ()),
                            ((reported_tx, release_rx), fast_source),
                            anchor(0),
                            (0, 0),
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: NZU64!(1),
                                max_outstanding_requests: NZUsize!(1),
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                            },
                        )
                        .await
                        .expect("tuple state sync should succeed")
                    });

            // Both databases reach a target after the first tip, and a later tip is refused.
            while !fast_ready.load(Ordering::SeqCst) {
                reschedule().await;
            }
            let (update, observed) = TipUpdate::with_observation(anchor(1), (1, 1));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            reported_rx
                .await
                .expect("lagging database should report its initial target");
            let (update, observed) = TipUpdate::with_observation(anchor(2), (2, 2));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Refused));

            // A forced tip is recorded and sent to both databases, and the set finishes there.
            let (update, observed) = TipUpdate::forced_with_observation(anchor(3), (3, 3));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            while fast_update_count.load(Ordering::SeqCst) < 2 {
                reschedule().await;
            }
            release_tx.send(()).unwrap();
            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(synced.0.read().await.final_target, 3);
            assert_eq!(synced.1.read().await.final_target, 3);
            assert_eq!(converged_anchor, anchor(3));
            assert_eq!(fast_update_count.load(Ordering::SeqCst), 2);
        });
    }

    /// A holding set whose databases reach the current generation while a forced tip is queued
    /// finishes there, unless the coordinator takes the forced tip first. Each seed orders the
    /// coordinator and the database tasks differently, and some seed must finish first.
    #[test]
    fn tuple_state_sync_converges_before_queued_forced_tip() {
        let mut converged_first = false;
        for seed in 0..16 {
            let final_target = deterministic::Runner::seeded(seed).start(|context| async move {
                let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
                let (reported_tx, reported_rx) = oneshot::channel();
                let (release_tx, release_rx) = oneshot::channel();
                let fast_ready = Arc::new(AtomicBool::new(false));
                let fast_source = FastSyncObserver {
                    ready: fast_ready.clone(),
                    update_count: Arc::new(AtomicUsize::new(0)),
                };
                let sync = context.child("tuple_state_sync_queued_forced_tip").spawn(
                    move |context| async move {
                        <(Shared<LaggingSyncDb>, Shared<ObservedFastSyncDb>) as StateSyncSet<
                            deterministic::Context,
                            (LagGate, FastSyncObserver),
                            sha256::Digest,
                        >>::sync(
                            context,
                            ((), ()),
                            ((reported_tx, release_rx), fast_source),
                            anchor(0),
                            (0, 0),
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: NZU64!(1),
                                max_outstanding_requests: NZUsize!(1),
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                            },
                        )
                        .await
                        .expect("tuple state sync should succeed")
                    },
                );

                // Both databases reach a target after the first tip, and the set holds.
                while !fast_ready.load(Ordering::SeqCst) {
                    reschedule().await;
                }
                let (update, observed) = TipUpdate::with_observation(anchor(1), (1, 1));
                let _ = tip_tx.send(update).await;
                assert_eq!(observed.await, Ok(Observation::Recorded));
                reported_rx
                    .await
                    .expect("lagging database should report its initial target");
                let (update, observed) = TipUpdate::with_observation(anchor(2), (2, 2));
                let _ = tip_tx.send(update).await;
                assert_eq!(observed.await, Ok(Observation::Refused));

                // A forced tip is queued as the lagging database reaches the recorded tip.
                let (update, observed) = TipUpdate::forced_with_observation(anchor(3), (3, 3));
                let _ = tip_tx.send(update).await;
                release_tx.send(()).unwrap();
                let (synced, converged_anchor) = sync.await.expect("sync task should complete");
                let final_target = synced.0.read().await.final_target;
                assert_eq!(synced.1.read().await.final_target, final_target);
                assert_eq!(converged_anchor, anchor(final_target));

                // A set that converged first never handles the forced tip.
                drop(tip_tx);
                match final_target {
                    1 => assert!(observed.await.is_err()),
                    3 => assert_eq!(observed.await, Ok(Observation::Recorded)),
                    _ => panic!("sync finished at target {final_target}"),
                }
                final_target
            });
            converged_first |= final_target == 1;
        }
        assert!(
            converged_first,
            "no seed converged before taking the forced tip"
        );
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
                    <(Shared<SlowSyncDb>, Shared<FastSyncDb>) as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
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
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;

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
                    <(Shared<SlowSyncDb>, Shared<FastSyncDb>) as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(8).unwrap(),
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                });

            while !fast_done.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            // Both tips are recorded before the slow database reaches a target.
            let (newer, newer_observed) = TipUpdate::with_observation(anchor(2), (2, 2));
            let (older, older_observed) = TipUpdate::with_observation(anchor(1), (1, 1));
            let _ = tip_tx.send(newer).await;
            let _ = tip_tx.send(older).await;
            drop(tip_tx);
            assert_eq!(newer_observed.await, Ok(Observation::Recorded));
            assert_eq!(older_observed.await, Ok(Observation::Recorded));
            slow_release.store(true, Ordering::SeqCst);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;
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

            let result = <(Shared<MismatchedTargetSyncDb>, Shared<FastSyncDb>) as StateSyncSet<
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
                    max_outstanding_requests: NZUsize!(1),
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
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
                <(Shared<ImmediateStateSyncDb>, Shared<FailingStateSyncDb>) as StateSyncSet<
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
                        max_outstanding_requests: NZUsize!(1),
                        update_channel_size: NonZeroUsize::new(1).unwrap(),
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

            let result = <(Shared<SlowSyncDb>, Shared<FailingStateSyncDb>) as StateSyncSet<
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
                    max_outstanding_requests: NZUsize!(1),
                    update_channel_size: NonZeroUsize::new(1).unwrap(),
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
                <(Shared<FinishClosedSyncDb>, Shared<FailingStateSyncDb>) as StateSyncSet<
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
                        max_outstanding_requests: NZUsize!(1),
                        update_channel_size: NonZeroUsize::new(1).unwrap(),
                    },
                )
                .await;

            let err = match result {
                Ok(_) => panic!("tuple state sync should return the database sync error"),
                Err(err) => err,
            };
            assert!(
                err.contains("state sync failed (index 1, db"),
                "error should include failing database index, got: {err}",
            );
            assert!(
                err.contains("FailingStateSyncDb"),
                "error should include failing database type, got: {err}",
            );
        });
    }

    /// A forced tip ends the hold: it is recorded and dispatched, and the coordinator holds again
    /// only once every database reaches another target.
    #[test]
    fn coordinator_forced_tip_releases_hold() {
        deterministic::Runner::default().start(|_context| async move {
            let mut state = CoordinatorState::new(2, anchor(0), (0u64, 0u64));
            state.record_reached(0, Reached::Generation(0));
            state.record_reached(1, Reached::Earlier);
            assert!(state.held());

            // A tip is refused while held.
            let (update, observed) = TipUpdate::with_observation(anchor(1), (1, 1));
            state.handle_tip(update);
            assert_eq!(observed.await, Ok(Observation::Refused));
            assert!(matches!(state.next_action(), CoordinatorAction::Wait));

            // A forced tip ends the hold and is dispatched as the next generation.
            let (update, observed) = TipUpdate::forced_with_observation(anchor(2), (2, 2));
            state.handle_tip(update);
            assert_eq!(observed.await, Ok(Observation::Recorded));
            assert!(!state.held());
            assert!(matches!(
                state.next_action(),
                CoordinatorAction::Dispatch { generation: 1, .. }
            ));

            // The set holds again once every database reaches another target.
            state.record_reached(0, Reached::Generation(1));
            assert!(!state.held());
            state.record_reached(1, Reached::Generation(1));
            assert!(state.held());
        });
    }

    /// Reached reports never wait for the coordinator. Reports a database records before the
    /// coordinator takes them coalesce to its newest generation, and a closed coordinator stops
    /// the sender.
    #[test]
    fn reached_reports_coalesce_without_waiting() {
        let (sender, receiver) = reached_channel(3);

        // Many reports with no take in between record without waiting.
        for generation in 0..64 {
            assert!(sender.send(0, Reached::Generation(generation)));
            assert!(sender.send(1, Reached::Earlier));
        }
        assert!(sender.send(0, Reached::Earlier));

        // A take yields each reporting database once, with its newest generation.
        assert_eq!(
            receiver.take(),
            vec![(0, Reached::Generation(63)), (1, Reached::Earlier)]
        );
        assert!(receiver.take().is_empty());

        // Once the coordinator stops, the sender reports it.
        drop(receiver);
        assert!(!sender.send(2, Reached::Earlier));
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
        state.record_reached(1, Reached::Generation(0));

        // Only database 0 has actually reached generation 1 so far.
        state.record_reached(0, Reached::Generation(1));

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

        state.record_reached(0, Reached::Generation(1));
        state.record_reached(1, Reached::Generation(1));
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

    /// The coordinator dispatches every recorded tip to every database and holds only once every
    /// database has reached a target. A tip recorded before the hold is still dispatched.
    #[test]
    fn coordinator_holds_once_every_database_reaches_a_target() {
        let mut state = CoordinatorState::new(2, anchor(0), (0u64, 0u64));

        // Database 1 reaches generation 0. A tip starts generation 1 for both databases.
        state.record_reached(1, Reached::Generation(0));
        state.record_tip_update(anchor(1), (1, 1));
        assert!(matches!(
            state.next_action(),
            CoordinatorAction::Dispatch { generation: 1, .. }
        ));
        assert!(!state.held());
        assert!(matches!(state.next_action(), CoordinatorAction::Wait));

        // Database 1 reaches generation 1, and another tip is recorded.
        state.record_reached(1, Reached::Generation(1));
        state.record_tip_update(anchor(2), (2, 2));

        // Database 0 reaches an earlier target. Every database has now reached one, and the
        // recorded tip is dispatched as generation 2.
        state.record_reached(0, Reached::Earlier);
        assert!(state.held());
        let CoordinatorAction::Dispatch {
            generation,
            targets,
        } = state.next_action()
        else {
            panic!("a recorded tip must be dispatched");
        };
        assert_eq!((generation, targets), (2, (2, 2)));

        // A late event for generation 1 does not count toward generation 2.
        state.record_reached(0, Reached::Generation(1));
        state.record_reached(1, Reached::Generation(2));
        assert!(matches!(state.next_action(), CoordinatorAction::Wait));

        // Both databases reach generation 2, and the coordinator converges at its anchor.
        state.record_reached(0, Reached::Generation(2));
        let CoordinatorAction::Converged {
            anchor: converged,
            targets,
        } = state.next_action()
        else {
            panic!("the coordinator should converge at generation 2");
        };
        assert_eq!(converged, anchor(2));
        assert_eq!(targets, (2, 2));
    }

    /// A database that reached its target keeps receiving each recorded tip while another has not
    /// reached one, and every database finishes at the same anchor.
    #[test]
    fn tuple_state_sync_reached_database_follows_tips() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let slow_source = SlowSyncController {
                release: slow_release.clone(),
            };
            let fast_source = FastSyncObserver {
                ready: fast_ready.clone(),
                update_count: fast_update_count.clone(),
            };
            let sync =
                context
                    .child("tuple_state_sync_algorithm")
                    .spawn(move |context| async move {
                        <(Shared<ObservedSlowSyncDb>, Shared<ObservedFastSyncDb>) as StateSyncSet<
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
                                max_outstanding_requests: NZUsize!(1),
                                update_channel_size: NonZeroUsize::new(4).unwrap(),
                            },
                        )
                        .await
                        .expect("tuple state sync should succeed")
                    });

            while !fast_ready.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            // The fast database receives each tip while the slow one has not started.
            for target in 1..=3u64 {
                let (update, observed) =
                    TipUpdate::with_observation(anchor(target), (target, target));
                let _ = tip_tx.send(update).await;
                assert_eq!(observed.await, Ok(Observation::Recorded));
                while fast_update_count.load(Ordering::SeqCst) < target as usize {
                    context.sleep(Duration::from_millis(1)).await;
                }
            }
            slow_release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;

            assert_eq!(
                slow_target, fast_target,
                "all databases should finish on the same converged target set"
            );
            assert_eq!(
                converged_anchor.height.get(),
                slow_target,
                "returned anchor height should match the converged generation"
            );
            assert_eq!(slow_target, 3);
            assert_eq!(fast_update_count.load(Ordering::SeqCst), 3);
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
                    <(Shared<SlowSyncDb>, Shared<ObservedFastSyncDb>) as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
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
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;

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
    fn tuple_state_sync_completes_when_database_target_is_unchanged() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let sync = context.child("tuple_state_sync_unchanged_target").spawn({
                let slow_source = slow_release.clone();
                let fast_source = FastSyncObserver {
                    ready: fast_ready.clone(),
                    update_count: fast_update_count.clone(),
                };
                move |context| async move {
                    <(Shared<SlowSyncDb>, Shared<DistinctObservedFastSyncDb>) as StateSyncSet<
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
                            max_outstanding_requests: NZUsize!(1),
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                }
            });

            while !fast_ready.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }

            // The tip is recorded before the slow database reaches a target.
            let (update, observed) = TipUpdate::with_observation(anchor(9), (9, 7));
            let _ = tip_tx.send(update).await;
            assert_eq!(observed.await, Ok(Observation::Recorded));
            slow_release.store(true, Ordering::SeqCst);
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;

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

    #[derive(Default)]
    struct AttachDb1;

    #[derive(Default)]
    struct AttachDb2;

    #[derive(Clone)]
    struct RecordingResolver {
        id: &'static str,
        log: Arc<commonware_utils::sync::Mutex<Vec<&'static str>>>,
    }

    impl RecordingResolver {
        fn new(
            id: &'static str,
            log: Arc<commonware_utils::sync::Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self { id, log }
        }
    }

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for RecordingResolver {
        async fn attach_database(&self, _db: Shared<DB>) {
            self.log.lock().push(self.id);
        }
    }

    #[test]
    fn single_db_attach_calls_single_resolver() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
            let resolver = RecordingResolver::new("db1", log.clone());
            let db = Shared::new("test", AttachDb1);

            resolver.attach_databases(db).await;
            assert_eq!(&*log.lock(), &["db1"]);
        });
    }

    #[test]
    fn tuple_attach_is_index_stable() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
            let resolvers = (
                RecordingResolver::new("resolver_0", log.clone()),
                RecordingResolver::new("resolver_1", log.clone()),
            );
            let databases = (
                Shared::new("test", AttachDb1),
                Shared::new("test", AttachDb2),
            );

            resolvers.attach_databases(databases).await;
            assert_eq!(&*log.lock(), &["resolver_0", "resolver_1"]);
        });
    }

    #[test]
    fn heterogeneous_tuple_attach_compiles() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
            let resolvers = (
                RecordingResolver::new("db1", log.clone()),
                RecordingResolver::new("db2", log.clone()),
            );
            let databases = (
                Shared::new("test", AttachDb1),
                Shared::new("test", AttachDb2),
            );

            resolvers.attach_databases(databases).await;
            assert_eq!(&*log.lock(), &["db1", "db2"]);
        });
    }
}
