//! Traits for database batch lifecycle and startup sync in [`Stateful`](super::Stateful).
//!
//! This module defines the boundary between stateful application logic and
//! storage backends (QMDB variants).
//!
//! # Batch Lifecycle
//!
//! Normal execution has three stages:
//! 1. [`Unmerkleized`]: mutable, in-progress batch (concrete types expose reads and writes).
//! 2. [`Merkleized`]: a sealed batch with a computed root.
//! 3. Finalization: persist the sealed batch via [`ManagedDb::finalize`].
//!
//! [`DatabaseSet`] groups one or more [`ManagedDb`] instances into one logical
//! unit for execution and commit.
//!
//! # Startup State Sync
//!
//! Startup sync is expressed by two traits:
//! - [`StateSyncDb`]: per-database sync entrypoint.
//! - [`StateSyncSet`]: set-level orchestration.
//!
//! ## Anchors
//!
//! Each set of sync targets is paired with an anchor `(Height, D)` where
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
//! The coordinator continuously drains tip updates and keeps only the latest
//! value before forwarding, which avoids target-channel backpressure buildup.
//! The `generation_state` map is pruned after every dispatch to only retain
//! generations currently assigned to at least one database, so memory usage
//! is bounded by the number of databases regardless of how long sync runs.

use commonware_consensus::types::Height;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{Metrics, Spawner};
use commonware_storage::qmdb::sync::SyncProgress;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, ring},
    sync::AsyncRwLock,
};
use futures::{
    future::{pending, Either},
    join,
};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

pub mod any;
pub mod current;
pub mod immutable;
pub mod p2p;

mod sync_metrics;

/// Mutable batch state before merkleization.
///
/// Concrete types provide key-value operations (`get`, `write`, `set`,
/// `append`, etc.) as inherent methods; the generic wrapper only needs
/// [`merkleize`](Self::merkleize).
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
pub trait Merkleized: Sized + Send + Sync {
    /// The digest type used for the state root.
    type Digest: Digest;

    /// The unmerkleized batch type produced by [`new_batch`](Self::new_batch).
    type Unmerkleized: Unmerkleized;

    /// The canonical state root committed in block headers.
    fn root(&self) -> Self::Digest;

    /// The root used for state-sync targeting.
    ///
    /// Defaults to [`root`](Self::root). Override when the sync engine
    /// operates on a different tree than the consensus root (e.g. the
    /// ops-only MMR in a `current` database, which lacks the activity
    /// bitmap incorporated into the canonical root).
    fn sync_root(&self) -> Self::Digest {
        self.root()
    }

    /// Create a child unmerkleized batch that reads through this batch's
    /// pending changes before falling back to the committed database state.
    ///
    /// In QMDB, this maps to `merkleized_batch.new_batch()`.
    fn new_batch(&self) -> Self::Unmerkleized;
}

/// One database managed by the [`Stateful`](super::Stateful) wrapper.
///
/// Implementations create new batches from committed state and persist finalized
/// batches back to storage.
///
/// [`new_batch`](Self::new_batch) receives `Arc<AsyncRwLock<Self>>` so batch
/// types can keep read-through access to committed state.
///
/// `E` is a trait generic (not an associated type), so one database type can
/// work across runtimes that satisfy the bounds.
pub trait ManagedDb<E>: Send + Sync + Sized {
    /// An in-progress batch of mutations that has not yet been merkleized.
    type Unmerkleized: Unmerkleized;

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
    /// Typically [`Target<Digest>`](commonware_storage::qmdb::sync::Target).
    type SyncTarget: Clone + PartialEq + Send + Sync;

    /// Construct a new database from its configuration.
    fn init(
        context: E,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Create a new unmerkleized batch rooted at the database's committed
    /// state.
    ///
    /// The `db` parameter is the `Arc<AsyncRwLock<Self>>` that wraps this
    /// database, allowing batch types to capture a shared reference for
    /// read-through to committed state.
    fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Apply a merkleized batch's changeset to the underlying database.
    ///
    /// In QMDB, this encapsulates calling `merkleized.finalize()` to produce
    /// a `Changeset`, then `db.apply_batch(changeset)` and `db.commit()`.
    fn finalize(
        &mut self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Return the sync target for this database's current committed state.
    fn sync_target(&self) -> impl Future<Output = Self::SyncTarget> + Send;

    /// Rewind committed state to `target`.
    ///
    /// Implementations must ensure rewind effects are durable before returning
    /// `Ok(())` (for example by committing after rewind).
    fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A collection of individually locked [`ManagedDb`] instances.
///
/// Each database is wrapped in `Arc<AsyncRwLock<...>>`, so the set is cheap to
/// clone and each database can be shared without a global lock.
///
/// `E` is a trait generic (not an associated type), so one set type can work
/// across runtimes that satisfy the bounds.
pub trait DatabaseSet<E>: Clone + Send + Sync + 'static {
    /// Tuple of [`ManagedDb::Unmerkleized`] for every database in the set.
    type Unmerkleized: Send;

    /// Tuple of [`ManagedDb::Merkleized`] for every database in the set.
    type Merkleized: Send + Sync;

    /// Configuration needed to construct every database in the set.
    ///
    /// - Single database sets use that database's [`ManagedDb::Config`].
    /// - Multi-database tuple sets use a tuple of per-database configs
    ///   `(Db1::Config, Db2::Config, ...)`.
    type Config: Send;

    /// Per-database sync targets extracted from a finalized block.
    ///
    /// For a single-database set this is typically
    /// [`Target<Digest>`](commonware_storage::qmdb::sync::Target). For
    /// multi-database sets it is a tuple of targets, one per database.
    type SyncTargets: Clone + PartialEq + Send + Sync;

    /// Construct the database set from its configuration.
    fn init(context: E, config: Self::Config) -> impl Future<Output = Self> + Send;

    /// Create unmerkleized batches from each database's committed state.
    ///
    /// Acquires a read lock on each database.
    fn new_batches(&self) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Create child unmerkleized batches from a pending merkleized parent.
    ///
    /// No lock is needed; reads come from the in-memory merkleized state.
    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized;

    /// Apply each merkleized batch's changeset to its underlying database.
    ///
    /// Acquires a write lock on each database.
    fn finalize(&self, batches: Self::Merkleized) -> impl Future<Output = ()> + Send;

    /// Return sync targets for the set's current committed state.
    fn committed_targets(&self) -> impl Future<Output = Self::SyncTargets> + Send;

    /// Rewind the set to the provided per-database targets.
    ///
    /// Rewind failures are fatal for startup recovery and therefore panic.
    fn rewind_to_targets(&self, targets: Self::SyncTargets) -> impl Future<Output = ()> + Send;
}

/// Parameters for a one-time state-sync pass.
#[derive(Clone, Copy, Debug)]
pub struct SyncEngineConfig {
    /// Maximum operations fetched per resolver request.
    pub fetch_batch_size: NonZeroU64,

    /// Number of operations applied per local apply step.
    pub apply_batch_size: usize,

    /// Maximum number of outstanding resolver requests.
    pub max_outstanding_requests: usize,

    /// Capacity of per-database target-update channels.
    pub update_channel_size: NonZeroUsize,

    /// Number of historical roots to retain for proof verification across
    /// target updates.
    pub max_retained_roots: usize,
}

/// A [`ManagedDb`] with a startup state-sync entrypoint.
pub trait StateSyncDb<E, R>: ManagedDb<E> {
    /// Error returned by the state-sync engine for this database.
    type SyncError: Debug + Send;

    /// Run state-sync for this database and return a fully-initialized instance.
    #[allow(clippy::too_many_arguments)]
    fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
        progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> impl Future<Output = Result<Self, Self::SyncError>> + Send;
}

/// Block-height and digest pair identifying the block that produced a set
/// of sync targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor<D: Digest> {
    /// Height of the anchoring block.
    pub height: Height,
    /// Digest of the anchoring block.
    pub digest: D,
}

/// A [`DatabaseSet`] that can run one-time startup state sync.
///
/// `D` is the block digest type. Each set of sync targets is paired
/// with an [`Anchor`] identifying the block that produced those targets.
/// On convergence, `sync` returns the anchor that all databases agreed on.
pub trait StateSyncSet<E, R, D>: DatabaseSet<E>
where
    D: Digest,
{
    /// Error returned if any database in the set fails startup state-sync.
    type Error: Debug + Send;

    /// Run one-time startup state-sync and return the initialized set
    /// together with the anchor all databases converged on.
    fn sync(
        context: E,
        config: Self::Config,
        resolvers: R,
        anchor: Anchor<D>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<(Anchor<D>, Self::SyncTargets)>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<(Self, Anchor<D>), Self::Error>> + Send;
}

/// Implement [`DatabaseSet`] for a single [`ManagedDb`] behind a lock.
impl<E: Clone + Send + Sync, T: ManagedDb<E> + 'static> DatabaseSet<E> for Arc<AsyncRwLock<T>> {
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;
    type Config = T::Config;
    type SyncTargets = T::SyncTarget;

    async fn init(context: E, config: Self::Config) -> Self {
        let db = T::init(context, config)
            .await
            .expect("database init failed");
        Self::new(AsyncRwLock::new(db))
    }

    async fn new_batches(&self) -> Self::Unmerkleized {
        T::new_batch(self).await
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        parent.new_batch()
    }

    async fn finalize(&self, batches: Self::Merkleized) {
        let mut database = self.write().await;
        finalize_or_panic(&mut *database, batches, None).await;
    }

    async fn committed_targets(&self) -> Self::SyncTargets {
        let database = self.read().await;
        T::sync_target(&*database).await
    }

    async fn rewind_to_targets(&self, target: Self::SyncTargets) {
        let mut database = self.write().await;
        rewind_or_panic(&mut *database, target, None).await;
    }
}

impl<E, T, R, D> StateSyncSet<E, R, D> for Arc<AsyncRwLock<T>>
where
    E: Clone + Send + Sync + Metrics,
    T: StateSyncDb<E, R> + 'static,
    R: Send + 'static,
    D: Digest,
{
    type Error = T::SyncError;

    async fn sync(
        context: E,
        config: Self::Config,
        resolver: R,
        anchor: Anchor<D>,
        target: Self::SyncTargets,
        tip_updates: ring::Receiver<(Anchor<D>, Self::SyncTargets)>,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<D>), Self::Error> {
        let (target_tx, target_rx) = mpsc::channel(sync_config.update_channel_size.get());
        let (finish_tx, finish_rx) = mpsc::channel(1);
        let (reached_tx, mut reached_rx) = mpsc::channel(1);

        let metrics = sync_metrics::SyncMetrics::new(&context);
        metrics.record_target_height(0, anchor.height.get());
        let (progress_tx, progress_drain) = sync_metrics::progress_channel(metrics.clone(), 0);

        let sync = T::sync_db(
            context,
            config,
            resolver,
            target,
            target_rx,
            Some(finish_rx),
            Some(reached_tx),
            sync_config,
            Some(progress_tx),
        );

        let coordinator = async {
            let mut latest_anchor = anchor;
            let mut tip_updates = Some(tip_updates);
            loop {
                let update_future = tip_updates.as_mut().map_or_else(
                    || Either::Right(pending()),
                    |updates| Either::Left(updates.recv()),
                );
                select! {
                    _ = reached_rx.recv() => {
                        let _ = finish_tx.send_lossy(()).await;
                        return latest_anchor;
                    },
                    update = update_future => {
                        let Some((new_anchor, new_target)) = update else {
                            tip_updates = None;
                            continue;
                        };
                        // Sync targets must only move forward.
                        if new_anchor.height <= latest_anchor.height {
                            continue;
                        }
                        latest_anchor = new_anchor;
                        metrics.record_target_height(0, latest_anchor.height.get());
                        if !target_tx.send_lossy(new_target).await {
                            return latest_anchor;
                        }
                    },
                }
            }
        };

        let (db_result, converged_anchor, _) = join!(sync, coordinator, progress_drain);
        let database = db_result?;
        Ok((Self::new(AsyncRwLock::new(database)), converged_anchor))
    }
}

/// Implement [`DatabaseSet`] for a tuple of individually-locked
/// [`ManagedDb`] instances.
macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<E: Clone + Send + Sync + Metrics, $($T: ManagedDb<E> + 'static),+> DatabaseSet<E>
            for ($(Arc<AsyncRwLock<$T>>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);
            type Config = ($($T::Config,)+);
            type SyncTargets = ($($T::SyncTarget,)+);

            async fn init(context: E, config: Self::Config) -> Self {
                let result = join!($(
                    async {
                        let db = $T::init(
                                context.clone().with_label(concat!("db_", stringify!($idx))),
                                config.$idx,
                            )
                            .await
                            .expect(concat!(
                                "database init failed (index ",
                                stringify!($idx),
                                ", type ",
                                stringify!($T),
                                ")",
                            ));
                        Arc::new(AsyncRwLock::new(db))
                    },
                )+);
                result
            }

            async fn new_batches(&self) -> Self::Unmerkleized {
                join!($($T::new_batch(&self.$idx),)+)
            }

            fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
                ($(parent.$idx.new_batch(),)+)
            }

            async fn finalize(&self, batches: Self::Merkleized) {
                join!($(
                    async {
                        let mut database = self.$idx.write().await;
                        finalize_or_panic(&mut *database, batches.$idx, Some($idx)).await;
                    },
                )+);
            }

            async fn committed_targets(&self) -> Self::SyncTargets {
                join!($(
                    async {
                        let database = self.$idx.read().await;
                        $T::sync_target(&*database).await
                    },
                )+)
            }

            async fn rewind_to_targets(&self, targets: Self::SyncTargets) {
                join!($(
                    async {
                        let mut database = self.$idx.write().await;
                        rewind_or_panic(&mut *database, targets.$idx, Some($idx)).await;
                    },
                )+);
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

struct CoordinatorSyncSenders<T> {
    target_tx: mpsc::Sender<T>,
    finish_tx: mpsc::Sender<()>,
    generation_tx: mpsc::Sender<(usize, T)>,
}

macro_rules! impl_state_sync_set {
    ($($T:ident : $R:ident : $idx:tt),+) => {
        impl<E, D, $($T, $R),+> StateSyncSet<E, ($($R,)+), D> for ($(Arc<AsyncRwLock<$T>>,)+)
        where
            E: Clone + Send + Sync + Spawner + Metrics,
            D: Digest,
            $(
                $T: StateSyncDb<E, $R> + 'static,
                $R: Send + 'static,
            )+
        {
            type Error = String;

            async fn sync(
                context: E,
                config: Self::Config,
                resolvers: ($($R,)+),
                anchor: Anchor<D>,
                targets: Self::SyncTargets,
                tip_updates: ring::Receiver<(Anchor<D>, Self::SyncTargets)>,
                sync_config: SyncEngineConfig,
            ) -> Result<(Self, Anchor<D>), Self::Error> {
                let sync_metrics = sync_metrics::SyncMetrics::new(&context);
                $(sync_metrics.record_target_height($idx, anchor.height.get());)+
                let progress_channels = ($(
                    sync_metrics::progress_channel(sync_metrics.clone(), $idx),
                )+);
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
                let (reached_event_tx, mut reached_event_rx) = mpsc::channel(16);
                let (completion_tx, mut completion_rx) = mpsc::channel(1);
                let db_count = [$($idx,)+].len();
                let coordinator_targets = targets.clone();
                let first_db_error: Arc<commonware_utils::sync::Mutex<Option<String>>> =
                    Arc::new(commonware_utils::sync::Mutex::new(None));
                let coordinator_result: Arc<commonware_utils::sync::Mutex<Option<Anchor<D>>>> =
                    Arc::new(commonware_utils::sync::Mutex::new(None));
                let finish_coordinator = {
                    let coordinator_result = coordinator_result.clone();
                    let coord_metrics = sync_metrics;
                    async move {
                        // Keep ownership of the original per-database senders inside this task so
                        // they are dropped as soon as the coordinator exits.
                        let coordinator_owned_senders = coordinator_owned_senders;
                        let mut tip_updates = Some(tip_updates);
                        let mut state = CoordinatorState::new(db_count, anchor, coordinator_targets);

                        loop {
                            // Phase 1: Drain reached events.
                            loop {
                                match reached_event_rx.try_recv() {
                                    Ok((idx, generation)) => state.record_reached(idx, generation),
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => return,
                                }
                            }

                            // Phase 2: Drain tip updates; keep only the latest.
                            if let Some(updates) = tip_updates.as_mut() {
                                loop {
                                    match updates.try_recv() {
                                        Ok((a, t)) => state.record_tip_update(a, t),
                                        Err(ring::TryRecvError::Empty) => break,
                                        Err(ring::TryRecvError::Disconnected) => {
                                            tip_updates = None;
                                            break;
                                        }
                                    }
                                }
                            }

                            // Phase 3: Decide what to do.
                            match state.next_action() {
                                CoordinatorAction::Converged(anchor) => {
                                    $(
                                        let _ = coordinator_senders.$idx.finish_tx.send_lossy(()).await;
                                    )+
                                    *coordinator_result.lock() = Some(anchor);
                                    return;
                                }
                                CoordinatorAction::Dispatch {
                                    generation,
                                    targets: dispatch_targets,
                                } => {
                                    let dispatch_height = state.anchor_height(generation);
                                    $(
                                        if state.should_dispatch($idx) {
                                            coord_metrics.record_target_height($idx, dispatch_height);
                                            let dispatch_target = dispatch_targets.$idx.clone();
                                            if !coordinator_senders.$idx
                                                .generation_tx
                                                .send_lossy((generation, dispatch_target.clone()))
                                                .await
                                            {
                                                return;
                                            }
                                            if !coordinator_senders.$idx
                                                .target_tx
                                                .send_lossy(dispatch_target)
                                                .await
                                            {
                                                return;
                                            }
                                        }
                                    )+
                                    continue;
                                }
                                CoordinatorAction::Wait => {}
                            }

                            // Phase 4: Block until the next event.
                            let update_future = tip_updates.as_mut().map_or_else(
                                || Either::Right(pending()),
                                |updates| Either::Left(updates.recv()),
                            );
                            select! {
                                reached_event = reached_event_rx.recv() => {
                                    let Some((idx, generation)) = reached_event else {
                                        return;
                                    };
                                    state.record_reached(idx, generation);
                                },
                                _ = completion_rx.recv() => {
                                    // A database task completed (success or failure). Close all
                                    // outstanding per-database channels immediately so peers
                                    // waiting on `finish_rx` or `target_rx` can terminate.
                                    drop(coordinator_owned_senders);
                                    return;
                                },
                                update = update_future => {
                                    let Some((a, t)) = update else {
                                        tip_updates = None;
                                        continue;
                                    };
                                    state.record_tip_update(a, t);
                                },
                            };
                        }
                    }
                };
                let synced = join!(
                    $(
                        async {
                            let first_db_error = first_db_error.clone();
                            let mut reached_target_rx = db_channels.$idx.reached_rx;
                            let mut generation_rx = Some(db_channels.$idx.generation_rx);
                            let mut current_generation = 0usize;
                            let mut current_target = targets.$idx.clone();
                            let mut last_reached_target = None;
                            let mut last_reported_generation = None;
                            let reached_event_sender = reached_event_tx.clone();
                            let completion_signal = completion_tx.clone();
                            let sync = $T::sync_db(
                                context.clone().with_label(concat!("db_", stringify!($idx))),
                                config.$idx,
                                resolvers.$idx,
                                targets.$idx,
                                db_channels.$idx.target_rx,
                                Some(db_channels.$idx.finish_rx),
                                Some(db_channels.$idx.reached_tx),
                                sync_config,
                                Some(progress_channels.$idx.0),
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
                            let progress_drain = progress_channels.$idx.1;
                            let (sync_result, _, _) = join!(sync, forward_reached, progress_drain);
                            let result = sync_result
                                .map(|database| Arc::new(AsyncRwLock::new(database)))
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
                        },
                    )+
                    finish_coordinator,
                );

                if let Some(err) = first_db_error.lock().take() {
                    return Err(err);
                }

                let synced = ($(synced.$idx?,)+);
                let Some(converged_anchor) = coordinator_result.lock().take() else {
                    return Err("state sync coordinator did not report a converged anchor".into());
                };

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
        loop {
            match updates.try_recv() {
                Ok((generation, target)) => {
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
    Converged(Anchor<D>),
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

    /// Return the anchor height for a given generation.
    fn anchor_height(&self, generation: usize) -> u64 {
        let (anchor, _) = self
            .generation_state
            .get(&generation)
            .unwrap_or_else(|| panic!("missing state for dispatch generation {generation}"));
        anchor.height.get()
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

                let (anchor, _) = self
                    .generation_state
                    .get(&min_gen)
                    .expect("missing state for converged generation")
                    .clone();
                return CoordinatorAction::Converged(anchor);
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
            .retain(|gen, _| self.dbs.iter().any(|db| db.generation() == *gen));
    }

    /// Whether database `idx` is a non-reached recipient for dispatch.
    fn should_dispatch(&self, idx: usize) -> bool {
        !self.dbs[idx].is_reached()
    }
}

async fn finalize_or_panic<E, T: ManagedDb<E>>(
    database: &mut T,
    batch: T::Merkleized,
    index: Option<usize>,
) {
    // Mutable finalize failures are fatal by design because other databases in
    // the same set may already have committed, leaving partially applied state.
    if let Err(err) = database.finalize(batch).await {
        match index {
            Some(index) => panic!(
                "database finalize failed (index {index}, type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
            None => panic!(
                "database finalize failed (type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
        }
    }
}

async fn rewind_or_panic<E, T: ManagedDb<E>>(
    database: &mut T,
    target: T::SyncTarget,
    index: Option<usize>,
) {
    // Mutable rewind failures are fatal by design because the database handle
    // may be internally diverged after a failed rewind.
    if let Err(err) = database.rewind_to_target(target).await {
        match index {
            Some(index) => panic!(
                "database rewind failed (index {index}, type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
            None => panic!(
                "database rewind failed (type {}): {err:?}",
                core::any::type_name::<T>(),
            ),
        }
    }
}

/// A resolver that can attach a database at runtime.
///
/// Implementations receive a database handle after startup so they can
/// serve incoming sync requests once the database is initialized.
pub trait AttachableResolver<DB>: Clone + Send + Sync + 'static {
    /// Attach a database for serving incoming requests.
    fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) -> impl Future<Output = ()> + Send;
}

/// Attach a database set to a resolver set with matching shape.
pub trait AttachableResolverSet<DBs>: Clone + Send + Sync + 'static {
    /// Attach all databases to their corresponding resolvers.
    fn attach_databases(&self, databases: DBs) -> impl Future<Output = ()> + Send;
}

impl<R, DB> AttachableResolverSet<Arc<AsyncRwLock<DB>>> for R
where
    R: AttachableResolver<DB>,
    DB: Send + Sync + 'static,
{
    async fn attach_databases(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_database(db).await;
    }
}

macro_rules! impl_attachable_resolver_set {
    ($($R:ident : $DB:ident : $idx:tt),+) => {
        impl<$($R, $DB),+> AttachableResolverSet<($(Arc<AsyncRwLock<$DB>>,)+)> for ($($R,)+)
        where
            $(
                $R: AttachableResolver<$DB>,
                $DB: Send + Sync + 'static,
            )+
        {
            async fn attach_databases(&self, databases: ($(Arc<AsyncRwLock<$DB>>,)+)) {
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
        Anchor, AttachableResolver, AttachableResolverSet, CoordinatorAction, CoordinatorState,
        DatabaseSet, ManagedDb, Merkleized, StateSyncDb, StateSyncSet, SyncEngineConfig,
        SyncProgress, Unmerkleized,
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::sha256;
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Metrics as _, Runner as _, Spawner as _};
    use commonware_utils::{
        channel::{mpsc, oneshot, ring},
        sync::AsyncRwLock,
    };
    use futures::{pin_mut, FutureExt, SinkExt};
    use std::{
        convert::Infallible,
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[derive(Clone, Copy)]
    struct TestUnmerkleized;

    struct TestMerkleized;

    impl Unmerkleized for TestUnmerkleized {
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(TestMerkleized)
        }
    }

    impl Merkleized for TestMerkleized {
        type Digest = sha256::Digest;
        type Unmerkleized = TestUnmerkleized;

        fn root(&self) -> Self::Digest {
            sha256::Digest::from([0; 32])
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }
    }

    #[derive(Default)]
    struct TestDb;

    impl<E: Send> ManagedDb<E> for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            let _guard = db.read().await;
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
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

    struct FastSyncDb {
        final_target: u64,
    }

    struct ImmediateStateSyncDb;

    struct FailingStateSyncDb;

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

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Err(TestFinalizeError)
        }

        async fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for BlockingFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = ();

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("BlockingFinalizeDb is constructed directly in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.await;
            }
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for SlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("SlowSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for FastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FastSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for FailingStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FailingStateSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for ImmediateStateSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ImmediateStateSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for FinishClosedSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("FinishClosedSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedSlowSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ObservedSlowSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for ObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("ObservedFastSyncDb is only constructed through state sync in tests")
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl<E: Send> ManagedDb<E> for DistinctObservedFastSyncDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!(
                "DistinctObservedFastSyncDb is only constructed through state sync in tests"
            )
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.final_target
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
        ) -> Result<Self, Self::SyncError> {
            while !release.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);

            loop {
                if let Some(reached_target) = reached_target.as_ref() {
                    if reached_target.send(final_target).await.is_err() {
                        break;
                    }
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
                    update = update_signal => {
                        match update {
                            Some(update) => {
                                final_target = update;
                            }
                            None => {
                                tip_updates = None;
                                if finish.is_none() {
                                    break;
                                }
                            }
                        }
                    },
                }
            }

            Ok(Self { final_target })
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
        ) -> Result<Self, Self::SyncError> {
            done.store(true, Ordering::SeqCst);
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);

            loop {
                if let Some(reached_target) = reached_target.as_ref() {
                    if reached_target.send(final_target).await.is_err() {
                        break;
                    }
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
                    update = update_signal => {
                        match update {
                            Some(update) => {
                                final_target = update;
                            }
                            None => {
                                tip_updates = None;
                                if finish.is_none() {
                                    break;
                                }
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
        ) -> Result<Self, Self::SyncError> {
            Ok(Self)
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
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
                    loop {
                        match update_rx.try_recv() {
                            Ok(update) => {
                                final_target = update;
                                observed_update = true;
                                reported_target = None;
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
                    if let Some(reached_target) = reached_target.as_ref() {
                        if reached_target.send(final_target).await.is_err() {
                            break;
                        }
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
                    update = update_signal => {
                        match update {
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);
            let mut reported_target = None;
            observer.ready.store(true, Ordering::SeqCst);

            loop {
                if reported_target != Some(final_target) {
                    if let Some(reached_target) = reached_target.as_ref() {
                        if reached_target.send(final_target).await.is_err() {
                            break;
                        }
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
                    update = update_signal => {
                        match update {
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
            _progress_tx: Option<mpsc::Sender<SyncProgress>>,
        ) -> Result<Self, Self::SyncError> {
            let mut final_target = target;
            let mut tip_updates = Some(tip_updates);
            let mut reported_target = None;
            observer.ready.store(true, Ordering::SeqCst);

            loop {
                if reported_target != Some(final_target) {
                    if let Some(reached_target) = reached_target.as_ref() {
                        if reached_target.send(final_target).await.is_err() {
                            break;
                        }
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
                    update = update_signal => {
                        match update {
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
            let db1 = Arc::new(AsyncRwLock::new(TestDb));
            let db2 = Arc::new(AsyncRwLock::new(TestDb));
            let databases = (db1.clone(), db2.clone());

            let writer1 = db1.write().await;
            let writer2 = db2.write().await;

            let new_batches =
                <(Arc<AsyncRwLock<TestDb>>, Arc<AsyncRwLock<TestDb>>) as DatabaseSet<
                    deterministic::Context,
                >>::new_batches(&databases);
            pin_mut!(new_batches);
            assert!(new_batches.as_mut().now_or_never().is_none());

            drop(writer2);
            {
                let writer2_again = db2.write();
                pin_mut!(writer2_again);
                assert!(
                    writer2_again.as_mut().now_or_never().is_none(),
                    "tuple new_batches should queue reads for all databases concurrently"
                );
            }

            drop(writer1);
            let _ = new_batches.await;
        });
    }

    #[test]
    fn tuple_finalize_runs_databases_in_parallel() {
        deterministic::Runner::default().start(|_context| async move {
            let (started1_tx, started1_rx) = oneshot::channel();
            let (started2_tx, started2_rx) = oneshot::channel();
            let (release1_tx, release1_rx) = oneshot::channel();
            let (release2_tx, release2_rx) = oneshot::channel();

            let databases = (
                Arc::new(AsyncRwLock::new(BlockingFinalizeDb::new(
                    started1_tx,
                    release1_rx,
                ))),
                Arc::new(AsyncRwLock::new(BlockingFinalizeDb::new(
                    started2_tx,
                    release2_rx,
                ))),
            );

            let finalize = <(
                Arc<AsyncRwLock<BlockingFinalizeDb>>,
                Arc<AsyncRwLock<BlockingFinalizeDb>>,
            ) as DatabaseSet<deterministic::Context>>::finalize(
                &databases,
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
            finalize.await;
        });
    }

    #[test]
    fn tuple_finalize_panic_identifies_failing_database() {
        let panic = std::panic::catch_unwind(|| {
            deterministic::Runner::default().start(|_context| async move {
                let databases = (
                    Arc::new(AsyncRwLock::new(TestDb)),
                    Arc::new(AsyncRwLock::new(FailingFinalizeDb)),
                );
                <(
                    Arc<AsyncRwLock<TestDb>>,
                    Arc<AsyncRwLock<FailingFinalizeDb>>,
                ) as DatabaseSet<deterministic::Context>>::finalize(
                    &databases,
                    (TestMerkleized, TestMerkleized),
                )
                .await;
            });
        })
        .expect_err("tuple finalize should panic when a database finalize fails");

        let panic = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&'static str>().copied())
            .expect("panic should be a string");
        assert!(
            panic.contains("index 1"),
            "panic should identify the failing database index: {panic}"
        );
        assert!(
            panic.contains("FailingFinalizeDb"),
            "panic should identify the failing database type: {panic}"
        );
    }

    type TestAnchor = Anchor<sha256::Digest>;

    fn anchor(n: u64) -> TestAnchor {
        Anchor {
            height: Height::new(n),
            digest: sha256::Digest::from([n as u8; 32]),
        }
    }

    #[test]
    fn single_state_sync_handles_closed_tip_updates_channel() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());
            let release = Arc::new(AtomicBool::new(false));
            let release_for_sync = release.clone();

            let sync = context
                .clone()
                .with_label("single_state_sync_closed_tip_updates")
                .spawn(move |context| async move {
                    <Arc<AsyncRwLock<SlowSyncDb>> as StateSyncSet<
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
                            apply_batch_size: 1,
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(1).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                });

            drop(tip_tx);
            context.sleep(Duration::from_millis(1)).await;
            release.store(true, Ordering::SeqCst);

            let (_database, converged_anchor) = sync.await.expect("sync task should complete");
            assert_eq!(converged_anchor, anchor(0));
        });
    }

    #[test]
    fn single_state_sync_ignores_backward_tip_updates() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let release = Arc::new(AtomicBool::new(true));
            let resolver = SlowSyncController {
                release: release.clone(),
            };

            let sync = context
                .clone()
                .with_label("single_state_sync_ignores_backward_tip_updates")
                .spawn(move |context| async move {
                    <Arc<AsyncRwLock<ObservedSlowSyncDb>> as StateSyncSet<
                        deterministic::Context,
                        SlowSyncController,
                        sha256::Digest,
                    >>::sync(
                        context,
                        (),
                        resolver,
                        anchor(0),
                        0,
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: 1,
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("single state sync should succeed")
                });

            let _ = tip_tx.send((anchor(2), 2)).await;
            let _ = tip_tx.send((anchor(1), 1)).await;
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
    fn tuple_state_sync_converges_before_finish() {
        deterministic::Runner::default().start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_done = Arc::new(AtomicBool::new(false));

            let slow_release_for_sync = slow_release.clone();
            let fast_done_for_sync = fast_done.clone();
            let sync = context.clone().with_label("tuple_state_sync").spawn(
                move |context| async move {
                    <(Arc<AsyncRwLock<SlowSyncDb>>, Arc<AsyncRwLock<FastSyncDb>>) as StateSyncSet<
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
                            apply_batch_size: 1,
                            max_outstanding_requests: 1,
                            update_channel_size: NonZeroUsize::new(4).unwrap(),
                            max_retained_roots: 0,
                        },
                    )
                    .await
                    .expect("tuple state sync should succeed")
                },
            );

            while !fast_done.load(Ordering::SeqCst) {
                context.sleep(Duration::from_millis(1)).await;
            }
            let _ = tip_tx.send((anchor(1), (1, 1))).await;
            let _ = tip_tx.send((anchor(2), (2, 2))).await;
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
                .clone()
                .with_label("tuple_state_sync_ignores_backward_tip_updates")
                .spawn(move |context| async move {
                    <(Arc<AsyncRwLock<SlowSyncDb>>, Arc<AsyncRwLock<FastSyncDb>>) as StateSyncSet<
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
                            apply_batch_size: 1,
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

            let _ = tip_tx.send((anchor(2), (2, 2))).await;
            let _ = tip_tx.send((anchor(1), (1, 1))).await;
            drop(tip_tx);
            context.sleep(Duration::from_millis(1)).await;
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
    fn tuple_state_sync_returns_db_error_instead_of_panicking_when_anchor_missing() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (_tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(1).unwrap());

            let result = <(
                Arc<AsyncRwLock<ImmediateStateSyncDb>>,
                Arc<AsyncRwLock<FailingStateSyncDb>>,
            ) as StateSyncSet<deterministic::Context, ((), ()), sha256::Digest>>::sync(
                context,
                ((), ()),
                ((), ()),
                anchor(0),
                (0, 0),
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NonZeroU64::new(1).unwrap(),
                    apply_batch_size: 1,
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

            let result = <(
                Arc<AsyncRwLock<SlowSyncDb>>,
                Arc<AsyncRwLock<FailingStateSyncDb>>,
            ) as StateSyncSet<
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
                    apply_batch_size: 1,
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

            let result = <(
                Arc<AsyncRwLock<FinishClosedSyncDb>>,
                Arc<AsyncRwLock<FailingStateSyncDb>>,
            ) as StateSyncSet<deterministic::Context, ((), ()), sha256::Digest>>::sync(
                context,
                ((), ()),
                ((), ()),
                anchor(0),
                (0, 0),
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NonZeroU64::new(1).unwrap(),
                    apply_batch_size: 1,
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
                "error should include failing database index, got: {err}",
            );
            assert!(
                err.contains("FailingStateSyncDb"),
                "error should include failing database type, got: {err}",
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
            CoordinatorAction::Converged(anchor) => {
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
            CoordinatorAction::Converged(anchor) => {
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
            CoordinatorAction::Converged(anchor) => {
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
            CoordinatorAction::Converged(anchor) => {
                panic!("coordinator should not converge with a pending tip: {anchor:?}")
            }
        }
    }

    #[test]
    #[should_panic(expected = "missing state for dispatch generation 1")]
    fn coordinator_anchor_height_panics_on_missing_generation_state() {
        let mut state = CoordinatorState::new(2, anchor(0), (0u64, 0u64));
        state.record_tip_update(anchor(1), (1, 1));
        let action = state.next_action();
        assert!(matches!(
            action,
            CoordinatorAction::Dispatch { generation: 1, .. }
        ));
        state.generation_state.remove(&1);
        let _ = state.anchor_height(1);
    }

    #[test]
    fn tuple_state_sync_stops_updates_after_reached_until_regroup() {
        deterministic::Runner::default().start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(32).unwrap());
            let slow_release = Arc::new(AtomicBool::new(true));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let slow_resolver = SlowSyncController {
                release: slow_release.clone(),
            };
            let fast_resolver = FastSyncObserver {
                ready: fast_ready.clone(),
                update_count: fast_update_count.clone(),
            };
            let sync = context.clone().with_label("tuple_state_sync_algorithm").spawn(
                move |context| async move {
                    <(
                        Arc<AsyncRwLock<ObservedSlowSyncDb>>,
                        Arc<AsyncRwLock<ObservedFastSyncDb>>,
                    ) as StateSyncSet<
                        deterministic::Context,
                        (SlowSyncController, FastSyncObserver),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_resolver, fast_resolver),
                        anchor(0),
                        (0, 0),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: 1,
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
                let _ = tip_tx.send((anchor(target), (target, target))).await;
            }
            drop(tip_tx);

            let (synced, converged_anchor) = sync.await.expect("sync task should complete");
            let slow_target = synced.0.read().await.final_target;
            let fast_target = synced.1.read().await.final_target;

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

            let sync = context.clone().with_label("tuple_state_sync_noop").spawn({
                let slow_resolver = slow_release.clone();
                let fast_resolver = FastSyncObserver {
                    ready: fast_ready.clone(),
                    update_count: fast_update_count.clone(),
                };
                move |context| async move {
                    <(
                        Arc<AsyncRwLock<SlowSyncDb>>,
                        Arc<AsyncRwLock<ObservedFastSyncDb>>,
                    ) as StateSyncSet<
                        deterministic::Context,
                        (Arc<AtomicBool>, FastSyncObserver),
                        sha256::Digest,
                    >>::sync(
                        context,
                        ((), ()),
                        (slow_resolver, fast_resolver),
                        anchor(target),
                        (target, target),
                        tip_rx,
                        SyncEngineConfig {
                            fetch_batch_size: NonZeroU64::new(1).unwrap(),
                            apply_batch_size: 1,
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
    fn tuple_state_sync_regroup_completes_when_database_target_is_unchanged() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut tip_tx, tip_rx) = ring::channel(NonZeroUsize::new(4).unwrap());
            let slow_release = Arc::new(AtomicBool::new(false));
            let fast_ready = Arc::new(AtomicBool::new(false));
            let fast_update_count = Arc::new(AtomicUsize::new(0));

            let sync = context
                .clone()
                .with_label("tuple_state_sync_regroup_unchanged_target")
                .spawn({
                    let slow_resolver = slow_release.clone();
                    let fast_resolver = FastSyncObserver {
                        ready: fast_ready.clone(),
                        update_count: fast_update_count.clone(),
                    };
                    move |context| async move {
                        <(
                            Arc<AsyncRwLock<SlowSyncDb>>,
                            Arc<AsyncRwLock<DistinctObservedFastSyncDb>>,
                        ) as StateSyncSet<
                            deterministic::Context,
                            (Arc<AtomicBool>, FastSyncObserver),
                            sha256::Digest,
                        >>::sync(
                            context,
                            ((), ()),
                            (slow_resolver, fast_resolver),
                            anchor(0),
                            (0, 7),
                            tip_rx,
                            SyncEngineConfig {
                                fetch_batch_size: NonZeroU64::new(1).unwrap(),
                                apply_batch_size: 1,
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

            let _ = tip_tx.send((anchor(9), (9, 7))).await;
            context.sleep(Duration::from_millis(1)).await;
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
                1,
                "the unchanged-target database should receive the regroup retarget exactly once",
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
        async fn attach_database(&self, _db: Arc<AsyncRwLock<DB>>) {
            self.log.lock().push(self.id);
        }
    }

    #[test]
    fn single_db_attach_calls_single_resolver() {
        deterministic::Runner::default().start(|_| async move {
            let log = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
            let resolver = RecordingResolver::new("db1", log.clone());
            let db = Arc::new(AsyncRwLock::new(AttachDb1));

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
                Arc::new(AsyncRwLock::new(AttachDb1)),
                Arc::new(AsyncRwLock::new(AttachDb2)),
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
                Arc::new(AsyncRwLock::new(AttachDb1)),
                Arc::new(AsyncRwLock::new(AttachDb2)),
            );

            resolvers.attach_databases(databases).await;
            assert_eq!(&*log.lock(), &["db1", "db2"]);
        });
    }
}
