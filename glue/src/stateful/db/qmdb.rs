//! Adapters from QMDB databases to [`ManagedDb`] and [`StateSyncDb`].
//!
//! Each QMDB database type implements [`Qmdb`] once, stating how it opens, wraps a
//! fresh batch, measures a [`Checkpoint`], and persists. The blanket impls here
//! derive [`ManagedDb`] and [`StateSyncDb`] from that. The split between databases
//! with a durable operation log (range targets) and compact databases (root plus
//! size targets) lives in [`SyncTarget`].

use super::{
    BatchContext, ManagedDb, Merkleized, Shared, StateSyncDb, SyncEngineConfig, Unmerkleized,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_runtime::{Handle, Metrics, Spawner, Supervisor as _};
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::{Error, sync},
};
use commonware_utils::{channel::mpsc, non_empty_range};
use std::{fmt::Debug, future::Future};

/// What a sync target measures about an applied state.
pub struct Checkpoint<F: Family, D: Digest> {
    /// State root.
    pub root: D,
    /// Location retained history is served from (the sync boundary).
    pub boundary: Location<F>,
    /// Number of operations.
    pub size: Location<F>,
}

/// Sync-target arithmetic of a database family.
///
/// Implemented for [`sync::Target`] (databases with a durable operation log) and
/// [`sync::CompactTarget`] (databases that retain only the current Merkle peaks).
pub trait SyncTarget<F: Family, D: Digest>:
    Clone + Debug + PartialEq + Send + Sync + Sized + 'static
{
    /// Target of a freshly initialized database whose root is `root`.
    fn initial(root: D) -> Self;

    /// Target reached by `checkpoint`.
    fn of(checkpoint: Checkpoint<F, D>) -> Self;

    /// Whether `checkpoint` reaches this target.
    fn matches(&self, checkpoint: &Checkpoint<F, D>) -> bool;

    /// Location pruning to this target retains from.
    fn prune_boundary(&self) -> Location<F>;

    /// Operation count of this target.
    fn size(&self) -> Location<F>;

    /// Sync a database to `target` from `source`, following `tip_updates`.
    #[allow(clippy::too_many_arguments)]
    fn sync<DB, S>(
        context: DB::Context,
        config: DB::Config,
        source: S,
        target: Self,
        tip_updates: mpsc::Receiver<Self>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self>>,
        sync_config: SyncEngineConfig,
    ) -> impl Future<Output = Result<DB, sync::Error<F, S::Error, D>>> + Send
    where
        DB: Qmdb<Family = F, Digest = D>,
        DB::Context: Metrics + Spawner,
        S: sync::SourceFor<DB>;
}

impl<F: Family, D: Digest> SyncTarget<F, D> for sync::Target<F, D> {
    fn initial(root: D) -> Self {
        Self::new(root, non_empty_range!(Location::new(0), Location::new(1)))
    }

    fn of(checkpoint: Checkpoint<F, D>) -> Self {
        Self::new(
            checkpoint.root,
            non_empty_range!(checkpoint.boundary, checkpoint.size),
        )
    }

    fn matches(&self, checkpoint: &Checkpoint<F, D>) -> bool {
        self.root == checkpoint.root
            && self.range.start() == checkpoint.boundary
            && self.range.end() == checkpoint.size
    }

    fn prune_boundary(&self) -> Location<F> {
        self.range.start()
    }

    fn size(&self) -> Location<F> {
        self.range.end()
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync<DB, S>(
        context: DB::Context,
        config: DB::Config,
        source: S,
        target: Self,
        tip_updates: mpsc::Receiver<Self>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self>>,
        sync_config: SyncEngineConfig,
    ) -> Result<DB, sync::Error<F, S::Error, D>>
    where
        DB: Qmdb<Family = F, Digest = D>,
        DB::Context: Metrics + Spawner,
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
}

/// Aborts an adapter task when its owning sync future completes or is cancelled.
struct Forwarder(Handle<()>);

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<F: Family, D: Digest> SyncTarget<F, D> for sync::CompactTarget<F, D> {
    fn initial(root: D) -> Self {
        Self {
            root,
            size: Location::new(1),
        }
    }

    fn of(checkpoint: Checkpoint<F, D>) -> Self {
        Self {
            root: checkpoint.root,
            size: checkpoint.size,
        }
    }

    fn matches(&self, checkpoint: &Checkpoint<F, D>) -> bool {
        self.root == checkpoint.root && self.size == checkpoint.size
    }

    fn prune_boundary(&self) -> Location<F> {
        self.size
    }

    fn size(&self) -> Location<F> {
        self.size
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync<DB, S>(
        context: DB::Context,
        config: DB::Config,
        source: S,
        target: Self,
        mut tip_updates: mpsc::Receiver<Self>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self>>,
        sync_config: SyncEngineConfig,
    ) -> Result<DB, sync::Error<F, S::Error, D>>
    where
        DB: Qmdb<Family = F, Digest = D>,
        DB::Context: Metrics + Spawner,
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
        let update_forwarder =
            Forwarder(context.child("compact_updates").spawn(move |_| async move {
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
            let (tx, mut rx) = mpsc::channel::<sync::Target<F, D>>(1);
            context.child("compact_reached").spawn(move |_| async move {
                while let Some(reached_engine_target) = rx.recv().await {
                    let target = Self {
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
}

/// A QMDB database adapted to the glue.
///
/// Implementing this derives [`ManagedDb`] and [`StateSyncDb`]. The context is
/// [`sync::Database::Context`], the one the database type is built for.
pub trait Qmdb: sync::Database<Config: Send, Op: Encode> + Sync {
    /// Wrapper around the family's unmerkleized batch.
    type Unmerkleized: Unmerkleized<Merkleized = Self::Merkleized, Error = Error<Self::Family>>;

    /// Wrapper around the family's merkleized batch.
    type Merkleized: Clone + Merkleized<Digest = Self::Digest, Unmerkleized = Self::Unmerkleized>;

    /// Sync target of the family.
    type SyncTarget: SyncTarget<Self::Family, Self::Digest>;

    /// Open the database.
    fn open(
        context: Self::Context,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Root of an empty database.
    fn initial_root() -> Self::Digest;

    /// Wrap a fresh batch rooted at the applied state, retaining `shared` for read-through.
    fn wrap_batch(&self, shared: Shared<Self>) -> Self::Unmerkleized;

    /// Measure the applied state.
    fn checkpoint(&self) -> Checkpoint<Self::Family, Self::Digest>;

    /// Measure the state `batch` produces once applied.
    fn batch_checkpoint(batch: &Self::Merkleized) -> Checkpoint<Self::Family, Self::Digest>;

    /// Apply a merkleized batch.
    fn apply_merkleized(
        self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Begin persisting every applied batch, reporting durability on the returned handle.
    fn persist(
        self,
    ) -> impl Future<Output = Result<(Self, Handle<()>), Error<Self::Family>>> + Send;

    /// Prune history before `boundary`.
    fn prune_to(
        self,
        boundary: Location<Self::Family>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Rewind to `size` operations. Durable on return.
    fn rewind_to(
        self,
        size: Location<Self::Family>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;
}

impl<D: Qmdb> ManagedDb<D::Context> for D {
    type Unmerkleized = <D as Qmdb>::Unmerkleized;
    type Merkleized = <D as Qmdb>::Merkleized;
    type Error = Error<D::Family>;
    type Config = <D as sync::Database>::Config;
    type SyncTarget = <D as Qmdb>::SyncTarget;

    async fn init(
        context: D::Context,
        config: <D as sync::Database>::Config,
    ) -> Result<Self, Error<D::Family>> {
        D::open(context, config).await
    }

    fn initial_sync_target() -> <D as Qmdb>::SyncTarget {
        SyncTarget::initial(D::initial_root())
    }

    fn new_batch(database: BatchContext<'_, Self>) -> <D as Qmdb>::Unmerkleized {
        let (database, shared) = database.into_parts();
        database.wrap_batch(shared)
    }

    fn matches_sync_target(
        batch: &<D as Qmdb>::Merkleized,
        target: &<D as Qmdb>::SyncTarget,
    ) -> bool {
        target.matches(&D::batch_checkpoint(batch))
    }

    async fn apply(self, batch: <D as Qmdb>::Merkleized) -> Result<Self, Error<D::Family>> {
        D::apply_merkleized(self, batch).await
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<D::Family>> {
        D::persist(self).await
    }

    async fn prune(self, target: &<D as Qmdb>::SyncTarget) -> Result<Self, Error<D::Family>> {
        D::prune_to(self, target.prune_boundary()).await
    }

    fn sync_target(&self) -> <D as Qmdb>::SyncTarget {
        SyncTarget::of(D::checkpoint(self))
    }

    async fn rewind_to_target(
        self,
        target: <D as Qmdb>::SyncTarget,
    ) -> Result<Self, Error<D::Family>> {
        let db = D::rewind_to(self, target.size()).await?;
        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

/// Every family requires a spawning context for state sync: compact targets run
/// adapter tasks that translate engine targets.
impl<D, R> StateSyncDb<D::Context, R> for D
where
    D: Qmdb,
    D::Context: Metrics + Spawner,
    R: sync::SourceFor<D>,
{
    type SyncError = sync::Error<D::Family, R::Error, D::Digest>;

    #[allow(clippy::too_many_arguments)]
    async fn sync_db(
        context: D::Context,
        config: <D as sync::Database>::Config,
        source: R,
        target: <D as Qmdb>::SyncTarget,
        tip_updates: mpsc::Receiver<<D as Qmdb>::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<<D as Qmdb>::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        SyncTarget::sync(
            context,
            config,
            source,
            target,
            tip_updates,
            finish,
            reached_target,
            sync_config,
        )
        .await
    }
}
