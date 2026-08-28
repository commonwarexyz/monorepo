//! [`ManagedDb`] and [`StateSyncDb`] implementations for QMDB databases.

use super::{
    BatchContext, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb, SyncEngineConfig,
    SyncSession, Unmerkleized as UnmerkleizedTrait,
};
use commonware_runtime::Handle;
use commonware_storage::{
    merkle::Location,
    qmdb::{
        Error,
        sync::{self, MerkleizedBatch as _},
    },
};
use std::{future::Future, ops::Deref, sync::Arc};

/// A QMDB database that glue can manage and state-sync.
pub trait Qmdb: sync::Database<Config: Send> + Sync {
    /// Storage batch before merkleization.
    type Batch: Send;

    /// Storage batch after merkleization.
    type MerkleizedBatch: sync::MerkleizedBatch<
            Family = Self::Family,
            Digest = Self::Digest,
            Unmerkleized<Self::Hasher> = Self::Batch,
        > + Send
        + Sync;

    /// Commit metadata carried by a batch.
    type Metadata: Send;

    /// `Option<Location<..>>` where a batch may set the inactivity floor, `()` where storage
    /// derives it.
    type Floor: Default + Send;

    /// Batch rooted at the applied state.
    fn new_batch(&self) -> Self::Batch;

    /// Merkleize `batch` against the applied state.
    fn merkleize(
        &self,
        batch: Self::Batch,
        metadata: Option<Self::Metadata>,
        floor: Self::Floor,
    ) -> impl Future<Output = Result<Arc<Self::MerkleizedBatch>, Error<Self::Family>>> + Send;

    /// Apply a merkleized batch.
    fn apply_batch(
        self,
        batch: Arc<Self::MerkleizedBatch>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Begin persisting every applied batch. The handle resolves once they are durable.
    fn start_sync(
        self,
    ) -> impl Future<Output = Result<(Self, Handle<()>), Error<Self::Family>>> + Send;

    /// Prune history `target` no longer needs.
    fn prune(
        self,
        target: &sync::Target<Self::Family, Self::Digest>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Rewind to `size` operations. Durable on return.
    fn rewind(
        self,
        size: Location<Self::Family>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;
}

/// A [`Qmdb`] batch before merkleization, reading through to its database's applied state.
pub struct Unmerkleized<D: Qmdb> {
    pub(super) batch: D::Batch,
    pub(super) db: Shared<D>,
    pub(super) metadata: Option<D::Metadata>,
    pub(super) floor: D::Floor,
}

impl<D: Qmdb> Deref for Unmerkleized<D> {
    type Target = D::Batch;

    fn deref(&self) -> &D::Batch {
        &self.batch
    }
}

impl<D: Qmdb> Unmerkleized<D> {
    /// Set commit metadata included in the next [`merkleize`](UnmerkleizedTrait::merkleize).
    pub fn with_metadata(mut self, metadata: D::Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl<D> Unmerkleized<D>
where
    D: Qmdb<Floor = Option<Location<<D as sync::Database>::Family>>>,
{
    /// Set the inactivity floor included in the next [`merkleize`](UnmerkleizedTrait::merkleize).
    /// When unset, the commit records floor 0.
    pub const fn with_inactivity_floor(mut self, floor: Location<D::Family>) -> Self {
        self.floor = Some(floor);
        self
    }
}

impl<D: Qmdb> UnmerkleizedTrait for Unmerkleized<D> {
    type Merkleized = Merkleized<D>;
    type Error = Error<D::Family>;

    async fn merkleize(self) -> Result<Merkleized<D>, Error<D::Family>> {
        let Self {
            batch,
            db,
            metadata,
            floor,
        } = self;
        let inner = {
            let guard = db.read().await;
            guard.merkleize(batch, metadata, floor).await?
        };
        Merkleized::new(inner, db)
    }
}

/// A [`Qmdb`] batch after merkleization, reading through to its database's applied state.
pub struct Merkleized<D: Qmdb> {
    pub(super) inner: Arc<D::MerkleizedBatch>,
    pub(super) db: Shared<D>,
    target: sync::Target<D::Family, D::Digest>,
}

impl<D: Qmdb> Merkleized<D> {
    /// Wrap a merkleized storage batch, failing if it reaches no sync target.
    pub(super) fn new(
        inner: Arc<D::MerkleizedBatch>,
        db: Shared<D>,
    ) -> Result<Self, Error<D::Family>> {
        let target = inner.target()?;
        Ok(Self { inner, db, target })
    }

    /// Sync target reached once this batch is applied.
    pub fn target(&self) -> sync::Target<D::Family, D::Digest> {
        self.target.clone()
    }
}

impl<D: Qmdb> Clone for Merkleized<D> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
            target: self.target.clone(),
        }
    }
}

impl<D: Qmdb> Deref for Merkleized<D> {
    type Target = D::MerkleizedBatch;

    fn deref(&self) -> &D::MerkleizedBatch {
        &self.inner
    }
}

impl<D: Qmdb> MerkleizedTrait for Merkleized<D> {
    type Digest = D::Digest;
    type Unmerkleized = Unmerkleized<D>;

    fn root(&self) -> D::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Unmerkleized<D> {
        Unmerkleized {
            batch: self.inner.new_batch::<D::Hasher>(),
            db: self.db.clone(),
            metadata: None,
            floor: D::Floor::default(),
        }
    }
}

impl<D: Qmdb> ManagedDb<D::Context> for D {
    type Unmerkleized = Unmerkleized<D>;
    type Merkleized = Merkleized<D>;
    type Error = Error<D::Family>;
    type Config = D::Config;
    type SyncTarget = sync::Target<D::Family, D::Digest>;

    async fn init(context: D::Context, config: D::Config) -> Result<Self, Error<D::Family>> {
        D::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        D::initial_target()
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Unmerkleized<D> {
        let (database, shared) = database.into_parts();
        Unmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            floor: D::Floor::default(),
        }
    }

    fn matches_sync_target(batch: &Merkleized<D>, target: &Self::SyncTarget) -> bool {
        batch.target == *target
    }

    async fn apply(self, batch: Merkleized<D>) -> Result<Self, Error<D::Family>> {
        self.apply_batch(batch.inner).await
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<D::Family>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<D::Family>> {
        Qmdb::prune(self, target).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<D::Family>> {
        let db = self.rewind(target.range.end()).await?;
        if db.target() != target {
            return Err(Error::DataCorrupted("rewound database target mismatch"));
        }
        Ok(db)
    }
}

impl<D, R> StateSyncDb<D::Context, R> for D
where
    D: Qmdb,
    R: sync::SourceFor<D>,
{
    type SyncError = sync::Error<D::Family, R::Error, D::Digest>;

    async fn sync_db(
        context: D::Context,
        config: D::Config,
        source: R,
        session: SyncSession<Self::SyncTarget>,
        limits: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::sync(sync::engine::Config {
            context,
            source,
            target: session.target,
            max_outstanding_requests: limits.max_outstanding_requests,
            fetch_batch_size: limits.fetch_batch_size,
            apply_batch_size: limits.apply_batch_size,
            db_config: config,
            update_rx: Some(session.tip_updates),
            finish_rx: session.finish,
            reached_target_tx: session.reached_target,
            max_retained_roots: limits.max_retained_roots,
        })
        .await
    }
}
