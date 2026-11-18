//! [`ManagedDb`] and [`StateSyncDb`] implementations for QMDB databases.
//!
//! Every database that implements [`Qmdb`] gets both traits. Batches add family-specific methods
//! to [`Unmerkleized`] and [`Merkleized`]:
//!
//! - [`any`](commonware_storage::qmdb::any) and [`current`](commonware_storage::qmdb::current)
//!   batches upsert and delete keys (`write`), read them (`get`, `get_many`), and stage reads
//!   (`stage`).
//! - [`immutable`](commonware_storage::qmdb::immutable) batches accept new keyed values (`set`)
//!   but no updates or deletions.
//! - [`keyless`](commonware_storage::qmdb::keyless) batches are append-only (`append`) and read
//!   operations by location rather than by key.
//! - [`compact`](commonware_storage::qmdb::compact) databases retain only the current Merkle
//!   peaks. Their batches `append` (keyless operations) or `set` (immutable operations) and
//!   merkleize, but support no historical reads.
//!
//! Batch reads consult the database at the time of the read for data their batch chain does not
//! hold, and return a `StaleRead` error once the database is at no state of that chain.

use super::{
    BatchContext, InitError, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized as UnmerkleizedTrait, validate_initialization,
};
use commonware_runtime::Handle;
use commonware_storage::qmdb::{
    Error,
    sync::{self, MerkleizedBatch as _},
};
use commonware_utils::channel::{mpsc, ring};
use std::{future::Future, ops::Deref, sync::Arc};

/// A QMDB database that glue can manage and state-sync.
pub trait Qmdb: sync::Database<Config: Send> + Sync {
    /// Storage batch before merkleization.
    type Batch: Send;

    /// Storage batch after merkleization.
    type MerkleizedBatch: sync::MerkleizedBatch<Family = Self::Family, Digest = Self::Digest>
        + Send
        + Sync;

    /// Batch rooted at the applied state.
    fn new_batch(&self) -> Self::Batch;

    /// Batch rooted at `parent`.
    fn new_child(parent: &Arc<Self::MerkleizedBatch>) -> Self::Batch;

    /// Merkleize `batch` against the applied state.
    fn merkleize(
        &self,
        batch: Self::Batch,
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
}

/// A [`Qmdb`] batch before merkleization, reading through to its database's applied state.
pub struct Unmerkleized<D: Qmdb> {
    pub(super) batch: D::Batch,
    pub(super) db: Shared<D>,
}

impl<D: Qmdb> Deref for Unmerkleized<D> {
    type Target = D::Batch;

    fn deref(&self) -> &D::Batch {
        &self.batch
    }
}

impl<D: Qmdb> UnmerkleizedTrait for Unmerkleized<D> {
    type Merkleized = Merkleized<D>;
    type Error = Error<D::Family>;

    async fn merkleize(self) -> Result<Merkleized<D>, Error<D::Family>> {
        let Self { batch, db } = self;
        let inner = {
            let guard = db.read().await;
            guard.merkleize(batch).await?
        };
        Ok(Merkleized { inner, db })
    }
}

/// A [`Qmdb`] batch after merkleization, reading through to its database's applied state.
pub struct Merkleized<D: Qmdb> {
    pub(super) inner: Arc<D::MerkleizedBatch>,
    pub(super) db: Shared<D>,
}

impl<D: Qmdb> Merkleized<D> {
    /// Sync target reached once this batch is applied.
    pub fn target(&self) -> sync::Target<D::Family, D::Digest> {
        self.inner.target()
    }
}

impl<D: Qmdb> Clone for Merkleized<D> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
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
            batch: D::new_child(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<D: Qmdb> ManagedDb<D::Context> for D {
    type Unmerkleized = Unmerkleized<D>;
    type Merkleized = Merkleized<D>;
    type Error = Error<D::Family>;
    type Config = D::Config;
    type SyncTarget = sync::Target<D::Family, D::Digest>;

    async fn init(
        context: D::Context,
        config: D::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Self::Error, Self::SyncTarget>> {
        let db = <D as sync::Database>::init(
            context,
            config,
            expected.as_ref().map(|target| target.range.end()),
        )
        .await
        .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        D::initial_target()
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Unmerkleized<D> {
        let (database, shared) = database.into_parts();
        Unmerkleized {
            batch: Qmdb::new_batch(database),
            db: shared,
        }
    }

    fn matches_sync_target(batch: &Merkleized<D>, target: &Self::SyncTarget) -> bool {
        batch.target() == *target
    }

    async fn apply(self, batch: Merkleized<D>) -> Result<Self, Error<D::Family>> {
        Qmdb::apply_batch(self, batch.inner).await
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<D::Family>> {
        Qmdb::start_sync(self).await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<D::Family>> {
        sync::Database::prune_to_target(self, target).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        sync::Database::target(self)
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
        target: Self::SyncTarget,
        tip_updates: ring::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<ring::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::sync(sync::Config {
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
}
