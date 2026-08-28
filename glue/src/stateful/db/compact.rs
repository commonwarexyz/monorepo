//! [`ManagedDb`] implementations for compact QMDBs.

use crate::stateful::db::{
    BatchContext, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_compact_db,
};
use commonware_codec::Read as CodecRead;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        compact::{Config, Db, MerkleizedBatch, UnmerkleizedBatch, Variant, initial_root},
        sync,
    },
};
use commonware_utils::channel::mpsc;
use std::{ops::Deref, sync::Arc};

/// Wraps a compact batch before merkleization.
pub struct CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    pub(super) batch: UnmerkleizedBatch<F, H, O, S>,
    db: Shared<Db<F, E, O, H, S>>,
    metadata: Option<O::Metadata>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, O, H, S> Deref for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = UnmerkleizedBatch<F, H, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, O, H, S> CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    /// Set commit metadata included in the next merkleization.
    pub fn with_metadata(mut self, metadata: O::Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor included in the next merkleization.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }
}

impl<F, E, O, H, S> UnmerkleizedTrait for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self
            .batch
            .merkleize(
                &db,
                self.metadata,
                self.inactivity_floor.unwrap_or_default(),
            )
            .await;
        Ok(CompactMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Wraps a compact batch after merkleization.
pub struct CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, O, S>>,
    db: Shared<Db<F, E, O, H, S>>,
}

impl<F, E, O, H, S> Clone for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, O, H, S> Deref for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = MerkleizedBatch<F, H::Digest, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, O, H, S> MerkleizedTrait for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        CompactUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, O, H, S> ManagedDb<E> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
    type Error = Error<F>;
    type Config = Config<<O as CodecRead>::Cfg, S>;
    type SyncTarget = sync::CompactTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::CompactTarget {
            root: initial_root::<F, O, H>(),
            size: Location::new(1),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CompactUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.size == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.size).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.size).await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

impl<F, E, O, H, S, R> StateSyncDb<E, R> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context + Spawner,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
    R: sync::SourceFor<Self>,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        source: R,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync_compact_db(
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
