//! [`ManagedDb`] implementation for QMDB [`immutable`](commonware_storage::qmdb::immutable)
//! databases.
//!
//! Immutable databases support adding new keyed values but not updates or
//! deletions. The wrapper types here capture `Arc<AsyncRwLock<Immutable>>`
//! so the batch API can read through to committed state.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{Codec, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    qmdb::{
        any::VariableValue,
        immutable::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            Config, Immutable, Operation,
        },
        sync::{self, resolver::Resolver, SyncProgress},
        Error,
    },
    translator::Translator,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock, Array};
use std::{ops::Deref, sync::Arc};

type ImmutableDbHandle<E, K, V, H, T> = Arc<AsyncRwLock<Immutable<E, K, V, H, T>>>;

/// Wraps an immutable [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct ImmutableUnmerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    batch: UnmerkleizedBatch<H, K, V>,
    db: ImmutableDbHandle<E, K, V, H, T>,
    metadata: Option<V>,
}

impl<E, K, V, H, T> Deref for ImmutableUnmerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Target = UnmerkleizedBatch<H, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E, K, V, H, T> ImmutableUnmerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }
}

/// Wraps an immutable [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct ImmutableMerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    batch: MerkleizedBatch<H::Digest, K, V>,
    db: ImmutableDbHandle<E, K, V, H, T>,
}

impl<E, K, V, H, T> Deref for ImmutableMerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Target = MerkleizedBatch<H::Digest, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E, K, V, H, T> ImmutableMerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }
}

impl<E, K, V, H, T> UnmerkleizedTrait for ImmutableUnmerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Merkleized = ImmutableMerkleized<E, K, V, H, T>;
    type Error = Error;

    async fn merkleize(self) -> Result<Self::Merkleized, Error> {
        Ok(ImmutableMerkleized {
            batch: self.batch.merkleize(self.metadata),
            db: self.db,
        })
    }
}

impl<E, K, V, H, T> MerkleizedTrait for ImmutableMerkleized<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnmerkleized<E, K, V, H, T>;

    fn root(&self) -> H::Digest {
        self.batch.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.batch.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

impl<E, K, V, H, T> ManagedDb<E> for Immutable<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    Operation<K, V>: Codec + CodecRead<Cfg = V::Cfg>,
{
    type Unmerkleized = ImmutableUnmerkleized<E, K, V, H, T>;
    type Merkleized = ImmutableMerkleized<E, K, V, H, T>;
    type Error = Error;
    // `Operation<K, V>::Cfg == V::Cfg` (see operation.rs), but the sync
    // `Database` trait associates `Config<T, V::Cfg>`. Use the projection
    // form here and add `V: CodecRead<Cfg = ...>` so both are satisfied.
    type Config = Config<T, V::Cfg>;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        ImmutableUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error> {
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error> {
        self.rewind(target.range.end()).await?;
        self.commit().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R> for Immutable<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    Operation<K, V>: Codec + CodecRead<Cfg = V::Cfg>,
    R: Resolver<Op = Operation<K, V>, Digest = H::Digest>,
{
    type SyncError = sync::Error<R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
        progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> Result<Self, Self::SyncError> {
        sync::sync(sync::engine::Config {
            context,
            resolver,
            target,
            max_outstanding_requests: sync_config.max_outstanding_requests,
            fetch_batch_size: sync_config.fetch_batch_size,
            apply_batch_size: sync_config.apply_batch_size,
            db_config: config,
            update_rx: Some(tip_updates),
            finish_rx: finish,
            reached_target_tx: reached_target,
            max_retained_roots: sync_config.max_retained_roots,
            progress_tx,
        })
        .await
    }
}
