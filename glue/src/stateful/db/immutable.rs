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
use commonware_codec::{Codec, EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    journal::{
        contiguous::{
            fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Mutable,
        },
        Error as JournalError,
    },
    mmr,
    qmdb::{
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        immutable::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            fixed, variable, Immutable, Operation,
        },
        operation::Key,
        sync::{self, resolver::Resolver, SyncProgress},
        Error,
    },
    translator::Translator,
    Persistable,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock, Array};
use std::{ops::Deref, sync::Arc};

type ImmutableDbHandle<E, K, V, C, H, T> =
    Arc<AsyncRwLock<Immutable<mmr::Family, E, K, V, C, H, T>>>;

/// Wraps an immutable [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct ImmutableUnmerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<mmr::Family, H, K, V>,
    db: ImmutableDbHandle<E, K, V, C, H, T>,
    metadata: Option<V::Value>,
}

impl<E, K, V, C, H, T> Deref for ImmutableUnmerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<mmr::Family, H, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E, K, V, C, H, T> ImmutableUnmerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    /// Read multiple values by key, amortizing lock acquisition and journal I/O.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &*db).await
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an immutable [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct ImmutableMerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<mmr::Family, H::Digest, K, V>>,
    db: ImmutableDbHandle<E, K, V, C, H, T>,
}

impl<E, K, V, C, H, T> Deref for ImmutableMerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    type Target = MerkleizedBatch<mmr::Family, H::Digest, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<E, K, V, C, H, T> ImmutableMerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.inner.get(key, &*db).await
    }

    /// Read multiple values by key, amortizing lock acquisition and journal I/O.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &*db).await
    }
}

impl<E, K, V, C, H, T> UnmerkleizedTrait for ImmutableUnmerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    type Merkleized = ImmutableMerkleized<E, K, V, C, H, T>;
    type Error = Error<mmr::Family>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<mmr::Family>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata);
        Ok(ImmutableMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<E, K, V, C, H, T> MerkleizedTrait for ImmutableMerkleized<E, K, V, C, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<K, V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnmerkleized<E, K, V, C, H, T>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

impl<E, K, V, H, T> ManagedDb<E> for fixed::Db<mmr::Family, E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
{
    type Unmerkleized = ImmutableUnmerkleized<
        E,
        K,
        FixedEncoding<V>,
        FixedJournal<E, fixed::Operation<K, V>>,
        H,
        T,
    >;
    type Merkleized =
        ImmutableMerkleized<E, K, FixedEncoding<V>, FixedJournal<E, fixed::Operation<K, V>>, H, T>;
    type Error = Error<mmr::Family>;
    type Config = fixed::Config<T>;
    type SyncTarget = sync::Target<mmr::Family, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<mmr::Family>> {
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

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<mmr::Family>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<mmr::Family>> {
        self.rewind(target.range.end()).await?;
        self.sync().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}

impl<E, K, V, H, T> ManagedDb<E> for variable::Db<mmr::Family, E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    variable::Operation<K, V>: Codec,
{
    type Unmerkleized = ImmutableUnmerkleized<
        E,
        K,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<K, V>>,
        H,
        T,
    >;
    type Merkleized = ImmutableMerkleized<
        E,
        K,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<K, V>>,
        H,
        T,
    >;
    type Error = Error<mmr::Family>;
    type Config = variable::Config<T, <variable::Operation<K, V> as CodecRead>::Cfg>;
    type SyncTarget = sync::Target<mmr::Family, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<mmr::Family>> {
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

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<mmr::Family>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<mmr::Family>> {
        self.rewind(target.range.end()).await?;
        self.sync().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R> for fixed::Db<mmr::Family, E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    R: Resolver<Family = mmr::Family, Op = fixed::Operation<K, V>, Digest = H::Digest>,
{
    type SyncError = sync::Error<mmr::Family, R::Error, H::Digest>;

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

impl<E, K, V, H, T, R> StateSyncDb<E, R> for variable::Db<mmr::Family, E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    variable::Operation<K, V>: Codec,
    R: Resolver<Family = mmr::Family, Op = variable::Operation<K, V>, Digest = H::Digest>,
{
    type SyncError = sync::Error<mmr::Family, R::Error, H::Digest>;

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
