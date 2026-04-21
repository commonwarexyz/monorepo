//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to committed state. This module provides wrapper types
//! that capture `Arc<AsyncRwLock<Db>>` alongside the raw batch so the
//! [`Unmerkleized`](super::Unmerkleized) and [`Merkleized`](super::Merkleized)
//! traits can be implemented without a DB parameter.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{Codec, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::{
        unordered::Index as UnorderedIdx, Ordered as OrderedIndex, Unordered as UnorderedIndex,
    },
    journal::contiguous::{
        fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Contiguous, Mutable,
    },
    merkle::{Family, Location},
    qmdb::{
        any::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            operation::{Operation, Update},
            ordered, unordered,
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
            FixedConfig, VariableConfig,
        },
        operation::Key,
        sync::{self, resolver::Resolver, SyncProgress},
        Error,
    },
    translator::Translator,
    Persistable,
};
use commonware_utils::{
    channel::mpsc,
    non_empty_range,
    sync::{AsyncRwLock, AsyncRwLockReadGuard},
    Array,
};
use std::{ops::Deref, sync::Arc};

type AnyDbHandle<F, E, C, I, H, U> = Arc<AsyncRwLock<Db<F, E, C, I, H, U>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct AnyUnmerkleized<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U>,
    db: AnyDbHandle<F, E, C, I, H, U>,
    metadata: Option<U::Value>,
}

/// Key-value operations for the `any` unordered update kind.
impl<F, E, C, I, H, K, V> AnyUnmerkleized<F, E, C, I, H, unordered::Update<K, V>>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Acquire a read lock on the DB.
    pub async fn lock(
        &self,
    ) -> AsyncRwLockReadGuard<'_, Db<F, E, C, I, H, unordered::Update<K, V>>> {
        self.db.read().await
    }

    /// Get a reference to the inner batch.
    pub const fn batch(&self) -> &UnmerkleizedBatch<F, H, unordered::Update<K, V>> {
        &self.batch
    }

    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    /// Read multiple values by key, amortizing lock acquisition and journal I/O.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &*db).await
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct AnyMerkleized<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, U>>,
    db: AnyDbHandle<F, E, C, I, H, U>,
}

impl<F, E, C, I, H, U> Deref for AnyUnmerkleized<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    type Target = UnmerkleizedBatch<F, H, U>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, C, I, H, U> Deref for AnyMerkleized<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    type Target = MerkleizedBatch<F, H::Digest, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Key-value operations for the `any` ordered update kind.
impl<F, E, C, I, H, K, V> AnyUnmerkleized<F, E, C, I, H, ordered::Update<K, V>>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    /// Read multiple values by key, amortizing lock acquisition and journal I/O.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &*db).await
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` unordered update kind.
impl<F, E, C, I, H, K, V> UnmerkleizedTrait
    for AnyUnmerkleized<F, E, C, I, H, unordered::Update<K, V>>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, E, C, I, H, unordered::Update<K, V>>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata).await?;
        Ok(AnyMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` ordered update kind.
impl<F, E, C, I, H, K, V> UnmerkleizedTrait
    for AnyUnmerkleized<F, E, C, I, H, ordered::Update<K, V>>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, E, C, I, H, ordered::Update<K, V>>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata).await?;
        Ok(AnyMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `any` update kinds.
impl<F, E, C, I, H, U> MerkleizedTrait for AnyMerkleized<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<F, U>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    Operation<F, U>: Codec,
    AnyUnmerkleized<F, E, C, I, H, U>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = AnyUnmerkleized<F, E, C, I, H, U>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

/// Implement [`ManagedDb`] for unordered QMDB databases with fixed-size values.
///
/// `new_batch` captures the `Arc<AsyncRwLock<Db>>` in the returned
/// wrapper so that `get()` and `merkleize()` can read through to
/// committed state.
///
/// `finalize` applies the merkleized batch's changeset and durably
/// commits it to disk.
impl<F, E, K, V, H, T> ManagedDb<E>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
{
    type Unmerkleized = AnyUnmerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
    >;
    type Merkleized = AnyMerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
    >;
    type Error = Error<F>;
    type Config = FixedConfig<T>;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(self.sync_boundary(), bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<F>> {
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

/// Implement [`ManagedDb`] for unordered QMDB databases with variable-size values.
impl<F, E, K, V, H, T> ManagedDb<E>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = AnyUnmerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
    >;
    type Merkleized = AnyMerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
    >;
    type Error = Error<F>;
    type Config = VariableConfig<
        T,
        <Operation<F, unordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
    >;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(self.sync_boundary(), bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<F>> {
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

impl<F, E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
    R: Resolver<
        Family = F,
        Op = Operation<F, unordered::Update<K, FixedEncoding<V>>>,
        Digest = H::Digest,
    >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

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

impl<F, E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
    R: Resolver<
        Family = F,
        Op = Operation<F, unordered::Update<K, VariableEncoding<V>>>,
        Digest = H::Digest,
    >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

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
