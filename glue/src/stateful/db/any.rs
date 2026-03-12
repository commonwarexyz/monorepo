//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to committed state. The glue [`UnmerkleizedTrait`] trait
//! does not carry a DB reference, so this module provides wrapper types
//! that capture `Arc<AsyncRwLock<Db>>` alongside the raw batch.

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
    mmr::Location,
    qmdb::{
        any::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            operation::{update, Operation},
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
            FixedConfig, VariableConfig,
        },
        operation::Key,
        sync, Error,
    },
    translator::Translator,
    Persistable,
};
use commonware_utils::{channel::mpsc, sync::AsyncRwLock, Array};
use std::sync::Arc;

type AnyDbHandle<E, C, I, H, U> = Arc<AsyncRwLock<Db<E, C, I, H, U>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, allowing it to implement the glue [`Unmerkleized`](UnmerkleizedTrait)
/// trait (which does not carry a DB parameter).
pub struct AnyUnmerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    batch: UnmerkleizedBatch<H, U>,
    db: AnyDbHandle<E, C, I, H, U>,
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, allowing it to implement the glue [`Merkleized`](MerkleizedTrait)
/// trait.
pub struct AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    batch: MerkleizedBatch<H::Digest, U>,
    db: AnyDbHandle<E, C, I, H, U>,
}

impl<E, C, I, H, U> AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Inactivity floor after merkleization.
    pub const fn inactivity_floor(&self) -> Location {
        self.batch.inactivity_floor()
    }

    /// Total operation count after merkleization.
    pub const fn size(&self) -> Location {
        self.batch.size()
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` unordered update kind.
impl<E, C, I, H, K, V> UnmerkleizedTrait for AnyUnmerkleized<E, C, I, H, update::Unordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key + Send,
    V: ValueEncoding + Send + 'static,
    C: Mutable<Item = Operation<update::Unordered<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
{
    type Key = K;
    type Value = V::Value;
    type Merkleized = AnyMerkleized<E, C, I, H, update::Unordered<K, V>>;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Error> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    fn write(mut self, key: Self::Key, value: Option<Self::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }

    async fn merkleize(self) -> Result<Self::Merkleized, Error> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(None, &*db).await?;
        Ok(AnyMerkleized {
            batch: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` ordered update kind.
impl<E, C, I, H, K, V> UnmerkleizedTrait for AnyUnmerkleized<E, C, I, H, update::Ordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key + Send,
    V: ValueEncoding + Send + 'static,
    C: Mutable<Item = Operation<update::Ordered<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Ordered<K, V>>: Codec,
{
    type Key = K;
    type Value = V::Value;
    type Merkleized = AnyMerkleized<E, C, I, H, update::Ordered<K, V>>;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Error> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    fn write(mut self, key: Self::Key, value: Option<Self::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }

    async fn merkleize(self) -> Result<Self::Merkleized, Error> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(None, &*db).await?;
        Ok(AnyMerkleized {
            batch: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `any` update kinds.
impl<E, C, I, H, U> MerkleizedTrait for AnyMerkleized<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Mutable<Item = Operation<U>> + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<U>: Codec,
    AnyUnmerkleized<E, C, I, H, U>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = AnyUnmerkleized<E, C, I, H, U>;

    fn root(&self) -> H::Digest {
        self.batch.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: self.batch.new_batch::<H>(),
            db: self.db.clone(),
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
impl<E, K, V, H, T> ManagedDb<E>
    for Db<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
{
    type Unmerkleized = AnyUnmerkleized<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >;
    type Merkleized = AnyMerkleized<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >;
    type Error = Error;
    type Config = FixedConfig<T>;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error> {
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }
}

/// Implement [`ManagedDb`] for unordered QMDB databases with variable-size values.
impl<E, K, V, H, T> ManagedDb<E>
    for Db<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    Operation<update::Unordered<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = AnyUnmerkleized<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >;
    type Merkleized = AnyMerkleized<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >;
    type Error = Error;
    type Config =
        VariableConfig<T, <Operation<update::Unordered<K, VariableEncoding<V>>> as CodecRead>::Cfg>;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error> {
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        E,
        FixedJournal<E, Operation<update::Unordered<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, FixedEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator + Send + Sync + 'static,
    R: commonware_storage::qmdb::sync::resolver::Resolver<
            Op = Operation<update::Unordered<K, FixedEncoding<V>>>,
            Digest = H::Digest,
        > + Clone
        + Send
        + Sync
        + 'static,
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
        })
        .await
    }
}

impl<E, K, V, H, T, R> StateSyncDb<E, R>
    for Db<
        E,
        VariableJournal<E, Operation<update::Unordered<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        update::Unordered<K, VariableEncoding<V>>,
    >
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator + Send + Sync + 'static,
    Operation<update::Unordered<K, VariableEncoding<V>>>: Codec,
    R: sync::resolver::Resolver<
            Op = Operation<update::Unordered<K, VariableEncoding<V>>>,
            Digest = H::Digest,
        > + Clone
        + Send
        + Sync
        + 'static,
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
        })
        .await
    }
}
