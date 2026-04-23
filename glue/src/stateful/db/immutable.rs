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
    merkle::{Family, Location},
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

type ImmutableDbHandle<F, E, K, V, C, H, T> = Arc<AsyncRwLock<Immutable<F, E, K, V, C, H, T>>>;

/// Wraps an immutable [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct ImmutableUnmerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, K, V>,
    db: ImmutableDbHandle<F, E, K, V, C, H, T>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, K, V, C, H, T> Deref for ImmutableUnmerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<F, H, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, K, V, C, H, T> ImmutableUnmerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor to include within the next [`merkleize`](UnmerkleizedTrait::merkleize) call.
    ///
    /// If unset, [`merkleize`](UnmerkleizedTrait::merkleize) will use the [`Default`] of [`Location`].
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }

    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    /// Read multiple values by key, falling back to committed state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
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
pub struct ImmutableMerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, K, V>>,
    db: ImmutableDbHandle<F, E, K, V, C, H, T>,
}

impl<F, E, K, V, C, H, T> Deref for ImmutableMerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    type Target = MerkleizedBatch<F, H::Digest, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, K, V, C, H, T> ImmutableMerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &*db).await
    }

    /// Read multiple values by key, falling back to committed state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &*db).await
    }
}

impl<F, E, K, V, C, H, T> UnmerkleizedTrait for ImmutableUnmerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    type Merkleized = ImmutableMerkleized<F, E, K, V, C, H, T>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(
            &*db,
            self.metadata,
            self.inactivity_floor.unwrap_or_default(),
        );
        Ok(ImmutableMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, K, V, C, H, T> MerkleizedTrait for ImmutableMerkleized<F, E, K, V, C, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    T: Translator,
    Operation<F, K, V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnmerkleized<F, E, K, V, C, H, T>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, K, V, H, T> ManagedDb<E> for fixed::Db<F, E, K, V, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
{
    type Unmerkleized = ImmutableUnmerkleized<
        F,
        E,
        K,
        FixedEncoding<V>,
        FixedJournal<E, fixed::Operation<F, K, V>>,
        H,
        T,
    >;
    type Merkleized = ImmutableMerkleized<
        F,
        E,
        K,
        FixedEncoding<V>,
        FixedJournal<E, fixed::Operation<F, K, V>>,
        H,
        T,
    >;
    type Error = Error<F>;
    type Config = fixed::Config<T>;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        ImmutableUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
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

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
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

impl<F, E, K, V, H, T> ManagedDb<E> for variable::Db<F, E, K, V, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    variable::Operation<F, K, V>: Codec,
{
    type Unmerkleized = ImmutableUnmerkleized<
        F,
        E,
        K,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<F, K, V>>,
        H,
        T,
    >;
    type Merkleized = ImmutableMerkleized<
        F,
        E,
        K,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<F, K, V>>,
        H,
        T,
    >;
    type Error = Error<F>;
    type Config = variable::Config<T, <variable::Operation<F, K, V> as CodecRead>::Cfg>;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        ImmutableUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
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

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
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

impl<F, E, K, V, H, T, R> StateSyncDb<E, R> for fixed::Db<F, E, K, V, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    R: Resolver<Family = F, Op = fixed::Operation<F, K, V>, Digest = H::Digest>,
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

impl<F, E, K, V, H, T, R> StateSyncDb<E, R> for variable::Db<F, E, K, V, H, T>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    variable::Operation<F, K, V>: Codec,
    R: Resolver<Family = F, Op = variable::Operation<F, K, V>, Digest = H::Digest>,
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
