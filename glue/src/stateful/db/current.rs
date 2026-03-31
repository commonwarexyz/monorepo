//! [`ManagedDb`] implementation for QMDB [`current`](commonware_storage::qmdb::current) databases.
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
    mmr::{self, Location},
    qmdb::{
        any::{
            operation::{Operation, Update},
            ordered, unordered,
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
        },
        current::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            FixedConfig, VariableConfig,
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

type CurrentDbHandle<E, C, I, H, U, const N: usize> = Arc<AsyncRwLock<Db<E, C, I, H, U, N>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct CurrentUnmerkleized<E, C, I, H, U, const N: usize>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    batch: UnmerkleizedBatch<H, U, N>,
    db: CurrentDbHandle<E, C, I, H, U, N>,
    metadata: Option<U::Value>,
}

/// Key-value operations for the `current` unordered update kind.
impl<E, C, I, H, K, V, const N: usize> CurrentUnmerkleized<E, C, I, H, unordered::Update<K, V>, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<mmr::Family, unordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<mmr::Family, unordered::Update<K, V>>: Codec,
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

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct CurrentMerkleized<E, C, I, H, U, const N: usize>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    batch: MerkleizedBatch<H::Digest, U, N>,
    db: CurrentDbHandle<E, C, I, H, U, N>,
}

impl<E, C, I, H, U, const N: usize> Deref for CurrentUnmerkleized<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    type Target = UnmerkleizedBatch<H, U, N>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E, C, I, H, U, const N: usize> Deref for CurrentMerkleized<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    type Target = MerkleizedBatch<H::Digest, U, N>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

/// Key-value operations for the `current` ordered update kind.
impl<E, C, I, H, K, V, const N: usize> CurrentUnmerkleized<E, C, I, H, ordered::Update<K, V>, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<mmr::Family, ordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<mmr::Family, ordered::Update<K, V>>: Codec,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.batch.get(key, &*db).await
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `current` unordered update kind.
impl<E, C, I, H, K, V, const N: usize> UnmerkleizedTrait
    for CurrentUnmerkleized<E, C, I, H, unordered::Update<K, V>, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<mmr::Family, unordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<mmr::Family, unordered::Update<K, V>>: Codec,
{
    type Merkleized = CurrentMerkleized<E, C, I, H, unordered::Update<K, V>, N>;
    type Error = Error<mmr::Family>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<mmr::Family>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(self.metadata, &*db).await?;
        Ok(CurrentMerkleized {
            batch: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `current` ordered update kind.
impl<E, C, I, H, K, V, const N: usize> UnmerkleizedTrait
    for CurrentUnmerkleized<E, C, I, H, ordered::Update<K, V>, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<mmr::Family, ordered::Update<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: OrderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<mmr::Family, ordered::Update<K, V>>: Codec,
{
    type Merkleized = CurrentMerkleized<E, C, I, H, ordered::Update<K, V>, N>;
    type Error = Error<mmr::Family>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<mmr::Family>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(self.metadata, &*db).await?;
        Ok(CurrentMerkleized {
            batch: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `current` update kinds.
impl<E, C, I, H, U, const N: usize> MerkleizedTrait for CurrentMerkleized<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<mmr::Family, U>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
    CurrentUnmerkleized<E, C, I, H, U, N>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = CurrentUnmerkleized<E, C, I, H, U, N>;

    fn root(&self) -> H::Digest {
        self.batch.root()
    }

    fn sync_root(&self) -> H::Digest {
        self.batch.ops_root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        CurrentUnmerkleized {
            batch: self.batch.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

/// Implement [`ManagedDb`] for unordered current QMDB databases with fixed-size values.
impl<E, K, V, H, T, const N: usize> ManagedDb<E>
    for Db<
        E,
        FixedJournal<E, Operation<mmr::Family, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
{
    type Unmerkleized = CurrentUnmerkleized<
        E,
        FixedJournal<E, Operation<mmr::Family, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
    >;
    type Merkleized = CurrentMerkleized<
        E,
        FixedJournal<E, Operation<mmr::Family, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
    >;
    type Error = Error<mmr::Family>;
    type Config = FixedConfig<T>;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<mmr::Family>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        CurrentUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<mmr::Family>> {
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.ops_root(),
            range: non_empty_range!(self.inactivity_floor_loc(), bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<mmr::Family>> {
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

/// Workaround for <https://github.com/rust-lang/rust/issues/115188>.
///
/// Inside a `ManagedDb` trait impl, `<Self>::init(...)` in a non-async `fn`
/// resolves to the *trait* method (infinite recursion), while in an
/// `async fn` it resolves correctly to the inherent method but the compiler
/// cannot verify the RPITIT future is `Send`. By placing the call in this
/// module -- which does not import `ManagedDb` -- the compiler
/// unambiguously picks the inherent `Db::init`.
mod open {
    use commonware_codec::{Codec, Read};
    use commonware_cryptography::Hasher;
    use commonware_runtime::{Clock, Metrics, Storage};
    use commonware_storage::{
        mmr,
        qmdb::{
            any::{
                operation::Operation,
                unordered,
                value::{VariableEncoding, VariableValue},
            },
            current::{unordered::variable::Db, VariableConfig},
            Error,
        },
    };
    use commonware_utils::Array;

    type VConfig<T, K, V> = VariableConfig<
        T,
        <Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>> as Read>::Cfg,
    >;

    pub(super) async fn variable<E, K, V, H, T, const N: usize>(
        context: E,
        config: VConfig<T, K, V>,
    ) -> Result<Db<E, K, V, H, T, N>, Error<mmr::Family>>
    where
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue + 'static,
        H: Hasher,
        T: commonware_storage::translator::Translator,
        Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>: Codec,
    {
        Db::init(context, config).await
    }
}

/// Implement [`ManagedDb`] for unordered current QMDB databases with variable-size values.
impl<E, K, V, H, T, const N: usize> ManagedDb<E>
    for Db<
        E,
        VariableJournal<E, Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
    >
where
    E: Storage + Clock + Metrics,
    K: Key + Array,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = CurrentUnmerkleized<
        E,
        VariableJournal<E, Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
    >;
    type Merkleized = CurrentMerkleized<
        E,
        VariableJournal<E, Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
    >;
    type Error = Error<mmr::Family>;
    type Config = VariableConfig<
        T,
        <Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
    >;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<mmr::Family>> {
        open::variable(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        CurrentUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<mmr::Family>> {
        let current_size = *self.bounds().await.end;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.ops_root(),
            range: non_empty_range!(self.inactivity_floor_loc(), bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<mmr::Family>> {
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

impl<E, K, V, H, T, R, const N: usize> StateSyncDb<E, R>
    for Db<
        E,
        FixedJournal<E, Operation<mmr::Family, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
    >
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
    R: Resolver<
        Op = Operation<mmr::Family, unordered::Update<K, FixedEncoding<V>>>,
        Digest = H::Digest,
    >,
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

impl<E, K, V, H, T, R, const N: usize> StateSyncDb<E, R>
    for Db<
        E,
        VariableJournal<E, Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
    >
where
    E: Storage + Clock + Metrics,
    K: Key + Array,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>: Codec,
    R: Resolver<
        Op = Operation<mmr::Family, unordered::Update<K, VariableEncoding<V>>>,
        Digest = H::Digest,
    >,
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
