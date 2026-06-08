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
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::{
        ordered::Index as OrderedIdx, unordered::Index as UnorderedIdx, Ordered as OrderedIndex,
        Unordered as UnorderedIndex,
    },
    journal::contiguous::{
        fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Contiguous, Mutable,
    },
    merkle::{Graftable, Location},
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
        sync::{self, resolver::Resolver, Target as CurrentSyncTarget},
        Error,
    },
    translator::Translator,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock, Array};
use std::{ops::Deref, sync::Arc};

type CurrentDbHandle<F, E, C, I, H, U, const N: usize, S> =
    Arc<AsyncRwLock<Db<F, E, C, I, H, U, N, S>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct CurrentUnmerkleized<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, N, S>,
    db: CurrentDbHandle<F, E, C, I, H, U, N, S>,
    metadata: Option<U::Value>,
}

/// Key-value operations for the `current` unordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentUnmerkleized<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
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

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct CurrentMerkleized<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, U, N, S>>,
    db: CurrentDbHandle<F, E, C, I, H, U, N, S>,
}

impl<F, E, C, I, H, U, const N: usize, S> Deref for CurrentUnmerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Target = UnmerkleizedBatch<F, H, U, N, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Deref for CurrentMerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Target = MerkleizedBatch<F, H::Digest, U, N, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Key-value operations for the `current` ordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentUnmerkleized<F, E, C, I, H, ordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
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

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Read-through operations for the `current` merkleized batch.
impl<F, E, C, I, H, U, const N: usize, S> CurrentMerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Read a value by key, falling back to committed state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &*db).await
    }

    /// Read multiple values by key, falling back to committed state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &*db).await
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `current` unordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S> UnmerkleizedTrait
    for CurrentUnmerkleized<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Merkleized = CurrentMerkleized<F, E, C, I, H, unordered::Update<K, V>, N, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata).await?;
        Ok(CurrentMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `current` ordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S> UnmerkleizedTrait
    for CurrentUnmerkleized<F, E, C, I, H, ordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Merkleized = CurrentMerkleized<F, E, C, I, H, ordered::Update<K, V>, N, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata).await?;
        Ok(CurrentMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `current` update kinds.
impl<F, E, C, I, H, U, const N: usize, S> MerkleizedTrait
    for CurrentMerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
    CurrentUnmerkleized<F, E, C, I, H, U, N, S>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = CurrentUnmerkleized<F, E, C, I, H, U, N, S>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        CurrentUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

/// Implement [`ManagedDb`] for unordered current QMDB databases with fixed-size values.
impl<F, E, K, V, H, T, const N: usize, S> ManagedDb<E>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
{
    type Unmerkleized = CurrentUnmerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >;
    type Merkleized = CurrentMerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >;
    type Error = Error<F>;
    type Config = FixedConfig<T, S>;
    type SyncTarget = CurrentSyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
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

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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

/// Implement [`ManagedDb`] for ordered current QMDB databases with fixed-size values.
impl<F, E, K, V, H, T, const N: usize, S> ManagedDb<E>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, ordered::Update<K, FixedEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
{
    type Unmerkleized = CurrentUnmerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, ordered::Update<K, FixedEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >;
    type Merkleized = CurrentMerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, ordered::Update<K, FixedEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >;
    type Error = Error<F>;
    type Config = FixedConfig<T, S>;
    type SyncTarget = CurrentSyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
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

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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
    use commonware_parallel::Strategy;
    use commonware_runtime::{Clock, Metrics, Storage};
    use commonware_storage::{
        merkle::Graftable,
        qmdb::{
            any::{
                operation::Operation,
                ordered, unordered,
                value::{VariableEncoding, VariableValue},
            },
            current::{
                ordered::variable::Db as OrderedVariableDb, unordered::variable::Db, VariableConfig,
            },
            Error,
        },
    };
    use commonware_utils::Array;

    type VConfig<T, F, K, V, S> = VariableConfig<
        T,
        <Operation<F, unordered::Update<K, VariableEncoding<V>>> as Read>::Cfg,
        S,
    >;
    type OrderedVConfig<T, F, K, V, S> =
        VariableConfig<T, <Operation<F, ordered::Update<K, VariableEncoding<V>>> as Read>::Cfg, S>;

    pub(super) async fn variable<F, E, K, V, H, T, const N: usize, S>(
        context: E,
        config: VConfig<T, F, K, V, S>,
    ) -> Result<Db<F, E, K, V, H, T, N, S>, Error<F>>
    where
        F: Graftable,
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue + 'static,
        H: Hasher,
        T: commonware_storage::translator::Translator,
        S: Strategy,
        Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
    {
        Db::init(context, config).await
    }

    pub(super) async fn ordered_variable<F, E, K, V, H, T, const N: usize, S>(
        context: E,
        config: OrderedVConfig<T, F, K, V, S>,
    ) -> Result<OrderedVariableDb<F, E, K, V, H, T, N, S>, Error<F>>
    where
        F: Graftable,
        E: Storage + Clock + Metrics,
        K: commonware_storage::qmdb::operation::Key,
        V: VariableValue + 'static,
        H: Hasher,
        T: commonware_storage::translator::Translator,
        S: Strategy,
        Operation<F, ordered::Update<K, VariableEncoding<V>>>: Codec,
    {
        OrderedVariableDb::init(context, config).await
    }
}

/// Implement [`ManagedDb`] for unordered current QMDB databases with variable-size values.
impl<F, E, K, V, H, T, const N: usize, S> ManagedDb<E>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key + Array,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = CurrentUnmerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >;
    type Merkleized = CurrentMerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >;
    type Error = Error<F>;
    type Config = VariableConfig<
        T,
        <Operation<F, unordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
        S,
    >;
    type SyncTarget = CurrentSyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
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

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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

/// Implement [`ManagedDb`] for ordered current QMDB databases with variable-size values.
impl<F, E, K, V, H, T, const N: usize, S> ManagedDb<E>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, ordered::Update<K, VariableEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, ordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = CurrentUnmerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, ordered::Update<K, VariableEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >;
    type Merkleized = CurrentMerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, ordered::Update<K, VariableEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >;
    type Error = Error<F>;
    type Config = VariableConfig<
        T,
        <Operation<F, ordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
        S,
    >;
    type SyncTarget = CurrentSyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        open::ordered_variable(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        CurrentUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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

/// Implement [`StateSyncDb`] for unordered current QMDB databases with fixed-size values.
impl<F, E, K, V, H, T, R, const N: usize, S> StateSyncDb<E, R>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
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

/// Implement [`StateSyncDb`] for ordered current QMDB databases with fixed-size values.
impl<F, E, K, V, H, T, R, const N: usize, S> StateSyncDb<E, R>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, ordered::Update<K, FixedEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, FixedEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    R: Resolver<
        Family = F,
        Op = Operation<F, ordered::Update<K, FixedEncoding<V>>>,
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

/// Implement [`StateSyncDb`] for unordered current QMDB databases with variable-size values.
impl<F, E, K, V, H, T, R, const N: usize, S> StateSyncDb<E, R>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key + Array,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
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

/// Implement [`StateSyncDb`] for ordered current QMDB databases with variable-size values.
impl<F, E, K, V, H, T, R, const N: usize, S> StateSyncDb<E, R>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, ordered::Update<K, VariableEncoding<V>>>>,
        OrderedIdx<T, Location<F>>,
        H,
        ordered::Update<K, VariableEncoding<V>>,
        N,
        S,
    >
where
    F: Graftable,
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, ordered::Update<K, VariableEncoding<V>>>: Codec,
    R: Resolver<
        Family = F,
        Op = Operation<F, ordered::Update<K, VariableEncoding<V>>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_storage::{
        journal::contiguous::{
            fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
        },
        merkle::{full::Config as MerkleConfig, mmr},
        qmdb::current::{
            ordered::{fixed as ordered_fixed, variable as ordered_variable},
            unordered::fixed,
        },
        translator::TwoCap,
    };
    use commonware_utils::{non_empty_range, NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type FixedDb = fixed::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;
    type OrderedFixedDb = ordered_fixed::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;
    type OrderedVariableDb = ordered_variable::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("stateful-current-journal-{suffix}"),
                metadata_partition: format!("stateful-current-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: format!("stateful-current-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("stateful-current-grafted-{suffix}"),
            translator: TwoCap,
        }
    }

    fn variable_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<TwoCap, ((), ()), Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("stateful-current-journal-{suffix}"),
                metadata_partition: format!("stateful-current-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: VariableJournalConfig {
                partition: format!("stateful-current-log-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("stateful-current-grafted-{suffix}"),
            translator: TwoCap,
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    fn assert_database_set<T: crate::stateful::db::DatabaseSet<deterministic::Context>>() {}

    #[test]
    fn ordered_current_db_trait_impls_compile() {
        assert_managed_db::<OrderedFixedDb>();
        assert_managed_db::<OrderedVariableDb>();
        assert_state_sync_db::<OrderedFixedDb, Arc<OrderedFixedDb>>();
        assert_state_sync_db::<OrderedVariableDb, Arc<OrderedVariableDb>>();
        assert_database_set::<Arc<AsyncRwLock<OrderedFixedDb>>>();
        assert_database_set::<Arc<AsyncRwLock<OrderedVariableDb>>>();
    }

    #[test]
    fn ordered_fixed_managed_db_finalizes_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-fixed-managed-db", &context);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));
            let key = Sha256::hash(b"key");
            let value = Sha256::hash(b"value");
            let metadata = Sha256::hash(b"metadata");
            let missing = Sha256::hash(b"missing");

            let batch = <OrderedFixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let mut guard = db.write().await;
                <OrderedFixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let proof = guard.exclusion_proof(&hasher, &missing).await.unwrap();
            assert!(OrderedFixedDb::verify_exclusion_proof(
                &hasher,
                &missing,
                &proof,
                &guard.root(),
            ));
        });
    }

    #[test]
    fn ordered_variable_managed_db_finalizes_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = variable_config("ordered-variable-managed-db", &context);
            let db = <OrderedVariableDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));
            let key = Sha256::hash(b"key");
            let value = Sha256::hash(b"value");
            let metadata = Sha256::hash(b"metadata");
            let missing = Sha256::hash(b"missing");

            let batch = <OrderedVariableDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let mut guard = db.write().await;
                <OrderedVariableDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let hasher = commonware_storage::qmdb::hasher::<Sha256>();
            let proof = guard.exclusion_proof(&hasher, &missing).await.unwrap();
            assert!(OrderedVariableDb::verify_exclusion_proof(
                &hasher,
                &missing,
                &proof,
                &guard.root(),
            ));
        });
    }

    #[test]
    fn ordered_managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-matches-sync-target", &context);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config.clone())
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let key = Sha256::hash(b"key");
            let value = Sha256::hash(b"value");
            let metadata = Sha256::hash(b"metadata");

            let batch = <OrderedFixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let mut verification_db =
                <OrderedFixedDb as ManagedDb<_>>::init(context.child("verification_db"), config)
                    .await
                    .unwrap();
            verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            verification_db.sync().await.unwrap();

            let valid_target =
                <OrderedFixedDb as ManagedDb<_>>::sync_target(&verification_db).await;
            assert!(<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(b"wrong ops root");
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range = non_empty_range!(
                mmr::Location::new(*valid_target.range.start()),
                mmr::Location::new(*valid_target.range.end() + 1)
            );
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }

    #[test]
    fn ordered_managed_db_rewind_to_target_round_trips() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-rewind-round-trip", &context);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let key1 = Sha256::hash(b"key1");
            let value1 = Sha256::hash(b"value1");
            let metadata1 = Sha256::hash(b"metadata1");
            let batch1 = <OrderedFixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key1, Some(value1))
                .with_metadata(metadata1);
            let merkleized1 = crate::stateful::db::Unmerkleized::merkleize(batch1)
                .await
                .unwrap();
            {
                let mut guard = db.write().await;
                <OrderedFixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized1)
                    .await
                    .unwrap();
            }
            let target_after_first = {
                let guard = db.read().await;
                <OrderedFixedDb as ManagedDb<_>>::sync_target(&*guard).await
            };

            let key2 = Sha256::hash(b"key2");
            let value2 = Sha256::hash(b"value2");
            let metadata2 = Sha256::hash(b"metadata2");
            let batch2 = <OrderedFixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key2, Some(value2))
                .with_metadata(metadata2);
            let merkleized2 = crate::stateful::db::Unmerkleized::merkleize(batch2)
                .await
                .unwrap();
            {
                let mut guard = db.write().await;
                <OrderedFixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized2)
                    .await
                    .unwrap();
            }

            {
                let mut guard = db.write().await;
                <OrderedFixedDb as ManagedDb<_>>::rewind_to_target(
                    &mut *guard,
                    target_after_first.clone(),
                )
                .await
                .unwrap();
            }
            let target_after_rewind = {
                let guard = db.read().await;
                <OrderedFixedDb as ManagedDb<_>>::sync_target(&*guard).await
            };
            assert_eq!(target_after_rewind, target_after_first);
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("matches-sync-target", &context);
            let db = FixedDb::init(context.child("db"), config.clone())
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let key = Sha256::hash(b"key");
            let value = Sha256::hash(b"value");
            let metadata = Sha256::hash(b"metadata");

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let mut verification_db = FixedDb::init(context.child("verification_db"), config)
                .await
                .unwrap();
            verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            verification_db.sync().await.unwrap();

            let valid_target = <FixedDb as ManagedDb<_>>::sync_target(&verification_db).await;
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(b"wrong ops root");
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range = non_empty_range!(
                mmr::Location::new(*valid_target.range.start()),
                mmr::Location::new(*valid_target.range.end() + 1)
            );
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }
}
