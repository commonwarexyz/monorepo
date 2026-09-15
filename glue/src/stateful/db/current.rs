//! [`ManagedDb`] implementation for QMDB [`current`](commonware_storage::qmdb::current) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to applied state. This module provides wrapper types
//! that capture a [`Shared`] database handle alongside the raw batch so the
//! [`Unmerkleized`](super::Unmerkleized) and [`Merkleized`](super::Merkleized)
//! traits can be implemented without a DB parameter.

use crate::stateful::db::{
    BatchContext, InitError, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized as UnmerkleizedTrait, sync_standard_db, validate_initialization,
};
use commonware_codec::{Codec, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    index::{
        Ordered as OrderedIndex, Unordered as UnorderedIndex, ordered::Index as OrderedIdx,
        unordered::Index as UnorderedIdx,
    },
    journal::contiguous::{
        Contiguous, Mutable, fixed::Journal as FixedJournal, variable::Journal as VariableJournal,
    },
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{
            initial_root,
            operation::{Operation, Update},
            ordered, unordered,
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
        },
        current::{
            FixedConfig, VariableConfig,
            batch::{MerkleizedBatch, Staged, UnmerkleizedBatch},
            db::Db,
        },
        operation::Key,
        sync::{self, Target as CurrentSyncTarget},
    },
    translator::Translator,
};
use commonware_utils::{Array, channel::mpsc, non_empty_range};
use std::{
    ops::{Deref, Range},
    sync::Arc,
};

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct CurrentUnmerkleized<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, N, S>,
    db: Shared<Db<F, E, C, I, H, U, N, S>>,
    metadata: Option<U::Value>,
}

/// Staged batch returned by [`CurrentUnmerkleized::stage`], wrapping a QMDB [`Staged`] with a
/// reference to the parent database.
///
/// Like any speculative batch, this handle is a branch-scoped view of the shared database: it
/// stays valid only while every batch finalized on the database is an ancestor of this batch
/// (see [`MerkleizedBatch`]'s branch-validity contract).
pub struct CurrentStaged<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    staged: Staged<F, H, U, N, S>,
    db: Shared<Db<F, E, C, I, H, U, N, S>>,
    metadata: Option<U::Value>,
}

/// Key-value operations shared by both `current` update kinds.
impl<F, E, C, I, H, U, const N: usize, S> CurrentUnmerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: U::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Read multiple values and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn stage(
        self,
        keys: &[&U::Key],
    ) -> Result<(Vec<Option<U::Value>>, CurrentStaged<F, E, C, I, H, U, N, S>), Error<F>> {
        let Self {
            batch,
            db,
            metadata,
        } = self;
        let (values, staged) = {
            let guard = db.read().await;
            batch.stage(keys, &guard).await?
        };
        Ok((
            values,
            CurrentStaged {
                staged,
                db,
                metadata,
            },
        ))
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct CurrentMerkleized<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, U, N, S>>,
    db: Shared<Db<F, E, C, I, H, U, N, S>>,
}

impl<F, E, C, I, H, U, const N: usize, S> Clone for CurrentMerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Deref for CurrentUnmerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
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
    E: Context,
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

/// Read-expansion operations for the `current` staged batch.
impl<F, E, C, I, H, U, const N: usize, S> CurrentStaged<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Set commit metadata included in the [`merkleize`](Self::merkleize) call, replacing any
    /// metadata set before staging.
    pub fn with_metadata(mut self, metadata: U::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Expand this staged batch with more reads.
    ///
    /// Existing read indices remain stable. Newly read keys are appended to the staged read set and
    /// assigned the returned range. Expansion does not deduplicate against previously staged keys
    /// and does not observe values computed for earlier staged slots but not yet passed to
    /// `merkleize`.
    pub async fn expand(
        self,
        keys: &[&U::Key],
    ) -> Result<(Range<usize>, Vec<Option<U::Value>>, Self), Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let (range, values, staged) = {
            let guard = db.read().await;
            staged.expand(keys, &guard).await?
        };
        Ok((
            range,
            values,
            Self {
                staged,
                db,
                metadata,
            },
        ))
    }
}

/// Staged merkleize for the `current` unordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentStaged<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](CurrentStaged::expand)
    /// before this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](CurrentStaged::expand) ranges.
    /// Metadata set via [`with_metadata`](CurrentStaged::with_metadata) (or before staging) is
    /// committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<CurrentMerkleized<F, E, C, I, H, unordered::Update<K, V>, N, S>, Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let inner = {
            let guard = db.read().await;
            staged.merkleize(updates, upserts, metadata, &guard).await?
        };
        Ok(CurrentMerkleized { inner, db })
    }
}

/// Staged merkleize for the `current` ordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentStaged<F, E, C, I, H, ordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](CurrentStaged::expand)
    /// before this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](CurrentStaged::expand) ranges.
    /// Metadata set via [`with_metadata`](CurrentStaged::with_metadata) (or before staging) is
    /// committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<CurrentMerkleized<F, E, C, I, H, ordered::Update<K, V>, N, S>, Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let inner = {
            let guard = db.read().await;
            staged.merkleize(updates, upserts, metadata, &guard).await?
        };
        Ok(CurrentMerkleized { inner, db })
    }
}

/// Read-through operations for the `current` merkleized batch.
impl<F, E, C, I, H, U, const N: usize, S> CurrentMerkleized<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `current` unordered update kind.
impl<F, E, C, I, H, K, V, const N: usize, S> UnmerkleizedTrait
    for CurrentUnmerkleized<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    F: Graftable,
    E: Context,
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
        let merkleized = self.batch.merkleize(&db, self.metadata).await?;
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
    E: Context,
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
        let merkleized = self.batch.merkleize(&db, self.metadata).await?;
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
    E: Context,
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
    E: Context + Spawner,
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

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>>> {
        let db = <Self>::init(
            context,
            config,
            expected.as_ref().map(|target| target.range.end()),
        )
        .await
        .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        CurrentSyncTarget::new(
            initial_root::<F, unordered::Update<K, FixedEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CurrentUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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
    E: Context + Spawner,
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

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>>> {
        let db = <Self>::init(
            context,
            config,
            expected.as_ref().map(|target| target.range.end()),
        )
        .await
        .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        CurrentSyncTarget::new(
            initial_root::<F, ordered::Update<K, FixedEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CurrentUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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
    use commonware_runtime::Spawner;
    use commonware_storage::{
        Context,
        merkle::Graftable,
        qmdb::{
            Error,
            any::{
                operation::Operation,
                ordered, unordered,
                value::{VariableEncoding, VariableValue},
            },
            current::{
                VariableConfig, ordered::variable::Db as OrderedVariableDb, unordered::variable::Db,
            },
        },
    };
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
        max_size: Option<commonware_storage::merkle::Location<F>>,
    ) -> Result<Db<F, E, K, V, H, T, N, S>, Error<F>>
    where
        F: Graftable,
        E: Context + Spawner,
        K: commonware_storage::qmdb::operation::Key,
        V: VariableValue + 'static,
        H: Hasher,
        T: commonware_storage::translator::Translator,
        S: Strategy,
        Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
    {
        Db::init(context, config, max_size).await
    }

    pub(super) async fn ordered_variable<F, E, K, V, H, T, const N: usize, S>(
        context: E,
        config: OrderedVConfig<T, F, K, V, S>,
        max_size: Option<commonware_storage::merkle::Location<F>>,
    ) -> Result<OrderedVariableDb<F, E, K, V, H, T, N, S>, Error<F>>
    where
        F: Graftable,
        E: Context + Spawner,
        K: commonware_storage::qmdb::operation::Key,
        V: VariableValue + 'static,
        H: Hasher,
        T: commonware_storage::translator::Translator,
        S: Strategy,
        Operation<F, ordered::Update<K, VariableEncoding<V>>>: Codec,
    {
        OrderedVariableDb::init(context, config, max_size).await
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
    E: Context + Spawner,
    K: Key,
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

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>>> {
        let db = open::variable(
            context,
            config,
            expected.as_ref().map(|target| target.range.end()),
        )
        .await
        .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        CurrentSyncTarget::new(
            initial_root::<F, unordered::Update<K, VariableEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CurrentUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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
    E: Context + Spawner,
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

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>>> {
        let db = open::ordered_variable(
            context,
            config,
            expected.as_ref().map(|target| target.range.end()),
        )
        .await
        .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        CurrentSyncTarget::new(
            initial_root::<F, ordered::Update<K, VariableEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CurrentUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.ops_root() == target.root
            && *target.range.start() == batch.sync_boundary()
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        CurrentSyncTarget::new(
            self.ops_root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
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
    E: Context + Spawner,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
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
        sync_standard_db(
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
    E: Context + Spawner,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher,
    T: Translator,
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
        sync_standard_db(
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
    E: Context + Spawner,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
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
        sync_standard_db(
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
    E: Context + Spawner,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, ordered::Update<K, VariableEncoding<V>>>: Codec,
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
        sync_standard_db(
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::boxed;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{
            self, Config as DeterministicConfig, FaultConfig, PartialWriteMode, WriteConfig,
        },
    };
    use commonware_storage::{
        journal::contiguous::{
            fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
        },
        merkle::{full::Config as MerkleConfig, mmr},
        qmdb::{
            any::unordered::fixed::Operation as FixedOperation,
            current::{
                ordered::{fixed as ordered_fixed, variable as ordered_variable},
                unordered::{fixed, variable},
            },
        },
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, probability};
    use std::num::{NonZeroU16, NonZeroUsize};

    #[boxed]
    async fn apply_and_finalize<D: ManagedDb<deterministic::Context>>(
        db: D,
        batch: D::Merkleized,
    ) -> D {
        let db = D::apply(db, batch).await.unwrap();
        let (db, sync) = D::finalize(db).await.unwrap();
        sync.await.expect("database sync failed");
        db
    }

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

    /// The unordered variable wrapper accepts variable-length keys.
    type VariableDb = variable::Db<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
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
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: format!("stateful-current-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("stateful-current-grafted-{suffix}"),
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("stateful-current-grafted-{suffix}"),
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
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
        assert_database_set::<Shared<OrderedFixedDb>>();
        assert_database_set::<Shared<OrderedVariableDb>>();
    }

    #[test]
    fn variable_current_db_trait_impls_compile() {
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
        assert_database_set::<Shared<VariableDb>>();
    }

    #[test]
    fn ordered_fixed_managed_db_applies_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-fixed-managed-db", &context);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);
            let missing = Sha256::hash(&[b"missing"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized).await);
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let proof = guard.exclusion_proof(&missing).await.unwrap();
            assert!(proof.verify::<Sha256>(&missing, &guard.root()));
        });
    }

    /// The glue staged wrapper (`CurrentUnmerkleized::stage` -> `CurrentStaged::expand` ->
    /// `CurrentStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an upsert, and metadata flow (both set
    /// on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow and db-handle pairing through the wrapper.
    #[test]
    fn ordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-fixed-glue-staged", &context);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = |i: u64| Sha256::hash(&[&i.to_be_bytes()]);
            let val = |i: u64| Sha256::hash(&[&(i + 10_000).to_be_bytes()]);
            let metadata = Sha256::hash(&[b"metadata"]);

            // Seed keys 0..50 and persist them.
            let mut seed = db.new_batch_for_test::<_>().await;
            for i in 0..50u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(seed)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized).await);
            }

            // Read set: key(1) updated, key(2) deleted, key(999) missing -> created.
            let read_keys = [key(1), key(2), key(999)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let indexed_updates = vec![(0, Some(val(1_000))), (1, None), (2, Some(val(1_001)))];
            let upserts = vec![(key(3), Some(val(1_002)))];

            // Explicit path.
            let mut explicit = db.new_batch_for_test::<_>().await;
            let explicit_values = explicit.get_many(&keys).await.unwrap();
            for (slot, value) in &indexed_updates {
                explicit = explicit.write(read_keys[*slot], *value);
            }
            for (k, v) in &upserts {
                explicit = explicit.write(*k, *v);
            }
            let explicit_root =
                crate::stateful::db::Unmerkleized::merkleize(explicit.with_metadata(metadata))
                    .await
                    .unwrap()
                    .root();

            // Staged path, with metadata set on the staged handle.
            let staged_batch = db.new_batch_for_test::<_>().await;
            let split = 2;
            let (mut staged_values, staged) = staged_batch.stage(&keys[..split]).await.unwrap();
            let (range, suffix_values, staged) = staged.expand(&keys[split..]).await.unwrap();
            assert_eq!(range, split..keys.len());
            staged_values.extend(suffix_values);
            let staged_root = staged
                .with_metadata(metadata)
                .merkleize(indexed_updates.clone(), upserts.clone())
                .await
                .unwrap()
                .root();

            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_root, staged_root);

            // Metadata set before staging must be carried through to staged merkleize.
            let carried_batch = db.new_batch_for_test::<_>().await.with_metadata(metadata);
            let (carried_values, staged) = carried_batch.stage(&keys).await.unwrap();
            let carried_root = staged
                .merkleize(indexed_updates.clone(), upserts.clone())
                .await
                .unwrap()
                .root();
            assert_eq!(explicit_values, carried_values);
            assert_eq!(explicit_root, carried_root);
        });
    }

    #[test]
    fn ordered_variable_managed_db_applies_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = variable_config("ordered-variable-managed-db", &context);
            let db = <OrderedVariableDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);
            let missing = Sha256::hash(&[b"missing"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedVariableDb>(database, merkleized).await);
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let proof = guard.exclusion_proof(&missing).await.unwrap();
            assert!(proof.verify::<Sha256>(&missing, &guard.root()));
        });
    }

    #[test]
    fn ordered_managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-matches-sync-target", &context);
            let db =
                <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config.clone(), None)
                    .await
                    .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let verification_db = <OrderedFixedDb as ManagedDb<_>>::init(
                context.child("verification_db"),
                fixed_config("ordered-matches-sync-target-verification", &context),
                None,
            )
            .await
            .unwrap();
            let (verification_db, _) = verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            let verification_db = verification_db.sync().await.unwrap();

            let valid_target = <OrderedFixedDb as ManagedDb<_>>::sync_target(&verification_db);
            assert!(<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(&[b"wrong ops root"]);
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range =
                non_empty_range!(valid_target.range.start(), valid_target.range.end() + 1);
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }

    #[test]
    fn ordered_managed_db_bounded_initialization_to_target_round_trips() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("ordered-rewind-round-trip", &context);
            let db =
                <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config.clone(), None)
                    .await
                    .unwrap();
            let db = Shared::new("test", db);

            let key1 = Sha256::hash(&[b"key1"]);
            let value1 = Sha256::hash(&[b"value1"]);
            let metadata1 = Sha256::hash(&[b"metadata1"]);
            let batch1 = db
                .new_batch_for_test::<_>()
                .await
                .write(key1, Some(value1))
                .with_metadata(metadata1);
            let merkleized1 = crate::stateful::db::Unmerkleized::merkleize(batch1)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized1).await);
            }
            let target_after_first = {
                let guard = db.read().await;
                <OrderedFixedDb as ManagedDb<_>>::sync_target(&guard)
            };

            let key2 = Sha256::hash(&[b"key2"]);
            let value2 = Sha256::hash(&[b"value2"]);
            let metadata2 = Sha256::hash(&[b"metadata2"]);
            let batch2 = db
                .new_batch_for_test::<_>()
                .await
                .write(key2, Some(value2))
                .with_metadata(metadata2);
            let merkleized2 = crate::stateful::db::Unmerkleized::merkleize(batch2)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized2).await);
            }

            drop(db);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(
                context.child("cap"),
                config.clone(),
                Some(target_after_first.clone()),
            )
            .await
            .unwrap();
            let target_after_rewind = <OrderedFixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(target_after_rewind, target_after_first);
            drop(db);

            let mut wrong_root = target_after_first.clone();
            wrong_root.root = Sha256::hash(&[b"wrong initialization root"]);
            let mut behind = target_after_first.clone();
            behind.range = non_empty_range!(behind.range.start(), behind.range.end() + 1);
            let mut wrong_floor = target_after_first.clone();
            wrong_floor.range =
                non_empty_range!(wrong_floor.range.start() + 1, wrong_floor.range.end());
            for (index, target) in [wrong_root, behind, wrong_floor].into_iter().enumerate() {
                assert!(matches!(
                    <OrderedFixedDb as ManagedDb<_>>::init(
                        context.child("mismatch").with_attribute("case", index),
                        config.clone(),
                        Some(target),
                    )
                    .await,
                    Err(InitError::TargetMismatch)
                ));
                let reopened = <OrderedFixedDb as ManagedDb<_>>::init(
                    context.child("restart").with_attribute("case", index),
                    config.clone(),
                    None,
                )
                .await
                .unwrap();
                assert_eq!(
                    <OrderedFixedDb as ManagedDb<_>>::sync_target(&reopened),
                    target_after_first
                );
                drop(reopened);
            }
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("matches-sync-target", &context);
            let db = FixedDb::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let verification_db = FixedDb::init(
                context.child("verification_db"),
                fixed_config("matches-sync-target-verification", &context),
                None,
            )
            .await
            .unwrap();
            let (verification_db, _) = verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            let verification_db = verification_db.sync().await.unwrap();

            let valid_target = <FixedDb as ManagedDb<_>>::sync_target(&verification_db);
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(&[b"wrong ops root"]);
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range =
                non_empty_range!(valid_target.range.start(), valid_target.range.end() + 1);
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }

    /// Finalize two targets, reopen at the first, apply without finalizing, then crash before any
    /// sync. Recovery must yield a legitimate history, the first target must reopen, and the
    /// discarded second target must be rejected.
    #[test]
    fn managed_db_bounded_init_then_apply_crash_recovers_history() {
        // One operation per page makes the initialization truncation page aligned and one blob
        // keeps both histories' writes overlapping.
        type FixedOp = FixedOperation<mmr::Family, Digest, Digest>;
        fn config(pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
            let page_size = NonZeroU16::new(<FixedOp as FixedSize>::SIZE as u16).unwrap();
            let mut config = fixed_config("bounded-init-crash", pooler);
            config.journal_config.page_cache =
                CacheRef::from_pooler(pooler, page_size, PAGE_CACHE_SIZE);
            config.journal_config.items_per_blob = NZU64!(1000);
            config.merkle_config.items_per_blob = NZU64!(1000);
            config
        }
        fn batch_for(i: u8) -> (Digest, Digest, Digest) {
            (
                Sha256::hash(&[b"key", &[i]]),
                Sha256::hash(&[b"value", &[i]]),
                Sha256::hash(&[b"metadata", &[i]]),
            )
        }

        // Keep unsynced writes and drop unsynced resizes at the crash.
        let runtime = DeterministicConfig::default().with_storage_fault_config(
            FaultConfig::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(1.0),
                mode: PartialWriteMode::Prefix,
            }),
        );
        let ((first, second, applied), checkpoint) = deterministic::Runner::new(runtime)
            .start_and_recover(|context| async move {
                let db = FixedDb::init(context.child("db"), config(&context), None)
                    .await
                    .unwrap();
                let db = Shared::new("test", db);

                let mut targets = Vec::new();
                for i in 1..=2 {
                    let (key, value, metadata) = batch_for(i);
                    let batch = db
                        .new_batch_for_test::<_>()
                        .await
                        .write(key, Some(value))
                        .with_metadata(metadata);
                    let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                        .await
                        .unwrap();
                    let (slot, database) = db.write().await;
                    slot.put(apply_and_finalize::<FixedDb>(database, merkleized).await);
                    let guard = db.read().await;
                    targets.push(<FixedDb as ManagedDb<_>>::sync_target(&guard));
                }
                let second = targets.pop().unwrap();
                let first = targets.pop().unwrap();
                assert_ne!(first, second);
                drop(db);

                // Reopen at the first target, discarding the second.
                let db = <FixedDb as ManagedDb<_>>::init(
                    context.child("bounded"),
                    config(&context),
                    Some(first.clone()),
                )
                .await
                .unwrap();
                assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
                let db = Shared::new("test", db);

                // Apply over the discarded target's bytes, then crash without finalizing.
                let (key, value, metadata) = batch_for(3);
                let batch = db
                    .new_batch_for_test::<_>()
                    .await
                    .write(key, Some(value))
                    .with_metadata(metadata);
                let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                    .await
                    .unwrap();
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let applied = <FixedDb as ManagedDb<_>>::sync_target(&database);
                assert_ne!(applied, first);
                assert_ne!(applied, second);
                slot.put(database);
                (first, second, applied)
            });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            // Only the first target, or the applied batch on top of it, is a legitimate history.
            let db = FixedDb::init(context.child("recover"), config(&context), None)
                .await
                .unwrap();
            let recovered = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert!(
                recovered == first || recovered == applied,
                "recovered {recovered:?} from neither history"
            );
            drop(db);

            // The first target reopens and durably discards anything above it.
            let db = <FixedDb as ManagedDb<_>>::init(
                context.child("first"),
                config(&context),
                Some(first.clone()),
            )
            .await
            .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
            drop(db);

            // The discarded second target cannot be restored.
            assert!(matches!(
                <FixedDb as ManagedDb<_>>::init(
                    context.child("second"),
                    config(&context),
                    Some(second),
                )
                .await,
                Err(InitError::TargetMismatch)
            ));

            // A rejected initialization leaves the first target in place.
            let db = FixedDb::init(context.child("restart"), config(&context), None)
                .await
                .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
        });
    }
}
