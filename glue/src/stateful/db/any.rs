//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to committed state. This module provides wrapper types
//! that capture `Arc<TracedAsyncRwLock<Db>>` alongside the raw batch so the
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
        unordered::Index as UnorderedIdx, Ordered as OrderedIndex, Unordered as UnorderedIndex,
    },
    journal::contiguous::{
        fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Contiguous, Mutable,
    },
    merkle::{Family, Location},
    qmdb::{
        any::{
            batch::{MerkleizedBatch, Staged, UnmerkleizedBatch},
            db::Db,
            operation::{Operation, Update},
            ordered, unordered,
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
            FixedConfig, VariableConfig,
        },
        operation::Key,
        sync::{self, resolver::Resolver, Target as AnySyncTarget},
        Error,
    },
    translator::Translator,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::TracedAsyncRwLock, Array};
use std::{
    ops::{Deref, Range},
    sync::Arc,
};

// Matches commonware_storage::qmdb::any::BITMAP_CHUNK_BYTES, which is crate-private.
const ANY_BITMAP_CHUNK_BYTES: usize = 64;

type AnyDbHandle<F, E, C, I, H, U, S> =
    Arc<TracedAsyncRwLock<Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>>>;

/// Wraps a QMDB [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct AnyUnmerkleized<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, S>,
    db: AnyDbHandle<F, E, C, I, H, U, S>,
    metadata: Option<U::Value>,
}

/// Staged batch returned by [`AnyUnmerkleized::stage`], wrapping a QMDB [`Staged`] with a
/// reference to the parent database.
///
/// Like any speculative batch, this handle is a branch-scoped view of the shared database: it
/// stays valid only while every batch finalized on the database is an ancestor of this batch
/// (see [`MerkleizedBatch`]'s branch-validity contract).
pub struct AnyStaged<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    staged: Staged<F, H, U, S>,
    db: AnyDbHandle<F, E, C, I, H, U, S>,
    metadata: Option<U::Value>,
}

/// Key-value operations for the `any` unordered update kind.
impl<F, E, C, I, H, K, V, S> AnyUnmerkleized<F, E, C, I, H, unordered::Update<K, V>, S>
where
    F: Family,
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

    /// Read multiple values and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn stage(
        self,
        keys: &[&K],
    ) -> Result<
        (
            Vec<Option<V::Value>>,
            AnyStaged<F, E, C, I, H, unordered::Update<K, V>, S>,
        ),
        Error<F>,
    > {
        let Self {
            batch,
            db,
            metadata,
        } = self;
        let (values, staged) = {
            let guard = db.read().await;
            batch.stage(keys, &*guard).await?
        };
        Ok((
            values,
            AnyStaged {
                staged,
                db,
                metadata,
            },
        ))
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct AnyMerkleized<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, U, S>>,
    db: AnyDbHandle<F, E, C, I, H, U, S>,
}

impl<F, E, C, I, H, U, S> Deref for AnyUnmerkleized<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Target = UnmerkleizedBatch<F, H, U, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, C, I, H, U, S> Deref for AnyMerkleized<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Target = MerkleizedBatch<F, H::Digest, U, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Read-expansion operations for the `any` staged batch.
impl<F, E, C, I, H, U, S> AnyStaged<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
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
            staged.expand(keys, &*guard).await?
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

/// Staged merkleize for the `any` unordered update kind.
impl<F, E, C, I, H, K, V, S> AnyStaged<F, E, C, I, H, unordered::Update<K, V>, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
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
    /// Consumes the staged handle and write vectors. Call [`expand`](AnyStaged::expand) before
    /// this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert; `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](AnyStaged::expand) ranges. Metadata
    /// set via [`with_metadata`](AnyStaged::with_metadata) (or before staging) is committed with the
    /// returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<AnyMerkleized<F, E, C, I, H, unordered::Update<K, V>, S>, Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let inner = {
            let guard = db.read().await;
            staged
                .merkleize(updates, upserts, metadata, &*guard)
                .await?
        };
        Ok(AnyMerkleized { inner, db })
    }
}

/// Staged merkleize for the `any` ordered update kind.
impl<F, E, C, I, H, K, V, S> AnyStaged<F, E, C, I, H, ordered::Update<K, V>, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
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
    /// Consumes the staged handle and write vectors. Call [`expand`](AnyStaged::expand) before
    /// this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert; `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](AnyStaged::expand) ranges. Metadata
    /// set via [`with_metadata`](AnyStaged::with_metadata) (or before staging) is committed with the
    /// returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<AnyMerkleized<F, E, C, I, H, ordered::Update<K, V>, S>, Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let inner = {
            let guard = db.read().await;
            staged
                .merkleize(updates, upserts, metadata, &*guard)
                .await?
        };
        Ok(AnyMerkleized { inner, db })
    }
}

/// Key-value operations for the `any` ordered update kind.
impl<F, E, C, I, H, K, V, S> AnyUnmerkleized<F, E, C, I, H, ordered::Update<K, V>, S>
where
    F: Family,
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

    /// Read multiple values and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn stage(
        self,
        keys: &[&K],
    ) -> Result<
        (
            Vec<Option<V::Value>>,
            AnyStaged<F, E, C, I, H, ordered::Update<K, V>, S>,
        ),
        Error<F>,
    > {
        let Self {
            batch,
            db,
            metadata,
        } = self;
        let (values, staged) = {
            let guard = db.read().await;
            batch.stage(keys, &*guard).await?
        };
        Ok((
            values,
            AnyStaged {
                staged,
                db,
                metadata,
            },
        ))
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: K, value: Option<V::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Read-through operations for the `any` merkleized batch.
impl<F, E, C, I, H, U, S> AnyMerkleized<F, E, C, I, H, U, S>
where
    F: Family,
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

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` unordered update kind.
impl<F, E, C, I, H, K, V, S> UnmerkleizedTrait
    for AnyUnmerkleized<F, E, C, I, H, unordered::Update<K, V>, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, E, C, I, H, unordered::Update<K, V>, S>;
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
impl<F, E, C, I, H, K, V, S> UnmerkleizedTrait
    for AnyUnmerkleized<F, E, C, I, H, ordered::Update<K, V>, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, E, C, I, H, ordered::Update<K, V>, S>;
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
impl<F, E, C, I, H, U, S> MerkleizedTrait for AnyMerkleized<F, E, C, I, H, U, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
    AnyUnmerkleized<F, E, C, I, H, U, S>: UnmerkleizedTrait,
{
    type Digest = H::Digest;
    type Unmerkleized = AnyUnmerkleized<F, E, C, I, H, U, S>;

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
/// `new_batch` captures the `Arc<TracedAsyncRwLock<Db>>` in the returned
/// wrapper so that `get()` and `merkleize()` can read through to
/// committed state.
///
/// `finalize` applies the merkleized batch's changeset and durably
/// commits it to disk.
impl<F, E, K, V, H, T, S> ManagedDb<E>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        ANY_BITMAP_CHUNK_BYTES,
        S,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
{
    type Unmerkleized = AnyUnmerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        S,
    >;
    type Merkleized = AnyMerkleized<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        S,
    >;
    type Error = Error<F>;
    type Config = FixedConfig<T, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<TracedAsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await
    }

    async fn prune(&mut self, target: &Self::SyncTarget) -> Result<(), Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget::new(
            self.root(),
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

/// Implement [`ManagedDb`] for unordered QMDB databases with variable-size values.
impl<F, E, K, V, H, T, S> ManagedDb<E>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        ANY_BITMAP_CHUNK_BYTES,
        S,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = AnyUnmerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        S,
    >;
    type Merkleized = AnyMerkleized<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        S,
    >;
    type Error = Error<F>;
    type Config = VariableConfig<
        T,
        <Operation<F, unordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
        S,
    >;
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<TracedAsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        AnyUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == Location::<F>::new(batch.bounds().total_size)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.sync().await
    }

    async fn prune(&mut self, target: &Self::SyncTarget) -> Result<(), Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget::new(
            self.root(),
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

impl<F, E, K, V, H, T, S, R> StateSyncDb<E, R>
    for Db<
        F,
        E,
        FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, FixedEncoding<V>>,
        ANY_BITMAP_CHUNK_BYTES,
        S,
    >
where
    F: Family,
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

impl<F, E, K, V, H, T, S, R> StateSyncDb<E, R>
    for Db<
        F,
        E,
        VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>>,
        UnorderedIdx<T, Location<F>>,
        H,
        unordered::Update<K, VariableEncoding<V>>,
        ANY_BITMAP_CHUNK_BYTES,
        S,
    >
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{full::Config as MerkleConfig, mmr},
        qmdb::any::unordered::fixed,
        translator::TwoCap,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type UnorderedFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("stateful-any-journal-{suffix}"),
                metadata_partition: format!("stateful-any-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: format!("stateful-any-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
        }
    }

    /// The glue staged wrapper (`AnyUnmerkleized::stage` -> `AnyStaged::expand` ->
    /// `AnyStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an upsert, and metadata flow (both set
    /// on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow and db-handle pairing through the wrapper.
    #[test]
    fn unordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("unordered-fixed-glue-staged", &context);
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Arc::new(TracedAsyncRwLock::new("test", db));

            let key = |i: u64| Sha256::hash(&i.to_be_bytes());
            let val = |i: u64| Sha256::hash(&(i + 10_000).to_be_bytes());
            let metadata = Sha256::hash(b"metadata");

            // Seed keys 0..50 and finalize.
            let mut seed = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db).await;
            for i in 0..50u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(seed)
                .await
                .unwrap();
            {
                let mut guard = db.write().await;
                <UnorderedFixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            // Read set: key(1) updated, key(2) deleted, key(999) missing -> created.
            let read_keys = [key(1), key(2), key(999)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let indexed_updates = vec![(0, Some(val(1_000))), (1, None), (2, Some(val(1_001)))];
            let upserts = vec![(key(3), Some(val(1_002)))];

            // Explicit path.
            let mut explicit = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db).await;
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
            let staged_batch = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db).await;
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
            let carried_batch = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .with_metadata(metadata);
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
}
