//! [`ManagedDb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! The QMDB batch API passes `&db` to `get()` and `merkleize()` for
//! read-through to applied state. The wrapper types here keep that shape: reads and
//! merkleization borrow the database at each call, so batches hold no database
//! handle and dropping one never drops the database.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_standard_db,
};
use commonware_codec::{Codec, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    index::{
        Ordered as OrderedIndex, Unordered as UnorderedIndex, unordered::Index as UnorderedIdx,
    },
    journal::{
        authenticated,
        contiguous::{
            Contiguous, Mutable, Snapshottable, fixed::Journal as FixedJournal,
            variable::Journal as VariableJournal,
        },
    },
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::{
            FixedConfig, VariableConfig,
            batch::{MerkleizedBatch, Staged, UnmerkleizedBatch},
            db::Db,
            initial_root,
            operation::{Operation, Update},
            ordered, unordered,
            value::{self, FixedEncoding, ValueEncoding, VariableEncoding},
        },
        operation::Key,
        sync::{self, Target as AnySyncTarget},
    },
    translator::Translator,
};
use commonware_utils::{Array, channel::mpsc, non_empty_range};
use std::{
    ops::{Deref, Range},
    sync::Arc,
};

// Matches commonware_storage::qmdb::any::BITMAP_CHUNK_BYTES, which is crate-private.
const ANY_BITMAP_CHUNK_BYTES: usize = 64;

/// Wraps a QMDB [`UnmerkleizedBatch`] to implement [`Unmerkleized`](super::Unmerkleized).
pub struct AnyUnmerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, S>,
    metadata: Option<U::Value>,
}

/// Staged batch returned by [`AnyUnmerkleized::stage`], wrapping a QMDB [`Staged`].
///
/// A branch-scoped view of the database: it
/// stays valid only while every batch finalized on the database is an ancestor of this batch
/// (see [`MerkleizedBatch`]'s branch-validity contract).
pub struct AnyStaged<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    staged: Staged<F, H, U, S>,
    metadata: Option<U::Value>,
}

/// Key-value operations shared by both `any` update kinds.
impl<F, H, U, S> AnyUnmerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
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
    pub async fn get<E, C, I>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Option<U::Value>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.batch.get(key, db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Vec<Option<U::Value>>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.batch.get_many(keys, db).await
    }

    /// Read multiple values and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn stage<E, C, I>(
        self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<(Vec<Option<U::Value>>, AnyStaged<F, H, U, S>), Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let (values, staged) = self.batch.stage(keys, db).await?;
        Ok((
            values,
            AnyStaged {
                staged,
                metadata: self.metadata,
            },
        ))
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

/// Wraps a QMDB [`MerkleizedBatch`] to implement [`Merkleized`](super::Merkleized).
pub struct AnyMerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, U, S>>,
}

impl<F, H, U, S> Deref for AnyUnmerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Target = UnmerkleizedBatch<F, H, U, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, H, U, S> Deref for AnyMerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
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
impl<F, H, U, S> AnyStaged<F, H, U, S>
where
    F: Family,
    U: Update,
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
    pub async fn expand<E, C, I>(
        self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<(Range<usize>, Vec<Option<U::Value>>, Self), Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let (range, values, staged) = self.staged.expand(keys, db).await?;
        Ok((
            range,
            values,
            Self {
                staged,
                metadata: self.metadata,
            },
        ))
    }
}

/// Staged merkleize for the `any` unordered update kind.
impl<F, H, K, V, S> AnyStaged<F, H, unordered::Update<K, V>, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](AnyStaged::expand) before
    /// this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](AnyStaged::expand) ranges. Metadata
    /// set via [`with_metadata`](AnyStaged::with_metadata) (or before staging) is committed with the
    /// returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize<E, C, I>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        db: &Db<F, E, C, I, H, unordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<AnyMerkleized<F, H, unordered::Update<K, V>, S>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let inner = self
            .staged
            .merkleize(updates, upserts, self.metadata, db)
            .await?;
        Ok(AnyMerkleized { inner })
    }
}

/// Staged merkleize for the `any` ordered update kind.
impl<F, H, K, V, S> AnyStaged<F, H, ordered::Update<K, V>, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](AnyStaged::expand) before
    /// this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](AnyStaged::expand) ranges. Metadata
    /// set via [`with_metadata`](AnyStaged::with_metadata) (or before staging) is committed with the
    /// returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize<E, C, I>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        db: &Db<F, E, C, I, H, ordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<AnyMerkleized<F, H, ordered::Update<K, V>, S>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
        I: OrderedIndex<Value = Location<F>> + 'static,
    {
        let inner = self
            .staged
            .merkleize(updates, upserts, self.metadata, db)
            .await?;
        Ok(AnyMerkleized { inner })
    }
}

/// Read-through operations for the `any` merkleized batch.
impl<F, H, U, S> AnyMerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get<E, C, I>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Option<U::Value>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get(key, db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Vec<Option<U::Value>>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get_many(keys, db).await
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` unordered update kind.
impl<F, E, C, I, H, K, V, S>
    UnmerkleizedTrait<Db<F, E, C, I, H, unordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>>
    for AnyUnmerkleized<F, H, unordered::Update<K, V>, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, H, unordered::Update<K, V>, S>;
    type Error = Error<F>;

    async fn merkleize(
        self,
        db: &Db<F, E, C, I, H, unordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Self::Merkleized, Error<F>> {
        let merkleized = self.batch.merkleize(db, self.metadata).await?;
        Ok(AnyMerkleized { inner: merkleized })
    }
}

/// Implement [`Unmerkleized`](UnmerkleizedTrait) for the `any` ordered update kind.
impl<F, E, C, I, H, K, V, S>
    UnmerkleizedTrait<Db<F, E, C, I, H, ordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>>
    for AnyUnmerkleized<F, H, ordered::Update<K, V>, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Merkleized = AnyMerkleized<F, H, ordered::Update<K, V>, S>;
    type Error = Error<F>;

    async fn merkleize(
        self,
        db: &Db<F, E, C, I, H, ordered::Update<K, V>, ANY_BITMAP_CHUNK_BYTES, S>,
    ) -> Result<Self::Merkleized, Error<F>> {
        let merkleized = self.batch.merkleize(db, self.metadata).await?;
        Ok(AnyMerkleized { inner: merkleized })
    }
}

/// Implement [`Merkleized`](MerkleizedTrait) for all supported `any` update kinds.
impl<F, H, U, S> MerkleizedTrait for AnyMerkleized<F, H, U, S>
where
    F: Family,
    U: Update,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Digest = H::Digest;
    type Unmerkleized = AnyUnmerkleized<F, H, U, S>;
    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            metadata: None,
        }
    }
}

/// Implement [`ManagedDb`] for unordered QMDB databases with fixed-size values.
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
    E: Context + Spawner,
    K: Array,
    V: value::FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
{
    type Unmerkleized = AnyUnmerkleized<F, H, unordered::Update<K, FixedEncoding<V>>, S>;
    type Merkleized = AnyMerkleized<F, H, unordered::Update<K, FixedEncoding<V>>, S>;
    type Error = Error<F>;
    type Config = FixedConfig<T, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = Arc<
        authenticated::Snapshot<
            F,
            E,
            <FixedJournal<E, Operation<F, unordered::Update<K, FixedEncoding<V>>>> as Snapshottable>::Reader,
            H,
        >,
    >;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, unordered::Update<K, FixedEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: Db::new_batch(self),
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn finalize(
        self,
        batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        let (db, handle) = db.start_sync().await?;
        let (db, snapshot) = db.snapshot().await?;
        Ok((db, Arc::new(snapshot), handle))
    }

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Error<F>> {
        let (db, snapshot) = self.snapshot().await?;
        Ok((db, Arc::new(snapshot)))
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget::new(
            self.root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.range.end()).await?;
        let db = db.sync().await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
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
    E: Context + Spawner,
    K: Key,
    V: value::VariableValue + 'static,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, unordered::Update<K, VariableEncoding<V>>>: Codec,
{
    type Unmerkleized = AnyUnmerkleized<F, H, unordered::Update<K, VariableEncoding<V>>, S>;
    type Merkleized = AnyMerkleized<F, H, unordered::Update<K, VariableEncoding<V>>, S>;
    type Error = Error<F>;
    type Config = VariableConfig<
        T,
        <Operation<F, unordered::Update<K, VariableEncoding<V>>> as CodecRead>::Cfg,
        S,
    >;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = Arc<
        authenticated::Snapshot<
            F,
            E,
            <VariableJournal<E, Operation<F, unordered::Update<K, VariableEncoding<V>>>> as Snapshottable>::Reader,
            H,
        >,
    >;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, unordered::Update<K, VariableEncoding<V>>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        AnyUnmerkleized {
            batch: Db::new_batch(self),
            metadata: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn finalize(
        self,
        batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        let (db, handle) = db.start_sync().await?;
        let (db, snapshot) = db.snapshot().await?;
        Ok((db, Arc::new(snapshot), handle))
    }

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Error<F>> {
        let (db, snapshot) = self.snapshot().await?;
        Ok((db, Arc::new(snapshot)))
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget::new(
            self.root(),
            non_empty_range!(self.sync_boundary(), bounds.end),
        )
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.range.end()).await?;
        let db = db.sync().await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{Location, full::Config as MerkleConfig, mmr},
        qmdb::{
            self,
            any::unordered::fixed,
            sync::{Request, Response, Source as SyncSource},
        },
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
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
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    /// The glue staged wrapper (`AnyUnmerkleized::stage` -> `AnyStaged::expand` ->
    /// `AnyStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an upsert, and metadata flow (both set
    /// on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow through the wrapper.
    #[test]
    fn unordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("unordered-fixed-glue-staged", &context);
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let key = |i: u64| Sha256::hash(&[&i.to_be_bytes()]);
            let val = |i: u64| Sha256::hash(&[&(i + 10_000).to_be_bytes()]);
            let metadata = Sha256::hash(&[b"metadata"]);

            // Seed keys 0..50 and finalize.
            let mut seed = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db);
            for i in 0..50u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(seed, &db)
                .await
                .unwrap();
            let db = {
                let (db, _, durability) =
                    <UnorderedFixedDb as ManagedDb<_>>::finalize(db, merkleized)
                        .await
                        .unwrap();
                durability.await.expect("finalize flush failed");
                db
            };

            // Read set: key(1) updated, key(2) deleted, key(999) missing -> created.
            let read_keys = [key(1), key(2), key(999)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let indexed_updates = vec![(0, Some(val(1_000))), (1, None), (2, Some(val(1_001)))];
            let upserts = vec![(key(3), Some(val(1_002)))];

            // Explicit path.
            let mut explicit = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db);
            let explicit_values = explicit.get_many(&keys, &db).await.unwrap();
            for (slot, value) in &indexed_updates {
                explicit = explicit.write(read_keys[*slot], *value);
            }
            for (k, v) in &upserts {
                explicit = explicit.write(*k, *v);
            }
            let explicit_root =
                crate::stateful::db::Unmerkleized::merkleize(explicit.with_metadata(metadata), &db)
                    .await
                    .unwrap()
                    .root();

            // Staged path, with metadata set on the staged handle.
            let staged_batch = <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db);
            let split = 2;
            let (mut staged_values, staged) =
                staged_batch.stage(&keys[..split], &db).await.unwrap();
            let (range, suffix_values, staged) = staged.expand(&keys[split..], &db).await.unwrap();
            assert_eq!(range, split..keys.len());
            staged_values.extend(suffix_values);
            let staged_root = staged
                .with_metadata(metadata)
                .merkleize(indexed_updates.clone(), upserts.clone(), &db)
                .await
                .unwrap()
                .root();

            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_root, staged_root);

            // Metadata set before staging must be carried through to staged merkleize.
            let carried_batch =
                <UnorderedFixedDb as ManagedDb<_>>::new_batch(&db).with_metadata(metadata);
            let (carried_values, staged) = carried_batch.stage(&keys, &db).await.unwrap();
            let carried_root = staged
                .merkleize(indexed_updates.clone(), upserts.clone(), &db)
                .await
                .unwrap()
                .root();
            assert_eq!(explicit_values, carried_values);
            assert_eq!(explicit_root, carried_root);
        });
    }

    type DelayedFixedDb = fixed::Db<
        mmr::Family,
        DelayedSyncContext<deterministic::Context>,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

    /// `finalize` must return, with the batch readable on the returned
    /// database, while its flush is still parked at the storage layer.
    /// Durability is reported only on the returned handle, and the captured
    /// snapshot must already prove the post-apply state.
    #[test]
    fn finalize_defers_flush_to_returned_handle() {
        deterministic::Runner::default().start(|context| async move {
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let config = fixed_config("unordered-fixed-deferred", &delayed);
            let db = drive_pending_syncs(
                &pending,
                <DelayedFixedDb as ManagedDb<_>>::init(delayed.child("db"), config),
            )
            .await
            .unwrap();

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let batch = <DelayedFixedDb as ManagedDb<_>>::new_batch(&db).write(key, Some(value));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch, &db)
                .await
                .unwrap();
            let (db, snapshot, sync) = <DelayedFixedDb as ManagedDb<_>>::finalize(db, merkleized)
                .await
                .unwrap();

            // The flush is parked, yet the batch is already readable.
            assert!(
                pending.starts() > pending.completions(),
                "finalize must leave its flush parked",
            );
            assert_eq!(db.get(&key).await.unwrap(), Some(value));

            // The snapshot freezes at the post-apply boundary and proves the
            // just-applied state, independent of durability.
            let size = Location::new(snapshot.bounds().end);
            assert_eq!(
                size,
                db.bounds().end,
                "snapshot must cover the applied batch"
            );
            let (response, _) = SyncSource::serve(
                &*snapshot,
                Request::Boundary {
                    size,
                    start: size - 1,
                },
            )
            .await
            .expect("captured snapshot must serve its tip");
            let Response::Boundary { proof, op, .. } = response else {
                panic!("expected a boundary response");
            };
            let root = proof
                .reconstruct_root(&qmdb::hasher::<Sha256>(), &[op.encode()], size - 1)
                .expect("served proof must reconstruct");
            assert_eq!(root, db.root(), "snapshot must prove the post-apply root");

            release_pending_syncs(&pending);
            drive_pending_syncs(&pending, sync)
                .await
                .expect("flush must succeed once released");
        });
    }
}
