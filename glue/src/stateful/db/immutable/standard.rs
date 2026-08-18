//! Journaled [`ManagedDb`] implementation for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Immutable databases support adding new keyed values but not updates or
//! deletions. Keyed batch reads lease the database through the batch's
//! [`Reader`] because the immutable proof snapshot carries no keyed
//! index.

use crate::stateful::db::{
    LogSnapshot, ManagedDb, Merkleized as MerkleizedTrait, Reader, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_standard_db,
};
use commonware_codec::{Codec, EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    journal::contiguous::{
        Mutable, fixed::Journal as FixedJournal, variable::Journal as VariableJournal,
    },
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        immutable::{
            Immutable, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            fixed, initial_root, variable,
        },
        operation::Key,
        sync::{self, Target as AnySyncTarget},
    },
    translator::Translator,
};
use commonware_utils::{Array, channel::mpsc, non_empty_range};
use std::{ops::Deref, sync::Arc};

/// Reader over the immutable database a wrapper batch reads through.
type DbHandle<F, E, K, V, C, H, T, S> = Reader<Immutable<F, E, K, V, C, H, T, S>>;

/// Wraps an immutable [`UnmerkleizedBatch`] to implement
/// [`Unmerkleized`](crate::stateful::db::Unmerkleized).
pub struct ImmutableUnmerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, K, V, S>,
    metadata: Option<V::Value>,
    inactivity_floor: Location<F>,
    reader: DbHandle<F, E, K, V, C, H, T, S>,
}

impl<F, E, K, V, C, H, T, S> Deref for ImmutableUnmerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<F, H, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, K, V, C, H, T, S> ImmutableUnmerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor to include within the next [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = floor;
        self
    }

    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        self.batch.get(key, &*self.reader.read().await).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        self.batch.get_many(keys, &*self.reader.read().await).await
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an immutable [`MerkleizedBatch`] to implement
/// [`Merkleized`](crate::stateful::db::Merkleized).
pub struct ImmutableMerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, K, V, S>>,
    reader: DbHandle<F, E, K, V, C, H, T, S>,
}

impl<F, E, K, V, C, H, T, S> Clone for ImmutableMerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            reader: self.reader.clone(),
        }
    }
}

impl<F, E, K, V, C, H, T, S> Deref for ImmutableMerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Target = MerkleizedBatch<F, H::Digest, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, K, V, C, H, T, S> ImmutableMerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        self.inner.get(key, &*self.reader.read().await).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        self.inner.get_many(keys, &*self.reader.read().await).await
    }
}

impl<F, E, K, V, C, H, T, S> UnmerkleizedTrait for ImmutableUnmerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Merkleized = ImmutableMerkleized<F, E, K, V, C, H, T, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let Self {
            batch,
            metadata,
            inactivity_floor,
            reader,
        } = self;
        let inner = batch
            .merkleize(&*reader.read().await, metadata, inactivity_floor)
            .await?;
        Ok(ImmutableMerkleized { inner, reader })
    }
}

impl<F, E, K, V, C, H, T, S> MerkleizedTrait for ImmutableMerkleized<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnmerkleized<F, E, K, V, C, H, T, S>;
    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            metadata: None,
            inactivity_floor: self.inner.bounds().inactivity_floor,
            reader: self.reader.clone(),
        }
    }
}

impl<F, E, K, V, H, T, S> ManagedDb<E> for fixed::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
{
    type Unmerkleized = ImmutableUnmerkleized<
        F,
        E,
        K,
        FixedEncoding<V>,
        FixedJournal<E, fixed::Operation<F, K, V>>,
        H,
        T,
        S,
    >;
    type Merkleized = ImmutableMerkleized<
        F,
        E,
        K,
        FixedEncoding<V>,
        FixedJournal<E, fixed::Operation<F, K, V>>,
        H,
        T,
        S,
    >;
    type Error = Error<F>;
    type Config = fixed::Config<T, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = LogSnapshot<F, E, FixedJournal<E, fixed::Operation<F, K, V>>, H>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, K, FixedEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    async fn new_batch(reader: Reader<Self>) -> Self::Unmerkleized {
        let (batch, inactivity_floor) = {
            let db = reader.read().await;
            (db.new_batch(), db.inactivity_floor_loc())
        };
        ImmutableUnmerkleized {
            batch,
            metadata: None,
            inactivity_floor,
            reader,
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
        let (db, sync) = db.start_sync().await?;
        let (db, snapshot) = db.snapshot().await?;
        Ok((db, Arc::new(snapshot), sync))
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

impl<F, E, K, V, H, T, S> ManagedDb<E> for variable::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
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
        S,
    >;
    type Merkleized = ImmutableMerkleized<
        F,
        E,
        K,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<F, K, V>>,
        H,
        T,
        S,
    >;
    type Error = Error<F>;
    type Config = variable::Config<T, <variable::Operation<F, K, V> as CodecRead>::Cfg, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = LogSnapshot<F, E, VariableJournal<E, variable::Operation<F, K, V>>, H>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, K, VariableEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    async fn new_batch(reader: Reader<Self>) -> Self::Unmerkleized {
        let (batch, inactivity_floor) = {
            let db = reader.read().await;
            (db.new_batch(), db.inactivity_floor_loc())
        };
        ImmutableUnmerkleized {
            batch,
            metadata: None,
            inactivity_floor,
            reader,
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
        let (db, sync) = db.start_sync().await?;
        let (db, snapshot) = db.snapshot().await?;
        Ok((db, Arc::new(snapshot), sync))
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

impl<F, E, K, V, H, T, R, S> StateSyncDb<E, R> for fixed::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
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

impl<F, E, K, V, H, T, R, S> StateSyncDb<E, R> for variable::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    T: Translator,
    S: Strategy,
    variable::Operation<F, K, V>: Codec,
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
