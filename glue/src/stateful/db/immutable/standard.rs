//! Journaled [`ManagedDb`] implementation for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Immutable databases support adding new keyed values but not updates or
//! deletions. Keyed batch reads borrow the database because the
//! immutable proof snapshot carries no keyed index.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_standard_db,
};
use commonware_codec::{Codec, EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    journal::{
        authenticated,
        contiguous::{
            Mutable, Snapshottable, fixed::Journal as FixedJournal,
            variable::Journal as VariableJournal,
        },
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

/// Wraps an immutable [`UnmerkleizedBatch`] to implement
/// [`Unmerkleized`](crate::stateful::db::Unmerkleized).
pub struct ImmutableUnmerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, K, V, S>,
    metadata: Option<V::Value>,
    inactivity_floor: Location<F>,
}

impl<F, K, V, H, S> Deref for ImmutableUnmerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<F, H, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, K, V, H, S> ImmutableUnmerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
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
    pub async fn get<E, C, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        T: Translator,
    {
        self.batch.get(key, db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, T>(
        &self,
        keys: &[&K],
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        T: Translator,
    {
        self.batch.get_many(keys, db).await
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an immutable [`MerkleizedBatch`] to implement
/// [`Merkleized`](crate::stateful::db::Merkleized).
pub struct ImmutableMerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, K, V, S>>,
}

impl<F, K, V, H, S> Deref for ImmutableMerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Target = MerkleizedBatch<F, H::Digest, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, K, V, H, S> ImmutableMerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get<E, C, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        T: Translator,
    {
        self.inner.get(key, db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, T>(
        &self,
        keys: &[&K],
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        T: Translator,
    {
        self.inner.get_many(keys, db).await
    }
}

impl<F, E, K, V, C, H, T, S> UnmerkleizedTrait<Immutable<F, E, K, V, C, H, T, S>>
    for ImmutableUnmerkleized<F, K, V, H, S>
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
    type Merkleized = ImmutableMerkleized<F, K, V, H, S>;
    type Error = Error<F>;

    async fn merkleize(
        self,
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Self::Merkleized, Error<F>> {
        let merkleized = self
            .batch
            .merkleize(db, self.metadata, self.inactivity_floor)
            .await;
        Ok(ImmutableMerkleized { inner: merkleized })
    }
}

impl<F, K, V, H, S> MerkleizedTrait for ImmutableMerkleized<F, K, V, H, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnmerkleized<F, K, V, H, S>;
    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            metadata: None,
            inactivity_floor: self.inner.bounds().inactivity_floor,
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
    type Unmerkleized = ImmutableUnmerkleized<F, K, FixedEncoding<V>, H, S>;
    type Merkleized = ImmutableMerkleized<F, K, FixedEncoding<V>, H, S>;
    type Error = Error<F>;
    type Config = fixed::Config<T, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = Arc<
        authenticated::Snapshot<
            F,
            E,
            <FixedJournal<E, fixed::Operation<F, K, V>> as Snapshottable>::Reader,
            H,
        >,
    >;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, K, FixedEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: Self::new_batch(self),
            metadata: None,
            inactivity_floor: self.inactivity_floor_loc(),
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
    type Unmerkleized = ImmutableUnmerkleized<F, K, VariableEncoding<V>, H, S>;
    type Merkleized = ImmutableMerkleized<F, K, VariableEncoding<V>, H, S>;
    type Error = Error<F>;
    type Config = variable::Config<T, <variable::Operation<F, K, V> as CodecRead>::Cfg, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;
    type Snapshot = Arc<
        authenticated::Snapshot<
            F,
            E,
            <VariableJournal<E, variable::Operation<F, K, V>> as Snapshottable>::Reader,
            H,
        >,
    >;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, K, VariableEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: Self::new_batch(self),
            metadata: None,
            inactivity_floor: self.inactivity_floor_loc(),
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
