//! [`Qmdb`] adapters for journaled QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Immutable databases support adding new keyed values but not updates or
//! deletions. The wrapper types here capture a [`Shared`] database handle
//! so the batch API can read through to applied state.

use crate::stateful::db::{
    Merkleized as MerkleizedTrait, Shared, Unmerkleized as UnmerkleizedTrait,
    qmdb::{Checkpoint, Qmdb},
};
use commonware_codec::{Codec, EncodeShared};
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
        sync,
    },
    translator::Translator,
};
use commonware_utils::Array;
use std::{ops::Deref, sync::Arc};

/// Shared handle to an immutable database.
type ImmutableDbHandle<F, E, K, V, C, H, T, S> = Shared<Immutable<F, E, K, V, C, H, T, S>>;

/// Wraps an immutable [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](crate::stateful::db::Unmerkleized) trait.
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
    db: ImmutableDbHandle<F, E, K, V, C, H, T, S>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
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
    ///
    /// If unset, [`merkleize`](UnmerkleizedTrait::merkleize) will use the [`Default`] of [`Location`].
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }

    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an immutable [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](crate::stateful::db::Merkleized) trait.
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
    db: ImmutableDbHandle<F, E, K, V, C, H, T, S>,
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
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
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
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
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
        let db = self.db.read().await;
        let merkleized = self
            .batch
            .merkleize(
                &db,
                self.metadata,
                self.inactivity_floor.unwrap_or_default(),
            )
            .await;
        Ok(ImmutableMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
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
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

/// Adapt journaled `immutable` databases with fixed-size values.
impl<F, E, K, V, H, T, S> Qmdb for fixed::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
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
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn open(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        Self::init(context, config).await
    }

    fn initial_root() -> H::Digest {
        initial_root::<F, K, FixedEncoding<V>, H>()
    }

    fn wrap_batch(&self, shared: Shared<Self>) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn checkpoint(&self) -> Checkpoint<F, H::Digest> {
        Checkpoint {
            root: self.root(),
            boundary: self.sync_boundary(),
            size: self.bounds().end,
        }
    }

    fn batch_checkpoint(batch: &Self::Merkleized) -> Checkpoint<F, H::Digest> {
        let bounds = batch.bounds();
        Checkpoint {
            root: batch.root(),
            boundary: bounds.inactivity_floor,
            size: bounds.tip.size,
        }
    }

    async fn apply_merkleized(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn persist(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune_to(self, boundary: Location<F>) -> Result<Self, Error<F>> {
        self.prune(boundary).await
    }

    async fn rewind_to(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await?.sync().await
    }
}

/// Adapt journaled `immutable` databases with variable-size values.
impl<F, E, K, V, H, T, S> Qmdb for variable::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher,
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
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn open(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        Self::init(context, config).await
    }

    fn initial_root() -> H::Digest {
        initial_root::<F, K, VariableEncoding<V>, H>()
    }

    fn wrap_batch(&self, shared: Shared<Self>) -> Self::Unmerkleized {
        ImmutableUnmerkleized {
            batch: self.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn checkpoint(&self) -> Checkpoint<F, H::Digest> {
        Checkpoint {
            root: self.root(),
            boundary: self.sync_boundary(),
            size: self.bounds().end,
        }
    }

    fn batch_checkpoint(batch: &Self::Merkleized) -> Checkpoint<F, H::Digest> {
        let bounds = batch.bounds();
        Checkpoint {
            root: batch.root(),
            boundary: bounds.inactivity_floor,
            size: bounds.tip.size,
        }
    }

    async fn apply_merkleized(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn persist(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune_to(self, boundary: Location<F>) -> Result<Self, Error<F>> {
        self.prune(boundary).await
    }

    async fn rewind_to(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await?.sync().await
    }
}
