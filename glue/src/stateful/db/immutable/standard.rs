//! Journaled [`ManagedDb`] and [`StateSyncDb`] implementations for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Immutable databases accept new keyed values but no updates or deletions. Batch reads consult
//! the database at the time of the read for keys their batch chain does not write, and return a
//! `StaleRead` error once the database is at no state of that chain.

use crate::stateful::db::{
    BatchContext, InitError, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized as UnmerkleizedTrait, sync_standard_db, validate_initialization,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
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
        immutable::{
            Db, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            fixed, initial_root, variable,
        },
        operation::Key,
        sync::{self, Target as AnySyncTarget},
        value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
    },
    translator::Translator,
};
use commonware_utils::{
    Array,
    channel::{mpsc, ring},
    non_empty_range,
};
use core::borrow::Borrow;
use std::{ops::Deref, sync::Arc};

/// Shared handle to an immutable database.
type ImmutableDbHandle<F, E, K, V, C, H, T, S> = Shared<Db<F, E, K, V, C, H, T, S>>;

/// A speculative batch of new keyed values over a shared immutable database.
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
    /// Sets the metadata committed by [`merkleize`](UnmerkleizedTrait::merkleize). `None` clears
    /// it.
    pub fn with_metadata(mut self, metadata: impl Into<Option<V::Value>>) -> Self {
        self.batch = self.batch.with_metadata(metadata);
        self
    }

    /// Sets the inactivity floor committed by [`merkleize`](UnmerkleizedTrait::merkleize)
    /// (inherited from the database or parent batch when unset).
    pub fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.batch = self.batch.with_inactivity_floor(floor);
        self
    }

    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<K> + Sync],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Sets `key` to `value` in the batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// A sealed immutable batch with a computed root.
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
    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<K> + Sync],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
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
        let merkleized = self.batch.merkleize(&db).await?;
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
        }
    }
}

impl<F, E, K, V, H, T, S> ManagedDb<E> for fixed::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue,
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
    type Error = Error<F>;
    type Config = fixed::Config<T, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>, Self::SyncTarget>> {
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
        AnySyncTarget {
            root: initial_root::<F, K, FixedEncoding<V>, H>(),
            range: non_empty_range!(Location::new(0), Location::new(1)),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        ImmutableUnmerkleized {
            batch: database.new_batch(),
            db: shared,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        self.apply_batch(batch.inner).await
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget {
            root: self.root(),
            range: non_empty_range!(self.sync_boundary(), bounds.end),
        }
    }
}

impl<F, E, K, V, H, T, S> ManagedDb<E> for variable::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue,
    H: Hasher,
    T: Translator,
    S: Strategy,
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

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>, Self::SyncTarget>> {
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
        AnySyncTarget {
            root: initial_root::<F, K, VariableEncoding<V>, H>(),
            range: non_empty_range!(Location::new(0), Location::new(1)),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        ImmutableUnmerkleized {
            batch: database.new_batch(),
            db: shared,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
            && *target.range.end() == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        self.apply_batch(batch.inner).await
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        self.prune((*target.range.start()).into()).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds();
        AnySyncTarget {
            root: self.root(),
            range: non_empty_range!(self.sync_boundary(), bounds.end),
        }
    }
}

impl<F, E, K, V, H, T, R, S> StateSyncDb<E, R> for fixed::Db<F, E, K, V, H, T, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue,
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
        tip_updates: ring::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<ring::Sender<Self::SyncTarget>>,
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
    V: VariableValue,
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
        tip_updates: ring::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<ring::Sender<Self::SyncTarget>>,
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
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{full::Config as MerkleConfig, mmr},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    type FixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    fn fixed_config(suffix: &str) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::new(NZU16!(101), NZUsize!(11));
        fixed::Config {
            merkle: MerkleConfig {
                journal_partition: format!("stateful-immutable-journal-{suffix}"),
                metadata_partition: format!("stateful-immutable-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-immutable-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_buffer: NZUsize!(1 << 21),
        }
    }

    #[test]
    fn unset_inactivity_floor_inherits_parent_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("inherit-parent-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let parent = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_inactivity_floor(mmr::Location::new(1));
            let parent = crate::stateful::db::Unmerkleized::merkleize(parent)
                .await
                .unwrap();
            let child = MerkleizedTrait::new_batch(&parent)
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]));
            let child = crate::stateful::db::Unmerkleized::merkleize(child)
                .await
                .unwrap();
            assert_eq!(child.bounds().inactivity_floor, mmr::Location::new(1));
        });
    }

    #[test]
    fn unset_inactivity_floor_inherits_applied_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("inherit-applied-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_inactivity_floor(mmr::Location::new(1));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, first)
                    .await
                    .unwrap();
                slot.put(database);
            }

            let next = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]));
            let next = crate::stateful::db::Unmerkleized::merkleize(next)
                .await
                .unwrap();
            assert_eq!(next.bounds().inactivity_floor, mmr::Location::new(1));
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, next)
                .await
                .unwrap();
            assert_eq!(database.inactivity_floor(), mmr::Location::new(1));
            slot.put(database);
        });
    }
}
