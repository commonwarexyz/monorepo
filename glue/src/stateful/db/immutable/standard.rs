//! Journaled [`ManagedDb`] implementation for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Immutable databases support adding new keyed values but not updates or
//! deletions. Keyed batch reads borrow the owning database because the
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
    ///
    /// If unset, the batch carries forward the floor it forked from. The floor must never
    /// decrease across commits.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = floor;
        self
    }

    /// Read a value by key, falling back to `db`'s committed state.
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

    /// Read multiple values by key, falling back to `db`'s committed state.
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
    /// Read a value by key, falling back to `db`'s committed state.
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

    /// Read multiple values by key, falling back to `db`'s committed state.
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
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    fn matches(&self, target: &Self::SyncTarget) -> bool {
        self.root() == target.root
            && *target.range.start() == self.bounds().inactivity_floor
            && *target.range.end() == self.bounds().tip.size
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::{Contiguous as _, fixed::Config as FixedJournalConfig},
        merkle::full::Config as MerkleConfig,
        mmr,
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::{NonZeroU16, NonZeroUsize};

    type FixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;
    type VariableDb = variable::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        Sequential,
    >;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        fixed::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    #[test]
    fn immutable_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_finalize_commits_fixed_immutable_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-immutable-managed-db", &context);
            let db = FixedDb::init(context.child("db"), config).await.unwrap();

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db).set(key, value);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch, &db)
                .await
                .unwrap();

            let (db, snapshot, durability) = <FixedDb as ManagedDb<_>>::finalize(db, merkleized)
                .await
                .unwrap();
            durability.await.expect("finalize flush failed");

            assert_eq!(db.get(&key).await.unwrap(), Some(value));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(target.root, db.root());
            assert_eq!(
                mmr::Location::new(snapshot.bounds().end),
                *target.range.end(),
                "captured snapshot must cover the applied batch",
            );
        });
    }

    #[test]
    fn merkleized_matches_rejects_wrong_replay_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-immutable-matches", &context);
            let db = FixedDb::init(context.child("db"), config).await.unwrap();

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db).set(key, value);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch, &db)
                .await
                .unwrap();

            let valid_target = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            );
            assert!(merkleized.matches(&valid_target));

            let wrong_start = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(
                    merkleized.bounds().inactivity_floor + 1,
                    merkleized.bounds().tip.size
                ),
            );
            assert!(!merkleized.matches(&wrong_start));

            let wrong_end = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size - 1
                ),
            );
            assert!(!merkleized.matches(&wrong_end));
        });
    }
}
