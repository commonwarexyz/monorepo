//! Journaled [`ManagedDb`] implementation for QMDB
//! [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! Keyless databases are append-only. Operations are addressed by
//! [`Location`] rather than by key.
//! The wrapper types here capture a [`Shared`] database handle so the batch API
//! can read through to applied state.

use crate::stateful::db::{
    BatchContext, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_standard_db,
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
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        keyless::{
            Keyless, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            fixed, initial_root, variable,
        },
        sync::{self, Target as AnySyncTarget},
    },
};
use commonware_utils::{channel::mpsc, non_empty_range};
use std::{ops::Deref, sync::Arc};

/// Wraps a keyless [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](crate::stateful::db::Unmerkleized) trait.
pub struct KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, V, S>,
    db: Shared<Keyless<F, E, V, C, H, S>>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, V, C, H, S> Deref for KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<F, H, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, V, C, H, S> KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
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

    /// Read a value by location, falling back to applied state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(location, &db).await
    }

    /// Read multiple values by location, falling back to applied state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(locations, &db).await
    }

    /// Append a value to the speculative batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

/// Wraps a keyless [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](crate::stateful::db::Merkleized) trait.
pub struct KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, V, S>>,
    db: Shared<Keyless<F, E, V, C, H, S>>,
}

impl<F, E, V, C, H, S> Clone for KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, V, C, H, S> Deref for KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Target = MerkleizedBatch<F, H::Digest, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, V, C, H, S> KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Read a value by location, falling back to applied state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(location, &db).await
    }

    /// Read multiple values by location, falling back to applied state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(locations, &db).await
    }
}

impl<F, E, V, C, H, S> UnmerkleizedTrait for KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Merkleized = KeylessMerkleized<F, E, V, C, H, S>;
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
        Ok(KeylessMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, V, C, H, S> MerkleizedTrait for KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = KeylessUnmerkleized<F, E, V, C, H, S>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        KeylessUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, V, H, S> ManagedDb<E> for fixed::Db<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
{
    type Unmerkleized =
        KeylessUnmerkleized<F, E, FixedEncoding<V>, FixedJournal<E, fixed::Operation<F, V>>, H, S>;
    type Merkleized =
        KeylessMerkleized<F, E, FixedEncoding<V>, FixedJournal<E, fixed::Operation<F, V>>, H, S>;
    type Error = Error<F>;
    type Config = fixed::Config<S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, FixedEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        KeylessUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
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

impl<F, E, V, H, S> ManagedDb<E> for variable::Db<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
{
    type Unmerkleized = KeylessUnmerkleized<
        F,
        E,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<F, V>>,
        H,
        S,
    >;
    type Merkleized = KeylessMerkleized<
        F,
        E,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<F, V>>,
        H,
        S,
    >;
    type Error = Error<F>;
    type Config = variable::Config<<variable::Operation<F, V> as CodecRead>::Cfg, S>;
    type SyncTarget = AnySyncTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        AnySyncTarget::new(
            initial_root::<F, VariableEncoding<V>, H>(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        KeylessUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root
            && *target.range.start() == batch.bounds().inactivity_floor
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

impl<F, E, V, H, S, R> StateSyncDb<E, R> for fixed::Db<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: FixedValue + 'static,
    H: Hasher + 'static,
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

impl<F, E, V, H, S, R> StateSyncDb<E, R> for variable::Db<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: VariableValue + 'static,
    H: Hasher + 'static,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MerkleConfig, mmr, qmdb::keyless as storage_keyless,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sequence::U64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type FixedDb = fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type VariableDb =
        variable::Db<mmr::Family, deterministic::Context, Vec<u8>, Sha256, Sequential>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> fixed::Config<Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        storage_keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    #[test]
    fn keyless_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_keyless_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-managed-db", &context);
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let (database, sync) = <FixedDb as ManagedDb<_>>::finalize(database).await.unwrap();
                slot.put(database);
                sync.await.expect("database sync failed");
            }

            let guard = db.read().await;
            assert_eq!(
                guard.get(mmr::Location::new(1)).await.unwrap(),
                Some(U64::new(7))
            );
            assert_eq!(guard.get_metadata().await.unwrap(), Some(U64::new(9)));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.start(), mmr::Location::new(1));
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_replay_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-matches-sync-target", &context);
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let valid_target = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            );
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let wrong_start = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(mmr::Location::new(0), merkleized.bounds().tip.size),
            );
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_start,
            ));

            let wrong_end = AnySyncTarget::new(
                merkleized.root(),
                non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size - 1
                ),
            );
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_end,
            ));
        });
    }
}
