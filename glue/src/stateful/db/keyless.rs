//! [`ManagedDb`] implementation for QMDB [`keyless`](commonware_storage::qmdb::keyless)
//! databases.
//!
//! Keyless databases are append-only. Operations are addressed by
//! [`Location`] rather than by key.
//! The wrapper types here capture `Arc<AsyncRwLock<Keyless>>` so the batch API
//! can read through to committed state.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    journal::{
        contiguous::{
            fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Mutable,
        },
        Error as JournalError,
    },
    merkle::{Family, Location},
    qmdb::{
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        keyless::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            fixed, variable, Keyless, Operation,
        },
        sync::{self, resolver::Resolver, SyncProgress},
        Error,
    },
    Persistable,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock};
use std::{ops::Deref, sync::Arc};

type KeylessDbHandle<F, E, V, C, H> = Arc<AsyncRwLock<Keyless<F, E, V, C, H>>>;

/// Wraps a keyless [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct KeylessUnmerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, V>,
    db: KeylessDbHandle<F, E, V, C, H>,
    metadata: Option<V::Value>,
}

impl<F, E, V, C, H> Deref for KeylessUnmerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    type Target = UnmerkleizedBatch<F, H, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, V, C, H> KeylessUnmerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Set commit metadata included in the next
    /// [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Read a value by location, falling back to committed state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(location, &*db).await
    }

    /// Read values at multiple locations, amortizing lock acquisition.
    ///
    /// Locations must be sorted in ascending order.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(locations, &*db).await
    }

    /// Append a value to the speculative batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

/// Wraps a keyless [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct KeylessMerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, V>>,
    db: KeylessDbHandle<F, E, V, C, H>,
}

impl<F, E, V, C, H> Deref for KeylessMerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    type Target = MerkleizedBatch<F, H::Digest, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, V, C, H> KeylessMerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Read a value by location, falling back to committed state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(location, &*db).await
    }

    /// Read values at multiple locations, amortizing lock acquisition.
    ///
    /// Locations must be sorted in ascending order.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(locations, &*db).await
    }
}

impl<F, E, V, C, H> UnmerkleizedTrait for KeylessUnmerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    type Merkleized = KeylessMerkleized<F, E, V, C, H>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(&*db, self.metadata);
        Ok(KeylessMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, V, C, H> MerkleizedTrait for KeylessMerkleized<F, E, V, C, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    type Digest = H::Digest;
    type Unmerkleized = KeylessUnmerkleized<F, E, V, C, H>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        KeylessUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

impl<F, E, V, H> ManagedDb<E> for fixed::Db<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: FixedValue + 'static,
    H: Hasher + 'static,
{
    type Unmerkleized =
        KeylessUnmerkleized<F, E, FixedEncoding<V>, FixedJournal<E, fixed::Operation<V>>, H>;
    type Merkleized =
        KeylessMerkleized<F, E, FixedEncoding<V>, FixedJournal<E, fixed::Operation<V>>, H>;
    type Error = Error<F>;
    type Config = fixed::Config;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        KeylessUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        self.rewind(target.range.end()).await?;
        self.commit().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}

impl<F, E, V, H> ManagedDb<E> for variable::Db<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: VariableValue + 'static,
    H: Hasher + 'static,
{
    type Unmerkleized = KeylessUnmerkleized<
        F,
        E,
        VariableEncoding<V>,
        VariableJournal<E, variable::Operation<V>>,
        H,
    >;
    type Merkleized =
        KeylessMerkleized<F, E, VariableEncoding<V>, VariableJournal<E, variable::Operation<V>>, H>;
    type Error = Error<F>;
    type Config = variable::Config<<variable::Operation<V> as CodecRead>::Cfg>;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        KeylessUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        self.rewind(target.range.end()).await?;
        self.commit().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}

impl<F, E, V, H, R> StateSyncDb<E, R> for fixed::Db<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    R: Resolver<Family = F, Op = fixed::Operation<V>, Digest = H::Digest>,
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
        progress_tx: Option<mpsc::Sender<SyncProgress>>,
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
            progress_tx,
        })
        .await
    }
}

impl<F, E, V, H, R> StateSyncDb<E, R> for variable::Db<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    R: Resolver<Family = F, Op = variable::Operation<V>, Digest = H::Digest>,
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
        progress_tx: Option<mpsc::Sender<SyncProgress>>,
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
            progress_tx,
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::journaled::Config as MerkleConfig, mmr, qmdb::keyless as storage_keyless,
    };
    use commonware_utils::{sequence::U64, NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type FixedDb = fixed::Db<mmr::Family, deterministic::Context, U64, Sha256>;
    type VariableDb = variable::Db<mmr::Family, deterministic::Context, Vec<u8>, Sha256>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> fixed::Config {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        storage_keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
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
    fn managed_db_finalize_commits_fixed_keyless_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-managed-db", &context);
            let db = FixedDb::init(context.with_label("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .append(U64::new(7))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            {
                let mut guard = db.write().await;
                <FixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            let guard = db.read().await;
            assert_eq!(
                guard.get(mmr::Location::new(1)).await.unwrap(),
                Some(U64::new(7))
            );
            assert_eq!(guard.get_metadata().await.unwrap(), Some(U64::new(9)));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&*guard).await;
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.start(), mmr::Location::new(0));
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }
}
