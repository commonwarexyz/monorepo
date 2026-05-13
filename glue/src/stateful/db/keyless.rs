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
use commonware_parallel::Strategy;
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
        sync::{self, resolver::Resolver},
        Error,
    },
    Persistable,
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock};
use std::{ops::Deref, sync::Arc};

type KeylessDbHandle<F, E, V, C, H, S> = Arc<AsyncRwLock<Keyless<F, E, V, C, H, S>>>;

/// Wraps a keyless [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    batch: UnmerkleizedBatch<F, H, V, S>,
    db: KeylessDbHandle<F, E, V, C, H, S>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, V, C, H, S> Deref for KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
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
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
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

    /// Read a value by location, falling back to committed state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(location, &*db).await
    }

    /// Read multiple values by location, falling back to committed state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
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
pub struct KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, V, S>>,
    db: KeylessDbHandle<F, E, V, C, H, S>,
}

impl<F, E, V, C, H, S> Deref for KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
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
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Read a value by location, falling back to committed state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(location, &*db).await
    }

    /// Read multiple values by location, falling back to committed state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(locations, &*db).await
    }
}

impl<F, E, V, C, H, S> UnmerkleizedTrait for KeylessUnmerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Merkleized = KeylessMerkleized<F, E, V, C, H, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(
            &*db,
            self.metadata,
            self.inactivity_floor.unwrap_or_default(),
        );
        Ok(KeylessMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, V, C, H, S> MerkleizedTrait for KeylessMerkleized<F, E, V, C, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
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
    E: Storage + Clock + Metrics,
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
            inactivity_floor: None,
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
            range: non_empty_range!(self.sync_boundary(), bounds.end),
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

impl<F, E, V, H, S> ManagedDb<E> for variable::Db<F, E, V, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
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
            inactivity_floor: None,
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
            range: non_empty_range!(self.sync_boundary(), bounds.end),
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

impl<F, E, V, H, S, R> StateSyncDb<E, R> for fixed::Db<F, E, V, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    R: Resolver<Family = F, Op = fixed::Operation<F, V>, Digest = H::Digest>,
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

impl<F, E, V, H, S, R> StateSyncDb<E, R> for variable::Db<F, E, V, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    R: Resolver<Family = F, Op = variable::Operation<F, V>, Digest = H::Digest>,
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
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::full::Config as MerkleConfig, mmr, qmdb::keyless as storage_keyless,
    };
    use commonware_utils::{sequence::U64, NZUsize, NZU16, NZU64};
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
                strategy: Sequential,
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
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
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
            assert_eq!(target.range.start(), mmr::Location::new(1));
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }
}
