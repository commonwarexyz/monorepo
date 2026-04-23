//! [`ManagedDb`] implementation for unjournaled QMDB
//! [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! These compact databases retain only the current Merkle peaks, so the glue
//! adapters expose append and merkleization operations but no historical reads.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::{
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        keyless::{
            fixed, variable, CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch,
            Operation,
        },
        sync::{self, SyncProgress},
        Error,
    },
};
use commonware_utils::{channel::mpsc, sync::AsyncRwLock};
use std::{ops::Deref, sync::Arc};

type KeylessUnjournaledDbHandle<F, E, V, H, C> = Arc<AsyncRwLock<CompactDb<F, E, V, H, C>>>;

fn drain_latest_target<T>(tip_updates: &mut mpsc::Receiver<T>) -> Option<T> {
    let mut latest = None;
    loop {
        match tip_updates.try_recv() {
            Ok(update) => latest = Some(update),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                return latest;
            }
        }
    }
}

/// Wraps an unjournaled keyless batch before merkleization.
pub struct KeylessUnjournaledUnmerkleized<F, E, V, H, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    batch: CompactUnmerkleizedBatch<F, H, V>,
    db: KeylessUnjournaledDbHandle<F, E, V, H, C>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, V, H, C> Deref for KeylessUnjournaledUnmerkleized<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Target = CompactUnmerkleizedBatch<F, H, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, V, H, C> KeylessUnjournaledUnmerkleized<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    /// Set commit metadata included in the next merkleization.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor included in the next merkleization.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }

    /// Append a value to the speculative batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

/// Wraps an unjournaled keyless batch after merkleization.
pub struct KeylessUnjournaledMerkleized<F, E, V, H, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    inner: Arc<CompactMerkleizedBatch<F, H::Digest, V>>,
    db: KeylessUnjournaledDbHandle<F, E, V, H, C>,
}

impl<F, E, V, H, C> Deref for KeylessUnjournaledMerkleized<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Target = CompactMerkleizedBatch<F, H::Digest, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, V, H, C> UnmerkleizedTrait for KeylessUnjournaledUnmerkleized<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Merkleized = KeylessUnjournaledMerkleized<F, E, V, H, C>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(
            &*db,
            self.metadata,
            self.inactivity_floor.unwrap_or_default(),
        );
        Ok(KeylessUnjournaledMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, V, H, C> MerkleizedTrait for KeylessUnjournaledMerkleized<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Digest = H::Digest;
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, V, H, C>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        KeylessUnjournaledUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, V, H> ManagedDb<E> for fixed::CompactDb<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    Operation<F, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
{
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, FixedEncoding<V>, H>;
    type Merkleized = KeylessUnjournaledMerkleized<F, E, FixedEncoding<V>, H>;
    type Error = Error<F>;
    type Config = fixed::CompactConfig;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        KeylessUnjournaledUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner)?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        self.current_target()
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Compact storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, V, H, C> ManagedDb<E> for variable::CompactDb<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, VariableEncoding<V>, H, C>;
    type Merkleized = KeylessUnjournaledMerkleized<F, E, VariableEncoding<V>, H, C>;
    type Error = Error<F>;
    type Config = variable::CompactConfig<C>;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        KeylessUnjournaledUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner)?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        self.current_target()
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Compact storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, V, H, R> StateSyncDb<E, R> for fixed::CompactDb<F, E, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics + Clone,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    Operation<F, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
    R: sync::compact::Resolver<
            Family = F,
            Op = Operation<F, FixedEncoding<V>>,
            Digest = H::Digest,
        >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        mut target: Self::SyncTarget,
        mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
        _progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> Result<Self, Self::SyncError> {
        let mut attempt = 0u64;
        loop {
            let context = context.clone().with_label(&format!("attempt_{attempt}"));
            attempt += 1;
            let db = sync::compact::sync(sync::compact::Config::<Self, R> {
                context,
                resolver: resolver.clone(),
                target: target.clone(),
                db_config: config.clone(),
            })
            .await?;

            if let Some(update) = drain_latest_target(&mut tip_updates) {
                target = update;
                continue;
            }

            if let Some(reached_target) = reached_target.as_ref() {
                if reached_target.send(target.clone()).await.is_err() {
                    return Ok(db);
                }
            }

            let Some(finish) = finish.as_mut() else {
                return Ok(db);
            };
            select! {
                _ = finish.recv() => return Ok(db),
                update = tip_updates.recv() => {
                    let Some(update) = update else {
                        return Ok(db);
                    };
                    target = update;
                },
            }
        }
    }
}

impl<F, E, V, H, C, R> StateSyncDb<E, R> for variable::CompactDb<F, E, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics + Clone,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    R: sync::compact::Resolver<
            Family = F,
            Op = Operation<F, VariableEncoding<V>>,
            Digest = H::Digest,
        >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        mut target: Self::SyncTarget,
        mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
        _progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> Result<Self, Self::SyncError> {
        let mut attempt = 0u64;
        loop {
            let context = context.clone().with_label(&format!("attempt_{attempt}"));
            attempt += 1;
            let db = sync::compact::sync(sync::compact::Config::<Self, R> {
                context,
                resolver: resolver.clone(),
                target: target.clone(),
                db_config: config.clone(),
            })
            .await?;

            if let Some(update) = drain_latest_target(&mut tip_updates) {
                target = update;
                continue;
            }

            if let Some(reached_target) = reached_target.as_ref() {
                if reached_target.send(target.clone()).await.is_err() {
                    return Ok(db);
                }
            }

            let Some(finish) = finish.as_mut() else {
                return Ok(db);
            };
            select! {
                _ = finish.recv() => return Ok(db),
                update = tip_updates.recv() => {
                    let Some(update) = update else {
                        return Ok(db);
                    };
                    target = update;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{compact::Config as MerkleConfig, full::Config as FullMerkleConfig, mmr},
        qmdb::keyless as storage_keyless,
    };
    use commonware_utils::{sequence::U64, NZU16, NZU64, NZUsize};

    type FixedDb = fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256>;
    type FullFixedDb = storage_keyless::fixed::Db<mmr::Family, deterministic::Context, U64, Sha256>;
    type VariableDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
    >;

    fn fixed_config(suffix: &str) -> fixed::CompactConfig {
        fixed::CompactConfig {
            merkle: MerkleConfig {
                partition: format!("stateful-keyless-unjournaled-{suffix}"),
                thread_pool: None,
            },
            commit_codec_config: (),
        }
    }

    fn full_fixed_config(suffix: &str, pooler: &impl BufferPooler) -> storage_keyless::fixed::Config {
        let page_cache = CacheRef::from_pooler(pooler, NZU16!(101), NZUsize!(11));
        storage_keyless::fixed::Config {
            merkle: FullMerkleConfig {
                journal_partition: format!("stateful-keyless-full-journal-{suffix}"),
                metadata_partition: format!("stateful-keyless-full-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-keyless-full-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    const fn sync_config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: 1,
            max_outstanding_requests: 1,
            update_channel_size: NZUsize!(1),
            max_retained_roots: 0,
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    #[test]
    fn keyless_unjournaled_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_finalize_commits_fixed_keyless_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("managed-db");
            let db = FixedDb::init(context.with_label("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let mut guard = db.write().await;
                <FixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(U64::new(9)));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&*guard).await;
            assert_eq!(target.root, guard.root());
            assert_eq!(target.leaf_count, mmr::Location::new(3));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_keyless_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut source = FixedDb::init(context.with_label("source"), fixed_config("source"))
                .await
                .unwrap();
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor);
            source.apply_batch(batch).unwrap();
            source.sync().await.unwrap();

            let target = source.current_target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.with_label("target"),
                fixed_config("target"),
                Arc::new(source),
                target.clone(),
                update_rx,
                None,
                None,
                sync_config(),
                None,
            )
            .await
            .unwrap();

            assert_eq!(synced.current_target(), target);
            assert_eq!(synced.get_metadata(), Some(U64::new(9)));
        });
    }

    #[test]
    fn state_sync_drains_queued_target_before_reporting_reached() {
        deterministic::Runner::default().start(|context| async move {
            let mut source = FullFixedDb::init(
                context.with_label("source"),
                full_fixed_config("source", &context),
            )
            .await
            .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor);
            source.apply_batch(batch).await.unwrap();
            source.sync().await.unwrap();
            let first_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(8))
                .merkleize(&source, Some(U64::new(10)), floor);
            source.apply_batch(batch).await.unwrap();
            source.sync().await.unwrap();
            let second_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            update_tx.send(second_target.clone()).await.unwrap();
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FullFixedDb>>>::sync_db(
                context.with_label("target"),
                fixed_config("target"),
                Arc::new(source),
                first_target,
                update_rx,
                None,
                Some(reached_tx),
                sync_config(),
                None,
            )
            .await
            .unwrap();

            assert_eq!(reached_rx.recv().await, Some(second_target.clone()));
            assert_eq!(synced.current_target(), second_target);
            assert_eq!(synced.get_metadata(), Some(U64::new(10)));
        });
    }

    #[test]
    fn managed_db_rewinds_fixed_keyless_unjournaled_one_commit_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("rewind");
            let mut db = FixedDb::init(context.with_label("db"), config)
                .await
                .unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor);
            db.apply_batch(batch).unwrap();
            db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(22)), floor);
            db.apply_batch(batch).unwrap();
            db.sync().await.unwrap();
            let second_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;
            assert_ne!(second_target, first_target);

            <FixedDb as ManagedDb<_>>::rewind_to_target(&mut db, first_target.clone())
                .await
                .unwrap();

            let rewound_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;
            assert_eq!(rewound_target, first_target);
            assert_eq!(db.get_metadata(), Some(U64::new(11)));
        });
    }
}
