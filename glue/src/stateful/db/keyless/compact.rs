//! Compact [`ManagedDb`] implementation for QMDB
//! [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! These compact databases retain only the current Merkle peaks, so the glue
//! adapters expose append and merkleization operations but no historical reads.

use crate::stateful::db::{
    BatchContext, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait, sync_compact_db,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        keyless::{
            CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation, fixed,
            initial_root, variable,
        },
        sync::{self},
    },
};
use commonware_utils::channel::mpsc;
use std::{ops::Deref, sync::Arc};

/// Wraps an unjournaled keyless batch before merkleization.
pub struct KeylessUnjournaledUnmerkleized<F, E, V, H, S, C = ()>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    batch: CompactUnmerkleizedBatch<F, H, V, S>,
    db: Shared<CompactDb<F, E, V, H, C, S>>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, V, H, S, C> Deref for KeylessUnjournaledUnmerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactUnmerkleizedBatch<F, H, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, V, H, S, C> KeylessUnjournaledUnmerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
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
pub struct KeylessUnjournaledMerkleized<F, E, V, H, S, C = ()>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    inner: Arc<CompactMerkleizedBatch<F, H::Digest, V, S>>,
    db: Shared<CompactDb<F, E, V, H, C, S>>,
}

impl<F, E, V, H, S, C> Clone for KeylessUnjournaledMerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, V, H, S, C> Deref for KeylessUnjournaledMerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactMerkleizedBatch<F, H::Digest, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, V, H, S, C> UnmerkleizedTrait for KeylessUnjournaledUnmerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Merkleized = KeylessUnjournaledMerkleized<F, E, V, H, S, C>;
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
        Ok(KeylessUnjournaledMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, V, H, S, C> MerkleizedTrait for KeylessUnjournaledMerkleized<F, E, V, H, S, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, V, H, S, C>;

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

impl<F, E, V, H, S> ManagedDb<E> for fixed::CompactDb<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
{
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, FixedEncoding<V>, H, S, ()>;
    type Merkleized = KeylessUnjournaledMerkleized<F, E, FixedEncoding<V>, H, S, ()>;
    type Error = Error<F>;
    type Config = fixed::CompactConfig<S>;
    type SyncTarget = sync::CompactTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::CompactTarget {
            root: initial_root::<F, FixedEncoding<V>, H>(),
            size: Location::new(1),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        KeylessUnjournaledUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.size == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.size).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.size).await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

impl<F, E, V, H, C, S> ManagedDb<E> for variable::CompactDb<F, E, V, H, C, S>
where
    F: Family,
    E: Context,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Unmerkleized = KeylessUnjournaledUnmerkleized<F, E, VariableEncoding<V>, H, S, C>;
    type Merkleized = KeylessUnjournaledMerkleized<F, E, VariableEncoding<V>, H, S, C>;
    type Error = Error<F>;
    type Config = variable::CompactConfig<C, S>;
    type SyncTarget = sync::CompactTarget<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::CompactTarget {
            root: initial_root::<F, VariableEncoding<V>, H>(),
            size: Location::new(1),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        KeylessUnjournaledUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.size == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.size).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.size).await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

impl<F, E, V, H, S, R> StateSyncDb<E, R> for fixed::CompactDb<F, E, V, H, S>
where
    F: Family,
    E: Context + Spawner,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
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
        sync_compact_db(
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

impl<F, E, V, H, C, S, R> StateSyncDb<E, R> for variable::CompactDb<F, E, V, H, C, S>
where
    F: Family,
    E: Context + Spawner,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
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
        sync_compact_db(
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
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock as _, Metrics as _, Runner as _, Supervisor as _,
        buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{full::Config as MerkleConfig, mmr},
        qmdb::keyless as storage_keyless,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};
    use futures::pin_mut;
    use std::time::Duration;

    type FixedDb = fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type FullFixedDb =
        storage_keyless::fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type VariableDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;

    #[derive(Clone)]
    struct SupersedingCompactSource {
        source: Arc<FixedDb>,
        stale_target: sync::CompactTarget<mmr::Family, Digest>,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl sync::Source for SupersedingCompactSource {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = storage_keyless::fixed::Operation<mmr::Family, U64>;
        type Error = <Arc<FixedDb> as sync::Source>::Error;

        async fn serve(
            &self,
            request: sync::Request<Self::Family>,
        ) -> Result<
            (
                sync::Response<Self::Family, Self::Op, Self::Digest>,
                sync::FeedbackTx,
            ),
            Self::Error,
        > {
            if request.size() == self.stale_target.size {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            self.source.serve(request).await
        }
    }

    fn fixed_config(context: &impl BufferPooler, suffix: &str) -> fixed::CompactConfig<Sequential> {
        fixed::CompactConfig {
            strategy: Sequential,
            witness: commonware_storage::journal::contiguous::variable::Config {
                partition: format!("stateful-keyless-unjournaled-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: (),
        }
    }

    fn full_fixed_config(
        context: &impl BufferPooler,
        suffix: &str,
    ) -> storage_keyless::fixed::Config<Sequential> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        storage_keyless::fixed::Config {
            merkle: MerkleConfig {
                journal_partition: format!("stateful-keyless-full-journal-{suffix}"),
                metadata_partition: format!("stateful-keyless-full-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-keyless-full-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    const fn sync_config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: NZU64!(1),
            max_outstanding_requests: 1,
            update_channel_size: NZUsize!(1),
            max_retained_roots: 0,
        }
    }

    async fn populated_fixed_db(context: deterministic::Context, suffix: &str) -> FixedDb {
        let config = fixed_config(&context, suffix);
        let source = FixedDb::init(context.child("db"), config).await.unwrap();
        let floor = source.inactivity_floor_loc();
        let batch = source
            .new_batch()
            .append(U64::new(7))
            .merkleize(&source, Some(U64::new(9)), floor)
            .await;
        let (source, _) = source.apply_batch(batch).await.unwrap();
        source.sync().await.unwrap()
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
    fn managed_db_apply_and_finalize_persists_fixed_keyless_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
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
            let expected_root = merkleized.root();

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
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(U64::new(9)));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.size, mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_apply_retains_each_keyless_rewind_target() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "apply-checkpoints");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_metadata(U64::new(11));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            let first_target = sync::CompactTarget {
                root: first.root(),
                size: first.bounds().tip.size,
            };
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, first)
                .await
                .unwrap();
            slot.put(database);

            let second = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(8))
                .with_metadata(U64::new(22));
            let second = crate::stateful::db::Unmerkleized::merkleize(second)
                .await
                .unwrap();
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, second)
                .await
                .unwrap();
            let (database, sync) = <FixedDb as ManagedDb<_>>::finalize(database).await.unwrap();
            sync.await.expect("database sync failed");
            slot.put(database);
            drop(db);

            let database = FixedDb::init(
                context.child("reopen"),
                fixed_config(&context, "apply-checkpoints"),
            )
            .await
            .unwrap();
            let database =
                <FixedDb as ManagedDb<_>>::rewind_to_target(database, first_target.clone())
                    .await
                    .unwrap();
            assert_eq!(
                <FixedDb as ManagedDb<_>>::sync_target(&database),
                first_target,
            );
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_size() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "matches-sync-target");
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

            let valid_target = sync::CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            };
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let wrong_size = sync::CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size - 1,
            };
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_size,
            ));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_keyless_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = populated_fixed_db(context.child("source"), "source").await;

            let target = source.target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.child("target"),
                fixed_config(&context, "target"),
                Arc::new(source),
                target.clone(),
                update_rx,
                None,
                None,
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(U64::new(9)));
        });
    }

    #[test]
    fn state_sync_stops_compact_update_forwarder_after_completion() {
        deterministic::Runner::default().start(|context| async move {
            let source = populated_fixed_db(context.child("source"), "source").await;

            let target = source.target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.child("target"),
                fixed_config(&context, "target"),
                Arc::new(source),
                target,
                update_rx,
                None,
                None,
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(
                count_running_tasks(&context, "target_compact_updates"),
                0,
                "compact target forwarder outlived the completed sync",
            );
            drop(synced);
        });
    }

    #[test]
    fn state_sync_drains_queued_target_before_reporting_reached() {
        deterministic::Runner::default().start(|context| async move {
            let source = FullFixedDb::init(
                context.child("source"),
                full_fixed_config(&context, "source"),
            )
            .await
            .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let first_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(8))
                .merkleize(&source, Some(U64::new(10)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let second_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            update_tx.send(second_target.clone()).await.unwrap();
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FullFixedDb>>>::sync_db(
                context.child("target"),
                fixed_config(&context, "target"),
                Arc::new(source),
                first_target,
                update_rx,
                None,
                Some(reached_tx),
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(reached_rx.recv().await, Some(second_target.clone()));
            assert_eq!(synced.target(), second_target);
            assert_eq!(synced.get_metadata(), Some(U64::new(10)));
        });
    }

    #[test]
    fn state_sync_reports_compact_progress() {
        deterministic::Runner::default().start(|context| async move {
            let source_context = context.child("source");
            let source_config = fixed_config(&source_context, "source");
            let source = FixedDb::init(source_context, source_config).await.unwrap();
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let target = source.target();

            // A larger target the source never serves. Its sync attempt
            // hangs so the test can observe the gauges while they diverge.
            let unservable_target = sync::CompactTarget {
                root: Sha256::hash(&[&[0xFF]]),
                size: target.size + 1,
            };
            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let superseding_source = SupersedingCompactSource {
                source: Arc::new(source),
                stale_target: unservable_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let (_finish_tx, finish_rx) = mpsc::channel(1);
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let client_context = context.child("client");
            let client_config = fixed_config(&client_context, "client");
            let sync = <FixedDb as StateSyncDb<_, _>>::sync_db(
                client_context,
                client_config,
                superseding_source,
                target.clone(),
                update_rx,
                Some(finish_rx),
                Some(reached_tx),
                sync_config(),
            );
            pin_mut!(sync);

            select! {
                _ = sync.as_mut() => panic!("sync completed before explicit finish signal"),
                reached = reached_rx.recv() => assert_eq!(reached, Some(target.clone())),
            }

            let synced_size = *target.size;
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_sync_target_size {synced_size}")),
                "missing compact sync target gauge: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_sync_size {synced_size}")),
                "missing compact sync progress gauge: {encoded}"
            );

            // Supersede with the unservable target and wait for its fetch to
            // start. The target gauge advances while the synced gauge still
            // reports the previously reached target.
            update_tx.send(unservable_target.clone()).await.unwrap();
            select! {
                _ = sync.as_mut() => panic!("sync completed with an unservable target"),
                request = stale_request_rx.recv() => assert_eq!(request, Some(())),
            }

            let target_size_val = *unservable_target.size;
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_sync_target_size {target_size_val}")),
                "target gauge should advance to the superseding target: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_sync_size {synced_size}")),
                "synced gauge should still report the reached target: {encoded}"
            );
        });
    }

    #[test]
    fn state_sync_supersedes_in_flight_stale_compact_target() {
        deterministic::Runner::default().start(|context| async move {
            let source = FixedDb::init(
                context.child("source"),
                fixed_config(&context, "supersede-source"),
            )
            .await
            .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let stale_target = source.target();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(8))
                .merkleize(&source, Some(U64::new(10)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let latest_target = source.target();

            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let superseding_source = SupersedingCompactSource {
                source: Arc::new(source),
                stale_target: stale_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let sync_handle = context.child("sync").spawn(move |context| async move {
                <FixedDb as StateSyncDb<_, _>>::sync_db(
                    context.child("target"),
                    fixed_config(&context, "supersede-target"),
                    superseding_source,
                    stale_target,
                    update_rx,
                    None,
                    None,
                    sync_config(),
                )
                .await
            });

            context
                .timeout(Duration::from_secs(1), async move {
                    stale_request_rx.recv().await.unwrap();
                })
                .await
                .expect("sync should request the stale target first");
            update_tx.send(latest_target.clone()).await.unwrap();

            let synced = context
                .timeout(Duration::from_secs(1), sync_handle)
                .await
                .expect("sync should switch to the latest target")
                .expect("spawned sync task should complete")
                .unwrap();

            assert_eq!(synced.target(), latest_target);
            assert_eq!(synced.get_metadata(), Some(U64::new(10)));
        });
    }

    #[test]
    fn managed_db_rewinds_fixed_keyless_unjournaled_multiple_commit_ranges() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "rewind");
            let mut db = FixedDb::init(context.child("db"), config).await.unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db);

            // Commit two more ranges so the rewind below spans multiple commits.
            for i in [2u64, 3] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .append(U64::new(i))
                    .merkleize(&db, Some(U64::new(i * 11)), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            let third_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_ne!(third_target, first_target);

            let db = <FixedDb as ManagedDb<_>>::rewind_to_target(db, first_target.clone())
                .await
                .unwrap();

            let rewound_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(rewound_target, first_target);
            assert_eq!(db.get_metadata(), Some(U64::new(11)));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_keyless_unjournaled_rewind_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = FixedDb::init(context.child("db"), config).await.unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for i in [1u64, 2, 3] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .append(U64::new(i))
                    .merkleize(&db, Some(U64::new(i * 11)), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<FixedDb as ManagedDb<_>>::sync_target(&db));
            }

            assert_ne!(targets[0], targets[1]);

            // Prune to the second target: the first is no longer a rewind target, but the
            // second still is.
            let db = <FixedDb as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            let db = <FixedDb as ManagedDb<_>>::rewind_to_target(db, targets[1].clone())
                .await
                .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), targets[1]);
            assert!(matches!(
                db.rewind(targets[0].size).await,
                Err(Error::Merkle(
                    commonware_storage::merkle::Error::RewindBeyondHistory
                ))
            ));
        });
    }
}
