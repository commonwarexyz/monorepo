//! Compact [`ManagedDb`] implementation for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! These compact databases retain only the current Merkle peaks, so the glue
//! adapters expose set and merkleization operations but no historical reads.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        immutable::{
            CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation, fixed,
            initial_root, variable,
        },
        operation::Key,
        sync::{self},
    },
};
use commonware_utils::{Array, channel::mpsc};
use std::{ops::Deref, sync::Arc};

/// Wraps an unjournaled immutable batch before merkleization.
pub struct ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C = ()>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    batch: CompactUnmerkleizedBatch<F, H, K, V, S>,
    db: Shared<CompactDb<F, E, K, V, H, C, S>>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, K, V, H, S, C> Deref for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactUnmerkleizedBatch<F, H, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, K, V, H, S, C> ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
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

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an unjournaled immutable batch after merkleization.
pub struct ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C = ()>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    inner: Arc<CompactMerkleizedBatch<F, H::Digest, K, V, S>>,
    db: Shared<CompactDb<F, E, K, V, H, C, S>>,
}

impl<F, E, K, V, H, S, C> Deref for ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactMerkleizedBatch<F, H::Digest, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, K, V, H, S, C> UnmerkleizedTrait
    for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>;
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
        Ok(ImmutableUnjournaledMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, K, V, H, S, C> MerkleizedTrait for ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnjournaledUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, K, V, H, S> ManagedDb<E> for fixed::CompactDb<F, E, K, V, H, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, K, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, FixedEncoding<V>, H, S, ()>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, FixedEncoding<V>, H, S, ()>;
    type Error = Error<F>;
    type Config = fixed::CompactConfig<S>;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::compact::Target::new(
            initial_root::<F, K, FixedEncoding<V>, H>(),
            Location::new(1),
        )
    }

    async fn new_batch(db: &Shared<Self>) -> Self::Unmerkleized {
        let guard = db.read().await;
        ImmutableUnjournaledUnmerkleized {
            batch: guard.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.leaf_count == Location::new(batch.bounds().total_size)
    }

    async fn finalize(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner)?;
        db.sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.leaf_count).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.leaf_count).await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

impl<F, E, K, V, H, C, S> ManagedDb<E> for variable::CompactDb<F, E, K, V, H, C, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, VariableEncoding<V>, H, S, C>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, VariableEncoding<V>, H, S, C>;
    type Error = Error<F>;
    type Config = variable::CompactConfig<C, S>;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::compact::Target::new(
            initial_root::<F, K, VariableEncoding<V>, H>(),
            Location::new(1),
        )
    }

    async fn new_batch(db: &Shared<Self>) -> Self::Unmerkleized {
        let guard = db.read().await;
        ImmutableUnjournaledUnmerkleized {
            batch: guard.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.leaf_count == Location::new(batch.bounds().total_size)
    }

    async fn finalize(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner)?;
        db.sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.leaf_count).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }

    async fn rewind_to_target(self, target: Self::SyncTarget) -> Result<Self, Error<F>> {
        let db = self.rewind(target.leaf_count).await?;

        let rewound_target = db.sync_target();
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(db)
    }
}

impl<F, E, K, V, H, R, S> StateSyncDb<E, R> for fixed::CompactDb<F, E, K, V, H, S>
where
    F: Family,
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, K, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
    R: sync::compact::Resolver<
            Family = F,
            Op = Operation<F, K, FixedEncoding<V>>,
            Digest = H::Digest,
        >,
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
        _sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::compact::sync(sync::compact::Config {
            context,
            resolver,
            target,
            db_config: config,
            update_rx: Some(tip_updates),
            finish_rx: finish,
            reached_target_tx: reached_target,
        })
        .await
    }
}

impl<F, E, K, V, H, C, R, S> StateSyncDb<E, R> for variable::CompactDb<F, E, K, V, H, C, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
    R: sync::compact::Resolver<
            Family = F,
            Op = Operation<F, K, VariableEncoding<V>>,
            Digest = H::Digest,
        >,
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
        _sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync::compact::sync(sync::compact::Config {
            context,
            resolver,
            target,
            db_config: config,
            update_rx: Some(tip_updates),
            finish_rx: finish,
            reached_target_tx: reached_target,
        })
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
        BufferPooler, Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{full::Config as MerkleConfig, mmr},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use futures::pin_mut;
    use std::time::Duration;

    type FixedDb =
        fixed::CompactDb<mmr::Family, deterministic::Context, Digest, Digest, Sha256, Sequential>;
    type FullFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;
    type VariableDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        ((), (commonware_codec::RangeCfg<usize>, ())),
        Sequential,
    >;

    fn fixed_config(context: &impl BufferPooler, suffix: &str) -> fixed::CompactConfig<Sequential> {
        fixed::CompactConfig {
            strategy: Sequential,
            witness: commonware_storage::journal::contiguous::variable::Config {
                partition: format!("stateful-immutable-unjournaled-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
                write_buffer: NZUsize!(1024),
            },
            commit_codec_config: (),
        }
    }

    fn full_fixed_config(
        context: &impl BufferPooler,
        suffix: &str,
    ) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        fixed::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("stateful-immutable-full-journal-{suffix}"),
                metadata_partition: format!("stateful-immutable-full-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-immutable-full-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
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

    #[derive(Clone)]
    struct SupersedingCompactResolver {
        source: Arc<FullFixedDb>,
        stale_target: sync::compact::Target<mmr::Family, Digest>,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl sync::compact::Resolver for SupersedingCompactResolver {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = fixed::Operation<mmr::Family, Digest, Digest>;
        type Error = sync::compact::ServeError<mmr::Family, Digest>;

        async fn get_compact_state(
            &self,
            target: sync::compact::Target<Self::Family, Self::Digest>,
        ) -> Result<sync::compact::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>
        {
            if target == self.stale_target {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            sync::compact::Resolver::get_compact_state(&self.source, target).await
        }
    }

    #[test]
    fn immutable_unjournaled_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_finalize_commits_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[1]);
            let value = Sha256::hash(&[2]);
            let metadata = Sha256::hash(&[3]);

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .set(key, value)
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let (slot, database) = db.write().await;
                slot.put(
                    <FixedDb as ManagedDb<_>>::finalize(database, merkleized)
                        .await
                        .unwrap(),
                );
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(metadata));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.leaf_count, mmr::Location::new(3));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_immutable_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = FixedDb::init(context.child("source"), fixed_config(&context, "source"))
                .await
                .unwrap();
            let metadata = Sha256::hash(&[3]);
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&source, Some(metadata), floor)
                .await;
            let (source, _) = source.apply_batch(batch).unwrap();
            let source = source.sync().await.unwrap();

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
            assert_eq!(synced.get_metadata(), Some(metadata));
        });
    }

    #[test]
    fn state_sync_reports_compact_progress() {
        deterministic::Runner::default().start(|context| async move {
            let source_context = context.child("source");
            let source_config = full_fixed_config(&source_context, "source");
            let source = FullFixedDb::init(source_context, source_config)
                .await
                .unwrap();
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&source, Some(Sha256::hash(&[3])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().end,
            };

            // A larger target the resolver never serves. Its sync attempt
            // hangs so the test can observe the gauges while they diverge.
            let unservable_target = sync::compact::Target {
                root: Sha256::hash(&[0xFF]),
                leaf_count: Location::new(*target.leaf_count + 1),
            };
            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let resolver = SupersedingCompactResolver {
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
                resolver,
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

            let synced_leaves = *target.leaf_count;
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_target_leaf_count {synced_leaves}")),
                "missing compact sync target gauge: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_leaf_count {synced_leaves}")),
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

            let target_leaves = *unservable_target.leaf_count;
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_target_leaf_count {target_leaves}")),
                "target gauge should advance to the superseding target: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_leaf_count {synced_leaves}")),
                "synced gauge should still report the reached target: {encoded}"
            );
        });
    }

    #[test]
    fn state_sync_supersedes_in_flight_stale_compact_target() {
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
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&source, Some(Sha256::hash(&[9])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let stale_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().end,
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[3]), Sha256::hash(&[4]))
                .merkleize(&source, Some(Sha256::hash(&[10])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let latest_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().end,
            };

            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let resolver = SupersedingCompactResolver {
                source: Arc::new(source),
                stale_target: stale_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let sync_handle = context.child("sync").spawn(move |context| async move {
                <FixedDb as StateSyncDb<_, _>>::sync_db(
                    context.child("target"),
                    fixed_config(&context, "supersede-target"),
                    resolver,
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
            assert_eq!(synced.get_metadata(), Some(Sha256::hash(&[10])));
        });
    }

    #[test]
    fn managed_db_rewinds_fixed_immutable_unjournaled_multiple_commit_ranges() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "rewind");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&db, Some(Sha256::hash(&[11])), floor)
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let mut db = db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db);

            // Commit two more ranges so the rewind below spans multiple commits.
            for i in [3u8, 5] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[i]), Sha256::hash(&[i + 1]))
                    .merkleize(&db, Some(Sha256::hash(&[i * 11])), floor)
                    .await;
                (db, _) = db.apply_batch(batch).unwrap();
                db = db.sync().await.unwrap();
            }
            let third_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_ne!(third_target, first_target);

            let db = <FixedDb as ManagedDb<_>>::rewind_to_target(db, first_target.clone())
                .await
                .unwrap();

            let rewound_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(rewound_target, first_target);
            assert_eq!(db.get_metadata(), Some(Sha256::hash(&[11])));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_immutable_unjournaled_rewind_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = FixedDb::init(context.child("db"), config).await.unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for i in [1u8, 3, 5] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[i]), Sha256::hash(&[i + 1]))
                    .merkleize(&db, Some(Sha256::hash(&[i * 11])), floor)
                    .await;
                (db, _) = db.apply_batch(batch).unwrap();
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
                db.rewind(targets[0].leaf_count).await,
                Err(Error::Merkle(
                    commonware_storage::merkle::Error::RewindBeyondHistory
                ))
            ));
        });
    }
}
