//! Compact [`ManagedDb`] and [`StateSyncDb`] implementations for QMDB
//! [`compact`](commonware_storage::qmdb::compact) databases.
//!
//! Compact databases retain only the current Merkle peaks. Batches support merkleization but no
//! historical reads.

use crate::stateful::db::{
    BatchContext, InitError, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized as UnmerkleizedTrait, sync_compact_db, validate_initialization,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        compact::{Config, Db, MerkleizedBatch, Operation, UnmerkleizedBatch, initial_root},
        sync,
    },
};
use commonware_utils::channel::mpsc;
use std::{ops::Deref, sync::Arc};

/// A speculative batch over a shared compact database.
pub struct CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    pub(super) batch: UnmerkleizedBatch<F, H, O, S>,
    db: Shared<Db<F, E, O, H, S>>,
    metadata: Option<O::Metadata>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, O, H, S> Deref for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = UnmerkleizedBatch<F, H, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, O, H, S> CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    /// Sets the metadata committed by [`merkleize`](UnmerkleizedTrait::merkleize).
    pub fn with_metadata(mut self, metadata: O::Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the inactivity floor committed by [`merkleize`](UnmerkleizedTrait::merkleize)
    /// (location 0 when unset).
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }
}

impl<F, E, O, H, S> UnmerkleizedTrait for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
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
            .await?;
        Ok(CompactMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// A sealed compact batch with a computed root.
pub struct CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, O, S>>,
    db: Shared<Db<F, E, O, H, S>>,
}

impl<F, E, O, H, S> Clone for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, O, H, S> Deref for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = MerkleizedBatch<F, H::Digest, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, O, H, S> MerkleizedTrait for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        CompactUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, O, H, S> ManagedDb<E> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
    type Error = Error<F>;
    type Config = Config<O::Cfg, S>;
    type SyncTarget = sync::CompactTarget<F, H::Digest>;

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>, Self::SyncTarget>> {
        let db = <Self>::init(context, config, expected.as_ref().map(|target| target.size))
            .await
            .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::CompactTarget {
            root: initial_root::<F, O, H>(),
            size: Location::new(1),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CompactUnmerkleized {
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
}

impl<F, E, O, H, S, R> StateSyncDb<E, R> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context + Spawner,
    O: Operation<F>,
    H: Hasher,
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
    use crate::stateful::db::DatabaseSet;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock as _, Metrics as _, Runner as _, Supervisor as _,
        buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks,
    };
    use commonware_storage::{
        journal::contiguous::{
            fixed::Config as FixedJournalConfig, variable::Config as JournalConfig,
        },
        merkle::{full::Config as MerkleConfig, mmb, mmr},
        qmdb::{immutable, keyless, sync::source, verify_proof_and_pinned_nodes},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};
    use futures::pin_mut;
    use std::time::Duration;

    type TestDb<F, O> = Db<F, deterministic::Context, O, Sha256, Sequential>;
    type TestBatch<F, O> = UnmerkleizedBatch<F, Sha256, O, Sequential>;

    /// Bounded initialization through [`ManagedDb::init`] reports target mismatches, restores an
    /// exact target that then serves and verifies, and fails once that target is pruned.
    fn bounded_initialization<F, O>(
        codec_config: O::Cfg,
        mutate: impl Fn(TestBatch<F, O>, u64) -> TestBatch<F, O>,
        metadata: impl Fn(u64) -> O::Metadata,
    ) where
        F: Family,
        O: Operation<F, Metadata: PartialEq + std::fmt::Debug>,
    {
        deterministic::Runner::default().start(|context| async move {
            let cfg = Config {
                strategy: Sequential,
                witness: JournalConfig {
                    partition: "compact-initialization-matrix".into(),
                    items_per_section: NZU64!(1),
                    compression: None,
                    codec_config,
                    page_cache: CacheRef::from_pooler(&context, NZU16!(101), NZUsize!(11)),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            };
            let db = <TestDb<F, O> as ManagedDb<_>>::init(context.child("seed"), cfg.clone(), None)
                .await
                .unwrap();
            let batch = mutate(mutate(mutate(db.new_batch(), 1), 2), 3)
                .merkleize(&db, Some(metadata(11)), Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let first = db.target();
            assert_eq!(first.size, Location::new(5));
            let batch = mutate(db.new_batch(), 4)
                .merkleize(&db, Some(metadata(22)), Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let latest = db.target();
            drop(db);

            let mut wrong_root = latest.clone();
            wrong_root.root = Sha256::fill(0xff);
            let result = <TestDb<F, O> as ManagedDb<_>>::init(
                context.child("wrong_root"),
                cfg.clone(),
                Some(wrong_root.clone()),
            )
            .await;
            let Err(InitError::TargetMismatch {
                expected,
                recovered,
            }) = result
            else {
                panic!("a wrong root must be a target mismatch");
            };
            assert_eq!(expected, wrong_root);
            assert_eq!(recovered, latest);

            // A cap inside a batch selects the preceding commit, but is not an exact sync target.
            let mut between = first.clone();
            between.size += 1;
            let result = <TestDb<F, O> as ManagedDb<_>>::init(
                context.child("between"),
                cfg.clone(),
                Some(between.clone()),
            )
            .await;
            let Err(InitError::TargetMismatch {
                expected,
                recovered,
            }) = result
            else {
                panic!("a size between commits must be a target mismatch");
            };
            assert_eq!(expected, between);
            assert_eq!(recovered, first);

            let db = <TestDb<F, O> as ManagedDb<_>>::init(
                context.child("exact"),
                cfg.clone(),
                Some(first.clone()),
            )
            .await
            .unwrap();
            assert_eq!(db.get_metadata(), Some(metadata(11)));
            assert_eq!(db.inactivity_floor_loc(), Location::new(0));
            let request = sync::Request::Boundary {
                size: first.size,
                start: first.size - 1,
            };
            let (response, _) = sync::Source::serve(&db, request).await.unwrap();
            let sync::Response::Boundary {
                proof,
                op,
                pinned_nodes,
            } = response
            else {
                panic!("expected boundary response");
            };
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &proof,
                first.size - 1,
                &[op],
                &pinned_nodes,
                &first.root
            ));
            drop(db);
            let db = TestDb::<F, O>::init(context.child("reopen"), cfg.clone(), None)
                .await
                .unwrap();
            assert_eq!(db.target(), first);

            let batch = mutate(db.new_batch(), 5)
                .merkleize(&db, Some(metadata(33)), first.size - 1)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let latest = db.target();
            let db = db.prune(latest.size).await.unwrap();
            drop(db);
            assert!(matches!(
                <TestDb<F, O> as ManagedDb<_>>::init(
                    context.child("pruned"),
                    cfg.clone(),
                    Some(first)
                )
                .await,
                Err(InitError::Database(Error::HistoricalFloorPruned(_)))
            ));
            let db =
                <TestDb<F, O> as ManagedDb<_>>::init(context.child("latest"), cfg, Some(latest))
                    .await
                    .unwrap();
            assert_eq!(db.get_metadata(), Some(metadata(33)));
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_fixed_mmr() {
        bounded_initialization::<mmr::Family, keyless::fixed::Operation<mmr::Family, U64>>(
            (),
            |batch, seed| batch.append(U64::new(seed)),
            U64::new,
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_variable_mmr() {
        bounded_initialization::<mmr::Family, keyless::variable::Operation<mmr::Family, Vec<u8>>>(
            ((..).into(), ()),
            |batch, seed| batch.append(seed.to_le_bytes().to_vec()),
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_fixed_mmr() {
        bounded_initialization::<
            mmr::Family,
            immutable::fixed::Operation<mmr::Family, Digest, Digest>,
        >(
            (),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    Sha256::hash(&[&seed.to_le_bytes()]),
                )
            },
            |seed| Sha256::hash(&[&seed.to_le_bytes()]),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_variable_mmr() {
        bounded_initialization::<
            mmr::Family,
            immutable::variable::Operation<mmr::Family, Digest, Vec<u8>>,
        >(
            ((), ((..).into(), ())),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    seed.to_le_bytes().to_vec(),
                )
            },
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_fixed_mmb() {
        bounded_initialization::<mmb::Family, keyless::fixed::Operation<mmb::Family, U64>>(
            (),
            |batch, seed| batch.append(U64::new(seed)),
            U64::new,
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_variable_mmb() {
        bounded_initialization::<mmb::Family, keyless::variable::Operation<mmb::Family, Vec<u8>>>(
            ((..).into(), ()),
            |batch, seed| batch.append(seed.to_le_bytes().to_vec()),
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_fixed_mmb() {
        bounded_initialization::<
            mmb::Family,
            immutable::fixed::Operation<mmb::Family, Digest, Digest>,
        >(
            (),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    Sha256::hash(&[&seed.to_le_bytes()]),
                )
            },
            |seed| Sha256::hash(&[&seed.to_le_bytes()]),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_variable_mmb() {
        bounded_initialization::<
            mmb::Family,
            immutable::variable::Operation<mmb::Family, Digest, Vec<u8>>,
        >(
            ((), ((..).into(), ())),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    seed.to_le_bytes().to_vec(),
                )
            },
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    type Target = sync::CompactTarget<mmr::Family, Digest>;
    type AdapterDb<O> = TestDb<mmr::Family, O>;
    type AdapterBatch<O> =
        CompactUnmerkleized<mmr::Family, deterministic::Context, O, Sha256, Sequential>;
    type KeylessOp = keyless::fixed::Operation<mmr::Family, U64>;
    type ImmutableOp = immutable::fixed::Operation<mmr::Family, Digest, Digest>;
    type FullKeylessDb =
        keyless::fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type FullImmutableDb = immutable::fixed::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

    /// An operation type the shared adapter tests run over.
    trait AdapterOperation:
        Operation<mmr::Family, Cfg = (), Metadata: PartialEq + std::fmt::Debug>
    {
        /// The full db that serves the same operations.
        type Full: sync::Source<Family = mmr::Family, Digest = Digest, Op = Self>
            + Send
            + Sync
            + 'static;

        /// Add the mutation derived from `seed` to a storage batch.
        fn mutate(batch: TestBatch<mmr::Family, Self>, seed: u64) -> TestBatch<mmr::Family, Self>;

        /// Add the mutation derived from `seed` to an adapter batch.
        fn mutate_managed(batch: AdapterBatch<Self>, seed: u64) -> AdapterBatch<Self>;

        /// The commit metadata for `seed`.
        fn commit_metadata(seed: u64) -> Self::Metadata;

        /// A full db with one synced batch per seed, and the target after each.
        async fn full_source(
            context: deterministic::Context,
            seeds: &[u64],
        ) -> (Arc<Self::Full>, Vec<Target>);
    }

    fn full_merkle_config(page_cache: CacheRef) -> MerkleConfig<Sequential> {
        MerkleConfig {
            journal_partition: "stateful-full-journal".into(),
            metadata_partition: "stateful-full-metadata".into(),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache,
        }
    }

    fn full_log_config(page_cache: CacheRef) -> FixedJournalConfig {
        FixedJournalConfig {
            partition: "stateful-full-log".into(),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    impl AdapterOperation for KeylessOp {
        type Full = FullKeylessDb;

        fn mutate(batch: TestBatch<mmr::Family, Self>, seed: u64) -> TestBatch<mmr::Family, Self> {
            batch.append(U64::new(seed))
        }

        fn mutate_managed(batch: AdapterBatch<Self>, seed: u64) -> AdapterBatch<Self> {
            batch.append(U64::new(seed))
        }

        fn commit_metadata(seed: u64) -> U64 {
            U64::new(seed + 1000)
        }

        async fn full_source(
            context: deterministic::Context,
            seeds: &[u64],
        ) -> (Arc<FullKeylessDb>, Vec<Target>) {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(101), NZUsize!(11));
            let config = keyless::fixed::Config {
                merkle: full_merkle_config(page_cache.clone()),
                log: full_log_config(page_cache),
            };
            let mut source = FullKeylessDb::init(context, config, None).await.unwrap();
            let mut targets = Vec::new();
            for &seed in seeds {
                let floor = source.inactivity_floor_loc();
                let batch = source
                    .new_batch()
                    .append(U64::new(seed))
                    .merkleize(&source, Some(Self::commit_metadata(seed)), floor)
                    .await
                    .unwrap();
                (source, _) = source.apply_batch(batch).await.unwrap();
                source = source.sync().await.unwrap();
                targets.push(Target {
                    root: source.root(),
                    size: source.bounds().end,
                });
            }
            (Arc::new(source), targets)
        }
    }

    fn immutable_key(seed: u64) -> Digest {
        Sha256::hash(&[&seed.to_be_bytes()])
    }

    fn immutable_value(seed: u64) -> Digest {
        Sha256::hash(&[&seed.to_le_bytes()])
    }

    impl AdapterOperation for ImmutableOp {
        type Full = FullImmutableDb;

        fn mutate(batch: TestBatch<mmr::Family, Self>, seed: u64) -> TestBatch<mmr::Family, Self> {
            batch.set(immutable_key(seed), immutable_value(seed))
        }

        fn mutate_managed(batch: AdapterBatch<Self>, seed: u64) -> AdapterBatch<Self> {
            batch.set(immutable_key(seed), immutable_value(seed))
        }

        fn commit_metadata(seed: u64) -> Digest {
            immutable_value(seed + 1000)
        }

        async fn full_source(
            context: deterministic::Context,
            seeds: &[u64],
        ) -> (Arc<FullImmutableDb>, Vec<Target>) {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(101), NZUsize!(11));
            let config = immutable::fixed::Config {
                merkle_config: full_merkle_config(page_cache.clone()),
                log: full_log_config(page_cache),
                translator: TwoCap,
                init_buffer: NZUsize!(1 << 21),
            };
            let mut source = FullImmutableDb::init(context, config, None).await.unwrap();
            let mut targets = Vec::new();
            for &seed in seeds {
                let floor = source.inactivity_floor_loc();
                let batch = source
                    .new_batch()
                    .set(immutable_key(seed), immutable_value(seed))
                    .merkleize(&source, Some(Self::commit_metadata(seed)), floor)
                    .await
                    .unwrap();
                (source, _) = source.apply_batch(batch).await.unwrap();
                source = source.sync().await.unwrap();
                targets.push(Target {
                    root: source.root(),
                    size: source.bounds().end,
                });
            }
            (Arc::new(source), targets)
        }
    }

    fn compact_config(context: &impl BufferPooler, suffix: &str) -> Config<(), Sequential> {
        Config {
            strategy: Sequential,
            witness: JournalConfig {
                partition: format!("stateful-compact-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
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

    /// A compact db with one synced batch per seed, and the target after each.
    async fn compact_source<O: AdapterOperation>(
        context: deterministic::Context,
        seeds: &[u64],
    ) -> (Arc<AdapterDb<O>>, Vec<Target>) {
        let config = compact_config(&context, "source");
        let mut source = AdapterDb::<O>::init(context, config, None).await.unwrap();
        let mut targets = Vec::new();
        for &seed in seeds {
            let floor = source.inactivity_floor_loc();
            let batch = O::mutate(source.new_batch(), seed)
                .merkleize(&source, Some(O::commit_metadata(seed)), floor)
                .await
                .unwrap();
            (source, _) = source.apply_batch(batch).await.unwrap();
            source = source.sync().await.unwrap();
            targets.push(source.target());
        }
        (Arc::new(source), targets)
    }

    /// Serves `source`, except that a request at `stale_target`'s size signals
    /// `stale_request_tx` and never completes.
    struct SupersedingSource<S> {
        source: Arc<S>,
        stale_target: Target,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl<S> Clone for SupersedingSource<S> {
        fn clone(&self) -> Self {
            Self {
                source: Arc::clone(&self.source),
                stale_target: self.stale_target.clone(),
                stale_request_tx: self.stale_request_tx.clone(),
            }
        }
    }

    impl<S> sync::Source for SupersedingSource<S>
    where
        S: sync::Source<Family = mmr::Family, Digest = Digest, Op: Send> + Send + Sync + 'static,
    {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = S::Op;
        type Error = <Arc<S> as sync::Source>::Error;

        async fn serve(&self, request: sync::Request<Self::Family>) -> source::Result<Self> {
            if request.size() == self.stale_target.size {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            self.source.serve(request).await
        }
    }

    #[test]
    fn trait_impls_compile() {
        fn assert_state_sync_db<T: StateSyncDb<deterministic::Context, Arc<T>>>() {}

        assert_state_sync_db::<AdapterDb<KeylessOp>>();
        assert_state_sync_db::<AdapterDb<keyless::variable::Operation<mmr::Family, Vec<u8>>>>();
        assert_state_sync_db::<AdapterDb<ImmutableOp>>();
        assert_state_sync_db::<
            AdapterDb<immutable::variable::Operation<mmr::Family, Digest, Vec<u8>>>,
        >();
    }

    fn managed_db_apply_and_finalize_persists_batches<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_config(&context, "managed-db");
            let db = AdapterDb::<O>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = O::mutate_managed(db.new_batch_for_test::<_>().await, 7)
                .with_inactivity_floor(Location::new(1))
                .with_metadata(O::commit_metadata(7));
            let merkleized = UnmerkleizedTrait::merkleize(batch).await.unwrap();
            let expected_root = merkleized.root();

            {
                let (slot, database) = db.write().await;
                let database = <AdapterDb<O> as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let (database, sync) = <AdapterDb<O> as ManagedDb<_>>::finalize(database)
                    .await
                    .unwrap();
                slot.put(database);
                sync.await.expect("database sync failed");
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(O::commit_metadata(7)));

            let target = <AdapterDb<O> as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, expected_root);
            assert_eq!(target.size, Location::new(3));
        });
    }

    fn managed_db_apply_retains_each_bounded_initialization_target<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_config(&context, "apply-checkpoints");
            let db = AdapterDb::<O>::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let first = O::mutate_managed(db.new_batch_for_test::<_>().await, 1)
                .with_metadata(O::commit_metadata(1));
            let first = UnmerkleizedTrait::merkleize(first).await.unwrap();
            let first_target = Target {
                root: first.root(),
                size: first.bounds().tip.size,
            };
            let (slot, database) = db.write().await;
            let database = <AdapterDb<O> as ManagedDb<_>>::apply(database, first)
                .await
                .unwrap();
            slot.put(database);

            let second = O::mutate_managed(db.new_batch_for_test::<_>().await, 2)
                .with_metadata(O::commit_metadata(2));
            let second = UnmerkleizedTrait::merkleize(second).await.unwrap();
            let (slot, database) = db.write().await;
            let database = <AdapterDb<O> as ManagedDb<_>>::apply(database, second)
                .await
                .unwrap();
            let (database, sync) = <AdapterDb<O> as ManagedDb<_>>::finalize(database)
                .await
                .unwrap();
            sync.await.expect("database sync failed");
            slot.put(database);
            drop(db);

            let database = <AdapterDb<O> as ManagedDb<_>>::init(
                context.child("reopen"),
                config,
                Some(first_target.clone()),
            )
            .await
            .unwrap();
            assert_eq!(
                <AdapterDb<O> as ManagedDb<_>>::sync_target(&database),
                first_target,
            );
        });
    }

    fn managed_db_matches_sync_target_rejects_wrong_size<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_config(&context, "matches-sync-target");
            let db = AdapterDb::<O>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = O::mutate_managed(db.new_batch_for_test::<_>().await, 7)
                .with_inactivity_floor(Location::new(1))
                .with_metadata(O::commit_metadata(7));
            let merkleized = UnmerkleizedTrait::merkleize(batch).await.unwrap();

            let valid_target = Target {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            };
            assert!(<AdapterDb<O> as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let wrong_size = Target {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size - 1,
            };
            assert!(!<AdapterDb<O> as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_size,
            ));
        });
    }

    fn database_set_bounded_initialization_persists_aligned_target<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_config(&context, "aligned-bounded-init");
            let db = AdapterDb::<O>::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = O::mutate_managed(db.new_batch_for_test::<_>().await, 1)
                .with_metadata(O::commit_metadata(1));
            let batch = UnmerkleizedTrait::merkleize(batch).await.unwrap();
            DatabaseSet::apply(&db, batch).await;
            let target = DatabaseSet::committed_targets(&db).await;
            DatabaseSet::finalize(&db).await.durable().await;
            drop(db);
            let db = <Shared<AdapterDb<O>> as DatabaseSet<_>>::init(
                context.child("aligned_cap"),
                config.clone(),
                Some(target.clone()),
            )
            .await;
            drop(db);

            let database = AdapterDb::<O>::init(context.child("reopen"), config, None)
                .await
                .unwrap();
            assert_eq!(
                <AdapterDb<O> as ManagedDb<_>>::sync_target(&database),
                target
            );
        });
    }

    fn state_sync_fetches_compact_state<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let (source, targets) = compact_source::<O>(context.child("source"), &[7]).await;

            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <AdapterDb<O> as StateSyncDb<_, _>>::sync_db(
                context.child("target"),
                compact_config(&context, "target"),
                source,
                targets[0].clone(),
                update_rx,
                None,
                None,
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.target(), targets[0]);
            assert_eq!(synced.get_metadata(), Some(O::commit_metadata(7)));
        });
    }

    fn state_sync_stops_compact_update_forwarder_after_completion<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let (source, targets) = compact_source::<O>(context.child("source"), &[7]).await;

            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <AdapterDb<O> as StateSyncDb<_, _>>::sync_db(
                context.child("target"),
                compact_config(&context, "target"),
                source,
                targets[0].clone(),
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

    fn state_sync_drains_queued_target_before_reporting_reached<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let (source, targets) = O::full_source(context.child("source"), &[7, 8]).await;

            let (update_tx, update_rx) = mpsc::channel(1);
            update_tx.send(targets[1].clone()).await.unwrap();
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let synced = <AdapterDb<O> as StateSyncDb<_, _>>::sync_db(
                context.child("target"),
                compact_config(&context, "target"),
                source,
                targets[0].clone(),
                update_rx,
                None,
                Some(reached_tx),
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(reached_rx.recv().await, Some(targets[1].clone()));
            assert_eq!(synced.target(), targets[1]);
            assert_eq!(synced.get_metadata(), Some(O::commit_metadata(8)));
        });
    }

    async fn state_sync_reports_compact_progress<O, S>(
        context: deterministic::Context,
        source: Arc<S>,
        target: Target,
    ) where
        O: AdapterOperation,
        S: sync::Source<Family = mmr::Family, Digest = Digest, Op = O> + Send + Sync + 'static,
    {
        // A larger target the source never serves. Its sync attempt
        // hangs so the test can observe the gauges while they diverge.
        let unservable_target = Target {
            root: Sha256::hash(&[&[0xFF]]),
            size: target.size + 1,
        };
        let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
        let superseding_source = SupersedingSource {
            source,
            stale_target: unservable_target.clone(),
            stale_request_tx,
        };

        let (update_tx, update_rx) = mpsc::channel(1);
        let (_finish_tx, finish_rx) = mpsc::channel(1);
        let (reached_tx, mut reached_rx) = mpsc::channel(1);
        let client_context = context.child("client");
        let client_config = compact_config(&client_context, "client");
        let sync = <AdapterDb<O> as StateSyncDb<_, _>>::sync_db(
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
    }

    /// The seeds of the stale and latest batches the superseding tests sync.
    const SUPERSEDE_SEEDS: [u64; 2] = [7, 8];

    async fn state_sync_supersedes_in_flight_stale_compact_target<O, S>(
        context: deterministic::Context,
        source: Arc<S>,
        targets: Vec<Target>,
    ) where
        O: AdapterOperation,
        S: sync::Source<Family = mmr::Family, Digest = Digest, Op = O> + Send + Sync + 'static,
    {
        let [stale_target, latest_target] = <[Target; 2]>::try_from(targets).unwrap();
        let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
        let superseding_source = SupersedingSource {
            source,
            stale_target: stale_target.clone(),
            stale_request_tx,
        };

        let (update_tx, update_rx) = mpsc::channel(1);
        let sync_handle = context.child("sync").spawn(move |context| async move {
            <AdapterDb<O> as StateSyncDb<_, _>>::sync_db(
                context.child("target"),
                compact_config(&context, "supersede-target"),
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
        assert_eq!(
            synced.get_metadata(),
            Some(O::commit_metadata(SUPERSEDE_SEEDS[1]))
        );
    }

    fn managed_db_initializes_multiple_commit_ranges<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_config(&context, "bounded-init");
            let mut db = AdapterDb::<O>::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();

            // Commit three ranges so reopening at the first target spans multiple commits.
            let mut targets = Vec::new();
            for seed in [1u64, 2, 3] {
                let floor = db.inactivity_floor_loc();
                let batch = O::mutate(db.new_batch(), seed)
                    .merkleize(&db, Some(O::commit_metadata(seed)), floor)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<AdapterDb<O> as ManagedDb<_>>::sync_target(&db));
            }
            assert_ne!(targets[2], targets[0]);

            drop(db);
            let db = <AdapterDb<O> as ManagedDb<_>>::init(
                context.child("cap"),
                config,
                Some(targets[0].clone()),
            )
            .await
            .unwrap();

            assert_eq!(<AdapterDb<O> as ManagedDb<_>>::sync_target(&db), targets[0]);
            assert_eq!(db.get_metadata(), Some(O::commit_metadata(1)));
        });
    }

    fn managed_db_prune_bounds_bounded_initialization_history<O: AdapterOperation>() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = compact_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = AdapterDb::<O>::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for seed in [1u64, 2, 3] {
                let floor = db.inactivity_floor_loc();
                let batch = O::mutate(db.new_batch(), seed)
                    .merkleize(&db, Some(O::commit_metadata(seed)), floor)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<AdapterDb<O> as ManagedDb<_>>::sync_target(&db));
            }
            assert_ne!(targets[0], targets[1]);

            // Pruning at the second target retains it but excludes the first.
            let db = <AdapterDb<O> as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            drop(db);
            let db = <AdapterDb<O> as ManagedDb<_>>::init(
                context.child("cap"),
                config.clone(),
                Some(targets[1].clone()),
            )
            .await
            .unwrap();
            assert_eq!(<AdapterDb<O> as ManagedDb<_>>::sync_target(&db), targets[1]);
            drop(db);
            assert!(matches!(
                <AdapterDb<O> as ManagedDb<_>>::init(
                    context.child("pruned_cap"),
                    config,
                    Some(targets[0].clone())
                )
                .await,
                Err(InitError::Database(Error::HistoricalFloorPruned(_)))
            ));
        });
    }

    macro_rules! adapter_tests {
        ($module:ident, $operation:ty) => {
            mod $module {
                use super::*;

                #[test]
                fn managed_db_apply_and_finalize_persists_batches() {
                    super::managed_db_apply_and_finalize_persists_batches::<$operation>();
                }

                #[test]
                fn managed_db_apply_retains_each_bounded_initialization_target() {
                    super::managed_db_apply_retains_each_bounded_initialization_target::<
                        $operation,
                    >();
                }

                #[test]
                fn managed_db_matches_sync_target_rejects_wrong_size() {
                    super::managed_db_matches_sync_target_rejects_wrong_size::<$operation>();
                }

                #[test]
                fn database_set_bounded_initialization_persists_aligned_target() {
                    super::database_set_bounded_initialization_persists_aligned_target::<
                        $operation,
                    >();
                }

                #[test]
                fn state_sync_fetches_compact_state() {
                    super::state_sync_fetches_compact_state::<$operation>();
                }

                #[test]
                fn state_sync_stops_compact_update_forwarder_after_completion() {
                    super::state_sync_stops_compact_update_forwarder_after_completion::<
                        $operation,
                    >();
                }

                #[test]
                fn state_sync_drains_queued_target_before_reporting_reached() {
                    super::state_sync_drains_queued_target_before_reporting_reached::<$operation>(
                    );
                }

                #[test]
                fn state_sync_reports_compact_progress_from_compact_source() {
                    deterministic::Runner::default().start(|context| async move {
                        let (source, targets) =
                            compact_source::<$operation>(context.child("source"), &[7]).await;
                        super::state_sync_reports_compact_progress::<$operation, _>(
                            context,
                            source,
                            targets[0].clone(),
                        )
                        .await;
                    });
                }

                #[test]
                fn state_sync_reports_compact_progress_from_full_source() {
                    deterministic::Runner::default().start(|context| async move {
                        let (source, targets) =
                            <$operation>::full_source(context.child("source"), &[7]).await;
                        super::state_sync_reports_compact_progress::<$operation, _>(
                            context,
                            source,
                            targets[0].clone(),
                        )
                        .await;
                    });
                }

                #[test]
                fn state_sync_supersedes_in_flight_stale_target_from_compact_source() {
                    deterministic::Runner::default().start(|context| async move {
                        let (source, targets) =
                            compact_source::<$operation>(context.child("source"), &SUPERSEDE_SEEDS)
                                .await;
                        super::state_sync_supersedes_in_flight_stale_compact_target::<
                            $operation,
                            _,
                        >(context, source, targets)
                        .await;
                    });
                }

                #[test]
                fn state_sync_supersedes_in_flight_stale_target_from_full_source() {
                    deterministic::Runner::default().start(|context| async move {
                        let (source, targets) =
                            <$operation>::full_source(context.child("source"), &SUPERSEDE_SEEDS)
                                .await;
                        super::state_sync_supersedes_in_flight_stale_compact_target::<
                            $operation,
                            _,
                        >(context, source, targets)
                        .await;
                    });
                }

                #[test]
                fn managed_db_initializes_multiple_commit_ranges() {
                    super::managed_db_initializes_multiple_commit_ranges::<$operation>();
                }

                #[test]
                fn managed_db_prune_bounds_bounded_initialization_history() {
                    super::managed_db_prune_bounds_bounded_initialization_history::<$operation>();
                }
            }
        };
    }

    adapter_tests!(keyless_fixed, KeylessOp);
    adapter_tests!(immutable_fixed, ImmutableOp);
}
