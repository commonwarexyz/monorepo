//! Sync tests for immutable databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for immutable databases and adds immutable-specific tests to
//! the modules the shared macro generates.

use crate::{
    merkle::{Location, full::Config as MerkleConfig},
    qmdb::{
        self,
        immutable::{self, variable::Operation},
        sync::{
            self, Target,
            engine::Config,
            harness::{
                CompactConfigOf, CompactOpOf, CompactSyncTestHarness, ConfigOf, DbOf, JournalOf,
                OpOf, PAGE_CACHE_SIZE, PAGE_SIZE, SyncTestHarness, prune_boxed,
            },
        },
    },
    translator::TwoCap,
};
use commonware_codec::Encode;
use commonware_cryptography::{Sha256, sha256};
use commonware_macros::boxed;
use commonware_math::algebra::Random;
use commonware_runtime::{
    BufferPooler, Metrics, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{NZU64, NZUsize, TestRng, non_empty_range};
use harnesses::VariableMmrHarness as H;
use rand::Rng as _;
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Immutable-specific harness methods used by the immutable-only sync tests.
pub(crate) trait ImmutableSyncTestHarness: SyncTestHarness {
    /// Key type of the database.
    type Key: Send + Sync + 'static;
    /// Value type stored under a key.
    type Value: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static;

    /// Applies `ops` like [`SyncTestHarness::apply_ops`], with the commit declaring `floor`
    /// as the inactivity floor.
    fn apply_ops_with_floor(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Metadata>,
        floor: Location<Self::Family>,
    ) -> impl Future<Output = Self::Db> + Send;
    /// Commits the applied batches of `db` so they survive a crash.
    fn commit(db: Self::Db) -> impl Future<Output = Self::Db> + Send;
    /// Returns the key and value an operation sets, or `None` for a commit.
    fn op_kv(op: &OpOf<Self>) -> Option<(&Self::Key, &Self::Value)>;
    /// Returns the value stored under `key`, if any.
    fn lookup(db: &Self::Db, key: &Self::Key) -> impl Future<Output = Option<Self::Value>> + Send;
}

/// A client synced over the full retained history of a target with a nonzero inactivity floor
/// matches that floor and resolves only keys set at or above it.
pub(crate) fn test_sync_nonzero_floor<H: ImmutableSyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;

        // First batch with floor=0.
        let early_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, early_ops.clone(), None).await;
        let target_db = H::commit(target_db).await;
        let first_commit_end = H::bounds(&target_db).end;

        // Second batch with floor = first_commit_end, declaring the first batch inactive.
        let late_ops = H::create_ops_seeded(50, 1);
        let target_db = H::apply_ops_with_floor(
            target_db,
            late_ops.clone(),
            Some(H::sample_metadata()),
            first_commit_end,
        )
        .await;
        let target_db = H::commit(target_db).await;

        assert_eq!(H::inactivity_floor_loc(&target_db), first_commit_end);

        // Sync from the oldest retained operation, below the floor, so the client also receives
        // the inactive first batch.
        let bounds = H::bounds(&target_db);
        let target_root = H::db_root(&target_db);

        let target_db = Arc::new(target_db);
        let db_config = H::config(&format!("floor_sync_{}", context.next_u64()), &context);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(100),
            target: Target {
                root: target_root,
                range: non_empty_range!(bounds.start, bounds.end),
            },
            context: context.child("client"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        assert_eq!(H::inactivity_floor_loc(&synced_db), first_commit_end);

        // Keys from the second batch (after the floor) should be findable.
        for op in &late_ops {
            if let Some((key, value)) = H::op_kv(op) {
                assert_eq!(H::lookup(&synced_db, key).await, Some(value.clone()));
            }
        }

        // Keys from the first batch (before the floor) should NOT be in the snapshot.
        for op in &early_ops {
            if let Some((key, _)) = H::op_kv(op) {
                assert_eq!(
                    H::lookup(&synced_db, key).await,
                    None,
                    "key from before floor should not be in synced snapshot"
                );
            }
        }

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

pub(crate) mod harnesses {
    use super::*;
    use crate::{
        journal::contiguous::Mutable,
        merkle::{Family, mmb, mmr},
        qmdb::any::value::ValueEncoding,
    };
    use commonware_codec::{EncodeShared, Read};
    use commonware_cryptography::Hasher as _;
    use commonware_parallel::Sequential;

    type VariableDb<F> = immutable::variable::Db<
        F,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

    fn variable_config(
        suffix: &str,
        pooler: &(impl BufferPooler + Metrics),
    ) -> immutable::variable::Config<TwoCap, ((), ()), Sequential> {
        const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(5);

        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        immutable::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-{suffix}"),
                items_per_section: ITEMS_PER_SECTION,
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_buffer: NZUsize!(1 << 21),
        }
    }

    fn variable_create_ops_seeded<F: Family>(
        n: usize,
        seed: u64,
    ) -> Vec<Operation<F, sha256::Digest, sha256::Digest>> {
        let mut rng = TestRng::new(seed);
        let mut ops = Vec::new();
        for _ in 0..n {
            let key = sha256::Digest::random(&mut rng);
            let value = sha256::Digest::random(&mut rng);
            ops.push(Operation::Set(key, value));
        }
        ops
    }

    #[boxed]
    async fn variable_apply_ops<F: Family>(
        db: VariableDb<F>,
        ops: Vec<Operation<F, sha256::Digest, sha256::Digest>>,
        metadata: Option<sha256::Digest>,
    ) -> VariableDb<F>
    where
        VariableDb<F>: qmdb::sync::Database,
    {
        let floor = db.inactivity_floor_loc();
        variable_apply_ops_with_floor::<F>(db, ops, metadata, floor).await
    }

    async fn variable_apply_ops_with_floor<F: Family>(
        db: VariableDb<F>,
        ops: Vec<Operation<F, sha256::Digest, sha256::Digest>>,
        metadata: Option<sha256::Digest>,
        floor: Location<F>,
    ) -> VariableDb<F>
    where
        VariableDb<F>: qmdb::sync::Database,
    {
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Set(key, value) => {
                    batch = batch.set(key, value);
                }
                Operation::Commit(_, _) => {
                    panic!("Commit operation not supported in apply_ops");
                }
            }
        }
        let merkleized = batch.merkleize(&db, metadata, floor).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db
    }

    pub(crate) struct VariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> SyncTestHarness for VariableHarness<F> {
        type Family = F;
        type Db = VariableDb<F>;
        type Metadata = sha256::Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
            variable_config(suffix, pooler)
        }

        fn create_ops(n: usize) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, 0)
        }

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            Sha256::fill(1)
        }

        async fn init_db(mut ctx: deterministic::Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config = variable_config(&format!("sync-test-{seed}"), &ctx);
            Self::Db::init(ctx, config, None).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: deterministic::Context,
            config: ConfigOf<Self>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, None).await.unwrap()
        }

        #[boxed]
        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn db_sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<OpOf<Self>>,
            metadata: Option<Self::Metadata>,
        ) -> Self::Db {
            variable_apply_ops::<F>(db, ops, metadata).await
        }

        async fn prune(db: Self::Db, loc: Location<Self::Family>) -> Self::Db {
            // Advance the inactivity floor to `loc` via a commit before pruning,
            // since prune requires the floor to be at or beyond the prune target.
            let merkleized = db.new_batch().merkleize(&db, None, loc).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();
            db.prune(loc).await.unwrap()
        }

        fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>> {
            db.bounds()
        }

        fn sync_boundary(db: &Self::Db) -> Location<Self::Family> {
            db.sync_boundary()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family> {
            db.inactivity_floor_loc()
        }

        fn db_root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        async fn get_metadata(db: &Self::Db) -> Option<Self::Metadata> {
            db.get_metadata().await.unwrap()
        }

        async fn assert_ops_applied(
            db: &Self::Db,
            _start: Location<Self::Family>,
            ops: &[OpOf<Self>],
        ) {
            for op in ops {
                if let Some((key, expected_value)) = Self::op_kv(op) {
                    let got = Self::lookup(db, key).await;
                    assert_eq!(got.as_ref(), Some(expected_value));
                }
            }
        }

        async fn assert_ops_absent(db: &Self::Db, ops: &[OpOf<Self>]) {
            for op in ops {
                if let Some((key, _)) = Self::op_kv(op) {
                    assert_eq!(Self::lookup(db, key).await, None);
                }
            }
        }
    }

    impl<F: Family> ImmutableSyncTestHarness for VariableHarness<F> {
        type Key = sha256::Digest;
        type Value = sha256::Digest;

        async fn apply_ops_with_floor(
            db: Self::Db,
            ops: Vec<OpOf<Self>>,
            metadata: Option<Self::Metadata>,
            floor: Location<Self::Family>,
        ) -> Self::Db {
            variable_apply_ops_with_floor::<F>(db, ops, metadata, floor).await
        }

        async fn commit(db: Self::Db) -> Self::Db {
            db.commit().await.unwrap()
        }

        fn op_kv(op: &OpOf<Self>) -> Option<(&Self::Key, &Self::Value)> {
            match op {
                Operation::Set(key, value) => Some((key, value)),
                Operation::Commit(_, _) => None,
            }
        }

        async fn lookup(db: &Self::Db, key: &Self::Key) -> Option<Self::Value> {
            db.get(key).await.unwrap()
        }
    }

    pub(crate) type VariableMmrHarness = VariableHarness<mmr::Family>;
    pub(crate) type VariableMmbHarness = VariableHarness<mmb::Family>;

    type CodecConfig = ((), (commonware_codec::RangeCfg<usize>, ()));

    type VariableBytesDb<F> = immutable::variable::Db<
        F,
        deterministic::Context,
        sha256::Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        Sequential,
    >;
    type CompactVariableDb<F> = immutable::variable::CompactDb<
        F,
        deterministic::Context,
        sha256::Digest,
        Vec<u8>,
        Sha256,
        CodecConfig,
        Sequential,
    >;
    type FixedDb<F> = immutable::fixed::Db<
        F,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;
    type CompactFixedDb<F> = immutable::fixed::CompactDb<
        F,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        Sequential,
    >;
    type FullDb<F, V, C> = immutable::Immutable<
        F,
        deterministic::Context,
        sha256::Digest,
        V,
        C,
        Sha256,
        TwoCap,
        Sequential,
    >;
    type CompactDb<F, V, C> =
        immutable::CompactDb<F, deterministic::Context, sha256::Digest, V, Sha256, C, Sequential>;
    type BaseOperation<F, V> = immutable::Operation<F, sha256::Digest, V>;

    fn variable_bytes_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> immutable::variable::Config<TwoCap, CodecConfig, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        immutable::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-{suffix}"),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_buffer: NZUsize!(1 << 21),
        }
    }

    fn fixed_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> immutable::fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        immutable::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::fixed::Config {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(5),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_buffer: NZUsize!(1 << 21),
        }
    }

    fn compact_config<C>(
        suffix: &str,
        pooler: &impl BufferPooler,
        commit_codec_config: C,
    ) -> immutable::CompactConfig<C, Sequential> {
        immutable::CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: format!("compact-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config,
        }
    }

    /// Returns the key set at `loc`. Each key is set at most once, so each location gets its own.
    fn key_at(loc: u64) -> sha256::Digest {
        Sha256::hash(&[&loc.to_be_bytes()], &Sequential)
    }

    async fn compact_apply<F, V, C>(
        db: CompactDb<F, V, C>,
        values: &[V::Value],
        metadata: Option<V::Value>,
        floor: Location<F>,
    ) -> CompactDb<F, V, C>
    where
        F: Family,
        V: ValueEncoding,
        BaseOperation<F, V>: EncodeShared + Read<Cfg = C>,
        C: Clone + Send + Sync + 'static,
    {
        let mut batch = db.new_batch();
        for (loc, value) in (*db.size()..).zip(values) {
            batch = batch.set(key_at(loc), value.clone());
        }
        let batch = batch.merkleize(&db, metadata, floor).await.unwrap();
        db.apply_batch(batch).await.unwrap().0
    }

    async fn full_apply<F, V, C>(
        db: FullDb<F, V, C>,
        values: &[V::Value],
        metadata: Option<V::Value>,
        floor: Location<F>,
    ) -> FullDb<F, V, C>
    where
        F: Family,
        V: ValueEncoding,
        C: Mutable<Item = BaseOperation<F, V>>,
        BaseOperation<F, V>: EncodeShared,
    {
        let mut batch = db.new_batch();
        for (loc, value) in (*db.bounds().end..).zip(values) {
            batch = batch.set(key_at(loc), value.clone());
        }
        let batch = batch.merkleize(&db, metadata, floor).await.unwrap();
        db.apply_batch(batch).await.unwrap().0
    }

    async fn compact_import<F, V, C>(
        ctx: deterministic::Context,
        config: &immutable::CompactConfig<C, Sequential>,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<sha256::Digest>,
        op: BaseOperation<F, V>,
    ) -> Result<CompactDb<F, V, C>, qmdb::Error<F>>
    where
        F: Family,
        V: ValueEncoding,
        BaseOperation<F, V>: EncodeShared + Read<Cfg = C>,
        C: Clone + Send + Sync + 'static,
    {
        let journal =
            crate::journal::contiguous::variable::Journal::init(ctx, config.witness.clone())
                .await?;
        CompactDb::init_from_sync(
            config.strategy.clone(),
            journal,
            config.commit_codec_config.clone(),
            last_commit_loc,
            pinned_nodes,
            op,
        )
    }

    fn commit_with_floor<F: Family, V: ValueEncoding>(
        op: BaseOperation<F, V>,
        floor: Location<F>,
    ) -> BaseOperation<F, V> {
        let BaseOperation::Commit(metadata, _) = op else {
            panic!("compact state should carry a commit operation");
        };
        BaseOperation::Commit(metadata, floor)
    }

    pub(crate) struct CompactVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> CompactSyncTestHarness for CompactVariableHarness<F> {
        type Family = F;
        type Db = CompactVariableDb<F>;
        type Full = VariableBytesDb<F>;
        type Value = Vec<u8>;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> CompactConfigOf<Self> {
            compact_config(suffix, pooler, ((), ((0..=10000).into(), ())))
        }

        fn with_witness_items_per_section(
            mut config: CompactConfigOf<Self>,
            items_per_section: NonZeroU64,
        ) -> CompactConfigOf<Self> {
            config.witness.items_per_section = items_per_section;
            config
        }

        fn value(seed: u8) -> Self::Value {
            vec![seed; 2 + seed as usize % 3]
        }

        async fn init(
            ctx: deterministic::Context,
            config: CompactConfigOf<Self>,
            max_size: Option<Location<F>>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, max_size).await.unwrap()
        }

        async fn init_full(ctx: deterministic::Context, suffix: &str) -> Self::Full {
            let config = variable_bytes_config(suffix, &ctx);
            Self::Full::init(ctx, config, None).await.unwrap()
        }

        async fn import(
            ctx: deterministic::Context,
            config: &CompactConfigOf<Self>,
            last_commit_loc: Location<F>,
            pinned_nodes: Vec<sha256::Digest>,
            op: CompactOpOf<Self>,
        ) -> Result<Self::Db, qmdb::Error<F>> {
            compact_import(ctx, config, last_commit_loc, pinned_nodes, op).await
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn destroy_full(full: Self::Full) {
            full.destroy().await.unwrap();
        }

        async fn apply(
            db: Self::Db,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Db {
            compact_apply(db, values, metadata, floor).await
        }

        async fn apply_full(
            full: Self::Full,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Full {
            full_apply(full, values, metadata, floor).await
        }

        async fn sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn commit_full(full: Self::Full) -> Self::Full {
            full.commit().await.unwrap()
        }

        async fn prune(db: Self::Db, loc: Location<F>) -> Result<Self::Db, qmdb::Error<F>> {
            db.prune(loc).await
        }

        fn root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        fn target(db: &Self::Db) -> sync::CompactTarget<F, sha256::Digest> {
            db.target()
        }

        fn size(db: &Self::Db) -> Location<F> {
            db.size()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<F> {
            db.inactivity_floor_loc()
        }

        fn metadata(db: &Self::Db) -> Option<Self::Value> {
            db.get_metadata()
        }

        fn full_root(full: &Self::Full) -> sha256::Digest {
            full.root()
        }

        fn full_bounds(full: &Self::Full) -> std::ops::Range<Location<F>> {
            full.bounds()
        }

        fn with_commit_floor(op: CompactOpOf<Self>, floor: Location<F>) -> CompactOpOf<Self> {
            commit_with_floor(op, floor)
        }
    }

    pub(crate) struct CompactFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> CompactSyncTestHarness for CompactFixedHarness<F> {
        type Family = F;
        type Db = CompactFixedDb<F>;
        type Full = FixedDb<F>;
        type Value = sha256::Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> CompactConfigOf<Self> {
            compact_config(suffix, pooler, ())
        }

        fn with_witness_items_per_section(
            mut config: CompactConfigOf<Self>,
            items_per_section: NonZeroU64,
        ) -> CompactConfigOf<Self> {
            config.witness.items_per_section = items_per_section;
            config
        }

        fn value(seed: u8) -> Self::Value {
            sha256::Digest::from([seed; 32])
        }

        async fn init(
            ctx: deterministic::Context,
            config: CompactConfigOf<Self>,
            max_size: Option<Location<F>>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, max_size).await.unwrap()
        }

        async fn init_full(ctx: deterministic::Context, suffix: &str) -> Self::Full {
            let config = fixed_config(suffix, &ctx);
            Self::Full::init(ctx, config, None).await.unwrap()
        }

        async fn import(
            ctx: deterministic::Context,
            config: &CompactConfigOf<Self>,
            last_commit_loc: Location<F>,
            pinned_nodes: Vec<sha256::Digest>,
            op: CompactOpOf<Self>,
        ) -> Result<Self::Db, qmdb::Error<F>> {
            compact_import(ctx, config, last_commit_loc, pinned_nodes, op).await
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn destroy_full(full: Self::Full) {
            full.destroy().await.unwrap();
        }

        async fn apply(
            db: Self::Db,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Db {
            compact_apply(db, values, metadata, floor).await
        }

        async fn apply_full(
            full: Self::Full,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Full {
            full_apply(full, values, metadata, floor).await
        }

        async fn sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn commit_full(full: Self::Full) -> Self::Full {
            full.commit().await.unwrap()
        }

        async fn prune(db: Self::Db, loc: Location<F>) -> Result<Self::Db, qmdb::Error<F>> {
            db.prune(loc).await
        }

        fn root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        fn target(db: &Self::Db) -> sync::CompactTarget<F, sha256::Digest> {
            db.target()
        }

        fn size(db: &Self::Db) -> Location<F> {
            db.size()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<F> {
            db.inactivity_floor_loc()
        }

        fn metadata(db: &Self::Db) -> Option<Self::Value> {
            db.get_metadata()
        }

        fn full_root(full: &Self::Full) -> sha256::Digest {
            full.root()
        }

        fn full_bounds(full: &Self::Full) -> std::ops::Range<Location<F>> {
            full.bounds()
        }

        fn with_commit_floor(op: CompactOpOf<Self>, floor: Location<F>) -> CompactOpOf<Self> {
            commit_with_floor(op, floor)
        }
    }

    pub(crate) type CompactVariableMmrHarness = CompactVariableHarness<mmr::Family>;
    pub(crate) type CompactVariableMmbHarness = CompactVariableHarness<mmb::Family>;
    pub(crate) type CompactFixedMmrHarness = CompactFixedHarness<mmr::Family>;
    pub(crate) type CompactFixedMmbHarness = CompactFixedHarness<mmb::Family>;
}

/// Emits the immutable-specific sync tests for `$harness`.
macro_rules! immutable_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_sync_nonzero_floor() {
            super::test_sync_nonzero_floor::<$harness>();
        }
    };
}

crate::qmdb::sync::harness::sync_tests!(
    harnesses::VariableMmrHarness,
    variable_mmr,
    immutable_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::VariableMmbHarness,
    variable_mmb,
    immutable_sync_tests
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactVariableMmrHarness,
    compact_variable_mmr
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactVariableMmbHarness,
    compact_variable_mmb
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactFixedMmrHarness,
    compact_fixed_mmr
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactFixedMmbHarness,
    compact_fixed_mmb
);

/// A completed sync journal reuses local pinned nodes only when the persisted state can
/// authenticate the target: a target starting below the local pruning boundary is declined,
/// while a matching target serves the pinned nodes locally.
#[commonware_macros::test_traced]
fn test_immutable_local_pinned_nodes_rejects_target_before_local_lower_bound() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let suffix = context.next_u64().to_string();
        let config = H::config(&suffix, &context);
        let mut db = H::init_db_with_config(context.child("db"), config.clone()).await;
        for seed in 0..3u64 {
            db = H::apply_ops(db, H::create_ops_seeded(100, seed), None).await;
        }
        let db = prune_boxed::<H>(db, Location::new(100)).await;
        let db = H::db_sync(db).await;

        let bounds = H::bounds(&db);
        let local_start = bounds.start;
        let local_end = bounds.end;
        assert!(local_start > Location::new(0));
        let sync_root = H::db_root(&db);

        // Reopen the operation journal independently to probe the persisted Merkle boundary.
        drop(db);
        let journal = <JournalOf<H> as qmdb::sync::Journal<_>>::new(
            context.child("journal"),
            qmdb::sync::DatabaseConfig::journal_config(&config),
            non_empty_range!(local_start, local_end),
        )
        .await
        .unwrap();

        let stale_target = Target {
            root: sync_root,
            range: non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        };
        assert!(
            <DbOf<H> as qmdb::sync::Database>::local_pinned_nodes(
                context.child("probe_stale"),
                &config,
                &stale_target,
                &journal,
            )
            .await
            .unwrap()
            .is_none()
        );

        let matching_target = Target {
            root: sync_root,
            range: non_empty_range!(local_start, local_end),
        };
        assert!(
            <DbOf<H> as qmdb::sync::Database>::local_pinned_nodes(
                context.child("probe_matching"),
                &config,
                &matching_target,
                &journal,
            )
            .await
            .unwrap()
            .is_some()
        );
        drop(journal);
    });
}
