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
                ConfigOf, DbOf, JournalOf, OpOf, PAGE_CACHE_SIZE, PAGE_SIZE, SyncTestHarness,
                compact_engine_config, prune_boxed,
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
    type Key: Send + Sync + 'static;
    type Value: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static;

    fn apply_ops_with_floor(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Metadata>,
        floor: Location<Self::Family>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn commit(db: Self::Db) -> impl Future<Output = Self::Db> + Send;
    fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family>;
    fn op_kv(op: &OpOf<Self>) -> Option<(&Self::Key, &Self::Value)>;
    fn lookup(db: &Self::Db, key: &Self::Key) -> impl Future<Output = Option<Self::Value>> + Send;
}

// ===== Immutable-specific tests =====

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
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
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

// ===== Harness implementations =====

pub(crate) mod harnesses {
    use super::*;
    use crate::merkle::{Family, mmb, mmr};
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

        fn db_root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        async fn get_metadata(db: &Self::Db) -> Option<Self::Metadata> {
            db.get_metadata().await.unwrap()
        }

        async fn assert_ops_applied(db: &Self::Db, ops: &[OpOf<Self>]) {
            for op in ops {
                if let Some((key, expected_value)) = Self::op_kv(op) {
                    let got = Self::lookup(db, key).await;
                    assert_eq!(got.as_ref(), Some(expected_value));
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

        fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family> {
            db.inactivity_floor_loc()
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
}

// ===== Test Generation =====

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

mod compact_variable {
    use super::*;
    use crate::{
        merkle::Family,
        qmdb::sync::source::tests::{SequenceSource, fetch_compact_state},
    };
    use commonware_parallel::Sequential;

    type CodecConfig = ((), (commonware_codec::RangeCfg<usize>, ()));
    type SourceConfig = immutable::variable::Config<TwoCap, CodecConfig, Sequential>;

    type SourceDb<F> = immutable::variable::Db<
        F,
        deterministic::Context,
        sha256::Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        Sequential,
    >;
    type ClientDb<F> = immutable::variable::CompactDb<
        F,
        deterministic::Context,
        sha256::Digest,
        Vec<u8>,
        Sha256,
        CodecConfig,
        Sequential,
    >;

    fn source_config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> SourceConfig {
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

    fn client_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> immutable::variable::CompactConfig<((), (commonware_codec::RangeCfg<usize>, ())), Sequential>
    {
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
            commit_codec_config: ((), ((0..=10000).into(), ())),
        }
    }

    pub(super) fn test_compact_full_source_missing_reports_missing_source<F: Family>() {
        deterministic::Runner::default().start(|_context| async move {
            let source: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb<F>>>> =
                Arc::new(commonware_utils::sync::AsyncRwLock::new(None));
            let target = sync::CompactTarget {
                root: sha256::Digest::from([0; 32]),
                size: Location::new(1),
            };

            assert!(matches!(
                fetch_compact_state(&source, target).await,
                Err(sync::ServeError::MissingSource)
            ));
        });
    }

    pub(super) fn test_compact_sync_roundtrip<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let metadata = vec![8, 8, 8];
            let floor = Location::new(1);
            let key_a = sha256::Digest::from([1; 32]);
            let key_b = sha256::Digest::from([2; 32]);
            let batch = source
                .new_batch()
                .set(key_a, vec![1, 2, 3])
                .set(key_b, vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix, &context);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();

            assert_eq!(client.root(), target.root);
            assert_eq!(client.get_metadata(), Some(metadata.clone()));
            assert_eq!(client.inactivity_floor_loc(), floor);
            drop(client);

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            assert_eq!(reopened.get_metadata(), Some(metadata));
            assert_eq!(reopened.inactivity_floor_loc(), floor);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_sync_recovers_after_invalid_proof<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-bad-proof-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .set(sha256::Digest::from([3; 32]), vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            // Corrupt the proof without touching `leaves`, so the response passes the
            // engine's size check and fails at verification itself.
            proof.digests.push(sha256::Digest::from([0xee; 32]));

            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![bad_state, good_state]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_sync_recovers_after_tampered_commit_floor<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-bad-floor-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .set(sha256::Digest::from([3; 32]), vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { op, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let immutable::variable::Operation::Commit(metadata, _) = op.clone() else {
                panic!("compact state should carry a commit operation");
            };
            *op = immutable::variable::Operation::Commit(metadata, Location::new(0));

            let sequence = SequenceSource::new(vec![bad_state, good_state]);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                sequence.clone(),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();

            assert_eq!(sequence.take_verdicts().await, vec![false, true]);
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_sync_recovers_after_tampered_pinned_nodes<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-bad-pinned-nodes-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let key_a = sha256::Digest::from([1; 32]);
            let key_b = sha256::Digest::from([2; 32]);
            let batch = source
                .new_batch()
                .set(key_a, vec![1, 2, 3])
                .set(key_b, vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { pinned_nodes, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let client_cfg = client_config(&suffix, &context);
            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![bad_state, good_state]),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), target.root);
            assert_eq!(synced.get_metadata(), Some(vec![7]));
            drop(synced);

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            assert_eq!(reopened.get_metadata(), Some(vec![7]));

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_sync_recovers_after_size_mismatch<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-bad-leaf-count-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .set(sha256::Digest::from([3; 32]), vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            proof.leaves -= 1;

            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![bad_state, good_state]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_full_source_serves_historical_target<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-stale-full-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch1 = source
                .new_batch()
                .set(sha256::Digest::from([1; 32]), vec![1, 2, 3])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.commit().await.unwrap();
            let stale_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let batch2 = source
                .new_batch()
                .set(sha256::Digest::from([2; 32]), vec![4, 5, 6])
                .merkleize(&source, Some(vec![2]), Location::new(2))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.commit().await.unwrap();
            let current_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                stale_target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), stale_target.root);
            assert_ne!(client.root(), current_target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    /// A compact source serves a target below its tip from the retained witness, until pruning
    /// drops that witness.
    pub(super) fn test_compact_source_serves_retained_target<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-retained-{}", context.next_u64());
            let mut source_cfg = client_config(&format!("{suffix}-source"), &context);
            // One witness per section, so pruning past the first target drops its witness.
            source_cfg.witness.items_per_section = NZU64!(1);
            let mut source = ClientDb::<F>::init(context.child("source"), source_cfg, None)
                .await
                .unwrap();

            // Apply two commits, recording the target after each.
            let mut targets = Vec::new();
            for i in 1u8..=2 {
                let floor = source.inactivity_floor_loc();
                let batch = source
                    .new_batch()
                    .set(sha256::Digest::from([i; 32]), vec![i])
                    .merkleize(&source, Some(vec![i]), floor)
                    .await
                    .unwrap();
                (source, _) = source.apply_batch(batch).await.unwrap();
                source = source.sync().await.unwrap();
                targets.push(source.target());
            }
            let source = Arc::new(source);

            // The first target is below the tip, and syncing to it succeeds.
            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("first"),
                source.clone(),
                targets[0].clone(),
                client_config(&format!("{suffix}-first"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), targets[0].root);
            assert_eq!(synced.get_metadata(), Some(vec![1]));
            synced.destroy().await.unwrap();

            // Pruning past the first target drops its witness.
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            let source = Arc::new(source.prune(targets[1].size).await.unwrap());
            let result: Result<ClientDb<F>, _> = sync::sync(compact_engine_config(
                context.child("pruned"),
                source.clone(),
                targets[0].clone(),
                client_config(&format!("{suffix}-pruned"), &context),
            ))
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Source(qmdb::Error::Journal(
                    crate::journal::Error::ItemPruned(_)
                )))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target<
        F: Family,
    >() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"), &context);
            let source =
                ClientDb::<F>::init(context.child("source_init"), source_cfg.clone(), None)
                    .await
                    .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source
                .new_batch()
                .set(sha256::Digest::from([10; 32]), vec![10, 11])
                .merkleize(&source, Some(metadata1.clone()), floor1)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.sync().await.unwrap();
            let target1 = source.target();
            drop(source);

            let source =
                ClientDb::<F>::init(context.child("source_reopen"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            assert_eq!(source.target(), target1);

            let served1: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 1),
                Arc::new(source),
                target1.clone(),
                client_config(&format!("{suffix}-serve1"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(served1.root(), target1.root);
            assert_eq!(served1.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served1.inactivity_floor_loc(), floor1);
            served1.destroy().await.unwrap();

            let source =
                ClientDb::<F>::init(context.child("source_resume"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source
                .new_batch()
                .set(sha256::Digest::from([20; 32]), vec![20, 21])
                .merkleize(&source, Some(metadata2.clone()), floor2)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.sync().await.unwrap();
            let target2 = source.target();
            assert_ne!(target2, target1);

            // Select the earlier target durably before serving it and growing a new suffix.
            drop(source);
            let source = ClientDb::<F>::init(
                context.child("cap_source"),
                source_cfg.clone(),
                Some(target1.size),
            )
            .await
            .unwrap();
            assert_eq!(source.target(), target1);

            let served2: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 2),
                Arc::new(source),
                target1.clone(),
                client_config(&format!("{suffix}-serve2"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(served2.root(), target1.root);
            assert_eq!(served2.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served2.inactivity_floor_loc(), floor1);
            served2.destroy().await.unwrap();

            let source =
                ClientDb::<F>::init(context.child("source_regrow"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            assert_eq!(source.target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source
                .new_batch()
                .set(sha256::Digest::from([30; 32]), vec![30, 31, 32])
                .merkleize(&source, Some(metadata3.clone()), floor3)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch3).await.unwrap();
            let source = source.sync().await.unwrap();
            let target3 = source.target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let served3: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 3),
                Arc::new(source),
                target3.clone(),
                client_config(&format!("{suffix}-serve3"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(served3.root(), target3.root);
            assert_eq!(served3.get_metadata(), Some(metadata3.clone()));
            assert_eq!(served3.inactivity_floor_loc(), floor3);
            served3.destroy().await.unwrap();

            let source = Arc::new(
                ClientDb::<F>::init(context.child("source_stale"), source_cfg.clone(), None)
                    .await
                    .unwrap(),
            );
            assert_eq!(source.target(), target3);
            // target2 names a divergent history. The regrown source reaches the same leaf
            // count under a different root, so it serves state the client can never verify.
            // The direct source has no further candidate, so rejection is terminal.
            let divergent_result: Result<ClientDb<F>, _> = sync::sync(compact_engine_config(
                context.child("divergent_client"),
                source.clone(),
                target2.clone(),
                client_config(&format!("{suffix}-divergent"), &context),
            ))
            .await;
            assert!(matches!(
                divergent_result,
                Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
            ));

            // A target below the retained tip is served from its retained witness.
            let stale: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("stale_client"),
                source.clone(),
                target1.clone(),
                client_config(&format!("{suffix}-stale"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(stale.root(), target1.root);
            assert_eq!(stale.get_metadata(), Some(metadata1.clone()));
            stale.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    /// Compact sync must reinitialize a partition whose witness journal was previously pruned
    /// (the journal reset must clear the nonzero pruning boundary).
    pub(super) fn test_compact_sync_reuses_pruned_partition<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-pruned-{}", context.next_u64());

            // Seed the client partition with several commits, then prune its witness journal.
            let mut client_cfg = client_config(&suffix, &context);
            client_cfg.witness.items_per_section = NZU64!(1);
            let mut seeded = ClientDb::<F>::init(context.child("seed"), client_cfg.clone(), None)
                .await
                .unwrap();
            for i in 1u8..=3 {
                let floor = seeded.inactivity_floor_loc();
                let batch = seeded
                    .new_batch()
                    .set(sha256::Digest::from([i; 32]), vec![i])
                    .merkleize(&seeded, Some(vec![i]), floor)
                    .await
                    .unwrap();
                (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                seeded = seeded.sync().await.unwrap();
            }

            // Leave a nonzero witness-journal pruning boundary for the import to replace.
            let boundary = seeded.size();
            let seeded = seeded.prune(boundary).await.unwrap();
            drop(seeded);

            // Sync different state into the same partition.
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let metadata = vec![9, 9, 9];
            let batch = source
                .new_batch()
                .set(sha256::Digest::from([9; 32]), vec![9])
                .merkleize(&source, Some(metadata.clone()), Location::new(0))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };

            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                Arc::new(source),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), target.root);
            drop(synced);

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            reopened.destroy().await.unwrap();
        });
    }

    /// Dropping a compact-sync import before its first persist leaves the previous witness
    /// journal untouched.
    pub(super) fn test_compact_sync_dropped_import_preserves_existing_state<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-immutable-dropped-{}", context.next_u64());

            // Seed the client partition with committed state A.
            let client_cfg = client_config(&suffix, &context);
            let seeded = ClientDb::<F>::init(context.child("seed"), client_cfg.clone(), None)
                .await
                .unwrap();
            let batch = seeded
                .new_batch()
                .set(sha256::Digest::from([1; 32]), vec![1])
                .merkleize(&seeded, Some(vec![1]), Location::new(0))
                .await
                .unwrap();
            let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
            let seeded = seeded.sync().await.unwrap();
            let target_a = seeded.target();
            drop(seeded);

            // Reconstruct state B into the same partition, then drop it before the first
            // persist (as a cancelled sync would).
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .set(sha256::Digest::from([9; 32]), vec![9])
                .merkleize(&source, Some(vec![9]), Location::new(0))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target_b = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            assert_ne!(target_b, target_a);
            let source = Arc::new(source);
            let response = fetch_compact_state(&source, target_b.clone())
                .await
                .unwrap();
            let sync::Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let journal = crate::journal::contiguous::variable::Journal::init(
                context.child("import"),
                client_cfg.witness.clone(),
            )
            .await
            .unwrap();
            let imported = ClientDb::<F>::init_from_sync(
                client_cfg.strategy.clone(),
                journal,
                client_cfg.commit_codec_config,
                target_b.size - 1,
                pinned_nodes,
                op,
            )
            .unwrap();
            assert_eq!(imported.target(), target_b);

            // Drop the unpersisted import. It must not replace the previous durable witness.
            drop(imported);

            // Pruning requires a persisted import; rebuild the pending import to check rejection.
            let response = fetch_compact_state(&source, target_b.clone())
                .await
                .unwrap();
            let sync::Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let journal = crate::journal::contiguous::variable::Journal::init(
                context.child("import").with_attribute("index", 2),
                client_cfg.witness.clone(),
            )
            .await
            .unwrap();
            let imported = ClientDb::<F>::init_from_sync(
                client_cfg.strategy.clone(),
                journal,
                client_cfg.commit_codec_config,
                target_b.size - 1,
                pinned_nodes,
                op,
            )
            .unwrap();
            assert!(imported.prune(target_b.size).await.is_err());

            // The dropped imports never touched the journal: state A is still there.
            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }
}

/// Emits the compact sync tests for `$family` under `$mod_name`.
macro_rules! compact_sync_tests {
    ($family:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::compact_variable;
            use commonware_macros::test_traced;

            #[test_traced("WARN")]
            fn test_compact_full_source_missing_reports_missing_source() {
                compact_variable::test_compact_full_source_missing_reports_missing_source::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_roundtrip() {
                compact_variable::test_compact_sync_roundtrip::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_invalid_proof() {
                compact_variable::test_compact_sync_recovers_after_invalid_proof::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_commit_floor() {
                compact_variable::test_compact_sync_recovers_after_tampered_commit_floor::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_pinned_nodes() {
                compact_variable::test_compact_sync_recovers_after_tampered_pinned_nodes::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_size_mismatch() {
                compact_variable::test_compact_sync_recovers_after_size_mismatch::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_full_source_serves_historical_target() {
                compact_variable::test_compact_full_source_serves_historical_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_serves_retained_target() {
                compact_variable::test_compact_source_serves_retained_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target() {
                compact_variable::test_compact_source_reopen_bounded_initialization_regrow_and_stale_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_reuses_pruned_partition() {
                compact_variable::test_compact_sync_reuses_pruned_partition::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_dropped_import_preserves_existing_state() {
                compact_variable::test_compact_sync_dropped_import_preserves_existing_state::<$family>();
            }
        }
    };
}

compact_sync_tests!(crate::merkle::mmr::Family, compact_variable_mmr);
compact_sync_tests!(crate::merkle::mmb::Family, compact_variable_mmb);
