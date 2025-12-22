//! Sync implementation for [Db].

use super::{Db, Operation};
use crate::{
    index::unordered::Index,
    journal::{authenticated, contiguous::variable},
    mmr::{mem::Clean, Location, Position, StandardHasher},
    qmdb::{self, any::VariableValue},
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::ops::Range;

impl<E, K, V, H, T> qmdb::sync::Database for Db<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = Operation<K, V>;
    type Journal = variable::Journal<E, Operation<K, V>>;
    type Hasher = H;
    type Config = qmdb::any::VariableConfig<T, <Operation<K, V> as Read>::Cfg>;
    type Digest = H::Digest;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let journal_config = variable::Config {
            partition: config.log_partition.clone(),
            items_per_section: config.log_items_per_blob,
            compression: config.log_compression,
            codec_config: config.log_codec_config.clone(),
            buffer_pool: config.buffer_pool.clone(),
            write_buffer: config.log_write_buffer,
        };

        variable::Journal::init_sync(
            context.with_label("log"),
            journal_config,
            *range.start..*range.end,
        )
        .await
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mut hasher = StandardHasher::<H>::new();

        let mmr = crate::mmr::journaled::Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: crate::mmr::journaled::Config {
                    journal_partition: db_config.mmr_journal_partition,
                    metadata_partition: db_config.mmr_metadata_partition,
                    items_per_blob: db_config.mmr_items_per_blob,
                    write_buffer: db_config.mmr_write_buffer,
                    thread_pool: db_config.thread_pool.clone(),
                    buffer_pool: db_config.buffer_pool.clone(),
                },
                // The last node of an MMR with `range.end` leaves is at the position
                // right before where the next leaf (at location `range.end`) goes.
                range: Position::try_from(range.start).unwrap()
                    ..Position::try_from(range.end + 1).unwrap(),
                pinned_nodes,
            },
            &mut hasher,
        )
        .await?;

        let log = authenticated::Journal::<_, _, _, Clean<DigestOf<H>>>::from_components(
            mmr,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;
        // Build the snapshot from the log.
        let snapshot = Index::new(context.with_label("snapshot"), db_config.translator.clone());
        let db = Self::from_components(range.start, log, snapshot).await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let size = journal.size();

        if size <= range.start {
            // Create a new journal with the new bounds
            journal.destroy().await?;
            Self::create_journal(context, config, range).await
        } else {
            // Just prune to the lower bound
            journal.prune(*range.start).await?;
            Ok(journal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::variable as variable_journal,
        mmr::iterator::nodes_to_pin,
        qmdb::{
            any::unordered::{sync_tests::SyncTestHarness, Update},
            store::CleanStore as _,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use futures::future::join_all;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use rstest::rstest;
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroU64,
    };

    const PAGE_SIZE: usize = 99;
    const PAGE_CACHE_SIZE: usize = 3;

    type VarConfig = qmdb::any::VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    fn test_config(suffix: &str) -> VarConfig {
        qmdb::any::VariableConfig {
            mmr_journal_partition: format!("mmr_journal_{suffix}"),
            mmr_metadata_partition: format!("mmr_metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(64),
            log_partition: format!("log_{suffix}"),
            log_items_per_blob: NZU64!(11),
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Type alias for tests
    type AnyTest = Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    fn test_value(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = test_config(&format!("{seed}"));
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    fn create_test_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = test_value(i as u64);
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Vec<u8>>>) {
        for op in ops {
            match op {
                Operation::Update(Update(key, value)) => {
                    db.update(key, value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    /// Harness for sync tests.
    struct VariableHarness;

    impl SyncTestHarness for VariableHarness {
        type Db = AnyTest;

        fn config(suffix: &str) -> VarConfig {
            test_config(suffix)
        }

        fn clone_config(config: &VarConfig) -> VarConfig {
            config.clone()
        }

        fn create_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
            create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            create_test_db(ctx).await
        }

        async fn init_db_with_config(ctx: Context, config: VarConfig) -> Self::Db {
            AnyTest::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(db: &mut Self::Db, ops: Vec<Operation<Digest, Vec<u8>>>) {
            apply_ops(db, ops).await
        }
    }

    #[test]
    fn test_sync_invalid_bounds() {
        crate::qmdb::any::unordered::sync_tests::test_sync_invalid_bounds::<VariableHarness>();
    }

    #[test]
    fn test_sync_resolver_fails() {
        crate::qmdb::any::unordered::sync_tests::test_sync_resolver_fails::<VariableHarness>();
    }

    #[rstest]
    #[case::small_batch_size_one(10, 1)]
    #[case::small_batch_size_gt_db_size(10, 20)]
    #[case::batch_size_one(1000, 1)]
    #[case::floor_div_db_batch_size(1000, 3)]
    #[case::floor_div_db_batch_size_2(1000, 999)]
    #[case::div_db_batch_size(1000, 100)]
    #[case::db_size_eq_batch_size(1000, 1000)]
    #[case::batch_size_gt_db_size(1000, 1001)]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: u64) {
        crate::qmdb::any::unordered::sync_tests::test_sync::<VariableHarness>(
            target_db_ops,
            NonZeroU64::new(fetch_batch_size).unwrap(),
        );
    }

    #[test]
    fn test_sync_subset_of_target_database() {
        crate::qmdb::any::unordered::sync_tests::test_sync_subset_of_target_database::<
            VariableHarness,
        >(1000);
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        crate::qmdb::any::unordered::sync_tests::test_sync_use_existing_db_partial_match::<
            VariableHarness,
        >(1000);
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        crate::qmdb::any::unordered::sync_tests::test_sync_use_existing_db_exact_match::<
            VariableHarness,
        >(1000);
    }

    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_lower_bound_decrease::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_upper_bound_decrease::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_bounds_increase::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_invalid_bounds::<VariableHarness>(
        );
    }

    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_on_done_client::<VariableHarness>(
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(1, 100)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(2, 100)]
    #[case(20, 10)]
    #[case(100, 1)]
    #[case(100, 2)]
    #[case(100, 100)]
    #[case(100, 1000)]
    fn test_target_update_during_sync(#[case] initial_ops: usize, #[case] additional_ops: usize) {
        crate::qmdb::any::unordered::sync_tests::test_target_update_during_sync::<VariableHarness>(
            initial_ops,
            additional_ops,
        );
    }

    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        crate::qmdb::any::unordered::sync_tests::test_sync_database_persistence::<VariableHarness>(
        );
    }

    /// Test `from_sync_result` with an empty source database syncing to a non-empty target.
    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        const NUM_OPS: usize = 100;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(NUM_OPS);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit(None).await.unwrap();
            source_db
                .prune(source_db.inactivity_floor_loc())
                .await
                .unwrap();

            let lower_bound = source_db.inactivity_floor_loc();
            let upper_bound = source_db.op_count();

            // Get pinned nodes and target hash before moving source_db
            let pinned_nodes_pos = nodes_to_pin(Position::try_from(lower_bound).unwrap());
            let pinned_nodes =
                join_all(pinned_nodes_pos.map(|pos| source_db.log.mmr.get_node(pos))).await;
            let pinned_nodes = pinned_nodes
                .iter()
                .map(|node| node.as_ref().unwrap().unwrap())
                .collect::<Vec<_>>();
            let target_hash = source_db.root();

            // Create log with operations
            let log_config = variable_journal::Config {
                partition: format!("ops_log_{}", context.next_u64()),
                items_per_section: NZU64!(1024),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(64),
            };
            let mut log = variable_journal::Journal::init_sync(
                context.with_label("ops_log"),
                log_config,
                *lower_bound..*upper_bound,
            )
            .await
            .unwrap();

            // Populate log with operations from source db
            for i in *lower_bound..*upper_bound {
                let op = source_db
                    .log
                    .read(Location::new_unchecked(i))
                    .await
                    .unwrap();
                log.append(op).await.unwrap();
            }

            let db_config = test_config(&format!("{}", context.next_u64()));
            let db =
                <Db<_, Digest, Vec<u8>, Sha256, TwoCap> as qmdb::sync::Database>::from_sync_result(
                    context.clone(),
                    db_config,
                    log,
                    Some(pinned_nodes),
                    lower_bound..upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(db.op_count(), upper_bound);
            assert_eq!(db.inactivity_floor_loc(), lower_bound);
            assert_eq!(db.log.mmr.size(), source_db.log.mmr.size());
            assert_eq!(db.op_count(), source_db.op_count());

            // Verify the root digest matches the target
            assert_eq!(db.root(), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &ops {
                if let Operation::Update(Update(key, value)) = op {
                    expected_kvs.insert(*key, value.clone());
                    deleted_keys.remove(key);
                } else if let Operation::Delete(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(db.get(&key).await.unwrap().is_none(),);
            }

            db.destroy().await.unwrap();
            source_db.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = variable_journal::Config {
                partition: format!("test_fresh_start_{}", context.next_u64()),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 26;
            let mut sync_journal = variable_journal::Journal::<_, Vec<u8>>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is initialized at the lower bound
            assert_eq!(sync_journal.size(), lower_bound);
            assert_eq!(sync_journal.oldest_retained_pos(), None);

            // Verify that operations can be appended starting from the sync position
            let append_pos = sync_journal.append(vec![100u8]).await.unwrap();
            assert_eq!(append_pos, lower_bound);

            // Verify we can read the appended operation
            let read_value = sync_journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, vec![100u8]);

            sync_journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = variable_journal::Config {
                partition: format!("test_overlap_{}", context.next_u64()),
                items_per_section: NZU64!(4),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };

            // Create initial journal with 20 operations
            let mut journal =
                variable_journal::Journal::<Context, Vec<u8>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            for i in 0u64..20 {
                journal.append(vec![i as u8]).await.unwrap();
            }
            journal.sync().await.unwrap();
            let journal_size = journal.size();
            assert_eq!(journal_size, 20);
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            let lower_bound = 8;
            let upper_bound = 31;
            let mut journal = variable_journal::Journal::<_, Vec<u8>>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            // Verify the journal size matches the original (no rewind needed)
            assert_eq!(journal.size(), journal_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(journal.oldest_retained_pos(), Some(lower_bound));

            // Verify operations from lower bound to original size are still readable
            for i in lower_bound..journal_size {
                let result = journal.read(i).await;
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), vec![i as u8]);
            }

            // Verify that new operations can be appended
            let append_pos = journal.append(vec![99u8]).await.unwrap();
            assert_eq!(append_pos, journal_size);

            // Verify the appended operation is readable
            let read_value = journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, vec![99u8]);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_exceeds_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = variable_journal::Config {
                partition: format!("test_unexpected_{}", context.next_u64()),
                items_per_section: NZU64!(4),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };

            // Create initial journal with 30 operations
            let mut journal =
                variable_journal::Journal::<Context, Vec<u8>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            for i in 0u64..30 {
                journal.append(vec![i as u8]).await.unwrap();
            }
            journal.sync().await.unwrap();
            let initial_size = journal.size();
            assert_eq!(initial_size, 30);
            journal.close().await.unwrap();

            // Initialize with sync boundaries where existing data exceeds the upper bound
            let lower_bound = 8;
            for upper_bound in 9..30 {
                let result = variable_journal::Journal::<Context, Vec<u8>>::init_sync(
                    context.clone(),
                    cfg.clone(),
                    lower_bound..upper_bound,
                )
                .await;

                assert!(matches!(result, Err(qmdb::Error::UnexpectedData(_))));
            }

            // Clean up - re-open the journal and destroy it properly
            let journal = variable_journal::Journal::<Context, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();
            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync target range.
    /// This tests the "prune only" scenario where existing data fits within sync boundaries.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = variable_journal::Config {
                partition: format!("test_exact_match_{}", context.next_u64()),
                items_per_section: NZU64!(3),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };

            // Create initial journal with 20 operations (0-19)
            let mut journal =
                variable_journal::Journal::<Context, Vec<u8>>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            for i in 0u64..20 {
                journal.append(vec![i as u8]).await.unwrap();
            }
            journal.sync().await.unwrap();
            let initial_size = journal.size();
            assert_eq!(initial_size, 20);
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            // Lower bound: 6 (prune operations 0-5)
            // Upper bound: 20 (last populated location is 19, so no rewinding needed)
            let lower_bound = 6;
            let upper_bound = 20;
            let mut journal = variable_journal::Journal::<_, Vec<u8>>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            // Verify the journal size remains the same (no rewinding needed)
            assert_eq!(journal.size(), initial_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(journal.oldest_retained_pos(), Some(lower_bound));

            // Verify operations from lower bound to end of existing data are readable
            for i in lower_bound..initial_size {
                let result = journal.read(i).await;
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), vec![i as u8]);
            }

            // Verify that new operations can be appended from the existing size
            let append_pos = journal.append(vec![88u8]).await.unwrap();
            assert_eq!(append_pos, initial_size);

            // Verify the appended operation is readable
            let read_value = journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, vec![88u8]);

            journal.destroy().await.unwrap();
        });
    }

    #[should_panic]
    #[test_traced]
    fn test_init_sync_invalid_range() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = variable_journal::Config {
                partition: format!("test_invalid_range_{}", context.next_u64()),
                items_per_section: NZU64!(4),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };

            let lower_bound = 6;
            let upper_bound = 6;
            let _result = variable_journal::Journal::<Context, Vec<u8>>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await;
        });
    }

    /// Test `from_sync_result` with an empty source database (nothing persisted) syncing to
    /// an empty target database.
    #[test_traced("WARN")]
    fn test_from_sync_result_empty_to_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let log_config = variable_journal::Config {
                partition: format!("sync_empty_log_{}", context.next_u64()),
                items_per_section: NZU64!(1000),
                compression: None,
                codec_config: ((0..=10000usize).into(), ()),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                write_buffer: NZUsize!(1024),
            };
            let mut log = variable_journal::Journal::<Context, Operation<Digest, Vec<u8>>>::init(
                context.clone(),
                log_config,
            )
            .await
            .unwrap();
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await
                .unwrap();

            let db_config = test_config(&format!("sync_empty_{}", context.next_u64()));
            let mut synced_db: AnyTest = <AnyTest as qmdb::sync::Database>::from_sync_result(
                context.clone(),
                db_config,
                log,
                None,
                Location::new_unchecked(0)..Location::new_unchecked(1),
                1024,
            )
            .await
            .unwrap();

            // Verify database state
            assert_eq!(synced_db.op_count(), 1);
            assert_eq!(synced_db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(synced_db.log.mmr.size(), 1);

            // Test that we can perform operations on the synced database
            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let value1 = vec![10u8; 16];
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let value2 = vec![20u8; 16];

            synced_db.update(key1, value1.clone()).await.unwrap();
            synced_db.update(key2, value2.clone()).await.unwrap();
            synced_db.commit(None).await.unwrap();

            // Verify the operations worked
            assert_eq!(synced_db.get(&key1).await.unwrap(), Some(value1));
            assert_eq!(synced_db.get(&key2).await.unwrap(), Some(value2));
            assert!(synced_db.op_count() > 0);

            synced_db.destroy().await.unwrap();
        });
    }

    /// Test `from_sync_result` where the database has some but not all of the operations in the
    /// target database.
    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        const NUM_OPS: usize = 100;
        const NUM_ADDITIONAL_OPS: usize = 5;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate two databases.
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = test_config(&format!("sync_partial_{}", context.next_u64()));
            let mut sync_db: AnyTest = Db::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();
            let original_ops = create_test_ops(NUM_OPS);
            apply_ops(&mut target_db, original_ops.clone()).await;
            target_db.commit(None).await.unwrap();
            target_db
                .prune(target_db.inactivity_floor_loc())
                .await
                .unwrap();
            apply_ops(&mut sync_db, original_ops.clone()).await;
            sync_db.commit(None).await.unwrap();
            sync_db.prune(sync_db.inactivity_floor_loc()).await.unwrap();
            let sync_db_original_size = sync_db.op_count();

            // Get pinned nodes before closing the database
            let pinned_nodes_map = sync_db.log.mmr.get_pinned_nodes();
            let pinned_nodes = nodes_to_pin(Position::try_from(sync_db_original_size).unwrap())
                .map(|pos| *pinned_nodes_map.get(&pos).unwrap())
                .collect::<Vec<_>>();

            // Close the sync db
            sync_db.close().await.unwrap();

            // Add more operations to the target db
            let more_ops = create_test_ops(NUM_ADDITIONAL_OPS);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit(None).await.unwrap();

            // Capture target db state for comparison
            let target_db_op_count = target_db.op_count();
            let target_db_inactivity_floor_loc = target_db.inactivity_floor_loc();
            let target_db_log_size = target_db.op_count();
            let target_db_mmr_size = target_db.log.mmr.size();

            let sync_lower_bound = target_db.inactivity_floor_loc();
            let sync_upper_bound = target_db.op_count();

            let target_hash = target_db.root();

            let AnyTest { log, .. } = target_db;
            let mmr = log.mmr;
            let journal = log.journal;

            // Re-open `sync_db` using from_sync_result
            let sync_db =
                <Db<_, Digest, Vec<u8>, Sha256, TwoCap> as qmdb::sync::Database>::from_sync_result(
                    context.clone(),
                    sync_db_config,
                    journal,
                    Some(pinned_nodes),
                    sync_lower_bound..sync_upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(
                sync_db.inactivity_floor_loc(),
                target_db_inactivity_floor_loc
            );
            assert_eq!(sync_db.inactivity_floor_loc(), sync_lower_bound);
            assert_eq!(sync_db.op_count(), target_db_log_size);
            assert_eq!(sync_db.log.mmr.size(), target_db_mmr_size);

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &original_ops {
                if let Operation::Update(Update(key, value)) = op {
                    expected_kvs.insert(*key, value.clone());
                    deleted_keys.remove(key);
                } else if let Operation::Delete(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = sync_db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(sync_db.get(&key).await.unwrap().is_none());
            }

            sync_db.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    /// Test `from_sync_result` where the database has all of the operations in the target range.
    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db_config = test_config(&format!("sync_exact_{}", context.next_u64()));
            let mut db: AnyTest = Db::init(context.clone(), db_config.clone()).await.unwrap();
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let sync_lower_bound = db.inactivity_floor_loc();
            let sync_upper_bound = db.op_count();
            let target_db_op_count = db.op_count();
            let target_db_inactivity_floor_loc = db.inactivity_floor_loc();
            let target_db_log_size = db.op_count();
            let target_db_mmr_size = db.log.mmr.size();

            let pinned_nodes = join_all(
                nodes_to_pin(Position::try_from(db.inactivity_floor_loc()).unwrap())
                    .map(|pos| db.log.mmr.get_node(pos)),
            )
            .await;
            let pinned_nodes = pinned_nodes
                .iter()
                .map(|node| node.as_ref().unwrap().unwrap())
                .collect::<Vec<_>>();
            let AnyTest { log, .. } = db;
            let mmr = log.mmr;
            let journal = log.journal;

            // When we re-open the database, the MMR is closed and the log is opened.
            mmr.close().await.unwrap();

            let sync_db: AnyTest =
                <Db<_, Digest, Vec<u8>, Sha256, TwoCap> as qmdb::sync::Database>::from_sync_result(
                    context.clone(),
                    db_config,
                    journal,
                    Some(pinned_nodes),
                    sync_lower_bound..sync_upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(
                sync_db.inactivity_floor_loc(),
                target_db_inactivity_floor_loc
            );
            assert_eq!(sync_db.inactivity_floor_loc(), sync_lower_bound);
            assert_eq!(sync_db.op_count(), target_db_log_size);
            assert_eq!(sync_db.log.mmr.size(), target_db_mmr_size);

            sync_db.destroy().await.unwrap();
        });
    }
}
