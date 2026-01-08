//! Sync implementation for [Db].

#[cfg(test)]
mod tests {
    use crate::{
        qmdb::{
            self,
            any::{sync::tests::SyncTestHarness, unordered::Update, unordered::variable::Db},
            Durable, Merkleized, NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use crate::qmdb::any::unordered::variable::Operation;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
    };
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use rstest::rstest;
    use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
    use crate::qmdb::any::sync::tests as sync_tests;

    const PAGE_SIZE: NonZeroU16 = NZU16!(99);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

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
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Type alias for tests
    type AnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

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

    type DirtyAnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Unmerkleized, NonDurable>;

    /// Applies the given operations to the database.
    async fn apply_ops_inner(
        mut db: DirtyAnyTest,
        ops: Vec<Operation<Digest, Vec<u8>>>,
    ) -> DirtyAnyTest {
        for op in ops {
            match op {
                Operation::Update(Update(key, value)) => {
                    db.update(key, value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(metadata, _) => {
                    db = db.commit(metadata).await.unwrap().0.into_mutable();
                }
            }
        }
        db
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

        async fn apply_ops(db: Self::Db, ops: Vec<Operation<Digest, Vec<u8>>>) -> Self::Db {
            apply_ops_inner(db.into_mutable(), ops)
                .await
                .commit(None)
                .await
                .unwrap()
                .0
                .into_merkleized()
        }
    }

    #[test_traced]
    fn test_sync_invalid_bounds() {
        sync_tests::test_sync_invalid_bounds::<VariableHarness>();
    }

    #[test_traced]
    fn test_sync_resolver_fails() {
        sync_tests::test_sync_resolver_fails::<VariableHarness>();
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
        sync_tests::test_sync::<VariableHarness>(
            target_db_ops,
            NonZeroU64::new(fetch_batch_size).unwrap(),
        );
    }

    #[test_traced]
    fn test_sync_subset_of_target_database() {
        sync_tests::test_sync_subset_of_target_database::<VariableHarness>(1000);
    }

    #[test_traced]
    fn test_sync_use_existing_db_partial_match() {
        sync_tests::test_sync_use_existing_db_partial_match::<VariableHarness>(
            1000,
        );
    }

    #[test_traced]
    fn test_sync_use_existing_db_exact_match() {
        sync_tests::test_sync_use_existing_db_exact_match::<VariableHarness>(
            1000,
        );
    }

    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        sync_tests::test_target_update_lower_bound_decrease::<VariableHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        sync_tests::test_target_update_upper_bound_decrease::<VariableHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        sync_tests::test_target_update_bounds_increase::<VariableHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        sync_tests::test_target_update_invalid_bounds::<VariableHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        sync_tests::test_target_update_on_done_client::<VariableHarness>();
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(1, 100)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[case(20, 10)]
    #[case(100, 1)]
    #[case(100, 2)]
    #[case(100, 100)]
    #[case(100, 1000)]
    fn test_target_update_during_sync(#[case] initial_ops: usize, #[case] additional_ops: usize) {
        sync_tests::test_target_update_during_sync::<VariableHarness>(
            initial_ops,
            additional_ops,
        );
    }

    #[test_traced]
    fn test_sync_database_persistence() {
        sync_tests::test_sync_database_persistence::<VariableHarness>();
    }

    #[test_traced]
    fn test_from_sync_result_empty_to_nonempty() {
        sync_tests::test_from_sync_result_empty_to_nonempty::<VariableHarness>();
    }

    #[test_traced("WARN")]
    fn test_from_sync_result_empty_to_empty() {
        sync_tests::test_from_sync_result_empty_to_empty::<VariableHarness>();
    }

    #[test_traced]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_partial_match::<
            VariableHarness,
        >();
    }

    #[test_traced]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_exact_match::<
            VariableHarness,
        >();
    }
}
