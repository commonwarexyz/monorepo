//! Sync implementation for [Db].

#[cfg(test)]
mod tests {
    use crate::qmdb::any::{
        ordered::variable::test,
        sync::tests as sync_tests,
    };
    use crate::qmdb::any::ordered::variable::Operation;
    use commonware_cryptography::sha256::Digest;
    use commonware_runtime::deterministic::Context;
    use rstest::rstest;
    use std::num::NonZeroU64;
    use sync_tests::SyncTestHarness;

    /// Harness for sync tests.
    struct VariableHarness;

    impl SyncTestHarness for VariableHarness {
        type Db = test::AnyTest;

        fn config(suffix: &str) -> test::VarConfig {
            test::create_test_config(suffix.parse().unwrap_or(0))
        }

        fn clone_config(config: &test::VarConfig) -> test::VarConfig {
            config.clone()
        }

        fn create_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
            test::create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            test::create_test_db(ctx).await
        }

        async fn init_db_with_config(ctx: Context, config: test::VarConfig) -> Self::Db {
            test::AnyTest::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(db: Self::Db, ops: Vec<Operation<Digest, Vec<u8>>>) -> Self::Db {
            let mut db = db.into_mutable();
            test::apply_ops(&mut db, ops).await;
            db.commit(None::<Vec<u8>>)
                .await
                .unwrap()
                .0
                .into_merkleized()
        }
    }

    #[test]
    fn test_sync_invalid_bounds() {
        sync_tests::test_sync_invalid_bounds::<VariableHarness>();
    }

    #[test]
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

    #[test]
    fn test_sync_subset_of_target_database() {
        sync_tests::test_sync_subset_of_target_database::<VariableHarness>(1000);
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        sync_tests::test_sync_use_existing_db_partial_match::<VariableHarness>(1000);
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        sync_tests::test_sync_use_existing_db_exact_match::<VariableHarness>(1000);
    }

    #[test]
    fn test_target_update_lower_bound_decrease() {
        sync_tests::test_target_update_lower_bound_decrease::<VariableHarness>();
    }

    #[test]
    fn test_target_update_upper_bound_decrease() {
        sync_tests::test_target_update_upper_bound_decrease::<VariableHarness>();
    }

    #[test]
    fn test_target_update_bounds_increase() {
        sync_tests::test_target_update_bounds_increase::<VariableHarness>();
    }

    #[test]
    fn test_target_update_invalid_bounds() {
        sync_tests::test_target_update_invalid_bounds::<VariableHarness>();
    }

    #[test]
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
        sync_tests::test_target_update_during_sync::<VariableHarness>(initial_ops, additional_ops);
    }

    #[test]
    fn test_sync_database_persistence() {
        sync_tests::test_sync_database_persistence::<VariableHarness>();
    }

    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        sync_tests::test_from_sync_result_empty_to_nonempty::<VariableHarness>();
    }

    #[test]
    fn test_from_sync_result_empty_to_empty() {
        sync_tests::test_from_sync_result_empty_to_empty::<VariableHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_partial_match::<VariableHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_exact_match::<VariableHarness>();
    }
}
