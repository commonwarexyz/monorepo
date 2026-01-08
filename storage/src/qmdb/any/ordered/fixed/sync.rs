//! Sync implementation for [Db].

#[cfg(test)]
mod tests {
    use crate::{
        qmdb::any::{
            ordered::fixed::test::{
                apply_ops, create_test_config, create_test_db, create_test_ops, AnyTest,
            },
            sync::tests as sync_tests,
        },
        translator::TwoCap,
    };
    use crate::qmdb::any::ordered::fixed::Operation;
    use commonware_cryptography::sha256::Digest;
    use commonware_runtime::deterministic::Context;
    use rstest::rstest;
    use std::num::NonZeroU64;
    use sync_tests::SyncTestHarness;

    /// Harness for sync tests.
    struct FixedHarness;

    impl SyncTestHarness for FixedHarness {
        type Db = AnyTest;

        fn config(suffix: &str) -> super::super::Config<TwoCap> {
            create_test_config(suffix.parse().unwrap_or(0))
        }

        fn clone_config(config: &super::super::Config<TwoCap>) -> super::super::Config<TwoCap> {
            config.clone()
        }

        fn create_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
            create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: super::super::Config<TwoCap>,
        ) -> Self::Db {
            AnyTest::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(db: Self::Db, ops: Vec<Operation<Digest, Digest>>) -> Self::Db {
            let mut db = db.into_mutable();
            apply_ops(&mut db, ops).await;
            db.commit(None::<Digest>).await.unwrap().0.into_merkleized()
        }
    }

    #[test]
    fn test_sync_invalid_bounds() {
        sync_tests::test_sync_invalid_bounds::<FixedHarness>();
    }

    #[test]
    fn test_sync_subset_of_target_database() {
        sync_tests::test_sync_subset_of_target_database::<FixedHarness>(1000);
    }

    #[rstest]
    #[case::singleton_batch_size_one(1, 1)]
    #[case::singleton_batch_size_gt_db_size(1, 2)]
    #[case::batch_size_one(1000, 1)]
    #[case::floor_div_db_batch_size(1000, 3)]
    #[case::floor_div_db_batch_size_2(1000, 999)]
    #[case::div_db_batch_size(1000, 100)]
    #[case::db_size_eq_batch_size(1000, 1000)]
    #[case::batch_size_gt_db_size(1000, 1001)]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: u64) {
        sync_tests::test_sync::<FixedHarness>(
            target_db_ops,
            NonZeroU64::new(fetch_batch_size).unwrap(),
        );
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        sync_tests::test_sync_use_existing_db_partial_match::<FixedHarness>(1000);
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        sync_tests::test_sync_use_existing_db_exact_match::<FixedHarness>(1000);
    }

    #[test]
    fn test_target_update_lower_bound_decrease() {
        sync_tests::test_target_update_lower_bound_decrease::<FixedHarness>();
    }

    #[test]
    fn test_target_update_upper_bound_decrease() {
        sync_tests::test_target_update_upper_bound_decrease::<FixedHarness>();
    }

    #[test]
    fn test_target_update_bounds_increase() {
        sync_tests::test_target_update_bounds_increase::<FixedHarness>();
    }

    #[test]
    fn test_target_update_invalid_bounds() {
        sync_tests::test_target_update_invalid_bounds::<FixedHarness>();
    }

    #[test]
    fn test_target_update_on_done_client() {
        sync_tests::test_target_update_on_done_client::<FixedHarness>();
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
        sync_tests::test_target_update_during_sync::<FixedHarness>(initial_ops, additional_ops);
    }

    #[test]
    fn test_sync_database_persistence() {
        sync_tests::test_sync_database_persistence::<FixedHarness>();
    }

    #[test]
    fn test_sync_resolver_fails() {
        sync_tests::test_sync_resolver_fails::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_empty_to_empty() {
        sync_tests::test_from_sync_result_empty_to_empty::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        sync_tests::test_from_sync_result_empty_to_nonempty::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_partial_match::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_exact_match::<FixedHarness>();
    }
}
