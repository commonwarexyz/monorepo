//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::any::sync::tests]
//! by implementing [SyncTestHarness] for current database types. The key difference from
//! `any` harnesses is that `sync_target_root` returns the **ops root** (via
//! [qmdb::sync::Database::root](crate::qmdb::sync::Database::root)), not the canonical root
//! returned by [MerkleizedStore::root](crate::qmdb::store::MerkleizedStore::root).

use crate::qmdb::{
    any::sync::tests::{ConfigOf, SyncTestHarness},
    current::tests::{fixed_config, variable_config},
    sync::Database as SyncDatabase,
};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{deterministic::Context, BufferPooler};

// ===== Harness Implementations =====

mod harnesses {
    use super::*;

    // ----- Unordered/Fixed -----

    pub struct UnorderedFixedHarness;

    impl SyncTestHarness for UnorderedFixedHarness {
        type Db = crate::qmdb::current::unordered::fixed::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::TwoCap,
            32,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<Digest, Digest>> {
            crate::qmdb::any::unordered::fixed::test::create_test_ops(n)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<Digest, Digest>> {
            crate::qmdb::any::unordered::fixed::test::create_test_ops_seeded(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = fixed_config::<crate::translator::TwoCap>("default", &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(ctx: Context, config: ConfigOf<Self>) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::{update::Unordered as Update, Operation};
            let mut db = db.into_mutable();
            for op in ops {
                match op {
                    Operation::Update(Update(key, value)) => {
                        db.write_batch([(key, Some(value))]).await.unwrap();
                    }
                    Operation::Delete(key) => {
                        db.write_batch([(key, Option::<Digest>::None)])
                            .await
                            .unwrap();
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let (durable, _) = db.commit(None::<Digest>).await.unwrap();
            durable
        }
    }

    // ----- Unordered/Variable -----

    pub struct UnorderedVariableHarness;

    impl SyncTestHarness for UnorderedVariableHarness {
        type Db = crate::qmdb::current::unordered::variable::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::TwoCap,
            32,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<Digest, Digest>> {
            create_unordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<Digest, Digest>> {
            create_unordered_variable_ops(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = variable_config::<crate::translator::TwoCap>("default", &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(ctx: Context, config: ConfigOf<Self>) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::{update::Unordered as Update, Operation};
            let mut db = db.into_mutable();
            for op in ops {
                match op {
                    Operation::Update(Update(key, value)) => {
                        db.write_batch([(key, Some(value))]).await.unwrap();
                    }
                    Operation::Delete(key) => {
                        db.write_batch([(key, Option::<Digest>::None)])
                            .await
                            .unwrap();
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let (durable, _) = db.commit(None::<Digest>).await.unwrap();
            durable
        }
    }

    // ----- Ordered/Fixed -----

    pub struct OrderedFixedHarness;

    impl SyncTestHarness for OrderedFixedHarness {
        type Db = crate::qmdb::current::ordered::fixed::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::OneCap,
            32,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<Digest, Digest>> {
            crate::qmdb::any::ordered::fixed::test::create_test_ops(n)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<Digest, Digest>> {
            crate::qmdb::any::ordered::fixed::test::create_test_ops_seeded(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = fixed_config::<crate::translator::OneCap>("default", &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(ctx: Context, config: ConfigOf<Self>) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::{update::Ordered as Update, Operation};
            let mut db = db.into_mutable();
            for op in ops {
                match op {
                    Operation::Update(Update { key, value, .. }) => {
                        db.write_batch([(key, Some(value))]).await.unwrap();
                    }
                    Operation::Delete(key) => {
                        db.write_batch([(key, Option::<Digest>::None)])
                            .await
                            .unwrap();
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let (durable, _) = db.commit(None::<Digest>).await.unwrap();
            durable
        }
    }

    // ----- Ordered/Variable -----

    pub struct OrderedVariableHarness;

    impl SyncTestHarness for OrderedVariableHarness {
        type Db = crate::qmdb::current::ordered::variable::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::OneCap,
            32,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<Digest, Digest>> {
            create_ordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<Digest, Digest>> {
            create_ordered_variable_ops(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = variable_config::<crate::translator::OneCap>("default", &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(ctx: Context, config: ConfigOf<Self>) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::{update::Ordered as Update, Operation};
            let mut db = db.into_mutable();
            for op in ops {
                match op {
                    Operation::Update(Update { key, value, .. }) => {
                        db.write_batch([(key, Some(value))]).await.unwrap();
                    }
                    Operation::Delete(key) => {
                        db.write_batch([(key, Option::<Digest>::None)])
                            .await
                            .unwrap();
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let (durable, _) = db.commit(None::<Digest>).await.unwrap();
            durable
        }
    }
}

// ===== Helper functions for creating test operations =====

/// Create test operations for unordered variable databases with Digest values.
fn create_unordered_variable_ops(
    n: usize,
    seed: u64,
) -> Vec<crate::qmdb::any::unordered::variable::Operation<Digest, Digest>> {
    use crate::qmdb::any::operation::{update::Unordered as Update, Operation};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng_seeded;

    let mut rng = test_rng_seeded(seed);
    let mut prev_key = Digest::random(&mut rng);
    let mut ops = Vec::new();
    for i in 0..n {
        let key = Digest::random(&mut rng);
        if i % 10 == 0 && i > 0 {
            ops.push(Operation::Delete(prev_key));
        } else {
            let value = Digest::random(&mut rng);
            ops.push(Operation::Update(Update(key, value)));
            prev_key = key;
        }
    }
    ops
}

/// Create test operations for ordered variable databases with Digest values.
fn create_ordered_variable_ops(
    n: usize,
    seed: u64,
) -> Vec<crate::qmdb::any::ordered::variable::Operation<Digest, Digest>> {
    use crate::qmdb::any::operation::{update::Ordered as Update, Operation};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng_seeded;

    let mut rng = test_rng_seeded(seed);
    let mut ops = Vec::new();
    for i in 0..n {
        let key = Digest::random(&mut rng);
        if i % 10 == 0 && i > 0 {
            ops.push(Operation::Delete(key));
        } else {
            let value = Digest::random(&mut rng);
            let next_key = Digest::random(&mut rng);
            ops.push(Operation::Update(Update {
                key,
                value,
                next_key,
            }));
        }
    }
    ops
}

// ===== Test Generation Macro =====

/// Dispatches to the shared test functions in [crate::qmdb::any::sync::tests].
macro_rules! current_sync_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[test_traced]
            fn test_sync_invalid_bounds() {
                crate::qmdb::any::sync::tests::test_sync_invalid_bounds::<$harness>();
            }

            #[test_traced]
            fn test_sync_resolver_fails() {
                crate::qmdb::any::sync::tests::test_sync_resolver_fails::<$harness>();
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
                crate::qmdb::any::sync::tests::test_sync::<$harness>(
                    target_db_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
            }

            #[test_traced]
            fn test_sync_subset_of_target_database() {
                crate::qmdb::any::sync::tests::test_sync_subset_of_target_database::<$harness>(
                    1000,
                );
            }

            #[test_traced]
            fn test_sync_use_existing_db_partial_match() {
                crate::qmdb::any::sync::tests::test_sync_use_existing_db_partial_match::<$harness>(
                    1000,
                );
            }

            #[test_traced]
            fn test_sync_use_existing_db_exact_match() {
                crate::qmdb::any::sync::tests::test_sync_use_existing_db_exact_match::<$harness>(
                    1000,
                );
            }

            #[test_traced("WARN")]
            fn test_target_update_lower_bound_decrease() {
                crate::qmdb::any::sync::tests::test_target_update_lower_bound_decrease::<$harness>(
                );
            }

            #[test_traced("WARN")]
            fn test_target_update_upper_bound_decrease() {
                crate::qmdb::any::sync::tests::test_target_update_upper_bound_decrease::<$harness>(
                );
            }

            #[test_traced("WARN")]
            fn test_target_update_bounds_increase() {
                crate::qmdb::any::sync::tests::test_target_update_bounds_increase::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_invalid_bounds() {
                crate::qmdb::any::sync::tests::test_target_update_invalid_bounds::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_on_done_client() {
                crate::qmdb::any::sync::tests::test_target_update_on_done_client::<$harness>();
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
            fn test_target_update_during_sync(
                #[case] initial_ops: usize,
                #[case] additional_ops: usize,
            ) {
                crate::qmdb::any::sync::tests::test_target_update_during_sync::<$harness>(
                    initial_ops,
                    additional_ops,
                );
            }

            #[test_traced]
            fn test_sync_database_persistence() {
                crate::qmdb::any::sync::tests::test_sync_database_persistence::<$harness>();
            }

            #[test_traced]
            fn test_sync_post_sync_usability() {
                crate::qmdb::any::sync::tests::test_sync_post_sync_usability::<$harness>();
            }
        }
    };
}

current_sync_tests_for_harness!(harnesses::UnorderedFixedHarness, unordered_fixed);
current_sync_tests_for_harness!(harnesses::UnorderedVariableHarness, unordered_variable);
current_sync_tests_for_harness!(harnesses::OrderedFixedHarness, ordered_fixed);
current_sync_tests_for_harness!(harnesses::OrderedVariableHarness, ordered_variable);
