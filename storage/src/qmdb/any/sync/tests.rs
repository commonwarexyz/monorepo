//! `any` database harnesses for the shared sync test suite.
//!
//! Shared sync test helpers live in [crate::qmdb::sync::tests]. This module keeps only
//! the `any`-specific harness implementations and test instantiations.

use crate::qmdb::sync::tests::*;

mod harnesses {
    use super::SyncTestHarness;
    use crate::{
        merkle::{self, mmb},
        qmdb::any::value::VariableEncoding,
        translator::TwoCap,
    };
    use commonware_cryptography::sha256::Digest;
    use commonware_math::algebra::Random;
    use commonware_runtime::{deterministic::Context, BufferPooler};
    use commonware_utils::test_rng_seeded;
    use rand::RngCore;

    // ===== Family-generic op creation helpers =====
    //
    // `Operation<F, K, V>` is phantom in F for Update/Delete variants, so ops
    // are structurally identical across families.

    fn create_ordered_fixed_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(Update {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    fn create_unordered_fixed_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    fn create_ordered_variable_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Vec<u8>>> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let len = ((rng.next_u64() % 13) + 7) as usize;
                let value = vec![(rng.next_u64() % 255) as u8; len];
                ops.push(Operation::Update(Update {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    fn create_unordered_variable_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Vec<u8>>> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let len = ((rng.next_u64() % 13) + 7) as usize;
                let value = vec![(rng.next_u64() % 255) as u8; len];
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    // ===== MMR harnesses (existing, unchanged) =====

    // ----- Ordered/Fixed -----

    pub struct OrderedFixedHarness;

    impl SyncTestHarness for OrderedFixedHarness {
        type Family = crate::mmr::Family;
        type Db = crate::qmdb::any::ordered::fixed::test::AnyTest;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config::<_>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<crate::mmr::Family, Digest, Digest>>
        {
            crate::qmdb::any::ordered::fixed::test::create_test_ops(n)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<crate::mmr::Family, Digest, Digest>>
        {
            crate::qmdb::any::ordered::fixed::test::create_test_ops_seeded(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            crate::qmdb::any::ordered::fixed::test::create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential>,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<
                crate::qmdb::any::ordered::fixed::Operation<crate::mmr::Family, Digest, Digest>,
            >,
        ) -> Self::Db {
            crate::qmdb::any::ordered::fixed::test::apply_ops(&mut db, ops).await;
            let merkleized = db.new_batch().merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Ordered/Variable -----

    pub struct OrderedVariableHarness;

    impl SyncTestHarness for OrderedVariableHarness {
        type Family = crate::mmr::Family;
        type Db = crate::qmdb::any::ordered::variable::test::AnyTest;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::ordered::variable::test::VarConfig {
            crate::qmdb::any::ordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
            )
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<crate::mmr::Family, Digest, Vec<u8>>>
        {
            crate::qmdb::any::ordered::variable::test::create_test_ops_seeded(n, seed)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<crate::mmr::Family, Digest, Vec<u8>>>
        {
            crate::qmdb::any::ordered::variable::test::create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            crate::qmdb::any::ordered::variable::test::create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::ordered::variable::test::VarConfig,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<
                crate::qmdb::any::ordered::variable::Operation<crate::mmr::Family, Digest, Vec<u8>>,
            >,
        ) -> Self::Db {
            crate::qmdb::any::ordered::variable::test::apply_ops(&mut db, ops).await;
            let merkleized = db
                .new_batch()
                .merkleize(&db, None::<Vec<u8>>)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Unordered/Fixed -----

    pub struct UnorderedFixedHarness;

    impl SyncTestHarness for UnorderedFixedHarness {
        type Family = crate::mmr::Family;
        type Db = crate::qmdb::any::unordered::fixed::test::AnyTest;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config::<_>(suffix, pooler)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<crate::mmr::Family, Digest, Digest>>
        {
            crate::qmdb::any::unordered::fixed::test::create_test_ops_seeded(n, seed)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<crate::mmr::Family, Digest, Digest>>
        {
            crate::qmdb::any::unordered::fixed::test::create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            crate::qmdb::any::unordered::fixed::test::create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential>,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<
                crate::qmdb::any::unordered::fixed::Operation<crate::mmr::Family, Digest, Digest>,
            >,
        ) -> Self::Db {
            crate::qmdb::any::unordered::fixed::test::apply_ops(&mut db, ops).await;
            let merkleized = db.new_batch().merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Unordered/Variable -----

    pub struct UnorderedVariableHarness;

    impl SyncTestHarness for UnorderedVariableHarness {
        type Family = crate::mmr::Family;
        type Db = crate::qmdb::any::unordered::variable::test::AnyTest;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::unordered::variable::test::VarConfig {
            crate::qmdb::any::unordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
            )
        }

        fn create_ops(
            n: usize,
        ) -> Vec<
            crate::qmdb::any::unordered::Operation<
                crate::mmr::Family,
                Digest,
                VariableEncoding<Vec<u8>>,
            >,
        > {
            crate::qmdb::any::unordered::variable::test::create_test_ops(n)
        }

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<super::OpOf<Self>> {
            crate::qmdb::any::unordered::variable::test::create_test_ops_seeded(n, seed)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            crate::qmdb::any::unordered::variable::test::create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::unordered::variable::test::VarConfig,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<
                crate::qmdb::any::unordered::Operation<
                    crate::mmr::Family,
                    Digest,
                    VariableEncoding<Vec<u8>>,
                >,
            >,
        ) -> Self::Db {
            crate::qmdb::any::unordered::variable::test::apply_ops(&mut db, ops).await;
            let merkleized = db
                .new_batch()
                .merkleize(&db, None::<Vec<u8>>)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ===== MMB harnesses =====

    // ----- Ordered/Fixed MMB -----

    pub struct OrderedFixedMmbHarness;

    impl SyncTestHarness for OrderedFixedMmbHarness {
        type Family = mmb::Family;
        type Db = crate::qmdb::any::ordered::fixed::Db<
            mmb::Family,
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config::<_>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>> {
            create_ordered_fixed_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>> {
            create_ordered_fixed_ops(n, seed)
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let cfg = crate::qmdb::any::test::fixed_db_config::<TwoCap>(&seed.to_string(), &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential>,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::Operation;
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(data) => {
                        batch = batch.write(data.key, Some(data.value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let merkleized = batch.merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let merkleized = db.new_batch().merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Ordered/Variable MMB -----

    pub struct OrderedVariableMmbHarness;

    impl SyncTestHarness for OrderedVariableMmbHarness {
        type Family = mmb::Family;
        type Db = crate::qmdb::any::ordered::variable::Db<
            mmb::Family,
            Context,
            Digest,
            Vec<u8>,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::ordered::variable::test::VarConfig {
            crate::qmdb::any::ordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
            )
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Vec<u8>>>
        {
            create_ordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Vec<u8>>>
        {
            create_ordered_variable_ops(n, seed)
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config = crate::qmdb::any::ordered::variable::test::create_test_config(seed, &ctx);
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::ordered::variable::test::VarConfig,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Vec<u8>>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::Operation;
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(data) => {
                        batch = batch.write(data.key, Some(data.value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let merkleized = batch.merkleize(&db, None::<Vec<u8>>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, None::<Vec<u8>>)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Unordered/Fixed MMB -----

    pub struct UnorderedFixedMmbHarness;

    impl SyncTestHarness for UnorderedFixedMmbHarness {
        type Family = mmb::Family;
        type Db = crate::qmdb::any::unordered::fixed::Db<
            mmb::Family,
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config::<_>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops(n, seed)
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let cfg = crate::qmdb::any::test::fixed_db_config::<TwoCap>(&seed.to_string(), &ctx);
            Self::Db::init(ctx, cfg).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential>,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            use crate::qmdb::any::operation::Operation;
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(data) => {
                        batch = batch.write(data.0, Some(data.1));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let merkleized = batch.merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let merkleized = db.new_batch().merkleize(&db, None::<Digest>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }

    // ----- Unordered/Variable MMB -----

    pub struct UnorderedVariableMmbHarness;

    impl SyncTestHarness for UnorderedVariableMmbHarness {
        type Family = mmb::Family;
        type Db = crate::qmdb::any::unordered::variable::Db<
            mmb::Family,
            Context,
            Digest,
            Vec<u8>,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::unordered::variable::test::VarConfig {
            crate::qmdb::any::unordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
            )
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Vec<u8>>>
        {
            create_unordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Vec<u8>>>
        {
            create_unordered_variable_ops(n, seed)
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config =
                crate::qmdb::any::unordered::variable::test::create_test_config(seed, &ctx);
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: Context,
            config: crate::qmdb::any::unordered::variable::test::VarConfig,
        ) -> Self::Db {
            Self::Db::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(
            mut db: Self::Db,
            ops: Vec<
                crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Vec<u8>>,
            >,
        ) -> Self::Db {
            use crate::qmdb::any::operation::Operation;
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(data) => {
                        batch = batch.write(data.0, Some(data.1));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            let merkleized = batch.merkleize(&db, None::<Vec<u8>>).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, None::<Vec<u8>>)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db
        }
    }
}

// ===== Test Generation Macro =====

/// Macro to generate all standard sync tests for a given harness.
macro_rules! sync_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[test_traced]
            fn test_sync_empty_operations_no_panic() {
                super::test_sync_empty_operations_no_panic::<$harness>();
            }

            #[test_traced]
            fn test_sync_subset_of_target_database() {
                super::test_sync_subset_of_target_database::<$harness>(1000);
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
                super::test_sync::<$harness>(
                    target_db_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
            }

            #[test_traced]
            fn test_sync_use_existing_db_partial_match() {
                super::test_sync_use_existing_db_partial_match::<$harness>(1000);
            }

            #[test_traced]
            fn test_sync_use_existing_db_exact_match() {
                super::test_sync_use_existing_db_exact_match::<$harness>(1000);
            }

            #[test_traced("WARN")]
            fn test_target_update_lower_bound_decrease() {
                super::test_target_update_lower_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_upper_bound_decrease() {
                super::test_target_update_upper_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_bounds_increase() {
                super::test_target_update_bounds_increase::<$harness>();
            }

            #[test]
            fn test_target_update_prune_only_rejected() {
                super::test_target_update_prune_only_rejected::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_on_done_client() {
                super::test_target_update_on_done_client::<$harness>();
            }

            #[test_traced]
            fn test_sync_waits_for_explicit_finish() {
                super::test_sync_waits_for_explicit_finish::<$harness>();
            }

            #[test_traced]
            fn test_sync_reports_progress_for_reached_targets_before_explicit_finish() {
                super::test_sync_reports_progress_for_reached_targets_before_explicit_finish::<
                    $harness,
                >();
            }

            #[test_traced]
            fn test_sync_handles_early_finish_signal() {
                super::test_sync_handles_early_finish_signal::<$harness>();
            }

            #[test_traced]
            fn test_sync_fails_when_finish_sender_dropped() {
                super::test_sync_fails_when_finish_sender_dropped::<$harness>();
            }

            #[test_traced]
            fn test_sync_allows_dropped_reached_target_receiver() {
                super::test_sync_allows_dropped_reached_target_receiver::<$harness>();
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
                super::test_target_update_during_sync::<$harness>(initial_ops, additional_ops);
            }

            #[test_traced]
            fn test_sync_database_persistence() {
                super::test_sync_database_persistence::<$harness>();
            }

            #[test_traced]
            fn test_sync_post_sync_usability() {
                super::test_sync_post_sync_usability::<$harness>();
            }

            #[test_traced]
            fn test_sync_resolver_fails() {
                super::test_sync_resolver_fails::<$harness>();
            }

            #[test_traced]
            fn test_sync_retries_bad_pinned_nodes() {
                super::test_sync_retries_bad_pinned_nodes::<$harness>();
            }

            #[test_traced]
            fn test_sync_waits_for_boundary_retry_after_target_update() {
                super::test_sync_waits_for_boundary_retry_after_target_update::<$harness>();
            }
        }
    };
}

/// Additional from_sync_result tests that require `FromSyncTestable`.
/// Only the MMR harnesses have `FromSyncTestable` impls.
macro_rules! from_sync_result_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;

            #[test_traced("WARN")]
            fn test_from_sync_result_empty_to_empty() {
                super::test_from_sync_result_empty_to_empty::<$harness>();
            }

            #[test_traced]
            fn test_from_sync_result_empty_to_nonempty() {
                super::test_from_sync_result_empty_to_nonempty::<$harness>();
            }

            #[test_traced]
            fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
                super::test_from_sync_result_nonempty_to_nonempty_partial_match::<$harness>();
            }

            #[test_traced]
            fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
                super::test_from_sync_result_nonempty_to_nonempty_exact_match::<$harness>();
            }
        }
    };
}

// MMR harnesses (all tests including from_sync_result)
sync_tests_for_harness!(harnesses::OrderedFixedHarness, ordered_fixed);
sync_tests_for_harness!(harnesses::OrderedVariableHarness, ordered_variable);
sync_tests_for_harness!(harnesses::UnorderedFixedHarness, unordered_fixed);
sync_tests_for_harness!(harnesses::UnorderedVariableHarness, unordered_variable);

from_sync_result_tests_for_harness!(harnesses::OrderedFixedHarness, ordered_fixed_from_sync);
from_sync_result_tests_for_harness!(
    harnesses::OrderedVariableHarness,
    ordered_variable_from_sync
);
from_sync_result_tests_for_harness!(harnesses::UnorderedFixedHarness, unordered_fixed_from_sync);
from_sync_result_tests_for_harness!(
    harnesses::UnorderedVariableHarness,
    unordered_variable_from_sync
);

// MMB harnesses (sync tests only, no from_sync_result)
sync_tests_for_harness!(harnesses::OrderedFixedMmbHarness, ordered_fixed_mmb);
sync_tests_for_harness!(harnesses::OrderedVariableMmbHarness, ordered_variable_mmb);
sync_tests_for_harness!(harnesses::UnorderedFixedMmbHarness, unordered_fixed_mmb);
sync_tests_for_harness!(
    harnesses::UnorderedVariableMmbHarness,
    unordered_variable_mmb
);
