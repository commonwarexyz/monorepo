//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::sync::tests] by
//! implementing [SyncTestHarness] for current database types. The key difference from `any`
//! harnesses is that `sync_target_root` returns the **QMDB ops root** (via
//! [qmdb::sync::Database::ops_root](crate::qmdb::sync::Database::ops_root)), not the database root
//! returned by `Db::root()`.
//!
//! Harnesses are instantiated for **both** MMR and MMB merkle families across each (ordered,
//! unordered) x (fixed, variable) database variant, so the shared suite runs twice per variant.
//!
//! In addition to the shared harness-based suite, this module contains focused tests for
//! `current`-specific sync behavior: overlay-state authentication (database-root check), pruned
//! MMB round-trip, and target-update regression coverage.

use crate::qmdb::{
    current::tests::{fixed_config, variable_config},
    sync::{
        tests::{ConfigOf, SyncTestHarness},
        Database as SyncDatabase,
    },
};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{
    deterministic, deterministic::Context, BufferPooler, Runner as _, Supervisor as _,
};
use commonware_utils::non_empty_range;
use rand::RngCore as _;

// ===== Harness Implementations =====

mod harnesses {
    use super::*;
    use crate::merkle::{self, mmb, mmr};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng_seeded;

    type OrderedFixedDb<F> = crate::qmdb::current::ordered::fixed::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::OneCap,
        32,
        Sequential,
    >;
    type OrderedVariableDb<F> = crate::qmdb::current::ordered::variable::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::OneCap,
        32,
        Sequential,
    >;
    type UnorderedFixedDb<F> = crate::qmdb::current::unordered::fixed::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
        Sequential,
    >;
    type UnorderedVariableDb<F> = crate::qmdb::current::unordered::variable::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
        Sequential,
    >;

    fn create_unordered_fixed_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};

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

    fn create_unordered_variable_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};

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

    fn create_ordered_fixed_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};

        let mut rng = test_rng_seeded(seed);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                let key = Digest::random(&mut rng);
                ops.push(Operation::Delete(key));
            } else {
                let key = Digest::random(&mut rng);
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

    fn create_ordered_variable_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};

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

    async fn apply_unordered_fixed_ops<F: merkle::Graftable>(
        mut db: UnorderedFixedDb<F>,
        ops: Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>>,
    ) -> UnorderedFixedDb<F> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};

        let merkleized = {
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(Update(key, value)) => {
                        batch = batch.write(key, Some(value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        db.apply_batch(merkleized).await.unwrap();
        db
    }

    async fn apply_unordered_variable_ops<F: merkle::Graftable>(
        mut db: UnorderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>>,
    ) -> UnorderedVariableDb<F> {
        use crate::qmdb::any::operation::{update::Unordered as Update, Operation};

        let merkleized = {
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(Update(key, value)) => {
                        batch = batch.write(key, Some(value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        db.apply_batch(merkleized).await.unwrap();
        db
    }

    async fn apply_ordered_fixed_ops<F: merkle::Graftable>(
        mut db: OrderedFixedDb<F>,
        ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
    ) -> OrderedFixedDb<F> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};

        let merkleized = {
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(Update { key, value, .. }) => {
                        batch = batch.write(key, Some(value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        db.apply_batch(merkleized).await.unwrap();
        db
    }

    async fn apply_ordered_variable_ops<F: merkle::Graftable>(
        mut db: OrderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>>,
    ) -> OrderedVariableDb<F> {
        use crate::qmdb::any::operation::{update::Ordered as Update, Operation};

        let merkleized = {
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    Operation::Update(Update { key, value, .. }) => {
                        batch = batch.write(key, Some(value));
                    }
                    Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        db.apply_batch(merkleized).await.unwrap();
        db
    }

    pub struct UnorderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedFixedHarness<F> {
        type Family = F;
        type Db = UnorderedFixedDb<F>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::ops_root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
            create_unordered_fixed_ops::<F>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
            create_unordered_fixed_ops::<F>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_fixed_ops(db, ops).await
        }
    }

    pub type UnorderedFixedMmrHarness = UnorderedFixedHarness<mmr::Family>;
    pub type UnorderedFixedMmbHarness = UnorderedFixedHarness<mmb::Family>;

    pub struct UnorderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedVariableHarness<F> {
        type Family = F;
        type Db = UnorderedVariableDb<F>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::ops_root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>> {
            create_unordered_variable_ops::<F>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>> {
            create_unordered_variable_ops::<F>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_variable_ops(db, ops).await
        }
    }

    pub type UnorderedVariableMmrHarness = UnorderedVariableHarness<mmr::Family>;
    pub type UnorderedVariableMmbHarness = UnorderedVariableHarness<mmb::Family>;

    pub struct OrderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for OrderedFixedHarness<F> {
        type Family = F;
        type Db = OrderedFixedDb<F>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::ops_root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
            create_ordered_fixed_ops::<F>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
            create_ordered_fixed_ops::<F>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_fixed_ops(db, ops).await
        }
    }

    pub type OrderedFixedMmrHarness = OrderedFixedHarness<mmr::Family>;
    pub type OrderedFixedMmbHarness = OrderedFixedHarness<mmb::Family>;

    pub struct OrderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for OrderedVariableHarness<F> {
        type Family = F;
        type Db = OrderedVariableDb<F>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::ops_root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>> {
            create_ordered_variable_ops::<F>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>> {
            create_ordered_variable_ops::<F>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_variable_ops(db, ops).await
        }
    }

    pub type OrderedVariableMmrHarness = OrderedVariableHarness<mmr::Family>;
    pub type OrderedVariableMmbHarness = OrderedVariableHarness<mmb::Family>;
}

/// Regression test: sync a pruned MMB-backed current DB and verify the synced DB has the
/// same database root, reopens cleanly, and returns the expected value.
///
/// The target DB commits the same key 100 times, forcing the inactivity floor past a full
/// 256-bit chunk boundary. Without overlay-state in the sync protocol, the receiver
/// re-derives `pruned_chunks` from `range.start / chunk_bits` and builds a grafted tree
/// whose pinned nodes don't match the sender's. The database roots diverge.
#[test_traced("INFO")]
fn test_current_mmb_sync_with_pruned_full_chunk_reopens() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context: Context| async move {
        type Db = crate::qmdb::current::unordered::variable::Db<
            crate::merkle::mmb::Family,
            Context,
            Digest,
            Digest,
            Sha256,
            crate::translator::TwoCap,
            32,
            Sequential,
        >;

        const COMMITS: u64 = 100;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.child("target");
        let mut target_db: Db = Db::init(
            target_context.child("target"),
            variable_config::<crate::translator::TwoCap>(&target_suffix, &target_context),
        )
        .await
        .unwrap();

        let key = Digest::from([7u8; 32]);
        let mut expected = None;
        for round in 0..COMMITS {
            expected = Some(Digest::from([round as u8; 32]));
            let merkleized = target_db
                .new_batch()
                .write(key, expected)
                .merkleize(&target_db, None)
                .await
                .unwrap();
            target_db.apply_batch(merkleized).await.unwrap();
            target_db.commit().await.unwrap();
        }

        assert!(
            *target_db.inactivity_floor_loc() >= 256,
            "expected inactivity floor past chunk 0"
        );

        target_db.prune(target_db.sync_boundary()).await.unwrap();

        let sync_root = SyncDatabase::ops_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary();
        let upper_bound = target_db.bounds().await.end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);
        // This uses the shared sync engine's ops-root target directly. The focused
        // `root_sync` tests below cover the current sync wrapper that authenticates ops
        // roots against trusted database roots.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.child("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target::from_roots(
                verification_root,
                sync_root,
                commonware_utils::non_empty_range!(lower_bound, upper_bound),
            ),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 4,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        })
        .await
        .unwrap();

        assert_eq!(SyncDatabase::ops_root(&synced_db), sync_root);
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.sync_boundary(), lower_bound);
        assert_eq!(synced_db.get(&key).await.unwrap(), expected);

        drop(synced_db);

        let reopened: Db = Db::init(context.child("reopened"), client_config)
            .await
            .unwrap();
        assert_eq!(SyncDatabase::ops_root(&reopened), sync_root);
        assert_eq!(reopened.root(), verification_root);
        assert_eq!(reopened.sync_boundary(), lower_bound);
        assert_eq!(reopened.get(&key).await.unwrap(), expected);

        reopened.destroy().await.unwrap();
        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

#[test_traced]
fn test_current_has_local_target_state_rejects_target_before_local_lower_bound() {
    type Db = crate::qmdb::current::unordered::variable::Db<
        crate::merkle::mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
        Sequential,
    >;

    let executor = deterministic::Runner::default();
    executor.start(|mut context: Context| async move {
        let suffix = context.next_u64().to_string();
        let config = variable_config::<crate::translator::TwoCap>(&suffix, &context);
        let mut db: Db = Db::init(context.child("db"), config.clone()).await.unwrap();

        let key = Digest::from([9u8; 32]);
        for round in 0..300u64 {
            let merkleized = db
                .new_batch()
                .write(key, Some(Digest::from([round as u8; 32])))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
        }
        let prune_loc = crate::merkle::Location::new(256);
        assert!(db.sync_boundary() >= prune_loc);
        db.prune(prune_loc).await.unwrap();

        let bounds = db.bounds().await;
        let local_start = bounds.start;
        let local_end = bounds.end;
        let sync_root = SyncDatabase::ops_root(&db);

        assert!(local_start > crate::merkle::Location::new(0));

        let root = db.root();
        let stale_target = crate::qmdb::sync::Target::from_roots(
            root,
            sync_root,
            non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        );
        assert!(
            !<Db as SyncDatabase>::has_local_target_state(
                context.child("probe_stale"),
                &config,
                &stale_target,
            )
            .await
        );

        let matching_target = crate::qmdb::sync::Target::from_roots(
            root,
            sync_root,
            non_empty_range!(local_start, local_end),
        );
        assert!(
            <Db as SyncDatabase>::has_local_target_state(
                context.child("probe_matching"),
                &config,
                &matching_target,
            )
            .await
        );

        db.destroy().await.unwrap();
    });
}

// ===== Test Generation Macro =====

/// Dispatches to the shared test functions in [crate::qmdb::sync::tests].
macro_rules! current_sync_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[test_traced]
            fn test_sync_resolver_fails() {
                crate::qmdb::sync::tests::test_sync_resolver_fails::<$harness>();
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
                crate::qmdb::sync::tests::test_sync::<$harness>(
                    target_db_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
            }

            #[test_traced]
            fn test_sync_subset_of_target_database() {
                crate::qmdb::sync::tests::test_sync_subset_of_target_database::<$harness>(1000);
            }

            #[test_traced]
            fn test_sync_use_existing_db_partial_match() {
                crate::qmdb::sync::tests::test_sync_use_existing_db_partial_match::<$harness>(1000);
            }

            #[test_traced]
            fn test_sync_use_existing_db_exact_match() {
                crate::qmdb::sync::tests::test_sync_use_existing_db_exact_match::<$harness>(1000);
            }

            #[test_traced("WARN")]
            fn test_target_update_lower_bound_decrease() {
                crate::qmdb::sync::tests::test_target_update_lower_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_upper_bound_decrease() {
                crate::qmdb::sync::tests::test_target_update_upper_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_bounds_increase() {
                crate::qmdb::sync::tests::test_target_update_bounds_increase::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_on_done_client() {
                crate::qmdb::sync::tests::test_target_update_on_done_client::<$harness>();
            }

            #[test_traced]
            fn test_sync_waits_for_explicit_finish() {
                crate::qmdb::sync::tests::test_sync_waits_for_explicit_finish::<$harness>();
            }

            #[test_traced]
            fn test_sync_handles_early_finish_signal() {
                crate::qmdb::sync::tests::test_sync_handles_early_finish_signal::<$harness>();
            }

            #[test_traced]
            fn test_sync_fails_when_finish_sender_dropped() {
                crate::qmdb::sync::tests::test_sync_fails_when_finish_sender_dropped::<$harness>();
            }

            #[test_traced]
            fn test_sync_allows_dropped_reached_target_receiver() {
                crate::qmdb::sync::tests::test_sync_allows_dropped_reached_target_receiver::<
                    $harness,
                >();
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
                crate::qmdb::sync::tests::test_target_update_during_sync::<$harness>(
                    initial_ops,
                    additional_ops,
                );
            }

            #[test_traced]
            fn test_sync_database_persistence() {
                crate::qmdb::sync::tests::test_sync_database_persistence::<$harness>();
            }

            #[test_traced]
            fn test_sync_post_sync_usability() {
                crate::qmdb::sync::tests::test_sync_post_sync_usability::<$harness>();
            }
        }
    };
}

current_sync_tests_for_harness!(harnesses::UnorderedFixedMmrHarness, unordered_fixed_mmr);
current_sync_tests_for_harness!(harnesses::UnorderedFixedMmbHarness, unordered_fixed_mmb);
current_sync_tests_for_harness!(
    harnesses::UnorderedVariableMmrHarness,
    unordered_variable_mmr
);
current_sync_tests_for_harness!(
    harnesses::UnorderedVariableMmbHarness,
    unordered_variable_mmb
);
current_sync_tests_for_harness!(harnesses::OrderedFixedMmrHarness, ordered_fixed_mmr);
current_sync_tests_for_harness!(harnesses::OrderedFixedMmbHarness, ordered_fixed_mmb);
current_sync_tests_for_harness!(harnesses::OrderedVariableMmrHarness, ordered_variable_mmr);
current_sync_tests_for_harness!(harnesses::OrderedVariableMmbHarness, ordered_variable_mmb);

mod root_sync {
    use super::*;
    use crate::{
        merkle::mmr,
        qmdb::{
            self,
            current::{
                proof::OpsRootWitness,
                sync::{self as current_sync, Target as CurrentTarget},
                tests::variable_config,
            },
        },
    };
    use commonware_runtime::{Clock, Spawner};
    use commonware_utils::NZU64;

    type Db = crate::qmdb::current::unordered::variable::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
        Sequential,
    >;

    async fn apply_round(db: &mut Db, key: Digest, round: u64) {
        let merkleized = db
            .new_batch()
            .write(key, Some(Digest::from([round as u8; 32])))
            .merkleize(db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
    }

    async fn build_target_db(context: &mut Context) -> Db {
        let suffix = context.next_u64().to_string();
        let cfg = variable_config::<crate::translator::TwoCap>(&suffix, context);
        let mut db: Db = Db::init(context.child("target"), cfg).await.unwrap();

        let key = Digest::from([7u8; 32]);
        for round in 0..10u64 {
            apply_round(&mut db, key, round).await;
        }
        db.sync().await.unwrap();
        db
    }

    async fn make_current_target(db: &Db) -> CurrentTarget<mmr::Family, Digest> {
        let hasher = qmdb::hasher::<Sha256>();
        let witness = db.ops_root_witness(&hasher).await.unwrap();
        let lower = db.sync_boundary();
        let upper = db.bounds().await.end;
        CurrentTarget {
            root: db.root(),
            ops_root: db.ops_root(),
            witness,
            range: non_empty_range!(lower, upper),
        }
    }

    #[test_traced("INFO")]
    fn test_root_sync_succeeds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let target = make_current_target(&target_db).await;
            let root = target.root;

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db = std::sync::Arc::new(target_db);
            let synced_db: Db = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await
            .unwrap();

            assert_eq!(synced_db.root(), root);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_root_sync_tracks_target_update() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let mut target_db = build_target_db(&mut context).await;
            let initial_target = make_current_target(&target_db).await;

            let key = Digest::from([7u8; 32]);
            for round in 10..20u64 {
                apply_round(&mut target_db, key, round).await;
            }
            target_db.sync().await.unwrap();
            let updated_target = make_current_target(&target_db).await;
            let expected_root = updated_target.root;

            let (update_sender, update_receiver) = commonware_utils::channel::mpsc::channel(1);
            let (finish_sender, finish_receiver) = commonware_utils::channel::mpsc::channel(1);
            update_sender.send(updated_target).await.unwrap();
            drop(update_sender);
            context.child("finish").spawn(move |context| async move {
                context.sleep(std::time::Duration::from_millis(1)).await;
                finish_sender.send(()).await.unwrap();
            });

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
            let target_db = std::sync::Arc::new(target_db);

            let synced_db: Db = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                target: initial_target,
                max_outstanding_requests: 1,
                fetch_batch_size: NZU64!(1),
                apply_batch_size: 1024,
                db_config: client_config,
                update_rx: Some(update_receiver),
                finish_rx: Some(finish_receiver),
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await
            .unwrap();

            assert_eq!(synced_db.root(), expected_root);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_root_sync_rejects_invalid_witness() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let mut target = make_current_target(&target_db).await;

            target.witness = OpsRootWitness {
                grafted_root: Digest::from([0xFFu8; 32]),
                ..target.witness
            };

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db = std::sync::Arc::new(target_db);
            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await;

            assert!(matches!(
                result,
                Err(crate::qmdb::sync::Error::Engine(
                    crate::qmdb::sync::EngineError::OpsRootWitnessInvalid
                ))
            ));

            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_root_sync_rejects_invalid_update_witness() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let mut target_db = build_target_db(&mut context).await;
            let initial_target = make_current_target(&target_db).await;

            let key = Digest::from([7u8; 32]);
            for round in 10..20u64 {
                apply_round(&mut target_db, key, round).await;
            }
            target_db.sync().await.unwrap();
            let mut updated_target = make_current_target(&target_db).await;
            updated_target.witness = OpsRootWitness {
                grafted_root: Digest::from([0xFFu8; 32]),
                ..updated_target.witness
            };

            let (update_sender, update_receiver) = commonware_utils::channel::mpsc::channel(1);
            let (_finish_sender, finish_receiver) = commonware_utils::channel::mpsc::channel(1);
            update_sender.send(updated_target).await.unwrap();
            drop(update_sender);

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
            let target_db = std::sync::Arc::new(target_db);

            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                target: initial_target,
                max_outstanding_requests: 1,
                fetch_batch_size: NZU64!(1),
                apply_batch_size: 1024,
                db_config: client_config,
                update_rx: Some(update_receiver),
                finish_rx: Some(finish_receiver),
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await;

            assert!(matches!(
                result,
                Err(crate::qmdb::sync::Error::Engine(
                    crate::qmdb::sync::EngineError::OpsRootWitnessInvalid
                ))
            ));

            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Verify that closing the caller's update channel while the engine is waiting
    /// for updates (with finish_rx) allows the engine to eventually complete.
    /// This exercises the Either::Right path in the forwarding select: the forward
    /// future exits, update_tx must be dropped so the engine sees
    /// UpdateChannelClosed, and then finish completes sync.
    #[test_traced("INFO")]
    fn test_root_sync_update_channel_close_unblocks_engine() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let target = make_current_target(&target_db).await;
            let root = target.root;

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db = std::sync::Arc::new(target_db);

            let (update_tx, update_rx) = commonware_utils::channel::mpsc::channel(1);
            let (finish_tx, finish_rx) = commonware_utils::channel::mpsc::channel(1);

            let sync_fut = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                target,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                update_rx: Some(update_rx),
                finish_rx: Some(finish_rx),
                reached_target_tx: None,
                max_retained_roots: 8,
            });

            // Drop the update sender to close the channel while the engine is
            // waiting for updates or a finish signal.
            drop(update_tx);

            // Send the finish signal so the engine can complete.
            finish_tx.send(()).await.unwrap();

            let synced_db: Db = sync_fut.await.unwrap();
            assert_eq!(synced_db.root(), root);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }
}
