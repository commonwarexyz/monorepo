//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::sync::tests] by
//! implementing [SyncTestHarness] for current database types.
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
use commonware_utils::{non_empty_range, range::NonEmptyRange};
use rand::RngCore as _;

fn dummy_current_target<F: crate::merkle::Graftable>(
    root: Digest,
    ops_root: Digest,
    range: NonEmptyRange<crate::merkle::Location<F>>,
) -> crate::qmdb::current::sync::Target<F, Digest> {
    crate::qmdb::current::sync::Target::new(
        root,
        ops_root,
        crate::qmdb::current::proof::OpsRootWitness {
            grafted_root: Digest::from([0; 32]),
            pending_chunk_digest: None.try_into().unwrap(),
            partial_chunk: None,
        },
        range,
    )
}

// ===== Harness Implementations =====

mod harnesses {
    use super::*;
    use crate::{
        merkle::{self, mmb, mmr},
        qmdb::current::{proof::OpsRootWitness, sync::Target as CurrentTarget},
    };
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

    fn target<F: merkle::Graftable>(
        root: Digest,
        ops_root: Digest,
        range: NonEmptyRange<crate::merkle::Location<F>>,
    ) -> CurrentTarget<F, Digest> {
        CurrentTarget::new(
            root,
            ops_root,
            OpsRootWitness {
                grafted_root: Digest::from([0; 32]),
                pending_chunk_digest: None.try_into().unwrap(),
                partial_chunk: None,
            },
            range,
        )
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
        type Target = CurrentTarget<F, Digest>;

        fn target(
            root: Digest,
            ops_root: Digest,
            range: NonEmptyRange<crate::merkle::Location<Self::Family>>,
        ) -> Self::Target {
            target(root, ops_root, range)
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
        type Target = CurrentTarget<F, Digest>;

        fn target(
            root: Digest,
            ops_root: Digest,
            range: NonEmptyRange<crate::merkle::Location<Self::Family>>,
        ) -> Self::Target {
            target(root, ops_root, range)
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
        type Target = CurrentTarget<F, Digest>;

        fn target(
            root: Digest,
            ops_root: Digest,
            range: NonEmptyRange<crate::merkle::Location<Self::Family>>,
        ) -> Self::Target {
            target(root, ops_root, range)
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
        type Target = CurrentTarget<F, Digest>;

        fn target(
            root: Digest,
            ops_root: Digest,
            range: NonEmptyRange<crate::merkle::Location<Self::Family>>,
        ) -> Self::Target {
            target(root, ops_root, range)
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
        // This uses the shared sync engine directly. The focused `root_sync` tests below cover the
        // current sync wrapper that authenticates target witnesses before starting the engine.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.child("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: dummy_current_target(
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
        let stale_target = dummy_current_target(
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

        let matching_target =
            dummy_current_target(root, sync_root, non_empty_range!(local_start, local_end));
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
        CurrentTarget::new(
            db.root(),
            db.ops_root(),
            witness,
            non_empty_range!(lower, upper),
        )
    }

    #[test_traced("INFO")]
    fn test_root_sync_succeeds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let root = target_db.root();

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db = std::sync::Arc::new(target_db);
            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            trusted_tx.send(root).await.unwrap();
            drop(trusted_tx);

            let synced_db: Db = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
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
            let initial_root = target_db.root();

            let key = Digest::from([7u8; 32]);
            for round in 10..20u64 {
                apply_round(&mut target_db, key, round).await;
            }
            target_db.sync().await.unwrap();
            let updated_root = target_db.root();

            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            let (finish_sender, finish_receiver) = commonware_utils::channel::mpsc::channel(1);
            trusted_tx.send(initial_root).await.unwrap();
            trusted_tx.send(updated_root).await.unwrap();
            drop(trusted_tx);
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
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 1,
                fetch_batch_size: NZU64!(1),
                apply_batch_size: 1024,
                db_config: client_config,
                finish_rx: Some(finish_receiver),
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await
            .unwrap();

            assert_eq!(synced_db.root(), updated_root);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// A resolver wrapper that delegates `get_operations` to an inner `Arc<Db>` but lets the
    /// test inject a custom `target_for_roots` response. Useful for testing the wrapper's
    /// trust gates (membership + witness checks) against malicious resolver behavior.
    #[derive(Clone)]
    struct AdversarialResolver {
        inner: std::sync::Arc<Db>,
        /// What to return from `target_for_roots`. `None` reflects a real cache miss; `Some`
        /// is what the adversary serves regardless of the trusted roots passed in.
        served: std::sync::Arc<
            commonware_utils::sync::AsyncMutex<
                Option<crate::qmdb::current::sync::Target<mmr::Family, Digest>>,
            >,
        >,
    }

    impl crate::qmdb::sync::Resolver for AdversarialResolver {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = <std::sync::Arc<Db> as crate::qmdb::sync::Resolver>::Op;
        type Error = qmdb::Error<mmr::Family>;

        async fn get_operations(
            &self,
            op_count: crate::merkle::Location<mmr::Family>,
            start_loc: crate::merkle::Location<mmr::Family>,
            max_ops: std::num::NonZeroU64,
            include_pinned_nodes: bool,
            cancel_rx: commonware_utils::channel::oneshot::Receiver<()>,
        ) -> Result<crate::qmdb::sync::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>
        {
            crate::qmdb::sync::Resolver::get_operations(
                &self.inner,
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                cancel_rx,
            )
            .await
        }
    }

    impl current_sync::CurrentResolver for AdversarialResolver {
        async fn target_for_roots(
            &self,
            _trusted_roots: &[Digest],
        ) -> Result<Option<crate::qmdb::current::sync::Target<mmr::Family, Digest>>, Self::Error>
        {
            let guard = self.served.lock().await;
            Ok(guard.clone())
        }
    }

    /// Resolver that returns `None` from `target_for_roots` for the first `lag` calls,
    /// then delegates to the inner `Arc<Db>`'s real cache. Simulates a resolver whose
    /// commit cache is behind the client's trusted-root buffer — exactly what
    /// `target_poll_interval` is meant to handle.
    #[derive(Clone)]
    struct LaggingResolver {
        inner: std::sync::Arc<Db>,
        remaining_lag: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl LaggingResolver {
        fn new(inner: std::sync::Arc<Db>, lag: usize) -> Self {
            Self {
                inner,
                remaining_lag: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(lag)),
            }
        }
    }

    impl crate::qmdb::sync::Resolver for LaggingResolver {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = <std::sync::Arc<Db> as crate::qmdb::sync::Resolver>::Op;
        type Error = qmdb::Error<mmr::Family>;

        async fn get_operations(
            &self,
            op_count: crate::merkle::Location<mmr::Family>,
            start_loc: crate::merkle::Location<mmr::Family>,
            max_ops: std::num::NonZeroU64,
            include_pinned_nodes: bool,
            cancel_rx: commonware_utils::channel::oneshot::Receiver<()>,
        ) -> Result<crate::qmdb::sync::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>
        {
            crate::qmdb::sync::Resolver::get_operations(
                &self.inner,
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                cancel_rx,
            )
            .await
        }
    }

    impl current_sync::CurrentResolver for LaggingResolver {
        async fn target_for_roots(
            &self,
            trusted_roots: &[Digest],
        ) -> Result<Option<crate::qmdb::current::sync::Target<mmr::Family, Digest>>, Self::Error>
        {
            // Decrement and probe atomically; non-zero means we're still lagging.
            let prev = self
                .remaining_lag
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |v| if v > 0 { Some(v - 1) } else { Some(0) },
                )
                .unwrap_or(0);
            if prev > 0 {
                return Ok(None);
            }
            Ok(self.inner.cached_target(trusted_roots).map(Into::into))
        }
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

            let target_db_arc = std::sync::Arc::new(target_db);
            // Trust the (tampered) target's root: the witness check should still reject the
            // returned target because the witness no longer hashes to that root.
            let trusted_root = target.root;
            let resolver = AdversarialResolver {
                inner: target_db_arc.clone(),
                served: std::sync::Arc::new(commonware_utils::sync::AsyncMutex::new(Some(target))),
            };

            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            trusted_tx.send(trusted_root).await.unwrap();
            drop(trusted_tx);

            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver,
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
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

            let target_db = std::sync::Arc::into_inner(target_db_arc).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_root_sync_rejects_untrusted_root() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let real_target = make_current_target(&target_db).await;

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db_arc = std::sync::Arc::new(target_db);

            // Adversary returns a self-consistent target (witness valid against its own root),
            // but the root is NOT in the client's trusted set. The wrapper must reject this
            // via the membership check; the engine's end-of-sync `RootMismatch` check is too
            // late to catch it (the engine would happily sync to the resolver's root).
            let resolver = AdversarialResolver {
                inner: target_db_arc.clone(),
                served: std::sync::Arc::new(commonware_utils::sync::AsyncMutex::new(Some(
                    real_target.clone(),
                ))),
            };

            // Trust a completely different root.
            let trusted_root = Digest::from([0xAAu8; 32]);
            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            trusted_tx.send(trusted_root).await.unwrap();
            drop(trusted_tx);

            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver,
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
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
            assert_ne!(real_target.root, trusted_root);

            let target_db = std::sync::Arc::into_inner(target_db_arc).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// `target_poll_interval = 0` must be rejected at sync entry rather than busy-looping.
    #[test_traced("INFO")]
    fn test_sync_rejects_zero_poll_interval() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let target_db = std::sync::Arc::new(target_db);
            let (_trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(1);
            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::ZERO,
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await;

            assert!(matches!(
                result,
                Err(crate::qmdb::sync::Error::Engine(
                    crate::qmdb::sync::EngineError::InvalidConfig(_)
                ))
            ));

            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Closing the trusted-root stream before any match yields `TrustedStreamClosed`,
    /// not the previous (misleading) `OpsRootWitnessInvalid`.
    #[test_traced("INFO")]
    fn test_sync_closed_trusted_stream_returns_dedicated_error() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let target_db = std::sync::Arc::new(target_db);
            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(1);
            drop(trusted_tx); // close immediately

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let result: Result<Db, _> = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await;

            assert!(matches!(
                result,
                Err(crate::qmdb::sync::Error::Engine(
                    crate::qmdb::sync::EngineError::TrustedStreamClosed
                ))
            ));

            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Init seeding: a freshly opened DB exposes its current root via `cached_target`
    /// without any subsequent commits. Restart liveness: closing and reopening the DB
    /// re-seeds the cache so the current root remains answerable.
    #[test_traced("INFO")]
    fn test_witness_cache_seeded_at_init() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let root = target_db.root();
            let cached = target_db.cached_target(&[root]);
            assert!(cached.is_some(), "init should seed the current target");
            let cached = cached.unwrap();
            assert_eq!(cached.root, root);
            assert_eq!(cached.ops_root, target_db.ops_root());

            target_db.destroy().await.unwrap();
        });
    }

    /// Verify that closing the trusted-root channel while the engine is waiting allows the
    /// engine to eventually complete via `finish_rx`. The wrapper's forward task exits when
    /// the channel closes, the engine sees `UpdateChannelClosed`, and `finish_rx` lets it
    /// complete.
    #[test_traced("INFO")]
    fn test_root_sync_trusted_channel_close_unblocks_engine() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let target = make_current_target(&target_db).await;
            let root = target.root;

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let target_db = std::sync::Arc::new(target_db);

            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            let (finish_tx, finish_rx) = commonware_utils::channel::mpsc::channel(1);

            // Send the initial trusted root, then close the channel. The engine then waits
            // on finish_rx; sending the finish signal lets it complete.
            trusted_tx.send(root).await.unwrap();
            drop(trusted_tx);

            let sync_fut = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver: target_db.clone(),
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                finish_rx: Some(finish_rx),
                reached_target_tx: None,
                max_retained_roots: 8,
            });

            finish_tx.send(()).await.unwrap();

            let synced_db: Db = sync_fut.await.unwrap();
            assert_eq!(synced_db.root(), root);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Verify cache grows across commits up to capacity, evicts FIFO, and serves any
    /// retained root.
    #[test_traced("INFO")]
    fn test_witness_cache_fifo_eviction() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            // Build a DB with witness_cache_size = 3.
            let suffix = context.next_u64().to_string();
            let mut cfg = variable_config::<crate::translator::TwoCap>(&suffix, &context);
            cfg.witness_cache_size = 3;
            let mut db: Db = Db::init(context.child("cache"), cfg).await.unwrap();

            let key = Digest::from([1u8; 32]);
            let mut roots = Vec::new();
            roots.push(db.root());
            // Five commits produce five new roots; only the most recent 3 should remain
            // (plus the init-seeded entry, which gets evicted by the 3rd commit).
            for round in 0..5u64 {
                apply_round(&mut db, key, round).await;
                roots.push(db.root());
            }

            // Oldest roots: evicted.
            for old_root in &roots[..roots.len() - 3] {
                assert!(
                    db.cached_target(&[*old_root]).is_none(),
                    "old root should be evicted"
                );
            }
            // Newest 3 roots: retained.
            for recent_root in &roots[roots.len() - 3..] {
                assert!(
                    db.cached_target(&[*recent_root]).is_some(),
                    "recent root should be cached"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// `witness_cache_size = 0` disables the cache entirely. All lookups return `None`.
    #[test_traced("INFO")]
    fn test_witness_cache_disabled() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let suffix = context.next_u64().to_string();
            let mut cfg = variable_config::<crate::translator::TwoCap>(&suffix, &context);
            cfg.witness_cache_size = 0;
            let mut db: Db = Db::init(context.child("cache"), cfg).await.unwrap();

            let initial_root = db.root();
            assert!(db.cached_target(&[initial_root]).is_none());

            let key = Digest::from([1u8; 32]);
            apply_round(&mut db, key, 0).await;
            assert!(db.cached_target(&[db.root()]).is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Pruning the DB evicts cache entries whose `range.start` is below the new boundary.
    /// Newer entries (range.start >= boundary) stay.
    #[test_traced("INFO")]
    fn test_witness_cache_evicted_by_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            // Larger cache so early roots aren't evicted by FIFO before we prune.
            let suffix = context.next_u64().to_string();
            let mut cfg = variable_config::<crate::translator::TwoCap>(&suffix, &context);
            cfg.witness_cache_size = 1024;
            let mut target_db: Db = Db::init(context.child("target"), cfg).await.unwrap();

            // The init-seed entry has range.start = 0 (empty DB).
            let init_root = target_db.root();
            assert!(target_db.cached_target(&[init_root]).is_some());

            // Apply enough operations so multiple bitmap chunks complete and the
            // `sync_boundary` advances past zero. CHUNK_SIZE_BITS is `N * 8 = 256`, so
            // ~400 commits is comfortably more than one full chunk. Keys cycle through
            // 256 distinct u8 patterns (rounds 256..399 overwrite earlier keys) — fine
            // for the test, which only cares about the operation count.
            for round in 0..400u64 {
                let key = Digest::from([(round & 0xFF) as u8; 32]);
                apply_round(&mut target_db, key, round).await;
            }
            target_db.sync().await.unwrap();

            let prune_loc = target_db.sync_boundary();
            assert!(*prune_loc > 0, "test relies on a non-zero prune boundary");
            // init_root's entry has range.start = 0, which is below prune_loc.
            assert!(target_db.cached_target(&[init_root]).is_some());

            target_db.prune(prune_loc).await.unwrap();

            // The init-seed entry (range.start = 0 < prune_loc) is evicted.
            assert!(
                target_db.cached_target(&[init_root]).is_none(),
                "entry with range.start below prune boundary should be evicted"
            );
            // The current target entry (range.start = sync_boundary = prune_loc) survives.
            let current_root = target_db.root();
            let post = target_db.cached_target(&[current_root]).unwrap();
            assert!(
                post.range.start() >= prune_loc,
                "surviving entries must have range.start >= prune boundary"
            );

            target_db.destroy().await.unwrap();
        });
    }

    /// Rewinding the DB drops every previously cached target (fork happened), and the
    /// post-rewind seed re-seeds with the rewound state's target.
    #[test_traced("INFO")]
    fn test_witness_cache_cleared_by_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let mut target_db = build_target_db(&mut context).await;
            let pre_rewind_size = target_db.bounds().await.end;
            let pre_rewind_root = target_db.root();

            // Advance further, then rewind back to the pre-rewind size. The post-rewind
            // root will match `pre_rewind_root` (deterministic), but cache entries from
            // the discarded-after-rewind branch should be gone.
            let key = Digest::from([3u8; 32]);
            for round in 200..210u64 {
                apply_round(&mut target_db, key, round).await;
            }
            target_db.sync().await.unwrap();
            let advanced_root = target_db.root();
            assert_ne!(advanced_root, pre_rewind_root);
            assert!(target_db.cached_target(&[advanced_root]).is_some());

            target_db.rewind(pre_rewind_size).await.unwrap();

            // After rewind: the advanced-branch entry is gone, only the (re-seeded)
            // current target remains.
            assert!(target_db.cached_target(&[advanced_root]).is_none());
            assert!(target_db.cached_target(&[target_db.root()]).is_some());

            target_db.destroy().await.unwrap();
        });
    }

    /// `cached_target` honors the order of the caller's slice — first matching root wins.
    #[test_traced("INFO")]
    fn test_witness_cache_lookup_multiple_roots() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let real_root = target_db.root();
            let unknown_root = Digest::from([0xCDu8; 32]);

            // Real root present in [unknown, unknown, real]: returns the real one.
            let hit = target_db.cached_target(&[unknown_root, unknown_root, real_root]);
            assert!(hit.is_some());
            assert_eq!(hit.unwrap().root, real_root);

            // All roots unknown: None.
            assert!(target_db
                .cached_target(&[unknown_root, Digest::from([0xEFu8; 32])])
                .is_none());

            // Empty slice: None.
            assert!(target_db.cached_target(&[]).is_none());

            target_db.destroy().await.unwrap();
        });
    }

    /// The resolver returns `None` for the first few `target_for_roots` calls (its commit
    /// cache lags the client's trusted-root buffer), then catches up. The wrapper must keep
    /// polling on the `target_poll_interval` cadence and succeed once the resolver returns
    /// a matching target. This is the primary liveness guarantee of `target_poll_interval`.
    #[test_traced("INFO")]
    fn test_sync_polls_resolver_until_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let root = target_db.root();
            let target_db = std::sync::Arc::new(target_db);

            // Resolver returns None for the first 3 queries, then serves the real target.
            let resolver = LaggingResolver::new(target_db.clone(), 3);

            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            trusted_tx.send(root).await.unwrap();
            // Keep the channel open: progress must come from polling, not from new roots.

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let synced_db: Db = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver,
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await
            .unwrap();

            assert_eq!(synced_db.root(), root);
            drop(trusted_tx);

            synced_db.destroy().await.unwrap();
            let target_db = std::sync::Arc::into_inner(target_db).unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Closing the trusted-root channel while the buffer already holds roots must NOT
    /// abort sync. The wrapper switches to poll-only mode and keeps querying the resolver
    /// until a buffered root produces a match.
    #[test_traced("INFO")]
    fn test_sync_continues_polling_after_stream_close_with_buffered_roots() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context: Context| async move {
            let target_db = build_target_db(&mut context).await;
            let root = target_db.root();
            let target_db = std::sync::Arc::new(target_db);

            // Resolver lags by 5 calls. The trusted-root channel is closed immediately
            // after the first send — so all subsequent polling must happen against an
            // already-closed channel.
            let resolver = LaggingResolver::new(target_db.clone(), 5);

            let (trusted_tx, trusted_rx) = commonware_utils::channel::mpsc::channel(4);
            trusted_tx.send(root).await.unwrap();
            drop(trusted_tx);

            let client_suffix = context.next_u64().to_string();
            let client_config =
                variable_config::<crate::translator::TwoCap>(&client_suffix, &context);

            let synced_db: Db = current_sync::sync(current_sync::Config {
                context: context.child("client"),
                resolver,
                trusted_root_rx: trusted_rx,
                trusted_root_buffer: std::num::NonZeroUsize::new(8).unwrap(),
                target_poll_interval: std::time::Duration::from_millis(1),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(64),
                apply_batch_size: 1024,
                db_config: client_config,
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
}
