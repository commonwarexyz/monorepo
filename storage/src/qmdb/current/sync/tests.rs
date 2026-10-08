//! Sync tests for [`crate::qmdb::current`] databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for `current` databases, runs a subset of the `any`-specific
//! tests from [`crate::qmdb::any::sync::tests`], and adds `current`-specific tests. Sync targets
//! the ops root, while the harness's canonical root is the root returned by `Db::root()`.

use crate::qmdb::{
    current::tests::{fixed_config, variable_config},
    floor::Proportional,
    sync::{
        Database as SyncDatabase,
        harness::{ConfigOf, SyncTestHarness},
    },
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Metrics, Runner as _, Supervisor as _, deterministic, deterministic::Context,
};
use commonware_utils::{NZU64, NZUsize, non_empty_range};
use rand::Rng as _;

mod harnesses {
    use super::*;
    use crate::merkle::{self, mmb, mmr};
    use commonware_math::algebra::Random;
    use commonware_utils::TestRng;

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
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};

        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};

        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};

        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};

        let mut rng = TestRng::new(seed);
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
        db: UnorderedFixedDb<F>,
        ops: Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>>,
        metadata: Option<Digest>,
    ) -> UnorderedFixedDb<F> {
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};

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
            batch
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_unordered_variable_ops<F: merkle::Graftable>(
        db: UnorderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>>,
        metadata: Option<Digest>,
    ) -> UnorderedVariableDb<F> {
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};

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
            batch
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_ordered_fixed_ops<F: merkle::Graftable>(
        db: OrderedFixedDb<F>,
        ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
        metadata: Option<Digest>,
    ) -> OrderedFixedDb<F> {
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};

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
            batch
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_ordered_variable_ops<F: merkle::Graftable>(
        db: OrderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>>,
        metadata: Option<Digest>,
    ) -> OrderedVariableDb<F> {
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};

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
            batch
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    pub struct UnorderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedFixedHarness<F> {
        type Family = F;
        type Db = UnorderedFixedDb<F>;
        type Metadata = Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
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

        fn sample_metadata() -> Digest {
            Digest::from([1; 32])
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = fixed_config::<crate::translator::TwoCap>("default", &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>>,
            metadata: Option<Digest>,
        ) -> Self::Db {
            apply_unordered_fixed_ops(db, ops, metadata).await
        }

        crate::qmdb::any::sync::tests::db_any_harness_methods!();
    }

    pub type UnorderedFixedMmrHarness = UnorderedFixedHarness<mmr::Family>;
    pub type UnorderedFixedMmbHarness = UnorderedFixedHarness<mmb::Family>;

    pub struct UnorderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedVariableHarness<F> {
        type Family = F;
        type Db = UnorderedVariableDb<F>;
        type Metadata = Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
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

        fn sample_metadata() -> Digest {
            Digest::from([1; 32])
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = variable_config::<crate::translator::TwoCap>("default", &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>>,
            metadata: Option<Digest>,
        ) -> Self::Db {
            apply_unordered_variable_ops(db, ops, metadata).await
        }

        crate::qmdb::any::sync::tests::db_any_harness_methods!();
    }

    pub type UnorderedVariableMmrHarness = UnorderedVariableHarness<mmr::Family>;
    pub type UnorderedVariableMmbHarness = UnorderedVariableHarness<mmb::Family>;

    pub struct OrderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for OrderedFixedHarness<F> {
        type Family = F;
        type Db = OrderedFixedDb<F>;
        type Metadata = Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
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

        fn sample_metadata() -> Digest {
            Digest::from([1; 32])
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = fixed_config::<crate::translator::OneCap>("default", &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
            metadata: Option<Digest>,
        ) -> Self::Db {
            apply_ordered_fixed_ops(db, ops, metadata).await
        }

        crate::qmdb::any::sync::tests::db_any_harness_methods!();
    }

    pub type OrderedFixedMmrHarness = OrderedFixedHarness<mmr::Family>;
    pub type OrderedFixedMmbHarness = OrderedFixedHarness<mmb::Family>;

    pub struct OrderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for OrderedVariableHarness<F> {
        type Family = F;
        type Db = OrderedVariableDb<F>;
        type Metadata = Digest;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
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

        fn sample_metadata() -> Digest {
            Digest::from([1; 32])
        }

        async fn init_db(ctx: Context) -> Self::Db {
            let cfg = variable_config::<crate::translator::OneCap>("default", &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>>,
            metadata: Option<Digest>,
        ) -> Self::Db {
            apply_ordered_variable_ops(db, ops, metadata).await
        }

        crate::qmdb::any::sync::tests::db_any_harness_methods!();
    }

    pub type OrderedVariableMmrHarness = OrderedVariableHarness<mmr::Family>;
    pub type OrderedVariableMmbHarness = OrderedVariableHarness<mmb::Family>;
}

/// Regression test: sync a pruned MMB-backed current DB and verify the synced DB has the
/// same canonical root, reopens cleanly, and returns the expected value.
///
/// The target DB commits the same key 100 times, forcing the inactivity floor past a full
/// 256-bit chunk boundary. The receiver derives `pruned_chunks` from `range.start` and must
/// source the grafted pinned nodes for that region from the ops tree (zero-chunk identity).
/// If those nodes do not match the sender's, the canonical roots diverge.
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
            None,
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
                .merkleize(&target_db, None, &mut Proportional)
                .await
                .unwrap();
            (target_db, _) = target_db.apply_batch(merkleized).await.unwrap();
            target_db = target_db.commit().await.unwrap();
        }

        assert!(
            *target_db.inactivity_floor_loc() >= 256,
            "expected inactivity floor past chunk 0"
        );

        let boundary = target_db.sync_boundary();
        let target_db = target_db.prune(boundary).await.unwrap();

        let sync_root = target_db.ops_root();
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary();
        let upper_bound = target_db.bounds().end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);

        // Sync targets the ops root, which is what the engine verifies. `build_db` reconstructs
        // the canonical root without authenticating it, so the assertions below compare it
        // against `verification_root`.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.child("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(4),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        })
        .await
        .unwrap();

        assert_eq!(synced_db.ops_root(), sync_root);
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.sync_boundary(), lower_bound);
        assert_eq!(synced_db.get(&key).await.unwrap(), expected);

        drop(synced_db);

        let reopened: Db = Db::init(context.child("reopened"), client_config, None)
            .await
            .unwrap();
        assert_eq!(reopened.ops_root(), sync_root);
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
fn test_current_local_pinned_nodes_rejects_target_before_local_lower_bound() {
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
        let mut db: Db = Db::init(context.child("db"), config.clone(), None)
            .await
            .unwrap();

        let key = Digest::from([9u8; 32]);
        for round in 0..300u64 {
            let merkleized = db
                .new_batch()
                .write(key, Some(Digest::from([round as u8; 32])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            db = db.commit().await.unwrap();
        }
        let prune_loc = crate::merkle::Location::new(256);
        assert!(db.sync_boundary() >= prune_loc);
        let db = db.prune(prune_loc).await.unwrap();

        let bounds = db.bounds();
        let local_start = bounds.start;
        let local_end = bounds.end;
        let sync_root = db.ops_root();

        assert!(local_start > crate::merkle::Location::new(0));

        // Reopen the operation journal independently to probe the persisted Merkle boundary.
        drop(db);
        let journal = <<Db as SyncDatabase>::Journal as crate::qmdb::sync::Journal<
            crate::merkle::mmr::Family,
        >>::new(
            context.child("journal"),
            crate::qmdb::sync::DatabaseConfig::journal_config(&config),
            non_empty_range!(local_start, local_end),
        )
        .await
        .unwrap();

        let stale_target = crate::qmdb::sync::Target {
            root: sync_root,
            range: non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        };
        assert!(
            <Db as SyncDatabase>::local_pinned_nodes(
                context.child("probe_stale"),
                &config,
                &stale_target,
                &journal,
            )
            .await
            .unwrap()
            .is_none()
        );

        let matching_target = crate::qmdb::sync::Target {
            root: sync_root,
            range: non_empty_range!(local_start, local_end),
        };
        assert!(
            <Db as SyncDatabase>::local_pinned_nodes(
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

/// Emits the `any`-specific sync tests that also run against `current` databases for `$harness`.
macro_rules! current_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_sync_waits_for_explicit_finish() {
            crate::qmdb::any::sync::tests::test_sync_waits_for_explicit_finish::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_handles_early_finish_signal() {
            crate::qmdb::any::sync::tests::test_sync_handles_early_finish_signal::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_fails_when_finish_sender_dropped() {
            crate::qmdb::any::sync::tests::test_sync_fails_when_finish_sender_dropped::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_allows_dropped_reached_target_receiver() {
            crate::qmdb::any::sync::tests::test_sync_allows_dropped_reached_target_receiver::<
                $harness,
            >();
        }

        #[test_traced("WARN")]
        fn test_sync_post_sync_usability() {
            crate::qmdb::any::sync::tests::test_sync_post_sync_usability::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_local_pinned_nodes_below_floor() {
            crate::qmdb::any::sync::tests::test_local_pinned_nodes_below_floor::<$harness>();
        }
    };
}

crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedFixedMmrHarness,
    unordered_fixed_mmr,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedFixedMmbHarness,
    unordered_fixed_mmb,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedVariableMmrHarness,
    unordered_variable_mmr,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedVariableMmbHarness,
    unordered_variable_mmb,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedFixedMmrHarness,
    ordered_fixed_mmr,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedFixedMmbHarness,
    ordered_fixed_mmb,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedVariableMmrHarness,
    ordered_variable_mmr,
    current_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedVariableMmbHarness,
    ordered_variable_mmb,
    current_sync_tests
);
