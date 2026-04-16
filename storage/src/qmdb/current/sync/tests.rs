//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::any::sync::tests]
//! by implementing [SyncTestHarness] for current database types. The key difference from
//! `any` harnesses is that `sync_target_root` returns the **ops root** (via
//! [qmdb::sync::Database::root](crate::qmdb::sync::Database::root)), not the canonical root
//! returned by `Db::root()`.
//!
//! Harnesses are instantiated for **both** MMR and MMB merkle families across each (ordered,
//! unordered) x (fixed, variable) database variant, so the shared suite runs twice per
//! variant.
//!
//! In addition to the shared harness-based suite, this module contains focused tests for
//! `current`-specific sync behavior: overlay-state authentication (canonical-root check),
//! pruned MMB round-trip, and target-update regression coverage.

use crate::qmdb::{
    any::sync::tests::{ConfigOf, SyncTestHarness},
    current::tests::{fixed_config, variable_config},
    sync::Database as SyncDatabase,
};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_macros::test_traced;
use commonware_runtime::{
    deterministic, deterministic::Context, BufferPooler, Metrics as _, Runner as _,
};
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
    >;
    type OrderedVariableDb<F> = crate::qmdb::current::ordered::variable::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::OneCap,
        32,
    >;
    type UnorderedFixedDb<F> = crate::qmdb::current::unordered::fixed::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
    >;
    type UnorderedVariableDb<F> = crate::qmdb::current::unordered::variable::Db<
        F,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
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

    pub struct UnorderedFixedMmrHarness;

    impl SyncTestHarness for UnorderedFixedMmrHarness {
        type Family = mmr::Family;
        type Db = UnorderedFixedDb<mmr::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmr::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops::<mmr::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmr::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops::<mmr::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<mmr::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_fixed_ops(db, ops).await
        }
    }

    pub struct UnorderedFixedMmbHarness;

    impl SyncTestHarness for UnorderedFixedMmbHarness {
        type Family = mmb::Family;
        type Db = UnorderedFixedDb<mmb::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops::<mmb::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_fixed_ops::<mmb::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_fixed_ops(db, ops).await
        }
    }

    pub struct UnorderedVariableMmrHarness;

    impl SyncTestHarness for UnorderedVariableMmrHarness {
        type Family = mmr::Family;
        type Db = UnorderedVariableDb<mmr::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmr::Family, Digest, Digest>>
        {
            create_unordered_variable_ops::<mmr::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmr::Family, Digest, Digest>>
        {
            create_unordered_variable_ops::<mmr::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<mmr::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_variable_ops(db, ops).await
        }
    }

    pub struct UnorderedVariableMmbHarness;

    impl SyncTestHarness for UnorderedVariableMmbHarness {
        type Family = mmb::Family;
        type Db = UnorderedVariableDb<mmb::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::TwoCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_variable_ops::<mmb::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Digest>>
        {
            create_unordered_variable_ops::<mmb::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_unordered_variable_ops(db, ops).await
        }
    }

    pub struct OrderedFixedMmrHarness;

    impl SyncTestHarness for OrderedFixedMmrHarness {
        type Family = mmr::Family;
        type Db = OrderedFixedDb<mmr::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmr::Family, Digest, Digest>> {
            create_ordered_fixed_ops::<mmr::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmr::Family, Digest, Digest>> {
            create_ordered_fixed_ops::<mmr::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<mmr::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_fixed_ops(db, ops).await
        }
    }

    pub struct OrderedFixedMmbHarness;

    impl SyncTestHarness for OrderedFixedMmbHarness {
        type Family = mmb::Family;
        type Db = OrderedFixedDb<mmb::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            fixed_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>> {
            create_ordered_fixed_ops::<mmb::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>> {
            create_ordered_fixed_ops::<mmb::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_fixed_ops(db, ops).await
        }
    }

    pub struct OrderedVariableMmrHarness;

    impl SyncTestHarness for OrderedVariableMmrHarness {
        type Family = mmr::Family;
        type Db = OrderedVariableDb<mmr::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmr::Family, Digest, Digest>>
        {
            create_ordered_variable_ops::<mmr::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmr::Family, Digest, Digest>>
        {
            create_ordered_variable_ops::<mmr::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<mmr::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_variable_ops(db, ops).await
        }
    }

    pub struct OrderedVariableMmbHarness;

    impl SyncTestHarness for OrderedVariableMmbHarness {
        type Family = mmb::Family;
        type Db = OrderedVariableDb<mmb::Family>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
        }

        fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self> {
            variable_config::<crate::translator::OneCap>(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Digest>>
        {
            create_ordered_variable_ops::<mmb::Family>(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Digest>>
        {
            create_ordered_variable_ops::<mmb::Family>(n, seed)
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
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<mmb::Family, Digest, Digest>>,
        ) -> Self::Db {
            apply_ordered_variable_ops(db, ops).await
        }
    }
}

/// Regression test: sync a pruned MMB-backed current DB and verify the synced DB has the
/// same canonical root, reopens cleanly, and returns the expected value.
///
/// The target DB commits the same key 100 times, forcing the inactivity floor past a full
/// 256-bit chunk boundary. Without overlay-state in the sync protocol, the receiver
/// re-derives `pruned_chunks` from `range.start / chunk_bits` and builds a grafted tree
/// whose pinned nodes don't match the sender's. The canonical roots diverge.
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
        >;

        const COMMITS: u64 = 100;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.with_label("target");
        let mut target_db: Db = Db::init(
            target_context.clone(),
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

        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.bounds().await.end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);
        // Supply the trusted canonical root so `build_db`'s authentication check actually
        // runs: this is the success-path coverage for the overlay-state authentication
        // anchor. A bad-root rejection path test belongs with the focused sync tests.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
                canonical_root: Some(verification_root),
            },
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

        assert_eq!(SyncDatabase::root(&synced_db), sync_root);
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);
        assert_eq!(synced_db.get(&key).await.unwrap(), expected);

        drop(synced_db);

        let reopened: Db = Db::init(context.with_label("reopened"), client_config)
            .await
            .unwrap();
        assert_eq!(SyncDatabase::root(&reopened), sync_root);
        assert_eq!(reopened.root(), verification_root);
        assert_eq!(reopened.inactivity_floor_loc(), lower_bound);
        assert_eq!(reopened.get(&key).await.unwrap(), expected);

        reopened.destroy().await.unwrap();
        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Verify that a wrong `canonical_root` in the sync target is rejected.
///
/// Uses the same pruned-MMB setup as `test_current_mmb_sync_with_pruned_full_chunk_reopens`
/// but supplies a fabricated canonical root. The sync engine successfully downloads and
/// applies all operations (the ops root is correct), but `build_db` rejects the result
/// because the rebuilt canonical root does not match the bogus target.
#[test_traced("INFO")]
fn test_canonical_root_mismatch_rejects_sync() {
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
        >;

        const COMMITS: u64 = 100;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.with_label("target");
        let mut target_db: Db = Db::init(
            target_context.clone(),
            variable_config::<crate::translator::TwoCap>(&target_suffix, &target_context),
        )
        .await
        .unwrap();

        let key = Digest::from([7u8; 32]);
        for round in 0..COMMITS {
            let value = Some(Digest::from([round as u8; 32]));
            let merkleized = target_db
                .new_batch()
                .write(key, value)
                .merkleize(&target_db, None)
                .await
                .unwrap();
            target_db.apply_batch(merkleized).await.unwrap();
            target_db.commit().await.unwrap();
        }

        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.bounds().await.end;

        // Fabricate a wrong canonical root.
        let wrong_canonical_root = Digest::from([0xFFu8; 32]);

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);
        let result = crate::qmdb::sync::sync::<Db, _>(crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config,
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
                canonical_root: Some(wrong_canonical_root),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 4,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        })
        .await;

        // The sync should fail because the canonical root doesn't match.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("sync should fail with wrong canonical_root"),
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("rebuilt canonical root does not match"),
            "unexpected error: {err_msg}",
        );

        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Verify that canonical-root authentication works for an unpruned database.
///
/// An unpruned `current` DB still has a canonical root (it just equals `combine_roots(ops,
/// empty_grafted, None)`). Passing the correct canonical root must succeed, confirming the
/// check works even when there is no overlay state to validate.
#[test_traced("INFO")]
fn test_canonical_root_correct_unpruned_sync() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context: Context| async move {
        type Db = crate::qmdb::current::unordered::variable::Db<
            crate::merkle::mmr::Family,
            Context,
            Digest,
            Digest,
            Sha256,
            crate::translator::TwoCap,
            32,
        >;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.with_label("target");
        let mut target_db: Db = Db::init(
            target_context.clone(),
            variable_config::<crate::translator::TwoCap>(&target_suffix, &target_context),
        )
        .await
        .unwrap();

        // Populate with distinct keys (no pruning).
        for i in 0u8..20 {
            let key = Digest::from([i; 32]);
            let value = Digest::from([i.wrapping_add(100); 32]);
            let merkleized = target_db
                .new_batch()
                .write(key, Some(value))
                .merkleize(&target_db, None)
                .await
                .unwrap();
            target_db.apply_batch(merkleized).await.unwrap();
            target_db.commit().await.unwrap();
        }

        let sync_root = SyncDatabase::root(&target_db);
        let canonical_root = target_db.root();
        let upper_bound = target_db.bounds().await.end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config,
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(
                    crate::merkle::Location::new(0),
                    upper_bound
                ),
                canonical_root: Some(canonical_root),
            },
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

        assert_eq!(SyncDatabase::root(&synced_db), sync_root);
        assert_eq!(synced_db.root(), canonical_root);

        drop(synced_db);
        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Verify that an authenticated retry forces fresh boundary state instead of reusing
/// stale persisted metadata.
///
/// Scenario:
/// 1. First sync attempt with a wrong `canonical_root` downloads all operations and
///    syncs the journal to disk, but fails the canonical-root check in `build_db`
///    before `sync_metadata` runs. The journal is at target; metadata is stale (empty).
/// 2. Second sync attempt with the correct `canonical_root` reuses the same journal
///    partition. Without the `needs_fresh_boundary_state` guard the engine would see
///    `is_at_target() == true`, complete immediately with `overlay_state == None`, fall
///    back to stale metadata, and fail the canonical-root check again — a permanent
///    stuck state.
/// 3. With the guard, the engine defers completion, fetches a fresh boundary batch
///    through the normal pipeline, obtains correct overlay state, and completes
///    successfully.
#[test_traced("INFO")]
fn test_authenticated_retry_forces_fresh_boundary_state() {
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
        >;

        const COMMITS: u64 = 100;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.with_label("target");
        let mut target_db: Db = Db::init(
            target_context.clone(),
            variable_config::<crate::translator::TwoCap>(&target_suffix, &target_context),
        )
        .await
        .unwrap();

        let key = Digest::from([7u8; 32]);
        for round in 0..COMMITS {
            let value = Some(Digest::from([round as u8; 32]));
            let merkleized = target_db
                .new_batch()
                .write(key, value)
                .merkleize(&target_db, None)
                .await
                .unwrap();
            target_db.apply_batch(merkleized).await.unwrap();
            target_db.commit().await.unwrap();
        }

        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let correct_canonical_root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.bounds().await.end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);

        // Attempt 1: wrong canonical root. The engine downloads all ops and syncs the
        // journal, but from_sync_result fails the canonical-root check. The on-disk
        // journal now contains all operations; metadata is still empty.
        let wrong_canonical_root = Digest::from([0xFFu8; 32]);
        let result = crate::qmdb::sync::sync::<Db, _>(crate::qmdb::sync::engine::Config {
            context: context.with_label("client1"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
                canonical_root: Some(wrong_canonical_root),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 4,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        })
        .await;
        assert!(
            result.is_err(),
            "first sync should fail with wrong canonical root",
        );

        // Attempt 2: correct canonical root, same journal partition. The engine finds
        // the journal already at target but defers completion until a fresh boundary
        // batch provides overlay state.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.with_label("client2"),
            db_config: client_config,
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
                canonical_root: Some(correct_canonical_root),
            },
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

        assert_eq!(SyncDatabase::root(&synced_db), sync_root);
        assert_eq!(synced_db.root(), correct_canonical_root);

        drop(synced_db);
        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Regression test: unordered MMB sync with explicit pruning across multiple chunks.
///
/// Commits a hot key 1000 times, prunes to the inactivity floor (which spans multiple
/// pruned chunks), then mid-sync adds 1000 more commits and prunes again. Historically this
/// tripped the grafted-tree reconstruction bug in the buggy
/// `nodes_to_pin(range.start).take(popcount(pruned_chunks))` extraction: for MMB with many
/// pruned chunks the first N ops pins did not correspond to the grafted pin positions, so
/// some pruned chunks needed internal ops nodes that were not boundary-stable pins and
/// `compute_grafted_root` failed looking them up.
///
/// After the overlay-state rollout (receiver rebuilds from explicit sender-supplied overlay
/// state instead of inferring from `range.start`), this passes. Kept as a regression guard
/// so the same shape cannot silently re-introduce the bug.
#[test_traced("INFO")]
fn test_current_mmb_unordered_sync_target_update_hot_key_exposes_bug() {
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
        >;

        // Push the sender's inactivity floor past several chunk boundaries so the pruned
        // prefix spans multiple chunks. The target update then adds more hot-key commits
        // on top, advancing the floor to a position that may or may not align with the
        // grafted pin structure under MMB's delayed merges.
        const INITIAL_COMMITS: u64 = 1000;
        const ADDITIONAL_COMMITS: u64 = 1000;

        let target_suffix = context.next_u64().to_string();
        let target_context = context.with_label("target");
        let mut target_db: Db = Db::init(
            target_context.clone(),
            variable_config::<crate::translator::TwoCap>(&target_suffix, &target_context),
        )
        .await
        .unwrap();

        let key = Digest::from([0x42u8; 32]);
        async fn commit_once(db: &mut Db, key: Digest, value: Digest) {
            let merkleized = db
                .new_batch()
                .write(key, Some(value))
                .merkleize(db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
        }

        for round in 0..INITIAL_COMMITS {
            commit_once(&mut target_db, key, Digest::from([round as u8; 32])).await;
        }

        // Prune so the sender has an explicitly pruned bitmap prefix. This forces the
        // receiver's sync-side `build_db` to reconstruct grafted pins from the synced
        // ops tree — the exact code path the overlay-state PR will fix.
        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        // Capture initial target state and start syncing.
        let initial_sync_root = SyncDatabase::root(&target_db);
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.bounds().await.end;

        let target_db =
            std::sync::Arc::new(commonware_utils::sync::AsyncRwLock::new(Some(target_db)));
        let (update_tx, update_rx) = commonware_utils::channel::mpsc::channel(1);

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let config = crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config,
            fetch_batch_size: commonware_utils::NZU64!(1),
            target: crate::qmdb::sync::Target {
                root: initial_sync_root,
                range: commonware_utils::non_empty_range!(initial_lower_bound, initial_upper_bound),
                canonical_root: None,
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 4,
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        // Step until the client has made some progress.
        let mut client = crate::qmdb::sync::engine::Engine::<Db, _>::new(config)
            .await
            .unwrap();
        loop {
            client = match client.step().await.unwrap() {
                crate::qmdb::sync::engine::NextStep::Continue(c) => c,
                crate::qmdb::sync::engine::NextStep::Complete(_) => {
                    panic!("client should not complete before target update")
                }
            };
            if client.journal().size().await > *initial_lower_bound {
                break;
            }
        }

        // Drive the target forward with more hot-key commits so that the new inactivity
        // floor lands in the delayed-merge-unstable region for MMB pin extraction.
        {
            let mut guard = target_db.write().await;
            let mut db = guard.take().unwrap();
            for round in 0..ADDITIONAL_COMMITS {
                commit_once(
                    &mut db,
                    key,
                    Digest::from([(round as u8).wrapping_add(128); 32]),
                )
                .await;
            }
            // Prune again so the new target boundary is also at a pruned prefix.
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let new_sync_root = SyncDatabase::root(&db);
            let new_lower = db.inactivity_floor_loc();
            let new_upper = db.bounds().await.end;
            *guard = Some(db);
            update_tx
                .send(crate::qmdb::sync::Target {
                    root: new_sync_root,
                    range: commonware_utils::non_empty_range!(new_lower, new_upper),
                    canonical_root: None,
                })
                .await
                .unwrap();
        }

        // Drive the sync to completion. Historically this aborted via the
        // verification-failure guard because the buggy ops-pin-derived grafted reconstruction
        // diverged from the sender's true overlay after the target update. After the
        // overlay-state rollout the receiver rebuilds from the sender's explicit overlay
        // payload, so the sync must complete successfully; the `.unwrap()` is the regression
        // guard.
        client.sync().await.unwrap();
    });
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
            fn test_target_update_on_done_client() {
                crate::qmdb::any::sync::tests::test_target_update_on_done_client::<$harness>();
            }

            #[test_traced]
            fn test_sync_waits_for_explicit_finish() {
                crate::qmdb::any::sync::tests::test_sync_waits_for_explicit_finish::<$harness>();
            }

            #[test_traced]
            fn test_sync_handles_early_finish_signal() {
                crate::qmdb::any::sync::tests::test_sync_handles_early_finish_signal::<$harness>();
            }

            #[test_traced]
            fn test_sync_fails_when_finish_sender_dropped() {
                crate::qmdb::any::sync::tests::test_sync_fails_when_finish_sender_dropped::<
                    $harness,
                >();
            }

            #[test_traced]
            fn test_sync_allows_dropped_reached_target_receiver() {
                crate::qmdb::any::sync::tests::test_sync_allows_dropped_reached_target_receiver::<
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
