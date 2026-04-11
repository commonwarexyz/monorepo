//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::any::sync::tests]
//! by implementing [SyncTestHarness] for current database types. The key difference from
//! `any` harnesses is that `sync_target_root` returns the **ops root** (via
//! [qmdb::sync::Database::root](crate::qmdb::sync::Database::root)), not the canonical root
//! returned by `Db::root()`.

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
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
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

/// Regression test for sync with multiple pruned chunks.
///
/// This tests the scenario where the ops tree has pinned nodes at heights above the grafting
/// height (covering multiple chunks). With N=32, CHUNK_SIZE_BITS=256, so 2 pruned chunks
/// requires 512 operations. The bug occurred because `compute_grafted_pinned_nodes` tried to
/// reconstruct individual chunk digests from ops peaks that spanned multiple chunks, which is
/// impossible since hash functions are one-way.
///
/// The fix uses the zero-chunk identity: for all-zero pruned chunks, the grafted tree's pinned
/// nodes have identical digests to the ops tree's peaks, so we can directly use the first
/// `popcount(pruned_chunks)` ops pins.
#[test_traced("INFO")]
fn test_current_mmr_sync_with_multiple_pruned_chunks() {
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

        // With N=32, CHUNK_SIZE_BITS=256. We need > 512 operations to have 2 full pruned chunks.
        // Each commit adds an operation, but we also need updates to create inactivity.
        // Use many commits updating the same key to ensure high inactivity floor.
        const COMMITS: u64 = 600;

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

        // Verify we have at least 2 complete chunks to prune (512 operations)
        assert!(
            *target_db.inactivity_floor_loc() >= 512,
            "expected inactivity floor past chunk 1 (512), got {}",
            *target_db.inactivity_floor_loc()
        );

        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.bounds().await.end;

        // Verify we're testing with 2+ pruned chunks
        let pruned_chunks = (*lower_bound / 256) as usize;
        assert!(
            pruned_chunks >= 2,
            "expected at least 2 pruned chunks, got {}",
            pruned_chunks
        );

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);

        // This sync would fail before the fix with:
        // "missing ops pinned node for pruned chunk reconstruction"
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.with_label("client"),
            db_config: client_config.clone(),
            fetch_batch_size: commonware_utils::NZU64!(64),
            target: crate::qmdb::sync::Target {
                root: sync_root,
                range: commonware_utils::non_empty_range!(lower_bound, upper_bound),
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

        synced_db.destroy().await.unwrap();
        std::sync::Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
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

current_sync_tests_for_harness!(
    self::harnesses::UnorderedFixedMmrHarness,
    unordered_fixed_mmr
);
current_sync_tests_for_harness!(
    self::harnesses::UnorderedFixedMmbHarness,
    unordered_fixed_mmb
);
current_sync_tests_for_harness!(
    self::harnesses::UnorderedVariableMmrHarness,
    unordered_variable_mmr
);
current_sync_tests_for_harness!(
    self::harnesses::UnorderedVariableMmbHarness,
    unordered_variable_mmb
);
current_sync_tests_for_harness!(self::harnesses::OrderedFixedMmrHarness, ordered_fixed_mmr);
current_sync_tests_for_harness!(self::harnesses::OrderedFixedMmbHarness, ordered_fixed_mmb);
current_sync_tests_for_harness!(
    self::harnesses::OrderedVariableMmrHarness,
    ordered_variable_mmr
);
current_sync_tests_for_harness!(
    self::harnesses::OrderedVariableMmbHarness,
    ordered_variable_mmb
);
