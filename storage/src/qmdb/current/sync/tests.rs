//! Tests for [crate::qmdb::current] state sync.
//!
//! This module reuses the shared sync test functions from [crate::qmdb::any::sync::tests] by
//! implementing [SyncTestHarness] for current database types. The key difference from `any`
//! harnesses is that `sync_target_root` returns the **QMDB ops root** (via
//! [qmdb::sync::Database::root](crate::qmdb::sync::Database::root)), not the canonical root
//! returned by `Db::root()`.
//!
//! Harnesses are instantiated for **both** MMR and MMB merkle families across each (ordered,
//! unordered) x (fixed, variable) database variant, so the shared suite runs twice per variant.
//!
//! In addition to the shared harness-based suite, this module contains focused tests for
//! `current`-specific sync behavior: overlay-state authentication (canonical-root check), pruned
//! MMB round-trip, and target-update regression coverage.

use crate::qmdb::{
    any::sync::tests::{ConfigOf, SyncTestHarness},
    current::tests::{fixed_config, variable_config},
    sync::Database as SyncDatabase,
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, deterministic, deterministic::Context,
};
use commonware_utils::non_empty_range;
use rand::Rng as _;

struct PendingMmrResolver<Op>(core::marker::PhantomData<fn() -> Op>);

impl<Op> PendingMmrResolver<Op> {
    const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<Op> Clone for PendingMmrResolver<Op> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<Op: 'static> crate::qmdb::sync::resolver::Resolver for PendingMmrResolver<Op> {
    type Family = crate::merkle::mmr::Family;
    type Digest = Digest;
    type Op = Op;
    type Error = std::convert::Infallible;

    async fn get_operations(
        &self,
        _op_count: crate::merkle::Location<Self::Family>,
        _start_loc: crate::merkle::Location<Self::Family>,
        _max_ops: core::num::NonZeroU64,
        _include_pinned_nodes: bool,
        _cancel_rx: commonware_utils::channel::oneshot::Receiver<()>,
    ) -> Result<
        crate::qmdb::sync::resolver::FetchResult<Self::Family, Self::Op, Self::Digest>,
        Self::Error,
    > {
        std::future::pending().await
    }
}

type FixedMmrDb<E> = crate::qmdb::current::unordered::fixed::Db<
    crate::merkle::mmr::Family,
    E,
    Digest,
    Digest,
    Sha256,
    crate::translator::OneCap,
    32,
    Sequential,
>;

type VariableMmrDb<E> = crate::qmdb::current::unordered::variable::Db<
    crate::merkle::mmr::Family,
    E,
    Digest,
    Digest,
    Sha256,
    crate::translator::OneCap,
    32,
    Sequential,
>;

async fn seed_fixed_mmr_client(
    context: &Context,
    suffix: &str,
) -> (
    crate::qmdb::current::FixedConfig<crate::translator::OneCap, Sequential>,
    crate::merkle::Location<crate::merkle::mmr::Family>,
) {
    let config = fixed_config::<crate::translator::OneCap>(suffix, context);
    let mut db = FixedMmrDb::<Context>::init(context.child("seed"), config.clone())
        .await
        .unwrap();
    let batch = db
        .new_batch()
        .write(Digest::from([1u8; 32]), Some(Digest::from([2u8; 32])))
        .merkleize(&db, None)
        .await
        .unwrap();
    (db, _) = db.apply_batch(batch).await.unwrap();
    let db = db.commit().await.unwrap().sync().await.unwrap();
    let end = db.bounds().end;
    drop(db);
    (config, end)
}

async fn assert_fixed_mmr_client_recovers_empty(
    context: Context,
    config: crate::qmdb::current::FixedConfig<crate::translator::OneCap, Sequential>,
) {
    use crate::merkle::Location;

    let db = FixedMmrDb::<Context>::init(context.child("recover"), config.clone())
        .await
        .expect("pending sync recovery must remain openable");
    assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
    let root = db.root();
    drop(db);

    let db = FixedMmrDb::<Context>::init(context.child("reopen"), config)
        .await
        .expect("recovered empty generation must remain stable");
    assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
    assert_eq!(db.root(), root);
    db.destroy().await.unwrap();
}

// ===== Harness Implementations =====

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
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_unordered_variable_ops<F: merkle::Graftable>(
        db: UnorderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Digest>>,
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
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_ordered_fixed_ops<F: merkle::Graftable>(
        db: OrderedFixedDb<F>,
        ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
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
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    async fn apply_ordered_variable_ops<F: merkle::Graftable>(
        db: OrderedVariableDb<F>,
        ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Digest>>,
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
            batch.merkleize(&db, None::<Digest>).await.unwrap()
        };
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    pub struct UnorderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedFixedHarness<F> {
        type Family = F;
        type Db = UnorderedFixedDb<F>;

        fn sync_target_root(db: &Self::Db) -> Digest {
            SyncDatabase::root(db)
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
            SyncDatabase::root(db)
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
            SyncDatabase::root(db)
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
            SyncDatabase::root(db)
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
            (target_db, _) = target_db.apply_batch(merkleized).await.unwrap();
            target_db = target_db.commit().await.unwrap();
        }

        assert!(
            *target_db.inactivity_floor_loc() >= 256,
            "expected inactivity floor past chunk 0"
        );

        let boundary = target_db.sync_boundary();
        let target_db = target_db.prune(boundary).await.unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary();
        let upper_bound = target_db.bounds().end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix, &context);
        let target_db = std::sync::Arc::new(target_db);
        // Supply the trusted canonical root so `build_db`'s authentication check actually
        // runs: this is the success-path coverage for the overlay-state authentication
        // anchor. A bad-root rejection path test belongs with the focused sync tests.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::engine::Config {
            context: context.child("client"),
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
        assert_eq!(synced_db.sync_boundary(), lower_bound);
        assert_eq!(synced_db.get(&key).await.unwrap(), expected);

        drop(synced_db);

        let reopened: Db = Db::init(context.child("reopened"), client_config)
            .await
            .unwrap();
        assert_eq!(SyncDatabase::root(&reopened), sync_root);
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

macro_rules! canceled_engine_after_journal_clear_test {
    ($name:ident, $db:ty, $op:ty, $config:ident, $suffix:literal $(,)?) => {
        #[test_traced]
        fn $name() {
            use commonware_utils::NZU64;

            const SUFFIX: &str = $suffix;

            let ((), checkpoint) =
                deterministic::Runner::default().start_and_recover(|context| async move {
                    let config = $config::<crate::translator::OneCap>(SUFFIX, &context);
                    let mut db = <$db>::init(context.child("seed"), config.clone())
                        .await
                        .unwrap();
                    let batch = db
                        .new_batch()
                        .write(Digest::from([1u8; 32]), Some(Digest::from([2u8; 32])))
                        .merkleize(&db, None)
                        .await
                        .unwrap();
                    (db, _) = db.apply_batch(batch).await.unwrap();
                    let db = db.commit().await.unwrap().sync().await.unwrap();
                    let start = db.bounds().end;
                    drop(db);

                    let end = start.checked_add(32).unwrap();
                    let engine: crate::qmdb::sync::Engine<$db, PendingMmrResolver<$op>> =
                        crate::qmdb::sync::Engine::new(crate::qmdb::sync::engine::Config {
                            context: context.child("engine"),
                            resolver: PendingMmrResolver::new(),
                            target: crate::qmdb::sync::Target {
                                root: Digest::from([9u8; 32]),
                                range: non_empty_range!(start, end),
                            },
                            max_outstanding_requests: 1,
                            fetch_batch_size: NZU64!(8),
                            apply_batch_size: 8,
                            db_config: config,
                            update_rx: None,
                            finish_rx: None,
                            reached_target_tx: None,
                            max_retained_roots: 0,
                        })
                        .await
                        .unwrap();
                    assert_eq!(
                        crate::journal::contiguous::Contiguous::bounds(engine.journal()),
                        *start..*start
                    );

                    // Cancel an actual Engine await after Journal::new durably cleared the raw log
                    // but before from_sync_result can assemble Full or Current metadata.
                    let mut stalled = Box::pin(engine.step());
                    assert!(futures::poll!(stalled.as_mut()).is_pending());
                    drop(stalled);
                });

            deterministic::Runner::from(checkpoint).start(|context| async move {
                let config = $config::<crate::translator::OneCap>(SUFFIX, &context);
                let db = <$db>::init(context.child("recover"), config.clone())
                    .await
                    .expect("pending sync recovery must remain openable");
                assert_eq!(
                    db.bounds(),
                    crate::merkle::Location::new(0)..crate::merkle::Location::new(1)
                );
                let root = db.root();
                drop(db);

                let db = <$db>::init(context.child("reopen"), config)
                    .await
                    .expect("recovered empty generation must remain stable");
                assert_eq!(
                    db.bounds(),
                    crate::merkle::Location::new(0)..crate::merkle::Location::new(1)
                );
                assert_eq!(db.root(), root);
                db.destroy().await.unwrap();
            });
        }
    };
}

canceled_engine_after_journal_clear_test!(
    test_canceled_engine_after_journal_clear_recovers_empty_generation,
    FixedMmrDb<Context>,
    crate::qmdb::any::unordered::fixed::Operation<
        crate::merkle::mmr::Family,
        Digest,
        Digest,
    >,
    fixed_config,
    "canceled-engine-journal-clear",
);

canceled_engine_after_journal_clear_test!(
    test_canceled_engine_after_variable_journal_clear_recovers_empty_generation,
    VariableMmrDb<Context>,
    crate::qmdb::any::unordered::variable::Operation<
        crate::merkle::mmr::Family,
        Digest,
        Digest,
    >,
    variable_config,
    "canceled-engine-variable-journal-clear",
);

#[test_traced]
fn test_canceled_engine_journal_append_recovers_empty_generation() {
    use crate::qmdb::{
        any::{operation::update::Unordered as UnorderedUpdate, unordered::fixed::Operation},
        sync::Engine,
    };
    use commonware_runtime::mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync};
    use commonware_utils::NZU64;

    type DelayedContext = DelayedSyncContext<Context>;
    type Op = Operation<crate::merkle::mmr::Family, Digest, Digest>;

    const SUFFIX: &str = "canceled-engine-journal-append";

    let ((), checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (config, start) = seed_fixed_mmr_client(&context, SUFFIX).await;
            let end = start.checked_add(64).unwrap();
            let pending = PendingSyncs::default();
            pending.unblock();
            let delayed = DelayedContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let mut engine: Engine<FixedMmrDb<DelayedContext>, PendingMmrResolver<Op>> =
                Engine::new(crate::qmdb::sync::engine::Config {
                    context: delayed,
                    resolver: PendingMmrResolver::new(),
                    target: crate::qmdb::sync::Target {
                        root: Digest::from([10u8; 32]),
                        range: non_empty_range!(start, end),
                    },
                    max_outstanding_requests: 1,
                    fetch_batch_size: NZU64!(8),
                    apply_batch_size: 8,
                    db_config: config,
                    update_rx: None,
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 0,
                })
                .await
                .unwrap();

            let mut operations = (0..15u8)
                .map(|i| {
                    Operation::Update(UnorderedUpdate(
                        Digest::from([i.wrapping_add(16); 32]),
                        Digest::from([i.wrapping_add(64); 32]),
                    ))
                })
                .collect::<Vec<_>>();
            operations.push(Operation::CommitFloor(None, start));
            engine.store_operations(start, operations);

            // A multi-blob append must await rollover durability. Interrupt that exact await after
            // the pre-sync Current intent is durable and before Full assembly begins.
            pending.arm();
            let mut applying = Box::pin(engine.apply_operations());
            for _ in 0..64 {
                assert!(futures::poll!(applying.as_mut()).is_pending());
                if pending.calls() != 0 {
                    break;
                }
                commonware_runtime::reschedule().await;
            }
            assert_eq!(pending.calls(), 1);
            let deferred = next_pending_sync(&pending);
            deferred.blocked.await.unwrap();
            drop(deferred.release);
            drop(applying);
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let config = fixed_config::<crate::translator::OneCap>(SUFFIX, &context);
        assert_fixed_mmr_client_recovers_empty(context, config).await;
    });
}

#[test_traced]
fn test_canceled_sync_metadata_publication_recovers_empty_generation() {
    use crate::{
        journal::contiguous::fixed,
        merkle::{Family as _, Location, mmr},
        qmdb::{
            any::unordered::fixed::{Operation, Update},
            current::unordered::fixed::Db,
        },
        translator::OneCap,
    };
    use commonware_runtime::mocks::{DelayedSyncContext, PendingSyncs};
    use commonware_utils::{bitmap::Readable as _, non_empty_range};

    type F = mmr::Family;
    type Op = Operation<F, Digest, Digest>;
    type NormalDb = Db<F, Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;
    type DelayedContext = DelayedSyncContext<Context>;
    type DelayedDb = Db<F, DelayedContext, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    const SUFFIX: &str = "canceled-sync-metadata-publication";
    const REPLACEMENT_START: u64 = 512;

    let (replacement_root, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let config = fixed_config::<OneCap>(SUFFIX, &context);

            // Persist an old Current generation with graft metadata that cannot describe the
            // replacement generation below.
            let mut old = NormalDb::init(context.child("old"), config.clone())
                .await
                .unwrap();
            let key = Digest::from([3u8; 32]);
            for round in 0..160u64 {
                let batch = old
                    .new_batch()
                    .write(key, Some(Digest::from([round as u8; 32])))
                    .merkleize(&old, None)
                    .await
                    .unwrap();
                (old, _) = old.apply_batch(batch).await.unwrap();
                old = old.commit().await.unwrap();
            }
            let old_boundary = old.sync_boundary();
            assert!(old_boundary > Location::new(0));
            assert!(old.bounds().end < Location::new(REPLACEMENT_START));
            let old = old.prune(old_boundary).await.unwrap().sync().await.unwrap();
            assert!(old.any.bitmap.pruned_chunks() > 0);
            drop(old);

            let range = non_empty_range!(
                Location::new(REPLACEMENT_START),
                Location::new(REPLACEMENT_START + 1)
            );
            let metadata = crate::qmdb::current::db::open_metadata::<F, _>(
                context.child("intent"),
                &config.grafted_metadata_partition,
            )
            .await
            .unwrap();
            drop(
                crate::qmdb::current::db::stage_sync::<F, _, Digest>(
                    metadata,
                    &crate::qmdb::sync::Target::new(Digest::from([0xAA; 32]), range.clone()),
                )
                .await
                .unwrap(),
            );

            // Prepare the replacement operations journal at a disjoint logical generation. Its
            // context has durability delays permanently disabled; only assemble_db's context is
            // armed below.
            let prep_pending = PendingSyncs::default();
            prep_pending.unblock();
            let prep_context = DelayedSyncContext {
                inner: context.child("prepare_log"),
                pending: prep_pending,
            };
            let journal =
                fixed::Journal::<_, Op>::init(prep_context, config.journal_config.clone())
                    .await
                    .unwrap();
            let journal = journal.clear_to_size(REPLACEMENT_START).await.unwrap();
            let commit = Op::CommitFloor(None, Location::new(REPLACEMENT_START));
            let (journal, _) = journal.append(&commit).await.unwrap();
            let journal = journal.sync().await.unwrap();

            let pinned_nodes = F::nodes_to_pin(Location::new(REPLACEMENT_START))
                .enumerate()
                .map(|(index, _)| Digest::from([index as u8 + 17; 32]))
                .collect();

            // Assemble and durably sync the replacement Full/log generation while retaining the
            // Current replacement intent. Delays are disabled during assembly, then armed for the
            // final graft-metadata publication only.
            let publish_pending = PendingSyncs::default();
            publish_pending.unblock();
            let publish_context = DelayedSyncContext {
                inner: context.child("assemble"),
                pending: publish_pending.clone(),
            };
            let db: DelayedDb =
                super::assemble_db::<F, _, Update<Digest, Digest>, _, Sha256, _, OneCap, 32, _>(
                    publish_context,
                    config.merkle_config.clone(),
                    journal,
                    config.translator.clone(),
                    Some(pinned_nodes),
                    range,
                    1024,
                    (),
                    config.init_buffer,
                    config.init_cache_size,
                    config.grafted_metadata_partition.clone(),
                    config.merkle_config.strategy.clone(),
                )
                .await
                .unwrap();
            let replacement_root = db.root();

            publish_pending.arm();
            let mut publication = Box::pin(db.sync_metadata());
            assert!(futures::poll!(publication.as_mut()).is_pending());
            assert_eq!(publish_pending.calls(), 1);
            drop(publication);
            replacement_root
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        let config = fixed_config::<OneCap>(SUFFIX, &context);
        let db = NormalDb::init(context.child("recover"), config.clone())
            .await
            .expect("surviving replacement intent must recover to an openable generation");
        let bounds = db.bounds();
        if bounds == (Location::new(0)..Location::new(1)) {
            assert_eq!(db.sync_boundary(), Location::new(0));
            assert_eq!(db.any.bitmap.pruned_chunks(), 0);
        } else {
            assert_eq!(
                bounds,
                Location::new(REPLACEMENT_START)..Location::new(REPLACEMENT_START + 1)
            );
            assert_eq!(db.root(), replacement_root);
        }
        let root = db.root();
        drop(db);

        let db = NormalDb::init(context.child("reopen"), config)
            .await
            .expect("recovered generation must remain stable on reopen");
        assert_eq!(db.bounds(), bounds);
        assert_eq!(db.root(), root);
        db.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_canceled_pending_sync_recovery_retries() {
    use crate::{
        merkle::{Location, mmr},
        qmdb::current::{db as current_db, unordered::fixed::Db},
        translator::OneCap,
    };
    use commonware_runtime::mocks::{DelayedSyncContext, PendingSyncs};

    type F = mmr::Family;
    type NormalDb = Db<F, Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;
    type DelayedContext = DelayedSyncContext<Context>;
    type DelayedDb = Db<F, DelayedContext, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    const SUFFIX: &str = "canceled-pending-sync-recovery";

    let ((), checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let config = fixed_config::<OneCap>(SUFFIX, &context);
            let mut db = NormalDb::init(context.child("old"), config.clone())
                .await
                .unwrap();
            let batch = db
                .new_batch()
                .write(Digest::from([1u8; 32]), Some(Digest::from([2u8; 32])))
                .merkleize(&db, None)
                .await
                .unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.commit().await.unwrap().sync().await.unwrap();
            drop(db);

            let metadata = current_db::open_metadata::<F, _>(
                context.child("intent"),
                &config.grafted_metadata_partition,
            )
            .await
            .unwrap();
            let target = crate::qmdb::sync::Target::new(
                Digest::from([0xAA; 32]),
                non_empty_range!(Location::new(0), Location::new(1)),
            );
            let metadata = current_db::stage_sync::<F, _, Digest>(metadata, &target)
                .await
                .unwrap();
            drop(metadata);
        });

    // Cancel the first durability await while ordinary initialization resolves the durable intent.
    // The Current marker is not removed until both backing resets complete, so restart retries.
    let ((), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let pending = PendingSyncs::default();
            pending.arm();
            let delayed = DelayedSyncContext {
                inner: context.child("interrupted_recovery"),
                pending: pending.clone(),
            };
            let config = fixed_config::<OneCap>(SUFFIX, &delayed);
            let mut recovery = Box::pin(DelayedDb::init(delayed, config));
            assert!(futures::poll!(recovery.as_mut()).is_pending());
            assert_eq!(pending.calls(), 1);
            drop(recovery);
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let config = fixed_config::<OneCap>(SUFFIX, &context);
        let db = NormalDb::init(context.child("recover"), config.clone())
            .await
            .expect("interrupted intent recovery must be retried");
        assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
        assert_eq!(db.sync_boundary(), Location::new(0));
        let root = db.root();
        drop(db);

        let db = NormalDb::init(context.child("reopen"), config)
            .await
            .expect("recovered empty generation must remain stable on reopen");
        assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
        assert_eq!(db.root(), root);
        db.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_incompatible_pending_target_resets_before_restage() {
    use crate::{
        journal::contiguous::fixed,
        merkle::{Location, mmr},
        qmdb::{
            any::unordered::fixed::Operation,
            current::{db as current_db, unordered::fixed::Db},
        },
        translator::OneCap,
    };

    type F = mmr::Family;
    type Op = Operation<F, Digest, Digest>;
    type DbType = Db<F, Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    const SUFFIX: &str = "incompatible-pending-target";

    deterministic::Runner::default().start(|context| async move {
        let (config, end) = seed_fixed_mmr_client(&context, SUFFIX).await;
        let range = non_empty_range!(Location::new(0), end);
        let first = crate::qmdb::sync::Target::new(Digest::from([1; 32]), range.clone());
        <DbType as SyncDatabase>::prepare_sync(context.child("prepare_first"), &config, &first)
            .await
            .unwrap();

        // A different root at the same size cannot reuse the first target's journal prefix.
        let second = crate::qmdb::sync::Target::new(Digest::from([2; 32]), range);
        <DbType as SyncDatabase>::prepare_sync(context.child("prepare_second"), &config, &second)
            .await
            .unwrap();

        let metadata = current_db::open_metadata::<F, _>(
            context.child("inspect_intent"),
            &config.grafted_metadata_partition,
        )
        .await
        .unwrap();
        let pending = current_db::pending_sync::<F, _, Digest>(&metadata)
            .unwrap()
            .unwrap();
        assert!(!pending.rejected);
        assert_eq!(pending.target, second);
        drop(metadata);

        let journal = fixed::Journal::<_, Op>::init(
            context.child("inspect_journal"),
            config.journal_config.clone(),
        )
        .await
        .unwrap();
        assert_eq!(journal.size(), 0);
        drop(journal);

        // Ordinary initialization can still resolve the new intent and return a reusable db.
        let db = DbType::init(context.child("recover"), config)
            .await
            .unwrap();
        assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
        db.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_rejected_sync_result_is_not_resumed() {
    use crate::{
        merkle::{Location, mmr},
        qmdb::current::{db as current_db, unordered::fixed::Db},
        translator::OneCap,
    };

    type F = mmr::Family;
    type DbType = Db<F, Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    deterministic::Runner::default().start(|context| async move {
        let config = fixed_config::<OneCap>("rejected-sync-result", &context);
        let mut db = DbType::init(context.child("db"), config.clone())
            .await
            .unwrap();
        let target = crate::qmdb::sync::Target::new(
            Digest::from([9; 32]),
            non_empty_range!(Location::new(0), Location::new(1)),
        );
        <DbType as SyncDatabase>::prepare_sync(context.child("prepare"), &config, &target)
            .await
            .unwrap();
        db.metadata = current_db::open_metadata::<F, _>(
            context.child("replacement_metadata"),
            &config.grafted_metadata_partition,
        )
        .await
        .unwrap();
        <DbType as SyncDatabase>::discard_sync_result(db)
            .await
            .unwrap();

        let metadata = current_db::open_metadata::<F, _>(
            context.child("inspect"),
            &config.grafted_metadata_partition,
        )
        .await
        .unwrap();
        let pending = current_db::pending_sync::<F, _, Digest>(&metadata)
            .unwrap()
            .unwrap();
        assert!(pending.rejected);
        assert_eq!(pending.target, target);
        drop(metadata);

        let db = DbType::init(context.child("recover"), config)
            .await
            .expect("a rejected target must reset instead of being resumed");
        assert_eq!(db.bounds(), Location::new(0)..Location::new(1));
        db.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_current_local_boundary_nodes_rejects_target_before_local_lower_bound() {
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
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            db = db.commit().await.unwrap();
        }
        let prune_loc = crate::merkle::Location::new(256);
        assert!(db.sync_boundary() >= prune_loc);
        let db = db.prune(prune_loc).await.unwrap();

        let bounds = db.bounds();
        let local_start = bounds.start;
        let local_end = bounds.end;
        let sync_root = SyncDatabase::root(&db);

        assert!(local_start > crate::merkle::Location::new(0));

        let stale_target = crate::qmdb::sync::Target {
            root: sync_root,
            range: non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        };
        assert!(
            <Db as SyncDatabase>::local_boundary_nodes(
                context.child("probe_stale"),
                &config,
                &stale_target,
                &db.any.log.journal,
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
            <Db as SyncDatabase>::local_boundary_nodes(
                context.child("probe_matching"),
                &config,
                &matching_target,
                &db.any.log.journal,
            )
            .await
            .unwrap()
            .is_some()
        );

        db.destroy().await.unwrap();
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
