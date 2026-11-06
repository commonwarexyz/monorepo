//! Sync tests for [`crate::qmdb::current`] databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for `current` databases, runs a subset of the `any`-specific
//! tests from [`crate::qmdb::any::sync::tests`], and adds `current`-specific tests. Sync targets
//! the ops root, while the harness's canonical root is the root returned by `Db::root()`.

use crate::qmdb::{
    current::tests::{fixed_config, variable_config},
    sync::{
        Database as SyncDatabase, Request, Response, Source as _,
        harness::{ConfigOf, SyncTestHarness},
    },
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::test_traced;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic, deterministic::Context};
use commonware_utils::{NZU64, NZUsize, non_empty_range, probability};
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
            batch.with_metadata(metadata).merkleize(&db).await.unwrap()
        };
        let db = db.apply_batch(merkleized).await.unwrap();
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
            batch.with_metadata(metadata).merkleize(&db).await.unwrap()
        };
        let db = db.apply_batch(merkleized).await.unwrap();
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
            batch.with_metadata(metadata).merkleize(&db).await.unwrap()
        };
        let db = db.apply_batch(merkleized).await.unwrap();
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
            batch.with_metadata(metadata).merkleize(&db).await.unwrap()
        };
        let db = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    pub struct UnorderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Graftable> SyncTestHarness for UnorderedFixedHarness<F> {
        type Family = F;
        type Db = UnorderedFixedDb<F>;
        type Metadata = Digest;

        fn config(suffix: &str) -> ConfigOf<Self> {
            fixed_config::<crate::translator::TwoCap>(suffix)
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
            let cfg = fixed_config::<crate::translator::TwoCap>("default");
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

        fn config(suffix: &str) -> ConfigOf<Self> {
            variable_config::<crate::translator::TwoCap>(suffix)
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
            let cfg = variable_config::<crate::translator::TwoCap>("default");
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

        fn config(suffix: &str) -> ConfigOf<Self> {
            fixed_config::<crate::translator::OneCap>(suffix)
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
            let cfg = fixed_config::<crate::translator::OneCap>("default");
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

        fn config(suffix: &str) -> ConfigOf<Self> {
            variable_config::<crate::translator::OneCap>(suffix)
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
            let cfg = variable_config::<crate::translator::OneCap>("default");
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
            variable_config::<crate::translator::TwoCap>(&target_suffix),
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
                .merkleize(&target_db)
                .await
                .unwrap();
            target_db = target_db.apply_batch(merkleized).await.unwrap();
            target_db = target_db.commit().await.unwrap();
        }

        assert!(
            *target_db.inactivity_floor() >= 256,
            "expected inactivity floor past chunk 0"
        );

        let boundary = target_db.sync_boundary();
        let target_db = target_db.prune(boundary).await.unwrap();

        let sync_root = SyncDatabase::root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary();
        let upper_bound = target_db.bounds().end;

        let client_suffix = context.next_u64().to_string();
        let client_config = variable_config::<crate::translator::TwoCap>(&client_suffix);
        let target_db = std::sync::Arc::new(target_db);

        // Sync targets the ops root, which is what the engine verifies. `build_db` reconstructs
        // the canonical root without authenticating it, so the assertions below compare it
        // against `verification_root`.
        let synced_db: Db = crate::qmdb::sync::sync(crate::qmdb::sync::Config {
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

        assert_eq!(SyncDatabase::root(&synced_db), sync_root);
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.sync_boundary(), lower_bound);
        assert_eq!(synced_db.get(&key).await.unwrap(), expected);

        drop(synced_db);

        let reopened: Db = Db::init(context.child("reopened"), client_config, None)
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
        let config = variable_config::<crate::translator::TwoCap>(&suffix);
        let mut db: Db = Db::init(context.child("db"), config.clone(), None)
            .await
            .unwrap();

        let key = Digest::from([9u8; 32]);
        for round in 0..300u64 {
            let merkleized = db
                .new_batch()
                .write(key, Some(Digest::from([round as u8; 32])))
                .merkleize(&db)
                .await
                .unwrap();
            db = db.apply_batch(merkleized).await.unwrap();
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

/// Persisting a sync result writes the grafted metadata before the operation frontier, so a
/// catch-up sync whose boundary prune fails reopens at the target.
#[test_traced]
fn test_current_sync_persist_failure_reopens_at_target() {
    type Db = crate::qmdb::current::unordered::fixed::Db<
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
    executor.start(|context: Context| async move {
        // Build the same history twice, so the local database already holds the target's
        // operations and recording the boundary prunes the ones before it.
        let key = Digest::from([9u8; 32]);
        let populate = |label: &'static str, config| {
            let context = context.child(label);
            async move {
                let mut db: Db = Db::init(context, config, None).await.unwrap();
                for round in 0..300u64 {
                    let merkleized = db
                        .new_batch()
                        .write(key, Some(Digest::from([round as u8; 32])))
                        .merkleize(&db)
                        .await
                        .unwrap();
                    db = db.apply_batch(merkleized).await.unwrap();
                }
                db.sync().await.unwrap()
            }
        };
        let source = populate(
            "source",
            fixed_config::<crate::translator::TwoCap>("source"),
        )
        .await;
        let local_config = fixed_config::<crate::translator::TwoCap>("local");
        let local = populate("local", local_config.clone()).await;
        let target = crate::qmdb::sync::Target {
            root: SyncDatabase::root(&source),
            range: non_empty_range!(source.sync_boundary(), source.bounds().end),
        };
        let canonical_root = source.root();
        assert!(
            *target.range.start() >= 2 * commonware_utils::bitmap::Prunable::<32>::CHUNK_SIZE_BITS,
            "chunk 0's root must not be a pinned node"
        );
        assert_eq!(local.root(), canonical_root);
        drop(local);

        // Failing every blob removal fails the prune that records the boundary, after the
        // frontier is written.
        let faults = context.storage_fault_config();
        faults.write().remove_rate = Some(probability!(1.0));
        let result = crate::qmdb::sync::sync::<Db, _>(crate::qmdb::sync::Config {
            context: context.child("sync"),
            db_config: local_config.clone(),
            fetch_batch_size: NZU64!(64),
            target: target.clone(),
            source: std::sync::Arc::new(source),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(4),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        })
        .await;
        assert!(matches!(result, Err(crate::qmdb::sync::Error::Database(_))));
        faults.write().remove_rate = None;

        // The database opens at the target and finishes the interrupted deletion.
        let reopened: Db = Db::init(context.child("reopened"), local_config, None)
            .await
            .unwrap();
        assert_eq!(SyncDatabase::root(&reopened), target.root);
        assert_eq!(reopened.root(), canonical_root);
        assert_eq!(reopened.bounds().start, target.range.start());
        reopened.destroy().await.unwrap();
    });
}

/// A catch-up sync interrupted after it writes the grafted metadata but before it records the
/// boundary reopens at the target under the previous frontier.
#[test_traced]
fn test_current_sync_interrupted_between_writes_reopens_at_target() {
    type Db = crate::qmdb::current::unordered::fixed::Db<
        crate::merkle::mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        crate::translator::TwoCap,
        32,
        Sequential,
    >;
    type Ops = crate::journal::contiguous::fixed::Journal<
        Context,
        crate::qmdb::any::unordered::fixed::Operation<crate::merkle::mmr::Family, Digest, Digest>,
    >;

    let executor = deterministic::Runner::default();
    executor.start(|context: Context| async move {
        // Build the same history twice. The local database stops earlier and prunes partway,
        // so its frontier lies before the target start and the sync must fetch a suffix.
        let key = Digest::from([9u8; 32]);
        let populate = |label: &'static str, config, rounds: u64, prune_at: Option<u64>| {
            let context = context.child(label);
            async move {
                let mut db: Db = Db::init(context, config, None).await.unwrap();
                for round in 0..rounds {
                    let merkleized = db
                        .new_batch()
                        .write(key, Some(Digest::from([round as u8; 32])))
                        .merkleize(&db)
                        .await
                        .unwrap();
                    db = db.apply_batch(merkleized).await.unwrap();
                    if prune_at == Some(round) {
                        let boundary = db.sync_boundary();
                        db = db.prune(boundary).await.unwrap();
                    }
                }
                db.sync().await.unwrap()
            }
        };
        let source = populate(
            "source",
            fixed_config::<crate::translator::TwoCap>("source"),
            300,
            None,
        )
        .await;
        let local_config = fixed_config::<crate::translator::TwoCap>("local");
        let local = populate("local", local_config.clone(), 280, Some(100)).await;
        let target = crate::qmdb::sync::Target {
            root: SyncDatabase::root(&source),
            range: non_empty_range!(source.sync_boundary(), source.bounds().end),
        };
        let canonical_root = source.root();
        let local_start = local.bounds().start;
        assert!(
            local_start < target.range.start(),
            "the target must start past the local frontier"
        );
        assert!(
            local.bounds().end < target.range.end(),
            "the sync must fetch a suffix"
        );
        drop(local);

        // Run the sync by hand: fetch the missing operations and the boundary pins, build the
        // database, and check its root.
        let range = target.range.clone();
        type Family = crate::merkle::mmr::Family;
        let mut journal = <Ops as crate::qmdb::sync::Journal<Family>>::new(
            context.child("journal"),
            local_config.log.clone(),
            range.clone(),
        )
        .await
        .unwrap();
        while <Ops as crate::qmdb::sync::Journal<Family>>::size(&journal) < *range.end() {
            let (response, _) = source
                .serve(Request::Operations {
                    size: range.end(),
                    start: <Ops as crate::qmdb::sync::Journal<Family>>::size(&journal),
                    max_ops: NZU64!(64),
                })
                .await
                .unwrap();
            let Response::Operations { operations, .. } = response else {
                panic!("expected operations");
            };
            journal = <Ops as crate::qmdb::sync::Journal<Family>>::append(journal, operations)
                .await
                .unwrap();
        }
        let journal = <Ops as crate::qmdb::sync::Journal<Family>>::sync(journal)
            .await
            .unwrap();
        let (response, _) = source
            .serve(Request::Boundary {
                size: range.end(),
                start: range.start(),
            })
            .await
            .unwrap();
        let Response::Boundary { pinned_nodes, .. } = response else {
            panic!("expected a boundary");
        };
        let db = Db::from_sync_result(
            context.child("sync"),
            local_config.clone(),
            journal,
            Some(pinned_nodes),
            range,
            NZU64!(1024),
        )
        .await
        .unwrap();
        assert_eq!(SyncDatabase::root(&db), target.root);

        // Persist only the first of the two writes, then stop.
        drop(db.sync_metadata().await.unwrap());

        // The database reopens at the target. The frontier is still the local one, so the
        // operations before the target start remain readable until the next prune.
        let reopened: Db = Db::init(context.child("reopened"), local_config, None)
            .await
            .unwrap();
        assert_eq!(SyncDatabase::root(&reopened), target.root);
        assert_eq!(reopened.root(), canonical_root);
        assert_eq!(reopened.bounds().start, local_start);
        assert_eq!(reopened.bounds().end, target.range.end());
        reopened.destroy().await.unwrap();
        source.destroy().await.unwrap();
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
