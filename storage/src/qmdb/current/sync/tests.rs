//! Tests for [crate::qmdb::current] state sync.

use crate::{
    journal::contiguous::Contiguous,
    kv::Gettable,
    mmr::Location,
    qmdb::{
        self,
        any::states::CleanAny,
        current::db,
        operation::Operation as OperationTrait,
        store::{LogStore as _, MerkleizedStore, PrunableStore},
        sync::{
            self,
            engine::{Config, NextStep},
            resolver::{self, Resolver},
            Engine, Target,
        },
        Durable,
    },
    Persistable,
};
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{deterministic, BufferPooler, Metrics, Runner as _};
use commonware_utils::{channel::mpsc, sync::AsyncRwLock, NZU64};
use rand::RngCore as _;
use std::{num::NonZeroU64, sync::Arc};

/// Type alias for the database type of a harness.
type DbOf<H> = <H as CurrentSyncTestHarness>::Db;

/// Type alias for the operation type of a harness.
type OpOf<H> = <DbOf<H> as qmdb::sync::Database>::Op;

/// Type alias for the sync config type of a harness.
type SyncConfigOf<H> = <DbOf<H> as qmdb::sync::Database>::Config;

/// Type alias for the journal type of a harness.
type JournalOf<H> = <DbOf<H> as qmdb::sync::Database>::Journal;

/// Trait for extracting the ops MMR root from a `current::Db`.
///
/// The sync engine targets the ops root (not the canonical root), so tests need
/// access to it. [`MerkleizedStore::root`] returns the canonical root.
trait OpsRootAccess {
    /// Get the ops MMR root from the internal any db.
    fn ops_root(&self) -> Digest;
}

impl<E, C, I, U, const N: usize> OpsRootAccess
    for db::Db<E, C, I, commonware_cryptography::Sha256, U, N, db::Merkleized<Digest>, Durable>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + Metrics,
    C: crate::journal::contiguous::Contiguous<Item: commonware_codec::CodecShared>,
    I: crate::index::Unordered<Value = Location>,
    U: Send + Sync,
{
    fn ops_root(&self) -> Digest {
        self.any.log.root()
    }
}

/// Harness trait for current sync tests.
trait CurrentSyncTestHarness: Sized + 'static {
    /// The database type being tested (Clean: Merkleized + Durable).
    type Db: qmdb::sync::Database<Context = deterministic::Context, Digest = Digest, Config: Clone>
        + CleanAny<Key = Digest>
        + MerkleizedStore<Digest = Digest>
        + Gettable<Key = Digest>
        + OpsRootAccess;

    /// Create a db config with unique partition names.
    fn config(suffix: &str, pooler: &impl BufferPooler) -> SyncConfigOf<Self>;

    /// Generate n test operations using the default seed (0).
    fn create_ops(n: usize) -> Vec<OpOf<Self>>;

    /// Generate n test operations using a specific seed.
    fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>>;

    /// Initialize a database with default config.
    fn init_db(ctx: deterministic::Context) -> impl std::future::Future<Output = Self::Db> + Send;

    /// Initialize a database with a specific config.
    fn init_db_with_config(
        ctx: deterministic::Context,
        config: SyncConfigOf<Self>,
    ) -> impl std::future::Future<Output = Self::Db> + Send;

    /// Apply operations to a database, commit, and merkleize.
    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
    ) -> impl std::future::Future<Output = Self::Db> + Send;
}

// ===== Test Functions =====

/// Test that invalid bounds are rejected.
fn test_sync_invalid_bounds<H: CurrentSyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.with_label("target")).await;
        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: Digest::from([1u8; 32]),
                range: Location::new_unchecked(31)..Location::new_unchecked(30),
            },
            context: context.with_label("client"),
            resolver: Arc::new(target_db),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        let result: Result<DbOf<H>, _> = sync::sync(config).await;
        match result {
            Err(sync::Error::Engine(sync::EngineError::InvalidTarget {
                lower_bound_pos,
                upper_bound_pos,
            })) => {
                assert_eq!(lower_bound_pos, Location::new_unchecked(31));
                assert_eq!(upper_bound_pos, Location::new_unchecked(30));
            }
            _ => panic!("expected InvalidTarget error"),
        }
    });
}

/// Test that resolver failure is handled correctly.
fn test_sync_resolver_fails<H: CurrentSyncTestHarness>()
where
    resolver::tests::FailResolver<OpOf<H>, Digest>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let resolver = resolver::tests::FailResolver::<OpOf<H>, Digest>::new();
        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            context: context.with_label("client"),
            target: Target {
                root: Digest::from([0; 32]),
                range: Location::new_unchecked(0)..Location::new_unchecked(5),
            },
            resolver,
            apply_batch_size: 2,
            max_outstanding_requests: 2,
            fetch_batch_size: NZU64!(2),
            db_config: config,
            update_rx: None,
        };

        let result: Result<DbOf<H>, _> = sync::sync(config).await;
        assert!(result.is_err());
    });
}

/// Test basic sync with various batch sizes.
fn test_sync<H: CurrentSyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    Arc<DbOf<H>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database.
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(target_db_ops);
        target_db = H::apply_ops(target_db, target_ops).await;
        target_db
            .prune(target_db.inactivity_floor_loc().await)
            .await
            .unwrap();

        let target_root = MerkleizedStore::root(&target_db);
        let target_op_count = target_db.bounds().await.end;
        let target_inactivity_floor = target_db.inactivity_floor_loc().await;
        let ops_root = target_db.ops_root();
        let lower_bound = target_inactivity_floor;

        // Configure sync.
        let config = H::config(&context.next_u64().to_string(), &context);
        let reopen_config = config.clone();
        let target_db = Arc::new(target_db);
        let client_context = context.with_label("client");

        let config = Config {
            db_config: config,
            fetch_batch_size,
            target: Target {
                root: ops_root,
                range: lower_bound..target_op_count,
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        // Verify database state.
        assert_eq!(synced_db.bounds().await.end, target_op_count);
        assert_eq!(
            synced_db.inactivity_floor_loc().await,
            target_inactivity_floor
        );
        assert_eq!(MerkleizedStore::root(&synced_db), target_root);

        // Verify persistence: drop and reopen.
        let final_root = MerkleizedStore::root(&synced_db);
        let final_op_count = synced_db.bounds().await.end;
        let final_inactivity_floor = synced_db.inactivity_floor_loc().await;
        drop(synced_db);
        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), reopen_config).await;
        assert_eq!(reopened_db.bounds().await.end, final_op_count);
        assert_eq!(
            reopened_db.inactivity_floor_loc().await,
            final_inactivity_floor
        );
        assert_eq!(MerkleizedStore::root(&reopened_db), final_root);

        reopened_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test syncing to a subset of the target database.
fn test_sync_subset_of_target_database<H: CurrentSyncTestHarness>(target_db_ops: usize)
where
    Arc<DbOf<H>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(target_db_ops);

        // Apply all but the last operation.
        target_db = H::apply_ops(target_db, target_ops[0..target_db_ops - 1].to_vec()).await;

        let upper_bound = target_db.bounds().await.end;
        let ops_root = target_db.ops_root();
        let target_root = MerkleizedStore::root(&target_db);
        let lower_bound = target_db.inactivity_floor_loc().await;

        // Add another operation after the sync range.
        let final_op = target_ops[target_db_ops - 1].clone();
        let final_key = final_op.key().cloned();
        target_db = H::apply_ops(target_db, vec![final_op]).await;

        let target_db = Arc::new(target_db);
        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: ops_root,
                range: lower_bound..upper_bound,
            },
            context: context.with_label("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();
        assert_eq!(synced_db.inactivity_floor_loc().await, lower_bound);
        assert_eq!(synced_db.bounds().await.end, upper_bound);
        assert_eq!(MerkleizedStore::root(&synced_db), target_root);

        if let Some(key) = final_key {
            assert!(synced_db.get(&key).await.unwrap().is_none());
        }

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that target updates during sync work correctly.
fn test_target_update_during_sync<H: CurrentSyncTestHarness>(
    initial_ops: usize,
    additional_ops: usize,
) where
    Arc<AsyncRwLock<Option<DbOf<H>>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(initial_ops);
        target_db = H::apply_ops(target_db, target_ops).await;

        let initial_lower_bound = target_db.inactivity_floor_loc().await;
        let initial_upper_bound = target_db.bounds().await.end;
        let initial_ops_root = target_db.ops_root();

        let target_db = Arc::new(AsyncRwLock::new(Some(target_db)));

        let (update_sender, update_receiver) = mpsc::channel(1);
        let config = H::config(&context.next_u64().to_string(), &context);

        let client = {
            let config = Config {
                context: context.with_label("client"),
                db_config: config,
                target: Target {
                    root: initial_ops_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                fetch_batch_size: NZU64!(1),
                max_outstanding_requests: 10,
                apply_batch_size: 1024,
                update_rx: Some(update_receiver),
            };
            let mut client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();
            loop {
                client = match client.step().await.unwrap() {
                    NextStep::Continue(c) => c,
                    NextStep::Complete(_) => panic!("client should not be complete yet"),
                };
                let log_size = client.journal().size().await;
                if log_size > initial_lower_bound {
                    break client;
                }
            }
        };

        // Add more operations to the target.
        let additional_ops_data = H::create_ops_seeded(additional_ops, 1);
        let new_target_root = {
            let mut db_guard = target_db.write().await;
            let db = db_guard.take().unwrap();
            let db = H::apply_ops(db, additional_ops_data).await;

            let new_lower_bound = db.inactivity_floor_loc().await;
            let new_upper_bound = db.bounds().await.end;
            let new_ops_root = db.ops_root();
            let new_target_root = MerkleizedStore::root(&db);
            *db_guard = Some(db);

            update_sender
                .send(Target {
                    root: new_ops_root,
                    range: new_lower_bound..new_upper_bound,
                })
                .await
                .unwrap();

            new_target_root
        };

        let synced_db = client.sync().await.unwrap();
        assert_eq!(MerkleizedStore::root(&synced_db), new_target_root);

        let target_db = Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .expect("db should be present");
        {
            let synced_bounds = synced_db.bounds().await;
            let target_bounds = target_db.bounds().await;
            assert_eq!(synced_bounds.end, target_bounds.end);
            assert_eq!(
                synced_db.inactivity_floor_loc().await,
                target_db.inactivity_floor_loc().await
            );
        }

        synced_db.destroy().await.unwrap();
        target_db.destroy().await.unwrap();
    });
}

/// Test that a synced database can be reopened and retain its state.
fn test_sync_database_persistence<H: CurrentSyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(10);
        target_db = H::apply_ops(target_db, target_ops).await;

        let target_root = MerkleizedStore::root(&target_db);
        let ops_root = target_db.ops_root();
        let lower_bound = target_db.inactivity_floor_loc().await;
        let upper_bound = target_db.bounds().await.end;

        let config = H::config(&context.next_u64().to_string(), &context);
        let reopen_config = config.clone();
        let target_db = Arc::new(target_db);
        let client_context = context.with_label("client");

        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: ops_root,
                range: lower_bound..upper_bound,
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();
        assert_eq!(MerkleizedStore::root(&synced_db), target_root);

        let expected_root = MerkleizedStore::root(&synced_db);
        let expected_op_count = synced_db.bounds().await.end;
        let expected_inactivity_floor = synced_db.inactivity_floor_loc().await;
        drop(synced_db);

        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), reopen_config).await;
        assert_eq!(MerkleizedStore::root(&reopened_db), expected_root);
        assert_eq!(reopened_db.bounds().await.end, expected_op_count);
        assert_eq!(
            reopened_db.inactivity_floor_loc().await,
            expected_inactivity_floor
        );

        reopened_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test post-sync usability: after syncing, the database supports normal operations.
fn test_sync_post_sync_usability<H: CurrentSyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops).await;

        let ops_root = target_db.ops_root();
        let lower_bound = target_db.inactivity_floor_loc().await;
        let upper_bound = target_db.bounds().await.end;
        let target_db = Arc::new(target_db);

        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(100),
            target: Target {
                root: ops_root,
                range: lower_bound..upper_bound,
            },
            context: context.with_label("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        let root_after_sync = MerkleizedStore::root(&synced_db);

        // Apply additional operations after sync.
        let more_ops = H::create_ops_seeded(10, 1);
        let synced_db = H::apply_ops(synced_db, more_ops).await;

        // Root should change after applying more ops.
        assert_ne!(MerkleizedStore::root(&synced_db), root_after_sync);
        assert!(synced_db.bounds().await.end > upper_bound);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

// ===== Harness Implementations =====

mod harnesses {
    use super::{CurrentSyncTestHarness, SyncConfigOf};
    use crate::qmdb::current::tests::{fixed_config, variable_config};
    use commonware_cryptography::sha256::Digest;
    use commonware_runtime::{deterministic::Context, BufferPooler};

    // ----- Unordered/Fixed -----

    pub struct UnorderedFixedHarness;

    impl CurrentSyncTestHarness for UnorderedFixedHarness {
        type Db = crate::qmdb::current::unordered::fixed::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::TwoCap,
            32,
        >;
        fn config(suffix: &str, pooler: &impl BufferPooler) -> SyncConfigOf<Self> {
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

        async fn init_db_with_config(ctx: Context, config: SyncConfigOf<Self>) -> Self::Db {
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
            durable.into_merkleized().await.unwrap()
        }
    }

    // ----- Unordered/Variable -----

    pub struct UnorderedVariableHarness;

    impl CurrentSyncTestHarness for UnorderedVariableHarness {
        type Db = crate::qmdb::current::unordered::variable::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::TwoCap,
            32,
        >;
        fn config(suffix: &str, pooler: &impl BufferPooler) -> SyncConfigOf<Self> {
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

        async fn init_db_with_config(ctx: Context, config: SyncConfigOf<Self>) -> Self::Db {
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
            durable.into_merkleized().await.unwrap()
        }
    }

    // ----- Ordered/Fixed -----

    pub struct OrderedFixedHarness;

    impl CurrentSyncTestHarness for OrderedFixedHarness {
        type Db = crate::qmdb::current::ordered::fixed::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::OneCap,
            32,
        >;
        fn config(suffix: &str, pooler: &impl BufferPooler) -> SyncConfigOf<Self> {
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

        async fn init_db_with_config(ctx: Context, config: SyncConfigOf<Self>) -> Self::Db {
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
            durable.into_merkleized().await.unwrap()
        }
    }

    // ----- Ordered/Variable -----

    pub struct OrderedVariableHarness;

    impl CurrentSyncTestHarness for OrderedVariableHarness {
        type Db = crate::qmdb::current::ordered::variable::Db<
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            crate::translator::OneCap,
            32,
        >;
        fn config(suffix: &str, pooler: &impl BufferPooler) -> SyncConfigOf<Self> {
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

        async fn init_db_with_config(ctx: Context, config: SyncConfigOf<Self>) -> Self::Db {
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
            durable.into_merkleized().await.unwrap()
        }
    }

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
}

// ===== Test Generation Macro =====

macro_rules! current_sync_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[test_traced]
            fn test_sync_invalid_bounds() {
                super::test_sync_invalid_bounds::<$harness>();
            }

            #[test_traced]
            fn test_sync_resolver_fails() {
                super::test_sync_resolver_fails::<$harness>();
            }

            #[rstest]
            #[case::small_batch_size_one(10, 1)]
            #[case::small_batch_size_gt_db_size(10, 20)]
            #[case::batch_size_one(1000, 1)]
            #[case::floor_div_db_batch_size(1000, 3)]
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
            fn test_sync_subset_of_target_database() {
                super::test_sync_subset_of_target_database::<$harness>(1000);
            }

            #[test_traced]
            fn test_sync_database_persistence() {
                super::test_sync_database_persistence::<$harness>();
            }

            #[test_traced]
            fn test_sync_post_sync_usability() {
                super::test_sync_post_sync_usability::<$harness>();
            }

            #[rstest]
            #[case(1, 1)]
            #[case(1, 2)]
            #[case(2, 1)]
            #[case(2, 2)]
            #[case(20, 10)]
            #[case(100, 1)]
            #[case(100, 100)]
            fn test_target_update_during_sync(
                #[case] initial_ops: usize,
                #[case] additional_ops: usize,
            ) {
                super::test_target_update_during_sync::<$harness>(initial_ops, additional_ops);
            }
        }
    };
}

current_sync_tests_for_harness!(harnesses::UnorderedFixedHarness, unordered_fixed);
current_sync_tests_for_harness!(harnesses::UnorderedVariableHarness, unordered_variable);
current_sync_tests_for_harness!(harnesses::OrderedFixedHarness, ordered_fixed);
current_sync_tests_for_harness!(harnesses::OrderedVariableHarness, ordered_variable);
