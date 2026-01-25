//! Generic sync tests that work for both fixed and variable databases.
//!
//! This module provides a test harness trait and generic test functions that can be
//! parameterized to run against either fixed-size or variable-size value databases.

use crate::{
    journal::contiguous::Contiguous,
    kv::Gettable,
    mmr::{Location, Position},
    qmdb::{
        self,
        any::states::CleanAny,
        operation::Operation as OperationTrait,
        store::{LogStore as _, MerkleizedStore, PrunableStore},
        sync::{
            self,
            engine::{Config, NextStep},
            resolver::{self, Resolver},
            Engine, Target,
        },
    },
    Persistable,
};
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{deterministic, Metrics, Runner as _, RwLock};
use commonware_utils::NZU64;
use futures::{channel::mpsc, SinkExt as _};
use rand::RngCore as _;
use std::{num::NonZeroU64, sync::Arc};

/// Type alias for the database type of a harness.
pub(crate) type DbOf<H> = <H as SyncTestHarness>::Db;

/// Type alias for the operation type of a harness.
pub(crate) type OpOf<H> = <DbOf<H> as qmdb::sync::Database>::Op;

/// Type alias for the config type of a harness.
pub(crate) type ConfigOf<H> = <DbOf<H> as qmdb::sync::Database>::Config;

/// Type alias for the journal type of a harness.
pub(crate) type JournalOf<H> = <DbOf<H> as qmdb::sync::Database>::Journal;

/// Trait for cleanup operations in tests.
pub(crate) trait Destructible {
    fn destroy(self) -> impl std::future::Future<Output = Result<(), qmdb::Error>> + Send;
}

// Implement Destructible for the concrete MMR type used in tests.
// This is here (rather than in fixed/variable modules) to avoid duplicate implementations.
impl Destructible
    for crate::mmr::journaled::Mmr<deterministic::Context, Digest, crate::mmr::mem::Clean<Digest>>
{
    async fn destroy(self) -> Result<(), qmdb::Error> {
        self.destroy().await.map_err(qmdb::Error::Mmr)
    }
}

/// Trait providing internal access for from_sync_result tests.
pub(crate) trait FromSyncTestable: qmdb::sync::Database {
    type Mmr: Destructible + Send;

    /// Get the MMR and journal from the database
    fn into_log_components(self) -> (Self::Mmr, Self::Journal);

    /// Get the pinned nodes at a given position
    fn pinned_nodes_at(
        &self,
        pos: Position,
    ) -> impl std::future::Future<Output = Vec<Self::Digest>> + Send;

    /// Get pinned nodes from the internal cached map (used before closing db in partial match tests)
    fn pinned_nodes_from_map(&self, pos: Position) -> Vec<Self::Digest>;
}

/// Harness for sync tests.
pub(crate) trait SyncTestHarness: Sized + 'static {
    /// The database type being tested (Clean state: Merkleized + Durable).
    type Db: qmdb::sync::Database<Context = deterministic::Context, Digest = Digest>
        + CleanAny<Key = Digest>
        + MerkleizedStore<Digest = Digest>
        + Gettable<Key = Digest>;

    /// Create a config with unique partition names
    fn config(suffix: &str) -> ConfigOf<Self>;

    /// Clone a config
    fn clone_config(config: &ConfigOf<Self>) -> ConfigOf<Self>;

    /// Generate n test operations using the default seed (0)
    fn create_ops(n: usize) -> Vec<OpOf<Self>>;

    /// Generate n test operations using a specific seed.
    /// Use different seeds when you need non-overlapping keys in the same test.
    fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>>;

    /// Initialize a database
    fn init_db(ctx: deterministic::Context) -> impl std::future::Future<Output = Self::Db> + Send;

    /// Initialize a database with a config
    fn init_db_with_config(
        ctx: deterministic::Context,
        config: ConfigOf<Self>,
    ) -> impl std::future::Future<Output = Self::Db> + Send;

    /// Apply operations to a database and commit (returns to Clean state)
    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
    ) -> impl std::future::Future<Output = Self::Db> + Send;
}

/// Test that invalid bounds are rejected
pub(crate) fn test_sync_invalid_bounds<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.with_label("target")).await;
        let db_config = H::config(&context.next_u64().to_string());
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: Digest::from([1u8; 32]),
                range: Location::new_unchecked(31)..Location::new_unchecked(30), // Invalid: start > end
            },
            context: context.with_label("client"),
            resolver: Arc::new(RwLock::new(target_db)),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        let result: Result<H::Db, _> = sync::sync(config).await;
        match result {
            Err(sync::Error::Engine(sync::EngineError::InvalidTarget {
                lower_bound_pos,
                upper_bound_pos,
            })) => {
                assert_eq!(lower_bound_pos, Location::new_unchecked(31));
                assert_eq!(upper_bound_pos, Location::new_unchecked(30));
            }
            _ => panic!("Expected InvalidTarget error"),
        }
    });
}

/// Test that resolver failure is handled correctly
pub(crate) fn test_sync_resolver_fails<H: SyncTestHarness>()
where
    resolver::tests::FailResolver<OpOf<H>, Digest>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let resolver = resolver::tests::FailResolver::<OpOf<H>, Digest>::new();
        let target_root = Digest::from([0; 32]);

        let db_config = H::config(&context.next_u64().to_string());
        let engine_config = Config {
            context: context.with_label("client"),
            target: Target {
                root: target_root,
                range: Location::new_unchecked(0)..Location::new_unchecked(5),
            },
            resolver,
            apply_batch_size: 2,
            max_outstanding_requests: 2,
            fetch_batch_size: NZU64!(2),
            db_config,
            update_rx: None,
        };

        let result: Result<H::Db, _> = sync::sync(engine_config).await;
        assert!(result.is_err());
    });
}

/// Test basic sync functionality with various batch sizes
pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(target_db_ops);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops
        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();

        let target_op_count = target_db.op_count();
        let target_inactivity_floor = target_db.inactivity_floor_loc();
        let target_root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();

        // Configure sync
        let db_config = H::config(&context.next_u64().to_string());
        let target_db = Arc::new(RwLock::new(target_db));
        let client_context = context.with_label("client");
        let config = Config {
            db_config: H::clone_config(&db_config),
            fetch_batch_size,
            target: Target {
                root: target_root,
                range: lower_bound..target_op_count,
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        // Perform sync
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state (root hash is the key verification)
        assert_eq!(synced_db.op_count(), target_op_count);
        assert_eq!(synced_db.inactivity_floor_loc(), target_inactivity_floor);
        assert_eq!(synced_db.root(), target_root);

        // Verify persistence
        let final_root = synced_db.root();
        let final_op_count = synced_db.op_count();
        let final_inactivity_floor = synced_db.inactivity_floor_loc();

        // Reopen and verify state persisted
        drop(synced_db);
        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), db_config).await;
        assert_eq!(reopened_db.op_count(), final_op_count);
        assert_eq!(reopened_db.inactivity_floor_loc(), final_inactivity_floor);
        assert_eq!(reopened_db.root(), final_root);

        // Cleanup
        reopened_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test syncing to a subset of the target database (target has additional ops beyond sync range)
pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>(target_db_ops: usize)
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(target_db_ops);

        // Apply all but the last operation
        target_db = H::apply_ops(target_db, target_ops[0..target_db_ops - 1].to_vec()).await;
        // commit already done in apply_ops

        let upper_bound = target_db.op_count();
        let root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();

        // Add another operation after the sync range
        let final_op = target_ops[target_db_ops - 1].clone();
        let final_key = final_op.key().cloned(); // Store the key before applying
        target_db = H::apply_ops(target_db, vec![final_op]).await;
        // commit already done in apply_ops

        // Sync to the original root (before final_op was added)
        let db_config = H::config(&context.next_u64().to_string());
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: lower_bound..upper_bound,
            },
            context: context.with_label("client"),
            resolver: Arc::new(RwLock::new(target_db)),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };

        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify the synced database has the correct range of operations
        assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);
        assert_eq!(synced_db.op_count(), upper_bound);

        // Verify the final root digest matches our target
        assert_eq!(synced_db.root(), root);

        // Verify the synced database doesn't have any operations beyond the sync range.
        // (the final_op should not be present)
        if let Some(key) = final_key {
            assert!(synced_db.get(&key).await.unwrap().is_none());
        }

        synced_db.destroy().await.unwrap();
    });
}

/// Test syncing where the sync client has some but not all of the operations in the target DB.
/// Tests the scenario where sync_db already has partial data and needs to sync additional ops.
pub(crate) fn test_sync_use_existing_db_partial_match<H: SyncTestHarness>(original_ops: usize)
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let original_ops_data = H::create_ops(original_ops);

        // Create two databases
        let mut target_db = H::init_db(context.with_label("target")).await;
        let sync_db_config = H::config(&context.next_u64().to_string());
        let client_context = context.with_label("client");
        let mut sync_db: H::Db =
            H::init_db_with_config(client_context.clone(), H::clone_config(&sync_db_config)).await;

        // Apply the same operations to both databases
        target_db = H::apply_ops(target_db, original_ops_data.clone()).await;
        sync_db = H::apply_ops(sync_db, original_ops_data.clone()).await;
        // commit already done in apply_ops
        // commit already done in apply_ops

        drop(sync_db);

        // Add more operations and commit the target database
        // (use different seed to avoid key collisions)
        let more_ops = H::create_ops_seeded(1, 1);
        target_db = H::apply_ops(target_db, more_ops.clone()).await;
        // commit already done in apply_ops

        let root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.op_count();

        // Reopen the sync database and sync it to the target database
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            db_config: sync_db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: lower_bound..upper_bound,
            },
            context: client_context.with_label("sync"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state
        assert_eq!(synced_db.op_count(), upper_bound);
        assert_eq!(
            synced_db.inactivity_floor_loc(),
            target_db.read().await.inactivity_floor_loc()
        );
        assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);
        assert_eq!(synced_db.op_count(), target_db.read().await.op_count());
        // Verify the root digest matches the target
        assert_eq!(synced_db.root(), root);

        // Verify that original operations are present and correct (by key lookup)
        for target_op in &original_ops_data {
            if let Some(key) = target_op.key() {
                let target_value = target_db.read().await.get(key).await.unwrap();
                let synced_value = synced_db.get(key).await.unwrap();
                assert_eq!(target_value.is_some(), synced_value.is_some());
            }
        }

        // Verify the last operation is present (if it's an update)
        if let Some(key) = more_ops[0].key() {
            let synced_value = synced_db.get(key).await.unwrap();
            let target_value = target_db.read().await.get(key).await.unwrap();
            assert_eq!(synced_value.is_some(), target_value.is_some());
        }

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test case where existing database on disk exactly matches the sync target.
/// Uses FailResolver to verify that no network requests are made since data already exists.
pub(crate) fn test_sync_use_existing_db_exact_match<H: SyncTestHarness>(num_ops: usize)
where
    resolver::tests::FailResolver<OpOf<H>, Digest>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_ops = H::create_ops(num_ops);

        // Create two databases with their own configs
        let target_config = H::config(&context.next_u64().to_string());
        let mut target_db =
            H::init_db_with_config(context.with_label("target"), target_config).await;
        let sync_config = H::config(&context.next_u64().to_string());
        let client_context = context.with_label("client");
        let mut sync_db =
            H::init_db_with_config(client_context.clone(), H::clone_config(&sync_config)).await;

        // Apply the same operations to both databases
        target_db = H::apply_ops(target_db, target_ops.clone()).await;
        sync_db = H::apply_ops(sync_db, target_ops.clone()).await;
        // commit already done in apply_ops
        // commit already done in apply_ops

        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();
        sync_db.prune(sync_db.inactivity_floor_loc()).await.unwrap();

        sync_db.sync().await.unwrap();
        drop(sync_db);

        // Capture target state
        let root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.op_count();

        // sync_db should never ask the resolver for operations
        // because it is already complete. Use a resolver that always fails
        // to ensure that it's not being used.
        let resolver = resolver::tests::FailResolver::<OpOf<H>, Digest>::new();
        let config = Config {
            db_config: sync_config, // Use same config to access same partitions
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: lower_bound..upper_bound,
            },
            context: client_context.with_label("sync"),
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state
        assert_eq!(synced_db.op_count(), upper_bound);
        assert_eq!(synced_db.op_count(), target_db.op_count());
        assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);

        // Verify the root digest matches the target
        assert_eq!(synced_db.root(), root);

        // Verify state matches for sample operations (via key lookup)
        for target_op in &target_ops {
            if let Some(key) = target_op.key() {
                let target_value = target_db.get(key).await.unwrap();
                let synced_value = synced_db.get(key).await.unwrap();
                assert_eq!(target_value.is_some(), synced_value.is_some());
            }
        }

        synced_db.destroy().await.unwrap();
        target_db.destroy().await.unwrap();
    });
}

/// Test that the client fails to sync if the lower bound is decreased via target update.
pub(crate) fn test_target_update_lower_bound_decrease<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture initial target state
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.op_count();
        let initial_root = target_db.root();

        // Create client with initial target
        let (mut update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string()),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: initial_lower_bound..initial_upper_bound,
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Send target update with decreased lower bound
        update_sender
            .send(Target {
                root: initial_root,
                range: initial_lower_bound.checked_sub(1).unwrap()
                    ..initial_upper_bound.checked_add(1).unwrap(),
            })
            .await
            .unwrap();

        let result = client.step().await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(
                sync::EngineError::SyncTargetMovedBackward { .. }
            ))
        ));

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that the client fails to sync if the upper bound is decreased via target update.
pub(crate) fn test_target_update_upper_bound_decrease<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture initial target state
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.op_count();
        let initial_root = target_db.root();

        // Create client with initial target
        let (mut update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string()),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: initial_lower_bound..initial_upper_bound,
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Send target update with decreased upper bound
        update_sender
            .send(Target {
                root: initial_root,
                range: initial_lower_bound..initial_upper_bound.checked_sub(1).unwrap(),
            })
            .await
            .unwrap();

        let result = client.step().await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(
                sync::EngineError::SyncTargetMovedBackward { .. }
            ))
        ));

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that the client succeeds when bounds are updated (increased).
pub(crate) fn test_target_update_bounds_increase<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(100);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture initial target state
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.op_count();
        let initial_root = target_db.root();

        // Apply more operations to the target database
        // (use different seed to avoid key collisions)
        let additional_ops = H::create_ops_seeded(1, 1);
        let new_root = {
            target_db = H::apply_ops(target_db, additional_ops).await;
            // commit already done in apply_ops

            // Capture new target state
            let new_lower_bound = target_db.inactivity_floor_loc();
            let new_upper_bound = target_db.op_count();
            let new_root = target_db.root();

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                context: context.with_label("client"),
                db_config: H::config(&context.next_u64().to_string()),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
            };

            // Send target update with increased bounds
            update_sender
                .send(Target {
                    root: new_root,
                    range: new_lower_bound..new_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: H::Db = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected final state
            assert_eq!(synced_db.root(), new_root);
            assert_eq!(synced_db.op_count(), new_upper_bound);
            assert_eq!(synced_db.inactivity_floor_loc(), new_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();

            new_root
        };
        let _ = new_root; // Silence unused variable warning
    });
}

/// Test that the client fails to sync with invalid bounds (lower > upper) sent via target update.
pub(crate) fn test_target_update_invalid_bounds<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture initial target state
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.op_count();
        let initial_root = target_db.root();

        // Create client with initial target
        let (mut update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string()),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: initial_lower_bound..initial_upper_bound,
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Send target update with invalid range (start > end)
        update_sender
            .send(Target {
                root: initial_root,
                range: initial_upper_bound..initial_lower_bound,
            })
            .await
            .unwrap();

        let result = client.step().await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidTarget { .. }))
        ));

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that target updates can be sent even after the client is done (no panic).
pub(crate) fn test_target_update_on_done_client<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(10);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture target state
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.op_count();
        let root = target_db.root();

        // Create client with target that will complete immediately
        let (mut update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string()),
            fetch_batch_size: NZU64!(20),
            target: Target {
                root,
                range: lower_bound..upper_bound,
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
        };

        // Complete the sync
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Attempt to apply a target update after sync is complete to verify
        // we don't panic
        let _ = update_sender
            .send(Target {
                // Dummy target update
                root: Digest::from([2u8; 32]),
                range: lower_bound + 1..upper_bound + 1,
            })
            .await;

        // Verify the synced database has the expected state
        assert_eq!(synced_db.root(), root);
        assert_eq!(synced_db.op_count(), upper_bound);
        assert_eq!(synced_db.inactivity_floor_loc(), lower_bound);

        synced_db.destroy().await.unwrap();

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that the client can handle target updates during sync execution.
pub(crate) fn test_target_update_during_sync<H: SyncTestHarness>(
    initial_ops: usize,
    additional_ops: usize,
) where
    Arc<RwLock<Option<DbOf<H>>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate target database with initial operations
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(initial_ops);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture initial target state
        let initial_lower_bound = target_db.inactivity_floor_loc();
        let initial_upper_bound = target_db.op_count();
        let initial_root = target_db.root();

        // Wrap target database for shared mutable access (using Option so we can take ownership)
        let target_db = Arc::new(RwLock::new(Some(target_db)));

        // Create client with initial target and small batch size
        let (mut update_sender, update_receiver) = mpsc::channel(1);
        // Step the client to process a batch
        let client = {
            let config = Config {
                context: context.with_label("client"),
                db_config: H::config(&context.next_u64().to_string()),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                max_outstanding_requests: 10,
                apply_batch_size: 1024,
                update_rx: Some(update_receiver),
            };
            let mut client: Engine<H::Db, _> = Engine::new(config).await.unwrap();
            loop {
                // Step the client until we have processed a batch of operations
                client = match client.step().await.unwrap() {
                    NextStep::Continue(new_client) => new_client,
                    NextStep::Complete(_) => panic!("client should not be complete"),
                };
                let log_size = client.journal().size();
                if log_size > initial_lower_bound {
                    break client;
                }
            }
        };

        // Modify the target database by adding more operations
        // (use different seed to avoid key collisions)
        let additional_ops_data = H::create_ops_seeded(additional_ops, 1);
        let new_root = {
            let mut db_guard = target_db.write().await;
            let db = db_guard.take().unwrap();
            let db = H::apply_ops(db, additional_ops_data).await;

            // Capture new target state
            let new_lower_bound = db.inactivity_floor_loc();
            let new_upper_bound = db.op_count();
            let new_root = db.root();
            *db_guard = Some(db);

            // Send target update with new target
            update_sender
                .send(Target {
                    root: new_root,
                    range: new_lower_bound..new_upper_bound,
                })
                .await
                .unwrap();

            new_root
        };

        // Complete the sync
        let synced_db = client.sync().await.unwrap();

        // Verify the synced database has the expected final state
        assert_eq!(synced_db.root(), new_root);

        // Verify the target database matches the synced database
        let target_db = Arc::try_unwrap(target_db).map_or_else(
            |_| panic!("Failed to unwrap Arc - still has references"),
            |rw_lock| rw_lock.into_inner().expect("db should be present"),
        );
        {
            assert_eq!(synced_db.op_count(), target_db.op_count());
            assert_eq!(
                synced_db.inactivity_floor_loc(),
                target_db.inactivity_floor_loc()
            );
            assert_eq!(synced_db.root(), target_db.root());
        }

        synced_db.destroy().await.unwrap();
        target_db.destroy().await.unwrap();
    });
}

/// Test demonstrating that a synced database can be reopened and retain its state.
pub(crate) fn test_sync_database_persistence<H: SyncTestHarness>()
where
    Arc<RwLock<DbOf<H>>>: Resolver<Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate a simple target database
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(10);
        target_db = H::apply_ops(target_db, target_ops).await;
        // commit already done in apply_ops

        // Capture target state
        let target_root = target_db.root();
        let lower_bound = target_db.inactivity_floor_loc();
        let upper_bound = target_db.op_count();

        // Perform sync
        let db_config = H::config(&context.next_u64().to_string());
        let client_context = context.with_label("client");
        let target_db = Arc::new(RwLock::new(target_db));
        let config = Config {
            db_config: H::clone_config(&db_config),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: target_root,
                range: lower_bound..upper_bound,
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify initial sync worked
        assert_eq!(synced_db.root(), target_root);

        // Save state before dropping
        let expected_root = synced_db.root();
        let expected_op_count = synced_db.op_count();
        let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc();

        // Re-open the database
        drop(synced_db);
        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), db_config).await;

        // Verify the state is unchanged
        assert_eq!(reopened_db.root(), expected_root);
        assert_eq!(reopened_db.op_count(), expected_op_count);
        assert_eq!(
            reopened_db.inactivity_floor_loc(),
            expected_inactivity_floor_loc
        );

        // Cleanup
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .into_inner()
            .destroy()
            .await
            .unwrap();
        reopened_db.destroy().await.unwrap();
    });
}

/// Test `from_sync_result` where the database has all operations in the target range.
pub(crate) fn test_from_sync_result_nonempty_to_nonempty_exact_match<H: SyncTestHarness>()
where
    DbOf<H>: FromSyncTestable,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let db_config = H::config(&context.next_u64().to_string());
        let mut db =
            H::init_db_with_config(context.with_label("source"), H::clone_config(&db_config)).await;
        let ops = H::create_ops(100);
        db = H::apply_ops(db, ops).await;
        // commit already done in apply_ops

        let sync_lower_bound = db.inactivity_floor_loc();
        let sync_upper_bound = db.op_count();
        let target_db_op_count = db.op_count();
        let target_db_inactivity_floor_loc = db.inactivity_floor_loc();

        let pinned_nodes = db
            .pinned_nodes_at(Position::try_from(db.inactivity_floor_loc()).unwrap())
            .await;
        let (_, journal) = db.into_log_components();

        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            db_config,
            journal,
            Some(pinned_nodes),
            sync_lower_bound..sync_upper_bound,
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(sync_db.op_count(), target_db_op_count);
        assert_eq!(
            sync_db.inactivity_floor_loc(),
            target_db_inactivity_floor_loc
        );
        assert_eq!(sync_db.inactivity_floor_loc(), sync_lower_bound);

        sync_db.destroy().await.unwrap();
    });
}

/// Test `from_sync_result` where the database has some but not all operations in the target range.
pub(crate) fn test_from_sync_result_nonempty_to_nonempty_partial_match<H: SyncTestHarness>()
where
    DbOf<H>: FromSyncTestable,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    const NUM_OPS: usize = 100;
    const NUM_ADDITIONAL_OPS: usize = 5;
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate two databases.
        let mut target_db = H::init_db(context.with_label("target")).await;
        let sync_db_config = H::config(&context.next_u64().to_string());
        let client_context = context.with_label("client");
        let mut sync_db =
            H::init_db_with_config(client_context.clone(), H::clone_config(&sync_db_config)).await;
        let original_ops = H::create_ops(NUM_OPS);
        target_db = H::apply_ops(target_db, original_ops.clone()).await;
        // commit already done in apply_ops
        target_db
            .prune(target_db.inactivity_floor_loc())
            .await
            .unwrap();
        sync_db = H::apply_ops(sync_db, original_ops.clone()).await;
        // commit already done in apply_ops
        sync_db.prune(sync_db.inactivity_floor_loc()).await.unwrap();
        let sync_db_original_size = sync_db.op_count();

        // Get pinned nodes before closing the database
        let pinned_nodes =
            sync_db.pinned_nodes_from_map(Position::try_from(sync_db_original_size).unwrap());

        sync_db.sync().await.unwrap();
        drop(sync_db);

        // Add more operations to the target db
        // (use different seed to avoid key collisions)
        let more_ops = H::create_ops_seeded(NUM_ADDITIONAL_OPS, 1);
        target_db = H::apply_ops(target_db, more_ops).await;
        // commit already done in apply_ops

        // Capture target db state for comparison
        let target_db_op_count = target_db.op_count();
        let target_db_inactivity_floor_loc = target_db.inactivity_floor_loc();
        let sync_lower_bound = target_db.inactivity_floor_loc();
        let sync_upper_bound = target_db.op_count();
        let target_hash = target_db.root();

        let (mmr, journal) = target_db.into_log_components();

        // Re-open `sync_db` using from_sync_result
        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            client_context.with_label("synced"),
            sync_db_config,
            journal,
            Some(pinned_nodes),
            sync_lower_bound..sync_upper_bound,
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(sync_db.op_count(), target_db_op_count);
        assert_eq!(
            sync_db.inactivity_floor_loc(),
            target_db_inactivity_floor_loc
        );
        assert_eq!(sync_db.inactivity_floor_loc(), sync_lower_bound);

        // Verify the root digest matches the target (verifies content integrity)
        assert_eq!(sync_db.root(), target_hash);

        sync_db.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    });
}

/// Test `from_sync_result` with an empty destination database syncing to a non-empty source.
/// This tests the scenario where a sync client starts fresh with no existing data.
pub(crate) fn test_from_sync_result_empty_to_nonempty<H: SyncTestHarness>()
where
    DbOf<H>: FromSyncTestable,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    const NUM_OPS: usize = 100;
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create and populate a source database
        let mut source_db = H::init_db(context.with_label("source")).await;
        let ops = H::create_ops(NUM_OPS);
        source_db = H::apply_ops(source_db, ops).await;
        // commit already done in apply_ops
        source_db
            .prune(source_db.inactivity_floor_loc())
            .await
            .unwrap();

        let lower_bound = source_db.inactivity_floor_loc();
        let upper_bound = source_db.op_count();

        // Get pinned nodes and target hash before deconstructing source_db
        let pinned_nodes = source_db
            .pinned_nodes_at(Position::try_from(lower_bound).unwrap())
            .await;
        let target_hash = source_db.root();
        let target_op_count = source_db.op_count();
        let target_inactivity_floor = source_db.inactivity_floor_loc();

        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string());

        let db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            new_db_config,
            journal,
            Some(pinned_nodes),
            lower_bound..upper_bound,
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(db.op_count(), target_op_count);
        assert_eq!(db.inactivity_floor_loc(), target_inactivity_floor);
        assert_eq!(db.inactivity_floor_loc(), lower_bound);

        // Verify the root digest matches the target
        assert_eq!(db.root(), target_hash);

        db.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    });
}

/// Test `from_sync_result` with an empty source database syncing to an empty target database.
pub(crate) fn test_from_sync_result_empty_to_empty<H: SyncTestHarness>()
where
    DbOf<H>: FromSyncTestable,
    OpOf<H>: Encode + Clone,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Create an empty database (initialized with a single CommitFloor operation)
        let source_db = H::init_db(context.with_label("source")).await;

        // An empty database has exactly 1 operation (the initial CommitFloor)
        assert_eq!(source_db.op_count(), Location::new_unchecked(1));

        let target_hash = source_db.root();
        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string());

        let mut synced_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            new_db_config,
            journal,
            None,
            Location::new_unchecked(0)..Location::new_unchecked(1),
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(synced_db.op_count(), Location::new_unchecked(1));
        assert_eq!(synced_db.inactivity_floor_loc(), Location::new_unchecked(0));
        assert_eq!(synced_db.root(), target_hash);

        // Test that we can perform operations on the synced database
        let ops = H::create_ops(10);
        synced_db = H::apply_ops(synced_db, ops).await;

        // Verify the operations worked
        assert!(synced_db.op_count() > Location::new_unchecked(1));

        synced_db.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    });
}
