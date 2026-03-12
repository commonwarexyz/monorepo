//! Generic sync tests that work for both fixed and variable databases.
//!
//! This module provides a test harness trait and generic test functions that can be
//! parameterized to run against either fixed-size or variable-size value databases.
//! The shared functions are `pub(crate)` so that `current::sync::tests` can reuse them.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Location},
    qmdb::{
        self,
        any::traits::DbAny,
        operation::Operation as OperationTrait,
        sync::{
            self,
            engine::{Config, NextStep},
            resolver::{self, FetchResult, Resolver},
            Engine, Target,
        },
    },
    Persistable,
};
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_macros::select;
use commonware_runtime::{deterministic, BufferPooler, Clock, Metrics, Runner as _};
use commonware_utils::{
    channel::{mpsc, oneshot},
    non_empty_range,
    sync::{AsyncRwLock, Mutex},
    NZU64,
};
use futures::{pin_mut, FutureExt};
use rand::RngCore as _;
use std::{
    num::NonZeroU64,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

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
    type Family: merkle::Family;

    fn destroy(
        self,
    ) -> impl std::future::Future<Output = Result<(), qmdb::Error<Self::Family>>> + Send;
}

// Implement Destructible once for the generic full Merkle type used in tests.
// This is here (rather than in fixed/variable modules) to avoid duplicate implementations.
impl<F: merkle::Family> Destructible
    for crate::merkle::full::Merkle<F, deterministic::Context, Digest>
{
    type Family = F;

    async fn destroy(self) -> Result<(), qmdb::Error<F>> {
        self.destroy().await.map_err(qmdb::Error::Merkle)
    }
}

/// Trait providing internal access for from_sync_result tests.
pub(crate) trait FromSyncTestable: qmdb::sync::Database {
    type Merkle: Destructible<Family = Self::Family> + Send;

    /// Get the Merkle structure and journal from the database.
    fn into_log_components(self) -> (Self::Merkle, Self::Journal);

    /// Get the pinned nodes at a given location
    fn pinned_nodes_at(
        &self,
        loc: Location<Self::Family>,
    ) -> impl std::future::Future<Output = Vec<Self::Digest>> + Send;
}

/// Harness for sync tests.
pub(crate) trait SyncTestHarness: Sized + 'static {
    /// The merkle family the database under test uses.
    type Family: merkle::Family;

    /// The database type being tested.
    type Db: qmdb::sync::Database<
            Family = Self::Family,
            Context = deterministic::Context,
            Digest = Digest,
            Config: Clone,
        > + DbAny<Self::Family, Key = Digest, Digest = Digest>;

    /// Return the root the sync engine targets.
    fn sync_target_root(db: &Self::Db) -> Digest;

    /// Create a config with unique partition names
    fn config(suffix: &str, pooler: &impl BufferPooler) -> ConfigOf<Self>;

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

    /// Apply operations to a database and commit.
    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
    ) -> impl std::future::Future<Output = Self::Db> + Send;
}

/// Test that empty operations arrays fetched do not cause panics when stored and applied
pub(crate) fn test_sync_empty_operations_no_panic<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Init target_db to satisfy engine configuration bounds
        let target_db = H::init_db(context.with_label("target")).await;

        // Use an arbitrary target
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: Digest::from([1u8; 32]),
                range: non_empty_range!(Location::new(0), Location::new(10)),
            },
            context: context.with_label("client"),
            resolver: Arc::new(target_db),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        // Create the engine
        let mut client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Pass empty operations vectors which should not cause panics
        client.store_operations(Location::new(0), vec![]);
        client.store_operations(Location::new(5), vec![]);

        // Apply operations which also shouldn't panic
        client.apply_operations().await.unwrap();

        // It is considered a success simply if it didn't panic.
    });
}

/// Test that resolver failure is handled correctly
pub(crate) fn test_sync_resolver_fails<H: SyncTestHarness>()
where
    resolver::tests::FailResolver<H::Family, OpOf<H>, Digest>:
        Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let resolver = resolver::tests::FailResolver::<H::Family, OpOf<H>, Digest>::new();
        let target_root = Digest::from([0; 32]);

        let db_config = H::config(&context.next_u64().to_string(), &context);
        let engine_config = Config {
            context: context.with_label("client"),
            target: Target {
                root: target_root,
                range: non_empty_range!(Location::new(0), Location::new(5)),
            },
            resolver,
            apply_batch_size: 2,
            max_outstanding_requests: 2,
            fetch_batch_size: NZU64!(2),
            db_config,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        let result: Result<H::Db, _> = sync::sync(engine_config).await;
        assert!(result.is_err());
    });
}

/// Test that the top-level sync future remains `Send`.
pub(crate) fn test_sync_future_is_send<H: SyncTestHarness>()
where
    resolver::tests::FailResolver<H::Family, OpOf<H>, Digest>:
        Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    ConfigOf<H>: Send,
    JournalOf<H>: Contiguous,
{
    fn assert_send<T: Send>(_value: T) {}

    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let resolver = resolver::tests::FailResolver::<H::Family, OpOf<H>, Digest>::new();
        let engine_config: Config<H::Db, _> = Config {
            context: context.with_label("client"),
            target: Target {
                root: Digest::from([0; 32]),
                range: non_empty_range!(Location::new(0), Location::new(5)),
            },
            resolver,
            apply_batch_size: 2,
            max_outstanding_requests: 2,
            fetch_batch_size: NZU64!(2),
            db_config: H::config(&context.next_u64().to_string(), &context),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        assert_send(sync::sync(engine_config));
    });
}

/// Test basic sync functionality with various batch sizes
pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
            .prune(target_db.sync_boundary().await)
            .await
            .unwrap();

        let target_op_count = target_db.bounds().await.end;
        let target_inactivity_floor = target_db.inactivity_floor_loc().await;
        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary().await;

        // Configure sync
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let target_db = Arc::new(target_db);
        let client_context = context.with_label("client");
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size,
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, target_op_count),
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        // Perform sync
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state (root hash is the key verification)
        assert_eq!(synced_db.bounds().await.end, target_op_count);
        assert_eq!(
            synced_db.inactivity_floor_loc().await,
            target_inactivity_floor
        );
        assert_eq!(synced_db.root(), verification_root);

        // Verify persistence
        let final_root = synced_db.root();
        let final_op_count = synced_db.bounds().await.end;
        let final_inactivity_floor = synced_db.inactivity_floor_loc().await;

        // Reopen and verify state persisted
        drop(synced_db);
        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), db_config).await;
        assert_eq!(reopened_db.bounds().await.end, final_op_count);
        assert_eq!(
            reopened_db.inactivity_floor_loc().await,
            final_inactivity_floor
        );
        assert_eq!(reopened_db.root(), final_root);

        // Cleanup
        reopened_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test syncing to a subset of the target database (target has additional ops beyond sync range)
pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>(target_db_ops: usize)
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<H::Family, Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(target_db_ops);

        // Apply all but the last operation
        target_db = H::apply_ops(target_db, target_ops[0..target_db_ops - 1].to_vec()).await;
        // commit already done in apply_ops

        let upper_bound = target_db.bounds().await.end;
        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary().await;

        // Add another operation after the sync range
        let final_op = target_ops[target_db_ops - 1].clone();
        let final_key = final_op.key().cloned(); // Store the key before applying
        target_db = H::apply_ops(target_db, vec![final_op]).await;
        // commit already done in apply_ops

        // Sync to the original root (before final_op was added)
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.with_label("client"),
            resolver: Arc::new(target_db),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify the synced database has the correct range of operations
        assert_eq!(synced_db.sync_boundary().await, lower_bound);
        assert_eq!(synced_db.bounds().await.end, upper_bound);

        // Verify the final root digest matches our target
        assert_eq!(synced_db.root(), verification_root);

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
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<H::Family, Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let original_ops_data = H::create_ops(original_ops);

        // Create two databases
        let mut target_db = H::init_db(context.with_label("target")).await;
        let sync_db_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.with_label("client");
        let mut sync_db: H::Db =
            H::init_db_with_config(client_context.clone(), sync_db_config.clone()).await;

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

        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;

        // Reopen the sync database and sync it to the target database
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: sync_db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: client_context.with_label("sync"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state
        let bounds = synced_db.bounds().await;
        assert_eq!(bounds.end, upper_bound);
        assert_eq!(
            synced_db.inactivity_floor_loc().await,
            target_db.inactivity_floor_loc().await
        );
        assert_eq!(bounds.end, target_db.bounds().await.end);
        // Verify the root digest matches the target
        assert_eq!(synced_db.root(), verification_root);

        // Verify that original operations are present and correct (by key lookup)
        for target_op in &original_ops_data {
            if let Some(key) = target_op.key() {
                let target_value = target_db.get(key).await.unwrap();
                let synced_value = synced_db.get(key).await.unwrap();
                assert_eq!(target_value.is_some(), synced_value.is_some());
            }
        }

        // Verify the last operation is present (if it's an update)
        if let Some(key) = more_ops[0].key() {
            let synced_value = synced_db.get(key).await.unwrap();
            let target_value = target_db.get(key).await.unwrap();
            assert_eq!(synced_value.is_some(), target_value.is_some());
        }

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test case where existing database on disk exactly matches the sync target.
/// Uses FailResolver to verify that no network requests are made since data already exists.
pub(crate) fn test_sync_use_existing_db_exact_match<H: SyncTestHarness>(num_ops: usize)
where
    resolver::tests::FailResolver<H::Family, OpOf<H>, Digest>:
        Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode + Clone + OperationTrait<H::Family, Key = Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_ops = H::create_ops(num_ops);

        // Create two databases with their own configs
        let target_config = H::config(&context.next_u64().to_string(), &context);
        let mut target_db =
            H::init_db_with_config(context.with_label("target"), target_config).await;
        let sync_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.with_label("client");
        let mut sync_db = H::init_db_with_config(client_context.clone(), sync_config.clone()).await;

        // Apply the same operations to both databases
        target_db = H::apply_ops(target_db, target_ops.clone()).await;
        sync_db = H::apply_ops(sync_db, target_ops.clone()).await;
        // commit already done in apply_ops
        // commit already done in apply_ops

        target_db
            .prune(target_db.sync_boundary().await)
            .await
            .unwrap();
        sync_db.prune(sync_db.sync_boundary().await).await.unwrap();

        sync_db.sync().await.unwrap();
        drop(sync_db);

        // Capture target state
        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;

        // sync_db should never ask the resolver for operations
        // because it is already complete. Use a resolver that always fails
        // to ensure that it's not being used.
        let resolver = resolver::tests::FailResolver::<H::Family, OpOf<H>, Digest>::new();
        let config = Config {
            db_config: sync_config, // Use same config to access same partitions
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: client_context.with_label("sync"),
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify database state
        let bounds = synced_db.bounds().await;
        assert_eq!(bounds.end, upper_bound);
        assert_eq!(bounds.end, target_db.bounds().await.end);
        assert_eq!(synced_db.sync_boundary().await, lower_bound);

        // Verify the root digest matches the target
        assert_eq!(synced_db.root(), verification_root);

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
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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

        // Use inactivity_floor as range.start so we have a non-zero bound to decrement.
        // The engine only checks that range.start does not decrease on updates; it doesn't
        // require range.start to equal sync_boundary here.
        let initial_lower_bound = target_db.inactivity_floor_loc().await;
        assert!(
            *initial_lower_bound > 0,
            "test setup requires non-zero inactivity floor"
        );
        let initial_upper_bound = target_db.bounds().await.end;
        let initial_root = H::sync_target_root(&target_db);

        // Create client with initial target
        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
            progress_tx: None,
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Send target update with decreased lower bound
        update_sender
            .send(Target {
                root: initial_root,
                range: non_empty_range!(
                    initial_lower_bound.checked_sub(1).unwrap(),
                    initial_upper_bound.checked_add(1).unwrap()
                ),
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
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that the client fails to sync if the upper bound is decreased via target update.
pub(crate) fn test_target_update_upper_bound_decrease<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
        let initial_lower_bound = target_db.sync_boundary().await;
        let initial_upper_bound = target_db.bounds().await.end;
        let initial_root = H::sync_target_root(&target_db);

        // Create client with initial target
        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
            progress_tx: None,
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        // Send target update with decreased upper bound
        update_sender
            .send(Target {
                root: initial_root,
                range: non_empty_range!(
                    initial_lower_bound,
                    initial_upper_bound.checked_sub(1).unwrap()
                ),
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
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that the client succeeds when bounds are updated (increased).
pub(crate) fn test_target_update_bounds_increase<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
        let initial_lower_bound = target_db.sync_boundary().await;
        let initial_upper_bound = target_db.bounds().await.end;
        let initial_root = H::sync_target_root(&target_db);

        // Apply more operations to the target database
        // (use different seed to avoid key collisions)
        let additional_ops = H::create_ops_seeded(1, 1);
        let new_verification_root = {
            target_db = H::apply_ops(target_db, additional_ops).await;
            // commit already done in apply_ops

            // Capture new target state
            let new_lower_bound = target_db.sync_boundary().await;
            let new_upper_bound = target_db.bounds().await.end;
            let new_sync_root = H::sync_target_root(&target_db);
            let new_verification_root = target_db.root();

            // Create client with placeholder initial target (stale compared to final target)
            let (update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(target_db);
            let config = Config {
                context: context.with_label("client"),
                db_config: H::config(&context.next_u64().to_string(), &context),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
                progress_tx: None,
            };

            // Send target update with increased bounds
            update_sender
                .send(Target {
                    root: new_sync_root,
                    range: non_empty_range!(new_lower_bound, new_upper_bound),
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: H::Db = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected final state
            assert_eq!(synced_db.root(), new_verification_root);
            assert_eq!(synced_db.bounds().await.end, new_upper_bound);
            assert_eq!(synced_db.sync_boundary().await, new_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .destroy()
                .await
                .unwrap();

            new_verification_root
        };
        let _ = new_verification_root; // Silence unused variable warning
    });
}

/// Test that target updates can be sent even after the client is done (no panic).
pub(crate) fn test_target_update_on_done_client<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;
        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();

        // Create client with target that will complete immediately
        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(20),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
            progress_tx: None,
        };

        // Complete the sync
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Attempt to apply a target update after sync is complete to verify
        // we don't panic
        let _ = update_sender
            .send(Target {
                // Dummy target update
                root: Digest::from([2u8; 32]),
                range: non_empty_range!(lower_bound + 1, upper_bound + 1),
            })
            .await;

        // Verify the synced database has the expected state
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.bounds().await.end, upper_bound);
        assert_eq!(synced_db.sync_boundary().await, lower_bound);

        synced_db.destroy().await.unwrap();

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that prune-only target updates are rejected when the authenticated state does not advance.
pub(crate) fn test_target_update_prune_only_rejected<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(50)).await;

        let initial_lower_bound = target_db.inactivity_floor_loc().await;
        assert!(
            *initial_lower_bound > 1,
            "test setup requires lower bound that can advance twice"
        );
        let upper_bound = target_db.bounds().await.end;
        let root = H::sync_target_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(2);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root,
                range: non_empty_range!(initial_lower_bound, upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        let first_target = Target {
            root,
            range: non_empty_range!(initial_lower_bound.checked_add(1).unwrap(), upper_bound),
        };
        let second_target = Target {
            root,
            range: non_empty_range!(initial_lower_bound.checked_add(2).unwrap(), upper_bound),
        };
        update_sender.send(first_target).await.unwrap();
        update_sender.send(second_target).await.unwrap();

        match client.step().await {
            Err(sync::Error::Engine(sync::EngineError::SyncTargetRootUnchanged)) => {}
            Err(err) => panic!("expected SyncTargetRootUnchanged, got {err:?}"),
            Ok(_) => panic!("prune-only update should be rejected"),
        }

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that explicit finish control waits for a finish signal even after reaching target.
pub(crate) fn test_sync_waits_for_explicit_finish<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10)).await;
        let initial_target = Target {
            root: H::sync_target_root(&target_db),
            range: non_empty_range!(
                target_db.sync_boundary().await,
                target_db.bounds().await.end
            ),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(5, 1)).await;
        let updated_lower_bound = target_db.sync_boundary().await;
        let updated_upper_bound = target_db.bounds().await.end;
        let updated_target = Target {
            root: H::sync_target_root(&target_db),
            range: non_empty_range!(updated_lower_bound, updated_upper_bound),
        };
        let updated_verification_root = target_db.root();

        let (update_sender, update_receiver) = mpsc::channel(1);
        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let (reached_sender, mut reached_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(10),
            target: initial_target.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: Some(update_receiver),
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 0,
            progress_tx: None,
        };

        let sync_handle = sync::sync(config);
        pin_mut!(sync_handle);

        select! {
            _ = sync_handle.as_mut() => {
                panic!("sync completed before explicit finish signal");
            },
            reached = reached_receiver.recv() => {
                let reached = reached.expect("engine should report reached-target before finish");
                assert_eq!(reached, initial_target);
            },
        }
        assert!(
            sync_handle.as_mut().now_or_never().is_none(),
            "sync must wait for explicit finish signal after reaching target"
        );

        update_sender
            .send(updated_target.clone())
            .await
            .expect("target update channel should be open");

        select! {
            _ = sync_handle.as_mut() => {
                panic!("sync completed before explicit finish signal for updated target");
            },
            reached = reached_receiver.recv() => {
                let reached = reached.expect("engine should report updated target before finish");
                assert_eq!(reached, updated_target);
            },
        }
        assert!(
            sync_handle.as_mut().now_or_never().is_none(),
            "sync must still wait for explicit finish signal after updated target is reached"
        );

        finish_sender
            .send(())
            .await
            .expect("finish signal channel should be open");

        let synced_db: H::Db = sync_handle
            .await
            .expect("sync should succeed after finish signal");
        assert_eq!(synced_db.root(), updated_verification_root);
        assert_eq!(synced_db.bounds().await.end, updated_upper_bound);
        assert_eq!(synced_db.sync_boundary().await, updated_lower_bound);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that a finish signal received before target completion still allows full sync.
pub(crate) fn test_sync_handles_early_finish_signal<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(30)).await;
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;
        let target = Target {
            root: H::sync_target_root(&target_db),
            range: non_empty_range!(lower_bound, upper_bound),
        };
        let verification_root = target_db.root();

        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let (reached_sender, mut reached_receiver) = mpsc::channel(1);
        finish_sender
            .send(())
            .await
            .expect("finish signal channel should be open");

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(3),
            target: target.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
            progress_tx: None,
        };

        let synced_db: H::Db = sync::sync(config)
            .await
            .expect("sync should complete after early finish signal");
        let reached = reached_receiver
            .recv()
            .await
            .expect("engine should report reached-target");

        assert_eq!(reached, target);
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.bounds().await.end, upper_bound);
        assert_eq!(synced_db.sync_boundary().await, lower_bound);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that dropping finish sender without sending is treated as an error.
pub(crate) fn test_sync_fails_when_finish_sender_dropped<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10)).await;
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;

        let (finish_sender, finish_receiver) = mpsc::channel(1);
        drop(finish_sender);

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: H::sync_target_root(&target_db),
                range: non_empty_range!(lower_bound, upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: Some(finish_receiver),
            reached_target_tx: None,
            max_retained_roots: 1,
            progress_tx: None,
        };

        let result: Result<H::Db, _> = sync::sync(config).await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::FinishChannelClosed))
        ));

        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

/// Test that dropping reached-target receiver does not fail sync.
pub(crate) fn test_sync_allows_dropped_reached_target_receiver<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10)).await;
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;
        let verification_root = target_db.root();

        let (reached_sender, reached_receiver) = mpsc::channel(1);
        drop(reached_receiver);

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: H::sync_target_root(&target_db),
                range: non_empty_range!(lower_bound, upper_bound),
            },
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
            progress_tx: None,
        };

        let synced_db: H::Db = sync::sync(config)
            .await
            .expect("sync should succeed when reached-target receiver is dropped");
        assert_eq!(synced_db.root(), verification_root);
        assert_eq!(synced_db.bounds().await.end, upper_bound);
        assert_eq!(synced_db.sync_boundary().await, lower_bound);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
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
    Arc<AsyncRwLock<Option<DbOf<H>>>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
        let initial_lower_bound = target_db.sync_boundary().await;
        let initial_upper_bound = target_db.bounds().await.end;
        let initial_sync_root = H::sync_target_root(&target_db);

        // Wrap target database for shared mutable access (using Option so we can take ownership)
        let target_db = Arc::new(AsyncRwLock::new(Some(target_db)));

        // Create client with initial target and small batch size
        let (update_sender, update_receiver) = mpsc::channel(1);
        // Step the client to process a batch
        let client = {
            let config = Config {
                context: context.with_label("client"),
                db_config: H::config(&context.next_u64().to_string(), &context),
                target: Target {
                    root: initial_sync_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                max_outstanding_requests: 10,
                apply_batch_size: 1024,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
                progress_tx: None,
            };
            let mut client: Engine<H::Db, _> = Engine::new(config).await.unwrap();
            loop {
                // Step the client until we have processed a batch of operations
                client = match client.step().await.unwrap() {
                    NextStep::Continue(new_client) => new_client,
                    NextStep::Complete(_) => panic!("client should not be complete"),
                };
                let log_size = client.journal().size().await;
                if log_size > initial_lower_bound {
                    break client;
                }
            }
        };

        // Modify the target database by adding more operations
        // (use different seed to avoid key collisions)
        let additional_ops_data = H::create_ops_seeded(additional_ops, 1);
        let new_verification_root = {
            let mut db_guard = target_db.write().await;
            let db = db_guard.take().unwrap();
            let db = H::apply_ops(db, additional_ops_data).await;

            // Capture new target state
            let new_lower_bound = db.sync_boundary().await;
            let new_upper_bound = db.bounds().await.end;
            let new_sync_root = H::sync_target_root(&db);
            let new_verification_root = db.root();
            *db_guard = Some(db);

            // Send target update with new target
            update_sender
                .send(Target {
                    root: new_sync_root,
                    range: non_empty_range!(new_lower_bound, new_upper_bound),
                })
                .await
                .unwrap();

            new_verification_root
        };

        // Complete the sync
        let synced_db = client.sync().await.unwrap();

        // Verify the synced database has the expected final state
        assert_eq!(synced_db.root(), new_verification_root);

        // Verify the target database matches the synced database
        let target_db = Arc::try_unwrap(target_db).map_or_else(
            |_| panic!("Failed to unwrap Arc - still has references"),
            |rw_lock| rw_lock.into_inner().expect("db should be present"),
        );
        {
            let synced_bounds = synced_db.bounds().await;
            let target_bounds = target_db.bounds().await;
            assert_eq!(synced_bounds.end, target_bounds.end);
            assert_eq!(
                synced_db.inactivity_floor_loc().await,
                target_db.inactivity_floor_loc().await
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
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
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
        let sync_root = H::sync_target_root(&target_db);
        let verification_root = target_db.root();
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;

        // Perform sync
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.with_label("client");
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: client_context.clone(),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        // Verify initial sync worked
        assert_eq!(synced_db.root(), verification_root);

        // Save state before dropping
        let expected_root = synced_db.root();
        let expected_op_count = synced_db.bounds().await.end;
        let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc().await;

        // Re-open the database
        drop(synced_db);
        let reopened_db =
            H::init_db_with_config(client_context.with_label("reopened"), db_config).await;

        // Verify the state is unchanged
        assert_eq!(reopened_db.root(), expected_root);
        assert_eq!(reopened_db.bounds().await.end, expected_op_count);
        assert_eq!(
            reopened_db.inactivity_floor_loc().await,
            expected_inactivity_floor_loc
        );

        // Cleanup
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
        reopened_db.destroy().await.unwrap();
    });
}

/// Test post-sync usability: after syncing, the database supports normal operations.
pub(crate) fn test_sync_post_sync_usability<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops).await;

        let sync_root = H::sync_target_root(&target_db);
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;
        let target_db = Arc::new(target_db);

        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(100),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.with_label("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        let root_after_sync = synced_db.root();

        // Apply additional operations after sync.
        let more_ops = H::create_ops_seeded(10, 1);
        let synced_db = H::apply_ops(synced_db, more_ops).await;

        // Root should change after applying more ops.
        assert_ne!(synced_db.root(), root_after_sync);
        assert!(synced_db.bounds().await.end > upper_bound);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
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
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let mut db = H::init_db_with_config(context.with_label("source"), db_config.clone()).await;
        let ops = H::create_ops(100);
        db = H::apply_ops(db, ops).await;
        // commit already done in apply_ops

        let sync_lower_bound = db.sync_boundary().await;
        let bounds = db.bounds().await;
        let sync_upper_bound = bounds.end;
        let target_db_op_count = bounds.end;
        let target_db_inactivity_floor_loc = db.inactivity_floor_loc().await;

        let pinned_nodes = db.pinned_nodes_at(sync_lower_bound).await;
        let (_, journal) = db.into_log_components();

        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(sync_lower_bound, sync_upper_bound),
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(sync_db.bounds().await.end, target_db_op_count);
        assert_eq!(
            sync_db.inactivity_floor_loc().await,
            target_db_inactivity_floor_loc
        );
        assert_eq!(sync_db.sync_boundary().await, sync_lower_bound);

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
        let sync_db_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.with_label("client");
        let mut sync_db =
            H::init_db_with_config(client_context.clone(), sync_db_config.clone()).await;
        let original_ops = H::create_ops(NUM_OPS);
        target_db = H::apply_ops(target_db, original_ops.clone()).await;
        // commit already done in apply_ops
        target_db
            .prune(target_db.sync_boundary().await)
            .await
            .unwrap();
        sync_db = H::apply_ops(sync_db, original_ops.clone()).await;
        // commit already done in apply_ops
        sync_db.prune(sync_db.sync_boundary().await).await.unwrap();
        sync_db.sync().await.unwrap();
        drop(sync_db);

        // Add more operations to the target db
        // (use different seed to avoid key collisions)
        let more_ops = H::create_ops_seeded(NUM_ADDITIONAL_OPS, 1);
        target_db = H::apply_ops(target_db, more_ops).await;
        // commit already done in apply_ops

        // Capture target db state for comparison
        let bounds = target_db.bounds().await;
        let target_db_op_count = bounds.end;
        let target_db_inactivity_floor_loc = target_db.inactivity_floor_loc().await;
        let sync_lower_bound = target_db.sync_boundary().await;
        let sync_upper_bound = bounds.end;
        let target_hash = target_db.root();

        // Get pinned nodes at the sync lower bound from the target db (which has all the data).
        let pinned_nodes = target_db.pinned_nodes_at(sync_lower_bound).await;

        let (mmr, journal) = target_db.into_log_components();

        // Re-open `sync_db` using from_sync_result
        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            client_context.with_label("synced"),
            sync_db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(sync_lower_bound, sync_upper_bound),
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(sync_db.bounds().await.end, target_db_op_count);
        assert_eq!(
            sync_db.inactivity_floor_loc().await,
            target_db_inactivity_floor_loc
        );
        assert_eq!(sync_db.sync_boundary().await, sync_lower_bound);

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
            .prune(source_db.sync_boundary().await)
            .await
            .unwrap();

        let lower_bound = source_db.sync_boundary().await;
        let upper_bound = source_db.bounds().await.end;

        // Get pinned nodes and target hash before deconstructing source_db
        let pinned_nodes = source_db.pinned_nodes_at(lower_bound).await;
        let target_hash = source_db.root();
        let target_op_count = source_db.bounds().await.end;
        let target_inactivity_floor = source_db.inactivity_floor_loc().await;

        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string(), &context);

        let db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            new_db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(lower_bound, upper_bound),
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(db.bounds().await.end, target_op_count);
        assert_eq!(db.inactivity_floor_loc().await, target_inactivity_floor);
        assert_eq!(db.sync_boundary().await, lower_bound);

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
        assert_eq!(source_db.bounds().await.end, Location::new(1));

        let target_hash = source_db.root();
        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string(), &context);

        let mut synced_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.with_label("synced"),
            new_db_config,
            journal,
            None,
            non_empty_range!(Location::new(0), Location::new(1)),
            1024,
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(synced_db.bounds().await.end, Location::new(1));
        assert_eq!(synced_db.inactivity_floor_loc().await, Location::new(0));
        assert_eq!(synced_db.root(), target_hash);

        // Test that we can perform operations on the synced database
        let ops = H::create_ops(10);
        synced_db = H::apply_ops(synced_db, ops).await;

        // Verify the operations worked
        assert!(synced_db.bounds().await.end > Location::new(1));

        synced_db.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    });
}

/// A resolver wrapper that corrupts pinned nodes on the first request, then returns correct
/// data on subsequent requests.
#[derive(Clone)]
struct CorruptFirstPinnedNodesResolver<R> {
    inner: R,
    corrupted: Arc<std::sync::atomic::AtomicBool>,
}

impl<R> Resolver for CorruptFirstPinnedNodesResolver<R>
where
    R: Resolver<Digest = Digest>,
{
    type Family = R::Family;
    type Digest = Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let mut result = self
            .inner
            .get_operations(
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                cancel_rx,
            )
            .await?;
        // Corrupt pinned nodes only on the first request that includes them.
        if result.pinned_nodes.is_some()
            && !self
                .corrupted
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            if let Some(ref mut nodes) = result.pinned_nodes {
                if !nodes.is_empty() {
                    nodes[0] = Digest::from([0xFFu8; 32]);
                }
            }
        }
        Ok(result)
    }
}

/// Test that corrupted pinned nodes on the first attempt are rejected and the sync
/// succeeds on retry when the resolver returns correct data.
pub(crate) fn test_sync_retries_bad_pinned_nodes<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Build a target database with some operations and prune so that pinned nodes are needed.
        let mut target_db = H::init_db(context.with_label("target")).await;
        let ops = H::create_ops(20);
        target_db = H::apply_ops(target_db, ops).await;
        target_db
            .prune(target_db.sync_boundary().await)
            .await
            .unwrap();

        let sync_root = H::sync_target_root(&target_db);
        let lower_bound = target_db.sync_boundary().await;
        let upper_bound = target_db.bounds().await.end;

        let db_config = H::config(&context.next_u64().to_string(), &context);

        let resolver = CorruptFirstPinnedNodesResolver {
            inner: Arc::new(target_db),
            corrupted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        let config = sync::engine::Config {
            db_config,
            fetch_batch_size: NZU64!(100),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.with_label("client"),
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
        };

        // Sync should succeed on the second attempt after the first corrupted pinned nodes
        // are rejected.
        let synced_db: H::Db = sync::sync(config).await.unwrap();
        assert_eq!(synced_db.root(), sync_root);
        synced_db.destroy().await.unwrap();
    });
}

/// A resolver wrapper that replays the first fresh boundary request against the retained
/// historical root, then blocks the retry until the test releases it.
#[derive(Clone)]
struct ReplayFreshBoundaryResolver<R: Resolver<Digest = Digest>> {
    inner: R,
    historical_target_size: Location<R::Family>,
    boundary_start: Location<R::Family>,
    release_historical_gap: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    release_boundary_retry: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    boundary_attempts: Arc<AtomicUsize>,
}

impl<R: Resolver<Digest = Digest>> Resolver for ReplayFreshBoundaryResolver<R> {
    type Family = R::Family;
    type Digest = Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        if op_count == self.historical_target_size {
            if include_pinned_nodes {
                let _ = cancel_rx.await;
                return self
                    .inner
                    .get_operations(
                        op_count,
                        start_loc,
                        max_ops,
                        include_pinned_nodes,
                        oneshot::channel().1,
                    )
                    .await;
            }

            let release = self.release_historical_gap.lock().take();
            if let Some(release) = release {
                let _ = release.await;
            }
        }

        if include_pinned_nodes && start_loc == self.boundary_start {
            let attempt = self.boundary_attempts.fetch_add(1, Ordering::Relaxed);
            if attempt == 0 {
                let mut result = self
                    .inner
                    .get_operations(
                        self.historical_target_size,
                        start_loc,
                        max_ops,
                        false,
                        oneshot::channel().1,
                    )
                    .await?;
                result.pinned_nodes = None;
                return Ok(result);
            }

            let release = self.release_boundary_retry.lock().take();
            if let Some(release) = release {
                let _ = release.await;
            }
        }

        self.inner
            .get_operations(
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                cancel_rx,
            )
            .await
    }
}

/// Test that reaching the journal target does not report completion while the pruned
/// boundary retry is still outstanding.
pub(crate) fn test_sync_waits_for_boundary_retry_after_target_update<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = Digest>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.with_label("target")).await;

        let mut seed = 0;
        loop {
            target_db = H::apply_ops(target_db, H::create_ops_seeded(32, seed)).await;
            target_db
                .prune(target_db.sync_boundary().await)
                .await
                .unwrap();

            if target_db.inactivity_floor_loc().await > Location::new(0) {
                break;
            }

            seed += 1;
            assert!(seed < 8, "expected prune floor to advance");
        }

        let old_target = Target {
            root: H::sync_target_root(&target_db),
            range: non_empty_range!(
                target_db.inactivity_floor_loc().await,
                target_db.bounds().await.end
            ),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(3, seed + 1)).await;
        let new_target = Target {
            root: H::sync_target_root(&target_db),
            range: non_empty_range!(
                target_db.inactivity_floor_loc().await,
                target_db.bounds().await.end
            ),
        };
        let verification_root = target_db.root();

        assert!(old_target.range.start() > Location::new(0));
        assert!(new_target.range.end() > old_target.range.end());

        let (release_historical_gap_tx, release_historical_gap_rx) = oneshot::channel();
        let (release_boundary_retry_tx, release_boundary_retry_rx) = oneshot::channel();
        let target_db = Arc::new(target_db);
        let resolver = ReplayFreshBoundaryResolver {
            inner: target_db.clone(),
            historical_target_size: old_target.range.end(),
            boundary_start: new_target.range.start(),
            release_historical_gap: Arc::new(Mutex::new(Some(release_historical_gap_rx))),
            release_boundary_retry: Arc::new(Mutex::new(Some(release_boundary_retry_rx))),
            boundary_attempts: Arc::new(AtomicUsize::new(0)),
        };

        let (update_sender, update_receiver) = mpsc::channel(1);
        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let (reached_sender, mut reached_receiver) = mpsc::channel(1);

        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(1),
            target: old_target.clone(),
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: 2,
            update_rx: Some(update_receiver),
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
            progress_tx: None,
        };

        let mut engine: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        update_sender.send(new_target.clone()).await.unwrap();
        finish_sender.send(()).await.unwrap();

        engine = match engine.step().await.unwrap() {
            NextStep::Continue(engine) => engine,
            NextStep::Complete(_) => panic!("target update should not complete sync"),
        };

        let _ = release_historical_gap_tx.send(());

        let journal_start = engine.journal().size().await;
        for step_idx in 0..4 {
            let next_step = engine.step();
            pin_mut!(next_step);

            select! {
                result = next_step.as_mut() => {
                    engine = match result.unwrap() {
                        NextStep::Continue(engine) => engine,
                        NextStep::Complete(_) => panic!("boundary retry should still be required"),
                    };
                    assert_eq!(
                        engine.journal().size().await,
                        journal_start,
                        "replayed fresh boundary responses must not advance the journal"
                    );
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!(
                        "engine should keep processing fetch results while the boundary retry is blocked: step={step_idx}"
                    );
                },
            }
        }
        assert!(
            reached_receiver.recv().now_or_never().is_none(),
            "engine should not report reached-target while boundary state is missing"
        );

        let _ = release_boundary_retry_tx.send(());

        let synced_db = engine.sync().await.unwrap();

        let reached = reached_receiver.recv().await.unwrap();
        assert_eq!(reached, new_target);
        assert_eq!(synced_db.root(), verification_root);

        synced_db.destroy().await.unwrap();
        Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
            .destroy()
            .await
            .unwrap();
    });
}

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
        ) -> crate::qmdb::any::FixedConfig<TwoCap> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
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
            config: crate::qmdb::any::FixedConfig<TwoCap>,
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
        ) -> crate::qmdb::any::FixedConfig<TwoCap> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
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
            config: crate::qmdb::any::FixedConfig<TwoCap>,
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
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
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
            config: crate::qmdb::any::FixedConfig<TwoCap>,
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
        >;

        fn sync_target_root(db: &Self::Db) -> Digest {
            db.root()
        }

        fn config(
            suffix: &str,
            pooler: &impl BufferPooler,
        ) -> crate::qmdb::any::FixedConfig<TwoCap> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
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
            config: crate::qmdb::any::FixedConfig<TwoCap>,
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

            #[test]
            fn test_sync_future_is_send() {
                super::test_sync_future_is_send::<$harness>();
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
