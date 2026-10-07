//! Sync tests for [`crate::qmdb::any`] databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for `any` databases and adds `any`-specific tests, some of which
//! the [`crate::qmdb::current`] sync tests also run.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Location},
    qmdb::{
        self,
        sync::{
            self, Engine, Feedback, Target,
            engine::{Config, NextStep},
            harness::{DbOf, JournalOf, OpOf, SyncTestHarness},
            source::{self, Request, Response, Source},
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_macros::select;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{
    NZU64,
    channel::{mpsc, oneshot},
    non_empty_range,
    sync::{AsyncRwLock, Mutex},
};
use futures::{FutureExt, pin_mut};
use rand::Rng as _;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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
    for crate::merkle::full::Merkle<
        F,
        deterministic::Context,
        Digest,
        commonware_parallel::Sequential,
    >
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

// ===== Any-specific tests =====

/// Test that empty operations arrays fetched do not cause panics when stored and applied
pub(crate) fn test_sync_empty_operations_no_panic<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Init target_db to satisfy engine configuration bounds
        let target_db = H::init_db(context.child("target")).await;

        // Use an arbitrary target
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: Digest::from([1u8; 32]),
                range: non_empty_range!(Location::new(0), Location::new(10)),
            },
            context: context.child("client"),
            source: Arc::new(target_db),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
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

/// Test that prune-only target updates (same end, larger start) are ignored.
pub(crate) fn test_target_update_prune_only_ignored<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(50), None).await;

        let initial_lower_bound = H::inactivity_floor_loc(&target_db);
        assert!(
            *initial_lower_bound > 1,
            "test setup requires lower bound that can advance twice"
        );
        let upper_bound = H::bounds(&target_db).end;
        let root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(2);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root,
                range: non_empty_range!(initial_lower_bound, upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
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

        // The non-advancing update is discarded and the sync completes at the original target.
        let synced_db: H::Db = client.sync().await.unwrap();
        assert_eq!(H::canonical_root(&synced_db), H::canonical_root(&target_db));
        H::destroy(synced_db).await;

        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Test that explicit finish control waits for a finish signal even after reaching target.
pub(crate) fn test_sync_waits_for_explicit_finish<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10), None).await;
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(H::sync_boundary(&target_db), H::bounds(&target_db).end),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(5, 1), None).await;
        let updated_lower_bound = H::sync_boundary(&target_db);
        let updated_upper_bound = H::bounds(&target_db).end;
        let updated_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(updated_lower_bound, updated_upper_bound),
        };
        let updated_verification_root = H::canonical_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let (reached_sender, mut reached_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(10),
            target: initial_target.clone(),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: Some(update_receiver),
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 0,
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
        assert_eq!(H::canonical_root(&synced_db), updated_verification_root);
        assert_eq!(H::bounds(&synced_db).end, updated_upper_bound);
        assert_eq!(H::sync_boundary(&synced_db), updated_lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

async fn wait_for_reached_progress<F: merkle::Family>(
    context: deterministic::Context,
    target: &Target<F, Digest>,
) {
    let target_size = *target.range.end();
    let size = format!("client_sync_size {target_size}");
    let target_size = format!("client_sync_target_size {target_size}");
    loop {
        let metrics = context.encode();
        if metrics.contains(&size) && metrics.contains(&target_size) {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
}

/// Test progress metrics for reached targets across target updates and explicit finish.
pub(crate) fn test_sync_reports_progress_for_reached_targets_before_explicit_finish<
    H: SyncTestHarness,
>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;

        target_db = H::apply_ops(target_db, H::create_ops(8), None).await;
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(
                H::sync_boundary(&target_db),
                H::bounds(&target_db).end
            ),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(5, 1), None).await;
        let first_update = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(
                H::sync_boundary(&target_db),
                H::bounds(&target_db).end
            ),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(5, 2), None).await;
        let second_update = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(
                H::sync_boundary(&target_db),
                H::bounds(&target_db).end
            ),
        };
        let final_root = H::canonical_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(2),
            target: initial_target.clone(),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: Some(update_receiver),
            finish_rx: Some(finish_receiver),
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        let sync_handle = sync::sync(config);
        pin_mut!(sync_handle);

        select! {
            _ = sync_handle.as_mut() => {
                panic!("sync completed before explicit finish signal");
            },
            _ = wait_for_reached_progress(context.child("storage"), &initial_target) => {},
        }
        assert!(
            sync_handle.as_mut().now_or_never().is_none(),
            "sync must wait for a target update or explicit finish after reaching the initial target"
        );

        update_sender
            .send(first_update.clone())
            .await
            .expect("target update channel should be open");
        select! {
            _ = sync_handle.as_mut() => {
                panic!("sync completed before explicit finish signal after first update");
            },
            _ = wait_for_reached_progress(context.child("storage"), &first_update) => {},
        }
        assert!(
            sync_handle.as_mut().now_or_never().is_none(),
            "sync must wait for another update or explicit finish after reaching the first update"
        );

        update_sender
            .send(second_update.clone())
            .await
            .expect("target update channel should be open");
        select! {
            _ = sync_handle.as_mut() => {
                panic!("sync completed before explicit finish signal after second update");
            },
            _ = wait_for_reached_progress(context.child("storage"), &second_update) => {},
        }
        assert!(
            sync_handle.as_mut().now_or_never().is_none(),
            "sync must wait for explicit finish after reporting final progress"
        );

        finish_sender
            .send(())
            .await
            .expect("finish signal channel should be open");

        let synced_db: H::Db = sync_handle
            .await
            .expect("sync should succeed after finish signal");
        assert_eq!(H::canonical_root(&synced_db), final_root);
        assert_eq!(H::bounds(&synced_db).end, *second_update.range.end());
        assert_eq!(H::sync_boundary(&synced_db), *second_update.range.start());

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Test that a finish signal received before target completion still allows full sync.
pub(crate) fn test_sync_handles_early_finish_signal<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(30), None).await;
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;
        let target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(lower_bound, upper_bound),
        };
        let verification_root = H::canonical_root(&target_db);

        let (finish_sender, finish_receiver) = mpsc::channel(1);
        let (reached_sender, mut reached_receiver) = mpsc::channel(1);
        finish_sender
            .send(())
            .await
            .expect("finish signal channel should be open");

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(3),
            target: target.clone(),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
        };

        let synced_db: H::Db = sync::sync(config)
            .await
            .expect("sync should complete after early finish signal");
        let reached = reached_receiver
            .recv()
            .await
            .expect("engine should report reached-target");

        assert_eq!(reached, target);
        assert_eq!(H::canonical_root(&synced_db), verification_root);
        assert_eq!(H::bounds(&synced_db).end, upper_bound);
        assert_eq!(H::sync_boundary(&synced_db), lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Test that dropping finish sender without sending is treated as an error.
pub(crate) fn test_sync_fails_when_finish_sender_dropped<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10), None).await;
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;

        let (finish_sender, finish_receiver) = mpsc::channel(1);
        drop(finish_sender);

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: H::db_root(&target_db),
                range: non_empty_range!(lower_bound, upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: Some(finish_receiver),
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        let result: Result<H::Db, _> = sync::sync(config).await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::FinishChannelClosed))
        ));

        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Test that dropping reached-target receiver does not fail sync.
pub(crate) fn test_sync_allows_dropped_reached_target_receiver<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        target_db = H::apply_ops(target_db, H::create_ops(10), None).await;
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;
        let verification_root = H::canonical_root(&target_db);

        let (reached_sender, reached_receiver) = mpsc::channel(1);
        drop(reached_receiver);

        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: H::db_root(&target_db),
                range: non_empty_range!(lower_bound, upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
        };

        let synced_db: H::Db = sync::sync(config)
            .await
            .expect("sync should succeed when reached-target receiver is dropped");
        assert_eq!(H::canonical_root(&synced_db), verification_root);
        assert_eq!(H::bounds(&synced_db).end, upper_bound);
        assert_eq!(H::sync_boundary(&synced_db), lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Test post-sync usability: after syncing, the database supports normal operations.
pub(crate) fn test_sync_post_sync_usability<H: SyncTestHarness>()
where
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(50);
        target_db = H::apply_ops(target_db, target_ops, None).await;

        let sync_root = H::db_root(&target_db);
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;
        let target_db = Arc::new(target_db);

        let config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            db_config: config,
            fetch_batch_size: NZU64!(100),
            target: Target {
                root: sync_root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.child("client"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let synced_db: H::Db = sync::sync(config).await.unwrap();

        let root_after_sync = H::canonical_root(&synced_db);

        // Apply additional operations after sync.
        let more_ops = H::create_ops_seeded(10, 1);
        let synced_db = H::apply_ops(synced_db, more_ops, None).await;

        // Root should change after applying more ops.
        assert_ne!(H::canonical_root(&synced_db), root_after_sync);
        assert!(H::bounds(&synced_db).end > upper_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
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
        let mut db = H::init_db_with_config(context.child("source"), db_config.clone()).await;
        let ops = H::create_ops(100);
        db = H::apply_ops(db, ops, None).await;
        // commit already done in apply_ops

        let sync_lower_bound = H::sync_boundary(&db);
        let bounds = H::bounds(&db);
        let sync_upper_bound = bounds.end;
        let target_db_op_count = bounds.end;
        let target_db_inactivity_floor_loc = H::inactivity_floor_loc(&db);

        let pinned_nodes = db.pinned_nodes_at(sync_lower_bound).await;
        let (_, journal) = db.into_log_components();

        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.child("synced"),
            db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(sync_lower_bound, sync_upper_bound),
            NZU64!(1024),
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(H::bounds(&sync_db).end, target_db_op_count);
        assert_eq!(
            H::inactivity_floor_loc(&sync_db),
            target_db_inactivity_floor_loc
        );
        assert_eq!(H::sync_boundary(&sync_db), sync_lower_bound);

        H::destroy(sync_db).await;
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
        let target_db = H::init_db(context.child("target")).await;
        let sync_db_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.child("client");
        let sync_db =
            H::init_db_with_config(client_context.child("client"), sync_db_config.clone()).await;
        let original_ops = H::create_ops(NUM_OPS);
        let target_db = H::apply_ops(target_db, original_ops.clone(), None).await;
        // commit already done in apply_ops
        let boundary = H::sync_boundary(&target_db);
        let target_db = H::prune(target_db, boundary).await;
        let sync_db = H::apply_ops(sync_db, original_ops.clone(), None).await;
        // commit already done in apply_ops
        let boundary = H::sync_boundary(&sync_db);
        let sync_db = H::prune(sync_db, boundary).await;
        let sync_db = H::db_sync(sync_db).await;
        drop(sync_db);

        // Add more operations to the target db
        // (use different seed to avoid key collisions)
        let more_ops = H::create_ops_seeded(NUM_ADDITIONAL_OPS, 1);
        let target_db = H::apply_ops(target_db, more_ops, None).await;
        // commit already done in apply_ops

        // Capture target db state for comparison
        let bounds = H::bounds(&target_db);
        let target_db_op_count = bounds.end;
        let target_db_inactivity_floor_loc = H::inactivity_floor_loc(&target_db);
        let sync_lower_bound = H::sync_boundary(&target_db);
        let sync_upper_bound = bounds.end;
        let target_hash = H::canonical_root(&target_db);

        // Get pinned nodes at the sync lower bound from the target db (which has all the data).
        let pinned_nodes = target_db.pinned_nodes_at(sync_lower_bound).await;

        let (mmr, journal) = target_db.into_log_components();

        // Re-open `sync_db` using from_sync_result
        let sync_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            client_context.child("synced"),
            sync_db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(sync_lower_bound, sync_upper_bound),
            NZU64!(1024),
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(H::bounds(&sync_db).end, target_db_op_count);
        assert_eq!(
            H::inactivity_floor_loc(&sync_db),
            target_db_inactivity_floor_loc
        );
        assert_eq!(H::sync_boundary(&sync_db), sync_lower_bound);

        // Verify the root digest matches the target (verifies content integrity)
        assert_eq!(H::canonical_root(&sync_db), target_hash);

        H::destroy(sync_db).await;
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
        let source_db = H::init_db(context.child("source")).await;
        let ops = H::create_ops(NUM_OPS);
        let source_db = H::apply_ops(source_db, ops, None).await;
        // commit already done in apply_ops
        let boundary = H::sync_boundary(&source_db);
        let source_db = H::prune(source_db, boundary).await;

        let lower_bound = H::sync_boundary(&source_db);
        let upper_bound = H::bounds(&source_db).end;

        // Get pinned nodes and target hash before deconstructing source_db
        let pinned_nodes = source_db.pinned_nodes_at(lower_bound).await;
        let target_hash = H::canonical_root(&source_db);
        let target_op_count = H::bounds(&source_db).end;
        let target_inactivity_floor = H::inactivity_floor_loc(&source_db);

        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string(), &context);

        let db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.child("synced"),
            new_db_config,
            journal,
            Some(pinned_nodes),
            non_empty_range!(lower_bound, upper_bound),
            NZU64!(1024),
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(H::bounds(&db).end, target_op_count);
        assert_eq!(H::inactivity_floor_loc(&db), target_inactivity_floor);
        assert_eq!(H::sync_boundary(&db), lower_bound);

        // Verify the root digest matches the target
        assert_eq!(H::canonical_root(&db), target_hash);

        H::destroy(db).await;
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
        let source_db = H::init_db(context.child("source")).await;

        // An empty database has exactly 1 operation (the initial CommitFloor)
        assert_eq!(H::bounds(&source_db).end, Location::new(1));

        let target_hash = H::canonical_root(&source_db);
        let (mmr, journal) = source_db.into_log_components();

        // Use a different config (simulating a new empty database)
        let new_db_config = H::config(&context.next_u64().to_string(), &context);

        let mut synced_db: DbOf<H> = <DbOf<H> as qmdb::sync::Database>::from_sync_result(
            context.child("synced"),
            new_db_config,
            journal,
            None,
            non_empty_range!(Location::new(0), Location::new(1)),
            NZU64!(1024),
        )
        .await
        .unwrap();

        // Verify database state
        assert_eq!(H::bounds(&synced_db).end, Location::new(1));
        assert_eq!(H::inactivity_floor_loc(&synced_db), Location::new(0));
        assert_eq!(H::canonical_root(&synced_db), target_hash);

        // Test that we can perform operations on the synced database
        let ops = H::create_ops(10);
        synced_db = H::apply_ops(synced_db, ops, None).await;

        // Verify the operations worked
        assert!(H::bounds(&synced_db).end > Location::new(1));

        H::destroy(synced_db).await;
        mmr.destroy().await.unwrap();
    });
}

/// Returns feedback that fetches at most one later candidate after explicit rejection.
fn one_retry_feedback<R: Send + 'static>(
    context: deterministic::Context,
    next: impl Future<Output = Option<R>> + Send + 'static,
) -> Feedback<R> {
    let (candidate_tx, candidate_rx) = mpsc::channel(1);
    let (verdict_tx, verdict_rx) = oneshot::channel();
    drop(context.spawn(move |_| async move {
        if !matches!(verdict_rx.await, Ok(false)) {
            return;
        }
        let Some(response) = next.await else {
            return;
        };
        let (next_verdict_tx, next_verdict_rx) = oneshot::channel();
        if candidate_tx.send((response, next_verdict_tx)).await.is_ok() {
            let _ = next_verdict_rx.await;
        }
    }));
    Feedback::new(verdict_tx, candidate_rx)
}

/// Corrupts the first pinned-node candidate, then offers a valid one in the same request.
#[derive(Clone)]
struct CorruptFirstPinnedNodesSource<R> {
    context: Arc<deterministic::Context>,
    inner: R,
    corrupted: Arc<std::sync::atomic::AtomicBool>,
}

impl<R, F> Source for CorruptFirstPinnedNodesSource<R>
where
    F: merkle::Family,
    R: Source<Family = F, Digest = Digest> + Clone + 'static,
    R::Op: Send + 'static,
{
    type Family = R::Family;
    type Digest = Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        let (mut response, feedback) = self.inner.serve(request).await?;
        assert!(feedback.is_none(), "test wrapper requires a direct source");

        // Corrupt pinned nodes only on the first boundary response.
        if let Response::Boundary { pinned_nodes, .. } = &mut response
            && !self
                .corrupted
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            && !pinned_nodes.is_empty()
        {
            pinned_nodes[0] = Digest::from([0xFFu8; 32]);
            let inner = self.inner.clone();
            let feedback = one_retry_feedback(
                self.context.child("corrupt_first_pinned_nodes"),
                async move {
                    let Ok((response, feedback)) = inner.serve(request).await else {
                        return None;
                    };
                    assert!(feedback.is_none(), "test wrapper requires a direct source");
                    drop(inner);
                    Some(response)
                },
            );
            return Ok((response, Some(feedback)));
        }
        Ok((response, None))
    }
}

/// Sync rejects corrupted pinned nodes and accepts a valid candidate from the same request.
pub(crate) fn test_sync_retries_bad_pinned_nodes<H: SyncTestHarness>()
where
    Arc<DbOf<H>>:
        Source<Family = H::Family, Op = OpOf<H>, Digest = Digest> + sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Build a target database with some operations and prune so that pinned nodes are needed.
        let target_db = H::init_db(context.child("target")).await;
        let ops = H::create_ops(20);
        let target_db = H::apply_ops(target_db, ops, None).await;
        let boundary = H::sync_boundary(&target_db);
        let target_db = H::prune(target_db, boundary).await;

        let sync_root = H::db_root(&target_db);
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;

        let db_config = H::config(&context.next_u64().to_string(), &context);

        let source = CorruptFirstPinnedNodesSource {
            context: Arc::new(context.child("source")),
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
            context: context.child("client"),
            source,
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };

        let synced_db: H::Db = sync::sync(config).await.unwrap();
        assert_eq!(H::db_root(&synced_db), sync_root);
        H::destroy(synced_db).await;
    });
}

/// A source wrapper that answers the first fresh boundary candidate against the retained
/// historical root, then blocks the next candidate in the same request until released.
#[derive(Clone)]
struct ReplayFreshBoundarySource<R, F: merkle::Family> {
    context: Arc<deterministic::Context>,
    inner: R,
    historical_target_size: Location<F>,
    boundary_start: Location<F>,
    release_historical_gap: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    release_boundary_retry: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    boundary_attempts: Arc<AtomicUsize>,
}

impl<R, F> Source for ReplayFreshBoundarySource<R, F>
where
    F: merkle::Family,
    R: Source<Family = F, Digest = Digest> + Clone + 'static,
    R::Op: Send + 'static,
{
    type Family = R::Family;
    type Digest = Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        if request.size() == self.historical_target_size {
            if matches!(request, Request::Boundary { .. }) {
                // Simulate a source that has not answered the old target's pinned-nodes
                // request when the target changes. The update moves the lower bound, which
                // cancels the request and drops this pending future.
                return std::future::pending().await;
            }

            let release = self.release_historical_gap.lock().take();
            if let Some(release) = release {
                let _ = release.await;
            }
        }

        if matches!(request, Request::Boundary { .. }) && request.start() == self.boundary_start {
            let attempt = self.boundary_attempts.fetch_add(1, Ordering::Relaxed);
            if attempt == 0 {
                // Offer an operations response against the historical size. The request keeps
                // the same feedback channel while the engine rejects it and waits for the fresh
                // boundary candidate.
                let historical = Request::Operations {
                    size: self.historical_target_size,
                    start: request.start(),
                    max_ops: request.max_ops(),
                };
                let (response, feedback) = self.inner.serve(historical).await?;
                assert!(feedback.is_none(), "test wrapper requires a direct source");
                let inner = self.inner.clone();
                let release_boundary_retry = Arc::clone(&self.release_boundary_retry);
                let feedback =
                    one_retry_feedback(self.context.child("replay_fresh_boundary"), async move {
                        let release = release_boundary_retry.lock().take();
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        let Ok((response, feedback)) = inner.serve(request).await else {
                            return None;
                        };
                        assert!(feedback.is_none(), "test wrapper requires a direct source");
                        drop(inner);
                        Some(response)
                    });
                return Ok((response, Some(feedback)));
            }

            let release = self.release_boundary_retry.lock().take();
            if let Some(release) = release {
                let _ = release.await;
            }
        }

        self.inner.serve(request).await
    }
}

/// Test that reaching the journal target does not report completion while the pruned
/// boundary retry is still outstanding.
pub(crate) fn test_sync_waits_for_boundary_retry_after_target_update<H: SyncTestHarness>()
where
    Arc<DbOf<H>>:
        Source<Family = H::Family, Op = OpOf<H>, Digest = Digest> + sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let mut target_db = H::init_db(context.child("target")).await;

        let mut seed = 0;
        loop {
            target_db = H::apply_ops(target_db, H::create_ops_seeded(32, seed), None).await;
            let boundary = H::sync_boundary(&target_db);
            target_db = H::prune(target_db, boundary).await;

            if H::inactivity_floor_loc(&target_db) > Location::new(0) {
                break;
            }

            seed += 1;
            assert!(seed < 8, "expected prune floor to advance");
        }

        let old_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(
                H::inactivity_floor_loc(&target_db),
                H::bounds(&target_db).end
            ),
        };

        target_db = H::apply_ops(target_db, H::create_ops_seeded(3, seed + 1), None).await;
        let new_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(
                H::inactivity_floor_loc(&target_db),
                H::bounds(&target_db).end
            ),
        };
        let verification_root = H::canonical_root(&target_db);

        assert!(old_target.range.start() > Location::new(0));
        assert!(new_target.range.start() > old_target.range.start());
        assert!(new_target.range.end() > old_target.range.end());

        let (release_historical_gap_tx, release_historical_gap_rx) = oneshot::channel();
        let (release_boundary_retry_tx, release_boundary_retry_rx) = oneshot::channel();
        let target_db = Arc::new(target_db);
        let source = ReplayFreshBoundarySource {
            context: Arc::new(context.child("source")),
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
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            fetch_batch_size: NZU64!(1),
            target: old_target.clone(),
            source,
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 2,
            update_rx: Some(update_receiver),
            finish_rx: Some(finish_receiver),
            reached_target_tx: Some(reached_sender),
            max_retained_roots: 1,
        };

        let mut engine: Engine<H::Db, _> = Engine::new(config).await.unwrap();

        update_sender.send(new_target.clone()).await.unwrap();
        finish_sender.send(()).await.unwrap();

        engine = match engine.step().await.unwrap() {
            NextStep::Continue(engine) => engine,
            NextStep::Complete(_) => panic!("target update should not complete sync"),
        };

        let _ = release_historical_gap_tx.send(());

        let journal_start = engine.journal().bounds().end;
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
                        engine.journal().bounds().end,
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
        assert_eq!(H::canonical_root(&synced_db), verification_root);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Requests seen by a [GatedSource].
struct GateLog<F: merkle::Family> {
    /// Whether new requests are served without waiting for release.
    open: bool,
    /// Unreleased requests that arrived while the gate was closed, with their release handles.
    held: Vec<(Request<F>, oneshot::Sender<()>)>,
    /// Requests the inner source answered.
    served: Vec<Request<F>>,
}

impl<F: merkle::Family> GateLog<F> {
    /// Held operation requests whose serve future is still alive.
    fn live_operations(&self) -> impl Iterator<Item = Request<F>> + '_ {
        self.held
            .iter()
            .filter(|(request, tx)| {
                matches!(request, Request::Operations { .. }) && !tx.is_closed()
            })
            .map(|(request, _)| *request)
    }
}

/// A source wrapper that holds each request until released while its gate is closed and records
/// the requests the inner source answers.
struct GatedSource<R, F: merkle::Family> {
    inner: R,
    log: Arc<Mutex<GateLog<F>>>,
}

impl<R, F> Source for GatedSource<R, F>
where
    F: merkle::Family,
    R: Source<Family = F, Digest = Digest>,
    R::Op: Send,
{
    type Family = F;
    type Digest = Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        let release = {
            let mut log = self.log.lock();
            if log.open {
                None
            } else {
                let (tx, rx) = oneshot::channel();
                log.held.push((request, tx));
                Some(rx)
            }
        };
        if let Some(release) = release {
            let _ = release.await;
        }
        let result = self.inner.serve(request).await;
        if result.is_ok() {
            self.log.lock().served.push(request);
        }
        result
    }
}

/// Test that operations fetched ahead of the journal tip are applied without fetching them again
/// across target updates that move the lower bound while the source prunes to each new lower
/// bound. Operation requests above the final lower bound survive the final update, and requests
/// that start below the pruned source are cancelled.
///
/// Before each update, the source commits and prunes until an in-flight operation request starts
/// below the source's oldest retained operation and ends beyond the new lower bound. Each round
/// first stores a fetched batch ahead of the held journal tip.
pub(crate) fn test_target_updates_keep_operations_across_pruned_floors<H: SyncTestHarness>()
where
    Arc<AsyncRwLock<Option<DbOf<H>>>>:
        Source<Family = H::Family, Op = OpOf<H>, Digest = Digest> + sync::SourceFor<DbOf<H>>,
    OpOf<H>: Encode,
    JournalOf<H>: Contiguous,
{
    const OUTSTANDING: usize = 4;
    const UPDATES: usize = 3;
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Build a source pruned to a floor above zero.
        let mut db = H::init_db(context.child("source")).await;
        db = H::apply_ops(db, H::create_ops(256), None).await;
        let floor = H::sync_boundary(&db);
        db = H::prune(db, floor).await;
        assert!(floor > Location::new(0));
        let mut target = Target {
            root: H::db_root(&db),
            range: non_empty_range!(floor, H::bounds(&db).end),
        };
        let source_db = Arc::new(AsyncRwLock::new(Some(db)));
        let log = Arc::new(Mutex::new(GateLog {
            open: false,
            held: Vec::new(),
            served: Vec::new(),
        }));

        // Start sync with a retention window that never evicts.
        let (update_tx, update_rx) = mpsc::channel(1);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&context.next_u64().to_string(), &context),
            target: target.clone(),
            source: GatedSource {
                inner: source_db.clone(),
                log: log.clone(),
            },
            fetch_batch_size: NZU64!(32),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: OUTSTANDING,
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 64,
        };

        // Drive sync alongside the test. A sync error fails the test at once.
        let sync = async {
            sync::sync::<DbOf<H>, _>(config)
                .await
                .expect("sync must complete")
        };
        let drive = async {
            // Wait for the boundary and operation requests of the first target.
            while log.lock().held.len() < OUTSTANDING {
                commonware_runtime::reschedule().await;
            }

            let mut seed = 1;
            let mut stored = Vec::new();
            let mut retained = Vec::new();
            for _ in 0..UPDATES {
                // Release the farthest in-flight operation request. The engine has stored its
                // batch once it issues the next request.
                let arrivals = {
                    let mut log = log.lock();
                    let farthest = log
                        .live_operations()
                        .max_by_key(|request| request.start())
                        .expect("an operation request must be in flight");
                    let index = log
                        .held
                        .iter()
                        .position(|(request, _)| *request == farthest)
                        .unwrap();
                    let (request, tx) = log.held.swap_remove(index);
                    tx.send(()).unwrap();
                    stored.push(request);
                    log.held.len()
                };
                while log.lock().held.len() == arrivals {
                    commonware_runtime::reschedule().await;
                }

                // Commit and prune the source until an in-flight operation request starts below
                // the source's oldest retained operation and ends beyond the new floor.
                let next = loop {
                    let mut guard = source_db.write().await;
                    let db =
                        H::apply_ops(guard.take().unwrap(), H::create_ops_seeded(1, seed), None)
                            .await;
                    seed += 1;
                    let floor = H::sync_boundary(&db);
                    let db = H::prune(db, floor).await;
                    let oldest = H::bounds(&db).start;
                    let next = Target {
                        root: H::db_root(&db),
                        range: non_empty_range!(floor, H::bounds(&db).end),
                    };
                    *guard = Some(db);
                    drop(guard);
                    assert!(next.range.start() > target.range.start(), "floor must move");
                    let straddled = log.lock().live_operations().any(|request| {
                        request.start() > target.range.start()
                            && request.start() < oldest
                            && request
                                .start()
                                .checked_add(request.max_ops().get())
                                .unwrap()
                                > floor
                    });
                    if straddled {
                        break next;
                    }
                    assert!(seed < 1000, "floor must straddle an in-flight request");
                };

                // Some in-flight operation requests start above the new floor.
                retained = log
                    .lock()
                    .live_operations()
                    .filter(|request| request.start() > next.range.start())
                    .collect::<Vec<_>>();
                assert!(!retained.is_empty());

                // Send the update. The engine has handled it once it requests the new boundary.
                update_tx.send(next.clone()).await.unwrap();
                let boundary = Request::Boundary {
                    size: next.range.end(),
                    start: next.range.start(),
                };
                while !log
                    .lock()
                    .held
                    .iter()
                    .any(|(request, _)| *request == boundary)
                {
                    commonware_runtime::reschedule().await;
                }
                target = next;
            }

            // A batch stored before an update lies at or above the final floor.
            let floor = target.range.start();
            assert!(stored.iter().any(|request| request.start() >= floor));

            // Stop updates and release every held request. Serving a request that starts below
            // the pruned source fails sync.
            drop(update_tx);
            let held = {
                let mut log = log.lock();
                log.open = true;
                std::mem::take(&mut log.held)
            };
            for (_, tx) in held {
                let _ = tx.send(());
            }
            (floor, retained)
        };
        let (synced, (floor, retained)) = futures::join!(sync, drive);

        // Sync completes at the latest target.
        let db = source_db.write().await.take().unwrap();
        assert_eq!(H::canonical_root(&synced), H::canonical_root(&db));

        // Operation requests in flight above the final floor survived the last update.
        let served = std::mem::take(&mut log.lock().served);
        for request in &retained {
            assert!(served.contains(request), "{request:?} must be served");
        }

        // No location at or above the final floor was served by two operation requests.
        let mut seen = BTreeSet::new();
        for request in &served {
            let Request::Operations {
                size,
                start,
                max_ops,
            } = *request
            else {
                continue;
            };
            let end = start.checked_add(max_ops.get()).unwrap().min(size);
            for loc in *start.max(floor)..*end {
                assert!(seen.insert(loc), "location {loc} refetched by {request:?}");
            }
        }

        H::destroy(synced).await;
        H::destroy(db).await;
    });
}

/// Test that local pinned nodes are found for a target whose lower bound precedes its inactivity
/// floor.
pub(crate) fn test_local_pinned_nodes_below_floor<H: SyncTestHarness>() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let config = H::config(&context.next_u64().to_string(), &context);
        let mut db = H::init_db_with_config(context.child("db"), config.clone()).await;

        // Rewrite the same keys until a peak lies wholly below the floor, so a floor taken from
        // the target's lower bound would produce a different root.
        let start = Location::new(1);
        let mut round = 0;
        loop {
            round += 1;
            assert!(round <= 64, "inactivity floor never passed a peak");
            db = H::apply_ops(db, H::create_ops(100), None).await;
            let end = H::bounds(&db).end;
            let floor = H::inactivity_floor_loc(&db);
            if <H::Family as merkle::Family>::inactive_peaks(end, floor)
                > <H::Family as merkle::Family>::inactive_peaks(end, start)
            {
                break;
            }
        }
        let target = Target {
            root: H::db_root(&db),
            range: non_empty_range!(start, H::bounds(&db).end),
        };
        drop(H::db_sync(db).await);

        let journal = <JournalOf<H> as sync::Journal<H::Family>>::new(
            context.child("journal"),
            sync::DatabaseConfig::journal_config(&config),
            target.range.clone(),
        )
        .await
        .unwrap();
        let pinned = <DbOf<H> as sync::Database>::local_pinned_nodes(
            context.child("probe"),
            &config,
            &target,
            &journal,
        )
        .await
        .unwrap();
        assert!(pinned.is_some());
        drop(journal);
    });
}

// ===== Harness implementations =====

/// Implements the [`SyncTestHarness`] methods that `any` and `current` databases provide alike.
macro_rules! db_any_harness_methods {
    () => {
        async fn init_db_with_config(
            ctx: commonware_runtime::deterministic::Context,
            config: $crate::qmdb::sync::harness::ConfigOf<Self>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, None).await.unwrap()
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn db_sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn prune(db: Self::Db, loc: $crate::merkle::Location<Self::Family>) -> Self::Db {
            let loc = loc.min(db.sync_boundary());
            db.prune(loc).await.unwrap()
        }

        fn bounds(db: &Self::Db) -> std::ops::Range<$crate::merkle::Location<Self::Family>> {
            db.bounds()
        }

        fn sync_boundary(db: &Self::Db) -> $crate::merkle::Location<Self::Family> {
            db.sync_boundary()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> $crate::merkle::Location<Self::Family> {
            db.inactivity_floor_loc()
        }

        fn db_root(db: &Self::Db) -> commonware_cryptography::sha256::Digest {
            $crate::qmdb::sync::Database::root(db)
        }

        fn canonical_root(db: &Self::Db) -> commonware_cryptography::sha256::Digest {
            db.root()
        }

        async fn get_metadata(db: &Self::Db) -> Option<Self::Metadata> {
            db.get_metadata().await.unwrap()
        }

        async fn assert_ops_applied(
            db: &Self::Db,
            ops: &[$crate::qmdb::sync::harness::OpOf<Self>],
        ) {
            use $crate::qmdb::any::operation::{Operation, update::Update as _};

            let mut expected = std::collections::BTreeMap::new();
            for op in ops {
                match op {
                    Operation::Update(update) => {
                        expected.insert(*update.key(), Some(update.value().clone()));
                    }
                    Operation::Delete(key) => {
                        expected.insert(*key, None);
                    }
                    Operation::CommitFloor(_, _) => {}
                }
            }
            for (key, value) in expected {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
        }

        async fn assert_ops_absent(db: &Self::Db, ops: &[$crate::qmdb::sync::harness::OpOf<Self>]) {
            use $crate::qmdb::any::operation::{Operation, update::Update as _};

            for op in ops {
                if let Operation::Update(update) = op {
                    assert!(db.get(update.key()).await.unwrap().is_none());
                }
            }
        }
    };
}
pub(crate) use db_any_harness_methods;

mod harnesses {
    use super::SyncTestHarness;
    use crate::{
        merkle::{self, mmb, mmr},
        qmdb::floor::Proportional,
        translator::TwoCap,
    };
    use commonware_cryptography::sha256::Digest;
    use commonware_math::algebra::Random;
    use commonware_runtime::{BufferPooler, Metrics, deterministic::Context};
    use commonware_utils::TestRng;
    use rand::Rng;

    // ===== Family-generic op creation helpers =====
    //
    // `Operation<F, K, V>` is phantom in F for Update/Delete variants, so ops
    // are structurally identical across families.

    fn create_ordered_fixed_ops<F: merkle::Family>(
        n: usize,
        seed: u64,
    ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};
        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};
        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Ordered as Update};
        let mut rng = TestRng::new(seed);
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
        use crate::qmdb::any::operation::{Operation, update::Unordered as Update};
        let mut rng = TestRng::new(seed);
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

    pub(crate) struct OrderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Family> SyncTestHarness for OrderedFixedHarness<F> {
        type Family = F;
        type Db = crate::qmdb::any::ordered::fixed::Db<
            F,
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;
        type Metadata = Digest;

        fn config(
            suffix: &str,
            pooler: &(impl BufferPooler + Metrics),
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
            create_ordered_fixed_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>> {
            create_ordered_fixed_ops(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            Digest::from([1; 32])
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let cfg = crate::qmdb::any::test::fixed_db_config::<TwoCap>(&seed.to_string(), &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::fixed::Operation<F, Digest, Digest>>,
            metadata: Option<Self::Metadata>,
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
            let merkleized = batch
                .merkleize(&db, None::<Digest>, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap()
        }

        db_any_harness_methods!();
    }

    pub(crate) type OrderedFixedMmrHarness = OrderedFixedHarness<mmr::Family>;
    pub(crate) type OrderedFixedMmbHarness = OrderedFixedHarness<mmb::Family>;

    pub(crate) struct OrderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Family> SyncTestHarness for OrderedVariableHarness<F> {
        type Family = F;
        type Db = crate::qmdb::any::ordered::variable::Db<
            F,
            Context,
            Digest,
            Vec<u8>,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;
        type Metadata = Vec<u8>;

        fn config(
            suffix: &str,
            pooler: &(impl BufferPooler + Metrics),
        ) -> crate::qmdb::any::ordered::variable::test::VarConfig {
            crate::qmdb::any::ordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
                (),
            )
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Vec<u8>>> {
            create_ordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Vec<u8>>> {
            create_ordered_variable_ops(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            vec![42]
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config =
                crate::qmdb::any::ordered::variable::test::create_test_config(seed, &ctx, ());
            Self::Db::init(ctx, config, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::ordered::variable::Operation<F, Digest, Vec<u8>>>,
            metadata: Option<Self::Metadata>,
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
            let merkleized = batch
                .merkleize(&db, None::<Vec<u8>>, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap()
        }

        db_any_harness_methods!();
    }

    pub(crate) type OrderedVariableMmrHarness = OrderedVariableHarness<mmr::Family>;
    pub(crate) type OrderedVariableMmbHarness = OrderedVariableHarness<mmb::Family>;

    pub(crate) struct UnorderedFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Family> SyncTestHarness for UnorderedFixedHarness<F> {
        type Family = F;
        type Db = crate::qmdb::any::unordered::fixed::Db<
            F,
            Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;
        type Metadata = Digest;

        fn config(
            suffix: &str,
            pooler: &(impl BufferPooler + Metrics),
        ) -> crate::qmdb::any::FixedConfig<TwoCap, commonware_parallel::Sequential> {
            crate::qmdb::any::test::fixed_db_config(suffix, pooler)
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
            create_unordered_fixed_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>> {
            create_unordered_fixed_ops(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            Digest::from([1; 32])
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let cfg = crate::qmdb::any::test::fixed_db_config::<TwoCap>(&seed.to_string(), &ctx);
            Self::Db::init(ctx, cfg, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::fixed::Operation<F, Digest, Digest>>,
            metadata: Option<Self::Metadata>,
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
            let merkleized = batch
                .merkleize(&db, None::<Digest>, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap()
        }

        db_any_harness_methods!();
    }

    pub(crate) type UnorderedFixedMmrHarness = UnorderedFixedHarness<mmr::Family>;
    pub(crate) type UnorderedFixedMmbHarness = UnorderedFixedHarness<mmb::Family>;

    pub(crate) struct UnorderedVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: merkle::Family> SyncTestHarness for UnorderedVariableHarness<F> {
        type Family = F;
        type Db = crate::qmdb::any::unordered::variable::Db<
            F,
            Context,
            Digest,
            Vec<u8>,
            commonware_cryptography::Sha256,
            TwoCap,
            commonware_parallel::Sequential,
        >;
        type Metadata = Vec<u8>;

        fn config(
            suffix: &str,
            pooler: &(impl BufferPooler + Metrics),
        ) -> crate::qmdb::any::unordered::variable::test::VarConfig {
            crate::qmdb::any::unordered::variable::test::create_test_config(
                suffix.parse().unwrap_or(0),
                pooler,
            )
        }

        fn create_ops(
            n: usize,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Vec<u8>>> {
            create_unordered_variable_ops(n, 0)
        }

        fn create_ops_seeded(
            n: usize,
            seed: u64,
        ) -> Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Vec<u8>>> {
            create_unordered_variable_ops(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            vec![42]
        }

        async fn init_db(mut ctx: Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config =
                crate::qmdb::any::unordered::variable::test::create_test_config(seed, &ctx);
            Self::Db::init(ctx, config, None).await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<crate::qmdb::any::unordered::variable::Operation<F, Digest, Vec<u8>>>,
            metadata: Option<Self::Metadata>,
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
            let merkleized = batch
                .merkleize(&db, None::<Vec<u8>>, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let merkleized = db
                .new_batch()
                .merkleize(&db, metadata, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap()
        }

        db_any_harness_methods!();
    }

    pub(crate) type UnorderedVariableMmrHarness = UnorderedVariableHarness<mmr::Family>;
    pub(crate) type UnorderedVariableMmbHarness = UnorderedVariableHarness<mmb::Family>;
}

// ===== Test generation =====

/// Emits the `any`-specific sync tests for `$harness`.
macro_rules! any_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_sync_empty_operations_no_panic() {
            super::test_sync_empty_operations_no_panic::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_update_prune_only_ignored() {
            super::test_target_update_prune_only_ignored::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_waits_for_explicit_finish() {
            super::test_sync_waits_for_explicit_finish::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_reports_progress_for_reached_targets_before_explicit_finish() {
            super::test_sync_reports_progress_for_reached_targets_before_explicit_finish::<
                $harness,
            >();
        }

        #[test_traced("WARN")]
        fn test_sync_handles_early_finish_signal() {
            super::test_sync_handles_early_finish_signal::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_fails_when_finish_sender_dropped() {
            super::test_sync_fails_when_finish_sender_dropped::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_allows_dropped_reached_target_receiver() {
            super::test_sync_allows_dropped_reached_target_receiver::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_post_sync_usability() {
            super::test_sync_post_sync_usability::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_retries_bad_pinned_nodes() {
            super::test_sync_retries_bad_pinned_nodes::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_waits_for_boundary_retry_after_target_update() {
            super::test_sync_waits_for_boundary_retry_after_target_update::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_updates_keep_operations_across_pruned_floors() {
            super::test_target_updates_keep_operations_across_pruned_floors::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_local_pinned_nodes_below_floor() {
            super::test_local_pinned_nodes_below_floor::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_from_sync_result_empty_to_empty() {
            super::test_from_sync_result_empty_to_empty::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_from_sync_result_empty_to_nonempty() {
            super::test_from_sync_result_empty_to_nonempty::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
            super::test_from_sync_result_nonempty_to_nonempty_partial_match::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
            super::test_from_sync_result_nonempty_to_nonempty_exact_match::<$harness>();
        }
    };
}

crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedFixedMmrHarness,
    ordered_fixed_mmr,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedVariableMmrHarness,
    ordered_variable_mmr,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedFixedMmrHarness,
    unordered_fixed_mmr,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedVariableMmrHarness,
    unordered_variable_mmr,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedFixedMmbHarness,
    ordered_fixed_mmb,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::OrderedVariableMmbHarness,
    ordered_variable_mmb,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedFixedMmbHarness,
    unordered_fixed_mmb,
    any_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::UnorderedVariableMmbHarness,
    unordered_variable_mmb,
    any_sync_tests
);
