//! Shared sync test harness.
//!
//! Defines the [`SyncTestHarness`] contract that each database implements, the sync tests
//! written against it, and the [`sync_tests`] macro that instantiates those tests per harness.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Location},
    qmdb::{
        self,
        sync::{
            self, Engine, Target,
            engine::{Config, NextStep},
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::sha256;
use commonware_macros::boxed;
use commonware_runtime::{BufferPooler, Metrics, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc, non_empty_range};
use rand::Rng as _;
use std::{
    fmt::Debug,
    future::Future,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

pub(crate) type DbOf<H> = <H as SyncTestHarness>::Db;
pub(crate) type OpOf<H> = <DbOf<H> as qmdb::sync::Database>::Op;
pub(crate) type ConfigOf<H> = <DbOf<H> as qmdb::sync::Database>::Config;
pub(crate) type JournalOf<H> = <DbOf<H> as qmdb::sync::Database>::Journal;

pub(crate) const PAGE_SIZE: NonZeroU16 = NZU16!(77);
pub(crate) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

/// Wraps [`SyncTestHarness::prune`] with a heap-allocated state machine (the future embeds
/// the database twice and exceeds the size lint in the deepest test).
#[boxed]
pub(crate) async fn prune_boxed<H: SyncTestHarness>(db: H::Db, loc: Location<H::Family>) -> H::Db {
    H::prune(db, loc).await
}

/// Harness that abstracts per-database and per-family details so the shared tests below can
/// operate on any database that supports sync.
pub(crate) trait SyncTestHarness: Sized + 'static {
    type Family: merkle::Family;
    type Db: qmdb::sync::Database<
            Family = Self::Family,
            Context = deterministic::Context,
            Digest = sha256::Digest,
            Config: Clone,
        > + Sync;
    type Metadata: Clone + PartialEq + Debug + Send + Sync + 'static;

    fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self>;
    fn create_ops(n: usize) -> Vec<OpOf<Self>>;
    fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>>;
    fn sample_metadata() -> Self::Metadata;

    fn init_db(ctx: deterministic::Context) -> impl Future<Output = Self::Db> + Send;
    fn init_db_with_config(
        ctx: deterministic::Context,
        config: ConfigOf<Self>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn destroy(db: Self::Db) -> impl Future<Output = ()> + Send;
    fn db_sync(db: Self::Db) -> impl Future<Output = Self::Db> + Send;

    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Metadata>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn prune(db: Self::Db, loc: Location<Self::Family>) -> impl Future<Output = Self::Db> + Send;

    fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>>;
    fn db_root(db: &Self::Db) -> sha256::Digest;
    fn get_metadata(db: &Self::Db) -> impl Future<Output = Option<Self::Metadata>> + Send;

    /// Panics unless every operation in `ops` is present in `db`.
    ///
    /// For keyed databases, each operation's key resolves to its value. For keyless databases,
    /// the operation values appear in order among the values stored at consecutive locations
    /// within the bounds of `db`, skipping locations that hold no value (such as commits
    /// without metadata).
    fn assert_ops_applied(db: &Self::Db, ops: &[OpOf<Self>]) -> impl Future<Output = ()> + Send;
}

// ===== Shared tests =====

pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(target_db_ops);
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;
        let bounds = H::bounds(&target_db);
        let target_op_count = bounds.end;
        let target_oldest_retained_loc = bounds.start;
        let target_root = H::db_root(&target_db);

        let db_config = H::config(&format!("sync_client_{}", context.next_u64()), &context);

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size,
            target: Target {
                root: target_root,
                range: non_empty_range!(target_oldest_retained_loc, target_op_count),
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
        let got_db: DbOf<H> = sync::sync(config).await.unwrap();

        let bounds = H::bounds(&got_db);
        assert_eq!(bounds.end, target_op_count);
        assert_eq!(bounds.start, target_oldest_retained_loc);
        assert_eq!(H::db_root(&got_db), target_root);

        H::assert_ops_applied(&got_db, &target_ops).await;

        let new_ops = H::create_ops_seeded(target_db_ops, 1);
        let got_db = H::apply_ops(got_db, new_ops.clone(), None).await;
        let target_db = Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("target_db should have no other references"));
        let target_db = H::apply_ops(target_db, new_ops, None).await;

        assert_eq!(H::db_root(&got_db), H::db_root(&target_db));

        H::destroy(got_db).await;
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_empty_to_nonempty<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops(target_db, vec![], Some(H::sample_metadata())).await;

        let bounds = H::bounds(&target_db);
        let target_op_count = bounds.end;
        let target_oldest_retained_loc = bounds.start;
        let target_root = H::db_root(&target_db);

        let db_config = H::config(&format!("empty_sync_{}", context.next_u64()), &context);
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: target_root,
                range: non_empty_range!(target_oldest_retained_loc, target_op_count),
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
        let got_db: DbOf<H> = sync::sync(config).await.unwrap();

        let bounds = H::bounds(&got_db);
        assert_eq!(bounds.end, target_op_count);
        assert_eq!(bounds.start, target_oldest_retained_loc);
        assert_eq!(H::db_root(&got_db), target_root);
        assert_eq!(H::get_metadata(&got_db).await, Some(H::sample_metadata()));

        H::destroy(got_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_database_persistence<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(10);
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;

        let target_root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db);
        let lower_bound = bounds.start;
        let op_count = bounds.end;

        let db_config = H::config("persistence-test", &context);
        let client_context = context.child("client");
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: target_root,
                range: non_empty_range!(lower_bound, op_count),
            },
            context: client_context.child("client"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        let expected_root = H::db_root(&synced_db);
        let bounds = H::bounds(&synced_db);
        let expected_op_count = bounds.end;
        let expected_oldest_retained_loc = bounds.start;

        H::db_sync(synced_db).await;
        let reopened_db = H::init_db_with_config(context.child("reopened"), db_config).await;

        assert_eq!(H::db_root(&reopened_db), expected_root);
        let bounds = H::bounds(&reopened_db);
        assert_eq!(bounds.end, expected_op_count);
        assert_eq!(bounds.start, expected_oldest_retained_loc);

        H::assert_ops_applied(&reopened_db, &target_ops).await;

        H::destroy(reopened_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_during_sync<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let initial_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, initial_ops.clone(), None).await;

        let bounds = H::bounds(&target_db);
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let additional_ops = H::create_ops_seeded(25, 1);
        let target_db = H::apply_ops(target_db, additional_ops.clone(), None).await;
        let final_upper_bound = H::bounds(&target_db).end;
        let final_root = H::db_root(&target_db);

        let target_db = Arc::new(target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let client = {
            let config = Config {
                context: context.child("client"),
                db_config: H::config(&format!("update_test_{}", context.next_u64()), &context),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                source: target_db.clone(),
                fetch_batch_size: NZU64!(2),
                max_outstanding_requests: 10,
                apply_batch_size: NZU64!(1024),
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };
            let mut client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();
            loop {
                client = match client.step().await.unwrap() {
                    NextStep::Continue(new_client) => new_client,
                    NextStep::Complete(_) => panic!("client should not be complete"),
                };
                let log_size = Contiguous::bounds(client.journal()).end;
                if log_size > *initial_lower_bound {
                    break client;
                }
            }
        };

        update_sender
            .send(Target {
                root: final_root,
                range: non_empty_range!(initial_lower_bound, final_upper_bound),
            })
            .await
            .unwrap();

        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), final_root);

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        {
            let bounds = H::bounds(&synced_db);
            let target_bounds = H::bounds(&target_db);
            assert_eq!(bounds.end, target_bounds.end);
            assert_eq!(bounds.start, target_bounds.start);
            assert_eq!(H::db_root(&synced_db), H::db_root(&target_db));
        }

        let all_ops = [initial_ops, additional_ops].concat();
        H::assert_ops_applied(&synced_db, &all_ops).await;

        H::destroy(synced_db).await;
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(30);
        let target_db = H::apply_ops(target_db, target_ops[..29].to_vec(), None).await;

        let target_root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db);
        let lower_bound = bounds.start;
        let op_count = bounds.end;

        let target_db = H::apply_ops(target_db, target_ops[29..].to_vec(), None).await;

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: H::config(&format!("subset_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(10),
            target: Target {
                root: target_root,
                range: non_empty_range!(lower_bound, op_count),
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
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        assert_eq!(H::bounds(&synced_db).end, op_count);

        H::destroy(synced_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_use_existing_db_partial_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let original_ops = H::create_ops(50);

        let target_db = H::init_db(context.child("target")).await;
        let sync_db_config = H::config(&format!("partial_{}", context.next_u64()), &context);
        let client_context = context.child("client");
        let sync_db =
            H::init_db_with_config(client_context.child("client"), sync_db_config.clone()).await;

        let target_db = H::apply_ops(target_db, original_ops.clone(), None).await;
        H::apply_ops(sync_db, original_ops, None).await;

        let last_op = H::create_ops_seeded(1, 1);
        let target_db = H::apply_ops(target_db, last_op, None).await;
        let root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db);
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: sync_db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.child("sync"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).end, upper_bound);
        assert_eq!(H::db_root(&sync_db), root);

        H::destroy(sync_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_use_existing_db_exact_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_ops = H::create_ops(40);

        let target_db = H::init_db(context.child("target")).await;
        let sync_config = H::config(&format!("exact_{}", context.next_u64()), &context);
        let client_context = context.child("client");
        let sync_db =
            H::init_db_with_config(client_context.child("client"), sync_config.clone()).await;

        let target_db = H::apply_ops(target_db, target_ops.clone(), None).await;
        H::apply_ops(sync_db, target_ops, None).await;

        let root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db);
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;

        let source = Arc::new(target_db);
        let config = Config {
            db_config: sync_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.child("sync"),
            source: source.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).end, upper_bound);
        assert_eq!(H::db_root(&sync_db), root);

        H::destroy(sync_db).await;
        let target_db = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_lower_bound_decrease<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(100);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let target_db = H::prune(target_db, Location::new(10)).await;

        let bounds = H::bounds(&target_db);
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("lb-dec-{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        update_sender
            .send(Target {
                root: initial_root,
                range: non_empty_range!(
                    initial_lower_bound.checked_sub(1).unwrap(),
                    initial_upper_bound
                ),
            })
            .await
            .unwrap();

        // The non-advancing update is discarded and the sync completes at the original target.
        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), initial_root);
        H::destroy(synced_db).await;

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_upper_bound_decrease<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db);
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("ub-dec-{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        update_sender
            .send(Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound - 1),
            })
            .await
            .unwrap();

        // The non-advancing update is discarded and the sync completes at the original target.
        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), initial_root);
        H::destroy(synced_db).await;

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_bounds_increase<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(100);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db);
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let more_ops = H::create_ops_seeded(5, 1);
        let target_db = H::apply_ops(target_db, more_ops, None).await;

        let target_db = H::prune(target_db, Location::new(10)).await;
        let target_db = H::apply_ops(target_db, vec![], None).await;

        let bounds = H::bounds(&target_db);
        let final_lower_bound = bounds.start;
        let final_upper_bound = bounds.end;
        let final_root = H::db_root(&target_db);

        assert_ne!(final_lower_bound, initial_lower_bound);
        assert_ne!(final_upper_bound, initial_upper_bound);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("bounds_inc_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(1),
            target: Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 1,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        update_sender
            .send(Target {
                root: final_root,
                range: non_empty_range!(final_lower_bound, final_upper_bound),
            })
            .await
            .unwrap();

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), final_root);
        let bounds = H::bounds(&synced_db);
        assert_eq!(bounds.end, final_upper_bound);
        assert_eq!(bounds.start, final_lower_bound);

        H::destroy(synced_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_on_done_client<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(10);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db);
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;
        let root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("done_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(20),
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        let _ = update_sender
            .send(Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(lower_bound + 1, upper_bound + 1),
            })
            .await;

        assert_eq!(H::db_root(&synced_db), root);
        let bounds = H::bounds(&synced_db);
        assert_eq!(bounds.end, upper_bound);
        assert_eq!(bounds.start, lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// Engine configuration for a compact sync over the one-operation range ending at the target.
pub(crate) fn compact_engine_config<DB, S>(
    context: DB::Context,
    source: S,
    target: sync::CompactTarget<DB::Family, DB::Digest>,
    db_config: DB::Config,
) -> sync::engine::Config<DB, S>
where
    DB: sync::Database,
    S: sync::SourceFor<DB>,
    DB::Op: Encode,
{
    sync::engine::Config {
        context,
        db_config,
        fetch_batch_size: NZU64!(1),
        target: sync::Target {
            root: target.root,
            range: non_empty_range!(target.size - 1, target.size),
        },
        source,
        apply_batch_size: NZU64!(1024),
        max_outstanding_requests: 1,
        update_rx: None,
        finish_rx: None,
        reached_target_tx: None,
        max_retained_roots: 1,
    }
}

// ===== Test Generation Macro =====

/// Instantiates the shared sync tests for `$harness` in a module named `$mod_name`.
///
/// The optional `$extra` names a macro that receives `$harness` and emits additional tests
/// into the same module.
macro_rules! sync_tests {
    ($harness:ty, $mod_name:ident $(, $extra:ident)?) => {
        mod $mod_name {
            use super::*;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[rstest]
            #[case::singleton_batch_size_one(1, 1)]
            #[case::singleton_batch_size_gt_db_size(1, 2)]
            #[case::batch_size_one(1000, 1)]
            #[case::floor_div_db_batch_size(1000, 3)]
            #[case::floor_div_db_batch_size_2(1000, 999)]
            #[case::div_db_batch_size(1000, 100)]
            #[case::db_size_eq_batch_size(1000, 1000)]
            #[case::batch_size_gt_db_size(1000, 1001)]
            fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: u64) {
                crate::qmdb::sync::harness::test_sync::<$harness>(
                    target_db_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
            }

            #[test_traced("WARN")]
            fn test_sync_empty_to_nonempty() {
                crate::qmdb::sync::harness::test_sync_empty_to_nonempty::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_sync_database_persistence() {
                crate::qmdb::sync::harness::test_sync_database_persistence::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_during_sync() {
                crate::qmdb::sync::harness::test_target_update_during_sync::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_sync_subset_of_target_database() {
                crate::qmdb::sync::harness::test_sync_subset_of_target_database::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_sync_use_existing_db_partial_match() {
                crate::qmdb::sync::harness::test_sync_use_existing_db_partial_match::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_sync_use_existing_db_exact_match() {
                crate::qmdb::sync::harness::test_sync_use_existing_db_exact_match::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_lower_bound_decrease() {
                crate::qmdb::sync::harness::test_target_update_lower_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_upper_bound_decrease() {
                crate::qmdb::sync::harness::test_target_update_upper_bound_decrease::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_bounds_increase() {
                crate::qmdb::sync::harness::test_target_update_bounds_increase::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_on_done_client() {
                crate::qmdb::sync::harness::test_target_update_on_done_client::<$harness>();
            }

            $( $extra!($harness); )?
        }
    };
}
pub(crate) use sync_tests;
