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
            source::tests::FailSource,
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::sha256;
use commonware_macros::boxed;
use commonware_runtime::{BufferPooler, Metrics, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc, non_empty_range, sync::AsyncRwLock};
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
    /// Merkle family of the database.
    type Family: merkle::Family;
    /// Database under test, which the sync engine builds, reopens, and serves from.
    type Db: qmdb::sync::Database<
            Family = Self::Family,
            Context = deterministic::Context,
            Digest = sha256::Digest,
            Config: Clone,
        > + Sync;
    /// Metadata type carried by commits.
    type Metadata: Clone + PartialEq + Debug + Send + Sync + 'static;

    /// Returns a config whose partitions are unique to `suffix`.
    fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self>;
    /// Returns `n` operations from a fixed seed.
    fn create_ops(n: usize) -> Vec<OpOf<Self>>;
    /// Returns `n` operations from `seed`, so distinct seeds touch distinct keys or values.
    fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>>;
    /// Returns the metadata the shared tests commit, so they can check it round-trips.
    fn sample_metadata() -> Self::Metadata;

    /// Opens a fresh database under partitions unique to `ctx`.
    fn init_db(ctx: deterministic::Context) -> impl Future<Output = Self::Db> + Send;
    /// Opens the database that `config` names, recovering any state it persisted.
    fn init_db_with_config(
        ctx: deterministic::Context,
        config: ConfigOf<Self>,
    ) -> impl Future<Output = Self::Db> + Send;
    /// Removes all persisted state of `db`.
    fn destroy(db: Self::Db) -> impl Future<Output = ()> + Send;
    /// Makes every applied operation of `db` durable.
    fn db_sync(db: Self::Db) -> impl Future<Output = Self::Db> + Send;

    /// Applies `ops` as one batch whose commit carries `metadata` and keeps the current
    /// inactivity floor. The result is durable only after [`Self::db_sync`].
    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Metadata>,
    ) -> impl Future<Output = Self::Db> + Send;

    /// Prunes operations before `loc`, or before the sync boundary of `db` when it precedes
    /// `loc`.
    ///
    /// Databases whose batches declare their inactivity floor raise it to `loc` first.
    fn prune(db: Self::Db, loc: Location<Self::Family>) -> impl Future<Output = Self::Db> + Send;

    /// Returns the range of retained operation locations in `db`.
    fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>>;

    /// Returns the most recent location from which `db` can be safely synced.
    fn sync_boundary(db: &Self::Db) -> Location<Self::Family>;

    /// Returns the location before which every operation in `db` is inactive.
    fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family>;

    /// Returns the root that sync verifies operations against.
    fn db_root(db: &Self::Db) -> sha256::Digest;

    /// Returns the root that commits to the full state of `db`.
    ///
    /// It differs from [`Self::db_root`] only for databases that authenticate more than their
    /// operations.
    fn canonical_root(db: &Self::Db) -> sha256::Digest {
        Self::db_root(db)
    }

    /// Returns the metadata carried by the last commit in `db`.
    fn get_metadata(db: &Self::Db) -> impl Future<Output = Option<Self::Metadata>> + Send;

    /// Panics unless every operation in `ops` is present in `db`, where `start` is the location
    /// at which `ops` were applied as one batch.
    ///
    /// For keyed databases, each key resolves to the value that applying `ops` in order leaves
    /// it with. For keyless databases, the value of the k-th operation is stored at `start + k`.
    fn assert_ops_applied(
        db: &Self::Db,
        start: Location<Self::Family>,
        ops: &[OpOf<Self>],
    ) -> impl Future<Output = ()> + Send;

    /// Panics if any operation in `ops` is present in `db`.
    ///
    /// For keyed databases, no key that `ops` sets resolves to a value. For keyless databases,
    /// no operation value is stored within the bounds of `db`.
    fn assert_ops_absent(db: &Self::Db, ops: &[OpOf<Self>]) -> impl Future<Output = ()> + Send;
}

/// A client synced from the target's sync boundary matches the target's bounds, floor, and roots,
/// stays in step with the target under further operations, and keeps that state across a reopen.
/// The cases vary the target size against the fetch batch size.
pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Prune the target as far as its sync boundary permits and request the range that begins
        // at that boundary.
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(target_db_ops);
        let target_start = H::bounds(&target_db).end;
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;
        let lower_bound = H::sync_boundary(&target_db);
        let target_db = H::prune(target_db, lower_bound).await;
        let target_op_count = H::bounds(&target_db).end;
        let target_floor = H::inactivity_floor_loc(&target_db);
        let target_root = H::db_root(&target_db);
        let target_canonical_root = H::canonical_root(&target_db);

        let db_config = H::config(&format!("sync_client_{}", context.next_u64()), &context);
        let client_context = context.child("client");
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size,
            target: Target {
                root: target_root,
                range: non_empty_range!(lower_bound, target_op_count),
            },
            context: client_context.child("client"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let got_db: DbOf<H> = sync::sync(config).await.unwrap();

        let bounds = H::bounds(&got_db);
        assert_eq!(bounds.end, target_op_count);
        assert_eq!(bounds.start, lower_bound);
        assert_eq!(H::inactivity_floor_loc(&got_db), target_floor);
        assert_eq!(H::db_root(&got_db), target_root);
        assert_eq!(H::canonical_root(&got_db), target_canonical_root);

        H::assert_ops_applied(&got_db, target_start, &target_ops).await;

        // The same new operations give both databases the same root and leave every operation
        // readable, so the synced client is a usable continuation of the target.
        let new_ops = H::create_ops_seeded(target_db_ops, 1);
        let new_start = H::bounds(&got_db).end;
        let got_db = H::apply_ops(got_db, new_ops.clone(), None).await;
        let target_db = Arc::try_unwrap(target_db)
            .unwrap_or_else(|_| panic!("target_db should have no other references"));
        let target_db = H::apply_ops(target_db, new_ops.clone(), None).await;

        assert_eq!(H::db_root(&got_db), H::db_root(&target_db));
        H::assert_ops_applied(&got_db, target_start, &target_ops).await;
        H::assert_ops_applied(&got_db, new_start, &new_ops).await;

        // The continued state persists across a reopen.
        let got_db = H::db_sync(got_db).await;
        drop(got_db);
        let got_db = H::init_db_with_config(client_context.child("reopened"), db_config).await;
        assert_eq!(H::bounds(&got_db).end, H::bounds(&target_db).end);
        assert_eq!(
            H::inactivity_floor_loc(&got_db),
            H::inactivity_floor_loc(&target_db)
        );
        assert_eq!(H::canonical_root(&got_db), H::canonical_root(&target_db));
        H::assert_ops_applied(&got_db, target_start, &target_ops).await;
        H::assert_ops_applied(&got_db, new_start, &new_ops).await;

        H::destroy(got_db).await;
        H::destroy(target_db).await;
    });
}

/// An empty client synced to a target that holds only commits recovers the target's bounds, root,
/// and commit metadata.
pub(crate) fn test_sync_empty_to_nonempty<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // The target applies no operations, so its history holds only commits, the last carrying
        // metadata.
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
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
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

/// A synced database that is made durable and reopened keeps the target's root, bounds, and
/// operations.
pub(crate) fn test_sync_database_persistence<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // The sync range spans the target's full retained history.
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(10);
        let target_start = H::bounds(&target_db).end;
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
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        let expected_root = H::db_root(&synced_db);
        let bounds = H::bounds(&synced_db);
        let expected_op_count = bounds.end;
        let expected_oldest_retained_loc = bounds.start;

        // A reopen from the same config must recover the synced state from storage alone.
        H::db_sync(synced_db).await;
        let reopened_db = H::init_db_with_config(context.child("reopened"), db_config).await;

        assert_eq!(H::db_root(&reopened_db), expected_root);
        let bounds = H::bounds(&reopened_db);
        assert_eq!(bounds.end, expected_op_count);
        assert_eq!(bounds.start, expected_oldest_retained_loc);

        H::assert_ops_applied(&reopened_db, target_start, &target_ops).await;

        H::destroy(reopened_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// A database synced to a newer target and then synced to an older one holds the older state,
/// which persists across a reopen.
pub(crate) fn test_sync_rewinds_to_older_target<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // The older target covers the shared base operations.
        let base_ops = H::create_ops(10);
        let older_source_config = H::config(&context.next_u64().to_string(), &context);
        let older_source =
            H::init_db_with_config(context.child("older_source"), older_source_config).await;
        let older_source = H::apply_ops(older_source, base_ops.clone(), None).await;
        let older_target = Target {
            root: H::db_root(&older_source),
            range: non_empty_range!(
                H::sync_boundary(&older_source),
                H::bounds(&older_source).end
            ),
        };
        let older_root = H::canonical_root(&older_source);

        // The newer source extends the same base history, so its target ends past the older one.
        let newer_source_config = H::config(&context.next_u64().to_string(), &context);
        let newer_source =
            H::init_db_with_config(context.child("newer_source"), newer_source_config).await;
        let newer_source = H::apply_ops(newer_source, base_ops, None).await;
        let newer_source = H::apply_ops(newer_source, H::create_ops_seeded(5, 1), None).await;
        let newer_target = Target {
            root: H::db_root(&newer_source),
            range: non_empty_range!(
                H::sync_boundary(&newer_source),
                H::bounds(&newer_source).end
            ),
        };
        let newer_root = H::canonical_root(&newer_source);
        assert!(newer_target.range.end() > older_target.range.end());

        // Sync the client to the newer target first, leaving that state in its storage.
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let client_context = context.child("client");
        let older_source = Arc::new(older_source);
        let newer_source = Arc::new(newer_source);
        let synced_db: DbOf<H> = sync::sync(Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: newer_target,
            context: client_context.child("newer"),
            source: newer_source.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        })
        .await
        .unwrap();
        assert_eq!(H::canonical_root(&synced_db), newer_root);
        drop(synced_db);

        // Syncing the same storage to the older target must rewind it to the older state.
        let recovered_db: DbOf<H> = sync::sync(Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: older_target.clone(),
            context: client_context.child("older"),
            source: older_source.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        })
        .await
        .unwrap();

        assert_eq!(H::canonical_root(&recovered_db), older_root);
        assert_eq!(H::bounds(&recovered_db).end, older_target.range.end());
        assert_eq!(H::sync_boundary(&recovered_db), older_target.range.start());
        drop(recovered_db);

        // The rewind is durable, so a reopen recovers the older state.
        let reopened_db = H::init_db_with_config(client_context.child("reopened"), db_config).await;
        assert_eq!(H::canonical_root(&reopened_db), older_root);
        assert_eq!(H::bounds(&reopened_db).end, older_target.range.end());
        assert_eq!(H::sync_boundary(&reopened_db), older_target.range.start());

        H::destroy(
            Arc::try_unwrap(older_source).unwrap_or_else(|_| panic!("failed to unwrap Arc")),
        )
        .await;
        H::destroy(
            Arc::try_unwrap(newer_source).unwrap_or_else(|_| panic!("failed to unwrap Arc")),
        )
        .await;
        H::destroy(reopened_db).await;
    });
}

/// A client that has started applying operations adopts a target update and completes at the
/// newer target with every operation applied. The cases vary the initial target size and the
/// number of operations the update adds, and also the fetch batch size.
pub(crate) fn test_target_update_during_sync<H: SyncTestHarness>(
    initial_ops: usize,
    additional_ops: usize,
    fetch_batch_size: NonZeroU64,
) where
    OpOf<H>: Encode + Clone,
    Arc<AsyncRwLock<Option<DbOf<H>>>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let initial_ops = H::create_ops(initial_ops);
        let initial_start = H::bounds(&target_db).end;
        let target_db = H::apply_ops(target_db, initial_ops.clone(), None).await;

        let initial_lower_bound = H::sync_boundary(&target_db);
        let initial_upper_bound = H::bounds(&target_db).end;
        let initial_root = H::db_root(&target_db);

        // The source is shared so the target can advance while the client syncs.
        let target_db = Arc::new(AsyncRwLock::new(Some(target_db)));

        // Step the client until it has applied an operation past the initial lower bound, so the
        // update arrives mid-sync.
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
                fetch_batch_size,
                max_outstanding_requests: NZUsize!(10),
                apply_batch_size: NZU64!(1024),
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
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

        // Advance the shared source and send its new target while the client is mid-sync.
        let additional_ops = H::create_ops_seeded(additional_ops, 1);
        let (additional_start, final_target) = {
            let mut db_guard = target_db.write().await;
            let db = db_guard.take().unwrap();
            let additional_start = H::bounds(&db).end;
            let db = H::apply_ops(db, additional_ops.clone(), None).await;
            let final_target = Target {
                root: H::db_root(&db),
                range: non_empty_range!(H::sync_boundary(&db), H::bounds(&db).end),
            };
            *db_guard = Some(db);
            (additional_start, final_target)
        };
        update_sender.send(final_target.clone()).await.unwrap();

        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), final_target.root);

        let target_db = Arc::try_unwrap(target_db).map_or_else(
            |_| panic!("Failed to unwrap Arc"),
            |lock| lock.into_inner().expect("db should be present"),
        );
        {
            let bounds = H::bounds(&synced_db);
            assert_eq!(bounds.end, H::bounds(&target_db).end);
            assert_eq!(bounds.start, final_target.range.start());
            assert_eq!(
                H::inactivity_floor_loc(&synced_db),
                H::inactivity_floor_loc(&target_db)
            );
            assert_eq!(H::db_root(&synced_db), H::db_root(&target_db));
            assert_eq!(H::canonical_root(&synced_db), H::canonical_root(&target_db));
        }

        H::assert_ops_applied(&synced_db, initial_start, &initial_ops).await;
        H::assert_ops_applied(&synced_db, additional_start, &additional_ops).await;

        H::destroy(synced_db).await;
        H::destroy(target_db).await;
    });
}

/// A client synced to a historical target of a source that has since advanced matches that target
/// and holds none of the later operations.
pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        // Record the target before the final operation, so it names a strict prefix of the
        // source.
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(1000);
        let (synced_ops, later_ops) = target_ops.split_at(target_ops.len() - 1);
        let target_db = H::apply_ops(target_db, synced_ops.to_vec(), None).await;

        let target_root = H::db_root(&target_db);
        let target_canonical_root = H::canonical_root(&target_db);
        let lower_bound = H::sync_boundary(&target_db);
        let op_count = H::bounds(&target_db).end;

        // Advance the source past the target, so it must serve the target from history.
        let target_db = H::apply_ops(target_db, later_ops.to_vec(), None).await;

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
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        // The later operation lies past the target and must be absent from the client.
        assert_eq!(H::db_root(&synced_db), target_root);
        assert_eq!(H::canonical_root(&synced_db), target_canonical_root);
        assert_eq!(H::bounds(&synced_db).end, op_count);
        assert_eq!(H::sync_boundary(&synced_db), lower_bound);
        H::assert_ops_absent(&synced_db, later_ops).await;

        H::destroy(synced_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// Syncing into client storage that has already applied a prefix of the target's operations
/// yields the target's floor, roots, and operations.
pub(crate) fn test_sync_use_existing_db_partial_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let original_ops = H::create_ops(1000);

        let target_db = H::init_db(context.child("target")).await;
        let sync_db_config = H::config(&format!("partial_{}", context.next_u64()), &context);
        let client_context = context.child("client");
        let sync_db =
            H::init_db_with_config(client_context.child("client"), sync_db_config.clone()).await;

        // The client applies the same operations as the target, then releases its storage.
        let original_start = H::bounds(&target_db).end;
        let target_db = H::apply_ops(target_db, original_ops.clone(), None).await;
        H::apply_ops(sync_db, original_ops.clone(), None).await;

        // One more operation on the target leaves the client holding all but its tail.
        let last_op = H::create_ops_seeded(1, 1);
        let last_start = H::bounds(&target_db).end;
        let target_db = H::apply_ops(target_db, last_op.clone(), None).await;
        let root = H::db_root(&target_db);
        let canonical_root = H::canonical_root(&target_db);
        let floor = H::inactivity_floor_loc(&target_db);
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: sync_db_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: client_context.child("sync"),
            source: target_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).end, upper_bound);
        assert_eq!(H::inactivity_floor_loc(&sync_db), floor);
        assert_eq!(H::db_root(&sync_db), root);
        assert_eq!(H::canonical_root(&sync_db), canonical_root);
        H::assert_ops_applied(&sync_db, original_start, &original_ops).await;
        H::assert_ops_applied(&sync_db, last_start, &last_op).await;

        H::destroy(sync_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// A client whose persisted state already equals the target completes without fetching from the
/// source and keeps the target's state.
pub(crate) fn test_sync_use_existing_db_exact_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_ops = H::create_ops(1000);

        let target_db = H::init_db(context.child("target")).await;
        let sync_config = H::config(&format!("exact_{}", context.next_u64()), &context);
        let client_context = context.child("client");
        let sync_db =
            H::init_db_with_config(client_context.child("client"), sync_config.clone()).await;

        // Both databases apply the same operations and prune to their sync boundaries, so the
        // client's persisted state equals the target.
        let target_start = H::bounds(&target_db).end;
        let target_db = H::apply_ops(target_db, target_ops.clone(), None).await;
        let sync_db = H::apply_ops(sync_db, target_ops.clone(), None).await;
        let boundary = H::sync_boundary(&target_db);
        let target_db = H::prune(target_db, boundary).await;
        let boundary = H::sync_boundary(&sync_db);
        let sync_db = H::prune(sync_db, boundary).await;
        drop(H::db_sync(sync_db).await);

        let root = H::db_root(&target_db);
        let canonical_root = H::canonical_root(&target_db);
        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;

        // The existing database already holds the target, so the source is never queried.
        let config = Config {
            db_config: sync_config,
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: client_context.child("sync"),
            source: FailSource::<H::Family, OpOf<H>, sha256::Digest>::new(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).end, upper_bound);
        assert_eq!(H::sync_boundary(&sync_db), lower_bound);
        assert_eq!(H::db_root(&sync_db), root);
        assert_eq!(H::canonical_root(&sync_db), canonical_root);
        H::assert_ops_applied(&sync_db, target_start, &target_ops).await;

        H::destroy(sync_db).await;
        H::destroy(target_db).await;
    });
}

/// Updates that lower the target's lower bound do not advance the target and are discarded, even
/// when they raise the upper bound.
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

        // Start at the inactivity floor, which is positive on every database, so the updates
        // below can decrease it. The engine requires only that the lower bound never decreases,
        // not that it equals the sync boundary.
        let initial_lower_bound = H::inactivity_floor_loc(&target_db);
        assert!(
            *initial_lower_bound > 0,
            "test setup requires non-zero inactivity floor"
        );
        let initial_upper_bound = H::bounds(&target_db).end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(2);
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
            max_outstanding_requests: NZUsize!(10),
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        // Both updates keep the root, so adopting the one with a larger end would fail sync with
        // an unchanged root.
        let lower_bound = initial_lower_bound.checked_sub(1).unwrap();
        for upper_bound in [
            initial_upper_bound,
            initial_upper_bound.checked_add(1).unwrap(),
        ] {
            update_sender
                .send(Target {
                    root: initial_root,
                    range: non_empty_range!(lower_bound, upper_bound),
                })
                .await
                .unwrap();
        }

        // The non-advancing updates are discarded and the sync completes at the original target.
        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), initial_root);
        assert_eq!(H::canonical_root(&synced_db), H::canonical_root(&target_db));
        H::destroy(synced_db).await;

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// An update that lowers the target's upper bound does not advance the target and is discarded.
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

        let initial_lower_bound = H::sync_boundary(&target_db);
        let initial_upper_bound = H::bounds(&target_db).end;
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
            max_outstanding_requests: NZUsize!(10),
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        // The update keeps the root and lower bound but ends one operation earlier.
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
        assert_eq!(H::canonical_root(&synced_db), H::canonical_root(&target_db));
        H::destroy(synced_db).await;

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// An update that raises both bounds is adopted, and the client completes with the updated
/// target's bounds, floor, roots, and sync boundary.
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

        // The lower bounds are inactivity floors, which advance with the target on every
        // database.
        let initial_lower_bound = H::inactivity_floor_loc(&target_db);
        let initial_upper_bound = H::bounds(&target_db).end;
        let initial_root = H::db_root(&target_db);

        // More operations move the target's upper bound.
        let more_ops = H::create_ops_seeded(5, 1);
        let target_db = H::apply_ops(target_db, more_ops, None).await;

        // Pruning and a later commit move the target's inactivity floor.
        let target_db = H::prune(target_db, Location::new(10)).await;
        let target_db = H::apply_ops(target_db, vec![], None).await;

        let final_lower_bound = H::inactivity_floor_loc(&target_db);
        let final_upper_bound = H::bounds(&target_db).end;
        let final_root = H::db_root(&target_db);
        let final_canonical_root = H::canonical_root(&target_db);
        let final_boundary = H::sync_boundary(&target_db);

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
            max_outstanding_requests: NZUsize!(1),
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
        };

        // Queue the update before sync starts, so it is pending from the first step.
        update_sender
            .send(Target {
                root: final_root,
                range: non_empty_range!(final_lower_bound, final_upper_bound),
            })
            .await
            .unwrap();

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), final_root);
        assert_eq!(H::canonical_root(&synced_db), final_canonical_root);
        let bounds = H::bounds(&synced_db);
        assert_eq!(bounds.end, final_upper_bound);
        assert_eq!(bounds.start, final_lower_bound);
        assert_eq!(H::inactivity_floor_loc(&synced_db), final_lower_bound);
        assert_eq!(H::sync_boundary(&synced_db), final_boundary);

        H::destroy(synced_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

/// An update sent after sync has returned leaves the synced database at the original target.
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

        let lower_bound = H::sync_boundary(&target_db);
        let upper_bound = H::bounds(&target_db).end;
        let root = H::db_root(&target_db);
        let canonical_root = H::canonical_root(&target_db);

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
            max_outstanding_requests: NZUsize!(10),
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
        };

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        // Sync has returned and dropped the update receiver, so the late update cannot reach it.
        let _ = update_sender
            .send(Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(lower_bound + 1, upper_bound + 1),
            })
            .await;

        assert_eq!(H::db_root(&synced_db), root);
        assert_eq!(H::canonical_root(&synced_db), canonical_root);
        let bounds = H::bounds(&synced_db);
        assert_eq!(bounds.end, upper_bound);
        assert_eq!(bounds.start, lower_bound);
        assert_eq!(H::sync_boundary(&synced_db), lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

/// A source error is terminal, so sync over a source that fails every request returns an error.
pub(crate) fn test_sync_source_fails<H: SyncTestHarness>()
where
    OpOf<H>: Encode,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            context: context.child("client"),
            target: Target {
                root: sha256::Digest::from([0; 32]),
                range: non_empty_range!(Location::new(0), Location::new(5)),
            },
            source: FailSource::<H::Family, OpOf<H>, sha256::Digest>::new(),
            apply_batch_size: NZU64!(2),
            max_outstanding_requests: NZUsize!(2),
            fetch_batch_size: NZU64!(2),
            db_config,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };

        let result: Result<DbOf<H>, _> = sync::sync(config).await;
        assert!(result.is_err());
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
        max_outstanding_requests: NZUsize!(1),
        update_rx: None,
        finish_rx: None,
        reached_target_tx: None,
    }
}

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
            #[case::small_batch_size_one(10, 1)]
            #[case::small_batch_size_gt_db_size(10, 20)]
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
            fn test_sync_rewinds_to_older_target() {
                crate::qmdb::sync::harness::test_sync_rewinds_to_older_target::<$harness>();
            }

            #[rstest]
            #[case(1, 1, 1)]
            #[case(1, 2, 1)]
            #[case(1, 100, 1)]
            #[case(2, 1, 1)]
            #[case(2, 2, 1)]
            #[case(2, 100, 1)]
            // Regression test: panicked when we didn't set pinned nodes after updating target
            #[case(20, 10, 1)]
            #[case(100, 1, 1)]
            #[case(100, 2, 1)]
            #[case(100, 100, 1)]
            #[case(100, 1000, 1)]
            #[case(50, 25, 1)]
            #[case::batch_size_two(50, 25, 2)]
            fn test_target_update_during_sync(
                #[case] initial_ops: usize,
                #[case] additional_ops: usize,
                #[case] fetch_batch_size: u64,
            ) {
                crate::qmdb::sync::harness::test_target_update_during_sync::<$harness>(
                    initial_ops,
                    additional_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
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

            #[test_traced("WARN")]
            fn test_sync_source_fails() {
                crate::qmdb::sync::harness::test_sync_source_fails::<$harness>();
            }

            $( $extra!($harness); )?
        }
    };
}
pub(crate) use sync_tests;
