//! Generic sync tests for keyless databases.
//!
//! This module defines a [`SyncTestHarness`] trait and generic test functions parameterized
//! over the harness, so the same tests can run against any combination of merkle family
//! (MMR, MMB) and database variant. Per-harness concrete `#[test]` functions are expanded
//! by the [`sync_tests_for_harness!`] macro.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, full::Config as MerkleConfig, mmb, mmr, Family, Location},
    qmdb::{
        self,
        keyless::{self, variable, Operation},
        sync::{
            self,
            engine::{Config, NextStep},
            resolver::{tests::FailResolver, Resolver},
            Engine, Target,
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{sha256, Sha256};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner as _, Supervisor as _,
};
use commonware_utils::{channel::mpsc, non_empty_range, test_rng_seeded, NZUsize, NZU16, NZU64};
use rand::RngCore as _;
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

pub(crate) type DbOf<H> = <H as SyncTestHarness>::Db;
pub(crate) type OpOf<H> = <DbOf<H> as qmdb::sync::Database>::Op;
pub(crate) type ConfigOf<H> = <DbOf<H> as qmdb::sync::Database>::Config;
pub(crate) type JournalOf<H> = <DbOf<H> as qmdb::sync::Database>::Journal;

const PAGE_SIZE: NonZeroU16 = NZU16!(77);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

/// Harness that abstracts per-family/per-variant details so the generic tests below
/// can operate on any keyless database.
pub(crate) trait SyncTestHarness: Sized + 'static {
    type Family: merkle::Family;
    type Db: qmdb::sync::Database<
            Family = Self::Family,
            Context = deterministic::Context,
            Digest = sha256::Digest,
            Config: Clone,
        > + Send
        + Sync;
    type Value: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static;

    fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self>;
    fn create_ops(n: usize) -> Vec<OpOf<Self>>;
    fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>>;
    fn sample_metadata() -> Self::Value;

    fn init_db(ctx: deterministic::Context) -> impl Future<Output = Self::Db> + Send;
    fn init_db_with_config(
        ctx: deterministic::Context,
        config: ConfigOf<Self>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn destroy(db: Self::Db) -> impl Future<Output = ()> + Send;
    fn db_sync(db: &Self::Db) -> impl Future<Output = ()> + Send;

    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn prune(db: &mut Self::Db, loc: Location<Self::Family>) -> impl Future<Output = ()> + Send;

    fn bounds(
        db: &Self::Db,
    ) -> impl Future<Output = std::ops::Range<Location<Self::Family>>> + Send;
    fn db_root(db: &Self::Db) -> sha256::Digest;
    fn get_metadata(db: &Self::Db) -> impl Future<Output = Option<Self::Value>> + Send;
    fn get_value(
        db: &Self::Db,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Option<Self::Value>> + Send;
    fn op_value(op: &OpOf<Self>) -> Option<&Self::Value>;
}

// ===== Generic tests =====

pub(crate) fn test_sync_resolver_fails<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let resolver = FailResolver::<H::Family, OpOf<H>, sha256::Digest>::new();
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            context: context.child("client"),
            target: Target::from_root(sha256::Digest::from([0; 32]), non_empty_range!(Location::new(0), Location::new(5))),
            resolver,
            apply_batch_size: 2,
            max_outstanding_requests: 2,
            fetch_batch_size: NZU64!(2),
            db_config,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };

        let result: Result<DbOf<H>, _> = sync::sync(config).await;
        assert!(result.is_err());
    });
}

pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(target_db_ops);
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;
        let bounds = H::bounds(&target_db).await;
        let target_op_count = bounds.end;
        let target_oldest_retained_loc = bounds.start;
        let target_root = H::db_root(&target_db);

        let db_config = H::config(&format!("sync_client_{}", context.next_u64()), &context);

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size,
            target: Target::from_root(target_root, non_empty_range!(target_oldest_retained_loc, target_op_count)),
            context: context.child("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let got_db: DbOf<H> = sync::sync(config).await.unwrap();

        let bounds = H::bounds(&got_db).await;
        assert_eq!(bounds.end, target_op_count);
        assert_eq!(bounds.start, target_oldest_retained_loc);
        assert_eq!(H::db_root(&got_db), target_root);

        for (i, op) in target_ops.iter().enumerate() {
            if let Some(expected_value) = H::op_value(op) {
                // +1 because location 0 is the initial commit
                let got = H::get_value(&got_db, Location::new(i as u64 + 1)).await;
                assert_eq!(got.as_ref(), Some(expected_value));
            }
        }

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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops(target_db, vec![], Some(H::sample_metadata())).await;

        let bounds = H::bounds(&target_db).await;
        let target_op_count = bounds.end;
        let target_oldest_retained_loc = bounds.start;
        let target_root = H::db_root(&target_db);

        let db_config = H::config(&format!("empty_sync_{}", context.next_u64()), &context);
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config,
            fetch_batch_size: NZU64!(10),
            target: Target::from_root(target_root, non_empty_range!(target_oldest_retained_loc, target_op_count)),
            context: context.child("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let got_db: DbOf<H> = sync::sync(config).await.unwrap();

        let bounds = H::bounds(&got_db).await;
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(10);
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;

        let target_root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let op_count = bounds.end;

        let db_config = H::config("persistence-test", &context);
        let client_context = context.child("client");
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: Target::from_root(target_root, non_empty_range!(lower_bound, op_count)),
            context: client_context.child("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        let expected_root = H::db_root(&synced_db);
        let bounds = H::bounds(&synced_db).await;
        let expected_op_count = bounds.end;
        let expected_oldest_retained_loc = bounds.start;

        H::db_sync(&synced_db).await;
        drop(synced_db);
        let reopened_db = H::init_db_with_config(context.child("reopened"), db_config).await;

        assert_eq!(H::db_root(&reopened_db), expected_root);
        let bounds = H::bounds(&reopened_db).await;
        assert_eq!(bounds.end, expected_op_count);
        assert_eq!(bounds.start, expected_oldest_retained_loc);

        for (i, op) in target_ops.iter().enumerate() {
            if let Some(expected_value) = H::op_value(op) {
                let got = H::get_value(&reopened_db, Location::new(i as u64 + 1)).await;
                assert_eq!(got.as_ref(), Some(expected_value));
            }
        }

        H::destroy(reopened_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_during_sync<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let initial_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, initial_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let additional_ops = H::create_ops_seeded(25, 1);
        let target_db = H::apply_ops(target_db, additional_ops, None).await;
        let final_upper_bound = H::bounds(&target_db).await.end;
        let final_root = H::db_root(&target_db);

        let target_db = Arc::new(target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let client = {
            let config = Config {
                context: context.child("client"),
                db_config: H::config(&format!("update_test_{}", context.next_u64()), &context),
                target: Target::from_root(initial_root, non_empty_range!(initial_lower_bound, initial_upper_bound)),
                resolver: target_db.clone(),
                fetch_batch_size: NZU64!(2),
                max_outstanding_requests: 10,
                apply_batch_size: 1024,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };
            let mut client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();
            loop {
                client = match client.step().await.unwrap() {
                    NextStep::Continue(new_client) => new_client,
                    NextStep::Complete(..) => panic!("client should not be complete"),
                };
                let log_size = Contiguous::size(client.journal()).await;
                if log_size > *initial_lower_bound {
                    break client;
                }
            }
        };

        update_sender
            .send(Target::from_root(final_root, non_empty_range!(initial_lower_bound, final_upper_bound)))
            .await
            .unwrap();

        let synced_db = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced_db), final_root);

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
        {
            let bounds = H::bounds(&synced_db).await;
            let target_bounds = H::bounds(&target_db).await;
            assert_eq!(bounds.end, target_bounds.end);
            assert_eq!(bounds.start, target_bounds.start);
            assert_eq!(H::db_root(&synced_db), H::db_root(&target_db));
        }

        H::destroy(synced_db).await;
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(30);
        let target_db = H::apply_ops(target_db, target_ops[..29].to_vec(), None).await;

        let target_root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let op_count = bounds.end;

        let target_db = H::apply_ops(target_db, target_ops[29..].to_vec(), None).await;

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: H::config(&format!("subset_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(10),
            target: Target::from_root(target_root, non_empty_range!(lower_bound, op_count)),
            context: context.child("client"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        assert_eq!(H::bounds(&synced_db).await.end, op_count);

        H::destroy(synced_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_use_existing_db_partial_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
        let sync_db = H::apply_ops(sync_db, original_ops, None).await;
        drop(sync_db);

        let last_op = H::create_ops_seeded(1, 1);
        let target_db = H::apply_ops(target_db, last_op, None).await;
        let root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;

        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: sync_db_config,
            fetch_batch_size: NZU64!(10),
            target: Target::from_root(root, non_empty_range!(lower_bound, upper_bound)),
            context: context.child("sync"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).await.end, upper_bound);
        assert_eq!(H::db_root(&sync_db), root);

        H::destroy(sync_db).await;
        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_use_existing_db_exact_match<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
        let sync_db = H::apply_ops(sync_db, target_ops, None).await;
        drop(sync_db);

        let root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;

        let resolver = Arc::new(target_db);
        let config = Config {
            db_config: sync_config,
            fetch_batch_size: NZU64!(10),
            target: Target::from_root(root, non_empty_range!(lower_bound, upper_bound)),
            context: context.child("sync"),
            resolver: resolver.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        };
        let sync_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&sync_db).await.end, upper_bound);
        assert_eq!(H::db_root(&sync_db), root);

        H::destroy(sync_db).await;
        let target_db =
            Arc::try_unwrap(resolver).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_lower_bound_decrease<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(100);
        let mut target_db = H::apply_ops(target_db, target_ops, None).await;

        H::prune(&mut target_db, Location::new(10)).await;

        let bounds = H::bounds(&target_db).await;
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("lb-dec-{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(5),
            target: Target::from_root(initial_root, non_empty_range!(initial_lower_bound, initial_upper_bound)),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        update_sender
            .send(Target::from_root(
                initial_root,
                non_empty_range!(
                    initial_lower_bound.checked_sub(1).unwrap(),
                    initial_upper_bound
                ),
            ))
            .await
            .unwrap();

        let result = client.step().await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(
                sync::EngineError::SyncTargetMovedBackward { .. }
            ))
        ));

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_upper_bound_decrease<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("ub-dec-{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(5),
            target: Target::from_root(initial_root, non_empty_range!(initial_lower_bound, initial_upper_bound)),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        update_sender
            .send(Target::from_root(initial_root, non_empty_range!(initial_lower_bound, initial_upper_bound - 1)))
            .await
            .unwrap();

        let result = client.step().await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(
                sync::EngineError::SyncTargetMovedBackward { .. }
            ))
        ));

        let target_db =
            Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_target_update_bounds_increase<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(100);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let more_ops = H::create_ops_seeded(5, 1);
        let mut target_db = H::apply_ops(target_db, more_ops, None).await;

        H::prune(&mut target_db, Location::new(10)).await;
        let target_db = H::apply_ops(target_db, vec![], None).await;

        let bounds = H::bounds(&target_db).await;
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
            target: Target::from_root(initial_root, non_empty_range!(initial_lower_bound, initial_upper_bound)),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        update_sender
            .send(Target::from_root(final_root, non_empty_range!(final_lower_bound, final_upper_bound)))
            .await
            .unwrap();

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), final_root);
        let bounds = H::bounds(&synced_db).await;
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Resolver<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_ops = H::create_ops(10);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;
        let root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.child("client"),
            db_config: H::config(&format!("done_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(20),
            target: Target::from_root(root, non_empty_range!(lower_bound, upper_bound)),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 10,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        let _ = update_sender
            .send(Target::from_root(sha256::Digest::from([2u8; 32]), non_empty_range!(lower_bound + 1, upper_bound + 1)))
            .await;

        assert_eq!(H::db_root(&synced_db), root);
        let bounds = H::bounds(&synced_db).await;
        assert_eq!(bounds.end, upper_bound);
        assert_eq!(bounds.start, lower_bound);

        H::destroy(synced_db).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc")))
            .await;
    });
}

// ===== Harness implementations =====

pub(crate) mod harnesses {
    use super::*;
    use commonware_parallel::Sequential;

    type VariableDb<F> = variable::Db<F, deterministic::Context, Vec<u8>, Sha256, Sequential>;
    type VariableOp<F> = Operation<F, crate::qmdb::any::value::VariableEncoding<Vec<u8>>>;

    fn variable_config(
        suffix: &str,
        pooler: &(impl BufferPooler + Metrics),
    ) -> variable::Config<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(5);

        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-{suffix}"),
                items_per_section: ITEMS_PER_SECTION,
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    fn variable_create_ops_seeded<F: Family>(n: usize, seed: u64) -> Vec<VariableOp<F>> {
        let mut rng = test_rng_seeded(seed);
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            let len = (rng.next_u32() % 100 + 1) as usize;
            let mut value = vec![0u8; len];
            rng.fill_bytes(&mut value);
            ops.push(Operation::Append(value));
        }
        ops
    }

    /// Applies the given operations and commits the database, advancing the inactivity floor to
    /// the new commit location so sync tests that exercise pruning can do so freely.
    async fn variable_apply_ops<F: Family>(
        mut db: VariableDb<F>,
        ops: Vec<VariableOp<F>>,
        metadata: Option<Vec<u8>>,
    ) -> VariableDb<F> {
        let appends = ops
            .iter()
            .filter(|op| matches!(op, Operation::Append(_)))
            .count() as u64;
        let new_commit = Location::new(db.last_commit_loc().as_u64() + 1 + appends);
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Append(value) => {
                    batch = batch.append(value);
                }
                Operation::Commit(_, _) => {
                    panic!("Commit operation not supported in apply_ops");
                }
            }
        }
        let merkleized = batch.merkleize(&db, metadata, new_commit);
        db.apply_batch(merkleized).await.unwrap();
        db
    }

    pub(crate) struct VariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> SyncTestHarness for VariableHarness<F> {
        type Family = F;
        type Db = VariableDb<F>;
        type Value = Vec<u8>;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
            variable_config(suffix, pooler)
        }

        fn create_ops(n: usize) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, 0)
        }

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, seed)
        }

        fn sample_metadata() -> Self::Value {
            vec![42]
        }

        async fn init_db(mut ctx: deterministic::Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config = variable_config(&format!("sync-test-{seed}"), &ctx);
            VariableDb::<F>::init(ctx, config).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: deterministic::Context,
            config: ConfigOf<Self>,
        ) -> Self::Db {
            VariableDb::<F>::init(ctx, config).await.unwrap()
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn db_sync(db: &Self::Db) {
            db.sync().await.unwrap();
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<OpOf<Self>>,
            metadata: Option<Self::Value>,
        ) -> Self::Db {
            variable_apply_ops::<F>(db, ops, metadata).await
        }

        async fn prune(db: &mut Self::Db, loc: Location<Self::Family>) {
            db.prune(loc).await.unwrap();
        }

        async fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>> {
            db.bounds().await
        }

        fn db_root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        async fn get_metadata(db: &Self::Db) -> Option<Self::Value> {
            db.get_metadata().await.unwrap()
        }

        async fn get_value(db: &Self::Db, loc: Location<Self::Family>) -> Option<Self::Value> {
            db.get(loc).await.unwrap()
        }

        fn op_value(op: &OpOf<Self>) -> Option<&Self::Value> {
            match op {
                Operation::Append(value) => Some(value),
                Operation::Commit(_, _) => None,
            }
        }
    }

    pub(crate) type VariableMmrHarness = VariableHarness<mmr::Family>;
    pub(crate) type VariableMmbHarness = VariableHarness<mmb::Family>;
}

// ===== Test Generation Macro =====

macro_rules! sync_tests_for_harness {
    ($harness:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::harnesses;
            use commonware_macros::test_traced;
            use rstest::rstest;
            use std::num::NonZeroU64;

            #[test_traced("WARN")]
            fn test_sync_resolver_fails() {
                super::test_sync_resolver_fails::<$harness>();
            }

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
                super::test_sync::<$harness>(
                    target_db_ops,
                    NonZeroU64::new(fetch_batch_size).unwrap(),
                );
            }

            #[test_traced("WARN")]
            fn test_sync_empty_to_nonempty() {
                super::test_sync_empty_to_nonempty::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_sync_database_persistence() {
                super::test_sync_database_persistence::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_target_update_during_sync() {
                super::test_target_update_during_sync::<$harness>();
            }

            #[test]
            fn test_sync_subset_of_target_database() {
                super::test_sync_subset_of_target_database::<$harness>();
            }

            #[test]
            fn test_sync_use_existing_db_partial_match() {
                super::test_sync_use_existing_db_partial_match::<$harness>();
            }

            #[test]
            fn test_sync_use_existing_db_exact_match() {
                super::test_sync_use_existing_db_exact_match::<$harness>();
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

            #[test_traced("WARN")]
            fn test_target_update_on_done_client() {
                super::test_target_update_on_done_client::<$harness>();
            }
        }
    };
}

sync_tests_for_harness!(harnesses::VariableMmrHarness, variable_mmr);
sync_tests_for_harness!(harnesses::VariableMmbHarness, variable_mmb);

mod compact_variable_mmr {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;

    type SourceDb = variable::Db<mmr::Family, deterministic::Context, Vec<u8>, Sha256, Sequential>;
    type ClientDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;

    fn source_config(
        suffix: &str,
        pooler: &(impl BufferPooler + Metrics),
    ) -> variable::Config<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    fn client_config(
        suffix: &str,
    ) -> variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        keyless::CompactConfig {
            merkle: crate::merkle::compact::Config {
                partition: format!("compact-{suffix}"),
                strategy: Sequential,
            },
            commit_codec_config: ((0..=10000).into(), ()),
        }
    }

    #[derive(Clone)]
    struct StaticResolver {
        state: sync::compact::State<
            mmr::Family,
            variable::Operation<mmr::Family, Vec<u8>>,
            sha256::Digest,
        >,
    }

    impl sync::compact::Resolver for StaticResolver {
        type Family = mmr::Family;
        type Digest = sha256::Digest;
        type Op = variable::Operation<mmr::Family, Vec<u8>>;
        type Error = qmdb::Error<mmr::Family>;

        async fn get_compact_state(
            &self,
            _target: sync::compact::Target<Self::Family, Self::Digest>,
        ) -> Result<sync::compact::State<Self::Family, Self::Op, Self::Digest>, Self::Error>
        {
            Ok(self.state.clone())
        }
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_missing_reports_missing_source() {
        deterministic::Runner::default().start(|_context| async move {
            let resolver: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb>>> =
                Arc::new(commonware_utils::sync::AsyncRwLock::new(None));
            let target = sync::compact::Target {
                root: sha256::Digest::from([0; 32]),
                leaf_count: Location::new(1),
            };

            assert!(matches!(
                sync::compact::Resolver::get_compact_state(&resolver, target).await,
                Err(sync::compact::ServeError::MissingSource)
            ));
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_roundtrip() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let metadata = vec![9, 9, 9];
            let floor = Location::new(2);
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor);
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix);
            let client: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: source.clone(),
                target: target.clone(),
                db_config: client_cfg.clone(),
            })
            .await
            .unwrap();

            assert_eq!(client.root(), target.root);
            assert_eq!(client.get_metadata(), Some(metadata.clone()));
            assert_eq!(client.inactivity_floor_loc(), floor);
            drop(client);

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            assert_eq!(reopened.get_metadata(), Some(metadata));
            assert_eq!(reopened.inactivity_floor_loc(), floor);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_invalid_proof() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-proof-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source.new_batch().append(vec![7, 8, 9]).merkleize(
                &source,
                Some(vec![1]),
                Location::new(1),
            );
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.last_commit_proof = crate::merkle::Proof::default();

            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver { state },
                target,
                db_config: client_config(&suffix),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::InvalidProof))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_tampered_pinned_nodes_without_persisting() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-pins-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2));
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let client_cfg = client_config(&suffix);
            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver {
                    state: state.clone(),
                },
                target: target.clone(),
                db_config: client_cfg.clone(),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::RootMismatch { .. }))
            ));

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.last_commit_loc(), Location::new(0));
            assert_eq!(reopened.get_metadata(), None);
            assert_eq!(reopened.inactivity_floor_loc(), Location::new(0));
            assert_ne!(reopened.root(), target.root);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_leaf_count_mismatch() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-leaf-count-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1));
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.leaf_count = Location::new(*state.leaf_count - 1);

            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver { state },
                target: target.clone(),
                db_config: client_config(&suffix),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::UnexpectedLeafCount {
                    expected,
                    actual
                })) if expected == target.leaf_count && actual == Location::new(*target.leaf_count - 1)
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_rejects_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-stale-full-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch1 = source.new_batch().append(vec![1, 2, 3]).merkleize(
                &source,
                Some(vec![1]),
                Location::new(1),
            );
            source.apply_batch(batch1).await.unwrap();
            source.commit().await.unwrap();
            let stale_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };

            let batch2 = source.new_batch().append(vec![4, 5, 6]).merkleize(
                &source,
                Some(vec![2]),
                Location::new(2),
            );
            source.apply_batch(batch2).await.unwrap();
            source.commit().await.unwrap();
            let current_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let result =
                sync::compact::Resolver::get_compact_state(&source, stale_target.clone()).await;
            assert!(matches!(
                result,
                Err(sync::compact::ServeError::StaleTarget { requested, current })
                    if requested == stale_target && current == current_target
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_source_reopen_rewind_regrow_and_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"));
            let mut source = ClientDb::init(context.child("source_init"), source_cfg.clone())
                .await
                .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source.new_batch().append(vec![10, 11]).merkleize(
                &source,
                Some(metadata1.clone()),
                floor1,
            );
            source.apply_batch(batch1).unwrap();
            source.sync().await.unwrap();
            let target1 = source.current_target();
            drop(source);

            let source = ClientDb::init(context.child("source_reopen"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.current_target(), target1);

            let serve1_cfg = client_config(&format!("{suffix}-serve1"));
            let served1: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 1),
                resolver: Arc::new(source),
                target: target1.clone(),
                db_config: serve1_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served1.root(), target1.root);
            assert_eq!(served1.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served1.inactivity_floor_loc(), floor1);
            served1.destroy().await.unwrap();

            let mut source = ClientDb::init(context.child("source_resume"), source_cfg.clone())
                .await
                .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source.new_batch().append(vec![20, 21]).merkleize(
                &source,
                Some(metadata2.clone()),
                floor2,
            );
            source.apply_batch(batch2).unwrap();
            source.sync().await.unwrap();
            let target2 = source.current_target();
            assert_ne!(target2, target1);

            source.rewind().await.unwrap();
            assert_eq!(source.current_target(), target1);

            let serve2_cfg = client_config(&format!("{suffix}-serve2"));
            let served2: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 2),
                resolver: Arc::new(source),
                target: target1.clone(),
                db_config: serve2_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served2.root(), target1.root);
            assert_eq!(served2.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served2.inactivity_floor_loc(), floor1);
            served2.destroy().await.unwrap();

            let mut source = ClientDb::init(context.child("source_regrow"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.current_target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source.new_batch().append(vec![30, 31, 32]).merkleize(
                &source,
                Some(metadata3.clone()),
                floor3,
            );
            source.apply_batch(batch3).unwrap();
            source.sync().await.unwrap();
            let target3 = source.current_target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let serve3_cfg = client_config(&format!("{suffix}-serve3"));
            let served3: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 3),
                resolver: Arc::new(source),
                target: target3.clone(),
                db_config: serve3_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served3.root(), target3.root);
            assert_eq!(served3.get_metadata(), Some(metadata3.clone()));
            assert_eq!(served3.inactivity_floor_loc(), floor3);
            served3.destroy().await.unwrap();

            let source = Arc::new(
                ClientDb::init(context.child("source_stale"), source_cfg.clone())
                    .await
                    .unwrap(),
            );
            let stale_result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("stale_client"),
                resolver: source.clone(),
                target: target2.clone(),
                db_config: client_config(&format!("{suffix}-stale")),
            })
            .await;
            assert!(matches!(
                stale_result,
                Err(sync::Error::Resolver(sync::compact::ServeError::StaleTarget {
                    requested,
                    current
                })) if requested == target2 && current == target3
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }
}

mod compact_variable_mmb {
    use super::*;
    use crate::merkle::mmb;
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;

    type SourceDb = variable::Db<mmb::Family, deterministic::Context, Vec<u8>, Sha256, Sequential>;
    type ClientDb = variable::CompactDb<
        mmb::Family,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;

    fn source_config(
        suffix: &str,
        pooler: &(impl BufferPooler + Metrics),
    ) -> variable::Config<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    fn client_config(
        suffix: &str,
    ) -> variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        keyless::CompactConfig {
            merkle: crate::merkle::compact::Config {
                partition: format!("compact-{suffix}"),
                strategy: Sequential,
            },
            commit_codec_config: ((0..=10000).into(), ()),
        }
    }

    #[derive(Clone)]
    struct StaticResolver {
        state: sync::compact::State<
            mmb::Family,
            variable::Operation<mmb::Family, Vec<u8>>,
            sha256::Digest,
        >,
    }

    impl sync::compact::Resolver for StaticResolver {
        type Family = mmb::Family;
        type Digest = sha256::Digest;
        type Op = variable::Operation<mmb::Family, Vec<u8>>;
        type Error = qmdb::Error<mmb::Family>;

        async fn get_compact_state(
            &self,
            _target: sync::compact::Target<Self::Family, Self::Digest>,
        ) -> Result<sync::compact::State<Self::Family, Self::Op, Self::Digest>, Self::Error>
        {
            Ok(self.state.clone())
        }
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_missing_reports_missing_source() {
        deterministic::Runner::default().start(|_context| async move {
            let resolver: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb>>> =
                Arc::new(commonware_utils::sync::AsyncRwLock::new(None));
            let target = sync::compact::Target {
                root: sha256::Digest::from([0; 32]),
                leaf_count: Location::new(1),
            };

            assert!(matches!(
                sync::compact::Resolver::get_compact_state(&resolver, target).await,
                Err(sync::compact::ServeError::MissingSource)
            ));
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_roundtrip() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let metadata = vec![3, 3, 3];
            let floor = Location::new(2);
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor);
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix);
            let client: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: source.clone(),
                target: target.clone(),
                db_config: client_cfg.clone(),
            })
            .await
            .unwrap();

            assert_eq!(client.root(), target.root);
            assert_eq!(client.get_metadata(), Some(metadata.clone()));
            assert_eq!(client.inactivity_floor_loc(), floor);
            drop(client);

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            assert_eq!(reopened.get_metadata(), Some(metadata));
            assert_eq!(reopened.inactivity_floor_loc(), floor);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_invalid_proof() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-proof-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source.new_batch().append(vec![7, 8, 9]).merkleize(
                &source,
                Some(vec![1]),
                Location::new(1),
            );
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.last_commit_proof = crate::merkle::Proof::default();

            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver { state },
                target,
                db_config: client_config(&suffix),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::InvalidProof))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_tampered_pinned_nodes_without_persisting() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-pins-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2));
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let client_cfg = client_config(&suffix);
            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver {
                    state: state.clone(),
                },
                target: target.clone(),
                db_config: client_cfg.clone(),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::RootMismatch { .. }))
            ));

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.last_commit_loc(), Location::new(0));
            assert_eq!(reopened.get_metadata(), None);
            assert_eq!(reopened.inactivity_floor_loc(), Location::new(0));
            assert_ne!(reopened.root(), target.root);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_rejects_leaf_count_mismatch() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-leaf-count-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1));
            source.apply_batch(batch).await.unwrap();
            source.commit().await.unwrap();

            let bounds = source.bounds().await;
            let target = sync::compact::Target {
                root: source.root(),
                leaf_count: bounds.end,
            };
            let source = Arc::new(source);
            let mut state = sync::compact::Resolver::get_compact_state(&source, target.clone())
                .await
                .unwrap();
            state.leaf_count = Location::new(*state.leaf_count - 1);

            let result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("client"),
                resolver: StaticResolver { state },
                target: target.clone(),
                db_config: client_config(&suffix),
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::UnexpectedLeafCount {
                    expected,
                    actual
                })) if expected == target.leaf_count && actual == Location::new(*target.leaf_count - 1)
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_rejects_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-stale-full-{}", context.next_u64());
            let mut source =
                SourceDb::init(context.child("source"), source_config(&suffix, &context))
                    .await
                    .unwrap();
            let batch1 = source.new_batch().append(vec![1, 2, 3]).merkleize(
                &source,
                Some(vec![1]),
                Location::new(1),
            );
            source.apply_batch(batch1).await.unwrap();
            source.commit().await.unwrap();
            let stale_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };

            let batch2 = source.new_batch().append(vec![4, 5, 6]).merkleize(
                &source,
                Some(vec![2]),
                Location::new(2),
            );
            source.apply_batch(batch2).await.unwrap();
            source.commit().await.unwrap();
            let current_target = sync::compact::Target {
                root: source.root(),
                leaf_count: source.bounds().await.end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let result =
                sync::compact::Resolver::get_compact_state(&source, stale_target.clone()).await;
            assert!(matches!(
                result,
                Err(sync::compact::ServeError::StaleTarget { requested, current })
                    if requested == stale_target && current == current_target
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_source_reopen_rewind_regrow_and_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"));
            let mut source = ClientDb::init(context.child("source_init"), source_cfg.clone())
                .await
                .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source.new_batch().append(vec![10, 11]).merkleize(
                &source,
                Some(metadata1.clone()),
                floor1,
            );
            source.apply_batch(batch1).unwrap();
            source.sync().await.unwrap();
            let target1 = source.current_target();
            drop(source);

            let source = ClientDb::init(context.child("source_reopen"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.current_target(), target1);

            let serve1_cfg = client_config(&format!("{suffix}-serve1"));
            let served1: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 1),
                resolver: Arc::new(source),
                target: target1.clone(),
                db_config: serve1_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served1.root(), target1.root);
            assert_eq!(served1.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served1.inactivity_floor_loc(), floor1);
            served1.destroy().await.unwrap();

            let mut source = ClientDb::init(context.child("source_resume"), source_cfg.clone())
                .await
                .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source.new_batch().append(vec![20, 21]).merkleize(
                &source,
                Some(metadata2.clone()),
                floor2,
            );
            source.apply_batch(batch2).unwrap();
            source.sync().await.unwrap();
            let target2 = source.current_target();
            assert_ne!(target2, target1);

            source.rewind().await.unwrap();
            assert_eq!(source.current_target(), target1);

            let serve2_cfg = client_config(&format!("{suffix}-serve2"));
            let served2: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 2),
                resolver: Arc::new(source),
                target: target1.clone(),
                db_config: serve2_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served2.root(), target1.root);
            assert_eq!(served2.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served2.inactivity_floor_loc(), floor1);
            served2.destroy().await.unwrap();

            let mut source = ClientDb::init(context.child("source_regrow"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.current_target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source.new_batch().append(vec![30, 31, 32]).merkleize(
                &source,
                Some(metadata3.clone()),
                floor3,
            );
            source.apply_batch(batch3).unwrap();
            source.sync().await.unwrap();
            let target3 = source.current_target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let serve3_cfg = client_config(&format!("{suffix}-serve3"));
            let served3: ClientDb = sync::compact::sync(sync::compact::Config {
                context: context.child("serve").with_attribute("index", 3),
                resolver: Arc::new(source),
                target: target3.clone(),
                db_config: serve3_cfg.clone(),
            })
            .await
            .unwrap();
            assert_eq!(served3.root(), target3.root);
            assert_eq!(served3.get_metadata(), Some(metadata3.clone()));
            assert_eq!(served3.inactivity_floor_loc(), floor3);
            served3.destroy().await.unwrap();

            let source = Arc::new(
                ClientDb::init(context.child("source_stale"), source_cfg.clone())
                    .await
                    .unwrap(),
            );
            assert_eq!(source.current_target(), target3);
            let stale_result: Result<ClientDb, _> = sync::compact::sync(sync::compact::Config {
                context: context.child("stale_client"),
                resolver: source.clone(),
                target: target2.clone(),
                db_config: client_config(&format!("{suffix}-stale")),
            })
            .await;
            assert!(matches!(
                stale_result,
                Err(sync::Error::Resolver(sync::compact::ServeError::StaleTarget {
                    requested,
                    current
                })) if requested == target2 && current == target3
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }
}
