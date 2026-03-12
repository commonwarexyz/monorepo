//! Generic sync tests for keyless databases.
//!
//! This module defines a [`SyncTestHarness`] trait and generic test functions parameterized
//! over the harness, so the same tests can run against any combination of merkle family
//! (MMR, MMB) and database variant. Per-harness concrete `#[test]` functions are expanded
//! by the [`sync_tests_for_harness!`] macro.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, journaled::Config as MerkleConfig, mmb, mmr, Family, Location},
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
    buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner as _,
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
            context: context.with_label("client"),
            target: Target {
                root: sha256::Digest::from([0; 32]),
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
        let target_db = H::init_db(context.with_label("target")).await;
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
            target: Target {
                root: target_root,
                range: non_empty_range!(target_oldest_retained_loc, target_op_count),
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
        let target_db = H::init_db(context.with_label("target")).await;
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
            target: Target {
                root: target_root,
                range: non_empty_range!(target_oldest_retained_loc, target_op_count),
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
        let target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(10);
        let target_db =
            H::apply_ops(target_db, target_ops.clone(), Some(H::sample_metadata())).await;

        let target_root = H::db_root(&target_db);
        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let op_count = bounds.end;

        let db_config = H::config("persistence-test", &context);
        let client_context = context.with_label("client");
        let target_db = Arc::new(target_db);
        let config = Config {
            db_config: db_config.clone(),
            fetch_batch_size: NZU64!(5),
            target: Target {
                root: target_root,
                range: non_empty_range!(lower_bound, op_count),
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
        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::db_root(&synced_db), target_root);
        let expected_root = H::db_root(&synced_db);
        let bounds = H::bounds(&synced_db).await;
        let expected_op_count = bounds.end;
        let expected_oldest_retained_loc = bounds.start;

        H::db_sync(&synced_db).await;
        drop(synced_db);
        let reopened_db = H::init_db_with_config(context.with_label("reopened"), db_config).await;

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
        let target_db = H::init_db(context.with_label("target")).await;
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
                context: context.with_label("client"),
                db_config: H::config(&format!("update_test_{}", context.next_u64()), &context),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                fetch_batch_size: NZU64!(2),
                max_outstanding_requests: 10,
                apply_batch_size: 1024,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
                progress_tx: None,
            };
            let mut client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();
            loop {
                client = match client.step().await.unwrap() {
                    NextStep::Continue(new_client) => new_client,
                    NextStep::Complete(_) => panic!("client should not be complete"),
                };
                let log_size = Contiguous::size(client.journal()).await;
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
        let target_db = H::init_db(context.with_label("target")).await;
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
            target: Target {
                root: target_root,
                range: non_empty_range!(lower_bound, op_count),
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

        let target_db = H::init_db(context.with_label("target")).await;
        let sync_db_config = H::config(&format!("partial_{}", context.next_u64()), &context);
        let client_context = context.with_label("client");
        let sync_db = H::init_db_with_config(client_context.clone(), sync_db_config.clone()).await;

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
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.with_label("sync"),
            resolver: target_db.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
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

        let target_db = H::init_db(context.with_label("target")).await;
        let sync_config = H::config(&format!("exact_{}", context.next_u64()), &context);
        let client_context = context.with_label("client");
        let sync_db = H::init_db_with_config(client_context.clone(), sync_config.clone()).await;

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
            target: Target {
                root,
                range: non_empty_range!(lower_bound, upper_bound),
            },
            context: context.with_label("sync"),
            resolver: resolver.clone(),
            apply_batch_size: 1024,
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
            progress_tx: None,
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
        let target_db = H::init_db(context.with_label("target")).await;
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
            context: context.with_label("client"),
            db_config: H::config(&format!("lb-dec-{}", context.next_u64()), &context),
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
        let target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&format!("ub-dec-{}", context.next_u64()), &context),
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
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        update_sender
            .send(Target {
                root: initial_root,
                range: non_empty_range!(initial_lower_bound, initial_upper_bound - 1),
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
        let target_db = H::init_db(context.with_label("target")).await;
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
            context: context.with_label("client"),
            db_config: H::config(&format!("bounds_inc_{}", context.next_u64()), &context),
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

        update_sender
            .send(Target {
                root: final_root,
                range: non_empty_range!(final_lower_bound, final_upper_bound),
            })
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
        let target_db = H::init_db(context.with_label("target")).await;
        let target_ops = H::create_ops(10);
        let target_db = H::apply_ops(target_db, target_ops, None).await;

        let bounds = H::bounds(&target_db).await;
        let lower_bound = bounds.start;
        let upper_bound = bounds.end;
        let root = H::db_root(&target_db);

        let (update_sender, update_receiver) = mpsc::channel(1);
        let target_db = Arc::new(target_db);
        let config = Config {
            context: context.with_label("client"),
            db_config: H::config(&format!("done_{}", context.next_u64()), &context),
            fetch_batch_size: NZU64!(20),
            target: Target {
                root,
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

        let synced_db: DbOf<H> = sync::sync(config).await.unwrap();

        let _ = update_sender
            .send(Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(lower_bound + 1, upper_bound + 1),
            })
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

    type VariableDb<F> = variable::Db<F, deterministic::Context, Vec<u8>, Sha256>;
    type VariableOp = Operation<crate::qmdb::any::value::VariableEncoding<Vec<u8>>>;

    fn variable_config(
        suffix: &str,
        pooler: &(impl BufferPooler + Metrics),
    ) -> variable::Config<(commonware_codec::RangeCfg<usize>, ())> {
        const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(5);

        let page_cache =
            CacheRef::from_pooler(&pooler.with_label("page_cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
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

    fn variable_create_ops_seeded(n: usize, seed: u64) -> Vec<VariableOp> {
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

    async fn variable_apply_ops<F: Family>(
        mut db: VariableDb<F>,
        ops: Vec<VariableOp>,
        metadata: Option<Vec<u8>>,
    ) -> VariableDb<F> {
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Append(value) => {
                    batch = batch.append(value);
                }
                Operation::Commit(_) => {
                    panic!("Commit operation not supported in apply_ops");
                }
            }
        }
        let merkleized = batch.merkleize(&db, metadata);
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
            variable_create_ops_seeded(n, 0)
        }

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded(n, seed)
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
                Operation::Commit(_) => None,
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
