//! Generic sync tests for keyless databases.
//!
//! This module defines a [`SyncTestHarness`] trait and generic test functions parameterized
//! over the harness, so the same tests can run against any combination of merkle family
//! (MMR, MMB) and database variant. Per-harness concrete `#[test]` functions are expanded
//! by the [`sync_tests_for_harness!`] macro.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Family, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        self,
        keyless::{self, Operation, variable},
        sync::{
            self, Engine, Target,
            engine::{Config, NextStep},
            source::{
                Source,
                tests::{FailSource, SequenceSource},
            },
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{Sha256, sha256};
use commonware_macros::boxed;
use commonware_runtime::{
    BufferPooler, Metrics, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng, channel::mpsc, non_empty_range};
use harnesses::VariableMmrHarness as H;
use rand::Rng as _;
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
    fn db_sync(db: Self::Db) -> impl Future<Output = Self::Db> + Send;

    fn apply_ops(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Self::Db> + Send;
    fn prune(db: Self::Db, loc: Location<Self::Family>) -> impl Future<Output = Self::Db> + Send;

    fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>>;
    fn db_root(db: &Self::Db) -> sha256::Digest;
    fn get_metadata(db: &Self::Db) -> impl Future<Output = Option<Self::Value>> + Send;
    fn get_value(
        db: &Self::Db,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Option<Self::Value>> + Send;
    fn op_value(op: &OpOf<Self>) -> Option<&Self::Value>;
}

// ===== Generic tests =====

pub(crate) fn test_sync_source_fails<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let source = FailSource::<H::Family, OpOf<H>, sha256::Digest>::new();
        let db_config = H::config(&context.next_u64().to_string(), &context);
        let config = Config {
            context: context.child("client"),
            target: Target {
                root: sha256::Digest::from([0; 32]),
                range: non_empty_range!(Location::new(0), Location::new(5)),
            },
            source,
            apply_batch_size: NZU64!(2),
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

/// Exercises each invalid-response arm of `handle_fetch_result`. A feedback-accepting source is
/// retried, and a source that accepts no feedback fails terminally with
/// [`sync::EngineError::InvalidResponse`].
pub(crate) fn test_engine_rejects_invalid_responses<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
{
    fn config_for<H: SyncTestHarness, S>(
        context: &deterministic::Context,
        suffix: &'static str,
        source: S,
        fetch_batch_size: NonZeroU64,
        target: &Target<H::Family, sha256::Digest>,
    ) -> Config<DbOf<H>, S>
    where
        S: sync::SourceFor<DbOf<H>>,
        OpOf<H>: Encode,
    {
        Config {
            context: context.child(suffix),
            target: target.clone(),
            source,
            apply_batch_size: NZU64!(2),
            max_outstanding_requests: 1,
            fetch_batch_size,
            db_config: H::config(suffix, context),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 0,
        }
    }

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops(target_db, H::create_ops(5), Some(H::sample_metadata())).await;
        let bounds = H::bounds(&target_db);
        let target_root = H::db_root(&target_db);
        let target_db = Arc::new(target_db);
        let (size, start) = (bounds.end, bounds.start);
        // The arm mapping below assumes every request is an Operations request, which
        // holds only while the lower sync bound needs no pinned nodes.
        assert_eq!(*start, 0);
        let max_ops = NZU64!(*size - *start);
        let (good, _) = target_db
            .serve(sync::Request::Operations {
                size,
                start,
                max_ops,
            })
            .await
            .unwrap();
        let target = Target {
            root: target_root,
            range: non_empty_range!(start, size),
        };

        // A batch that fails proof verification is terminal without feedback...
        let mut bad = good.clone();
        let sync::Response::Operations { proof, .. } = &mut bad else {
            unreachable!("operations request returns an operations response");
        };
        proof.digests.push(sha256::Digest::from([0xee; 32]));
        let source = SequenceSource::new(vec![(bad.clone(), None)]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            &context,
            "verify_term",
            source,
            max_ops,
            &target,
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        // ...and retried when the source accepts feedback.
        let (bad_tx, bad_rx) = commonware_utils::channel::oneshot::channel();
        let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
        let source = SequenceSource::new(vec![(bad, Some(bad_tx)), (good.clone(), Some(good_tx))]);
        let synced: DbOf<H> = sync::sync(config_for::<H, _>(
            &context,
            "verify_retry",
            source,
            max_ops,
            &target,
        ))
        .await
        .unwrap();
        assert!(!bad_rx.await.unwrap());
        assert!(good_rx.await.unwrap());
        assert_eq!(H::db_root(&synced), target_root);
        H::destroy(synced).await;

        // An empty batch is invalid regardless of its proof.
        let sync::Response::Operations {
            proof: good_proof,
            operations: good_ops,
        } = good.clone()
        else {
            unreachable!("operations request returns an operations response");
        };
        let empty = sync::Response::Operations {
            proof: good_proof.clone(),
            operations: vec![],
        };
        let source = SequenceSource::new(vec![(empty, None)]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            &context, "empty", source, max_ops, &target,
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        // A batch larger than the request's max_ops is invalid.
        let source = SequenceSource::new(vec![(good.clone(), None)]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            &context,
            "overflow",
            source,
            NZU64!(2),
            &target,
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        // A boundary-shaped answer to an operations request is invalid even when its proof
        // is plausible.
        let boundary = sync::Response::Boundary {
            proof: good_proof,
            op: good_ops.into_iter().next().unwrap(),
            pinned_nodes: vec![],
        };
        let source = SequenceSource::new(vec![(boundary, None)]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            &context, "mismatch", source, max_ops, &target,
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        let target_db = Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("single ref"));
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync<H: SyncTestHarness>(target_db_ops: usize, fetch_batch_size: NonZeroU64)
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let target_db = H::init_db(context.child("target")).await;
        let initial_ops = H::create_ops(50);
        let target_db = H::apply_ops(target_db, initial_ops, None).await;

        let bounds = H::bounds(&target_db);
        let initial_lower_bound = bounds.start;
        let initial_upper_bound = bounds.end;
        let initial_root = H::db_root(&target_db);

        let additional_ops = H::create_ops_seeded(25, 1);
        let target_db = H::apply_ops(target_db, additional_ops, None).await;
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

        H::destroy(synced_db).await;
        H::destroy(target_db).await;
    });
}

pub(crate) fn test_sync_subset_of_target_database<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
    OpOf<H>: Encode + Clone + Send + Sync,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>,
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    fn variable_create_ops_seeded<F: Family>(n: usize, seed: u64) -> Vec<VariableOp<F>> {
        let mut rng = TestRng::new(seed);
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
        db: VariableDb<F>,
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
        let merkleized = batch.merkleize(&db, metadata, new_commit).await;
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
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

        #[boxed]
        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn db_sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn apply_ops(
            db: Self::Db,
            ops: Vec<OpOf<Self>>,
            metadata: Option<Self::Value>,
        ) -> Self::Db {
            variable_apply_ops::<F>(db, ops, metadata).await
        }

        async fn prune(db: Self::Db, loc: Location<Self::Family>) -> Self::Db {
            db.prune(loc).await.unwrap()
        }

        fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>> {
            db.bounds()
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
            fn test_sync_source_fails() {
                super::test_sync_source_fails::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_engine_rejects_invalid_responses() {
                super::test_engine_rejects_invalid_responses::<$harness>();
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

/// A completed sync journal reuses local pinned nodes only when the persisted state can
/// authenticate the target: a target starting below the local pruning boundary is declined,
/// while a matching target serves the pinned nodes locally.
#[commonware_macros::test_traced]
fn test_keyless_local_pinned_nodes_rejects_target_before_local_lower_bound() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let suffix = context.next_u64().to_string();
        let config = H::config(&suffix, &context);
        let mut db = H::init_db_with_config(context.child("db"), config.clone()).await;
        for seed in 0..3u64 {
            db = Box::pin(H::apply_ops(db, H::create_ops_seeded(100, seed), None)).await;
        }
        let db = H::prune(db, Location::new(100)).await;
        let db = H::db_sync(db).await;

        let bounds = H::bounds(&db);
        let local_start = bounds.start;
        let local_end = bounds.end;
        assert!(local_start > Location::new(0));
        let sync_root = H::db_root(&db);

        let stale_target = Target {
            root: sync_root,
            range: non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        };
        assert!(
            <DbOf<H> as qmdb::sync::Database>::local_pinned_nodes(
                context.child("probe_stale"),
                &config,
                &stale_target,
                &db.journal.journal,
            )
            .await
            .unwrap()
            .is_none()
        );

        let matching_target = Target {
            root: sync_root,
            range: non_empty_range!(local_start, local_end),
        };
        assert!(
            <DbOf<H> as qmdb::sync::Database>::local_pinned_nodes(
                context.child("probe_matching"),
                &config,
                &matching_target,
                &db.journal.journal,
            )
            .await
            .unwrap()
            .is_some()
        );

        H::destroy(db).await;
    });
}

/// Engine configuration for a compact sync over the one-operation range ending at the target.
fn compact_engine_config<DB, S>(
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

mod compact_variable_mmr {
    use super::*;
    use crate::qmdb::sync::source::tests::{SequenceSource, dropped_feedback, fetch_compact_state};
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    fn client_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        keyless::CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: format!("compact-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: ((0..=10000).into(), ()),
        }
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_missing_reports_missing_source() {
        deterministic::Runner::default().start(|_context| async move {
            let source: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb>>> =
                Arc::new(commonware_utils::sync::AsyncRwLock::new(None));
            let target = sync::CompactTarget {
                root: sha256::Digest::from([0; 32]),
                size: Location::new(1),
            };

            assert!(matches!(
                fetch_compact_state(&source, target).await,
                Err(sync::ServeError::MissingSource)
            ));
        });
    }

    #[test_traced("WARN")]
    fn test_replay_sync_single_op_range() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("single-op-{}", context.next_u64());
            // Per-op section/blob sizes so pruning to the floor retains exactly one operation.
            let fine_config = |sfx: &str, pooler: &deterministic::Context| {
                let mut config = source_config(sfx, pooler);
                config.log.items_per_section = NZU64!(1);
                config.merkle.items_per_blob = NZU64!(1);
                config
            };
            let source = SourceDb::init(context.child("source"), fine_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, None, Location::new(0))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            // A second commit declares the floor at its own location. Everything before it is
            // inactive, so pruning retains exactly that one operation.
            let metadata = vec![7, 7];
            let floor = source.bounds().end;
            let batch = source
                .new_batch()
                .merkleize(&source, Some(metadata.clone()), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let source = source.prune(floor).await.unwrap();

            let bounds = source.bounds();
            assert_eq!(*bounds.end - *bounds.start, 1);
            let target_root = source.root();
            let source = Arc::new(source);

            let client: SourceDb = sync::sync(sync::engine::Config {
                context: context.child("client"),
                db_config: fine_config(&format!("{suffix}-client"), &context),
                fetch_batch_size: NZU64!(2),
                target: sync::Target {
                    root: target_root,
                    range: non_empty_range!(bounds.start, bounds.end),
                },
                source: source.clone(),
                apply_batch_size: NZU64!(1024),
                max_outstanding_requests: 2,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            })
            .await
            .unwrap();

            assert_eq!(client.root(), target_root);
            assert_eq!(client.bounds(), bounds);
            assert_eq!(client.get_metadata().await.unwrap(), Some(metadata));
            client.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("still shared"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_roundtrip() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let metadata = vec![9, 9, 9];
            let floor = Location::new(2);
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix, &context);
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                target.clone(),
                client_cfg.clone(),
            ))
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
    fn test_compact_sync_recovers_after_invalid_proof() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-proof-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            // Corrupt the proof without touching `leaves`, so the response passes the
            // engine's size check and fails at verification itself.
            proof.digests.push(sha256::Digest::from([0xee; 32]));

            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![
                    (bad_state, dropped_feedback()),
                    (good_state, dropped_feedback()),
                ]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_tampered_commit_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-floor-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { op, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let variable::Operation::Commit(metadata, _) = op.clone() else {
                panic!("compact state should carry a commit operation");
            };
            *op = variable::Operation::Commit(metadata, Location::new(0));

            let (bad_tx, bad_rx) = commonware_utils::channel::oneshot::channel();
            let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![(bad_state, Some(bad_tx)), (good_state, Some(good_tx))]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();

            assert!(!bad_rx.await.unwrap());
            assert!(good_rx.await.unwrap());
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_size_mismatch() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-leaf-count-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            proof.leaves -= 1;

            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![
                    (bad_state, dropped_feedback()),
                    (good_state, dropped_feedback()),
                ]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_tampered_pinned_nodes() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-feedback-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { pinned_nodes, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let (bad_tx, bad_rx) = commonware_utils::channel::oneshot::channel();
            let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
            let sequence =
                SequenceSource::new(vec![(bad_state, Some(bad_tx)), (good_state, Some(good_tx))]);

            let client_cfg = client_config(&suffix, &context);
            let synced: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                sequence,
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();

            assert!(!bad_rx.await.unwrap());
            assert!(good_rx.await.unwrap());
            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(vec![7]));

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target);
            assert_eq!(reopened.get_metadata(), Some(vec![7]));

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_serves_historical_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-stale-full-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch1 = source
                .new_batch()
                .append(vec![1, 2, 3])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.commit().await.unwrap();
            let stale_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let batch2 = source
                .new_batch()
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![2]), Location::new(2))
                .await;
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.commit().await.unwrap();
            let current_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                stale_target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), stale_target.root);
            assert_ne!(client.root(), current_target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_source_reopen_rewind_regrow_and_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"), &context);
            let source = ClientDb::init(context.child("source_init"), source_cfg.clone())
                .await
                .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source
                .new_batch()
                .append(vec![10, 11])
                .merkleize(&source, Some(metadata1.clone()), floor1)
                .await;
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.sync().await.unwrap();
            let target1 = source.target();
            drop(source);

            let source = ClientDb::init(context.child("source_reopen"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.target(), target1);

            let serve1_cfg = client_config(&format!("{suffix}-serve1"), &context);
            let served1: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 1),
                Arc::new(source),
                target1.clone(),
                serve1_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(served1.root(), target1.root);
            assert_eq!(served1.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served1.inactivity_floor_loc(), floor1);
            served1.destroy().await.unwrap();

            let source = ClientDb::init(context.child("source_resume"), source_cfg.clone())
                .await
                .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source
                .new_batch()
                .append(vec![20, 21])
                .merkleize(&source, Some(metadata2.clone()), floor2)
                .await;
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.sync().await.unwrap();
            let target2 = source.target();
            assert_ne!(target2, target1);

            let source = source.rewind(target1.size).await.unwrap();
            assert_eq!(source.target(), target1);

            let serve2_cfg = client_config(&format!("{suffix}-serve2"), &context);
            let served2: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 2),
                Arc::new(source),
                target1.clone(),
                serve2_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(served2.root(), target1.root);
            assert_eq!(served2.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served2.inactivity_floor_loc(), floor1);
            served2.destroy().await.unwrap();

            let source = ClientDb::init(context.child("source_regrow"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source
                .new_batch()
                .append(vec![30, 31, 32])
                .merkleize(&source, Some(metadata3.clone()), floor3)
                .await;
            let (source, _) = source.apply_batch(batch3).await.unwrap();
            let source = source.sync().await.unwrap();
            let target3 = source.target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let serve3_cfg = client_config(&format!("{suffix}-serve3"), &context);
            let served3: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 3),
                Arc::new(source),
                target3.clone(),
                serve3_cfg.clone(),
            ))
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
            // target2 names a divergent history. The regrown source reaches the same leaf
            // count under a different root, so it serves state the client can never verify.
            // With no feedback channel, the engine fails instead of retrying.
            let divergent_result: Result<ClientDb, _> = sync::sync(compact_engine_config(
                context.child("divergent_client"),
                source.clone(),
                target2.clone(),
                client_config(&format!("{suffix}-divergent"), &context),
            ))
            .await;
            assert!(matches!(
                divergent_result,
                Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
            ));

            // A target below the retained tip is refused outright because the witness serves
            // only its latest commit.
            let stale_result: Result<ClientDb, _> = sync::sync(compact_engine_config(
                context.child("stale_client"),
                source.clone(),
                target1.clone(),
                client_config(&format!("{suffix}-stale"), &context),
            ))
            .await;
            assert!(matches!(
                stale_result,
                Err(sync::Error::Source(qmdb::Error::Journal(
                    crate::journal::Error::ItemPruned(_)
                )))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    /// Compact sync must reinitialize a partition whose witness journal was previously pruned
    /// (the journal reset must clear the nonzero pruning boundary).
    #[test_traced("WARN")]
    fn test_compact_sync_reuses_pruned_partition() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-pruned-{}", context.next_u64());

            // Seed the client partition with several commits, then prune its witness journal.
            let mut client_cfg = client_config(&suffix, &context);
            client_cfg.witness.items_per_section = NZU64!(1);
            let mut seeded = ClientDb::init(context.child("seed"), client_cfg.clone())
                .await
                .unwrap();
            let mut first_size = None;
            for i in 1u8..=3 {
                let floor = seeded.inactivity_floor_loc();
                let batch = seeded
                    .new_batch()
                    .append(vec![i])
                    .merkleize(&seeded, Some(vec![i]), floor)
                    .await;
                (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                seeded = seeded.sync().await.unwrap();
                first_size.get_or_insert(seeded.size());
            }
            let boundary = seeded.size();
            let seeded = seeded.prune(boundary).await.unwrap();
            // The prune moved the journal's pruning boundary: the first commit is unreachable.
            assert!(matches!(
                seeded.rewind(first_size.unwrap()).await,
                Err(crate::qmdb::Error::Merkle(
                    crate::merkle::Error::RewindBeyondHistory
                ))
            ));

            // Sync different state into the same partition.
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let metadata = vec![9, 9, 9];
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .merkleize(&source, Some(metadata.clone()), Location::new(0))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };

            let synced: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                Arc::new(source),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), target.root);
            drop(synced);

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            reopened.destroy().await.unwrap();
        });
    }

    /// A boundary response can verify against its target while reconstructing a different
    /// canonical root. Rejecting that import must preserve the destination's durable witness.
    #[test_traced("WARN")]
    fn test_compact_sync_root_mismatch_preserves_existing_state() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-root-mismatch-{}", context.next_u64());

            // Seed the destination partition with durable state that a failed import must not
            // replace.
            let client_cfg = client_config(&suffix, &context);
            let seeded = ClientDb::init(context.child("seed"), client_cfg.clone())
                .await
                .unwrap();
            let batch = seeded
                .new_batch()
                .append(vec![1])
                .merkleize(&seeded, Some(vec![1]), Location::new(0))
                .await;
            let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
            let seeded = seeded.sync().await.unwrap();
            let original_target = seeded.target();
            drop(seeded);

            // Build a compact boundary response from a valid source state.
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![2])
                .append(vec![3])
                .append(vec![4])
                .append(vec![5])
                .append(vec![6])
                .merkleize(&source, Some(vec![9]), Location::new(0))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let size = source.bounds().end;
            let last_commit_loc = size - 1;
            let canonical_target = sync::CompactTarget {
                root: source.root(),
                size,
            };
            let source = Arc::new(source);
            let (response, _) = fetch_compact_state(&source, canonical_target)
                .await
                .unwrap();
            let sync::Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                unreachable!("boundary fetch returns a boundary response");
            };

            // Authenticate the boundary against a root with one inactive peak. The proof is valid
            // for this target, but the commit's encoded floor reconstructs the source's canonical
            // root instead, so only the engine's final root check rejects the import.
            let hasher = qmdb::hasher::<Sha256>();
            let proof = source
                .journal
                .merkle
                .historical_proof(&hasher, size, last_commit_loc, 1)
                .await
                .unwrap();
            let noncanonical_root = source.journal.merkle.root(&hasher, 1).unwrap();
            assert_ne!(noncanonical_root, source.root());

            // The rejected reconstruction must remain provisional.
            let result: Result<ClientDb, _> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![(
                    sync::Response::Boundary {
                        proof,
                        op,
                        pinned_nodes,
                    },
                    None,
                )]),
                sync::CompactTarget {
                    root: noncanonical_root,
                    size,
                },
                client_cfg.clone(),
            ))
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::RootMismatch { .. }))
            ));

            // Reopening the destination must recover the original durable state.
            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.target(), original_target);

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    /// Dropping a compact-sync import before its first persist leaves the previous witness
    /// journal untouched.
    #[test_traced("WARN")]
    fn test_compact_sync_dropped_import_preserves_existing_state() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-dropped-{}", context.next_u64());

            // Seed the client partition with committed state A.
            let client_cfg = client_config(&suffix, &context);
            let seeded = ClientDb::init(context.child("seed"), client_cfg.clone())
                .await
                .unwrap();
            let batch = seeded
                .new_batch()
                .append(vec![1])
                .merkleize(&seeded, Some(vec![1]), Location::new(0))
                .await;
            let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
            let seeded = seeded.sync().await.unwrap();
            let target_a = seeded.target();
            drop(seeded);

            // Reconstruct state B into the same partition, then drop it before the first
            // persist (as a cancelled sync would).
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![9])
                .merkleize(&source, Some(vec![9]), Location::new(0))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target_b = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            assert_ne!(target_b, target_a);
            let source = Arc::new(source);
            let (response, _) = fetch_compact_state(&source, target_b.clone())
                .await
                .unwrap();
            let sync::Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let journal = crate::journal::contiguous::variable::Journal::init(
                context.child("import"),
                client_cfg.witness.clone(),
            )
            .await
            .unwrap();
            let imported = ClientDb::init_from_sync(
                client_cfg.strategy.clone(),
                journal,
                client_cfg.commit_codec_config,
                target_b.size - 1,
                pinned_nodes,
                op,
            )
            .unwrap();
            assert_eq!(imported.target(), target_b);

            // Rewind is rejected until the import is persisted, even to the imported leaf
            // count itself: the fast path must not report unpersisted state as durable.
            assert!(imported.rewind(target_b.size).await.is_err());

            // Prune is likewise rejected while the import is pending; rebuild the import.
            let (response, _) = fetch_compact_state(&source, target_b.clone())
                .await
                .unwrap();
            let sync::Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let journal = crate::journal::contiguous::variable::Journal::init(
                context.child("import").with_attribute("index", 2),
                client_cfg.witness.clone(),
            )
            .await
            .unwrap();
            let imported = ClientDb::init_from_sync(
                client_cfg.strategy.clone(),
                journal,
                client_cfg.commit_codec_config,
                target_b.size - 1,
                pinned_nodes,
                op,
            )
            .unwrap();
            assert!(imported.prune(target_b.size).await.is_err());

            // The dropped imports never touched the journal: state A is still there.
            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }
}

mod compact_variable_mmb {
    use super::*;
    use crate::{
        merkle::mmb,
        qmdb::sync::source::tests::{SequenceSource, dropped_feedback, fetch_compact_state},
    };
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
                replay_buffer: NZUsize!(1024),
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
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    fn client_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        keyless::CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: format!("compact-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: ((0..=10000).into(), ()),
        }
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_missing_reports_missing_source() {
        deterministic::Runner::default().start(|_context| async move {
            let source: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb>>> =
                Arc::new(commonware_utils::sync::AsyncRwLock::new(None));
            let target = sync::CompactTarget {
                root: sha256::Digest::from([0; 32]),
                size: Location::new(1),
            };

            assert!(matches!(
                fetch_compact_state(&source, target).await,
                Err(sync::ServeError::MissingSource)
            ));
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_roundtrip() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let metadata = vec![3, 3, 3];
            let floor = Location::new(2);
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix, &context);
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                target.clone(),
                client_cfg.clone(),
            ))
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
    fn test_compact_sync_recovers_after_invalid_proof() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-proof-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            // Corrupt the proof without touching `leaves`, so the response passes the
            // engine's size check and fails at verification itself.
            proof.digests.push(sha256::Digest::from([0xee; 32]));

            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![
                    (bad_state, dropped_feedback()),
                    (good_state, dropped_feedback()),
                ]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_tampered_commit_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-floor-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { op, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let variable::Operation::Commit(metadata, _) = op.clone() else {
                panic!("compact state should carry a commit operation");
            };
            *op = variable::Operation::Commit(metadata, Location::new(0));

            let (bad_tx, bad_rx) = commonware_utils::channel::oneshot::channel();
            let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![(bad_state, Some(bad_tx)), (good_state, Some(good_tx))]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();

            assert!(!bad_rx.await.unwrap());
            assert!(good_rx.await.unwrap());
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_tampered_pinned_nodes() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!(
                "compact-keyless-mmb-bad-pinned-nodes-{}",
                context.next_u64()
            );
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { pinned_nodes, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let client_cfg = client_config(&suffix, &context);
            let synced: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![
                    (bad_state, dropped_feedback()),
                    (good_state, dropped_feedback()),
                ]),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(synced.target(), target);
            drop(synced);

            let reopened = ClientDb::init(context.child("reopen"), client_cfg)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target);
            assert_eq!(reopened.get_metadata(), Some(vec![7]));

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_sync_recovers_after_size_mismatch() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-bad-leaf-count-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone())
                .await
                .unwrap()
                .0;
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            proof.leaves -= 1;

            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![
                    (bad_state, dropped_feedback()),
                    (good_state, dropped_feedback()),
                ]),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_full_source_serves_historical_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-stale-full-{}", context.next_u64());
            let source = SourceDb::init(context.child("source"), source_config(&suffix, &context))
                .await
                .unwrap();
            let batch1 = source
                .new_batch()
                .append(vec![1, 2, 3])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await;
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.commit().await.unwrap();
            let stale_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let batch2 = source
                .new_batch()
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![2]), Location::new(2))
                .await;
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.commit().await.unwrap();
            let current_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let client: ClientDb = sync::sync(compact_engine_config(
                context.child("client"),
                source.clone(),
                stale_target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();
            assert_eq!(client.root(), stale_target.root);
            assert_ne!(client.root(), current_target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_compact_source_reopen_rewind_regrow_and_stale_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-mmb-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"), &context);
            let source = ClientDb::init(context.child("source_init"), source_cfg.clone())
                .await
                .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source
                .new_batch()
                .append(vec![10, 11])
                .merkleize(&source, Some(metadata1.clone()), floor1)
                .await;
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.sync().await.unwrap();
            let target1 = source.target();
            drop(source);

            let source = ClientDb::init(context.child("source_reopen"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.target(), target1);

            let serve1_cfg = client_config(&format!("{suffix}-serve1"), &context);
            let served1: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 1),
                Arc::new(source),
                target1.clone(),
                serve1_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(served1.root(), target1.root);
            assert_eq!(served1.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served1.inactivity_floor_loc(), floor1);
            served1.destroy().await.unwrap();

            let source = ClientDb::init(context.child("source_resume"), source_cfg.clone())
                .await
                .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source
                .new_batch()
                .append(vec![20, 21])
                .merkleize(&source, Some(metadata2.clone()), floor2)
                .await;
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.sync().await.unwrap();
            let target2 = source.target();
            assert_ne!(target2, target1);

            let source = source.rewind(target1.size).await.unwrap();
            assert_eq!(source.target(), target1);

            let serve2_cfg = client_config(&format!("{suffix}-serve2"), &context);
            let served2: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 2),
                Arc::new(source),
                target1.clone(),
                serve2_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(served2.root(), target1.root);
            assert_eq!(served2.get_metadata(), Some(metadata1.clone()));
            assert_eq!(served2.inactivity_floor_loc(), floor1);
            served2.destroy().await.unwrap();

            let source = ClientDb::init(context.child("source_regrow"), source_cfg.clone())
                .await
                .unwrap();
            assert_eq!(source.target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source
                .new_batch()
                .append(vec![30, 31, 32])
                .merkleize(&source, Some(metadata3.clone()), floor3)
                .await;
            let (source, _) = source.apply_batch(batch3).await.unwrap();
            let source = source.sync().await.unwrap();
            let target3 = source.target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let serve3_cfg = client_config(&format!("{suffix}-serve3"), &context);
            let served3: ClientDb = sync::sync(compact_engine_config(
                context.child("serve").with_attribute("index", 3),
                Arc::new(source),
                target3.clone(),
                serve3_cfg.clone(),
            ))
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
            assert_eq!(source.target(), target3);
            // target2 names a divergent history. The regrown source reaches the same leaf
            // count under a different root, so it serves state the client can never verify.
            // With no feedback channel, the engine fails instead of retrying.
            let divergent_result: Result<ClientDb, _> = sync::sync(compact_engine_config(
                context.child("divergent_client"),
                source.clone(),
                target2.clone(),
                client_config(&format!("{suffix}-divergent"), &context),
            ))
            .await;
            assert!(matches!(
                divergent_result,
                Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
            ));

            // A target below the retained tip is refused outright because the witness serves
            // only its latest commit.
            let stale_result: Result<ClientDb, _> = sync::sync(compact_engine_config(
                context.child("stale_client"),
                source.clone(),
                target1.clone(),
                client_config(&format!("{suffix}-stale"), &context),
            ))
            .await;
            assert!(matches!(
                stale_result,
                Err(sync::Error::Source(qmdb::Error::Journal(
                    crate::journal::Error::ItemPruned(_)
                )))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }
}
