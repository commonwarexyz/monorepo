//! Sync tests for keyless databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for keyless databases and adds keyless-specific tests to the
//! modules the shared macro generates.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{Family, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        self,
        keyless::{self, Operation, variable},
        sync::{
            self, Engine, Target,
            engine::{Config, NextStep},
            harness::{
                ConfigOf, DbOf, JournalOf, OpOf, PAGE_CACHE_SIZE, PAGE_SIZE, SyncTestHarness,
                compact_engine_config,
            },
            source::{
                Source,
                tests::{FailSource, SequenceSource},
            },
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{Sha256, sha256};
use commonware_macros::{boxed, select};
use commonware_runtime::{
    BufferPooler, Metrics, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{
    NZU64, NZUsize, TestRng,
    channel::{mpsc, oneshot},
    non_empty_range,
    sync::Mutex,
};
use harnesses::VariableMmrHarness as H;
use rand::Rng as _;
use std::{collections::BTreeSet, num::NonZeroU64, pin::pin, sync::Arc};

// ===== Keyless-specific tests =====

pub(crate) fn test_sync_source_fails<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
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

/// Invalid candidates are retried within the same source call while more candidates remain.
/// An exhausted source fails with [`sync::EngineError::InvalidResponse`].
pub(crate) fn test_engine_rejects_invalid_responses<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: Source<Family = H::Family, Op = OpOf<H>, Digest = sha256::Digest>
        + sync::SourceFor<DbOf<H>>,
{
    fn config_for<H: SyncTestHarness, S>(
        context: deterministic::Context,
        suffix: &str,
        source: S,
        fetch_batch_size: NonZeroU64,
        target: &Target<H::Family, sha256::Digest>,
    ) -> Config<DbOf<H>, S>
    where
        S: sync::SourceFor<DbOf<H>>,
        OpOf<H>: Encode,
    {
        let db_config = H::config(suffix, &context);
        Config {
            context,
            target: target.clone(),
            source,
            apply_batch_size: NZU64!(2),
            max_outstanding_requests: 1,
            fetch_batch_size,
            db_config,
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
        let good = target_db
            .serve(sync::Request::Operations {
                size,
                start,
                max_ops,
            })
            .await
            .unwrap()
            .0;
        let target = Target {
            root: target_root,
            range: non_empty_range!(start, size),
        };

        // Failed proof verification is terminal when no candidate remains.
        let mut bad = good.clone();
        let sync::Response::Operations { proof, .. } = &mut bad else {
            unreachable!("operations request returns an operations response");
        };
        proof.digests.push(sha256::Digest::from([0xee; 32]));
        let source = SequenceSource::new(vec![bad.clone()]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            context.child("terminal"),
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

        // A valid candidate lets the same source call complete after rejection.
        let source = SequenceSource::new(vec![bad, good.clone()]);
        let synced: DbOf<H> = sync::sync(config_for::<H, _>(
            context.child("retry"),
            "verify_retry",
            source.clone(),
            max_ops,
            &target,
        ))
        .await
        .unwrap();
        assert_eq!(source.take_verdicts().await, vec![false, true]);
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
        let source = SequenceSource::new(vec![empty]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            context.child("empty"),
            "empty",
            source,
            max_ops,
            &target,
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        // A batch larger than the request's max_ops is invalid.
        let source = SequenceSource::new(vec![good.clone()]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            context.child("overflow"),
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
        let source = SequenceSource::new(vec![boundary]);
        let result: Result<DbOf<H>, _> = sync::sync(config_for::<H, _>(
            context.child("mismatch"),
            "mismatch",
            source,
            max_ops,
            &target,
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

/// A source wrapper that holds the first boundary response until released and panics on a
/// second boundary request.
struct DelayedBoundary<S> {
    source: S,
    gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

impl<S: Source<Op: Send>> Source for DelayedBoundary<S> {
    type Family = S::Family;
    type Digest = S::Digest;
    type Op = S::Op;
    type Error = S::Error;

    async fn serve(&self, request: sync::Request<Self::Family>) -> sync::source::Result<Self> {
        let response = self.source.serve(request).await?;
        if matches!(request, sync::Request::Boundary { .. }) {
            let (requested, release) = self
                .gate
                .lock()
                .take()
                .expect("the unchanged boundary must not be fetched again");
            requested.send(()).unwrap();
            release.await.unwrap();
        }
        Ok(response)
    }
}

/// A boundary response requested before a target update with an unchanged lower bound is
/// applied without a second boundary request, and sync completes after its root is evicted.
pub(crate) fn test_target_updates_preserve_delayed_boundary<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Build three targets that share a lower bound above zero.
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops(target_db, H::create_ops(20), None).await;
        let target_db = H::prune(target_db, Location::new(5)).await;
        let start = H::bounds(&target_db).start;
        assert!(*start > 0);
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(start, H::bounds(&target_db).end),
        };
        let target_db = H::apply_ops(target_db, H::create_ops_seeded(10, 1), None).await;
        let next_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(start, H::bounds(&target_db).end),
        };
        let target_db = H::apply_ops(target_db, H::create_ops_seeded(10, 2), None).await;
        let final_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(start, H::bounds(&target_db).end),
        };

        // Start sync with a source that holds the boundary response.
        let target_db = Arc::new(target_db);
        let (requested_tx, requested_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (update_tx, update_rx) = mpsc::channel(1);
        let config = Config {
            context: context.child("client"),
            db_config: H::config("delayed_boundary", &context),
            target: initial_target,
            source: DelayedBoundary {
                source: target_db.clone(),
                gate: Mutex::new(Some((requested_tx, release_rx))),
            },
            fetch_batch_size: NZU64!(4),
            max_outstanding_requests: 1,
            apply_batch_size: NZU64!(4),
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 1,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        // Hold a real boundary proof until the engine has processed the first update.
        let client = {
            let mut step = pin!(client.step());
            select! {
                requested = requested_rx => requested.unwrap(),
                _ = step.as_mut() => panic!("the boundary response must remain pending"),
            }
            update_tx.send(next_target).await.unwrap();
            match step.await.unwrap() {
                NextStep::Continue(client) => client,
                NextStep::Complete(_) => panic!("client should not be complete"),
            }
        };

        // Release the boundary response requested against the first root.
        release_tx.send(()).unwrap();
        let client = match client.step().await.unwrap() {
            NextStep::Continue(client) => client,
            NextStep::Complete(_) => panic!("client should not be complete"),
        };
        assert_eq!(
            Contiguous::bounds(client.journal()).end,
            *start + 1,
            "the retained boundary response must apply"
        );

        // The boundary is now verified and applied. Evict its original root before finishing.
        update_tx.send(final_target.clone()).await.unwrap();
        drop(update_tx);
        let synced = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced), final_target.root);
        assert_eq!(H::bounds(&synced), start..final_target.range.end());
        H::destroy(synced).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("single source"))).await;
    });
}

/// A source wrapper that never answers the boundary request at `stalled` and panics when an
/// operation request covers a location an earlier operation request covered.
struct StalledBoundary<S: Source> {
    source: S,
    stalled: Location<S::Family>,
    requested: Mutex<BTreeSet<u64>>,
}

impl<S: Source<Op: Send>> Source for StalledBoundary<S> {
    type Family = S::Family;
    type Digest = S::Digest;
    type Op = S::Op;
    type Error = S::Error;

    async fn serve(&self, request: sync::Request<Self::Family>) -> sync::source::Result<Self> {
        match request {
            sync::Request::Boundary { start, .. } if start == self.stalled => {
                return std::future::pending().await;
            }
            sync::Request::Operations { start, max_ops, .. } => {
                let end = start.checked_add(max_ops.get()).unwrap();
                let mut requested = self.requested.lock();
                for loc in *start..*end {
                    assert!(
                        requested.insert(loc),
                        "location {loc} refetched by {request:?}"
                    );
                }
            }
            sync::Request::Boundary { .. } => {}
        }
        self.source.serve(request).await
    }
}

/// Operations fetched ahead of the journal tip are applied after a target update moves the lower
/// bound into them, without fetching them again.
pub(crate) fn test_target_update_keeps_operations_above_moved_floor<H: SyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Build a target pruned above zero and a later target whose lower bound is two higher.
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops(target_db, H::create_ops(20), None).await;
        let target_db = H::prune(target_db, Location::new(5)).await;
        let floor = H::bounds(&target_db).start;
        assert!(*floor > 0);
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(floor, H::bounds(&target_db).end),
        };
        let target_db = H::apply_ops(target_db, H::create_ops_seeded(10, 1), None).await;
        let next_floor = floor.checked_add(2).unwrap();
        let next_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(next_floor, H::bounds(&target_db).end),
        };

        // Start sync with a source that stalls the boundary at the first lower bound.
        let target_db = Arc::new(target_db);
        let (update_tx, update_rx) = mpsc::channel(1);
        let config = Config {
            context: context.child("client"),
            db_config: H::config("moved_floor", &context),
            target: initial_target,
            source: StalledBoundary {
                source: target_db.clone(),
                stalled: floor,
                requested: Mutex::new(BTreeSet::new()),
            },
            fetch_batch_size: NZU64!(3),
            max_outstanding_requests: 2,
            apply_batch_size: NZU64!(4),
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 4,
        };
        let client: Engine<DbOf<H>, _> = Engine::new(config).await.unwrap();

        // The first operation batch is stored while the journal waits for the boundary.
        let client = match client.step().await.unwrap() {
            NextStep::Continue(client) => client,
            NextStep::Complete(_) => panic!("client should not be complete"),
        };
        assert_eq!(Contiguous::bounds(client.journal()).end, *floor);

        // Move the lower bound into the stored batch and finish at the later target. The source
        // panics if a location is requested twice.
        update_tx.send(next_target.clone()).await.unwrap();
        drop(update_tx);
        let synced = client.sync().await.unwrap();
        assert_eq!(H::db_root(&synced), next_target.root);
        H::destroy(synced).await;
        H::destroy(Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("single source"))).await;
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
        let new_commit = db.bounds().end + appends;
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
        let merkleized = batch.merkleize(&db, metadata, new_commit).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db
    }

    pub(crate) struct VariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> SyncTestHarness for VariableHarness<F> {
        type Family = F;
        type Db = VariableDb<F>;
        type Metadata = Vec<u8>;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> ConfigOf<Self> {
            variable_config(suffix, pooler)
        }

        fn create_ops(n: usize) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, 0)
        }

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<OpOf<Self>> {
            variable_create_ops_seeded::<F>(n, seed)
        }

        fn sample_metadata() -> Self::Metadata {
            vec![42]
        }

        async fn init_db(mut ctx: deterministic::Context) -> Self::Db {
            let seed = ctx.next_u64();
            let config = variable_config(&format!("sync-test-{seed}"), &ctx);
            VariableDb::<F>::init(ctx, config, None).await.unwrap()
        }

        async fn init_db_with_config(
            ctx: deterministic::Context,
            config: ConfigOf<Self>,
        ) -> Self::Db {
            VariableDb::<F>::init(ctx, config, None).await.unwrap()
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
            metadata: Option<Self::Metadata>,
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

        async fn get_metadata(db: &Self::Db) -> Option<Self::Metadata> {
            db.get_metadata().await.unwrap()
        }

        async fn assert_ops_applied(db: &Self::Db, ops: &[OpOf<Self>]) {
            let expected: Vec<&Vec<u8>> = ops
                .iter()
                .filter_map(|op| match op {
                    Operation::Append(value) => Some(value),
                    Operation::Commit(_, _) => None,
                })
                .collect();
            if expected.is_empty() {
                return;
            }
            let bounds = db.bounds();
            let mut stored = Vec::new();
            for loc in *bounds.start..*bounds.end {
                if let Some(value) = db.get(Location::new(loc)).await.unwrap() {
                    stored.push(value);
                }
            }
            assert!(
                stored
                    .windows(expected.len())
                    .any(|window| window.iter().eq(expected.iter().copied())),
                "operation values are not stored at consecutive locations"
            );
        }
    }

    pub(crate) type VariableMmrHarness = VariableHarness<mmr::Family>;
    pub(crate) type VariableMmbHarness = VariableHarness<mmb::Family>;
}

// ===== Test Generation =====

/// Emits the keyless-specific sync tests for `$harness`.
macro_rules! keyless_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_sync_source_fails() {
            super::test_sync_source_fails::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_engine_rejects_invalid_responses() {
            super::test_engine_rejects_invalid_responses::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_updates_preserve_delayed_boundary() {
            super::test_target_updates_preserve_delayed_boundary::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_update_keeps_operations_above_moved_floor() {
            super::test_target_update_keeps_operations_above_moved_floor::<$harness>();
        }
    };
}

crate::qmdb::sync::harness::sync_tests!(
    harnesses::VariableMmrHarness,
    variable_mmr,
    keyless_sync_tests
);
crate::qmdb::sync::harness::sync_tests!(
    harnesses::VariableMmbHarness,
    variable_mmb,
    keyless_sync_tests
);

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

        // Reopen the operation journal independently to probe the persisted Merkle boundary.
        drop(db);
        let journal = <JournalOf<H> as qmdb::sync::Journal<_>>::new(
            context.child("journal"),
            qmdb::sync::DatabaseConfig::journal_config(&config),
            non_empty_range!(local_start, local_end),
        )
        .await
        .unwrap();

        let stale_target = Target {
            root: sync_root,
            range: non_empty_range!(local_start.checked_sub(1).unwrap(), local_end),
        };
        assert!(
            <DbOf<H> as qmdb::sync::Database>::local_pinned_nodes(
                context.child("probe_stale"),
                &config,
                &stale_target,
                &journal,
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
                &journal,
            )
            .await
            .unwrap()
            .is_some()
        );
        drop(journal);
    });
}

mod compact_variable {
    use super::*;
    use crate::qmdb::sync::source::tests::{SequenceSource, fetch_compact_state};
    use commonware_parallel::Sequential;

    type SourceDb<F> = variable::Db<F, deterministic::Context, Vec<u8>, Sha256, Sequential>;
    type ClientDb<F> = variable::CompactDb<
        F,
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

    pub(super) fn test_compact_full_source_missing_reports_missing_source<F: Family>() {
        deterministic::Runner::default().start(|_context| async move {
            let source: Arc<commonware_utils::sync::AsyncRwLock<Option<SourceDb<F>>>> =
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

    pub(super) fn test_replay_sync_single_op_range<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("single-op-{}", context.next_u64());
            // Per-op section/blob sizes so pruning to the floor retains exactly one operation.
            let fine_config = |sfx: &str, pooler: &deterministic::Context| {
                let mut config = source_config(sfx, pooler);
                config.log.items_per_section = NZU64!(1);
                config.merkle.items_per_blob = NZU64!(1);
                config
            };
            let source = SourceDb::<F>::init(
                context.child("source"),
                fine_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, None, Location::new(0))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            // A second commit declares the floor at its own location. Everything before it is
            // inactive, so pruning retains exactly that one operation.
            let metadata = vec![7, 7];
            let floor = source.bounds().end;
            let batch = source
                .new_batch()
                .merkleize(&source, Some(metadata.clone()), floor)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let source = source.prune(floor).await.unwrap();

            let bounds = source.bounds();
            assert_eq!(*bounds.end - *bounds.start, 1);
            let target_root = source.root();
            let source = Arc::new(source);

            let client: SourceDb<F> = sync::sync(sync::engine::Config {
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

    pub(super) fn test_compact_sync_roundtrip<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let metadata = vec![9, 9, 9];
            let floor = Location::new(2);
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(metadata.clone()), floor)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let client_cfg = client_config(&suffix, &context);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
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

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
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

    pub(super) fn test_compact_sync_recovers_after_invalid_proof<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-proof-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            // Corrupt the proof without touching `leaves`, so the response passes the
            // engine's size check and fails at verification itself.
            proof.digests.push(sha256::Digest::from([0xee; 32]));

            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![bad_state, good_state]),
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

    pub(super) fn test_compact_sync_recovers_after_tampered_commit_floor<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-floor-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { op, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            let variable::Operation::Commit(metadata, _) = op.clone() else {
                panic!("compact state should carry a commit operation");
            };
            *op = variable::Operation::Commit(metadata, Location::new(0));

            let sequence = SequenceSource::new(vec![bad_state, good_state]);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                sequence.clone(),
                target.clone(),
                client_config(&suffix, &context),
            ))
            .await
            .unwrap();

            assert_eq!(sequence.take_verdicts().await, vec![false, true]);
            assert_eq!(client.root(), target.root);
            client.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_sync_recovers_after_size_mismatch<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-leaf-count-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![7, 8, 9])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { proof, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            proof.leaves -= 1;

            let client: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![bad_state, good_state]),
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

    pub(super) fn test_compact_sync_recovers_after_tampered_pinned_nodes<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-bad-pinned-nodes-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .append(vec![4, 5, 6])
                .merkleize(&source, Some(vec![7]), Location::new(2))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();

            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            let source = Arc::new(source);
            let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
            let mut bad_state = good_state.clone();
            let sync::Response::Boundary { pinned_nodes, .. } = &mut bad_state else {
                unreachable!("boundary fetch returns a boundary response");
            };
            pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

            let sequence = SequenceSource::new(vec![bad_state, good_state]);

            let client_cfg = client_config(&suffix, &context);
            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                sequence.clone(),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();

            assert_eq!(sequence.take_verdicts().await, vec![false, true]);
            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(vec![7]));
            drop(synced);

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target);
            assert_eq!(reopened.get_metadata(), Some(vec![7]));

            reopened.destroy().await.unwrap();
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_full_source_serves_historical_target<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-stale-full-{}", context.next_u64());
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch1 = source
                .new_batch()
                .append(vec![1, 2, 3])
                .merkleize(&source, Some(vec![1]), Location::new(1))
                .await
                .unwrap();
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
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.commit().await.unwrap();
            let current_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };
            assert_ne!(stale_target, current_target);

            let source = Arc::new(source);
            let client: ClientDb<F> = sync::sync(compact_engine_config(
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

    /// A compact source serves a target below its tip from the retained witness, until pruning
    /// drops that witness.
    pub(super) fn test_compact_source_serves_retained_target<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-retained-{}", context.next_u64());
            let mut source_cfg = client_config(&format!("{suffix}-source"), &context);
            // One witness per section, so pruning past the first target drops its witness.
            source_cfg.witness.items_per_section = NZU64!(1);
            let mut source = ClientDb::<F>::init(context.child("source"), source_cfg, None)
                .await
                .unwrap();

            // Apply two commits, recording the target after each.
            let mut targets = Vec::new();
            for i in 1u8..=2 {
                let floor = source.inactivity_floor_loc();
                let batch = source
                    .new_batch()
                    .append(vec![i])
                    .merkleize(&source, Some(vec![i]), floor)
                    .await
                    .unwrap();
                (source, _) = source.apply_batch(batch).await.unwrap();
                source = source.sync().await.unwrap();
                targets.push(source.target());
            }
            let source = Arc::new(source);

            // The first target is below the tip, and syncing to it succeeds.
            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("first"),
                source.clone(),
                targets[0].clone(),
                client_config(&format!("{suffix}-first"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), targets[0].root);
            assert_eq!(synced.get_metadata(), Some(vec![1]));
            synced.destroy().await.unwrap();

            // Pruning past the first target drops its witness.
            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            let source = Arc::new(source.prune(targets[1].size).await.unwrap());
            let result: Result<ClientDb<F>, _> = sync::sync(compact_engine_config(
                context.child("pruned"),
                source.clone(),
                targets[0].clone(),
                client_config(&format!("{suffix}-pruned"), &context),
            ))
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Source(qmdb::Error::Journal(
                    crate::journal::Error::ItemPruned(_)
                )))
            ));

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    pub(super) fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target<
        F: Family,
    >() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-unj-source-{}", context.next_u64());
            let source_cfg = client_config(&format!("{suffix}-source"), &context);
            let source =
                ClientDb::<F>::init(context.child("source_init"), source_cfg.clone(), None)
                    .await
                    .unwrap();

            let metadata1 = vec![1, 1, 1];
            let floor1 = Location::new(1);
            let batch1 = source
                .new_batch()
                .append(vec![10, 11])
                .merkleize(&source, Some(metadata1.clone()), floor1)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch1).await.unwrap();
            let source = source.sync().await.unwrap();
            let target1 = source.target();
            drop(source);

            let source =
                ClientDb::<F>::init(context.child("source_reopen"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            assert_eq!(source.target(), target1);

            let serve1_cfg = client_config(&format!("{suffix}-serve1"), &context);
            let served1: ClientDb<F> = sync::sync(compact_engine_config(
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

            let source =
                ClientDb::<F>::init(context.child("source_resume"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            let metadata2 = vec![2, 2, 2];
            let floor2 = Location::new(2);
            let batch2 = source
                .new_batch()
                .append(vec![20, 21])
                .merkleize(&source, Some(metadata2.clone()), floor2)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch2).await.unwrap();
            let source = source.sync().await.unwrap();
            let target2 = source.target();
            assert_ne!(target2, target1);

            // Select the earlier target durably before serving it and growing a new suffix.
            drop(source);
            let source = ClientDb::<F>::init(
                context.child("cap_source"),
                source_cfg.clone(),
                Some(target1.size),
            )
            .await
            .unwrap();
            assert_eq!(source.target(), target1);

            let serve2_cfg = client_config(&format!("{suffix}-serve2"), &context);
            let served2: ClientDb<F> = sync::sync(compact_engine_config(
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

            let source =
                ClientDb::<F>::init(context.child("source_regrow"), source_cfg.clone(), None)
                    .await
                    .unwrap();
            assert_eq!(source.target(), target1);
            let metadata3 = vec![3, 3, 3];
            let floor3 = Location::new(2);
            let batch3 = source
                .new_batch()
                .append(vec![30, 31, 32])
                .merkleize(&source, Some(metadata3.clone()), floor3)
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch3).await.unwrap();
            let source = source.sync().await.unwrap();
            let target3 = source.target();
            assert_ne!(target3, target1);
            assert_ne!(target3, target2);

            let serve3_cfg = client_config(&format!("{suffix}-serve3"), &context);
            let served3: ClientDb<F> = sync::sync(compact_engine_config(
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
                ClientDb::<F>::init(context.child("source_stale"), source_cfg.clone(), None)
                    .await
                    .unwrap(),
            );
            assert_eq!(source.target(), target3);
            // target2 names a divergent history. The regrown source reaches the same leaf
            // count under a different root, so it serves state the client can never verify.
            // The direct source has no further candidate, so rejection is terminal.
            let divergent_result: Result<ClientDb<F>, _> = sync::sync(compact_engine_config(
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

            // A target below the retained tip is served from its retained witness.
            let stale: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("stale_client"),
                source.clone(),
                target1.clone(),
                client_config(&format!("{suffix}-stale"), &context),
            ))
            .await
            .unwrap();
            assert_eq!(stale.root(), target1.root);
            assert_eq!(stale.get_metadata(), Some(metadata1.clone()));
            stale.destroy().await.unwrap();

            let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
            source.destroy().await.unwrap();
        });
    }

    /// Compact sync must reinitialize a partition whose witness journal was previously pruned
    /// (the journal reset must clear the nonzero pruning boundary).
    pub(super) fn test_compact_sync_reuses_pruned_partition<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-pruned-{}", context.next_u64());

            // Seed the client partition with several commits, then prune its witness journal.
            let mut client_cfg = client_config(&suffix, &context);
            client_cfg.witness.items_per_section = NZU64!(1);
            let mut seeded = ClientDb::<F>::init(context.child("seed"), client_cfg.clone(), None)
                .await
                .unwrap();
            for i in 1u8..=3 {
                let floor = seeded.inactivity_floor_loc();
                let batch = seeded
                    .new_batch()
                    .append(vec![i])
                    .merkleize(&seeded, Some(vec![i]), floor)
                    .await
                    .unwrap();
                (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                seeded = seeded.sync().await.unwrap();
            }

            // Leave a nonzero witness-journal pruning boundary for the import to replace.
            let boundary = seeded.size();
            let seeded = seeded.prune(boundary).await.unwrap();
            drop(seeded);

            // Sync different state into the same partition.
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let metadata = vec![9, 9, 9];
            let batch = source
                .new_batch()
                .append(vec![1, 2, 3])
                .merkleize(&source, Some(metadata.clone()), Location::new(0))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };

            let synced: ClientDb<F> = sync::sync(compact_engine_config(
                context.child("client"),
                Arc::new(source),
                target.clone(),
                client_cfg.clone(),
            ))
            .await
            .unwrap();
            assert_eq!(synced.root(), target.root);
            drop(synced);

            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.root(), target.root);
            reopened.destroy().await.unwrap();
        });
    }

    /// A boundary response can verify against its target while reconstructing a different
    /// canonical root. Rejecting that import must preserve the destination's durable witness.
    pub(super) fn test_compact_sync_root_mismatch_preserves_existing_state<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-root-mismatch-{}", context.next_u64());

            // Seed the destination partition with durable state that a failed import must not
            // replace.
            let client_cfg = client_config(&suffix, &context);
            let seeded = ClientDb::<F>::init(context.child("seed"), client_cfg.clone(), None)
                .await
                .unwrap();
            let batch = seeded
                .new_batch()
                .append(vec![1])
                .merkleize(&seeded, Some(vec![1]), Location::new(0))
                .await
                .unwrap();
            let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
            let seeded = seeded.sync().await.unwrap();
            let original_target = seeded.target();
            drop(seeded);

            // Build a compact boundary response from a valid source state.
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
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
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let size = source.bounds().end;
            let last_commit_loc = size - 1;
            let canonical_target = sync::CompactTarget {
                root: source.root(),
                size,
            };
            let source = Arc::new(source);
            let response = fetch_compact_state(&source, canonical_target)
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
            let result: Result<ClientDb<F>, _> = sync::sync(compact_engine_config(
                context.child("client"),
                SequenceSource::new(vec![sync::Response::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                }]),
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
            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
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
    pub(super) fn test_compact_sync_dropped_import_preserves_existing_state<F: Family>() {
        deterministic::Runner::default().start(|mut context| async move {
            let suffix = format!("compact-keyless-dropped-{}", context.next_u64());

            // Seed the client partition with committed state A.
            let client_cfg = client_config(&suffix, &context);
            let seeded = ClientDb::<F>::init(context.child("seed"), client_cfg.clone(), None)
                .await
                .unwrap();
            let batch = seeded
                .new_batch()
                .append(vec![1])
                .merkleize(&seeded, Some(vec![1]), Location::new(0))
                .await
                .unwrap();
            let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
            let seeded = seeded.sync().await.unwrap();
            let target_a = seeded.target();
            drop(seeded);

            // Reconstruct state B into the same partition, then drop it before the first
            // persist (as a cancelled sync would).
            let source = SourceDb::<F>::init(
                context.child("source"),
                source_config(&suffix, &context),
                None,
            )
            .await
            .unwrap();
            let batch = source
                .new_batch()
                .append(vec![9])
                .merkleize(&source, Some(vec![9]), Location::new(0))
                .await
                .unwrap();
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.commit().await.unwrap();
            let bounds = source.bounds();
            let target_b = sync::CompactTarget {
                root: source.root(),
                size: bounds.end,
            };
            assert_ne!(target_b, target_a);
            let source = Arc::new(source);
            let response = fetch_compact_state(&source, target_b.clone())
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
            let imported = ClientDb::<F>::init_from_sync(
                client_cfg.strategy.clone(),
                journal,
                client_cfg.commit_codec_config,
                target_b.size - 1,
                pinned_nodes,
                op,
            )
            .unwrap();
            assert_eq!(imported.target(), target_b);

            // Drop the unpersisted import. It must not replace the previous durable witness.
            drop(imported);

            // Pruning requires a persisted import; rebuild the pending import to check rejection.
            let response = fetch_compact_state(&source, target_b.clone())
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
            let imported = ClientDb::<F>::init_from_sync(
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
            let reopened = ClientDb::<F>::init(context.child("reopen"), client_cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }
}

/// Emits the compact sync tests for `$family` under `$mod_name`.
macro_rules! compact_sync_tests {
    ($family:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::compact_variable;
            use commonware_macros::test_traced;

            #[test_traced("WARN")]
            fn test_compact_full_source_missing_reports_missing_source() {
                compact_variable::test_compact_full_source_missing_reports_missing_source::<$family>();
            }

            #[test_traced("WARN")]
            fn test_replay_sync_single_op_range() {
                compact_variable::test_replay_sync_single_op_range::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_roundtrip() {
                compact_variable::test_compact_sync_roundtrip::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_invalid_proof() {
                compact_variable::test_compact_sync_recovers_after_invalid_proof::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_commit_floor() {
                compact_variable::test_compact_sync_recovers_after_tampered_commit_floor::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_size_mismatch() {
                compact_variable::test_compact_sync_recovers_after_size_mismatch::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_pinned_nodes() {
                compact_variable::test_compact_sync_recovers_after_tampered_pinned_nodes::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_full_source_serves_historical_target() {
                compact_variable::test_compact_full_source_serves_historical_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_serves_retained_target() {
                compact_variable::test_compact_source_serves_retained_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target() {
                compact_variable::test_compact_source_reopen_bounded_initialization_regrow_and_stale_target::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_reuses_pruned_partition() {
                compact_variable::test_compact_sync_reuses_pruned_partition::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_root_mismatch_preserves_existing_state() {
                compact_variable::test_compact_sync_root_mismatch_preserves_existing_state::<$family>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_dropped_import_preserves_existing_state() {
                compact_variable::test_compact_sync_dropped_import_preserves_existing_state::<$family>();
            }
        }
    };
}

compact_sync_tests!(crate::merkle::mmr::Family, compact_variable_mmr);
compact_sync_tests!(crate::merkle::mmb::Family, compact_variable_mmb);
