//! Sync tests for keyless databases.
//!
//! The harness contract and the shared sync tests live in [`crate::qmdb::sync::harness`]. This
//! module implements the harness for keyless databases and adds keyless-specific tests to the
//! modules the shared macro generates.

use crate::{
    journal::contiguous::Contiguous,
    merkle::{Family, Location, Proof, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        self,
        keyless::{self, Operation, fixed, variable},
        sync::{
            self, Engine, Target,
            engine::{Config, NextStep},
            harness::{
                CompactConfigOf, CompactOpOf, CompactSyncTestHarness, ConfigOf, DbOf, JournalOf,
                OpOf, PAGE_CACHE_SIZE, PAGE_SIZE, SyncTestHarness, compact_engine_config,
            },
            source::{
                Source,
                tests::{SequenceSource, fetch_compact_state},
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
use std::{collections::BTreeSet, future::Future, num::NonZeroU64, pin::pin, sync::Arc};

/// Keyless-specific harness methods used by the keyless-only sync tests.
pub(crate) trait KeylessSyncTestHarness: SyncTestHarness {
    /// Applies `ops` in a batch whose commit declares its own location as the inactivity floor.
    fn apply_ops_raising_floor(
        db: Self::Db,
        ops: Vec<OpOf<Self>>,
        metadata: Option<Self::Metadata>,
    ) -> impl Future<Output = Self::Db> + Send;
}

/// Keyless-specific harness methods used by the keyless-only compact sync tests.
pub(crate) trait KeylessCompactSyncTestHarness: CompactSyncTestHarness {
    /// Proves the last commit of `full` against the root computed with `inactive_peaks`
    /// inactive peaks, and returns the proof with that root.
    fn last_commit_proof(
        full: &Self::Full,
        inactive_peaks: usize,
    ) -> impl Future<Output = (Proof<Self::Family, sha256::Digest>, sha256::Digest)> + Send;
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
            max_outstanding_requests: NZUsize!(1),
            fetch_batch_size,
            db_config,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
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

/// A client synced over the full retained history of a source whose inactivity floor is at its
/// last commit matches the source's bounds, floor, and root, and holds every operation.
pub(crate) fn test_sync_full_range_with_floor_at_last_commit<H: KeylessSyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // The unpruned source raises its floor to its last commit.
        let source_db = H::init_db(context.child("source")).await;
        let ops = H::create_ops(100);
        let start = H::bounds(&source_db).end;
        let source_db =
            H::apply_ops_raising_floor(source_db, ops.clone(), Some(H::sample_metadata())).await;
        let bounds = H::bounds(&source_db);
        let floor = H::inactivity_floor_loc(&source_db);
        assert_eq!(floor, bounds.end.checked_sub(1).unwrap());
        let root = H::db_root(&source_db);

        // Sync a fresh client over the full range.
        let source_db = Arc::new(source_db);
        let config = Config {
            db_config: H::config("full_range_floor_at_last_commit", &context),
            fetch_batch_size: NZU64!(10),
            target: Target {
                root,
                range: non_empty_range!(bounds.start, bounds.end),
            },
            context: context.child("client"),
            source: source_db.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(1),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        };
        let synced: DbOf<H> = sync::sync(config).await.unwrap();

        assert_eq!(H::bounds(&synced), bounds);
        assert_eq!(H::inactivity_floor_loc(&synced), floor);
        assert_eq!(H::db_root(&synced), root);
        H::assert_ops_applied(&synced, start, &ops).await;

        H::destroy(synced).await;
        H::destroy(Arc::try_unwrap(source_db).unwrap_or_else(|_| panic!("single source"))).await;
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
/// applied without a second boundary request, and sync completes at a later target.
pub(crate) fn test_target_updates_preserve_delayed_boundary<H: KeylessSyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Build three targets that share a lower bound above zero while their commit floors
        // advance.
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops_raising_floor(target_db, H::create_ops(20), None).await;
        let target_db = H::prune(target_db, Location::new(5)).await;
        let start = H::bounds(&target_db).start;
        assert!(*start > 0);
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(start, H::bounds(&target_db).end),
        };
        let target_db =
            H::apply_ops_raising_floor(target_db, H::create_ops_seeded(10, 1), None).await;
        let next_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(start, H::bounds(&target_db).end),
        };
        let target_db =
            H::apply_ops_raising_floor(target_db, H::create_ops_seeded(10, 2), None).await;
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
            max_outstanding_requests: NZUsize!(1),
            apply_batch_size: NZU64!(4),
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
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

        // The boundary is now verified and applied. Move to a later target before finishing.
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
pub(crate) fn test_target_update_keeps_operations_above_moved_floor<H: KeylessSyncTestHarness>()
where
    OpOf<H>: Encode + Clone,
    Arc<DbOf<H>>: sync::SourceFor<DbOf<H>>,
    JournalOf<H>: Contiguous,
{
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Build a target pruned above zero and a later target whose lower bound is two higher,
        // each with a commit floor at its last commit.
        let target_db = H::init_db(context.child("target")).await;
        let target_db = H::apply_ops_raising_floor(target_db, H::create_ops(20), None).await;
        let target_db = H::prune(target_db, Location::new(5)).await;
        let floor = H::bounds(&target_db).start;
        assert!(*floor > 0);
        let initial_target = Target {
            root: H::db_root(&target_db),
            range: non_empty_range!(floor, H::bounds(&target_db).end),
        };
        let target_db =
            H::apply_ops_raising_floor(target_db, H::create_ops_seeded(10, 1), None).await;
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
            max_outstanding_requests: NZUsize!(2),
            apply_batch_size: NZU64!(4),
            update_rx: Some(update_rx),
            finish_rx: None,
            reached_target_tx: None,
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

/// A source pruned to a commit that declares its own location as the floor leaves a one-operation
/// sync range, and syncing that range reproduces the source's root, bounds, and metadata.
pub(crate) fn test_replay_sync_single_op_range<F: Family>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("single-op-{}", context.next_u64());
        // Per-op section/blob sizes so pruning to the floor retains exactly one operation.
        let fine_config = |sfx: &str, pooler: &deterministic::Context| {
            let mut config = harnesses::VariableHarness::<F>::config(sfx, pooler);
            config.log.items_per_section = NZU64!(1);
            config.merkle.items_per_blob = NZU64!(1);
            config
        };
        let source = DbOf::<harnesses::VariableHarness<F>>::init(
            context.child("source"),
            fine_config(&suffix, &context),
            None,
        )
        .await
        .unwrap();

        // The first commit appends two values and keeps the floor at zero.
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

        // The sync range holds only the floor commit, so one boundary response supplies all of it.
        let client: DbOf<harnesses::VariableHarness<F>> = sync::sync(sync::engine::Config {
            context: context.child("client"),
            db_config: fine_config(&format!("{suffix}-client"), &context),
            fetch_batch_size: NZU64!(2),
            target: sync::Target {
                root: target_root,
                range: non_empty_range!(bounds.start, bounds.end),
            },
            source: source.clone(),
            apply_batch_size: NZU64!(1024),
            max_outstanding_requests: NZUsize!(2),
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
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

/// A boundary response can verify against its target while reconstructing a different
/// canonical root. Rejecting that import must preserve the destination's durable witness.
pub(crate) fn test_compact_sync_root_mismatch_preserves_existing_state<
    H: KeylessCompactSyncTestHarness,
>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-keyless-root-mismatch-{}", context.next_u64());

        // Seed the destination partition with durable state that a failed import must not
        // replace.
        let client_cfg = H::config(&suffix, &context);
        let seeded = H::init(context.child("seed"), client_cfg.clone(), None).await;
        let seeded = H::apply(seeded, &[H::value(1)], Some(H::value(1)), Location::new(0)).await;
        let seeded = H::sync(seeded).await;
        let original_target = H::target(&seeded);
        drop(seeded);

        // Build a compact boundary response from a valid source state.
        let source = H::init_full(context.child("source"), &suffix).await;
        let values: Vec<_> = (2..=6).map(H::value).collect();
        let source = H::apply_full(source, &values, Some(H::value(9)), Location::new(0)).await;
        let source = H::commit_full(source).await;
        let size = H::full_bounds(&source).end;
        let canonical_target = sync::CompactTarget {
            root: H::full_root(&source),
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
        let (proof, noncanonical_root) = H::last_commit_proof(&source, 1).await;
        assert_ne!(noncanonical_root, H::full_root(&source));

        // The rejected reconstruction must remain provisional.
        let result: Result<H::Db, _> = sync::sync(compact_engine_config(
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
        let reopened = H::init(context.child("reopen"), client_cfg, None).await;
        assert_eq!(H::target(&reopened), original_target);

        H::destroy(reopened).await;
        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

pub(crate) mod harnesses {
    use super::*;
    use crate::{journal::contiguous::Mutable, qmdb::any::value::ValueEncoding};
    use commonware_codec::{EncodeShared, Read};
    use commonware_parallel::Sequential;
    use commonware_utils::sequence::U64;

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

    /// Applies the given operations in a batch whose commit declares `floor`.
    async fn variable_apply_ops<F: Family>(
        db: VariableDb<F>,
        ops: Vec<VariableOp<F>>,
        metadata: Option<Vec<u8>>,
        floor: Location<F>,
    ) -> VariableDb<F> {
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
        let merkleized = batch.merkleize(&db, metadata, floor).await.unwrap();
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
            let floor = db.inactivity_floor_loc();
            variable_apply_ops::<F>(db, ops, metadata, floor).await
        }

        async fn prune(db: Self::Db, loc: Location<Self::Family>) -> Self::Db {
            // Prune requires the floor to be at or beyond the prune target, so commit `loc` as
            // the floor unless the floor already exceeds it.
            let db = if db.inactivity_floor_loc() > loc {
                db
            } else {
                let merkleized = db.new_batch().merkleize(&db, None, loc).await.unwrap();
                let (db, _) = db.apply_batch(merkleized).await.unwrap();
                db.commit().await.unwrap()
            };
            db.prune(loc).await.unwrap()
        }

        fn bounds(db: &Self::Db) -> std::ops::Range<Location<Self::Family>> {
            db.bounds()
        }

        fn sync_boundary(db: &Self::Db) -> Location<Self::Family> {
            db.sync_boundary()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family> {
            db.inactivity_floor_loc()
        }

        fn db_root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        async fn get_metadata(db: &Self::Db) -> Option<Self::Metadata> {
            db.get_metadata().await.unwrap()
        }

        async fn assert_ops_applied(
            db: &Self::Db,
            start: Location<Self::Family>,
            ops: &[OpOf<Self>],
        ) {
            for (loc, op) in (*start..).zip(ops) {
                let Operation::Append(value) = op else {
                    panic!("apply_ops does not apply commit operations");
                };
                let got = db.get(Location::new(loc)).await.unwrap();
                assert_eq!(got.as_ref(), Some(value), "wrong value at location {loc}");
            }
        }

        async fn assert_ops_absent(db: &Self::Db, ops: &[OpOf<Self>]) {
            let bounds = db.bounds();
            for loc in *bounds.start..*bounds.end {
                if let Some(value) = db.get(Location::new(loc)).await.unwrap() {
                    assert!(
                        !ops.iter()
                            .any(|op| matches!(op, Operation::Append(v) if *v == value)),
                        "operation value is stored at location {loc}"
                    );
                }
            }
        }
    }

    impl<F: Family> KeylessSyncTestHarness for VariableHarness<F> {
        async fn apply_ops_raising_floor(
            db: Self::Db,
            ops: Vec<OpOf<Self>>,
            metadata: Option<Self::Metadata>,
        ) -> Self::Db {
            let floor = db.bounds().end + ops.len() as u64;
            variable_apply_ops::<F>(db, ops, metadata, floor).await
        }
    }

    pub(crate) type VariableMmrHarness = VariableHarness<mmr::Family>;
    pub(crate) type VariableMmbHarness = VariableHarness<mmb::Family>;

    type CompactVariableDb<F> = variable::CompactDb<
        F,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;
    type FixedDb<F> = fixed::Db<F, deterministic::Context, U64, Sha256, Sequential>;
    type CompactFixedDb<F> = fixed::CompactDb<F, deterministic::Context, U64, Sha256, Sequential>;
    type FullDb<F, V, C> = keyless::Keyless<F, deterministic::Context, V, C, Sha256, Sequential>;
    type CompactDb<F, V, C> =
        keyless::CompactDb<F, deterministic::Context, V, Sha256, C, Sequential>;

    fn fixed_config(suffix: &str, pooler: &impl BufferPooler) -> fixed::Config<Sequential> {
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
            log: crate::journal::contiguous::fixed::Config {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    fn compact_config<C>(
        suffix: &str,
        pooler: &impl BufferPooler,
        commit_codec_config: C,
    ) -> keyless::CompactConfig<C, Sequential> {
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
            commit_codec_config,
        }
    }

    async fn compact_apply<F, V, C>(
        db: CompactDb<F, V, C>,
        values: &[V::Value],
        metadata: Option<V::Value>,
        floor: Location<F>,
    ) -> CompactDb<F, V, C>
    where
        F: Family,
        V: ValueEncoding,
        Operation<F, V>: EncodeShared + Read<Cfg = C>,
        C: Clone + Send + Sync + 'static,
    {
        let mut batch = db.new_batch();
        for value in values {
            batch = batch.append(value.clone());
        }
        let batch = batch.merkleize(&db, metadata, floor).await.unwrap();
        db.apply_batch(batch).await.unwrap().0
    }

    async fn full_apply<F, V, C>(
        db: FullDb<F, V, C>,
        values: &[V::Value],
        metadata: Option<V::Value>,
        floor: Location<F>,
    ) -> FullDb<F, V, C>
    where
        F: Family,
        V: ValueEncoding,
        C: Mutable<Item = Operation<F, V>>,
        Operation<F, V>: EncodeShared,
    {
        let mut batch = db.new_batch();
        for value in values {
            batch = batch.append(value.clone());
        }
        let batch = batch.merkleize(&db, metadata, floor).await.unwrap();
        db.apply_batch(batch).await.unwrap().0
    }

    async fn compact_import<F, V, C>(
        ctx: deterministic::Context,
        config: &keyless::CompactConfig<C, Sequential>,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<sha256::Digest>,
        op: Operation<F, V>,
    ) -> Result<CompactDb<F, V, C>, qmdb::Error<F>>
    where
        F: Family,
        V: ValueEncoding,
        Operation<F, V>: EncodeShared + Read<Cfg = C>,
        C: Clone + Send + Sync + 'static,
    {
        let journal =
            crate::journal::contiguous::variable::Journal::init(ctx, config.witness.clone())
                .await?;
        CompactDb::init_from_sync(
            config.strategy.clone(),
            journal,
            config.commit_codec_config.clone(),
            last_commit_loc,
            pinned_nodes,
            op,
        )
    }

    async fn full_last_commit_proof<F, V, C>(
        db: &FullDb<F, V, C>,
        inactive_peaks: usize,
    ) -> (Proof<F, sha256::Digest>, sha256::Digest)
    where
        F: Family,
        V: ValueEncoding,
        C: Mutable<Item = Operation<F, V>>,
        Operation<F, V>: EncodeShared,
    {
        let hasher = qmdb::hasher::<Sha256>();
        let size = db.bounds().end;
        let proof = db
            .journal
            .merkle
            .historical_proof(&hasher, size, size - 1, inactive_peaks)
            .await
            .unwrap();
        let root = db.journal.merkle.root(&hasher, inactive_peaks).unwrap();
        (proof, root)
    }

    fn commit_with_floor<F: Family, V: ValueEncoding>(
        op: Operation<F, V>,
        floor: Location<F>,
    ) -> Operation<F, V> {
        let Operation::Commit(metadata, _) = op else {
            panic!("compact state should carry a commit operation");
        };
        Operation::Commit(metadata, floor)
    }

    pub(crate) struct CompactVariableHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> CompactSyncTestHarness for CompactVariableHarness<F> {
        type Family = F;
        type Db = CompactVariableDb<F>;
        type Full = VariableDb<F>;
        type Value = Vec<u8>;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> CompactConfigOf<Self> {
            compact_config(suffix, pooler, ((0..=10000).into(), ()))
        }

        fn with_witness_items_per_section(
            mut config: CompactConfigOf<Self>,
            items_per_section: NonZeroU64,
        ) -> CompactConfigOf<Self> {
            config.witness.items_per_section = items_per_section;
            config
        }

        fn value(seed: u8) -> Self::Value {
            vec![seed; 2 + seed as usize % 3]
        }

        async fn init(
            ctx: deterministic::Context,
            config: CompactConfigOf<Self>,
            max_size: Option<Location<F>>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, max_size).await.unwrap()
        }

        async fn init_full(ctx: deterministic::Context, suffix: &str) -> Self::Full {
            let config = variable_config(suffix, &ctx);
            Self::Full::init(ctx, config, None).await.unwrap()
        }

        async fn import(
            ctx: deterministic::Context,
            config: &CompactConfigOf<Self>,
            last_commit_loc: Location<F>,
            pinned_nodes: Vec<sha256::Digest>,
            op: CompactOpOf<Self>,
        ) -> Result<Self::Db, qmdb::Error<F>> {
            compact_import(ctx, config, last_commit_loc, pinned_nodes, op).await
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn destroy_full(full: Self::Full) {
            full.destroy().await.unwrap();
        }

        async fn apply(
            db: Self::Db,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Db {
            compact_apply(db, values, metadata, floor).await
        }

        async fn apply_full(
            full: Self::Full,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Full {
            full_apply(full, values, metadata, floor).await
        }

        async fn sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn commit_full(full: Self::Full) -> Self::Full {
            full.commit().await.unwrap()
        }

        async fn prune(db: Self::Db, loc: Location<F>) -> Result<Self::Db, qmdb::Error<F>> {
            db.prune(loc).await
        }

        fn root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        fn target(db: &Self::Db) -> sync::CompactTarget<F, sha256::Digest> {
            db.target()
        }

        fn size(db: &Self::Db) -> Location<F> {
            db.size()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<F> {
            db.inactivity_floor_loc()
        }

        fn metadata(db: &Self::Db) -> Option<Self::Value> {
            db.get_metadata()
        }

        fn full_root(full: &Self::Full) -> sha256::Digest {
            full.root()
        }

        fn full_bounds(full: &Self::Full) -> std::ops::Range<Location<F>> {
            full.bounds()
        }

        fn with_commit_floor(op: CompactOpOf<Self>, floor: Location<F>) -> CompactOpOf<Self> {
            commit_with_floor(op, floor)
        }
    }

    impl<F: Family> KeylessCompactSyncTestHarness for CompactVariableHarness<F> {
        async fn last_commit_proof(
            full: &Self::Full,
            inactive_peaks: usize,
        ) -> (Proof<F, sha256::Digest>, sha256::Digest) {
            full_last_commit_proof(full, inactive_peaks).await
        }
    }

    pub(crate) struct CompactFixedHarness<F>(std::marker::PhantomData<F>);

    impl<F: Family> CompactSyncTestHarness for CompactFixedHarness<F> {
        type Family = F;
        type Db = CompactFixedDb<F>;
        type Full = FixedDb<F>;
        type Value = U64;

        fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> CompactConfigOf<Self> {
            compact_config(suffix, pooler, ())
        }

        fn with_witness_items_per_section(
            mut config: CompactConfigOf<Self>,
            items_per_section: NonZeroU64,
        ) -> CompactConfigOf<Self> {
            config.witness.items_per_section = items_per_section;
            config
        }

        fn value(seed: u8) -> Self::Value {
            U64::new(seed.into())
        }

        async fn init(
            ctx: deterministic::Context,
            config: CompactConfigOf<Self>,
            max_size: Option<Location<F>>,
        ) -> Self::Db {
            Self::Db::init(ctx, config, max_size).await.unwrap()
        }

        async fn init_full(ctx: deterministic::Context, suffix: &str) -> Self::Full {
            let config = fixed_config(suffix, &ctx);
            Self::Full::init(ctx, config, None).await.unwrap()
        }

        async fn import(
            ctx: deterministic::Context,
            config: &CompactConfigOf<Self>,
            last_commit_loc: Location<F>,
            pinned_nodes: Vec<sha256::Digest>,
            op: CompactOpOf<Self>,
        ) -> Result<Self::Db, qmdb::Error<F>> {
            compact_import(ctx, config, last_commit_loc, pinned_nodes, op).await
        }

        async fn destroy(db: Self::Db) {
            db.destroy().await.unwrap();
        }

        async fn destroy_full(full: Self::Full) {
            full.destroy().await.unwrap();
        }

        async fn apply(
            db: Self::Db,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Db {
            compact_apply(db, values, metadata, floor).await
        }

        async fn apply_full(
            full: Self::Full,
            values: &[Self::Value],
            metadata: Option<Self::Value>,
            floor: Location<F>,
        ) -> Self::Full {
            full_apply(full, values, metadata, floor).await
        }

        async fn sync(db: Self::Db) -> Self::Db {
            db.sync().await.unwrap()
        }

        async fn commit_full(full: Self::Full) -> Self::Full {
            full.commit().await.unwrap()
        }

        async fn prune(db: Self::Db, loc: Location<F>) -> Result<Self::Db, qmdb::Error<F>> {
            db.prune(loc).await
        }

        fn root(db: &Self::Db) -> sha256::Digest {
            db.root()
        }

        fn target(db: &Self::Db) -> sync::CompactTarget<F, sha256::Digest> {
            db.target()
        }

        fn size(db: &Self::Db) -> Location<F> {
            db.size()
        }

        fn inactivity_floor_loc(db: &Self::Db) -> Location<F> {
            db.inactivity_floor_loc()
        }

        fn metadata(db: &Self::Db) -> Option<Self::Value> {
            db.get_metadata()
        }

        fn full_root(full: &Self::Full) -> sha256::Digest {
            full.root()
        }

        fn full_bounds(full: &Self::Full) -> std::ops::Range<Location<F>> {
            full.bounds()
        }

        fn with_commit_floor(op: CompactOpOf<Self>, floor: Location<F>) -> CompactOpOf<Self> {
            commit_with_floor(op, floor)
        }
    }

    impl<F: Family> KeylessCompactSyncTestHarness for CompactFixedHarness<F> {
        async fn last_commit_proof(
            full: &Self::Full,
            inactive_peaks: usize,
        ) -> (Proof<F, sha256::Digest>, sha256::Digest) {
            full_last_commit_proof(full, inactive_peaks).await
        }
    }

    pub(crate) type CompactVariableMmrHarness = CompactVariableHarness<mmr::Family>;
    pub(crate) type CompactVariableMmbHarness = CompactVariableHarness<mmb::Family>;
    pub(crate) type CompactFixedMmrHarness = CompactFixedHarness<mmr::Family>;
    pub(crate) type CompactFixedMmbHarness = CompactFixedHarness<mmb::Family>;
}

/// Emits the keyless-specific sync tests for `$harness`.
macro_rules! keyless_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_engine_rejects_invalid_responses() {
            super::test_engine_rejects_invalid_responses::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_sync_full_range_with_floor_at_last_commit() {
            super::test_sync_full_range_with_floor_at_last_commit::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_updates_preserve_delayed_boundary() {
            super::test_target_updates_preserve_delayed_boundary::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_target_update_keeps_operations_above_moved_floor() {
            super::test_target_update_keeps_operations_above_moved_floor::<$harness>();
        }

        #[test_traced("WARN")]
        fn test_replay_sync_single_op_range() {
            super::test_replay_sync_single_op_range::<<$harness as SyncTestHarness>::Family>();
        }
    };
}

/// Emits the keyless-specific compact sync tests for `$harness`.
macro_rules! keyless_compact_sync_tests {
    ($harness:ty) => {
        #[test_traced("WARN")]
        fn test_compact_sync_root_mismatch_preserves_existing_state() {
            super::test_compact_sync_root_mismatch_preserves_existing_state::<$harness>();
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
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactVariableMmrHarness,
    compact_variable_mmr,
    keyless_compact_sync_tests
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactVariableMmbHarness,
    compact_variable_mmb,
    keyless_compact_sync_tests
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactFixedMmrHarness,
    compact_fixed_mmr,
    keyless_compact_sync_tests
);
crate::qmdb::sync::harness::compact_sync_tests!(
    harnesses::CompactFixedMmbHarness,
    compact_fixed_mmb,
    keyless_compact_sync_tests
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
        // Each batch raises the floor to its commit, so the prune below needs no floor commit.
        for seed in 0..3u64 {
            db = Box::pin(H::apply_ops_raising_floor(
                db,
                H::create_ops_seeded(100, seed),
                None,
            ))
            .await;
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
