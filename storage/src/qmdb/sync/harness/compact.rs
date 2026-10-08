//! Shared compact sync test harness.
//!
//! Defines the [`CompactSyncTestHarness`] contract that each compact database implements, the
//! compact sync tests written against it, and the [`compact_sync_tests`] macro that instantiates
//! those tests per harness.

use super::compact_engine_config;
use crate::{
    merkle::{self, Location},
    qmdb::{
        self,
        sync::{
            self,
            source::tests::{SequenceSource, fetch_compact_state},
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::sha256;
use commonware_runtime::{BufferPooler, Metrics, Runner as _, Supervisor as _, deterministic};
use commonware_utils::NZU64;
use rand::Rng as _;
use std::{fmt::Debug, future::Future, num::NonZeroU64, sync::Arc};

pub(crate) type CompactOpOf<H> = <<H as CompactSyncTestHarness>::Db as qmdb::sync::Database>::Op;
pub(crate) type CompactConfigOf<H> =
    <<H as CompactSyncTestHarness>::Db as qmdb::sync::Database>::Config;

/// Harness that abstracts per-database and per-family details so the shared compact tests below
/// can operate on any compact database that supports sync.
pub(crate) trait CompactSyncTestHarness: Sized + 'static {
    /// Merkle family of the database.
    type Family: merkle::Family;
    /// Compact database under test. It is also the source when a compact peer serves the sync.
    type Db: qmdb::sync::Database<
            Family = Self::Family,
            Context = deterministic::Context,
            Digest = sha256::Digest,
            Op: Clone + Encode,
            Config: Clone,
        > + sync::Source<
            Family = Self::Family,
            Digest = sha256::Digest,
            Op = CompactOpOf<Self>,
            Error = qmdb::Error<Self::Family>,
        >;
    /// Full database that serves compact sync from its retained history.
    type Full: sync::Source<
            Family = Self::Family,
            Digest = sha256::Digest,
            Op = CompactOpOf<Self>,
            Error = qmdb::Error<Self::Family>,
        >;
    /// Value type used for operations and for commit metadata.
    type Value: Clone + PartialEq + Debug + Send + Sync + 'static;

    /// Returns a compact config whose partitions are unique to `suffix`.
    fn config(suffix: &str, pooler: &(impl BufferPooler + Metrics)) -> CompactConfigOf<Self>;
    /// Returns `config` with the witness journal split into sections of `items_per_section`
    /// entries, so pruning can drop individual witnesses.
    fn with_witness_items_per_section(
        config: CompactConfigOf<Self>,
        items_per_section: NonZeroU64,
    ) -> CompactConfigOf<Self>;
    /// Returns a value derived from `seed`. Distinct seeds yield distinct values.
    fn value(seed: u8) -> Self::Value;

    /// Opens the compact database that `config` names, restoring at most `max_size` operations
    /// when a bound is given.
    fn init(
        ctx: deterministic::Context,
        config: CompactConfigOf<Self>,
        max_size: Option<Location<Self::Family>>,
    ) -> impl Future<Output = Self::Db> + Send;
    /// Opens a fresh full database under partitions unique to `suffix`.
    fn init_full(
        ctx: deterministic::Context,
        suffix: &str,
    ) -> impl Future<Output = Self::Full> + Send;
    /// Rebuilds a database from a boundary response without persisting it.
    fn import(
        ctx: deterministic::Context,
        config: &CompactConfigOf<Self>,
        last_commit_loc: Location<Self::Family>,
        pinned_nodes: Vec<sha256::Digest>,
        op: CompactOpOf<Self>,
    ) -> impl Future<Output = Result<Self::Db, qmdb::Error<Self::Family>>> + Send;
    /// Removes all persisted state of `db`.
    fn destroy(db: Self::Db) -> impl Future<Output = ()> + Send;
    /// Removes all persisted state of `full`.
    fn destroy_full(full: Self::Full) -> impl Future<Output = ()> + Send;

    /// Applies one batch of `values` whose commit carries `metadata` and `floor`, without
    /// making it durable.
    fn apply(
        db: Self::Db,
        values: &[Self::Value],
        metadata: Option<Self::Value>,
        floor: Location<Self::Family>,
    ) -> impl Future<Output = Self::Db> + Send;
    /// Applies one batch to `full` like [`Self::apply`].
    fn apply_full(
        full: Self::Full,
        values: &[Self::Value],
        metadata: Option<Self::Value>,
        floor: Location<Self::Family>,
    ) -> impl Future<Output = Self::Full> + Send;
    /// Makes every applied batch of `db` durable.
    fn sync(db: Self::Db) -> impl Future<Output = Self::Db> + Send;
    /// Commits the applied batches of `full`.
    fn commit_full(full: Self::Full) -> impl Future<Output = Self::Full> + Send;
    /// Drops the witnesses of commits with fewer than `loc` operations. Fails while a
    /// compact sync import has not been applied.
    fn prune(
        db: Self::Db,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Self::Db, qmdb::Error<Self::Family>>> + Send;

    /// Returns the current root of `db`.
    fn root(db: &Self::Db) -> sha256::Digest;
    /// Returns the compact sync target for the current state of `db`.
    fn target(db: &Self::Db) -> sync::CompactTarget<Self::Family, sha256::Digest>;
    /// Returns the number of operations in `db`, commits included.
    fn size(db: &Self::Db) -> Location<Self::Family>;
    /// Returns the inactivity floor declared by the last commit in `db`.
    fn inactivity_floor_loc(db: &Self::Db) -> Location<Self::Family>;
    /// Returns the metadata carried by the last commit in `db`.
    fn metadata(db: &Self::Db) -> Option<Self::Value>;
    /// Returns the current root of `full`.
    fn full_root(full: &Self::Full) -> sha256::Digest;
    /// Returns the range of retained operation locations in `full`.
    fn full_bounds(full: &Self::Full) -> std::ops::Range<Location<Self::Family>>;

    /// Replaces the inactivity floor of the commit operation `op`.
    fn with_commit_floor(op: CompactOpOf<Self>, floor: Location<Self::Family>)
    -> CompactOpOf<Self>;
}

/// A shared full-source slot that holds no database answers a compact fetch with `MissingSource`.
pub(crate) fn test_compact_full_source_missing_reports_missing_source<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|_context| async move {
        let source: Arc<commonware_utils::sync::AsyncRwLock<Option<H::Full>>> =
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

/// Compact sync from a full source reproduces the target's root, metadata, and inactivity floor,
/// and that state survives a reopen.
pub(crate) fn test_compact_sync_roundtrip<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-{}", context.next_u64());

        // The source commits metadata and a nonzero floor that the client must reproduce.
        let source = H::init_full(context.child("source"), &suffix).await;
        let metadata = H::value(9);
        let floor = Location::new(2);
        let source = H::apply_full(
            source,
            &[H::value(1), H::value(4)],
            Some(metadata.clone()),
            floor,
        )
        .await;
        let source = H::commit_full(source).await;

        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
            size: bounds.end,
        };
        let source = Arc::new(source);
        let client_cfg = H::config(&suffix, &context);
        let client: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            source.clone(),
            target.clone(),
            client_cfg.clone(),
        ))
        .await
        .unwrap();

        assert_eq!(H::root(&client), target.root);
        assert_eq!(H::metadata(&client), Some(metadata.clone()));
        assert_eq!(H::inactivity_floor_loc(&client), floor);
        drop(client);

        // The synced witness is durable, so a reopen recovers the same state.
        let reopened = H::init(context.child("reopen"), client_cfg, None).await;
        assert_eq!(H::root(&reopened), target.root);
        assert_eq!(H::metadata(&reopened), Some(metadata));
        assert_eq!(H::inactivity_floor_loc(&reopened), floor);

        H::destroy(reopened).await;
        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A compact sync rejects a boundary candidate whose proof fails verification and completes from
/// the next candidate of the same request.
pub(crate) fn test_compact_sync_recovers_after_invalid_proof<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-bad-proof-{}", context.next_u64());
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(7)], Some(H::value(1)), Location::new(1)).await;
        let source = H::commit_full(source).await;

        // Derive the bad candidate from the honest response, so only the proof differs.
        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
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

        // The source offers the bad candidate first and the honest one as its retry.
        let client: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            SequenceSource::new(vec![bad_state, good_state]),
            target.clone(),
            H::config(&suffix, &context),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&client), target.root);
        H::destroy(client).await;

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A compact sync rejects a boundary candidate whose commit carries a tampered inactivity floor,
/// which verification covers, and completes from the next candidate of the same request.
pub(crate) fn test_compact_sync_recovers_after_tampered_commit_floor<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-bad-floor-{}", context.next_u64());
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(7)], Some(H::value(1)), Location::new(1)).await;
        let source = H::commit_full(source).await;

        // Derive the bad candidate from the honest response, rewriting only the commit's floor.
        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
            size: bounds.end,
        };
        let source = Arc::new(source);
        let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
        let mut bad_state = good_state.clone();
        let sync::Response::Boundary { op, .. } = &mut bad_state else {
            unreachable!("boundary fetch returns a boundary response");
        };
        *op = H::with_commit_floor(op.clone(), Location::new(0));

        // The source offers the bad candidate first and the honest one as its retry.
        let sequence = SequenceSource::new(vec![bad_state, good_state]);
        let client: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            sequence.clone(),
            target.clone(),
            H::config(&suffix, &context),
        ))
        .await
        .unwrap();

        // The verdicts show the engine judged the tampered candidate invalid and the honest one
        // valid.
        assert_eq!(sequence.take_verdicts().await, vec![false, true]);
        assert_eq!(H::root(&client), target.root);
        H::destroy(client).await;

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A compact sync rejects a boundary candidate whose proof claims one fewer leaf than the target
/// and completes from the next candidate of the same request.
pub(crate) fn test_compact_sync_recovers_after_size_mismatch<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-bad-leaf-count-{}", context.next_u64());
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(7)], Some(H::value(1)), Location::new(1)).await;
        let source = H::commit_full(source).await;

        // Derive the bad candidate from the honest response, lowering only the proof's leaf count.
        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
            size: bounds.end,
        };
        let source = Arc::new(source);
        let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
        let mut bad_state = good_state.clone();
        let sync::Response::Boundary { proof, .. } = &mut bad_state else {
            unreachable!("boundary fetch returns a boundary response");
        };
        proof.leaves -= 1;

        // The source offers the bad candidate first and the honest one as its retry.
        let client: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            SequenceSource::new(vec![bad_state, good_state]),
            target.clone(),
            H::config(&suffix, &context),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&client), target.root);
        H::destroy(client).await;

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A compact sync rejects a boundary candidate with a tampered pinned node and completes from the
/// next candidate of the same request, persisting the honest state.
pub(crate) fn test_compact_sync_recovers_after_tampered_pinned_nodes<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-bad-pinned-nodes-{}", context.next_u64());
        let source = H::init_full(context.child("source"), &suffix).await;
        let source = H::apply_full(
            source,
            &[H::value(1), H::value(4)],
            Some(H::value(7)),
            Location::new(2),
        )
        .await;
        let source = H::commit_full(source).await;

        // Derive the bad candidate from the honest response, replacing only its first pinned node.
        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
            size: bounds.end,
        };
        let source = Arc::new(source);
        let good_state = fetch_compact_state(&source, target.clone()).await.unwrap();
        let mut bad_state = good_state.clone();
        let sync::Response::Boundary { pinned_nodes, .. } = &mut bad_state else {
            unreachable!("boundary fetch returns a boundary response");
        };
        pinned_nodes[0] = sha256::Digest::from([0xaa; 32]);

        // The source offers the bad candidate first and the honest one as its retry.
        let sequence = SequenceSource::new(vec![bad_state, good_state]);

        let client_cfg = H::config(&suffix, &context);
        let synced: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            sequence.clone(),
            target.clone(),
            client_cfg.clone(),
        ))
        .await
        .unwrap();

        // The verdicts show the engine judged the tampered candidate invalid and the honest one
        // valid.
        assert_eq!(sequence.take_verdicts().await, vec![false, true]);
        assert_eq!(H::target(&synced), target);
        assert_eq!(H::metadata(&synced), Some(H::value(7)));
        drop(synced);

        // The accepted state is durable, so a reopen recovers it.
        let reopened = H::init(context.child("reopen"), client_cfg, None).await;
        assert_eq!(H::target(&reopened), target);
        assert_eq!(H::metadata(&reopened), Some(H::value(7)));

        H::destroy(reopened).await;
        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A full source serves a compact target below its tip, and the client reaches that historical
/// root rather than the current one.
pub(crate) fn test_compact_full_source_serves_historical_target<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-stale-full-{}", context.next_u64());

        // The stale target is the source's state after its first commit.
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(1)], Some(H::value(1)), Location::new(1)).await;
        let source = H::commit_full(source).await;
        let stale_target = sync::CompactTarget {
            root: H::full_root(&source),
            size: H::full_bounds(&source).end,
        };

        // A second commit moves the source's tip past the stale target.
        let source =
            H::apply_full(source, &[H::value(4)], Some(H::value(2)), Location::new(2)).await;
        let source = H::commit_full(source).await;
        let current_target = sync::CompactTarget {
            root: H::full_root(&source),
            size: H::full_bounds(&source).end,
        };
        assert_ne!(stale_target, current_target);

        let source = Arc::new(source);
        let client: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            source.clone(),
            stale_target.clone(),
            H::config(&suffix, &context),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&client), stale_target.root);
        assert_ne!(H::root(&client), current_target.root);
        H::destroy(client).await;

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy_full(source).await;
    });
}

/// A compact source serves a target below its tip from the retained witness, until pruning
/// drops that witness.
pub(crate) fn test_compact_source_serves_retained_target<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-retained-{}", context.next_u64());
        // One witness per section, so pruning past the first target drops its witness.
        let source_cfg = H::with_witness_items_per_section(
            H::config(&format!("{suffix}-source"), &context),
            NZU64!(1),
        );
        let mut source = H::init(context.child("source"), source_cfg, None).await;

        // Apply two commits, recording the target after each.
        let mut targets = Vec::new();
        for i in 1u8..=2 {
            let floor = H::inactivity_floor_loc(&source);
            source = H::apply(source, &[H::value(i)], Some(H::value(i)), floor).await;
            source = H::sync(source).await;
            targets.push(H::target(&source));
        }
        let source = Arc::new(source);

        // The first target is below the tip, and syncing to it succeeds.
        let synced: H::Db = sync::sync(compact_engine_config(
            context.child("first"),
            source.clone(),
            targets[0].clone(),
            H::config(&format!("{suffix}-first"), &context),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&synced), targets[0].root);
        assert_eq!(H::metadata(&synced), Some(H::value(1)));
        H::destroy(synced).await;

        // Pruning past the first target drops its witness.
        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        let source = Arc::new(H::prune(source, targets[1].size).await.unwrap());
        let result: Result<H::Db, _> = sync::sync(compact_engine_config(
            context.child("pruned"),
            source.clone(),
            targets[0].clone(),
            H::config(&format!("{suffix}-pruned"), &context),
        ))
        .await;
        assert!(matches!(
            result,
            Err(sync::Error::Source(qmdb::Error::Journal(
                crate::journal::Error::ItemPruned(_)
            )))
        ));

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy(source).await;
    });
}

/// A compact source reopened with a size bound durably rewinds to an earlier target and regrows a
/// different suffix. It keeps serving retained targets and rejects a target from discarded history.
pub(crate) fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target<
    H: CompactSyncTestHarness,
>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-unj-source-{}", context.next_u64());
        let source_cfg = H::config(&format!("{suffix}-source"), &context);
        let source = H::init(context.child("source_init"), source_cfg.clone(), None).await;

        // The first commit fixes target1, the state the bounded reopen later returns to.
        let metadata1 = H::value(1);
        let floor1 = Location::new(1);
        let source = H::apply(source, &[H::value(10)], Some(metadata1.clone()), floor1).await;
        let source = H::sync(source).await;
        let target1 = H::target(&source);
        drop(source);

        // A reopened source recovers target1 and serves it to a fresh client.
        let source = H::init(context.child("source_reopen"), source_cfg.clone(), None).await;
        assert_eq!(H::target(&source), target1);

        let serve1_cfg = H::config(&format!("{suffix}-serve1"), &context);
        let served1: H::Db = sync::sync(compact_engine_config(
            context.child("serve").with_attribute("index", 1),
            Arc::new(source),
            target1.clone(),
            serve1_cfg.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&served1), target1.root);
        assert_eq!(H::metadata(&served1), Some(metadata1.clone()));
        assert_eq!(H::inactivity_floor_loc(&served1), floor1);
        H::destroy(served1).await;

        // Grow the source to target2, the history the bounded reopen discards.
        let source = H::init(context.child("source_resume"), source_cfg.clone(), None).await;
        let metadata2 = H::value(2);
        let floor2 = Location::new(2);
        let source = H::apply(source, &[H::value(20)], Some(metadata2.clone()), floor2).await;
        let source = H::sync(source).await;
        let target2 = H::target(&source);
        assert_ne!(target2, target1);

        // Select the earlier target durably before serving it and growing a new suffix.
        drop(source);
        let source = H::init(
            context.child("cap_source"),
            source_cfg.clone(),
            Some(target1.size),
        )
        .await;
        assert_eq!(H::target(&source), target1);

        let serve2_cfg = H::config(&format!("{suffix}-serve2"), &context);
        let served2: H::Db = sync::sync(compact_engine_config(
            context.child("serve").with_attribute("index", 2),
            Arc::new(source),
            target1.clone(),
            serve2_cfg.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&served2), target1.root);
        assert_eq!(H::metadata(&served2), Some(metadata1.clone()));
        assert_eq!(H::inactivity_floor_loc(&served2), floor1);
        H::destroy(served2).await;

        // The rewind persists across an unbounded reopen, and a new commit regrows the source to
        // target3, which differs from both earlier targets.
        let source = H::init(context.child("source_regrow"), source_cfg.clone(), None).await;
        assert_eq!(H::target(&source), target1);
        let metadata3 = H::value(3);
        let floor3 = Location::new(2);
        let source = H::apply(source, &[H::value(30)], Some(metadata3.clone()), floor3).await;
        let source = H::sync(source).await;
        let target3 = H::target(&source);
        assert_ne!(target3, target1);
        assert_ne!(target3, target2);

        let serve3_cfg = H::config(&format!("{suffix}-serve3"), &context);
        let served3: H::Db = sync::sync(compact_engine_config(
            context.child("serve").with_attribute("index", 3),
            Arc::new(source),
            target3.clone(),
            serve3_cfg.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&served3), target3.root);
        assert_eq!(H::metadata(&served3), Some(metadata3.clone()));
        assert_eq!(H::inactivity_floor_loc(&served3), floor3);
        H::destroy(served3).await;

        let source =
            Arc::new(H::init(context.child("source_stale"), source_cfg.clone(), None).await);
        assert_eq!(H::target(&source), target3);
        // target2 names a divergent history. The regrown source reaches the same leaf
        // count under a different root, so it serves state the client can never verify.
        // The direct source has no further candidate, so rejection is terminal.
        let divergent_result: Result<H::Db, _> = sync::sync(compact_engine_config(
            context.child("divergent_client"),
            source.clone(),
            target2.clone(),
            H::config(&format!("{suffix}-divergent"), &context),
        ))
        .await;
        assert!(matches!(
            divergent_result,
            Err(sync::Error::Engine(sync::EngineError::InvalidResponse))
        ));

        // A target below the retained tip is served from its retained witness.
        let stale: H::Db = sync::sync(compact_engine_config(
            context.child("stale_client"),
            source.clone(),
            target1.clone(),
            H::config(&format!("{suffix}-stale"), &context),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&stale), target1.root);
        assert_eq!(H::metadata(&stale), Some(metadata1.clone()));
        H::destroy(stale).await;

        let source = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        H::destroy(source).await;
    });
}

/// Compact sync must reinitialize a partition whose witness journal was previously pruned
/// (the journal reset must clear the nonzero pruning boundary).
pub(crate) fn test_compact_sync_reuses_pruned_partition<H: CompactSyncTestHarness>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-pruned-{}", context.next_u64());

        // Seed the client partition with several commits, then prune its witness journal.
        let client_cfg = H::with_witness_items_per_section(H::config(&suffix, &context), NZU64!(1));
        let mut seeded = H::init(context.child("seed"), client_cfg.clone(), None).await;
        for i in 1u8..=3 {
            let floor = H::inactivity_floor_loc(&seeded);
            seeded = H::apply(seeded, &[H::value(i)], Some(H::value(i)), floor).await;
            seeded = H::sync(seeded).await;
        }

        // Leave a nonzero witness-journal pruning boundary for the import to replace.
        let boundary = H::size(&seeded);
        let seeded = H::prune(seeded, boundary).await.unwrap();
        drop(seeded);

        // Sync different state into the same partition.
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(1)], Some(H::value(9)), Location::new(0)).await;
        let source = H::commit_full(source).await;
        let bounds = H::full_bounds(&source);
        let target = sync::CompactTarget {
            root: H::full_root(&source),
            size: bounds.end,
        };

        let synced: H::Db = sync::sync(compact_engine_config(
            context.child("client"),
            Arc::new(source),
            target.clone(),
            client_cfg.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(H::root(&synced), target.root);
        drop(synced);

        // A reopen reads the reinitialized witness journal, so the synced root must survive it.
        let reopened = H::init(context.child("reopen"), client_cfg, None).await;
        assert_eq!(H::root(&reopened), target.root);
        H::destroy(reopened).await;
    });
}

/// Dropping a compact-sync import before its first persist leaves the previous witness
/// journal untouched.
pub(crate) fn test_compact_sync_dropped_import_preserves_existing_state<
    H: CompactSyncTestHarness,
>() {
    deterministic::Runner::default().start(|mut context| async move {
        let suffix = format!("compact-dropped-{}", context.next_u64());

        // Seed the client partition with committed state A.
        let client_cfg = H::config(&suffix, &context);
        let seeded = H::init(context.child("seed"), client_cfg.clone(), None).await;
        let seeded = H::apply(seeded, &[H::value(1)], Some(H::value(1)), Location::new(0)).await;
        let seeded = H::sync(seeded).await;
        let target_a = H::target(&seeded);
        drop(seeded);

        // Reconstruct state B into the same partition, then drop it before the first
        // persist (as a cancelled sync would).
        let source = H::init_full(context.child("source"), &suffix).await;
        let source =
            H::apply_full(source, &[H::value(9)], Some(H::value(9)), Location::new(0)).await;
        let source = H::commit_full(source).await;
        let bounds = H::full_bounds(&source);
        let target_b = sync::CompactTarget {
            root: H::full_root(&source),
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
        let imported = H::import(
            context.child("import"),
            &client_cfg,
            target_b.size - 1,
            pinned_nodes,
            op,
        )
        .await
        .unwrap();
        assert_eq!(H::target(&imported), target_b);

        // Drop the unpersisted import. It must not replace the previous durable witness.
        drop(imported);

        // Pruning requires a persisted import, so rebuild the pending import to check rejection.
        let response = fetch_compact_state(&source, target_b.clone())
            .await
            .unwrap();
        let sync::Response::Boundary {
            op, pinned_nodes, ..
        } = response
        else {
            unreachable!("boundary fetch returns a boundary response");
        };
        let imported = H::import(
            context.child("import").with_attribute("index", 2),
            &client_cfg,
            target_b.size - 1,
            pinned_nodes,
            op,
        )
        .await
        .unwrap();
        assert!(H::prune(imported, target_b.size).await.is_err());

        // The dropped imports never touched the journal: state A is still there.
        let reopened = H::init(context.child("reopen"), client_cfg, None).await;
        assert_eq!(H::target(&reopened), target_a);
        H::destroy(reopened).await;
    });
}

/// Instantiates the shared compact sync tests for `$harness` in a module named `$mod_name`.
///
/// The optional `$extra` names a macro that receives `$harness` and emits additional tests
/// into the same module.
macro_rules! compact_sync_tests {
    ($harness:ty, $mod_name:ident $(, $extra:ident)?) => {
        mod $mod_name {
            use super::*;
            use commonware_macros::test_traced;

            #[test_traced("WARN")]
            fn test_compact_full_source_missing_reports_missing_source() {
                crate::qmdb::sync::harness::test_compact_full_source_missing_reports_missing_source::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_roundtrip() {
                crate::qmdb::sync::harness::test_compact_sync_roundtrip::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_invalid_proof() {
                crate::qmdb::sync::harness::test_compact_sync_recovers_after_invalid_proof::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_commit_floor() {
                crate::qmdb::sync::harness::test_compact_sync_recovers_after_tampered_commit_floor::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_size_mismatch() {
                crate::qmdb::sync::harness::test_compact_sync_recovers_after_size_mismatch::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_recovers_after_tampered_pinned_nodes() {
                crate::qmdb::sync::harness::test_compact_sync_recovers_after_tampered_pinned_nodes::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_full_source_serves_historical_target() {
                crate::qmdb::sync::harness::test_compact_full_source_serves_historical_target::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_serves_retained_target() {
                crate::qmdb::sync::harness::test_compact_source_serves_retained_target::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_source_reopen_bounded_initialization_regrow_and_stale_target() {
                crate::qmdb::sync::harness::test_compact_source_reopen_bounded_initialization_regrow_and_stale_target::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_reuses_pruned_partition() {
                crate::qmdb::sync::harness::test_compact_sync_reuses_pruned_partition::<$harness>();
            }

            #[test_traced("WARN")]
            fn test_compact_sync_dropped_import_preserves_existing_state() {
                crate::qmdb::sync::harness::test_compact_sync_dropped_import_preserves_existing_state::<$harness>();
            }

            $( $extra!($harness); )?
        }
    };
}
pub(crate) use compact_sync_tests;
