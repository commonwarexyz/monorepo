//! A keyless authenticated database for fixed-size data.
//!
//! For variable-size values, use [super::variable].

use crate::{
    journal::contiguous::fixed::{self, Config as JournalConfig},
    qmdb::{any::value::FixedEncoding, keyless::operation::Operation as BaseOperation},
};

/// Keyless operation for fixed-size values.
pub type Operation<F, V> = BaseOperation<F, FixedEncoding<V>>;

/// A keyless authenticated database for fixed-size data.
pub type Db<F, E, V, H, S> =
    super::Keyless<F, E, FixedEncoding<V>, fixed::Journal<E, Operation<F, V>>, H, S>;

/// A compact keyless authenticated db for fixed-size data.
pub type CompactDb<F, E, V, H, S> = super::CompactDb<F, E, FixedEncoding<V>, H, (), S>;

/// Configuration for a fixed-size [keyless](super) authenticated db.
pub type Config<S> = super::Config<JournalConfig, S>;

/// Configuration for a fixed-size [keyless](super) compact db.
pub type CompactConfig<S> = super::CompactConfig<(), S>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{Family, Location, mmb, mmr},
        qmdb::{
            Error,
            keyless::tests::{self, keyless_tests},
        },
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::{boxed, test_traced};
    use commonware_parallel::{Rayon, Sequential, Strategy};
    use commonware_runtime::{
        BufferPooler, Metrics as _, Runner as _, Spawner as _, Strategizer as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};
    use core::future::Future;
    use futures::FutureExt as _;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn db_config<S: Strategy>(suffix: &str, pooler: &impl BufferPooler, strategy: S) -> Config<S> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle: crate::merkle::full::Config {
                journal_partition: format!("fixed-journal-{suffix}"),
                metadata_partition: format!("fixed-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("fixed-log-journal-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        }
    }

    type TestDb<F> =
        Db<F, deterministic::Context, commonware_utils::sequence::U64, Sha256, Sequential>;
    type TestRayonDb<F> =
        Db<F, deterministic::Context, commonware_utils::sequence::U64, Sha256, Rayon>;
    type TestCompactDb<F> =
        CompactDb<F, deterministic::Context, commonware_utils::sequence::U64, Sha256, Sequential>;

    async fn open_db<F: Family>(context: deterministic::Context) -> TestDb<F> {
        open_db_with_suffix("partition", context).await
    }

    async fn open_db_with_suffix<F: Family>(
        suffix: &str,
        context: deterministic::Context,
    ) -> TestDb<F> {
        let cfg = db_config(suffix, &context, Sequential);
        TestDb::init(context, cfg, None).await.unwrap()
    }

    async fn open_rayon_db<F: Family>(context: deterministic::Context) -> TestRayonDb<F> {
        let strategy = context.strategy(NZUsize!(2));
        let cfg = db_config("rayon", &context, strategy);
        TestRayonDb::init(context, cfg, None).await.unwrap()
    }

    async fn open_compact<F: crate::merkle::Family>(
        context: deterministic::Context,
    ) -> TestCompactDb<F> {
        let cfg = CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: "compact-keyless-fixed-witness".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: (),
        };
        TestCompactDb::init(context, cfg, None).await.unwrap()
    }

    async fn bounded_standard<F: Family>(context: deterministic::Context) {
        for cap in [0, 1, 2, 3, 4, 6, 7, 8, 12, 13, 14, 100] {
            let cfg = db_config(&format!("caps-{cap}"), &context, Sequential);
            let mut db = TestDb::<F>::init(context.child("create"), cfg.clone(), None)
                .await
                .unwrap();
            let mut commits = vec![(db.bounds().end, db.root())];
            for count in [1, 3, 5] {
                let mut batch = db.new_batch();
                for value in 0..count {
                    batch = batch.append(U64::new(value));
                }
                let batch = batch.merkleize(&db, None, Location::new(0)).await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                commits.push((db.bounds().end, db.root()));
            }
            db = db.sync().await.unwrap();
            let tip = *commits.last().unwrap();
            drop(db);
            let opened =
                TestDb::<F>::init(context.child("cap"), cfg.clone(), Some(Location::new(cap)))
                    .await;
            if cap == 0 {
                assert!(matches!(opened, Err(Error::InvalidInitializationBound)));
                let db = TestDb::<F>::init(context.child("unchanged"), cfg, None)
                    .await
                    .unwrap();
                assert_eq!((db.bounds().end, db.root()), tip);
                continue;
            }
            let expected = *commits
                .iter()
                .rev()
                .find(|(size, _)| **size <= cap)
                .unwrap();
            let db = opened.unwrap();
            assert_eq!((db.bounds().end, db.root()), expected);
            drop(db);
            let mut db = TestDb::<F>::init(context.child("restart"), cfg.clone(), None)
                .await
                .unwrap();
            assert_eq!((db.bounds().end, db.root()), expected);
            let batch = db
                .new_batch()
                .append(U64::new(999))
                .merkleize(&db, None, Location::new(0))
                .await;
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.sync().await.unwrap();
            let appended = (db.bounds().end, db.root());
            drop(db);
            let db = TestDb::<F>::init(context.child("appended"), cfg, None)
                .await
                .unwrap();
            assert_eq!((db.bounds().end, db.root()), appended);
        }
    }
    #[test_traced]
    fn test_standard_bounded_initialization_mmr() {
        deterministic::Runner::default().start(bounded_standard::<mmr::Family>);
    }
    #[test_traced]
    fn test_standard_bounded_initialization_mmb() {
        deterministic::Runner::default().start(bounded_standard::<mmb::Family>);
    }

    async fn bounded_compact<F: Family>(context: deterministic::Context) {
        for cap in [0, 1, 2, 3, 4, 6, 7, 8, 12, 13, 14, 100] {
            let cfg = CompactConfig {
                strategy: Sequential,
                witness: crate::journal::contiguous::variable::Config {
                    partition: format!("caps-{cap}"),
                    items_per_section: NZU64!(3),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
                commit_codec_config: (),
            };
            let mut db = TestCompactDb::<F>::init(context.child("create"), cfg.clone(), None)
                .await
                .unwrap();
            let mut commits = vec![(db.size(), db.root())];
            for count in [1, 3, 5] {
                let mut batch = db.new_batch();
                for value in 0..count {
                    batch = batch.append(U64::new(value));
                }
                let batch = batch.merkleize(&db, None, Location::new(0)).await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                commits.push((db.size(), db.root()));
            }
            db = db.sync().await.unwrap();
            let tip = *commits.last().unwrap();
            drop(db);
            let opened = TestCompactDb::<F>::init(
                context.child("cap"),
                cfg.clone(),
                Some(Location::new(cap)),
            )
            .await;
            if cap == 0 {
                assert!(matches!(opened, Err(Error::InvalidInitializationBound)));
                let db = TestCompactDb::<F>::init(context.child("unchanged"), cfg, None)
                    .await
                    .unwrap();
                assert_eq!((db.size(), db.root()), tip);
                continue;
            }
            let expected = *commits
                .iter()
                .rev()
                .find(|(size, _)| **size <= cap)
                .unwrap();
            let db = opened.unwrap();
            assert_eq!((db.size(), db.root()), expected);
            drop(db);
            let mut db = TestCompactDb::<F>::init(context.child("restart"), cfg.clone(), None)
                .await
                .unwrap();
            assert_eq!((db.size(), db.root()), expected);
            let batch = db
                .new_batch()
                .append(U64::new(999))
                .merkleize(&db, None, Location::new(0))
                .await;
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.sync().await.unwrap();
            let appended = (db.size(), db.root());
            drop(db);
            let db = TestCompactDb::<F>::init(context.child("appended"), cfg, None)
                .await
                .unwrap();
            assert_eq!((db.size(), db.root()), appended);
        }
    }
    #[test_traced]
    fn test_compact_bounded_initialization_mmr() {
        deterministic::Runner::default().start(bounded_compact::<mmr::Family>);
    }
    #[test_traced]
    fn test_compact_bounded_initialization_mmb() {
        deterministic::Runner::default().start(bounded_compact::<mmb::Family>);
    }

    fn bounded_open<F: Family>() -> tests::BoundedOpen<TestDb<F>, F> {
        Box::new(|ctx, cap| {
            Box::pin(async move {
                let cfg = db_config("partition", &ctx, Sequential);
                TestDb::init(ctx, cfg, Some(cap)).await
            })
        })
    }

    fn reopen<F: Family>() -> tests::Reopen<TestDb<F>> {
        Box::new(|ctx| Box::pin(open_db(ctx)))
    }

    /// A keyless db over a delayed-sync storage backend.
    type DelayedDb =
        Db<mmr::Family, DelayedSyncContext<deterministic::Context>, U64, Sha256, Sequential>;

    /// Open a [DelayedDb] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the recovered database, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first). The journal
    /// uses large pages and blobs: an apply that fills the write buffer or rolls the blob over
    /// waits for the in-flight sync, so mid-sync applies must stay clear of both.
    fn open_delayed_db(
        context: &deterministic::Context,
        label: &'static str,
        suffix: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedDb, Error<mmr::Family>>> {
        let mut cfg = db_config(suffix, context, Sequential);
        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        cfg.log.items_per_blob = NZU64!(1000);
        cfg.log.page_cache = page_cache.clone();
        cfg.merkle.items_per_blob = NZU64!(1000);
        cfg.merkle.page_cache = page_cache;
        DelayedDb::init(
            DelayedSyncContext {
                inner: context.child(label),
                pending: pending.clone(),
            },
            cfg,
            None,
        )
    }

    /// Apply a single-append batch with inactivity floor `floor`, returning the appended
    /// value's location.
    async fn apply_append(
        db: DelayedDb,
        value: U64,
        floor: Location<mmr::Family>,
    ) -> (DelayedDb, Location<mmr::Family>) {
        let batch = db
            .new_batch()
            .append(value)
            .merkleize(&db, None, floor)
            .await;
        let (db, range) = db.apply_batch(batch).await.unwrap();
        (db, range.start)
    }

    /// A sync handle must not block database use while the backend sync is pending.
    #[test_traced]
    fn test_keyless_fixed_start_sync_overlaps_work() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "start-sync-overlap", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            let value0 = U64::new(1);
            let loc0;
            let floor = db.inactivity_floor_loc();
            (db, loc0) = apply_append(db, value0.clone(), floor).await;

            let starts_before = pending.starts();
            let entered_before = pending.entered();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);

            // Observe the sync while the database keeps working.
            let waiter = ctx
                .child("await_sync")
                .spawn(|_| async move { handle.await.unwrap() });
            while pending.entered() == entered_before {
                reschedule().await;
            }

            // Reads and applies complete before the sync does.
            assert_eq!(db.get(loc0).await.unwrap(), Some(value0));
            let value1 = U64::new(2);
            let loc1;
            let floor = db.inactivity_floor_loc();
            (db, loc1) = apply_append(db, value1.clone(), floor).await;
            assert_eq!(
                pending.completions(),
                completions_before,
                "the database made progress while the sync was still in flight"
            );

            pending.unblock();
            waiter.await.unwrap();

            // The mid-sync batch is durable after the next start_sync completes.
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", "start-sync-overlap", &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get(loc1).await.unwrap(), Some(value1));
            db.destroy().await.unwrap();
        });
    }

    /// A sync begun by `start_sync` that fails in flight surfaces the error through both the
    /// returned handle and the next durability operation.
    #[test_traced]
    fn test_keyless_fixed_start_sync_failure_propagates() {
        deterministic::Runner::default().start(|ctx| async move {
            // Pass syncs through so opening the database doesn't park.
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "start-sync-fail", &pending)
                .await
                .unwrap();
            let floor = db.inactivity_floor_loc();
            (db, _) = apply_append(db, U64::new(1), floor).await;

            // Arm all future syncs to resolve to an injected error.
            pending.arm_fail();

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );
            let starts_before = pending.starts();
            // A failed mutable method consumes the database per the failures-are-fatal contract.
            assert!(
                db.commit().await.is_err(),
                "the next durability op surfaces the failed in-flight sync"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "the surfaced error is the retained failure, not a fresh sync's"
            );
        });
    }

    /// State persisted via an awaited start_sync handle is recovered on reopen.
    #[test_traced]
    fn test_keyless_fixed_start_sync_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "start-sync-recovery", &pending)
                .await
                .unwrap();
            let value = U64::new(1);
            let loc;
            let floor = db.inactivity_floor_loc();
            (db, loc) = apply_append(db, value.clone(), floor).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", "start-sync-recovery", &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get(loc).await.unwrap(), Some(value));
            db.destroy().await.unwrap();
        });
    }

    /// Pruning drains the in-flight sync before mutating storage.
    #[test_traced]
    fn test_keyless_fixed_start_sync_prune_waits() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "start-sync-prune", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            // Two batches: the second declares floor 2 so the prune below is non-trivial.
            (db, _) = apply_append(db, U64::new(1), Location::new(0)).await;
            (db, _) = apply_append(db, U64::new(2), Location::new(2)).await;

            let starts_before = pending.starts();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);

            let floor = db.inactivity_floor_loc();
            assert!(*floor > 0);
            let db = {
                let mut prune = std::pin::pin!(db.prune(floor));
                assert!(
                    prune.as_mut().now_or_never().is_none(),
                    "prune proceeded while the started sync was pending"
                );
                pending.unblock();
                prune.await.unwrap()
            };
            handle.await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_metrics() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            let value = commonware_utils::sequence::U64::new(7);
            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .append(value.clone())
                .merkleize(&db, None, floor)
                .await;
            let (db, range) = db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(range.start).await.unwrap(), Some(value.clone()));
            assert_eq!(
                db.get_many(&[range.start]).await.unwrap(),
                vec![Some(value)]
            );
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();
            let (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let _db = db.prune(crate::merkle::Location::new(0)).await.unwrap();

            let metrics = ctx.encode();
            for expected in [
                "db_size 3",
                "db_pruning_boundary 0",
                "db_retained 3",
                "db_inactivity_floor 0",
                "db_last_commit 2",
                "db_get_calls_total 1",
                "db_get_many_calls_total 1",
                "db_lookups_requested_total 2",
                "db_apply_batch_calls_total 1",
                "db_operations_applied_total 2",
                "db_commit_calls_total 1",
                "db_sync_calls_total 1",
                "db_start_sync_calls_total 1",
                "db_prune_calls_total 1",
                "db_get_duration_count 1",
                "db_get_many_duration_count 1",
                "db_apply_batch_duration_count 1",
                "db_commit_duration_count 1",
                "db_sync_duration_count 1",
                "db_prune_duration_count 1",
            ] {
                assert!(metrics.contains(expected), "missing {expected}\n{metrics}");
            }
        });
    }

    keyless_tests! {
        test_keyless_fixed_empty => run_empty, reopen_indexed;
        test_keyless_fixed_build_basic => run_build_basic, reopen_indexed;
        test_keyless_fixed_recovery => run_recovery, reopen_indexed;
        test_keyless_fixed_non_empty_recovery => run_non_empty_recovery, reopen_indexed;
        test_keyless_fixed_proof => run_proof, db;
        test_keyless_fixed_proof_comprehensive => run_proof_comprehensive, db;
        test_keyless_fixed_proof_with_pruning => run_proof_with_pruning, reopen_indexed;
        test_keyless_fixed_empty_db_recovery => run_empty_db_recovery, reopen_indexed;
        test_keyless_fixed_replay_with_trailing_appends => run_replay_with_trailing_appends, reopen_indexed;
        test_keyless_fixed_get_out_of_bounds => run_get_out_of_bounds, db;
        test_keyless_fixed_metadata => run_metadata, db;
        test_keyless_fixed_pruning => run_pruning, reopen;
        test_keyless_fixed_batch_get => run_batch_get, db;
        test_keyless_fixed_batch_stacked_get => run_batch_stacked_get, db;
        test_keyless_fixed_batch_speculative_root => run_batch_speculative_root, db;
        test_keyless_fixed_merkleized_batch_get => run_merkleized_batch_get, db;
        test_keyless_fixed_batch_chained => run_batch_chained, db;
        test_keyless_fixed_operations_match_applied_log => run_operations_match_applied_log, db;
        test_keyless_fixed_batch_chained_apply_sequential => run_batch_chained_apply_sequential, db;
        test_keyless_fixed_batch_many_sequential => run_batch_many_sequential, db;
        test_keyless_fixed_batch_empty => run_batch_empty, db;
        test_keyless_fixed_batch_chained_merkleized_get => run_batch_chained_merkleized_get, db;
        test_keyless_fixed_batch_large => run_batch_large, db;
        test_keyless_fixed_stale_batch => run_stale_batch, reopen;
        test_keyless_fixed_stale_batch_chained => run_stale_batch_chained, db;
        test_keyless_fixed_sequential_commit_parent_then_child => run_sequential_commit_parent_then_child, db;
        test_keyless_fixed_stale_batch_child_before_parent => run_stale_batch_child_before_parent, db;
        test_keyless_fixed_to_batch => run_to_batch, db;
        test_keyless_fixed_child_root_matches_pending_and_committed => run_child_root_matches_pending_and_committed, db;
        test_keyless_fixed_bounded_initialization_recovery => run_bounded_initialization_recovery, bounded;
        test_keyless_fixed_bounded_initialization_pruned_target_errors =>
            run_bounded_initialization_pruned_target_errors, bounded;
        test_keyless_fixed_floor_tracking => run_floor_tracking, reopen_indexed;
        test_keyless_fixed_floor_regression_rejected => run_floor_regression_rejected, reopen;
        test_keyless_fixed_floor_beyond_commit_loc_rejected => run_floor_beyond_commit_loc_rejected, reopen;
        test_keyless_fixed_bounded_initialization_restores_floor =>
            run_bounded_initialization_restores_floor, bounded_floor;
        test_keyless_fixed_floor_at_commit_loc_accepted => run_floor_at_commit_loc_accepted, db;
        test_keyless_fixed_bounded_initialization_after_reopen_with_floor =>
            run_bounded_initialization_after_reopen_with_floor, bounded_indexed;
        test_keyless_fixed_ancestor_floor_regression_rejected => run_ancestor_floor_regression_rejected, reopen;
        test_keyless_fixed_ancestor_floor_beyond_commit_loc_rejected => run_ancestor_floor_beyond_commit_loc_rejected, db;
        test_keyless_fixed_chained_apply_with_valid_floors_succeeds => run_chained_apply_with_valid_floors_succeeds, db;
        test_keyless_fixed_single_commit_live_set => run_single_commit_live_set, reopen_indexed;
        test_keyless_fixed_commit_after_sync_recovery => run_commit_after_sync_recovery, reopen_indexed;
        test_keyless_fixed_get_many => run_get_many, db;
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_shared_helper_accepts_rayon_strategy() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_rayon_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::run_metadata(db).await;
        });
    }

    #[boxed]
    async fn assert_compact_root_compatibility<F: crate::merkle::Family>(
        ctx: deterministic::Context,
    ) {
        let db = open_db::<F>(ctx.child("db")).await;
        let compact = open_compact::<F>(ctx.child("compact")).await;
        assert_eq!(db.root(), compact.root());

        let v1 = commonware_utils::sequence::U64::new(1);
        let v2 = commonware_utils::sequence::U64::new(2);
        let metadata = commonware_utils::sequence::U64::new(99);

        let floor = db.inactivity_floor_loc();
        let retained = db
            .new_batch()
            .append(v1.clone())
            .append(v2.clone())
            .merkleize(&db, Some(metadata.clone()), floor)
            .await;
        let compact_batch = compact
            .new_batch()
            .append(v1)
            .append(v2)
            .merkleize(&compact, Some(metadata.clone()), floor)
            .await;

        assert_eq!(retained.root(), compact_batch.root());

        let (db, _) = db.apply_batch(retained).await.unwrap();
        let (compact, _) = compact.apply_batch(compact_batch).await.unwrap();
        let db = db.commit().await.unwrap();
        let compact = compact.sync().await.unwrap();

        assert_eq!(db.root(), compact.root());
        assert_eq!(compact.get_metadata(), Some(metadata.clone()));

        drop(compact);
        let reopened = open_compact::<F>(ctx.child("reopen")).await;
        assert_eq!(db.root(), reopened.root());
        assert_eq!(reopened.get_metadata(), Some(metadata));

        reopened.destroy().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_compact_root_compatibility() {
        deterministic::Runner::default().start(|ctx| async move {
            assert_compact_root_compatibility::<mmr::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_compact_root_compatibility_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            assert_compact_root_compatibility::<mmb::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_floor_changes_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmr::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmr::Family>("root-b", ctx.child("b")).await;
            tests::run_floor_changes_root(db_a, db_b).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_floor_changes_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmb::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmb::Family>("root-b", ctx.child("b")).await;
            tests::run_floor_changes_root(db_a, db_b).await;
        });
    }

    /// Smoke test: verify the sync engine works end-to-end with a fixed-size keyless database.
    /// The full sync test suite runs against the variable variant via the harness in
    /// [`super::super::sync::tests`]; this test covers the fixed-size code path.
    #[test_traced("WARN")]
    fn test_keyless_fixed_sync() {
        use crate::{
            merkle::Location,
            qmdb::sync::{self, Target, engine::Config},
        };
        use commonware_utils::{non_empty_range, sequence::U64};
        use std::sync::Arc;

        deterministic::Runner::default().start(|ctx| async move {
            let target_config = db_config("sync-target", &ctx, Sequential);
            let target_db: TestDb<mmr::Family> =
                TestDb::init(ctx.child("target"), target_config, None)
                    .await
                    .unwrap();

            let mut batch = target_db.new_batch();
            for i in 0..20u64 {
                batch = batch.append(U64::new(i * 10 + 1));
            }
            let floor = target_db.inactivity_floor_loc();
            let merkleized = batch.merkleize(&target_db, None, floor).await;
            let (target_db, _) = target_db.apply_batch(merkleized).await.unwrap();

            let target_root = target_db.root();
            let bounds = target_db.bounds();
            let lower_bound = bounds.start;
            let upper_bound = bounds.end;

            let client_config = db_config("sync-client", &ctx, Sequential);
            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: client_config,
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    range: non_empty_range!(lower_bound, upper_bound),
                },
                context: ctx.child("client"),
                source: target_db.clone(),
                apply_batch_size: NZU64!(1024),
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let synced_db: TestDb<mmr::Family> = sync::sync(config).await.unwrap();

            assert_eq!(synced_db.root(), target_root);
            let bounds = synced_db.bounds();
            assert_eq!(bounds.end, upper_bound);
            assert_eq!(bounds.start, lower_bound);

            for i in 0..20u64 {
                let got = synced_db.get(Location::new(i + 1)).await.unwrap();
                assert_eq!(got, Some(U64::new(i * 10 + 1)));
            }

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }
}
