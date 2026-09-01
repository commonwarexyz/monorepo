//! An immutable authenticated database with fixed-size values.
//!
//! For variable-size values, use [super::variable] instead.

use super::{Config as BaseConfig, Immutable, operation::Operation as BaseOperation};
use crate::{
    Context,
    journal::{
        authenticated,
        contiguous::fixed::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        Error, ROOT_BAGGING,
        any::{FixedValue, value::FixedEncoding},
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::Array;

/// Type alias for a fixed-size operation.
pub type Operation<F, K, V> = BaseOperation<F, K, FixedEncoding<V>>;

/// Type alias for the fixed-size immutable database.
pub type Db<F, E, K, V, H, T, S> =
    Immutable<F, E, K, FixedEncoding<V>, fixed::Journal<E, Operation<F, K, V>>, H, T, S>;

/// Type alias for the fixed-size compact immutable db.
pub type CompactDb<F, E, K, V, H, S> = super::CompactDb<F, E, K, FixedEncoding<V>, H, (), S>;

type Journal<F, E, K, V, H, S> =
    authenticated::Journal<F, E, fixed::Journal<E, Operation<F, K, V>>, H, S>;

/// Configuration for a fixed-size immutable authenticated db.
pub type Config<T, S> = BaseConfig<T, JournalConfig, S>;

/// Configuration for a fixed-size compact immutable db.
pub type CompactConfig<S> = super::CompactConfig<(), S>;

impl<F: Family, E: Context, K: Array, V: FixedValue, H: Hasher, T: Translator, S: Strategy>
    Db<F, E, K, V, H, T, S>
{
    /// Returns a [Db] initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T, S>) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, K, V, H, S> = Journal::new(
            context.child("journal"),
            cfg.merkle_config,
            cfg.log,
            Operation::<F, K, V>::is_commit,
            ROOT_BAGGING,
        )
        .await?;
        Self::init_from_journal(
            journal,
            context,
            cfg.translator,
            cfg.init_buffer,
            cfg.init_cache_size,
        )
        .await
    }
}

impl<F: Family, E: Context, K: Array, V: FixedValue, H: Hasher, S: Strategy>
    CompactDb<F, E, K, V, H, S>
{
    /// Returns a [CompactDb] initialized from `cfg`.
    pub async fn init(context: E, cfg: CompactConfig<S>) -> Result<Self, Error<F>> {
        let merkle = crate::merkle::compact::Merkle::new(cfg.strategy);
        Self::init_from_merkle(merkle, context.child("witness"), cfg.witness, ()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{Location, full::Config as MmrConfig, mmb, mmr},
        qmdb::immutable::tests::{self, immutable_tests},
        translator::TwoCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::{boxed, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Metrics, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use core::{future::Future, pin::Pin};
    use futures::FutureExt as _;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn config(suffix: &str, pooler: &impl BufferPooler) -> Config<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle_config: MmrConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                items_per_blob: NZU64!(5),
                partition: format!("log-{suffix}"),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        }
    }

    async fn open_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential> {
        let cfg = config("partition", &context);
        Db::init(context, cfg).await.unwrap()
    }

    async fn open_compact<F: Family>(
        context: deterministic::Context,
    ) -> CompactDb<F, deterministic::Context, Digest, Digest, Sha256, Sequential> {
        let cfg = CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: "compact-immutable-fixed-witness".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: (),
        };
        CompactDb::init(context, cfg).await.unwrap()
    }

    /// An immutable db over a delayed-sync storage backend.
    type DelayedDb = Db<
        mmr::Family,
        DelayedSyncContext<deterministic::Context>,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

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
        let mut cfg = config(suffix, context);
        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        cfg.log.items_per_blob = NZU64!(1000);
        cfg.log.page_cache = page_cache.clone();
        cfg.merkle_config.items_per_blob = NZU64!(1000);
        cfg.merkle_config.page_cache = page_cache;
        DelayedDb::init(
            DelayedSyncContext {
                inner: context.child(label),
                pending: pending.clone(),
            },
            cfg,
        )
    }

    /// Apply a single-key batch writing `key -> value` with inactivity floor `floor`.
    async fn apply_set(
        db: DelayedDb,
        key: Digest,
        value: Digest,
        floor: Location<mmr::Family>,
    ) -> DelayedDb {
        let batch = db
            .new_batch()
            .set(key, value)
            .merkleize(&db, None, floor)
            .await;
        let (db, _) = db.apply_batch(batch).await.unwrap();
        db
    }

    /// A sync handle must not block database use while the backend sync is pending.
    #[test_traced]
    fn test_fixed_start_sync_overlaps_work() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "start-sync-overlap", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            let key0 = Sha256::fill(1u8);
            let value0 = Sha256::fill(2u8);
            let floor = db.inactivity_floor_loc();
            db = apply_set(db, key0, value0, floor).await;

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
            assert_eq!(db.get(&key0).await.unwrap(), Some(value0));
            let key1 = Sha256::fill(3u8);
            let value1 = Sha256::fill(4u8);
            let floor = db.inactivity_floor_loc();
            db = apply_set(db, key1, value1, floor).await;
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
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
            db.destroy().await.unwrap();
        });
    }

    /// A sync begun by `start_sync` that fails in flight surfaces the error through both the
    /// returned handle and the next durability operation.
    #[test_traced]
    fn test_fixed_start_sync_failure_propagates() {
        deterministic::Runner::default().start(|ctx| async move {
            // Pass syncs through so opening the database doesn't park.
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "start-sync-fail", &pending)
                .await
                .unwrap();
            let floor = db.inactivity_floor_loc();
            db = apply_set(db, Sha256::fill(1u8), Sha256::fill(2u8), floor).await;

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
    fn test_fixed_start_sync_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "start-sync-recovery", &pending)
                .await
                .unwrap();
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let floor = db.inactivity_floor_loc();
            db = apply_set(db, key, value, floor).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", "start-sync-recovery", &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            db.destroy().await.unwrap();
        });
    }

    /// Pruning drains the in-flight sync before mutating storage.
    #[test_traced]
    fn test_fixed_start_sync_prune_waits() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "start-sync-prune", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            // Two batches: the second declares floor 2 so the prune below is non-trivial.
            db = apply_set(db, Sha256::fill(1u8), Sha256::fill(2u8), Location::new(0)).await;
            db = apply_set(db, Sha256::fill(3u8), Sha256::fill(4u8), Location::new(2)).await;

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

    /// Rewinding drains the in-flight sync before mutating storage.
    #[test_traced]
    fn test_fixed_start_sync_rewind_waits() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "start-sync-rewind", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_set(db, Sha256::fill(1u8), Sha256::fill(2u8), Location::new(0)).await;
            db = drive_pending_syncs(&pending, db.commit()).await.unwrap();
            let committed_root = db.root();
            let committed_size = db.bounds().end;
            db = apply_set(db, Sha256::fill(3u8), Sha256::fill(4u8), Location::new(0)).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();

            let db = {
                let mut rewind = std::pin::pin!(db.rewind(committed_size));
                assert!(
                    rewind.as_mut().now_or_never().is_none(),
                    "rewind proceeded while the started sync was pending"
                );
                pending.unblock();
                rewind.await.unwrap()
            };
            handle.await.unwrap();
            assert_eq!(db.root(), committed_root);
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_metrics() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(key, value)
                .merkleize(&db, None, floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            assert_eq!(db.get_many(&[&key]).await.unwrap(), vec![Some(value)]);
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

    #[allow(clippy::type_complexity)]
    fn open<F: Family>(
        ctx: deterministic::Context,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Db<
                        F,
                        deterministic::Context,
                        Digest,
                        Digest,
                        Sha256,
                        TwoCap,
                        Sequential,
                    >,
                > + Send,
        >,
    > {
        Box::pin(open_db::<F>(ctx))
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send(
        db: Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>,
        key: Digest,
        loc: crate::merkle::mmr::Location,
    ) {
        is_send(db.get(&key));
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_rewind_is_send(
        db: Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>,
        loc: crate::merkle::mmr::Location,
    ) {
        is_send(db.rewind(loc));
    }

    fn small_sections_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> Config<TwoCap, Sequential> {
        let mut cfg = config(suffix, pooler);
        cfg.log.items_per_blob = NZU64!(1);
        cfg
    }

    async fn open_small_sections_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential> {
        let cfg = small_sections_config("partition", &context);
        Db::init(context, cfg).await.unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn open_small_sections<F: Family>(
        ctx: deterministic::Context,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Db<
                        F,
                        deterministic::Context,
                        Digest,
                        Digest,
                        Sha256,
                        TwoCap,
                        Sequential,
                    >,
                > + Send,
        >,
    > {
        Box::pin(open_small_sections_db::<F>(ctx))
    }

    immutable_tests! {
        test_fixed_empty => run_empty, open;
        test_fixed_build_basic => run_build_basic, open;
        test_fixed_proof_verify => run_proof_verify, open;
        test_fixed_prune => run_prune, open;
        test_fixed_batch_chain => run_batch_chain, open;
        test_fixed_operations_match_applied_log => run_operations_match_applied_log, open;
        test_fixed_build_and_authenticate => run_build_and_authenticate, open;
        test_fixed_recovery_from_failed_merkle_sync => run_recovery_from_failed_merkle_sync, open;
        test_fixed_recovery_from_failed_log_sync => run_recovery_from_failed_log_sync, open;
        test_fixed_pruning => run_pruning, open;
        test_fixed_prune_beyond_floor => run_prune_beyond_floor, open;
        test_fixed_batch_get_read_through => run_batch_get_read_through, open;
        test_fixed_batch_stacked_get => run_batch_stacked_get, open;
        test_fixed_batch_stacked_apply => run_batch_stacked_apply, open;
        test_fixed_batch_speculative_root => run_batch_speculative_root, open;
        test_fixed_merkleized_batch_get => run_merkleized_batch_get, open;
        test_fixed_batch_sequential_apply => run_batch_sequential_apply, open;
        test_fixed_batch_many_sequential => run_batch_many_sequential, open;
        test_fixed_batch_empty_batch => run_batch_empty_batch, open;
        test_fixed_batch_chained_merkleized_get => run_batch_chained_merkleized_get, open;
        test_fixed_batch_large => run_batch_large, open;
        test_fixed_batch_chained_key_override => run_batch_chained_key_override, open;
        test_fixed_batch_sequential_key_override => run_batch_sequential_key_override, open_small_sections;
        test_fixed_batch_metadata => run_batch_metadata, open;
        test_fixed_stale_batch_rejected => run_stale_batch_rejected, open;
        test_fixed_stale_batch_chained => run_stale_batch_chained, open;
        test_fixed_sequential_commit_parent_then_child => run_sequential_commit_parent_then_child, open;
        test_fixed_stale_batch_child_applied_before_parent => run_stale_batch_child_applied_before_parent, open;
        test_fixed_child_root_matches_pending_and_committed => run_child_root_matches_pending_and_committed, open;
        test_fixed_to_batch => run_to_batch, open;
        test_fixed_rewind_recovery => run_rewind_recovery, open;
        test_fixed_rewind_pruned_target_errors => run_rewind_pruned_target_errors, open_small_sections;
        test_fixed_inactivity_floor_tracking => run_inactivity_floor_tracking, open;
        test_fixed_floor_monotonicity => run_floor_monotonicity, open;
        test_fixed_floor_monotonicity_violation => run_floor_monotonicity_violation, open;
        test_fixed_floor_beyond_size => run_floor_beyond_size, open;
        test_fixed_chained_ancestor_floor_regression => run_chained_ancestor_floor_regression, open;
        test_fixed_chained_ancestor_floor_beyond_size => run_chained_ancestor_floor_beyond_size, open;
        test_fixed_rewind_restores_floor => run_rewind_restores_floor, open;
        test_fixed_single_commit_live_set => run_single_commit_live_set, open;
        test_fixed_rewind_after_reopen_with_floor_change => run_rewind_after_reopen_with_floor_change, open;
        test_fixed_rewind_after_reopen_partial_floor_gap => run_rewind_after_reopen_partial_floor_gap, open;
        test_fixed_commit_after_sync_recovery => run_commit_after_sync_recovery, open;
        test_fixed_prune_after_uncommitted_apply_batch_recovery => run_prune_after_uncommitted_apply_batch_recovery, open;
        test_fixed_rewind_preserves_collision_bucket => run_rewind_preserves_collision_bucket, open;
        test_fixed_get_many => run_get_many, open;
        test_fixed_get_many_unexpected_data => run_get_many_unexpected_data, open;
        test_fixed_rewind_after_reopen_repeated_key_gap => run_rewind_after_reopen_repeated_key_gap, open;
        test_fixed_rewind_after_reopen_mixed_gap_retained => run_rewind_after_reopen_mixed_gap_retained, open;
    }

    #[boxed]
    async fn assert_compact_root_compatibility<F: Family>(ctx: deterministic::Context) {
        let db = open_db::<F>(ctx.child("db")).await;
        let compact = open_compact::<F>(ctx.child("compact")).await;
        assert_eq!(db.root(), compact.root());

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(11u8);
        let k2 = Sha256::fill(2u8);
        let v2 = Sha256::fill(22u8);
        let metadata = Sha256::fill(99u8);

        let floor = db.inactivity_floor_loc();
        let retained = db
            .new_batch()
            .set(k1, v1)
            .set(k2, v2)
            .merkleize(&db, Some(metadata), floor)
            .await;
        let compact_batch = compact
            .new_batch()
            .set(k1, v1)
            .set(k2, v2)
            .merkleize(&compact, Some(metadata), floor)
            .await;

        assert_eq!(retained.root(), compact_batch.root());

        let (db, _) = db.apply_batch(retained).await.unwrap();
        let (compact, _) = compact.apply_batch(compact_batch).await.unwrap();
        let db = db.commit().await.unwrap();
        let compact = compact.sync().await.unwrap();

        assert_eq!(db.root(), compact.root());
        assert_eq!(compact.get_metadata(), Some(metadata));

        drop(compact);
        let reopened = open_compact::<F>(ctx.child("reopen")).await;
        assert_eq!(db.root(), reopened.root());
        assert_eq!(reopened.get_metadata(), Some(metadata));

        reopened.destroy().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_fixed_compact_root_compatibility() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            assert_compact_root_compatibility::<mmr::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_compact_root_compatibility_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            assert_compact_root_compatibility::<mmb::Family>(ctx).await;
        });
    }
}
