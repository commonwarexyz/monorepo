//! A keyless authenticated database for variable-length data.
//!
//! For fixed-size values, use [super::fixed].

use crate::{
    Context,
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        Error, ROOT_BAGGING,
        any::value::{VariableEncoding, VariableValue},
        keyless::operation::Operation as BaseOperation,
        operation::Committable,
    },
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

/// Keyless operation for variable-length values.
pub type Operation<F, V> = BaseOperation<F, VariableEncoding<V>>;

/// A keyless authenticated database for variable-length data.
pub type Db<F, E, V, H, S> =
    super::Keyless<F, E, VariableEncoding<V>, variable::Journal<E, Operation<F, V>>, H, S>;

/// A compact keyless authenticated db for variable-length data.
pub type CompactDb<F, E, V, H, C, S> = super::CompactDb<F, E, VariableEncoding<V>, H, C, S>;

type Journal<F, E, V, H, S> =
    authenticated::Journal<F, E, variable::Journal<E, Operation<F, V>>, H, S>;

/// Configuration for a variable-size [keyless](super) authenticated db.
pub type Config<C, S> = super::Config<JournalConfig<C>, S>;

/// Configuration for a variable-size [keyless](super) compact db.
pub type CompactConfig<C, S> = super::CompactConfig<C, S>;

impl<F: Family, E: Context, V: VariableValue, H: Hasher, S: Strategy> Db<F, E, V, H, S> {
    /// Returns a [Db] initialized from `cfg`. Any uncommitted operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<<Operation<F, V> as Read>::Cfg, S>,
    ) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, V, H, S> = Journal::new(
            context.child("journal"),
            cfg.merkle,
            cfg.log,
            Operation::<F, V>::is_commit,
            ROOT_BAGGING,
        )
        .await?;
        Self::init_from_journal(journal, context).await
    }
}

impl<
    F: Family,
    E: Context,
    V: VariableValue,
    H: Hasher,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
> CompactDb<F, E, V, H, C, S>
where
    Operation<F, V>: Read<Cfg = C>,
{
    /// Returns a [CompactDb] initialized from `cfg`.
    pub async fn init(context: E, cfg: CompactConfig<C, S>) -> Result<Self, Error<F>> {
        let merkle = crate::merkle::compact::Merkle::new(cfg.strategy);
        Self::init_from_merkle(
            merkle,
            context.child("witness"),
            cfg.witness,
            cfg.commit_codec_config,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{mmb, mmr},
        qmdb::keyless::tests::{self, keyless_tests},
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::{boxed, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::{NonZeroU16, NonZeroUsize};

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn db_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> Config<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle: crate::merkle::full::Config {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
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

    type TestDb<F> = Db<F, deterministic::Context, Vec<u8>, Sha256, Sequential>;
    type TestCompactDb<F> = CompactDb<
        F,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db<F: Family>(context: deterministic::Context) -> TestDb<F> {
        open_db_with_suffix("partition", context).await
    }

    async fn open_db_with_suffix<F: Family>(
        suffix: &str,
        context: deterministic::Context,
    ) -> TestDb<F> {
        let cfg = db_config(suffix, &context);
        TestDb::init(context, cfg).await.unwrap()
    }

    async fn open_compact<F: crate::merkle::Family>(
        context: deterministic::Context,
    ) -> TestCompactDb<F> {
        let cfg = CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: "compact-keyless-variable-witness".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: ((0..=10000usize).into(), ()),
        };
        TestCompactDb::init(context, cfg).await.unwrap()
    }

    fn reopen<F: Family>() -> tests::Reopen<TestDb<F>> {
        Box::new(|ctx| Box::pin(open_db(ctx)))
    }

    keyless_tests! {
        test_keyless_variable_empty => run_empty, reopen_indexed;
        test_keyless_variable_build_basic => run_build_basic, reopen_indexed;
        test_keyless_variable_recovery => run_recovery, reopen_indexed;
        test_keyless_variable_non_empty_recovery => run_non_empty_recovery, reopen_indexed;
        test_keyless_variable_proof => run_proof, db;
        test_keyless_variable_proof_comprehensive => run_proof_comprehensive, db;
        test_keyless_variable_proof_with_pruning => run_proof_with_pruning, reopen_indexed;
        test_keyless_variable_empty_db_recovery => run_empty_db_recovery, reopen_indexed;
        test_keyless_variable_replay_with_trailing_appends => run_replay_with_trailing_appends, reopen_indexed;
        test_keyless_variable_get_out_of_bounds => run_get_out_of_bounds, db;
        test_keyless_variable_metadata => run_metadata, db;
        test_keyless_variable_pruning => run_pruning, reopen;
        test_keyless_variable_batch_get => run_batch_get, db;
        test_keyless_variable_batch_stacked_get => run_batch_stacked_get, db;
        test_keyless_variable_batch_speculative_root => run_batch_speculative_root, db;
        test_keyless_variable_merkleized_batch_get => run_merkleized_batch_get, db;
        test_keyless_variable_batch_chained => run_batch_chained, db;
        test_keyless_variable_operations_match_applied_log => run_operations_match_applied_log, db;
        test_keyless_variable_batch_chained_apply_sequential => run_batch_chained_apply_sequential, db;
        test_keyless_variable_batch_many_sequential => run_batch_many_sequential, db;
        test_keyless_variable_batch_empty => run_batch_empty, db;
        test_keyless_variable_batch_chained_merkleized_get => run_batch_chained_merkleized_get, db;
        test_keyless_variable_batch_large => run_batch_large, db;
        test_keyless_variable_stale_batch => run_stale_batch, reopen;
        test_keyless_variable_stale_batch_chained => run_stale_batch_chained, db;
        test_keyless_variable_sequential_commit_parent_then_child => run_sequential_commit_parent_then_child, db;
        test_keyless_variable_stale_batch_child_before_parent => run_stale_batch_child_before_parent, db;
        test_keyless_variable_to_batch => run_to_batch, db;
        test_keyless_variable_child_root_matches_pending_and_committed => run_child_root_matches_pending_and_committed, db;
        test_keyless_variable_rewind_recovery => run_rewind_recovery, reopen;
        test_keyless_variable_rewind_pruned_target_errors => run_rewind_pruned_target_errors, reopen;
        test_keyless_variable_floor_tracking => run_floor_tracking, reopen_indexed;
        test_keyless_variable_floor_regression_rejected => run_floor_regression_rejected, reopen;
        test_keyless_variable_floor_beyond_commit_loc_rejected => run_floor_beyond_commit_loc_rejected, reopen;
        test_keyless_variable_rewind_restores_floor => run_rewind_restores_floor, db;
        test_keyless_variable_floor_at_commit_loc_accepted => run_floor_at_commit_loc_accepted, db;
        test_keyless_variable_rewind_after_reopen_with_floor => run_rewind_after_reopen_with_floor, reopen_indexed;
        test_keyless_variable_ancestor_floor_regression_rejected => run_ancestor_floor_regression_rejected, reopen;
        test_keyless_variable_ancestor_floor_beyond_commit_loc_rejected => run_ancestor_floor_beyond_commit_loc_rejected, db;
        test_keyless_variable_chained_apply_with_valid_floors_succeeds => run_chained_apply_with_valid_floors_succeeds, db;
        test_keyless_variable_single_commit_live_set => run_single_commit_live_set, reopen_indexed;
        test_keyless_variable_commit_after_sync_recovery => run_commit_after_sync_recovery, reopen_indexed;
        test_keyless_variable_get_many => run_get_many, db;
        test_keyless_variable_partial_ancestor_commit => run_partial_ancestor_commit, db;
        test_keyless_variable_delayed_merkleize_after_ancestor_apply => run_delayed_merkleize_after_ancestor_apply, db;
    }

    /// Regression: when pruning leaves `bounds.start` mid-blob ahead of the first retained commit,
    /// `historical_proof` for sizes in that leading interval must report `HistoricalFloorPruned`
    /// (the floor metadata is gone) rather than the misleading `UnexpectedData` (which sounds like
    /// data corruption).
    ///
    /// Items_per_section=7 with batches of 3 appends + 1 commit places commits at locations 0, 4,
    /// 8, 12, .... Pruning to loc=8 removes blob 0 (end=7 <=
    /// 8) and retains blob 1 ([7, 14)). `bounds.start = 7` is a non-commit op (an Append), and the
    /// previous commit at location 4 was pruned. `historical_proof(op_count=8, ...)` asks for the
    /// state just before the first retained commit, which has no retained governing floor.
    #[test_traced("INFO")]
    fn test_keyless_variable_historical_proof_floor_pruned() {
        use crate::merkle::Location;
        deterministic::Runner::default().start(|ctx| async move {
            let mut db = open_db::<mmr::Family>(ctx.child("db")).await;

            // Build commits at 0, 4, 8, 12, ... (3 appends + 1 commit per batch).
            for batch_idx in 0u64..15 {
                let mut batch = db.new_batch();
                for j in 0..3 {
                    batch =
                        batch.append(<Vec<u8> as crate::qmdb::keyless::tests::TestValue>::make(
                            batch_idx * 10 + j,
                        ));
                }
                let new_commit_loc = db.last_commit_loc() + 1 + 3;
                let merkleized = batch.merkleize(&db, None, new_commit_loc).await;
                (db, _) = db.apply_batch(merkleized).await.unwrap();
            }

            // Prune to loc=8: blob 0 ([0,7)) end=7 <= 8 -> pruned. bounds.start = 7, first retained
            // commit is at 8.
            let db = db.prune(Location::new(8)).await.unwrap();
            let bounds = db.bounds();
            assert_eq!(*bounds.start, 7);

            // op_count = first retained commit (= state just before that commit). Expected:
            // HistoricalFloorPruned, NOT UnexpectedData.
            let result = db
                .historical_proof(Location::new(8), bounds.start, NZU64!(5))
                .await;
            assert!(
                !matches!(result, Err(Error::UnexpectedData(_))),
                "must not surface as UnexpectedData; got {result:?}",
            );
            assert!(
                matches!(result, Err(Error::HistoricalFloorPruned(loc)) if loc == Location::new(8)),
                "expected HistoricalFloorPruned(8), got {result:?}",
            );

            // Sanity: a commit-boundary size whose floor is retained still works. First retained
            // commit at 8 declares some floor; op_count=9 is the post-commit size whose governing
            // floor is the one declared at op 8.
            db.historical_proof(Location::new(9), Location::new(8), NZU64!(1))
                .await
                .expect("commit-boundary historical_proof should succeed");

            db.destroy().await.unwrap();
        });
    }

    #[boxed]
    async fn assert_compact_root_compatibility<F: crate::merkle::Family>(
        ctx: deterministic::Context,
    ) {
        let db = open_db::<F>(ctx.child("db")).await;
        let compact = open_compact::<F>(ctx.child("compact")).await;
        assert_eq!(db.root(), compact.root());

        let v1 = b"hello".to_vec();
        let v2 = b"world".to_vec();
        let metadata = b"metadata".to_vec();

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
    fn test_keyless_variable_compact_root_compatibility() {
        deterministic::Runner::default().start(|ctx| async move {
            assert_compact_root_compatibility::<mmr::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_compact_root_compatibility_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            assert_compact_root_compatibility::<mmb::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_changes_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmb::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmb::Family>("root-b", ctx.child("b")).await;
            tests::run_floor_changes_root(db_a, db_b).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_changes_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmr::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmr::Family>("root-b", ctx.child("b")).await;
            tests::run_floor_changes_root(db_a, db_b).await;
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send(
        db: TestDb<mmr::Family>,
        loc: crate::merkle::Location<mmr::Family>,
    ) {
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.get(loc));
        is_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_rewind_is_send(db: TestDb<mmr::Family>, loc: crate::merkle::Location<mmr::Family>) {
        is_send(db.rewind(loc));
    }
}
