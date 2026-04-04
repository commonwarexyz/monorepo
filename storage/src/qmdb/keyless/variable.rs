//! A keyless authenticated database for variable-length data.
//!
//! For fixed-size values, use [super::fixed].

use crate::{
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        any::value::{VariableEncoding, VariableValue},
        keyless::operation::Operation as BaseOperation,
        operation::Committable,
        Error,
    },
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

/// Keyless operation for variable-length values.
pub type Operation<V> = BaseOperation<VariableEncoding<V>>;

/// A keyless authenticated database for variable-length data.
pub type Db<F, E, V, H> =
    super::Keyless<F, E, VariableEncoding<V>, variable::Journal<E, Operation<V>>, H>;

type Journal<F, E, V, H> = authenticated::Journal<F, E, variable::Journal<E, Operation<V>>, H>;

/// Configuration for a variable-size [keyless](super) authenticated db.
pub type Config<C> = super::Config<JournalConfig<C>>;

impl<F: Family, E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Db<F, E, V, H> {
    /// Returns a [Db] initialized from `cfg`. Any uncommitted operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<<Operation<V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, V, H> =
            Journal::new(context, cfg.merkle, cfg.log, Operation::<V>::is_commit).await?;
        Self::init_from_journal(journal).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        merkle::{mmb, mmr},
        qmdb::keyless::tests,
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn db_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle: crate::merkle::journaled::Config {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    type TestDb<F> = Db<F, deterministic::Context, Vec<u8>, Sha256>;

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db<F: crate::merkle::Family>(context: deterministic::Context) -> TestDb<F> {
        let cfg = db_config("partition", &context);
        TestDb::init(context, cfg).await.unwrap()
    }

    fn reopen<F: crate::merkle::Family>() -> tests::Reopen<TestDb<F>> {
        Box::new(|ctx| Box::pin(open_db(ctx)))
    }

    #[test_traced("INFO")]
    fn test_keyless_db_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_build_basic() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_comprehensive() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_with_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmr::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_get_out_of_bounds() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_metadata() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_stale_changeset() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset(db).await;
        });
    }

    #[test_traced]
    fn test_stale_changeset_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset_chained(db).await;
        });
    }

    #[test_traced]
    fn test_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_stale_partial_ancestor_commit() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_partial_ancestor_commit(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_to_batch() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_child_root_matches_pending_and_committed() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_pruned_target_errors() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }

    // mmb::Family variants

    #[test_traced("INFO")]
    fn test_keyless_db_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_build_basic_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_comprehensive_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_with_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmb::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_get_out_of_bounds_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_metadata_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_stale_changeset_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset(db).await;
        });
    }

    #[test_traced]
    fn test_stale_changeset_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset_chained(db).await;
        });
    }

    #[test_traced]
    fn test_sequential_commit_parent_then_child_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_changeset_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_to_batch_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_child_root_matches_pending_and_committed_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_pruned_target_errors_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send(
        db: &mut TestDb<mmr::Family>,
        loc: crate::merkle::Location<mmr::Family>,
    ) {
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.sync());
        is_send(db.get(loc));
        is_send(db.rewind(loc));
    }
}
