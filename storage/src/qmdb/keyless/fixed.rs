//! A keyless authenticated database for fixed-size data.
//!
//! For variable-size values, use [super::variable].

use crate::{
    journal::{
        authenticated,
        contiguous::fixed::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        any::value::{FixedEncoding, FixedValue},
        keyless::operation::Operation as BaseOperation,
        operation::Committable,
        Error,
    },
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

/// Keyless operation for fixed-size values.
pub type Operation<V> = BaseOperation<FixedEncoding<V>>;

/// A keyless authenticated database for fixed-size data.
pub type Db<F, E, V, H> =
    super::Keyless<F, E, FixedEncoding<V>, fixed::Journal<E, Operation<V>>, H>;

type Journal<F, E, V, H> = authenticated::Journal<F, E, fixed::Journal<E, Operation<V>>, H>;

/// Configuration for a fixed-size [keyless](super) authenticated db.
pub type Config = super::Config<JournalConfig>;

impl<F: Family, E: Storage + Clock + Metrics, V: FixedValue, H: Hasher> Db<F, E, V, H> {
    /// Returns a [Db] initialized from `cfg`. Any uncommitted operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error<F>> {
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
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn db_config(suffix: &str, page_cache: CacheRef) -> Config {
        Config {
            merkle: crate::merkle::journaled::Config {
                journal_partition: format!("fixed-journal-{suffix}"),
                metadata_partition: format!("fixed-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("fixed-log-journal-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    type TestDb<F> = Db<F, deterministic::Context, commonware_utils::sequence::U64, Sha256>;

    async fn open_db<F: crate::merkle::Family>(context: deterministic::Context) -> TestDb<F> {
        let page_cache = CacheRef::from_pooler(context.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
        let cfg = db_config("partition", page_cache);
        TestDb::init(context, cfg).await.unwrap()
    }

    fn reopen<F: crate::merkle::Family>() -> tests::Reopen<TestDb<F>> {
        Box::new(|ctx| Box::pin(open_db(ctx)))
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_build_basic() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_non_empty_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof_comprehensive() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof_with_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_empty_db_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_replay_with_trailing_appends() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmr::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_get_out_of_bounds() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.clone()).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_metadata() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_stacked_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_speculative_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_merkleized_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained_apply_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_many_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained_merkleized_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_large() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch_chained(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch_child_before_parent() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_to_batch() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_child_root_matches_pending_and_committed() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_rewind_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_rewind_pruned_target_errors() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }

    // mmb::Family variants

    #[test_traced("INFO")]
    fn test_keyless_fixed_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_build_basic_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_non_empty_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof_comprehensive_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_proof_with_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_empty_db_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_fixed_replay_with_trailing_appends_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db1")).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmb::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_get_out_of_bounds_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.clone()).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_metadata_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_stacked_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_speculative_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_merkleized_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained_apply_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_many_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_chained_merkleized_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_batch_large_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch_chained(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_sequential_commit_parent_then_child_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_stale_batch_child_before_parent_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_stale_batch_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_to_batch_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_fixed_child_root_matches_pending_and_committed_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_rewind_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_fixed_rewind_pruned_target_errors_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.with_label("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }
}
