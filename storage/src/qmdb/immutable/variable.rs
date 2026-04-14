//! An immutable authenticated database with variable-size values.
//!
//! For fixed-size values, use [super::fixed] instead.

use super::{operation::Operation as BaseOperation, Config as BaseConfig, Immutable};
use crate::{
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        any::{value::VariableEncoding, VariableValue},
        operation::Key,
        Error,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

/// Type alias for a variable-size operation.
pub type Operation<K, V> = BaseOperation<K, VariableEncoding<V>>;

/// Type alias for the variable-size immutable database.
pub type Db<F, E, K, V, H, T> =
    Immutable<F, E, K, VariableEncoding<V>, variable::Journal<E, Operation<K, V>>, H, T>;

type Journal<F, E, K, V, H> =
    authenticated::Journal<F, E, variable::Journal<E, Operation<K, V>>, H>;

/// Configuration for a variable-size immutable authenticated db.
pub type Config<T, C> = BaseConfig<T, JournalConfig<C>>;

impl<
        F: Family,
        E: Storage + Clock + Metrics,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
    > Db<F, E, K, V, H, T>
{
    /// Returns a [Db] initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, K, V, H> = Journal::new(
            context.clone(),
            cfg.merkle_config,
            cfg.log,
            Operation::<K, V>::is_commit,
        )
        .await?;
        Self::init_from_journal(journal, context, cfg.translator).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::variable::Config as JournalConfig,
        merkle::{journaled::Config as MmrConfig, mmb, mmr},
        qmdb::immutable::test,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::{future::Future, pin::Pin};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn config(suffix: &str, page_cache: CacheRef) -> Config<TwoCap, ((), ())> {
        super::BaseConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("log-{suffix}"),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
        }
    }

    async fn open_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap> {
        let page_cache = CacheRef::from_pooler(context.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
        let cfg = config("partition", page_cache);
        Db::init(context, cfg).await.unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn open<F: Family>(
        ctx: deterministic::Context,
    ) -> Pin<
        Box<
            dyn Future<Output = Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap>>
                + Send,
        >,
    > {
        Box::pin(open_db::<F>(ctx))
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send(
        db: &mut Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap>,
        key: Digest,
        loc: crate::merkle::mmr::Location,
    ) {
        is_send(db.get(&key));
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.sync());
        is_send(db.rewind(loc));
    }

    fn small_sections_config(suffix: &str, page_cache: CacheRef) -> Config<TwoCap, ((), ())> {
        let mut cfg = config(suffix, page_cache);
        cfg.log.items_per_section = NZU64!(1);
        cfg
    }

    async fn open_small_sections_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap> {
        let page_cache = CacheRef::from_pooler(context.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
        let cfg = small_sections_config("partition", page_cache);
        Db::init(context, cfg).await.unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn open_small_sections<F: Family>(
        ctx: deterministic::Context,
    ) -> Pin<
        Box<
            dyn Future<Output = Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap>>
                + Send,
        >,
    > {
        Box::pin(open_small_sections_db::<F>(ctx))
    }

    #[test_traced("WARN")]
    fn test_variable_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_empty(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_basic(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_proof_verify() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_proof_verify(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_batch_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chain(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_and_authenticate(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_recovery_from_failed_merkle_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_merkle_sync(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_log_sync(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_pruning(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune_beyond_commit(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_get_read_through(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_stacked_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_apply(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_speculative_root(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_merkleized_batch_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_merkleized_batch_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_sequential_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_apply(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_many_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_many_sequential(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_empty_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_empty_batch(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_chained_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_merkleized_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_large() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_large(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_chained_key_override() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_key_override(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_sequential_key_override() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_key_override(
                ctx,
                open_small_sections::<mmr::Family>,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_metadata(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_rejected(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_chained(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_sequential_commit_parent_then_child() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_sequential_commit_parent_then_child(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_child_applied_before_parent(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_partial_ancestor_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_partial_ancestor_commit(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_child_root_matches_pending_and_committed() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_child_root_matches_pending_and_committed(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_to_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_to_batch(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_rewind_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_recovery(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_rewind_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_pruned_target_errors(
                ctx,
                open_small_sections::<mmr::Family>,
            )
            .await;
        });
    }

    // -- MMB test wrappers --

    #[test_traced("WARN")]
    fn test_variable_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_empty(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_build_basic_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_basic(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_proof_verify_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_proof_verify(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_prune_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_variable_batch_chain_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chain(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_build_and_authenticate_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_and_authenticate(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_recovery_from_failed_merkle_sync_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_merkle_sync(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_recovery_from_failed_log_sync_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_log_sync(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_pruning(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_prune_beyond_commit_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune_beyond_commit(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_get_read_through_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_get_read_through(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_stacked_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_stacked_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_apply(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_speculative_root_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_speculative_root(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_merkleized_batch_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_merkleized_batch_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_sequential_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_apply(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_many_sequential_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_many_sequential(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_empty_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_empty_batch(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_chained_merkleized_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_merkleized_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_large_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_large(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_chained_key_override_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_key_override(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_sequential_key_override_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_key_override(
                ctx,
                open_small_sections::<mmb::Family>,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_batch_metadata_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_metadata(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_rejected_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_rejected(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_chained_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_chained(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_variable_sequential_commit_parent_then_child_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_sequential_commit_parent_then_child(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_stale_batch_child_applied_before_parent_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_child_applied_before_parent(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_child_root_matches_pending_and_committed_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_child_root_matches_pending_and_committed(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_variable_to_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_to_batch(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_rewind_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_recovery(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_rewind_pruned_target_errors_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_pruned_target_errors(
                ctx,
                open_small_sections::<mmb::Family>,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_variable_apply_after_ancestor_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_apply_after_ancestor_dropped(ctx, open::<mmr::Family>).await;
        });
    }
}
