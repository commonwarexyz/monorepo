//! An immutable authenticated database with variable-size values.
//!
//! For fixed-size values, use [super::fixed] instead.

use super::{Config as BaseConfig, Immutable, operation::Operation as BaseOperation};
use crate::{
    Context,
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        Error, ROOT_BAGGING,
        any::{VariableValue, value::VariableEncoding},
        operation::Key,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

/// Type alias for a variable-size operation.
pub type Operation<F, K, V> = BaseOperation<F, K, VariableEncoding<V>>;

/// Type alias for the variable-size immutable database.
pub type Db<F, E, K, V, H, T, S> =
    Immutable<F, E, K, VariableEncoding<V>, variable::Journal<E, Operation<F, K, V>>, H, T, S>;

/// Type alias for the variable-size compact immutable db.
pub type CompactDb<F, E, K, V, H, C, S> = super::CompactDb<F, E, K, VariableEncoding<V>, H, C, S>;

type Journal<F, E, K, V, H, S> =
    authenticated::Journal<F, E, variable::Journal<E, Operation<F, K, V>>, H, S>;

/// Configuration for a variable-size immutable authenticated db.
pub type Config<T, C, S> = BaseConfig<T, JournalConfig<C>, S>;

/// Configuration for a variable-size compact immutable db.
pub type CompactConfig<C, S> = super::CompactConfig<C, S>;

impl<F: Family, E: Context, K: Key, V: VariableValue, H: Hasher, T: Translator, S: Strategy>
    Db<F, E, K, V, H, T, S>
{
    /// Returns a [Db] initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<F, K, V> as Read>::Cfg, S>,
    ) -> Result<Self, Error<F>> {
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

impl<
    F: Family,
    E: Context,
    K: Key,
    V: VariableValue,
    H: Hasher,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
> CompactDb<F, E, K, V, H, C, S>
where
    Operation<F, K, V>: Read<Cfg = C>,
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
        journal::contiguous::variable::Config as JournalConfig,
        merkle::{full::Config as MmrConfig, mmb, mmr},
        qmdb::immutable::tests::{self, immutable_tests},
        translator::TwoCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::{boxed, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use core::{future::Future, pin::Pin};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn config(suffix: &str, pooler: &impl BufferPooler) -> Config<TwoCap, ((), ()), Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        super::BaseConfig {
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
                partition: format!("log-{suffix}"),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: ((), ()),
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
    ) -> CompactDb<F, deterministic::Context, Digest, Digest, Sha256, ((), ()), Sequential> {
        let cfg = CompactConfig {
            strategy: Sequential,
            witness: crate::journal::contiguous::variable::Config {
                partition: "compact-immutable-variable-witness".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: ((), ()),
        };
        CompactDb::init(context, cfg).await.unwrap()
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
    ) -> Config<TwoCap, ((), ()), Sequential> {
        let mut cfg = config(suffix, pooler);
        cfg.log.items_per_section = NZU64!(1);
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
        test_variable_empty => run_empty, open;
        test_variable_build_basic => run_build_basic, open;
        test_variable_proof_verify => run_proof_verify, open;
        test_variable_prune => run_prune, open;
        test_variable_batch_chain => run_batch_chain, open;
        test_variable_operations_match_applied_log => run_operations_match_applied_log, open;
        test_variable_build_and_authenticate => run_build_and_authenticate, open;
        test_variable_recovery_from_failed_merkle_sync => run_recovery_from_failed_merkle_sync, open;
        test_variable_recovery_from_failed_log_sync => run_recovery_from_failed_log_sync, open;
        test_variable_pruning => run_pruning, open;
        test_variable_prune_beyond_floor => run_prune_beyond_floor, open;
        test_variable_batch_get_read_through => run_batch_get_read_through, open;
        test_variable_batch_stacked_get => run_batch_stacked_get, open;
        test_variable_batch_stacked_apply => run_batch_stacked_apply, open;
        test_variable_batch_speculative_root => run_batch_speculative_root, open;
        test_variable_merkleized_batch_get => run_merkleized_batch_get, open;
        test_variable_batch_sequential_apply => run_batch_sequential_apply, open;
        test_variable_batch_many_sequential => run_batch_many_sequential, open;
        test_variable_batch_empty_batch => run_batch_empty_batch, open;
        test_variable_batch_chained_merkleized_get => run_batch_chained_merkleized_get, open;
        test_variable_batch_large => run_batch_large, open;
        test_variable_batch_chained_key_override => run_batch_chained_key_override, open;
        test_variable_batch_sequential_key_override => run_batch_sequential_key_override, open_small_sections;
        test_variable_batch_metadata => run_batch_metadata, open;
        test_variable_stale_batch_rejected => run_stale_batch_rejected, open;
        test_variable_stale_batch_chained => run_stale_batch_chained, open;
        test_variable_sequential_commit_parent_then_child => run_sequential_commit_parent_then_child, open;
        test_variable_stale_batch_child_applied_before_parent => run_stale_batch_child_applied_before_parent, open;
        test_variable_child_root_matches_pending_and_committed => run_child_root_matches_pending_and_committed, open;
        test_variable_to_batch => run_to_batch, open;
        test_variable_rewind_recovery => run_rewind_recovery, open;
        test_variable_rewind_pruned_target_errors => run_rewind_pruned_target_errors, open_small_sections;
        test_variable_inactivity_floor_tracking => run_inactivity_floor_tracking, open;
        test_variable_floor_monotonicity => run_floor_monotonicity, open;
        test_variable_floor_monotonicity_violation => run_floor_monotonicity_violation, open;
        test_variable_floor_beyond_size => run_floor_beyond_size, open;
        test_variable_chained_ancestor_floor_regression => run_chained_ancestor_floor_regression, open;
        test_variable_chained_ancestor_floor_beyond_size => run_chained_ancestor_floor_beyond_size, open;
        test_variable_rewind_restores_floor => run_rewind_restores_floor, open;
        test_variable_single_commit_live_set => run_single_commit_live_set, open;
        test_variable_rewind_after_reopen_with_floor_change => run_rewind_after_reopen_with_floor_change, open;
        test_variable_rewind_after_reopen_partial_floor_gap => run_rewind_after_reopen_partial_floor_gap, open;
        test_variable_commit_after_sync_recovery => run_commit_after_sync_recovery, open;
        test_variable_partial_ancestor_commit => run_partial_ancestor_commit, open;
        test_variable_delayed_merkleize_after_ancestor_apply => run_delayed_merkleize_after_ancestor_apply, open;
        test_variable_get_many => run_get_many, open;
        test_variable_get_many_unexpected_data => run_get_many_unexpected_data, open;
        test_variable_apply_after_ancestor_dropped => run_apply_after_ancestor_dropped, open;
        test_variable_rewind_preserves_collision_bucket => run_rewind_preserves_collision_bucket, open;
        test_variable_rewind_after_reopen_repeated_key_gap => run_rewind_after_reopen_repeated_key_gap, open;
        test_variable_rewind_after_reopen_mixed_gap_retained => run_rewind_after_reopen_mixed_gap_retained, open;
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
    fn test_variable_compact_root_compatibility() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            assert_compact_root_compatibility::<mmr::Family>(ctx).await;
        });
    }

    #[test_traced("INFO")]
    fn test_variable_compact_root_compatibility_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            assert_compact_root_compatibility::<mmb::Family>(ctx).await;
        });
    }
}
