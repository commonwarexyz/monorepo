//! An immutable authenticated database with fixed-size values.
//!
//! For variable-size values, use [super::variable] instead.

use super::{operation::Operation as BaseOperation, Config as BaseConfig, Immutable};
use crate::{
    journal::{
        authenticated,
        contiguous::fixed::{self, Config as JournalConfig},
    },
    merkle::Family,
    qmdb::{
        any::{value::FixedEncoding, FixedValue},
        Error,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

/// Type alias for a fixed-size operation.
pub type Operation<F, K, V> = BaseOperation<F, K, FixedEncoding<V>>;

/// Type alias for the fixed-size immutable database.
pub type Db<F, E, K, V, H, T> =
    Immutable<F, E, K, FixedEncoding<V>, fixed::Journal<E, Operation<F, K, V>>, H, T>;

/// Type alias for the fixed-size compact immutable db.
pub type CompactDb<F, E, K, V, H> = super::CompactDb<F, E, K, FixedEncoding<V>, H>;

type Journal<F, E, K, V, H> =
    authenticated::Journal<F, E, fixed::Journal<E, Operation<F, K, V>>, H>;

/// Configuration for a fixed-size immutable authenticated db.
pub type Config<T> = BaseConfig<T, JournalConfig>;

/// Configuration for a fixed-size compact immutable db.
pub type CompactConfig = super::CompactConfig<()>;

impl<
        F: Family,
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
    > Db<F, E, K, V, H, T>
{
    /// Returns a [Db] initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, K, V, H> = Journal::new(
            context.clone(),
            cfg.merkle_config,
            cfg.log,
            Operation::<F, K, V>::is_commit,
        )
        .await?;
        Self::init_from_journal(journal, context, cfg.translator).await
    }
}

impl<F: Family, E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher>
    CompactDb<F, E, K, V, H>
{
    /// Returns a [CompactDb] initialized from `cfg`.
    pub async fn init(context: E, cfg: CompactConfig) -> Result<Self, Error<F>> {
        let merkle = crate::merkle::compact::Merkle::init(
            context,
            &crate::merkle::hasher::Standard::<H>::new(),
            cfg.merkle,
        )
        .await?;
        Self::init_from_merkle(merkle, ()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{full::Config as MmrConfig, mmb, mmr},
        qmdb::immutable::test,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::{future::Future, pin::Pin};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn config(suffix: &str, pooler: &impl BufferPooler) -> Config<TwoCap> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle_config: MmrConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                items_per_blob: NZU64!(5),
                partition: format!("log-{suffix}"),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
        }
    }

    async fn open_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap> {
        let cfg = config("partition", &context);
        Db::init(context, cfg).await.unwrap()
    }

    async fn open_compact<F: Family>(
        context: deterministic::Context,
    ) -> CompactDb<F, deterministic::Context, Digest, Digest, Sha256> {
        let cfg = CompactConfig {
            merkle: crate::merkle::compact::Config {
                partition: "compact-immutable-fixed".into(),
                thread_pool: None,
            },
            commit_codec_config: (),
        };
        CompactDb::init(context, cfg).await.unwrap()
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

    fn small_sections_config(suffix: &str, pooler: &impl BufferPooler) -> Config<TwoCap> {
        let mut cfg = config(suffix, pooler);
        cfg.log.items_per_blob = NZU64!(1);
        cfg
    }

    async fn open_small_sections_db<F: Family>(
        context: deterministic::Context,
    ) -> Db<F, deterministic::Context, Digest, Digest, Sha256, TwoCap> {
        let cfg = small_sections_config("partition", &context);
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
    fn test_fixed_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_empty(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_basic(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_proof_verify() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_proof_verify(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_batch_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chain(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_and_authenticate(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_recovery_from_failed_merkle_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_merkle_sync(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_log_sync(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_pruning(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_prune_beyond_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune_beyond_floor(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_get_read_through(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_stacked_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_apply(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_speculative_root(ctx, open::<mmr::Family>).await;
        });
    }

    async fn assert_compact_root_compatibility<F: Family>(ctx: deterministic::Context) {
        let mut db = open_db::<F>(ctx.with_label("db")).await;
        let mut compact = open_compact::<F>(ctx.with_label("compact")).await;
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
            .merkleize(&db, Some(metadata), floor);
        let compact_batch =
            compact
                .new_batch()
                .set(k1, v1)
                .set(k2, v2)
                .merkleize(&compact, Some(metadata), floor);

        assert_eq!(retained.root(), compact_batch.root());

        db.apply_batch(retained).await.unwrap();
        compact.apply_batch(compact_batch).unwrap();
        db.commit().await.unwrap();
        compact.commit().await.unwrap();

        assert_eq!(db.root(), compact.root());
        assert_eq!(compact.get_metadata(), Some(metadata));

        drop(compact);
        let reopened = open_compact::<F>(ctx.with_label("reopen")).await;
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

    #[test_traced("INFO")]
    fn test_fixed_merkleized_batch_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_merkleized_batch_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_sequential_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_apply(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_many_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_many_sequential(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_empty_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_empty_batch(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_chained_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_merkleized_get(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_large() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_large(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_chained_key_override() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_key_override(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_sequential_key_override() {
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
    fn test_fixed_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_metadata(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_rejected(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_chained(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_sequential_commit_parent_then_child() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_sequential_commit_parent_then_child(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_child_applied_before_parent(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_child_root_matches_pending_and_committed() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_child_root_matches_pending_and_committed(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_to_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_to_batch(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_recovery(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_preserves_collision_bucket() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_preserves_collision_bucket(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_pruned_target_errors(
                ctx,
                open_small_sections::<mmr::Family>,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_get_many() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_get_many(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_get_many_unexpected_data() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_get_many_unexpected_data(ctx, open::<mmr::Family>).await;
        });
    }

    // -- MMB test wrappers --

    #[test_traced("WARN")]
    fn test_fixed_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_empty(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_build_basic_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_basic(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_proof_verify_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_proof_verify(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_prune_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_batch_chain_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chain(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_build_and_authenticate_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_build_and_authenticate(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_recovery_from_failed_merkle_sync_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_merkle_sync(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_recovery_from_failed_log_sync_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_recovery_from_failed_log_sync(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("WARN")]
    fn test_fixed_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_pruning(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_prune_beyond_floor_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_prune_beyond_floor(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_get_read_through_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_get_read_through(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_stacked_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_stacked_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_stacked_apply(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_speculative_root_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_speculative_root(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_merkleized_batch_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_merkleized_batch_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_sequential_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_sequential_apply(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_many_sequential_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_many_sequential(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_empty_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_empty_batch(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_chained_merkleized_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_merkleized_get(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_large_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_large(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_chained_key_override_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_chained_key_override(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_batch_sequential_key_override_mmb() {
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
    fn test_fixed_batch_metadata_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_batch_metadata(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_rejected_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_rejected(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_chained_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_chained(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced]
    fn test_fixed_sequential_commit_parent_then_child_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_sequential_commit_parent_then_child(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_stale_batch_child_applied_before_parent_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_stale_batch_child_applied_before_parent(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_child_root_matches_pending_and_committed_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_child_root_matches_pending_and_committed(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced]
    fn test_fixed_to_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_to_batch(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_recovery(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_pruned_target_errors_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_pruned_target_errors(
                ctx,
                open_small_sections::<mmb::Family>,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_inactivity_floor_tracking() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_inactivity_floor_tracking(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_monotonicity() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_monotonicity(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_monotonicity_violation() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_monotonicity_violation(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_beyond_size() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_beyond_size(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_chained_ancestor_floor_regression() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_chained_ancestor_floor_regression(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_chained_ancestor_floor_beyond_size() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_chained_ancestor_floor_beyond_size(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_restores_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_restores_floor(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_inactivity_floor_tracking_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_inactivity_floor_tracking(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_monotonicity_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_monotonicity(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_monotonicity_violation_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_monotonicity_violation(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_floor_beyond_size_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_floor_beyond_size(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_chained_ancestor_floor_regression_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_chained_ancestor_floor_regression(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_chained_ancestor_floor_beyond_size_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_chained_ancestor_floor_beyond_size(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_restores_floor_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_restores_floor(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_single_commit_live_set() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_single_commit_live_set(ctx, open::<mmr::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_single_commit_live_set_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_single_commit_live_set(ctx, open::<mmb::Family>).await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_after_reopen_with_floor_change() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_after_reopen_with_floor_change(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_after_reopen_with_floor_change_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_after_reopen_with_floor_change(ctx, open::<mmb::Family>)
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_after_reopen_partial_floor_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_after_reopen_partial_floor_gap(ctx, open::<mmr::Family>)
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_fixed_rewind_after_reopen_partial_floor_gap_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            test::test_immutable_rewind_after_reopen_partial_floor_gap(ctx, open::<mmb::Family>)
                .await;
        });
    }
}
