//! A keyless authenticated database for variable-length data.
//!
//! For fixed-size values, use [super::fixed].

use crate::{
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    merkle::{hasher::Standard as StandardHasher, Family},
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
pub type Operation<F, V> = BaseOperation<F, VariableEncoding<V>>;

/// A keyless authenticated database for variable-length data.
pub type Db<F, E, V, H> =
    super::Keyless<F, E, VariableEncoding<V>, variable::Journal<E, Operation<F, V>>, H>;

/// A compact keyless authenticated db for variable-length data.
pub type CompactDb<F, E, V, H, C> = super::CompactDb<F, E, VariableEncoding<V>, H, C>;

type Journal<F, E, V, H> = authenticated::Journal<F, E, variable::Journal<E, Operation<F, V>>, H>;

/// Configuration for a variable-size [keyless](super) authenticated db.
pub type Config<C> = super::Config<JournalConfig<C>>;

/// Configuration for a variable-size [keyless](super) compact db.
pub type CompactConfig<C> = super::CompactConfig<C>;

impl<F: Family, E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Db<F, E, V, H> {
    /// Returns a [Db] initialized from `cfg`. Any uncommitted operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<<Operation<F, V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
        let journal: Journal<F, E, V, H> =
            Journal::new(context, cfg.merkle, cfg.log, Operation::<F, V>::is_commit).await?;
        Self::init_from_journal(journal).await
    }
}

impl<
        F: Family,
        E: Storage + Clock + Metrics,
        V: VariableValue,
        H: Hasher,
        C: Clone + Send + Sync + 'static,
    > CompactDb<F, E, V, H, C>
where
    Operation<F, V>: Read<Cfg = C>,
{
    /// Returns a [CompactDb] initialized from `cfg`.
    pub async fn init(context: E, cfg: CompactConfig<C>) -> Result<Self, Error<F>> {
        let merkle =
            crate::merkle::compact::Merkle::init(context, &StandardHasher::<H>::new(), cfg.merkle)
                .await?;
        Self::init_from_merkle(merkle, cfg.commit_codec_config).await
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
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
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
            merkle: crate::merkle::full::Config {
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
    type TestCompactDb<F> = CompactDb<
        F,
        deterministic::Context,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
    >;

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db<F: crate::merkle::Family>(context: deterministic::Context) -> TestDb<F> {
        open_db_with_suffix("partition", context).await
    }

    async fn open_db_with_suffix<F: crate::merkle::Family>(
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
            merkle: crate::merkle::compact::Config {
                partition: "compact-keyless-variable".into(),
                thread_pool: None,
            },
            commit_codec_config: ((0..=10000usize).into(), ()),
        };
        TestCompactDb::init(context, cfg).await.unwrap()
    }

    fn reopen<F: crate::merkle::Family>() -> tests::Reopen<TestDb<F>> {
        Box::new(|ctx| Box::pin(open_db(ctx)))
    }

    #[test_traced("INFO")]
    fn test_keyless_db_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_build_basic() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_comprehensive() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_with_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmr::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_get_out_of_bounds() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_metadata() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    async fn assert_compact_root_compatibility<F: crate::merkle::Family>(
        ctx: deterministic::Context,
    ) {
        let mut db = open_db::<F>(ctx.child("db")).await;
        let mut compact = open_compact::<F>(ctx.child("compact")).await;
        assert_eq!(db.root(), compact.root());

        let v1 = b"hello".to_vec();
        let v2 = b"world".to_vec();
        let metadata = b"metadata".to_vec();

        let floor = db.inactivity_floor_loc();
        let retained = db
            .new_batch()
            .append(v1.clone())
            .append(v2.clone())
            .merkleize(&db, Some(metadata.clone()), floor);
        let compact_batch = compact.new_batch().append(v1).append(v2).merkleize(
            &compact,
            Some(metadata.clone()),
            floor,
        );

        assert_eq!(retained.root(), compact_batch.root());

        db.apply_batch(retained).await.unwrap();
        compact.apply_batch(compact_batch).unwrap();
        db.commit().await.unwrap();
        compact.commit().await.unwrap();

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
    fn test_keyless_db_pruning() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_get_many() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_get_many(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_stale_batch() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch(db).await;
        });
    }

    #[test_traced]
    fn test_stale_batch_chained() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch_chained(db).await;
        });
    }

    #[test_traced]
    fn test_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_stale_batch_child_applied_before_parent() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_partial_ancestor_commit() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_partial_ancestor_commit(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_to_batch() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_child_root_matches_pending_and_committed() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_pruned_target_errors() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }

    // mmb::Family variants

    #[test_traced("INFO")]
    fn test_keyless_db_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_empty(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_build_basic_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_build_basic(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_non_empty_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_proof(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_comprehensive_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_proof_comprehensive(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_proof_with_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_proof_with_pruning(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_empty_db_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_replay_with_trailing_appends(ctx, db, reopen::<mmb::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_get_out_of_bounds_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("storage")).await;
            tests::test_keyless_db_get_out_of_bounds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_metadata_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_metadata(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_db_pruning_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_pruning(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_stacked_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_speculative_root(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_merkleized_batch_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained_apply_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_many_sequential(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_empty(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_chained_merkleized_get(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_batch_large(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_stale_batch_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch(db).await;
        });
    }

    #[test_traced]
    fn test_stale_batch_chained_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch_chained(db).await;
        });
    }

    #[test_traced]
    fn test_sequential_commit_parent_then_child_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_sequential_commit_parent_then_child(db).await;
        });
    }

    #[test_traced]
    fn test_stale_batch_child_applied_before_parent_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_stale_batch_child_before_parent(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_to_batch_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_to_batch(db).await;
        });
    }

    #[test_traced]
    fn test_keyless_child_root_matches_pending_and_committed_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_child_root_matches_pending_and_committed(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_recovery_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_recovery(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_rewind_pruned_target_errors_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_pruned_target_errors(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_tracking_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_floor_tracking(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_regression_rejected_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_regression_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_beyond_commit_loc_rejected_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_beyond_commit_loc_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_rewind_restores_floor_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_restores_floor(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_changes_root_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmb::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmb::Family>("root-b", ctx.child("b")).await;
            tests::test_keyless_db_floor_changes_root(db_a, db_b).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_at_commit_loc_accepted_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_at_commit_loc_accepted(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_rewind_after_reopen_with_floor_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_rewind_after_reopen_with_floor(ctx, db, reopen::<mmb::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_ancestor_floor_regression_rejected_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_ancestor_floor_regression_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_ancestor_floor_beyond_commit_loc_rejected_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_ancestor_floor_beyond_commit_loc_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_chained_apply_with_valid_floors_succeeds_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db")).await;
            tests::test_keyless_db_chained_apply_with_valid_floors_succeeds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_single_commit_live_set_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmb::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_single_commit_live_set(ctx, db, reopen::<mmb::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_tracking() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_floor_tracking(ctx, db, reopen::<mmr::Family>()).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_regression_rejected() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_regression_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_beyond_commit_loc_rejected() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_beyond_commit_loc_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_rewind_restores_floor() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_rewind_restores_floor(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_changes_root() {
        deterministic::Runner::default().start(|ctx| async move {
            let db_a = open_db_with_suffix::<mmr::Family>("root-a", ctx.child("a")).await;
            let db_b = open_db_with_suffix::<mmr::Family>("root-b", ctx.child("b")).await;
            tests::test_keyless_db_floor_changes_root(db_a, db_b).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_floor_at_commit_loc_accepted() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_floor_at_commit_loc_accepted(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_rewind_after_reopen_with_floor() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_rewind_after_reopen_with_floor(ctx, db, reopen::<mmr::Family>())
                .await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_ancestor_floor_regression_rejected() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_ancestor_floor_regression_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_ancestor_floor_beyond_commit_loc_rejected() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_ancestor_floor_beyond_commit_loc_rejected(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_chained_apply_with_valid_floors_succeeds() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db")).await;
            tests::test_keyless_db_chained_apply_with_valid_floors_succeeds(db).await;
        });
    }

    #[test_traced("INFO")]
    fn test_keyless_variable_single_commit_live_set() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db::<mmr::Family>(ctx.child("db").with_attribute("index", 1)).await;
            tests::test_keyless_db_single_commit_live_set(ctx, db, reopen::<mmr::Family>()).await;
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
