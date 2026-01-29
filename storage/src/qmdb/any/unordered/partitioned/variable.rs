//! A partitioned variant of [crate::qmdb::any::unordered::variable] that uses a partitioned index for the snapshot.
//!
//! See [crate::qmdb::any::unordered::partitioned::fixed] for details on partitioned indices and when to use them.

use crate::{
    index::partitioned::unordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, Location},
    qmdb::{
        any::{unordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Committable as _,
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

pub type Update<K, V> = unordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB with a partitioned snapshot index and variable-size values.
///
/// This is the partitioned variant of [crate::qmdb::any::unordered::variable::Db]. The const generic `P` specifies
/// the number of prefix bytes used for partitioning:
/// - `P = 1`: 256 partitions
/// - `P = 2`: 65,536 partitions
/// - `P = 3`: ~16 million partitions
///
/// See the [fixed module documentation](crate::qmdb::any::unordered::partitioned::fixed) for guidance on when to use partitioned indices.
pub type Db<E, K, V, H, T, const P: usize, S = Merkleized<H>, D = Durable> =
    crate::qmdb::any::unordered::Db<E, Journal<E, Operation<K, V>>, Index<T, Location, P>, H, Update<K, V>, S, D>;

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
    > Db<E, K, V, H, T, P, Merkleized<H>, Durable>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the
    /// snapshot is built from the log, `callback` is invoked for each operation with its activity
    /// status and previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        let mmr_config = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_config = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_blob,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.log_write_buffer,
        };

        let mut log = authenticated::Journal::<_, Journal<_, _>, _, _>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::<K, V>::is_commit,
        )
        .await?;

        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log.sync().await?;
        }

        let index = Index::new(context.with_label("index"), cfg.translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::{any::test::variable_db_config, Durable, Merkleized},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    // Config for Vec<u8> value type (requires custom codec config).
    type VarConfig = VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    fn create_test_config(suffix: &str) -> VarConfig {
        VariableConfig {
            mmr_journal_partition: format!("pv_journal_{suffix}"),
            mmr_metadata_partition: format!("pv_metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("pv_log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Type alias with 256 partitions (P=1) and Vec<u8> values.
    type AnyTestP1 = Db<
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        1,
        Merkleized<Sha256>,
        Durable,
    >;

    /// Type alias with 256 partitions (P=1) and Digest values.
    /// Some shared tests require Digest as the value type.
    type AnyTestDigestP1 = Db<
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        1,
        Merkleized<Sha256>,
        Durable,
    >;

    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    async fn open_db_p1(context: Context) -> AnyTestP1 {
        AnyTestP1::init(context, create_test_config("partition_p1"))
            .await
            .unwrap()
    }

    async fn open_digest_db_p1(context: Context) -> AnyTestDigestP1 {
        AnyTestDigestP1::init(context, variable_db_config("unordered_partitioned_var_p1"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_partitioned_variable_p1_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_variable_p1_non_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_non_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_variable_p1_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_variable_p1_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            crate::qmdb::any::unordered::test::test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db_p1(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_variable_p1_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            crate::qmdb::any::unordered::test::test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db_p1(ctx))
            })
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_variable_p1_multiple_commits_delete_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_digest_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_multiple_commits_delete_replayed(
                db_context,
                db,
                |ctx| Box::pin(open_digest_db_p1(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_partitioned_variable_p1_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db_p1(context).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
        });
    }
}
