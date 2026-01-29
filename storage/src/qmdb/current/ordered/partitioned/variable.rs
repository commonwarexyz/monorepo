//! A partitioned variant of [crate::qmdb::current::ordered::variable] that uses a partitioned index for the snapshot.
//!
//! See [crate::qmdb::any::unordered::partitioned::fixed] for details on partitioned indices and
//! when to use them.

pub use crate::qmdb::current::ordered::db::KeyValueProof;
use crate::{
    bitmap::CleanBitMap,
    index::partitioned::ordered::Index,
    journal::contiguous::variable::Journal,
    mmr::{Location, StandardHasher},
    qmdb::{
        any::{
            ordered::partitioned::variable::{Db as AnyDb, Operation},
            value::VariableEncoding,
            VariableValue,
        },
        current::{
            db::{merkleize_grafted_bitmap, root},
            VariableConfig as Config,
        },
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::{FixedSize, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;

/// A partitioned variant of [crate::qmdb::current::ordered::variable::Db].
///
/// The const generic `P` specifies the number of prefix bytes used for partitioning:
/// - `P = 1`: 256 partitions
/// - `P = 2`: 65,536 partitions
/// - `P = 3`: ~16 million partitions
pub type Db<E, K, V, H, T, const P: usize, const N: usize, S = Merkleized<H>, D = Durable> =
    crate::qmdb::current::ordered::db::Db<E, Journal<E, Operation<K, V>>, K, VariableEncoding<V>, Index<T, Location, P>, H, N, S, D>;

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > Db<E, K, V, H, T, P, N, Merkleized<H>, Durable>
where
    Operation<K, V>: Read,
{
    /// Initializes a [Db] from the given `config`. Leverages parallel Merkleization to initialize
    /// the bitmap MMR if a thread pool is provided.
    pub async fn init(
        context: E,
        config: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        const {
            assert!(
                N.is_multiple_of(H::Digest::SIZE),
                "chunk size must be some multiple of the digest size",
            );
            assert!(N.is_power_of_two(), "chunk size must be a power of 2");
        }

        let thread_pool = config.thread_pool.clone();
        let bitmap_metadata_partition = config.bitmap_metadata_partition.clone();

        let mut hasher = StandardHasher::<H>::new();
        let mut status = CleanBitMap::init(
            context.with_label("bitmap"),
            &bitmap_metadata_partition,
            thread_pool,
            &mut hasher,
        )
        .await?
        .into_dirty();

        // Initialize the anydb with a callback that initializes the status bitmap.
        let last_known_inactivity_floor = Location::new_unchecked(status.len());
        let any = AnyDb::<_, K, V, H, T, P>::init_with_callback(
            context.with_label("any"),
            config.into(),
            Some(last_known_inactivity_floor),
            |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            },
        )
        .await?;

        let status = merkleize_grafted_bitmap(&mut hasher, status, &any.log.mmr).await?;

        // Compute and cache the root
        let cached_root = Some(root(&mut hasher, &status, &any.log.mmr).await?);

        Ok(Self {
            any,
            status,
            cached_root,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::{
            current::{tests, VariableConfig},
            Durable, Merkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    type VarConfig = VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    fn current_db_config(partition_prefix: &str) -> VarConfig {
        VariableConfig {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("{partition_prefix}_log_partition"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Type alias with 256 partitions (P=1).
    type CleanCurrentTestP1 =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, 1, 32, Merkleized<Sha256>, Durable>;

    async fn open_db(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CleanCurrentTestP1 {
        CleanCurrentTestP1::init(context, current_db_config(&partition_prefix))
            .await
            .unwrap()
    }

    #[test_traced("DEBUG")]
    fn test_build_small_close_reopen() {
        crate::qmdb::current::ordered::tests::test_build_small_close_reopen::<CleanCurrentTestP1, _, _>(
            open_db,
        );
    }

    #[test_traced("WARN")]
    fn test_build_big() {
        // Expected values after commit + merkleize + prune for ordered variant.
        tests::test_current_db_build_big::<CleanCurrentTestP1, _, _>(open_db, 4241, 3383);
    }

    #[test_traced("WARN")]
    fn test_build_random_close_reopen() {
        tests::test_build_random_close_reopen(open_db);
    }

    #[test_traced("WARN")]
    fn test_simulate_write_failures() {
        tests::test_simulate_write_failures(open_db);
    }

    #[test_traced("WARN")]
    fn test_different_pruning_delays_same_root() {
        tests::test_different_pruning_delays_same_root::<CleanCurrentTestP1, _, _>(open_db);
    }

    #[test_traced("WARN")]
    fn test_sync_persists_bitmap_pruning_boundary() {
        tests::test_sync_persists_bitmap_pruning_boundary::<CleanCurrentTestP1, _, _>(open_db);
    }
}
