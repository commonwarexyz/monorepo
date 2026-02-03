//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, maintains a next-key ordering for each active key, and allows values to have
//! variable sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::ordered::fixed]
//! instead for better performance._

use crate::{
    index::ordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, Location},
    qmdb::{
        any::{ordered, value::VariableEncoding, VariableConfig, VariableValue},
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

pub type Update<K, V> = ordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = ordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T, Merkleized<H>, Durable>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Any uncommitted log operations will be
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
            page_cache: cfg.page_cache.clone(),
        };

        let journal_config = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_blob,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            page_cache: cfg.page_cache,
            write_buffer: cfg.log_write_buffer,
        };

        let mut log = authenticated::Journal::<_, Journal<_, _>, _, _>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::is_commit,
        )
        .await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            let mut dirty_log = log.into_dirty();
            dirty_log
                .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log = dirty_log.merkleize();
            log.sync().await?;
        }

        let index = Index::new(context.with_label("index"), cfg.translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        mmr::Position,
        qmdb::{Durable, Merkleized, NonDurable, Unmerkleized},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
    };
    use commonware_utils::{test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: u16 = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    pub(crate) type VarConfig = VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    /// Type aliases for concrete [Db] types used in these unit tests.
    pub(crate) type AnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>, Durable>;
    type MutableAnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Unmerkleized, NonDurable>;

    pub(crate) fn create_test_config(seed: u64) -> VarConfig {
        VariableConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::new(NZU16!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Create n random operations using the default seed (0). Some portion of
    /// the updates are deletes. create_test_ops(n) is a prefix of
    /// create_test_ops(n') for n < n'.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(n: usize, seed: u64) -> Vec<Operation<Digest, Vec<u8>>> {
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = to_bytes(rng.next_u64());
                ops.push(Operation::Update(ordered::Update {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut MutableAnyTest, ops: Vec<Operation<Digest, Vec<u8>>>) {
        for op in ops {
            match op {
                Operation::Update(data) => {
                    db.update(data.key, data.value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(_, _) => {
                    // CommitFloor consumes self - not supported in this helper.
                    // Test data from create_test_ops never includes CommitFloor.
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            mmr::{iterator::nodes_to_pin, journaled::Mmr, mem::Clean},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest, Clean<Digest>>;

        impl FromSyncTestable for AnyTest {
            type Mmr = TestMmr;

            fn into_log_components(self) -> (Self::Mmr, Self::Journal) {
                (self.log.mmr, self.log.journal)
            }

            async fn pinned_nodes_at(&self, pos: Position) -> Vec<Digest> {
                join_all(nodes_to_pin(pos).map(|p| self.log.mmr.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }

            fn pinned_nodes_from_map(&self, pos: Position) -> Vec<Digest> {
                let map = self.log.mmr.get_pinned_nodes();
                nodes_to_pin(pos).map(|p| *map.get(&p).unwrap()).collect()
            }
        }
    }
}
