//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, maintains a next-key ordering for each active key, and allows values to have
//! variable sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::ordered::fixed]
//! instead for better performance._

use crate::{
    index::ordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{init_variable, ordered, value::VariableEncoding, VariableConfig, VariableValue},
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

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
        init_variable(context, cfg, known_inactivity_floor, callback, |ctx, t| {
            Index::new(ctx, t)
        })
        .await
    }
}

/// Partitioned index variants that divide the key space into `2^(P*8)` partitions.
///
/// See [partitioned::Db] for the generic type, or use the convenience aliases:
/// - [partitioned::p256::Db] for 256 partitions (P=1)
/// - [partitioned::p64k::Db] for 65,536 partitions (P=2)
pub mod partitioned {
    pub use super::{Operation, Update};
    use crate::{
        index::partitioned::ordered::Index,
        journal::contiguous::variable::Journal,
        mmr::Location,
        qmdb::{
            any::{init_variable, VariableConfig, VariableValue},
            Durable, Error, Merkleized,
        },
        translator::Translator,
    };
    use commonware_codec::Read;
    use commonware_cryptography::Hasher;
    use commonware_runtime::{Clock, Metrics, Storage};
    use commonware_utils::Array;

    /// An ordered key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<E, K, V, H, T, const P: usize, S = Merkleized<H>, D = Durable> =
        crate::qmdb::any::ordered::Db<
            E,
            Journal<E, Operation<K, V>>,
            Index<T, Location, P>,
            H,
            Update<K, V>,
            S,
            D,
        >;

    impl<
            E: Storage + Clock + Metrics,
            K: Array,
            V: VariableValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<E, K, V, H, T, P, Merkleized<H>, Durable>
    where
        Operation<K, V>: Read,
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
            init_variable(context, cfg, known_inactivity_floor, callback, |ctx, t| {
                Index::new(ctx, t)
            })
            .await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Variable-value DB with 256 partitions.
        pub type Db<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
            super::Db<E, K, V, H, T, 1, S, D>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Variable-value DB with 65,536 partitions.
        pub type Db<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
            super::Db<E, K, V, H, T, 2, S, D>;
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        kv::{
            tests::{assert_batchable, assert_gettable, assert_send},
            Batchable as _, Deletable as _, Updatable as _,
        },
        mmr::{Location, Position},
        qmdb::{
            any::{
                ordered::test::{
                    test_digest_ordered_any_db_basic, test_digest_ordered_any_db_empty,
                    test_ordered_any_db_basic, test_ordered_any_db_empty,
                    test_ordered_any_update_collision_edge_case,
                },
                test::variable_db_config,
            },
            store::tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
            Durable, Merkleized, NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, test_rng_seeded, NZUsize, NZU16, NZU64};
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
                    db.write_batch([(data.key, Some(data.value))])
                        .await
                        .unwrap();
                }
                Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await.unwrap();
                }
                Operation::CommitFloor(_, _, _) => {
                    // CommitFloor consumes self - not supported in this helper.
                    // Test data from create_test_ops never includes CommitFloor.
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    // Tests calling generic helpers with Digest-key and Digest-value DB (non-partitioned variant)

    /// Type alias for a variable db with Digest keys AND Digest values (for generic tests).
    type DigestVariableDb = Db<Context, Digest, Digest, Sha256, TwoCap>;

    /// Return a variable db with Digest keys and values for generic tests.
    async fn open_digest_variable_db(context: Context) -> DigestVariableDb {
        DigestVariableDb::init(context, variable_db_config("digest_partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_digest_ordered_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_variable_db(context.with_label("initial")).await;
            test_digest_ordered_any_db_empty(context, db, |ctx| {
                Box::pin(open_digest_variable_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_digest_ordered_any_variable_db_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_variable_db(context.with_label("initial")).await;
            test_digest_ordered_any_db_basic(context, db, |ctx| {
                Box::pin(open_digest_variable_db(ctx))
            })
            .await;
        });
    }

    // Tests using FixedBytes<4> keys (for edge cases that require specific key patterns)

    /// Type alias for a variable db with FixedBytes<4> keys.
    type VariableDb = Db<Context, FixedBytes<4>, Digest, Sha256, TwoCap>;

    /// Return a variable db with FixedBytes<4> keys.
    async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("fixed_bytes_var_partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("initial")).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("initial")).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_variable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with two colliding keys, and creates a new one between them using a batch
    /// update.
    #[test_traced("WARN")]
    fn test_ordered_any_update_batch_create_between_collisions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db(context.clone()).await.into_mutable();

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            db.write_batch([(key1.clone(), Some(val))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val))]).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            // Batch-insert the middle key.
            let mut db = db.into_mutable();
            let mut batch = db.start_batch();
            batch.update(key2.clone(), val).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key1);

            let db = db.into_mutable().commit(None).await.unwrap().0;
            db.into_merkleized().destroy().await.unwrap();
        });
    }

    /// Batch create/delete cases where the deleted key is the previous key of a newly created key,
    /// and vice-versa.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_delete_prev_links() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key1 = FixedBytes::from([0x10u8, 0x00, 0x00, 0x00]);
            let key2 = FixedBytes::from([0x20u8, 0x00, 0x00, 0x00]);
            let key3 = FixedBytes::from([0x30u8, 0x00, 0x00, 0x00]);
            let val1 = Sha256::fill(1u8);
            let val2 = Sha256::fill(2u8);
            let val3 = Sha256::fill(3u8);

            // Delete the previous key of a newly created key.
            let mut db = open_variable_db(context.with_label("first"))
                .await
                .into_mutable();
            db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val3))]).await.unwrap();
            let mut db = db.commit(None).await.unwrap().0.into_mutable();

            let mut batch = db.start_batch();
            batch.delete(key1.clone()).await.unwrap();
            batch.create(key2.clone(), val2).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert!(db.get(&key1).await.unwrap().is_none());
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert_eq!(db.get(&key3).await.unwrap(), Some(val3));
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key2);
            let db = db.commit(None).await.unwrap().0;
            db.into_merkleized().destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.with_label("second"))
                .await
                .into_mutable();
            db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val3))]).await.unwrap();
            let mut db = db.commit(None).await.unwrap().0.into_mutable();

            let mut batch = db.start_batch();
            batch.create(key2.clone(), val2).await.unwrap();
            batch.delete(key3.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(val1));
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert!(db.get(&key3).await.unwrap().is_none());
            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key1);
            let db = db.commit(None).await.unwrap().0;
            db.into_merkleized().destroy().await.unwrap();
        });
    }

    // Partitioned variant tests

    type PartitionedAnyTest =
        super::partitioned::Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 1>;

    async fn open_partitioned_db(context: deterministic::Context) -> PartitionedAnyTest {
        PartitionedAnyTest::init(context, variable_db_config("ordered_partitioned_var_p1"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_partitioned_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_partitioned_db(db_context.clone()).await;
            test_digest_ordered_any_db_empty(db_context, db, |ctx| {
                Box::pin(open_partitioned_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_partitioned_db(db_context.clone()).await;
            test_digest_ordered_any_db_basic(db_context, db, |ctx| {
                Box::pin(open_partitioned_db(ctx))
            })
            .await;
        });
    }

    #[allow(dead_code)]
    fn assert_merkleized_db_futures_are_send(db: &mut AnyTest, key: Digest, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_mutable_db_futures_are_send(db: &mut MutableAnyTest, key: Digest, value: Vec<u8>) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_send(db.write_batch([(key, Some(value.clone()))]));
        assert_send(db.write_batch([(key, None)]));
        assert_batchable(db, key, value);
        assert_send(db.get_all(&key));
        assert_send(db.get_with_loc(&key));
        assert_send(db.get_span(&key));
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(db: MutableAnyTest) {
        assert_send(db.commit(None));
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
        }
    }
}
