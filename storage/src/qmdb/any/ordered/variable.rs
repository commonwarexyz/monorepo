//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, maintains a next-key ordering for each active key, and allows values to have
//! variable sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::ordered::fixed]
//! instead for better performance._

use crate::{
    index::ordered::Index,
    journal::contiguous::variable::Journal,
    merkle::{Family, Location},
    qmdb::{
        any::{ordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Key,
        Bagging, Error,
    },
    translator::Translator,
    Context,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;

pub type Update<K, V> = ordered::Update<K, VariableEncoding<V>>;
pub type Operation<F, K, V> = ordered::Operation<F, K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<F, E, K, V, H, T> =
    super::Db<F, E, Journal<E, Operation<F, K, V>>, Index<T, Location<F>>, H, Update<K, V>>;

impl<F: Family + Bagging, E: Context, K: Key, V: VariableValue, H: Hasher, T: Translator>
    Db<F, E, K, V, H, T>
where
    Operation<F, K, V>: Codec,
{
    /// Returns a [Db] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
        crate::qmdb::any::init(context, cfg).await
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
        merkle::{Family, Location},
        qmdb::{
            any::{VariableConfig, VariableValue},
            operation::Key,
            Bagging, Error,
        },
        translator::Translator,
        Context,
    };
    use commonware_codec::{Codec, Read};
    use commonware_cryptography::Hasher;

    /// An ordered key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<F, E, K, V, H, T, const P: usize> = crate::qmdb::any::ordered::Db<
        F,
        E,
        Journal<E, Operation<F, K, V>>,
        Index<T, Location<F>, P>,
        H,
        Update<K, V>,
    >;

    impl<
            F: Family + Bagging,
            E: Context,
            K: Key,
            V: VariableValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<F, E, K, V, H, T, P>
    where
        Operation<F, K, V>: Codec,
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(
            context: E,
            cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
        ) -> Result<Self, Error<F>> {
            crate::qmdb::any::init(context, cfg).await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Variable-value DB with 256 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 1>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Variable-value DB with 65,536 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 2>;
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        mmr,
        qmdb::any::{
            ordered::test::{
                test_ordered_any_db_basic, test_ordered_any_db_empty,
                test_ordered_any_update_collision_edge_case,
            },
            test::variable_db_config,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;
    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: u16 = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    pub(crate) type VarConfig =
        VariableConfig<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))>;

    /// Type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<mmr::Family, deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    pub(crate) fn create_test_config(seed: u64, pooler: &impl BufferPooler) -> VarConfig {
        let page_cache =
            CacheRef::from_pooler(pooler, NZU16!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE));
        VariableConfig {
            merkle_config: crate::mmr::full::Config {
                journal_partition: format!("mmr-journal-{seed}"),
                metadata_partition: format!("mmr-metadata-{seed}"),
                items_per_blob: NZU64!(12), // intentionally small and janky size
                write_buffer: NZUsize!(64),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: crate::journal::contiguous::variable::Config {
                partition: format!("log-journal-{seed}"),
                items_per_section: NZU64!(14), // intentionally small and janky size
                write_buffer: NZUsize!(64),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                page_cache,
            },
            translator: TwoCap,
            split_root: true,
            root_bagging: <mmr::Family as crate::qmdb::Bagging>::BAGGING,
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed, &context);
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
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<mmr::Family, Digest, Vec<u8>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(
        n: usize,
        seed: u64,
    ) -> Vec<Operation<mmr::Family, Digest, Vec<u8>>> {
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
    pub(crate) async fn apply_ops(
        db: &mut AnyTest,
        ops: Vec<Operation<mmr::Family, Digest, Vec<u8>>>,
    ) {
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Update(data) => {
                    batch = batch.write(data.key, Some(data.value));
                }
                Operation::Delete(key) => {
                    batch = batch.write(key, None);
                }
                Operation::CommitFloor(_, _) => {
                    // CommitFloor consumes self - not supported in this helper.
                    // Test data from create_test_ops never includes CommitFloor.
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
    }

    // Tests using FixedBytes<4> keys (for edge cases that require specific key patterns)

    /// Type alias for a variable db with FixedBytes<4> keys.
    type VariableDb = Db<mmr::Family, Context, FixedBytes<4>, Digest, Sha256, TwoCap>;

    /// Return a variable db with FixedBytes<4> keys.
    async fn open_variable_db(context: Context) -> VariableDb {
        let cfg = variable_db_config::<mmr::Family, _>("fixed-bytes-var-partition", &context);
        VariableDb::init(context, cfg).await.unwrap()
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
            let mut db = open_variable_db(context.clone()).await;

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            let merkleized = db
                .new_batch()
                .write(key1.clone(), Some(val))
                .write(key3.clone(), Some(val))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            // Batch-insert the middle key.
            let merkleized = db
                .new_batch()
                .write(key2.clone(), Some(val))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key1);

            db.destroy().await.unwrap();
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
            let mut db = open_variable_db(context.with_label("first")).await;
            let merkleized = db
                .new_batch()
                .write(key1.clone(), Some(val1))
                .write(key3.clone(), Some(val3))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            let merkleized = db
                .new_batch()
                .write(key1.clone(), None)
                .write(key2.clone(), Some(val2))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert!(db.get(&key1).await.unwrap().is_none());
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert_eq!(db.get(&key3).await.unwrap(), Some(val3));
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key2);
            db.destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.with_label("second")).await;
            let merkleized = db
                .new_batch()
                .write(key1.clone(), Some(val1))
                .write(key3.clone(), Some(val3))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            let merkleized = db
                .new_batch()
                .write(key2.clone(), Some(val2))
                .write(key3.clone(), None)
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(val1));
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert!(db.get(&key3).await.unwrap().is_none());
            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key1);
            db.destroy().await.unwrap();
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_non_trait_futures_are_send(db: &mut AnyTest, key: Digest) {
        is_send(db.get_all(&key));
        is_send(db.get_with_loc(&key));
        is_send(db.get_span(&key));
    }

    /// Parent inserts a key, child inserts another; commit parent then
    /// apply child sequentially. Verifies next-key pointers
    /// are correct after both commits.
    #[test_traced("WARN")]
    fn test_ordered_sequential_commit_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Seed with initial data so the ordered index is non-trivial.
            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Parent batch: insert key_a.
            let key_a = Digest::random(&mut test_rng_seeded(800));
            let val_a = vec![1u8; 10];
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_a, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child batch: insert key_b.
            let key_b = Digest::random(&mut test_rng_seeded(801));
            let val_b = vec![2u8; 10];
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();

            // Both keys should be readable.
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);

            db.destroy().await.unwrap();
        });
    }

    /// Parent inserts key_x, child deletes key_x. After committing parent
    /// then child sequentially, key_x should be gone and the
    /// next-key ring should exclude it.
    #[test_traced("WARN")]
    fn test_ordered_sequential_commit_delete_after_insert() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            let key_x = Digest::random(&mut test_rng_seeded(810));
            let val_x = vec![10u8; 8];
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_x, Some(val_x.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_x, None)
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_x);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();

            // key_x should be deleted.
            assert!(db.get(&key_x).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Parent and child both modify the same key. After committing parent
    /// then child sequentially, the child's value wins.
    #[test_traced("WARN")]
    fn test_ordered_sequential_commit_overlapping_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            let key_x = Digest::random(&mut test_rng_seeded(820));
            let val_a = vec![10u8; 8];
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_x, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            let val_b = vec![20u8; 8];
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_x, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_b);

            db.destroy().await.unwrap();
        });
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            merkle::mmr::{self, full::Mmr},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest>;

        impl FromSyncTestable for AnyTest {
            type Merkle = TestMmr;

            fn into_log_components(self) -> (Self::Merkle, Self::Journal) {
                (self.log.merkle, self.log.journal)
            }

            async fn pinned_nodes_at(&self, loc: mmr::Location) -> Vec<Digest> {
                join_all(mmr::Family::nodes_to_pin(loc).map(|p| self.log.merkle.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }
        }
    }
}
