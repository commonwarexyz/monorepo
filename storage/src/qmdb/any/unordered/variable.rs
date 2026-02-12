//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::unordered::fixed]
//! instead for better performance._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{init_variable, unordered, value::VariableEncoding, VariableConfig, VariableValue},
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

pub type Update<K, V> = unordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T, Merkleized<H>, Durable>
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

/// Partitioned index variants that divide the key space into `2^(P*8)` partitions.
///
/// See [partitioned::Db] for the generic type, or use the convenience aliases:
/// - [partitioned::p256::Db] for 256 partitions (P=1)
/// - [partitioned::p64k::Db] for 65,536 partitions (P=2)
pub mod partitioned {
    pub use super::{Operation, Update};
    use crate::{
        index::partitioned::unordered::Index,
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

    /// A key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<E, K, V, H, T, const P: usize, S = Merkleized<H>, D = Durable> =
        crate::qmdb::any::unordered::Db<
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
        index::Unordered as _,
        kv::tests::{assert_batchable, assert_gettable, assert_send},
        qmdb::{
            any::{
                test::variable_db_config,
                unordered::test::{
                    test_any_db_basic, test_any_db_build_and_authenticate, test_any_db_empty,
                },
            },
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
                LogStore,
            },
            NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    pub(crate) fn create_test_config(seed: u64, pooler: &impl BufferPooler) -> VarConfig {
        VariableConfig {
            mmr_journal_partition: format!("journal_{seed}"),
            mmr_metadata_partition: format!("metadata_{seed}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    pub(crate) type VarConfig = VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>, Durable>;
    type MutableAnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Unmerkleized, NonDurable>;

    /// Type alias for Digest-valued variable DB (used for generic tests that require Digest values).
    type DigestAnyTest =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed, &context);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Return a Digest-valued variable database for generic tests.
    async fn open_digest_db(context: Context) -> DigestAnyTest {
        let cfg = variable_db_config("digest_partition", &context);
        DigestAnyTest::init(context, cfg).await.unwrap()
    }

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Create n random operations using the default seed (0). Some portion of
    /// the updates are deletes. create_test_ops(n) is a prefix of
    /// create_test_ops(n') for n < n'.
    pub(crate) fn create_test_ops(
        n: usize,
    ) -> Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(
        n: usize,
        seed: u64,
    ) -> Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>> {
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(unordered::Operation::Delete(prev_key));
            } else {
                let value = to_bytes(rng.next_u64());
                ops.push(unordered::Operation::Update(unordered::Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(
        db: &mut MutableAnyTest,
        ops: Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>>,
    ) {
        for op in ops {
            match op {
                unordered::Operation::Update(unordered::Update(key, value)) => {
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
                unordered::Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await.unwrap();
                }
                unordered::Operation::CommitFloor(_, _) => {
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        let cfg = create_test_config(0, &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let db = open_db(context.with_label("open1")).await;
            let root = db.root();
            let mut db = db.into_mutable();
            db.write_batch((0..ELEMENTS).map(|i| {
                (
                    Sha256::hash(&i.to_be_bytes()),
                    Some(vec![(i % 255) as u8; ((i % 13) + 7) as usize]),
                )
            }))
            .await
            .unwrap();

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.with_label("open2")).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Update every 3rd key
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.with_label("open3")).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Delete every 7th key
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.write_batch([(k, None)]).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.with_label("open4")).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.write_batch([(k, None)]).await.unwrap();
            }
            let mut db = db.commit(None).await.unwrap().0.into_merkleized();

            let root = db.root();
            assert_eq!(db.bounds().end, 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.bounds().start, Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

            db.sync().await.unwrap();
            drop(db);

            // Confirm state is preserved after reopen.
            let db = open_db(context.with_label("open5")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.bounds().end, 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            assert_eq!(db.log.bounds().start, Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db(ctx))
            })
            .await;
        });
    }

    #[test_traced]
    fn test_any_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.write_batch([(key1, Some(vec![10]))]).await.unwrap();
            db.write_batch([(key2, Some(vec![20]))]).await.unwrap();
            db.write_batch([(key3, Some(vec![30]))]).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let mut db = db.into_merkleized();
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_unordered_variable_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let cfg = create_test_config(seed, &ctx);
            AnyTest::init(ctx, cfg).await.unwrap().into_mutable()
        });
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            mmr::{iterator::nodes_to_pin, journaled::Mmr, mem::Clean, Position},
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

    /// Regression test for https://github.com/commonwarexyz/monorepo/issues/2787
    #[allow(dead_code, clippy::manual_async_fn)]
    fn issue_2787_regression(
        db: &crate::qmdb::immutable::Immutable<
            deterministic::Context,
            Digest,
            Vec<u8>,
            Sha256,
            TwoCap,
        >,
        key: Digest,
    ) -> impl std::future::Future<Output = ()> + Send + use<'_> {
        async move {
            let _ = db.get(&key).await;
        }
    }

    type MutableDb =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Unmerkleized, NonDurable>;

    #[allow(dead_code)]
    fn assert_merkleized_db_futures_are_send(db: &mut AnyTest, key: Digest, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_mutable_db_futures_are_send(db: &mut MutableDb, key: Digest, value: Vec<u8>) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_send(db.write_batch([(key, Some(value.clone()))]));
        assert_send(db.write_batch([(key, None)]));
        assert_batchable(db, key, value);
        assert_send(db.get_with_loc(&key));
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(db: MutableDb) {
        assert_send(db.commit(None));
    }

    // Partitioned variant tests

    type PartitionedVarConfig = VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    fn partitioned_config(suffix: &str, pooler: &impl BufferPooler) -> PartitionedVarConfig {
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
            page_cache: CacheRef::from_pooler(pooler, NZU16!(77), NZUsize!(9)),
        }
    }

    type PartitionedAnyTestP1 =
        super::partitioned::Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, 1>;

    type PartitionedAnyTestDigestP1 =
        super::partitioned::Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 1>;

    fn partitioned_to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    #[inline]
    async fn open_partitioned_db_p1(context: Context) -> PartitionedAnyTestP1 {
        let cfg = partitioned_config("partition_p1", &context);
        PartitionedAnyTestP1::init(context, cfg).await.unwrap()
    }

    async fn open_partitioned_digest_db_p1(context: Context) -> PartitionedAnyTestDigestP1 {
        let cfg = variable_db_config("unordered_partitioned_var_p1", &context);
        PartitionedAnyTestDigestP1::init(context, cfg).await.unwrap()
    }

    #[test_traced("WARN")]
    fn test_partitioned_variable_p1_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_partitioned_db_p1(db_context.clone()).await;
            test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_partitioned_db_p1(ctx)),
                partitioned_to_bytes,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_variable_p1_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_partitioned_digest_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_partitioned_digest_db_p1(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_variable_p1_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_partitioned_digest_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_partitioned_digest_db_p1(ctx))
            })
            .await;
        });
    }
}
