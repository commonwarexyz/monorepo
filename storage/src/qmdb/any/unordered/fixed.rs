//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::Location,
    qmdb::{
        any::{init_fixed, unordered, value::FixedEncoding, FixedConfig as Config, FixedValue},
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

pub type Update<K, V> = unordered::Update<K, FixedEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, FixedEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T, Merkleized<H>, Durable>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the snapshot
    /// is built from the log, `callback` is invoked for each operation with its activity status and
    /// previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: Config<T>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        init_fixed(context, cfg, known_inactivity_floor, callback, |ctx, t| {
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
        journal::contiguous::fixed::Journal,
        mmr::Location,
        qmdb::{
            any::{init_fixed, FixedConfig as Config, FixedValue},
            Durable, Error, Merkleized,
        },
        translator::Translator,
    };
    use commonware_cryptography::Hasher;
    use commonware_runtime::{Clock, Metrics, Storage};
    use commonware_utils::Array;

    /// A key-value QMDB with a partitioned snapshot index.
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
            V: FixedValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<E, K, V, H, T, P, Merkleized<H>, Durable>
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
            Self::init_with_callback(context, cfg, None, |_, _| {}).await
        }

        /// Initialize the DB, invoking `callback` for each operation processed during recovery.
        ///
        /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
        /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the snapshot
        /// is built from the log, `callback` is invoked for each operation with its activity status and
        /// previous location (if any).
        pub(crate) async fn init_with_callback(
            context: E,
            cfg: Config<T>,
            known_inactivity_floor: Option<Location>,
            callback: impl FnMut(bool, Option<Location>),
        ) -> Result<Self, Error> {
            init_fixed(context, cfg, known_inactivity_floor, callback, |ctx, t| {
                Index::new(ctx, t)
            })
            .await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Fixed-value DB with 256 partitions.
        pub type Db<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
            super::Db<E, K, V, H, T, 1, S, D>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Fixed-value DB with 65,536 partitions.
        pub type Db<E, K, V, H, T, S = crate::qmdb::Merkleized<H>, D = crate::qmdb::Durable> =
            super::Db<E, K, V, H, T, 2, S, D>;
    }
}

// pub(crate) so helpers can be used by the sync module.
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        kv::tests::{assert_batchable, assert_gettable, assert_send},
        mmr::{Location, Position, StandardHasher},
        qmdb::{
            any::{
                test::fixed_db_config,
                unordered::{fixed::Operation, Update},
            },
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
                LogStore,
            },
            verify_proof, NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZU64};
    use rand::RngCore;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, Merkleized<Sha256>, Durable>;
    pub(crate) type DirtyAnyTest =
        Db<Context, Digest, Digest, Sha256, TwoCap, Unmerkleized, NonDurable>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        let cfg = fixed_db_config::<TwoCap>("partition", &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let cfg = fixed_db_config::<TwoCap>(&seed.to_string(), &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    /// Create n random operations using the default seed (0). Some portion of
    /// the updates are deletes. create_test_ops(n) is a prefix of
    /// create_test_ops(n') for n < n'.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed.
    /// Use different seeds when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(n: usize, seed: u64) -> Vec<Operation<Digest, Digest>> {
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut DirtyAnyTest, ops: Vec<Operation<Digest, Digest>>) {
        for op in ops {
            match op {
                Operation::Update(Update(key, value)) => {
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await.unwrap();
                }
                Operation::CommitFloor(_, _) => {
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let mut db = open_db(db_context.clone()).await.into_mutable();

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.write_batch([(k, Some(v))]).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            drop(db);
            let db = open_db(db_context.with_label("reopened")).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await.into_mutable();
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root_hash = db.root();
            let original_op_count = db.bounds().await.end;

            // Historical proof should match "regular" proof when historical size == current database size
            let max_ops = NZU64!(10);
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(6), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) =
                db.proof(Location::new_unchecked(6), max_ops).await.unwrap();

            assert_eq!(historical_proof.leaves, regular_proof.leaves);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert_eq!(historical_ops, ops[5..15]);
            let mut hasher = StandardHasher::<Sha256>::new();
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(6),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            // (use different seed to avoid key collisions)
            let mut db = db.into_mutable();
            let more_ops = create_test_ops_seeded(5, 1);
            apply_ops(&mut db, more_ops.clone()).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(6), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(historical_proof.leaves, original_op_count);
            assert_eq!(historical_proof.leaves, regular_proof.leaves);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(6),
                &historical_ops,
                &root_hash
            ));

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(
                    db.bounds().await.end + 1,
                    Location::new_unchecked(6),
                    NZU64!(10)
                )
                .await,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let ops = create_test_ops(50);

            let mut db = create_test_db(context.with_label("first"))
                .await
                .into_mutable();
            apply_ops(&mut db, ops.clone()).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();

            let root = db.root();
            let full_size = db.bounds().await.end;

            // Verify a single-op proof at the full commit size.
            let (proof, proof_ops) = db
                .proof(Location::new_unchecked(1), NZU64!(1))
                .await
                .unwrap();
            assert_eq!(proof_ops.len(), 1);
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(1),
                &proof_ops,
                &root
            ));

            // historical_proof at full size should match proof.
            let (hp, hp_ops) = db
                .historical_proof(full_size, Location::new_unchecked(1), NZU64!(1))
                .await
                .unwrap();
            assert_eq!(hp.digests, proof.digests);
            assert_eq!(hp_ops, proof_ops);

            // Test requesting more operations than available in historical position.
            let (_proof, limited_ops) = db
                .historical_proof(
                    Location::new_unchecked(11),
                    Location::new_unchecked(6),
                    NZU64!(20),
                )
                .await
                .unwrap();
            assert_eq!(limited_ops.len(), 5); // limited by historical size
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position.
            let (min_proof, min_ops) = db
                .historical_proof(
                    Location::new_unchecked(4),
                    Location::new_unchecked(1),
                    NZU64!(3),
                )
                .await
                .unwrap();
            assert_eq!(min_proof.leaves, Location::new_unchecked(4));
            assert_eq!(min_ops.len(), 3);
            assert_eq!(min_ops, ops[0..3]);

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ops = create_test_ops(100);
            let mut hasher = StandardHasher::<Sha256>::new();
            let start_loc = Location::new_unchecked(2);
            let max_ops = NZU64!(10);

            // Build checkpoints only at commit points and record reference proofs/roots there.
            let mut db = create_test_db(context.with_label("main"))
                .await
                .into_mutable();
            let mut offset = 0usize;
            let mut checkpoints = Vec::new();
            for chunk in [20usize, 15, 25, 30, 10] {
                apply_ops(&mut db, ops[offset..offset + chunk].to_vec()).await;
                offset += chunk;

                let (clean_db, _) = db.commit(None).await.unwrap();
                let clean_db = clean_db.into_merkleized();
                let end_loc = clean_db.bounds().await.end;
                let root = clean_db.root();
                let (proof, proof_ops) = clean_db.proof(start_loc, max_ops).await.unwrap();
                checkpoints.push((end_loc, root, proof, proof_ops));

                db = clean_db.into_mutable();
            }

            // Grow state past the checkpoints and verify all historical proofs from that later state.
            let final_db = db.commit(None).await.unwrap().0.into_merkleized();
            for (historical_size, root, reference_proof, reference_ops) in checkpoints {
                let (historical_proof, historical_ops) = final_db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await
                    .unwrap();
                assert_eq!(historical_proof.leaves, reference_proof.leaves);
                assert_eq!(historical_proof.digests, reference_proof.digests);
                assert_eq!(historical_ops, reference_ops);
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &root
                ));
            }

            // Verify the current full-size proof against the current root as a final sanity check.
            let full_root = final_db.root();
            let (full_proof, full_ops) = final_db.proof(start_loc, max_ops).await.unwrap();
            assert!(verify_proof(
                &mut hasher,
                &full_proof,
                start_loc,
                &full_ops,
                &full_root
            ));

            final_db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_unordered_fixed_batch() {
        batch_tests::test_batch(|ctx| async move { create_test_db(ctx).await.into_mutable() });
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
    fn assert_mutable_db_futures_are_send(db: &mut DirtyAnyTest, key: Digest, value: Digest) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_send(db.write_batch([(key, Some(value))]));
        assert_send(db.write_batch([(key, None)]));
        assert_batchable(db, key, value);
        assert_send(db.get_with_loc(&key));
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(db: DirtyAnyTest) {
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

            fn pinned_nodes_from_map(&self, pos: Position) -> Vec<Digest> {
                let map = self.log.mmr.get_pinned_nodes();
                nodes_to_pin(pos).map(|p| *map.get(&p).unwrap()).collect()
            }
        }
    }
}
