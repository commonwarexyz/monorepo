//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, unordered, value::FixedEncoding, FixedConfig as Config,
            FixedValue,
        },
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

pub mod sync;

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
        let translator = cfg.translator.clone();
        let mut log = init_fixed_authenticated_log(context.clone(), cfg).await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log.sync().await?;
        }

        let log = Self::init_from_log(
            Index::new(context.clone(), translator),
            log,
            known_inactivity_floor,
            callback,
        )
        .await?;

        Ok(log)
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        kv::tests::{assert_batchable, assert_deletable, assert_gettable, assert_send},
        mmr::{Location, Position, StandardHasher},
        qmdb::{
            any::unordered::{fixed::Operation, Update},
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
            },
            verify_proof, NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::num::{NonZeroU16, NonZeroUsize};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    pub(crate) fn any_db_config(suffix: &str) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, Merkleized<Sha256>, Durable>;
    pub(crate) type DirtyAnyTest =
        Db<Context, Digest, Digest, Sha256, TwoCap, Unmerkleized, NonDurable>;

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    pub(crate) fn create_test_config(seed: u64) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(13), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(11), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
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
                    db.update(key, value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(_, _) => {
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_non_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_digest,
            )
            .await;
        });
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
                db.update(k, v).await.unwrap();
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

    #[test_traced("WARN")]
    fn test_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_multiple_commits_delete_replayed(
                db_context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_digest,
            )
            .await;
        });
    }

    // Test that merkleization state changes don't reset `steps`.
    #[test_traced("DEBUG")]
    fn test_any_unordered_fixed_db_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
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
            let original_op_count = db.op_count();

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
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(6), NZU64!(10))
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
            let mut db = create_test_db(context.with_label("first"))
                .await
                .into_mutable();
            let ops = create_test_ops(50);
            apply_ops(&mut db, ops.clone()).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test singleton database
            let (single_proof, single_ops) = db
                .historical_proof(
                    Location::new_unchecked(2),
                    Location::new_unchecked(1),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(single_proof.leaves, Location::new_unchecked(2));
            assert_eq!(single_ops.len(), 1);

            // Create historical database with single operation without committing it.
            let mut single_db = create_test_db(context.with_label("second"))
                .await
                .into_mutable();
            apply_ops(&mut single_db, ops[0..1].to_vec()).await;
            let single_db = single_db.into_merkleized();
            let single_root = single_db.root();

            assert!(verify_proof(
                &mut hasher,
                &single_proof,
                Location::new_unchecked(1),
                &single_ops,
                &single_root
            ));

            // Test requesting more operations than available in historical position
            let (_limited_proof, limited_ops) = db
                .historical_proof(
                    Location::new_unchecked(11),
                    Location::new_unchecked(6),
                    NZU64!(20),
                )
                .await
                .unwrap();
            assert_eq!(limited_ops.len(), 5); // Should be limited by historical position
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position
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

            // Can't destroy the db unless it's durable, so we need to commit first.
            let (single_db, _) = single_db.commit(None).await.unwrap();
            single_db.destroy().await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.with_label("main"))
                .await
                .into_mutable();
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test historical proof generation for several historical states.
            let start_loc = Location::new_unchecked(21);
            let max_ops = NZU64!(10);
            for end_loc in 32..51 {
                let end_loc = Location::new_unchecked(end_loc);
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.leaves, end_loc);

                // Create reference database at the given historical size
                let mut ref_db = create_test_db(context.with_label(&format!("ref_{}", *end_loc)))
                    .await
                    .into_mutable();
                apply_ops(&mut ref_db, ops[0..(*end_loc - 1) as usize].to_vec()).await;
                let ref_db = ref_db.into_merkleized();

                let (ref_proof, ref_ops) = ref_db.proof(start_loc, max_ops).await.unwrap();
                assert_eq!(ref_proof.leaves, historical_proof.leaves);
                assert_eq!(ref_ops, historical_ops);
                assert_eq!(ref_proof.digests, historical_proof.digests);
                let end_loc = std::cmp::min(start_loc.checked_add(max_ops.get()).unwrap(), end_loc);
                assert_eq!(
                    ref_ops,
                    ops[(*start_loc - 1) as usize..(*end_loc - 1) as usize]
                );

                // Verify proof against reference root
                let ref_root = ref_db.root();
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &ref_root
                ));

                let (ref_db, _) = ref_db.commit(None).await.unwrap();
                ref_db.destroy().await.unwrap();
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await.into_mutable();
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            let db = db.commit(None).await.unwrap().0.into_merkleized();

            let historical_op_count = Location::new_unchecked(5);
            let (proof, ops) = db
                .historical_proof(historical_op_count, Location::new_unchecked(1), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(proof.leaves, historical_op_count);
            assert_eq!(ops.len(), 4);

            let mut hasher = StandardHasher::<Sha256>::new();

            // Changing the proof digests should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.digests[0] = Sha256::hash(b"invalid");
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut proof = proof.clone();
                proof.digests.push(Sha256::hash(b"invalid"));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the ops should cause verification to fail
            {
                let mut ops = ops.clone();
                ops[0] = Operation::Update(Update(Sha256::hash(b"key1"), Sha256::hash(b"value1")));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut ops = ops.clone();
                ops.push(Operation::Update(Update(
                    Sha256::hash(b"key1"),
                    Sha256::hash(b"value1"),
                )));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the start location should cause verification to fail
            {
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(1),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the root digest should cause verification to fail
            {
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &Sha256::hash(b"invalid")
                ));
            }

            // Changing the proof size should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.leaves = Location::new_unchecked(100);
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            db.destroy().await.unwrap();
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
        assert_send(db.update(key, value));
        assert_send(db.create(key, value));
        assert_deletable(db, key);
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
            qmdb::any::unordered::sync_tests::FromSyncTestable,
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
