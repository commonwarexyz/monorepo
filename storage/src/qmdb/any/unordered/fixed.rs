//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::{mem::Clean, Location},
    qmdb::{
        any::{
            init_fixed_authenticated_log,
            unordered::{IndexedLog, Operation as OperationTrait},
            FixedConfig as Config,
        },
        operation::fixed::{unordered::Operation, Value},
        Error,
    },
    translator::Translator,
};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

impl<K: Array, V: Value> OperationTrait for Operation<K, V> {
    fn new_update(key: K, value: V) -> Self {
        Self::Update(key, value)
    }

    fn new_delete(key: K) -> Self {
        Self::Delete(key)
    }

    fn new_commit_floor(metadata: Option<V>, location: Location) -> Self {
        Self::CommitFloor(metadata, location)
    }
}

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, H, T, S = Clean<DigestOf<H>>> =
    IndexedLog<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, S>;

impl<E: Storage + Clock + Metrics, K: Array, V: Value, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] QMDB initialized from `cfg`. Any uncommitted log operations will be
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
        let log = init_fixed_authenticated_log(context.clone(), cfg).await?;
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
        mmr::{Position, StandardHasher},
        qmdb::{
            operation::fixed::unordered::Operation,
            store::{batch_tests, CleanStore as _},
            verify_proof,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::collections::HashMap;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

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
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    pub(crate) type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

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
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Digest>>) {
        for op in ops {
            match op {
                Operation::Update(key, value) => {
                    db.update(key, value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(837));
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(837));
            assert_eq!(db.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = NZU64!(4);
            let end_loc = db.op_count();
            let start_pos = db.log.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor via commit and make sure historical inactive operations
            // are still provable.
            db.commit(None).await.unwrap();
            let root = db.root();
            assert!(start_loc < db.inactivity_floor_loc());

            for loc in *start_loc..*end_loc {
                let loc = Location::new_unchecked(loc);
                let (proof, log) = db.proof(loc, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &log, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            async fn apply_more_ops(db: &mut AnyTest) {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let db = open_db(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut AnyTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure, syncing nothing except one
            // element of the mmr.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
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
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            let metadata = Sha256::hash(&42u64.to_be_bytes());
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = Sha256::hash(&(i * 1000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(Some(metadata)).await.unwrap();
            }
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit(None).await.unwrap(); // make sure None metadata "overwrites" previous
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root();
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();
            let root_hash = db.root();
            let original_op_count = db.op_count();

            // Historical proof should match "regular" proof when historical size == current database size
            let max_ops = NZU64!(10);
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(5), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) =
                db.proof(Location::new_unchecked(5), max_ops).await.unwrap();

            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert_eq!(historical_ops, ops[5..15]);
            let mut hasher = StandardHasher::<Sha256>::new();
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(5),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            let more_ops = create_test_ops(5);
            apply_ops(&mut db, more_ops.clone()).await;
            db.commit(None).await.unwrap();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(5), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(
                historical_proof.size,
                Position::try_from(original_op_count).unwrap()
            );
            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(5),
                &historical_ops,
                &root_hash
            ));

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(5), NZU64!(10))
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
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(50);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test singleton database
            let (single_proof, single_ops) = db
                .historical_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(
                single_proof.size,
                Position::try_from(Location::new_unchecked(1)).unwrap()
            );
            assert_eq!(single_ops.len(), 1);

            // Create historical database with single operation
            let mut single_db = create_test_db(context.clone()).await;
            apply_ops(&mut single_db, ops[0..1].to_vec()).await;
            // Don't commit - this changes the root due to commit operations
            single_db.sync().await.unwrap();
            let single_root = single_db.root();

            assert!(verify_proof(
                &mut hasher,
                &single_proof,
                Location::new_unchecked(0),
                &single_ops,
                &single_root
            ));

            // Test requesting more operations than available in historical position
            let (_limited_proof, limited_ops) = db
                .historical_proof(
                    Location::new_unchecked(10),
                    Location::new_unchecked(5),
                    NZU64!(20),
                )
                .await
                .unwrap();
            assert_eq!(limited_ops.len(), 5); // Should be limited by historical position
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position
            let (min_proof, min_ops) = db
                .historical_proof(
                    Location::new_unchecked(3),
                    Location::new_unchecked(0),
                    NZU64!(3),
                )
                .await
                .unwrap();
            assert_eq!(
                min_proof.size,
                Position::try_from(Location::new_unchecked(3)).unwrap()
            );
            assert_eq!(min_ops.len(), 3);
            assert_eq!(min_ops, ops[0..3]);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test historical proof generation for several historical states.
            let start_loc = Location::new_unchecked(20);
            let max_ops = NZU64!(10);
            for end_loc in 31..50 {
                let end_loc = Location::new_unchecked(end_loc);
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.size, Position::try_from(end_loc).unwrap());

                // Create  reference database at the given historical size
                let mut ref_db = create_test_db(context.clone()).await;
                apply_ops(&mut ref_db, ops[0..*end_loc as usize].to_vec()).await;
                // Sync to process dirty nodes but don't commit - commit changes the root due to commit operations
                ref_db.sync().await.unwrap();

                let (ref_proof, ref_ops) = ref_db.proof(start_loc, max_ops).await.unwrap();
                assert_eq!(ref_proof.size, historical_proof.size);
                assert_eq!(ref_ops, historical_ops);
                assert_eq!(ref_proof.digests, historical_proof.digests);
                let end_loc = std::cmp::min(start_loc.checked_add(max_ops.get()).unwrap(), end_loc);
                assert_eq!(ref_ops, ops[*start_loc as usize..*end_loc as usize]);

                // Verify proof against reference root
                let ref_root = ref_db.root();
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &ref_root
                ),);

                ref_db.destroy().await.unwrap();
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            db.commit(None).await.unwrap();

            let historical_op_count = Location::new_unchecked(5);
            let historical_mmr_size = Position::try_from(historical_op_count).unwrap();
            let (proof, ops) = db
                .historical_proof(historical_op_count, Location::new_unchecked(1), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(proof.size, historical_mmr_size);
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
                ops[0] = Operation::Update(Sha256::hash(b"key1"), Sha256::hash(b"value1"));
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
                ops.push(Operation::Update(
                    Sha256::hash(b"key1"),
                    Sha256::hash(b"value1"),
                ));
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
                proof.size = Position::new(100);
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
    fn test_batch() {
        batch_tests::test_batch(|ctx| async move { create_test_db(ctx).await });
    }
}
