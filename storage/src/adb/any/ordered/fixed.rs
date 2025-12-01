//! An _ordered_ variant of a Any authenticated database with fixed-size values which additionally
//! maintains the lexicographic-next active key of each active key. For example, if the active key
//! set is `{bar, baz, foo}`, then the next-key value for `bar` is `baz`, the next-key value for
//! `baz` is `foo`, and because we define the next-key of the very last key as the first key, the
//! next-key value for `foo` is `bar`.

use crate::{
    adb::{
        any::{
            init_fixed_authenticated_log,
            ordered::{IndexedLog, Operation as OperationTrait},
            FixedConfig as Config,
        },
        operation::{fixed::ordered::Operation as FixedOperation, KeyData},
        Error,
    },
    index::ordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::{mem::Clean, Location},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

pub type Operation<K, V> = FixedOperation<K, V>;

impl<K: Array, V: CodecFixed<Cfg = ()>> OperationTrait for Operation<K, V> {
    fn new_update(key: K, value: V, next_key: K) -> Self {
        Self::Update(KeyData {
            key,
            value,
            next_key,
        })
    }

    fn new_delete(key: K) -> Self {
        Self::Delete(key)
    }

    fn new_commit_floor(metadata: Option<V>, location: Location) -> Self {
        Self::CommitFloor(metadata, location)
    }
}

/// A key-value ADB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, H, T, S = Clean<DigestOf<H>>> =
    IndexedLog<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, S>;

impl<E: Storage + Clock + Metrics, K: Array, V: CodecFixed<Cfg = ()>, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
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
        let index = Index::new(context.with_label("index"), translator);
        let log = IndexedLog::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::{
            any::AnyDb as _,
            store::{batch_tests, Db as _},
            verify_proof,
        },
        index::Unordered as _,
        mmr::{mem::Mmr as MemMmr, Position, StandardHasher as Standard},
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use rand::{rngs::StdRng, seq::IteratorRandom, RngCore, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    fn any_db_config(suffix: &str) -> Config<TwoCap> {
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
    type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    fn create_test_config(seed: u64) -> Config<TwoCap> {
        create_generic_test_config::<TwoCap>(seed, TwoCap)
    }

    fn create_generic_test_config<T: Translator>(seed: u64, t: T) -> Config<T> {
        Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: t,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(KeyData {
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
    async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Digest>>) {
        for op in ops {
            match op {
                Operation::Update(data) => {
                    db.update(data.key, data.value).await.unwrap();
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
    fn test_ordered_any_fixed_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert!(db.is_empty());
            assert!(db.get_metadata().await.unwrap().is_none());
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(
                &db.root(),
                MemMmr::default().merkleize(&mut hasher, None).root()
            );

            // Make sure closing/reopening gets us back to the same state, even after adding an
            // uncommitted op, and even without a clean shutdown.
            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            let root = db.root();
            db.update(d1, d2).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = Sha256::fill(3u8);
            let range = db.commit(Some(metadata)).await.unwrap();
            assert_eq!(range.start, 0);
            assert_eq!(range.end, 1);
            assert_eq!(db.op_count(), 1); // floor op added
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            let root = db.root();
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            assert_eq!(db.root(), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc());
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    // Test the edge case that arises where we're inserting the second key and it precedes the first
    // key, but shares the same translated key.
    fn test_ordered_any_fixed_db_translated_key_collision_edge_case() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let seed = context.next_u64();
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db =
                Any::<Context, FixedBytes<2>, i32, Sha256, OneCap>::init(context.clone(), config)
                    .await
                    .unwrap();
            let key1 = FixedBytes::<2>::new([1u8, 1u8]);
            let key2 = FixedBytes::<2>::new([1u8, 3u8]);
            // Create some keys that will not be added to the snapshot.
            let early_key = FixedBytes::<2>::new([0u8, 2u8]);
            let late_key = FixedBytes::<2>::new([3u8, 0u8]);
            let middle_key = FixedBytes::<2>::new([1u8, 2u8]);

            db.update(key1.clone(), 1).await.unwrap();
            db.update(key2.clone(), 2).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key2.clone());

            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());

            db.commit(None).await.unwrap();
            assert!(db.is_empty());

            // Update the keys in opposite order from earlier.
            db.update(key2.clone(), 2).await.unwrap();
            db.update(key1.clone(), 1).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            // Delete the keys in opposite order from earlier.
            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());
            db.commit(None).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::fill(1u8);
            let key2 = Sha256::fill(2u8);
            let val1 = Sha256::fill(3u8);
            let val2 = Sha256::fill(4u8);

            assert!(db.get(&key1).await.unwrap().is_none());
            assert!(db.get(&key2).await.unwrap().is_none());

            assert!(db.create(key1, val1).await.unwrap());
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val1, key1));
            assert!(db.get_all(&key2).await.unwrap().is_none());

            assert!(db.create(key2, val2).await.unwrap());
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val1, key2));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val2, key1));

            db.delete(key1).await.unwrap();
            assert!(db.get_all(&key1).await.unwrap().is_none());
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val2, key2));

            let new_val = Sha256::fill(5u8);
            db.update(key1, new_val).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (new_val, key2));

            db.update(key2, new_val).await.unwrap();
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (new_val, key1));

            assert_eq!(db.op_count(), 8); // 2 new keys (4), 2 updates (2), 1 deletion (2)
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc(), 0);
            db.sync().await.unwrap();

            // Make sure create won't modify active keys.
            assert!(!db.create(key1, val1).await.unwrap());
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (new_val, key2));

            // take one floor raising step, which should move the first active op (at location 5) to
            // tip, leaving the floor at the next location (6).
            let loc = db.inactivity_floor_loc();
            db.inactivity_floor_loc = db.as_floor_helper().raise_floor(loc).await.unwrap();
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(6));
            assert_eq!(db.op_count(), 9);
            db.sync().await.unwrap();

            // Delete all keys and commit the changes.
            assert!(db.delete(key1).await.unwrap());
            assert!(db.delete(key2).await.unwrap());
            assert!(db.get(&key1).await.unwrap().is_none());
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 12);
            db.commit(None).await.unwrap();
            let root = db.root();

            // Since this db no longer has any active keys, the inactivity floor should have been
            // set to tip.
            assert_eq!(db.inactivity_floor_loc(), db.op_count() - 1);

            // Multiple deletions of the same key should be a no-op.
            assert!(!db.delete(key1).await.unwrap());
            assert_eq!(db.op_count(), 13);
            assert_eq!(db.root(), root);

            // Deletions of non-existent keys should be a no-op.
            let key3 = Sha256::fill(5u8);
            assert!(!db.delete(key3).await.unwrap());
            assert_eq!(db.op_count(), 13);
            db.sync().await.unwrap();
            assert_eq!(db.root(), root);

            // Make sure closing/reopening gets us back to the same state.
            assert_eq!(db.op_count(), 13);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 13);
            assert_eq!(db.root(), root);

            // Re-activate the keys by updating them.
            db.update(key1, val1).await.unwrap();
            db.update(key2, val2).await.unwrap();
            db.delete(key1).await.unwrap();
            db.update(key2, val1).await.unwrap();
            db.update(key1, val2).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val2, key2));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val1, key1));
            assert_eq!(db.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();
            let mut db = open_db(context).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.snapshot.keys(), 2);

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit(None).await.unwrap();

            assert!(db.root() != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.root(), root);

            // We should not be able to prune beyond the inactivity floor.
            assert!(matches!(
                db.prune(db.inactivity_floor_loc() + 1).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
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

            assert_eq!(db.op_count(), 2619);
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert_eq!(db.op_count(), 2619);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.inactivity_floor_loc(), 3382);
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.inactivity_floor_loc(), 3382);
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

            for i in start_loc.as_u64()..end_loc.as_u64() {
                let loc = Location::from(i);
                let (proof, log) = db.proof(loc, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &log, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_non_empty_db_recovery() {
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
    fn test_ordered_any_fixed_empty_db_recovery() {
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

            // Insert operations without commit then simulate failure, syncing nothing.
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
    fn test_ordered_any_fixed_db_log_replay() {
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
    fn test_ordered_any_fixed_db_multiple_commits_delete_gets_replayed() {
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
            db.commit(None).await.unwrap();
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
    fn test_ordered_any_fixed_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();
            let mut hasher = Standard::<Sha256>::new();
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

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(50);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

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

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = Standard::<Sha256>::new();
            let root = db.root();

            let start_loc = Location::new_unchecked(20);
            let max_ops = NZU64!(10);
            let (proof, ops) = db.proof(start_loc, max_ops).await.unwrap();

            // Now keep adding operations and make sure we can still generate a historical proof that matches the original.
            let historical_size = db.op_count();

            for _ in 1..10 {
                let more_ops = create_test_ops(100);
                apply_ops(&mut db, more_ops).await;
                db.commit(None).await.unwrap();

                let (historical_proof, historical_ops) = db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await
                    .unwrap();
                assert_eq!(proof.size, historical_proof.size);
                assert_eq!(ops, historical_ops);
                assert_eq!(proof.digests, historical_proof.digests);

                // Verify proof against reference root
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_invalid() {
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

            let mut hasher = Standard::<Sha256>::new();

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
            let changed_op = Operation::Update(KeyData {
                key: Sha256::hash(b"key1"),
                value: Sha256::hash(b"value1"),
                next_key: Sha256::hash(b"key2"),
            });
            {
                let mut ops = ops.clone();
                ops[0] = changed_op.clone();
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
                ops.push(changed_op);
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
                proof.size = Position::from(100u64);
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

    #[test]
    fn test_ordered_any_fixed_db_span_maintenance_under_collisions() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            async fn insert_random<T: Translator>(
                db: &mut Any<Context, Digest, i32, Sha256, T>,
                rng: &mut StdRng,
            ) {
                let mut keys = BTreeMap::new();

                // Insert 1000 random keys into both the db and an ordered map.
                for i in 0..1000 {
                    let key = Digest::random(rng);
                    keys.insert(key, i);
                    db.update(key, i).await.unwrap();
                }

                db.commit(None).await.unwrap();

                // Make sure the db and ordered map agree on contents & key order.
                let mut iter = keys.iter();
                let first_key = iter.next().unwrap().0;
                let mut next_key = db.get_all(first_key).await.unwrap().unwrap().1;
                for (key, value) in iter {
                    let (v, next) = db.get_all(key).await.unwrap().unwrap();
                    assert_eq!(*value, v);
                    assert_eq!(*key, next_key);
                    assert_eq!(db.get_span(key).await.unwrap().unwrap().1.next_key, next);
                    next_key = next;
                }

                // Delete some random keys and check order agreement again.
                for _ in 0..500 {
                    let key = keys.keys().choose(rng).cloned().unwrap();
                    keys.remove(&key);
                    db.delete(key).await.unwrap();
                }

                let mut iter = keys.iter();
                let first_key = iter.next().unwrap().0;
                let mut next_key = db.get_all(first_key).await.unwrap().unwrap().1;
                for (key, value) in iter {
                    let (v, next) = db.get_all(key).await.unwrap().unwrap();
                    assert_eq!(*value, v);
                    assert_eq!(*key, next_key);
                    assert_eq!(db.get_span(key).await.unwrap().unwrap().1.next_key, next);
                    next_key = next;
                }

                // Delete the rest of the keys and make sure we get back to empty.
                for _ in 0..500 {
                    let key = keys.keys().choose(rng).cloned().unwrap();
                    keys.remove(&key);
                    db.delete(key).await.unwrap();
                }
                assert_eq!(keys.len(), 0);
                assert!(db.is_empty());
                assert_eq!(db.get_span(&Digest::random(rng)).await.unwrap(), None);
            }

            let mut rng = StdRng::seed_from_u64(context.next_u64());
            let seed = context.next_u64();

            // Use a OneCap to ensure many collisions.
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db = Any::<Context, Digest, i32, Sha256, OneCap>::init(context.clone(), config)
                .await
                .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();

            // Repeat test with TwoCap to test low/no collisions.
            let config = create_generic_test_config::<TwoCap>(seed, TwoCap);
            let mut db = Any::<Context, Digest, i32, Sha256, TwoCap>::init(context.clone(), config)
                .await
                .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            batch_tests::run_batch_tests(|| {
                let ctx = context.clone();
                async move { create_test_db(ctx.clone()).await }
            })
            .await
            .unwrap();
        });
    }
}
