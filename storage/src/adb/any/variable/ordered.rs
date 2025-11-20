//! An _ordered_ variant of a Any authenticated database with variable-sized values which
//! additionally maintains the lexicographic-next active key of each active key. For example, if the
//! active key set is `{bar, baz, foo}`, then the next-key value for `bar` is `baz`, the next-key
//! value for `baz` is `foo`, and because we define the next-key of the very last key as the first
//! key, the next-key value for `foo` is `bar`.

use crate::{
    adb::{
        any::{
            find_span, get_update_op, last_key_in_iter,
            variable::{init_authenticated_log, Config},
            OperationLog, UpdateLocResult,
        },
        operation::{variable::ordered::Operation, KeyData},
        store::Db,
        Error,
    },
    index::{ordered::Index, Cursor as _, Ordered as _, Unordered as _},
    journal::contiguous::variable::Journal,
    mmr::{Location, Proof, StandardHasher},
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::num::NonZeroU64;

type Contiguous<E, K, V> = Journal<E, Operation<K, V>>;

/// Type alias for the operation log of this [Any] database variant.
type AnyLog<E, K, V, H, T> =
    OperationLog<E, Contiguous<E, K, V>, Operation<K, V>, Index<T, Location>, H, T>;

/// A key-value ADB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key, and access to the lexicographically-next active key of a given
/// active key.
pub struct Any<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator> {
    /// The authenticated log of operations.
    pub(crate) log: AnyLog<E, K, V, H, T>,
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let snapshot = Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let log = init_authenticated_log(context, cfg).await?;
        let log = OperationLog::init(log, snapshot, |_, _| {}).await?;

        Ok(Self { log })
    }

    /// Finds and updates the location of the previous key to `key` in the snapshot for cases where
    /// the previous key does not share the same translated key, returning an UpdateLocResult
    /// indicating the specific outcome.
    ///
    /// # Panics
    ///
    /// Panics if the snapshot is empty.
    async fn update_non_colliding_prev_key_loc(
        &mut self,
        key: &K,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V>, Error> {
        assert!(!self.is_empty(), "snapshot should not be empty");
        let iter = self.log.snapshot.prev_translated_key(key);
        if let Some((loc, prev_key)) = last_key_in_iter(&self.log.log, iter).await? {
            callback(Some(loc));
            self.log
                .update_known_loc(&prev_key.key, loc, next_loc)
                .await?;
            return Ok(UpdateLocResult::NotExists(prev_key));
        }

        // Unusual case where there is no previous key, in which case we cycle around to the
        // greatest key.
        let iter = self.log.snapshot.last_translated_key();
        let last_key = last_key_in_iter(&self.log.log, iter).await?;
        let (loc, last_key) = last_key.expect("no last key found in non-empty snapshot");

        callback(Some(loc));
        self.log
            .update_known_loc(&last_key.key, loc, next_loc)
            .await?;

        Ok(UpdateLocResult::NotExists(last_key))
    }

    /// Update the location of `key` to `next_loc` in the snapshot, and update the location of
    /// previous key to `next_loc + 1` if its next key will need to be updated to `key`. Returns an
    /// UpdateLocResult indicating the specific outcome. If `create_only` is true, then the key is
    /// only updated if it is not already in the snapshot, and otherwise NotExists is returned
    /// without performing any state changes.
    async fn update_loc(
        &mut self,
        key: &K,
        create_only: bool,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V>, Error> {
        let keys = self.log.active_keys;
        let mut best_prev_key: Option<(Location, KeyData<K, V>)> = None;
        {
            // If the translated key is not in the snapshot, insert the new location and return the
            // previous key info.
            let Some(mut cursor) = self.log.snapshot.get_mut_or_insert(key, next_loc) else {
                callback(None);
                return self
                    .update_non_colliding_prev_key_loc(key, next_loc + 1, callback)
                    .await;
            };

            // Iterate over conflicts in the snapshot entry to try and find the key, or its
            // predecessor if it doesn't exist.
            while let Some(&loc) = cursor.next() {
                let data = get_update_op(&self.log.log, loc).await?;
                if data.key == *key {
                    // Found the key in the snapshot.
                    if create_only {
                        return Ok(UpdateLocResult::Exists(data.next_key));
                    }
                    // Update its location and return its next-key.
                    assert!(next_loc > loc);
                    cursor.update(next_loc);
                    callback(Some(loc));
                    return Ok(UpdateLocResult::Exists(data.next_key));
                }
                if data.key > *key {
                    continue;
                }
                if let Some((_, ref key_data)) = best_prev_key {
                    if data.key > key_data.key {
                        best_prev_key = Some((loc, data));
                    }
                } else {
                    best_prev_key = Some((loc, data));
                }
            }

            if keys != 1 || best_prev_key.is_some() {
                // For the special case handled below around the snapshot having only one translated
                // key, avoid inserting the key into the snapshot here otherwise we'll confuse the
                // subsequent search for the best_prev_key.
                cursor.insert(next_loc);
                callback(None);
            }
        }

        if keys == 1 && best_prev_key.is_none() {
            // In this special case, our key precedes all keys in the snapshot, thus we need to
            // "cycle around" to the very last key. But this key must share the same translated
            // key since there's only one.
            let iter = self.log.snapshot.get(key);
            best_prev_key = last_key_in_iter(&self.log.log, iter).await?;
            assert!(
                best_prev_key.is_some(),
                "best_prev_key should have been found"
            );
            self.log.snapshot.insert(key, next_loc);
            callback(None);
        }

        let Some((loc, prev_key_data)) = best_prev_key else {
            // The previous key was not found, meaning it does not share the same translated key.
            // This should be the common case when collisions are rare.
            return self
                .update_non_colliding_prev_key_loc(key, next_loc + 1, callback)
                .await;
        };

        // The previous key was found within the same snapshot entry as `key`.
        let mut cursor = self
            .log
            .snapshot
            .get_mut(&prev_key_data.key)
            .expect("prev_key already known to exist");
        assert!(
            cursor.find(|&l| *l == loc),
            "prev_key should have been found"
        );
        cursor.update(next_loc + 1);
        callback(Some(loc));

        Ok(UpdateLocResult::NotExists(prev_key_data))
    }

    /// Get the (value, next-key) pair of `key` in the db, or None if it has no value.
    pub async fn get_all(&self, key: &K) -> Result<Option<(V, K)>, Error> {
        Ok(self.log.get_key_op_loc(key).await?.map(|(op, _)| match op {
            Operation::Update(data) => (data.value, data.next_key),
            _ => unreachable!("location does not reference update operation"),
        }))
    }

    /// Get the operation that defines the span whose range contains `key`, or None if the DB is
    /// empty.
    pub async fn get_span(&self, key: &K) -> Result<Option<(Location, KeyData<K, V>)>, Error> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        let iter = self.log.snapshot.get(key);
        let span = find_span(&self.log.log, iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let iter = self.log.snapshot.prev_translated_key(key);
        let span = find_span(&self.log.log, iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        // If we get here, then `key` must precede the first key in the snapshot, in which case we
        // have to cycle around to the very last key.
        let iter = self.log.snapshot.last_translated_key();
        let span = find_span(&self.log.log, iter, key)
            .await?
            .expect("a span that includes any given key should always exist if db is non-empty");

        Ok(Some(span))
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Updates `key` to have value `value` while maintaining appropriate next_key spans. The
    /// operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. For each operation added to the log by this method, the callback is
    /// invoked with the old location of the affected key (if any).
    pub(crate) async fn update_with_callback(
        &mut self,
        key: K,
        value: V,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<(), Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.log.snapshot.insert(&key, next_loc);
            let op = Operation::Update(KeyData {
                key: key.clone(),
                value,
                next_key: key,
            });
            callback(None);
            self.log.append(op).await?;
            self.log.active_keys += 1;
            return Ok(());
        }
        let res = self.update_loc(&key, false, next_loc, callback).await?;
        let op = match res {
            UpdateLocResult::Exists(next_key) => Operation::Update(KeyData {
                key,
                value,
                next_key,
            }),
            UpdateLocResult::NotExists(prev_data) => {
                self.log.active_keys += 1;
                self.log
                    .append(Operation::Update(KeyData {
                        key: key.clone(),
                        value,
                        next_key: prev_data.next_key,
                    }))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                Operation::Update(KeyData {
                    key: prev_data.key,
                    value: prev_data.value,
                    next_key: key,
                })
            }
        };

        self.log.append(op).await?;

        // For either a new key or an update of existing key, we inactivate exactly one previous
        // operation. A new key inactivates a previous span, and an update of existing key
        // inactivates a previous value.
        self.log.steps += 1;

        Ok(())
    }

    pub(crate) async fn create_with_callback(
        &mut self,
        key: K,
        value: V,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<bool, Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.log.snapshot.insert(&key, next_loc);
            let op = Operation::Update(KeyData {
                key: key.clone(),
                value,
                next_key: key,
            });
            callback(None);
            self.log.append(op).await?;
            self.log.active_keys += 1;
            return Ok(true);
        }
        let res = self.update_loc(&key, true, next_loc, callback).await?;
        match res {
            UpdateLocResult::Exists(_) => {
                return Ok(false);
            }
            UpdateLocResult::NotExists(prev_data) => {
                self.log.active_keys += 1;
                let value_update_op = Operation::Update(KeyData {
                    key: key.clone(),
                    value,
                    next_key: prev_data.next_key,
                });
                let next_key_update_op = Operation::Update(KeyData {
                    key: prev_data.key,
                    value: prev_data.value,
                    next_key: key,
                });
                self.log.append(value_update_op).await?;
                self.log.append(next_key_update_op).await?;
            }
        };

        // Creating a new key involves inactivating a previous span, requiring we increment `steps`.
        self.log.steps += 1;

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. For each operation added to the log by this method, the callback is
    /// invoked with the old location of the affected key (if any).
    pub(crate) async fn delete_with_callback(
        &mut self,
        key: K,
        mut callback: impl FnMut(bool, Option<Location>),
    ) -> Result<(), Error> {
        let mut prev_key = None;
        let mut next_key = None;
        {
            // If the translated key is in the snapshot, get a cursor to look for the key.
            let Some(mut cursor) = self.log.snapshot.get_mut(&key) else {
                // no-op
                return Ok(());
            };

            // Iterate over conflicts in the snapshot entry to delete the key if it exists, and
            // potentially find the previous key.
            while let Some(&loc) = cursor.next() {
                let data = get_update_op(&self.log.log, loc).await?;
                if data.key == key {
                    // The key is in the snapshot, so delete it.
                    cursor.delete();
                    next_key = Some(data.next_key);
                    callback(false, Some(loc));
                    continue;
                }
                if data.key > key {
                    continue;
                }
                let Some((_, ref current_prev_key, _)) = prev_key else {
                    prev_key = Some((loc, data.key.clone(), data.value));
                    continue;
                };
                if data.key > *current_prev_key {
                    prev_key = Some((loc, data.key.clone(), data.value));
                }
            }
        }

        let Some(next_key) = next_key else {
            // no-op
            return Ok(());
        };

        self.log.active_keys -= 1;
        let op = Operation::Delete(key.clone());
        self.log.append(op).await?;
        self.log.steps += 1;

        if self.is_empty() {
            // This was the last key in the DB so there is no span to update.
            return Ok(());
        }

        // Find & update the affected span.
        if prev_key.is_none() {
            let iter = self.log.snapshot.prev_translated_key(&key);
            let last_key = last_key_in_iter(&self.log.log, iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }
        if prev_key.is_none() {
            // Unusual case where we deleted the very first key in the DB, so the very last key in
            // the DB defines the span in need of update.
            let iter = self.log.snapshot.last_translated_key();
            let last_key = last_key_in_iter(&self.log.log, iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }

        let prev_key = prev_key.expect("prev_key should have been found");

        let loc = self.op_count();
        callback(true, Some(prev_key.0));
        self.log
            .update_known_loc(&prev_key.1, prev_key.0, loc)
            .await?;

        let op = Operation::Update(KeyData {
            key: prev_key.1,
            value: prev_key.2,
            next_key,
        });
        self.log.append(op).await?;
        self.log.steps += 1;

        Ok(())
    }

    /// Return the root of the db.
    pub fn root(&self, hasher: &mut StandardHasher<H>) -> H::Digest {
        self.log.root(hasher)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.log
            .historical_proof(op_count, start_loc, max_ops)
            .await
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.log.raise_floor().await?;

        // Commit the log to ensure this commit is durable.
        self.log
            .commit(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    ///
    /// # Errors
    ///
    /// Returns Error if there is some underlying storage failure.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.log.last_commit else {
            return Ok(None);
        };

        let Operation::CommitFloor(metadata, _) = self.log.read(last_commit).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Simulate an unclean shutdown by consuming the db. If commit_log is true, the log will be
    /// committed before consuming.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(mut self, commit_log: bool) -> Result<(), Error> {
        if commit_log {
            self.log.log.commit().await?;
        }

        Ok(())
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator> Db<K, V>
    for Any<E, K, V, H, T>
{
    fn op_count(&self) -> Location {
        self.log.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.log.inactivity_floor_loc
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.log.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update_with_callback(key, value, |_| {}).await
    }

    async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        self.create_with_callback(key, value, |_| {}).await
    }

    async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let mut r = false;
        self.delete_with_callback(key, |_, _| r = true).await?;

        Ok(r)
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.log.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.log.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};
    use std::collections::HashMap;

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an `Any` database initialized with the config provided by [db_config].
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_commit_on_empty_db() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = StandardHasher::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.log.oldest_retained_loc(), None);
            assert_eq!(db.log.pruning_boundary(), Location::new_unchecked(0));
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let empty_root = db.root(&mut hasher);
            assert_eq!(empty_root, MemMmr::default().root(&mut hasher));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let v1 = vec![1u8; 8];
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), empty_root);
            assert_eq!(db.op_count(), 0);

            let empty_proof = Proof::default();
            assert!(verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &empty_root
            ));

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(&mut hasher), root);

            // Empty proof should no longer verify.
            assert!(!verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &root
            ));

            // Single op proof should verify.
            let (proof, ops) = db
                .proof(Location::new_unchecked(0), NZU64!(1))
                .await
                .unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root
            ));

            // Add one more op.
            db.commit(None).await.unwrap();
            // Historical proof from larger db should match proof from smaller db.
            let (proof2, ops2) = db
                .historical_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(proof, proof2);
            assert_eq!(ops, ops2);

            // Proof will not verify against the root of the bigger db.
            let root2 = db.root(&mut hasher);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root2
            ));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(d1, vec![2u8; 20]).await.unwrap();
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.log.inactivity_floor_loc <= 3);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = StandardHasher::<Sha256>::new();

            let key1 = Sha256::fill(1u8);
            let key2 = Sha256::fill(2u8);
            let val1 = vec![1u8; 8];
            let val2 = vec![2u8; 20];

            assert!(db.get(&key1).await.unwrap().is_none());
            assert!(db.get(&key2).await.unwrap().is_none());

            assert!(db.create(key1, val1.clone()).await.unwrap());
            assert_eq!(
                db.get_all(&key1).await.unwrap().unwrap(),
                (val1.clone(), key1)
            );
            assert!(db.get_all(&key2).await.unwrap().is_none());

            assert!(db.create(key2, val2.clone()).await.unwrap());
            assert_eq!(
                db.get_all(&key1).await.unwrap().unwrap(),
                (val1.clone(), key2)
            );
            assert_eq!(
                db.get_all(&key2).await.unwrap().unwrap(),
                (val2.clone(), key1)
            );

            db.delete(key1).await.unwrap();
            assert!(db.get_all(&key1).await.unwrap().is_none());
            assert_eq!(
                db.get_all(&key2).await.unwrap().unwrap(),
                (val2.clone(), key2)
            );

            let new_val = vec![5u8; 16];
            db.update(key1, new_val.clone()).await.unwrap();
            assert_eq!(
                db.get_all(&key1).await.unwrap().unwrap(),
                (new_val.clone(), key2)
            );

            db.update(key2, new_val.clone()).await.unwrap();
            assert_eq!(
                db.get_all(&key2).await.unwrap().unwrap(),
                (new_val.clone(), key1)
            );

            assert_eq!(db.op_count(), 8); // 2 new keys (4), 2 updates (2), 1 deletion (2)
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc(), 0);
            db.sync().await.unwrap();

            // Make sure create won't modify active keys.
            assert!(!db.create(key1, val1.clone()).await.unwrap());
            assert_eq!(
                db.get_all(&key1).await.unwrap().unwrap(),
                (new_val.clone(), key2)
            );

            // take one floor raising step, which should move the first active op (at location 5) to
            // tip, leaving the floor at the next location (6).
            let loc = db.inactivity_floor_loc();
            db.log.inactivity_floor_loc = db.log.as_floor_helper().raise_floor(loc).await.unwrap();
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
            let root = db.root(&mut hasher);

            // Since this db no longer has any active keys, the inactivity floor should have been
            // set to tip.
            assert_eq!(db.inactivity_floor_loc(), db.op_count() - 1);

            // Multiple deletions of the same key should be a no-op.
            assert!(!db.delete(key1).await.unwrap());
            assert_eq!(db.log.op_count(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let key3 = Sha256::fill(5u8);
            assert!(!db.delete(key3).await.unwrap());
            assert_eq!(db.log.op_count(), 13);
            db.sync().await.unwrap();
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            assert_eq!(db.op_count(), 13);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Re-activate the keys by updating them.
            db.update(key1, val1.clone()).await.unwrap();
            db.update(key2, val2.clone()).await.unwrap();
            db.delete(key1).await.unwrap();
            db.update(key2, val1.clone()).await.unwrap();
            db.update(key1, val2.clone()).await.unwrap();
            assert_eq!(
                db.get_all(&key1).await.unwrap().unwrap(),
                (val2.clone(), key2)
            );
            assert_eq!(
                db.get_all(&key2).await.unwrap().unwrap(),
                (val1.clone(), key1)
            );
            assert_eq!(db.log.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(27), metadata))
            );

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit(None).await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);

            // We should not be able to prune beyond the inactivity floor.
            assert!(matches!(
                db.prune(db.inactivity_floor_loc() + 1).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
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
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(0));
            assert_eq!(
                db.log.oldest_retained_loc().unwrap(),
                Location::new_unchecked(0)
            ); // no pruning yet
            assert_eq!(db.log.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(3382));
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(3382));
            assert_eq!(db.log.snapshot.items(), 857);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(3382));
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.log.snapshot.items(), 857);

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
            let start_pos = db.log.log.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            assert!(start_loc < db.log.inactivity_floor_loc);

            for loc in *start_loc..*end_loc {
                let (proof, log) = db
                    .proof(Location::new_unchecked(loc), max_ops)
                    .await
                    .unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(loc),
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
            let iter = db.log.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                    db.update(k, v.clone()).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(None).await.unwrap();
            }
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit(None).await.unwrap();
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_ordered_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.log.inactivity_floor_loc).await.unwrap();

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_variable_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_more_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_variable_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the log).
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ordered_any_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }
}
