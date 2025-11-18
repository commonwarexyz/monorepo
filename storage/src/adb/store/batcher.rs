//! The [Batcher] implements the [ trait to provide a transparent batching layer on top of any
//! other [Db] implementation. Calls to the batcher's update and delete methods are cached and
//! applied to the wrapped database in batch upon calling [Batcher::commit] or
//! [Batcher::apply_updates].

use super::{Batchable, Db, Error};
use crate::translator::Translator;
use commonware_codec::Codec;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::marker::PhantomData;
use std::collections::HashMap;

enum UpdateOrDelete<V: Codec + Clone> {
    Update(V),
    Delete,
}

/// The [Batcher] caches update and delete operations, applying them in batch to the underlying
/// database in calls to [Batcher::commit], or [Batcher::apply_updates].
pub struct Batcher<
    E: Storage + Clock + Metrics,
    K: Array,
    V: Codec + Clone,
    T: Translator,
    D: Db<E, K, V, T>,
> {
    db: D,
    updates: HashMap<K, UpdateOrDelete<V>>,
    _phantom: PhantomData<(E, T)>,
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: Codec + Clone,
        T: Translator,
        D: Db<E, K, V, T>,
    > Batcher<E, K, V, T, D>
{
    /// Create a new batcher wrapping the given database.
    pub fn new(db: D) -> Self {
        Self {
            db,
            updates: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Get a reference to the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// Take the underlying database from the batcher. Any cached updates will be applied before returning.
    pub async fn take(mut self) -> Result<D, Error> {
        self.apply_updates().await?;

        Ok(self.db)
    }

    /// Applies any cached updates to the underlying db via the batch update method without applying
    /// a commit operation.
    ///
    /// # Errors
    ///
    /// - Propagates any underlying database errors. Because these errors are generally unrecoverable,
    ///   no effort is made to preserve batcher state should one occur.
    pub async fn apply_updates(&mut self) -> Result<(), Error> {
        let updates = std::mem::take(&mut self.updates);
        let updates_iter =
            updates
                .iter()
                .filter_map(|(key, update_or_delete)| match update_or_delete {
                    UpdateOrDelete::Update(value) => Some((key.clone(), value.clone())),
                    UpdateOrDelete::Delete => None,
                });
        let deletes_iter =
            updates
                .iter()
                .filter_map(|(key, update_or_delete)| match update_or_delete {
                    UpdateOrDelete::Update(_) => None,
                    UpdateOrDelete::Delete => Some(key.clone()),
                });

        self.db.batch_update(updates_iter, deletes_iter).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: Codec + Clone,
        T: Translator,
        D: Db<E, K, V, T>,
    > Batchable<K, V> for Batcher<E, K, V, T, D>
{
    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        match self.updates.get(key) {
            Some(UpdateOrDelete::Update(value)) => Ok(Some(value.clone())),
            Some(UpdateOrDelete::Delete) => Ok(None),
            None => self.db.get(key).await,
        }
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.updates.insert(key, UpdateOrDelete::Update(value));

        Ok(())
    }

    async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        if let Some(update_or_delete) = self.updates.get_mut(&key) {
            match update_or_delete {
                UpdateOrDelete::Update(_) => {
                    return Ok(false);
                }
                UpdateOrDelete::Delete => {
                    *update_or_delete = UpdateOrDelete::Update(value);
                    return Ok(true);
                }
            }
        }

        // Don't update the key if it already exists in the db.
        if self.db.get(&key).await?.is_some() {
            return Ok(false);
        }

        self.updates.insert(key, UpdateOrDelete::Update(value));

        Ok(true)
    }

    async fn delete(&mut self, key: K) -> Result<bool, Error> {
        if let Some(update_or_delete) = self.updates.get_mut(&key) {
            match update_or_delete {
                UpdateOrDelete::Update(_) => {
                    *update_or_delete = UpdateOrDelete::Delete;
                    return Ok(true);
                }
                UpdateOrDelete::Delete => {
                    return Ok(false);
                }
            }
        }

        if self.db.get(&key).await?.is_some() {
            self.updates.insert(key, UpdateOrDelete::Delete);
            return Ok(true);
        }

        Ok(false)
    }

    /// Delete the value assigned to `key` in the database, if any. This version is more efficient
    /// than regular `delete` because it doesn't provide a return value indicating whether the key
    /// was already deleted.
    async fn delete_unchecked(&mut self, key: K) -> Result<(), Error> {
        if let Some(update_or_delete) = self.updates.get_mut(&key) {
            match update_or_delete {
                UpdateOrDelete::Update(_) => {
                    *update_or_delete = UpdateOrDelete::Delete;
                }
                UpdateOrDelete::Delete => {}
            }
            return Ok(());
        }

        self.updates.insert(key, UpdateOrDelete::Delete);

        Ok(())
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.apply_updates().await?;

        self.db.commit().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::store::{Config, Store},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use rand::RngCore;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 99;
    const PAGE_CACHE_SIZE: usize = 9;

    /// A type alias for the concrete [Store] type used in these unit tests.
    type StoreTest = Store<deterministic::Context, Digest, Digest, TwoCap>;

    fn create_test_config(seed: u64) -> Config<TwoCap, ()> {
        Config {
            log_partition: format!("log_{seed}"),
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(11), // intentionally small and janky size
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub async fn create_test_db(mut context: Context) -> StoreTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        StoreTest::init(context, config).await.unwrap()
    }

    async fn assert_matching_gets(
        db1: &impl Batchable<Digest, Digest>,
        db2: &impl Batchable<Digest, Digest>,
        key1: &Digest,
        key2: &Digest,
    ) {
        assert_eq!(db1.get(key1).await.unwrap(), db2.get(key1).await.unwrap());
        assert_eq!(db1.get(key2).await.unwrap(), db2.get(key2).await.unwrap());
    }

    // Perform identical updates to a db and a batched db, and make sure get operations produce
    // equivalent results.
    #[test_traced("DEBUG")]
    fn test_batcher_db_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let mut batched_db = create_test_db(context.clone()).await.into_batcher();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.inactivity_floor_loc(), 0);

            // Test calling commit on an empty db.
            db.commit(None).await.unwrap();
            batched_db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op added
            assert_eq!(batched_db.db().op_count(), 1);

            // Add 2 keys to the db and make sure batching is equivalent to no batching after
            // commit.
            let k1 = Sha256::fill(1u8);
            let v1 = Sha256::fill(2u8);
            let k2 = Sha256::fill(3u8);
            let v2 = Sha256::fill(4u8);

            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert!(db.create(k1, v1).await.unwrap());
            assert!(batched_db.create(k1, v1).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.update(k2, v2).await.unwrap();
            batched_db.update(k2, v2).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            // Create of an existing key should fail.
            assert!(!db.create(k1, v1).await.unwrap());
            assert!(!batched_db.create(k1, v1).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.commit(None).await.unwrap();
            batched_db.commit().await.unwrap();
            assert_eq!(db.op_count(), 5); // two updates, two commits, one floor raise.
            assert_eq!(batched_db.db().op_count(), 5);
            assert_eq!(db.inactivity_floor_loc(), 2);
            assert_eq!(batched_db.db().inactivity_floor_loc(), 2);

            // Create of an existing key should fail after commit.
            assert!(!db.create(k1, v1).await.unwrap());
            assert!(!batched_db.create(k1, v1).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            // Delete the keys and make sure batching is equivalent.
            assert!(db.delete(k1).await.unwrap());
            batched_db.delete_unchecked(k1).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert!(db.delete(k2).await.unwrap());
            assert!(batched_db.delete(k2).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            // Double delete should be no-op.
            assert!(!db.delete(k1).await.unwrap());
            assert!(!batched_db.delete(k1).await.unwrap());
            batched_db.delete_unchecked(k1).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.commit(None).await.unwrap();
            batched_db.commit().await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert_eq!(db.op_count(), 8);
            assert_eq!(batched_db.db().op_count(), 8);
            assert!(db.is_empty());
            assert!(batched_db.db().is_empty());

            // Double delete after commit should still be a no-op.
            assert!(!db.delete(k1).await.unwrap());
            assert!(!batched_db.delete(k1).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert_eq!(
                db.inactivity_floor_loc(),
                batched_db.db().inactivity_floor_loc()
            );

            // Now test some updates where behavior (other than get) diverges due to batching.
            db.update(k1, v1).await.unwrap();
            batched_db.update(k1, v1).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.update(k2, v2).await.unwrap();
            batched_db.update(k2, v2).await.unwrap(); // double update of k2
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.update(k2, v1).await.unwrap();
            batched_db.update(k2, v1).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.commit(None).await.unwrap();
            batched_db.commit().await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert_eq!(db.op_count(), 14);
            assert_eq!(batched_db.db().op_count(), 12); // double update swallowed

            // Create of an existing key should fail after commit.
            assert!(!db.create(k1, v2).await.unwrap());
            assert!(!batched_db.create(k1, v2).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.update(k1, v2).await.unwrap();
            batched_db.update(k1, v2).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert!(db.delete(k1).await.unwrap());
            batched_db.delete_unchecked(k1).await.unwrap(); // will swallow the earlier update of k1
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            db.commit(None).await.unwrap();
            batched_db.commit().await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            assert_eq!(db.op_count(), 20);
            assert_eq!(batched_db.db().op_count(), 16); // delete, commit, 2 floor raise -- no update

            // Test sync. Will call apply_updates internally.
            db.update(k1, v1).await.unwrap();
            batched_db.update(k1, v1).await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            // Make sure create-after-delete works.
            assert!(db.delete(k1).await.unwrap());
            batched_db.delete_unchecked(k1).await.unwrap();
            assert!(db.create(k1, v1).await.unwrap());
            assert!(batched_db.create(k1, v1).await.unwrap());
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            let batched_db = batched_db.take().await.unwrap();
            assert_matching_gets(&db, &batched_db, &k1, &k2).await;

            // Clean up.
            db.destroy().await.unwrap();
            batched_db.destroy().await.unwrap();
        });
    }
}
