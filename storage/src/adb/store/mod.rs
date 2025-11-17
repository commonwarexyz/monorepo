//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! # Terminology
//!
//! A _key_ in an unauthenticated database either has a _value_ or it doesn't. The _update_
//! operation gives a key a specific value whether it previously had no value or had a different
//! value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is an [Operation::Update] operation, and (3) it is the most recent operation for that
//! key.
//!
//! # Lifecycle
//!
//! 1. **Initialization**: Create with [Store::init] using a [Config]
//! 2. **Insertion**: Use [Store::update] to assign a value to a given key
//! 3. **Deletions**: Use [Store::delete] to remove a key's value
//! 4. **Persistence**: Call [Store::commit] to make changes durable
//! 5. **Queries**: Use [Store::get] to retrieve current values
//! 6. **Cleanup**: Call [Store::close] to shutdown gracefully or [Store::destroy] to remove all
//!    data
//!
//! # Pruning
//!
//! The database maintains a location before which all operations are inactive, called the
//! _inactivity floor_. These items can be cleaned from storage by calling [Db::prune].
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     adb::store::{Config, Store, Db as _},
//!     translator::TwoCap,
//! };
//! use commonware_utils::{NZUsize, NZU64};
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_runtime::{buffer::PoolRef, deterministic::Runner, Metrics, Runner as _};
//!
//! const PAGE_SIZE: usize = 77;
//! const PAGE_CACHE_SIZE: usize = 9;
//!
//! let executor = Runner::default();
//! executor.start(|mut ctx| async move {
//!     let config = Config {
//!         log_partition: "test_partition".to_string(),
//!         log_write_buffer: NZUsize!(64 * 1024),
//!         log_compression: None,
//!         log_codec_config: (),
//!         log_items_per_section: NZU64!(4),
//!         translator: TwoCap,
//!         buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
//!     };
//!     let mut store =
//!         Store::<_, Digest, Digest, TwoCap>::init(ctx.with_label("store"), config)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     store.update(k, v).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = store.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Commit the operation to make it persistent
//!     let metadata = Some(Digest::random(&mut ctx));
//!     store.commit(metadata).await.unwrap();
//!
//!     // Delete the key's value
//!     store.delete(k).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = store.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Commit the operation to make it persistent
//!     store.commit(None).await.unwrap();
//!
//!     // Destroy the store
//!     store.destroy().await.unwrap();
//! });
//! ```

use crate::{
    adb::{
        build_snapshot_from_log, create_key, delete_key,
        operation::{variable::Operation, Keyed as _},
        rewind_uncommitted, update_key, Error, FloorHelper,
    },
    index::{unordered::Index, Unordered as _},
    journal::contiguous::variable::{Config as JournalConfig, Journal},
    mmr::Location,
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use core::{future::Future, marker::PhantomData};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

/// Configuration for initializing a [Store] database.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [`RStorage`] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the [Journal].
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [Journal].
    pub log_items_per_section: NonZeroU64,

    /// The [`Translator`] used by the compressed index.
    pub translator: T,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// A trait for any key-value store based on an append-only log of operations.
pub trait Db<E: RStorage + Clock + Metrics, K: Array, V: Codec, T: Translator> {
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    fn op_count(&self) -> Location;

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    fn inactivity_floor_loc(&self) -> Location;

    /// Get the value of `key` in the db, or None if it has no value.
    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Error>>;

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    fn update(&mut self, key: K, value: V) -> impl Future<Output = Result<(), Error>>;

    /// Updates the value associated with the given key in the store, inserting a default value if
    /// the key does not already exist.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [Db::commit] is called. Uncommitted operations will be rolled back if the
    /// store is closed without committing.
    fn upsert(
        &mut self,
        key: K,
        update: impl FnOnce(&mut V),
    ) -> impl Future<Output = Result<(), Error>>
    where
        V: Default,
    {
        async {
            let mut value = self.get(&key).await?.unwrap_or_default();
            update(&mut value);

            self.update(key, value).await
        }
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    fn create(&mut self, key: K, value: V) -> impl Future<Output = Result<bool, Error>>;

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    fn delete(&mut self, key: K) -> impl Future<Output = Result<bool, Error>>;

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    fn commit(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
    fn prune(&mut self, prune_loc: Location) -> impl Future<Output = Result<(), Error>>;

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Destroy the db, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

/// An unauthenticated key-value database based off of an append-only [Journal] of operations.
pub struct Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
{
    /// A log of all [Operation]s that have been applied to the store.
    log: Journal<E, Operation<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Update].
    snapshot: Index<T, Location>,

    /// The number of active keys in the store.
    active_keys: usize,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: Location,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    steps: u64,

    /// The location of the last commit operation (if any exists).
    last_commit: Option<Location>,
}

/// Type alias for the shared state wrapper used by this Any database variant.
type FloorHelperState<'a, E, K, V, T> =
    FloorHelper<'a, T, Index<T, Location>, Journal<E, Operation<K, V>>, Operation<K, V>>;

impl<E, K, V, T> Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
{
    /// Initializes a new [`Store`] database with the given configuration.
    ///
    /// ## Rollback
    ///
    /// Any uncommitted operations will be rolled back if the [Store] was previously closed without
    /// committing.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut log = Journal::<E, Operation<K, V>>::init(
            context.with_label("log"),
            JournalConfig {
                partition: cfg.log_partition,
                items_per_section: cfg.log_items_per_section,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        // Rewind log to remove uncommitted operations.
        let log_size = rewind_uncommitted(&mut log).await?;
        let (last_commit, inactivity_floor_loc) = if log_size > 0 {
            let last_commit_loc = log_size - 1;
            let floor_loc = log
                .read(last_commit_loc)
                .await?
                .has_floor()
                .expect("last operation should be a commit floor");
            (Some(Location::new_unchecked(last_commit_loc)), floor_loc)
        } else {
            (None, Location::new_unchecked(0))
        };

        // Build the snapshot.
        let mut snapshot = Index::init(context.with_label("snapshot"), cfg.translator);
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;

        Ok(Self {
            log,
            snapshot,
            active_keys,
            inactivity_floor_loc,
            steps: 0,
            last_commit,
        })
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for &loc in self.snapshot.get(key) {
            let Operation::Update(k, v) = self.get_op(loc).await? else {
                unreachable!("location ({loc}) does not reference update operation");
            };

            if &k == key {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    fn as_floor_helper(&mut self) -> FloorHelperState<'_, E, K, V, T> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
            translator: PhantomData,
        }
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Caller can
    /// associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }
        self.steps = 0;

        let op_count = self.op_count();
        self.last_commit = Some(op_count);

        // Apply the commit operation with the new inactivity floor.
        let loc = self.inactivity_floor_loc;
        self.log
            .append(Operation::CommitFloor(metadata, loc))
            .await?;

        // Commit the log to ensure this commit is durable.
        self.log.commit().await.map_err(Into::into)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await?;

        Ok(())
    }

    /// Prune historical operations that are behind the inactivity floor. This does not affect the
    /// state root.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        // Prune the log. The log will prune at section boundaries, so the actual oldest retained
        // location may be less than requested.
        if !self.log.prune(*prune_loc).await? {
            return Ok(());
        }

        debug!(
            log_size = ?self.op_count(),
            oldest_retained_loc = ?self.log.oldest_retained_pos(),
            ?prune_loc,
            "pruned inactive ops"
        );

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    ///
    /// # Errors
    ///
    /// Returns Error if there is some underlying storage failure.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let Operation::CommitFloor(metadata, _) = self.get_op(last_commit).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Closes the store. Any uncommitted operations will be lost if they have not been committed
    /// via [Store::commit].
    pub async fn close(self) -> Result<(), Error> {
        self.log.close().await?;

        Ok(())
    }

    /// Destroys the store permanently, removing all persistent data associated with it.
    ///
    /// # Warning
    ///
    /// This operation is irreversible. Do not call this method unless you are sure
    /// you want to delete all data associated with this store permanently!
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await?;

        Ok(())
    }

    /// Returns the number of operations that have been applied to the store, including those that
    /// are not yet committed.
    pub fn op_count(&self) -> Location {
        Location::new_unchecked(self.log.size())
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Gets a [Operation] from the log at the given location. Returns [Error::OperationPruned]
    /// if the location precedes the oldest retained location. The location is otherwise assumed
    /// valid.
    async fn get_op(&self, loc: Location) -> Result<Operation<K, V>, Error> {
        assert!(loc < self.op_count());

        // Get the operation from the log at the specified position.
        // The journal will return ItemPruned if the location is pruned.
        self.log.read(*loc).await.map_err(|e| match e {
            crate::journal::Error::ItemPruned(_) => Error::OperationPruned(loc),
            e => Error::Journal(e),
        })
    }
}

impl<E, K, V, T> Db<E, K, V, T> for Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();
        if update_key(&mut self.snapshot, &self.log, &key, new_loc)
            .await?
            .is_some()
        {
            self.steps += 1;
        } else {
            self.active_keys += 1;
        }

        self.log.append(Operation::Update(key, value)).await?;

        Ok(())
    }

    async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        let new_loc = self.op_count();
        if !create_key(&mut self.snapshot, &self.log, &key, new_loc).await? {
            return Ok(false);
        }

        self.active_keys += 1;
        self.log.append(Operation::Update(key, value)).await?;

        Ok(true)
    }

    async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let r = delete_key(&mut self.snapshot, &self.log, &key).await?;
        if r.is_none() {
            return Ok(false);
        }

        self.log.append(Operation::Delete(key)).await?;
        self.steps += 1;
        self.active_keys -= 1;

        Ok(true)
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_cryptography::{
        blake3::{Blake3, Digest},
        Digest as _, Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    /// The type of the store used in tests.
    type TestStore = Store<deterministic::Context, Digest, Vec<u8>, TwoCap>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = Config {
            log_partition: "journal".to_string(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        };
        Store::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_store_construct_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = create_test_store(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.log.oldest_retained_pos(), None);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = vec![1, 2, 3];
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = create_test_store(context.clone()).await;
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let mut db = create_test_store(context.clone()).await;

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(Digest::random(&mut context), vec![1, 2, 3])
                .await
                .unwrap();
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.inactivity_floor_loc <= 3);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_construct_basic() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the store is empty
            assert_eq!(store.op_count(), 0);
            assert_eq!(store.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Attempt to get a key that does not exist
            let result = store.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            store.update(key, value.clone()).await.unwrap();

            assert_eq!(store.op_count(), 1);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Sync the store to persist the changes
            store.sync().await.unwrap();

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(store.op_count(), 0);
            assert_eq!(store.inactivity_floor_loc, 0);
            assert!(store.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair
            store.update(key, value.clone()).await.unwrap();

            assert_eq!(store.op_count(), 1);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Persist the changes
            let metadata = Some(vec![99, 100]);
            store.commit(metadata.clone()).await.unwrap();
            assert_eq!(
                store.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(2), metadata.clone()))
            );

            // Even though the store was pruned, the inactivity floor was raised by 2, and
            // the old operations remain in the same blob as an active operation, so they're
            // retained.
            assert_eq!(store.op_count(), 3);
            assert_eq!(store.inactivity_floor_loc, 1);

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(store.op_count(), 3);
            assert_eq!(store.inactivity_floor_loc, 1);

            // Fetch the value, ensuring it is still present
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);
            store.update(k1, v1.clone()).await.unwrap();
            store.update(k2, v2.clone()).await.unwrap();

            assert_eq!(store.op_count(), 5);
            assert_eq!(store.inactivity_floor_loc, 1);

            // Make sure we can still get metadata.
            assert_eq!(
                store.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(2), metadata))
            );

            store.commit(None).await.unwrap();
            assert_eq!(
                store.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(6), None))
            );

            assert_eq!(store.op_count(), 7);
            assert_eq!(store.inactivity_floor_loc, 2);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(store.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(store.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(store.get(&k2).await.unwrap().unwrap(), v2);

            // Ensure upsert works for existing key.
            store.upsert(k1, |v| v.push(7)).await.unwrap();
            assert_eq!(
                store.get(&k1).await.unwrap().unwrap(),
                vec![2, 3, 4, 5, 6, 7]
            );

            // Ensure upsert works for new key.
            let k3 = Digest::random(&mut ctx);
            store.upsert(k3, |v| v.push(8)).await.unwrap();
            assert_eq!(store.get(&k3).await.unwrap().unwrap(), vec![8]);

            // Destroy the store
            store.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_log_replay() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Digest::random(&mut ctx);
            for _ in 0..UPDATES {
                let v = vec![1, 2, 3, 4, 5];
                store.update(k, v.clone()).await.unwrap();
            }

            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            store.commit(None).await.unwrap();
            store.close().await.unwrap();

            // Re-open the store, prune it, then ensure it replays the log correctly.
            let mut store = create_test_store(ctx.with_label("store")).await;
            store.prune(store.inactivity_floor_loc()).await.unwrap();

            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // 100 operations were applied, each triggering one step, plus the commit op.
            assert_eq!(store.op_count(), UPDATES * 2 + 1);
            // Only the highest `Update` operation is active, plus the commit operation above it.
            let expected_floor = UPDATES * 2 - 1;
            assert_eq!(store.inactivity_floor_loc, expected_floor);

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(
                store.log.oldest_retained_pos(),
                Some(expected_floor - expected_floor % 7)
            );

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            let (k1, v1) = (Digest::random(&mut ctx), vec![1, 2, 3, 4, 5]);
            let (mut k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8, 9, 10]);

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            store.update(k1, v1.clone()).await.unwrap();
            store.update(k2, v2.clone()).await.unwrap();

            assert_eq!(store.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(store.get(&k2).await.unwrap().unwrap(), v2);

            store.commit(None).await.unwrap();
            store.close().await.unwrap();

            // Re-open the store to ensure it builds the snapshot for the conflicting
            // keys correctly.
            let store = create_test_store(ctx.with_label("store")).await;

            assert_eq!(store.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(store.get(&k2).await.unwrap().unwrap(), v2);

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_delete() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Insert a key-value pair
            let k = Digest::random(&mut ctx);
            let v = vec![1, 2, 3, 4, 5];
            store.update(k, v.clone()).await.unwrap();

            // Fetch the value
            let fetched_value = store.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            assert!(store.delete(k).await.unwrap());

            // Ensure the key is no longer present
            let fetched_value = store.get(&k).await.unwrap();
            assert!(fetched_value.is_none());
            assert!(!store.delete(k).await.unwrap());

            // Commit the changes
            store.commit(None).await.unwrap();

            // Re-open the store and ensure the key is still deleted
            let mut store = create_test_store(ctx.with_label("store")).await;
            let fetched_value = store.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            store.update(k, v.clone()).await.unwrap();
            let fetched_value = store.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Commit the changes
            store.commit(None).await.unwrap();

            // Re-open the store and ensure the snapshot restores the key, after processing
            // the delete and the subsequent set.
            let mut store = create_test_store(ctx.with_label("store")).await;
            let fetched_value = store.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete a non-existent key (no-op)
            let k_n = Digest::random(&mut ctx);
            store.delete(k_n).await.unwrap();

            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            let iter = store.snapshot.get(&k_n);
            assert_eq!(iter.count(), 0);

            store.destroy().await.unwrap();
        });
    }

    /// Tests the pruning example in the module documentation.
    #[test_traced("DEBUG")]
    fn test_store_pruning() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            let k_a = Digest::random(&mut ctx);
            let k_b = Digest::random(&mut ctx);

            let v_a = vec![1];
            let v_b = vec![];
            let v_c = vec![4, 5, 6];

            store.update(k_a, v_a.clone()).await.unwrap();
            store.update(k_b, v_b.clone()).await.unwrap();

            store.commit(None).await.unwrap();
            assert_eq!(store.op_count(), 4);
            assert_eq!(store.inactivity_floor_loc, 1);
            assert_eq!(store.get(&k_a).await.unwrap().unwrap(), v_a);

            store.update(k_b, v_a.clone()).await.unwrap();
            store.update(k_a, v_c.clone()).await.unwrap();

            store.commit(None).await.unwrap();
            assert_eq!(store.op_count(), 10);
            assert_eq!(store.inactivity_floor_loc, 7);
            assert_eq!(store.get(&k_a).await.unwrap().unwrap(), v_c);
            assert_eq!(store.get(&k_b).await.unwrap().unwrap(), v_a);

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = create_test_store(context.with_label("store")).await;

            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            drop(db);
            let mut db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), 0);

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let op_count = db.op_count();

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            drop(db);
            let mut db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), op_count);

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let op_count = db.op_count();
            assert_eq!(op_count, 1672);
            assert_eq!(db.snapshot.items(), 1000);

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            drop(db);
            let db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), op_count);

            // Close and reopen the store to ensure the final commit is preserved.
            db.close().await.unwrap();
            let mut db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), op_count);

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            assert_eq!(db.op_count(), 1960);
            assert_eq!(db.inactivity_floor_loc, 755);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.oldest_retained_pos(), Some(755 - 755 % 7));
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }
}
