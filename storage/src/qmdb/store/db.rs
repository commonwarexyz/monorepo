//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! # Lifecycle
//!
//! Unlike authenticated stores which have 4 potential states, an unauthenticated store only has
//! two:
//!
//! - **Clean**: The store has no uncommitted operations and its key/value state is immutable. Use
//!   `into_dirty` to transform it into a dirty state.
//!
//! - **Dirty**: The store has uncommitted operations and its key/value state is mutable. Use
//!   `commit` to transform it into a clean state.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     qmdb::store::db::{Config, Db},
//!     translator::TwoCap,
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_math::algebra::Random;
//! use commonware_runtime::{buffer::PoolRef, deterministic::Runner, Metrics, Runner as _};
//!
//! use std::num::NonZeroU16;
//! const PAGE_SIZE: NonZeroU16 = NZU16!(8192);
//! const PAGE_CACHE_SIZE: usize = 100;
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
//!         buffer_pool: PoolRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
//!     };
//!     let db =
//!         Db::<_, Digest, Digest, TwoCap>::init(ctx.with_label("store"), config)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     let mut db = db.into_dirty();
//!     db.update(k, v).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Commit the operation to make it persistent
//!     let metadata = Some(Digest::random(&mut ctx));
//!     let (db, _) = db.commit(metadata).await.unwrap();
//!
//!     // Delete the key's value
//!     let mut db = db.into_dirty();
//!     db.delete(k).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Commit the operation to make it persistent
//!     let (db, _) = db.commit(None).await.unwrap();
//!
//!     // Destroy the store
//!     db.destroy().await.unwrap();
//! });
//! ```

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::contiguous::{
        variable::{Config as JournalConfig, Journal},
        MutableContiguous as _,
    },
    kv::{Batchable, Deletable, Updatable},
    mmr::Location,
    qmdb::{
        any::{
            unordered::{variable::Operation, Update},
            VariableValue,
        },
        build_snapshot_from_log, create_key, delete_key,
        operation::{Committable as _, Operation as _},
        store::{Durable, LogStore, NonDurable, PrunableStore, State},
        update_key, Error, FloorHelper,
    },
    translator::Translator,
    Persistable,
};
use commonware_codec::Read;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage};
use commonware_utils::Array;
use core::ops::Range;
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

/// Configuration for initializing a [Db].
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the [Journal].
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [Journal].
    pub log_items_per_section: NonZeroU64,

    /// The [Translator] used by the [Index].
    pub translator: T,

    /// The [PoolRef] to use for caching data.
    pub buffer_pool: PoolRef,
}

/// An unauthenticated key-value database based off of an append-only [Journal] of operations.
pub struct Db<E, K, V, T, S = Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
    S: State,
{
    /// A log of all [Operation]s that have been applied to the store.
    ///
    /// # Invariants
    ///
    /// - There is always at least one commit operation in the log.
    /// - The log is never pruned beyond the inactivity floor.
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
    pub inactivity_floor_loc: Location,

    /// The location of the last commit operation.
    pub last_commit_loc: Location,

    /// The state of the store.
    pub state: S,
}

impl<E, K, V, T, S> Db<E, K, V, T, S>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
    S: State,
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for &loc in self.snapshot.get(key) {
            let Operation::Update(Update(k, v)) = self.get_op(loc).await? else {
                unreachable!("location ({loc}) does not reference update operation");
            };

            if &k == key {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Whether the db currently has no active keys.
    pub const fn is_empty(&self) -> bool {
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

    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    pub const fn op_count(&self) -> Location {
        Location::new_unchecked(self.log.size())
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let Operation::CommitFloor(metadata, _) = self.log.read(*self.last_commit_loc).await?
        else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(metadata)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
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
}

impl<E, K, V, T> Db<E, K, V, T, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    /// Initializes a new [Db] with the given configuration.
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
        if log.rewind_to(|op| op.is_commit()).await? == 0 {
            warn!("Log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
        }

        // Sync the log to avoid having to repeat any recovery that may have been performed on next
        // startup.
        log.sync().await?;

        let last_commit_loc =
            Location::new_unchecked(log.size().checked_sub(1).expect("commit should exist"));
        let op = log.read(*last_commit_loc).await?;
        let inactivity_floor_loc = op.has_floor().expect("last op should be a commit");

        // Build the snapshot.
        let mut snapshot = Index::new(context.with_label("snapshot"), cfg.translator);
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;

        Ok(Self {
            log,
            snapshot,
            active_keys,
            inactivity_floor_loc,
            last_commit_loc,
            state: Durable,
        })
    }

    /// Convert this clean store into its dirty counterpart for making updates.
    pub fn into_dirty(self) -> Db<E, K, V, T, NonDurable> {
        Db {
            log: self.log,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            state: NonDurable::default(),
        }
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }
}

impl<E, K, V, T> Db<E, K, V, T, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, Index<T, Location>, Journal<E, Operation<K, V>>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();
        if update_key(&mut self.snapshot, &self.log, &key, new_loc)
            .await?
            .is_some()
        {
            self.state.steps += 1;
        } else {
            self.active_keys += 1;
        }

        self.log
            .append(Operation::Update(Update(key, value)))
            .await?;

        Ok(())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        let new_loc = self.op_count();
        if !create_key(&mut self.snapshot, &self.log, &key, new_loc).await? {
            return Ok(false);
        }

        self.active_keys += 1;
        self.log
            .append(Operation::Update(Update(key, value)))
            .await?;

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let r = delete_key(&mut self.snapshot, &self.log, &key).await?;
        if r.is_none() {
            return Ok(false);
        }

        self.log.append(Operation::Delete(key)).await?;
        self.state.steps += 1;
        self.active_keys -= 1;

        Ok(true)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations. The end of the returned range
    /// includes the commit operation itself, and hence will always be equal to `op_count`.
    ///
    /// Note that even if no operations were added since the last commit, this is a root-state
    /// changing operation.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    ///
    /// Consumes this dirty store and returns a clean one.
    pub async fn commit(
        mut self,
        metadata: Option<V>,
    ) -> Result<(Db<E, K, V, T, Durable>, Range<Location>), Error> {
        let start_loc = self.last_commit_loc + 1;

        // Raise the inactivity floor by taking `self.state.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.state.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }

        // Apply the commit operation with the new inactivity floor.
        self.last_commit_loc = Location::new_unchecked(
            self.log
                .append(Operation::CommitFloor(metadata, self.inactivity_floor_loc))
                .await?,
        );

        let range = start_loc..self.op_count();

        // Commit the log to ensure durability.
        self.log.commit().await?;

        Ok((
            Db {
                log: self.log,
                snapshot: self.snapshot,
                active_keys: self.active_keys,
                inactivity_floor_loc: self.inactivity_floor_loc,
                last_commit_loc: self.last_commit_loc,
                state: Durable,
            },
            range,
        ))
    }
}

impl<E, K, V, T> Persistable for Db<E, K, V, T, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        // No-op, DB already in recoverable state.
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E, K, V, T, S> LogStore for Db<E, K, V, T, S>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
    S: State,
{
    type Value = V;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<E, K, V, T, S> PrunableStore for Db<E, K, V, T, S>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
    S: State,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<E, K, V, T, S> crate::kv::Gettable for Db<E, K, V, T, S>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
    S: State,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

impl<E, K, V, T> Updatable for Db<E, K, V, T, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

impl<E, K, V, T> Deletable for Db<E, K, V, T, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<E, K, V, T> Batchable for Db<E, K, V, T, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Self::Error>
    where
        Iter: Iterator<Item = (Self::Key, Option<Self::Value>)> + Send + 'a,
    {
        for (key, value) in iter {
            if let Some(value) = value {
                self.update(key, value).await?;
            } else {
                self.delete(key).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{kv::Gettable as _, translator::TwoCap};
    use commonware_cryptography::{
        blake3::{Blake3, Digest},
        Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// The type of the store used in tests.
    type TestStore = Db<deterministic::Context, Digest, Vec<u8>, TwoCap, Durable>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = Config {
            log_partition: "journal".to_string(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            translator: TwoCap,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        TestStore::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_store_construct_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = create_test_store(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.log.oldest_retained_pos(), Some(0));
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert!(matches!(
                db.prune(Location::new_unchecked(1)).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = vec![1, 2, 3];
            let mut dirty = db.into_dirty();
            dirty.update(d1, v1).await.unwrap();
            drop(dirty);

            let db = create_test_store(context.clone()).await.into_dirty();
            assert_eq!(db.op_count(), 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![1, 2, 3];
            let (mut db, range) = db.commit(Some(metadata.clone())).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 2);
            assert_eq!(db.op_count(), 2);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            let mut db = create_test_store(context.clone()).await.into_dirty();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(Digest::random(&mut context), vec![1, 2, 3])
                .await
                .unwrap();
            let (mut db, _) = db.commit(None).await.unwrap();
            for _ in 1..100 {
                (db, _) = db.into_dirty().commit(None).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.inactivity_floor_loc <= 3);
                assert!(db.get_metadata().await.unwrap().is_none());
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_construct_basic() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Ensure the store is empty
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Attempt to get a key that does not exist
            let result = db.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            db.update(key, value.clone()).await.unwrap();

            assert_eq!(db.op_count(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Simulate commit failure.
            drop(db);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair
            db.update(key, value.clone()).await.unwrap();

            assert_eq!(db.op_count(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);

            // Persist the changes
            let metadata = vec![99, 100];
            let (db, range) = db.commit(Some(metadata.clone())).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            // Even though the store was pruned, the inactivity floor was raised by 2, and
            // the old operations remain in the same blob as an active operation, so they're
            // retained.
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Ensure the re-opened store retained the committed operations
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);
            db.update(k1, v1.clone()).await.unwrap();
            db.update(k2, v2.clone()).await.unwrap();

            assert_eq!(db.op_count(), 6);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Make sure we can still get metadata.
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            let (db, range) = db.commit(None).await.unwrap();
            assert_eq!(range.start, 4);
            assert_eq!(range.end, db.op_count());
            assert_eq!(db.get_metadata().await.unwrap(), None);
            let mut db = db.into_dirty();

            assert_eq!(db.op_count(), 8);
            assert_eq!(db.inactivity_floor_loc, 3);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Update existing key with modified value.
            let mut v1_updated = db.get(&k1).await.unwrap().unwrap();
            v1_updated.push(7);
            db.update(k1, v1_updated).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), vec![2, 3, 4, 5, 6, 7]);

            // Create new key.
            let mut db = db.into_dirty();
            let k3 = Digest::random(&mut ctx);
            db.update(k3, vec![8]).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            assert_eq!(db.get(&k3).await.unwrap().unwrap(), vec![8]);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_log_replay() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Digest::random(&mut ctx);
            for _ in 0..UPDATES {
                let v = vec![1, 2, 3, 4, 5];
                db.update(k, v.clone()).await.unwrap();
            }

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            let (mut db, _) = db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            drop(db);

            // Re-open the store, prune it, then ensure it replays the log correctly.
            let mut db = create_test_store(ctx.with_label("store")).await;
            db.prune(db.inactivity_floor_loc()).await.unwrap();

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // 100 operations were applied, each triggering one step, plus the commit op.
            assert_eq!(db.op_count(), UPDATES * 2 + 2);
            // Only the highest `Update` operation is active, plus the commit operation above it.
            let expected_floor = UPDATES * 2;
            assert_eq!(db.inactivity_floor_loc, expected_floor);

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(
                db.log.oldest_retained_pos(),
                Some(expected_floor - expected_floor % 7)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            let (k1, v1) = (Digest::random(&mut ctx), vec![1, 2, 3, 4, 5]);
            let (mut k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8, 9, 10]);

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            db.update(k1, v1.clone()).await.unwrap();
            db.update(k2, v2.clone()).await.unwrap();

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            let (mut db, _) = db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            drop(db);

            // Re-open the store to ensure it builds the snapshot for the conflicting
            // keys correctly.
            let db = create_test_store(ctx.with_label("store")).await;

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_delete() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Insert a key-value pair
            let k = Digest::random(&mut ctx);
            let v = vec![1, 2, 3, 4, 5];
            db.update(k, v.clone()).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            // Fetch the value
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            let mut db = db.into_dirty();
            assert!(db.delete(k).await.unwrap());

            // Ensure the key is no longer present
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());
            assert!(!db.delete(k).await.unwrap());

            // Commit the changes
            let _ = db.commit(None).await.unwrap();

            // Re-open the store and ensure the key is still deleted
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            db.update(k, v.clone()).await.unwrap();
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Commit the changes
            let _ = db.commit(None).await.unwrap();

            // Re-open the store and ensure the snapshot restores the key, after processing
            // the delete and the subsequent set.
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete a non-existent key (no-op)
            let k_n = Digest::random(&mut ctx);
            db.delete(k_n).await.unwrap();

            let (db, range) = db.commit(None).await.unwrap();
            assert_eq!(range.start, 9);
            assert_eq!(range.end, 11);

            assert!(db.get(&k_n).await.unwrap().is_none());
            // Make sure k is still there
            assert!(db.get(&k).await.unwrap().is_some());

            db.destroy().await.unwrap();
        });
    }

    /// Tests the pruning example in the module documentation.
    #[test_traced("DEBUG")]
    fn test_store_pruning() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            let k_a = Digest::random(&mut ctx);
            let k_b = Digest::random(&mut ctx);

            let v_a = vec![1];
            let v_b = vec![];
            let v_c = vec![4, 5, 6];

            db.update(k_a, v_a.clone()).await.unwrap();
            db.update(k_b, v_b.clone()).await.unwrap();

            let (db, _) = db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 5);
            assert_eq!(db.inactivity_floor_loc, 2);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_a);

            let mut db = db.into_dirty();
            db.update(k_b, v_a.clone()).await.unwrap();
            db.update(k_a, v_c.clone()).await.unwrap();

            let (db, _) = db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 11);
            assert_eq!(db.inactivity_floor_loc, 8);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_c);
            assert_eq!(db.get(&k_b).await.unwrap().unwrap(), v_a);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = create_test_store(context.with_label("store"))
                .await
                .into_dirty();

            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            drop(db);
            let db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), 1);

            // re-apply the updates and commit them this time.
            let mut db = db.into_dirty();
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            let (db, _) = db.commit(None).await.unwrap();
            let op_count = db.op_count();

            // Update every 3rd key
            let mut db = db.into_dirty();
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
            let mut db = create_test_store(context.with_label("store"))
                .await
                .into_dirty();
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
            let (db, _) = db.commit(None).await.unwrap();
            let op_count = db.op_count();
            assert_eq!(op_count, 1673);
            assert_eq!(db.snapshot.items(), 1000);

            // Delete every 7th key
            let mut db = db.into_dirty();
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

            // Sync and reopen the store to ensure the final commit is preserved.
            let mut db = db;
            db.sync().await.unwrap();
            drop(db);
            let mut db = create_test_store(context.with_label("store"))
                .await
                .into_dirty();
            assert_eq!(db.op_count(), op_count);

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            let (mut db, _) = db.commit(None).await.unwrap();

            assert_eq!(db.op_count(), 1961);
            assert_eq!(db.inactivity_floor_loc, 756);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.oldest_retained_pos(), Some(756 /*- 756 % 7 == 0*/));
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_batchable() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Ensure the store is empty
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            let mut batch = db.start_batch();

            // Attempt to get a key that does not exist
            let result = batch.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            batch.update(key, value.clone()).await.unwrap();

            assert_eq!(db.op_count(), 1); // The batch is not applied yet
            assert_eq!(db.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = batch.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);
            db.write_batch(batch.into_iter()).await.unwrap();
            drop(db);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store"))
                .await
                .into_dirty();

            // Ensure the batch was not applied since we didn't commit.
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair
            let mut batch = db.start_batch();
            batch.update(key, value.clone()).await.unwrap();

            // Persist the changes
            db.write_batch(batch.into_iter()).await.unwrap();
            assert_eq!(db.op_count(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);
            let metadata = vec![99, 100];
            let (db, range) = db.commit(Some(metadata.clone())).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            drop(db);

            // Re-open the store
            let db = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    fn assert_send<T: Send>(_: T) {}

    #[test_traced]
    fn test_futures_are_send() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_store(context.with_label("store")).await;
            let key = Blake3::hash(&[1, 2, 3]);
            let loc = Location::new_unchecked(0);

            assert_send(db.get(&key));
            assert_send(db.get_metadata());
            assert_send(db.sync());
            assert_send(db.prune(loc));

            let mut db = db.into_dirty();
            assert_send(db.get(&key));
            assert_send(db.get_metadata());
            assert_send(db.update(key, vec![]));
            assert_send(db.create(key, vec![]));
            assert_send(db.upsert(key, |_| {}));
            assert_send(db.delete(key));
            assert_send(db.commit(None));
        });
    }
}
