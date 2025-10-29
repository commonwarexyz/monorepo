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
//!     adb::store::{Config, Store},
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
//!         log_journal_partition: "test_partition".to_string(),
//!         log_write_buffer: NZUsize!(64 * 1024),
//!         log_compression: None,
//!         log_codec_config: (),
//!         log_items_per_section: NZU64!(4),
//!         locations_journal_partition: "locations_partition".to_string(),
//!         locations_items_per_blob: NZU64!(4),
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
    adb::operation::variable::Operation,
    index::{Cursor, Index as _, Unordered as Index},
    journal::{
        contiguous::fixed::{Config as FConfig, Journal as FJournal},
        segmented::variable::{Config as VConfig, Journal as VJournal},
    },
    mmr::Location,
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::{Array, NZUsize};
use core::future::Future;
use futures::{pin_mut, try_join, StreamExt};
use std::{
    collections::HashMap,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::{debug, warn};

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Errors that can occur when interacting with a [Store] database.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The requested operation has been pruned.
    #[error("operation pruned")]
    OperationPruned(Location),

    #[error(transparent)]
    Journal(#[from] crate::journal::Error),

    #[error(transparent)]
    Adb(#[from] crate::adb::Error),
}

/// Configuration for initializing a [Store] database.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [`RStorage`] partition used to persist the log of operations.
    pub log_journal_partition: String,

    /// The size of the write buffer to use for each blob in the [`VJournal`].
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [`VJournal`].
    pub log_items_per_section: NonZeroU64,

    /// The name of the [`RStorage`] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_items_per_blob: NonZeroU64,

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

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    fn delete(&mut self, key: K) -> impl Future<Output = Result<(), Error>>;

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

    /// Prune historical operations prior to `target_prune_loc`. This does not affect the db's root
    /// or current snapshot.
    fn prune(&mut self, target_prune_loc: Location) -> impl Future<Output = Result<(), Error>>;

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Destroy the db, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

/// An unauthenticated key-value database based off of an append-only [VJournal] of operations.
pub struct Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
{
    /// A log of all [Operation]s that have been applied to the store.
    log: VJournal<E, Operation<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// section and offset within the section containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Update].
    snapshot: Index<T, Location>,

    /// The number of items to store in each section of the variable journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations: FJournal<E, u32>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: Location,

    /// The location of the oldest operation in the log that remains readable.
    oldest_retained_loc: Location,

    /// The total number of operations that have been applied to the store.
    log_size: Location,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// The location of the last commit operation (if any exists).
    pub(crate) last_commit: Option<Location>,
}

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
        let snapshot = Index::init(context.with_label("snapshot"), cfg.translator);

        let log = VJournal::init(
            context.with_label("log"),
            VConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let locations = FJournal::init(
            context.with_label("locations"),
            FConfig {
                partition: cfg.locations_journal_partition,
                items_per_blob: cfg.locations_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        let db = Self {
            log,
            snapshot,
            log_items_per_section: cfg.log_items_per_section.get(),
            locations,
            inactivity_floor_loc: Location::new_unchecked(0),
            oldest_retained_loc: Location::new_unchecked(0),
            log_size: Location::new_unchecked(0),
            steps: 0,
            last_commit: None,
        };

        db.build_snapshot_from_log().await
    }

    /// Gets the value associated with the given key in the store.
    ///
    /// If the key does not exist, returns `Ok(None)`.
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

    /// Get the value of the operation with location `loc` in the db. Returns
    /// [Error::OperationPruned] if loc precedes the oldest retained location. The location is
    /// otherwise assumed valid.
    pub async fn get_loc(&self, loc: Location) -> Result<Option<V>, Error> {
        assert!(loc < self.log_size);
        let op = self.get_op(loc).await?;

        Ok(op.into_value())
    }

    /// Updates the value associated with the given key in the store.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [Store::commit] is called. Uncommitted operations will be rolled back
    /// if the store is closed without committing.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.log_size;
        if let Some(old_loc) = self.get_key_loc(&key).await? {
            Self::update_loc(&mut self.snapshot, &key, old_loc, new_loc);
            self.steps += 1;
        } else {
            self.snapshot.insert(&key, new_loc);
        };

        self.apply_op(Operation::Update(key, value))
            .await
            .map(|_| ())
    }

    /// Updates the value associated with the given key in the store, inserting a default value
    /// if the key does not already exist.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [Store::commit] is called. Uncommitted operations will be rolled back
    /// if the store is closed without committing.
    pub async fn upsert(&mut self, key: K, update: impl FnOnce(&mut V)) -> Result<(), Error>
    where
        V: Default,
    {
        let mut value = self.get(&key).await?.unwrap_or_default();
        update(&mut value);

        self.update(key, value).await
    }

    /// Deletes the value associated with the given key in the store. If the key has no value,
    /// the operation is a no-op.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        let Some(old_loc) = self.get_key_loc(&key).await? else {
            // Key does not exist, so this is a no-op.
            return Ok(());
        };

        Self::delete_loc(&mut self.snapshot, &key, old_loc);
        self.steps += 1;

        self.apply_op(Operation::Delete(key)).await.map(|_| ())
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
                self.raise_floor().await?;
            }
        }
        self.steps = 0;

        // Apply the commit operation with the new inactivity floor.
        self.apply_op(Operation::CommitFloor(metadata, self.inactivity_floor_loc))
            .await?;
        self.last_commit = Some(self.op_count() - 1);

        let section = self.current_section();
        self.log.sync(section).await?;

        debug!(log_size = ?self.log_size, "commit complete");

        Ok(())
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one.
    ///
    /// # Errors
    ///
    /// Expects there is at least one active operation above the inactivity floor, and returns Error
    /// otherwise.
    async fn raise_floor(&mut self) -> Result<(), Error> {
        // Search for the first active operation above the inactivity floor and move it to tip.
        //
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1829): optimize this w/ a bitmap.
        let mut op = self.get_op(self.inactivity_floor_loc).await?;
        while self
            .move_op_if_active(op, self.inactivity_floor_loc)
            .await?
            .is_none()
        {
            self.inactivity_floor_loc += 1;
            op = self.get_op(self.inactivity_floor_loc).await?;
        }

        // Increment the floor to the next operation since we know the current one is inactive.
        self.inactivity_floor_loc += 1;

        Ok(())
    }

    fn current_section(&self) -> u64 {
        *self.log_size / self.log_items_per_section
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let current_section = *self.log_size / self.log_items_per_section;
        try_join!(self.log.sync(current_section), self.locations.sync())?;

        Ok(())
    }

    /// Prune historical operations that are behind the inactivity floor. This does not affect the
    /// state root.
    ///
    /// # Panics
    ///
    /// Panics if `target_prune_loc` is greater than the inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        // Calculate the target pruning position: inactivity_floor_loc.
        assert!(target_prune_loc <= self.inactivity_floor_loc);
        if target_prune_loc <= self.oldest_retained_loc {
            return Ok(());
        }

        // Sync locations so it never ends up behind the log.
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1554): Extend recovery to avoid
        // this sync.
        self.locations.sync().await?;

        // Prune the log up to the section containing the requested pruning location. We always
        // prune the log first, and then prune the locations structure based on the log's actual
        // pruning boundary. This procedure ensures all log operations always have corresponding
        // location entries, even in the event of failures, with no need for special recovery.
        let section_with_target = *target_prune_loc / self.log_items_per_section;
        if !self.log.prune(section_with_target).await? {
            return Ok(());
        }
        self.oldest_retained_loc =
            Location::new_unchecked(section_with_target * self.log_items_per_section);
        debug!(
            log_size = ?self.log_size,
            oldest_retained_loc = ?self.oldest_retained_loc,
            ?target_prune_loc,
            "pruned inactive ops"
        );

        // Prune the locations map up to the oldest retained item in the log after pruning.
        self.locations
            .prune(*self.oldest_retained_loc)
            .await
            .map_err(Error::Journal)?;

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
        try_join!(self.log.close(), self.locations.close())?;

        Ok(())
    }

    /// Simulates a commit failure by avoiding syncing either or both of the log or locations.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(
        mut self,
        sync_locations: bool,
        sync_log: bool,
    ) -> Result<(), Error> {
        if sync_locations {
            self.locations.sync().await?;
        }
        if sync_log {
            let section = self.current_section();
            self.log.sync(section).await?;
        }

        Ok(())
    }

    /// Destroys the store permanently, removing all persistent data associated with it.
    ///
    /// # Warning
    ///
    /// This operation is irreversible. Do not call this method unless you are sure
    /// you want to delete all data associated with this store permanently!
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(self.log.destroy(), self.locations.destroy())?;
        Ok(())
    }

    /// Returns the number of operations that have been applied to the store, including those that
    /// are not yet committed.
    pub fn op_count(&self) -> Location {
        self.log_size
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.snapshot.keys() == 0
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Builds the database's snapshot from the log of operations. Any operations that sit above
    /// the latest commit operation are removed.
    ///
    /// Returns the number of operations that were applied to the store, the oldest retained
    /// location, and the inactivity floor location.
    async fn build_snapshot_from_log(mut self) -> Result<Self, Error> {
        let mut locations_size = self.locations.size().await?;

        // The location and blob-offset of the first operation to follow the last known commit point.
        let mut after_last_commit = None;
        // The set of operations that have not yet been committed.
        let mut uncommitted_ops = HashMap::new();
        let mut oldest_retained_loc_found = false;
        {
            let stream = self
                .log
                .replay(0, 0, NZUsize!(SNAPSHOT_READ_BUFFER_SIZE))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::Journal(e));
                    }
                    Ok((section, offset, _, op)) => {
                        if !oldest_retained_loc_found {
                            self.log_size =
                                Location::new_unchecked(section * self.log_items_per_section);
                            self.oldest_retained_loc = self.log_size;
                            oldest_retained_loc_found = true;
                        }

                        let loc = self.log_size; // location of the current operation.
                        if after_last_commit.is_none() {
                            after_last_commit = Some((loc, offset));
                        }

                        self.log_size += 1;

                        // Consistency check: confirm the provided section matches what we expect from this operation's
                        // index.
                        let expected = *loc / self.log_items_per_section;
                        assert_eq!(section, expected,
                                "given section {section} did not match expected section {expected} from location {loc}");

                        if self.log_size > locations_size {
                            warn!(section, offset, "operation was missing from location map");
                            self.locations.append(offset).await?;
                            locations_size += 1;
                        }

                        match op {
                            Operation::Delete(key) => {
                                let result = self.get_key_loc(&key).await?;
                                if let Some(old_loc) = result {
                                    uncommitted_ops.insert(key, (Some(old_loc), None));
                                } else {
                                    uncommitted_ops.remove(&key);
                                }
                            }
                            Operation::Update(key, _) => {
                                let result = self.get_key_loc(&key).await?;
                                if let Some(old_loc) = result {
                                    uncommitted_ops.insert(key, (Some(old_loc), Some(loc)));
                                } else {
                                    uncommitted_ops.insert(key, (None, Some(loc)));
                                }
                            }
                            Operation::CommitFloor(_, loc) => {
                                self.inactivity_floor_loc = loc;

                                // Apply all uncommitted operations.
                                for (key, (old_loc, new_loc)) in uncommitted_ops.iter() {
                                    if let Some(old_loc) = old_loc {
                                        if let Some(new_loc) = new_loc {
                                            Self::update_loc(
                                                &mut self.snapshot,
                                                key,
                                                *old_loc,
                                                *new_loc,
                                            );
                                        } else {
                                            Self::delete_loc(&mut self.snapshot, key, *old_loc);
                                        }
                                    } else {
                                        assert!(new_loc.is_some());
                                        self.snapshot.insert(key, new_loc.unwrap());
                                    }
                                }
                                uncommitted_ops.clear();
                                after_last_commit = None;
                            }
                            _ => unreachable!(
                                "unexpected operation type at offset {offset} of section {section}"
                            ),
                        }
                    }
                }
            }
        }

        // Rewind the operations log if necessary.
        if let Some((end_loc, end_offset)) = after_last_commit {
            assert!(!uncommitted_ops.is_empty());
            warn!(
                op_count = uncommitted_ops.len(),
                log_size = ?end_loc,
                end_offset,
                "rewinding over uncommitted operations at end of log"
            );
            let prune_to_section = *end_loc / self.log_items_per_section;
            self.log
                .rewind_to_offset(prune_to_section, end_offset)
                .await?;
            self.log.sync(prune_to_section).await?;
            self.log_size = end_loc;
        }

        // Pop any locations that are ahead of the last log commit point.
        if locations_size > self.log_size {
            warn!(
                locations_size,
                log_size = ?self.log_size,
                "rewinding uncommitted locations"
            );
            self.locations.rewind(*self.log_size).await?;
            self.locations.sync().await?;
        }

        // Confirm post-conditions hold.
        assert_eq!(self.log_size, self.locations.size().await?);
        self.last_commit = self
            .locations
            .size()
            .await?
            .checked_sub(1)
            .map(Location::new_unchecked);
        assert!(
            self.last_commit.is_none()
                || matches!(
                    self.get_op(self.last_commit.unwrap()).await?,
                    Operation::CommitFloor(_, _)
                )
        );

        debug!(log_size = ?self.log_size, "build_snapshot_from_log complete");

        Ok(self)
    }

    /// Append the operation to the log. The `commit` method must be called to make any applied operation
    /// persistent & recoverable.
    async fn apply_op(&mut self, op: Operation<K, V>) -> Result<u32, Error> {
        // Append the operation to the current section of the operations log.
        let section = self.current_section();
        let (offset, _) = self.log.append(section, op).await?;

        // Append the offset of the new operation to locations.
        self.locations.append(offset).await?;

        // Update the uncommitted operations count and increment the log size
        self.log_size += 1;

        // Maintain the invariant that all completely full sections are synced & immutable.
        if self.current_section() != section {
            self.log.sync(section).await?;
        }

        Ok(offset)
    }

    /// Gets the location of the most recent [Operation::Update] for the key, or [None] if the key
    /// does not have a value.
    async fn get_key_loc(&self, key: &K) -> Result<Option<Location>, Error> {
        for loc in self.snapshot.get(key) {
            match self.get_op(*loc).await {
                Ok(Operation::Update(k, _)) => {
                    if k == *key {
                        return Ok(Some(*loc));
                    }
                }
                Err(Error::OperationPruned(_)) => {
                    unreachable!("invalid location in snapshot: loc={loc}")
                }
                _ => unreachable!("non-update operation referenced by snapshot: loc={loc}"),
            }
        }

        Ok(None)
    }

    /// Gets a [Operation] from the log at the given location. Returns [Error::OperationPruned]
    /// if the location precedes the oldest retained location. The location is otherwise assumed
    /// valid.
    async fn get_op(&self, loc: Location) -> Result<Operation<K, V>, Error> {
        assert!(loc < self.log_size);
        if loc < self.oldest_retained_loc {
            return Err(Error::OperationPruned(loc));
        }

        let section = *loc / self.log_items_per_section;
        let offset = self.locations.read(*loc).await?;

        // Get the operation from the log at the specified section and offset.
        self.log.get(section, offset).await.map_err(Error::Journal)
    }

    /// Updates the snapshot with the new operation location for the given key.
    fn update_loc(
        snapshot: &mut Index<T, Location>,
        key: &K,
        old_loc: Location,
        new_loc: Location,
    ) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        // Find the location in the snapshot and update it.
        if cursor.find(|&loc| loc == old_loc) {
            cursor.update(new_loc);
        }
    }

    /// Deletes items in the snapshot that point to the given location.
    fn delete_loc(snapshot: &mut Index<T, Location>, key: &K, old_loc: Location) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        // Find the key in the snapshot and delete it.
        if cursor.find(|&loc| loc == old_loc) {
            cursor.delete();
        }
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    async fn move_op_if_active(
        &mut self,
        op: Operation<K, V>,
        old_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.key() else {
            // `op` is not a key-related operation, so it is not active.
            return Ok(None);
        };

        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        let new_loc = self.log_size;

        if cursor.find(|&loc| loc == old_loc) {
            // Update the location of the operation in the snapshot.
            cursor.update(new_loc);
            drop(cursor);

            self.apply_op(op).await?;
            Ok(Some(old_loc))
        } else {
            // The operation is not active, so this is a no-op.
            Ok(None)
        }
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
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        self.prune(target_prune_loc).await
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
        blake3::{hash, Digest},
        Digest as _,
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
            log_journal_partition: "journal".to_string(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            locations_journal_partition: "locations_journal".to_string(),
            locations_items_per_blob: NZU64!(11),
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
            assert_eq!(db.oldest_retained_loc, 0);
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

            assert_eq!(store.log_size, 1);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Sync the store to persist the changes
            store.sync().await.unwrap();

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(store.log_size, 0);
            assert_eq!(store.inactivity_floor_loc, 0);
            assert!(store.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair
            store.update(key, value.clone()).await.unwrap();

            assert_eq!(store.log_size, 1);
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
            assert_eq!(store.log_size, 3);
            assert_eq!(store.inactivity_floor_loc, 1);

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(store.log_size, 3);
            assert_eq!(store.inactivity_floor_loc, 1);

            // Fetch the value, ensuring it is still present
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);
            store.update(k1, v1.clone()).await.unwrap();
            store.update(k2, v2.clone()).await.unwrap();

            assert_eq!(store.log_size, 5);
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

            assert_eq!(store.log_size, 7);
            assert_eq!(store.inactivity_floor_loc, 2);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(store.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(store.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(store.get(&k2).await.unwrap().unwrap(), v2);

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
            assert_eq!(store.log_size, UPDATES * 2 + 1);
            // Only the highest `Update` operation is active, plus the commit operation above it.
            let expected_floor = UPDATES * 2 - 1;
            assert_eq!(store.inactivity_floor_loc, expected_floor);

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(
                store.oldest_retained_loc,
                expected_floor - expected_floor % 7
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
            store.delete(k).await.unwrap();

            // Ensure the key is no longer present
            let fetched_value = store.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

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
                let k = hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false).await.unwrap();
            let mut db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), 0);

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
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
                let k = hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false).await.unwrap();
            let mut db = create_test_store(context.with_label("store")).await;
            assert_eq!(db.op_count(), op_count);

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
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
                let k = hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false).await.unwrap();
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
                let k = hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            assert_eq!(db.op_count(), 1960);
            assert_eq!(db.inactivity_floor_loc, 755);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.oldest_retained_loc, 755 - 755 % 7);
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }
}
