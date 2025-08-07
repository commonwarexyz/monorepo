//! A mutable key-value database that supports variable-sized values.
//!
//! # Terminology
//!
//! A _key_ in an unauthenticated database either has a _value_ or it doesn't. The _update_ operation
//! gives a key a specific value whether it previously had no value or had a different value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is a [`Operation::Set`] operation, and (3) it is the most recent operation for that key.
//!
//! # Lifecycle
//!
//! 1. **Initialization**: Create with [`Store::init`] using a [`Config`]
//! 2. **Insertion**: Use [`Store::update`] to set a value for a given key
//! 3. **Deletions**: Use [`Store::delete`] to remove a key's value
//! 4. **Persistence**: Call [`Store::commit`] to make changes durable
//! 5. **Queries**: Use [`Store::get`] to retrieve current values
//! 6. **Cleanup**: Call [`Store::close`] to shutdown gracefully or [`Store::destroy`] to remove all data
//!
//! # Pruning
//!
//! The database prunes _inactive_ operations every time [`Store::commit`] is called. To achieve this,
//! an _inactivity floor_ is maintained, which is the location at which all operations before are inactive.
//! At commit-time, the inactivity floor is raised by the number of uncommitted operations plus 1 for the
//! tailing commit op. During this process, any encountered active operations are re-applied to the tip of
//! the log.
//!
//! |                               Log State                                | Inactivity Floor | Uncommitted Ops |
//! |------------------------------------------------------------------------|------------------|-----------------|
//! | [pre-commit] Set(a, v), Set(a, v')                                     |                0 |               2 |
//! | [raise-floor] Set(a, v), Set(a, v'), Set(a, v'), Set(a, v')            |                3 |               2 |
//! | [prune+commit] Set(a, v'), Commit(3)                                   |                3 |               0 |
//! | [pre-commit] Set(a, v'), Commit(3), Set(b, v), Set(a, v'')             |                3 |               2 |
//! | [raise-floor] Set(a, v'), Commit(3), Set(b, v), Set(a, v''), Set(b, v) |                6 |               2 |
//! | [prune+commit] Set(a, v''), Set(b, v), Commit(6)                       |                6 |               0 |
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     store::{Config, Store},
//!     translator::TwoCap,
//! };
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
//!         log_write_buffer: 64 * 1024,
//!         log_compression: None,
//!         log_codec_config: (),
//!         log_items_per_section: 4,
//!         locations_journal_partition: "locations_partition".to_string(),
//!         locations_items_per_blob: 4,
//!         translator: TwoCap,
//!         buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
//!     store.commit().await.unwrap();
//!
//!     // Delete the key's value
//!     store.delete(k).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = store.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Commit the operation to make it persistent
//!     store.commit().await.unwrap();
//!
//!     // Destroy the store
//!     store.destroy().await.unwrap();
//! });
//! ```

use crate::{
    index::Index,
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
        Error as JError,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::{sequence::U32, Array, Span};
use futures::{pin_mut, try_join, StreamExt};
use tracing::{debug, warn};

pub mod operation;
use operation::Operation;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Errors that can occur when interacting with a [`Store`] database.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Journal(#[from] crate::journal::Error),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,
}

/// Configuration for initializing a [`Store`] database.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [`RStorage`] partition used to persist the log of operations.
    pub log_journal_partition: String,

    /// The size of the write buffer to use for each blob in the [`VJournal`].
    pub log_write_buffer: usize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [`VJournal`].
    pub log_items_per_section: u64,

    /// The name of the [`RStorage`] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_items_per_blob: u64,

    /// The [`Translator`] used by the compressed index.
    pub translator: T,

    /// The buffer pool to use for caching data.
    // TODO: Use this for the variable journal as well (#1223)
    pub buffer_pool: PoolRef,
}

/// An unauthenticated key-value database based off of an append-only [`VJournal`] of operations.
pub struct Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Span,
    T: Translator,
{
    /// A log of all [`Operation`]s that have been applied to the store.
    log: VJournal<E, Operation<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// section and offset within the section containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [`Operation::Set`].
    snapshot: Index<T, u64>,

    /// The number of items to store in each section of the variable journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations: FJournal<E, U32>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: u64,

    /// The location of the oldest operation in the log that remains readable.
    oldest_retained_loc: u64,

    /// The total numer of operations that have been applied to the store.
    op_count: u64,

    /// The number of operations that are pending commit.
    uncommitted_ops: u64,
}

impl<E, K, V, T> Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Span,
    T: Translator,
{
    /// Initializes a new [`Store`] database with the given configuration.
    ///
    /// ## Rollback
    ///
    /// Any uncommitted operations will be rolled back if the [`Store`] was previously closed without
    /// committing.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let snapshot: Index<T, u64> = Index::init(context.with_label("snapshot"), cfg.translator);

        let log = VJournal::init(
            context.with_label("log"),
            VConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
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
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        let db = Self {
            log,
            snapshot,
            log_items_per_section: cfg.log_items_per_section,
            locations,
            inactivity_floor_loc: 0,
            oldest_retained_loc: 0,
            op_count: 0,
            uncommitted_ops: 0,
        };
        db.build_snapshot_from_log().await
    }

    /// Gets the value associated with the given key in the store.
    ///
    /// If the key does not exist, returns `Ok(None)`.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for location in self.snapshot.get(key) {
            let Operation::Set(k, v) = self.get_op(*location).await? else {
                panic!("location ({location}) does not reference set operation",);
            };

            if &k == key {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Updates the value associated with the given key in the store.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [`Store::commit`] is called. Uncommitted operations will be rolled back
    /// if the store is closed without committing.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_location = self.op_count;
        if let Some(old_location) = self.get_loc(&key).await? {
            Self::update_loc(&mut self.snapshot, &key, old_location, new_location);
        } else {
            self.snapshot.insert(&key, new_location);
        };

        self.apply_op(Operation::Set(key.clone(), value.clone()))
            .await
            .map(|_| ())
    }

    /// Deletes the value associated with the given key in the store. If the key has no value,
    /// the operation is a no-op.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        let Some(old_loc) = self.get_loc(&key).await? else {
            // Key does not exist, so this is a no-op.
            return Ok(());
        };

        Self::delete_loc(&mut self.snapshot, &key, old_loc);

        self.apply_op(Operation::Delete(key)).await.map(|_| ())
    }

    /// Commits all uncommitted operations to the store, making them persistent and recoverable.
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.raise_inactivity_floor(self.uncommitted_ops + 1)
            .await?;
        self.uncommitted_ops = 0;

        self.sync().await?;
        self.prune_inactive().await
    }

    /// Closes the store. Any uncommitted operations will be lost if they have not been committed
    /// via [`Store::commit`].
    pub async fn close(self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing store with uncommitted operations"
            );
        }

        try_join!(self.log.close(), self.locations.close())?;
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

    /// Returns the number of operations that have been applied to the store.
    pub fn op_count(&self) -> u64 {
        self.op_count
    }

    /// Syncs the active section of the log to persistent storage.
    ///
    /// This method ensures that all buffered data is written to disk, but unlike [`Store::commit`],
    /// does not create a commit point.
    ///
    /// Use this method when you want to ensure data durability without creating a formal
    /// transaction boundary.
    async fn sync(&mut self) -> Result<(), Error> {
        let current_section = self.op_count / self.log_items_per_section;
        try_join!(self.log.sync(current_section), self.locations.sync())?;
        Ok(())
    }

    /// Builds the database's snapshot from the log of operations. Any operations that sit above
    /// the latest commit operation are removed.
    ///
    /// Returns the number of operations that were applied to the store, the oldest retained
    /// location, and the inactivity floor location.
    async fn build_snapshot_from_log(mut self) -> Result<Self, Error> {
        let mut uncommitted_updates = Vec::new();
        let mut uncommitted_ops = 0;
        let mut last_commit_loc = None;
        let mut oldest_retained_loc = None;

        {
            let stream = self.log.replay(SNAPSHOT_READ_BUFFER_SIZE).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (section, offset, _, op) = result?;

                if oldest_retained_loc.is_none() {
                    self.op_count = section * self.log_items_per_section;
                    oldest_retained_loc = Some(self.op_count);
                }

                let loc = self.op_count;
                self.op_count += 1;

                match op {
                    Operation::Set(key, _) => {
                        uncommitted_ops += 1;

                        uncommitted_updates.push((loc, section, offset, key));
                    }
                    Operation::Delete(key) => {
                        uncommitted_ops += 1;

                        // If there are any pending commit operations for this key, remove them
                        // before they are written to the snapshot.
                        uncommitted_updates = uncommitted_updates
                            .into_iter()
                            .filter(|(_, _, _, k)| *k != key)
                            .collect::<Vec<_>>();

                        let Some(old_loc) = self.get_loc(&key).await? else {
                            continue;
                        };

                        Self::delete_loc(&mut self.snapshot, &key, old_loc);
                    }
                    Operation::Commit(floor_loc) => {
                        // Bump the inactivity floor
                        self.inactivity_floor_loc = floor_loc;
                        last_commit_loc = Some((section, offset));

                        // Flush all uncommitted update operations to the snapshot
                        for (pos, _, _, key) in uncommitted_updates.iter() {
                            let Some(old_loc) = self.get_loc(key).await? else {
                                self.snapshot.insert(key, *pos);
                                continue;
                            };

                            Self::update_loc(&mut self.snapshot, key, old_loc, *pos);
                        }

                        // Clear uncommitted operations
                        uncommitted_updates.clear();
                        uncommitted_ops = 0;
                    }
                }
            }
        }

        if uncommitted_ops > 0 {
            if let Some((last_section, last_offset)) = last_commit_loc {
                let last_uncommitted_loc = self.op_count - uncommitted_ops;
                self.op_count = last_uncommitted_loc;

                try_join!(
                    self.log.rewind(last_section, last_offset as u64 + 1),
                    self.locations.rewind(last_uncommitted_loc)
                )?;
            } else {
                // No commits found; Drain log entirely.
                self.op_count = 0;
                try_join!(self.log.rewind(0, 0), self.locations.rewind(0))?;
            }
        }

        self.oldest_retained_loc = oldest_retained_loc.unwrap_or(0);

        assert_eq!(self.op_count, self.locations.size().await?);
        assert_eq!(self.uncommitted_ops, 0);

        Ok(self)
    }

    /// Append the operation to the log. The `commit` method must be called to make any applied operation
    /// persistent & recoverable.
    async fn apply_op(&mut self, op: Operation<K, V>) -> Result<u32, Error> {
        let current_section = self.op_count / self.log_items_per_section;

        // Append the operation to the entry log, and the offset to the locations log.
        //
        // The section number can be derived from the location by dividing the location
        // by the number of items to store in each section, hence why we only store a
        // map of location -> offset within the section.
        let (offset, _) = self.log.append(current_section, op).await?;
        self.locations.append(offset.into()).await?;

        self.uncommitted_ops += 1;
        self.op_count += 1;

        let new_section = self.op_count / self.log_items_per_section;

        // Sync the previous section if we transitioned to a new section
        if new_section != current_section {
            self.log.sync(current_section).await?;
        }

        Ok(offset)
    }

    /// Gets the location of the most recent [`Operation::Set`] for the key, or [`None`] if
    /// the key does not have a value.
    async fn get_loc(&self, key: &K) -> Result<Option<u64>, Error> {
        for loc in self.snapshot.get(key) {
            match self.get_op(*loc).await {
                Ok(Operation::Set(k, _)) => {
                    if k == *key {
                        return Ok(Some(*loc));
                    }
                }
                Err(Error::KeyNotFound) => return Ok(None),
                _ => continue,
            }
        }

        Ok(None)
    }

    /// Gets a [`Operation`] from the log at the given location.
    async fn get_op(&self, location: u64) -> Result<Operation<K, V>, Error> {
        let section = location / self.log_items_per_section;
        let offset = self.locations.read(location).await?.to_u32();

        // Get the operation from the log at the specified section and offset.
        let Some(op) = self.log.get(section, offset).await? else {
            return Err(Error::KeyNotFound);
        };

        Ok(op)
    }

    /// Updates the snapshot with the new operation location for the given key.
    fn update_loc(snapshot: &mut Index<T, u64>, key: &K, old_location: u64, new_location: u64) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        // Iterate over conflicts in the snapshot.
        while let Some(location) = cursor.next() {
            if *location == old_location {
                // Update the cursor with the new location for this key.
                cursor.update(new_location);
                return;
            }
        }
    }

    /// Deletes items in the snapshot that point to the given location.
    fn delete_loc(snapshot: &mut Index<T, u64>, key: &K, old_location: u64) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        // Iterate over conflicts in the snapshot.
        while let Some(location) = cursor.next() {
            if *location == old_location {
                // Delete the element from the cursor.
                cursor.delete();
                return;
            }
        }
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    async fn move_op_if_active(
        &mut self,
        op: Operation<K, V>,
        old_location: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.to_key() else {
            // `op` is not a key-related operation, so it is not active.
            return Ok(None);
        };

        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        let new_location = self.op_count;

        // Iterate over all conflicting keys in the snapshot.
        while let Some(&location) = cursor.next() {
            if location == old_location {
                // Update the location of the operation in the snapshot.
                cursor.update(new_location);
                drop(cursor);

                self.apply_op(op).await?;
                return Ok(Some(old_location));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the db's snapshot.
    async fn raise_inactivity_floor(&mut self, max_steps: u64) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count {
                break;
            }
            let op = self.get_op(self.inactivity_floor_loc).await?;
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Operation::Commit(self.inactivity_floor_loc))
            .await
            .map(|_| ())
    }

    /// Prune historical operations that are behind the inactivity floor. This does not affect the
    /// current snapshot.
    async fn prune_inactive(&mut self) -> Result<(), Error> {
        if self.op_count == 0 {
            return Ok(());
        }

        // Calculate the target pruning position: inactivity_floor_loc.
        let target_prune_loc = self.inactivity_floor_loc;
        let ops_to_prune = target_prune_loc.saturating_sub(self.oldest_retained_loc);
        if ops_to_prune == 0 {
            return Ok(());
        }
        debug!(ops_to_prune, target_prune_loc, "pruning inactive ops");

        // Prune the log up to the section containing the requested pruning location. We always
        // prune the log first, and then prune the locations structure based on the log's
        // actual pruning boundary. This procedure ensures all log operations always have
        // corresponding location entries, even in the event of failures, with no need for
        // special recovery.
        let section = target_prune_loc / self.log_items_per_section;
        match self.log.prune(section).await {
            Ok(_) | Err(JError::AlreadyPrunedToSection(_)) => {
                // Treat "already pruned to section" as a no-op.
            }
            Err(e) => {
                return Err(Error::Journal(e));
            }
        }
        self.oldest_retained_loc = section * self.log_items_per_section;

        // Prune the locations map up to the oldest retained item in the log after pruning.
        self.locations
            .prune(self.oldest_retained_loc)
            .await
            .map_err(Error::Journal)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_cryptography::{blake3::Digest, Digest as _};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    /// The type of the store used in tests.
    type TestStore = Store<deterministic::Context, Digest, Digest, TwoCap>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = Config {
            log_journal_partition: "journal".to_string(),
            log_write_buffer: 64 * 1024,
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: 4,
            locations_journal_partition: "locations".to_string(),
            locations_items_per_blob: 4,
            translator: TwoCap,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            assert!(matches!(db.prune_inactive().await, Ok(())));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = Digest::random(&mut context);
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = create_test_store(context.clone()).await;
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1);
            assert!(matches!(db.prune_inactive().await, Ok(())));
            let mut db = create_test_store(context.clone()).await;

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit().await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
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
            assert_eq!(store.op_count, 0);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = Digest::random(&mut ctx);

            // Attempt to get a key that does not exist
            let result = store.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            store.update(key, value).await.unwrap();

            assert_eq!(store.op_count, 1);
            assert_eq!(store.uncommitted_ops, 1);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Sync the store to persist the changes
            store.sync().await.unwrap();

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(store.op_count, 0);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Insert a key-value pair
            store.update(key, value).await.unwrap();

            assert_eq!(store.op_count, 1);
            assert_eq!(store.uncommitted_ops, 1);
            assert_eq!(store.inactivity_floor_loc, 0);

            // Persist the changes
            store.commit().await.unwrap();

            // Even though the store was pruned, the inactivity floor was raised by 2, and
            // the old operations remain in the same blob as an active operation, so they're
            // retained.
            assert_eq!(store.op_count, 4);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 2);

            // Re-open the store
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(store.op_count, 4);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), Digest::random(&mut ctx));
            let (k2, v2) = (Digest::random(&mut ctx), Digest::random(&mut ctx));
            store.update(k1, v1).await.unwrap();
            store.update(k2, v2).await.unwrap();

            assert_eq!(store.op_count, 6);
            assert_eq!(store.uncommitted_ops, 2);
            assert_eq!(store.inactivity_floor_loc, 2);

            store.commit().await.unwrap();

            assert_eq!(store.op_count, 9);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 5);

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
                let v = Digest::random(&mut ctx);
                store.update(k, v).await.unwrap();
            }

            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            store.commit().await.unwrap();
            store.close().await.unwrap();

            // Re-open the store to ensure it replays the log correctly.
            let store = create_test_store(ctx.with_label("store")).await;

            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // 100 operations were applied, and two were moved due to their activity, plus
            // the commit operation.
            assert_eq!(store.op_count, UPDATES + 3);
            // Only the highest `Set` operation is active, plus the commit operation above it.
            assert_eq!(store.inactivity_floor_loc, UPDATES + 1);
            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(store.oldest_retained_loc, UPDATES);
            assert_eq!(store.uncommitted_ops, 0);

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            let (k1, v1) = (Digest::random(&mut ctx), Digest::random(&mut ctx));
            let (mut k2, v2) = (Digest::random(&mut ctx), Digest::random(&mut ctx));

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            store.update(k1, v1).await.unwrap();
            store.update(k2, v2).await.unwrap();

            assert_eq!(store.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(store.get(&k2).await.unwrap().unwrap(), v2);

            store.commit().await.unwrap();
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
            let v = Digest::random(&mut ctx);
            store.update(k, v).await.unwrap();

            // Fetch the value
            let fetched_value = store.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            store.delete(k).await.unwrap();

            // Ensure the key is no longer present
            let fetched_value = store.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Commit the changes
            store.commit().await.unwrap();

            // Re-open the store and ensure the key is still deleted
            let mut store = create_test_store(ctx.with_label("store")).await;
            let fetched_value = store.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            store.update(k, v).await.unwrap();
            let fetched_value = store.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Commit the changes
            store.commit().await.unwrap();

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

            let v_a = Digest::random(&mut ctx);
            let v_b = Digest::random(&mut ctx);
            let v_c = Digest::random(&mut ctx);

            store.update(k_a, v_a).await.unwrap();
            store.update(k_b, v_b).await.unwrap();

            store.commit().await.unwrap();
            assert_eq!(store.op_count, 6);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 3);
            assert_eq!(store.get(&k_a).await.unwrap().unwrap(), v_a);

            store.update(k_b, v_a).await.unwrap();
            store.update(k_a, v_c).await.unwrap();

            store.commit().await.unwrap();
            assert_eq!(store.op_count, 9);
            assert_eq!(store.uncommitted_ops, 0);
            assert_eq!(store.inactivity_floor_loc, 6);
            assert_eq!(store.get(&k_a).await.unwrap().unwrap(), v_c);
            assert_eq!(store.get(&k_b).await.unwrap().unwrap(), v_a);

            store.destroy().await.unwrap();
        });
    }
}
