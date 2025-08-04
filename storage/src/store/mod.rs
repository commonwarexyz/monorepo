//! An unauthenticated key-value database with variable-sized values.
//!
//! # Terminology
//!
//! A _key_ in an unauthenticated database either has a _value_ or it doesn't. The _update_ operation
//! gives a key a specific value whether it previously had no value or had a different value. After
//! a key assumes a value, it can no longer be deleted, only updated with a new value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is a [`Variable::Set`] operation, and (3) it is the most recent operation for that key.
//!
//! # Lifecycle
//!
//! 1. **Initialization**: Create with [`Store::init`] using a [`Config`]
//! 2. **Insertion**: Use [`Store::update`] to set a value for a given key
//! 3. **Queries**: Use [`Store::get`] to retrieve current values
//! 4. **Persistence**: Call [`Store::commit`] to make changes durable
//! 5. **Cleanup**: Call [`Store::close`] to shutdown gracefully or [`Store::destroy`] to remove all data
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     store::{Config, Store},
//!     translator::TwoCap,
//! };
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_runtime::{deterministic::Runner, Metrics, Runner as _};
//!
//! let executor = Runner::default();
//! executor.start(|mut ctx| async move {
//!     let config = Config {
//!         log_journal_partition: "test_partition".to_string(),
//!         log_write_buffer: 64 * 1024,
//!         log_compression: None,
//!         log_codec_config: (),
//!         log_items_per_section: 4,
//!         translator: TwoCap,
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
//!     // Destroy the store
//!     store.destroy().await.unwrap();
//! });
//! ```
//!
//! # TODO
//! - [ ] Inactivity floor for pruning the log.

use crate::{
    adb::operation::Variable,
    index::Index,
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::{sequence::U32, Array, Span};
use futures::{pin_mut, try_join, StreamExt};
use tracing::warn;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for initializing a [`Store`] database.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [`RStorage`] partition used to persist the log of operations.
    pub log_journal_partition: String,

    /// The size of the write buffer to use for each blob in the [`Journal`].
    pub log_write_buffer: usize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [`Journal`].
    pub log_items_per_section: u64,

    /// The name of the [`RStorage`] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_items_per_blob: u64,

    /// The [`Translator`] used by the compressed index.
    pub translator: T,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// An unauthenticated key-value database based off of an append-only [`Journal`] of operations.
pub struct Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Span,
    T: Translator,
{
    /// A log of all [`Variable`] operations that have been applied to the store.
    log: VJournal<E, Variable<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// section and offset within the section containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [`Variable::Set`].
    snapshot: Index<T, u64>,

    /// The number of items to store in each section of the variable journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations: FJournal<E, U32>,

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
        cfg: Config<T, <Variable<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator);

        let mut log = VJournal::init(
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

        // Build the snapshot by replaying the log of operations.
        let op_count = Self::build_snapshot_from_log(&mut log, &mut snapshot).await?;

        Ok(Self {
            log,
            snapshot,
            log_items_per_section: cfg.log_items_per_section,
            locations,
            op_count,
            uncommitted_ops: 0,
        })
    }

    /// Gets the value associated with the given key in the store.
    ///
    /// If the key does not exist, returns `Ok(None)`.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for location in self.snapshot.get(key) {
            let (k, v) = Self::get_update_op(
                &self.log,
                &self.locations,
                self.log_items_per_section,
                *location,
            )
            .await?;

            if &k == key {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Updates the value associated with the given key in the store.
    ///
    /// If the key already has the same value, this is a no-op and no log entry is created.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [`Store::commit`] is called. Uncommitted operations will be rolled back
    /// if the store is closed without committing.
    pub async fn update(&mut self, key: K, value: V) -> Result<UpdateResult, Error> {
        // Check if this is a no-op
        if let Some(current_value) = self.get(&key).await? {
            if current_value == value {
                return Ok(UpdateResult::NoOp);
            }
        }

        let new_location = self.op_count;
        self.apply_op(Variable::Set(key.clone(), value.clone()))
            .await?;

        Self::update_loc(
            &mut self.snapshot,
            &self.log,
            &self.locations,
            self.log_items_per_section,
            key,
            value,
            new_location,
        )
        .await
    }

    /// Commits all uncommitted operations to the store, making them persistent and recoverable.
    pub async fn commit(&mut self) -> Result<(), Error> {
        if self.uncommitted_ops == 0 {
            warn!("No operations to commit");
            return Ok(());
        }

        // Apply a commit operation to mark the transaction boundary
        self.apply_op(Variable::Commit()).await?;

        // Sync all data to disk
        self.sync().await?;

        self.uncommitted_ops = 0;
        Ok(())
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
        try_join!(self.log.destroy(), self.locations.destroy(),)?;
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
    async fn build_snapshot_from_log(
        log: &mut VJournal<E, Variable<K, V>>,
        snapshot: &mut Index<T, u64>,
    ) -> Result<u64, Error> {
        let mut operations = Vec::new();

        // Replay operations from the log
        {
            let stream = log.replay(SNAPSHOT_READ_BUFFER_SIZE).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (section, offset, _size, op) = result?;
                operations.push((section, offset, op))
            }
        }

        // Find the last commit operation to determine where to rewind
        let mut rewind_pos = 0;
        for (i, (_section, _offset, op)) in operations.iter().enumerate().rev() {
            if let Variable::Commit() = op {
                // Everything up to and including the commit is committed
                rewind_pos = i + 1;
                break;
            }
        }

        // Rewind uncommitted operations if necessary
        if rewind_pos != operations.len() {
            let op_count = operations.len() - rewind_pos;
            warn!(op_count, "rewinding over uncommitted log operations");

            // Rewind to the appropriate position
            if rewind_pos > 0 {
                // Rewind to just after the last committed operation
                let (last_section, last_offset, _) = &operations[rewind_pos - 1];
                log.rewind(*last_section, *last_offset as u64 + 1)
                    .await
                    .map_err(Error::Journal)?;
            } else {
                // No commits found, rewind to beginning (empty log)
                log.rewind(0, 0).await.map_err(Error::Journal)?;
            }

            operations.truncate(rewind_pos);
        }

        for (pos, (_, _, op)) in operations.iter().enumerate() {
            if let Variable::Set(key, _) = op {
                let pos = pos as u64;

                let Some(mut cursor) = snapshot.get_mut_or_insert(key, pos) else {
                    continue;
                };

                // Set the cursor location to the most recent position for this key.
                while cursor.next().is_some() {
                    cursor.update(pos);
                    continue;
                }

                // Add the key to the snapshot.
                cursor.insert(pos);
            }
        }

        Ok(operations.len() as u64)
    }

    /// Append the operation to the log. The `commit` method must be called to make any applied operation
    /// persistent & recoverable.
    async fn apply_op(&mut self, op: Variable<K, V>) -> Result<u32, Error> {
        let old_section = self.op_count / self.log_items_per_section;

        self.uncommitted_ops += 1;
        self.op_count += 1;

        let section = self.op_count / self.log_items_per_section;

        // Append the operation to the entry log, and the offset to the locations log.
        let (offset, _size) = self.log.append(section, op).await?;
        self.locations.append(offset.into()).await?;

        // Sync the previous section if we transitioned to a new section
        if section != old_section {
            self.log.sync(old_section).await?;
        }

        Ok(offset)
    }

    /// Gets a [`Variable::Set`] operation from the log at the given location.
    ///
    /// # Panics
    ///
    /// Panics if the location does not reference a [`Variable::Set`] operation or if the
    /// section is not present in the log.
    async fn get_update_op(
        log: &VJournal<E, Variable<K, V>>,
        locations: &FJournal<E, U32>,
        log_items_per_section: u64,
        location: u64,
    ) -> Result<(K, V), Error> {
        let section = location / log_items_per_section;
        let offset = locations.read(location).await?.to_u32();

        let Some(Variable::Set(k, v)) = log.get(section, offset).await? else {
            panic!(
                "location does not reference set operation. section={section}, offset={section}",
            );
        };

        Ok((k, v))
    }

    /// Updates the snapshot with the new operation location for the given key.
    async fn update_loc(
        snapshot: &mut Index<T, u64>,
        log: &VJournal<E, Variable<K, V>>,
        locations: &FJournal<E, U32>,
        log_items_per_section: u64,
        key: K,
        value: V,
        new_location: u64,
    ) -> Result<UpdateResult, Error> {
        // Update the snapshot with the new operation location.
        let Some(mut cursor) = snapshot.get_mut_or_insert(&key, new_location) else {
            return Ok(UpdateResult::Inserted(new_location));
        };

        // Iterate over conflicts in the snapshot.
        while let Some(location) = cursor.next() {
            let (k, v) =
                Self::get_update_op(log, locations, log_items_per_section, *location).await?;
            if k == key {
                if v == value {
                    return Ok(UpdateResult::NoOp);
                }

                // Update the cursor with the new location for this key.
                let result = UpdateResult::Updated(*location, new_location);
                cursor.update(new_location);
                return Ok(result);
            }
        }

        // The key wasn't in the snapshot, so add it to the cursor.
        cursor.insert(new_location);
        Ok(UpdateResult::Inserted(new_location))
    }
}

/// The result of a database `update` operation.
pub enum UpdateResult {
    /// Tried to set a key to its current value.
    NoOp,
    /// Key was not previously in the snapshot & its new loc is the wrapped value.
    Inserted(u64),
    /// Key was previously in the snapshot & its (old, new) loc pair is wrapped.
    Updated(u64, u64),
}

/// Errors that can occur when interacting with a [`Store`] database.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Journal(#[from] crate::journal::Error),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,
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
            locations_items_per_blob: 7,
            translator: TwoCap,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        Store::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    fn test_store() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut store = create_test_store(ctx.with_label("store")).await;

            // Ensure the store is empty
            assert_eq!(store.op_count, 0);
            assert_eq!(store.uncommitted_ops, 0);

            let key = Digest::random(&mut ctx);
            let value = Digest::random(&mut ctx);

            // Attempt to get a key that does not exist
            let result = store.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            store.update(key, value).await.unwrap();

            assert_eq!(store.op_count, 1);
            assert_eq!(store.uncommitted_ops, 1);

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

            // Insert a key-value pair
            store.update(key, value).await.unwrap();

            assert_eq!(store.op_count, 1);
            assert_eq!(store.uncommitted_ops, 1);

            // Persist the changes
            store.commit().await.unwrap();

            assert_eq!(store.op_count, 2);
            assert_eq!(store.uncommitted_ops, 0);

            // Re-open the store
            let store = create_test_store(ctx.with_label("store")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(store.op_count, 2);
            assert_eq!(store.uncommitted_ops, 0);

            // Fetch the value
            let fetched_value = store.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

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
            const UPDATES: usize = 100;
            let k = Digest::random(&mut ctx);
            for _ in 0..UPDATES {
                let v = Digest::random(&mut ctx);
                store.update(k, v).await.unwrap();
            }

            store.commit().await.unwrap();
            store.close().await.unwrap();

            // Re-open the store to ensure it replays the log correctly.
            let store = create_test_store(ctx.with_label("store")).await;
            let iter = store.snapshot.get(&k);
            assert_eq!(iter.count(), UPDATES);

            store.destroy().await.unwrap();
        });
    }
}
