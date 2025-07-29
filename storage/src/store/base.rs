//! A simple append-only key-value [`Store`], based on a log of state-change operations backed by a [`Journal`].

use crate::{
    index::Index,
    journal::fixed::{Config as JConfig, Journal},
    store::{operation::Fixed, Error, UpdateResult},
    translator::Translator,
};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use futures::{pin_mut, StreamExt};
use tracing::{debug, warn};

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for initializing a [`Store`] database.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [`RStorage`] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: usize,

    /// The [`Translator`] used by the compressed index.
    pub translator: T,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// A simple append-only key-value store backed by a log of operations.
///
/// The [`Store`] provides persistent key-value storage with transactional semantics and automatic
/// recovery. This store does not provide cryptographic authentication, making efficient for local storage
/// scenarios where proof generation is not required.
///
/// If data authentication is required for your use case, consider using [`crate::adb`] instead.
///
/// # Lifecycle
///
/// 1. **Initialization**: Create with [`Store::init`] using a [Config]
/// 2. **Operations**: Use [`Store::update`] and [`Store::delete`] to modify state
/// 3. **Queries**: Use [`Store::get`] to retrieve current values
/// 4. **Persistence**: Call [`Store::commit`] to make changes durable
/// 5. **Cleanup**: Call [`Store::close`] to shutdown gracefully or [`Store::destroy`] to remove all data
///
/// # Example
///
/// ```rust,ignore
/// use commonware_storage::store::base::{Store, Config};
/// use commonware_storage::translator::TwoCap;
/// use commonware_cryptography::Sha256;
/// use commonware_runtime::{
///     buffer::PoolRef,
///     deterministic::{self},
///     Runner as _,
/// };
///
/// const PAGE_SIZE: usize = 77;
/// const PAGE_CACHE_SIZE: usize = 9;
///
/// // Initialize store configuration
/// let config = Config {
///     log_journal_partition: "my_store_log".to_string(),
///     log_items_per_blob: 1000,
///     log_write_buffer: 64 * 1024,
///     translator: TwoCap,
///     buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
/// };
///
/// // Create and use the store
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     let mut store = Store::init(context, config).await.unwrap();
///     let key = Sha256::fill(1u8);
///     let value = Sha256::fill(2u8);
///     store.update(key, value).await.unwrap();
///     let retrieved_value = store.get(&key).await.unwrap();
///     store.commit().await.unwrap(); // Persist changes
///
///     store.destroy().await.unwrap(); // Clean up resources
/// });
/// ```
pub struct Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Array,
    T: Translator,
{
    /// The [`Store`]'s log of operations.
    ///
    /// This log is expected to be pruned to the `pruned_to_loc` boundary and contain all subsequent operations.
    pub(super) log: Journal<E, Fixed<K, V>>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(super) inactivity_floor_loc: u64,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [`Fixed::Update`].
    pub(super) snapshot: Index<T, u64>,

    /// The number of operations that are pending commit.
    pub(super) uncommitted_ops: u64,

    /// The total number of operations applied to the store (committed + uncommitted).
    ///
    /// This provides a monotonically increasing counter of all operations, including those
    /// not yet committed. It serves as the next available location for new operations.
    pub(super) op_count: u64,
}

impl<E, K, V, T> Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Array,
    T: Translator,
{
    /// Initialize a new [`Store`] from the given configuration.
    ///
    /// This method creates a new [`Store`] instance or recovers an existing one from persistent storage.
    /// Any uncommitted operations from a previous session are automatically discarded, ensuring
    /// the store state reflects only the last successfully committed operation.
    ///
    /// # Recovery Behavior
    ///
    /// On initialization, the store performs the following recovery steps:
    /// 1. Loads the operation log from persistent storage
    /// 2. Rewinds over any uncommitted operations (those after the last commit)
    /// 3. Rebuilds the in-memory snapshot by replaying committed operations
    /// 4. Sets the inactivity floor based on the pruning state
    ///
    /// # Arguments
    ///
    /// * `context` - The execution context providing storage, clock, and metrics
    /// * `cfg` - Configuration parameters for the store
    ///
    /// # Returns
    ///
    /// A newly initialized store ready for operations.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - The storage backend is inaccessible
    /// - The operation log is corrupted
    /// - The index cannot be initialized
    /// - Recovery from persistent state fails
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        let mut snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());

        let mut log = Journal::init(
            context.with_label("log"),
            JConfig {
                partition: cfg.log_journal_partition,
                items_per_blob: cfg.log_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        // Back up over / discard any uncommitted operations in the log.
        let log_size = log.size().await?;
        let mut rewind_pos = log_size;
        while rewind_pos > 0 {
            if let Fixed::Commit(_) = log.read(rewind_pos - 1).await? {
                break;
            }
            rewind_pos -= 1;
        }
        if rewind_pos != log_size {
            let op_count = log_size - rewind_pos;
            warn!(op_count, "rewinding over uncommitted log operations");
            log.rewind(rewind_pos).await?;
        }

        // Get the starting position for snapshot reconstruction based on journal pruning
        let start_pos = log.oldest_retained_pos().await?.unwrap_or(0);
        let inactivity_floor_loc =
            Self::build_snapshot_from_log(start_pos, &log, &mut snapshot).await?;

        // Initialize op_count to the current log size
        let op_count = log.size().await?;

        Ok(Store {
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            op_count,
        })
    }

    /// Retrieve the current value associated with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// * `Some(value)` if the key has an active value
    /// * `None` if the key has no value or has been deleted
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the operation log cannot be read to resolve the key's value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_with_loc(key).await?.map(|(v, _)| v))
    }

    /// Retrieve the current value and log location for the given key.
    ///
    /// This method returns both the key's current value and the location in the operation log
    /// where that value was set. This is useful for tracking operation history or debugging.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// * `Some((value, location))` if the key has an active value
    /// * `None` if the key has no value or has been deleted
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the operation log cannot be read to resolve the key's value.
    pub async fn get_with_loc(&self, key: &K) -> Result<Option<(V, u64)>, Error> {
        for &loc in self.snapshot.get(key) {
            let (k, v) = Self::get_update_op(&self.log, loc).await?;
            if k == *key {
                return Ok(Some((v, loc)));
            }
        }

        Ok(None)
    }

    /// Get the total number of operations applied to this store.
    ///
    /// This count includes both committed and uncommitted operations, providing the total
    /// number of operations that have been applied since the store was created. The count
    /// is monotonically increasing and serves as the next available operation location.
    ///
    /// # Returns
    ///
    /// The total operation count as a 64-bit unsigned integer.
    pub fn op_count(&self) -> u64 {
        self.op_count
    }

    /// Get the oldest operation location that remains readable in the log.
    ///
    /// Due to pruning, older operations may be removed from the log to save space.
    /// This method returns the location of the oldest operation that can still be read,
    /// or `None` if the log is empty.
    ///
    /// # Returns
    ///
    /// * `Some(location)` - The oldest readable operation location
    /// * `None` - The log is empty or all operations have been pruned
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the journal state cannot be queried.
    pub async fn oldest_retained_loc(&self) -> Result<Option<u64>, Error> {
        self.log
            .oldest_retained_pos()
            .await
            .map_err(Error::JournalError)
    }

    /// Update the value associated with the given key.
    ///
    /// If the key already has the exact same value, the operation is treated as a no-op and no log entry is created.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until [`Store::commit`] is called. Uncommitted operations will be rolled back
    /// if the store is closed without committing.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to update
    /// * `value` - The new value to associate with the key
    ///
    /// # Returns
    ///
    /// An [`UpdateResult`] indicating whether the operation resulted in an insertion,
    /// update, or no-op.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - The operation cannot be written to the log
    /// - The snapshot index cannot be updated
    pub async fn update(&mut self, key: K, value: V) -> Result<UpdateResult, Error> {
        let new_loc = self.op_count();
        let res = Self::update_loc(
            &mut self.snapshot,
            &self.log,
            key.clone(),
            Some(&value),
            new_loc,
        )
        .await?;
        match res {
            UpdateResult::NoOp => {
                // The key already has this value, so this is a no-op.
                return Ok(res);
            }
            UpdateResult::Inserted(_) => (),
            UpdateResult::Updated(_, _) => (),
        }

        let op = Fixed::Update(key, value);
        self.apply_op(op).await?;

        Ok(res)
    }

    /// Delete the given key and its associated value.
    ///
    /// If the key already has no value, the operation is treated as a no-op and no log entry is created.
    ///
    /// The deletion is immediately visible in subsequent queries, but remains uncommitted until
    /// [`Store::commit`] is called. Uncommitted deletions will be rolled back if the store is
    /// closed without committing.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    ///
    /// # Returns
    ///
    /// * `Some(location)` - The log location of the deleted value, if the key existed
    /// * `None` - The key had no value to delete
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - The delete operation cannot be written to the log
    /// - The snapshot index cannot be updated
    pub async fn delete(&mut self, key: K) -> Result<Option<u64>, Error> {
        let loc = self.op_count();
        let r = Self::delete_key(&mut self.snapshot, &self.log, &key, loc).await?;
        if r.is_some() {
            self.apply_op(Fixed::Deleted(key)).await?;
        };

        Ok(r)
    }

    /// Commit all pending operations to persistent storage.
    ///
    /// This method ensures that all operations performed since the last commit are durably
    /// persisted and will be recovered if the store is reopened. The commit process involves:
    ///
    /// 1. Advancing the inactivity floor to mark superseded operations as inactive
    /// 2. Writing a commit marker to the operation log
    /// 3. Synchronizing all data to persistent storage
    /// 4. Pruning inactive operations to reclaim space
    ///
    /// After a successful commit, the uncommitted operation count is reset to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - The commit marker cannot be written to the log
    /// - Data cannot be synchronized to persistent storage
    /// - Pruning of inactive operations fails
    ///
    /// # Note
    ///
    /// This operation may be expensive as it involves disk I/O and potentially significant
    /// computation to identify and prune inactive operations.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(self.uncommitted_ops + 1)
            .await?;
        self.uncommitted_ops = 0;
        self.sync().await?;

        // TODO: Make the frequency with which we prune known inactive items configurable in case
        // this turns out to be a significant part of commit overhead, or the user wants to ensure
        // the log is backed up externally before discarding.
        self.prune_inactive().await
    }

    /// Close the store, releasing all resources.
    ///
    /// This method performs a clean shutdown of the store, ensuring that all background
    /// operations are completed and resources are properly released. Any operations that
    /// have not been committed via [`Store::commit`] will be lost.
    ///
    /// # Warning
    ///
    /// Uncommitted operations will be permanently lost. If you need to preserve pending
    /// operations, call [`Store::commit`] before closing.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying journal cannot be closed cleanly.
    pub async fn close(self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing store with uncommitted operations"
            );
        }

        self.log.close().await.map_err(Error::JournalError)
    }

    /// Destroy the store, permanently removing all data from persistent storage.
    ///
    /// This method irreversibly deletes all store data, including the operation log and
    /// any cached state. Use this method when you want to completely remove a store and
    /// reclaim its storage space.
    ///
    /// # Warning
    ///
    /// This operation is irreversible. All data will be permanently lost.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying storage cannot be destroyed.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Error::JournalError)
    }

    /// Synchronize the store's current state to persistent storage.
    ///
    /// This method ensures that all buffered data is written to disk, but does not create
    /// a commit point. Unlike [`Store::commit`], this method does not advance the inactivity
    /// floor or prune operations.
    ///
    /// Use this method when you want to ensure data durability without creating a formal
    /// transaction boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the data cannot be synchronized to persistent storage.
    async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Error::JournalError)
    }

    /// Builds the database's snapshot by replaying the log starting at `start_pos`.
    async fn build_snapshot_from_log(
        start_pos: u64,
        log: &Journal<E, Fixed<K, V>>,
        snapshot: &mut Index<T, u64>,
    ) -> Result<u64, Error> {
        let mut inactivity_floor_loc = start_pos;

        let stream = log.replay(SNAPSHOT_READ_BUFFER_SIZE, start_pos).await?;
        pin_mut!(stream);
        while let Some(result) = stream.next().await {
            match result {
                Err(e) => {
                    return Err(Error::JournalError(e));
                }
                Ok((i, op)) => match op {
                    Fixed::Deleted(key) => {
                        Self::delete_key(snapshot, log, &key, i).await?;
                    }
                    Fixed::Update(key, _) => {
                        Self::update_loc(snapshot, log, key, None, i).await?;
                    }
                    Fixed::Commit(loc) => inactivity_floor_loc = loc,
                },
            }
        }

        Ok(inactivity_floor_loc)
    }

    /// Update the location of `key` to `new_loc` in the snapshot and return its old location, or
    /// insert it if the key isn't already present. If a `value` is provided, then it is used to see
    /// if the key is already assigned that value, in which case there is no update and
    /// UpdateResult::NoOp is returned.
    async fn update_loc(
        snapshot: &mut Index<T, u64>,
        log: &Journal<E, Fixed<K, V>>,
        key: K,
        value: Option<&V>,
        new_loc: u64,
    ) -> Result<UpdateResult, Error> {
        // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
        // cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut_or_insert(&key, new_loc) else {
            return Ok(UpdateResult::Inserted(new_loc));
        };

        // Iterate over conflicts in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, v) = Self::get_update_op(log, loc).await?;
            if k == key {
                // Found the key in the snapshot.
                if let Some(value) = value {
                    if v == *value {
                        // The key value is the same as the previous one: treat as a no-op.
                        return Ok(UpdateResult::NoOp);
                    }
                }

                // Update its location to the given one.
                assert!(new_loc > loc);
                cursor.update(new_loc);
                return Ok(UpdateResult::Updated(loc, new_loc));
            }
        }

        // The key wasn't in the snapshot, so add it to the cursor.
        cursor.insert(new_loc);
        Ok(UpdateResult::Inserted(new_loc))
    }

    /// Get the update operation corresponding to a location from the snapshot.
    ///
    /// # Warning
    ///
    /// Panics if the location does not reference an update operation. This should never happen
    /// unless the snapshot is buggy, or this method is being used to look up an operation
    /// independent of the snapshot contents.
    async fn get_update_op(log: &Journal<E, Fixed<K, V>>, loc: u64) -> Result<(K, V), Error> {
        let Fixed::Update(k, v) = log.read(loc).await? else {
            panic!("location does not reference update operation. loc={loc}");
        };

        Ok((k, v))
    }

    /// Delete `key` from the snapshot if it exists, returning the location that was previously
    /// associated with it.
    async fn delete_key(
        snapshot: &mut Index<T, u64>,
        log: &Journal<E, Fixed<K, V>>,
        key: &K,
        delete_loc: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is in the snapshot, get a cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return Ok(None);
        };
        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, _) = Self::get_update_op(log, loc).await?;
            if k == *key {
                // The key is in the snapshot, so delete it.
                //
                // If there are no longer any conflicting keys in the cursor, it will
                // automatically be removed from the snapshot.
                assert!(loc < delete_loc);
                cursor.delete();
                return Ok(Some(loc));
            }
        }

        // The key isn't in the conflicting keys, so this is a no-op.
        Ok(None)
    }

    /// Append the operation to the log. The `commit` method must be called to make any applied operation persistent & recoverable.
    async fn apply_op(&mut self, op: Fixed<K, V>) -> Result<u64, Error> {
        self.uncommitted_ops += 1;
        self.op_count += 1;

        // Append the operation to the log.
        self.log.append(op).await.map_err(Error::JournalError)
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    async fn move_op_if_active(
        &mut self,
        op: Fixed<K, V>,
        old_loc: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.to_key() else {
            // `op` is a commit
            return Ok(None);
        };
        let new_loc = self.op_count();
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            if loc == old_loc {
                // Update the location of the operation in the snapshot.
                cursor.update(new_loc);
                drop(cursor);

                // Apply the operation to the log.
                self.apply_op(op).await?;
                return Ok(Some(old_loc));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the store's snapshot.
    async fn raise_inactivity_floor(&mut self, max_steps: u64) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.log.read(self.inactivity_floor_loc).await?;
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Fixed::Commit(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune any historical operations that are known to be inactive (those preceding the
    /// inactivity floor). This does not affect the store's snapshot.
    async fn prune_inactive(&mut self) -> Result<(), Error> {
        let Some(oldest_retained_loc) = self.oldest_retained_loc().await? else {
            return Ok(());
        };

        let pruned_ops = self.inactivity_floor_loc - oldest_retained_loc;
        if pruned_ops == 0 {
            return Ok(());
        }
        debug!(pruned = pruned_ops, "pruning inactive ops");

        self.log.prune(self.inactivity_floor_loc).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self},
        Runner as _,
    };

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn store_config(suffix: &str) -> Config<TwoCap> {
        Config {
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: 7,
            log_write_buffer: 1024,
            translator: TwoCap,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete Store type used in these unit tests.
    type TestStore = Store<deterministic::Context, Digest, Digest, TwoCap>;

    /// Return a Store initialized with a fixed config.
    async fn open_store(context: deterministic::Context) -> TestStore {
        TestStore::init(context, store_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_store_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), 0);
            assert_eq!(store.oldest_retained_loc().await.unwrap(), None);
            assert!(matches!(store.prune_inactive().await, Ok(())));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            store.update(d1, d2).await.unwrap();
            store.close().await.unwrap();
            let mut store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), 0);

            // Test calling commit on an empty store which should make it (durably) non-empty.
            store.commit().await.unwrap();
            assert_eq!(store.op_count(), 1); // floor op added
            assert!(matches!(store.prune_inactive().await, Ok(())));
            let mut store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), 1);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                store.commit().await.unwrap();
                assert_eq!(store.op_count() - 1, store.inactivity_floor_loc);
            }

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_basic_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut store = open_store(context.clone()).await;

            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);

            assert!(store.get(&d1).await.unwrap().is_none());
            assert!(store.get(&d2).await.unwrap().is_none());

            // Insert first key-value pair
            assert!(matches!(
                store.update(d1, d2).await.unwrap(),
                UpdateResult::Inserted(0)
            ));
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d2);
            assert!(store.get(&d2).await.unwrap().is_none());

            // Insert second key-value pair
            assert!(matches!(
                store.update(d2, d1).await.unwrap(),
                UpdateResult::Inserted(1)
            ));
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d2);
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d1);

            // Delete first key
            assert!(matches!(store.delete(d1).await.unwrap(), Some(0)));
            assert!(store.get(&d1).await.unwrap().is_none());
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d1);

            // Re-insert first key with new value
            assert!(matches!(
                store.update(d1, d1).await.unwrap(),
                UpdateResult::Inserted(3)
            ));
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d1);

            // Update second key
            assert!(matches!(
                store.update(d2, d2).await.unwrap(),
                UpdateResult::Updated(1, 4)
            ));
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(store.op_count(), 5); // 4 updates, 1 deletion.
            assert_eq!(store.inactivity_floor_loc, 0);

            // Multiple assignments of the same value should be a no-op.
            assert!(matches!(
                store.update(d1, d1).await.unwrap(),
                UpdateResult::NoOp
            ));
            assert!(matches!(
                store.update(d2, d2).await.unwrap(),
                UpdateResult::NoOp
            ));
            // Op count should be unchanged.
            assert_eq!(store.op_count(), 5);

            // Test deletion of non-existent key is no-op
            let d3 = Sha256::fill(3u8);
            assert!(store.delete(d3).await.unwrap().is_none());
            assert_eq!(store.op_count(), 5);

            // Commit and verify state is persisted
            store.commit().await.unwrap();
            let op_count_after_commit = store.op_count();
            assert!(op_count_after_commit > 5); // Should include commit operations

            store.close().await.unwrap();
            let store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), op_count_after_commit);
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d1);
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d2);

            store.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut store = open_store(context.clone()).await;

            // Insert some data and sync but don't commit
            const ELEMENTS: u64 = 100;
            for i in 0u64..ELEMENTS {
                let k = Sha256::fill((i % 256) as u8);
                let v = Sha256::fill(((i * 1000) % 256) as u8);
                store.update(k, v).await.unwrap();
            }
            store.sync().await.unwrap();

            // Close without committing - data should be lost on reopen
            store.close().await.unwrap();
            let mut store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), 0);

            // Now insert data and commit
            for i in 0u64..ELEMENTS {
                let k = Sha256::fill((i % 256) as u8);
                let v = Sha256::fill(((i * 1000) % 256) as u8);
                store.update(k, v).await.unwrap();
            }
            store.commit().await.unwrap();
            let op_count = store.op_count();

            // Close and reopen - data should be preserved
            store.close().await.unwrap();
            let store = open_store(context.clone()).await;
            assert_eq!(store.op_count(), op_count);

            // Verify data integrity
            for i in 0u64..ELEMENTS {
                let k = Sha256::fill((i % 256) as u8);
                let expected_v = Sha256::fill(((i * 1000) % 256) as u8);
                if i < 256 {
                    // Only the last 256 entries should be present due to overwrites
                    let actual_v = store.get(&k).await.unwrap();
                    if let Some(v) = actual_v {
                        // The value should be the last one written for this key
                        assert_eq!(v, expected_v);
                    }
                }
            }

            store.destroy().await.unwrap();
        });
    }
}
