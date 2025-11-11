//! A [Contiguous] journal with an [Unordered] index for fast key lookups.

use crate::{
    adb::operation::{Committable, Keyed},
    index::{Cursor, Unordered},
    journal::contiguous::Contiguous,
    mmr::Location,
    translator::Translator,
};
use commonware_runtime::Metrics;
use commonware_utils::NZUsize;
use core::{marker::PhantomData, num::NonZeroUsize};
use futures::{pin_mut, StreamExt as _};
use thiserror::Error;
use tracing::warn;

/// The size of the read buffer to use for replaying operations when rebuilding the index.
const INDEX_READ_BUFFER_SIZE: NonZeroUsize = NZUsize!(1 << 16);

/// Errors that can occur when interacting with an indexed contiguous journal.
#[derive(Error, Debug)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("operation pruned: {0}")]
    OperationPruned(Location),

    #[error("key not found")]
    KeyNotFound,
}

/// An indexed contiguous journal that maintains a index alongside an operation log.
///
/// The index maps keys to their locations in the journal, enabling efficient
/// lookups.
/// while maintaining a complete and durable operation history.
///
/// # Type Parameters
///
/// - `T`: The translator used to map keys to a compact representation
/// - `I`: The unordered index type storing the index
/// - `C`: The contiguous journal type storing operations
/// - `O`: The operation type, which must support key extraction
///
/// # Invariants
///
/// - The index only contains references to update operations (not deletes or other types)
/// - `active_keys` accurately reflects the number of keys with values in the index
/// - Operations in the journal at locations referenced by the index must be readable
pub struct IndexedContiguous<T, I, C, O>
where
    T: Translator,
    I: Unordered<T, Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
{
    /// The index mapping keys to their locations in the journal.
    index: I,

    /// The contiguous journal of operations.
    journal: C,

    /// Number of active keys.
    active_keys: usize,

    /// Phantom data for the translator and operation types.
    _phantom: PhantomData<(T, O)>,
}

impl<T, I, C, O> IndexedContiguous<T, I, C, O>
where
    T: Translator,
    I: Unordered<T, Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
{
    /// Find and return the location of the update operation for `key`, if it exists. The cursor is
    /// positioned at the matching location, and can be used to update or delete the key.
    async fn find_update_op<Cu>(
        journal: &C,
        cursor: &mut Cu,
        key: &O::Key,
    ) -> Result<Option<Location>, Error>
    where
        Cu: Cursor<Value = Location>,
    {
        while let Some(&loc) = cursor.next() {
            let op = journal.read(*loc).await?;
            let k = op.key().expect("operation without key");
            if *k == *key {
                return Ok(Some(loc));
            }
        }

        Ok(None)
    }

    /// Delete `key` from the index if it exists, returning the location that was previously
    /// associated with it.
    async fn delete_key(
        index: &mut I,
        journal: &C,
        key: &O::Key,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is in the index, get a cursor to look for the key.
        let Some(mut cursor) = index.get_mut(key) else {
            return Ok(None);
        };

        // Find the matching key among all conflicts, then delete it.
        let Some(loc) = Self::find_update_op(journal, &mut cursor, key).await? else {
            return Ok(None);
        };
        cursor.delete();

        Ok(Some(loc))
    }

    /// Update the location of `key` to `new_loc` in the index and return its old location, or insert
    /// it if the key isn't already present.
    async fn update_loc(
        index: &mut I,
        journal: &C,
        key: &O::Key,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the index, insert the new location. Otherwise, get a
        // cursor to look for the key.
        let Some(mut cursor) = index.get_mut_or_insert(key, new_loc) else {
            return Ok(None);
        };

        // Find the matching key among all conflicts, then update its location.
        if let Some(loc) = Self::find_update_op(journal, &mut cursor, key).await? {
            cursor.update(new_loc);
            return Ok(Some(loc));
        }

        // The key wasn't in the index, so add it to the cursor.
        cursor.insert(new_loc);

        Ok(None)
    }

    /// Initialize a new `IndexedContiguous` and build the index from the journal.
    ///
    /// Creates a new indexed journal that wraps an existing journal and builds the index
    /// by replaying operations from `pruning_boundary` to the current tip of the journal.
    ///
    /// # Arguments
    ///
    /// * `context` - Metrics context for the index
    /// * `translator` - The translator used to map keys to compact representations
    /// * `journal` - An already-initialized contiguous journal
    /// * `pruning_boundary` - The location to start replaying from
    pub async fn init(
        context: impl Metrics,
        translator: T,
        journal: C,
        pruning_boundary: Location,
    ) -> Result<Self, Error> {
        let index = I::init(context, translator);

        let mut indexed = Self {
            index: index,
            journal,
            active_keys: 0,
            _phantom: PhantomData,
        };

        indexed.build_index(pruning_boundary, |_, _| {}).await?;
        Ok(indexed)
    }

    /// Build or rebuild the index by replaying the journal starting at the given location.
    ///
    /// Replays operations from `pruning_boundary` to the current tip of the journal, updating the
    /// index for each keyed operation. The callback is invoked for each operation
    /// to notify the caller about activity status changes.
    ///
    /// # Arguments
    ///
    /// * `pruning_boundary` - The location to start replaying from
    /// * `callback` - Function invoked for each operation with `(is_active, inactivated_location)`
    ///
    /// # Callback Parameters
    ///
    /// - `is_active`: `true` if the operation is an active update, `false` if it's a delete
    /// - `inactivated_location`: The location of the operation that was inactivated (if any)
    pub async fn build_index<F>(
        &mut self,
        pruning_boundary: Location,
        mut callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        let stream = self
            .journal
            .replay(*pruning_boundary, INDEX_READ_BUFFER_SIZE)
            .await?;
        pin_mut!(stream);
        let last_commit_loc = self.journal.size().saturating_sub(1);

        while let Some(result) = stream.next().await {
            let (loc, op) = result?;
            if let Some(key) = op.key() {
                if op.is_delete() {
                    let old_loc = Self::delete_key(&mut self.index, &self.journal, key).await?;
                    callback(false, old_loc);
                    if old_loc.is_some() {
                        self.active_keys -= 1;
                    }
                } else if op.is_update() {
                    let new_loc = Location::new_unchecked(loc);
                    let old_loc =
                        Self::update_loc(&mut self.index, &self.journal, key, new_loc).await?;
                    callback(true, old_loc);
                    if old_loc.is_none() {
                        self.active_keys += 1;
                    }
                }
            } else if op.has_floor().is_some() {
                callback(loc == last_commit_loc, None);
            }
        }

        Ok(())
    }

    pub async fn append(&mut self, op: O) -> Result<Location, Error> {
        let new_loc = Location::new_unchecked(self.journal.size());

        // Update index before appending to journal
        if let Some(key) = op.key() {
            if op.is_delete() {
                if Self::delete_key(&mut self.index, &self.journal, key)
                    .await?
                    .is_some()
                {
                    self.active_keys -= 1;
                }
            } else if op.is_update() {
                if Self::update_loc(&mut self.index, &self.journal, key, new_loc)
                    .await?
                    .is_none()
                {
                    self.active_keys += 1;
                }
            }
        }

        self.journal.append(op).await?;

        Ok(new_loc)
    }

    pub async fn append_without_index_update(&mut self, op: O) -> Result<Location, Error> {
        let loc = self.journal.append(op).await?;
        Ok(Location::new_unchecked(loc))
    }

    pub async fn rewind_uncommitted(&mut self) -> Result<u64, Error>
    where
        O: Committable,
    {
        let log_size = self.journal.size();
        let mut rewind_size = log_size;
        while rewind_size > 0 {
            let op = self.journal.read(rewind_size - 1).await?;
            if op.is_commit() {
                break;
            }
            rewind_size -= 1;
        }
        if rewind_size != log_size {
            let rewound_ops = log_size - rewind_size;
            warn!(
                log_size,
                rewound_ops, "rewinding over uncommitted log operations"
            );
            self.journal.rewind(rewind_size).await?;
            self.journal.sync().await?;
        }

        Ok(rewind_size)
    }

    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        self.journal.rewind(size).await?;
        Ok(())
    }

    pub async fn get_location(&self, key: &O::Key) -> Result<Option<Location>, Error> {
        for &loc in self.index.get(key) {
            let op = self.journal.read(*loc).await?;
            let k = op.key().expect("operation without key");
            if *k == *key {
                return Ok(Some(loc));
            }
        }

        Ok(None)
    }

    /// Returns an iterator over all locations in the index for the given key.
    pub fn get_locations<'a>(&'a self, key: &'a O::Key) -> impl Iterator<Item = &'a Location> + 'a {
        self.index.get(key)
    }

    /// Returns a reference to the index.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// Returns a mutable reference to the index.
    pub fn index_mut(&mut self) -> &mut I {
        &mut self.index
    }

    /// Returns a reference to the journal.
    pub fn journal(&self) -> &C {
        &self.journal
    }

    /// Returns a mutable reference to the journal.
    pub fn journal_mut(&mut self) -> &mut C {
        &mut self.journal
    }

    /// Returns the number of active keys in the index.
    pub fn active_keys(&self) -> usize {
        self.active_keys
    }

    /// Returns the current size of the journal (number of operations).
    pub fn size(&self) -> u64 {
        self.journal.size()
    }

    /// Returns the location before which all items have been pruned.
    pub fn pruning_boundary(&self) -> u64 {
        self.journal.pruning_boundary()
    }

    /// Returns the oldest retained position in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        self.journal.oldest_retained_pos()
    }

    /// Commit the journal.
    ///
    /// Durably persists the journal but does not write all data, potentially leaving
    /// recovery required on startup. This is faster than `sync` but may require recovery
    /// on startup if a crash occurs before `sync`.
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.journal.commit().await?;
        Ok(())
    }

    /// Sync the journal.
    ///
    /// Durably persists the journal and writes all data, guaranteeing no recovery will
    /// be required on startup. This provides a stronger guarantee than `commit` but may
    /// be slower.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.journal.sync().await?;
        Ok(())
    }

    /// Close the journal, syncing all pending writes and releasing resources.
    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await?;
        Ok(())
    }

    /// Destroy the journal, removing all associated storage.
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::fixed::unordered::Operation,
        index::unordered::Index,
        journal::contiguous::fixed::{Config, Journal},
        translator::TwoCap,
    };
    use commonware_runtime::buffer::PoolRef;
    use commonware_runtime::deterministic::Runner;
    use commonware_runtime::Runner as _;
    use commonware_utils::{sequence::U64, NZUsize, NZU64};

    type TestIndexed = IndexedContiguous<
        TwoCap,
        Index<TwoCap, Location>,
        Journal<commonware_runtime::deterministic::Context, Operation<U64, U64>>,
        Operation<U64, U64>,
    >;

    #[test]
    fn test_init() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            assert_eq!(indexed.active_keys(), 0);
            assert_eq!(indexed.size(), 0);

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_append_update_operation() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let key = U64::new(123);
            let value = U64::new(456);
            let op = Operation::Update(key.clone(), value);

            let loc = indexed.append(op).await.unwrap();

            assert_eq!(*loc, 0);
            assert_eq!(indexed.active_keys(), 1);
            assert_eq!(indexed.size(), 1);

            // Verify we can find the key
            let found_loc = indexed.get_location(&key).await.unwrap();
            assert_eq!(found_loc, Some(loc));

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_append_delete_operation() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let key = U64::new(123);
            let value = U64::new(456);

            // First, add the key
            let _update_loc = indexed
                .append(Operation::Update(key.clone(), value))
                .await
                .unwrap();
            assert_eq!(indexed.active_keys(), 1);

            // Then delete it
            let _delete_loc = indexed
                .append(Operation::Delete(key.clone()))
                .await
                .unwrap();
            assert_eq!(indexed.active_keys(), 0);

            // Verify the key is no longer found
            let found_loc = indexed.get_location(&key).await.unwrap();
            assert_eq!(found_loc, None);

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_build_index_from_log() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let mut journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Pre-populate the journal
            let key1 = U64::new(1);
            let key2 = U64::new(2);
            let key3 = U64::new(3);
            journal
                .append(Operation::Update(key1.clone(), U64::new(100)))
                .await
                .unwrap();
            journal
                .append(Operation::Update(key2.clone(), U64::new(200)))
                .await
                .unwrap();
            journal
                .append(Operation::Delete(key1.clone()))
                .await
                .unwrap();
            journal
                .append(Operation::Update(key3.clone(), U64::new(300)))
                .await
                .unwrap();

            // Create indexed and build index
            let indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            // Check active keys
            assert_eq!(indexed.active_keys(), 2); // key2 and key3 are active

            // Check index contents
            assert_eq!(indexed.get_location(&key1).await.unwrap(), None); // deleted
            assert_eq!(
                indexed.get_location(&key2).await.unwrap(),
                Some(Location::new_unchecked(1))
            );
            assert_eq!(
                indexed.get_location(&key3).await.unwrap(),
                Some(Location::new_unchecked(3))
            );

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_uncommitted() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            // Add operations with a commit in between
            indexed
                .append(Operation::Update(U64::new(1), U64::new(100)))
                .await
                .unwrap();
            indexed
                .append(Operation::Update(U64::new(2), U64::new(200)))
                .await
                .unwrap();
            indexed
                .append(Operation::CommitFloor(Location::new_unchecked(0)))
                .await
                .unwrap();
            indexed
                .append(Operation::Update(U64::new(3), U64::new(300)))
                .await
                .unwrap();
            indexed
                .append(Operation::Update(U64::new(4), U64::new(400)))
                .await
                .unwrap();

            assert_eq!(indexed.size(), 5);

            // Rewind uncommitted should remove the last 2 operations
            let new_size = indexed.rewind_uncommitted().await.unwrap();
            assert_eq!(new_size, 3);
            assert_eq!(indexed.size(), 3);

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_update_same_key_multiple_times() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let key = U64::new(123);

            // Update the same key multiple times
            let loc1 = indexed
                .append(Operation::Update(key.clone(), U64::new(100)))
                .await
                .unwrap();
            let loc2 = indexed
                .append(Operation::Update(key.clone(), U64::new(200)))
                .await
                .unwrap();
            let loc3 = indexed
                .append(Operation::Update(key.clone(), U64::new(300)))
                .await
                .unwrap();

            // Active keys should still be 1
            assert_eq!(indexed.active_keys(), 1);

            // Should only find the latest location
            let found_loc = indexed.get_location(&key).await.unwrap();
            assert_eq!(found_loc, Some(loc3));
            assert_ne!(found_loc, Some(loc1));
            assert_ne!(found_loc, Some(loc2));

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rebuild_index() {
        // Test that we can rebuild a index by calling build_index again
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let mut journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Pre-populate the journal
            journal
                .append(Operation::Update(U64::new(1), U64::new(100)))
                .await
                .unwrap();
            journal
                .append(Operation::Update(U64::new(2), U64::new(200)))
                .await
                .unwrap();

            // Build initial index
            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            assert_eq!(indexed.active_keys(), 2);

            // Rebuild from a different location (should update existing entries)
            indexed
                .build_index(Location::new_unchecked(1), |_, _| {})
                .await
                .unwrap();
            // After rebuilding from location 1, we still have the same keys
            // (because we're just replaying the second operation again)
            assert_eq!(indexed.active_keys(), 2);

            indexed.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_append_without_index_update() {
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let key = U64::new(123);
            let value = U64::new(456);
            let op = Operation::Update(key.clone(), value);

            // Append without index update
            let _loc = indexed.append_without_index_update(op).await.unwrap();

            // Active keys should still be 0 since index wasn't updated
            assert_eq!(indexed.active_keys(), 0);

            // But the journal should have the operation
            assert_eq!(indexed.size(), 1);

            // Now build the index
            indexed
                .build_index(Location::new_unchecked(0), |_, _| {})
                .await
                .unwrap();

            // Now active keys should be 1
            assert_eq!(indexed.active_keys(), 1);

            indexed.destroy().await.unwrap();
        });
    }

    // Integration tests

    #[test]
    fn test_deterministic_replay() {
        // Test that building index incrementally vs in batch produces identical results
        let executor = Runner::default();
        executor.start(|ctx| async move {
            // Build incrementally
            let journal1 = Journal::init(
                ctx.with_label("journal1"),
                Config {
                    partition: "test1".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed1: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed1"),
                TwoCap,
                journal1,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let key1 = U64::new(1);
            let key2 = U64::new(2);
            indexed1
                .append(Operation::Update(key1.clone(), U64::new(100)))
                .await
                .unwrap();
            indexed1
                .append(Operation::Update(key2.clone(), U64::new(200)))
                .await
                .unwrap();
            indexed1
                .append(Operation::Delete(key1.clone()))
                .await
                .unwrap();
            indexed1
                .append(Operation::Update(key1.clone(), U64::new(300)))
                .await
                .unwrap();

            let active_keys_1 = indexed1.active_keys();
            let loc1_1 = indexed1.get_location(&key1).await.unwrap();
            let loc2_1 = indexed1.get_location(&key2).await.unwrap();

            // Build in batch
            let mut journal2 = Journal::init(
                ctx.with_label("journal2"),
                Config {
                    partition: "test2".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            journal2
                .append(Operation::Update(key1.clone(), U64::new(100)))
                .await
                .unwrap();
            journal2
                .append(Operation::Update(key2.clone(), U64::new(200)))
                .await
                .unwrap();
            journal2
                .append(Operation::Delete(key1.clone()))
                .await
                .unwrap();
            journal2
                .append(Operation::Update(key1.clone(), U64::new(300)))
                .await
                .unwrap();

            let indexed2: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed2"),
                TwoCap,
                journal2,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            let active_keys_2 = indexed2.active_keys();
            let loc1_2 = indexed2.get_location(&key1).await.unwrap();
            let loc2_2 = indexed2.get_location(&key2).await.unwrap();

            // Verify both produce identical results
            assert_eq!(active_keys_1, active_keys_2);
            assert_eq!(loc1_1, loc1_2);
            assert_eq!(loc2_1, loc2_2);

            indexed1.destroy().await.unwrap();
            indexed2.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_crash_recovery_simulation() {
        // Simulate a crash by dropping IndexedContiguous and recreating it
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let partition = "crash_test".to_string();

            // Phase 1: Create and populate
            {
                let journal = Journal::init(
                    ctx.with_label("journal"),
                    Config {
                        partition: partition.clone(),
                        items_per_blob: NZU64!(4),
                        buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                        write_buffer: NZUsize!(1024),
                    },
                )
                .await
                .unwrap();

                let mut indexed: TestIndexed = IndexedContiguous::init(
                    ctx.with_label("indexed"),
                    TwoCap,
                    journal,
                    Location::new_unchecked(0),
                )
                .await
                .unwrap();

                indexed
                    .append(Operation::Update(U64::new(1), U64::new(100)))
                    .await
                    .unwrap();
                indexed
                    .append(Operation::Update(U64::new(2), U64::new(200)))
                    .await
                    .unwrap();
                indexed.sync().await.unwrap();

                // Simulate crash by just dropping (not calling destroy)
            }

            // Phase 2: Recover
            {
                let journal = Journal::init(
                    ctx.with_label("journal"),
                    Config {
                        partition: partition.clone(),
                        items_per_blob: NZU64!(4),
                        buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                        write_buffer: NZUsize!(1024),
                    },
                )
                .await
                .unwrap();

                let indexed: TestIndexed = IndexedContiguous::init(
                    ctx.with_label("indexed"),
                    TwoCap,
                    journal,
                    Location::new_unchecked(0),
                )
                .await
                .unwrap();

                // Verify recovered state
                assert_eq!(indexed.active_keys(), 2);
                assert_eq!(indexed.size(), 2);
                assert!(indexed.get_location(&U64::new(1)).await.unwrap().is_some());
                assert!(indexed.get_location(&U64::new(2)).await.unwrap().is_some());

                indexed.destroy().await.unwrap();
            }
        });
    }

    #[test]
    fn test_committable_operations_with_rewind() {
        // Test rewind_uncommitted with mixed committed and uncommitted operations
        let executor = Runner::default();
        executor.start(|ctx| async move {
            let journal = Journal::init(
                ctx.with_label("journal"),
                Config {
                    partition: "committable_test".to_string(),
                    items_per_blob: NZU64!(4),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(4)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            let mut indexed: TestIndexed = IndexedContiguous::init(
                ctx.with_label("indexed"),
                TwoCap,
                journal,
                Location::new_unchecked(0),
            )
            .await
            .unwrap();

            // Add some operations and commit
            indexed
                .append(Operation::Update(U64::new(1), U64::new(100)))
                .await
                .unwrap();
            indexed
                .append(Operation::Update(U64::new(2), U64::new(200)))
                .await
                .unwrap();
            indexed
                .append(Operation::CommitFloor(Location::new_unchecked(0)))
                .await
                .unwrap();

            // Add more operations and commit
            indexed
                .append(Operation::Update(U64::new(3), U64::new(300)))
                .await
                .unwrap();
            indexed
                .append(Operation::CommitFloor(Location::new_unchecked(2)))
                .await
                .unwrap();

            // Add uncommitted operations
            indexed
                .append(Operation::Update(U64::new(4), U64::new(400)))
                .await
                .unwrap();
            indexed
                .append(Operation::Update(U64::new(5), U64::new(500)))
                .await
                .unwrap();

            assert_eq!(indexed.size(), 7);
            assert_eq!(indexed.active_keys(), 5);

            // Rewind uncommitted
            let new_size = indexed.rewind_uncommitted().await.unwrap();
            assert_eq!(new_size, 5); // Should rewind to last commit

            // Note: After rewinding, the index is stale (it still has keys 4 and 5)
            // In a real application, you would need to reinitialize IndexedContiguous
            // to get a fresh index. We just verify the journal was rewound correctly.
            assert_eq!(indexed.size(), 5);

            indexed.destroy().await.unwrap();
        });
    }
}
