//! An indexed authenticated journal combining an authenticated journal with a key-to-location snapshot.
//!
//! # Purpose
//!
//! `IndexedJournal` extends `AuthenticatedJournal` by adding a snapshot index that maps keys to
//! their most recent operation locations. This enables the concept of "active" operations -
//! operations whose keys currently exist in the snapshot at specific locations.
//!
//! # Abstraction Boundaries
//!
//! **IndexedJournal knows about:**
//! - Snapshot (key → location mapping)
//! - Operations in the log (via AuthenticatedJournal)
//! - Whether specific operations are active (in snapshot)
//!
//! **IndexedJournal does NOT know about:**
//! - Inactivity floors (database-level policy)
//! - Floor-raising strategies (database-level logic)
//! - Commit policies (database-level logic)
//!
//! Databases implement their own policies using IndexedJournal's snapshot-aware primitives.
//!
//! # Key Methods
//!
//! - `move_op_if_active`: Check if an operation is active and move it to tip if so
//! - `update_key_loc`: Update a key's location in the snapshot
//! - `delete_key`: Remove a key from the snapshot
//! - `get_key_loc`: Query the current operation for a key
//!
//! # Invariants
//!
//! - The snapshot only contains locations for Update operations (never Delete or Commit)
//! - All locations in the snapshot reference valid positions in the authenticated journal's log

use crate::{
    adb::{
        authenticated_journal::AuthenticatedJournal,
        operation::{Committable, Keyed},
        Error,
    },
    index::{Cursor, Index},
    journal::contiguous::Contiguous,
    mmr::Location,
};
use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use futures::StreamExt as _;

pub struct IndexedJournal<
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed + Committable + Encode,
    H: Hasher,
> {
    /// The authenticated journal maintaining synchronized MMR and log.
    ///
    /// Handles all authenticated append-only operations without knowledge
    /// of keys or activity status.
    pub(crate) authenticated_journal: AuthenticatedJournal<E, C, O, H>,

    /// A snapshot mapping keys to their most recent operation locations.
    ///
    /// # Invariant
    ///
    /// Only contains locations of Update operations (not Delete or Commit).
    pub(crate) snapshot: I,
}

impl<E, I, C, O, H> IndexedJournal<E, I, C, O, H>
where
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed + Committable + Encode,
    H: Hasher,
{
    /// Create a new IndexedJournal from an authenticated journal and snapshot.
    ///
    /// # Invariants
    ///
    /// The caller must ensure the snapshot is consistent with the authenticated journal
    /// (all snapshot entries reference valid Update operations in the log).
    pub fn new(authenticated_journal: AuthenticatedJournal<E, C, O, H>, snapshot: I) -> Self {
        Self {
            authenticated_journal,
            snapshot,
        }
    }

    /// Initialize an IndexedJournal by building the snapshot from the log.
    ///
    /// This rebuilds the snapshot by replaying operations from `start_loc` onwards.
    /// The `callback` is invoked for each operation:
    /// - For Update: `callback(true, old_loc)` where `old_loc` is the previous location (if any)
    /// - For Delete: `callback(false, old_loc)` where `old_loc` is the previous location (if any)
    /// - For CommitFloor: `callback(is_last_op, None)` where `is_last_op` indicates if this is the last operation
    pub async fn init<F>(
        authenticated_journal: AuthenticatedJournal<E, C, O, H>,
        mut snapshot: I,
        start_loc: Location,
        mut callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        const BUFFER_SIZE: usize = 1024;

        // Process stream in a separate scope so it's dropped before we move authenticated_journal
        {
            let stream = authenticated_journal
                .log
                .replay(
                    *start_loc,
                    core::num::NonZeroUsize::new(BUFFER_SIZE).unwrap(),
                )
                .await?;
            futures::pin_mut!(stream);
            let last_commit_loc = authenticated_journal.log.size().await.saturating_sub(1);

            while let Some(result) = stream.next().await {
                let (loc, op) = result?;
                if let Some(key) = op.key() {
                    if op.is_delete() {
                        // Delete key from snapshot - find the matching location
                        let mut old_loc = None;
                        if let Some(mut cursor) = snapshot.get_mut(key) {
                            // Find the key's current location
                            while let Some(&snap_loc) = cursor.next() {
                                let snap_op = authenticated_journal.log.read(*snap_loc).await?;
                                if snap_op.key() == Some(key) {
                                    old_loc = Some(snap_loc);
                                    cursor.delete();
                                    break;
                                }
                            }
                        }
                        callback(false, old_loc);
                    } else if op.is_update() {
                        let new_loc = Location::new_unchecked(loc);
                        // Update key's location in snapshot
                        let mut old_loc = None;
                        if let Some(mut cursor) = snapshot.get_mut_or_insert(key, new_loc) {
                            // Find if key already exists
                            while let Some(&snap_loc) = cursor.next() {
                                let snap_op = authenticated_journal.log.read(*snap_loc).await?;
                                if snap_op.key() == Some(key) {
                                    assert!(new_loc > snap_loc);
                                    old_loc = Some(snap_loc);
                                    cursor.update(new_loc);
                                    break;
                                }
                            }
                            if old_loc.is_none() {
                                // Key not found, insert it
                                cursor.insert(new_loc);
                            }
                        }
                        callback(true, old_loc);
                    }
                } else if op.commit_floor().is_some() {
                    callback(loc == last_commit_loc, None);
                }
            }
        } // stream is dropped here

        Ok(Self {
            authenticated_journal,
            snapshot,
        })
    }

    /// Moves the given operation to the tip of the log if it is active.
    ///
    /// An operation is "active" if its key exists in the snapshot at this specific location.
    /// Returns `Ok(true)` if moved, `Ok(false)` if not active.
    pub async fn move_op_if_active(&mut self, op: O, old_loc: Location) -> Result<bool, Error> {
        let Some(key) = op.key() else {
            return Ok(false);
        };

        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(false);
        };
        if !cursor.find(|&loc| loc == old_loc) {
            return Ok(false);
        }

        cursor.update(Location::new_unchecked(
            self.authenticated_journal.log.size().await,
        ));
        drop(cursor);

        self.authenticated_journal.apply_op(op).await?;
        Ok(true)
    }

    /// Apply an operation: append to log+MMR and update snapshot.
    ///
    /// This is the common pattern used by databases when applying operations.
    /// For operations with keys (Update), updates the snapshot to point to the new location.
    /// For operations with keys (Delete), removes the key from the snapshot.
    /// For keyless operations (CommitFloor), just appends to log+MMR.
    pub async fn apply_op(&mut self, op: O) -> Result<(), Error> {
        // Get location where operation will be appended
        let new_loc = Location::new_unchecked(self.authenticated_journal.log.size().await);

        // If operation has a key, update snapshot first
        if let Some(key) = op.key() {
            if op.is_update() {
                // Update snapshot to point to new location
                self.update_key_loc(key, new_loc).await?;
            } else if op.is_delete() {
                // Delete from snapshot
                self.delete_key(key).await?;
            }
        }

        // Apply operation to authenticated journal (log + MMR)
        self.authenticated_journal.apply_op(op).await?;

        Ok(())
    }

    /// Updates the location of a key in the snapshot to `new_loc`.
    ///
    /// Returns the old location if the key existed, or None if it's a new key.
    pub async fn update_key_loc(
        &mut self,
        key: &<O as Keyed>::Key,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        let Some(mut cursor) = self.snapshot.get_mut_or_insert(key, new_loc) else {
            return Ok(None);
        };

        if let Some(loc) =
            Self::find_key_in_log(&self.authenticated_journal.log, &mut cursor, key).await?
        {
            assert!(new_loc > loc);
            cursor.update(new_loc);
            return Ok(Some(loc));
        }

        cursor.insert(new_loc);
        Ok(None)
    }

    /// Deletes a key from the snapshot if it exists.
    ///
    /// Returns the old location if the key existed, or None if it didn't.
    pub async fn delete_key(&mut self, key: &<O as Keyed>::Key) -> Result<Option<Location>, Error> {
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        let Some(loc) =
            Self::find_key_in_log(&self.authenticated_journal.log, &mut cursor, key).await?
        else {
            return Ok(None);
        };
        cursor.delete();
        Ok(Some(loc))
    }

    /// Helper: Find and return the location of the update operation for `key` in the log.
    ///
    /// Positions cursor at matching location for update/delete operations.
    async fn find_key_in_log<CUR>(
        log: &C,
        cursor: &mut CUR,
        key: &<O as Keyed>::Key,
    ) -> Result<Option<Location>, Error>
    where
        CUR: Cursor<Value = Location>,
    {
        while let Some(&loc) = cursor.next() {
            let op = log.read(*loc).await?;
            let k = op.key().expect("operation without key");
            if *k == *key {
                return Ok(Some(loc));
            }
        }
        Ok(None)
    }

    /// Get value and location for a key (used by unordered databases).
    pub async fn get_key_loc(
        &self,
        key: &<O as Keyed>::Key,
    ) -> Result<Option<(O, Location)>, Error> {
        for &loc in self.snapshot.get(key) {
            let op = self.authenticated_journal.log.read(*loc).await?;
            let k = op.key().expect("operation without key");
            if *k == *key {
                return Ok(Some((op, loc)));
            }
        }
        Ok(None)
    }

    /// Check if snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshot.keys() == 0
    }

    /// Get count of active keys.
    pub fn key_count(&self) -> u64 {
        self.snapshot.keys().try_into().expect("key count overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::fixed::unordered::Operation, index::unordered::Index,
        journal::contiguous::fixed::Journal, translator::EightCap,
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use core::num::NonZeroUsize as NZUsize;

    type TestKey = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestValue = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestOperation = Operation<TestKey, TestValue>;

    const PAGE_SIZE: usize = 1024;
    const PAGE_CACHE_SIZE: usize = 16;

    fn mmr_config() -> crate::mmr::journaled::Config {
        crate::mmr::journaled::Config {
            journal_partition: "mmr".to_string(),
            metadata_partition: "mmr_meta".to_string(),
            items_per_blob: 100.try_into().unwrap(),
            write_buffer: 1024.try_into().unwrap(),
            thread_pool: None,
            buffer_pool: PoolRef::new(
                NZUsize::new(PAGE_SIZE).unwrap(),
                NZUsize::new(PAGE_CACHE_SIZE).unwrap(),
            ),
        }
    }

    fn log_config() -> crate::journal::contiguous::fixed::Config {
        crate::journal::contiguous::fixed::Config {
            partition: "log".to_string(),
            items_per_blob: 100.try_into().unwrap(),
            write_buffer: 1024.try_into().unwrap(),
            buffer_pool: PoolRef::new(
                NZUsize::new(PAGE_SIZE).unwrap(),
                NZUsize::new(PAGE_CACHE_SIZE).unwrap(),
            ),
        }
    }

    #[test]
    fn test_move_op_if_active_moves_active_operation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize authenticated journal using new()
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            let snapshot = Index::init(context.with_label("snapshot"), EightCap);

            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // Add an operation
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let op = Operation::Update(key, value);
            let loc = Location::new_unchecked(0);

            indexed_journal
                .authenticated_journal
                .apply_op(op.clone())
                .await
                .unwrap();
            indexed_journal.update_key_loc(&key, loc).await.unwrap();

            // Verify the operation is active and can be moved
            let moved = indexed_journal.move_op_if_active(op, loc).await.unwrap();
            assert!(moved);

            // Verify the snapshot was updated
            let new_loc = Location::new_unchecked(1);
            let (found_op, found_loc) = indexed_journal.get_key_loc(&key).await.unwrap().unwrap();
            assert_eq!(found_loc, new_loc);
            if let Operation::Update(k, v) = found_op {
                assert_eq!(k, key);
                assert_eq!(v, value);
            } else {
                panic!("Expected Update operation");
            }
        });
    }

    #[test]
    fn test_move_op_if_active_returns_false_for_inactive() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            let snapshot = Index::init(context.with_label("snapshot"), EightCap);

            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // Try to move an operation that was never added to snapshot
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let op = Operation::Update(key, value);
            let loc = Location::new_unchecked(0);

            let moved = indexed_journal.move_op_if_active(op, loc).await.unwrap();
            assert!(!moved);
        });
    }

    #[test]
    fn test_move_op_if_active_returns_false_for_keyless_op() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            let snapshot = Index::init(context.with_label("snapshot"), EightCap);

            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // CommitFloor operations have no key
            let op = TestOperation::CommitFloor(Location::new_unchecked(0));
            let loc = Location::new_unchecked(0);

            let moved = indexed_journal.move_op_if_active(op, loc).await.unwrap();
            assert!(!moved);
        });
    }

    #[test]
    fn test_apply_op_update() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();
            let snapshot = Index::init(context.with_label("snapshot"), EightCap);
            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // Apply an Update operation
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(10u8);
            let op = TestOperation::Update(key, value);
            indexed_journal.apply_op(op.clone()).await.unwrap();

            // Verify operation was added to log
            assert_eq!(indexed_journal.authenticated_journal.log.size().await, 1);

            // Verify snapshot was updated
            let (retrieved_op, loc) = indexed_journal.get_key_loc(&key).await.unwrap().unwrap();
            assert_eq!(retrieved_op.key().unwrap(), &key);
            assert_eq!(loc, Location::new_unchecked(0));

            // Verify MMR was updated
            assert_eq!(
                indexed_journal.authenticated_journal.mmr.leaves(),
                Location::new_unchecked(1)
            );
        });
    }

    #[test]
    fn test_apply_op_delete() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();
            let snapshot = Index::init(context.with_label("snapshot"), EightCap);
            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // First apply an Update operation
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(10u8);
            let update_op = TestOperation::Update(key, value);
            indexed_journal.apply_op(update_op).await.unwrap();

            // Verify key is in snapshot
            assert_eq!(indexed_journal.key_count(), 1);

            // Now apply a Delete operation
            let delete_op = TestOperation::Delete(key);
            indexed_journal.apply_op(delete_op).await.unwrap();

            // Verify operation was added to log
            assert_eq!(indexed_journal.authenticated_journal.log.size().await, 2);

            // Verify key was deleted from snapshot
            assert_eq!(indexed_journal.key_count(), 0);
            assert!(indexed_journal.get_key_loc(&key).await.unwrap().is_none());

            // Verify MMR was updated
            assert_eq!(
                indexed_journal.authenticated_journal.mmr.leaves(),
                Location::new_unchecked(2)
            );
        });
    }

    #[test]
    fn test_apply_op_commit_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();
            let snapshot = Index::init(context.with_label("snapshot"), EightCap);
            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // Apply a CommitFloor operation (keyless)
            let commit_op = TestOperation::CommitFloor(Location::new_unchecked(0));
            indexed_journal.apply_op(commit_op).await.unwrap();

            // Verify operation was added to log
            assert_eq!(indexed_journal.authenticated_journal.log.size().await, 1);

            // Verify snapshot was not modified (CommitFloor has no key)
            assert_eq!(indexed_journal.key_count(), 0);

            // Verify MMR was updated
            assert_eq!(
                indexed_journal.authenticated_journal.mmr.leaves(),
                Location::new_unchecked(1)
            );
        });
    }

    #[test]
    fn test_init_builds_snapshot_from_log() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            // Populate the log with operations
            let key1 = Sha256::fill(1u8);
            let key2 = Sha256::fill(2u8);
            let value1 = Sha256::fill(10u8);
            let value2 = Sha256::fill(20u8);

            authenticated_journal
                .apply_op(TestOperation::Update(key1, value1))
                .await
                .unwrap();
            authenticated_journal
                .apply_op(TestOperation::Update(key2, value2))
                .await
                .unwrap();
            authenticated_journal
                .apply_op(TestOperation::CommitFloor(Location::new_unchecked(0)))
                .await
                .unwrap();

            // Close and recreate to simulate recovery scenario
            authenticated_journal.close().await.unwrap();

            // Re-initialize authenticated journal
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            // Initialize IndexedJournal which should build snapshot from log
            let snapshot = Index::init(context.with_label("snapshot"), EightCap);
            let mut callback_invocations = Vec::new();
            let indexed_journal = IndexedJournal::init(
                authenticated_journal,
                snapshot,
                Location::new_unchecked(0),
                |is_update, old_loc| {
                    callback_invocations.push((is_update, old_loc));
                },
            )
            .await
            .unwrap();

            // Verify snapshot was built correctly
            assert_eq!(indexed_journal.key_count(), 2);
            assert!(indexed_journal.get_key_loc(&key1).await.unwrap().is_some());
            assert!(indexed_journal.get_key_loc(&key2).await.unwrap().is_some());

            // Verify callback was invoked correctly
            assert_eq!(callback_invocations.len(), 3);
            assert_eq!(callback_invocations[0], (true, None)); // Update key1
            assert_eq!(callback_invocations[1], (true, None)); // Update key2
            assert_eq!(callback_invocations[2], (true, None)); // CommitFloor (last op)
        });
    }

    #[test]
    fn test_init_with_delete_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            // Create, then delete a key
            let key1 = Sha256::fill(1u8);
            let value1 = Sha256::fill(10u8);

            authenticated_journal
                .apply_op(TestOperation::Update(key1, value1))
                .await
                .unwrap();
            authenticated_journal
                .apply_op(TestOperation::Delete(key1))
                .await
                .unwrap();

            // Close and recreate
            authenticated_journal.close().await.unwrap();

            // Re-initialize
            let authenticated_journal =
                <AuthenticatedJournal<
                    deterministic::Context,
                    Journal<deterministic::Context, TestOperation>,
                    TestOperation,
                    Sha256,
                >>::new(context.clone(), mmr_config(), log_config())
                .await
                .unwrap();

            // Initialize IndexedJournal
            let snapshot = Index::init(context.with_label("snapshot"), EightCap);
            let indexed_journal = IndexedJournal::init(
                authenticated_journal,
                snapshot,
                Location::new_unchecked(0),
                |_, _| {},
            )
            .await
            .unwrap();

            // Verify key was deleted from snapshot
            assert_eq!(indexed_journal.key_count(), 0);
            assert!(indexed_journal.get_key_loc(&key1).await.unwrap().is_none());
        });
    }
}
