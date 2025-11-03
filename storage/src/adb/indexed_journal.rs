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
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

pub struct IndexedJournal<
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
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
    O: Keyed + Committable,
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
        adb::operation::fixed::unordered::Operation,
        index::unordered::Index,
        journal::contiguous::fixed::Journal,
        mmr::{journaled::Mmr, StandardHasher},
        translator::EightCap,
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use core::num::NonZeroUsize as NZUsize;

    type TestKey = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestValue = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestOperation = Operation<TestKey, TestValue>;

    const PAGE_SIZE: usize = 1024;
    const PAGE_CACHE_SIZE: usize = 16;

    #[test]
    fn test_move_op_if_active_moves_active_operation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();

            // Initialize authenticated journal
            let mmr = Mmr::init(
                context.with_label("mmr"),
                &mut hasher,
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
                },
            )
            .await
            .unwrap();

            let log = Journal::init(
                context.with_label("log"),
                crate::journal::contiguous::fixed::Config {
                    partition: "log".to_string(),
                    items_per_blob: 100.try_into().unwrap(),
                    write_buffer: 1024.try_into().unwrap(),
                    buffer_pool: PoolRef::new(
                        NZUsize::new(PAGE_SIZE).unwrap(),
                        NZUsize::new(PAGE_CACHE_SIZE).unwrap(),
                    ),
                },
            )
            .await
            .unwrap();

            let authenticated_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

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
            let mut hasher = StandardHasher::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("mmr"),
                &mut hasher,
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
                },
            )
            .await
            .unwrap();

            let log = Journal::init(
                context.with_label("log"),
                crate::journal::contiguous::fixed::Config {
                    partition: "log".to_string(),
                    items_per_blob: 100.try_into().unwrap(),
                    write_buffer: 1024.try_into().unwrap(),
                    buffer_pool: PoolRef::new(
                        NZUsize::new(PAGE_SIZE).unwrap(),
                        NZUsize::new(PAGE_CACHE_SIZE).unwrap(),
                    ),
                },
            )
            .await
            .unwrap();

            let authenticated_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

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
            let mut hasher = StandardHasher::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("mmr"),
                &mut hasher,
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
                },
            )
            .await
            .unwrap();

            let log = Journal::init(
                context.with_label("log"),
                crate::journal::contiguous::fixed::Config {
                    partition: "log".to_string(),
                    items_per_blob: 100.try_into().unwrap(),
                    write_buffer: 1024.try_into().unwrap(),
                    buffer_pool: PoolRef::new(
                        NZUsize::new(PAGE_SIZE).unwrap(),
                        NZUsize::new(PAGE_CACHE_SIZE).unwrap(),
                    ),
                },
            )
            .await
            .unwrap();

            let authenticated_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            let snapshot = Index::init(context.with_label("snapshot"), EightCap);

            let mut indexed_journal = IndexedJournal::new(authenticated_journal, snapshot);

            // CommitFloor operations have no key
            let op = TestOperation::CommitFloor(Location::new_unchecked(0));
            let loc = Location::new_unchecked(0);

            let moved = indexed_journal.move_op_if_active(op, loc).await.unwrap();
            assert!(!moved);
        });
    }
}
