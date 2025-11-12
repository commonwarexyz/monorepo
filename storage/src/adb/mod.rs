//! A collection of authenticated databases (ADB).
//!
//! # Terminology
//!
//! A _key_ in an authenticated database either has a _value_ or it doesn't. Two types of
//! _operations_ can be applied to the db to modify the state of a specific key. A key that has a
//! value can change to one without a value through the _delete_ operation. The _update_ operation
//! gives a key a specific value whether it previously had no value or had a different value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is an update operation, and (3) it is the most recent operation for that key.

use crate::{
    adb::operation::{Committable, Keyed},
    index::{Cursor, Unordered as Index},
    journal::contiguous::Contiguous,
    mmr::{bitmap::BitMap, Location},
    translator::Translator,
};
use commonware_cryptography::Digest;
use commonware_utils::NZUsize;
use core::{marker::PhantomData, num::NonZeroUsize};
use futures::{pin_mut, StreamExt as _};
use thiserror::Error;
use tracing::warn;

pub mod any;
pub mod current;
pub mod immutable;
pub mod keyless;
pub mod operation;
pub mod store;
pub mod sync;
pub mod verify;
pub use verify::{
    create_multi_proof, create_proof, create_proof_store, create_proof_store_from_digests,
    digests_required_for_proof, extract_pinned_nodes, verify_multi_proof, verify_proof,
    verify_proof_and_extract_digests,
};

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    Mmr(#[from] crate::mmr::Error),

    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    #[error("operation pruned: {0}")]
    OperationPruned(Location),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,

    /// The key exists in the db, so we cannot prove its exclusion.
    #[error("key exists")]
    KeyExists,

    #[error("unexpected data at location: {0}")]
    UnexpectedData(Location),

    #[error("location out of bounds: {0} >= {1}")]
    LocationOutOfBounds(Location, Location),

    #[error("prune location {0} beyond minimum required location {1}")]
    PruneBeyondMinRequired(Location, Location),

    #[error("uncommitted operations present")]
    UncommittedOperations,
}

impl From<crate::journal::authenticated::Error> for Error {
    fn from(e: crate::journal::authenticated::Error) -> Self {
        match e {
            crate::journal::authenticated::Error::Journal(j) => Error::Journal(j),
            crate::journal::authenticated::Error::Mmr(m) => Error::Mmr(m),
        }
    }
}

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: NonZeroUsize = NZUsize!(1 << 16);

/// Rewinds the log to the point of the last commit, returning the size of the log after rewinding.
/// Assumes there is at least one unpruned commit operation in the log if the log has been pruned.
pub(super) async fn rewind_uncommitted<O: Committable>(
    log: &mut impl Contiguous<Item = O>,
) -> Result<u64, Error> {
    let log_size = log.size();
    let mut rewind_size = log_size;
    while rewind_size > 0 {
        if log.read(rewind_size - 1).await?.is_commit() {
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
        log.rewind(rewind_size).await?;
        log.sync().await?;
    }

    Ok(rewind_size)
}

/// Builds the database's snapshot by replaying the log starting at the inactivity floor. Assumes
/// the log is not pruned beyond the inactivity floor. The callback is invoked for each replayed
/// operation, indicating activity status updates. The first argument of the callback is the
/// activity status of the operation, and the second argument is the location of the operation it
/// inactivates (if any). Returns the number of active keys in the db.
pub(super) async fn build_snapshot_from_log<O, T, I, F>(
    inactivity_floor_loc: Location,
    log: &impl Contiguous<Item = O>,
    snapshot: &mut I,
    mut callback: F,
) -> Result<usize, Error>
where
    O: Keyed,
    T: Translator,
    I: Index<T, Value = Location>,
    F: FnMut(bool, Option<Location>),
{
    let stream = log
        .replay(*inactivity_floor_loc, SNAPSHOT_READ_BUFFER_SIZE)
        .await?;
    pin_mut!(stream);
    let last_commit_loc = log.size().saturating_sub(1);
    let mut active_keys: usize = 0;
    while let Some(result) = stream.next().await {
        let (loc, op) = result?;
        if let Some(key) = op.key() {
            if op.is_delete() {
                let old_loc = delete_key(snapshot, log, key).await?;
                callback(false, old_loc);
                if old_loc.is_some() {
                    active_keys -= 1;
                }
            } else if op.is_update() {
                let new_loc = Location::new_unchecked(loc);
                let old_loc = update_loc(snapshot, log, key, new_loc).await?;
                callback(true, old_loc);
                if old_loc.is_none() {
                    active_keys += 1;
                }
            }
        } else if op.has_floor().is_some() {
            callback(loc == last_commit_loc, None);
        }
    }

    Ok(active_keys)
}

/// Delete `key` from the snapshot if it exists, returning the location that was previously
/// associated with it.
async fn delete_key<T, I, O>(
    snapshot: &mut I,
    log: &impl Contiguous<Item = O>,
    key: &O::Key,
) -> Result<Option<Location>, Error>
where
    T: Translator,
    I: Index<T, Value = Location>,
    O: Keyed,
{
    // If the translated key is in the snapshot, get a cursor to look for the key.
    let Some(mut cursor) = snapshot.get_mut(key) else {
        return Ok(None);
    };

    // Find the matching key among all conflicts, then delete it.
    let Some(loc) = find_update_op(log, &mut cursor, key).await? else {
        return Ok(None);
    };
    cursor.delete();

    Ok(Some(loc))
}

/// Update the location of `key` to `new_loc` in the snapshot and return its old location, or insert
/// it if the key isn't already present.
async fn update_loc<T, I, O>(
    snapshot: &mut I,
    log: &impl Contiguous<Item = O>,
    key: &<O as Keyed>::Key,
    new_loc: Location,
) -> Result<Option<Location>, Error>
where
    T: Translator,
    I: Index<T, Value = Location>,
    O: Keyed,
{
    // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
    // cursor to look for the key.
    let Some(mut cursor) = snapshot.get_mut_or_insert(key, new_loc) else {
        return Ok(None);
    };

    // Find the matching key among all conflicts, then update its location.
    if let Some(loc) = find_update_op(log, &mut cursor, key).await? {
        assert!(new_loc > loc);
        cursor.update(new_loc);
        return Ok(Some(loc));
    }

    // The key wasn't in the snapshot, so add it to the cursor.
    cursor.insert(new_loc);

    Ok(None)
}

/// Find and return the location of the update operation for `key`, if it exists. The cursor is
/// positioned at the matching location, and can be used to update or delete the key.
async fn find_update_op<C, O>(
    log: &impl Contiguous<Item = O>,
    cursor: &mut C,
    key: &<O as Keyed>::Key,
) -> Result<Option<Location>, Error>
where
    C: Cursor<Value = Location>,
    O: Keyed,
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

/// A wrapper of DB state required for implementing inactivity floor management.
pub(crate) struct FloorHelper<
    'a,
    T: Translator,
    I: Index<T, Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
> {
    pub snapshot: &'a mut I,
    pub log: &'a mut C,
    pub translator: PhantomData<T>,
}

impl<T, I, C, O> FloorHelper<'_, T, I, C, O>
where
    T: Translator,
    I: Index<T, Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
{
    /// Moves the given operation to the tip of the log if it is active, rendering its old location
    /// inactive. If the operation was not active, then this is a no-op. Returns whether the
    /// operation was moved.
    async fn move_op_if_active(&mut self, op: O, old_loc: Location) -> Result<bool, Error> {
        let Some(key) = op.key() else {
            return Ok(false); // operations without keys cannot be active
        };

        // If we find a snapshot entry corresponding to the operation, we know it's active.
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(false);
        };
        if !cursor.find(|&loc| loc == old_loc) {
            return Ok(false);
        }

        // Update the operation's snapshot location to point to tip.
        cursor.update(Location::new_unchecked(self.log.size()));
        drop(cursor);

        // Apply the operation at tip.
        self.log.append(op).await?;

        Ok(true)
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one. Returns the new inactivity floor location.
    ///
    /// # Panics
    ///
    /// Expects there is at least one active operation above the inactivity floor, and panics
    /// otherwise.
    // TODO(https://github.com/commonwarexyz/monorepo/issues/1829): callers of this method should
    // migrate to using [Self::raise_floor_with_bitmap] instead.
    async fn raise_floor(&mut self, mut inactivity_floor_loc: Location) -> Result<Location, Error>
    where
        T: Translator,
        I: Index<T, Value = Location>,
        O: Keyed,
    {
        let tip_loc = Location::new_unchecked(self.log.size());
        loop {
            assert!(
                *inactivity_floor_loc < tip_loc,
                "no active operations above the inactivity floor"
            );
            let old_loc = inactivity_floor_loc;
            inactivity_floor_loc += 1;
            let op = self.log.read(*old_loc).await?;
            if self.move_op_if_active(op, old_loc).await? {
                return Ok(inactivity_floor_loc);
            }
        }
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if there is not at least one active operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<D: Digest, const N: usize>(
        &mut self,
        status: &mut BitMap<D, N>,
        mut inactivity_floor_loc: Location,
    ) -> Result<Location, Error>
    where
        I: Index<T, Value = Location>,
        O: Keyed,
    {
        // Use the status bitmap to find the first active operation above the inactivity floor.
        while !status.get_bit(*inactivity_floor_loc) {
            inactivity_floor_loc += 1;
        }

        // Move the active operation to tip.
        let op = self.log.read(*inactivity_floor_loc).await?;
        assert!(
            self.move_op_if_active(op, inactivity_floor_loc).await?,
            "op should be active based on status bitmap"
        );
        status.set_bit(*inactivity_floor_loc, false);
        status.push(true);

        Ok(inactivity_floor_loc + 1)
    }
}
