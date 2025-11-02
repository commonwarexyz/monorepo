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
    adb::operation::Keyed,
    index::{Cursor, Index},
    journal::contiguous::{fixed::Journal, Contiguous},
    mmr::{journaled, Location},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
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

    #[error("prune location {0} beyond last commit {1}")]
    PruneBeyondCommit(Location, Location),

    #[error("prune location {0} beyond inactivity floor {1}")]
    PruneBeyondInactivityFloor(Location, Location),

    #[error("uncommitted operations present")]
    UncommittedOperations,
}

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: NonZeroUsize = NZUsize!(1 << 16);

/// Builds the database's snapshot by replaying the log starting at the inactivity floor. Assumes
/// the log and mmr have the same number of operations and are not pruned beyond the inactivity
/// floor. The callback is invoked for each replayed operation, indicating activity status updates.
/// The first argument of the callback is the activity status of the operation, and the second
/// argument is the location of the operation it inactivates (if any).
pub(super) async fn build_snapshot_from_log<O, I, F>(
    inactivity_floor_loc: Location,
    log: &impl Contiguous<Item = O>,
    snapshot: &mut I,
    mut callback: F,
) -> Result<(), Error>
where
    O: Keyed,
    I: Index<Value = Location>,
    F: FnMut(bool, Option<Location>),
{
    let stream = log
        .replay(*inactivity_floor_loc, SNAPSHOT_READ_BUFFER_SIZE)
        .await?;
    pin_mut!(stream);
    let last_commit_loc = log.size().await.saturating_sub(1);
    while let Some(result) = stream.next().await {
        let (loc, op) = result?;
        if let Some(key) = op.key() {
            if op.is_delete() {
                let old_loc = delete_key(snapshot, log, key).await?;
                callback(false, old_loc);
            } else if op.is_update() {
                let new_loc = Location::new_unchecked(loc);
                let old_loc = update_loc(snapshot, log, key, new_loc).await?;
                callback(true, old_loc);
            }
        } else if op.commit_floor().is_some() {
            callback(loc == last_commit_loc, None);
        }
    }

    Ok(())
}

/// Delete `key` from the snapshot if it exists, returning the location that was previously
/// associated with it.
async fn delete_key<I, O>(
    snapshot: &mut I,
    log: &impl Contiguous<Item = O>,
    key: &O::Key,
) -> Result<Option<Location>, Error>
where
    I: Index<Value = Location>,
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
async fn update_loc<I: Index<Value = Location>, O>(
    snapshot: &mut I,
    log: &impl Contiguous<Item = O>,
    key: &<O as Keyed>::Key,
    new_loc: Location,
) -> Result<Option<Location>, Error>
where
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
