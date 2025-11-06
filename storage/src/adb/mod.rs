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
    index::{Cursor, Index},
    journal::contiguous::Contiguous,
    mmr::{journaled::Mmr, Location, Position, StandardHasher},
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use futures::{pin_mut, StreamExt as _};
use thiserror::Error;
use tracing::{debug, warn};

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

/// Discard any uncommitted log operations and correct any inconsistencies between the MMR and
/// log. Returns the size of the log after alignment.
///
/// # Post-conditions
/// - The log will either be empty, or its last operation will be a commit operation.
/// - The number of leaves in the MMR will be equal to the number of operations in the log.
pub(super) async fn align_mmr_and_log<
    E: Storage + Clock + Metrics,
    O: Codec + Committable,
    H: Hasher,
>(
    mut mmr: Mmr<E, H>,
    log: &mut impl Contiguous<Item = O>,
    hasher: &mut StandardHasher<H>,
) -> Result<(Mmr<E, H>, u64), Error> {
    // Back up over / discard any uncommitted operations in the log.
    let log_size = rewind_uncommitted(log).await?;

    // Pop any MMR elements that are ahead of the last log commit point.
    let mut next_mmr_leaf_num = mmr.leaves();
    if next_mmr_leaf_num > log_size {
        let pop_count = next_mmr_leaf_num - log_size;
        warn!(log_size, ?pop_count, "popping uncommitted MMR operations");
        mmr.pop(*pop_count as usize).await?;
        next_mmr_leaf_num = Location::new_unchecked(log_size);
    }

    // If the MMR is behind, replay log operations to catch up.
    if next_mmr_leaf_num < log_size {
        let replay_count = log_size - *next_mmr_leaf_num;
        warn!(
            log_size,
            replay_count, "MMR lags behind log, replaying log to catch up"
        );

        let mut mmr = mmr.into_dirty();
        while next_mmr_leaf_num < log_size {
            let op = log.read(*next_mmr_leaf_num).await?;
            mmr.add_batched(hasher, &op.encode()).await?;
            next_mmr_leaf_num += 1;
        }

        let mut mmr = mmr.merkleize(hasher);
        mmr.sync().await.map_err(Error::Mmr)?;

        assert_eq!(log_size, mmr.leaves());
        return Ok((mmr, log_size));
    }

    // At this point the MMR and log should be consistent.
    assert_eq!(log_size, mmr.leaves());

    Ok((mmr, log_size))
}

/// Discard any uncommitted log operations and correct any inconsistencies between the MMR and
/// log. Returns the inactivity floor location set by the last commit.
///
/// # Post-conditions
/// - The log will either be empty, or its last operation will be a commit operation.
/// - The number of leaves in the MMR will be equal to the number of operations in the log.
pub(super) async fn align_mmr_and_floored_log<
    E: Storage + Clock + Metrics,
    O: Keyed + Committable,
    H: Hasher,
>(
    mmr: Mmr<E, H>,
    log: &mut impl Contiguous<Item = O>,
    hasher: &mut StandardHasher<H>,
) -> Result<(Mmr<E, H>, Location), Error> {
    let (mmr, log_size) = align_mmr_and_log(mmr, log, hasher).await?;
    if log_size == 0 {
        return Ok((mmr, Location::new_unchecked(0)));
    };
    let op = log.read(log_size - 1).await?;

    // The final operation in the log must be a commit wrapping the inactivity floor.
    let floor = op
        .has_floor()
        .expect("last operation should be a commit floor");
    Ok((mmr, floor))
}

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
/// inactivates (if any).
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
    let last_commit_loc = log.size().saturating_sub(1);
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
        } else if op.has_floor().is_some() {
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

/// Common implementation for pruning an authenticated database of operations prior to `prune_loc`.
///
/// # Errors
///
/// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > `min_required_loc`.
/// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
async fn prune_db<E, O, H>(
    mmr: &mut Mmr<E, H>,
    log: &mut impl Contiguous<Item = O>,
    prune_loc: Location,
    min_required_loc: Location,
    op_count: Location,
) -> Result<(), Error>
where
    E: Storage + Clock + Metrics,
    O: Codec,
    H: Hasher,
{
    if prune_loc > min_required_loc {
        return Err(Error::PruneBeyondMinRequired(prune_loc, min_required_loc));
    }

    if mmr.size() == 0 {
        // DB is empty, nothing to prune.
        return Ok(());
    };

    // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
    // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
    // the operations between the MMR tip and the log pruning boundary.
    mmr.sync().await?;

    // Prune the log. The log will prune at section boundaries, so the actual oldest retained
    // location may be less than requested.
    if !log.prune(*prune_loc).await? {
        return Ok(());
    }

    mmr.prune_to_pos(Position::try_from(prune_loc)?).await?;

    debug!(
        ?op_count,
        oldest_retained_loc = log.oldest_retained_pos(),
        ?prune_loc,
        "pruned inactive ops"
    );

    Ok(())
}
