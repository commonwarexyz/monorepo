//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated
//! with a key.

use crate::{
    adb::{operation::Keyed, Error},
    index::{Cursor, Index},
    journal::contiguous::Contiguous,
    mmr::{journaled::Mmr, Location, StandardHasher},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::NZUsize;
use futures::{pin_mut, StreamExt as _};
use tracing::warn;

pub mod fixed;
pub mod variable;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Discard any uncommitted log operations, then correct any inconsistencies between the MMR and
/// log.
///
/// # Post-conditions
/// - The log will either be empty, or its last operation will be a commit floor operation.
/// - The number of leaves in the MMR will be equal to the number of operations in the log.
pub(crate) async fn align_mmr_and_log<E: Storage + Clock + Metrics, O: Keyed, H: Hasher>(
    mmr: &mut Mmr<E, H>,
    log: &mut impl Contiguous<Item = O>,
    hasher: &mut StandardHasher<H>,
) -> Result<Location, Error>
where
{
    // Back up over / discard any uncommitted operations in the log.
    let mut log_size: Location = log.size().await.into();
    let mut rewind_leaf_num = log_size;
    let mut inactivity_floor_loc = Location::new_unchecked(0);
    while rewind_leaf_num > 0 {
        let op = log.read(rewind_leaf_num.as_u64() - 1).await?;
        if let Some(loc) = op.commit_floor() {
            inactivity_floor_loc = loc;
            break;
        }
        rewind_leaf_num -= 1;
    }
    if rewind_leaf_num != log_size {
        let op_count = log_size - rewind_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "rewinding over uncommitted log operations"
        );
        log.rewind(rewind_leaf_num.as_u64()).await?;
        log.sync().await?;
        log_size = rewind_leaf_num;
    }

    // Pop any MMR elements that are ahead of the last log commit point.
    let mut next_mmr_leaf_num = mmr.leaves();
    if next_mmr_leaf_num > log_size {
        let op_count = next_mmr_leaf_num - log_size;
        warn!(?log_size, ?op_count, "popping uncommitted MMR operations");
        mmr.pop(op_count.as_u64() as usize).await?;
        next_mmr_leaf_num = log_size;
    }

    // If the MMR is behind, replay log operations to catch up.
    if next_mmr_leaf_num < log_size {
        let op_count = log_size - next_mmr_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "MMR lags behind log, replaying log to catch up"
        );
        while next_mmr_leaf_num < log_size {
            let op = log.read(next_mmr_leaf_num.as_u64()).await?;
            mmr.add_batched(hasher, &op.encode()).await?;
            next_mmr_leaf_num += 1;
        }
        mmr.sync(hasher).await.map_err(Error::Mmr)?;
    }

    // At this point the MMR and log should be consistent.
    assert_eq!(log.size().await, mmr.leaves());

    // The final operation in the log (if any) should be a commit.
    let last_op_loc = log.size().await.checked_sub(1);
    assert!(
        last_op_loc.is_none()
            || log
                .read(last_op_loc.unwrap())
                .await?
                .commit_floor()
                .is_some()
    );

    Ok(inactivity_floor_loc)
}

/// Builds the database's snapshot by replaying the log starting at the inactivity floor. Assumes
/// the log and mmr have the same number of operations and are not pruned beyond the inactivity
/// floor. The callback is invoked for each replayed operation, indicating activity status updates.
/// The first argument of the callback is the activity status of the operation, and the second
/// argument is the location of the operation it inactivates (if any).
pub(crate) async fn build_snapshot_from_log<O, I, F>(
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
        .replay(*inactivity_floor_loc, NZUsize!(SNAPSHOT_READ_BUFFER_SIZE))
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
