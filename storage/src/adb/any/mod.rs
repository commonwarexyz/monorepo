//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated
//! with a key.

use crate::{
    adb::{operation::Keyed, Error},
    index::{Cursor, Index},
    journal::contiguous::Contiguous,
    mmr::{bitmap::BitMap, journaled::Mmr, Location, Position, Proof, StandardHasher},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use core::num::NonZeroU64;
use futures::{future::try_join_all, try_join, TryFutureExt as _};

pub mod fixed;
pub mod variable;

/// Common implementation for historical_proof.
///
/// Generates a proof with respect to the state of the MMR when it had `op_count` operations.
///
/// # Errors
///
/// - Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
///   [crate::mmr::MAX_LOCATION].
/// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count` or `op_count` >
///   number of operations in the log.
/// - Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
async fn historical_proof<E, O, H>(
    mmr: &Mmr<E, H>,
    log: &impl Contiguous<Item = O>,
    op_count: Location,
    start_loc: Location,
    max_ops: NonZeroU64,
) -> Result<(Proof<H::Digest>, Vec<O>), Error>
where
    E: Storage + Clock + Metrics,
    O: Keyed,
    H: Hasher,
{
    let size = Location::new_unchecked(log.size());
    if op_count > size {
        return Err(crate::mmr::Error::RangeOutOfBounds(size).into());
    }
    if start_loc >= op_count {
        return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
    }
    let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));

    let mmr_size = Position::try_from(op_count)?;
    let proof = mmr
        .historical_range_proof(mmr_size, start_loc..end_loc)
        .await?;

    let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
    let futures = (*start_loc..*end_loc)
        .map(|i| log.read(i))
        .collect::<Vec<_>>();
    try_join_all(futures)
        .await?
        .into_iter()
        .for_each(|op| ops.push(op));

    Ok((proof, ops))
}

/// A wrapper of DB state required for invoking operations shared across variants.
pub(crate) struct Shared<
    'a,
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
    H: Hasher,
> {
    pub snapshot: &'a mut I,
    pub mmr: &'a mut Mmr<E, H>,
    pub log: &'a mut C,
    pub hasher: &'a mut StandardHasher<H>,
}

impl<E, I, C, O, H> Shared<'_, E, I, C, O, H>
where
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    C: Contiguous<Item = O>,
    O: Keyed,
    H: Hasher,
{
    /// Append `op` to the log and add it to the MMR. The operation will be subject to rollback
    /// until the next successful `commit`.
    pub(super) async fn apply_op(&mut self, op: O) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Append operation to the log and update the MMR in parallel.
        try_join!(
            self.mmr
                .add_batched(self.hasher, &encoded_op)
                .map_err(Error::Mmr),
            self.log.append(op).map_err(Into::into)
        )?;

        Ok(())
    }

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
        self.apply_op(op).await?;

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
        E: Storage + Clock + Metrics,
        I: Index<Value = Location>,
        H: Hasher,
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
    pub(crate) async fn raise_floor_with_bitmap<const N: usize>(
        &mut self,
        status: &mut BitMap<H, N>,
        mut inactivity_floor_loc: Location,
    ) -> Result<Location, Error>
    where
        E: Storage + Clock + Metrics,
        I: Index<Value = Location>,
        O: Keyed,
        H: Hasher,
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

    /// Sync only the log and process the updates to the MMR in parallel.
    async fn sync_log_and_process_updates(&mut self) -> Result<(), Error> {
        let mmr_fut = async {
            self.mmr.merkleize(self.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.log.sync().map_err(Into::into), mmr_fut)?;

        Ok(())
    }

    /// Sync the log and the MMR to disk.
    async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::Journal),
            self.mmr.sync(self.hasher).map_err(Into::into)
        )?;

        Ok(())
    }
}
