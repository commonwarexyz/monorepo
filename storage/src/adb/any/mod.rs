//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated
//! with a key.

use crate::{
    adb::{operation::Keyed, Error},
    index::{Cursor, Unordered as Index},
    journal::contiguous::Contiguous,
    mmr::{bitmap::BitMap, Location},
    translator::Translator,
};
use commonware_cryptography::Hasher;
use core::marker::PhantomData;

pub mod fixed;
pub mod variable;

/// A wrapper of DB state required for invoking operations shared across variants.
pub(crate) struct Shared<
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

impl<T, I, C, O> Shared<'_, T, I, C, O>
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
    pub(crate) async fn raise_floor_with_bitmap<H: Hasher, const N: usize>(
        &mut self,
        status: &mut BitMap<H, N>,
        mut inactivity_floor_loc: Location,
    ) -> Result<Location, Error>
    where
        T: Translator,
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
