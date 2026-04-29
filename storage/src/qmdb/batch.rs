//! Shared validation for QMDB batch application.
//!
//! Variant batches own their operations, Merkle data, and read-through behavior. This module only
//! describes the log positions and inactivity floor needed to validate and publish a batch.
//!
//! `Bounds` is the batch's proposal: where it starts, what committed state it was built from, where
//! it ends, and which inactivity floor its commit declares. `Plan` is the accepted transition
//! derived from those bounds against the database's current commit state.

use crate::{
    merkle::{Family, Location},
    qmdb::Error,
};
use core::ops::Range;

/// Proposed log positions for a merkleized batch.
///
/// A batch carries these bounds before it is applied. `Plan::new` validates them against the
/// database tip and turns them into the commit-state transition to publish after effects succeed.
#[derive(Clone, Copy)]
pub(crate) struct Bounds<F: Family> {
    /// Leaf count before this batch's local operations.
    base_size: u64,
    /// Committed leaf count when the batch chain was forked. Used for stale-batch detection.
    committed_size: u64,
    /// Leaf count after this batch (data ops + the commit leaf) is applied.
    new_size: u64,
    /// Inactivity floor declared by this batch's commit operation.
    commit_floor: Location<F>,
}

impl<F: Family> Bounds<F> {
    /// Build metadata for a committed state with no speculative appends. Used by `to_batch` to
    /// represent the database tip as an empty batch; all three positions collapse to `size`.
    pub(crate) const fn committed(size: u64, commit_floor: Location<F>) -> Self {
        Self {
            base_size: size,
            committed_size: size,
            new_size: size,
            commit_floor,
        }
    }

    /// Build bounds for `item_count` data ops plus one trailing commit leaf.
    /// `new_size` becomes `base_size + item_count + 1`.
    pub(crate) const fn from_item_count(
        base_size: u64,
        committed_size: u64,
        item_count: usize,
        commit_floor: Location<F>,
    ) -> Self {
        Self {
            base_size,
            committed_size,
            new_size: base_size + item_count as u64 + 1,
            commit_floor,
        }
    }

    /// Return the committed leaf count when this batch chain was created.
    pub(crate) const fn committed_size(&self) -> u64 {
        self.committed_size
    }

    /// Return the leaf count after this batch is applied.
    pub(crate) const fn new_size(&self) -> u64 {
        self.new_size
    }

    /// Return the inactivity floor declared by this batch's commit operation.
    pub(crate) const fn commit_floor(&self) -> Location<F> {
        self.commit_floor
    }

    /// Return whether this batch has not yet been reflected in a database of `current_db_size`.
    pub(crate) const fn is_unapplied(&self, current_db_size: u64) -> bool {
        self.new_size > current_db_size
    }

    /// Return the location of the commit operation ending this chain.
    pub(crate) fn commit_loc(&self) -> Location<F> {
        debug_assert!(self.new_size > 0);
        Location::new(self.new_size - 1)
    }

    /// Validate that the current database size can reach this batch.
    ///
    /// This is intentionally size-based, matching the underlying Merkle batch layer. Callers must
    /// still treat equal-size orphaned branches as invalid.
    pub(crate) fn validate_stale(
        &self,
        current_db_size: u64,
        ancestor_ends: impl IntoIterator<Item = u64>,
    ) -> Result<(), Error<F>> {
        if current_db_size == self.committed_size || current_db_size == self.base_size {
            return Ok(());
        }
        if ancestor_ends.into_iter().any(|end| end == current_db_size) {
            return Ok(());
        }
        Err(Error::StaleBatch {
            db_size: current_db_size,
            batch_db_size: self.committed_size,
            batch_base_size: self.base_size,
        })
    }

    /// Validate floor monotonicity for unapplied ancestors and this batch.
    pub(crate) fn validate_floors<I>(
        &self,
        starting_floor: Location<F>,
        current_db_size: u64,
        ancestors: I,
    ) -> Result<(), Error<F>>
    where
        I: IntoIterator<Item = (u64, Location<F>)>,
        I::IntoIter: DoubleEndedIterator,
    {
        let mut prev_floor = starting_floor;
        for (ancestor_end, ancestor_floor) in ancestors.into_iter().rev() {
            if ancestor_end <= current_db_size {
                continue;
            }
            let ancestor_commit_loc = Location::new(ancestor_end - 1);
            if ancestor_floor < prev_floor {
                return Err(Error::FloorRegressed(ancestor_floor, prev_floor));
            }
            if ancestor_floor > ancestor_commit_loc {
                return Err(Error::FloorBeyondSize(ancestor_floor, ancestor_commit_loc));
            }
            prev_floor = ancestor_floor;
        }

        let commit_loc = self.commit_loc();
        if self.commit_floor < prev_floor {
            return Err(Error::FloorRegressed(self.commit_floor, prev_floor));
        }
        if self.commit_floor > commit_loc {
            return Err(Error::FloorBeyondSize(self.commit_floor, commit_loc));
        }
        Ok(())
    }
}

/// Validated transition from the current database tip to an accepted batch state.
///
/// `Plan::new` checks that the batch can be applied, but it does not mutate the database. Callers
/// should first run their variant-specific effects (journal append, Merkle update, snapshot update)
/// and only then publish these next commit locations.
pub(crate) struct Plan<F: Family> {
    operation_range: Range<Location<F>>,
    next_last_commit_loc: Location<F>,
    next_inactivity_floor_loc: Location<F>,
}

impl<F: Family> Plan<F> {
    /// Validate that `bounds` can extend the committed database state.
    pub(crate) fn new<I>(
        last_commit_loc: Location<F>,
        inactivity_floor_loc: Location<F>,
        bounds: &Bounds<F>,
        ancestors: I,
    ) -> Result<Self, Error<F>>
    where
        I: Clone + IntoIterator<Item = Bounds<F>>,
        I::IntoIter: DoubleEndedIterator,
    {
        let committed_size = last_commit_loc + 1;
        bounds.validate_stale(
            *committed_size,
            ancestors
                .clone()
                .into_iter()
                .map(|bounds| bounds.new_size()),
        )?;
        bounds.validate_floors(
            inactivity_floor_loc,
            *committed_size,
            ancestors
                .into_iter()
                .map(|ancestor| (ancestor.new_size(), ancestor.commit_floor())),
        )?;
        let next_last_commit_loc = bounds.commit_loc();
        Ok(Self {
            operation_range: committed_size..(next_last_commit_loc + 1),
            next_last_commit_loc,
            next_inactivity_floor_loc: bounds.commit_floor(),
        })
    }

    /// Return the committed leaf count before this validated apply.
    pub(crate) fn committed_size(&self) -> u64 {
        *self.operation_range.start
    }

    /// Return whether `bounds` has not yet been reflected in the validated committed state.
    pub(crate) fn is_unapplied(&self, bounds: &Bounds<F>) -> bool {
        bounds.is_unapplied(self.committed_size())
    }

    /// Return the operation range covered by the planned apply.
    pub(crate) fn operation_range(&self) -> Range<Location<F>> {
        self.operation_range.clone()
    }

    /// Return the commit location that becomes current after the planned apply succeeds.
    pub(crate) const fn next_last_commit_loc(&self) -> Location<F> {
        self.next_last_commit_loc
    }

    /// Return the inactivity floor that becomes current after the planned apply succeeds.
    pub(crate) const fn next_inactivity_floor_loc(&self) -> Location<F> {
        self.next_inactivity_floor_loc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;

    type F = mmr::Family;

    #[test]
    fn batch_bounds_validates_stale_sizes() {
        let bounds = Bounds::<F>::from_item_count(10, 10, 2, Location::new(12));

        assert!(bounds.validate_stale(10, []).is_ok());
        assert!(bounds.validate_stale(12, [12]).is_ok());

        let err = bounds.validate_stale(11, []).unwrap_err();
        assert!(matches!(
            err,
            Error::StaleBatch {
                db_size: 11,
                batch_db_size: 10,
                batch_base_size: 10,
            }
        ));
    }

    #[test]
    fn batch_bounds_validates_floor_monotonicity() {
        let bounds = Bounds::<F>::from_item_count(10, 10, 2, Location::new(8));

        assert!(bounds
            .validate_floors(Location::new(5), 10, [(12, Location::new(7))])
            .is_ok());

        let err = bounds
            .validate_floors(Location::new(5), 10, [(12, Location::new(4))])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::FloorRegressed(floor, previous)
                if floor == Location::new(4) && previous == Location::new(5)
        ));
    }

    #[test]
    fn batch_bounds_rejects_floor_beyond_commit() {
        let bounds = Bounds::<F>::from_item_count(10, 10, 2, Location::new(13));

        let err = bounds
            .validate_floors(Location::new(5), 10, [])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::FloorBeyondSize(floor, commit)
                if floor == Location::new(13) && commit == Location::new(12)
        ));
    }

    #[test]
    fn plan_describes_commit_location_transition() {
        let plan = Plan::<F> {
            operation_range: Location::new(1)..Location::new(4),
            next_last_commit_loc: Location::new(3),
            next_inactivity_floor_loc: Location::new(2),
        };

        assert_eq!(plan.operation_range(), Location::new(1)..Location::new(4));
        assert_eq!(plan.next_last_commit_loc(), Location::new(3));
        assert_eq!(plan.next_inactivity_floor_loc(), Location::new(2));
    }

    #[test]
    fn plan_tracks_committed_size_for_effects() {
        let plan = Plan::<F> {
            operation_range: Location::new(10)..Location::new(13),
            next_last_commit_loc: Location::new(12),
            next_inactivity_floor_loc: Location::new(8),
        };
        let applied = Bounds::<F>::from_item_count(7, 7, 2, Location::new(8));
        let unapplied = Bounds::<F>::from_item_count(10, 10, 2, Location::new(8));

        assert_eq!(plan.committed_size(), 10);
        assert!(!plan.is_unapplied(&applied));
        assert!(plan.is_unapplied(&unapplied));
    }
}
