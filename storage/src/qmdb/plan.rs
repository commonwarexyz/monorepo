//! Apply planning shared by QMDB apply paths.
//!
//! Applying a batch has two phases:
//! 1. validate that the batch can extend the committed database state, and
//! 2. after variant-specific effects have succeeded, publish the next commit locations.
//!
//! [`Plan`] is the typestate connecting those phases.

use crate::{
    merkle::{Family, Location},
    qmdb::{
        append_batch::{AppendBatchView, BatchExtent},
        Error,
    },
};
use commonware_cryptography::Digest;
use core::ops::Range;
use std::sync::Arc;

/// Validate that `batch` can extend the committed database state.
pub(crate) fn apply<F, D, B, W>(
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    batch: &B,
    ancestors: &[Arc<W>],
) -> Result<Plan<F>, Error<F>>
where
    F: Family,
    D: Digest,
    B: AppendBatchView<F, D>,
    W: AppendBatchView<F, D>,
{
    let ancestor_extents: Vec<_> = ancestors
        .iter()
        .map(|ancestor| *ancestor.extent())
        .collect();
    extent(
        last_commit_loc,
        inactivity_floor_loc,
        batch.extent(),
        &ancestor_extents,
    )
}

/// Validate that `extent` can extend the committed database state.
pub(crate) fn extent<F: Family>(
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    extent: &BatchExtent<F>,
    ancestors: &[BatchExtent<F>],
) -> Result<Plan<F>, Error<F>> {
    let committed_size = last_commit_loc + 1;
    extent.validate_stale(
        *committed_size,
        ancestors.iter().map(BatchExtent::total_size),
    )?;
    extent.validate_floors(
        inactivity_floor_loc,
        *committed_size,
        ancestors
            .iter()
            .map(|ancestor| (ancestor.total_size(), ancestor.commit_floor())),
    )?;
    let next_last_commit_loc = extent.commit_loc();
    Ok(Plan {
        range: committed_size..(next_last_commit_loc + 1),
        next_last_commit_loc,
        next_inactivity_floor_loc: extent.commit_floor(),
    })
}

/// Validated commit-location transition for a batch apply.
///
/// This is not a transaction boundary. Database-specific effects run after validation and before
/// publishing the next commit locations; those effects may still fail according to each database's
/// existing fatal-error rules.
pub(crate) struct Plan<F: Family> {
    range: Range<Location<F>>,
    next_last_commit_loc: Location<F>,
    next_inactivity_floor_loc: Location<F>,
}

impl<F: Family> Plan<F> {
    /// Return the committed leaf count before this validated apply.
    pub(crate) fn committed_size(&self) -> u64 {
        *self.range.start
    }

    /// Return whether `extent` has not yet been reflected in the validated source state.
    pub(crate) fn is_unapplied(&self, extent: &BatchExtent<F>) -> bool {
        extent.is_unapplied(self.committed_size())
    }

    /// Return the operation range written by the planned apply.
    pub(crate) fn range(&self) -> Range<Location<F>> {
        self.range.clone()
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
    fn plan_describes_commit_location_transition() {
        let plan = Plan::<F> {
            range: Location::new(1)..Location::new(4),
            next_last_commit_loc: Location::new(3),
            next_inactivity_floor_loc: Location::new(2),
        };

        assert_eq!(plan.range(), Location::new(1)..Location::new(4));
        assert_eq!(plan.next_last_commit_loc(), Location::new(3));
        assert_eq!(plan.next_inactivity_floor_loc(), Location::new(2));
    }

    #[test]
    fn plan_tracks_source_size_for_effects() {
        let plan = Plan::<F> {
            range: Location::new(10)..Location::new(13),
            next_last_commit_loc: Location::new(12),
            next_inactivity_floor_loc: Location::new(8),
        };
        let applied = BatchExtent::<F>::from_item_count(7, 7, 2, Location::new(8));
        let unapplied = BatchExtent::<F>::from_item_count(10, 10, 2, Location::new(8));

        assert_eq!(plan.committed_size(), 10);
        assert!(!plan.is_unapplied(&applied));
        assert!(plan.is_unapplied(&unapplied));
    }
}
