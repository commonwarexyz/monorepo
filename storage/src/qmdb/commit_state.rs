//! Commit-pointer state shared by QMDb apply paths.
//!
//! Applying a batch has two phases:
//! 1. validate that the batch can be applied to the current committed chain, and
//! 2. after variant-specific effects have succeeded, advance the committed chain.
//!
//! [`ValidatedApply`] is the typestate connecting those phases. Callers can only obtain it from
//! [`CommitState::validate`], and its fields are private, so commit pointers cannot be advanced
//! through this API without first running validation.

use crate::{
    merkle::{Family, Location},
    qmdb::{
        batch_core::{AppendBatchCore, BatchSpan, HasCore},
        Error,
    },
};
use commonware_cryptography::Digest;
use core::ops::Range;
use std::sync::Arc;

/// Shared commit-pointer state.
pub(crate) struct CommitState<F: Family> {
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
}

impl<F: Family> CommitState<F> {
    /// Create commit state from already-validated commit pointers.
    pub(crate) const fn new(
        last_commit_loc: Location<F>,
        inactivity_floor_loc: Location<F>,
    ) -> Self {
        Self {
            last_commit_loc,
            inactivity_floor_loc,
        }
    }

    /// Return the location of the last committed operation.
    pub(crate) const fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    /// Return the inactivity floor declared by the last committed batch.
    pub(crate) const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the location of the next operation appended to this db.
    pub(crate) fn size(&self) -> Location<F> {
        Location::new(*self.last_commit_loc + 1)
    }

    /// Restore commit pointers after a rewind/reload path has already validated its target.
    ///
    /// This bypasses the normal `validate -> ValidatedApply -> commit` apply path. Use it only
    /// after a separate authenticated or journal-backed recovery path has selected the target.
    /// Adjacent effects, such as resetting a compact metadata cache, remain the caller's
    /// responsibility.
    pub(crate) const fn restore(
        &mut self,
        last_commit_loc: Location<F>,
        inactivity_floor_loc: Location<F>,
    ) {
        self.last_commit_loc = last_commit_loc;
        self.inactivity_floor_loc = inactivity_floor_loc;
    }

    /// Validate that `core` can be applied to this state.
    pub(crate) fn validate<D, W>(
        &self,
        core: &AppendBatchCore<F, D>,
        ancestors: &[Arc<W>],
    ) -> Result<ValidatedApply<F>, Error<F>>
    where
        D: Digest,
        W: HasCore<F, D>,
    {
        core.validate_apply(self.inactivity_floor_loc, *self.size(), ancestors)?;
        Ok(ValidatedApply {
            start_loc: self.last_commit_loc + 1,
            last_commit_loc: core.commit_loc(),
            inactivity_floor_loc: core.commit_floor(),
        })
    }
}

/// Validated commit-pointer transition for a batch apply.
///
/// This is not a transaction boundary. Database-specific effects run after validation and before
/// `commit`; those effects may still fail according to each database's existing fatal-error
/// rules.
pub(crate) struct ValidatedApply<F: Family> {
    start_loc: Location<F>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
}

impl<F: Family> ValidatedApply<F> {
    /// Return the committed leaf count before this validated apply.
    pub(crate) fn committed_size(&self) -> u64 {
        *self.start_loc
    }

    /// Return whether `span` has not yet been reflected in the validated source state.
    pub(crate) fn is_unapplied(&self, span: &BatchSpan<F>) -> bool {
        span.is_unapplied(self.committed_size())
    }

    /// Advance `state` and return the range written by the validated batch.
    pub(crate) fn commit(self, state: &mut CommitState<F>) -> Range<Location<F>> {
        state.last_commit_loc = self.last_commit_loc;
        state.inactivity_floor_loc = self.inactivity_floor_loc;
        self.start_loc..(self.last_commit_loc + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;

    type F = mmr::Family;

    #[test]
    fn validated_apply_commits_pointer_transition() {
        let mut state = CommitState::<F>::new(Location::new(0), Location::new(0));
        let validated = ValidatedApply {
            start_loc: Location::new(1),
            last_commit_loc: Location::new(3),
            inactivity_floor_loc: Location::new(2),
        };

        let range = validated.commit(&mut state);

        assert_eq!(range, Location::new(1)..Location::new(4));
        assert_eq!(state.last_commit_loc(), Location::new(3));
        assert_eq!(state.inactivity_floor_loc(), Location::new(2));
    }

    #[test]
    fn validated_apply_tracks_source_size_for_effects() {
        let validated = ValidatedApply {
            start_loc: Location::new(10),
            last_commit_loc: Location::new(12),
            inactivity_floor_loc: Location::new(8),
        };
        let applied = BatchSpan::<F>::from_item_count(7, 7, 2, Location::new(8));
        let unapplied = BatchSpan::<F>::from_item_count(10, 10, 2, Location::new(8));

        assert_eq!(validated.committed_size(), 10);
        assert!(!validated.is_unapplied(&applied));
        assert!(validated.is_unapplied(&unapplied));
    }
}
