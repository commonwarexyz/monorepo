//! Shared validation for QMDB batch chains.
//!
//! A batch chain is a linked sequence of in-memory batches built on top of a DB state. Each batch
//! records its state via [`Bounds`] (where its operations sit in the log, and the root at each
//! applicable boundary) and the inactivity floor declared by its commit. Older batches in the chain
//! are tracked as [`AncestorBounds`] in newest-first order. Some may already be applied to the
//! database while others may not.
//!
//! Before applying a batch to the DB, the internal validation checks two things shared across QMDB
//! variants (any, immutable, keyless):
//!
//! - The batch is not stale: the current DB state must match either the batch's recorded DB state
//!   or one of its ancestor states.
//! - Commit floors are monotonically non-decreasing along the chain, and no floor exceeds
//!   its own commit location. Ancestors already applied to the database are skipped because their
//!   floors were validated when they were first applied. The rest of the chain and the tip are
//!   checked.
//!
//! Internal helpers walk the chain via weak parent references and snapshot ancestor bounds into a
//! `Vec` for storage on a merkleized batch.

use crate::{
    merkle::{Family, Location},
    qmdb::Error,
};
use commonware_cryptography::Digest;
use core::iter;
use std::{
    ops::Deref,
    sync::{Arc, Weak},
};

/// A database reference proven to be on a batch chain's own states, required for every
/// committed read through the chain.
///
/// Committed-read helpers take this instead of a bare database reference, so a read path
/// that skips the check fails to compile. It can only be minted by [`Bounds::on_chain`]
/// and [`Commitment::on_chain`]. Holding the wrapped reference also freezes the database
/// for the duration of the call. Every state mutation takes the database by value, so no
/// apply, prune, or rewind can interleave with a checked read.
pub(crate) struct OnChain<'a, T>(&'a T);

impl<T> Clone for OnChain<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OnChain<'_, T> {}

impl<T> Deref for OnChain<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0
    }
}

/// Identifies a QMDB state by its operation `size` and authenticated `root`.
#[derive(Clone, Copy, Debug)]
pub struct Commitment<F: Family, D: Digest> {
    /// Number of operations in the state.
    pub size: Location<F>,
    /// Root committing to those operations.
    pub root: D,
}

impl<F: Family, D: Digest> Commitment<F, D> {
    /// Create a [`Commitment`] from an operation `size` and its committing `root` digest.
    pub(crate) const fn new(size: Location<F>, root: D) -> Self {
        Self { size, root }
    }

    /// Check a committed read for a batch built directly on the database at this
    /// commitment. With no ancestors to account for applies, only the unchanged state is
    /// readable. Returns [`Error::StaleRead`] otherwise.
    pub(crate) fn on_chain<'a, T>(
        &self,
        db: &'a T,
        current: Self,
    ) -> Result<OnChain<'a, T>, Error<F>> {
        if *self == current {
            Ok(OnChain(db))
        } else {
            Err(Error::StaleRead)
        }
    }
}

// `Family` is not `PartialEq`, so deriving would demand `F: PartialEq` at every call site.
// Compare the fields directly, which needs only `Location<F>: PartialEq` and `D: Eq`.
impl<F: Family, D: Digest> PartialEq for Commitment<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.root == other.root
    }
}

impl<F: Family, D: Digest> Eq for Commitment<F, D> {}

/// Bounds declared by an ancestor batch's commit.
#[derive(Clone)]
pub struct AncestorBounds<F: Family, D: Digest> {
    /// Inactivity floor declared by the ancestor commit.
    pub floor: Location<F>,
    /// [`Commitment`] after the ancestor batch.
    pub state: Commitment<F, D>,
}

/// Position and inactivity-floor state for a merkleized QMDB batch.
#[derive(Clone)]
pub struct Bounds<F: Family, D: Digest> {
    /// [`Commitment`] immediately before this batch's own operations.
    pub base: Commitment<F, D>,
    /// [`Commitment`] at the boundary between applied database operations and operations kept in
    /// this batch chain.
    ///
    /// Usually this is the database state when the batch chain was created.
    pub db: Commitment<F, D>,
    /// This batch's tip [`Commitment`]: the state after all its operations.
    pub tip: Commitment<F, D>,
    /// Ancestor bounds in newest-first order.
    pub ancestors: Vec<AncestorBounds<F, D>>,
    /// Inactivity floor declared by this batch's commit.
    pub inactivity_floor: Location<F>,
}

impl<F: Family, D: Digest> Bounds<F, D> {
    /// Create initial bounds for a batch built directly from the current database state.
    ///
    /// The base, DB boundary, and tip all coincide at `state`, with no ancestors.
    pub(crate) const fn from_db(state: Commitment<F, D>, inactivity_floor: Location<F>) -> Self {
        Self {
            base: state,
            db: state,
            tip: state,
            ancestors: Vec::new(),
            inactivity_floor,
        }
    }

    /// Check a committed read through a chain with these bounds. The live state must be
    /// one the chain accounts for -- this batch's own tip (reads through an already
    /// applied batch stay valid), the chain's database boundary, or an ancestor's tip.
    /// Anything else means a batch from a different fork was applied or the database was
    /// rewound off the chain, and reading through it would mix two forks, so the read is
    /// refused with [`Error::StaleRead`].
    ///
    /// Every member state is reachable only by applying this chain's own batches, whose
    /// diffs shadow every key they touched, so a read that passes this check is exact.
    /// The overlays are retained on the merkleized batch itself, so this holds even
    /// after the ancestor batches are dropped.
    ///
    /// Membership compares full commitments (size and root), never sizes alone, because a
    /// sibling fork can commit the same operation count with different contents.
    pub(crate) fn on_chain<'a, T>(
        &self,
        db: &'a T,
        current: Commitment<F, D>,
    ) -> Result<OnChain<'a, T>, Error<F>> {
        if current == self.tip
            || current == self.db
            || self
                .ancestors
                .iter()
                .any(|ancestor| ancestor.state == current)
        {
            Ok(OnChain(db))
        } else {
            Err(Error::StaleRead)
        }
    }

    /// Validate that this batch can be applied to the current database state.
    pub(crate) fn validate_apply_to(
        &self,
        current: Commitment<F, D>,
        current_floor: Location<F>,
    ) -> Result<(), Error<F>> {
        validate_batch_applicable(current, self.db, &self.ancestors)?;
        validate_commit_floors(
            current_floor,
            current.size,
            &self.ancestors,
            self.inactivity_floor,
            self.tip
                .size
                .checked_sub(1)
                .expect("merkleized batch includes a commit"),
        )
    }
}

/// Iterate over a batch's live ancestors, starting at `parent`.
///
/// Iteration stops when a weak parent reference cannot be upgraded.
pub(crate) fn ancestors<T, P>(
    parent: Option<Weak<T>>,
    mut parent_of: P,
) -> impl Iterator<Item = Arc<T>>
where
    P: for<'a> FnMut(&'a T) -> Option<&'a Weak<T>>,
{
    let mut next = parent.as_ref().and_then(Weak::upgrade);
    iter::from_fn(move || {
        let batch = next.take()?;
        next = parent_of(&batch).and_then(Weak::upgrade);
        Some(batch)
    })
}

/// Iterate over a strong parent followed by its live ancestors.
pub(crate) fn parent_and_ancestors<T, P, I>(
    parent: Option<&Arc<T>>,
    mut ancestors_of: P,
) -> impl Iterator<Item = Arc<T>> + use<T, P, I>
where
    P: FnMut(&Arc<T>) -> I,
    I: IntoIterator<Item = Arc<T>>,
{
    parent.cloned().into_iter().flat_map(move |parent| {
        let ancestors = ancestors_of(&parent);
        iter::once(parent).chain(ancestors)
    })
}

/// Collect ancestor bounds in newest-first order.
pub(crate) fn collect_ancestor_bounds<T, F, D, I, L, C>(
    ancestors: I,
    floor: L,
    state: C,
) -> Vec<AncestorBounds<F, D>>
where
    F: Family,
    D: Digest,
    I: IntoIterator<Item = Arc<T>>,
    L: Fn(&T) -> Location<F>,
    C: Fn(&T) -> Commitment<F, D>,
{
    ancestors
        .into_iter()
        .map(|batch| AncestorBounds {
            floor: floor(&batch),
            state: state(&batch),
        })
        .collect()
}

/// Advance the inherited DB boundary past applied ancestors no longer reachable
/// through the weak parent chain.
pub(crate) fn effective_boundary<F: Family, D: Digest>(
    inherited: Commitment<F, D>,
    oldest_live_base: Option<Commitment<F, D>>,
) -> Commitment<F, D> {
    oldest_live_base
        .filter(|base| base.size > inherited.size)
        .unwrap_or(inherited)
}

/// Validate that a batch can be applied to the database at the given [`Commitment`].
///
/// A batch is applicable if the database has not advanced since the batch was created, if all
/// ancestors are already applied, or if the database has advanced to one of the batch's ancestor
/// [`Commitment`]s.
pub(crate) fn validate_batch_applicable<F: Family, D: Digest>(
    current: Commitment<F, D>,
    batch_db: Commitment<F, D>,
    ancestors: &[AncestorBounds<F, D>],
) -> Result<(), Error<F>> {
    // A separate base check is unnecessary: a direct batch's base is `batch_db`, while a child
    // batch's base is its first ancestor.
    if current == batch_db || ancestors.iter().any(|ancestor| ancestor.state == current) {
        return Ok(());
    }

    Err(Error::StaleBatch)
}

/// Validate commit-floor monotonicity for a batch chain.
///
/// Ancestors are stored newest-first. Validation walks them in reverse so unapplied ancestors are
/// checked oldest-to-newest, then checks the tip. Ancestors at or below `db_size` are already
/// applied locally and are skipped.
pub(crate) fn validate_commit_floors<F: Family, D: Digest>(
    starting_floor: Location<F>,
    db_size: Location<F>,
    ancestors: &[AncestorBounds<F, D>],
    tip_floor: Location<F>,
    tip_commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    let mut prev_floor = starting_floor;
    for ancestor in ancestors.iter().rev() {
        if ancestor.state.size <= db_size {
            continue;
        }

        let ancestor_commit_loc = ancestor.state.size - 1;
        if ancestor.floor < prev_floor {
            return Err(Error::FloorRegressed(ancestor.floor, prev_floor));
        }
        if ancestor.floor > ancestor_commit_loc {
            return Err(Error::FloorBeyondSize(ancestor.floor, ancestor_commit_loc));
        }
        prev_floor = ancestor.floor;
    }

    if tip_floor < prev_floor {
        return Err(Error::FloorRegressed(tip_floor, prev_floor));
    }
    if tip_floor > tip_commit_loc {
        return Err(Error::FloorBeyondSize(tip_floor, tip_commit_loc));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_cryptography::sha256;
    use std::sync::{Arc, Weak};

    type F = mmr::Family;
    type D = sha256::Digest;

    struct TestBatch {
        id: u8,
        bounds: Bounds<F, D>,
        parent: Option<Weak<Self>>,
    }

    const fn loc(n: u64) -> Location<F> {
        Location::new(n)
    }

    fn state(size: u64, marker: u8) -> Commitment<F, D> {
        Commitment::new(Location::new(size), D::from([marker; 32]))
    }

    fn ancestor(floor: Location<F>, end: u64, marker: u8) -> AncestorBounds<F, D> {
        AncestorBounds {
            floor,
            state: state(end, marker),
        }
    }

    #[test]
    fn validate_batch_applicable_accepts_valid_boundaries() {
        let ancestors = vec![ancestor(loc(10), 12, 12), ancestor(loc(14), 16, 16)];
        // Current matches the recorded DB state.
        assert!(validate_batch_applicable::<F, D>(state(10, 1), state(10, 1), &ancestors).is_ok());
        // Current matches one of the ancestor states.
        assert!(validate_batch_applicable::<F, D>(state(16, 16), state(10, 1), &ancestors).is_ok());
    }

    #[test]
    fn validate_batch_applicable_rejects_stale_batch() {
        let ancestors = vec![ancestor(loc(10), 12, 12), ancestor(loc(14), 16, 16)];
        let result = validate_batch_applicable::<F, D>(state(18, 18), state(10, 1), &ancestors);
        assert!(matches!(result, Err(Error::StaleBatch)));
    }

    #[test]
    fn validate_batch_applicable_rejects_equal_size_sibling() {
        let ancestors = vec![ancestor(loc(14), 16, 16)];
        let result = validate_batch_applicable::<F, D>(state(16, 99), state(10, 1), &ancestors);
        assert!(matches!(result, Err(Error::StaleBatch)));
    }

    #[test]
    fn on_chain_accepts_own_states_only() {
        let bounds = Bounds::<F, D> {
            base: state(10, 1),
            db: state(10, 1),
            tip: state(18, 18),
            ancestors: vec![ancestor(loc(10), 12, 12), ancestor(loc(14), 16, 16)],
            inactivity_floor: loc(11),
        };
        // Own tip, database boundary, and ancestor tips are readable.
        assert!(bounds.on_chain(&(), state(18, 18)).is_ok());
        assert!(bounds.on_chain(&(), state(10, 1)).is_ok());
        assert!(bounds.on_chain(&(), state(16, 16)).is_ok());
        // Foreign states are not, including at sizes the chain also reaches.
        assert!(matches!(
            bounds.on_chain(&(), state(19, 19)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            bounds.on_chain(&(), state(16, 99)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            bounds.on_chain(&(), state(18, 99)),
            Err(Error::StaleRead)
        ));
    }

    #[test]
    fn on_chain_from_base_commitment_requires_unchanged_state() {
        let base = state(10, 1);
        assert!(base.on_chain(&(), state(10, 1)).is_ok());
        assert!(matches!(
            base.on_chain(&(), state(10, 2)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            base.on_chain(&(), state(11, 1)),
            Err(Error::StaleRead)
        ));
    }

    #[test]
    fn ancestors_iterates_parent_first() {
        let grandparent = Arc::new(TestBatch {
            id: 1,
            bounds: Bounds {
                base: state(0, 0),
                db: state(0, 0),
                tip: state(5, 5),
                ancestors: Vec::new(),
                inactivity_floor: loc(3),
            },
            parent: None,
        });
        let parent = Arc::new(TestBatch {
            id: 2,
            bounds: Bounds {
                base: state(5, 5),
                db: state(0, 0),
                tip: state(7, 7),
                ancestors: vec![ancestor(loc(3), 5, 5)],
                inactivity_floor: loc(6),
            },
            parent: Some(Arc::downgrade(&grandparent)),
        });

        let ids: Vec<_> = ancestors(Some(Arc::downgrade(&parent)), |batch| batch.parent.as_ref())
            .map(|batch| batch.id)
            .collect();

        assert_eq!(ids, vec![2, 1]);
    }

    #[test]
    fn collect_ancestor_bounds_preserves_pairing_and_order() {
        let parent = Arc::new(TestBatch {
            id: 1,
            bounds: Bounds {
                base: state(0, 0),
                db: state(0, 0),
                tip: state(12, 12),
                ancestors: Vec::new(),
                inactivity_floor: loc(10),
            },
            parent: None,
        });
        let grandparent = Arc::new(TestBatch {
            id: 2,
            bounds: Bounds {
                base: state(0, 0),
                db: state(0, 0),
                tip: state(8, 8),
                ancestors: Vec::new(),
                inactivity_floor: loc(6),
            },
            parent: None,
        });

        let bounds = collect_ancestor_bounds(
            vec![Arc::clone(&parent), Arc::clone(&grandparent)],
            |batch| batch.bounds.inactivity_floor,
            |batch| state(*batch.bounds.tip.size, *batch.bounds.tip.size as u8),
        );

        assert_eq!(bounds.len(), 2);
        assert_eq!(bounds[0].floor, loc(10));
        assert_eq!(bounds[0].state, state(12, 12));
        assert_eq!(bounds[1].floor, loc(6));
        assert_eq!(bounds[1].state, state(8, 8));
    }

    #[test]
    fn bounds_validates_apply_to_current_state() {
        let bounds = Bounds::<F, D> {
            base: state(10, 1),
            db: state(10, 1),
            tip: state(14, 14),
            ancestors: vec![ancestor(loc(10), 12, 12)],
            inactivity_floor: loc(11),
        };
        assert!(bounds.validate_apply_to(state(10, 1), loc(9)).is_ok());

        let result = bounds.validate_apply_to(state(11, 11), loc(9));
        assert!(matches!(result, Err(Error::StaleBatch)));
    }

    #[test]
    fn validate_commit_floors_accepts_monotonic_chain() {
        let ancestors = vec![ancestor(loc(6), 7, 7), ancestor(loc(4), 5, 5)];
        assert!(
            validate_commit_floors::<F, D>(loc(2), loc(1), &ancestors, loc(8), loc(9),).is_ok()
        );
    }

    #[test]
    fn validate_commit_floors_skips_committed_ancestors() {
        let ancestors = vec![ancestor(loc(1), 7, 7), ancestor(loc(1), 5, 5)];
        assert!(
            validate_commit_floors::<F, D>(loc(6), loc(7), &ancestors, loc(8), loc(9),).is_ok()
        );
    }

    #[test]
    fn validate_commit_floors_rejects_ancestor_regression() {
        let ancestors = vec![ancestor(loc(6), 7, 7), ancestor(loc(3), 5, 5)];
        let result = validate_commit_floors::<F, D>(loc(4), loc(1), &ancestors, loc(8), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorRegressed(floor, previous)) if floor == loc(3) && previous == loc(4)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_ancestor_floor_beyond_commit() {
        let ancestors = vec![ancestor(loc(8), 7, 7), ancestor(loc(4), 5, 5)];
        let result = validate_commit_floors::<F, D>(loc(2), loc(1), &ancestors, loc(9), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorBeyondSize(floor, commit)) if floor == loc(8) && commit == loc(6)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_tip_regression() {
        let ancestors = vec![ancestor(loc(4), 5, 5)];
        let result = validate_commit_floors::<F, D>(loc(2), loc(1), &ancestors, loc(3), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorRegressed(floor, previous)) if floor == loc(3) && previous == loc(4)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_tip_floor_beyond_commit() {
        let ancestors = vec![ancestor(loc(4), 5, 5)];
        let result = validate_commit_floors::<F, D>(loc(2), loc(1), &ancestors, loc(10), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorBeyondSize(floor, commit)) if floor == loc(10) && commit == loc(9)
        ));
    }
}
