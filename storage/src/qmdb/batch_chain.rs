//! Shared validation for QMDB batch chains.

use crate::{
    merkle::{Family, Location},
    qmdb::Error,
};
use core::iter;
use std::sync::{Arc, Weak};

/// Bounds declared by an ancestor batch's commit.
#[derive(Clone)]
pub(crate) struct AncestorBounds<F: Family> {
    /// Inactivity floor declared by the ancestor commit.
    pub(crate) floor: Location<F>,
    /// Total operations after the ancestor batch.
    pub(crate) end: u64,
}

/// Position and inactivity-floor state for a merkleized QMDB batch.
#[derive(Clone)]
pub(crate) struct Bounds<F: Family> {
    /// Total operations before this batch's own operations.
    pub(crate) base_size: u64,
    /// Boundary between committed DB operations and operations kept in this batch chain.
    ///
    /// Usually this is the DB size when the batch was created. If older ancestors were
    /// dropped, the boundary moves forward to the oldest ancestor still kept in memory.
    pub(crate) db_size: u64,
    /// Total operations after this batch.
    pub(crate) total_size: u64,
    /// Ancestor bounds in newest-first order.
    pub(crate) ancestors: Vec<AncestorBounds<F>>,
    /// Inactivity floor declared by this batch's commit.
    pub(crate) inactivity_floor: Location<F>,
}

impl<F: Family> Bounds<F> {
    /// Validate that this batch can be applied to the current database state.
    pub(crate) fn validate_apply_to(
        &self,
        current_size: u64,
        current_floor: Location<F>,
    ) -> Result<(), Error<F>> {
        validate_batch_applicable(current_size, self.db_size, self.base_size, &self.ancestors)?;
        validate_commit_floors(
            current_floor,
            current_size,
            &self.ancestors,
            self.inactivity_floor,
            Location::new(
                self.total_size
                    .checked_sub(1)
                    .expect("merkleized batch includes a commit"),
            ),
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
) -> impl Iterator<Item = Arc<T>>
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
pub(crate) fn collect_ancestor_bounds<T, F, I, E, L>(
    ancestors: I,
    floor: L,
    end: E,
) -> Vec<AncestorBounds<F>>
where
    F: Family,
    I: IntoIterator<Item = Arc<T>>,
    E: Fn(&T) -> u64,
    L: Fn(&T) -> Location<F>,
{
    let mut bounds = Vec::new();

    for batch in ancestors {
        bounds.push(AncestorBounds {
            floor: floor(&batch),
            end: end(&batch),
        });
    }

    bounds
}

/// Validate that a batch can be applied to a database with `db_size` committed operations.
///
/// A batch is applicable if the database has not advanced since the batch was created
/// (`batch_db_size`), if all ancestors are already committed (`batch_base_size`), or if the
/// database has advanced to one of the batch's ancestor boundaries.
pub(crate) fn validate_batch_applicable<F: Family>(
    db_size: u64,
    batch_db_size: u64,
    batch_base_size: u64,
    ancestors: &[AncestorBounds<F>],
) -> Result<(), Error<F>> {
    if db_size == batch_db_size
        || db_size == batch_base_size
        || ancestors.iter().any(|ancestor| ancestor.end == db_size)
    {
        return Ok(());
    }

    Err(Error::StaleBatch {
        db_size,
        batch_db_size,
        batch_base_size,
    })
}

/// Validate commit-floor monotonicity for a batch chain.
///
/// Ancestors are stored newest-first. Validation walks them in reverse so unapplied ancestors are
/// checked oldest-to-newest, then checks the tip. Ancestors at or below `db_size` are already
/// committed locally and are skipped.
pub(crate) fn validate_commit_floors<F: Family>(
    starting_floor: Location<F>,
    db_size: u64,
    ancestors: &[AncestorBounds<F>],
    tip_floor: Location<F>,
    tip_commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    let mut prev_floor = starting_floor;
    for ancestor in ancestors.iter().rev() {
        if ancestor.end <= db_size {
            continue;
        }

        let ancestor_commit_loc = Location::new(ancestor.end - 1);
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
    use std::sync::{Arc, Weak};

    type F = mmr::Family;

    struct TestBatch {
        id: u8,
        bounds: Bounds<F>,
        parent: Option<Weak<TestBatch>>,
    }

    const fn loc(n: u64) -> Location<F> {
        Location::new(n)
    }

    const fn ancestor(floor: Location<F>, end: u64) -> AncestorBounds<F> {
        AncestorBounds { floor, end }
    }

    #[test]
    fn validate_batch_applicable_accepts_valid_boundaries() {
        let ancestors = vec![ancestor(loc(10), 12), ancestor(loc(14), 16)];
        assert!(validate_batch_applicable::<F>(10, 10, 20, &ancestors).is_ok());
        assert!(validate_batch_applicable::<F>(20, 10, 20, &ancestors).is_ok());
        assert!(validate_batch_applicable::<F>(16, 10, 20, &ancestors).is_ok());
    }

    #[test]
    fn validate_batch_applicable_rejects_stale_batch() {
        let ancestors = vec![ancestor(loc(10), 12), ancestor(loc(14), 16)];
        let result = validate_batch_applicable::<F>(18, 10, 20, &ancestors);
        assert!(matches!(
            result,
            Err(Error::StaleBatch {
                db_size: 18,
                batch_db_size: 10,
                batch_base_size: 20,
            })
        ));
    }

    #[test]
    fn ancestors_iterates_parent_first() {
        let grandparent = Arc::new(TestBatch {
            id: 1,
            bounds: Bounds {
                base_size: 0,
                db_size: 0,
                total_size: 5,
                ancestors: Vec::new(),
                inactivity_floor: loc(3),
            },
            parent: None,
        });
        let parent = Arc::new(TestBatch {
            id: 2,
            bounds: Bounds {
                base_size: 5,
                db_size: 0,
                total_size: 7,
                ancestors: vec![ancestor(loc(3), 5)],
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
                base_size: 0,
                db_size: 0,
                total_size: 12,
                ancestors: Vec::new(),
                inactivity_floor: loc(10),
            },
            parent: None,
        });
        let grandparent = Arc::new(TestBatch {
            id: 2,
            bounds: Bounds {
                base_size: 0,
                db_size: 0,
                total_size: 8,
                ancestors: Vec::new(),
                inactivity_floor: loc(6),
            },
            parent: None,
        });

        let bounds = collect_ancestor_bounds(
            vec![Arc::clone(&parent), Arc::clone(&grandparent)],
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.bounds.total_size,
        );

        assert_eq!(bounds.len(), 2);
        assert_eq!((bounds[0].floor, bounds[0].end), (loc(10), 12));
        assert_eq!((bounds[1].floor, bounds[1].end), (loc(6), 8));
    }

    #[test]
    fn bounds_validates_apply_to_current_state() {
        let bounds = Bounds::<F> {
            base_size: 10,
            db_size: 10,
            total_size: 14,
            ancestors: vec![ancestor(loc(10), 12)],
            inactivity_floor: loc(11),
        };
        assert!(bounds.validate_apply_to(10, loc(9)).is_ok());

        let result = bounds.validate_apply_to(11, loc(9));
        assert!(matches!(
            result,
            Err(Error::StaleBatch {
                db_size: 11,
                batch_db_size: 10,
                batch_base_size: 10,
            })
        ));
    }

    #[test]
    fn validate_commit_floors_accepts_monotonic_chain() {
        let ancestors = vec![ancestor(loc(6), 7), ancestor(loc(4), 5)];
        assert!(validate_commit_floors::<F>(loc(2), 1, &ancestors, loc(8), loc(9),).is_ok());
    }

    #[test]
    fn validate_commit_floors_skips_committed_ancestors() {
        let ancestors = vec![ancestor(loc(1), 7), ancestor(loc(1), 5)];
        assert!(validate_commit_floors::<F>(loc(6), 7, &ancestors, loc(8), loc(9),).is_ok());
    }

    #[test]
    fn validate_commit_floors_rejects_ancestor_regression() {
        let ancestors = vec![ancestor(loc(6), 7), ancestor(loc(3), 5)];
        let result = validate_commit_floors::<F>(loc(4), 1, &ancestors, loc(8), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorRegressed(floor, previous)) if floor == loc(3) && previous == loc(4)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_ancestor_floor_beyond_commit() {
        let ancestors = vec![ancestor(loc(8), 7), ancestor(loc(4), 5)];
        let result = validate_commit_floors::<F>(loc(2), 1, &ancestors, loc(9), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorBeyondSize(floor, commit)) if floor == loc(8) && commit == loc(6)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_tip_regression() {
        let ancestors = vec![ancestor(loc(4), 5)];
        let result = validate_commit_floors::<F>(loc(2), 1, &ancestors, loc(3), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorRegressed(floor, previous)) if floor == loc(3) && previous == loc(4)
        ));
    }

    #[test]
    fn validate_commit_floors_rejects_tip_floor_beyond_commit() {
        let ancestors = vec![ancestor(loc(4), 5)];
        let result = validate_commit_floors::<F>(loc(2), 1, &ancestors, loc(10), loc(9));
        assert!(matches!(
            result,
            Err(Error::FloorBeyondSize(floor, commit)) if floor == loc(10) && commit == loc(9)
        ));
    }
}
