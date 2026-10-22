//! Shared validation for QMDB batch chains.
//!
//! A batch chain is a linked sequence of in-memory batches built on top of a database state. Each
//! batch records its states via [`Bounds`] and the inactivity floor declared by its commit. Some
//! ancestors may already be applied to the database.
//!
//! A state is a database commitment (size and root). The states of a batch's chain are its
//! recorded database boundary, each ancestor's tip, and the batch's own tip. While the database is
//! at one of them, the database is compatible with the batch. At any other state the batch is
//! stale, for example after a sibling or a descendant of the batch is applied, and reads through
//! it return [`Error::StaleRead`].
//!
//! Value reads through a batch that the database is compatible with are exact. An exact read
//! returns the batch's writes, then its ancestors' writes newest first, then the database,
//! regardless of which ancestors the database has applied or which handles were dropped. Proof
//! and pinned-node reads also need the ancestors' Merkle nodes, so they require those ancestors
//! to be held.
//!
//! Merkleization returns [`Error::StaleBatch`] for a stale batch, and also once an unapplied
//! ancestor is dropped, because merkleize reads ancestor operations through weak parent links. It
//! also checks that the batch's floor is at least the floor it builds on and at most its own
//! commit location. Applying a batch requires the database to be at its recorded boundary or an
//! ancestor's tip, and the root commits to the floor at each of those states, so the floor checks
//! made at merkleize still hold at apply.

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

/// A database reference proven compatible with a batch chain.
///
/// Only [`Bounds::compatible`], [`Commitment::compatible`], and [`merkleizable`] create one, and
/// callers must pass them the wrapped database's own commitment. Every state mutation takes the
/// database by value, so the database stays in the checked state while this borrow lives. Public
/// database methods reached through [`Deref`] do not require the witness.
pub(crate) struct Compatible<'a, T>(&'a T);

impl<T> Clone for Compatible<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Compatible<'_, T> {}

impl<T> Deref for Compatible<'_, T> {
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

    /// Check that `current` still equals this commitment, for reads through a batch built
    /// directly on the database at this commitment. Returns [`Error::StaleRead`] otherwise.
    pub(crate) fn compatible<'a, T>(
        &self,
        db: &'a T,
        current: Self,
    ) -> Result<Compatible<'a, T>, Error<F>> {
        if *self == current {
            Ok(Compatible(db))
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

/// Position and inactivity-floor state for a merkleized QMDB batch.
#[derive(Clone)]
pub struct Bounds<F: Family, D: Digest> {
    /// [`Commitment`] immediately before this batch's own operations.
    pub base: Commitment<F, D>,
    /// [`Commitment`] at the recorded database boundary, between applied database operations and
    /// operations kept in this batch chain.
    ///
    /// Usually this is the database state when the batch chain was created.
    pub db: Commitment<F, D>,
    /// This batch's tip [`Commitment`]: the state after all its operations.
    pub tip: Commitment<F, D>,
    /// Tip commitments this batch retained from its ancestors at merkleize, newest first.
    pub ancestors: Vec<Commitment<F, D>>,
    /// Inactivity floor declared by this batch's commit.
    pub inactivity_floor: Location<F>,
}

impl<F: Family, D: Digest> Bounds<F, D> {
    /// Create initial bounds for a batch built directly from the current database state.
    ///
    /// The base, recorded database boundary, and tip all coincide at `state`, with no ancestors.
    pub(crate) const fn from_db(state: Commitment<F, D>, inactivity_floor: Location<F>) -> Self {
        Self {
            base: state,
            db: state,
            tip: state,
            ancestors: Vec::new(),
            inactivity_floor,
        }
    }

    /// Check that `current` is a state of this batch's chain: the batch's tip, the recorded
    /// database boundary, or an ancestor's tip. Returns [`Error::StaleRead`] otherwise.
    ///
    /// The tip keeps an applied batch readable. A read that passes is exact, because the batch
    /// retains the writes of every ancestor the database has not applied. States are compared by
    /// size and root, since a sibling can reach the same size with different operations.
    pub(crate) fn compatible<'a, T>(
        &self,
        db: &'a T,
        current: Commitment<F, D>,
    ) -> Result<Compatible<'a, T>, Error<F>> {
        if current == self.tip || current == self.db || self.ancestors.contains(&current) {
            Ok(Compatible(db))
        } else {
            Err(Error::StaleRead)
        }
    }

    /// Validate that this batch can be applied to the current database state.
    pub(crate) fn validate_apply_to(&self, current: Commitment<F, D>) -> Result<(), Error<F>> {
        validate_batch_applicable(current, self.db, self.ancestors.iter().copied())
    }
}

/// Iterate over a batch's reachable ancestors, newest first, starting at `parent`.
///
/// Iteration stops at the first dropped ancestor, so an older ancestor is unreachable even while
/// another handle holds it.
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

/// Iterate over a strong parent followed by its reachable ancestors.
pub(crate) fn parent_and_ancestors<'a, T, P, I>(
    parent: Option<&'a Arc<T>>,
    mut ancestors_of: P,
) -> impl Iterator<Item = Arc<T>> + use<'a, T, P, I>
where
    P: FnMut(&'a Arc<T>) -> I,
    I: IntoIterator<Item = Arc<T>>,
{
    parent
        .into_iter()
        .flat_map(move |parent| iter::once(Arc::clone(parent)).chain(ancestors_of(parent)))
}

/// Advance the inherited recorded boundary to the base of the oldest reachable ancestor.
///
/// Merkleize collects ancestors through weak parent links, so it cannot read the operations of a
/// dropped ancestor or of anything older, whether or not they were applied. For a database still
/// below the oldest reachable ancestor's base, [`validate_batch_applicable`] then returns
/// [`Error::StaleBatch`]. Value reads are unaffected, because merkleized batches retain their
/// ancestors' diffs and operation chunks.
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
/// [`Commitment`]s, given by `ancestors`.
pub(crate) fn validate_batch_applicable<F: Family, D: Digest>(
    current: Commitment<F, D>,
    batch_db: Commitment<F, D>,
    ancestors: impl IntoIterator<Item = Commitment<F, D>>,
) -> Result<(), Error<F>> {
    // A separate base check is unnecessary: a direct batch's base is `batch_db`, while a child
    // batch's base is its first ancestor.
    if current == batch_db || ancestors.into_iter().any(|state| state == current) {
        return Ok(());
    }

    Err(Error::StaleBatch)
}

/// Validate that a batch whose reachable ancestors have the tips `ancestors` can be merkleized
/// against `db` at `current`, and return the witness that database reads require.
///
/// This applies [`validate_batch_applicable`] with `boundary`, the result of
/// [`effective_boundary`]. The witness holds no ancestor, so callers must hold strong references
/// to the ancestor batches until merkleization finishes.
///
/// # Errors
///
/// Returns [`Error::StaleBatch`] if `current` is neither `boundary` nor a reachable ancestor's tip.
pub(crate) fn merkleizable<'a, T, F: Family, D: Digest>(
    db: &'a T,
    current: Commitment<F, D>,
    boundary: Commitment<F, D>,
    ancestors: impl IntoIterator<Item = Commitment<F, D>>,
) -> Result<Compatible<'a, T>, Error<F>> {
    validate_batch_applicable(current, boundary, ancestors)?;
    Ok(Compatible(db))
}

/// Validate a batch's floor against the floor it builds on (`start`) and its own commit location.
///
/// Each ancestor's floor was validated when it was merkleized. A batch from `to_batch` carries the
/// database's floor.
///
/// # Errors
///
/// Returns [`Error::FloorRegressed`] if `floor < start` and [`Error::FloorBeyondSize`] if
/// `floor > commit_loc`.
pub(crate) fn validate_merkleize_floor<F: Family>(
    start: Location<F>,
    floor: Location<F>,
    commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    if floor < start {
        return Err(Error::FloorRegressed(floor, start));
    }
    if floor > commit_loc {
        return Err(Error::FloorBeyondSize(floor, commit_loc));
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
        parent: Option<Weak<Self>>,
    }

    const fn loc(n: u64) -> Location<F> {
        Location::new(n)
    }

    fn state(size: u64, marker: u8) -> Commitment<F, D> {
        Commitment::new(Location::new(size), D::from([marker; 32]))
    }

    #[test]
    fn validate_batch_applicable_accepts_valid_boundaries() {
        let ancestors = [state(12, 12), state(16, 16)];
        // Current matches the recorded DB state.
        assert!(validate_batch_applicable::<F, D>(state(10, 1), state(10, 1), ancestors).is_ok());
        // Current matches one of the ancestor states.
        assert!(validate_batch_applicable::<F, D>(state(16, 16), state(10, 1), ancestors).is_ok());
    }

    #[test]
    fn validate_batch_applicable_rejects_stale_batch() {
        let ancestors = [state(12, 12), state(16, 16)];
        let result = validate_batch_applicable::<F, D>(state(18, 18), state(10, 1), ancestors);
        assert!(matches!(result, Err(Error::StaleBatch)));
    }

    #[test]
    fn validate_batch_applicable_rejects_equal_size_sibling() {
        let ancestors = [state(16, 16)];
        let result = validate_batch_applicable::<F, D>(state(16, 99), state(10, 1), ancestors);
        assert!(matches!(result, Err(Error::StaleBatch)));
    }

    #[test]
    fn compatible_accepts_own_states_only() {
        // Ancestors are newest-first, and the batch builds on the newest one's tip.
        let bounds = Bounds::<F, D> {
            base: state(16, 16),
            db: state(10, 1),
            tip: state(18, 18),
            ancestors: vec![state(16, 16), state(12, 12)],
            inactivity_floor: loc(14),
        };

        // Own tip, database boundary, and ancestor tips are readable.
        assert!(bounds.compatible(&(), state(18, 18)).is_ok());
        assert!(bounds.compatible(&(), state(10, 1)).is_ok());
        assert!(bounds.compatible(&(), state(16, 16)).is_ok());

        // Foreign states are not, including at sizes the chain also reaches.
        assert!(matches!(
            bounds.compatible(&(), state(19, 19)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            bounds.compatible(&(), state(16, 99)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            bounds.compatible(&(), state(18, 99)),
            Err(Error::StaleRead)
        ));
    }

    #[test]
    fn compatible_from_base_commitment_requires_unchanged_state() {
        let base = state(10, 1);
        assert!(base.compatible(&(), state(10, 1)).is_ok());
        assert!(matches!(
            base.compatible(&(), state(10, 2)),
            Err(Error::StaleRead)
        ));
        assert!(matches!(
            base.compatible(&(), state(11, 1)),
            Err(Error::StaleRead)
        ));
    }

    #[test]
    fn ancestors_iterates_parent_first() {
        let grandparent = Arc::new(TestBatch {
            id: 1,
            parent: None,
        });
        let parent = Arc::new(TestBatch {
            id: 2,
            parent: Some(Arc::downgrade(&grandparent)),
        });

        let ids: Vec<_> = ancestors(Some(Arc::downgrade(&parent)), |batch| batch.parent.as_ref())
            .map(|batch| batch.id)
            .collect();

        assert_eq!(ids, vec![2, 1]);
    }

    #[test]
    fn bounds_validates_apply_to_current_state() {
        let bounds = Bounds::<F, D> {
            base: state(10, 1),
            db: state(10, 1),
            tip: state(14, 14),
            ancestors: vec![state(12, 12)],
            inactivity_floor: loc(11),
        };
        assert!(bounds.validate_apply_to(state(10, 1)).is_ok());
        assert!(bounds.validate_apply_to(state(12, 12)).is_ok());

        let result = bounds.validate_apply_to(state(11, 11));
        assert!(matches!(result, Err(Error::StaleBatch)));

        // The batch's own tip is readable but not applicable, since an applied batch cannot be
        // applied again.
        let result = bounds.validate_apply_to(state(14, 14));
        assert!(matches!(result, Err(Error::StaleBatch)));
    }
}
