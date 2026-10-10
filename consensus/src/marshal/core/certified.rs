//! Commitments this node certified.

use crate::types::Height;
use commonware_cryptography::Digest;
use std::collections::{BTreeMap, BTreeSet};

/// Commitments of proposals this node certified, and ancestors of them,
/// indexed by height.
///
/// A certified block arrives bound to its commitment, and its certification,
/// by this node or by the honest validators consensus required, checked its
/// embedded parent commitment against a root-bound parent. So recording a
/// certified block also records its parent, and a block fetched under this
/// knowledge extends it to that block's parent. Entries at or below the
/// finalized tip are pruned and cannot be reinserted.
pub(super) struct Certified<C: Digest> {
    entries: BTreeMap<Height, BTreeSet<C>>,
    min: Height,
}

impl<C: Digest> Certified<C> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            min: Height::new(1),
        }
    }

    /// Records `commitment` at `height` as certified unless below the retention minimum.
    pub(super) fn insert(&mut self, height: Height, commitment: C) {
        if height < self.min {
            return;
        }
        self.entries.entry(height).or_default().insert(commitment);
    }

    /// Returns true when `commitment` at `height` is known certified.
    pub(super) fn contains(&self, height: Height, commitment: &C) -> bool {
        self.entries
            .get(&height)
            .is_some_and(|commitments| commitments.contains(commitment))
    }

    /// Returns true when a certified commitment at `height` matches `predicate`.
    pub(super) fn contains_matching(
        &self,
        height: Height,
        predicate: impl FnMut(&C) -> bool,
    ) -> bool {
        self.entries
            .get(&height)
            .is_some_and(|commitments| commitments.iter().any(predicate))
    }

    /// Retains entries at or above `min` and rejects future inserts below it.
    /// The retention minimum never decreases.
    pub(super) fn retain(&mut self, min: Height) {
        if min <= self.min {
            return;
        }
        self.min = min;
        self.entries = self.entries.split_off(&min);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256};

    #[test]
    fn contains_is_height_scoped_and_retain_keeps_from_min() {
        let mut certified = Certified::new();
        let a = Sha256::hash(&[b"a"]);
        let b = Sha256::hash(&[b"b"]);
        let c = Sha256::hash(&[b"c"]);
        certified.insert(Height::new(5), a);
        certified.insert(Height::new(6), c);
        certified.insert(Height::new(7), b);

        assert!(certified.contains(Height::new(5), &a));
        assert!(!certified.contains(Height::new(6), &a));
        assert!(!certified.contains(Height::new(5), &b));

        certified.retain(Height::new(6));
        assert!(!certified.contains(Height::new(5), &a));
        assert!(certified.contains(Height::new(6), &c));
        assert!(certified.contains(Height::new(7), &b));

        // Late inserts cannot restore pruned heights, even after a stale retain
        certified.retain(Height::new(4));
        certified.insert(Height::new(5), a);
        certified.insert(Height::new(6), a);
        assert!(!certified.contains(Height::new(5), &a));
        assert!(certified.contains(Height::new(6), &a));

        let mut certified = Certified::new();
        certified.insert(Height::zero(), a);
        assert!(!certified.contains(Height::zero(), &a));
    }
}
