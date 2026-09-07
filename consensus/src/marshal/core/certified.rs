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
/// processed floor are pruned.
pub(super) struct Certified<C: Digest> {
    entries: BTreeMap<Height, BTreeSet<C>>,
}

impl<C: Digest> Certified<C> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Records `commitment` at `height` as certified.
    pub(super) fn insert(&mut self, height: Height, commitment: C) {
        self.entries.entry(height).or_default().insert(commitment);
    }

    /// Returns true when `commitment` at `height` is known certified.
    pub(super) fn contains(&self, height: Height, commitment: &C) -> bool {
        self.entries
            .get(&height)
            .is_some_and(|commitments| commitments.contains(commitment))
    }

    /// Drops entries below `min`.
    pub(super) fn prune(&mut self, min: Height) {
        self.entries = self.entries.split_off(&min);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256};

    #[test]
    fn contains_is_height_scoped_and_prune_drops_below_min() {
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

        certified.prune(Height::new(6));
        assert!(!certified.contains(Height::new(5), &a));
        assert!(certified.contains(Height::new(6), &c));
        assert!(certified.contains(Height::new(7), &b));
    }
}
