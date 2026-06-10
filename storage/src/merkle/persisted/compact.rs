//! A compact, in-memory Merkle structure.
//!
//! Unlike [`crate::merkle::full`], this type retains only the state needed to compute the
//! current root and append new leaves: the leaf count and the pinned frontier nodes (the
//! tree's peaks). These suffice because the root is computed by folding the peaks and an
//! append reads only the peaks it merges with, so a tree rebuilt from a
//! `(leaf_count, pinned_nodes)` snapshot has the same root and the same future append
//! behavior as the original.
//!
//! Nodes created by appends are retained only until a prune or reset; after that they are no
//! longer readable.

use crate::merkle::{
    batch,
    hasher::Hasher,
    mem::{Config as MemConfig, Mem},
    Error, Family, Location,
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_utils::sync::RwLock;
use std::sync::Arc;

/// Append-only wrapper around [`batch::UnmerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    inner: batch::UnmerkleizedBatch<F, D, S>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Wrap an existing [`batch::UnmerkleizedBatch`] as an append-only batch.
    pub(crate) const fn wrap(inner: batch::UnmerkleizedBatch<F, D, S>) -> Self {
        Self { inner }
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &impl Hasher<F, Digest = D>, element: &[u8]) -> Self {
        Self {
            inner: self.inner.add(hasher, element),
        }
    }

    /// Add a run of pre-computed leaf digests, in order.
    pub(crate) fn add_leaf_digests(self, digests: impl IntoIterator<Item = D>) -> Self {
        Self {
            inner: self.inner.add_leaf_digests(digests),
        }
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        self.inner.leaves()
    }

    /// Consume this batch and produce an immutable [`batch::MerkleizedBatch`] with computed root.
    pub fn merkleize(
        self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        self.inner.merkleize(base, hasher)
    }
}

/// A Merkle structure that retains only the state required to continue appending.
pub struct Merkle<F: Family, D: Digest, S: Strategy> {
    inner: RwLock<Mem<F, D>>,
    strategy: S,
}

impl<F: Family, D: Digest, S: Strategy> Merkle<F, D, S> {
    /// Create an empty `Merkle`.
    pub const fn new(strategy: S) -> Self {
        Self {
            inner: RwLock::new(Mem::new()),
            strategy,
        }
    }

    /// Create a `Merkle` from a compact state snapshot.
    pub(crate) fn from_compact_state(
        strategy: S,
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        let mem = Self::mem_from_compact_state(leaves, pinned_nodes)?;
        Ok(Self {
            inner: RwLock::new(mem),
            strategy,
        })
    }

    /// Build a [`Mem`] with no retained nodes from a compact state snapshot.
    fn mem_from_compact_state(
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Mem<F, D>, Error<F>> {
        if !leaves.is_valid() {
            return Err(Error::LocationOverflow(leaves));
        }
        if pinned_nodes.len() != F::nodes_to_pin(leaves).count() {
            return Err(Error::InvalidPinnedNodes);
        }
        if leaves == 0 {
            Ok(Mem::new())
        } else {
            Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: leaves,
                pinned_nodes,
            })
        }
    }

    /// Replace the in-memory tree with one rebuilt from a compact state snapshot, discarding
    /// the current state.
    pub(crate) fn reset_to(
        &self,
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<(), Error<F>> {
        let mem = Self::mem_from_compact_state(leaves, pinned_nodes)?;
        *self.inner.write() = mem;
        Ok(())
    }

    /// Discard all retained nodes except the pinned frontier.
    pub(crate) fn prune_to_frontier(&self) {
        self.inner.write().prune_all();
    }

    /// Return the root digest of the current state.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        self.inner.read().root(hasher, inactive_peaks)
    }

    /// Return the number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().leaves()
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }

    /// Borrow the in-memory [`Mem`].
    ///
    /// The closure runs under the tree's read lock, which is not re-entrant: do not call other
    /// methods of this [`Merkle`] from within it.
    pub fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        let inner = self.inner.read();
        f(&inner)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D, S> {
        let inner = self.inner.read();
        UnmerkleizedBatch::wrap(inner.new_batch_with_strategy(self.strategy.clone()))
    }

    /// Create an owned merkleized batch representing the current state.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        let inner = self.inner.read();
        batch::MerkleizedBatch::from_mem_with_strategy(&inner, self.strategy.clone())
    }

    /// Apply a merkleized batch to the in-memory structure.
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D, S>) -> Result<(), Error<F>> {
        self.inner.get_mut().apply_batch(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard as StandardHasher, mmb, mmr, Bagging::ForwardFold};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;

    type TestMerkle<F> = Merkle<F, <Sha256 as commonware_cryptography::Hasher>::Digest, Sequential>;

    fn append<F: Family>(merkle: &mut TestMerkle<F>, values: &[&[u8]]) {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let batch = {
            let mut b = merkle.new_batch();
            for v in values {
                b = b.add(&hasher, v);
            }
            merkle.with_mem(|mem| b.merkleize(mem, &hasher))
        };
        merkle.apply_batch(&batch).unwrap();
    }

    fn pinned_nodes<F: Family>(
        merkle: &TestMerkle<F>,
    ) -> Vec<<Sha256 as commonware_cryptography::Hasher>::Digest> {
        merkle.with_mem(|mem| {
            F::nodes_to_pin(mem.leaves())
                .map(|pos| *mem.get_node_unchecked(pos))
                .collect()
        })
    }

    fn assert_reset_to_round_trip<F: Family>() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let mut merkle = TestMerkle::<F>::new(Sequential);
        append(&mut merkle, &[b"a", b"b", b"c"]);
        let root = merkle.root(&hasher, 0).unwrap();
        let leaves = merkle.leaves();
        let pins = pinned_nodes(&merkle);

        // Pruning to the frontier does not change the root.
        merkle.prune_to_frontier();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);

        // A fresh tree reset to the snapshot reproduces the same state.
        let mut restored = TestMerkle::<F>::new(Sequential);
        append(&mut restored, &[b"x"]);
        restored.reset_to(leaves, pins.clone()).unwrap();
        assert_eq!(restored.root(&hasher, 0).unwrap(), root);
        assert_eq!(restored.leaves(), leaves);

        // Both trees evolve identically from the snapshot.
        append(&mut merkle, &[b"d"]);
        append(&mut restored, &[b"d"]);
        assert_eq!(
            restored.root(&hasher, 0).unwrap(),
            merkle.root(&hasher, 0).unwrap()
        );

        // from_compact_state builds the same tree as reset_to.
        let from_state = TestMerkle::<F>::from_compact_state(Sequential, leaves, pins).unwrap();
        assert_eq!(from_state.root(&hasher, 0).unwrap(), root);
    }

    #[test]
    fn test_reset_to_round_trip_mmr() {
        assert_reset_to_round_trip::<mmr::Family>();
    }

    #[test]
    fn test_reset_to_round_trip_mmb() {
        assert_reset_to_round_trip::<mmb::Family>();
    }

    #[test]
    fn test_reset_to_rejects_invalid_snapshot() {
        let mut merkle = TestMerkle::<mmr::Family>::new(Sequential);
        append(&mut merkle, &[b"a", b"b"]);
        let leaves = merkle.leaves();

        // Wrong pin count.
        assert!(matches!(
            merkle.reset_to(leaves, vec![]),
            Err(Error::InvalidPinnedNodes)
        ));

        // Leaf count beyond the family maximum.
        let too_many = Location::new(mmr::Family::MAX_LEAVES.as_u64() + 1);
        assert!(matches!(
            merkle.reset_to(too_many, vec![]),
            Err(Error::LocationOverflow(loc)) if loc == too_many
        ));
    }
}
