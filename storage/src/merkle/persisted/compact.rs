//! A compact, in-memory Merkle structure.
//!
//! Unlike [`crate::merkle::full`], this type retains only the state needed to compute the
//! current root and append new leaves: the leaf count and the pinned frontier nodes (the
//! tree's peaks). These suffice because the root is computed by folding the peaks and an
//! append reads only the peaks it merges with, so a tree rebuilt from a
//! `(leaf_count, pinned_nodes)` snapshot has the same root and the same future append
//! behavior as the original.
//!
//! Nodes created by appends are retained only until the structure is pruned to its frontier.
//! After that they are no longer readable.

use crate::merkle::{
    Error, Family, Location, batch,
    hasher::Hasher,
    mem::{Config as MemConfig, Mem},
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
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

    /// Retain the live parent chain up to the first dropped weak link.
    ///
    /// Nodes beyond that link are read from committed state.
    pub(crate) fn retain_ancestors(&self) -> Vec<Arc<batch::MerkleizedBatch<F, D, S>>> {
        self.inner.retain_ancestors()
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
///
/// The [`Mem`] is held as an [`Arc`] so `snapshot` can hand a zero-copy, immutable view to
/// jobs running off the calling task. Mutations go through [`Arc::make_mut`]: they are
/// in-place while no snapshot is alive and copy-on-write otherwise, so a snapshot never
/// observes later mutations.
pub struct Merkle<F: Family, D: Digest, S: Strategy> {
    mem: Arc<Mem<F, D>>,
    strategy: S,
}

impl<F: Family, D: Digest, S: Strategy> Merkle<F, D, S> {
    /// Create an empty `Merkle`.
    pub fn new(strategy: S) -> Self {
        Self {
            mem: Arc::new(Mem::new()),
            strategy,
        }
    }

    /// Create a `Merkle` with no retained nodes from its compact state.
    pub(crate) fn from_compact_state(
        strategy: S,
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        if !leaves.is_valid() {
            return Err(Error::LocationOverflow(leaves));
        }
        if pinned_nodes.len() != F::nodes_to_pin(leaves).count() {
            return Err(Error::InvalidPinnedNodes);
        }
        let mem = if leaves == 0 {
            Mem::new()
        } else {
            Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: leaves,
                pinned_nodes,
            })?
        };
        Ok(Self {
            mem: Arc::new(mem),
            strategy,
        })
    }

    /// Discard all retained nodes except the pinned frontier.
    pub(crate) fn prune_to_frontier(&mut self) {
        Arc::make_mut(&mut self.mem).prune_all();
    }

    /// Hash `element` and append it as a single leaf.
    pub(crate) fn append_leaf(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
        element: &[u8],
    ) -> Result<(), Error<F>> {
        let batch = self
            .new_batch()
            .add(hasher, element)
            .merkleize(&self.mem, hasher);
        self.apply_batch(&batch)
    }

    /// Return the root digest of the current state.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        self.mem.root(hasher, inactive_peaks)
    }

    /// Return the number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.mem.leaves()
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }

    /// The in-memory [`Mem`].
    pub fn mem(&self) -> &Mem<F, D> {
        &self.mem
    }

    /// Return a zero-copy, immutable snapshot of the in-memory [`Mem`].
    ///
    /// The snapshot never observes later mutations: mutators copy-on-write while a snapshot is
    /// alive. Use this to move committed node fallback into a job running off the calling task;
    /// prefer [`Merkle::mem()`] when a borrow suffices.
    pub(crate) fn snapshot(&self) -> Arc<Mem<F, D>> {
        Arc::clone(&self.mem)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D, S> {
        UnmerkleizedBatch::wrap(self.mem.new_batch_with_strategy(self.strategy.clone()))
    }

    /// Create an owned merkleized batch representing the current state.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        batch::MerkleizedBatch::from_mem_with_strategy(&self.mem, self.strategy.clone())
    }

    /// Apply a merkleized batch to the in-memory structure.
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D, S>) -> Result<(), Error<F>> {
        Arc::make_mut(&mut self.mem).apply_batch(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{Bagging::ForwardFold, hasher::Standard as StandardHasher, mmb, mmr};
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
            b.merkleize(merkle.mem(), &hasher)
        };
        merkle.apply_batch(&batch).unwrap();
    }

    fn pinned_nodes<F: Family>(
        merkle: &TestMerkle<F>,
    ) -> Vec<<Sha256 as commonware_cryptography::Hasher>::Digest> {
        let mem = merkle.mem();
        F::nodes_to_pin(mem.leaves())
            .map(|pos| *mem.get_node_unchecked(pos))
            .collect()
    }

    fn assert_compact_state_round_trip<F: Family>() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let mut merkle = TestMerkle::<F>::new(Sequential);
        append(&mut merkle, &[b"a", b"b", b"c"]);
        let root = merkle.root(&hasher, 0).unwrap();
        let leaves = merkle.leaves();
        let pinned_nodes = pinned_nodes(&merkle);

        // Pruning to the frontier does not change the root.
        merkle.prune_to_frontier();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);

        // A Merkle rebuilt from the compact state has the same root and leaf count.
        let mut restored =
            TestMerkle::<F>::from_compact_state(Sequential, leaves, pinned_nodes).unwrap();
        assert_eq!(restored.root(&hasher, 0).unwrap(), root);
        assert_eq!(restored.leaves(), leaves);

        // Both trees evolve identically from the snapshot.
        append(&mut merkle, &[b"d"]);
        append(&mut restored, &[b"d"]);
        assert_eq!(
            restored.root(&hasher, 0).unwrap(),
            merkle.root(&hasher, 0).unwrap()
        );
    }

    #[test]
    fn test_compact_state_round_trip_mmr() {
        assert_compact_state_round_trip::<mmr::Family>();
    }

    #[test]
    fn test_compact_state_round_trip_mmb() {
        assert_compact_state_round_trip::<mmb::Family>();
    }

    #[test]
    fn test_from_compact_state_rejects_invalid_snapshot() {
        let mut merkle = TestMerkle::<mmr::Family>::new(Sequential);
        append(&mut merkle, &[b"a", b"b"]);
        let leaves = merkle.leaves();

        // Wrong pinned-node count.
        assert!(matches!(
            TestMerkle::<mmr::Family>::from_compact_state(Sequential, leaves, vec![]),
            Err(Error::InvalidPinnedNodes)
        ));

        // Leaf count beyond the family maximum.
        let too_many = mmr::Family::MAX_LEAVES + 1;
        assert!(matches!(
            TestMerkle::<mmr::Family>::from_compact_state(Sequential, too_many, vec![]),
            Err(Error::LocationOverflow(loc)) if loc == too_many
        ));
    }
}
