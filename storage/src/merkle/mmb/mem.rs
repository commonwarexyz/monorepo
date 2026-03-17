//! A basic, no_std compatible MMB where all nodes are stored in-memory.
//!
//! `Mmb<D>` is a thin wrapper around [`crate::merkle::mem::Mem`] that provides MMB-specific error types
//! and batch/proof construction.

use crate::merkle::{
    batch::BatchChainInfo,
    hasher::Hasher,
    mem,
    mmb::{iterator::PeakIterator, Error, Family, Location, Position},
    proof::Proof,
};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Configuration for initializing an [Mmb].
pub struct Config<D: Digest> {
    /// The retained nodes of the MMB.
    pub nodes: Vec<D>,

    /// The leaf location up to which this MMB has been pruned, or 0 if this MMB has never been
    /// pruned.
    pub pruned_to: Location,

    /// The pinned nodes of the MMB, in the order expected by `iterator::nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// A basic MMB where all nodes are stored in-memory.
///
/// Nodes in this structure are either retained, pruned, or pinned. Retained nodes are stored in
/// the main deque. Pruned nodes precede `pruned_to_pos` and are no longer stored unless they are
/// still required for root computation or proof generation, in which case they are kept in
/// `pinned_nodes`.
pub struct Mmb<D: Digest> {
    inner: mem::Mem<Family, D>,
}

impl<D: Digest> Mmb<D> {
    /// Create a new, empty MMB.
    pub fn new(hasher: &mut impl Hasher<Family, Digest = D>) -> Self {
        Self {
            inner: mem::Mem::new(hasher),
        }
    }

    /// Return an [Mmb] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the expected
    /// count for `config.pruned_to`.
    ///
    /// Returns [Error::InvalidSize] if the MMB size is invalid.
    pub fn init(
        config: Config<D>,
        hasher: &mut impl Hasher<Family, Digest = D>,
    ) -> Result<Self, Error> {
        let inner = mem::Mem::init(
            mem::Config {
                nodes: config.nodes,
                pruned_to: config.pruned_to,
                pinned_nodes: config.pinned_nodes,
            },
            hasher,
        )?;
        Ok(Self { inner })
    }

    /// Re-initialize the MMB with the given nodes, pruning boundary, and pinned nodes.
    pub fn from_components(
        hasher: &mut impl Hasher<Family, Digest = D>,
        nodes: Vec<D>,
        pruned_to: Location,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error> {
        Self::init(
            Config {
                nodes,
                pruned_to,
                pinned_nodes,
            },
            hasher,
        )
    }

    /// Return the total number of nodes in the MMB, irrespective of any pruning.
    pub fn size(&self) -> Position {
        self.inner.size()
    }

    /// Return the total number of leaves in the MMB.
    pub const fn leaves(&self) -> Location {
        self.inner.leaves()
    }

    /// Returns [start, end) where `start` is the oldest retained leaf and `end` is the total leaf
    /// count.
    pub fn bounds(&self) -> Range<Location> {
        self.inner.bounds()
    }

    /// Return a new iterator over the peaks of the MMB.
    pub fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Get the root digest.
    pub const fn root(&self) -> &D {
        self.inner.root()
    }

    /// Return the requested node or None if it is not stored in the MMB.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        self.inner.get_node(pos)
    }

    /// Create a new speculative batch with this MMB as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<'_, D, Self> {
        super::batch::UnmerkleizedBatch::new(self)
    }

    /// Apply a changeset produced by [`super::batch::MerkleizedBatch::finalize`].
    ///
    /// A changeset is only valid if the MMB has not been modified since the
    /// batch that produced it was created. Applying a stale changeset returns
    /// [`super::Error::StaleChangeset`].
    pub fn apply(&mut self, changeset: super::batch::Changeset<D>) -> Result<(), Error> {
        self.inner.apply(changeset).map_err(Error::from)?;
        // MMB needs to refresh pinned nodes after apply because nodes_to_pin depends on size.
        self.inner.refresh_pinned_nodes();
        Ok(())
    }

    /// Prune all nodes up to but not including the given leaf location, and pin the nodes still
    /// required for root computation and proof generation.
    pub fn prune(&mut self, loc: Location) -> Result<(), Error> {
        self.inner.prune(loc).map_err(Error::from)
    }

    /// Prune all retained nodes.
    pub fn prune_all(&mut self) {
        self.inner.prune_all();
    }

    /// Return an inclusion proof for the element at location `loc`.
    pub fn proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<Family, D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Return an inclusion proof for all elements within the provided `range` of locations.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<Family, D>, Error> {
        crate::merkle::proof::build_range_proof(hasher, self.inner.leaves(), range, |pos| {
            self.inner.get_node(pos)
        })
        .map_err(Error::from)
    }

    /// Get the digests of nodes that need to be pinned at the provided pruning boundary.
    #[cfg(test)]
    fn node_digests_to_pin(&self, prune_pos: Position) -> Vec<D> {
        self.inner.node_digests_to_pin(prune_pos)
    }
}

impl<D: Digest> crate::merkle::Readable for Mmb<D> {
    type Family = Family;
    type Digest = D;
    type Error = Error;
    type PeakIterator = PeakIterator;

    fn size(&self) -> Position {
        self.inner.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.inner.get_node(pos)
    }

    fn root(&self) -> D {
        *self.inner.root()
    }

    fn pruned_to_pos(&self) -> Position {
        self.inner.pruned_to_pos()
    }

    fn peak_iterator(&self) -> Self::PeakIterator {
        PeakIterator::new(self.inner.size())
    }

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<Family, D>, Error> {
        self.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<Family, D>, Error> {
        self.range_proof(hasher, range)
    }
}

impl<D: Digest> BatchChainInfo<Family> for Mmb<D> {
    type Digest = D;

    fn base_size(&self) -> Position {
        self.inner.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position, D>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, Readable as _};
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    fn build_mmb(n: u64) -> (H, Mmb<D>) {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_empty_mmb() {
        let mut hasher = H::new();
        let mmb = Mmb::<D>::new(&mut hasher);
        assert_eq!(mmb.size(), 0u64);
        assert_eq!(mmb.leaves(), 0u64);
    }

    #[test]
    fn test_add_elements() {
        let (_, mmb) = build_mmb(8);
        assert_eq!(*mmb.leaves(), 8);
        // MMB with 8 leaves has 13 nodes (2*8 - ilog2(9) = 16 - 3 = 13).
        assert_eq!(*mmb.size(), 13);
    }

    #[test]
    fn test_mmb_structure_8_elements() {
        let (_, mmb) = build_mmb(8);
        // All 13 nodes should be retained.
        for pos in 0..13u64 {
            assert!(
                mmb.get_node(Position::new(pos)).is_some(),
                "missing node at pos {pos}"
            );
        }
        assert!(mmb.get_node(Position::new(13)).is_none());
    }

    #[test]
    fn test_root_stable_through_pruning() {
        let (mut hasher, mut mmb) = build_mmb(20);
        let root_before = *mmb.root();

        mmb.prune(Location::new(10)).unwrap();
        assert_eq!(*mmb.root(), root_before);

        // Re-initialize from components and verify root matches.
        let nodes: Vec<D> = (0..mmb.size().as_u64() - mmb.pruned_to_pos().as_u64())
            .map(|i| {
                mmb.get_node(Position::new(i + mmb.pruned_to_pos().as_u64()))
                    .unwrap()
            })
            .collect();

        let pinned_digests = mmb.node_digests_to_pin(mmb.pruned_to_pos());
        let pruned_to = Location::try_from(mmb.pruned_to_pos()).unwrap();
        let restored = Mmb::from_components(&mut hasher, nodes, pruned_to, pinned_digests).unwrap();
        assert_eq!(*restored.root(), root_before);
    }

    #[test]
    fn test_prune_and_reinit() {
        let (mut hasher, mut mmb) = build_mmb(16);
        let root_before = *mmb.root();

        mmb.prune(Location::new(8)).unwrap();
        assert_eq!(*mmb.root(), root_before);

        // Extract retained nodes and pinned digests.
        let pruned_pos = mmb.pruned_to_pos();
        let retained_count = (*mmb.size() - *pruned_pos) as usize;
        let nodes: Vec<D> = (0..retained_count)
            .map(|i| mmb.get_node(Position::new(*pruned_pos + i as u64)).unwrap())
            .collect();
        let pinned = mmb.node_digests_to_pin(pruned_pos);
        let pruned_to = Location::try_from(pruned_pos).unwrap();

        let reinit = Mmb::from_components(&mut hasher, nodes, pruned_to, pinned).unwrap();
        assert_eq!(*reinit.root(), root_before);
    }

    #[test]
    fn test_append_after_partial_prune() {
        let (mut hasher, mut mmb) = build_mmb(10);
        mmb.prune(Location::new(5)).unwrap();

        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 10u64..15 {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        assert_eq!(*mmb.leaves(), 15);
    }

    #[test]
    fn test_stale_changeset_rejected() {
        let (mut hasher, mut mmb) = build_mmb(5);

        // Create a changeset against size 5.
        let changeset = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"a");
            batch.merkleize(&mut hasher).finalize()
        };

        // Mutate the base first.
        let changeset2 = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"b");
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset2).unwrap();

        // Now the first changeset is stale.
        assert!(matches!(
            mmb.apply(changeset),
            Err(Error::StaleChangeset { .. })
        ));
    }

    #[test]
    fn test_update_leaf() {
        let (mut hasher, mut mmb) = build_mmb(8);
        let root_before = *mmb.root();

        let changeset = {
            let mut batch = mmb.new_batch();
            batch
                .update_leaf(&mut hasher, Location::new(3), b"updated")
                .unwrap();
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        assert_ne!(
            *mmb.root(),
            root_before,
            "root should change after leaf update"
        );
    }

    #[test]
    fn test_update_leaf_on_every_position() {
        for n in 1u64..=32 {
            let (mut hasher, mmb) = build_mmb(n);
            for loc in 0..n {
                let mut batch = mmb.new_batch();
                batch
                    .update_leaf(&mut hasher, Location::new(loc), b"new-value")
                    .unwrap();
                let merkleized = batch.merkleize(&mut hasher);

                // Verify the root changed.
                assert_ne!(
                    merkleized.root(),
                    *mmb.root(),
                    "n={n}, loc={loc}: root should change"
                );
            }
        }
    }

    #[test]
    fn test_update_leaf_out_of_bounds() {
        let (mut hasher, mmb) = build_mmb(5);
        let mut batch = mmb.new_batch();
        let result = batch.update_leaf(&mut hasher, Location::new(5), b"oob");
        assert!(matches!(result, Err(Error::LeafOutOfBounds(_))));
    }

    #[test]
    fn test_update_leaf_with_append() {
        let (mut hasher, mut mmb) = build_mmb(8);

        let changeset = {
            let mut batch = mmb.new_batch();
            batch
                .update_leaf(&mut hasher, Location::new(3), b"updated")
                .unwrap();
            batch.add(&mut hasher, b"new-element");
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        assert_eq!(*mmb.leaves(), 9);
    }

    #[test]
    fn test_batch_lifecycle() {
        let (mut hasher, mmb) = build_mmb(10);
        let base_root = *mmb.root();

        // Create batch, add leaves, merkleize, verify root differs.
        let mut batch = mmb.new_batch();
        for i in 10u64..15 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized = batch.merkleize(&mut hasher);
        assert_ne!(merkleized.root(), base_root);

        // Base should be unchanged.
        assert_eq!(*mmb.root(), base_root);
    }

    #[test]
    fn test_batch_fork() {
        let (mut hasher, mmb) = build_mmb(10);

        // Fork A.
        let mut batch_a = mmb.new_batch();
        batch_a.add(&mut hasher, b"a");
        let merkleized_a = batch_a.merkleize(&mut hasher);

        // Fork B.
        let mut batch_b = mmb.new_batch();
        batch_b.add(&mut hasher, b"b");
        let merkleized_b = batch_b.merkleize(&mut hasher);

        assert_ne!(merkleized_a.root(), merkleized_b.root());
    }

    #[test]
    fn test_sequential_changesets() {
        let (mut hasher, mut mmb) = build_mmb(5);

        // Changeset 1.
        let cs1 = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"a");
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(cs1).unwrap();

        // Changeset 2.
        let cs2 = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"b");
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(cs2).unwrap();
        assert_eq!(*mmb.leaves(), 7);
    }

    #[test]
    fn test_three_deep_batch_stacking() {
        let (mut hasher, mmb) = build_mmb(10);

        // Base <- A <- B <- C.
        let mut batch_a = mmb.new_batch();
        batch_a.add(&mut hasher, b"a");
        let merkleized_a = batch_a.merkleize(&mut hasher);

        let mut batch_b = merkleized_a.new_batch();
        batch_b.add(&mut hasher, b"b");
        let merkleized_b = batch_b.merkleize(&mut hasher);

        let mut batch_c = merkleized_b.new_batch();
        batch_c.add(&mut hasher, b"c");
        let merkleized_c = batch_c.merkleize(&mut hasher);

        // Flatten C's changeset all the way to base.
        let changeset = merkleized_c.finalize();
        drop(merkleized_b);
        drop(merkleized_a);
        let mut base = mmb;
        base.apply(changeset).unwrap();

        assert_eq!(*base.leaves(), 13);
    }

    #[test]
    fn test_batch_on_pruned_base() {
        let (mut hasher, mut mmb) = build_mmb(20);
        mmb.prune(Location::new(10)).unwrap();

        let changeset = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"new");
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        assert_eq!(*mmb.leaves(), 21);
    }

    #[test]
    fn test_batch_proof_verification() {
        let (mut hasher, mmb) = build_mmb(20);

        let mut batch = mmb.new_batch();
        for i in 20u64..25 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized = batch.merkleize(&mut hasher);

        // Verify proof for a base element.
        let proof = merkleized.proof(&mut hasher, Location::new(5)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &5u64.to_be_bytes(),
            Location::new(5),
            &merkleized.root(),
        ));

        // Verify proof for a new element.
        let proof = merkleized.proof(&mut hasher, Location::new(22)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &22u64.to_be_bytes(),
            Location::new(22),
            &merkleized.root(),
        ));
    }

    #[test]
    fn test_flattened_changeset_preserves_overwrites() {
        let (mut hasher, mut mmb) = build_mmb(10);

        // Layer A: update leaf 3.
        let mut batch_a = mmb.new_batch();
        batch_a
            .update_leaf(&mut hasher, Location::new(3), b"updated")
            .unwrap();
        let merkleized_a = batch_a.merkleize(&mut hasher);

        // Layer B on A: add a leaf.
        let mut batch_b = merkleized_a.new_batch();
        batch_b.add(&mut hasher, b"new");
        let merkleized_b = batch_b.merkleize(&mut hasher);
        let b_root = merkleized_b.root();

        let changeset = merkleized_b.finalize();
        drop(merkleized_a);
        mmb.apply(changeset).unwrap();
        assert_eq!(*mmb.root(), b_root);
    }
}
