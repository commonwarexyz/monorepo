//! MMB-specific batch layer built on the shared [`merkle::batch`](crate::merkle::batch)
//! infrastructure.
//!
//! Provides `add`, `update_leaf`, and `merkleize` for the MMB family. See
//! [`crate::merkle::batch`] for the lifecycle overview.

use crate::merkle::{
    batch::{self, Clean, Dirty},
    hasher::Hasher,
    mmb::{
        iterator::{birthed_node_pos, child_leaves, leaf_pos, peak_birth_leaf, PeakIterator},
        proof, Error, Family, Location, Position,
    },
    Proof, Readable,
};
use alloc::vec::Vec;
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMB-specific type alias for `merkle::proof::Proof`.
pub type MmbProof<D> = Proof<Family, D>;

pub use batch::BatchChainInfo;

/// Collect the path of internal nodes from `peak_pos` down to the leaf at `target_loc`,
/// in top-down order. The leaf itself is not included.
fn collect_path(
    mut pos: Position,
    mut height: u32,
    mut leaf_start: u64,
    target_loc: Location,
) -> Vec<(Position, u32)> {
    let mut path = Vec::with_capacity(height as usize);
    while height > 0 {
        path.push((pos, height));
        let mid_leaf = leaf_start + (1u64 << (height - 1));
        let (left_leaf, right_leaf) = child_leaves(
            peak_birth_leaf(Location::new(leaf_start + (1u64 << height) - 1), height),
            height,
        );
        let is_child_leaf = height == 1;
        if target_loc.as_u64() < mid_leaf {
            pos = birthed_node_pos(left_leaf, is_child_leaf);
            height -= 1;
        } else {
            pos = birthed_node_pos(right_leaf, is_child_leaf);
            height -= 1;
            leaf_start = mid_leaf;
        }
    }
    path
}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = batch::UnmerkleizedBatch<'a, Family, D, P>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, D, P> = batch::MerkleizedBatch<'a, Family, D, P>;

/// Owned set of changes against a base MMB.
pub type Changeset<D> = batch::Changeset<Family, D>;

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>>
    UnmerkleizedBatch<'a, D, P>
{
    /// Add a pre-computed leaf digest. Returns the leaf's location.
    pub fn add_leaf_digest(&mut self, digest: D) -> Location {
        let loc = self.leaves();
        let pos = leaf_pos(loc);
        debug_assert_eq!(pos, self.size());

        // Capture the merge height BEFORE appending (size is valid here).
        // Since MMB maintains a constant merge rate and PeakIterator yields from newest
        // to oldest, we simulate adding a new leaf (height 0) and locate the merge.
        let mut prev_height = 0;
        let mut merge_height = None;
        for (_, height) in PeakIterator::new(self.size()) {
            if height == prev_height {
                merge_height = Some(height + 1);
                break;
            }
            prev_height = height;
        }

        self.appended.push(digest);

        // Perform the deferred merge, if any.
        if let Some(height) = merge_height {
            let parent_pos = Position::new(pos.as_u64() + 1);
            self.appended.push(D::EMPTY); // placeholder
            self.state.insert(parent_pos, height);
        }

        loc
    }

    /// Hash `element` and add it as a leaf. Returns the leaf's location.
    pub fn add(
        &mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        element: &[u8],
    ) -> Location {
        let digest = hasher.leaf_digest(leaf_pos(self.leaves()), element);
        self.add_leaf_digest(digest)
    }

    /// Update the leaf at `loc` to `element`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafOutOfBounds`] if `loc` is not an existing leaf.
    /// Returns [`Error::ElementPruned`] if the leaf has been pruned.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        let leaves = self.leaves();
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        let digest = hasher.leaf_digest(pos, element);
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(())
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(&mut self, loc: Location, digest: D) -> Result<(), Error> {
        let leaves = self.leaves();
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(())
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(&mut self, updates: &[(Location, D)]) -> Result<(), Error> {
        let leaves = self.leaves();
        let prune_boundary = self.parent.pruned_to_pos();
        for (loc, _) in updates {
            if *loc >= leaves {
                return Err(Error::LeafOutOfBounds(*loc));
            }
            let pos = Position::try_from(*loc)?;
            if pos < prune_boundary {
                return Err(Error::ElementPruned(pos));
            }
        }
        for (loc, digest) in updates {
            let pos = Position::try_from(*loc).unwrap();
            self.store_node(pos, *digest);
            self.mark_dirty(*loc);
        }
        Ok(())
    }

    /// Mark ancestors of the leaf at `loc` as dirty up to its peak.
    fn mark_dirty(&mut self, loc: Location) {
        let size = self.size();
        let peaks = PeakIterator::new(size);
        let mut end_leaf_cursor = peaks.leaves().as_u64();

        for (peak_pos, height) in peaks {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;
            end_leaf_cursor = leaf_start;

            if loc.as_u64() < leaf_start || loc.as_u64() >= leaf_start + leaves_in_peak {
                continue;
            }

            // Collect the path from peak to leaf (top-down), then insert bottom-up so we
            // can early-exit when we hit a node that was already dirtied by a prior
            // update_leaf.
            let path = collect_path(peak_pos, height, leaf_start, loc);
            for &(pos, h) in path.iter().rev() {
                if !self.state.insert(pos, h) {
                    break; // already dirty from a prior update_leaf, ancestors must be too
                }
            }
            return;
        }

        panic!("leaf {loc} not found in any peak (size: {size})");
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with a computed root.
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
    ) -> MerkleizedBatch<'a, D, P> {
        self.merkleize_dirty(hasher);

        // Compute root from peaks.
        let leaves = Location::try_from(self.size()).expect("invalid mmb size");
        let mut peaks: Vec<D> = PeakIterator::new(self.size())
            .map(|(peak_pos, _)| self.get_node(peak_pos).expect("peak missing"))
            .collect();
        peaks.reverse(); // oldest to newest for root fold
        let root = hasher.root(leaves, peaks.iter());

        batch::Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Clean { root },
            #[cfg(feature = "std")]
            pool: self.pool,
        }
    }
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>> Readable
    for MerkleizedBatch<'a, D, P>
{
    type Family = Family;
    type Digest = D;
    type Error = Error;
    type PeakIterator = PeakIterator;

    fn size(&self) -> Position {
        self.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.get_node(pos)
    }

    fn root(&self) -> D {
        self.state.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.parent.pruned_to_pos()
    }

    fn peak_iterator(&self) -> Self::PeakIterator {
        PeakIterator::new(self.size())
    }

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
    ) -> Result<MmbProof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<MmbProof<D>, Error> {
        proof::build_range_proof(hasher, self.leaves(), range, |pos| self.get_node(pos))
    }
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>>
    MerkleizedBatch<'a, D, P>
{
    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, D, Self> {
        let batch = UnmerkleizedBatch::new(self);
        #[cfg(feature = "std")]
        let batch = batch.with_pool(self.pool.clone());
        batch
    }

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        batch::Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Dirty::default(),
            #[cfg(feature = "std")]
            pool: self.pool,
        }
    }
}
