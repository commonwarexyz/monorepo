//! MMB-specific batch layer built on the shared [`merkle::batch`](crate::merkle::batch)
//! infrastructure.
//!
//! Provides `add`, `update_leaf`, and `merkleize` for the MMB family. See
//! [`crate::merkle::batch`] for the lifecycle overview.

use crate::merkle::{
    batch::{self, Clean, Dirty},
    hasher::Hasher,
    mmb::{
        iterator::{leaf_pos, PeakIterator},
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

/// Return the height of the single parent birthed when appending `loc`, if any.
///
/// MMB appends create exactly one parent unless `loc + 2` is a power of two.
#[inline]
const fn append_merge_height(loc: Location) -> Option<u32> {
    let leaf = loc.as_u64();
    if (leaf + 2).is_power_of_two() {
        None
    } else {
        Some((leaf + 1).trailing_ones() + 1)
    }
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
    /// Add a pre-computed leaf digest.
    pub fn add_leaf_digest(mut self, digest: D) -> Self {
        let loc = self.leaves();
        let pos = leaf_pos(loc);
        debug_assert_eq!(pos, self.size());

        self.appended.push(digest);

        // Perform the deferred merge, if any.
        if let Some(height) = append_merge_height(loc) {
            let parent_pos = Position::new(pos.as_u64() + 1);
            self.appended.push(D::EMPTY); // placeholder
            self.state.insert(parent_pos, height);
        }

        self
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &mut impl Hasher<Family, Digest = D>, element: &[u8]) -> Self {
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
        mut self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<Self, Error> {
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
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location, digest: D) -> Result<Self, Error> {
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
        Ok(self)
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(mut self, updates: &[(Location, D)]) -> Result<Self, Error> {
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
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with a computed root.
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Family, Digest = D>,
    ) -> MerkleizedBatch<'a, D, P> {
        self.merkleize_dirty(hasher);

        // Compute root from peaks.
        let leaves = Location::try_from(self.size()).expect("invalid mmb size");
        let peaks: Vec<D> = PeakIterator::new(self.size())
            .map(|(peak_pos, _)| self.get_node(peak_pos).expect("peak missing"))
            .collect();
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

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<MmbProof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
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

#[cfg(test)]
mod tests {
    use super::append_merge_height;
    use crate::mmb::Location;

    #[test]
    fn test_append_merge_height_schedule() {
        let expected = [
            None,
            Some(1),
            None,
            Some(1),
            Some(2),
            Some(1),
            None,
            Some(1),
            Some(2),
            Some(1),
            Some(3),
            Some(1),
            Some(2),
            Some(1),
            None,
            Some(1),
        ];

        for (leaf, height) in expected.into_iter().enumerate() {
            assert_eq!(append_merge_height(Location::new(leaf as u64)), height);
        }
    }
}
