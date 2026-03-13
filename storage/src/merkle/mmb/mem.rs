//! A basic, no_std compatible MMB where all nodes are stored in-memory.

use crate::merkle::{
    hasher::Hasher,
    mmb::{iterator::leaf_pos, proof, Error, Family, Location, Position},
    proof::Proof,
};
use alloc::vec::Vec;
use commonware_cryptography::Digest;
use core::ops::Range;

/// Find the rightmost pair of adjacent same-height peaks. Returns the index of the left element
/// in the pair, or `None` if no such pair exists.
fn find_merge_pair(peaks: &[(Position, u32)]) -> Option<usize> {
    (0..peaks.len().saturating_sub(1))
        .rev()
        .find(|&i| peaks[i].1 == peaks[i + 1].1)
}

/// A basic MMB where all nodes are stored in-memory.
///
/// Nodes are stored in a flat vector indexed by position. The MMB invariant guarantees
/// that positions are always appended in strictly increasing order (one leaf and at most
/// one parent per step), so a Vec is sufficient.
pub struct Mmb<D: Digest> {
    /// All node digests, indexed by position.
    nodes: Vec<D>,

    /// Current peaks as (position, height), ordered oldest to newest.
    peaks: Vec<(Position, u32)>,

    /// The root digest of the MMB.
    root: D,

    /// The number of leaves in the MMB.
    leaves: Location,
}

impl<D: Digest> Mmb<D> {
    /// Create a new, empty MMB.
    pub fn new(hasher: &mut impl Hasher<Family = Family, Digest = D>) -> Self {
        let root = hasher.root(Location::new(0), core::iter::empty::<&D>());
        Self {
            nodes: Vec::new(),
            peaks: Vec::new(),
            root,
            leaves: Location::new(0),
        }
    }

    /// Append an element to the MMB and return its leaf location.
    pub fn append(
        &mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        element: &[u8],
    ) -> Location {
        let loc = self.leaves;
        let pos = leaf_pos(loc);
        debug_assert_eq!(pos.as_u64() as usize, self.nodes.len());

        // Append the leaf.
        let leaf_d = hasher.leaf_digest(pos, element);
        self.nodes.push(leaf_d);
        self.peaks.push((pos, 0));

        // Merge if a unique pair of adjacent same-height peaks exists. The pair may be
        // anywhere in the list, not necessarily at the end.
        if let Some(idx) = find_merge_pair(&self.peaks) {
            let (left_pos, _) = self.peaks[idx];
            let (right_pos, h) = self.peaks[idx + 1];
            let parent_pos = Position::new(pos.as_u64() + 1);
            let parent_d = hasher.node_digest(
                parent_pos,
                &self.nodes[left_pos.as_u64() as usize],
                &self.nodes[right_pos.as_u64() as usize],
            );
            debug_assert_eq!(parent_pos.as_u64() as usize, self.nodes.len());
            self.nodes.push(parent_d);
            // Replace the pair with the new parent peak.
            self.peaks[idx] = (parent_pos, h + 1);
            self.peaks.remove(idx + 1);
        }

        // Update leaf count and recompute root.
        self.leaves = Location::new(*loc + 1);
        let peak_digests: Vec<&D> = self
            .peaks
            .iter()
            .map(|(p, _)| &self.nodes[p.as_u64() as usize])
            .collect();
        self.root = hasher.root(self.leaves, peak_digests);
        loc
    }

    /// Return the total number of nodes in the MMB.
    pub const fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64)
    }

    /// Return the total number of leaves in the MMB.
    pub const fn leaves(&self) -> Location {
        self.leaves
    }

    /// Get the root digest.
    pub const fn root(&self) -> &D {
        &self.root
    }

    /// Get the digest of a node at the given position, or `None` if the position is out of bounds.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        self.nodes.get(pos.as_u64() as usize).copied()
    }

    /// Return an inclusion proof for the element at location `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds the valid range.
    /// Returns [Error::RangeOutOfBounds] if `loc` >= [Self::leaves()].
    /// Returns [Error::ElementPruned] if a required node is missing.
    pub fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<Family, D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1)
    }

    /// Return an inclusion proof for all elements within the provided `range` of locations.
    ///
    /// # Errors
    ///
    /// Returns [Error::Empty] if the range is empty.
    /// Returns [Error::LocationOverflow] if any location exceeds the valid range.
    /// Returns [Error::RangeOutOfBounds] if `range.end` > [Self::leaves()].
    /// Returns [Error::ElementPruned] if a required node is missing.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<Family, D>, Error> {
        proof::build_range_proof(hasher, self.leaves, range, |pos| self.get_node(pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mmb::Family};
    use commonware_cryptography::Sha256;

    type H = Standard<Family, Sha256>;

    #[test]
    fn test_empty() {
        let mut hasher = H::new();
        let mmb = Mmb::new(&mut hasher);
        assert_eq!(*mmb.leaves(), 0);
        assert_eq!(*mmb.size(), 0);
    }

    #[test]
    fn test_append_and_size() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        // After 8 leaves, the MMB should have 13 nodes (from the module doc example).
        for i in 0u64..8 {
            let loc = mmb.append(&mut hasher, &i.to_be_bytes());
            assert_eq!(*loc, i);
        }
        assert_eq!(*mmb.leaves(), 8);
        assert_eq!(*mmb.size(), 13);
    }

    #[test]
    fn test_root_changes_with_each_append() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let mut prev_root = *mmb.root();
        for i in 0u64..16 {
            mmb.append(&mut hasher, &i.to_be_bytes());
            assert_ne!(
                *mmb.root(),
                prev_root,
                "root should change after append {i}"
            );
            prev_root = *mmb.root();
        }
    }

    #[test]
    fn test_single_element_proof_roundtrip() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        for i in 0u64..16 {
            mmb.append(&mut hasher, &i.to_be_bytes());
        }
        let root = *mmb.root();
        for i in 0u64..16 {
            let proof = mmb
                .proof(&mut hasher, Location::new(i))
                .unwrap_or_else(|e| panic!("loc={i}: {e}"));
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    &root
                ),
                "loc={i}: proof should verify"
            );
        }
    }
}
