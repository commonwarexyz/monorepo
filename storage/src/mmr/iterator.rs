//! Iterators for traversing MMRs of a given size, and functions for computing various MMR
//! properties from their output. These are lower levels methods that are useful for implementing
//! new MMR variants or extensions.

use super::Position;
use alloc::vec::Vec;

/// A PeakIterator returns a (position, height) tuple for each peak in an MMR with the given size,
/// in decreasing order of height.
///
/// For the example MMR depicted at the top of this file, the PeakIterator would yield:
/// ```text
/// [(14, 3), (17, 1), (18, 0)]
/// ```
#[derive(Default)]
pub struct PeakIterator {
    size: Position, // number of nodes in the MMR at the point the iterator was initialized
    node_pos: Position, // position of the current node
    two_h: u64,     // 2^(height+1) of the current node
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of a MMR with the given number of nodes.
    ///
    /// # Panics
    ///
    /// Iteration will panic if size is not a valid MMR size. If used on untrusted input, call
    /// [Position::is_mmr_size] first.
    pub fn new(size: Position) -> Self {
        if size == 0 {
            return Self::default();
        }
        // Compute the position at which to start the search for peaks. This starting position will
        // not be in the MMR unless it happens to be a single perfect binary tree, but that's OK as
        // we will descend leftward until we find the first peak.
        let start = u64::MAX >> size.leading_zeros();
        assert_ne!(start, u64::MAX, "size overflow");
        let two_h = 1 << start.trailing_ones();
        Self {
            size,
            node_pos: Position::new(start - 1),
            two_h,
        }
    }

    /// Return the position of the last leaf in an MMR of the given size.
    ///
    /// This is an O(log2(n)) operation.
    ///
    /// # Panics
    ///
    /// Panics if size is too large (specifically, the topmost bit should be 0).
    pub fn last_leaf_pos(size: Position) -> Position {
        if size == 0 {
            return Position::new(0);
        }

        let last_peak = Self::new(size)
            .last()
            .expect("PeakIterator has at least one peak when size > 0");
        last_peak.0.checked_sub(last_peak.1 as u64).unwrap()
    }

    /// Returns the largest valid MMR size that is no greater than the given size.
    ///
    /// This is an O(log2(n)) operation using binary search on the number of leaves.
    ///
    /// # Panics
    ///
    /// Panics if `size` exceeds [crate::mmr::MAX_POSITION].
    pub fn to_nearest_size(size: Position) -> Position {
        assert!(
            size <= crate::mmr::MAX_POSITION,
            "size exceeds MAX_POSITION"
        );

        // Algorithm: A valid MMR size corresponds to a specific number of leaves N, where:
        // mmr_size(N) = 2*N - popcount(N)
        // This formula comes from the fact that N leaves require N-1 internal nodes, but merging
        // creates popcount(N)-1 additional nodes. We binary search for the largest N where
        // mmr_size(N) <= size.

        if size == 0 {
            return size;
        }

        // Binary search for the largest N (number of leaves) such that
        // mmr_size(N) = 2*N - popcount(N) <= size
        let size_val = size.as_u64();
        let mut low = 0u64;
        let mut high = size_val; // MMR size >= leaf count, so N <= size

        while low < high {
            // Use div_ceil for upper-biased midpoint in binary search
            let mid = (low + high).div_ceil(2);
            let mmr_size = 2 * mid - mid.count_ones() as u64;

            if mmr_size <= size_val {
                low = mid;
            } else {
                high = mid - 1;
            }
        }

        // low is the largest N where mmr_size(N) <= size
        let result = 2 * low - low.count_ones() as u64;
        Position::new(result)
    }
}

impl Iterator for PeakIterator {
    type Item = (Position, u32); // (peak, height)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.node_pos < self.size {
                // found a peak
                let peak_item = (self.node_pos, self.two_h.trailing_zeros() - 1);
                // move to the right sibling
                self.node_pos += self.two_h - 1;
                assert!(self.node_pos >= self.size); // sibling shouldn't be in the MMR if MMR is valid
                return Some(peak_item);
            }
            // descend to the left child
            self.two_h >>= 1;
            self.node_pos -= self.two_h;
        }
        None
    }
}

/// Returns the set of peaks that will require a new parent after adding the next leaf to an MMR
/// with the given peaks. This set is non-empty only if there is a height-0 (leaf) peak in the MMR.
/// The result will contain this leaf peak plus the other MMR peaks with contiguously increasing
/// height. Nodes in the result are ordered by decreasing height.
pub(crate) fn nodes_needing_parents(peak_iterator: PeakIterator) -> Vec<Position> {
    let mut peaks = Vec::new();
    let mut last_height = u32::MAX;

    for (peak_pos, height) in peak_iterator {
        assert!(last_height > 0);
        assert!(height < last_height);
        if height != last_height - 1 {
            peaks.clear();
        }
        peaks.push(peak_pos);
        last_height = height;
    }
    if last_height != 0 {
        // there is no peak that is a leaf
        peaks.clear();
    }
    peaks
}

/// Returns the height of the node at position `pos` in an MMR.
#[cfg(any(feature = "std", test))]
pub(crate) const fn pos_to_height(pos: Position) -> u32 {
    let mut pos = pos.as_u64();

    if pos == 0 {
        return 0;
    }

    let mut size = u64::MAX >> pos.leading_zeros();
    while size != 0 {
        if pos >= size {
            pos -= size;
        }
        size >>= 1;
    }

    pos as u32
}

/// A PathIterator returns a (parent_pos, sibling_pos) tuple for the sibling of each node along the
/// path from a given perfect binary tree peak to a designated leaf, not including the peak itself.
///
/// For example, consider the tree below and the path from the peak to leaf node 3. Nodes on the
/// path are [6, 5, 3] and tagged with '*' in the diagram):
///
/// ```text
///
///          6*
///        /   \
///       2     5*
///      / \   / \
///     0   1 3*  4
///
/// A PathIterator for this example yields:
///    [(6, 2), (5, 4)]
/// ```
#[derive(Debug)]
pub struct PathIterator {
    leaf_pos: Position, // position of the leaf node in the path
    node_pos: Position, // current node position in the path from peak to leaf
    two_h: u64,         // 2^height of the current node
}

impl PathIterator {
    /// Return a PathIterator over the siblings of nodes along the path from peak to leaf in the
    /// perfect binary tree with peak `peak_pos` and having height `height`, not including the peak
    /// itself.
    pub const fn new(leaf_pos: Position, peak_pos: Position, height: u32) -> Self {
        Self {
            leaf_pos,
            node_pos: peak_pos,
            two_h: 1 << height,
        }
    }
}

impl Iterator for PathIterator {
    type Item = (Position, Position); // (parent_pos, sibling_pos)

    fn next(&mut self) -> Option<Self::Item> {
        if self.two_h <= 1 {
            return None;
        }

        let left_pos = self.node_pos - self.two_h;
        let right_pos = self.node_pos - 1;
        self.two_h >>= 1;

        if left_pos < self.leaf_pos {
            let r = Some((self.node_pos, left_pos));
            self.node_pos = right_pos;
            return r;
        }
        let r = Some((self.node_pos, right_pos));
        self.node_pos = left_pos;
        r
    }
}

/// Return the list of pruned (pos < `start_pos`) node positions that are still required for
/// proving any retained node.
///
/// This set consists of every pruned node that is either (1) a peak, or (2) has no descendent
/// in the retained section, but its immediate parent does. (A node meeting condition (2) can be
/// shown to always be the left-child of its parent.)
///
/// This set of nodes does not change with the MMR's size, only the pruning boundary. For a
/// given pruning boundary that happens to be a valid MMR size, one can prove that this set is
/// exactly the set of peaks for an MMR whose size equals the pruning boundary. If the pruning
/// boundary is not a valid MMR size, then the set corresponds to the peaks of the largest MMR
/// whose size is less than the pruning boundary.
pub(crate) fn nodes_to_pin(start_pos: Position) -> impl Iterator<Item = Position> {
    PeakIterator::new(PeakIterator::to_nearest_size(start_pos)).map(|(pos, _)| pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{hasher::Standard, mem::CleanMmr, Location};
    use commonware_cryptography::Sha256;

    #[test]
    fn test_leaf_loc_calculation() {
        // Build MMR with 1000 leaves and make sure we can correctly convert each leaf position to
        // its number and back again.
        let mut hasher = Standard::<Sha256>::new();
        let mut mmr = CleanMmr::new(&mut hasher);
        let mut loc_to_pos = Vec::new();
        let digest = [1u8; 32];
        for _ in 0u64..1000 {
            loc_to_pos.push(mmr.add(&mut hasher, &digest));
        }

        let mut last_leaf_pos = 0;
        for (leaf_loc_expected, leaf_pos) in loc_to_pos.into_iter().enumerate() {
            let leaf_loc_got = Location::try_from(leaf_pos).unwrap();
            assert_eq!(
                leaf_loc_got,
                Location::new_unchecked(leaf_loc_expected as u64)
            );
            let leaf_pos_got = Position::try_from(leaf_loc_got).unwrap();
            assert_eq!(leaf_pos_got, *leaf_pos);
            for i in last_leaf_pos + 1..*leaf_pos {
                assert!(Location::try_from(Position::new(i)).is_err());
            }
            last_leaf_pos = *leaf_pos;
        }
    }

    #[test]
    #[should_panic(expected = "size exceeds MAX_POSITION")]
    fn test_to_nearest_size_panic() {
        PeakIterator::to_nearest_size(crate::mmr::MAX_POSITION + 1);
    }

    #[test]
    fn test_to_nearest_size() {
        // Build an MMR incrementally and verify to_nearest_size for all intermediate values
        let mut hasher = Standard::<Sha256>::new();
        let mut mmr = CleanMmr::new(&mut hasher);
        let digest = [1u8; 32];

        for _ in 0..1000 {
            let current_size = mmr.size();

            // Test positions from current size up to current size + 10
            for test_pos in *current_size..=*current_size + 10 {
                let rounded = PeakIterator::to_nearest_size(Position::new(test_pos));

                // Verify rounded is a valid MMR size
                assert!(
                    rounded.is_mmr_size(),
                    "rounded size {rounded} should be valid (test_pos: {test_pos}, current: {current_size})",
                );

                // Verify rounded <= test_pos
                assert!(
                    rounded <= test_pos,
                    "rounded {rounded} should be <= test_pos {test_pos} (current: {current_size})",
                );

                // Verify rounded is the largest valid size <= test_pos
                if rounded < test_pos {
                    assert!(
                        !(rounded + 1).is_mmr_size(),
                        "rounded {rounded} should be largest valid size <= {test_pos} (current: {current_size})",
                    );
                }
            }

            mmr.add(&mut hasher, &digest);
        }
    }

    #[test]
    fn test_to_nearest_size_specific_cases() {
        // Test edge cases
        assert_eq!(PeakIterator::to_nearest_size(Position::new(0)), 0);
        assert_eq!(PeakIterator::to_nearest_size(Position::new(1)), 1);

        // Test consecutive values
        let mut expected = Position::new(0);
        for size in 0..=20 {
            let rounded = PeakIterator::to_nearest_size(Position::new(size));
            assert_eq!(rounded, expected);
            if Position::new(size + 1).is_mmr_size() {
                expected = Position::new(size + 1);
            }
        }

        // Test with large value
        let large_size = Position::new(1_000_000);
        let rounded = PeakIterator::to_nearest_size(large_size);
        assert!(rounded.is_mmr_size());
        assert!(rounded <= large_size);

        // Test maximum allowed input
        let largest_valid_size = crate::mmr::MAX_POSITION;
        let rounded = PeakIterator::to_nearest_size(largest_valid_size);
        assert!(rounded.is_mmr_size());
        assert!(rounded <= largest_valid_size);
    }
}
