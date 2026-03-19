//! Generic peak-to-leaf path iterator for Merkle-family data structures.
//!
//! [`Iterator`] traverses the path from a peak to a leaf within a perfect binary tree,
//! yielding `(parent_pos, sibling_pos, height)` tuples at each level. The traversal is top-down
//! (peak first), using [`Family::children`] for child positions and leaf locations for the
//! left/right decision at each level.

use crate::merkle::{Family, Location, Position};

/// Maximum number of items a [`Iterator`] can yield. A peak of height `h` has `2^h`
/// leaves, and leaf counts are stored as `u64`, so the maximum peak height is `u64::BITS - 1`.
pub(super) const MAX_PATH_LEN: usize = u64::BITS as usize - 1;

/// Yields `(parent_pos, sibling_pos, height)` for each internal node on the path from a peak
/// to a designated leaf, in top-down order (peak first). The peak itself is the first parent
/// yielded; the leaf is never yielded.
///
/// For example, consider an MMR tree and the path from the peak to leaf at location 2
/// (position 3):
///
/// ```text
///          6
///        /   \
///       2     5
///      / \   / \
///     0   1 3   4
/// ```
///
/// `path::Iterator` yields: `[(6, 2, 2), (5, 4, 1)]`
/// - Node 6 (height 2): left child 2 is the sibling, right child 5 is on the path.
/// - Node 5 (height 1): right child 4 is the sibling, left child 3 is the target leaf.
#[derive(Debug)]
pub struct Iterator<F: Family> {
    target_loc: Location<F>, // leaf we are navigating toward
    node_pos: Position<F>,   // current node on the path (starts at peak)
    first_leaf: u64,         // location of the leftmost leaf in the current subtree
    height: u32,             // height of the current node
}

impl<F: Family> Iterator<F> {
    /// Create a new path iterator from a peak to a leaf.
    ///
    /// - `peak_pos`: position of the peak node.
    /// - `height`: height of the peak.
    /// - `first_leaf_loc`: location of the leftmost leaf in this peak's subtree.
    /// - `target_loc`: location of the target leaf.
    pub const fn new(
        peak_pos: Position<F>,
        height: u32,
        first_leaf_loc: Location<F>,
        target_loc: Location<F>,
    ) -> Self {
        Self {
            target_loc,
            node_pos: peak_pos,
            first_leaf: first_leaf_loc.as_u64(),
            height,
        }
    }
}

impl<F: Family> core::iter::Iterator for Iterator<F> {
    /// `(parent_pos, sibling_pos, height)` where height is the parent's height.
    type Item = (Position<F>, Position<F>, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.height == 0 {
            return None;
        }

        let parent_pos = self.node_pos;
        let parent_height = self.height;
        let (left, right) = F::children(parent_pos, parent_height);

        let mid = self.first_leaf + (1u64 << (parent_height - 1));
        self.height -= 1;

        if self.target_loc.as_u64() < mid {
            // Target is in the left subtree.
            self.node_pos = left;
            Some((parent_pos, right, parent_height))
        } else {
            // Target is in the right subtree.
            self.node_pos = right;
            self.first_leaf = mid;
            Some((parent_pos, left, parent_height))
        }
    }
}
