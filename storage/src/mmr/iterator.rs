//! Iterators for traversing MMRs of a given size, and functions for computing various MMR
//! properties from their output.

/// A PeakIterator returns a (position, height) tuple for each peak in an MMR with the given size,
/// in decreasing order of height.
///
/// For the example MMR depicted at the top of this file, the PeakIterator would yield:
/// ```text
/// [(14, 3), (17, 1), (18, 0)]
/// ```
#[derive(Default)]
pub(crate) struct PeakIterator {
    size: u64,     // number of nodes in the MMR at the point the iterator was initialized
    node_pos: u64, // position of the current node
    two_h: u64,    // 2^(height+1) of the current node
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of a MMR with the given number of nodes.
    pub(crate) fn new(size: u64) -> PeakIterator {
        if size == 0 {
            return PeakIterator::default();
        }
        // Compute the position at which to start the search for peaks. This starting position will
        // not be in the MMR unless it happens to be a single perfect binary tree, but that's OK as
        // we will descend leftward until we find the first peak.
        let start = u64::MAX >> size.leading_zeros();
        let two_h = 1 << start.trailing_ones();
        PeakIterator {
            size,
            node_pos: start - 1,
            two_h,
        }
    }

    /// Return the position of the last leaf in an MMR of the given size.
    ///
    /// This is an O(log2(n)) operation.
    pub(crate) fn last_leaf_pos(size: u64) -> u64 {
        if size == 0 {
            return 0;
        }

        let last_peak = PeakIterator::new(size).last().unwrap();
        last_peak.0 - last_peak.1 as u64
    }

    /// Return if an MMR of the given `size` has a valid structure.
    ///
    /// The implementation verifies that peaks in the MMR of the given size have strictly decreasing
    /// height, which is a necessary condition for MMR validity.
    pub(crate) fn check_validity(mut size: u64) -> bool {
        if size <= 1 {
            return true;
        }

        // Consider each mountain from left to right.
        // For each, subtract its size from `size`.
        // We should find that the size eventually reaches 0
        // (the last mountain has more than 1 element) or 1
        // (the last mountain has 1 element).
        // If the size never reaches 0, there are "left over"
        // nodes and there isn't an MMR with the given `size`.

        // Height of the root of the smallest perfect binary
        // tree containing `size` (leaf is height 0)
        let mut height = 63 - size.leading_zeros();
        while height > 0 && size > 1 {
            // Subtract the size of the next mountain.
            // If it's bigger than the remaining size, it's not in this range.
            let mountain_size = (1 << (height + 1)) - 1;
            if size >= mountain_size {
                size -= mountain_size;
            }
            height -= 1;
        }
        size <= 1
    }
}

impl Iterator for PeakIterator {
    type Item = (u64, u32); // (peak, height)

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
pub(crate) fn nodes_needing_parents(peak_iterator: PeakIterator) -> Vec<u64> {
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

/// Returns the number of the leaf at position `leaf_pos` in an MMR, or None if
/// this is not a leaf.
///
/// This computation is O(log2(n)) in the given position.
#[allow(dead_code)] // TODO: remove this when we start using it
pub(crate) fn leaf_pos_to_num(leaf_pos: u64) -> Option<u64> {
    if leaf_pos == 0 {
        return Some(0);
    }

    let start = u64::MAX >> (leaf_pos + 1).leading_zeros();
    let height = start.trailing_ones();
    let mut two_h = 1 << (height - 1);
    let mut cur_node = start - 1;
    let mut leaf_num_floor = 0u64;

    while two_h > 1 {
        if cur_node == leaf_pos {
            return None;
        }
        let left_pos = cur_node - two_h;
        two_h >>= 1;
        if leaf_pos > left_pos {
            // The leaf is in the right subtree, so we must account for the leaves in the left
            // subtree all of which precede it.
            leaf_num_floor += two_h;
            cur_node -= 1; // move to the right child
        } else {
            // The node is in the left subtree
            cur_node = left_pos;
        }
    }

    Some(leaf_num_floor)
}

/// Returns the position of the leaf with number `leaf_num` in an MMR.
///
/// This computation is O(log2(n)) in `leaf_num`.
pub(crate) fn leaf_num_to_pos(leaf_num: u64) -> u64 {
    if leaf_num == 0 {
        return 0;
    }

    // The following won't underflow because any sane leaf number would have several leading zeros.
    let mut pos = u64::MAX >> (leaf_num.leading_zeros() - 1);
    let mut two_h = (pos >> 2) + 1;
    pos -= 1;

    // `pos` is the position of the peak of the lowest mountain that includes both the very first
    // leaf and the given leaf. We descend from this peak to the leaf level by descending left or
    // right depending on the relevant bit of `leaf_num`. The position we arrive at is the position
    // of the leaf.
    while two_h != 0 {
        if leaf_num & two_h != 0 {
            // descend right
            pos -= 1;
        } else {
            pos -= two_h << 1;
        }
        two_h >>= 1;
    }

    pos
}

/// Returns the position of the oldest provable node in the represented MMR.
pub(crate) fn oldest_provable_pos(peak_iterator: PeakIterator, oldest_retained_pos: u64) -> u64 {
    if peak_iterator.size == 0 {
        return 0;
    }
    for (peak_pos, height) in peak_iterator {
        if peak_pos < oldest_retained_pos {
            continue;
        }
        // We have found the tree containing the oldest retained node. Now we look for the
        // highest node in this tree whose left-sibling is pruned (if any). The provable nodes
        // are those that strictly follow this node. If no such node exists, then all existing
        // nodes are provable
        let mut two_h = 1 << height;
        let mut cur_node = peak_pos;
        while two_h > 1 {
            let left_pos = cur_node - two_h;
            let right_pos = cur_node - 1;
            if left_pos < oldest_retained_pos {
                // found pruned left sibling
                return right_pos + 1;
            }
            two_h >>= 1;
            cur_node = left_pos;
        }
        return oldest_retained_pos;
    }
    // The oldest retained node should always be at or equal to the last peak (aka the last node
    // in the MMR), so if we get here, the MMR corresponding to the inputs is invalid.
    panic!("mmr invalid")
}

/// Returns the position of the oldest node whose digest will be required to prove inclusion of
/// `provable_pos`. The implementation assumes that the peak digests will remain available.
///
/// Pruning this position will render the node with position `provable_pos` unprovable.
pub(crate) fn oldest_required_proof_pos(peak_iterator: PeakIterator, provable_pos: u64) -> u64 {
    if peak_iterator.size == 0 {
        return 0;
    }
    for (peak_pos, height) in peak_iterator {
        if peak_pos < provable_pos {
            continue;
        }
        // We have found the tree containing the node we want to guarantee is provable. We
        // now walk down the path from its root to this node.
        let iter = PathIterator::new(provable_pos, peak_pos, height);
        for (parent_pos, sibling_pos) in iter {
            if parent_pos == provable_pos {
                // If we hit the node we are trying to prove while walking the path, then no
                // older nodes are required to prove it.
                return provable_pos;
            }
            // If we hit a node whose sibling precedes the position we wish to prove, then that
            // sibling is required to prove it, and it's the oldest such node.
            if sibling_pos < provable_pos {
                return sibling_pos;
            }
        }
        return provable_pos;
    }
    // The oldest retained node should always be at or equal to the last peak (aka the last node
    // in the MMR), so if we get here, the MMR corresponding to the inputs is invalid.
    panic!("mmr invalid")
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
pub(crate) struct PathIterator {
    leaf_pos: u64, // position of the leaf node in the path
    node_pos: u64, // current node position in the path from peak to leaf
    two_h: u64,    // 2^height of the current node
}

impl PathIterator {
    /// Return a PathIterator over the siblings of nodes along the path from peak to leaf in the
    /// perfect binary tree with peak `peak_pos` and having height `height`, not including the peak
    /// itself.
    pub(crate) fn new(leaf_pos: u64, peak_pos: u64, height: u32) -> PathIterator {
        PathIterator {
            leaf_pos,
            node_pos: peak_pos,
            two_h: 1 << height,
        }
    }
}

impl Iterator for PathIterator {
    type Item = (u64, u64); // (parent_pos, sibling_pos)

    fn next(&mut self) -> Option<Self::Item> {
        if self.two_h <= 1 {
            return None;
        }

        let left_pos = self.node_pos - self.two_h;
        let right_pos = left_pos + self.two_h - 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::mem::Mmr;
    use commonware_cryptography::{sha256::hash, Sha256};

    // Very basic testing for the proving boundary computations. Testing of the validity of these
    // boundaries appears in the verification crate.
    #[test]
    fn test_proof_boundaries() {
        for oldest_retained in 0u64..19 {
            let iter = PeakIterator::new(19);
            let oldest_provable = oldest_provable_pos(iter, oldest_retained);
            assert!(oldest_provable >= oldest_retained);
        }

        for provable_pos in 0u64..19 {
            let iter = PeakIterator::new(19);
            let oldest_required = oldest_required_proof_pos(iter, provable_pos);
            assert!(oldest_required <= provable_pos);
        }
    }

    #[test]
    fn test_leaf_num_calculation() {
        let digest = hash(b"testing");

        // Build MMR with 1000 leaves and make sure we can correctly convert each leaf position to
        // its number and back again.
        let mut mmr = Mmr::<Sha256>::new();
        let mut hasher = Sha256::default();
        let mut num_to_pos = Vec::new();
        for _ in 0u64..1000 {
            num_to_pos.push(mmr.add(&mut hasher, &digest));
        }

        let mut last_leaf_pos = 0;
        for (leaf_num_expected, leaf_pos) in num_to_pos.iter().enumerate() {
            let leaf_num_got = leaf_pos_to_num(*leaf_pos).unwrap();
            assert_eq!(leaf_num_got, leaf_num_expected as u64);
            let leaf_pos_got = leaf_num_to_pos(leaf_num_got);
            assert_eq!(leaf_pos_got, *leaf_pos);
            for i in last_leaf_pos + 1..*leaf_pos {
                assert!(leaf_pos_to_num(i).is_none());
            }
            last_leaf_pos = *leaf_pos;
        }
    }

    #[test]
    fn test_check_validity() {
        // Test cases for check_validity function
        let valid_sizes = vec![
            0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18, 19, 22, 23, 25, 26, 31, 32, 34, 35, 38, 39, 41,
            42, 46, 47, 49, 50, 53, 54, 56, 57, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024,
            2047, 2048, 4095, 4096,
        ];
        let invalid_sizes = vec![
            2, 5, 6, 9, 12, 13, 14, 17, 20, 21, 24, 27, 28, 29, 30, 36, 37, 40, 43, 44, 45, 48, 51,
            52, 55, 58, 65, 129, 257, 513,
        ];

        for size in valid_sizes {
            assert!(
                PeakIterator::check_validity(size),
                "Expected validity for size {}",
                size
            );
        }

        for size in invalid_sizes {
            assert!(
                !PeakIterator::check_validity(size),
                "Expected invalidity for size {}",
                size
            );
        }

        for i in 2..63 {
            assert!(PeakIterator::check_validity((1 << i) - 1));
            assert!(PeakIterator::check_validity(1 << i));
            assert!(!PeakIterator::check_validity((1 << i) + 1));
        }
    }
}
