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

    /// Return if an MMR of the given `size` has a valid structure.
    ///
    /// The implementation verifies that peaks in the MMR of the given size have strictly decreasing
    /// height, which is a necessary condition for MMR validity.
    pub(crate) fn check_validity(size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let start = u64::MAX >> size.leading_zeros();
        let mut two_h = 1 << start.trailing_ones();
        let mut node_pos = start - 1;
        while two_h > 1 {
            if node_pos < size {
                if two_h == 2 {
                    // If this peak is a leaf yet there are more nodes remaining, then this MMR is
                    // invalid.
                    return node_pos == size - 1;
                }
                // move to the right sibling
                node_pos += two_h - 1;
                if node_pos < size {
                    // If the right sibling is in the MMR, then it is invalid.
                    return false;
                }
                continue;
            }
            // descend to the left child
            two_h >>= 1;
            node_pos -= two_h;
        }
        true
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

/// Returns the position of the oldest provable node in the represented MMR.
pub(crate) fn oldest_provable_pos(peak_iterator: PeakIterator, oldest_remembered_pos: u64) -> u64 {
    if peak_iterator.size == 0 {
        return 0;
    }
    for (peak_pos, height) in peak_iterator {
        if peak_pos < oldest_remembered_pos {
            continue;
        }
        // We have found the tree containing the oldest remembered node. Now we look for the
        // highest node in this tree whose left-sibling is pruned (if any). The provable nodes
        // are those that strictly follow this node. If no such node exists, then all existing
        // nodes are provable
        let mut two_h = 1 << height;
        let mut cur_node = peak_pos;
        while two_h > 1 {
            let left_pos = cur_node - two_h;
            let right_pos = left_pos + two_h - 1;
            if left_pos < oldest_remembered_pos {
                // found pruned left sibling
                return right_pos + 1;
            }
            two_h >>= 1;
            cur_node = left_pos;
        }
        return oldest_remembered_pos;
    }
    // The oldest remembered node should always be at or equal to the last peak (aka the last node
    // in the MMR), so if we get here, the MMR corresponding to the inputs is invalid.
    panic!("mmr invalid")
}

/// Returns the position of the oldest node whose digest will be required to prove inclusion of
/// `provable_pos`.
///
/// Forgetting this position will render the node with position `provable_pos` unprovable.
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
    // The oldest remembered node should always be at or equal to the last peak (aka the last node
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

    // Very basic testing for the proving boundary computations. Testing of the validity of these
    // boundaries appears in the verification crate.
    #[test]
    fn test_proof_boundaries() {
        for oldest_remembered in 0u64..19u64 {
            let iter = PeakIterator::new(19);
            let oldest_provable = oldest_provable_pos(iter, oldest_remembered);
            assert!(oldest_provable >= oldest_remembered);
        }

        for provable_pos in 0u64..19u64 {
            let iter = PeakIterator::new(19);
            let oldest_required = oldest_required_proof_pos(iter, provable_pos);
            assert!(oldest_required <= provable_pos);
        }
    }
}
