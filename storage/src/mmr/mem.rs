//! A bare-bones MMR structure without pruning and where all nodes are hashes & maintained in
//! memory.

use crate::mmr::{Hash, Hasher};

/// Implementation of `InMemoryMMR`.
pub struct InMemoryMMR<const N: usize, H: Hasher<N>> {
    hasher: H,
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from highest peak to lowest.
    nodes: Vec<Hash<N>>,
}

#[derive(Default)]
struct PeakIterator {
    sz: u64,    // Number of nodes in the MMR at the point the iterator was initialized.
    peak: u64,  // 1-based index of the current peak, which may not be in the MMR.
    two_h: u64, // 2^(height+1) of the current peak, where a leaf has a height of 0.
}

/// A PeakIterator returns a (height, position) tuple for each peak in the MMR, in decreasing order
/// of height. Height starts at 0 for leaves, and a peak position is its 0-based offset into the
/// underlying nodes vector. The iterator will only return the peaks that existed at the time of its
/// initialization if new elements are added to the MMR between iterations.
impl Iterator for PeakIterator {
    type Item = (u32, u64); // (height, peak)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.peak <= self.sz {
                // found a peak
                let r = (self.two_h.trailing_zeros() - 1, self.peak - 1);
                // move to the right sibling
                self.peak += self.two_h - 1;
                assert!(self.peak > self.sz); // sibling shouldn't be in the MMR if MMR is valid
                return Some(r);
            }
            // descend to the left child
            self.two_h >>= 1;
            self.peak -= self.two_h;
        }
        None
    }
}

// Return a new iterator over the peaks of a MMR with the given number of nodes.
fn peak_iterator(sz: u64) -> PeakIterator {
    if sz == 0 {
        return PeakIterator::default();
    }
    // Compute the starting peak. This starting peak will not be in the MMR unless it happens to
    // be a full binary tree, but that's OK as we will descend leftward until we find one.
    let peak = u64::MAX >> sz.leading_zeros();
    let two_h = 1 << peak.trailing_ones();
    PeakIterator { sz, peak, two_h }
}

impl<const N: usize, H: Hasher<N>> InMemoryMMR<N, H> {
    /// Return a new (empty) `InMemoryMMR`.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            nodes: Vec::new(),
        }
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        peak_iterator(self.nodes.len() as u64)
    }

    // Returns the set of peaks that will require a new parent after adding the next leaf to the
    // MMR. This set is non-empty only if there is a height-0 (leaf) peak in the MMR. The result
    // will contain this leaf peak plus the other MMR peaks with contiguously increasing height.
    // Nodes in the result are ordered by decreasing height (so the leaf node comes last).
    fn nodes_needing_parents(&mut self) -> Vec<u64> {
        let mut peaks = Vec::new();
        let it = self.peak_iterator();
        let mut last_height = u32::MAX;
        for (height, peak) in it {
            assert!(last_height > 0);
            assert!(height < last_height);
            if height != last_height - 1 {
                peaks.clear();
            }
            peaks.push(peak);
            last_height = height;
        }
        if last_height != 0 {
            // there is no peak that is a leaf
            peaks.clear();
        }
        peaks
    }

    /// Add a leaf to the MMR and return its position in the MMR.
    pub fn add(&mut self, leaf_hash: &Hash<N>) -> u64 {
        let peaks = self.nodes_needing_parents();

        // insert the new leaf hash into the MMR
        let leaf_pos = self.nodes.len() as u64;
        let mut current_hash = self.hasher.leaf_hash(leaf_pos, leaf_hash);
        self.nodes.push(current_hash);

        // Compute the new parent nodes, if any, and insert them into the MMR.
        for sibling_pos in peaks.iter().rev() {
            let parent_pos = self.nodes.len() as u64;
            current_hash = self.hasher.node_hash(
                parent_pos,
                &self.nodes[*sibling_pos as usize],
                &current_hash,
            );
            self.nodes.push(current_hash);
        }
        leaf_pos
    }

    /// Computes the root hash of the MMR.
    pub fn root_hash(&mut self) -> Hash<N> {
        let peaks = self
            .peak_iterator()
            .map(|(_, peak)| &self.nodes[peak as usize]);
        self.hasher.root_hash(self.nodes.len() as u64, peaks)
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::{Hash, Hasher, InMemoryMMR, Sha256Hasher};

    #[test]
    /// Test MMR building by consecutively adding 11 equal values to a new MMR. In the end the MMR
    /// should have 19 nodes total with 3 peaks, exactly as pictured in the MMR example here:
    /// https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/
    ///
    /// Pasted here for convenience:
    ///
    ///    Height
    ///      3              14
    ///                   /    \
    ///                  /      \
    ///                 /        \
    ///                /          \
    ///      2        6            13
    ///             /   \        /    \
    ///      1     2     5      9     12     17
    ///           / \   / \    / \   /  \   /  \
    ///      0   0   1 3   4  7   8 10  11 15  16 18
    fn test_add_eleven_values() {
        let mut mmr: InMemoryMMR<32, Sha256Hasher> = InMemoryMMR::new(Sha256Hasher::new());
        // the empty iterator should have no peaks
        assert_eq!(mmr.peak_iterator().next(), None);

        let leaf_hash: Hash<32> = Hash(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&leaf_hash));
            let peaks: Vec<(u32, u64)> = mmr.peak_iterator().collect();
            assert_ne!(peaks.len(), 0);
            assert!(peaks.len() <= mmr.nodes.len());
            let nodes_needing_parents = mmr.nodes_needing_parents();
            assert!(nodes_needing_parents.len() <= peaks.len());
        }
        assert_eq!(mmr.nodes.len(), 19, "mmr not of expected size");
        assert_eq!(
            leaves,
            vec![0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18],
            "mmr leaf positions not as expected"
        );
        let peaks: Vec<(u32, u64)> = mmr.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![(3, 14), (1, 17), (0, 18)],
            "mmr peaks not as expected"
        );

        // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
        // heighest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
        let peaks_needing_parents = mmr.nodes_needing_parents();
        assert_eq!(
            peaks_needing_parents,
            vec![17, 18],
            "mmr nodes needing parents not as expected"
        );

        // verify leaf hashes
        let mut hasher = Sha256Hasher::new();
        for leaf in leaves {
            let hash = hasher.leaf_hash(leaf, &leaf_hash);
            assert_eq!(mmr.nodes[leaf as usize], hash);
        }

        // verify height=1 hashes
        let hash2 = hasher.node_hash(2, &mmr.nodes[0], &mmr.nodes[1]);
        assert_eq!(mmr.nodes[2], hash2);
        let hash5 = hasher.node_hash(5, &mmr.nodes[3], &mmr.nodes[4]);
        assert_eq!(mmr.nodes[5], hash5);
        let hash9 = hasher.node_hash(9, &mmr.nodes[7], &mmr.nodes[8]);
        assert_eq!(mmr.nodes[9], hash9);
        let hash12 = hasher.node_hash(12, &mmr.nodes[10], &mmr.nodes[11]);
        assert_eq!(mmr.nodes[12], hash12);
        let hash17 = hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
        assert_eq!(mmr.nodes[17], hash17);

        // verify height=2 hashes
        let hash6 = hasher.node_hash(6, &mmr.nodes[2], &mmr.nodes[5]);
        assert_eq!(mmr.nodes[6], hash6);
        let hash13 = hasher.node_hash(13, &mmr.nodes[9], &mmr.nodes[12]);
        assert_eq!(mmr.nodes[13], hash13);
        let hash17 = hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
        assert_eq!(mmr.nodes[17], hash17);

        // verify topmost hash
        let hash14 = hasher.node_hash(14, &mmr.nodes[6], &mmr.nodes[13]);
        assert_eq!(mmr.nodes[14], hash14);

        // verify root hash
        let root_hash = mmr.root_hash();
        let peak_hashes = vec![hash14, hash17, mmr.nodes[18]];
        let expected_root_hash = hasher.root_hash(19, peak_hashes.iter());
        assert_eq!(root_hash, expected_root_hash, "incorrect root hash");
    }
}
