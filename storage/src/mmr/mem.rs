//! A bare-bones MMR structure without pruning and where all elements are hashes & maintained in memory.

use crate::mmr::{Hash, Hasher};

/// Implementation of `InMemoryMMR`.
pub struct InMemoryMMR<const N: usize, H: Hasher<N>> {
    hasher: H,
    elements: Vec<Hash<N>>,
}

#[derive(Default)]
struct PeakIterator {
    sz: u64,    // Number of elements in the MMR at the point the iterator was initialized.
    peak: u64,  // 1-based index of the current peak, which may not be in the MMR.
    two_h: u64, // 2^(height+1) of the current peak, where a leaf has a height of 0.
}

/// A PeakIterator returns a (height, peak) tuple for each peak in the MMR. Height starts at 0 for leaves, and a peak is
/// a 0-based index of the represented element. You can change the MMR underneath during iteration, but the iterator
/// will only return the peaks that existed at the time of its initialization.
impl Iterator for PeakIterator {
    type Item = (u32, u64); // (height, peak)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.peak <= self.sz {
                let r = (self.two_h.trailing_zeros() - 1, self.peak - 1);
                self.peak += self.two_h - 1; // move to the right sibling
                return Some(r);
            }
            self.two_h >>= 1;
            self.peak -= self.two_h; // descend to the left child
        }
        None
    }
}

impl<const N: usize, H: Hasher<N>> InMemoryMMR<N, H> {
    /// Return a new (empty) `InMemoryMMR`.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            elements: Vec::new(),
        }
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        let sz = self.elements.len() as u64;
        if sz == 0 {
            return PeakIterator::default();
        }
        // Compute the starting peak. This starting peak will not be in the MMR unless it happens to
        // be a full binary tree, but that's OK as we will descend leftward until we find one.
        let peak = u64::MAX >> sz.leading_zeros();
        let two_h = 1 << peak.trailing_ones();
        PeakIterator { sz, peak, two_h }
    }

    // Returns the set of peaks that will require a new parent after adding the next element to the
    // MMR. This set is non-empty only if there is a height-0 (leaf) peak in the MMR. The result
    // will contain this leaf peak plus all other MMR peaks of consecutively increasing height, in
    // reverse order (that is, the leaf peak comes last).
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

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, element: &Hash<N>) -> u64 {
        let peaks = self.nodes_needing_parents();

        // insert the new leaf hash into the MMR
        let leaf_pos = self.elements.len() as u64;
        let mut current_hash = self.hasher.hash_leaf(leaf_pos, element);
        self.elements.push(current_hash);

        // Compute the new parent nodes, if any, and insert them into the MMR.
        for sibling_pos in peaks.iter().rev() {
            let parent_pos = self.elements.len() as u64;
            current_hash = self.hasher.hash_node(
                parent_pos,
                &self.elements[*sibling_pos as usize],
                &current_hash,
            );
            self.elements.push(current_hash);
        }
        leaf_pos
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

        let element: Hash<32> = Hash(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&element));
            let peaks: Vec<(u32, u64)> = mmr.peak_iterator().collect();
            assert_ne!(peaks.len(), 0);
            assert!(peaks.len() <= mmr.elements.len());
        }
        assert_eq!(mmr.elements.len(), 19, "mmr not of expected size");
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
            let hash = hasher.hash_leaf(leaf, &element);
            assert_eq!(mmr.elements[leaf as usize], hash);
        }

        // verify height=1 hashes
        let hash2 = hasher.hash_node(2, &mmr.elements[0], &mmr.elements[1]);
        assert_eq!(mmr.elements[2], hash2);
        let hash5 = hasher.hash_node(5, &mmr.elements[3], &mmr.elements[4]);
        assert_eq!(mmr.elements[5], hash5);
        let hash9 = hasher.hash_node(9, &mmr.elements[7], &mmr.elements[8]);
        assert_eq!(mmr.elements[9], hash9);
        let hash12 = hasher.hash_node(12, &mmr.elements[10], &mmr.elements[11]);
        assert_eq!(mmr.elements[12], hash12);
        let hash17 = hasher.hash_node(17, &mmr.elements[15], &mmr.elements[16]);
        assert_eq!(mmr.elements[17], hash17);

        // verify height=2 hashes
        let hash6 = hasher.hash_node(6, &mmr.elements[2], &mmr.elements[5]);
        assert_eq!(mmr.elements[6], hash6);
        let hash13 = hasher.hash_node(13, &mmr.elements[9], &mmr.elements[12]);
        assert_eq!(mmr.elements[13], hash13);
        let hash17 = hasher.hash_node(17, &mmr.elements[15], &mmr.elements[16]);
        assert_eq!(mmr.elements[17], hash17);

        // verify topmost hash
        let hash14 = hasher.hash_node(14, &mmr.elements[6], &mmr.elements[13]);
        assert_eq!(mmr.elements[14], hash14);
    }
}
