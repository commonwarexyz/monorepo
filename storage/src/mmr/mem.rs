//! A bare-bones MMR structure without pruning and where all nodes are hashes & maintained in
//! memory within a single vector.

use crate::mmr::hasher::Hasher;
use crate::mmr::iterator::{nodes_needing_parents, PathIterator, PeakIterator};
use crate::mmr::verification::Proof;
use commonware_cryptography::{Digest, Hasher as CHasher};

/// Implementation of `Mmr`.
pub struct Mmr<H: CHasher> {
    hasher: H,
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from tallest tree to shortest.
    nodes: Vec<Digest>,
}

impl<H: CHasher> Default for Mmr<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Mmr<H> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            hasher: H::new(),
            nodes: Vec::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.nodes.len() as u64)
    }

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, element: &Digest) -> u64 {
        let peaks = nodes_needing_parents(self.peak_iterator());
        let element_pos = self.nodes.len() as u64;
        let hasher = &mut Hasher::new(&mut self.hasher);

        // Insert the element into the MMR as a leaf.
        let mut hash = hasher.leaf_hash(element_pos, element);
        self.nodes.push(hash.clone());

        // Compute the new parent nodes, if any, and insert them into the MMR.
        for sibling_pos in peaks.into_iter().rev() {
            let parent_pos = self.nodes.len() as u64;
            hash = hasher.node_hash(parent_pos, &self.nodes[sibling_pos as usize], &hash);
            self.nodes.push(hash.clone());
        }
        element_pos
    }

    /// Computes the root hash of the MMR.
    pub fn root_hash(&mut self) -> Digest {
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| &self.nodes[peak_pos as usize]);
        let hasher = &mut Hasher::new(&mut self.hasher);
        hasher.root_hash(self.nodes.len() as u64, peaks)
    }

    /// Return an inclusion proof for the specified element that consists of the size of the MMR and
    /// a vector of hashes. The proof vector contains: (1) the peak hashes other than the peak of
    /// the perfect tree containing the element, followed by: (2) the nodes in the remaining perfect
    /// tree necessary for reconstructing its peak hash from the specified element. Both segments
    /// are ordered by decreasing height.
    pub fn proof(&self, element_pos: u64) -> Proof {
        self.range_proof(element_pos, element_pos)
    }

    // Return an inclusion proof for the specified range of elements. The range is inclusive of
    // both endpoints.
    pub fn range_proof(&self, start_element_pos: u64, end_element_pos: u64) -> Proof {
        let mut hashes: Vec<Digest> = Vec::new();
        let mut start_tree_with_element = (u64::MAX, 0);
        let mut end_tree_with_element = (u64::MAX, 0);

        // Include peak hashes only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_iterator = self.peak_iterator();
        while let Some(item) = peak_iterator.next() {
            if start_tree_with_element.0 == u64::MAX && item.0 >= start_element_pos {
                // found the first tree to contain an element in the range
                start_tree_with_element = item;
                if item.0 >= end_element_pos {
                    // start and end tree are the same
                    end_tree_with_element = item;
                    continue;
                }
                for item in peak_iterator.by_ref() {
                    if item.0 >= end_element_pos {
                        // found the last tree to contain an element in the range
                        end_tree_with_element = item;
                        break;
                    }
                }
            } else {
                hashes.push(self.nodes[item.0 as usize].clone());
            }
        }
        assert!(start_tree_with_element.0 != u64::MAX);
        assert!(end_tree_with_element.0 != u64::MAX);

        // For the trees containing elements in the range, add left-sibling hashes of nodes along
        // the leftmost path, and right-sibling hashes of nodes along the rightmost path, in
        // decreasing order of the position of the parent node.
        let left_path_iter = PathIterator::new(
            start_element_pos,
            start_tree_with_element.0,
            start_tree_with_element.1,
        );

        let mut siblings = Vec::<(u64, u64)>::new();
        if start_element_pos == end_element_pos {
            // For the (common) case of a single element range, the right and left path are the
            // same so no need to process each independently.
            siblings.extend(left_path_iter);
        } else {
            let right_path_iter = PathIterator::new(
                end_element_pos,
                end_tree_with_element.0,
                end_tree_with_element.1,
            );
            // filter the right path for right siblings only
            siblings.extend(right_path_iter.filter(|(parent_pos, pos)| *parent_pos == *pos + 1));
            // filter the left path for left siblings only
            siblings.extend(left_path_iter.filter(|(parent_pos, pos)| *parent_pos != *pos + 1));

            // If the range spans more than one tree, then the hashes must already be in the correct
            // order. Otherwise, we enforce the desired order through sorting.
            if start_tree_with_element.0 == end_tree_with_element.0 {
                siblings.sort_by(|a, b| b.0.cmp(&a.0));
            }
        }
        hashes.extend(
            siblings
                .iter()
                .map(|(_, pos)| self.nodes[*pos as usize].clone()),
        );
        Proof {
            size: self.nodes.len() as u64,
            hashes,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::hasher::Hasher;
    use crate::mmr::iterator::nodes_needing_parents;
    use crate::mmr::mem::Mmr;
    use commonware_cryptography::{Digest, Sha256};

    #[test]
    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    fn test_add_eleven_values() {
        let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
        assert_eq!(
            mmr.peak_iterator().next(),
            None,
            "empty iterator should have no peaks"
        );

        let element = Digest::from_static(b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&element));
            let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
            assert_ne!(peaks.len(), 0);
            assert!(peaks.len() <= mmr.nodes.len());
            let nodes_needing_parents = nodes_needing_parents(mmr.peak_iterator());
            assert!(nodes_needing_parents.len() <= peaks.len());
        }
        assert_eq!(mmr.nodes.len(), 19, "mmr not of expected size");
        assert_eq!(
            leaves,
            vec![0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18],
            "mmr leaf positions not as expected"
        );
        let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![(14, 3), (17, 1), (18, 0)],
            "mmr peaks not as expected"
        );

        // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
        // highest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
        let peaks_needing_parents = nodes_needing_parents(mmr.peak_iterator());
        assert_eq!(
            peaks_needing_parents,
            vec![17, 18],
            "mmr nodes needing parents not as expected"
        );

        // verify leaf hashes
        let mut hasher = Sha256::default();
        let mut mmr_hasher = Hasher::new(&mut hasher);
        for leaf in leaves.iter().by_ref() {
            let hash = mmr_hasher.leaf_hash(*leaf, &element);
            assert_eq!(mmr.nodes[*leaf as usize], hash);
        }

        // verify height=1 hashes
        let hash2 = mmr_hasher.node_hash(2, &mmr.nodes[0], &mmr.nodes[1]);
        assert_eq!(mmr.nodes[2], hash2);
        let hash5 = mmr_hasher.node_hash(5, &mmr.nodes[3], &mmr.nodes[4]);
        assert_eq!(mmr.nodes[5], hash5);
        let hash9 = mmr_hasher.node_hash(9, &mmr.nodes[7], &mmr.nodes[8]);
        assert_eq!(mmr.nodes[9], hash9);
        let hash12 = mmr_hasher.node_hash(12, &mmr.nodes[10], &mmr.nodes[11]);
        assert_eq!(mmr.nodes[12], hash12);
        let hash17 = mmr_hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
        assert_eq!(mmr.nodes[17], hash17);

        // verify height=2 hashes
        let hash6 = mmr_hasher.node_hash(6, &mmr.nodes[2], &mmr.nodes[5]);
        assert_eq!(mmr.nodes[6], hash6);
        let hash13 = mmr_hasher.node_hash(13, &mmr.nodes[9], &mmr.nodes[12]);
        assert_eq!(mmr.nodes[13], hash13);
        let hash17 = mmr_hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
        assert_eq!(mmr.nodes[17], hash17);

        // verify topmost hash
        let hash14 = mmr_hasher.node_hash(14, &mmr.nodes[6], &mmr.nodes[13]);
        assert_eq!(mmr.nodes[14], hash14);

        // verify root hash
        let root_hash = mmr.root_hash();
        let peak_hashes = [hash14, hash17, mmr.nodes[18].clone()];
        let expected_root_hash = mmr_hasher.root_hash(19, peak_hashes.iter());
        assert_eq!(root_hash, expected_root_hash, "incorrect root hash");
    }
}
