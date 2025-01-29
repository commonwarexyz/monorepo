//! A basic MMR where all nodes are stored in-memory.

use crate::mmr::hasher::Hasher;
use crate::mmr::iterator::{nodes_needing_parents, PathIterator, PeakIterator};
use crate::mmr::verification::Proof;
use crate::mmr::Error;
use crate::mmr::Error::{ElementPruned, InvalidElementPosition};
use commonware_cryptography::Hasher as CHasher;

/// Implementation of `Mmr`.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX
/// (u32::MAX on 32-bit architectures).
pub struct Mmr<H: CHasher> {
    hasher: H,
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from tallest tree to shortest.
    nodes: Vec<H::Digest>,
    // The position of the oldest element still maintained by the MMR. Will be 0 unless forgetting
    // has been invoked. If non-zero, then proofs can only be generated for elements with positions
    // strictly after this point.
    oldest_remembered_pos: u64,
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
            oldest_remembered_pos: 0,
        }
    }

    /// Return the total number of nodes in the MMR, independent of any forgetting.
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64 + self.oldest_remembered_pos
    }

    /// Return the position of the oldest remembered node in the MMR. Proofs can only be generated
    /// for elements in ranges that follow this position.
    pub fn oldest_remembered_node_pos(&self) -> u64 {
        self.oldest_remembered_pos
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: u64) -> u64 {
        index + self.oldest_remembered_pos
    }

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, element: &H::Digest) -> u64 {
        let peaks = nodes_needing_parents(self.peak_iterator());
        let element_pos = self.index_to_pos(self.nodes.len() as u64);
        let hasher = &mut Hasher::new(&mut self.hasher);

        // Insert the element into the MMR as a leaf.
        let mut hash = hasher.leaf_hash(element_pos, element);
        self.nodes.push(hash.clone());

        // Compute the new parent nodes, if any, and insert them into the MMR.
        for sibling_pos in peaks.into_iter().rev() {
            let parent_pos = self.oldest_remembered_pos + self.nodes.len() as u64;
            let sibling_index = (sibling_pos - self.oldest_remembered_pos) as usize;
            hash = hasher.node_hash(parent_pos, &self.nodes[sibling_index], &hash);
            self.nodes.push(hash.clone());
        }
        element_pos
    }

    /// Computes the root hash of the MMR.
    pub fn root_hash(&mut self) -> H::Digest {
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| &self.nodes[(peak_pos - self.oldest_remembered_pos) as usize]);
        let size = self.size();
        Hasher::new(&mut self.hasher).root_hash(size, peaks)
    }

    /// Return an inclusion proof for the specified element. Returns `ElementPruned` error if the
    /// requested element is not currently stored by this MMR.
    pub fn proof(&self, element_pos: u64) -> Result<Proof<H>, Error> {
        self.range_proof(element_pos, element_pos)
    }

    /// Return an inclusion proof for the specified range of elements. The range is inclusive of
    /// both endpoints. Returns `ElementPruned` if the requested range is outside the range
    /// currently stored by this MMR.
    pub fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H>, Error> {
        if start_element_pos != 0 && start_element_pos <= self.oldest_remembered_pos {
            return Err(ElementPruned(self.oldest_remembered_pos));
        }
        let mut hashes: Vec<H::Digest> = Vec::new();
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
                hashes.push(self.nodes[(item.0 - self.oldest_remembered_pos) as usize].clone());
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
                .map(|(_, pos)| self.nodes[(*pos - self.oldest_remembered_pos) as usize].clone()),
        );
        Ok(Proof {
            size: self.size(),
            hashes,
        })
    }

    /// Returns the position of the oldest element that must be retained by this MMR in order to
    /// preserve its ability to generate proofs for new elements. This is the position of the
    /// right-most leaf in the left-most peak. For the example tree in mod.rs, this would be node
    /// 11.
    pub fn oldest_required_element(&self) -> u64 {
        match self.peak_iterator().next() {
            None => {
                // Degenerate case, only happens when MMR is empty.
                0
            }
            Some((pos, height)) => {
                // Rightmost leaf position in a tree is the position of its peak minus its height.
                pos - height as u64
            }
        }
    }

    /// Removes all nodes up to but not including that with the given position from the MMR. Returns
    /// `InvalidElementPosition` error if removing the nodes would break the ability to generate
    /// proofs for new elements. After forgetting, you will only be able to generate proofs for
    /// (ranges of) nodes non-inclusively following the given node.
    pub fn forget(&mut self, oldest_to_remember_pos: u64) -> Result<(), Error> {
        if oldest_to_remember_pos <= self.oldest_remembered_pos {
            return Ok(());
        }
        let oldest_required_pos = self.oldest_required_element();
        if oldest_to_remember_pos > oldest_required_pos {
            return Err(InvalidElementPosition);
        }
        self.forget_to_pos(oldest_to_remember_pos);
        Ok(())
    }

    /// Forget as many nodes as possible without breaking proof generation going forward, returning
    /// the position of the oldest remembered node after forgetting, or 0 if nothing was forgotten.
    pub fn forget_max(&mut self) -> u64 {
        let top_peak = self.peak_iterator().next();
        match top_peak {
            None => 0,
            Some((pos, height)) => {
                self.forget_to_pos(pos - height as u64);
                self.oldest_remembered_pos
            }
        }
    }

    fn forget_to_pos(&mut self, pos: u64) {
        let nodes_to_remove = (pos - self.oldest_remembered_pos) as usize;
        self.oldest_remembered_pos = pos;
        self.nodes = self.nodes[nodes_to_remove..self.nodes.len()].to_vec();
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::hasher::Hasher;
    use crate::mmr::iterator::nodes_needing_parents;
    use crate::mmr::mem::Mmr;
    use commonware_cryptography::{Hasher as CHasher, Sha256};

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_add_eleven_values() {
        let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
        assert_eq!(
            mmr.peak_iterator().next(),
            None,
            "empty iterator should have no peaks"
        );
        assert_eq!(
            mmr.forget_max(),
            0,
            "forget_max on empty MMR should do nothing"
        );
        assert_eq!(
            mmr.oldest_required_element(),
            0,
            "oldest_required_element should return 0 on empty MMR"
        );
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&element));
            let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
            assert_ne!(peaks.len(), 0);
            assert!(peaks.len() <= mmr.size() as usize);
            let nodes_needing_parents = nodes_needing_parents(mmr.peak_iterator());
            assert!(nodes_needing_parents.len() <= peaks.len());
        }
        assert_eq!(mmr.oldest_remembered_node_pos(), 0);
        assert_eq!(mmr.size(), 19, "mmr not of expected size");
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
        let peak_hashes = [hash14, hash17, mmr.nodes[18]];
        let expected_root_hash = mmr_hasher.root_hash(19, peak_hashes.iter());
        assert_eq!(root_hash, expected_root_hash, "incorrect root hash");

        // forgetting tests
        assert_eq!(
            mmr.forget_max(),
            11,
            "forget_max should forget to right-most leaf of leftmost peak"
        );
        assert_eq!(mmr.oldest_remembered_node_pos(), 11);
        assert!(
            mmr.forget(12).is_err(),
            "forgetting too many nodes should fail"
        );
        assert!(
            mmr.forget(10).is_ok(),
            "forgetting already forgotten nodes should be ok"
        );
        let root_hash_after_forget = mmr.root_hash();
        assert_eq!(
            root_hash, root_hash_after_forget,
            "root hash changed after forgetting"
        );
        assert!(
            mmr.proof(11).is_err(),
            "attempts to prove elements at or before the oldest remaining should fail"
        );
        assert!(
            mmr.range_proof(10, 15).is_err(),
            "attempts to range_prove elements at or before the oldest remaining should fail"
        );
        assert!(
            mmr.range_proof(15, 18).is_ok(),
            "attempts to range_prove over elements following oldest remaining should succeed"
        );
    }
}
