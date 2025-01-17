//! A bare-bones MMR structure without pruning and where all nodes are hashes & maintained in
//! memory.
//!
//! TERMINOLOGY:
//!
//! An MMR is a list of perfect binary trees of strictly decreasing height, ordered from left to
//! right. The roots of these trees are called the "peaks" of the MMR.
//!
//! Each "element" stored in the MMR is represented by some leaf node in one of these perfect trees.
//!
//! The "position" of a node in the MMR is defined as the 0-based index of the node in the
//! underlying nodes vector. As the MMR is an append-only data structure, node positions never
//! change and can be used as stable identifiers.
//!
//! The "height" of a node is 0 for a leaf, 1 for the parent of 2 leaves, and so on.
//!
//! The "root hash" of an MMR is the result of hashing together the size of the MMR and the hashes
//! of every peak in decreasing order of height.

use crate::mmr::{Hash, Hasher, Proof};

/// Implementation of `InMemoryMMR`.
pub struct InMemoryMMR<const N: usize, H: Hasher<N>> {
    hasher: H,
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from tallest tree to shortest.
    nodes: Vec<Hash<N>>,
}

/// A PeakIterator returns a (position, height) tuple for each peak in the MMR, in decreasing order
/// of height. The iterator will only return the peaks that existed at the time of its
/// initialization if new elements are added to the MMR between iterations.
#[derive(Default)]
struct PeakIterator {
    sz: u64,       // number of nodes in the MMR at the point the iterator was initialized
    node_pos: u64, // position of the current node
    two_h: u64,    // 2^(height+1) of the current node
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of a MMR with the given number of nodes.
    fn new(sz: u64) -> PeakIterator {
        if sz == 0 {
            return PeakIterator::default();
        }
        // Compute the position at which to start the search for peaks. This starting position will not
        // be in the MMR unless it happens to be a single perfect binary tree, but that's OK as we will
        // descend leftward until we find the first peak.
        let start = u64::MAX >> sz.leading_zeros();
        let two_h = 1 << start.trailing_ones();
        PeakIterator {
            sz,
            node_pos: start - 1,
            two_h,
        }
    }
}

impl Iterator for PeakIterator {
    type Item = (u64, u32); // (peak, height)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.node_pos < self.sz {
                // found a peak
                let peak_item = (self.node_pos, self.two_h.trailing_zeros() - 1);
                // move to the right sibling
                self.node_pos += self.two_h - 1;
                assert!(self.node_pos >= self.sz); // sibling shouldn't be in the MMR if MMR is valid
                return Some(peak_item);
            }
            // descend to the left child
            self.two_h >>= 1;
            self.node_pos -= self.two_h;
        }
        None
    }
}

/// A PathIterator returns a (parent_pos, sibling_pos) tuple for the sibling of each node along the
/// path from a given perfect binary tree peak to a designated leaf, not including the peak itself.
///
/// For example, for the tree below, the path from the peak to leaf node 3 would produce:
/// [(6, 2), (5, 4)]
///          6
///        /   \
///       2     5
///      / \   / \
///     0   1 3   4
#[derive(Debug)]
struct PathIterator {
    leaf_pos: u64, // position of the leaf node in the path
    node_pos: u64, // current node position in the path from peak to leaf
    two_h: u64,    // 2^height of the current node
}

impl PathIterator {
    /// Return a PathIterator over the siblings of nodes along the path from peak to leaf in the perfect
    /// binary tree with peak `peak_pos` and having height `height`, not including the peak itself.
    fn new(leaf_pos: u64, peak_pos: u64, height: u32) -> PathIterator {
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

/// Return true if `proof` proves that `element` appears at position `element_pos` within the MMR
/// with root hash `root_hash`.
pub fn verify_proof<const N: usize, H: Hasher<N>>(
    proof: &Proof<N>,
    element: &Hash<N>,
    element_pos: u64,
    root_hash: &Hash<N>,
    hasher: &mut H,
) -> bool {
    let mut peak_hashes = Vec::new();
    let mut proof_hashes = proof.hashes.iter();
    let mut missing_peak_height = u32::MAX;

    for (peak_pos, height) in PeakIterator::new(proof.sz) {
        if missing_peak_height == u32::MAX && peak_pos >= element_pos {
            // Found the peak of the tree whose hash we must reconstruct.
            missing_peak_height = height;
            let mut hashes = proof.hashes.iter().rev();
            match peak_hash_from_element(
                peak_pos,
                height,
                element,
                element_pos,
                &mut hashes,
                hasher,
            ) {
                Ok(peak_hash) => peak_hashes.push(peak_hash),
                Err(_) => return false, // missing proof hashes
            }
        } else if let Some(peak_hash) = proof_hashes.next() {
            peak_hashes.push(*peak_hash);
        } else {
            return false; // invalid number of proof hashes
        }
    }
    // To prevent proof malleability, verify that every proof hash must have been used as input.
    if proof.hashes.len() != peak_hashes.len() - 1 + (missing_peak_height as usize) {
        return false;
    }
    *root_hash == hasher.root_hash(proof.sz, peak_hashes.iter())
}

/// Computes the peak hash of the perfect tree with peak `peak_pos` from one of its elements and its
/// sibling hashes along the path from leaf to peak, returning the result unless some hashes were
/// missing.
fn peak_hash_from_element<'a, const N: usize, H: Hasher<N>>(
    peak_pos: u64,
    height: u32,
    element: &Hash<N>,
    element_pos: u64,
    sibling_hashes: &mut impl Iterator<Item = &'a Hash<N>>,
    hasher: &mut H,
) -> Result<Hash<N>, ()> {
    let mut hash = hasher.leaf_hash(element_pos, element);
    let path_vec: Vec<(u64, u64)> =
        PathIterator::new(element_pos, peak_pos, height).collect::<Vec<_>>();
    let mut two_h = 2;

    for (parent_pos, pos) in path_vec.into_iter().rev() {
        let sibling_hash = sibling_hashes.next().ok_or(())?;
        hash = if parent_pos == pos + 1 {
            hasher.node_hash(pos + 1, &hash, sibling_hash)
        } else {
            hasher.node_hash(pos + two_h, sibling_hash, &hash)
        };
        two_h <<= 1;
    }
    Ok(hash)
}

/// Return true if `proof` proves that the `elements` appear consecutively at positions
/// `start_element_pos` through `end_element_pos` (inclusive) within the MMR with root hash
/// `root_hash`.
pub fn verify_range_proof<const N: usize, H: Hasher<N>>(
    proof: &Proof<N>,
    elements: &[Hash<N>],
    start_element_pos: u64,
    end_element_pos: u64,
    root_hash: &Hash<N>,
    hasher: &mut H,
) -> bool {
    let mut proof_hashes_iter = proof.hashes.iter();
    let mut elements_iter = elements.iter();
    let mut siblings_iter = proof.hashes.iter().rev();

    // Include peak hashes only for trees that have no elements from the range, and keep track
    // of the starting and ending trees of those that do contain some.
    let mut peak_hashes: Vec<Hash<N>> = Vec::new();
    for (peak_pos, height) in PeakIterator::new(proof.sz) {
        let leftmost_pos = peak_pos + 2 - (1 << (height + 1));
        if peak_pos >= start_element_pos && leftmost_pos <= end_element_pos {
            match peak_hash_from_range(
                peak_pos,
                1 << height,
                start_element_pos,
                end_element_pos,
                &mut elements_iter,
                &mut siblings_iter,
                hasher,
            ) {
                Ok(peak_hash) => peak_hashes.push(peak_hash),
                Err(_) => return false, // missing hashes
            }
        } else if let Some(hash) = proof_hashes_iter.next() {
            peak_hashes.push(*hash);
        } else {
            return false;
        }
    }
    // TODO: eliminate any potential for proof malleability
    *root_hash == hasher.root_hash(proof.sz, peak_hashes.iter())
}

fn peak_hash_from_range<'a, const N: usize, H: Hasher<N>>(
    node_pos: u64,      // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
    elements: &mut impl Iterator<Item = &'a Hash<N>>,
    sibling_hashes: &mut impl Iterator<Item = &'a Hash<N>>,
    hasher: &mut H,
) -> Result<Hash<N>, ()> {
    assert_ne!(two_h, 0);
    if two_h == 1 {
        // we are at a leaf
        assert!(node_pos >= leftmost_pos);
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_hash(node_pos, element)),
            None => return Err(()),
        }
    }

    let left_pos = node_pos - two_h;
    let mut left_hash: Option<Hash<N>> = None;
    let right_pos = left_pos + two_h - 1;
    let mut right_hash: Option<Hash<N>> = None;

    if left_pos >= leftmost_pos {
        // Descend left
        match peak_hash_from_range(
            left_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_hashes,
            hasher,
        ) {
            Ok(h) => left_hash = Some(h),
            Err(_) => return Err(()),
        }
    }
    if left_pos < rightmost_pos {
        // Descend right
        match peak_hash_from_range(
            right_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_hashes,
            hasher,
        ) {
            Ok(h) => right_hash = Some(h),
            Err(_) => return Err(()),
        }
    }

    if left_hash.is_none() {
        match sibling_hashes.next() {
            Some(hash) => left_hash = Some(*hash),
            None => return Err(()),
        }
    }
    if right_hash.is_none() {
        match sibling_hashes.next() {
            Some(hash) => right_hash = Some(*hash),
            None => return Err(()),
        }
    }
    Ok(hasher.node_hash(node_pos, &left_hash.unwrap(), &right_hash.unwrap()))
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
        PeakIterator::new(self.nodes.len() as u64)
    }

    /// Returns the set of peaks that will require a new parent after adding the next leaf to the
    /// MMR. This set is non-empty only if there is a height-0 (leaf) peak in the MMR. The result
    /// will contain this leaf peak plus the other MMR peaks with contiguously increasing height.
    /// Nodes in the result are ordered by decreasing height.
    fn nodes_needing_parents(&self) -> Vec<u64> {
        let mut peaks = Vec::new();
        let mut last_height = u32::MAX;

        for (peak_pos, height) in self.peak_iterator() {
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

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, element: &Hash<N>) -> u64 {
        let peaks = self.nodes_needing_parents();
        let element_pos = self.nodes.len() as u64;

        // Insert the element into the MMR as a leaf.
        let mut hash = self.hasher.leaf_hash(element_pos, element);
        self.nodes.push(hash);

        // Compute the new parent nodes, if any, and insert them into the MMR.
        for sibling_pos in peaks.into_iter().rev() {
            let parent_pos = self.nodes.len() as u64;
            hash = self
                .hasher
                .node_hash(parent_pos, &self.nodes[sibling_pos as usize], &hash);
            self.nodes.push(hash);
        }
        element_pos
    }

    /// Computes the root hash of the MMR.
    pub fn root_hash(&mut self) -> Hash<N> {
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| &self.nodes[peak_pos as usize]);
        self.hasher.root_hash(self.nodes.len() as u64, peaks)
    }

    /// Return an inclusion proof for the specified element that consists of the size of the MMR and
    /// a vector of hashes. The proof vector contains: (1) the peak hashes other than the peak of
    /// the perfect tree containing the element, followed by: (2) the nodes in the remaining perfect
    /// tree necessary for reconstructing its peak hash from the specified element. Both segments
    /// are ordered by decreasing height.
    pub fn proof(&self, element_pos: u64) -> Proof<N> {
        let mut hashes: Vec<Hash<N>> = Vec::new();
        // tree_with_leaf will hold the peak_pos and height of the perfect tree containing the leaf
        let mut tree_with_leaf = (u64::MAX, 0);

        // Include all peak hashes except for that corresponding to the tree with the leaf.
        for item in self.peak_iterator() {
            if tree_with_leaf.0 == u64::MAX && item.0 >= element_pos {
                tree_with_leaf = item;
            } else {
                hashes.push(self.nodes[item.0 as usize]);
            }
        }

        // Add sibling hashes of nodes along the path from peak to leaf in the tree with the leaf.
        let path_iter = PathIterator::new(element_pos, tree_with_leaf.0, tree_with_leaf.1);
        hashes.extend(path_iter.map(|(_, pos)| self.nodes[pos as usize]));
        Proof {
            sz: self.nodes.len() as u64,
            hashes,
        }
    }

    // Return an inclusion proof for the specified range of elements. The range is inclusive of
    // both endpoints.
    pub fn range_proof(&self, start_element_pos: u64, end_element_pos: u64) -> Proof<N> {
        let mut hashes: Vec<Hash<N>> = Vec::new();
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
                hashes.push(self.nodes[item.0 as usize]);
            }
        }
        assert!(start_tree_with_element.0 != u64::MAX);
        assert!(end_tree_with_element.0 != u64::MAX);

        let left_path_iter = PathIterator::new(
            start_element_pos,
            start_tree_with_element.0,
            start_tree_with_element.1,
        );
        let right_path_iter = PathIterator::new(
            end_element_pos,
            end_tree_with_element.0,
            end_tree_with_element.1,
        );

        let mut siblings = Vec::<(u64, u64)>::new();
        siblings.extend(right_path_iter.filter(|(parent_pos, pos)| *parent_pos == *pos + 1));
        siblings.extend(left_path_iter.filter(|(parent_pos, pos)| *parent_pos != *pos + 1));
        if start_tree_with_element.0 == end_tree_with_element.0 {
            siblings.sort_by(|a, b| b.0.cmp(&a.0));
        }

        hashes.extend(siblings.iter().map(|(_, pos)| self.nodes[*pos as usize]));

        Proof {
            sz: self.nodes.len() as u64,
            hashes,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::{
        mem::InMemoryMMR, verify_proof, verify_range_proof, Hash, Hasher, Sha256Hasher,
    };

    #[test]
    /// Test MMR building by consecutively adding 11 equal elements to a new MMR. The resulting MMR
    /// should have 19 nodes total with 3 peaks corresponding to 3 perfect binary trees exactly as
    /// pictured in the MMR example here:
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
        assert_eq!(
            mmr.peak_iterator().next(),
            None,
            "empty iterator should have no peaks"
        );

        let element: Hash<32> = Hash(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&element));
            let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
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
        let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![(14, 3), (17, 1), (18, 0)],
            "mmr peaks not as expected"
        );

        // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
        // highest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
        let peaks_needing_parents = mmr.nodes_needing_parents();
        assert_eq!(
            peaks_needing_parents,
            vec![17, 18],
            "mmr nodes needing parents not as expected"
        );

        // verify leaf hashes
        let mut hasher = Sha256Hasher::default();
        for leaf in leaves.iter().by_ref() {
            let hash = hasher.leaf_hash(*leaf, &element);
            assert_eq!(mmr.nodes[*leaf as usize], hash);
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
        let peak_hashes = [hash14, hash17, mmr.nodes[18]];
        let expected_root_hash = hasher.root_hash(19, peak_hashes.iter());
        assert_eq!(root_hash, expected_root_hash, "incorrect root hash");

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in leaves.iter().by_ref() {
            let proof = mmr.proof(*leaf);
            assert!(
                verify_proof::<32, Sha256Hasher>(&proof, &element, *leaf, &root_hash, &mut hasher),
                "valid proof should verify successfully"
            );
            let range_proof = mmr.range_proof(*leaf, *leaf);
            assert_eq!(
                proof, range_proof,
                "single element range proof should be identical to single element proof"
            );
            assert!(
                verify_range_proof::<32, Sha256Hasher>(
                    &range_proof,
                    &[element],
                    *leaf,
                    *leaf,
                    &root_hash,
                    &mut hasher
                ),
                "valid proof should verify successfully with verify_range_proof"
            );
        }

        // confirm mangling the proof or proof args results in failed validation
        const POS: u64 = 18;
        let proof = mmr.proof(POS);
        assert!(
            verify_proof::<32, Sha256Hasher>(&proof, &element, POS, &root_hash, &mut hasher),
            "proof verification should be successful"
        );
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof, &element, POS + 1, &root_hash, &mut hasher),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !verify_proof::<32, Sha256Hasher>(
                &proof,
                &Hash([0u8; 32]),
                POS,
                &root_hash,
                &mut hasher
            ),
            "proof verification should fail with mangled leaf element"
        );
        let root_hash2 = Hash([0u8; 32]);
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof, &element, POS, &root_hash2, &mut hasher),
            "proof verification should fail with mangled root_hash"
        );
        let mut proof2 = proof.clone();
        proof2.hashes[0] = Hash([0u8; 32]);
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof2, &element, POS, &root_hash, &mut hasher),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.sz = 10;
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof2, &element, POS, &root_hash, &mut hasher),
            "proof verification should fail with incorrect size"
        );
        proof2 = proof.clone();
        proof2.hashes.push(Hash([0u8; 32]));
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof2, &element, POS, &root_hash, &mut hasher),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.hashes.is_empty() {
            proof2.hashes.pop();
            assert!(
                !verify_proof::<32, Sha256Hasher>(&proof2, &element, 7, &root_hash, &mut hasher),
                "proof verification should fail with missing hashes"
            );
        }
        proof2 = proof.clone();
        proof2.hashes.clear();
        proof2
            .hashes
            .extend(&mut proof.hashes[0..peak_hashes.len() - 1].iter());
        // sneak in an extra hash that won't be used in the computation and make sure it's detected
        proof2.hashes.push(Hash([0u8; 32]));
        proof2
            .hashes
            .extend(proof.hashes[peak_hashes.len() - 1..].iter());
        assert!(
            !verify_proof::<32, Sha256Hasher>(&proof2, &element, POS, &root_hash, &mut hasher),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );

        // test range proofs over all possible ranges of at least two elements
        let mut outer_iter = leaves.iter();
        while let Some(leaf1) = outer_iter.next() {
            let inner_iter = outer_iter.clone();
            for leaf2 in inner_iter {
                let elements = vec![element; leaves.len()];
                let range_proof = mmr.range_proof(*leaf1, *leaf2);
                assert!(
                    verify_range_proof::<32, Sha256Hasher>(
                        &range_proof,
                        &elements,
                        *leaf1,
                        *leaf2,
                        &root_hash,
                        &mut hasher,
                    ),
                    "valid range proof should verify successfully"
                );
            }
        }
    }
}
