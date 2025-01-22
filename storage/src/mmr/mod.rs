//! A Merkle Mountain Range (MMR) is an append-only data structure that allows for efficient
//! verification of the inclusion of an element, or some range of consecutive elements, in a list.
//!
//! # Terminology
//!
//! An MMR is a list of perfect binary trees of strictly decreasing height. The roots of these trees
//! are called the "peaks" of the MMR. Each "element" stored in the MMR is represented by some leaf
//! node in one of these perfect trees, storing a positioned hash of the element. Non-leaf nodes
//! store a positioned hash of their children.
//!
//! The "size" of an MMR is the total number of nodes summed over all trees.
//!
//! The nodes of the MMR are ordered by a post-order traversal of the MMR trees, starting from the
//! from tallest tree to shortest. The "position" of a node in the MMR is defined as the 0-based
//! index of the node in this ordering. This implies the positions of elements, which are always
//! leaves, may not be contiguous even if they were consecutively added.
//!
//! As the MMR is an append-only data structure, node positions never change and can be used as
//! stable identifiers.
//!
//! The "height" of a node is 0 for a leaf, 1 for the parent of 2 leaves, and so on.
//!
//! The "root hash" of an MMR is the result of hashing together the size of the MMR and the hashes
//! of every peak in decreasing order of height.
//!
//! # Examples
//!
//! (Borrowed from <https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/>): After adding 11
//! elements to an MMR, it will have 19 nodes total with 3 peaks corresponding to 3 perfect binary
//! trees as pictured below, with nodes identified by their positions:
//!
//! ```text
//!    Height
//!      3              14
//!                   /    \
//!                  /      \
//!                 /        \
//!                /          \
//!      2        6            13
//!             /   \        /    \
//!      1     2     5      9     12     17
//!           / \   / \    / \   /  \   /  \
//!      0   0   1 3   4  7   8 10  11 15  16 18
//! ```
//!
//! The root hash in this example is computed as:
//!
//! ```text
//!
//! Hash(19,
//!   Hash(14,                                                  // first peak
//!     Hash(6,
//!       Hash(2, Hash(0, element_0), Hash(1, element_1)),
//!       Hash(5, Hash(3, element_2), Hash(4, element_4))
//!     )
//!     Hash(13,
//!       Hash(9, Hash(7, element_0), Hash(8, element_8)),
//!       Hash(12, Hash(10, element_10), Hash(11, element_11))
//!     )
//!   )
//!   Hash(17, Hash(15, element_15), Hash(16, element_16))      // second peak
//!   Hash(18, element_18)                                      // third peak
//! )
//! ```

pub mod mem;

use commonware_cryptography::{Digest, Hasher as CHasher};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A Proof contains the information necessary for proving the inclusion of an element, or some
/// range of elements, in the MMR.
pub struct Proof {
    size: u64, // total # of nodes in the MMR
    hashes: Vec<Digest>,
}

/// Hasher decorator the MMR uses for computing leaf, node and root hashes.
struct Hasher<'a, H: CHasher> {
    hasher: &'a mut H,
}

impl<'a, H: CHasher> Hasher<'a, H> {
    fn new(hasher: &'a mut H) -> Self {
        Self { hasher }
    }

    /// Computes the hash for a leaf given its position and the element it represents.
    fn leaf_hash(&mut self, pos: u64, element: &Digest) -> Digest {
        self.update_with_pos(pos);
        self.update_with_hash(element);
        self.finalize_reset()
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &Digest, right_hash: &Digest) -> Digest {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize_reset()
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'b>(&mut self, pos: u64, peak_hashes: impl Iterator<Item = &'b Digest>) -> Digest {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize_reset()
    }

    fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }
    fn update_with_hash(&mut self, hash: &Digest) {
        self.hasher.update(hash);
    }
    fn finalize_reset(&mut self) -> Digest {
        self.hasher.finalize()
    }
}

/// Return true if `proof` proves that `element` appears at position `element_pos` within the MMR
/// with root hash `root_hash`.
pub fn verify_proof<H: CHasher>(
    proof: &Proof,
    element: &Digest,
    element_pos: u64,
    root_hash: &Digest,
    hasher: &mut H,
) -> bool {
    verify_range_proof(
        proof,
        &[element.clone()],
        element_pos,
        element_pos,
        root_hash,
        hasher,
    )
}

/// Return true if `proof` proves that the `elements` appear consecutively between positions
/// `start_element_pos` through `end_element_pos` (inclusive) within the MMR with root hash
/// `root_hash`.
pub fn verify_range_proof<H: CHasher>(
    proof: &Proof,
    elements: &[Digest],
    start_element_pos: u64,
    end_element_pos: u64,
    root_hash: &Digest,
    hasher: &mut H,
) -> bool {
    let mut proof_hashes_iter = proof.hashes.iter();
    let mut elements_iter = elements.iter();
    let mut siblings_iter = proof.hashes.iter().rev();
    let mut mmr_hasher = Hasher::<H>::new(hasher);

    // Include peak hashes only for trees that have no elements from the range, and keep track of
    // the starting and ending trees of those that do contain some.
    let mut peak_hashes: Vec<Digest> = Vec::new();
    let mut proof_hashes_used = 0;
    for (peak_pos, height) in PeakIterator::new(proof.size) {
        let leftmost_pos = peak_pos + 2 - (1 << (height + 1));
        if peak_pos >= start_element_pos && leftmost_pos <= end_element_pos {
            match peak_hash_from_range(
                peak_pos,
                1 << height,
                start_element_pos,
                end_element_pos,
                &mut elements_iter,
                &mut siblings_iter,
                &mut mmr_hasher,
            ) {
                Ok(peak_hash) => peak_hashes.push(peak_hash),
                Err(_) => return false, // missing hashes
            }
        } else if let Some(hash) = proof_hashes_iter.next() {
            proof_hashes_used += 1;
            peak_hashes.push(hash.clone());
        } else {
            return false;
        }
    }

    if elements_iter.next().is_some() {
        return false; // some elements were not used in the proof
    }
    let next_sibling = siblings_iter.next();
    if (proof_hashes_used == 0 && next_sibling.is_some())
        || (next_sibling.is_some() && *next_sibling.unwrap() != proof.hashes[proof_hashes_used - 1])
    {
        // some proof data was not used during verification, so we must return false to prevent
        // proof malleability attacks.
        return false;
    }
    *root_hash == mmr_hasher.root_hash(proof.size, peak_hashes.iter())
}

fn peak_hash_from_range<'a, H: CHasher>(
    node_pos: u64,      // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
    elements: &mut impl Iterator<Item = &'a Digest>,
    sibling_hashes: &mut impl Iterator<Item = &'a Digest>,
    hasher: &mut Hasher<H>,
) -> Result<Digest, ()> {
    assert_ne!(two_h, 0);
    if two_h == 1 {
        // we are at a leaf
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_hash(node_pos, element)),
            None => return Err(()),
        }
    }

    let left_pos = node_pos - two_h;
    let mut left_hash: Option<Digest> = None;
    let right_pos = left_pos + two_h - 1;
    let mut right_hash: Option<Digest> = None;

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
            Ok(h) => left_hash = Some(h.clone()),
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
            Ok(h) => right_hash = Some(h.clone()),
            Err(_) => return Err(()),
        }
    }

    if left_hash.is_none() {
        match sibling_hashes.next() {
            Some(hash) => left_hash = Some(hash.clone()),
            None => return Err(()),
        }
    }
    if right_hash.is_none() {
        match sibling_hashes.next() {
            Some(hash) => right_hash = Some(hash.clone()),
            None => return Err(()),
        }
    }
    Ok(hasher.node_hash(node_pos, &left_hash.unwrap(), &right_hash.unwrap()))
}

/// A PeakIterator returns a (position, height) tuple for each peak in an MMR with the given size,
/// in decreasing order of height.
///
/// For the example MMR depicted at the top of this file, the PeakIterator would yield:
/// ```text
/// [(14, 3), (17, 1), (18, 0)]
/// ```
#[derive(Default)]
struct PeakIterator {
    size: u64,     // number of nodes in the MMR at the point the iterator was initialized
    node_pos: u64, // position of the current node
    two_h: u64,    // 2^(height+1) of the current node
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of a MMR with the given number of nodes.
    fn new(size: u64) -> PeakIterator {
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
fn nodes_needing_parents(peak_iterator: PeakIterator) -> Vec<u64> {
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
struct PathIterator {
    leaf_pos: u64, // position of the leaf node in the path
    node_pos: u64, // current node position in the path from peak to leaf
    two_h: u64,    // 2^height of the current node
}

impl PathIterator {
    /// Return a PathIterator over the siblings of nodes along the path from peak to leaf in the
    /// perfect binary tree with peak `peak_pos` and having height `height`, not including the peak
    /// itself.
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

#[cfg(test)]
mod tests {
    use commonware_cryptography::{Digest, Hasher as CHasher, Sha256};

    #[test]
    fn test_leaf_hash_sha256() {
        test_leaf_hash::<Sha256>();
    }

    #[test]
    fn test_node_hash_sha256() {
        test_node_hash::<Sha256>();
    }

    #[test]
    fn test_root_hash_sha256() {
        test_root_hash::<Sha256>();
    }

    fn test_leaf_hash<H: CHasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);

        let out = mmr_hasher.leaf_hash(0, &hash1);
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "hash should be non-zero"
        );

        let mut out2 = mmr_hasher.leaf_hash(0, &hash1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_hash(1, &hash1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_hash(0, &hash2);
        assert_ne!(out, out2, "hash should change with different input hash");
    }

    fn test_node_hash<H: CHasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use

        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);
        let hash3 = Digest::from(vec![3u8; H::len()]);

        let out = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "hash should be non-zero"
        );

        let mut out2 = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.node_hash(1, &hash1, &hash2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.node_hash(0, &hash3, &hash2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash1, &hash3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash2, &hash1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    fn test_root_hash<H: CHasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);
        let hash3 = Digest::from(vec![3u8; H::len()]);
        let hash4 = Digest::from(vec![4u8; H::len()]);

        let empty_vec: Vec<Digest> = Vec::new();
        let empty_out = mmr_hasher.root_hash(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            Digest::from(vec![0u8; H::len()]),
            "root hash of empty MMR should be non-zero"
        );

        let vec = [hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];
        let out = mmr_hasher.root_hash(10, vec.iter());
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "root hash should be non-zero"
        );
        assert_ne!(out, empty_out, "root hash should differ from empty MMR");

        let mut out2 = mmr_hasher.root_hash(10, vec.iter());
        assert_eq!(out, out2, "root hash should be computed consistently");

        out2 = mmr_hasher.root_hash(11, vec.iter());
        assert_ne!(out, out2, "root hash should change with different position");

        let vec2 = [hash1.clone(), hash2.clone(), hash4.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec2.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different hash order"
        );

        let vec3 = [hash1.clone(), hash2.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec3.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different number of hashes"
        );
    }
}
