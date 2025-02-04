//! A stateless Binary Merkle Tree.
//!
//! The tree is constructed level-by-level. Level 0 consists of the leaf nodes. At each higher
//! level, pairs of nodes are combined using the provided hasher. If a level contains an odd number
//! of nodes, the missing sibling is replaced with `H::Digest::default()`.
//!
//! For example, given three leaves A, B, and C, the tree is constructed as follows:
//!
//! ```text
//!     Level 2 (root):       [combine(combine(A,B),combine(C,DEFAULT))]
//!     Level 1:              [combine(A,B),combine(C,DEFAULT)]
//!     Level 0 (leaves):     [A,B,C]
//! ```
//!
//! A Merkle proof for a given leaf is generated by collecting the sibling at each level (from the leaf
//! up to the root). The proof can then be used to verify that the leaf is part of the tree.
//!
//! This data structure is often used to generate a root for a block digest (over included transactions).
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::binary::Tree;
//! use commonware_cryptography::{hash, Sha256, sha256::Digest};
//!
//! // Build tree
//! let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
//! let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
//! let mut hasher = Sha256::default();
//! let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
//! let root = tree.root();
//!
//! // Generate a proof for leaf at index 1.
//! let proof = tree.prove(0).unwrap();
//! assert!(proof.verify(&mut hasher, &digests[0], 0, &root));
//! ```

use bytes::{Buf, BufMut};
use commonware_cryptography::{Digest, Hasher};
use std::mem::size_of;

fn combine_root<H: Hasher>(
    hasher: &mut H,
    leaves: u32,
    left: &H::Digest,
    right: &H::Digest,
) -> H::Digest {
    hasher.update(&leaves.to_be_bytes());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// Combines two digests into a new digest.
fn combine_branches<H: Hasher>(hasher: &mut H, left: &H::Digest, right: &H::Digest) -> H::Digest {
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

fn combine_leaves<H: Hasher>(
    hasher: &mut H,
    left: &H::Digest,
    left_pos: u32,
    right: &H::Digest,
    right_pos: u32,
) -> H::Digest {
    hasher.update(&left_pos.to_be_bytes());
    hasher.update(left);
    hasher.update(&right_pos.to_be_bytes());
    hasher.update(right);
    hasher.finalize()
}

/// A stateless Binary Merkle Tree that computes a root over an arbitrary set
/// of [commonware_cryptography::Digest].
#[derive(Clone, Debug)]
pub struct Tree<H: Hasher> {
    /// Number of leaves in the tree.
    leaves: u32,

    /// Levels of the tree: level 0 contains the leaves, and each subsequent level
    /// contains the parent nodes computed from the previous level.
    ///
    /// The last level contains a single node: the root.
    levels: Vec<Vec<H::Digest>>,
}

impl<H: Hasher> Tree<H> {
    /// Builds a Merkle Tree from a slice of leaf digests.
    ///
    /// If `leaves` is empty, returns `None`.
    pub fn new(hasher: &mut H, leaves: Vec<H::Digest>) -> Option<Self> {
        // Ensure there are non-zero leaves.
        if leaves.is_empty() {
            return None;
        }

        // Level 0: the leaves.
        let leaves_len: u32 = leaves.len().try_into().ok()?;
        let mut levels = Vec::new();
        levels.push(leaves);

        // Build higher levels until we reach the root.
        let mut pos = 0u32;
        while levels.last().unwrap().len() > 1 {
            let current_level = levels.last().unwrap();
            let next_level_len = (current_level.len() + 1) / 2;
            let mut next_level = Vec::with_capacity(next_level_len);
            for chunk in current_level.chunks(2) {
                // Select the left and right children of the current chunk.
                let left = &chunk[0];
                let right = if chunk.len() == 2 {
                    &chunk[1]
                } else {
                    // If the chunk has an odd number of nodes, use a duplicate of the left child.
                    &chunk[0]
                };

                // Combine the children into a parent node based on their location in the tree.
                if levels.len() == 1 {
                    next_level.push(combine_leaves(hasher, left, pos, right, pos + 1));
                    pos += 2;
                } else if next_level_len != 1 {
                    next_level.push(combine_branches(hasher, left, right));
                } else {
                    next_level.push(combine_root(hasher, leaves_len, left, right));
                }
            }

            // Add the next level to the tree
            levels.push(next_level);
        }

        Some(Self {
            leaves: leaves_len,
            levels,
        })
    }

    /// Returns a reference to the Merkle root, if the tree is non-empty.
    pub fn root(&self) -> H::Digest {
        self.levels.last().unwrap().first().unwrap().clone()
    }

    /// Generates a Merkle proof for the leaf at `leaf_index`.
    ///
    /// The proof contains the sibling hash at each level needed to reconstruct the root.
    pub fn prove(&self, leaf_index: u32) -> Option<Proof<H>> {
        if leaf_index >= self.leaves {
            return None;
        }

        // For each level (except the root level) record the sibling.
        let mut proof_hashes = Vec::new();
        let mut index = leaf_index;
        for level in &self.levels {
            if level.len() == 1 {
                break; // Reached the root.
            }
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling_index = sibling_index as usize;
            let sibling = if sibling_index < level.len() {
                level[sibling_index].clone()
            } else {
                // Use a duplicate of the current node if no right child exists.
                level[index as usize].clone()
            };
            proof_hashes.push(sibling);
            index /= 2;
        }
        Some(Proof {
            leaves: self.leaves,
            hashes: proof_hashes,
        })
    }
}

/// A binary Merkle tree proof represented solely as a vector of sibling hashes.
#[derive(Clone, Debug)]
pub struct Proof<H: Hasher> {
    pub leaves: u32,

    /// The sibling hashes from the leaf up to the root, ordered from bottom (closest to leaf) to top.
    pub hashes: Vec<H::Digest>,
}

impl<H: Hasher> PartialEq for Proof<H>
where
    H::Digest: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.hashes == other.hashes
    }
}

impl<H: Hasher> Eq for Proof<H> where H::Digest: Eq {}

impl<H: Hasher> Proof<H> {
    /// Verifies that a given leaf (i.e. element digest) at position `leaf_index` is included in the Binary Merkle Tree
    /// with the expected root hash.
    ///
    /// The proof consists of sibling hashes stored from the leaf up to the root. At each level, if the current
    /// node is a left child (even index), the sibling is combined to the right; if it is a right child (odd index),
    /// the sibling is combined to the left.
    pub fn verify(
        &self,
        hasher: &mut H,
        element: &H::Digest,
        element_pos: u32,
        root_hash: &H::Digest,
    ) -> bool {
        // Ensure element isn't past allowed
        if element_pos >= self.leaves {
            return false;
        }

        // Compute the root hash by combining the element with each sibling hash in the proof.
        let mut computed = element.clone();
        let mut index = element_pos;
        let proof_len = self.hashes.len();
        for (i, sibling) in self.hashes.iter().enumerate() {
            if i == 0 {
                // First level: combine leaves with positional data.
                if index % 2 == 0 {
                    computed = combine_leaves(hasher, &computed, index, sibling, index + 1);
                } else {
                    computed = combine_leaves(hasher, sibling, index - 1, &computed, index);
                }
            } else if i == proof_len - 1 && proof_len > 1 {
                // Final level: use combine_root.
                if index % 2 == 0 {
                    computed = combine_root(hasher, self.leaves, &computed, sibling);
                } else {
                    computed = combine_root(hasher, self.leaves, sibling, &computed);
                }
            } else {
                // Intermediate levels: use combine_branches.
                if index % 2 == 0 {
                    computed = combine_branches(hasher, &computed, sibling);
                } else {
                    computed = combine_branches(hasher, sibling, &computed);
                }
            }
            index /= 2;
        }
        computed == *root_hash
    }

    /// Returns the maximum number of bytes any serialized proof may occupy.
    pub fn max_serialization_size() -> usize {
        size_of::<u32>() + u8::MAX as usize * size_of::<H::Digest>()
    }

    /// Serializes the proof as the concatenation of each hash.
    pub fn serialize(&self) -> Vec<u8> {
        // There should never be more than 255 hashes in a proof (would mean the Binary Merkle Tree
        // has more than 2^255 leaves).
        assert!(
            self.hashes.len() <= u8::MAX as usize,
            "too many hashes in proof"
        );

        // Serialize the proof as the concatenation of each hash.
        let bytes_len = size_of::<u32>() + self.hashes.len() * size_of::<H::Digest>();
        let mut bytes = Vec::with_capacity(bytes_len);
        bytes.put_u32(self.leaves);
        for hash in &self.hashes {
            bytes.extend_from_slice(hash.as_ref());
        }
        bytes
    }

    /// Deserializes a proof from its canonical serialized representation.
    pub fn deserialize(mut buf: &[u8]) -> Option<Self> {
        // Get leaves
        if buf.len() < size_of::<u32>() {
            return None;
        }
        let leaves = buf.get_u32();

        // Read hashes
        if buf.remaining() % size_of::<H::Digest>() != 0 {
            return None;
        }
        let num_hashes = buf.len() / size_of::<H::Digest>();
        if num_hashes > u8::MAX as usize {
            return None;
        }
        let mut hashes = Vec::with_capacity(num_hashes);
        for _ in 0..num_hashes {
            let hash = H::Digest::read_from(&mut buf).ok()?;
            hashes.push(hash);
        }
        Some(Self { leaves, hashes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        hash,
        sha256::{Digest, Sha256},
    };

    #[test]
    fn test_merkle_tree_single() {
        // Build tree
        let tx = b"tx";
        let leaf = hash(tx);
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, vec![leaf.clone()]).unwrap();

        // The root should equal the only leaf.
        assert_eq!(tree.root(), leaf);

        // Proof verification: a single-element tree proof verifies against the leaf itself.
        let proof = tree.prove(0).unwrap();
        assert!(proof.verify(&mut hasher, &leaf, 0, &leaf));
    }

    #[test]
    fn test_merkle_tree_multiple() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // For each leaf, generate and verify its proof.
        for (i, leaf) in digests.iter().enumerate() {
            let proof = tree.prove(i as u32).unwrap();
            let mut hasher = Sha256::default();
            assert!(
                proof.verify(&mut hasher, leaf, i as u32, &root),
                "Proof failed for leaf index {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_serialization() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a proof for leaf at index 1.
        let proof = tree.prove(1).unwrap();
        let serialized = proof.serialize();
        let deserialized = Proof::<Sha256>::deserialize(&serialized).unwrap();
        assert_eq!(proof, deserialized);

        // Verify the deserialized proof.
        deserialized.verify(&mut hasher, &digests[1], 1, &root);
    }

    #[test]
    fn test_invalid_proof_wrong_element() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let proof = tree.prove(2).unwrap();

        // Use a wrong element (e.g. hash of a different transaction).
        let wrong_leaf = hash(b"wrong_tx");
        let valid = proof.verify(&mut hasher, &wrong_leaf, 2, &root);
        assert!(!valid, "Verification should fail with a wrong leaf element");
    }

    #[test]
    fn test_invalid_proof_wrong_index() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.prove(1).unwrap();

        // Use an incorrect index (e.g. 2 instead of 1).
        let valid = proof.verify(&mut hasher, &digests[1], 2, &root);
        assert!(
            !valid,
            "Verification should fail with an incorrect element index"
        );
    }

    #[test]
    fn test_invalid_proof_wrong_root() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 0.
        let proof = tree.prove(0).unwrap();

        // Use a wrong root (hash of a different input).
        let wrong_root = hash(b"wrong_root");
        let valid = proof.verify(&mut hasher, &digests[0], 0, &wrong_root);
        assert!(
            !valid,
            "Verification should fail with an incorrect root hash"
        );
    }

    #[test]
    fn test_invalid_proof_serialization_truncated() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.prove(1).unwrap();
        let mut serialized = proof.serialize();

        // Truncate one byte.
        serialized.pop();
        let deserialized = Proof::<Sha256>::deserialize(&serialized);
        assert!(
            deserialized.is_none(),
            "Deserialization should fail with truncated data"
        );
    }

    #[test]
    fn test_invalid_proof_serialization_extra() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.prove(1).unwrap();
        let mut serialized = proof.serialize();

        // Append an extra byte.
        serialized.push(0u8);
        let deserialized = Proof::<Sha256>::deserialize(&serialized);
        assert!(
            deserialized.is_none(),
            "Deserialization should fail with extra data"
        );
    }

    #[test]
    fn test_invalid_proof_modified_hash() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let mut proof = tree.prove(2).unwrap();

        // Modify the first hash in the proof.
        proof.hashes[0] = hash(b"modified");
        let valid = proof.verify(&mut hasher, &digests[2], 2, &root);
        assert!(
            !valid,
            "Verification should fail if a proof hash is tampered with"
        );
    }

    #[test]
    fn test_odd_tree_duplicate_index_proof() {
        // Build a tree with an odd number of leaves.
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // The tree was built with 3 leaves; index 2 is the last valid index.
        let proof = tree.prove(2).unwrap();

        // Verification should succeed for the proper index 2.
        assert!(proof.verify(&mut hasher, &digests[2], 2, &root));

        // Should not be able to generate a proof for an out-of-range index (e.g. 3).
        assert!(tree.prove(3).is_none());

        // Attempting to verify using an out-of-range index (e.g. 3, which would correspond
        // to a duplicate leaf that doesn't actually exist) should fail.
        assert!(
            !proof.verify(&mut hasher, &digests[2], 3, &root),
            "Verification should fail for an invalid duplicate leaf index"
        );
    }
}
