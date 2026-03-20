//! Merkle tree over GF(2^128) for cryptographically authenticated memory
//!
//! Uses Rescue-Prime hash function with 128-bit field elements.
//! Provides 64-bit collision resistance (birthday bound on 128-bit field).

use commonware_commitment::field::{BinaryElem128, BinaryFieldElement};
use crate::rescue::{hash_leaf, hash_pair};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Merkle tree over GF(2^128)
#[derive(Debug, Clone)]
pub struct MerkleTree128 {
    /// Leaf values (memory words as u128)
    leaves: Vec<u128>,
    /// Internal nodes, level by level (bottom-up)
    nodes: Vec<Vec<BinaryElem128>>,
    /// Tree height = log2(num_leaves)
    height: usize,
    /// Root hash
    root: BinaryElem128,
}

/// Merkle proof for a single leaf
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof128 {
    /// Index of the leaf
    pub index: usize,
    /// Value at that leaf
    pub value: u128,
    /// Sibling hashes along the path to root
    pub siblings: Vec<BinaryElem128>,
    /// Expected root
    pub root: BinaryElem128,
}

impl MerkleTree128 {
    /// Create a new merkle tree from leaf values
    ///
    /// Number of leaves must be a power of 2.
    pub fn new(leaves: Vec<u128>) -> Result<Self, &'static str> {
        if leaves.is_empty() {
            return Err("cannot create empty tree");
        }
        if !leaves.len().is_power_of_two() {
            return Err("number of leaves must be power of 2");
        }

        let height = leaves.len().trailing_zeros() as usize;
        let mut tree = Self {
            leaves: leaves.clone(),
            nodes: Vec::new(),
            height,
            root: BinaryElem128::zero(),
        };
        tree.rebuild();
        Ok(tree)
    }

    /// Create tree with given size, all zeros
    pub fn with_size(size: usize) -> Result<Self, &'static str> {
        if !size.is_power_of_two() {
            return Err("size must be power of 2");
        }
        Self::new(vec![0u128; size])
    }

    /// Rebuild the entire tree from leaves
    fn rebuild(&mut self) {
        let mut current_level: Vec<BinaryElem128> = self.leaves
            .iter()
            .map(|&leaf| hash_leaf(BinaryElem128::from(leaf)))
            .collect();

        let mut all_levels = vec![current_level.clone()];

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = chunk.get(1).copied().unwrap_or(left);
                next_level.push(hash_pair(left, right));
            }
            current_level = next_level.clone();
            all_levels.push(next_level);
        }

        self.root = current_level[0];
        self.nodes = all_levels;
    }

    /// Get the root hash
    pub fn root(&self) -> BinaryElem128 {
        self.root
    }

    /// Read a leaf value
    pub fn read(&self, index: usize) -> Option<u128> {
        self.leaves.get(index).copied()
    }

    /// Update a leaf and recompute affected hashes (O(log n))
    pub fn write(&mut self, index: usize, value: u128) -> Result<(), &'static str> {
        if index >= self.leaves.len() {
            return Err("index out of bounds");
        }

        self.leaves[index] = value;
        self.nodes[0][index] = hash_leaf(BinaryElem128::from(value));

        let mut idx = index;
        for level in 1..self.nodes.len() {
            idx /= 2;
            let left_idx = idx * 2;
            let right_idx = left_idx + 1;
            let left = self.nodes[level - 1][left_idx];
            let right = self.nodes[level - 1]
                .get(right_idx)
                .copied()
                .unwrap_or(left);
            self.nodes[level][idx] = hash_pair(left, right);
        }

        self.root = self.nodes[self.nodes.len() - 1][0];
        Ok(())
    }

    /// Generate a merkle proof for a leaf
    pub fn prove(&self, index: usize) -> Result<MerkleProof128, &'static str> {
        if index >= self.leaves.len() {
            return Err("index out of bounds");
        }

        let value = self.leaves[index];
        let mut siblings = Vec::with_capacity(self.height);
        let mut idx = index;

        for level in 0..self.height {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = self.nodes[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(self.nodes[level][idx]);
            siblings.push(sibling);
            idx /= 2;
        }

        Ok(MerkleProof128 {
            index,
            value,
            siblings,
            root: self.root,
        })
    }

    /// Verify a merkle proof
    pub fn verify_proof(proof: &MerkleProof128) -> bool {
        let mut current = hash_leaf(BinaryElem128::from(proof.value));
        let mut idx = proof.index;

        for sibling in &proof.siblings {
            if idx % 2 == 0 {
                current = hash_pair(current, *sibling);
            } else {
                current = hash_pair(*sibling, current);
            }
            idx /= 2;
        }

        current == proof.root
    }
}

impl MerkleProof128 {
    /// Verify this proof
    pub fn verify(&self) -> bool {
        MerkleTree128::verify_proof(self)
    }

    /// Recompute the root from this proof (for constraint generation)
    pub fn compute_root(&self) -> BinaryElem128 {
        let mut current = hash_leaf(BinaryElem128::from(self.value));
        let mut idx = self.index;

        for sibling in &self.siblings {
            if idx % 2 == 0 {
                current = hash_pair(current, *sibling);
            } else {
                current = hash_pair(*sibling, current);
            }
            idx /= 2;
        }

        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tree() {
        let leaves = vec![1u128, 2, 3, 4];
        let tree = MerkleTree128::new(leaves).unwrap();
        assert_eq!(tree.height, 2);
        assert_ne!(tree.root(), BinaryElem128::zero());
    }

    #[test]
    fn test_proof_valid() {
        let leaves = vec![10u128, 20, 30, 40, 50, 60, 70, 80];
        let tree = MerkleTree128::new(leaves).unwrap();
        for i in 0..8 {
            let proof = tree.prove(i).unwrap();
            assert!(proof.verify(), "proof failed for index {}", i);
            assert_eq!(proof.root, tree.root());
        }
    }

    #[test]
    fn test_proof_wrong_value() {
        let leaves = vec![100u128, 200, 300, 400];
        let tree = MerkleTree128::new(leaves).unwrap();
        let mut proof = tree.prove(2).unwrap();
        proof.value = 999;
        assert!(!proof.verify(), "tampered proof should not verify");
    }

    #[test]
    fn test_write_updates_root() {
        let leaves = vec![0u128; 4];
        let mut tree = MerkleTree128::new(leaves).unwrap();
        let root_before = tree.root();
        tree.write(2, 42).unwrap();
        assert_ne!(tree.root(), root_before);
        assert_eq!(tree.read(2), Some(42));
    }

    #[test]
    fn test_deterministic() {
        let leaves = vec![1u128, 2, 3, 4, 5, 6, 7, 8];
        let tree1 = MerkleTree128::new(leaves.clone()).unwrap();
        let tree2 = MerkleTree128::new(leaves).unwrap();
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_compute_root_matches() {
        let leaves = vec![1u128, 2, 3, 4];
        let tree = MerkleTree128::new(leaves).unwrap();
        let proof = tree.prove(2).unwrap();
        let computed = proof.compute_root();
        assert_eq!(computed, tree.root());
    }
}
