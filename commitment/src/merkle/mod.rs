//! Merkle tree commitment with batched proofs.
//!
//! Implements the "Commit" service: given encoded matrix rows, produce
//! a compact Merkle root and respond to opening queries with batched
//! inclusion proofs.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use blake3::Hasher;
use bytemuck::Pod;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A 32-byte hash digest.
pub type Hash = [u8; 32];

/// A complete binary Merkle tree storing every layer.
pub struct CompleteMerkleTree {
    pub layers: Vec<Vec<Hash>>,
}

/// A Merkle root commitment.
#[derive(Clone, Debug)]
pub struct MerkleRoot {
    pub root: Option<Hash>,
}

impl MerkleRoot {
    /// Returns the size in bytes (0 if empty, 32 otherwise).
    pub fn size_of(&self) -> usize {
        self.root.map_or(0, |_| 32)
    }
}

/// A batched Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct BatchedMerkleProof {
    pub siblings: Vec<Hash>,
}

impl BatchedMerkleProof {
    /// Returns the total byte size of all sibling hashes.
    pub fn size_of(&self) -> usize {
        self.siblings.len() * 32
    }
}

/// Returns `true` if `n` is a power of two.
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

/// Hash a single leaf value using BLAKE3.
pub fn hash_leaf<T: Pod>(leaf: &T) -> Hash {
    let bytes = bytemuck::bytes_of(leaf);
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Hash two sibling nodes together using BLAKE3.
pub fn hash_siblings(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Build a complete Merkle tree from a slice of leaves.
///
/// # Panics
///
/// Panics if the number of leaves is not a power of 2.
pub fn build_merkle_tree<T: Pod + Send + Sync>(leaves: &[T]) -> CompleteMerkleTree {
    if leaves.is_empty() {
        return CompleteMerkleTree { layers: vec![] };
    }

    if !is_power_of_two(leaves.len()) {
        panic!("Number of leaves must be a power of 2");
    }

    let mut current_layer: Vec<Hash> = {
        #[cfg(feature = "parallel")]
        {
            if leaves.len() >= 64 {
                leaves.par_iter().map(|leaf| hash_leaf(leaf)).collect()
            } else {
                leaves.iter().map(|leaf| hash_leaf(leaf)).collect()
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            leaves.iter().map(|leaf| hash_leaf(leaf)).collect()
        }
    };

    let mut layers = vec![current_layer.clone()];

    while current_layer.len() > 1 {
        let next_layer: Vec<Hash> = {
            #[cfg(feature = "parallel")]
            {
                if current_layer.len() >= 64 {
                    current_layer
                        .par_chunks_exact(2)
                        .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                        .collect()
                } else {
                    current_layer
                        .chunks_exact(2)
                        .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                        .collect()
                }
            }
            #[cfg(not(feature = "parallel"))]
            {
                current_layer
                    .chunks_exact(2)
                    .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                    .collect()
            }
        };

        layers.push(next_layer.clone());
        current_layer = next_layer;
    }

    CompleteMerkleTree { layers }
}

/// Build a Merkle tree from pre-hashed leaf digests.
///
/// Skips the leaf hashing step — use this when leaves are already
/// hashed (e.g. by `hash_row`). Avoids double-hashing.
pub fn build_merkle_tree_from_hashes(leaf_hashes: &[Hash]) -> CompleteMerkleTree {
    if leaf_hashes.is_empty() {
        return CompleteMerkleTree { layers: vec![] };
    }

    if !is_power_of_two(leaf_hashes.len()) {
        panic!("Number of leaf hashes must be a power of 2");
    }

    let mut current_layer = leaf_hashes.to_vec();
    let mut layers = vec![current_layer.clone()];

    while current_layer.len() > 1 {
        let next_layer: Vec<Hash> = {
            #[cfg(feature = "parallel")]
            {
                if current_layer.len() >= 64 {
                    current_layer
                        .par_chunks_exact(2)
                        .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                        .collect()
                } else {
                    current_layer
                        .chunks_exact(2)
                        .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                        .collect()
                }
            }
            #[cfg(not(feature = "parallel"))]
            {
                current_layer
                    .chunks_exact(2)
                    .map(|chunk| hash_siblings(&chunk[0], &chunk[1]))
                    .collect()
            }
        };

        layers.push(next_layer.clone());
        current_layer = next_layer;
    }

    CompleteMerkleTree { layers }
}

/// Verify a batched Merkle proof against pre-hashed leaves.
///
/// Like [`verify`] but skips leaf hashing — the caller provides
/// the leaf digests directly.
pub fn verify_hashed(
    root: &MerkleRoot,
    proof: &BatchedMerkleProof,
    depth: usize,
    leaf_hashes: &[Hash],
    leaf_indices: &[usize],
) -> bool {
    let Some(expected_root) = root.root else {
        return false;
    };

    if depth == 0 {
        if leaf_hashes.len() == 1 && leaf_indices.len() == 1 && leaf_indices[0] == 0 {
            return leaf_hashes[0] == expected_root;
        }
        return false;
    }

    let mut layer = leaf_hashes.to_vec();
    let mut queries = leaf_indices.to_vec();
    let mut curr_cnt = queries.len();
    let mut proof_cnt = 0;

    for _ in 0..depth {
        let (next_cnt, next_proof_cnt) = verify_ith_layer(
            &mut layer,
            &mut queries,
            curr_cnt,
            &proof.siblings,
            proof_cnt,
        );
        curr_cnt = next_cnt;
        proof_cnt = next_proof_cnt;
    }

    curr_cnt == 1 && proof_cnt == proof.siblings.len() && layer[0] == expected_root
}

impl CompleteMerkleTree {
    /// Returns the root commitment of the tree.
    pub fn get_root(&self) -> MerkleRoot {
        MerkleRoot {
            root: self.layers.last().and_then(|layer| layer.first()).copied(),
        }
    }

    /// Returns the depth of the tree (number of layers minus one).
    pub fn get_depth(&self) -> usize {
        if self.layers.is_empty() {
            0
        } else {
            self.layers.len() - 1
        }
    }

    /// Generate a batched proof for the given query indices.
    pub fn prove(&self, queries: &[usize]) -> BatchedMerkleProof {
        prove_batch(self, queries)
    }

    /// Generate trace for a leaf at given index.
    ///
    /// Returns each opposite node from top to bottom as the tree is navigated
    /// to arrive at the leaf. This follows the graypaper specification for
    /// creating justifications of data inclusion.
    ///
    /// # Arguments
    /// * `index` - 0-based index of the leaf
    ///
    /// # Returns
    /// Vector of sibling hashes from root to leaf (top to bottom)
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range for the number of leaves.
    pub fn trace(&self, index: usize) -> Vec<Hash> {
        if self.layers.is_empty() {
            return vec![];
        }

        let num_leaves = self.layers[0].len();
        if index >= num_leaves {
            panic!(
                "Index {} out of range (tree has {} leaves)",
                index, num_leaves
            );
        }

        if num_leaves == 1 {
            return vec![];
        }

        let mut trace = Vec::new();
        let mut current_index = index;

        for layer_idx in 0..(self.layers.len() - 1) {
            let layer = &self.layers[layer_idx];

            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < layer.len() {
                trace.push(layer[sibling_index]);
            }

            current_index /= 2;
        }

        // Reverse to get top-to-bottom order (as per graypaper spec)
        trace.reverse();
        trace
    }
}

/// Verify a batched Merkle proof (0-based indices).
pub fn verify<T: Pod + Send + Sync>(
    root: &MerkleRoot,
    proof: &BatchedMerkleProof,
    depth: usize,
    leaves: &[T],
    leaf_indices: &[usize],
) -> bool {
    verify_batch(root, proof, depth, leaves, leaf_indices)
}

// ---------------------------------------------------------------------------
// Batch proof internals
// ---------------------------------------------------------------------------

/// Create a batched proof for multiple queries (0-based indices).
pub fn prove_batch(tree: &CompleteMerkleTree, queries: &[usize]) -> BatchedMerkleProof {
    let mut siblings = Vec::new();
    let depth = tree.get_depth();

    if depth == 0 || queries.is_empty() {
        return BatchedMerkleProof { siblings };
    }

    let mut queries_buff = queries.to_vec();
    let mut queries_cnt = queries_buff.len();

    for layer_idx in 0..depth {
        queries_cnt = ith_layer(
            &tree.layers[layer_idx],
            queries_cnt,
            &mut queries_buff,
            &mut siblings,
        );
    }

    BatchedMerkleProof { siblings }
}

/// Verify a batched proof (0-based indices).
pub fn verify_batch<T: Pod + Send + Sync>(
    root: &MerkleRoot,
    proof: &BatchedMerkleProof,
    depth: usize,
    leaves: &[T],
    leaf_indices: &[usize],
) -> bool {
    let Some(expected_root) = root.root else {
        return false;
    };

    if depth == 0 {
        if leaves.len() == 1 && leaf_indices.len() == 1 && leaf_indices[0] == 0 {
            let leaf_hash = hash_leaf(&leaves[0]);
            return leaf_hash == expected_root;
        }
        return false;
    }

    let mut layer: Vec<Hash> = {
        #[cfg(feature = "parallel")]
        {
            leaves.par_iter().map(hash_leaf).collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            leaves.iter().map(hash_leaf).collect()
        }
    };

    let mut queries = leaf_indices.to_vec();

    let mut curr_cnt = queries.len();
    let mut proof_cnt = 0;

    for _ in 0..depth {
        let (next_cnt, next_proof_cnt) = verify_ith_layer(
            &mut layer,
            &mut queries,
            curr_cnt,
            &proof.siblings,
            proof_cnt,
        );

        curr_cnt = next_cnt;
        proof_cnt = next_proof_cnt;
    }

    curr_cnt == 1 && proof_cnt == proof.siblings.len() && layer[0] == expected_root
}

fn ith_layer(
    current_layer: &[Hash],
    queries_len: usize,
    queries: &mut Vec<usize>,
    proof: &mut Vec<Hash>,
) -> usize {
    let mut next_queries_len = 0;
    let mut i = 0;

    while i < queries_len {
        let query = queries[i];
        let sibling = query ^ 1;

        queries[next_queries_len] = query >> 1;
        next_queries_len += 1;

        if i == queries_len - 1 {
            proof.push(current_layer[sibling]);
            break;
        }

        if !query.is_multiple_of(2) {
            proof.push(current_layer[sibling]);
            i += 1;
        } else if queries[i + 1] != sibling {
            proof.push(current_layer[sibling]);
            i += 1;
        } else {
            i += 2;
        }
    }

    next_queries_len
}

fn verify_ith_layer(
    layer: &mut Vec<Hash>,
    queries: &mut Vec<usize>,
    curr_cnt: usize,
    proof: &[Hash],
    mut proof_cnt: usize,
) -> (usize, usize) {
    let mut next_cnt = 0;
    let mut i = 0;

    while i < curr_cnt {
        let query = queries[i];
        let sibling = query ^ 1;

        queries[next_cnt] = query >> 1;
        next_cnt += 1;

        if i == curr_cnt - 1 {
            proof_cnt += 1;
            let pp = proof.get(proof_cnt - 1).copied().unwrap_or_default();
            layer[next_cnt - 1] = if !query.is_multiple_of(2) {
                hash_siblings(&pp, &layer[i])
            } else {
                hash_siblings(&layer[i], &pp)
            };
            break;
        }

        if !query.is_multiple_of(2) {
            proof_cnt += 1;
            let pp = proof.get(proof_cnt - 1).copied().unwrap_or_default();
            layer[next_cnt - 1] = hash_siblings(&pp, &layer[i]);
            i += 1;
        } else if queries[i + 1] != sibling {
            proof_cnt += 1;
            let pp = proof.get(proof_cnt - 1).copied().unwrap_or_default();
            layer[next_cnt - 1] = hash_siblings(&layer[i], &pp);
            i += 1;
        } else {
            layer[next_cnt - 1] = hash_siblings(&layer[i], &layer[i + 1]);
            i += 2;
        }
    }

    (next_cnt, proof_cnt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{seq::SliceRandom, thread_rng};

    #[test]
    fn test_empty_tree() {
        let leaves: Vec<u64> = vec![];
        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        assert!(root.root.is_none());
        assert_eq!(tree.get_depth(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let leaves = vec![42u64];
        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        assert!(root.root.is_some());
        assert_eq!(tree.get_depth(), 0);
    }

    #[test]
    fn test_merkle_tree_basic() {
        let leaves: Vec<[u16; 4]> = (0..16).map(|i| [i, i + 1, i + 2, i + 3]).collect();

        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        assert!(root.root.is_some());
        assert_eq!(tree.get_depth(), 4);
    }

    #[test]
    fn test_batch_proof() {
        let leaves: Vec<u64> = (0..16).collect();
        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        let queries = vec![0, 2, 6, 9];
        let proof = tree.prove(&queries);

        let queried_leaves: Vec<u64> = queries.iter().map(|&i| leaves[i]).collect();

        assert!(verify(
            &root,
            &proof,
            tree.get_depth(),
            &queried_leaves,
            &queries
        ));
    }

    #[test]
    fn test_invalid_proof() {
        let leaves: Vec<u64> = (0..16).collect();
        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        let queries = vec![0, 2, 6, 9];
        let proof = tree.prove(&queries);

        let wrong_leaves: Vec<u64> = vec![100, 200, 300, 400];

        assert!(!verify(
            &root,
            &proof,
            tree.get_depth(),
            &wrong_leaves,
            &queries
        ));
    }

    #[test]
    fn test_large_random_subset() {
        let n = 10;
        let num_leaves = 1 << n;
        let num_queries = 100;

        let leaves: Vec<[u16; 4]> = (0..num_leaves)
            .map(|_| {
                let val = rand::random::<u16>();
                [val; 4]
            })
            .collect();

        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root();

        let mut rng = thread_rng();
        let mut queries: Vec<usize> = (0..num_leaves).collect();
        queries.shuffle(&mut rng);
        queries.truncate(num_queries);
        queries.sort_unstable();

        let proof = tree.prove(&queries);

        let queried_leaves: Vec<[u16; 4]> = queries.iter().map(|&q| leaves[q]).collect();

        assert!(verify(
            &root,
            &proof,
            tree.get_depth(),
            &queried_leaves,
            &queries
        ));
    }

    #[test]
    #[should_panic(expected = "Number of leaves must be a power of 2")]
    fn test_non_power_of_two_panics() {
        let leaves: Vec<u64> = (0..15).collect();
        let _ = build_merkle_tree(&leaves);
    }

    #[test]
    fn test_debug_batch_proof() {
        let leaves: Vec<u64> = (0..16).collect();
        let tree = build_merkle_tree(&leaves);

        // Verify tree structure
        for (i, layer) in tree.layers.iter().enumerate() {
            assert!(
                !layer.is_empty(),
                "Layer {} should not be empty",
                i
            );
        }

        let queries = vec![0, 2, 6, 9];
        let proof = tree.prove(&queries);

        assert!(!proof.siblings.is_empty(), "Proof should have siblings");

        let queried_leaves: Vec<u64> = queries.iter().map(|&i| leaves[i]).collect();

        let is_valid = verify(
            &tree.get_root(),
            &proof,
            tree.get_depth(),
            &queried_leaves,
            &queries,
        );

        assert!(is_valid);
    }

    #[test]
    fn test_simple_proof() {
        let leaves: Vec<u64> = vec![0, 1, 2, 3];
        let tree = build_merkle_tree(&leaves);

        // Test single query first
        let queries = vec![0];
        let proof = tree.prove(&queries);

        let queried_leaves = vec![leaves[0]];

        let is_valid = verify(
            &tree.get_root(),
            &proof,
            tree.get_depth(),
            &queried_leaves,
            &queries,
        );

        assert!(is_valid, "Single query verification failed");

        // Test multiple queries
        let queries = vec![0, 2];
        let proof = tree.prove(&queries);

        let queried_leaves: Vec<u64> = queries.iter().map(|&i| leaves[i]).collect();

        let is_valid = verify(
            &tree.get_root(),
            &proof,
            tree.get_depth(),
            &queried_leaves,
            &queries,
        );

        assert!(is_valid, "Multiple query verification failed");
    }

    #[test]
    fn test_trace_basic() {
        let leaves: Vec<u64> = (0..8).collect();
        let tree = build_merkle_tree(&leaves);

        let trace = tree.trace(3);

        assert_eq!(trace.len(), tree.get_depth());

        for (i, hash) in trace.iter().enumerate() {
            assert_ne!(*hash, [0u8; 32], "Hash at level {} should not be zero", i);
        }
    }

    #[test]
    fn test_trace_verification() {
        let leaves: Vec<u64> = (0..8).collect();
        let tree = build_merkle_tree(&leaves);

        let index = 5;
        let trace = tree.trace(index);
        let leaf_hash = hash_leaf(&leaves[index]);

        let mut current_hash = leaf_hash;
        let mut current_index = index;

        for sibling_hash in trace.iter().rev() {
            if current_index % 2 == 0 {
                current_hash = hash_siblings(&current_hash, sibling_hash);
            } else {
                current_hash = hash_siblings(sibling_hash, &current_hash);
            }
            current_index /= 2;
        }

        assert_eq!(current_hash, tree.get_root().root.unwrap());
    }

    #[test]
    fn test_trace_all_leaves() {
        let leaves: Vec<u64> = (0..16).collect();
        let tree = build_merkle_tree(&leaves);
        let root = tree.get_root().root.unwrap();

        for index in 0..leaves.len() {
            let trace = tree.trace(index);
            let leaf_hash = hash_leaf(&leaves[index]);

            let mut current_hash = leaf_hash;
            let mut current_index = index;

            for sibling_hash in trace.iter().rev() {
                if current_index % 2 == 0 {
                    current_hash = hash_siblings(&current_hash, sibling_hash);
                } else {
                    current_hash = hash_siblings(sibling_hash, &current_hash);
                }
                current_index /= 2;
            }

            assert_eq!(
                current_hash, root,
                "Trace verification failed for index {}",
                index
            );
        }
    }

    #[test]
    fn test_trace_empty_tree() {
        let leaves: Vec<u64> = vec![];
        let tree = build_merkle_tree(&leaves);
        let trace = tree.trace(0);
        assert_eq!(trace.len(), 0);
    }

    #[test]
    fn test_trace_single_leaf() {
        let leaves = vec![42u64];
        let tree = build_merkle_tree(&leaves);
        let trace = tree.trace(0);
        assert_eq!(trace.len(), 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn test_trace_invalid_index() {
        let leaves: Vec<u64> = (0..8).collect();
        let tree = build_merkle_tree(&leaves);
        let _ = tree.trace(8);
    }

    #[test]
    fn test_trace_matches_graypaper_definition() {
        let leaves: Vec<u64> = (0..4).collect();
        let tree = build_merkle_tree(&leaves);

        let trace = tree.trace(2);

        assert_eq!(trace.len(), 2);

        // Verify by reconstructing root
        let leaf_hash = hash_leaf(&leaves[2]);
        let h23 = hash_siblings(&leaf_hash, &trace[1]);
        let root = hash_siblings(&trace[0], &h23);

        assert_eq!(root, tree.get_root().root.unwrap());
    }
}
