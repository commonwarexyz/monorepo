use bytes::{Buf, BufMut, Bytes};
use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::mem::size_of;
use std::ops::Deref;

/// Computes the combined hash of two digests.
fn combine_hashes(left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    hasher.finalize()
}

/// Computes the Merkle root from a slice of digests with minimal allocations.
/// Returns `None` if the input slice is empty. When an odd number of nodes exists at a level,
/// the last node is duplicated.
pub fn compute_merkle_root(digests: &[Digest]) -> Option<Digest> {
    if digests.is_empty() {
        return None;
    }
    let mut current_level = digests.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for pair in current_level.chunks(2) {
            let parent = if pair.len() == 2 {
                combine_hashes(pair[0].clone(), pair[1].clone())
            } else {
                combine_hashes(pair[0].clone(), pair[0].clone())
            };
            next_level.push(parent);
        }
        current_level = next_level;
    }
    current_level.pop()
}

/// A proof element indicating the sibling digest and its position relative to the current hash.
#[derive(Clone, Debug)]
pub enum MerkleProofElem {
    /// Sibling is on the left; the parent is computed as combine_hashes(sibling, current_hash)
    Left(Digest),
    /// Sibling is on the right; the parent is computed as combine_hashes(current_hash, sibling)
    Right(Digest),
}

/// Verifies that a given leaf digest is included in a Merkle tree with the expected root.
///
/// # Arguments
///
/// * `leaf` - The digest corresponding to the transaction.
/// * `proof` - A slice of proof elements from the leaf up to the root.
/// * `expected_root` - The known Merkle root to verify against.
///
/// # Returns
///
/// `true` if the proof is valid and the computed root equals `expected_root`, else `false`.
pub fn verify_merkle_proof(leaf: Digest, proof: &[MerkleProofElem], expected_root: Digest) -> bool {
    let mut computed = leaf;
    for elem in proof {
        computed = match elem {
            MerkleProofElem::Left(sibling) => combine_hashes(sibling.clone(), computed),
            MerkleProofElem::Right(sibling) => combine_hashes(computed, sibling.clone()),
        };
    }
    computed == expected_root
}

/// Generates a Merkle proof of inclusion for a given leaf index in the slice of digests.
/// Returns `None` if the index is out of bounds or the input is empty.
pub fn generate_merkle_proof(
    digests: &[Digest],
    leaf_index: usize,
) -> Option<Vec<MerkleProofElem>> {
    if digests.is_empty() || leaf_index >= digests.len() {
        return None;
    }
    let mut proof = Vec::new();
    let mut index = leaf_index;
    let mut current_level: Vec<Digest> = digests.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i].clone();
            let right = if i + 1 < current_level.len() {
                current_level[i + 1].clone()
            } else {
                left.clone() // duplicate the last node if odd number
            };

            // If the current index is in this pair, record the sibling.
            if i == index || i + 1 == index {
                if index % 2 == 0 {
                    // Current is left child; sibling is right.
                    proof.push(MerkleProofElem::Right(right.clone()));
                } else {
                    // Current is right child; sibling is left.
                    proof.push(MerkleProofElem::Left(left.clone()));
                }
            }

            let parent = combine_hashes(left, right);
            next_level.push(parent);
        }
        index /= 2;
        current_level = next_level;
    }
    Some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;

    // Helper function to create a digest from a byte slice.
    fn digest_from_bytes(data: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    }

    #[test]
    fn test_merkle_root_single() {
        let data = b"transaction";
        let digest = digest_from_bytes(data);
        let root = compute_merkle_root(&[digest.clone()]);
        assert_eq!(root, Some(digest));
    }

    #[test]
    fn test_merkle_root_multiple() {
        let txs = ["tx1", "tx2", "tx3", "tx4"];
        let digests: Vec<Digest> = txs
            .iter()
            .map(|tx| digest_from_bytes(tx.as_bytes()))
            .collect();
        let root = compute_merkle_root(&digests);
        assert!(root.is_some());
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let txs = ["tx1", "tx2", "tx3", "tx4", "tx5"];
        let digests: Vec<Digest> = txs
            .iter()
            .map(|tx| digest_from_bytes(tx.as_bytes()))
            .collect();
        let root = compute_merkle_root(&digests).unwrap();

        // Verify that each leaf's proof validates against the computed Merkle root.
        for (i, leaf) in digests.iter().enumerate() {
            let proof = generate_merkle_proof(&digests, i)
                .expect(&format!("proof should be generated for index {}", i));
            let verified = verify_merkle_proof(leaf.clone(), &proof, root.clone());
            assert!(verified, "Proof verification failed for index {}", i);
        }
    }
}
