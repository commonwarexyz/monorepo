//! Stateless binary Merkle Tree.

use commonware_cryptography::{Digest, Hasher};
use std::mem::size_of;

/// Combines two digests into a new digest.
fn combine<H: Hasher>(hasher: &mut H, left: H::Digest, right: H::Digest) -> H::Digest {
    hasher.update(left.as_ref());
    hasher.update(right.as_ref());
    hasher.finalize()
}

/// Compute the Merkle root of a slice of leaf digests.
///
/// If the slice is empty, returns `None`. For an odd number of nodes at a level,
/// the last node is duplicated.
pub fn compute<H: Hasher>(hasher: &mut H, digests: &[H::Digest]) -> Option<H::Digest> {
    // If there are no leaves, there can be no root.
    if digests.is_empty() {
        return None;
    }

    // Build the Merkle tree from the leaves up to the root.
    let mut current_level = digests.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for chunk in current_level.chunks(2) {
            let left = chunk[0].clone();
            let right = if chunk.len() == 2 {
                chunk[1].clone()
            } else {
                left.clone()
            };
            let parent = combine(hasher, left, right);
            next_level.push(parent);
        }
        current_level = next_level;
    }
    current_level.into_iter().next()
}

/// A binary Merkle tree proof represented solely as a vector of sibling hashes.
#[derive(Clone, Debug)]
pub struct Proof<H: Hasher> {
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
    /// Verifies that a given leaf (i.e. element digest) at position `leaf_index` is included in the Merkle tree
    /// with the expected root hash.
    ///
    /// The proof consists of sibling hashes stored from the leaf up to the root. At each level, if the current
    /// node is a left child (even index), the sibling is combined to the right; if it is a right child (odd index),
    /// the sibling is combined to the left.
    pub fn verify(
        &self,
        hasher: &mut H,
        element: &H::Digest,
        element_pos: u64,
        root_hash: &H::Digest,
    ) -> bool {
        let mut computed = element.clone();
        let mut index = element_pos;
        for sibling in &self.hashes {
            if index % 2 == 0 {
                computed = combine(hasher, computed, sibling.clone());
            } else {
                computed = combine(hasher, sibling.clone(), computed);
            }
            index /= 2;
        }
        computed == *root_hash
    }

    /// Returns the maximum number of bytes any serialized proof may occupy.
    pub fn max_serialization_size() -> usize {
        u8::MAX as usize * size_of::<H::Digest>()
    }

    /// Serializes the proof as the concatenation of each hash.
    pub fn serialize(&self) -> Vec<u8> {
        // A proof should never contain more hashes than the depth of the MMR, thus a single byte
        // for encoding the length of the hashes array still allows serializing MMRs up to 2^255
        // elements.
        assert!(
            self.hashes.len() <= u8::MAX as usize,
            "too many hashes in proof"
        );

        let bytes_len = self.hashes.len() * size_of::<H::Digest>();
        let mut bytes = Vec::with_capacity(bytes_len);
        for hash in &self.hashes {
            bytes.extend_from_slice(hash.as_ref());
        }
        bytes
    }

    /// Deserializes a proof from its canonical serialized representation.
    pub fn deserialize(mut buf: &[u8]) -> Option<Self> {
        if buf.len() % size_of::<H::Digest>() != 0 {
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
        Some(Self { hashes })
    }
}

/// Generates a binary Merkle tree proof of inclusion for the leaf at `leaf_index` from a slice of leaf digests.
///
/// The tree is constructed by pairing adjacent digests (duplicating the last one if necessary).
pub fn generate_proof<H: Hasher>(
    hasher: &mut H,
    digests: &[H::Digest],
    leaf_index: usize,
) -> Option<Proof<H>> {
    if digests.is_empty() || leaf_index >= digests.len() {
        return None;
    }
    let mut proof_hashes = Vec::new();
    let mut index = leaf_index;
    let mut current_level = digests.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i].clone();
            let right = if i + 1 < current_level.len() {
                current_level[i + 1].clone()
            } else {
                left.clone() // duplicate if odd count
            };

            // If the current leaf is in this pair, record the sibling.
            if i == index || i + 1 == index {
                if index % 2 == 0 {
                    proof_hashes.push(right.clone());
                } else {
                    proof_hashes.push(left.clone());
                }
            }

            let parent = combine(hasher, left, right);
            next_level.push(parent);
        }
        index /= 2;
        current_level = next_level;
    }
    Some(Proof {
        hashes: proof_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        hash,
        sha256::{Digest, Sha256},
    };

    #[test]
    fn test_compute_merkle_root_single() {
        let tx = b"tx";
        let leaf = hash(tx);
        let root = compute_merkle_root::<Sha256>(&[leaf.clone()]).unwrap();
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_compute_merkle_root_multiple() {
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let root = compute_merkle_root::<Sha256>(&digests).unwrap();

        // Verify each leaf's proof yields the computed root.
        for (i, leaf) in digests.iter().enumerate() {
            let proof = generate_proof::<Sha256>(&digests, i).unwrap();
            let mut hasher = Sha256::default();
            assert!(
                proof.verify_element_inclusion(&mut hasher, leaf, i as u64, &root),
                "Proof failed for leaf index {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_single_element() {
        let tx = b"transaction";
        let leaf = hash(tx);
        let digests = vec![leaf.clone()];
        let root = leaf.clone();
        let proof = generate_proof::<Sha256>(&digests, 0).unwrap();
        let mut hasher = Sha256::default();
        assert!(proof.verify_element_inclusion(&mut hasher, &leaf, 0, &root));
    }

    #[test]
    fn test_merkle_proof_multiple() {
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let root = compute_merkle_root::<Sha256>(&digests).unwrap();

        // Verify each leaf's proof.
        for (i, leaf) in digests.iter().enumerate() {
            let proof = generate_proof::<Sha256>(&digests, i).unwrap();
            let mut hasher = Sha256::default();
            assert!(
                proof.verify_element_inclusion(&mut hasher, leaf, i as u64, &root),
                "Proof failed for leaf index {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_serialization() {
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let proof = generate_proof::<Sha256>(&digests, 1).unwrap();
        let serialized = proof.serialize();
        let deserialized = Proof::<Sha256>::deserialize(&serialized).unwrap();
        assert_eq!(proof, deserialized);
    }
}
