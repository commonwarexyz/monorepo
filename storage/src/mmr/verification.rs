use crate::mmr::hasher::Hasher;
use crate::mmr::iterator::PeakIterator;
use bytes::{Buf, BufMut};
use commonware_cryptography::Hasher as CHasher;

/// A `Proof` contains the information necessary for proving the inclusion of an element, or some
/// range of elements, in the MMR from its root hash. The `hashes` vector contains: (1) the peak
/// hashes other than those belonging to trees containing some elements within the range being
/// proven, followed by: (2) the nodes in the remaining perfect trees necessary for reconstructing
/// their peak hashes from the elements within the range. Both segments are ordered by decreasing
/// height.
#[derive(Clone, Debug, Eq)]
/// A Proof contains the information necessary for proving the inclusion of an element, or some
/// range of elements, in the MMR.
pub struct Proof<H: CHasher> {
    /// The total number of nodes in the MMR.
    pub size: u64,
    /// The hashes necessary for proving the inclusion of an element, or range of elements, in the MMR.
    pub hashes: Vec<H::Digest>,
}

impl<H: CHasher> PartialEq for Proof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.hashes == other.hashes
    }
}

impl<H: CHasher> Proof<H> {
    /// Return true if `proof` proves that `element` appears at position `element_pos` within the MMR
    /// with root hash `root_hash`.
    pub fn verify_element_inclusion(
        &self,
        hasher: &mut H,
        element: &H::Digest,
        element_pos: u64,
        root_hash: &H::Digest,
    ) -> bool {
        self.verify_range_inclusion(
            hasher,
            &[element.clone()],
            element_pos,
            element_pos,
            root_hash,
        )
    }

    /// Return true if `proof` proves that the `elements` appear consecutively between positions
    /// `start_element_pos` through `end_element_pos` (inclusive) within the MMR with root hash
    /// `root_hash`.
    pub fn verify_range_inclusion(
        &self,
        hasher: &mut H,
        elements: &[H::Digest],
        start_element_pos: u64,
        end_element_pos: u64,
        root_hash: &H::Digest,
    ) -> bool {
        let mut proof_hashes_iter = self.hashes.iter();
        let mut elements_iter = elements.iter();
        let mut siblings_iter = self.hashes.iter().rev();
        let mut mmr_hasher = Hasher::<H>::new(hasher);

        // Include peak hashes only for trees that have no elements from the range, and keep track of
        // the starting and ending trees of those that do contain some.
        let mut peak_hashes: Vec<H::Digest> = Vec::new();
        let mut proof_hashes_used = 0;
        for (peak_pos, height) in PeakIterator::new(self.size) {
            let leftmost_pos = peak_pos + 2 - (1 << (height + 1));
            if peak_pos >= start_element_pos && leftmost_pos <= end_element_pos {
                match peak_hash_from_range(
                    &mut mmr_hasher,
                    peak_pos,
                    1 << height,
                    start_element_pos,
                    end_element_pos,
                    &mut elements_iter,
                    &mut siblings_iter,
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
            || (next_sibling.is_some()
                && *next_sibling.unwrap() != self.hashes[proof_hashes_used - 1])
        {
            // some proof data was not used during verification, so we must return false to prevent
            // proof malleability attacks.
            return false;
        }
        *root_hash == mmr_hasher.root_hash(self.size, peak_hashes.iter())
    }

    /// Return the maximum size in bytes of any serialized `Proof`.
    pub fn max_serialization_size() -> usize {
        size_of::<u64>() + (u8::MAX as usize * size_of::<H::Digest>())
    }

    /// Canonically serializes the `Proof` as:
    /// ```text
    ///    [0-8): size (u64 big-endian)
    ///    [8-...): raw bytes of each hash, each of length `H::len()`
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let bytes_len = size_of::<u64>() + (self.hashes.len() * size_of::<H::Digest>());
        let mut bytes = Vec::with_capacity(bytes_len);
        bytes.put_u64(self.size);

        // A proof should never contain more hashes than the depth of the MMR, thus a single byte
        // for encoding the length of the hashes array still allows serializing MMRs up to 2^255
        // elements.
        assert!(
            self.hashes.len() <= u8::MAX as usize,
            "too many hashes in proof"
        );
        for hash in self.hashes.iter() {
            bytes.extend_from_slice(hash.as_ref());
        }
        assert_eq!(bytes.len(), bytes_len, "serialization length mismatch");
        bytes.to_vec()
    }

    /// Deserializes a canonically encoded `Proof`. See `serialize` for the serialization format.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let mut buf = bytes;
        if buf.len() < size_of::<u64>() {
            return None;
        }
        let size = buf.get_u64();

        // A proof should divide neatly into the hash length and not contain more than 255 hashes.
        let buf_remaining = buf.remaining();
        let hashes_len = buf_remaining / size_of::<H::Digest>();
        if buf_remaining % size_of::<H::Digest>() != 0 || hashes_len > u8::MAX as usize {
            return None;
        }
        let mut hashes = Vec::with_capacity(hashes_len);
        for _ in 0..hashes_len {
            let mut digest = H::Digest::default();
            buf.copy_to_slice(&mut digest);
            hashes.push(digest);
        }
        Some(Self { size, hashes })
    }
}

fn peak_hash_from_range<'a, H: CHasher>(
    hasher: &mut Hasher<H>,
    node_pos: u64,      // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
    elements: &mut impl Iterator<Item = &'a H::Digest>,
    sibling_hashes: &mut impl Iterator<Item = &'a H::Digest>,
) -> Result<H::Digest, ()> {
    assert_ne!(two_h, 0);
    if two_h == 1 {
        // we are at a leaf
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_hash(node_pos, element)),
            None => return Err(()),
        }
    }

    let left_pos = node_pos - two_h;
    let mut left_hash: Option<H::Digest> = None;
    let right_pos = left_pos + two_h - 1;
    let mut right_hash: Option<H::Digest> = None;

    if left_pos >= leftmost_pos {
        // Descend left
        match peak_hash_from_range(
            hasher,
            left_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_hashes,
        ) {
            Ok(h) => left_hash = Some(h.clone()),
            Err(_) => return Err(()),
        }
    }
    if left_pos < rightmost_pos {
        // Descend right
        match peak_hash_from_range(
            hasher,
            right_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_hashes,
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

#[cfg(test)]
mod tests {
    use super::Proof;
    use crate::mmr::mem::Mmr;
    use commonware_cryptography::{sha256::Digest, Sha256};

    fn test_digest(v: u8) -> Digest {
        Digest::from([v; size_of::<Digest>()])
    }

    #[test]
    fn test_verify_element() {
        // create an 11 element MMR over which we'll test single-element inclusion proofs
        let mut mmr = Mmr::<Sha256>::new();
        let element = Digest::from(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&element));
        }

        let root_hash = mmr.root_hash();
        let mut hasher = Sha256::default();

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in leaves.iter().by_ref() {
            let proof = mmr.proof(*leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, *leaf, &root_hash),
                "valid proof should verify successfully"
            );
        }

        // confirm mangling the proof or proof args results in failed validation
        const POS: u64 = 18;
        let proof = mmr.proof(POS).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, &element, POS, &root_hash),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS + 1, &root_hash,),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS - 1, &root_hash),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &test_digest(0), POS, &root_hash,),
            "proof verification should fail with mangled element"
        );
        let root_hash2 = test_digest(0);
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS, &root_hash2),
            "proof verification should fail with mangled root_hash"
        );
        let mut proof2 = proof.clone();
        proof2.hashes[0] = test_digest(0);
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_hash),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.size = 10;
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_hash),
            "proof verification should fail with incorrect size"
        );
        proof2 = proof.clone();
        proof2.hashes.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_hash),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.hashes.is_empty() {
            proof2.hashes.pop();
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, 7, &root_hash),
                "proof verification should fail with missing hashes"
            );
        }
        proof2 = proof.clone();
        proof2.hashes.clear();
        const PEAK_COUNT: usize = 3;
        proof2
            .hashes
            .extend(proof.hashes[0..PEAK_COUNT - 1].iter().cloned());
        // sneak in an extra hash that won't be used in the computation and make sure it's detected
        proof2.hashes.push(test_digest(0));
        proof2
            .hashes
            .extend(proof.hashes[PEAK_COUNT - 1..].iter().cloned());
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_hash),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );
    }

    #[test]
    fn test_verify_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr: Mmr<Sha256> = Mmr::default();
        let mut elements = Vec::<Digest>::new();
        let mut element_positions = Vec::<u64>::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(elements.last().unwrap()));
        }
        // test range proofs over all possible ranges of at least 2 elements
        let root_hash = mmr.root_hash();
        let mut hasher = Sha256::default();
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let start_pos = element_positions[i];
                let end_pos = element_positions[j];
                let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j + 1],
                        start_pos,
                        end_pos,
                        &root_hash,
                    ),
                    "valid range proof should verify successfully {}:{}",
                    i,
                    j
                );
            }
        }

        // create a test range for which we will mangle data and confirm the proof fails
        let start_index = 33;
        let end_index = 39;
        let start_pos = element_positions[start_index];
        let end_pos = element_positions[end_index];
        let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
        let valid_elements = &elements[start_index..end_index + 1];
        assert!(
            range_proof.verify_range_inclusion(
                &mut hasher,
                valid_elements,
                start_pos,
                end_pos,
                &root_hash,
            ),
            "valid range proof should verify successfully"
        );
        let mut invalid_proof = range_proof.clone();
        for _i in 0..range_proof.hashes.len() {
            invalid_proof.hashes.remove(0);
            assert!(
                !range_proof.verify_range_inclusion(
                    &mut hasher,
                    &Vec::new(),
                    start_pos,
                    end_pos,
                    &root_hash,
                ),
                "range proof with removed elements should fail"
            );
        }
        // confirm proof fails with invalid element hashes
        for i in 0..elements.len() {
            for j in i..elements.len() {
                assert!(
                    (i == start_index && j == end_index) // exclude the valid element range
                                    || !range_proof.verify_range_inclusion(
                                        &mut hasher,
                                        &elements[i..j + 1],
                                        start_pos,
                                        end_pos,
                                        &root_hash,
                                    ),
                    "range proof with invalid elements should fail {}:{}",
                    i,
                    j
                );
            }
        }
        // confirm proof fails with invalid root hash
        let mut invalid_root_hash = test_digest(0);
        invalid_root_hash[29] = root_hash.as_ref()[29] + 1;
        assert!(
            !range_proof.verify_range_inclusion(
                &mut hasher,
                valid_elements,
                start_pos,
                end_pos,
                &invalid_root_hash,
            ),
            "range proof with invalid root hash should fail"
        );
        // mangle the proof and confirm it fails
        let mut invalid_proof = range_proof.clone();
        invalid_proof.hashes[1] = test_digest(0);
        assert!(
            !invalid_proof.verify_range_inclusion(
                &mut hasher,
                valid_elements,
                start_pos,
                end_pos,
                &root_hash,
            ),
            "mangled range proof should fail verification"
        );
        // inserting elements into the proof should also cause it to fail (malleability check)
        for i in 0..range_proof.hashes.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.hashes.insert(i, test_digest(0));
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    end_pos,
                    &root_hash,
                ),
                "mangled range proof should fail verification. inserted element at: {}",
                i
            );
        }
        // removing proof elements should cause verification to fail
        let mut invalid_proof = range_proof.clone();
        for _ in 0..range_proof.hashes.len() {
            invalid_proof.hashes.remove(0);
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    end_pos,
                    &root_hash,
                ),
                "shortened range proof should fail verification"
            );
        }
        // bad element range should cause verification to fail
        for i in 0..elements.len() {
            for j in 0..elements.len() {
                let start_pos2 = element_positions[i];
                let end_pos2 = element_positions[j];
                if start_pos2 == start_pos && end_pos2 == end_pos {
                    continue;
                }
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos2,
                        end_pos2,
                        &root_hash,
                    ),
                    "bad element range should fail verification {}:{}",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn test_range_proofs_after_forgetting() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr: Mmr<Sha256> = Mmr::default();
        let mut elements = Vec::<Digest>::new();
        let mut element_positions = Vec::<u64>::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(elements.last().unwrap()));
        }

        // forget the max # of elements
        assert_eq!(mmr.forget_max(), 57);

        // Prune the elements from our lists that can no longer be proven after forgetting.
        for i in 0..elements.len() {
            if element_positions[i] > 57 {
                elements = elements[i..elements.len()].to_vec();
                element_positions = element_positions[i..element_positions.len()].to_vec();
                break;
            }
        }

        // test range proofs over all possible ranges of at least 2 elements
        let root_hash = mmr.root_hash();
        let mut hasher = Sha256::default();
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let start_pos = element_positions[i];
                let end_pos = element_positions[j];
                let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j + 1],
                        start_pos,
                        end_pos,
                        &root_hash,
                    ),
                    "valid range proof over remaining elements should verify successfully",
                );
            }
        }

        // add a few more nodes, forget again, and test again to make sure repeated forgetting works
        for i in 0..37 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(elements.last().unwrap()));
        }
        let updated_root_hash = mmr.root_hash();
        assert_eq!(mmr.oldest_required_element(), 120);
        assert!(mmr.forget(120).is_ok());
        for i in 0..elements.len() {
            if element_positions[i] > 120 {
                elements = elements[i..elements.len()].to_vec();
                element_positions = element_positions[i..element_positions.len()].to_vec();
                break;
            }
        }
        let start_pos = element_positions[0];
        let end_pos = *element_positions.last().unwrap();
        let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
        assert!(
            range_proof.verify_range_inclusion(
                &mut hasher,
                &elements,
                start_pos,
                end_pos,
                &updated_root_hash,
            ),
            "valid range proof over remaining elements after 2 forgetting rounds should verify successfully",
        );
    }

    #[test]
    fn test_proof_serialization() {
        assert_eq!(
            Proof::<Sha256>::max_serialization_size(),
            8168,
            "wrong max serialization size of a Sha256 proof"
        );
        // create a new MMR and add a non-trivial amount of elements
        let mut mmr: Mmr<Sha256> = Mmr::default();
        let mut elements = Vec::<Digest>::new();
        let mut element_positions = Vec::<u64>::new();
        for i in 0..25 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(elements.last().unwrap()));
        }
        // Generate proofs over all possible ranges of elements and confirm each
        // serializes=>deserializes correctly.
        for i in 0..elements.len() {
            for j in i..elements.len() {
                let start_pos = element_positions[i];
                let end_pos = element_positions[j];
                let proof = mmr.range_proof(start_pos, end_pos).unwrap();

                let mut serialized_proof = proof.serialize();
                let deserialized_proof = Proof::<Sha256>::deserialize(&serialized_proof);
                assert!(deserialized_proof.is_some(), "proof didn't deserialize");
                assert_eq!(
                    proof,
                    deserialized_proof.unwrap(),
                    "deserialized proof should match source proof"
                );

                let deserialized_truncated =
                    Proof::<Sha256>::deserialize(&serialized_proof[0..serialized_proof.len() - 1]);
                assert!(
                    deserialized_truncated.is_none(),
                    "proof should not deserialize with truncated data"
                );

                serialized_proof.push(i as u8);
                assert!(
                    Proof::<Sha256>::deserialize(&serialized_proof).is_none(),
                    "proof should not deserialize with extra data"
                );
            }
        }
    }
}
