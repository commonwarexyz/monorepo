//! Defines the inclusion `Proof` structure, functions for generating them from any MMR implementing
//! the `Storage` trait, and functions for verifying them against a root hash.

use crate::mmr::{
    iterator::{PathIterator, PeakIterator},
    Error,
    Error::*,
    Hasher, Storage,
};
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, ReadExt};
use commonware_cryptography::Hasher as CHasher;
use futures::future::try_join_all;
use tracing::debug;

/// Contains the information necessary for proving the inclusion of an element, or some range of
/// elements, in the MMR from its root hash.
///
/// The `digests` vector contains:
///
/// 1: the digests of each peak corresponding to a mountain containing no elements from the element
/// range being proven in decreasing order of height, followed by:
///
/// 2: the nodes in the remaining mountains necessary for reconstructing their peak digests from the
/// elements within the range, ordered by the position of their parent.
#[derive(Clone, Debug, Eq)]
pub struct Proof<H: CHasher> {
    /// The total number of nodes in the MMR.
    pub size: u64,
    /// The digests necessary for proving the inclusion of an element, or range of elements, in the
    /// MMR.
    pub digests: Vec<H::Digest>,
}

impl<H: CHasher> PartialEq for Proof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.digests == other.digests
    }
}

impl<H: CHasher> Proof<H> {
    /// Return true if `proof` proves that `element` appears at position `element_pos` within the
    /// MMR with root `root_digest`.
    pub async fn verify_element_inclusion<M: Hasher<H>>(
        &self,
        hasher: &mut M,
        element: &[u8],
        element_pos: u64,
        root_digest: &H::Digest,
    ) -> Result<bool, Error> {
        self.verify_range_inclusion(hasher, &[element], element_pos, element_pos, root_digest)
            .await
    }

    /// Return true if `proof` proves that the `elements` appear consecutively between positions
    /// `start_element_pos` through `end_element_pos` (inclusive) within the MMR with root hash
    /// `root_digest`.
    pub async fn verify_range_inclusion<M: Hasher<H>, T>(
        &self,
        hasher: &mut M,
        elements: T,
        start_element_pos: u64,
        end_element_pos: u64,
        root_digest: &H::Digest,
    ) -> Result<bool, Error>
    where
        T: IntoIterator<Item: AsRef<[u8]>>,
    {
        match self
            .reconstruct_root(hasher, elements, start_element_pos, end_element_pos)
            .await
        {
            Ok(reconstructed_root) => Ok(*root_digest == reconstructed_root),
            Err(MissingDigests) => {
                debug!("Not enough digests in proof to reconstruct peak digests");
                Ok(false)
            }
            Err(ExtraDigests) => {
                debug!("Not all digests in proof were used to reconstruct peak digests");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    pub(super) async fn reconstruct_root<M: Hasher<H>, T>(
        &self,
        hasher: &mut M,
        elements: T,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<H::Digest, Error>
    where
        T: IntoIterator<Item: AsRef<[u8]>>,
    {
        let peak_digests = self
            .reconstruct_peak_digests(hasher, elements, start_element_pos, end_element_pos)
            .await?;

        Ok(hasher.root_digest(self.size, peak_digests.iter()))
    }

    /// Reconstruct the peak digests of the MMR that produced this proof, returning `MissingDigests`
    /// error if there are not enough proof digests, or `ExtraDigests` error if not all proof
    /// digests were used in the reconstruction.
    async fn reconstruct_peak_digests<T>(
        &self,
        hasher: &mut impl Hasher<H>,
        elements: T,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Vec<H::Digest>, Error>
    where
        T: IntoIterator<Item: AsRef<[u8]>>,
    {
        let mut proof_digests_iter = self.digests.iter();
        let mut siblings_iter = self.digests.iter().rev();
        let mut elements_iter = elements.into_iter();

        // Include peak digests only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_digests: Vec<H::Digest> = Vec::new();
        let mut proof_digests_used = 0;
        for (peak_pos, height) in PeakIterator::new(self.size) {
            let leftmost_pos = peak_pos + 2 - (1 << (height + 1));
            if peak_pos >= start_element_pos && leftmost_pos <= end_element_pos {
                let hash = peak_digest_from_range(
                    hasher,
                    peak_pos,
                    1 << height,
                    start_element_pos,
                    end_element_pos,
                    &mut elements_iter,
                    &mut siblings_iter,
                )
                .await?;
                peak_digests.push(hash);
            } else if let Some(hash) = proof_digests_iter.next() {
                proof_digests_used += 1;
                peak_digests.push(*hash);
            } else {
                return Err(MissingDigests);
            }
        }

        if elements_iter.next().is_some() {
            return Err(ExtraDigests);
        }
        let next_sibling = siblings_iter.next();
        if (proof_digests_used == 0 && next_sibling.is_some())
            || (next_sibling.is_some()
                && *next_sibling.unwrap() != self.digests[proof_digests_used - 1])
        {
            return Err(ExtraDigests);
        }

        Ok(peak_digests)
    }

    /// Return the maximum size in bytes of any serialized `Proof`.
    pub fn max_serialization_size() -> usize {
        u64::SIZE + (u8::MAX as usize * H::Digest::SIZE)
    }

    /// Canonically serializes the `Proof` as:
    /// ```text
    ///    [0-8): size (u64 big-endian)
    ///    [8-...): raw bytes of each hash, each of length `H::len()`
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        // A proof should never contain more digests than the depth of the MMR, thus a single byte
        // for encoding the length of the digests array still allows serializing MMRs up to 2^255
        // elements.
        assert!(
            self.digests.len() <= u8::MAX as usize,
            "too many digests in proof"
        );

        // Serialize the proof as a byte vector.
        let bytes_len = u64::SIZE + (self.digests.len() * H::Digest::SIZE);
        let mut bytes = Vec::with_capacity(bytes_len);
        bytes.put_u64(self.size);
        for hash in self.digests.iter() {
            bytes.extend_from_slice(hash.as_ref());
        }
        assert_eq!(bytes.len(), bytes_len, "serialization length mismatch");
        bytes.to_vec()
    }

    /// Deserializes a canonically encoded `Proof`. See `serialize` for the serialization format.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let mut buf = bytes;
        if buf.len() < u64::SIZE {
            return None;
        }
        let size = buf.get_u64();

        // A proof should divide neatly into the hash length and not contain more than 255 digests.
        let buf_remaining = buf.remaining();
        let digests_len = buf_remaining / H::Digest::SIZE;
        if buf_remaining % H::Digest::SIZE != 0 || digests_len > u8::MAX as usize {
            return None;
        }
        let mut digests = Vec::with_capacity(digests_len);
        for _ in 0..digests_len {
            let digest = H::Digest::read(&mut buf).ok()?;
            digests.push(digest);
        }
        Some(Self { size, digests })
    }

    /// Return the list of pruned (pos < `start_pos`) node positions that are still required for
    /// proving any retained node.
    ///
    /// This set consists of every pruned node that is either (1) a peak, or (2) has no descendent
    /// in the retained section, but its immediate parent does. (A node meeting condition (2) can be
    /// shown to always be the left-child of its parent.)
    ///
    /// This set of nodes does not change with the MMR's size, only the pruning boundary. For a
    /// given pruning boundary that happens to be a valid MMR size, one can prove that this set is
    /// exactly the set of peaks for an MMR whose size equals the pruning boundary. If the pruning
    /// boundary is not a valid MMR size, then the set corresponds to the peaks of the largest MMR
    /// whose size is less than the pruning boundary.
    pub fn nodes_to_pin(start_pos: u64) -> impl Iterator<Item = u64> {
        PeakIterator::new(PeakIterator::to_nearest_size(start_pos)).map(|(pos, _)| pos)
    }

    /// Return the list of node positions required by the range proof for the specified range of
    /// elements, inclusive of both endpoints.
    pub fn nodes_required_for_range_proof(
        size: u64,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Vec<u64> {
        let mut positions = Vec::new();

        // Find the mountains that contain no elements from the range. The peaks of these mountains
        // are required to prove the range, so they are added to the result.
        let mut start_tree_with_element = (u64::MAX, 0);
        let mut end_tree_with_element = (u64::MAX, 0);
        let mut peak_iterator = PeakIterator::new(size);
        while let Some(item) = peak_iterator.next() {
            if start_tree_with_element.0 == u64::MAX && item.0 >= start_element_pos {
                // Found the first tree to contain an element in the range
                start_tree_with_element = item;
                if item.0 >= end_element_pos {
                    // Start and end tree are the same
                    end_tree_with_element = item;
                    continue;
                }
                for item in peak_iterator.by_ref() {
                    if item.0 >= end_element_pos {
                        // Found the last tree to contain an element in the range
                        end_tree_with_element = item;
                        break;
                    }
                }
            } else {
                // Tree is outside the range, its peak is thus required.
                positions.push(item.0);
            }
        }
        assert!(start_tree_with_element.0 != u64::MAX);
        assert!(end_tree_with_element.0 != u64::MAX);

        // Include the positions of any left-siblings of each node on the path from peak to
        // leftmost-leaf, and right-siblings for the path from peak to rightmost-leaf. These are
        // added in order of decreasing parent position.
        let left_path_iter = PathIterator::new(
            start_element_pos,
            start_tree_with_element.0,
            start_tree_with_element.1,
        );

        let mut siblings = Vec::new();
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

            // If the range spans more than one tree, then the digests must already be in the correct
            // order. Otherwise, we enforce the desired order through sorting.
            if start_tree_with_element.0 == end_tree_with_element.0 {
                siblings.sort_by(|a, b| b.0.cmp(&a.0));
            }
        }
        positions.extend(siblings.into_iter().map(|(_, pos)| pos));
        positions
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
    ///
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn range_proof<S: Storage<H::Digest>>(
        mmr: &S,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H>, Error> {
        let mut digests: Vec<H::Digest> = Vec::new();
        let positions =
            Self::nodes_required_for_range_proof(mmr.size(), start_element_pos, end_element_pos);

        let node_futures = positions.iter().map(|pos| mmr.get_node(*pos));
        let hash_results = try_join_all(node_futures).await?;

        for (i, hash_result) in hash_results.into_iter().enumerate() {
            match hash_result {
                Some(hash) => digests.push(hash),
                None => return Err(Error::ElementPruned(positions[i])),
            };
        }

        Ok(Proof {
            size: mmr.size(),
            digests,
        })
    }
}

async fn peak_digest_from_range<'a, H, M: Hasher<H>, I, S>(
    hasher: &mut M,
    pos: u64,           // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
    elements: &mut I,
    sibling_digests: &mut S,
) -> Result<H::Digest, Error>
where
    H: CHasher,
    I: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a H::Digest>,
{
    assert_ne!(two_h, 0);
    if two_h == 1 {
        // we are at a leaf
        match elements.next() {
            Some(element) => return hasher.leaf_digest(pos, element.as_ref()).await,
            None => return Err(MissingDigests),
        }
    }

    let mut left_digest: Option<H::Digest> = None;
    let mut right_digest: Option<H::Digest> = None;

    let left_pos = pos - two_h;
    let right_pos = left_pos + two_h - 1;
    if left_pos >= leftmost_pos {
        // Descend left
        let future = Box::pin(peak_digest_from_range(
            hasher,
            left_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_digests,
        ));
        left_digest = Some(future.await?);
    }
    if left_pos < rightmost_pos {
        // Descend right
        let future = Box::pin(peak_digest_from_range(
            hasher,
            right_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_digests,
        ));
        right_digest = Some(future.await?);
    }

    if left_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => left_digest = Some(*hash),
            None => return Err(MissingDigests),
        }
    }
    if right_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => right_digest = Some(*hash),
            None => return Err(MissingDigests),
        }
    }

    Ok(hasher.node_digest(pos, &left_digest.unwrap(), &right_digest.unwrap()))
}

#[cfg(test)]
mod tests {
    use super::Proof;
    use crate::mmr::{hasher::Standard, mem::Mmr};
    use commonware_cryptography::{hash, sha256::Digest, Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner};

    fn test_digest(v: u8) -> Digest {
        hash(&[v])
    }

    #[test]
    fn test_verification_verify_element() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create an 11 element MMR over which we'll test single-element inclusion proofs
            let mut mmr = Mmr::new();
            let element = Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<u64> = Vec::new();
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for _ in 0..11 {
                leaves.push(mmr.add(&mut hasher, &element).await.unwrap());
            }

            let root_digest = mmr.root(&mut hasher);

            // confirm the proof of inclusion for each leaf successfully verifies
            for leaf in leaves.iter().by_ref() {
                let proof = mmr.proof(*leaf).await.unwrap();
                assert!(
                    proof
                        .verify_element_inclusion(&mut hasher, &element, *leaf, &root_digest)
                        .await
                        .unwrap(),
                    "valid proof should verify successfully"
                );
            }

            // confirm mangling the proof or proof args results in failed validation
            const POS: u64 = 18;
            let proof = mmr.proof(POS).await.unwrap();
            assert!(
                proof
                    .verify_element_inclusion(&mut hasher, &element, POS, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should be successful"
            );
            assert!(
                !proof
                    .verify_element_inclusion(&mut hasher, &element, POS + 1, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with incorrect element position"
            );
            assert!(
                !proof
                    .verify_element_inclusion(&mut hasher, &element, POS - 1, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with incorrect element position 2"
            );
            assert!(
                !proof
                    .verify_element_inclusion(&mut hasher, &test_digest(0), POS, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with mangled element"
            );
            let root_digest2 = test_digest(0);
            assert!(
                !proof
                    .verify_element_inclusion(&mut hasher, &element, POS, &root_digest2)
                    .await
                    .unwrap(),
                "proof verification should fail with mangled root_digest"
            );
            let mut proof2 = proof.clone();
            proof2.digests[0] = test_digest(0);
            assert!(
                !proof2
                    .verify_element_inclusion(&mut hasher, &element, POS, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with mangled proof hash"
            );
            proof2 = proof.clone();
            proof2.size = 10;
            assert!(
                !proof2
                    .verify_element_inclusion(&mut hasher, &element, POS, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with incorrect size"
            );
            proof2 = proof.clone();
            proof2.digests.push(test_digest(0));
            assert!(
                !proof2
                    .verify_element_inclusion(&mut hasher, &element, POS, &root_digest)
                    .await
                    .unwrap(),
                "proof verification should fail with extra hash"
            );
            proof2 = proof.clone();
            while !proof2.digests.is_empty() {
                proof2.digests.pop();
                assert!(
                    !proof2
                        .verify_element_inclusion(&mut hasher, &element, 7, &root_digest)
                        .await
                        .unwrap(),
                    "proof verification should fail with missing digests"
                );
            }
            proof2 = proof.clone();
            proof2.digests.clear();
            const PEAK_COUNT: usize = 3;
            proof2
                .digests
                .extend(proof.digests[0..PEAK_COUNT - 1].iter().cloned());
            // sneak in an extra hash that won't be used in the computation and make sure it's
            // detected
            proof2.digests.push(test_digest(0));
            proof2
                .digests
                .extend(proof.digests[PEAK_COUNT - 1..].iter().cloned());
            assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_digest).await.unwrap(),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );
        });
    }

    #[test]
    fn test_verification_verify_range() {
        let executor = deterministic::Runner::default();

        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(
                    mmr.add(&mut hasher, elements.last().unwrap())
                        .await
                        .unwrap(),
                );
            }
            // test range proofs over all possible ranges of at least 2 elements
            let root_digest = mmr.root(&mut hasher);

            for i in 0..elements.len() {
                for j in i + 1..elements.len() {
                    let start_pos = element_positions[i];
                    let end_pos = element_positions[j];
                    let range_proof = mmr.range_proof(start_pos, end_pos).await.unwrap();
                    assert!(
                        range_proof
                            .verify_range_inclusion(
                                &mut hasher,
                                &elements[i..j + 1],
                                start_pos,
                                end_pos,
                                &root_digest,
                            )
                            .await
                            .unwrap(),
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
            let range_proof = mmr.range_proof(start_pos, end_pos).await.unwrap();
            let valid_elements = &elements[start_index..end_index + 1];
            assert!(
                range_proof
                    .verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos,
                        end_pos,
                        &root_digest,
                    )
                    .await
                    .unwrap(),
                "valid range proof should verify successfully"
            );
            let mut invalid_proof = range_proof.clone();
            for _i in 0..range_proof.digests.len() {
                invalid_proof.digests.remove(0);
                assert!(
                    !range_proof
                        .verify_range_inclusion(
                            &mut hasher,
                            Vec::<&[u8]>::new(),
                            start_pos,
                            end_pos,
                            &root_digest,
                        )
                        .await
                        .unwrap(),
                    "range proof with removed elements should fail"
                );
            }
            // confirm proof fails with invalid element digests
            for i in 0..elements.len() {
                for j in i..elements.len() {
                    if i == start_index && j == end_index {
                        // skip the valid range
                        continue;
                    }
                    assert!(
                        !range_proof
                            .verify_range_inclusion(
                                &mut hasher,
                                &elements[i..j + 1],
                                start_pos,
                                end_pos,
                                &root_digest,
                            )
                            .await
                            .unwrap(),
                        "range proof with invalid elements should fail {}:{}",
                        i,
                        j
                    );
                }
            }
            // confirm proof fails with invalid root hash
            let invalid_root_digest = test_digest(1);
            assert!(
                !range_proof
                    .verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos,
                        end_pos,
                        &invalid_root_digest,
                    )
                    .await
                    .unwrap(),
                "range proof with invalid root hash should fail"
            );
            // mangle the proof and confirm it fails
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests[1] = test_digest(0);
            assert!(
                !invalid_proof
                    .verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos,
                        end_pos,
                        &root_digest,
                    )
                    .await
                    .unwrap(),
                "mangled range proof should fail verification"
            );
            // inserting elements into the proof should also cause it to fail (malleability check)
            for i in 0..range_proof.digests.len() {
                let mut invalid_proof = range_proof.clone();
                invalid_proof.digests.insert(i, test_digest(0));
                assert!(
                    !invalid_proof
                        .verify_range_inclusion(
                            &mut hasher,
                            valid_elements,
                            start_pos,
                            end_pos,
                            &root_digest,
                        )
                        .await
                        .unwrap(),
                    "mangled range proof should fail verification. inserted element at: {}",
                    i
                );
            }
            // removing proof elements should cause verification to fail
            let mut invalid_proof = range_proof.clone();
            for _ in 0..range_proof.digests.len() {
                invalid_proof.digests.remove(0);
                assert!(
                    !invalid_proof
                        .verify_range_inclusion(
                            &mut hasher,
                            valid_elements,
                            start_pos,
                            end_pos,
                            &root_digest,
                        )
                        .await
                        .unwrap(),
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
                        !range_proof
                            .verify_range_inclusion(
                                &mut hasher,
                                valid_elements,
                                start_pos2,
                                end_pos2,
                                &root_digest,
                            )
                            .await
                            .unwrap(),
                        "bad element range should fail verification {}:{}",
                        i,
                        j
                    );
                }
            }
        });
    }

    #[test]
    fn test_verification_retained_nodes_provable_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(
                    mmr.add(&mut hasher, elements.last().unwrap())
                        .await
                        .unwrap(),
                );
            }

            // Confirm we can successfully prove all retained elements in the MMR after pruning.
            let root = mmr.root(&mut hasher);
            for i in 1..mmr.size() {
                mmr.prune_to_pos(i);
                let pruned_root = mmr.root(&mut hasher);
                assert_eq!(root, pruned_root);
                for (j, pos) in element_positions.iter().enumerate() {
                    let proof = mmr.proof(*pos).await;
                    if *pos < i {
                        assert!(proof.is_err());
                    } else {
                        assert!(proof.is_ok());
                        assert!(proof
                            .unwrap()
                            .verify_element_inclusion(&mut hasher, &elements[j], *pos, &root)
                            .await
                            .unwrap());
                    }
                }
            }
        });
    }

    #[test]
    fn test_verification_ranges_provable_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()).await.unwrap());
            }

            // prune up to the first peak
            mmr.prune_to_pos(62);
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 62);
            for i in 0..elements.len() {
                if element_positions[i] > 62 {
                    elements = elements[i..elements.len()].to_vec();
                    element_positions = element_positions[i..element_positions.len()].to_vec();
                    break;
                }
            }

            // test range proofs over all possible ranges of at least 2 elements
            let root_digest = mmr.root(&mut hasher);
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for i in 0..elements.len() {
                for j in i + 1..elements.len() {
                    let start_pos = element_positions[i];
                    let end_pos = element_positions[j];
                    let range_proof = mmr.range_proof(start_pos, end_pos).await.unwrap();
                    assert!(
                        range_proof.verify_range_inclusion(
                            &mut hasher,
                            &elements[i..j + 1],
                            start_pos,
                            end_pos,
                            &root_digest,
                        ).await.unwrap(),
                        "valid range proof over remaining elements should verify successfully",
                    );
                }
            }

            // add a few more nodes, prune again, and test again to make sure repeated pruning works
            for i in 0..37 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()).await.unwrap());
            }
            mmr.prune_to_pos(130); // a bit after the new highest peak
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 130);

            let updated_root_digest = mmr.root(&mut hasher);
            for i in 0..elements.len() {
                if element_positions[i] >= 130 {
                    elements = elements[i..elements.len()].to_vec();
                    element_positions = element_positions[i..element_positions.len()].to_vec();
                    break;
                }
            }
            let start_pos = element_positions[0];
            let end_pos = *element_positions.last().unwrap();
            let range_proof = mmr.range_proof(start_pos, end_pos).await.unwrap();
            assert!(
                range_proof.verify_range_inclusion(
                    &mut hasher,
                    elements,
                    start_pos,
                    end_pos,
                    &updated_root_digest,
                ).await.unwrap(),
                "valid range proof over remaining elements after 2 pruning rounds should verify successfully",
            );
        });
    }

    #[test]
    fn test_verification_proof_serialization() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            assert_eq!(
                Proof::<Sha256>::max_serialization_size(),
                8168,
                "wrong max serialization size of a Sha256 proof"
            );
            // create a new MMR and add a non-trivial amount of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
            for i in 0..25 {
                elements.push(test_digest(i));
                element_positions.push(
                    mmr.add(&mut hasher, elements.last().unwrap())
                        .await
                        .unwrap(),
                );
            }

            // Generate proofs over all possible ranges of elements and confirm each
            // serializes=>deserializes correctly.
            for i in 0..elements.len() {
                for j in i..elements.len() {
                    let start_pos = element_positions[i];
                    let end_pos = element_positions[j];
                    let proof = mmr.range_proof(start_pos, end_pos).await.unwrap();

                    let mut serialized_proof = proof.serialize();
                    let deserialized_proof = Proof::<Sha256>::deserialize(&serialized_proof);
                    assert!(deserialized_proof.is_some(), "proof didn't deserialize");
                    assert_eq!(
                        proof,
                        deserialized_proof.unwrap(),
                        "deserialized proof should match source proof"
                    );

                    let deserialized_truncated = Proof::<Sha256>::deserialize(
                        &serialized_proof[0..serialized_proof.len() - 1],
                    );
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
        });
    }
}
