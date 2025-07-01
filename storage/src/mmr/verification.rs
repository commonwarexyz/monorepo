//! Defines the inclusion [Proof] structure, functions for generating them from any MMR implementing
//! the [Storage] trait, and functions for verifying them against a root digest.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num, PathIterator, PeakIterator},
    storage::Storage,
    Error, Hasher,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Hasher as CHasher};
use futures::future::try_join_all;
use tracing::debug;

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(Error, Debug)]
pub(crate) enum ReconstructionError {
    #[error("missing digests in proof")]
    MissingDigests,
    #[error("extra digests in proof")]
    ExtraDigests,
    #[error("start position is not a leaf")]
    InvalidStartPos,
    #[error("end position exceeds MMR size")]
    InvalidEndPos,
    #[error("missing elements")]
    MissingElements,
}

/// Contains the information necessary for proving the inclusion of an element, or some range of
/// elements, in the MMR from its root digest.
///
/// The `digests` vector contains:
///
/// 1: the digests of each peak corresponding to a mountain containing no elements from the element
/// range being proven in decreasing order of height, followed by:
///
/// 2: the nodes in the remaining mountains necessary for reconstructing their peak digests from the
/// elements within the range, ordered by the position of their parent.
#[derive(Clone, Debug, Eq)]
pub struct Proof<D: Digest> {
    /// The total number of nodes in the MMR.
    pub size: u64,
    /// The digests necessary for proving the inclusion of an element, or range of elements, in the
    /// MMR.
    pub digests: Vec<D>,
}

impl<D: Digest> PartialEq for Proof<D> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.digests == other.digests
    }
}

impl<D: Digest> EncodeSize for Proof<D> {
    fn encode_size(&self) -> usize {
        UInt(self.size).encode_size() + self.digests.encode_size()
    }
}

impl<D: Digest> Write for Proof<D> {
    fn write(&self, buf: &mut impl BufMut) {
        // Write the number of nodes in the MMR as a varint
        UInt(self.size).write(buf);

        // Write the digests
        self.digests.write(buf);
    }
}

impl<D: Digest> Read for Proof<D> {
    /// The maximum number of digests in the proof.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_len: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        // Read the number of nodes in the MMR
        let size = UInt::<u64>::read(buf)?.into();

        // Read the digests
        let range = ..=max_len;
        let digests = Vec::<D>::read_range(buf, range)?;
        Ok(Proof { size, digests })
    }
}

impl<D: Digest> Default for Proof<D> {
    /// Create an empty proof. The empty proof will verify only against the root hash of an empty
    /// (`size == 0`) MMR.
    fn default() -> Self {
        Self {
            size: 0,
            digests: vec![],
        }
    }
}

impl<D: Digest> Proof<D> {
    /// Return true if `proof` proves that `element` appears at position `element_pos` within the
    /// MMR with root `root_digest`.
    pub fn verify_element_inclusion<I, H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        element_pos: u64,
        root_digest: &D,
    ) -> bool
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
    {
        self.verify_range_inclusion(hasher, &[element], element_pos, root_digest)
    }

    /// Return true if `proof` proves that the `elements` appear consecutively starting at position
    /// `start_element_pos` within the MMR with root `root_digest`.
    pub fn verify_range_inclusion<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
        root_digest: &D,
    ) -> bool
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        match self.reconstruct_root(hasher, elements, start_element_pos) {
            Ok(reconstructed_root) => *root_digest == reconstructed_root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                false
            }
        }
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, or returns a [ReconstructionError] if the input data is invalid.
    pub(crate) fn reconstruct_root<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
    ) -> Result<D, ReconstructionError>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        let peak_digests = self.reconstruct_peak_digests(hasher, elements, start_element_pos)?;

        Ok(hasher.root_digest(self.size, peak_digests.iter()))
    }

    /// Reconstruct the peak digests of the MMR that produced this proof, returning
    /// [ReconstructionError] if the input data is invalid.
    fn reconstruct_peak_digests<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
    ) -> Result<Vec<D>, ReconstructionError>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_element_pos == 0 {
                return Ok(vec![]);
            }
            return Err(ReconstructionError::MissingElements);
        }
        let Some(start_leaf) = leaf_pos_to_num(start_element_pos) else {
            debug!(pos = start_element_pos, "start pos is not a leaf");
            return Err(ReconstructionError::InvalidStartPos);
        };
        let end_element_pos = if elements.len() == 1 {
            start_element_pos
        } else {
            leaf_num_to_pos(start_leaf + elements.len() as u64 - 1)
        };
        if end_element_pos >= self.size {
            return Err(ReconstructionError::InvalidEndPos);
        }

        let mut proof_digests_iter = self.digests.iter();
        let mut siblings_iter = self.digests.iter().rev();

        // Include peak digests only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_digests: Vec<D> = Vec::new();
        let mut proof_digests_used = 0;
        let mut elements_iter = elements.iter();
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
                )?;
                peak_digests.push(hash);
            } else if let Some(hash) = proof_digests_iter.next() {
                proof_digests_used += 1;
                peak_digests.push(*hash);
            } else {
                return Err(ReconstructionError::MissingDigests);
            }
        }

        if elements_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        let next_sibling = siblings_iter.next();
        if (proof_digests_used == 0 && next_sibling.is_some())
            || (next_sibling.is_some()
                && *next_sibling.unwrap() != self.digests[proof_digests_used - 1])
        {
            return Err(ReconstructionError::ExtraDigests);
        }

        Ok(peak_digests)
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
        while let Some(peak) = peak_iterator.next() {
            if start_tree_with_element.0 == u64::MAX && peak.0 >= start_element_pos {
                // Found the first tree to contain an element in the range
                start_tree_with_element = peak;
                if peak.0 >= end_element_pos {
                    // Start and end tree are the same
                    end_tree_with_element = peak;
                    continue;
                }
                for peak in peak_iterator.by_ref() {
                    if peak.0 >= end_element_pos {
                        // Found the last tree to contain an element in the range
                        end_tree_with_element = peak;
                        break;
                    }
                }
            } else {
                // Tree is outside the range, its peak is thus required.
                positions.push(peak.0);
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
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn range_proof<S: Storage<D>>(
        mmr: &S,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<D>, Error> {
        let mut digests: Vec<D> = Vec::new();
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

fn peak_digest_from_range<'a, I, H, E, S>(
    hasher: &mut H,
    pos: u64,           // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
    elements: &mut E,
    sibling_digests: &mut S,
) -> Result<I::Digest, ReconstructionError>
where
    I: CHasher,
    H: Hasher<I>,
    E: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a I::Digest>,
{
    assert_ne!(two_h, 0);
    if two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    let mut left_digest: Option<I::Digest> = None;
    let mut right_digest: Option<I::Digest> = None;

    let left_pos = pos - two_h;
    let right_pos = left_pos + two_h - 1;
    if left_pos >= leftmost_pos {
        // Descend left
        left_digest = Some(peak_digest_from_range(
            hasher,
            left_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_digests,
        )?);
    }
    if left_pos < rightmost_pos {
        // Descend right
        right_digest = Some(peak_digest_from_range(
            hasher,
            right_pos,
            two_h >> 1,
            leftmost_pos,
            rightmost_pos,
            elements,
            sibling_digests,
        )?);
    }

    if left_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => left_digest = Some(*hash),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }
    if right_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => right_digest = Some(*hash),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    Ok(hasher.node_digest(pos, &left_digest.unwrap(), &right_digest.unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{hasher::Standard, mem::Mmr};
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{hash, sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn test_digest(v: u8) -> Digest {
        hash(&[v])
    }

    #[test_traced]
    fn test_verification_empty_proof() {
        // Test that an empty proof authenticates an empty MMR.
        let mmr = Mmr::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        let root_digest = mmr.root(&mut hasher);
        let proof = Proof::default();
        assert!(proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 0, &root_digest));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 1, &root_digest));

        // Invalid root should fail to verify.
        let test_digest = test_digest(0);
        assert!(!proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 0, &test_digest));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&mut hasher, &[test_digest], 0, &root_digest));
    }

    #[test_traced]
    fn test_verification_verify_element() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create an 11 element MMR over which we'll test single-element inclusion proofs
            let mut mmr = Mmr::new();
            let element = Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<u64> = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for _ in 0..11 {
                leaves.push(mmr.add(&mut hasher, &element));
            }

            let root_digest = mmr.root(&mut hasher);

            // confirm the proof of inclusion for each leaf successfully verifies
            for leaf in leaves.iter().by_ref() {
                let proof: Proof<Digest> = mmr.proof(*leaf).await.unwrap();
                assert!(
                    proof.verify_element_inclusion(&mut hasher, &element, *leaf, &root_digest),
                    "valid proof should verify successfully"
                );
            }

            // confirm mangling the proof or proof args results in failed validation
            const POS: u64 = 18;
            let proof = mmr.proof(POS).await.unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, POS, &root_digest),
                "proof verification should be successful"
            );
            assert!(
                !proof.verify_element_inclusion(&mut hasher, &element, POS + 1, &root_digest),
                "proof verification should fail with incorrect element position"
            );
            assert!(
                !proof.verify_element_inclusion(&mut hasher, &element, POS - 1, &root_digest),
                "proof verification should fail with incorrect element position 2"
            );
            assert!(
                !proof.verify_element_inclusion(&mut hasher, &test_digest(0), POS, &root_digest),
                "proof verification should fail with mangled element"
            );
            let root_digest2 = test_digest(0);
            assert!(
                !proof.verify_element_inclusion(&mut hasher, &element, POS, &root_digest2),
                "proof verification should fail with mangled root_digest"
            );
            let mut proof2 = proof.clone();
            proof2.digests[0] = test_digest(0);
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_digest),
                "proof verification should fail with mangled proof hash"
            );
            proof2 = proof.clone();
            proof2.size = 10;
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_digest),
                "proof verification should fail with incorrect size"
            );
            proof2 = proof.clone();
            proof2.digests.push(test_digest(0));
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_digest),
                "proof verification should fail with extra hash"
            );
            proof2 = proof.clone();
            while !proof2.digests.is_empty() {
                proof2.digests.pop();
                assert!(
                    !proof2.verify_element_inclusion(&mut hasher, &element, 7, &root_digest),
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
                !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root_digest),
                "proof verification should fail with extra hash even if it's unused by the computation"
            );
        });
    }

    #[test_traced]
    fn test_verification_verify_range() {
        let executor = deterministic::Runner::default();

        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
            }
            // test range proofs over all possible ranges of at least 2 elements
            let root_digest = mmr.root(&mut hasher);

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
                            &root_digest,
                        ),
                        "valid range proof should verify successfully {i}:{j}",
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
                range_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    &root_digest,
                ),
                "valid range proof should verify successfully"
            );
            let mut invalid_proof = range_proof.clone();
            for _i in 0..range_proof.digests.len() {
                invalid_proof.digests.remove(0);
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        &[] as &[Digest],
                        start_pos,
                        &root_digest,
                    ),
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
                        !range_proof.verify_range_inclusion(
                            &mut hasher,
                            &elements[i..j + 1],
                            start_pos,
                            &root_digest,
                        ),
                        "range proof with invalid elements should fail {i}:{j}",
                    );
                }
            }
            // confirm proof fails with invalid root
            let invalid_root_digest = test_digest(1);
            assert!(
                !range_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    &invalid_root_digest,
                ),
                "range proof with invalid root should fail"
            );
            // mangle the proof and confirm it fails
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests[1] = test_digest(0);
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    &root_digest,
                ),
                "mangled range proof should fail verification"
            );
            // inserting elements into the proof should also cause it to fail (malleability check)
            for i in 0..range_proof.digests.len() {
                let mut invalid_proof = range_proof.clone();
                invalid_proof.digests.insert(i, test_digest(0));
                assert!(
                    !invalid_proof.verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos,
                        &root_digest,
                    ),
                    "mangled range proof should fail verification. inserted element at: {i}",
                );
            }
            // removing proof elements should cause verification to fail
            let mut invalid_proof = range_proof.clone();
            for _ in 0..range_proof.digests.len() {
                invalid_proof.digests.remove(0);
                assert!(
                    !invalid_proof.verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos,
                        &root_digest,
                    ),
                    "shortened range proof should fail verification"
                );
            }
            // bad element range should cause verification to fail
            for (i, _) in elements.iter().enumerate() {
                for (j, _) in elements.iter().enumerate() {
                    let start_pos2 = element_positions[i];
                    if start_pos2 == start_pos {
                        continue;
                    }
                    assert!(
                        !range_proof.verify_range_inclusion(
                            &mut hasher,
                            valid_elements,
                            start_pos2,
                            &root_digest,
                        ),
                        "bad element range should fail verification {i}:{j}",
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_retained_nodes_provable_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
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
                        assert!(proof.unwrap().verify_element_inclusion(
                            &mut hasher,
                            &elements[j],
                            *pos,
                            &root
                        ));
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_ranges_provable_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
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
                            &root_digest,
                        ),
                        "valid range proof over remaining elements should verify successfully",
                    );
                }
            }

            // add a few more nodes, prune again, and test again to make sure repeated pruning works
            for i in 0..37 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
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
                    &elements,
                        start_pos,
                    &updated_root_digest,
                ),
                "valid range proof over remaining elements after 2 pruning rounds should verify successfully",
            );
        });
    }

    #[test_traced]
    fn test_verification_proof_serialization() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount of elements
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..25 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
            }

            // Generate proofs over all possible ranges of elements and confirm each
            // serializes=>deserializes correctly.
            for i in 0..elements.len() {
                for j in i..elements.len() {
                    let start_pos = element_positions[i];
                    let end_pos = element_positions[j];
                    let proof = mmr.range_proof(start_pos, end_pos).await.unwrap();

                    let expected_size = proof.encode_size();
                    let serialized_proof = proof.encode().freeze();
                    assert_eq!(
                        serialized_proof.len(),
                        expected_size,
                        "serialized proof should have expected size"
                    );
                    let max_digests = proof.digests.len();
                    let deserialized_proof =
                        Proof::decode_cfg(serialized_proof, &max_digests).unwrap();
                    assert_eq!(
                        proof, deserialized_proof,
                        "deserialized proof should match source proof"
                    );

                    // Remove one byte from the end of the serialized
                    // proof and confirm it fails to deserialize.
                    let serialized_proof = proof.encode().freeze();
                    let serialized_proof: Bytes =
                        serialized_proof.slice(0..serialized_proof.len() - 1);
                    assert!(
                        Proof::<Digest>::decode_cfg(serialized_proof, &max_digests).is_err(),
                        "proof should not deserialize with truncated data"
                    );

                    // Add 1 byte of extra data to the end of the serialized
                    // proof and confirm it fails to deserialize.
                    let mut serialized_proof = proof.encode();
                    serialized_proof.extend_from_slice(&[0; 10]);
                    let serialized_proof = serialized_proof.freeze();

                    assert!(
                        Proof::<Digest>::decode_cfg(serialized_proof, &max_digests,).is_err(),
                        "proof should not deserialize with extra data"
                    );

                    // Confirm deserialization fails when max length is exceeded.
                    if max_digests > 0 {
                        let serialized_proof = proof.encode().freeze();
                        assert!(
                            Proof::<Digest>::decode_cfg(serialized_proof, &(max_digests - 1),)
                                .is_err(),
                            "proof should not deserialize with max length exceeded"
                        );
                    }
                }
            }
        });
    }
}
