//! MMR-specific proof tests.

#[cfg(test)]
mod tests {
    use crate::merkle::{
        self as merkle,
        mmr::{
            iterator::PeakIterator, mem::Mmr, Error, Family, Location, Position,
            StandardHasher as Standard,
        },
        proof::{nodes_required_for_multi_proof, Blueprint},
        Bagging, Family as _, LocationRangeExt as _,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    #[test]
    fn test_proving_digests_from_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new();
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let batch = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mmr, &hasher)
        };
        mmr.apply_batch(&batch).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();

        // Test 1: compute_digests over the entire range should contain a digest for every node
        // in the tree.
        let proof = mmr
            .range_proof(&hasher, Location::new(0)..mmr.leaves(), 0)
            .unwrap();
        let mut node_digests = proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements,
                Location::new(0),
                &root,
                0,
            )
            .unwrap();
        assert_eq!(node_digests.len() as u64, mmr.size());
        node_digests.sort_by_key(|(pos, _)| *pos);
        for (i, (pos, d)) in node_digests.into_iter().enumerate() {
            assert_eq!(pos, i as u64);
            assert_eq!(mmr.get_node(pos).unwrap(), d);
        }
        // Make sure the wrong root fails.
        let wrong_root = elements[0]; // any other digest will do
        assert!(matches!(
            proof.verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements,
                Location::new(0),
                &wrong_root,
                0,
            ),
            Err(Error::RootMismatch)
        ));

        // Test 2: Single element range (first element)
        let range = Location::new(0)..Location::new(1);
        let single_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
        let range_start = range.start;
        let single_digests = single_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                &root,
                0,
            )
            .unwrap();
        assert!(single_digests.len() > 1);

        // Test 3: Single element range (middle element)
        let mid_idx = 24;
        let range = Location::new(mid_idx)..Location::new(mid_idx + 1);
        let range_start = range.start;
        let mid_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
        let mid_digests = mid_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                &root,
                0,
            )
            .unwrap();
        assert!(mid_digests.len() > 1);

        // Test 4: Single element range (last element)
        let last_idx = elements.len() as u64 - 1;
        let range = Location::new(last_idx)..Location::new(last_idx + 1);
        let range_start = range.start;
        let last_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                &root,
                0,
            )
            .unwrap();
        assert!(!last_digests.is_empty());

        // Test 5: Small range at the beginning
        let range = Location::new(0)..Location::new(5);
        let range_start = range.start;
        let small_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
        let small_digests = small_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                &root,
                0,
            )
            .unwrap();
        // Verify that we get digests for the range elements and their ancestors
        assert!(small_digests.len() > 5);

        // Test 6: Medium range in the middle
        let range = Location::new(10)..Location::new(31);
        let range_start = range.start;
        let mid_range_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
        let mid_range_digests = mid_range_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                &root,
                0,
            )
            .unwrap();
        let num_elements = range.end - range.start;
        assert!(mid_range_digests.len() as u64 > num_elements);
    }

    #[test]
    fn test_max_location_is_provable() {
        // MAX_LEAVES is the largest valid leaf count.
        let max_loc = Family::MAX_LEAVES;
        let max_loc_plus_1 = Location::new(*max_loc + 1);

        let result = Blueprint::new(max_loc, 0, Bagging::ForwardFold, max_loc - 1..max_loc);
        assert!(
            result.is_ok(),
            "Should be able to prove with MAX_LEAVES leaves"
        );

        // MAX_LEAVES + 1 should be rejected.
        let result_overflow = Blueprint::new(
            max_loc_plus_1,
            0,
            Bagging::ForwardFold,
            max_loc..max_loc_plus_1,
        );
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LEAVES"
        );
        assert!(matches!(
            result_overflow,
            Err(merkle::Error::LocationOverflow(_))
        ));
    }

    #[test]
    fn test_max_location_multi_proof() {
        let max_loc = Family::MAX_LEAVES;
        let result =
            nodes_required_for_multi_proof(max_loc, 0, Bagging::ForwardFold, &[max_loc - 1]);
        assert!(
            result.is_ok(),
            "Should be able to generate multi-proof for MAX_LEAVES"
        );

        // MAX_LEAVES + 1 should be rejected.
        let invalid_loc = max_loc + 1;
        let result_overflow =
            nodes_required_for_multi_proof(invalid_loc, 0, Bagging::ForwardFold, &[max_loc]);
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LEAVES in multi-proof"
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_sufficient() {
        // Verify that MAX_PROOF_DIGESTS_PER_ELEMENT (122) is sufficient for any single-element
        // proof in the largest valid MMR.
        //
        // MMR sizes follow: mmr_size(N) = 2*N - popcount(N) where N = leaf count.
        // The number of peaks equals popcount(N).
        //
        // To maximize peaks, we want N with maximum popcount. N = 2^62 - 1 has 62 one-bits:
        //   N = 0x3FFFFFFFFFFFFFFF = 2^0 + 2^1 + ... + 2^61
        //
        // This gives us 62 perfect binary trees with leaf counts 2^0, 2^1, ..., 2^61
        // and corresponding heights 0, 1, ..., 61.
        //
        // mmr_size(2^62 - 1) = 2*(2^62 - 1) - 62 = 2^63 - 2 - 62 = 2^63 - 64
        //
        // For a single-element proof in a tree of height h:
        //   - Path siblings from leaf to peak: h digests
        //   - Other peaks (not containing the element): (62 - 1) = 61 digests
        //   - Total: h + 61 digests
        //
        // Worst case: element in tallest tree (h = 61)
        //   - Path siblings: 61
        //   - Other peaks: 61
        //   - Total: 61 + 61 = 122 digests

        const NUM_PEAKS: usize = 62;
        const MAX_TREE_HEIGHT: usize = 61;
        const EXPECTED_WORST_CASE: usize = MAX_TREE_HEIGHT + (NUM_PEAKS - 1);

        let many_peaks_size = Position::new((1u64 << 63) - 64);
        assert!(
            many_peaks_size.is_valid_size(),
            "Size {many_peaks_size} should be a valid MMR size",
        );

        let peak_count = PeakIterator::new(many_peaks_size).count();
        assert_eq!(peak_count, NUM_PEAKS);

        // Verify the peak heights are 61, 60, ..., 1, 0 (from left to right)
        let peaks: Vec<_> = PeakIterator::new(many_peaks_size).collect();
        for (i, &(_pos, height)) in peaks.iter().enumerate() {
            let expected_height = (NUM_PEAKS - 1 - i) as u32;
            assert_eq!(
                height, expected_height,
                "Peak {i} should have height {expected_height}, got {height}",
            );
        }

        // Test location 0 (leftmost leaf, in tallest tree of height 61)
        // Expected: 61 path siblings + 61 other peaks = 122 digests
        let leaves = Location::try_from(many_peaks_size).unwrap();
        let loc = Location::new(0);
        let bp = Blueprint::new(leaves, 0, Bagging::ForwardFold, loc..loc + 1)
            .expect("should compute blueprint for location 0");
        let total_nodes = bp.fold_prefix.len() + bp.fetch_nodes.len();

        assert_eq!(
            total_nodes,
            EXPECTED_WORST_CASE,
            "Location 0 proof should require exactly {EXPECTED_WORST_CASE} digests (61 path + 61 peaks)",
        );

        // Test the rightmost leaf (in smallest tree of height 0, which is itself a peak)
        // Expected: 0 path siblings + 61 other peaks = 61 digests
        let last_leaf_loc = leaves - 1;
        let bp = Blueprint::new(
            leaves,
            0,
            Bagging::ForwardFold,
            last_leaf_loc..last_leaf_loc + 1,
        )
        .expect("should compute blueprint for last leaf");
        let total_nodes = bp.fold_prefix.len() + bp.fetch_nodes.len();

        let expected_last_leaf = NUM_PEAKS - 1;
        assert_eq!(
            total_nodes,
            expected_last_leaf,
            "Last leaf proof should require exactly {expected_last_leaf} digests (0 path + 61 peaks)",
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_is_maximum() {
        // For K peaks, the worst-case proof needs: (max_tree_height) + (K - 1) digests
        // With K peaks of heights K-1, K-2, ..., 0, this is (K-1) + (K-1) = 2*(K-1)
        //
        // To get K peaks, leaf count N must have exactly K bits set.
        // MMR size = 2*N - popcount(N) = 2*N - K
        //
        // For 63 peaks: N = 2^63 - 1 (63 bits set), size = 2*(2^63 - 1) - 63 = 2^64 - 65

        // This exceeds MAX_NODES, so is_valid_size() returns false.

        let n_for_63_peaks = (1u128 << 63) - 1;
        let size_for_63_peaks = 2 * n_for_63_peaks - 63; // = 2^64 - 65
        assert!(
            size_for_63_peaks > *Family::MAX_NODES as u128,
            "63 peaks requires size {size_for_63_peaks} > MAX_NODES",
        );

        let size_truncated = size_for_63_peaks as u64;
        assert!(
            !Position::new(size_truncated).is_valid_size(),
            "Size for 63 peaks should fail is_valid_size()"
        );
    }

    /// Regression test: pinned nodes that are sibling digests (not fold-prefix peaks) must be
    /// verified against the extracted proof digests. A 3-leaf MMR with start_loc=1 has a pinned
    /// node at position 0 (L0) which is a sibling within the range peak, not a fold-prefix peak.
    #[test]
    fn test_verify_proof_and_pinned_nodes_sibling_case() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new();
        let elements: Vec<Digest> = (0..3).map(test_digest).collect();
        let batch = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&mmr, &hasher)
        };
        mmr.apply_batch(&batch).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();

        // Proof for range [1, 3) -- fold prefix is empty, pinned node at position 0 is a sibling.
        let start_loc = Location::new(1);
        let proof = mmr
            .range_proof(&hasher, start_loc..Location::new(3), 0)
            .unwrap();

        let pinned: Vec<Digest> = mmr.nodes_to_pin(start_loc).into_values().collect();
        assert_eq!(pinned.len(), 1, "should have exactly one pinned node");

        // Correct pinned nodes must verify.
        assert!(
            proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[1..],
                start_loc,
                &pinned,
                &root,
                0
            ),
            "valid pinned nodes should verify"
        );

        // Wrong pinned digest must fail.
        let bad_pinned = vec![test_digest(99)];
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[1..],
                start_loc,
                &bad_pinned,
                &root,
                0,
            ),
            "wrong pinned digest should fail"
        );

        // Extra pinned node must fail.
        let extra_pinned = vec![pinned[0], test_digest(42)];
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[1..],
                start_loc,
                &extra_pinned,
                &root,
                0,
            ),
            "extra pinned node should fail"
        );

        // Empty pinned nodes must fail (start_loc > 0 requires at least one).
        assert!(
            !proof.verify_proof_and_pinned_nodes(&hasher, &elements[1..], start_loc, &[], &root, 0),
            "missing pinned nodes should fail"
        );
    }

    /// Test verify_proof_and_pinned_nodes when pinned nodes ARE fold-prefix peaks.
    #[test]
    fn test_verify_proof_and_pinned_nodes_fold_prefix_case() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new();
        // 10-leaf MMR: peaks at positions covering [0-7] and [8-9].
        // start_loc=8 puts the first peak entirely in the fold prefix.
        let elements: Vec<Digest> = (0..10).map(test_digest).collect();
        let batch = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&mmr, &hasher)
        };
        mmr.apply_batch(&batch).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();

        let start_loc = Location::new(8);
        let proof = mmr
            .range_proof(&hasher, start_loc..Location::new(10), 0)
            .unwrap();

        let pinned: Vec<Digest> = mmr.nodes_to_pin(start_loc).into_values().collect();
        assert_eq!(pinned.len(), 1, "should have one fold-prefix peak");

        assert!(
            proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[8..],
                start_loc,
                &pinned,
                &root,
                0
            ),
            "valid fold-prefix pinned nodes should verify"
        );

        // Wrong digest must fail.
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[8..],
                start_loc,
                &[test_digest(99)],
                &root,
                0,
            ),
            "wrong fold-prefix digest should fail"
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Family;
        use crate::merkle::proof::Proof;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Proof<Family, Sha256Digest>>,
        }
    }
}
