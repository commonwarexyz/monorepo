use crate::merkle::{
    hasher::Standard, verification::ProofStore, Error, Family, Location, Position, Proof,
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};

/// Verify that a [Proof] is valid for a range of operations and a target root.
pub fn verify_proof<F, Op, H, D>(
    hasher: &Standard<H>,
    proof: &Proof<F, D>,
    start_loc: Location<F>,
    operations: &[Op],
    target_root: &D,
) -> bool
where
    F: Family,
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion(hasher, &elements, start_loc, target_root)
}

/// Verify that both a [Proof] and a set of pinned nodes are valid with respect to a target root.
///
/// The `pinned_nodes` are the individual peak digests before the proven range (as returned by
/// `nodes_to_pin`). When `start_loc` is 0, `pinned_nodes` must be empty.
pub fn verify_proof_and_pinned_nodes<F, Op, H, D>(
    hasher: &Standard<H>,
    proof: &Proof<F, D>,
    start_loc: Location<F>,
    operations: &[Op],
    pinned_nodes: &[D],
    target_root: &D,
) -> bool
where
    F: Family,
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_proof_and_pinned_nodes(hasher, &elements, start_loc, pinned_nodes, target_root)
}

/// Verify that a [Proof] is valid for a range of operations and extract all digests (and their
/// positions) in the range of the [Proof].
pub fn verify_proof_and_extract_digests<F, Op, H, D>(
    hasher: &Standard<H>,
    proof: &Proof<F, D>,
    start_loc: Location<F>,
    operations: &[Op],
    target_root: &D,
) -> Result<Vec<(Position<F>, D)>, Error<F>>
where
    F: Family,
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion_and_extract_digests(hasher, &elements, start_loc, target_root)
}

/// Verify a [Proof] and convert it into a [ProofStore].
pub fn create_proof_store<F, Op, H, D>(
    hasher: &Standard<H>,
    proof: &Proof<F, D>,
    start_loc: Location<F>,
    operations: &[Op],
    root: &D,
) -> Result<ProofStore<F, D>, Error<F>>
where
    F: Family,
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    ProofStore::new(hasher, proof, &elements, start_loc, root)
}

/// Create a Multi-Proof for specific operations (identified by location) from a [ProofStore].
///
/// `peaks` must contain any peak digests that fall in the fold prefix of the original proof
/// (peaks entirely before the original range's start location). If the original range started
/// at location 0, pass an empty slice.
pub fn create_multi_proof<F, D>(
    proof_store: &ProofStore<F, D>,
    locations: &[Location<F>],
    peaks: &[(Position<F>, D)],
) -> Result<Proof<F, D>, Error<F>>
where
    F: Family,
    D: Digest,
{
    proof_store.multi_proof(locations, peaks)
}

/// Verify a Multi-Proof for operations at specific locations.
pub fn verify_multi_proof<F, Op, H, D>(
    hasher: &Standard<H>,
    proof: &Proof<F, D>,
    operations: &[(Location<F>, Op)],
    target_root: &D,
) -> bool
where
    F: Family,
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations
        .iter()
        .map(|(loc, op)| (op.encode(), *loc))
        .collect::<Vec<_>>();
    proof.verify_multi_inclusion(hasher, &elements, target_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{mem::Mem, LocationRangeExt as _},
        mmb, mmr,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    fn test_hasher() -> Standard<Sha256> {
        Standard::new()
    }

    // ---- Generic inner functions for tests that work on both MMR and MMB ----

    fn verify_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();

        // Generate proof for all operations
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(0)..Location::<F>::new(3))
            .unwrap();

        // Verify the proof
        assert!(verify_proof(
            &hasher,
            &proof,
            Location::<F>::new(0), // start_loc
            &operations,
            root,
        ));

        // Verify the proof with the wrong root
        let wrong_root = test_digest(99);
        assert!(!verify_proof(
            &hasher,
            &proof,
            Location::<F>::new(0),
            &operations,
            &wrong_root,
        ));

        // Verify the proof with the wrong operations
        let wrong_operations = vec![9, 10, 11];
        assert!(!verify_proof(
            &hasher,
            &proof,
            Location::<F>::new(0),
            &wrong_operations,
            root,
        ));
    }

    #[test_traced]
    fn test_verify_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_inner::<mmb::Family>() });
    }

    fn verify_proof_with_offset_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        let operations = vec![10, 11, 12];
        {
            // Add some initial operations (that we won't prove)
            let mut batch = merkle.new_batch();
            for i in 0u64..5 {
                batch = batch.add(&hasher, &i.encode());
            }

            // Add operations we want to prove (starting at location 5)
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let start_loc = Location::<F>::new(5u64);
        let root = merkle.root();
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(5)..Location::<F>::new(8))
            .unwrap();

        // Verify with correct start location
        assert!(verify_proof(&hasher, &proof, start_loc, &operations, root,));

        // Verify fails with wrong start location
        assert!(!verify_proof(
            &hasher,
            &proof,
            Location::<F>::new(0), // wrong start_loc
            &operations,
            root,
        ));
    }

    #[test_traced]
    fn test_verify_proof_with_offset_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_with_offset_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_proof_with_offset_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_with_offset_inner::<mmb::Family>() });
    }

    fn verify_proof_and_extract_digests_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3, 4];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();
        let range = Location::<F>::new(1)..Location::<F>::new(4);
        let proof = merkle.range_proof(&hasher, range.clone()).unwrap();

        // Verify and extract digests for subset of operations
        let result = verify_proof_and_extract_digests(
            &hasher,
            &proof,
            Location::<F>::new(1), // start_loc
            &operations[range.to_usize_range()],
            root,
        );
        assert!(result.is_ok());
        let digests = result.unwrap();
        assert!(!digests.is_empty());

        // Should fail with wrong root
        let wrong_root = test_digest(99);
        assert!(verify_proof_and_extract_digests(
            &hasher,
            &proof,
            Location::<F>::new(1),
            &operations[range.to_usize_range()],
            &wrong_root,
        )
        .is_err());
    }

    #[test_traced]
    fn test_verify_proof_and_extract_digests_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_and_extract_digests_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_proof_and_extract_digests_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_proof_and_extract_digests_inner::<mmb::Family>() });
    }

    fn create_proof_store_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add some operations to the merkle structure
        let op_count = 15;
        let operations: Vec<u64> = (0..op_count).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();
        let range = Location::<F>::new(0)..Location::<F>::new(3);
        let proof = merkle.range_proof(&hasher, range.clone()).unwrap();

        // Create proof store
        let result = create_proof_store(
            &hasher,
            &proof,
            range.start,                         // start_loc
            &operations[range.to_usize_range()], // Only the first 3 operations covered by the proof
            root,
        );
        assert!(result.is_ok());
        let proof_store = result.unwrap();

        // Verify we can generate sub-proofs from the store
        let range = Location::<F>::new(0)..Location::<F>::new(2);
        let sub_proof = proof_store.range_proof(&hasher, range.clone()).unwrap();

        // Verify the sub-proof
        assert!(verify_proof(
            &hasher,
            &sub_proof,
            range.start,
            &operations[range.to_usize_range()],
            root,
        ));
    }

    #[test_traced]
    fn test_create_proof_store_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_proof_store_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_create_proof_store_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_proof_store_inner::<mmb::Family>() });
    }

    fn create_proof_store_invalid_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let range = Location::<F>::new(0)..Location::<F>::new(2);
        let proof = merkle.range_proof(&hasher, range).unwrap();

        // Should fail with invalid root
        let wrong_root = test_digest(99);
        assert!(create_proof_store(
            &hasher,
            &proof,
            Location::<F>::new(0),
            &operations,
            &wrong_root,
        )
        .is_err());
    }

    #[test_traced]
    fn test_create_proof_store_invalid_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_proof_store_invalid_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_create_proof_store_invalid_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_proof_store_invalid_proof_inner::<mmb::Family>() });
    }

    fn create_multi_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add operations to the merkle structure
        let operations: Vec<u64> = (0..20).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();

        // Create proof for full range
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(0)..Location::<F>::new(20))
            .unwrap();

        // Create proof store
        let proof_store =
            create_proof_store(&hasher, &proof, Location::<F>::new(0), &operations, root).unwrap();

        // Generate multi-proof for specific locations
        let target_locations = vec![
            Location::<F>::new(2),
            Location::<F>::new(5),
            Location::<F>::new(10),
            Location::<F>::new(15),
            Location::<F>::new(18),
        ];
        let multi_proof = create_multi_proof(&proof_store, &target_locations, &[]).unwrap();

        // Prepare operations for verification
        let selected_ops: Vec<(Location<F>, u64)> = target_locations
            .iter()
            .map(|&loc| (loc, operations[*loc as usize]))
            .collect();

        // Verify the multi-proof
        assert!(verify_multi_proof(
            &hasher,
            &multi_proof,
            &selected_ops,
            root,
        ));
    }

    #[test_traced]
    fn test_create_multi_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_multi_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_create_multi_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { create_multi_proof_inner::<mmb::Family>() });
    }

    fn create_multi_proof_with_fold_prefix_peaks_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Build a merkle structure with peaks covering locations 0-31, 32-47, and 48.
        let operations: Vec<u64> = (0..49).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                batch = batch.add(&hasher, &op.encode());
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();

        // Proof store starts at 32, so the first peak is folded into the proof prefix.
        let range = Location::<F>::new(32)..Location::<F>::new(49);
        let proof = merkle.range_proof(&hasher, range.clone()).unwrap();
        let proof_store = create_proof_store(
            &hasher,
            &proof,
            range.start,
            &operations[range.to_usize_range()],
            root,
        )
        .unwrap();

        let target_locations = vec![Location::<F>::new(33), Location::<F>::new(48)];

        // Without the folded-prefix peaks, multi-proof generation should fail.
        // Walk peaks tracking a leaf cursor to find those entirely before the range start.
        let mut leaf_cursor = Location::<F>::new(0);
        let fold_prefix_peaks: Vec<_> = F::peaks(Position::<F>::try_from(merkle.leaves()).unwrap())
            .take_while(|(_, height)| {
                let leaf_end = leaf_cursor + (1u64 << height);
                let before = leaf_end <= range.start;
                if before {
                    leaf_cursor = leaf_end;
                }
                before
            })
            .map(|(peak_pos, _)| (peak_pos, merkle.get_node(peak_pos).unwrap()))
            .collect();
        assert!(!fold_prefix_peaks.is_empty());

        let missing_peaks = create_multi_proof(&proof_store, &target_locations, &[]);
        assert!(matches!(
            missing_peaks,
            Err(crate::merkle::Error::ElementPruned(pos)) if pos == fold_prefix_peaks[0].0
        ));

        // Supplying the required peaks should produce a valid multi-proof.
        let multi_proof =
            create_multi_proof(&proof_store, &target_locations, &fold_prefix_peaks).unwrap();
        let selected_ops: Vec<(Location<F>, u64)> = target_locations
            .iter()
            .map(|&loc| (loc, operations[*loc as usize]))
            .collect();
        assert!(verify_multi_proof(
            &hasher,
            &multi_proof,
            &selected_ops,
            root,
        ));
    }

    #[test_traced]
    fn test_create_multi_proof_with_fold_prefix_peaks_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            create_multi_proof_with_fold_prefix_peaks_inner::<mmr::Family>()
        });
    }

    #[test_traced]
    fn test_create_multi_proof_with_fold_prefix_peaks_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            create_multi_proof_with_fold_prefix_peaks_inner::<mmb::Family>()
        });
    }

    fn verify_multi_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add operations to the merkle structure
        let operations: Vec<u64> = (0..10).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();

        // Generate multi-proof via range proof -> proof store -> multi-proof
        let target_locations = vec![
            Location::<F>::new(1),
            Location::<F>::new(4),
            Location::<F>::new(7),
        ];
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(0)..merkle.leaves())
            .unwrap();
        let proof_store =
            create_proof_store(&hasher, &proof, Location::<F>::new(0), &operations, root).unwrap();
        let multi_proof = create_multi_proof(&proof_store, &target_locations, &[]).unwrap();

        // Verify with correct operations
        let selected_ops = vec![
            (Location::<F>::new(1), operations[1]),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(verify_multi_proof(
            &hasher,
            &multi_proof,
            &selected_ops,
            root,
        ));

        // Verify fails with wrong operations
        let wrong_ops = vec![
            (Location::<F>::new(1), 99),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(!verify_multi_proof(&hasher, &multi_proof, &wrong_ops, root,));

        // Verify fails with wrong locations
        let wrong_locations = vec![
            (Location::<F>::new(0), operations[1]),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(!verify_multi_proof(
            &hasher,
            &multi_proof,
            &wrong_locations,
            root,
        ));
    }

    #[test_traced]
    fn test_verify_multi_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_multi_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_multi_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_multi_proof_inner::<mmb::Family>() });
    }

    fn multi_proof_empty_inner<F: Family>() {
        let hasher = test_hasher();
        let empty_merkle = Mem::<F, Digest>::new(&hasher);
        let empty_root = empty_merkle.root();

        // Empty proof should verify against an empty merkle structure.
        let empty_proof = Proof::default();
        assert!(verify_multi_proof(
            &hasher,
            &empty_proof,
            &[] as &[(Location<F>, u64)],
            empty_root,
        ));

        // Proofs over empty locations should otherwise not be allowed.
        let mut merkle = Mem::<F, Digest>::new(&hasher);
        let operations: Vec<u64> = (0..5).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                batch = batch.add(&hasher, &op.encode());
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(0)..merkle.leaves())
            .unwrap();
        let proof_store =
            create_proof_store(&hasher, &proof, Location::<F>::new(0), &operations, root).unwrap();
        assert!(matches!(
            create_multi_proof(&proof_store, &[], &[]),
            Err(crate::merkle::Error::Empty)
        ));
    }

    #[test_traced]
    fn test_multi_proof_empty_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_empty_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_multi_proof_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_empty_inner::<mmb::Family>() });
    }

    fn multi_proof_single_element_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new(&hasher);

        // Add operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&hasher, &merkle);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root();

        // Create proof store for all elements
        let proof = merkle
            .range_proof(&hasher, Location::<F>::new(0)..Location::<F>::new(3))
            .unwrap();
        let proof_store =
            create_proof_store(&hasher, &proof, Location::<F>::new(0), &operations, root).unwrap();

        // Generate multi-proof for single element
        let multi_proof = create_multi_proof(&proof_store, &[Location::<F>::new(1)], &[]).unwrap();

        // Verify single element
        assert!(verify_multi_proof(
            &hasher,
            &multi_proof,
            &[(Location::<F>::new(1), operations[1])],
            root,
        ));
    }

    #[test_traced]
    fn test_multi_proof_single_element_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_single_element_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_multi_proof_single_element_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_single_element_inner::<mmb::Family>() });
    }
}
