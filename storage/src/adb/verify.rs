use crate::mmr::{
    hasher::Standard,
    iterator::leaf_num_to_pos,
    verification::{Proof, ProofStore},
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};

/// Verify that a [Proof] is valid for a range of operations and a target root
pub fn verify_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let start_pos = leaf_num_to_pos(start_loc);
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion(hasher, &elements, start_pos, target_root)
}

/// Extract pinned nodes from the [Proof] starting at `start_loc`.
pub fn extract_pinned_nodes<D: Digest>(
    proof: &Proof<D>,
    start_loc: u64,
    operations_len: u64,
) -> Result<Vec<D>, crate::mmr::Error> {
    let start_pos_mmr = leaf_num_to_pos(start_loc);
    let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
    proof.extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
}

/// Verify that a [Proof] is valid for a range of operations and extract all digests (and their positions)
/// in the range of the [Proof].
pub fn verify_proof_and_extract_digests<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    target_root: &D,
) -> Result<Vec<(u64, D)>, crate::mmr::Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let start_pos = leaf_num_to_pos(start_loc);
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion_and_extract_digests(hasher, &elements, start_pos, target_root)
}

/// Calculate the digests required to construct a [Proof] for a range of operations.
pub fn digests_required_for_proof<D: Digest>(size: u64, start_loc: u64, end_loc: u64) -> Vec<u64> {
    let size = leaf_num_to_pos(size);
    let start_pos = leaf_num_to_pos(start_loc);
    let end_pos = leaf_num_to_pos(end_loc);
    Proof::<D>::nodes_required_for_range_proof(size, start_pos, end_pos)
}

/// Create a [Proof] from a size and a list of digests.
///
/// To compute the digests required for a [Proof], use [digests_required_for_proof].
pub fn create_proof<D: Digest>(size: u64, digests: Vec<D>) -> Proof<D> {
    let size = leaf_num_to_pos(size);
    Proof::<D> { size, digests }
}

/// Verify a [Proof] and convert it into a [ProofStore].
pub fn create_proof_store<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    root: &D,
) -> Result<ProofStore<D>, crate::mmr::Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // Convert operation location to MMR position
    let start_pos = leaf_num_to_pos(start_loc);

    // Encode operations for verification
    let elements: Vec<Vec<u8>> = operations.iter().map(|op| op.encode().to_vec()).collect();

    // Create ProofStore by verifying the proof and extracting all digests
    ProofStore::new(hasher, proof, &elements, start_pos, root)
}

/// Create a [ProofStore] from a list of digests (output by [verify_proof_and_extract_digests]).
///
/// If you have not yet verified the proof, use [create_proof_store] instead.
pub fn create_proof_store_from_digests<D: Digest>(
    proof: &Proof<D>,
    digests: Vec<(u64, D)>,
) -> ProofStore<D> {
    ProofStore::new_from_digests(proof.size, digests)
}

/// Create a Multi-Proof for specific operations (identified by location) from a [ProofStore].
pub async fn create_multi_proof<D: Digest>(
    proof_store: &ProofStore<D>,
    locations: &[u64],
) -> Result<Proof<D>, crate::mmr::Error> {
    // Convert locations to MMR positions
    let positions: Vec<u64> = locations.iter().map(|&loc| leaf_num_to_pos(loc)).collect();

    // Generate the proof
    Proof::multi_proof(proof_store, &positions).await
}

/// Verify a Multi-Proof for operations at specific locations.
pub fn verify_multi_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    operations: &[(u64, Op)],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // Encode operations and convert locations to positions
    let elements = operations
        .iter()
        .map(|(loc, op)| (op.encode(), leaf_num_to_pos(*loc)))
        .collect::<Vec<_>>();

    // Verify the proof
    proof.verify_multi_inclusion(hasher, &elements, target_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::mem::Mmr;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    fn test_hasher() -> Standard<Sha256> {
        Standard::new()
    }

    #[test_traced]
    fn test_verify_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some operations to the MMR
            let operations = vec![1, 2, 3];
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);

            // Generate proof for all operations
            let proof = mmr.range_proof(positions[0], positions[2]).await.unwrap();

            // Verify the proof
            assert!(verify_proof(
                &mut hasher,
                &proof,
                0, // start_loc
                &operations,
                &root,
            ));

            // Verify the proof with the wrong root
            let wrong_root = test_digest(99);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                0,
                &operations,
                &wrong_root,
            ));

            // Verify the proof with the wrong operations
            let wrong_operations = vec![9, 10, 11];
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                0,
                &wrong_operations,
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_verify_proof_with_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some initial operations (that we won't prove)
            for i in 0u64..5 {
                mmr.add(&mut hasher, &i.encode());
            }

            // Add operations we want to prove (starting at location 5)
            let operations = vec![10, 11, 12];
            let start_loc = 5u64;
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);
            let proof = mmr.range_proof(positions[0], positions[2]).await.unwrap();

            // Verify with correct start location
            assert!(verify_proof(
                &mut hasher,
                &proof,
                start_loc,
                &operations,
                &root,
            ));

            // Verify fails with wrong start location
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                0, // wrong start_loc
                &operations,
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_extract_pinned_nodes() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add elements
            let mut positions = Vec::new();
            for i in 0u64..10 {
                positions.push(mmr.add(&mut hasher, &i.encode()));
            }

            // Generate proof for a range
            let start_loc = 2u64;
            let operations_len = 4u64;
            let end_loc = start_loc + operations_len - 1;
            let proof = mmr
                .range_proof(positions[start_loc as usize], positions[end_loc as usize])
                .await
                .unwrap();

            // Extract pinned nodes
            let pinned_nodes = extract_pinned_nodes(&proof, start_loc, operations_len);
            assert!(pinned_nodes.is_ok());
            let nodes = pinned_nodes.unwrap();
            assert!(!nodes.is_empty());

            // Verify the extracted nodes match what we expect from the proof
            let start_pos = leaf_num_to_pos(start_loc);
            let expected_pinned: Vec<u64> = Proof::<Digest>::nodes_to_pin(start_pos).collect();
            assert_eq!(nodes.len(), expected_pinned.len());
        });
    }

    #[test_traced]
    fn test_verify_proof_and_extract_digests() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some operations to the MMR
            let operations = vec![1, 2, 3, 4];
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);
            let proof = mmr.range_proof(positions[1], positions[3]).await.unwrap();

            // Verify and extract digests for subset of operations
            let result = verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                1, // start_loc
                &operations[1..4],
                &root,
            );
            assert!(result.is_ok());
            let digests = result.unwrap();
            assert!(!digests.is_empty());

            // Should fail with wrong root
            let wrong_root = test_digest(99);
            assert!(verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                1,
                &operations[1..4],
                &wrong_root,
            )
            .is_err());
        });
    }

    #[test_traced]
    fn test_create_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Build MMR with test operations
            let operations: Vec<u64> = (0..15).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                positions.push(mmr.add(&mut hasher, &encoded));
            }
            let root = mmr.root(&mut hasher);

            // The size here is the number of leaves added (15 in this case)
            let size = 15;
            let start_loc = 3u64;
            let end_loc = 7u64;

            // Get required digests
            let required_positions = digests_required_for_proof::<Digest>(size, start_loc, end_loc);

            // Fetch the actual digests
            let mut digests = Vec::new();
            for pos in required_positions {
                if let Some(digest) = mmr.get_node(pos) {
                    digests.push(digest);
                }
            }

            // Construct proof
            let proof = create_proof(size, digests.clone());
            assert_eq!(proof.size, leaf_num_to_pos(size));
            assert_eq!(proof.digests.len(), digests.len());

            // Verify the constructed proof works correctly
            assert!(verify_proof(
                &mut hasher,
                &proof,
                start_loc,
                &operations[start_loc as usize..=end_loc as usize],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_create_proof_store() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some operations to the MMR
            let operations: Vec<u64> = (0..15).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);
            let proof = mmr.range_proof(positions[0], positions[2]).await.unwrap();

            // Create proof store
            let result = create_proof_store(
                &mut hasher,
                &proof,
                0,                 // start_loc
                &operations[0..3], // Only the first 3 operations covered by the proof
                &root,
            );
            assert!(result.is_ok());
            let proof_store = result.unwrap();

            // Verify we can generate sub-proofs from the store
            let sub_proof = Proof::<Digest>::range_proof(&proof_store, positions[0], positions[1])
                .await
                .unwrap();

            // Verify the sub-proof
            assert!(verify_proof(
                &mut hasher,
                &sub_proof,
                0,
                &operations[0..2],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_create_proof_store_invalid_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some operations to the MMR
            let operations = vec![1, 2, 3];
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let proof = mmr.range_proof(positions[0], positions[1]).await.unwrap();

            // Should fail with invalid root
            let wrong_root = test_digest(99);
            assert!(create_proof_store(&mut hasher, &proof, 0, &operations, &wrong_root).is_err());
        });
    }

    #[test_traced]
    fn test_create_proof_store_from_digests() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add some operations to the MMR
            let operations = vec![1, 2, 3];
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);
            let proof = mmr.range_proof(positions[0], positions[2]).await.unwrap();

            // First verify and extract digests
            let digests =
                verify_proof_and_extract_digests(&mut hasher, &proof, 0, &operations, &root)
                    .unwrap();

            // Create proof store from digests
            let proof_store = create_proof_store_from_digests(&proof, digests);

            // Verify we can use the proof store
            let sub_proof = Proof::<Digest>::range_proof(&proof_store, positions[0], positions[1])
                .await
                .unwrap();

            // Verify the sub-proof
            assert!(verify_proof(
                &mut hasher,
                &sub_proof,
                0,
                &operations[0..2],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_create_multi_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add operations to the MMR
            let operations: Vec<u64> = (0..20).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);

            // Create proof for full range
            let proof = mmr.range_proof(positions[0], positions[19]).await.unwrap();

            // Create proof store
            let proof_store =
                create_proof_store(&mut hasher, &proof, 0, &operations, &root).unwrap();

            // Generate multi-proof for specific locations
            let target_locations = vec![2, 5, 10, 15, 18];
            let multi_proof = create_multi_proof(&proof_store, &target_locations)
                .await
                .unwrap();

            // Prepare operations for verification
            let selected_ops: Vec<(u64, u64)> = target_locations
                .iter()
                .map(|&loc| (loc, operations[loc as usize]))
                .collect();

            // Verify the multi-proof
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &selected_ops,
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_verify_multi_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add operations to the MMR
            let operations: Vec<u64> = (0..10).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);

            // Generate multi-proof directly from MMR
            let target_positions = vec![positions[1], positions[4], positions[7]];
            let multi_proof = Proof::multi_proof(&mmr, &target_positions).await.unwrap();

            // Verify with correct operations
            let selected_ops = vec![(1, operations[1]), (4, operations[4]), (7, operations[7])];
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &selected_ops,
                &root,
            ));

            // Verify fails with wrong operations
            let wrong_ops = vec![(1, 99), (4, operations[4]), (7, operations[7])];
            assert!(!verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &wrong_ops,
                &root,
            ));

            // Verify fails with wrong locations
            let wrong_locations = vec![(0, operations[1]), (4, operations[4]), (7, operations[7])];
            assert!(!verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &wrong_locations,
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_multi_proof_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();

            // Test with empty MMR (which is the correct case for empty proof)
            let empty_mmr = Mmr::new();
            let empty_root = empty_mmr.root(&mut hasher);
            let empty_proof = Proof::multi_proof(&empty_mmr, &[]).await.unwrap();
            assert!(empty_proof.verify_multi_inclusion(
                &mut hasher,
                &[] as &[(&[u8], u64)],
                &empty_root,
            ));

            // Also test that empty proof with non-empty MMR
            let mut mmr = Mmr::new();
            for i in 0..5 {
                let data = vec![i];
                mmr.add(&mut hasher, &data);
            }
            let multi_proof = Proof::multi_proof(&mmr, &[]).await.unwrap();

            // Empty multi-proof should have the right size but no digests
            assert_eq!(multi_proof.size, mmr.size());
            assert!(multi_proof.digests.is_empty());

            // Verify the empty proof
            assert!(verify_multi_proof(
                &mut hasher,
                &empty_proof,
                &[] as &[(u64, u64)],
                &empty_root,
            ));
        });
    }

    #[test_traced]
    fn test_multi_proof_single_element() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Add operations to the MMR
            let operations = vec![1, 2, 3];
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);

            // Create proof store for all elements
            let proof = mmr.range_proof(positions[0], positions[2]).await.unwrap();
            let proof_store =
                create_proof_store(&mut hasher, &proof, 0, &operations, &root).unwrap();

            // Generate multi-proof for single element
            let multi_proof = create_multi_proof(&proof_store, &[1]).await.unwrap();

            // Verify single element
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &[(1, operations[1])],
                &root,
            ));
        });
    }
}
