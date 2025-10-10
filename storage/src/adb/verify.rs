use crate::mmr::{
    proof, verification, verification::ProofStore, Error, Location, Position, Proof,
    StandardHasher as Standard,
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};
use core::ops::Range;

/// Verify that a [Proof] is valid for a range of operations and a target root.
pub fn verify_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: Location,
    operations: &[Op],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion(hasher, &elements, start_loc, target_root)
}

/// Extract pinned nodes from the [Proof] starting at `start_loc`.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if `start_loc + operations_len` > [crate::mmr::MAX_LOCATION].
pub fn extract_pinned_nodes<D: Digest>(
    proof: &Proof<D>,
    start_loc: Location,
    operations_len: u64,
) -> Result<Vec<D>, Error> {
    let Some(end_loc) = start_loc.checked_add(operations_len) else {
        return Err(Error::LocationOverflow(start_loc));
    };
    proof.extract_pinned_nodes(start_loc..end_loc)
}

/// Verify that a [Proof] is valid for a range of operations and extract all digests (and their positions)
/// in the range of the [Proof].
pub fn verify_proof_and_extract_digests<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: Location,
    operations: &[Op],
    target_root: &D,
) -> Result<Vec<(Position, D)>, Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion_and_extract_digests(hasher, &elements, start_loc, target_root)
}

/// Calculate the digests required to construct a [Proof] for a range of operations.
///
/// # Errors
///
/// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or an element in `range` >
/// [crate::mmr::MAX_LOCATION].
///
/// Returns [crate::mmr::Error::RangeOutOfBounds] if the last element position in `range`
/// is out of bounds for the MMR size.
pub fn digests_required_for_proof<D: Digest>(
    op_count: Location,
    range: Range<Location>,
) -> Result<Vec<Position>, crate::mmr::Error> {
    let mmr_size = Position::try_from(op_count)?;
    proof::nodes_required_for_range_proof(mmr_size, range)
}

/// Create a [Proof] from a op_count and a list of digests.
///
/// To compute the digests required for a [Proof], use [digests_required_for_proof].
///
/// # Errors
///
/// Returns [crate::mmr::Error::LocationOverflow] if `op_count` > [crate::mmr::MAX_LOCATION].
pub fn create_proof<D: Digest>(
    op_count: Location,
    digests: Vec<D>,
) -> Result<Proof<D>, crate::mmr::Error> {
    Ok(Proof::<D> {
        size: Position::try_from(op_count)?,
        digests,
    })
}

/// Verify a [Proof] and convert it into a [ProofStore].
pub fn create_proof_store<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: Location,
    operations: &[Op],
    root: &D,
) -> Result<ProofStore<D>, Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // Encode operations for verification
    let elements: Vec<Vec<u8>> = operations.iter().map(|op| op.encode().to_vec()).collect();

    // Create ProofStore by verifying the proof and extracting all digests
    ProofStore::new(hasher, proof, &elements, start_loc, root)
}

/// Create a [ProofStore] from a list of digests (output by [verify_proof_and_extract_digests]).
///
/// If you have not yet verified the proof, use [create_proof_store] instead.
pub fn create_proof_store_from_digests<D: Digest>(
    proof: &Proof<D>,
    digests: Vec<(Position, D)>,
) -> ProofStore<D> {
    ProofStore::new_from_digests(proof.size, digests)
}

/// Create a Multi-Proof for specific operations (identified by location) from a [ProofStore].
pub async fn create_multi_proof<D: Digest>(
    proof_store: &ProofStore<D>,
    locations: &[Location],
) -> Result<Proof<D>, Error> {
    // Generate the proof
    verification::multi_proof(proof_store, locations).await
}

/// Verify a Multi-Proof for operations at specific locations.
pub fn verify_multi_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    operations: &[(Location, Op)],
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
        .map(|(loc, op)| (op.encode(), *loc))
        .collect::<Vec<_>>();

    // Verify the proof
    proof.verify_multi_inclusion(hasher, &elements, target_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{iterator::nodes_to_pin, location::LocationRangeExt as _, mem::Mmr};
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
            let proof = mmr
                .range_proof(Location::new_unchecked(0)..Location::new_unchecked(3))
                .unwrap();

            // Verify the proof
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0), // start_loc
                &operations,
                &root,
            ));

            // Verify the proof with the wrong root
            let wrong_root = test_digest(99);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &operations,
                &wrong_root,
            ));

            // Verify the proof with the wrong operations
            let wrong_operations = vec![9, 10, 11];
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
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
            let start_loc = Location::new_unchecked(5u64);
            for op in &operations {
                let encoded = op.encode();
                mmr.add(&mut hasher, &encoded);
            }
            let root = mmr.root(&mut hasher);
            let proof = mmr
                .range_proof(Location::new_unchecked(5)..Location::new_unchecked(8))
                .unwrap();

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
                Location::new_unchecked(0), // wrong start_loc
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
            let start_loc = Location::new_unchecked(2);
            let operations_len = 4u64;
            let end_loc = start_loc + operations_len;
            let range = start_loc..end_loc;
            let proof = mmr.range_proof(range).unwrap();

            // Extract pinned nodes
            let pinned_nodes = extract_pinned_nodes(&proof, start_loc, operations_len);
            assert!(pinned_nodes.is_ok());
            let nodes = pinned_nodes.unwrap();
            assert!(!nodes.is_empty());

            // Verify the extracted nodes match what we expect from the proof
            let start_pos = Position::try_from(start_loc).unwrap();
            let expected_pinned: Vec<Position> = nodes_to_pin(start_pos).collect();
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
            let range = Location::new_unchecked(1)..Location::new_unchecked(4);
            let proof = mmr.range_proof(range.clone()).unwrap();

            // Verify and extract digests for subset of operations
            let result = verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                Location::new_unchecked(1), // start_loc
                &operations[range.to_usize_range()],
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
                Location::new_unchecked(1),
                &operations[range.to_usize_range()],
                &wrong_root,
            )
            .is_err());
        });
    }

    #[test_traced]
    fn test_create_proof() {
        const OP_COUNT: Location = Location::new_unchecked(15);

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new();

            // Build MMR with test operations

            let operations: Vec<u64> = (0..*OP_COUNT).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                positions.push(mmr.add(&mut hasher, &encoded));
            }
            let root = mmr.root(&mut hasher);

            // The size here is the number of leaves added (15 in this case)
            let start_loc = Location::new_unchecked(3u64);
            let end_loc = Location::new_unchecked(8u64);

            // Get required digests (note: range is exclusive, so end_loc + 1)
            let end_plus_one = end_loc.checked_add(1).expect("test location in bounds");
            let required_positions =
                digests_required_for_proof::<Digest>(OP_COUNT, start_loc..end_plus_one).unwrap();

            // Fetch the actual digests
            let mut digests = Vec::new();
            for pos in required_positions {
                if let Some(digest) = mmr.get_node(pos) {
                    digests.push(digest);
                }
            }

            // Construct proof
            let proof = create_proof(OP_COUNT, digests.clone()).expect("test locations valid");
            assert_eq!(proof.size, Position::try_from(OP_COUNT).unwrap());
            assert_eq!(proof.digests.len(), digests.len());

            assert!(verify_proof(
                &mut hasher,
                &proof,
                start_loc,
                &operations[*start_loc as usize..=*end_loc as usize],
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
            let op_count = 15;
            let operations: Vec<u64> = (0..op_count).collect();
            let mut positions = Vec::new();
            for op in &operations {
                let encoded = op.encode();
                let pos = mmr.add(&mut hasher, &encoded);
                positions.push(pos);
            }
            let root = mmr.root(&mut hasher);
            let range = Location::new_unchecked(0)..Location::new_unchecked(3);
            let proof = mmr.range_proof(range.clone()).unwrap();

            // Create proof store
            let result = create_proof_store(
                &mut hasher,
                &proof,
                range.start,                         // start_loc
                &operations[range.to_usize_range()], // Only the first 3 operations covered by the proof
                &root,
            );
            assert!(result.is_ok());
            let proof_store = result.unwrap();

            // Verify we can generate sub-proofs from the store
            let range = Location::new_unchecked(0)..Location::new_unchecked(2);
            let sub_proof = verification::range_proof(&proof_store, range.clone())
                .await
                .unwrap();

            // Verify the sub-proof
            assert!(verify_proof(
                &mut hasher,
                &sub_proof,
                range.start,
                &operations[range.to_usize_range()],
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
            let range = Location::new_unchecked(0)..Location::new_unchecked(2);
            let proof = mmr.range_proof(range).unwrap();

            // Should fail with invalid root
            let wrong_root = test_digest(99);
            assert!(create_proof_store(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &operations,
                &wrong_root
            )
            .is_err());
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
            let proof = mmr
                .range_proof(Location::new_unchecked(0)..Location::new_unchecked(3))
                .unwrap();

            // First verify and extract digests
            let digests = verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &operations,
                &root,
            )
            .unwrap();

            // Create proof store from digests
            let proof_store = create_proof_store_from_digests(&proof, digests);

            // Verify we can use the proof store
            let sub_proof = verification::range_proof(
                &proof_store,
                Location::new_unchecked(0)..Location::new_unchecked(2),
            )
            .await
            .unwrap();

            // Verify the sub-proof
            assert!(verify_proof(
                &mut hasher,
                &sub_proof,
                Location::new_unchecked(0),
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
            for op in &operations {
                let encoded = op.encode();
                mmr.add(&mut hasher, &encoded);
            }
            let root = mmr.root(&mut hasher);

            // Create proof for full range
            let proof = mmr
                .range_proof(Location::new_unchecked(0)..Location::new_unchecked(20))
                .unwrap();

            // Create proof store
            let proof_store = create_proof_store(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &operations,
                &root,
            )
            .unwrap();

            // Generate multi-proof for specific locations
            let target_locations = vec![
                Location::new_unchecked(2),
                Location::new_unchecked(5),
                Location::new_unchecked(10),
                Location::new_unchecked(15),
                Location::new_unchecked(18),
            ];
            let multi_proof = create_multi_proof(&proof_store, &target_locations)
                .await
                .unwrap();

            // Prepare operations for verification
            let selected_ops: Vec<(Location, u64)> = target_locations
                .iter()
                .map(|&loc| (loc, operations[*loc as usize]))
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
            let target_locations = vec![
                Location::new_unchecked(1),
                Location::new_unchecked(4),
                Location::new_unchecked(7),
            ];
            let multi_proof = verification::multi_proof(&mmr, &target_locations)
                .await
                .unwrap();

            // Verify with correct operations
            let selected_ops = vec![
                (Location::new_unchecked(1), operations[1]),
                (Location::new_unchecked(4), operations[4]),
                (Location::new_unchecked(7), operations[7]),
            ];
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &selected_ops,
                &root,
            ));

            // Verify fails with wrong operations
            let wrong_ops = vec![
                (Location::new_unchecked(1), 99),
                (Location::new_unchecked(4), operations[4]),
                (Location::new_unchecked(7), operations[7]),
            ];
            assert!(!verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &wrong_ops,
                &root,
            ));

            // Verify fails with wrong locations
            let wrong_locations = vec![
                (Location::new_unchecked(0), operations[1]),
                (Location::new_unchecked(4), operations[4]),
                (Location::new_unchecked(7), operations[7]),
            ];
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
            let empty_mmr = Mmr::new();
            let empty_root = empty_mmr.root(&mut hasher);

            // Empty proof should verify against an empty MMR/database.
            let empty_proof = Proof::default();
            assert!(verify_multi_proof(
                &mut hasher,
                &empty_proof,
                &[] as &[(Location, u64)],
                &empty_root,
            ));

            // Proofs over empty locations should otherwise not be allowed.
            assert!(matches!(
                verification::multi_proof(&empty_mmr, &[]).await,
                Err(Error::Empty)
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
            let proof = mmr
                .range_proof(Location::new_unchecked(0)..Location::new_unchecked(3))
                .unwrap();
            let proof_store = create_proof_store(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &operations,
                &root,
            )
            .unwrap();

            // Generate multi-proof for single element
            let multi_proof = create_multi_proof(&proof_store, &[Location::new_unchecked(1)])
                .await
                .unwrap();

            // Verify single element
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &[(Location::new_unchecked(1), operations[1])],
                &root,
            ));
        });
    }
}
