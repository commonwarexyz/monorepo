use crate::mmr::{
    verification::ProofStore, Error, Location, Position, Proof, StandardHasher as Standard,
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};

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

/// Verify that both a [Proof] and a set of pinned nodes are valid with respect to a target root.
///
/// The `pinned_nodes` are the individual peak digests before the proven range (as returned by
/// `nodes_to_pin`). When `start_loc` is 0, `pinned_nodes` must be empty.
pub fn verify_proof_and_pinned_nodes<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: Location,
    operations: &[Op],
    pinned_nodes: &[D],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_proof_and_pinned_nodes(hasher, &elements, start_loc, pinned_nodes, target_root)
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
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();

    // Create ProofStore by verifying the proof and extracting all digests
    ProofStore::new(hasher, proof, &elements, start_loc, root)
}

/// Create a Multi-Proof for specific operations (identified by location) from a [ProofStore].
///
/// `peaks` must contain any peak digests that fall in the fold prefix of the original proof
/// (peaks entirely before the original range's start location). If the original range started
/// at location 0, pass an empty slice.
pub fn create_multi_proof<D: Digest>(
    proof_store: &ProofStore<D>,
    locations: &[Location],
    peaks: &[(Position, D)],
) -> Result<Proof<D>, Error> {
    proof_store.multi_proof(locations, peaks)
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
    use crate::mmr::{location::LocationRangeExt as _, mem::Mmr, verification};
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
            let mut mmr = Mmr::new(&mut hasher);

            // Add some operations to the MMR
            let operations = vec![1, 2, 3];
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();

            // Generate proof for all operations
            let proof = mmr
                .range_proof(&mut hasher, Location::new(0)..Location::new(3))
                .unwrap();

            // Verify the proof
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new(0), // start_loc
                &operations,
                root,
            ));

            // Verify the proof with the wrong root
            let wrong_root = test_digest(99);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new(0),
                &operations,
                &wrong_root,
            ));

            // Verify the proof with the wrong operations
            let wrong_operations = vec![9, 10, 11];
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new(0),
                &wrong_operations,
                root,
            ));
        });
    }

    #[test_traced]
    fn test_verify_proof_with_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            let operations = vec![10, 11, 12];
            {
                // Add some initial operations (that we won't prove)
                let mut batch = mmr.new_batch();
                for i in 0u64..5 {
                    batch = batch.add(&mut hasher, &i.encode());
                }

                // Add operations we want to prove (starting at location 5)
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let start_loc = Location::new(5u64);
            let root = mmr.root();
            let proof = mmr
                .range_proof(&mut hasher, Location::new(5)..Location::new(8))
                .unwrap();

            // Verify with correct start location
            assert!(verify_proof(
                &mut hasher,
                &proof,
                start_loc,
                &operations,
                root,
            ));

            // Verify fails with wrong start location
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new(0), // wrong start_loc
                &operations,
                root,
            ));
        });
    }

    #[test_traced]
    fn test_verify_proof_and_extract_digests() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Add some operations to the MMR
            let operations = vec![1, 2, 3, 4];
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();
            let range = Location::new(1)..Location::new(4);
            let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();

            // Verify and extract digests for subset of operations
            let result = verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                Location::new(1), // start_loc
                &operations[range.to_usize_range()],
                root,
            );
            assert!(result.is_ok());
            let digests = result.unwrap();
            assert!(!digests.is_empty());

            // Should fail with wrong root
            let wrong_root = test_digest(99);
            assert!(verify_proof_and_extract_digests(
                &mut hasher,
                &proof,
                Location::new(1),
                &operations[range.to_usize_range()],
                &wrong_root,
            )
            .is_err());
        });
    }

    #[test_traced]
    fn test_create_proof_store() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Add some operations to the MMR
            let op_count = 15;
            let operations: Vec<u64> = (0..op_count).collect();
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();
            let range = Location::new(0)..Location::new(3);
            let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();

            // Create proof store
            let result = create_proof_store(
                &mut hasher,
                &proof,
                range.start,                         // start_loc
                &operations[range.to_usize_range()], // Only the first 3 operations covered by the proof
                root,
            );
            assert!(result.is_ok());
            let proof_store = result.unwrap();

            // Verify we can generate sub-proofs from the store
            let range = Location::new(0)..Location::new(2);
            let sub_proof = proof_store.range_proof(&mut hasher, range.clone()).unwrap();

            // Verify the sub-proof
            assert!(verify_proof(
                &mut hasher,
                &sub_proof,
                range.start,
                &operations[range.to_usize_range()],
                root,
            ));
        });
    }

    #[test_traced]
    fn test_create_proof_store_invalid_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Add some operations to the MMR
            let operations = vec![1, 2, 3];
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let range = Location::new(0)..Location::new(2);
            let proof = mmr.range_proof(&mut hasher, range).unwrap();

            // Should fail with invalid root
            let wrong_root = test_digest(99);
            assert!(create_proof_store(
                &mut hasher,
                &proof,
                Location::new(0),
                &operations,
                &wrong_root,
            )
            .is_err());
        });
    }

    #[test_traced]
    fn test_create_multi_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Add operations to the MMR
            let operations: Vec<u64> = (0..20).collect();
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();

            // Create proof for full range
            let proof = mmr
                .range_proof(&mut hasher, Location::new(0)..Location::new(20))
                .unwrap();

            // Create proof store
            let proof_store =
                create_proof_store(&mut hasher, &proof, Location::new(0), &operations, root)
                    .unwrap();

            // Generate multi-proof for specific locations
            let target_locations = vec![
                Location::new(2),
                Location::new(5),
                Location::new(10),
                Location::new(15),
                Location::new(18),
            ];
            let multi_proof = create_multi_proof(&proof_store, &target_locations, &[]).unwrap();

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
                root,
            ));
        });
    }

    #[test_traced]
    fn test_create_multi_proof_with_fold_prefix_peaks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Build an MMR with peaks covering locations 0-31, 32-47, and 48.
            let operations: Vec<u64> = (0..49).collect();
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    batch = batch.add(&mut hasher, &op.encode());
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();

            // Proof store starts at 32, so the first peak is folded into the proof prefix.
            let range = Location::new(32)..Location::new(49);
            let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
            let proof_store = create_proof_store(
                &mut hasher,
                &proof,
                range.start,
                &operations[range.to_usize_range()],
                root,
            )
            .unwrap();

            let target_locations = vec![Location::new(33), Location::new(48)];

            // Without the folded-prefix peaks, multi-proof generation should fail.
            let start_pos = Position::try_from(range.start).unwrap();
            let fold_prefix_peaks: Vec<_> = mmr
                .peak_iterator()
                .take_while(|(peak_pos, _)| *peak_pos < start_pos)
                .map(|(peak_pos, _)| (peak_pos, mmr.get_node(peak_pos).unwrap()))
                .collect();
            assert!(!fold_prefix_peaks.is_empty());

            let missing_peaks = create_multi_proof(&proof_store, &target_locations, &[]);
            assert!(matches!(
                missing_peaks,
                Err(Error::ElementPruned(pos)) if pos == fold_prefix_peaks[0].0
            ));

            // Supplying the required peaks should produce a valid multi-proof.
            let multi_proof =
                create_multi_proof(&proof_store, &target_locations, &fold_prefix_peaks).unwrap();
            let selected_ops: Vec<(Location, u64)> = target_locations
                .iter()
                .map(|&loc| (loc, operations[*loc as usize]))
                .collect();
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &selected_ops,
                root,
            ));
        });
    }

    #[test_traced]
    fn test_verify_multi_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let mut mmr = Mmr::new(&mut hasher);

            // Add operations to the MMR
            let operations: Vec<u64> = (0..10).collect();
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();

            // Generate multi-proof directly from MMR
            let target_locations = vec![Location::new(1), Location::new(4), Location::new(7)];
            let multi_proof = verification::multi_proof(&mmr, &target_locations)
                .await
                .unwrap();

            // Verify with correct operations
            let selected_ops = vec![
                (Location::new(1), operations[1]),
                (Location::new(4), operations[4]),
                (Location::new(7), operations[7]),
            ];
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &selected_ops,
                root,
            ));

            // Verify fails with wrong operations
            let wrong_ops = vec![
                (Location::new(1), 99),
                (Location::new(4), operations[4]),
                (Location::new(7), operations[7]),
            ];
            assert!(!verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &wrong_ops,
                root,
            ));

            // Verify fails with wrong locations
            let wrong_locations = vec![
                (Location::new(0), operations[1]),
                (Location::new(4), operations[4]),
                (Location::new(7), operations[7]),
            ];
            assert!(!verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &wrong_locations,
                root,
            ));
        });
    }

    #[test_traced]
    fn test_multi_proof_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = test_hasher();
            let empty_mmr = Mmr::new(&mut hasher);
            let empty_root = empty_mmr.root();

            // Empty proof should verify against an empty MMR/database.
            let empty_proof = Proof::default();
            assert!(verify_multi_proof(
                &mut hasher,
                &empty_proof,
                &[] as &[(Location, u64)],
                empty_root,
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
            let mut mmr = Mmr::new(&mut hasher);

            // Add operations to the MMR
            let operations = vec![1, 2, 3];
            {
                let mut batch = mmr.new_batch();
                for op in &operations {
                    let encoded = op.encode();
                    batch = batch.add(&mut hasher, &encoded);
                }
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
            let root = mmr.root();

            // Create proof store for all elements
            let proof = mmr
                .range_proof(&mut hasher, Location::new(0)..Location::new(3))
                .unwrap();
            let proof_store =
                create_proof_store(&mut hasher, &proof, Location::new(0), &operations, root)
                    .unwrap();

            // Generate multi-proof for single element
            let multi_proof = create_multi_proof(&proof_store, &[Location::new(1)], &[]).unwrap();

            // Verify single element
            assert!(verify_multi_proof(
                &mut hasher,
                &multi_proof,
                &[(Location::new(1), operations[1])],
                root,
            ));
        });
    }
}
