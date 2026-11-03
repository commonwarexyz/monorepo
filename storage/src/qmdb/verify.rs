use crate::{
    merkle::{Error, Family, Location, Position, Proof, verification::ProofStore},
    qmdb,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, DigestOf, Hasher};

/// Digests extracted from a verified proof, paired with their Merkle positions.
pub type ExtractedDigests<F, H> = Vec<(Position<F>, DigestOf<H>)>;

/// Verification of [Proof]s over QMDB operations.
///
/// Unlike [Proof]'s own methods, which take pre-encoded elements and a hasher, these take the
/// operations and a [Hasher] type, and encode and hash them the same way QMDB databases do. A
/// proof from a database therefore verifies against that database's root.
pub trait ProofExt<F: Family, D: Digest> {
    /// Return true if the proof authenticates `ops` at the locations starting at `start_loc` in
    /// the database with the provided `root`.
    fn verify<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> bool;

    /// Return true if the proof is valid as [Self::verify] checks and `pinned_nodes` are the
    /// nodes pinned at `start_loc` in the database with the provided `root`.
    ///
    /// When `start_loc` is 0, `pinned_nodes` must be empty.
    fn verify_with_pinned_nodes<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        pinned_nodes: &[D],
        root: &D,
    ) -> bool;

    /// Verify the proof as [Self::verify] does and return every digest, with its position,
    /// needed to reconstruct `root`, including the proof's own digests.
    ///
    /// # Errors
    ///
    /// Returns [Error::RootMismatch] if the proof reconstructs a root other than `root`, or
    /// [Error::InvalidProof] if the proof or its inputs are malformed.
    fn verify_and_extract_digests<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> Result<ExtractedDigests<F, H>, Error<F>>;

    /// Verify the proof as [Self::verify] does and convert it into a [ProofStore], from which
    /// [ProofStore::multi_proof] builds proofs for operations within the range.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is invalid or does not reconstruct `root`.
    fn to_proof_store<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> Result<ProofStore<F, D>, Error<F>>;

    /// Return true if this multi-proof authenticates each operation at its location in the
    /// database with the provided `root`.
    ///
    /// Operations must be in strictly ascending location order. Returns `false` if a location
    /// repeats or precedes the one before it, even if the operations are genuine.
    fn verify_multi<H: Hasher<Digest = D>, O: Encode>(
        &self,
        ops: &[(Location<F>, O)],
        root: &D,
    ) -> bool;
}

/// Encode `ops` as the elements a Merkle proof authenticates.
fn encode_ops<O: Encode>(ops: &[O]) -> Vec<Bytes> {
    ops.iter().map(Encode::encode).collect()
}

impl<F: Family, D: Digest> ProofExt<F, D> for Proof<F, D> {
    fn verify<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> bool {
        self.verify_range_inclusion(&qmdb::hasher::<H>(), start_loc, &encode_ops(ops), root)
    }

    fn verify_with_pinned_nodes<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        pinned_nodes: &[D],
        root: &D,
    ) -> bool {
        self.verify_range_inclusion_with_pinned_nodes(
            &qmdb::hasher::<H>(),
            start_loc,
            &encode_ops(ops),
            pinned_nodes,
            root,
        )
    }

    fn verify_and_extract_digests<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> Result<ExtractedDigests<F, H>, Error<F>> {
        self.verify_range_inclusion_and_extract_digests(
            &qmdb::hasher::<H>(),
            start_loc,
            &encode_ops(ops),
            root,
        )
    }

    fn to_proof_store<H: Hasher<Digest = D>, O: Encode>(
        &self,
        start_loc: Location<F>,
        ops: &[O],
        root: &D,
    ) -> Result<ProofStore<F, D>, Error<F>> {
        ProofStore::new(
            &qmdb::hasher::<H>(),
            self,
            start_loc,
            &encode_ops(ops),
            root,
        )
    }

    fn verify_multi<H: Hasher<Digest = D>, O: Encode>(
        &self,
        ops: &[(Location<F>, O)],
        root: &D,
    ) -> bool {
        let elements = ops
            .iter()
            .map(|(loc, op)| (*loc, op.encode()))
            .collect::<Vec<_>>();
        self.verify_multi_inclusion(&qmdb::hasher::<H>(), &elements, root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{LocationRangeExt as _, RangePlan, hasher::Standard, mem::Mem},
        mmb, mmr,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner, deterministic};
    use core::ops::Range;

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[&[v]])
    }

    fn test_hasher() -> Standard<Sha256> {
        qmdb::hasher::<Sha256>()
    }

    fn qmdb_range_proof<F: Family>(
        hasher: &Standard<Sha256>,
        merkle: &Mem<F, Digest>,
        inactive_peaks: usize,
        range: Range<Location<F>>,
    ) -> Proof<F, Digest> {
        RangePlan::new(merkle.leaves(), range)
            .unwrap()
            .build(hasher, inactive_peaks, |pos| merkle.get_node(pos))
            .unwrap()
    }

    // ---- Generic inner functions for tests that work on both MMR and MMB ----

    fn verify_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();

        // Generate proof for all operations
        let proof = qmdb_range_proof(
            &hasher,
            &merkle,
            0,
            Location::<F>::new(0)..Location::<F>::new(3),
        );

        // Verify the proof
        assert!(proof.verify::<Sha256, _>(
            Location::<F>::new(0), // start_loc
            &operations,
            &root
        ));

        // Verify the proof with the wrong root
        let wrong_root = test_digest(99);
        assert!(!proof.verify::<Sha256, _>(Location::<F>::new(0), &operations, &wrong_root));

        // Verify the proof with the wrong operations
        let wrong_operations = vec![9, 10, 11];
        assert!(!proof.verify::<Sha256, _>(Location::<F>::new(0), &wrong_operations, &root));
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
        let mut merkle = Mem::<F, Digest>::new();

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
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let start_loc = Location::<F>::new(5u64);
        let root = merkle.root(&hasher, 0).unwrap();
        let proof = qmdb_range_proof(
            &hasher,
            &merkle,
            0,
            Location::<F>::new(5)..Location::<F>::new(8),
        );

        // Verify with correct start location
        assert!(proof.verify::<Sha256, _>(start_loc, &operations, &root));

        // Verify fails with wrong start location
        assert!(!proof.verify::<Sha256, _>(
            Location::<F>::new(0), // wrong start_loc
            &operations,
            &root
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

    fn verify_and_extract_digests_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3, 4];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();
        let range = Location::<F>::new(1)..Location::<F>::new(4);
        let proof = qmdb_range_proof(&hasher, &merkle, 0, range.clone());

        // Verify and extract digests for subset of operations
        let result = proof.verify_and_extract_digests::<Sha256, _>(
            Location::<F>::new(1), // start_loc
            &operations[range.to_usize_range()],
            &root,
        );
        assert!(result.is_ok());
        let digests = result.unwrap();
        assert!(!digests.is_empty());

        // Should fail with wrong root
        let wrong_root = test_digest(99);
        assert!(
            proof
                .verify_and_extract_digests::<Sha256, _>(
                    Location::<F>::new(1),
                    &operations[range.to_usize_range()],
                    &wrong_root
                )
                .is_err()
        );
    }

    #[test_traced]
    fn test_verify_and_extract_digests_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_and_extract_digests_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_and_extract_digests_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_and_extract_digests_inner::<mmb::Family>() });
    }

    fn to_proof_store_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add some operations to the merkle structure
        let op_count = 15;
        let operations: Vec<u64> = (0..op_count).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();
        let range = Location::<F>::new(0)..Location::<F>::new(3);
        let proof = qmdb_range_proof(&hasher, &merkle, 0, range.clone());

        // Create proof store
        let result = proof.to_proof_store::<Sha256, _>(
            range.start,                         // start_loc
            &operations[range.to_usize_range()], // Only the first 3 operations covered by the proof
            &root,
        );
        assert!(result.is_ok());
        let proof_store = result.unwrap();

        // Verify we can generate sub-proofs from the store
        let range = Location::<F>::new(0)..Location::<F>::new(2);
        let sub_proof = proof_store.range_proof(&hasher, range.clone()).unwrap();

        // Verify the sub-proof
        assert!(sub_proof.verify::<Sha256, _>(
            range.start,
            &operations[range.to_usize_range()],
            &root
        ));
    }

    #[test_traced]
    fn test_to_proof_store_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { to_proof_store_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_to_proof_store_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { to_proof_store_inner::<mmb::Family>() });
    }

    fn to_proof_store_invalid_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add some operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let range = Location::<F>::new(0)..Location::<F>::new(2);
        let proof = qmdb_range_proof(&hasher, &merkle, 0, range);

        // Should fail with invalid root
        let wrong_root = test_digest(99);
        assert!(
            proof
                .to_proof_store::<Sha256, _>(Location::<F>::new(0), &operations, &wrong_root)
                .is_err()
        );
    }

    #[test_traced]
    fn test_to_proof_store_invalid_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { to_proof_store_invalid_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_to_proof_store_invalid_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { to_proof_store_invalid_proof_inner::<mmb::Family>() });
    }

    fn multi_proof_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add operations to the merkle structure
        let operations: Vec<u64> = (0..20).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();

        // Create proof for full range
        let proof = qmdb_range_proof(
            &hasher,
            &merkle,
            0,
            Location::<F>::new(0)..Location::<F>::new(20),
        );

        // Create proof store
        let proof_store = proof
            .to_proof_store::<Sha256, _>(Location::<F>::new(0), &operations, &root)
            .unwrap();

        // Generate multi-proof for specific locations
        let target_locations = vec![
            Location::<F>::new(2),
            Location::<F>::new(5),
            Location::<F>::new(10),
            Location::<F>::new(15),
            Location::<F>::new(18),
        ];
        let multi_proof = proof_store.multi_proof(&target_locations, &[]).unwrap();

        // Locations must be strictly ascending.
        let mut duplicate_locations = target_locations.clone();
        duplicate_locations.insert(1, target_locations[0]);
        assert!(matches!(
            proof_store.multi_proof(&duplicate_locations, &[]),
            Err(Error::DuplicateLocation(loc)) if loc == target_locations[0]
        ));
        let mut unsorted_locations = target_locations.clone();
        unsorted_locations.swap(0, 1);
        assert!(matches!(
            proof_store.multi_proof(&unsorted_locations, &[]),
            Err(Error::UnsortedLocation(loc)) if loc == target_locations[0]
        ));

        // Prepare operations for verification
        let selected_ops: Vec<(Location<F>, u64)> = target_locations
            .iter()
            .map(|&loc| (loc, operations[*loc as usize]))
            .collect();

        // Verify the multi-proof
        assert!(multi_proof.verify_multi::<Sha256, _>(&selected_ops, &root));
    }

    #[test_traced]
    fn test_multi_proof_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_multi_proof_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { multi_proof_inner::<mmb::Family>() });
    }

    fn multi_proof_with_fold_prefix_peaks_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Build a merkle structure with peaks covering locations 0-31, 32-47, and 48.
        let operations: Vec<u64> = (0..49).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                batch = batch.add(&hasher, &op.encode());
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let inactive_peaks = 1;
        let root = merkle.root(&hasher, inactive_peaks).unwrap();

        // Proof store starts at 32, so the first peak is folded into the proof prefix.
        let range = Location::<F>::new(32)..Location::<F>::new(49);
        let proof = qmdb_range_proof(&hasher, &merkle, inactive_peaks, range.clone());
        let proof_store = proof
            .to_proof_store::<Sha256, _>(range.start, &operations[range.to_usize_range()], &root)
            .unwrap();
        assert_eq!(proof.inactive_peaks, inactive_peaks);

        let mut tampered = proof.clone();
        tampered.inactive_peaks = 0;
        assert!(!tampered.verify::<Sha256, _>(
            range.start,
            &operations[range.to_usize_range()],
            &root
        ));
        assert!(
            tampered
                .to_proof_store::<Sha256, _>(
                    range.start,
                    &operations[range.to_usize_range()],
                    &root
                )
                .is_err()
        );

        let mut tampered = proof;
        tampered.inactive_peaks = inactive_peaks + 1;
        assert!(!tampered.verify::<Sha256, _>(
            range.start,
            &operations[range.to_usize_range()],
            &root
        ));
        assert!(
            tampered
                .to_proof_store::<Sha256, _>(
                    range.start,
                    &operations[range.to_usize_range()],
                    &root
                )
                .is_err()
        );

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

        let missing_peaks = proof_store.multi_proof(&target_locations, &[]);
        assert!(matches!(
            missing_peaks,
            Err(crate::merkle::Error::ElementPruned(pos)) if pos == fold_prefix_peaks[0].0
        ));

        // Supplying the required peaks should produce a valid multi-proof.
        let multi_proof = proof_store
            .multi_proof(&target_locations, &fold_prefix_peaks)
            .unwrap();
        let selected_ops: Vec<(Location<F>, u64)> = target_locations
            .iter()
            .map(|&loc| (loc, operations[*loc as usize]))
            .collect();
        assert!(multi_proof.verify_multi::<Sha256, _>(&selected_ops, &root));

        let mut tampered = multi_proof;
        tampered.inactive_peaks = 0;
        assert!(!tampered.verify_multi::<Sha256, _>(&selected_ops, &root));
    }

    #[test_traced]
    fn test_multi_proof_with_fold_prefix_peaks_mmr() {
        let executor = deterministic::Runner::default();
        executor
            .start(|_| async move { multi_proof_with_fold_prefix_peaks_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_multi_proof_with_fold_prefix_peaks_mmb() {
        let executor = deterministic::Runner::default();
        executor
            .start(|_| async move { multi_proof_with_fold_prefix_peaks_inner::<mmb::Family>() });
    }

    fn verify_multi_inner<F: Family>() {
        let hasher = test_hasher();
        let mut merkle = Mem::<F, Digest>::new();

        // Add operations to the merkle structure
        let operations: Vec<u64> = (0..10).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();

        // Generate multi-proof via range proof -> proof store -> multi-proof
        let target_locations = vec![
            Location::<F>::new(1),
            Location::<F>::new(4),
            Location::<F>::new(7),
        ];
        let proof = qmdb_range_proof(&hasher, &merkle, 0, Location::<F>::new(0)..merkle.leaves());
        let proof_store = proof
            .to_proof_store::<Sha256, _>(Location::<F>::new(0), &operations, &root)
            .unwrap();
        let multi_proof = proof_store.multi_proof(&target_locations, &[]).unwrap();

        // Verify with correct operations
        let selected_ops = vec![
            (Location::<F>::new(1), operations[1]),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(multi_proof.verify_multi::<Sha256, _>(&selected_ops, &root));

        // Genuine operations fail when a location repeats or precedes the one before it.
        let mut duplicate_ops = selected_ops.clone();
        duplicate_ops.insert(1, selected_ops[0]);
        assert!(!multi_proof.verify_multi::<Sha256, _>(&duplicate_ops, &root));
        duplicate_ops[1].1 ^= 1;
        assert!(!multi_proof.verify_multi::<Sha256, _>(&duplicate_ops, &root));
        let mut unsorted_ops = selected_ops;
        unsorted_ops.swap(0, 1);
        assert!(!multi_proof.verify_multi::<Sha256, _>(&unsorted_ops, &root));

        // Verify fails with wrong operations
        let wrong_ops = vec![
            (Location::<F>::new(1), 99),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(!multi_proof.verify_multi::<Sha256, _>(&wrong_ops, &root));

        // Verify fails with wrong locations
        let wrong_locations = vec![
            (Location::<F>::new(0), operations[1]),
            (Location::<F>::new(4), operations[4]),
            (Location::<F>::new(7), operations[7]),
        ];
        assert!(!multi_proof.verify_multi::<Sha256, _>(&wrong_locations, &root));
    }

    #[test_traced]
    fn test_verify_multi_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_multi_inner::<mmr::Family>() });
    }

    #[test_traced]
    fn test_verify_multi_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move { verify_multi_inner::<mmb::Family>() });
    }

    fn multi_proof_empty_inner<F: Family>() {
        let hasher = test_hasher();
        let empty_merkle = Mem::<F, Digest>::new();
        let empty_root = empty_merkle.root(&hasher, 0).unwrap();

        // Empty proof should verify against an empty merkle structure.
        let empty_proof = Proof::default();
        assert!(empty_proof.verify_multi::<Sha256, _>(&[] as &[(Location<F>, u64)], &empty_root));

        // Proofs over empty locations should otherwise not be allowed.
        let mut merkle = Mem::<F, Digest>::new();
        let operations: Vec<u64> = (0..5).collect();
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                batch = batch.add(&hasher, &op.encode());
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();
        let proof = qmdb_range_proof(&hasher, &merkle, 0, Location::<F>::new(0)..merkle.leaves());
        let proof_store = proof
            .to_proof_store::<Sha256, _>(Location::<F>::new(0), &operations, &root)
            .unwrap();
        assert!(matches!(
            proof_store.multi_proof(&[], &[]),
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
        let mut merkle = Mem::<F, Digest>::new();

        // Add operations to the merkle structure
        let operations = vec![1, 2, 3];
        {
            let mut batch = merkle.new_batch();
            for op in &operations {
                let encoded = op.encode();
                batch = batch.add(&hasher, &encoded);
            }
            let batch = batch.merkleize(&merkle, &hasher);
            merkle.apply_batch(&batch).unwrap();
        }
        let root = merkle.root(&hasher, 0).unwrap();

        // Create proof store for all elements
        let proof = qmdb_range_proof(
            &hasher,
            &merkle,
            0,
            Location::<F>::new(0)..Location::<F>::new(3),
        );
        let proof_store = proof
            .to_proof_store::<Sha256, _>(Location::<F>::new(0), &operations, &root)
            .unwrap();

        // Generate multi-proof for single element
        let multi_proof = proof_store
            .multi_proof(&[Location::<F>::new(1)], &[])
            .unwrap();

        // Verify single element
        assert!(
            multi_proof.verify_multi::<Sha256, _>(&[(Location::<F>::new(1), operations[1])], &root)
        );
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
