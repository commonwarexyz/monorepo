//! MMB-specific proof construction and verification.
//!
//! Provides functions for building and verifying inclusion proofs against MMB root digests.

#[cfg(test)]
mod tests {
    use crate::{
        merkle::{hasher::Standard, mmb::mem::Mmb, proof::Blueprint},
        mmb::Location,
    };
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    /// Build an in-memory MMB with `n` elements (element i = i.to_be_bytes()).
    fn make_mmb(n: u64) -> (H, Mmb<D>) {
        let hasher = H::new();
        let mut mmb = Mmb::new(&hasher);
        let batch = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mmb, &hasher)
        };
        mmb.apply_batch(&batch).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_verify_proof_and_pinned_nodes_boundary_stable_cases() {
        let hasher = H::new();

        // Case 1: the pinned boundary node is used as a left sibling in the proof.
        let (_, mmb) = make_mmb(3);
        let elements: Vec<_> = (0u64..3).map(|i| i.to_be_bytes()).collect();
        let start_loc = Location::new(1);
        let proof = mmb
            .range_proof(&hasher, start_loc..Location::new(3))
            .unwrap();
        let pinned_map = mmb.nodes_to_pin(start_loc);
        let pinned: Vec<_> =
            <crate::merkle::mmb::Family as crate::merkle::Family>::nodes_to_pin(start_loc)
                .map(|pos| pinned_map[&pos])
                .collect();
        assert_eq!(pinned.len(), 1);
        assert!(proof.verify_proof_and_pinned_nodes(
            &hasher,
            &elements[1..],
            start_loc,
            &pinned,
            mmb.root(),
        ));

        // Case 2: the current proof folds a later parent peak, but the pinned boundary still
        // stores the older 4-leaf decomposition.
        let (_, mmb) = make_mmb(5);
        let elements: Vec<_> = (0u64..5).map(|i| i.to_be_bytes()).collect();
        let start_loc = Location::new(4);
        let proof = mmb
            .range_proof(&hasher, start_loc..Location::new(5))
            .unwrap();
        let pinned_map = mmb.nodes_to_pin(start_loc);
        let pinned: Vec<_> =
            <crate::merkle::mmb::Family as crate::merkle::Family>::nodes_to_pin(start_loc)
                .map(|pos| pinned_map[&pos])
                .collect();
        assert_eq!(pinned.len(), 2);
        assert!(proof.verify_proof_and_pinned_nodes(
            &hasher,
            &elements[4..],
            start_loc,
            &pinned,
            mmb.root(),
        ));
    }

    #[test]
    fn test_last_element_proof_size_is_two() {
        // An MMB property is that the most recent item always has a small proof
        // (at most 2 digests). Verify this holds as the tree grows.
        let hasher = H::new();
        let (_, mut mmb) = make_mmb(1000);
        let mut n = 1000u64;

        while n <= 5000 {
            let leaves = mmb.leaves();
            let root = *mmb.root();

            let loc = n - 1;
            let bp = Blueprint::new(leaves, Location::new(loc)..Location::new(n)).unwrap();

            let total_digests = usize::from(!bp.fold_prefix.is_empty()) + bp.fetch_nodes.len();
            assert!(
                total_digests <= 2,
                "n={n}: expected <= 2 digests, got {total_digests} \
                 (fold_prefix={}, fetch_nodes={})",
                bp.fold_prefix.len(),
                bp.fetch_nodes.len(),
            );

            // Verify the proof actually works.
            let proof = mmb.proof(&hasher, Location::new(loc)).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root,
                ),
                "n={n}: verification failed"
            );

            // Grow by 100 elements.
            let batch = {
                let mut batch = mmb.new_batch();
                for i in n..n + 100 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();
            n += 100;
        }
    }
}
