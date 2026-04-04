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
            batch.merkleize(&hasher, &mmb)
        };
        mmb.apply_batch(&batch).unwrap();
        (hasher, mmb)
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
                batch.merkleize(&hasher, &mmb)
            };
            mmb.apply_batch(&batch).unwrap();
            n += 100;
        }
    }
}
