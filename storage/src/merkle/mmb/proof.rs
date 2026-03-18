//! MMB-specific proof construction and verification.
//!
//! Provides functions for building and verifying inclusion proofs against MMB root digests.

use crate::merkle::{
    mmb::{Error, Location, Position},
    proof as merkle_proof,
};
use alloc::collections::BTreeSet;

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
#[allow(dead_code)]
pub(crate) fn nodes_required_for_multi_proof(
    leaves: Location,
    locations: &[Location],
) -> Result<BTreeSet<Position>, Error> {
    merkle_proof::nodes_required_for_multi_proof(leaves, locations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mmb::mem::Mmb, proof::Blueprint};
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    /// Build an in-memory MMB with `n` elements (element i = i.to_be_bytes()).
    fn make_mmb(n: u64) -> (H, Mmb<D>) {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch = batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_last_element_proof_size_is_two() {
        // An MMB property is that the most recent item always has a small proof
        // (at most 2 digests). Verify this holds as the tree grows.
        let mut hasher = H::new();
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
            let proof = mmb.proof(&mut hasher, Location::new(loc)).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root,
                ),
                "n={n}: verification failed"
            );

            // Grow by 100 elements.
            let changeset = {
                let mut batch = mmb.new_batch();
                for i in n..n + 100 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
            n += 100;
        }
    }
}
