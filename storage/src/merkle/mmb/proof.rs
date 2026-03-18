//! MMB-specific proof construction and verification.
//!
//! Provides functions for building and verifying inclusion proofs against MMB root digests.

use crate::merkle::{
    hasher::Hasher,
    mmb::{Error, Family, Location, Position},
    proof::{self as merkle_proof, Proof},
};
use alloc::collections::BTreeSet;
use commonware_cryptography::Digest;
use core::ops::Range;

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
#[allow(dead_code)]
pub(crate) fn nodes_required_for_multi_proof(
    leaves: Location,
    locations: &[Location],
) -> Result<BTreeSet<Position>, Error> {
    merkle_proof::nodes_required_for_multi_proof(leaves, locations)
}

/// Build a range proof from a node-fetching closure.
pub(crate) fn build_range_proof<D, H>(
    hasher: &mut H,
    leaves: Location,
    range: Range<Location>,
    get_node: impl Fn(Position) -> Option<D>,
) -> Result<Proof<Family, D>, Error>
where
    D: Digest,
    H: Hasher<Family, Digest = D>,
{
    merkle_proof::build_range_proof(hasher, leaves, range, get_node, Error::ElementPruned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        hasher::Standard,
        mmb::{iterator::leaf_pos, mem::Mmb, Family},
        proof::Blueprint,
    };
    use alloc::vec;
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
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_blueprint_errors() {
        let leaves = Location::new(10);

        // Empty range.
        assert!(matches!(
            Blueprint::new(leaves, Location::new(3)..Location::new(3)),
            Err(crate::merkle::Error::Empty)
        ));

        // Out of bounds.
        assert!(matches!(
            Blueprint::new(leaves, Location::new(0)..Location::new(11)),
            Err(crate::merkle::Error::RangeOutOfBounds(_))
        ));

        // Empty locations for multi-proof.
        assert!(matches!(
            nodes_required_for_multi_proof(leaves, &[]),
            Err(Error::Empty)
        ));
    }

    #[test]
    fn test_single_element_proof_positions() {
        for n in 1u64..=64 {
            let (_, mmb) = make_mmb(n);
            let leaves = mmb.leaves();
            let size = mmb.size();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = Blueprint::new(leaves, loc..loc + 1).unwrap();
                let mut positions: Vec<Position> = Vec::new();
                positions.extend(&bp.fold_prefix);
                positions.extend(&bp.fetch_nodes);

                for &pos in &positions {
                    assert!(pos < size, "n={n}, loc={loc}: pos {pos} >= size {size}");
                }
                // Should not contain the element's own leaf position.
                let lp = leaf_pos(loc);
                assert!(
                    !positions.contains(&lp),
                    "n={n}, loc={loc}: should not contain leaf pos {lp}"
                );
            }
        }
    }

    #[test]
    fn test_no_duplicate_positions() {
        for n in 1u64..=64 {
            let (_, mmb) = make_mmb(n);
            let leaves = mmb.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = Blueprint::new(leaves, loc..loc + 1).unwrap();
                let mut positions: Vec<Position> = Vec::new();
                positions.extend(&bp.fold_prefix);
                positions.extend(&bp.fetch_nodes);
                let set: BTreeSet<_> = positions.iter().copied().collect();
                assert_eq!(
                    positions.len(),
                    set.len(),
                    "n={n}, loc={loc}: duplicate positions"
                );
            }
        }
    }

    #[test]
    fn test_single_element_proof_reconstruction() {
        for n in 1u64..=64 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = mmb
                    .proof(&mut hasher, Location::new(loc_idx))
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: build failed: {e:?}"));

                let elements = [loc_idx.to_be_bytes()];
                let start_loc = Location::new(loc_idx);

                let reconstructed = proof
                    .reconstruct_root(&mut hasher, &elements, start_loc)
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: reconstruct failed: {e:?}"));
                assert_eq!(reconstructed, root, "n={n}, loc={loc_idx}: root mismatch");
            }
        }
    }

    #[test]
    fn test_range_proof_reconstruction() {
        for n in 2u64..=32 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            let ranges: Vec<(u64, u64)> = vec![
                (0, n),
                (0, 1),
                (n - 1, n),
                (0, n.min(3)),
                (n.saturating_sub(3), n),
            ];

            for (start, end) in ranges {
                if start >= end || end > n {
                    continue;
                }
                let proof = mmb
                    .range_proof(&mut hasher, Location::new(start)..Location::new(end))
                    .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: build failed: {e:?}"));
                let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();
                let start_loc = Location::new(start);

                let reconstructed = proof
                    .reconstruct_root(&mut hasher, &elements, start_loc)
                    .unwrap_or_else(|e| {
                        panic!("n={n}, range={start}..{end}: reconstruct failed: {e}")
                    });
                assert_eq!(
                    reconstructed, root,
                    "n={n}, range={start}..{end}: root mismatch"
                );
            }
        }
    }

    #[test]
    fn test_verify_element_inclusion() {
        for n in 1u64..=32 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = mmb.proof(&mut hasher, Location::new(loc_idx)).unwrap();
                let loc = Location::new(loc_idx);

                assert!(
                    proof.verify_element_inclusion(&mut hasher, &loc_idx.to_be_bytes(), loc, &root),
                    "n={n}, loc={loc_idx}: verification failed"
                );

                // Wrong element should fail.
                assert!(
                    !proof.verify_element_inclusion(
                        &mut hasher,
                        &(loc_idx + 1000).to_be_bytes(),
                        loc,
                        &root,
                    ),
                    "n={n}, loc={loc_idx}: wrong element should not verify"
                );
            }
        }
    }

    #[test]
    fn test_full_range() {
        for n in 1u64..=32 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            let proof = mmb
                .range_proof(&mut hasher, Location::new(0)..Location::new(n))
                .unwrap();
            let elements: Vec<_> = (0..n).map(|i| i.to_be_bytes()).collect();
            let reconstructed = proof
                .reconstruct_root(&mut hasher, &elements, Location::new(0))
                .unwrap();
            assert_eq!(reconstructed, root, "n={n}: full range failed");

            // Full range should have 0 digests.
            assert_eq!(
                proof.digests.len(),
                0,
                "n={n}: full range proof should have 0 digests"
            );
        }
    }

    #[test]
    fn test_empty_proof_verifies_empty_tree() {
        let mut hasher = H::new();
        let mmb = Mmb::<D>::new(&mut hasher);
        let root = *mmb.root();
        let proof = Proof::<Family, D>::default();

        // Empty proof should verify against the empty MMB root.
        assert!(proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[&[u8]],
            Location::new(0),
            &root,
        ));

        // Non-zero start_loc with empty elements should fail.
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[&[u8]],
            Location::new(1),
            &root,
        ));
    }

    #[test]
    fn test_every_element_contributes_to_root() {
        for n in [8u64, 13, 20, 32] {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            let start = 1;
            let end = n - 1;
            let proof = mmb
                .range_proof(&mut hasher, Location::new(start)..Location::new(end))
                .unwrap();
            let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

            // Valid elements verify.
            assert!(
                proof.verify_range_inclusion(&mut hasher, &elements, Location::new(start), &root),
                "n={n}: valid range should verify"
            );

            // Flipping one byte in each element must cause failure.
            for flip_idx in 0..elements.len() {
                let mut tampered = elements.clone();
                tampered[flip_idx][0] ^= 0xFF;
                assert!(
                    !proof.verify_range_inclusion(
                        &mut hasher,
                        &tampered,
                        Location::new(start),
                        &root,
                    ),
                    "n={n}: tampered element at index {flip_idx} should not verify"
                );
            }
        }
    }

    #[test]
    fn test_multi_proof_generation_and_verify() {
        let (mut hasher, mmb) = make_mmb(20);
        let root = *mmb.root();

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes =
            nodes_required_for_multi_proof(mmb.leaves(), locations).expect("valid locations");
        let digests = nodes
            .into_iter()
            .map(|pos| mmb.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mmb.leaves(),
            digests,
        };

        // Verify the proof.
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &root
        ));

        // Different order should also verify.
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (10u64.to_be_bytes(), Location::new(10)),
                (5u64.to_be_bytes(), Location::new(5)),
                (0u64.to_be_bytes(), Location::new(0)),
            ],
            &root
        ));

        // Wrong elements should fail.
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (99u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &root
        ));

        // Wrong root should fail.
        let wrong_root = hasher.digest(b"wrong");
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &wrong_root
        ));

        // Empty multi-proof on empty tree.
        let mut hasher2 = H::new();
        let empty_mmb = Mmb::new(&mut hasher2);
        let empty_proof: Proof<Family, D> = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &mut hasher2,
            &[] as &[([u8; 8], Location)],
            empty_mmb.root()
        ));
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
                    batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
            n += 100;
        }
    }

    #[test]
    fn test_tampered_proof_digests_rejected() {
        for n in [8u64, 13, 20, 32] {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in [0, n / 2, n - 1] {
                let proof = mmb.proof(&mut hasher, Location::new(loc_idx)).unwrap();
                let element = loc_idx.to_be_bytes();
                let loc = Location::new(loc_idx);

                assert!(proof.verify_element_inclusion(&mut hasher, &element, loc, &root));

                for digest_idx in 0..proof.digests.len() {
                    let mut tampered = proof.clone();
                    tampered.digests[digest_idx].0[0] ^= 1;
                    assert!(
                        !tampered.verify_element_inclusion(&mut hasher, &element, loc, &root),
                        "n={n}, loc={loc_idx}: tampered digest[{digest_idx}] should not verify"
                    );
                }
            }
        }
    }
}
