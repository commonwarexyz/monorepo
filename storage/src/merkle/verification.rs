//! Defines functions for generating various [Proof] types from any Merkle structure implementing
//! the [Storage] trait. Also defines a [ProofStore] type that can be used to generate proofs over
//! any subset or sub-range of the original range.
//!
//! ## Historical Proof Generation
//!
//! This module provides both current and historical proof generation capabilities:
//! - [range_proof] generates proofs against the current state
//! - [historical_range_proof] generates proofs against historical states
//!
//! Historical proofs are essential for sync operations where we need to prove elements against a
//! past state of the structure rather than its current state.

use crate::merkle::{
    hasher::Hasher,
    proof::{self as merkle_proof, Blueprint},
    storage::Storage,
    Error, Family, Location, Position, Proof,
};
use commonware_cryptography::Digest;
use core::ops::Range;
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashMap};

/// A store derived from a [Proof] that can be used to generate proofs over any sub-range of the
/// original range.
pub struct ProofStore<F: Family, D> {
    digests: HashMap<Position<F>, D>,
    size: Position<F>,
    /// The fold prefix accumulator from the original proof, if any peaks preceded the proven range.
    fold_acc: Option<D>,
    /// Number of peaks that were folded into `fold_acc`.
    num_fold_peaks: usize,
}

impl<F: Family, D: Digest> ProofStore<F, D> {
    /// Create a [ProofStore] from a [Proof] of inclusion of the provided range of elements from
    /// the structure with root `root`. The resulting store can be used to generate range proofs
    /// over any sub-range of the original range. Returns an error if the proof is invalid or could
    /// not be verified against the given root.
    ///
    /// The fold prefix accumulator from the proof is stored internally so that sub-range proofs
    /// with different fold prefix boundaries can be generated without requiring individual peak
    /// digests.
    pub fn new<H, E>(
        hasher: &H,
        proof: &Proof<F, D>,
        elements: &[E],
        start_loc: Location<F>,
        root: &D,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        let digests =
            proof.verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)?;
        let map: HashMap<Position<F>, D> = digests.into_iter().collect();

        let size = Position::try_from(proof.leaves)?;

        // Count peaks in the fold prefix using the same leaf-coverage logic that proof
        // construction uses. Some families (for example MMB) do not order peaks by position.
        let num_fold_peaks = Blueprint::<F>::fold_prefix(proof.leaves, start_loc)?.len();

        let fold_acc = if num_fold_peaks > 0 {
            Some(*proof.digests.first().ok_or(Error::InvalidProof)?)
        } else {
            None
        };

        Ok(Self {
            size,
            digests: map,
            fold_acc,
            num_fold_peaks,
        })
    }

    /// Return a range proof for the nodes corresponding to the given location range.
    ///
    /// The sub-range's fold prefix accumulator is derived from the stored fold accumulator
    /// (covering the original proof's fold prefix peaks) plus any additional peaks that are
    /// individually available in the store (original range peaks now preceding the sub-range).
    pub fn range_proof<H: Hasher<F, Digest = D>>(
        &self,
        hasher: &H,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        let leaves = Location::try_from(self.size)?;
        let bp = Blueprint::new(leaves, range)?;

        let mut digests: Vec<D> = Vec::new();
        if !bp.fold_prefix.is_empty() {
            // Start from the stored fold accumulator (which does not include the leaf count).
            let mut acc = self.fold_acc;
            // Fold in peaks beyond those already covered by the stored accumulator.
            for &pos in bp.fold_prefix.iter().skip(self.num_fold_peaks) {
                match self.digests.get(&pos) {
                    Some(d) => {
                        acc = Some(acc.map_or(*d, |a| hasher.fold(&a, d)));
                    }
                    None => return Err(Error::ElementPruned(pos)),
                }
            }
            digests.push(acc.expect("fold_prefix is non-empty so acc must be set"));
        }

        for &pos in &bp.fetch_nodes {
            match self.digests.get(&pos) {
                Some(d) => digests.push(*d),
                None => return Err(Error::ElementPruned(pos)),
            }
        }

        Ok(Proof { leaves, digests })
    }

    /// Return a multi proof for the elements corresponding to the given locations.
    ///
    /// Since multi-proofs require individual node digests (not fold accumulators), callers must
    /// supply any peak digests that fall in the fold prefix of the original proof. These are the
    /// peaks entirely before the original range's start location. If the original range started
    /// at location 0, no peaks are needed.
    pub fn multi_proof(
        &self,
        locations: &[Location<F>],
        peaks: &[(Position<F>, D)],
    ) -> Result<Proof<F, D>, Error<F>> {
        if locations.is_empty() {
            return Err(Error::Empty);
        }

        let leaves = Location::try_from(self.size)?;
        let node_positions: BTreeSet<_> =
            merkle_proof::nodes_required_for_multi_proof(leaves, locations)?;

        let peak_map: HashMap<Position<F>, D> = peaks.iter().copied().collect();

        let mut digests = Vec::with_capacity(node_positions.len());
        for &pos in &node_positions {
            if let Some(d) = self.digests.get(&pos) {
                digests.push(*d);
            } else if let Some(d) = peak_map.get(&pos) {
                digests.push(*d);
            } else {
                return Err(Error::ElementPruned(pos));
            }
        }

        Ok(Proof { leaves, digests })
    }
}

/// Return a range proof for the nodes corresponding to the given location range.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `range` > [Family::MAX_LEAVES]
/// Returns [Error::RangeOutOfBounds] if any location in `range` > `merkle.size()`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if the requested range is empty
pub async fn range_proof<
    F: Family,
    D: Digest,
    H: Hasher<F, Digest = D>,
    S: Storage<F, Digest = D>,
>(
    hasher: &H,
    merkle: &S,
    range: Range<Location<F>>,
) -> Result<Proof<F, D>, Error<F>> {
    let leaves = Location::try_from(merkle.size().await)?;
    historical_range_proof(hasher, merkle, leaves, range).await
}

/// Analogous to range_proof but for a previous database state. Specifically, the state when the
/// structure had `leaves` leaves.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `range` > [Family::MAX_LEAVES]
/// Returns [Error::RangeOutOfBounds] if any location in `range` > `leaves`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if the requested range is empty
pub async fn historical_range_proof<
    F: Family,
    D: Digest,
    H: Hasher<F, Digest = D>,
    S: Storage<F, Digest = D>,
>(
    hasher: &H,
    merkle: &S,
    leaves: Location<F>,
    range: Range<Location<F>>,
) -> Result<Proof<F, D>, Error<F>> {
    let bp = Blueprint::new(leaves, range)?;

    let mut digests: Vec<D> = Vec::new();
    if !bp.fold_prefix.is_empty() {
        let node_futures = bp.fold_prefix.iter().map(|&pos| merkle.get_node(pos));
        let results = try_join_all(node_futures).await?;
        let mut acc = results[0].ok_or(Error::ElementPruned(bp.fold_prefix[0]))?;
        for (i, &result) in results.iter().enumerate().skip(1) {
            let d = result.ok_or(Error::ElementPruned(bp.fold_prefix[i]))?;
            acc = hasher.fold(&acc, &d);
        }
        digests.push(acc);
    }

    let node_futures = bp.fetch_nodes.iter().map(|&pos| merkle.get_node(pos));
    let results = try_join_all(node_futures).await?;
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Some(d) => digests.push(d),
            None => return Err(Error::ElementPruned(bp.fetch_nodes[i])),
        }
    }

    Ok(Proof { leaves, digests })
}

/// Return an inclusion proof for the elements at the specified locations. This is analogous to
/// range_proof but supports non-contiguous locations.
///
/// The order of positions does not affect the output (sorted internally).
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `locations` > [Family::MAX_LEAVES]
/// Returns [Error::RangeOutOfBounds] if any location in `locations` > `merkle.size()`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if locations is empty
pub async fn multi_proof<F: Family, D: Digest, S: Storage<F, Digest = D>>(
    merkle: &S,
    locations: &[Location<F>],
) -> Result<Proof<F, D>, Error<F>> {
    if locations.is_empty() {
        // Disallow proofs over empty element lists just as we disallow proofs over empty ranges.
        return Err(Error::Empty);
    }

    // Collect all required node positions
    let size = merkle.size().await;
    let leaves = Location::try_from(size)?;
    let node_positions: BTreeSet<_> =
        merkle_proof::nodes_required_for_multi_proof(leaves, locations)?;

    // Fetch all required digests in parallel and collect with positions
    let node_futures: Vec<_> = node_positions
        .iter()
        .map(|&pos| async move { merkle.get_node(pos).await.map(|digest| (pos, digest)) })
        .collect();
    let results = try_join_all(node_futures).await?;

    // Build the proof, returning error with correct position on pruned nodes
    let mut digests = Vec::with_capacity(results.len());
    for (pos, digest) in results {
        match digest {
            Some(digest) => digests.push(digest),
            None => return Err(Error::ElementPruned(pos)),
        }
    }

    Ok(Proof { leaves, digests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::LocationRangeExt as _,
        mmb::{mem::Mmb, Location as MmbLocation},
        mmr::{mem::Mmr, StandardHasher as Standard},
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    #[test_traced]
    fn test_verification_proof_store() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // create a new MMR and add a non-trivial amount (49) of elements
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&hasher);
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let batch = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&hasher, &mmr)
            };
            mmr.apply_batch(&batch).unwrap();
            let root = mmr.root();

            // Extract a ProofStore from a proof over a variety of ranges, starting with the full
            // range and shrinking each endpoint with each iteration.
            let mut range_start = Location::new(0);
            let mut range_end = Location::new(49);
            while range_start < range_end {
                let range = range_start..range_end;
                let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
                let proof_store = ProofStore::new(
                    &hasher,
                    &range_proof,
                    &elements[range.to_usize_range()],
                    range_start,
                    root,
                )
                .unwrap();

                // Verify that the ProofStore can be used to generate proofs over a host of
                // sub-ranges starting with the full range down to a range containing a single
                // element.
                let mut subrange_start = range_start;
                let mut subrange_end = range_end;
                while subrange_start < subrange_end {
                    // Verify a proof over a sub-range of the original range.
                    let sub_range = subrange_start..subrange_end;
                    let sub_range_proof =
                        proof_store.range_proof(&hasher, sub_range.clone()).unwrap();
                    assert!(sub_range_proof.verify_range_inclusion(
                        &hasher,
                        &elements[sub_range.to_usize_range()],
                        sub_range.start,
                        root
                    ));
                    subrange_start += 1;
                    subrange_end -= 1;
                }
                range_start += 1;
                range_end -= 1;
            }
        });
    }

    #[test_traced]
    fn test_verification_proof_store_with_fold_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build MMR with 49 elements. Peaks cover locations 0-31, 32-47, 48.
            // A proof starting at location 32 puts the first peak entirely in the fold prefix.
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&hasher);
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let batch = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&hasher, &mmr)
            };
            mmr.apply_batch(&batch).unwrap();
            let root = mmr.root();

            // Proof for range 32..49 has a non-empty fold prefix (the 32-leaf peak).
            // The ProofStore derives the fold accumulator from the proof itself, so
            // sub-proofs should succeed for all sub-ranges without needing peaks.
            let range = Location::new(32)..Location::new(49);
            let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                root,
            )
            .unwrap();

            // Sub-proofs should succeed for all sub-ranges.
            for start in 32u64..49 {
                for end in (start + 1)..=49 {
                    let sub_range = Location::new(start)..Location::new(end);
                    let sub_proof = proof_store.range_proof(&hasher, sub_range.clone()).unwrap();
                    assert!(
                        sub_proof.verify_range_inclusion(
                            &hasher,
                            &elements[sub_range.to_usize_range()],
                            sub_range.start,
                            root,
                        ),
                        "sub-proof should verify for range {start}..{end}"
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_proof_store_with_fold_prefix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmb = Mmb::new(&hasher);
            let elements: Vec<_> = (0..8).map(test_digest).collect();
            let batch = {
                let mut batch = mmb.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&hasher, &mmb)
            };
            mmb.apply_batch(&batch).unwrap();
            let root = mmb.root();

            // With 8 leaves, the oldest MMB peak covers locations 0..4 but sits at position 7,
            // while the first leaf in the proven range (location 4) sits at position 6.
            // A position-based peak comparison therefore misclassifies the fold prefix.
            let range = MmbLocation::new(4)..MmbLocation::new(8);
            let range_proof = mmb.range_proof(&hasher, range.clone()).unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                root,
            )
            .unwrap();

            for start in 4u64..8 {
                for end in (start + 1)..=8 {
                    let sub_range = MmbLocation::new(start)..MmbLocation::new(end);
                    let sub_proof = proof_store.range_proof(&hasher, sub_range.clone()).unwrap();
                    assert!(
                        sub_proof.verify_range_inclusion(
                            &hasher,
                            &elements[sub_range.to_usize_range()],
                            sub_range.start,
                            root,
                        ),
                        "sub-proof should verify for MMB range {start}..{end}"
                    );
                }
            }
        });
    }
}
