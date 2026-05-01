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
    Bagging, Error, Family, Location, Position, Proof,
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
    /// Suffix peaks hidden behind `suffix_acc`.
    suffix_peaks: Vec<Position<F>>,
    /// Backward-folded accumulator for `suffix_peaks`.
    suffix_acc: Option<D>,
    /// The number of inactive peaks from the original proof.
    inactive_peaks: usize,
    /// The strategy used to fold peaks after the inactive prefix.
    bagging: Bagging,
}

impl<F: Family, D: Digest> ProofStore<F, D> {
    /// Create a [ProofStore] from a [Proof] of inclusion of the provided range of elements from
    /// the structure with root `root`, using the bagging carried by `hasher`. The resulting store
    /// can be used to generate range proofs over any sub-range of the original range. Returns an
    /// error if the proof is invalid or could not be verified against the given root.
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
        let bagging = hasher.root_bagging();
        let digests =
            proof.verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)?;
        let map: HashMap<Position<F>, D> = digests.into_iter().collect();

        let size = Position::try_from(proof.leaves)?;

        // Count peaks in the fold prefix using the same leaf-coverage logic that proof
        // construction uses. Some families (for example MMB) do not order peaks by position.
        let end_loc = start_loc
            .checked_add(elements.len() as u64)
            .ok_or(Error::LocationOverflow(F::MAX_LEAVES))?;
        let bp = Blueprint::<F>::new(
            proof.leaves,
            proof.inactive_peaks,
            bagging,
            start_loc..end_loc,
        )?;
        let proof_digests = bp
            .split_proof_digests(&proof.digests)
            .map_err(|_| Error::InvalidProof)?;
        let num_fold_peaks = bp.fold_prefix.len();

        let fold_acc = if num_fold_peaks > 0 {
            Some(*proof.digests.first().ok_or(Error::InvalidProof)?)
        } else {
            None
        };
        let suffix_peaks = bp
            .suffix_peaks()
            .map_or_else(Vec::new, |peaks| peaks.to_vec());
        let suffix_acc = proof_digests.suffix_acc.copied();

        Ok(Self {
            size,
            digests: map,
            fold_acc,
            num_fold_peaks,
            suffix_peaks,
            suffix_acc,
            inactive_peaks: proof.inactive_peaks,
            bagging,
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
        let bp = Blueprint::new(leaves, self.inactive_peaks, self.bagging, range)?;

        let mut digests: Vec<D> = Vec::new();
        if !bp.fold_prefix.is_empty() {
            // Start from the stored fold accumulator (which does not include the leaf count).
            let mut acc = self.fold_acc;
            // Fold in peaks beyond those already covered by the stored accumulator.
            for sub in bp.fold_prefix.iter().skip(self.num_fold_peaks) {
                match self.digests.get(&sub.pos) {
                    Some(d) => {
                        acc = Some(acc.map_or(*d, |a| hasher.fold(&a, d)));
                    }
                    None => return Err(Error::ElementPruned(sub.pos)),
                }
            }
            digests.push(acc.expect("fold_prefix is non-empty so acc must be set"));
        }

        let prefix_active_count = bp.prefix_active_count();
        let after_count = bp.after_peaks_count();
        for &pos in &bp.fetch_nodes[..prefix_active_count + after_count] {
            match self.digests.get(&pos) {
                Some(d) => digests.push(*d),
                None => return Err(Error::ElementPruned(pos)),
            }
        }
        if let Some(suffix_peaks) = bp.suffix_peaks() {
            digests.push(self.suffix_acc(hasher, suffix_peaks)?);
        }
        for &pos in &bp.fetch_nodes[prefix_active_count + after_count..] {
            match self.digests.get(&pos) {
                Some(d) => digests.push(*d),
                None => return Err(Error::ElementPruned(pos)),
            }
        }

        Ok(Proof {
            leaves,
            inactive_peaks: self.inactive_peaks,
            digests,
        })
    }

    fn suffix_acc<H: Hasher<F, Digest = D>>(
        &self,
        hasher: &H,
        suffix_peaks: &[Position<F>],
    ) -> Result<D, Error<F>> {
        if suffix_peaks.is_empty() {
            return Err(Error::InvalidProof);
        }

        if self.suffix_peaks.is_empty() {
            let (last_pos, rest) = suffix_peaks
                .split_last()
                .expect("suffix_peaks is non-empty");
            let mut acc = *self
                .digests
                .get(last_pos)
                .ok_or(Error::ElementPruned(*last_pos))?;
            for &pos in rest.iter().rev() {
                let d = self.digests.get(&pos).ok_or(Error::ElementPruned(pos))?;
                acc = hasher.fold(d, &acc);
            }
            return Ok(acc);
        }

        if suffix_peaks.len() < self.suffix_peaks.len()
            || !suffix_peaks.ends_with(&self.suffix_peaks)
        {
            return Err(Error::ElementPruned(self.suffix_peaks[0]));
        }

        let mut acc = self.suffix_acc.ok_or(Error::InvalidProof)?;
        let visible_len = suffix_peaks.len() - self.suffix_peaks.len();
        for &pos in suffix_peaks[..visible_len].iter().rev() {
            let d = self.digests.get(&pos).ok_or(Error::ElementPruned(pos))?;
            acc = hasher.fold(d, &acc);
        }
        Ok(acc)
    }

    /// Return a multi proof for the elements corresponding to the given locations.
    ///
    /// Since multi-proofs require individual node digests (not fold accumulators), callers must
    /// supply any peak digests that the source proof did not preserve individually:
    ///
    /// - **Fold prefix peaks**: peaks entirely before the original range's start location. These
    ///   are needed whenever the original range did not start at location 0.
    /// - **Backward-fold suffix peaks**: for `BackwardFold` proofs, the active peaks after the
    ///   original range are folded into a single synthetic accumulator. The individual digests
    ///   are not in the source proof and must be supplied by the caller (see
    ///   [`ProofStore::suffix_peak_positions`]).
    ///
    /// The returned proof uses the position-keyed multi-proof layout, which keeps peaks explicit
    /// rather than collapsing them into accumulators.
    ///
    /// # Errors
    ///
    /// - [`Error::CompressedDigest`] if a required digest sits inside a backward-fold suffix
    ///   accumulator and was not supplied via `peaks`. The caller can recover by supplying it.
    /// - [`Error::ElementPruned`] if a required digest is genuinely unavailable.
    pub fn multi_proof(
        &self,
        locations: &[Location<F>],
        peaks: &[(Position<F>, D)],
    ) -> Result<Proof<F, D>, Error<F>> {
        if locations.is_empty() {
            return Err(Error::Empty);
        }

        let leaves = Location::try_from(self.size)?;
        let node_positions: BTreeSet<_> = merkle_proof::nodes_required_for_multi_proof(
            leaves,
            self.inactive_peaks,
            self.bagging,
            locations,
        )?;

        let peak_map: HashMap<Position<F>, D> = peaks.iter().copied().collect();

        let mut digests = Vec::with_capacity(node_positions.len());
        for &pos in &node_positions {
            if let Some(d) = self.digests.get(&pos) {
                digests.push(*d);
            } else if let Some(d) = peak_map.get(&pos) {
                digests.push(*d);
            } else if self.suffix_peaks.contains(&pos) {
                // The digest exists in the source structure but was folded into the synthetic
                // suffix accumulator when the original proof was built. Distinguish this from
                // genuine pruning so callers know they can recover by supplying the digest.
                return Err(Error::CompressedDigest(pos));
            } else {
                return Err(Error::ElementPruned(pos));
            }
        }

        Ok(Proof {
            leaves,
            inactive_peaks: self.inactive_peaks,
            digests,
        })
    }

    /// Returns the positions of suffix peaks that were collapsed into the source proof's
    /// backward-fold accumulator, if any.
    ///
    /// These are the positions that [`Self::multi_proof`] reports via
    /// [`Error::CompressedDigest`] when the caller has not supplied them through the `peaks`
    /// argument. The slice is empty for forward-folded proofs and for backward-folded proofs
    /// whose original range had no active suffix.
    pub fn suffix_peak_positions(&self) -> &[Position<F>] {
        &self.suffix_peaks
    }
}

/// Return a range proof for the nodes corresponding to the given location range.
///
/// The proof commits to `inactive_peaks`; peak bagging is selected by `hasher`.
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
    inactive_peaks: usize,
) -> Result<Proof<F, D>, Error<F>> {
    let leaves = Location::try_from(merkle.size().await)?;
    historical_range_proof(hasher, merkle, leaves, range, inactive_peaks).await
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
    inactive_peaks: usize,
) -> Result<Proof<F, D>, Error<F>> {
    let bp = Blueprint::new(leaves, inactive_peaks, hasher.root_bagging(), range)?;

    let mut all_positions = BTreeSet::new();
    all_positions.extend(bp.fold_prefix.iter().map(|s| s.pos));
    all_positions.extend(bp.fetch_nodes.iter().copied());
    if let Some(suffix_peaks) = bp.suffix_peaks() {
        all_positions.extend(suffix_peaks.iter().copied());
    }

    let node_futures: Vec<_> = all_positions
        .into_iter()
        .map(|pos| async move { merkle.get_node(pos).await.map(|digest| (pos, digest)) })
        .collect();
    let fetched = try_join_all(node_futures)
        .await?
        .into_iter()
        .map(|(pos, digest)| digest.ok_or(Error::ElementPruned(pos)).map(|d| (pos, d)))
        .collect::<Result<HashMap<_, _>, _>>()?;

    bp.build_proof(
        hasher,
        inactive_peaks,
        |pos| fetched.get(&pos).copied(),
        Error::ElementPruned,
    )
}

/// Return an inclusion proof for the elements at the specified locations. This is analogous to
/// range_proof but supports non-contiguous locations.
///
/// The proof commits to `inactive_peaks`; peak bagging is supplied by `bagging`.
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
    inactive_peaks: usize,
    bagging: Bagging,
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
        merkle_proof::nodes_required_for_multi_proof(leaves, inactive_peaks, bagging, locations)?;

    // Fetch all required digests in parallel and collect with positions
    let node_futures: Vec<_> = node_positions
        .iter()
        .map(|&pos| async move { merkle.get_node(pos).await.map(|digest| (pos, digest)) })
        .collect();
    // Build the proof, returning error with correct position on pruned nodes.
    let digests = try_join_all(node_futures)
        .await?
        .into_iter()
        .map(|(pos, digest)| digest.ok_or(Error::ElementPruned(pos)))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Proof {
        leaves,
        inactive_peaks,
        digests,
    })
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
            let mut mmr = Mmr::new();
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let batch = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            let root = mmr.root(&hasher, 0).unwrap();

            // Extract a ProofStore from a proof over a variety of ranges, starting with the full
            // range and shrinking each endpoint with each iteration.
            let mut range_start = Location::new(0);
            let mut range_end = Location::new(49);
            while range_start < range_end {
                let range = range_start..range_end;
                let range_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
                let proof_store = ProofStore::new(
                    &hasher,
                    &range_proof,
                    &elements[range.to_usize_range()],
                    range_start,
                    &root,
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
                        &root
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
            let mut mmr = Mmr::new();
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let batch = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            let root = mmr.root(&hasher, 0).unwrap();

            // Proof for range 32..49 has a non-empty fold prefix (the 32-leaf peak).
            // The ProofStore derives the fold accumulator from the proof itself, so
            // sub-proofs should succeed for all sub-ranges without needing peaks.
            let range = Location::new(32)..Location::new(49);
            let range_proof = mmr.range_proof(&hasher, range.clone(), 0).unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                &root,
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
                            &root
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
            let mut mmb = Mmb::new();
            let elements: Vec<_> = (0..8).map(test_digest).collect();
            let batch = {
                let mut batch = mmb.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();
            let root = mmb.root(&hasher, 0).unwrap();

            // With 8 leaves, the oldest MMB peak covers locations 0..4 but sits at position 7,
            // while the first leaf in the proven range (location 4) sits at position 6.
            // A position-based peak comparison therefore misclassifies the fold prefix.
            let range = MmbLocation::new(4)..MmbLocation::new(8);
            let range_proof = mmb.range_proof(&hasher, range.clone(), 0).unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                &root,
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
                            &root
                        ),
                        "sub-proof should verify for MMB range {start}..{end}"
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_proof_store_with_backward_fold_suffix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let inactive_peaks = 0;
            let mut mmb = Mmb::new();
            let elements: Vec<_> = (0..123).map(test_digest).collect();
            let batch = {
                let mut batch = mmb.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();
            let hasher: Standard<Sha256> = Standard::backward();
            let root = mmb.root(&hasher, inactive_peaks).unwrap();

            let range = MmbLocation::new(0)..MmbLocation::new(1);
            let proof =
                historical_range_proof(&hasher, &mmb, mmb.leaves(), range.clone(), inactive_peaks)
                    .await
                    .unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &proof,
                &elements[range.to_usize_range()],
                range.start,
                &root,
            )
            .unwrap();

            let same_range_proof = proof_store.range_proof(&hasher, range.clone()).unwrap();
            assert!(same_range_proof.verify_range_inclusion(
                &hasher,
                &elements[range.to_usize_range()],
                range.start,
                &root
            ));
            assert!(matches!(
                proof_store.range_proof(&hasher, MmbLocation::new(64)..MmbLocation::new(65)),
                Err(Error::ElementPruned(_))
            ));
        });
    }

    /// Pyramid-MMB deployments commit the canonical sync root with `split_backward(k)` for
    /// `k > 0`: the oldest `k` peaks are forward-folded into the inactive prefix accumulator and
    /// the active suffix is backward-folded. Exercises sub-range proof construction across
    /// every sub-range of the active region and asserts that sub-ranges into the inactive
    /// prefix are correctly rejected as unrecoverable.
    #[test_traced]
    fn test_verification_proof_store_with_backward_fold_inactive_prefix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmb = Mmb::new();
            let elements: Vec<_> = (0..123).map(test_digest).collect();
            let batch = {
                let mut batch = mmb.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();

            // Choose a non-zero inactive prefix and locate the first active leaf as the sum of
            // the leading peaks' leaf capacities. The proven range covers the entire active
            // region so the inactive prefix is forward-folded into the prefix accumulator and
            // any subsequent backward-fold suffix is empty (no peaks past the proven range).
            let inactive_peaks = 2;
            let active_start: u64 = crate::mmb::Family::peaks(mmb.size())
                .take(inactive_peaks)
                .map(|(_, h)| 1u64 << h)
                .sum();
            let total_leaves = *mmb.leaves();
            assert!(active_start > 0 && active_start < total_leaves);

            let hasher: Standard<Sha256> = Standard::backward();
            let root = mmb.root(&hasher, inactive_peaks).unwrap();

            let range = MmbLocation::new(active_start)..MmbLocation::new(total_leaves);
            let range_proof =
                historical_range_proof(&hasher, &mmb, mmb.leaves(), range.clone(), inactive_peaks)
                    .await
                    .unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                &root)
            .unwrap();

            // Every sub-range of the active region round-trips through the store.
            for start in active_start..total_leaves {
                for end in (start + 1)..=total_leaves {
                    let sub_range = MmbLocation::new(start)..MmbLocation::new(end);
                    let sub_proof = proof_store.range_proof(&hasher, sub_range.clone()).unwrap();
                    assert!(
                        sub_proof.verify_range_inclusion(
                            &hasher,
                            &elements[sub_range.to_usize_range()],
                            sub_range.start,
                            &root),
                        "sub-proof should verify for MMB range {start}..{end} with split_backward({inactive_peaks})"
                    );
                }
            }

            // Sub-ranges into the inactive prefix are unrecoverable: those peaks were folded
            // into the prefix accumulator and individual digests are not retained.
            assert!(matches!(
                proof_store.range_proof(&hasher, MmbLocation::new(0)..MmbLocation::new(1)),
                Err(Error::ElementPruned(_))
            ));
        });
    }

    /// Backward-folded `BackwardFold` proofs collapse the active suffix peaks into a synthetic
    /// accumulator. `multi_proof()` over a covered location must distinguish "needed digest is
    /// hidden behind that accumulator" from "needed digest is genuinely pruned" so callers know
    /// the witness is recoverable. Validates three cases:
    /// 1. A multi-proof built directly from the source structure (full witness) verifies.
    /// 2. A multi-proof derived from a backward-folded `ProofStore` returns `CompressedDigest`
    ///    (not `ElementPruned`) when suffix peak digests aren't supplied.
    /// 3. Supplying the missing suffix peaks via `peaks` unblocks verification.
    #[test_traced]
    fn test_verification_proof_store_multi_proof_backward_fold_suffix_peaks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmb = Mmb::new();
            let elements: Vec<_> = (0..123).map(test_digest).collect();
            let batch = {
                let mut batch = mmb.new_batch();
                for element in &elements {
                    batch = batch.add(&hasher, element);
                }
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();
            let hasher: Standard<Sha256> = Standard::backward();
            let inactive_peaks = 0usize;
            let root = mmb.root(&hasher, inactive_peaks).unwrap();

            let target = vec![MmbLocation::new(0)];
            let selected: Vec<_> = target
                .iter()
                .map(|&loc| (elements[*loc as usize], loc))
                .collect();

            // Case 1: multi-proof built from the source structure with the full witness verifies.
            let direct = multi_proof(&mmb, inactive_peaks, Bagging::BackwardFold, &target)
                .await
                .unwrap();
            assert!(direct.verify_multi_inclusion(&hasher, &selected, &root));

            // Build a ProofStore from a backward-folded range proof over a single leaf.
            // The other ~6 active peaks are folded into one synthetic suffix accumulator.
            let range = MmbLocation::new(0)..MmbLocation::new(1);
            let range_proof =
                historical_range_proof(&hasher, &mmb, mmb.leaves(), range.clone(), inactive_peaks)
                    .await
                    .unwrap();
            let proof_store = ProofStore::new(
                &hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                &root,
            )
            .unwrap();

            // The store knows which suffix peaks are hidden.
            let hidden = proof_store.suffix_peak_positions().to_vec();
            assert!(
                !hidden.is_empty(),
                "backward-folded proof over a partial range should have hidden suffix peaks"
            );

            // Case 2: without the missing peaks, multi_proof reports them as
            // CompressedDigest (recoverable) rather than ElementPruned (data lost).
            let result = proof_store.multi_proof(&target, &[]);
            assert!(
                !matches!(result, Err(Error::ElementPruned(_))),
                "covered location must not surface as ElementPruned; got {result:?}",
            );
            let missing_pos = match result {
                Err(Error::CompressedDigest(pos)) => pos,
                other => panic!("expected CompressedDigest, got {other:?}"),
            };
            assert!(
                hidden.contains(&missing_pos),
                "{missing_pos:?} should be one of {hidden:?}"
            );

            // Case 3: supplying every hidden peak via the `peaks` slice produces a verifying
            // multi-proof.
            let peaks: Vec<(_, _)> = hidden
                .iter()
                .map(|&pos| (pos, mmb.get_node(pos).unwrap()))
                .collect();
            let derived = proof_store.multi_proof(&target, &peaks).unwrap();
            assert!(derived.verify_multi_inclusion(&hasher, &selected, &root));
        });
    }
}
