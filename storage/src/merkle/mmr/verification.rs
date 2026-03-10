//! Defines functions for generating various [Proof] types from any MMR implementing the [Storage]
//! trait. Also defines a [ProofStore] type that can be used to generate proofs over any subset or
//! sub-range of the original range.
//!
//! ## Historical Proof Generation
//!
//! This module provides both current and historical proof generation capabilities:
//! - [range_proof] generates proofs against the current MMR state
//! - [historical_range_proof] generates proofs against historical MMR states
//!
//! Historical proofs are essential for sync operations where we need to prove elements against a
//! past state of the MMR rather than its current state.

use crate::mmr::{hasher::Hasher, proof, storage::Storage, Error, Location, Mmr, Position, Proof};
use commonware_cryptography::Digest;
use core::ops::Range;
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashMap};

/// A store derived from a [Proof] that can be used to generate proofs over any sub-range of the
/// original range.
///
/// Stores individual node digests extracted during proof verification. For peaks that were folded
/// in the original proof, the folded accumulator is stored so that sub-proofs can reuse it.
pub struct ProofStore<D> {
    digests: HashMap<Position, D>,
    leaves: Location,
    size: Position,
    /// The fold accumulator covering the original proof's fold_prefix peaks and Hash(leaves).
    /// When generating sub-proofs whose fold_prefix is a superset of the original, this
    /// accumulator serves as the starting point.
    fold_acc: D,
    /// The set of peak positions whose digests were folded into `fold_acc`.
    folded_peaks: Vec<Position>,
}

impl<D: Digest> ProofStore<D> {
    /// Create a new [ProofStore] from a valid [Proof] over the given range of elements. The
    /// resulting store can be used to generate proofs over any sub-range of the original range.
    /// Returns an error if the proof is invalid or could not be verified against the given root.
    pub fn new<H, E>(
        hasher: &mut H,
        proof: &Proof<D>,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> Result<Self, Error>
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        let digests =
            proof.verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)?;

        let bp = proof::nodes_required_for_range_proof(
            proof.leaves,
            start_loc..start_loc + elements.len() as u64,
        )?;

        let fold_acc = if !bp.fold_prefix.is_empty() {
            proof.digests[0]
        } else {
            hasher.digest(&proof.leaves.as_u64().to_be_bytes())
        };

        Ok(Self {
            size: Position::try_from(proof.leaves)?,
            leaves: proof.leaves,
            digests: digests.into_iter().collect(),
            fold_acc,
            folded_peaks: bp.fold_prefix,
        })
    }

    /// Create a new [ProofStore] from the result of calling
    /// [Proof::verify_range_inclusion_and_extract_digests]. The resulting store can be used to
    /// generate proofs over any sub-range of the original range.
    pub fn new_from_digests<H: Hasher<Mmr, Digest = D>>(
        hasher: &mut H,
        leaves: Location,
        digests: Vec<(Position, D)>,
    ) -> Result<Self, Error> {
        let size = Position::try_from(leaves)?;
        let fold_acc = hasher.digest(&leaves.as_u64().to_be_bytes());
        Ok(Self {
            size,
            leaves,
            digests: digests.into_iter().collect(),
            fold_acc,
            folded_peaks: Vec::new(),
        })
    }

    /// Return a range proof for the nodes corresponding to the given location range.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<Mmr, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        let bp = proof::nodes_required_for_range_proof(self.leaves, range)?;

        let mut digests = Vec::new();

        // Build the fold prefix. The sub-range's fold_prefix may include peaks that were
        // already folded in the original proof. Use the stored fold_acc as the starting point
        // and fold any additional peaks from our digest map.
        if !bp.fold_prefix.is_empty() {
            let mut acc = self.fold_acc;
            for &peak_pos in &bp.fold_prefix {
                if self.folded_peaks.contains(&peak_pos) {
                    // Already folded into fold_acc.
                    continue;
                }
                let peak_d = self
                    .digests
                    .get(&peak_pos)
                    .ok_or(Error::ElementPruned(peak_pos))?;
                acc = hasher.fold_peak(&acc, peak_d);
            }
            digests.push(acc);
        }

        // Fetch raw digests for after-peaks and siblings.
        for &pos in &bp.fetch_nodes {
            let d = self
                .digests
                .get(&pos)
                .ok_or(Error::ElementPruned(pos))?;
            digests.push(*d);
        }

        Ok(Proof {
            leaves: self.leaves,
            digests,
        })
    }

    /// Return a multi proof for the elements corresponding to the given locations.
    pub async fn multi_proof(&self, locations: &[Location]) -> Result<Proof<D>, Error> {
        multi_proof(self, locations).await
    }
}

impl<D: Digest> Storage<Mmr, D> for ProofStore<D> {
    async fn get_node(&self, pos: Position) -> Result<Option<D>, Error> {
        Ok(self.digests.get(&pos).cloned())
    }

    async fn size(&self) -> Position {
        self.size
    }
}

/// Return a range proof for the nodes corresponding to the given location range.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `range` > [crate::mmr::MAX_LOCATION]
/// Returns [Error::RangeOutOfBounds] if any location in `range` > `mmr.size()`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if the requested range is empty
pub async fn range_proof<D: Digest, S: Storage<Mmr, D>>(
    mmr: &S,
    hasher: &mut impl Hasher<Mmr, Digest = D>,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let leaves = Location::try_from(mmr.size().await)?;
    historical_range_proof(mmr, hasher, leaves, range).await
}

/// Analogous to range_proof but for a previous database state. Specifically, the state when the MMR
/// had `leaves` leaves.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `range` > [crate::mmr::MAX_LOCATION]
/// Returns [Error::RangeOutOfBounds] if any location in `range` > `leaves`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if the requested range is empty
pub async fn historical_range_proof<D: Digest, S: Storage<Mmr, D>>(
    mmr: &S,
    hasher: &mut impl Hasher<Mmr, Digest = D>,
    leaves: Location,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let bp = proof::nodes_required_for_range_proof(leaves, range)?;

    let mut digests = Vec::new();

    // Fold preceding peaks into a single accumulator digest.
    if !bp.fold_prefix.is_empty() {
        let mut acc = hasher.digest(&leaves.as_u64().to_be_bytes());
        for &peak_pos in &bp.fold_prefix {
            let peak_d = mmr
                .get_node(peak_pos)
                .await?
                .ok_or(Error::ElementPruned(peak_pos))?;
            acc = hasher.fold_peak(&acc, &peak_d);
        }
        digests.push(acc);
    }

    // Fetch raw digests for after-peaks and siblings.
    let node_futures = bp.fetch_nodes.iter().map(|pos| mmr.get_node(*pos));
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
/// Returns [Error::LocationOverflow] if any location in `locations` > [crate::mmr::MAX_LOCATION]
/// Returns [Error::RangeOutOfBounds] if any location in `locations` > `mmr.size()`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if locations is empty
pub async fn multi_proof<D: Digest, S: Storage<Mmr, D>>(
    mmr: &S,
    locations: &[Location],
) -> Result<Proof<D>, Error> {
    if locations.is_empty() {
        // Disallow proofs over empty element lists just as we disallow proofs over empty ranges.
        return Err(Error::Empty);
    }

    // Collect all required node positions
    let size = mmr.size().await;
    let leaves = Location::try_from(size)?;
    let node_positions: BTreeSet<_> = proof::nodes_required_for_multi_proof(leaves, locations)?;

    // Fetch all required digests in parallel and collect with positions
    let node_futures: Vec<_> = node_positions
        .iter()
        .map(|&pos| async move { mmr.get_node(pos).await.map(|digest| (pos, digest)) })
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
    use crate::mmr::{mem::DirtyMmr, LocationRangeExt as _, StandardHasher as Standard};
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
            let mut mmr = DirtyMmr::new();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
            }
            let mmr = mmr.merkleize(&mut hasher, None);
            let root = mmr.root();

            // Extract a ProofStore from a proof over a variety of ranges, starting with the full
            // range and shrinking each endpoint with each iteration.
            let mut range_start = Location::new(0);
            let mut range_end = Location::new(49);
            while range_start < range_end {
                let range = range_start..range_end;
                let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
                let proof_store = ProofStore::new(
                    &mut hasher,
                    &range_proof,
                    &elements[range.to_usize_range()],
                    range_start,
                    root,
                )
                .unwrap();

                // Verify that the ProofStore can be used to generate proofs over a host of sub-ranges
                // starting with the full range down to a range containing a single element.
                let mut subrange_start = range_start;
                let mut subrange_end = range_end;
                while subrange_start < subrange_end {
                    // Verify a proof over a sub-range of the original range.
                    let sub_range = subrange_start..subrange_end;
                    let sub_range_proof = proof_store
                        .range_proof(&mut hasher, sub_range.clone())
                        .unwrap();
                    assert!(sub_range_proof.verify_range_inclusion(
                        &mut hasher,
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
}
