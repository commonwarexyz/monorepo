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

use crate::mmr::{hasher::Hasher, proof, storage::Storage, Error, Location, Position, Proof};
use commonware_cryptography::{Digest, Hasher as CHasher};
use core::ops::Range;
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashMap};

/// A store derived from a [Proof] that can be used to generate proofs over any sub-range of the
/// original range.
pub struct ProofStore<D> {
    digests: HashMap<Position, D>,
    size: Position,
}

impl<D: Digest> ProofStore<D> {
    /// Create a new [ProofStore] from a valid [Proof] over the given range of elements. The
    /// resulting store can be used to generate proofs over any sub-range of the original range.
    /// Returns an error if the proof is invalid or could not be verified against the given root.
    pub fn new<I, H, E>(
        hasher: &mut H,
        proof: &Proof<D>,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> Result<Self, Error>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        let digests =
            proof.verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)?;

        Ok(ProofStore::new_from_digests(proof.size, digests))
    }

    /// Create a new [ProofStore] from the result of calling
    /// [Proof::verify_range_inclusion_and_extract_digests]. The resulting store can be used to
    /// generate proofs over any sub-range of the original range.
    pub fn new_from_digests(size: Position, digests: Vec<(Position, D)>) -> Self {
        Self {
            size,
            digests: digests.into_iter().collect(),
        }
    }

    /// Return a range proof for the nodes corresponding to the given location range.
    pub async fn range_proof(&self, range: Range<Location>) -> Result<Proof<D>, Error> {
        range_proof(self, range).await
    }

    /// Return a multi proof for the elements corresponding to the given locations.
    pub async fn multi_proof(&self, locations: &[Location]) -> Result<Proof<D>, Error> {
        multi_proof(self, locations).await
    }
}

impl<D: Digest> Storage<D> for ProofStore<D> {
    async fn get_node(&self, pos: Position) -> Result<Option<D>, Error> {
        Ok(self.digests.get(&pos).cloned())
    }

    fn size(&self) -> Position {
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
pub async fn range_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    historical_range_proof(mmr, mmr.size(), range).await
}

/// Analogous to range_proof but for a previous database state. Specifically, the state when the MMR
/// had `size` nodes.
///
/// # Errors
///
/// Returns [Error::LocationOverflow] if any location in `range` > [crate::mmr::MAX_LOCATION]
/// Returns [Error::RangeOutOfBounds] if any location in `range` > `size`
/// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned
/// Returns [Error::Empty] if the requested range is empty
pub async fn historical_range_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    size: Position,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    // Get the positions of all nodes needed to generate the proof.
    let positions = proof::nodes_required_for_range_proof(size, range)?;

    // Fetch the digest of each.
    let mut digests: Vec<D> = Vec::new();
    let node_futures = positions.iter().map(|pos| mmr.get_node(*pos));
    let hash_results = try_join_all(node_futures).await?;

    for (i, hash_result) in hash_results.into_iter().enumerate() {
        match hash_result {
            Some(hash) => digests.push(hash),
            None => return Err(Error::ElementPruned(positions[i])),
        };
    }

    Ok(Proof { size, digests })
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
pub async fn multi_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    locations: &[Location],
) -> Result<Proof<D>, Error> {
    if locations.is_empty() {
        // Disallow proofs over empty element lists just as we disallow proofs over empty ranges.
        return Err(Error::Empty);
    }

    // Collect all required node positions
    let size = mmr.size();
    let node_positions: BTreeSet<_> = proof::nodes_required_for_multi_proof(size, locations)?;

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

    Ok(Proof { size, digests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{location::LocationRangeExt as _, mem::Mmr, StandardHasher as Standard};
    use commonware_cryptography::{sha256::Digest, Sha256};
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
            let mut mmr = Mmr::default();
            let mut elements = Vec::new();
            let mut element_positions = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0..49 {
                elements.push(test_digest(i));
                element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
            }
            let root = mmr.root(&mut hasher);

            // Extract a ProofStore from a proof over a variety of ranges, starting with the full
            // range and shrinking each endpoint with each iteration.
            let mut range_start = Location::new_unchecked(0);
            let mut range_end = Location::new_unchecked(49);
            while range_start < range_end {
                let range = range_start..range_end;
                let range_proof = mmr.range_proof(range.clone()).unwrap();
                let proof_store = ProofStore::new(
                    &mut hasher,
                    &range_proof,
                    &elements[range.to_usize_range()],
                    range_start,
                    &root,
                )
                .unwrap();

                // Verify that the ProofStore can be used to generate proofs over a host of sub-ranges
                // starting with the full range down to a range containing a single element.
                let mut subrange_start = range_start;
                let mut subrange_end = range_end;
                while subrange_start < subrange_end {
                    // Verify a proof over a sub-range of the original range.
                    let sub_range = subrange_start..subrange_end;
                    let sub_range_proof = proof_store.range_proof(sub_range.clone()).await.unwrap();
                    assert!(sub_range_proof.verify_range_inclusion(
                        &mut hasher,
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
}
