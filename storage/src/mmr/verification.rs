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

use crate::mmr::{hasher::Hasher, proof, storage::Storage, Error, Proof};
use commonware_cryptography::{Digest, Hasher as CHasher};
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashMap};

/// A store derived from a [Proof] that can be used to generate proofs over any sub-range of the
/// original range.
pub struct ProofStore<D> {
    digests: HashMap<u64, D>,
    size: u64,
}

impl<D: Digest> ProofStore<D> {
    /// Create a new [ProofStore] from a valid [Proof] over the given range of elements. The
    /// resulting store can be used to generate proofs over any sub-range of the original range.
    /// Returns an error if the proof is invalid or could not be verified against the given root.
    pub fn new<I, H, E>(
        hasher: &mut H,
        proof: &Proof<D>,
        elements: &[E],
        start_element_pos: u64,
        root: &D,
    ) -> Result<Self, Error>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        let digests = proof.verify_range_inclusion_and_extract_digests(
            hasher,
            elements,
            start_element_pos,
            root,
        )?;

        Ok(ProofStore::new_from_digests(proof.size, digests))
    }

    /// Create a new [ProofStore] from the result of calling
    /// [Proof::verify_range_inclusion_and_extract_digests]. The resulting store can be used to
    /// generate proofs over any sub-range of the original range.
    pub fn new_from_digests(size: u64, digests: Vec<(u64, D)>) -> Self {
        Self {
            size,
            digests: digests.into_iter().collect(),
        }
    }

    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<D>, Error> {
        range_proof(self, start_element_pos, end_element_pos).await
    }

    pub async fn multi_proof(&self, positions: &[u64]) -> Result<Proof<D>, Error> {
        multi_proof(self, positions).await
    }
}

impl<D: Digest> Storage<D> for ProofStore<D> {
    async fn get_node(&self, pos: u64) -> Result<Option<D>, Error> {
        Ok(self.digests.get(&pos).cloned())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
/// Returns ElementPruned error if some element needed to generate the proof has been pruned.
pub async fn range_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    start_element_pos: u64,
    end_element_pos: u64,
) -> Result<Proof<D>, Error> {
    historical_range_proof(mmr, mmr.size(), start_element_pos, end_element_pos).await
}

/// Analogous to range_proof but for a previous database state.
/// Specifically, the state when the MMR had `size` elements.
pub async fn historical_range_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    size: u64,
    start_element_pos: u64,
    end_element_pos: u64,
) -> Result<Proof<D>, Error> {
    assert!(start_element_pos <= end_element_pos);
    assert!(start_element_pos < mmr.size());
    assert!(end_element_pos < mmr.size());

    let mut digests: Vec<D> = Vec::new();
    let positions = proof::nodes_required_for_range_proof(size, start_element_pos, end_element_pos);

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

/// Return an inclusion proof for the specified positions. This is analogous to range_proof but
/// supports non-contiguous positions.
///
/// The order of positions does not affect the output (sorted internally).
pub async fn multi_proof<D: Digest, S: Storage<D>>(
    mmr: &S,
    positions: &[u64],
) -> Result<Proof<D>, Error> {
    // If there are no positions, return an empty proof
    let size = mmr.size();
    if positions.is_empty() {
        return Ok(Proof {
            size,
            digests: vec![],
        });
    }

    // Collect all required node positions
    let node_positions: BTreeSet<_> = proof::nodes_required_for_multi_proof(size, positions);

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
    use crate::mmr::{mem::Mmr, StandardHasher as Standard};
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
            let mut range_start = 0;
            let mut range_end = 48;
            while range_start <= range_end {
                let range_proof = mmr
                    .range_proof(element_positions[range_start], element_positions[range_end])
                    .unwrap();
                let proof_store = ProofStore::new(
                    &mut hasher,
                    &range_proof,
                    &elements[range_start..range_end + 1],
                    element_positions[range_start],
                    &root,
                )
                .unwrap();

                // Verify that the ProofStore can be used to generate proofs over a host of sub-ranges
                // starting with the full range down to a range containing a single element.
                let mut subrange_start = range_start;
                let mut subrange_end = range_end;
                while subrange_start <= subrange_end {
                    // Verify a proof over a sub-range of the original range.
                    let sub_range_proof = proof_store
                        .range_proof(
                            element_positions[subrange_start],
                            element_positions[subrange_end],
                        )
                        .await
                        .unwrap();
                    assert!(sub_range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[subrange_start..subrange_end + 1],
                        element_positions[subrange_start],
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
