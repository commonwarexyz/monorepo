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
use commonware_cryptography::Digest;
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
    /// Create a [ProofStore] from a [Proof] of inclusion of the provided range of elements from the
    /// MMR with root `root` and peaks `peaks`. The resulting store can be used to generate proofs
    /// over any sub-range of the original range. Returns an error if the proof is invalid or could
    /// not be verified against the given root.
    pub fn new<H, E>(
        hasher: &mut H,
        proof: &Proof<D>,
        elements: &[E],
        start_loc: Location,
        root: &D,
        peaks: &[(Position, D)],
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        E: AsRef<[u8]>,
    {
        let digests =
            proof.verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)?;
        let mut map: HashMap<Position, D> = digests.into_iter().collect();
        for &(pos, digest) in peaks {
            match map.get(&pos) {
                Some(existing) if *existing != digest => return Err(Error::InvalidProof),
                Some(_) => {}
                None => {
                    map.insert(pos, digest);
                }
            }
        }
        Ok(Self {
            size: Position::try_from(proof.leaves)?,
            digests: map,
        })
    }

    /// Return a range proof for the nodes corresponding to the given location range.
    pub async fn range_proof<H: Hasher<Digest = D>>(
        &self,
        hasher: &mut H,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        range_proof(hasher, self, range).await
    }

    /// Return a multi proof for the elements corresponding to the given locations.
    pub async fn multi_proof(&self, locations: &[Location]) -> Result<Proof<D>, Error> {
        multi_proof(self, locations).await
    }
}

impl<D: Digest> Storage for ProofStore<D> {
    type Digest = D;
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
pub async fn range_proof<D: Digest, H: Hasher<Digest = D>, S: Storage<Digest = D>>(
    hasher: &mut H,
    mmr: &S,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let leaves = Location::try_from(mmr.size().await)?;
    historical_range_proof(hasher, mmr, leaves, range).await
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
pub async fn historical_range_proof<D: Digest, H: Hasher<Digest = D>, S: Storage<Digest = D>>(
    hasher: &mut H,
    mmr: &S,
    leaves: Location,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let bp = proof::proof_blueprint(leaves, range)?;

    let mut digests: Vec<D> = Vec::new();
    if !bp.fold_prefix.is_empty() {
        let mut acc = hasher.digest(&leaves.to_be_bytes());
        let node_futures = bp.fold_prefix.iter().map(|&pos| mmr.get_node(pos));
        let results = try_join_all(node_futures).await?;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Some(d) => acc = hasher.fold(&acc, &d),
                None => return Err(Error::ElementPruned(bp.fold_prefix[i])),
            }
        }
        digests.push(acc);
    }

    let node_futures = bp.fetch_nodes.iter().map(|&pos| mmr.get_node(pos));
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
pub async fn multi_proof<D: Digest, S: Storage<Digest = D>>(
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
    use crate::mmr::{location::LocationRangeExt as _, mem::Mmr, StandardHasher as Standard};
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let changeset = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch.add(&mut hasher, element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let root = mmr.root();

            // Collect all peak (position, digest) pairs for supplying to ProofStore.
            let peaks: Vec<(Position, Digest)> = mmr
                .peak_iterator()
                .map(|(pos, _)| (pos, mmr.get_node(pos).unwrap()))
                .collect();

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
                    &peaks,
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
                        .await
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

    #[test_traced]
    fn test_verification_proof_store_with_fold_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build MMR with 49 elements. Peaks cover locations 0-31, 32-47, 48.
            // A proof starting at location 32 puts the first peak entirely in the fold prefix.
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let elements: Vec<_> = (0..49).map(test_digest).collect();
            let changeset = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch.add(&mut hasher, element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let root = mmr.root();

            // Collect peak digests from the MMR.
            let peaks: Vec<(Position, Digest)> = mmr
                .peak_iterator()
                .map(|(pos, _)| (pos, mmr.get_node(pos).unwrap()))
                .collect();

            // Proof for range 32..49 has a non-empty fold prefix (the 32-leaf peak).
            let range = Location::new(32)..Location::new(49);
            let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();

            // Without peaks, sub-proof generation should fail for sub-ranges that need the
            // fold-prefix peak individually.
            let no_peaks_store = ProofStore::new(
                &mut hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                root,
                &[],
            )
            .unwrap();
            // A sub-range that starts at the same location would need the same fold prefix,
            // which requires fetching the individual peak digest from the store.
            let sub_range = Location::new(32)..Location::new(40);
            assert!(
                no_peaks_store
                    .range_proof(&mut hasher, sub_range)
                    .await
                    .is_err(),
                "sub-proof should fail without peaks for fold-prefix"
            );

            // With peaks supplied, the ProofStore has the individual peak digests.
            let with_peaks_store = ProofStore::new(
                &mut hasher,
                &range_proof,
                &elements[range.to_usize_range()],
                range.start,
                root,
                &peaks,
            )
            .unwrap();

            // Sub-proofs should now succeed for all sub-ranges.
            for start in 32u64..49 {
                for end in (start + 1)..=49 {
                    let sub_range = Location::new(start)..Location::new(end);
                    let sub_proof = with_peaks_store
                        .range_proof(&mut hasher, sub_range.clone())
                        .await
                        .unwrap();
                    assert!(
                        sub_proof.verify_range_inclusion(
                            &mut hasher,
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
    fn test_verification_proof_store_rejects_conflicting_peak() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let elements: Vec<_> = (0..15).map(test_digest).collect();
            let changeset = {
                let mut batch = mmr.new_batch();
                for element in &elements {
                    batch.add(&mut hasher, element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let root = mmr.root();

            let range = Location::new(0)..Location::new(3);
            let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();

            let conflicting_peak = Position::new(0);
            let result = ProofStore::new(
                &mut hasher,
                &proof,
                &elements[range.to_usize_range()],
                range.start,
                root,
                &[(conflicting_peak, test_digest(255))],
            );
            assert!(
                matches!(result, Err(Error::InvalidProof)),
                "conflicting supplied peak should be rejected"
            );
        });
    }
}
