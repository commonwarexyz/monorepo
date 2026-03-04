//! Async proof generation for MMBs backed by any [Storage] implementation.

use crate::mmb::{hasher::Hasher, proof, proof::Proof, storage::Storage, Error, Location, Mmb};
use commonware_cryptography::Digest;
use core::ops::Range;
use futures::future::try_join_all;

/// Return a range proof for the given location range against the current MMB state.
pub async fn range_proof<D: Digest, S: Storage<Mmb, D>>(
    mmb: &S,
    hasher: &mut impl Hasher<Mmb, Digest = D>,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let leaves = Location::try_from(mmb.size().await)?;
    historical_range_proof(mmb, hasher, leaves, range).await
}

/// Return a range proof for the given location range against a historical MMB state with `leaves`
/// leaves.
pub async fn historical_range_proof<D: Digest, S: Storage<Mmb, D>>(
    mmb: &S,
    hasher: &mut impl Hasher<Mmb, Digest = D>,
    leaves: Location,
    range: Range<Location>,
) -> Result<Proof<D>, Error> {
    let bp = proof::nodes_required_for_range_proof(leaves, range)?;

    let mut digests = Vec::new();

    // Fold preceding peaks into a single accumulator digest.
    if !bp.fold_prefix.is_empty() {
        let mut acc = hasher.digest(&leaves.as_u64().to_be_bytes());
        for &peak_pos in &bp.fold_prefix {
            let peak_d = mmb
                .get_node(peak_pos)
                .await?
                .ok_or(Error::ElementPruned(peak_pos))?;
            acc = hasher.fold_peak(&acc, &peak_d);
        }
        digests.push(acc);
    }

    // Fetch raw digests for after-peaks and siblings.
    let node_futures = bp.fetch_nodes.iter().map(|pos| mmb.get_node(*pos));
    let results = try_join_all(node_futures).await?;
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Some(d) => digests.push(d),
            None => return Err(Error::ElementPruned(bp.fetch_nodes[i])),
        }
    }

    Ok(Proof { leaves, digests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmb::{
        hasher::Standard,
        mem::{CleanMmb, DirtyMmb},
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    fn build_mmb(n: u64) -> CleanMmb<D> {
        let mut hasher = H::new();
        let mut mmb = DirtyMmb::new();
        for i in 0..n {
            mmb.add(&mut hasher, &i.to_be_bytes());
        }
        mmb.merkleize(&mut hasher, None)
    }

    #[test_traced]
    fn test_async_range_proof_matches_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = H::new();

            for n in 1u64..=64 {
                let mmb = build_mmb(n);
                let root = *mmb.root();

                for start in 0..n {
                    for end in (start + 1)..=n {
                        let loc_range = Location::new(start)..Location::new(end);

                        // Generate proof via sync in-memory method.
                        let sync_proof = mmb.range_proof(&mut hasher, loc_range.clone()).unwrap();

                        // Generate proof via async Storage-based method.
                        let async_proof =
                            range_proof(&mmb, &mut hasher, loc_range.clone()).await.unwrap();

                        assert_eq!(
                            sync_proof.digests, async_proof.digests,
                            "n={n}, range={start}..{end}: proof mismatch"
                        );

                        // Verify both proofs work.
                        let elements: Vec<_> =
                            (start..end).map(|i| i.to_be_bytes()).collect();
                        assert!(
                            async_proof.verify_range_inclusion(
                                &mut hasher,
                                &elements,
                                Location::new(start),
                                &root,
                            ),
                            "n={n}, range={start}..{end}: async proof verification failed"
                        );
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_historical_range_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = H::new();

            // Build MMB with 50 elements.
            let mmb = build_mmb(50);

            // Build a reference MMB with 30 elements to get the historical root.
            let ref_mmb = build_mmb(30);
            let historical_leaves = ref_mmb.leaves();
            let historical_root = *ref_mmb.root();

            // Generate historical proof from the full MMB.
            let range = Location::new(5)..Location::new(20);
            let proof = historical_range_proof(&mmb, &mut hasher, historical_leaves, range.clone())
                .await
                .unwrap();

            // Verify against historical root.
            let elements: Vec<_> = (5u64..20).map(|i| i.to_be_bytes()).collect();
            assert!(proof.verify_range_inclusion(
                &mut hasher,
                &elements,
                range.start,
                &historical_root,
            ));
        });
    }
}
