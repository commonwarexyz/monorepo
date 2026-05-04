//! Re-exports of the generic verification module, specialized for the MMR [Family].

use crate::merkle::{
    hasher::Hasher,
    mmr::{Error, Family, Location, Proof},
    storage::Storage,
    Bagging,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMR-specialized [ProofStore](crate::merkle::verification::ProofStore).
pub type ProofStore<D> = crate::merkle::verification::ProofStore<Family, D>;

/// Return a range proof for the nodes corresponding to the given location range.
pub async fn range_proof<
    D: Digest,
    H: Hasher<Family, Digest = D>,
    S: Storage<Family, Digest = D>,
>(
    hasher: &H,
    mmr: &S,
    range: Range<Location>,
    inactive_peaks: usize,
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::range_proof(hasher, mmr, range, inactive_peaks).await
}

/// Analogous to [range_proof] but for a previous database state.
pub async fn historical_range_proof<
    D: Digest,
    H: Hasher<Family, Digest = D>,
    S: Storage<Family, Digest = D>,
>(
    hasher: &H,
    mmr: &S,
    leaves: Location,
    range: Range<Location>,
    inactive_peaks: usize,
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::historical_range_proof(hasher, mmr, leaves, range, inactive_peaks)
        .await
}

/// Return an inclusion proof for the elements at the specified locations.
pub async fn multi_proof<D: Digest, S: Storage<Family, Digest = D>>(
    mmr: &S,
    inactive_peaks: usize,
    bagging: Bagging,
    locations: &[Location],
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::multi_proof(mmr, inactive_peaks, bagging, locations).await
}
