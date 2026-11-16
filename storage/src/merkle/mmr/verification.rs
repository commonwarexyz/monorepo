//! Re-exports of the generic verification module, specialized for the MMR [Family].

use crate::merkle::{
    hasher::Hasher,
    mmr::{Error, Family, Location, Proof},
    storage::Storage,
};
use core::ops::Range;

/// MMR-specialized [ProofStore](crate::merkle::verification::ProofStore).
pub type ProofStore<D> = crate::merkle::verification::ProofStore<Family, D>;

/// Return a range proof for the nodes corresponding to the given location range.
pub async fn range_proof<H: Hasher<Family>, S: Storage<Family, Digest = H::Digest>>(
    hasher: &H,
    mmr: &S,
    range: Range<Location>,
    inactive_peaks: usize,
) -> Result<Proof<H::Digest>, Error> {
    crate::merkle::verification::range_proof(hasher, mmr, range, inactive_peaks).await
}

/// Analogous to [range_proof] but for a previous database state.
pub async fn historical_range_proof<H: Hasher<Family>, S: Storage<Family, Digest = H::Digest>>(
    hasher: &H,
    mmr: &S,
    leaves: Location,
    range: Range<Location>,
    inactive_peaks: usize,
) -> Result<Proof<H::Digest>, Error> {
    crate::merkle::verification::historical_range_proof(hasher, mmr, leaves, range, inactive_peaks)
        .await
}

/// Return an inclusion proof for the elements at the specified locations.
///
/// Locations must be strictly ascending. The error names the first invalid location:
/// [Error::DuplicateLocation] if it repeats the location before it and [Error::UnsortedLocation]
/// if it precedes it.
pub async fn multi_proof<S: Storage<Family>>(
    mmr: &S,
    inactive_peaks: usize,
    locations: &[Location],
) -> Result<Proof<S::Digest>, Error> {
    crate::merkle::verification::multi_proof(mmr, inactive_peaks, locations).await
}
