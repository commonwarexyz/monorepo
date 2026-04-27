//! Re-exports of the generic verification module, specialized for the MMR [Family].

use crate::merkle::{
    hasher::Hasher,
    mmr::{Error, Family, Location, Proof},
    storage::Storage,
    RootSpec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMR-specialized [ProofStore](crate::merkle::verification::ProofStore).
pub type ProofStore<D> = crate::merkle::verification::ProofStore<Family, D>;

/// Return a range proof for the nodes corresponding to the given location range.
///
/// This is a thin wrapper around the generic
/// [range_proof](crate::merkle::verification::range_proof), specialized for the MMR family.
pub async fn range_proof<
    D: Digest,
    H: Hasher<Family, Digest = D>,
    S: Storage<Family, Digest = D>,
>(
    hasher: &H,
    mmr: &S,
    range: Range<Location>,
    spec: RootSpec,
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::range_proof(hasher, mmr, range, spec).await
}

/// Analogous to [range_proof] but for a previous database state.
///
/// This is a thin wrapper around the generic
/// [historical_range_proof](crate::merkle::verification::historical_range_proof), specialized for
/// the MMR family.
pub async fn historical_range_proof<
    D: Digest,
    H: Hasher<Family, Digest = D>,
    S: Storage<Family, Digest = D>,
>(
    hasher: &H,
    mmr: &S,
    leaves: Location,
    range: Range<Location>,
    spec: RootSpec,
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::historical_range_proof(hasher, mmr, leaves, range, spec).await
}

/// Return an inclusion proof for the elements at the specified locations.
///
/// This is a thin wrapper around the generic
/// [multi_proof](crate::merkle::verification::multi_proof), specialized for the MMR family.
pub async fn multi_proof<D: Digest, S: Storage<Family, Digest = D>>(
    mmr: &S,
    spec: RootSpec,
    locations: &[Location],
) -> Result<Proof<D>, Error> {
    crate::merkle::verification::multi_proof(mmr, spec, locations).await
}
