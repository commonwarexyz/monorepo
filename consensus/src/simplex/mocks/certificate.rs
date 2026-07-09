//! Helpers for constructing votes and certificates in tests.

use crate::simplex::{
    scheme::Scheme,
    types::{Certified, Kind, Signed},
};
use commonware_cryptography::Digest;
use commonware_parallel::Sequential;

/// Signs a vote of kind `K` over `payload` with each scheme.
pub fn sign_votes<'a, K, S, D>(
    schemes: impl IntoIterator<Item = &'a S>,
    payload: &K::Payload,
) -> Vec<Signed<K, S, D>>
where
    K: Kind<D>,
    S: Scheme<D> + 'a,
    D: Digest,
{
    schemes
        .into_iter()
        .map(|scheme| Signed::sign(scheme, payload.clone()).expect("scheme can sign"))
        .collect()
}

/// Builds a certificate of kind `K` from `votes`, assembled by `assembler`.
pub fn build_certificate<K, S, D>(assembler: &S, votes: &[Signed<K, S, D>]) -> Certified<K, S, D>
where
    K: Kind<D>,
    S: Scheme<D>,
    D: Digest,
{
    Certified::from_votes(assembler, votes, &Sequential)
        .expect("certificate requires a quorum of votes")
}
