//! Helpers for constructing votes and certificates in tests.

use crate::simplex::{
    scheme::Scheme,
    types::{Certified, Phase, Signed},
};
use commonware_cryptography::Digest;
use commonware_parallel::Sequential;

/// Signs a vote of phase `P` over `claim` with each scheme.
pub fn sign_votes<'a, P, S, D>(
    schemes: impl IntoIterator<Item = &'a S>,
    claim: &P::Claim<D>,
) -> Vec<Signed<P, S, D>>
where
    P: Phase,
    S: Scheme<D> + 'a,
    D: Digest,
{
    schemes
        .into_iter()
        .map(|scheme| Signed::sign(scheme, claim.clone()).expect("scheme can sign"))
        .collect()
}

/// Builds a certificate of phase `P` from `votes`, assembled by `assembler`.
pub fn build_certificate<P, S, D>(assembler: &S, votes: &[Signed<P, S, D>]) -> Certified<P, S, D>
where
    P: Phase,
    S: Scheme<D>,
    D: Digest,
{
    Certified::from_votes(assembler, votes, &Sequential)
        .expect("certificate requires a quorum of votes")
}
