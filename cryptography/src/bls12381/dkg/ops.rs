//! Stateless operations useful in a DKG/Resharing procedure.

use crate::bls12381::{
    dkg::Error,
    primitives::{group::Share, poly},
};
use rand::RngCore;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::BTreeMap;

/// Generate shares and a commitment.
pub fn generate_shares<R: RngCore>(
    rng: &mut R,
    share: Option<Share>,
    n: u32,
    t: u32,
) -> (poly::Public, Vec<Share>) {
    // Generate a secret polynomial and commit to it
    let mut secret = poly::new_from(t - 1, rng);
    if let Some(share) = share {
        // Set the free coefficient of the secret polynomial to the secret
        // of the previous DKG
        secret.set(0, share.private);
    }

    // Commit to polynomial and generate shares
    let commitment = poly::Public::commit(secret.clone());
    let shares = (0..n)
        .map(|i| {
            let eval = secret.evaluate(i);
            Share {
                index: eval.index,
                private: eval.value,
            }
        })
        .collect::<Vec<_>>();
    (commitment, shares)
}

/// Verify that a given commitment is valid for a dealer. If a previous
/// polynomial is provided, verify that the commitment is on that polynomial.
pub fn verify_commitment(
    previous: Option<&poly::Public>,
    dealer: u32,
    commitment: &poly::Public,
    t: u32,
) -> Result<(), Error> {
    if let Some(previous) = previous {
        let expected = previous.evaluate(dealer).value;
        if expected != *commitment.constant() {
            return Err(Error::UnexpectedPolynomial);
        }
    }
    if commitment.degree() != t - 1 {
        return Err(Error::CommitmentWrongDegree);
    }
    Ok(())
}

/// Verify that a given share is valid for a specified recipient.
pub fn verify_share(
    previous: Option<&poly::Public>,
    dealer: u32,
    commitment: &poly::Public,
    t: u32,
    recipient: u32,
    share: &Share,
) -> Result<(), Error> {
    // Verify that commitment is on previous public polynomial (if provided)
    verify_commitment(previous, dealer, commitment, t)?;

    // Check if share is valid
    if share.index != recipient {
        return Err(Error::MisdirectedShare);
    }
    let expected = share.public();
    let given = commitment.evaluate(share.index);
    if given.value != expected {
        return Err(Error::ShareWrongCommitment);
    }
    Ok(())
}

/// Construct a new public polynomial by summing all commitments.
pub fn construct_public(
    commitments: Vec<poly::Public>,
    required: u32,
) -> Result<poly::Public, Error> {
    if commitments.len() < required as usize {
        return Err(Error::InsufficientDealings);
    }
    let mut public = poly::Public::zero();
    for commitment in commitments {
        public.add(&commitment);
    }
    Ok(public)
}

/// Recover public polynomial by interpolating coeffcient-wise all
/// polynomials.
///
/// It is assumed that the required number of commitments are provided.
pub fn recover_public(
    previous: &poly::Public,
    commitments: BTreeMap<u32, poly::Public>,
    threshold: u32,
    concurrency: usize,
) -> Result<poly::Public, Error> {
    // Ensure we have enough commitments to interpolate
    let required = previous.required();
    if commitments.len() < required as usize {
        return Err(Error::InsufficientDealings);
    }

    // Construct pool to perform interpolation
    let pool = ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .build()
        .expect("unable to build thread pool");

    // Perform interpolation over each coefficient
    let new = match pool.install(|| {
        (0..threshold)
            .into_par_iter()
            .map(|coeff| {
                let evals: Vec<_> = commitments
                    .iter()
                    .map(|(dealer, commitment)| poly::Eval {
                        index: *dealer,
                        value: commitment.get(coeff),
                    })
                    .collect();
                match poly::Public::recover(required, evals) {
                    Ok(point) => Ok(point),
                    Err(_) => Err(Error::PublicKeyInterpolationFailed),
                }
            })
            .collect::<Result<Vec<_>, _>>()
    }) {
        Ok(points) => poly::Public::from(points),
        Err(e) => return Err(e),
    };

    // Ensure public key matches
    if previous.constant() != new.constant() {
        return Err(Error::ReshareMismatch);
    }
    Ok(new)
}
