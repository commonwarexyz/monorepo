//! Stateless operations useful in a DKG/Resharing procedure.

use crate::bls12381::{
    dkg::Error,
    primitives::{
        group::Share,
        ops::msm_interpolate,
        poly::{self, compute_weights},
        variant::Variant,
    },
};
use rand_core::CryptoRngCore;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::BTreeMap;

/// Generate shares and a commitment.
pub fn generate_shares<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    share: Option<Share>,
    n: u32,
    t: u32,
) -> (poly::Public<V>, Vec<Share>) {
    // Generate a secret polynomial and commit to it
    let mut secret = poly::new_from(t - 1, rng);
    if let Some(share) = share {
        // Set the free coefficient of the secret polynomial to the secret
        // of the previous DKG
        secret.set(0, share.private);
    }

    // Commit to polynomial and generate shares
    let commitment = poly::Public::<V>::commit(secret.clone());
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

/// Evaluates the polynomial at `n` indices.
pub fn evaluate_all<V: Variant>(polynomial: &poly::Public<V>, n: u32) -> Vec<V::Public> {
    let mut evals = Vec::with_capacity(n as usize);
    for index in 0..n {
        evals.push(polynomial.evaluate(index).value);
    }
    evals
}

/// Verify that a given commitment is valid for a dealer. If a previous
/// polynomial is provided, verify that the commitment is on that polynomial.
pub fn verify_commitment<V: Variant>(
    previous: Option<&poly::Public<V>>,
    dealer: u32,
    commitment: &poly::Public<V>,
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
pub fn verify_share<V: Variant>(
    previous: Option<&poly::Public<V>>,
    dealer: u32,
    commitment: &poly::Public<V>,
    t: u32,
    recipient: u32,
    share: &Share,
) -> Result<(), Error> {
    // Verify that commitment is on previous public polynomial (if provided)
    verify_commitment::<V>(previous, dealer, commitment, t)?;

    // Check if share is valid
    if share.index != recipient {
        return Err(Error::MisdirectedShare);
    }
    let expected = share.public::<V>();
    let given = commitment.evaluate(share.index);
    if given.value != expected {
        return Err(Error::ShareWrongCommitment);
    }
    Ok(())
}

/// Construct a new public polynomial by summing all commitments.
pub fn construct_public<V: Variant>(
    commitments: Vec<poly::Public<V>>,
    required: u32,
) -> Result<poly::Public<V>, Error> {
    if commitments.len() < required as usize {
        return Err(Error::InsufficientDealings);
    }
    let mut public = poly::Public::<V>::zero();
    for commitment in commitments {
        public.add(&commitment);
    }
    Ok(public)
}

/// Recover public polynomial by interpolating coefficient-wise all
/// polynomials using precomputed Barycentric Weights.
///
/// It is assumed that the required number of commitments are provided.
pub fn recover_public_with_weights<V: Variant>(
    previous: &poly::Public<V>,
    commitments: BTreeMap<u32, poly::Public<V>>,
    weights: &BTreeMap<u32, poly::Weight>,
    threshold: u32,
    concurrency: usize,
) -> Result<poly::Public<V>, Error> {
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

    // Perform interpolation over each coefficient using the precomputed weights
    let new = match pool.install(|| {
        (0..threshold)
            .into_par_iter()
            .map(|coeff| {
                // Extract evaluations for this coefficient from all commitments
                let evals = commitments
                    .iter()
                    .map(|(dealer, commitment)| poly::Eval {
                        index: *dealer,
                        value: commitment.get(coeff),
                    })
                    .collect::<Vec<_>>();

                // Use precomputed weights for interpolation
                msm_interpolate(weights, &evals).map_err(|_| Error::PublicKeyInterpolationFailed)
            })
            .collect::<Result<Vec<_>, _>>()
    }) {
        Ok(points) => poly::Public::<V>::from(points),
        Err(e) => return Err(e),
    };

    // Ensure public key matches
    if previous.constant() != new.constant() {
        return Err(Error::ReshareMismatch);
    }
    Ok(new)
}

/// Recover public polynomial by interpolating coefficient-wise all
/// polynomials.
///
/// It is assumed that the required number of commitments are provided.
pub fn recover_public<V: Variant>(
    previous: &poly::Public<V>,
    commitments: BTreeMap<u32, poly::Public<V>>,
    threshold: u32,
    concurrency: usize,
) -> Result<poly::Public<V>, Error> {
    // Ensure we have enough commitments to interpolate
    let required = previous.required();
    if commitments.len() < required as usize {
        return Err(Error::InsufficientDealings);
    }

    // Precompute Barycentric Weights for all coefficients
    let indices: Vec<u32> = commitments.keys().cloned().collect();
    let weights = compute_weights(indices).map_err(|_| Error::PublicKeyInterpolationFailed)?;

    // Perform interpolation over each coefficient using the precomputed weights
    recover_public_with_weights::<V>(previous, commitments, &weights, threshold, concurrency)
}
