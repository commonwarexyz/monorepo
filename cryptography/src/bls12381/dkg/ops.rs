//! Stateless operations useful in a DKG/Resharing procedure.

use crate::bls12381::{
    dkg::Error,
    primitives::{
        group::{Scalar, Share},
        poly,
        variant::Variant,
    },
};
use commonware_math::{
    algebra::{Additive as _, Random, Space},
    poly::Interpolator,
};
use commonware_utils::{ordered::Map, TryCollect};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

/// Generate shares and a commitment.
pub fn generate_shares<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    share: Option<Share>,
    n: u32,
    t: u32,
) -> (poly::Public<V>, Vec<Share>) {
    let share = share
        .map(|x| x.private)
        .unwrap_or_else(|| Scalar::random(&mut *rng));
    // Generate a secret polynomial and commit to it
    let secret = poly::Private::new_with_constant(rng, t - 1, share);

    // Commit to polynomial and generate shares
    let commitment = poly::Public::<V>::commit(secret.clone());
    let shares = (0..n)
        .map(|index| {
            let eval = secret.eval(&Scalar::from_index(index));
            Share {
                index,
                private: eval,
            }
        })
        .collect::<Vec<_>>();
    (commitment, shares)
}

/// Evaluates the polynomial at `n` indices.
pub fn evaluate_all<V: Variant>(polynomial: &poly::Public<V>, n: u32) -> Vec<V::Public> {
    (0..n)
        .map(|i| polynomial.eval_msm(&Scalar::from_index(i)))
        .collect()
}

/// Verify that a given commitment is valid for a dealer. If a previous
/// polynomial is provided, verify that the commitment is on that polynomial.
pub fn verify_commitment<V: Variant>(
    previous: Option<&poly::Public<V>>,
    commitment: &poly::Public<V>,
    dealer: u32,
    t: u32,
) -> Result<(), Error> {
    if let Some(previous) = previous {
        if previous.eval_msm(&Scalar::from_index(dealer)) != *commitment.constant() {
            return Err(Error::UnexpectedPolynomial);
        }
    }
    if commitment.degree() != t - 1 {
        return Err(Error::CommitmentWrongDegree);
    }
    Ok(())
}

/// Verify that a given share is valid for a specified recipient.
///
/// # Warning
///
/// This function assumes the provided commitment has already been verified.
pub fn verify_share<V: Variant>(
    commitment: &poly::Public<V>,
    recipient: u32,
    share: &Share,
) -> Result<(), Error> {
    // Check if share is valid
    if share.index != recipient {
        return Err(Error::MisdirectedShare);
    }
    let expected = share.public::<V>();
    let given = commitment.eval_msm(&Scalar::from_index(share.index));
    if given != expected {
        return Err(Error::ShareWrongCommitment);
    }
    Ok(())
}

/// Construct a public polynomial by summing a vector of commitments.
pub fn construct_public<'a, V: Variant>(
    commitments: impl IntoIterator<Item = &'a poly::Public<V>>,
    required: u32,
) -> Result<poly::Public<V>, Error> {
    // Compute new public polynomial by summing all commitments
    let mut count = 0;
    let mut public = poly::Public::<V>::zero();
    for commitment in commitments.into_iter() {
        public += commitment;
        count += 1;
    }

    // Ensure we have enough commitments
    if count < required {
        return Err(Error::InsufficientDealings);
    }
    Ok(public)
}

/// Recover public polynomial by interpolating coefficient-wise all
/// polynomials using precomputed Barycentric Weights.
///
/// It is assumed that the required number of commitments are provided.
pub fn recover_public_with_weights<V: Variant>(
    previous: &poly::Public<V>,
    commitments: &BTreeMap<u32, poly::Public<V>>,
    weights: &BTreeMap<u32, poly::Weight>,
    _threshold: u32,
    concurrency: usize,
) -> Result<poly::Public<V>, Error> {
    // Ensure we have enough commitments to interpolate
    let required = previous.required();
    if commitments.len() < required.get() as usize {
        return Err(Error::InsufficientDealings);
    }
    if commitments.keys().any(|i| !weights.contains_key(i)) {
        return Err(Error::InsufficientDealings);
    }
    if weights.keys().any(|i| !commitments.contains_key(i)) {
        return Err(Error::InsufficientDealings);
    }
    let commitments = commitments.values().cloned().collect::<Vec<_>>();
    let weights = weights
        .values()
        .map(|w| w.as_scalar())
        .cloned()
        .collect::<Vec<_>>();
    let new = poly::Public::<V>::msm(&commitments, &weights, concurrency);

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
    commitments: &BTreeMap<u32, poly::Public<V>>,
    _threshold: u32,
    concurrency: usize,
) -> Result<poly::Public<V>, Error> {
    // Ensure we have enough commitments to interpolate
    let required = previous.required();
    if commitments.len() < required.get() as usize {
        return Err(Error::InsufficientDealings);
    }

    let interpolator = Interpolator::new(commitments.keys().map(|&i| (i, Scalar::from_index(i))));
    let evals = commitments
        .iter()
        .map(|(&i, p)| (i, p.clone()))
        .try_collect::<Map<_, _>>()
        .map_err(|_| Error::DuplicateCommitment)?;
    interpolator
        .interpolate(&evals, concurrency)
        .ok_or(Error::PublicKeyInterpolationFailed)
}
