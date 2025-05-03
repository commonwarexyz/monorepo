//! Lagrange interpolation for BLS12-381 threshold signatures.
//!
//! This implementation is based on [J.-P. Berrut and L. N.
//! Trefethen, “Barycentric Lagrange Interpolation,” SIAM Rev., vol. 46, no. 3,
//! pp. 501–517, 2004](https://people.maths.ox.ac.uk/trefethen/barycentric.pdf).

use super::poly::{Eval, PartialSignature, Poly};
use crate::bls12381::primitives::{
    group::{self, Element, Scalar},
    Error,
};
use std::collections::{BTreeMap, HashMap};

/// A Barycentric Weight for interpolation at x=0.
pub struct Weight(Scalar);

/// Computes Barycentric Weights for a given set of indices.
///
/// These weights can be reused for multiple interpolations with the same set of points.
///
/// # Arguments
/// * `indices` - The indices of the points used for interpolation (x = index + 1)
/// * `required` - The threshold number of points required for interpolation
///
/// # Returns
/// * `Result<BTreeMap<u32, Weight>, Error>` - Map of index to its corresponding weight
pub fn compute_weights(indices: &[u32], required: u32) -> Result<BTreeMap<u32, Weight>, Error> {
    if indices.len() < required as usize {
        return Err(Error::NotEnoughPartialSignatures(
            required as usize,
            indices.len(),
        ));
    }

    // Sort indices (just as in the original recover function)
    let mut sorted_indices = indices.to_vec();
    sorted_indices.sort();
    let sorted_indices = sorted_indices
        .into_iter()
        .take(required as usize)
        .collect::<Vec<_>>();

    let mut weights = BTreeMap::new();

    // For each index, compute its Lagrange basis polynomial evaluated at x=0
    for &index in &sorted_indices {
        // Convert index to x-coordinate (x = index + 1)
        let mut xi = Scalar::zero();
        xi.set_int(index + 1);

        // Initialize numerator and denominator for Lagrange coefficient
        let (mut num, mut den) = (Scalar::one(), Scalar::one());

        // Compute product terms for Lagrange basis polynomial
        for &j_index in &sorted_indices {
            if index != j_index {
                // Convert j_index to x-coordinate (x = j_index + 1)
                let mut xj = Scalar::zero();
                xj.set_int(j_index + 1);

                // Numerator: product of all xj (since we're evaluating at x=0)
                num.mul(&xj);

                // Denominator: product of all (xj - xi)
                let mut diff = xj;
                diff.sub(&xi);
                den.mul(&diff);
            }
        }

        // Compute inverse of denominator
        let inv = den.inverse().ok_or(Error::NoInverse)?;

        // Compute weight: numerator * inverse of denominator
        num.mul(&inv);

        // Store the weight
        weights.insert(index, Weight(num));
    }

    Ok(weights)
}

/// Extension trait for Lagrange Interpolation.
pub trait Interpolation<C: Element> {
    /// Recovers a point using the Barycentric Weights.
    fn recover_with_weights(evals: &[Eval<C>], weights: &BTreeMap<u32, Weight>)
        -> Result<C, Error>;
}

/// Implementation of the Interpolation trait for [Poly].
impl<C: Element> Interpolation<C> for Poly<C> {
    /// Recovers a polynomial value at x=0 using Barycentric Weights.
    ///
    /// # Arguments
    /// * `evals` - The evaluations to interpolate (must be sorted by index)
    /// * `weights` - Precomputed weights for the corresponding indices
    ///
    /// # Returns
    /// * `Result<C, Error>` - The interpolated value at x=0
    fn recover_with_weights(
        evals: &[Eval<C>],
        weights: &BTreeMap<u32, Weight>,
    ) -> Result<C, Error> {
        let mut result = C::zero();

        // Combine the evaluation points using the precomputed weights
        for eval in evals {
            if let Some(weight) = weights.get(&eval.index) {
                // Scale the y-value by the precomputed weight
                let mut scaled_value = eval.value.clone();
                scaled_value.mul(&weight.0);

                // Add to the result
                result.add(&scaled_value);
            } else {
                return Err(Error::InvalidIndex);
            }
        }

        Ok(result)
    }
}

/// Computes and caches Lagrange weights for threshold signatures
pub struct SignatureWeights {
    // Map of signature set configuration to precomputed weights
    weights_cache: HashMap<Vec<u32>, BTreeMap<u32, Weight>>,
}

impl Default for SignatureWeights {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureWeights {
    /// Creates a new empty signature weights cache
    pub fn new() -> Self {
        Self {
            weights_cache: HashMap::new(),
        }
    }

    /// Gets or computes Lagrange weights for a set of signature indices
    ///
    /// # Arguments
    /// * `indices` - The sorted indices of signers
    /// * `threshold` - The threshold number of signatures required
    ///
    /// # Returns
    /// * `Result<&BTreeMap<u32, LagrangeWeight>, Error>` - Precomputed weights
    pub fn get_weights(
        &mut self,
        indices: &[u32],
        threshold: u32,
    ) -> Result<&BTreeMap<u32, LagrangeWeight>, Error> {
        let key = indices.to_vec();
        if !self.weights_cache.contains_key(&key) {
            let weights = compute_lagrange_weights(indices, threshold)?;
            self.weights_cache.insert(key.clone(), weights);
        }
        Ok(self.weights_cache.get(&key).unwrap())
    }
}

/// Recovers a threshold signature using precomputed weights
///
/// # Arguments
/// * `threshold` - The number of required signatures
/// * `signatures` - The partial signatures to combine
/// * `weights` - Precomputed Lagrange weights for the signature indices
///
/// # Returns
/// * `Result<group::Signature, Error>` - The recovered threshold signature
pub fn threshold_signature_recover_with_weights(
    partial_sigs: &[PartialSignature],
    weights: &BTreeMap<u32, LagrangeWeight>,
) -> Result<group::Signature, Error> {
    // Use precomputed weights to combine the partial signatures
    let mut result = group::Signature::zero();

    for sig in partial_sigs {
        if let Some(weight) = weights.get(&sig.index) {
            // Scale the signature by the precomputed weight
            let mut scaled_sig = sig.value;
            scaled_sig.mul(&weight.0);

            // Add to the result
            result.add(&scaled_sig);
        } else {
            return Err(Error::InvalidIndex);
        }
    }

    Ok(result)
}

/// Example of optimized signature recovery for multiple signatures
pub fn recover_multiple_signatures(
    signature_sets: &[Vec<PartialSignature>],
    threshold: u32,
) -> Result<Vec<group::Signature>, Error> {
    // Create or reuse a signature weights cache
    let mut weights_cache = SignatureWeights::new();

    // Process each signature set with the same precomputed weights when possible
    signature_sets
        .iter()
        .map(|partial_sigs| {
            // Extract and sort indices
            let mut indices: Vec<u32> = partial_sigs.iter().map(|sig| sig.index).collect();
            indices.sort();

            // Get or compute weights for these indices
            let weights = weights_cache.get_weights(&indices, threshold)?;

            // Recover the signature using the precomputed weights
            threshold_signature_recover_with_weights(partial_sigs, weights)
        })
        .collect()
}
