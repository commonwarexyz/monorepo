//!Polynomial reconstruction using precomputed Lagrange weights.
//! https://scicomp.stackexchange.com/questions/24667/efficient-way-to-compute-lagrange-polynomials: only computes at 0

use crate::bls12381::primitives::{
    group::{self, Element, Scalar},
    Error,
};
use std::collections::{BTreeMap, HashMap};

use super::poly::{ Eval, PartialSignature, Poly};

/// A precomputed Lagrange weight for interpolation at x=0
pub struct LagrangeWeight(Scalar);

/// Computes Lagrange interpolation weights for a given set of indices
///
/// These weights can be reused for multiple interpolations with the same set of points.
/// 
/// # Arguments
/// * `indices` - The indices of the points used for interpolation (x = index + 1)
/// * `required` - The threshold number of points required for interpolation
///
/// # Returns
/// * `Result<BTreeMap<u32, LagrangeWeight>, Error>` - Map of index to its corresponding weight
pub fn compute_lagrange_weights(
    indices: &[u32],
    required: u32,
) -> Result<BTreeMap<u32, LagrangeWeight>, Error> {
    if indices.len() < required as usize {
        return Err(Error::NotEnoughPartialSignatures(required as usize, indices.len()));
    }

    // Sort indices (just as in the original recover function)
    let mut sorted_indices = indices.to_vec();
    sorted_indices.sort();
    let sorted_indices = sorted_indices.into_iter().take(required as usize).collect::<Vec<_>>();

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
        weights.insert(index, LagrangeWeight(num));
    }
    
    Ok(weights)
}

/// Extension trait for polynomial operations using precomputed weights
pub trait PolyOps<C: Element> {
    /// Recovers a point using precomputed Lagrange weights
    fn recover_with_weights(
        evals: &[Eval<C>],
        weights: &BTreeMap<u32, LagrangeWeight>,
    ) -> Result<C, Error>;
}

/// Implementation of polynomial operations for any element type
impl<C: Element> PolyOps<C> for Poly<C> {
    /// Recovers a polynomial value at x=0 using precomputed Lagrange weights
    ///
    /// # Arguments
    /// * `evals` - The evaluations to interpolate (must be sorted by index)
    /// * `weights` - Precomputed Lagrange weights for the corresponding indices
    ///
    /// # Returns
    /// * `Result<C, Error>` - The interpolated value at x=0
    fn recover_with_weights(
        evals: &[Eval<C>],
        weights: &BTreeMap<u32, LagrangeWeight>,
    ) -> Result<C, Error> {
        let mut result = C::zero();
        
        // Combine the evaluation points using the precomputed weights
        for eval in evals {
            if let Some(weight) = weights.get(&eval.index) {
                // Scale the y-value by the precomputed weight
                let mut scaled_value = eval.value;
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
    weights_cache: HashMap<Vec<u32>, BTreeMap<u32, LagrangeWeight>>,
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
    pub fn get_weights(&mut self, indices: &[u32], threshold: u32) -> Result<&BTreeMap<u32, LagrangeWeight>, Error> {
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