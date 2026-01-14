//! Batch subgroup membership checks for BLS12-381 points.
//!
//! This module provides parallelized batch checking of subgroup membership
//! for unchecked G1 and G2 points.

use super::super::group::{G1Unchecked, G2Unchecked, G1, G2};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_parallel::Strategy;

/// Result of a batch subgroup check operation.
pub struct CheckResult<T> {
    /// Points that passed the subgroup check.
    pub valid: Vec<T>,
    /// Indices of points that failed the subgroup check.
    pub invalid_indices: Vec<usize>,
}

/// Batch check G1 points for subgroup membership.
///
/// Uses the provided parallelization strategy to check multiple points
/// concurrently. Returns both the successfully checked points and the
/// indices of any points that failed the check.
pub fn check_g1_subgroup<S: Strategy>(points: Vec<G1Unchecked>, strategy: &S) -> CheckResult<G1> {
    let results: Vec<(usize, Result<G1, _>)> =
        strategy.map_collect_vec(points.into_iter().enumerate(), |(i, p)| (i, p.check()));

    let mut valid = Vec::new();
    let mut invalid_indices = Vec::new();

    for (i, result) in results {
        match result {
            Ok(p) => valid.push(p),
            Err(_) => invalid_indices.push(i),
        }
    }

    CheckResult {
        valid,
        invalid_indices,
    }
}

/// Batch check G2 points for subgroup membership.
///
/// Uses the provided parallelization strategy to check multiple points
/// concurrently. Returns both the successfully checked points and the
/// indices of any points that failed the check.
pub fn check_g2_subgroup<S: Strategy>(points: Vec<G2Unchecked>, strategy: &S) -> CheckResult<G2> {
    let results: Vec<(usize, Result<G2, _>)> =
        strategy.map_collect_vec(points.into_iter().enumerate(), |(i, p)| (i, p.check()));

    let mut valid = Vec::new();
    let mut invalid_indices = Vec::new();

    for (i, result) in results {
        match result {
            Ok(p) => valid.push(p),
            Err(_) => invalid_indices.push(i),
        }
    }

    CheckResult {
        valid,
        invalid_indices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Scalar;
    use commonware_codec::{Encode, ReadExt};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn test_check_g1_subgroup_valid() {
        let mut rng = test_rng();

        // Create valid G1 points
        let points: Vec<G1> = (0..10)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();

        // Serialize and deserialize as unchecked
        let unchecked: Vec<G1Unchecked> = points
            .iter()
            .map(|p| {
                let encoded = p.encode();
                G1Unchecked::read(&mut encoded.as_ref()).unwrap()
            })
            .collect();

        // Batch check
        let result = check_g1_subgroup(unchecked, &Sequential);

        assert_eq!(result.valid.len(), 10);
        assert!(result.invalid_indices.is_empty());

        // Verify the points match
        for (original, checked) in points.iter().zip(result.valid.iter()) {
            assert_eq!(original, checked);
        }
    }

    #[test]
    fn test_check_g2_subgroup_valid() {
        let mut rng = test_rng();

        // Create valid G2 points
        let points: Vec<G2> = (0..10)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();

        // Serialize and deserialize as unchecked
        let unchecked: Vec<G2Unchecked> = points
            .iter()
            .map(|p| {
                let encoded = p.encode();
                G2Unchecked::read(&mut encoded.as_ref()).unwrap()
            })
            .collect();

        // Batch check
        let result = check_g2_subgroup(unchecked, &Sequential);

        assert_eq!(result.valid.len(), 10);
        assert!(result.invalid_indices.is_empty());

        // Verify the points match
        for (original, checked) in points.iter().zip(result.valid.iter()) {
            assert_eq!(original, checked);
        }
    }

    #[test]
    fn test_check_empty() {
        let result_g1 = check_g1_subgroup(vec![], &Sequential);
        assert!(result_g1.valid.is_empty());
        assert!(result_g1.invalid_indices.is_empty());

        let result_g2 = check_g2_subgroup(vec![], &Sequential);
        assert!(result_g2.valid.is_empty());
        assert!(result_g2.invalid_indices.is_empty());
    }
}
