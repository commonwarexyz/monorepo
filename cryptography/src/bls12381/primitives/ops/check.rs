//! Batch subgroup membership checks for G1/G2 points.
//!
//! This module provides parallelized batch checking of subgroup membership
//! for BLS12-381 curve points. Use these functions to efficiently verify
//! that multiple deserialized points are in the correct subgroup before
//! using them in cryptographic operations.

use super::super::group::{G1, G2};
use commonware_codec::Error;
use commonware_parallel::Strategy;

/// Result of a batch subgroup check operation.
///
/// Contains the indices of points that failed the subgroup check.
pub struct CheckResult {
    /// Indices of points that are NOT in the correct subgroup.
    pub failed_indices: Vec<usize>,
}

impl CheckResult {
    /// Returns true if all points passed the subgroup check.
    pub const fn all_valid(&self) -> bool {
        self.failed_indices.is_empty()
    }
}

/// Batch check G1 points for subgroup membership (parallelized).
///
/// Returns the indices of points that failed the subgroup check.
pub fn check_g1_subgroup<S: Strategy>(points: &[G1], strategy: &S) -> CheckResult {
    let results: Vec<(usize, Result<(), Error>)> = strategy
        .map_collect_vec(points.iter().enumerate(), |(i, p)| {
            (i, p.ensure_in_subgroup())
        });

    let failed_indices: Vec<usize> = results
        .into_iter()
        .filter_map(|(i, r)| if r.is_err() { Some(i) } else { None })
        .collect();

    CheckResult { failed_indices }
}

/// Batch check G2 points for subgroup membership (parallelized).
///
/// Returns the indices of points that failed the subgroup check.
pub fn check_g2_subgroup<S: Strategy>(points: &[G2], strategy: &S) -> CheckResult {
    let results: Vec<(usize, Result<(), Error>)> = strategy
        .map_collect_vec(points.iter().enumerate(), |(i, p)| {
            (i, p.ensure_in_subgroup())
        });

    let failed_indices: Vec<usize> = results
        .into_iter()
        .filter_map(|(i, r)| if r.is_err() { Some(i) } else { None })
        .collect();

    CheckResult { failed_indices }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::{Scalar, G1, G2};
    use commonware_codec::{Encode, ReadExt};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn test_check_g1_subgroup_valid() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..10)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();

        let result = check_g1_subgroup(&points, &Sequential);
        assert!(result.all_valid());
    }

    #[test]
    fn test_check_g2_subgroup_valid() {
        let mut rng = test_rng();
        let points: Vec<G2> = (0..10)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();

        let result = check_g2_subgroup(&points, &Sequential);
        assert!(result.all_valid());
    }

    #[test]
    fn test_check_g1_roundtrip() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..10)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();

        // Encode and decode (decode skips subgroup check now)
        let decoded: Vec<G1> = points
            .iter()
            .map(|p| {
                let encoded = p.encode();
                G1::read(&mut encoded.as_ref()).unwrap()
            })
            .collect();

        // Batch check should pass
        let result = check_g1_subgroup(&decoded, &Sequential);
        assert!(result.all_valid());

        // Verify they're the same points
        for (orig, dec) in points.iter().zip(decoded.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_check_g2_roundtrip() {
        let mut rng = test_rng();
        let points: Vec<G2> = (0..10)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();

        // Encode and decode (decode skips subgroup check now)
        let decoded: Vec<G2> = points
            .iter()
            .map(|p| {
                let encoded = p.encode();
                G2::read(&mut encoded.as_ref()).unwrap()
            })
            .collect();

        // Batch check should pass
        let result = check_g2_subgroup(&decoded, &Sequential);
        assert!(result.all_valid());

        // Verify they're the same points
        for (orig, dec) in points.iter().zip(decoded.iter()) {
            assert_eq!(orig, dec);
        }
    }
}
