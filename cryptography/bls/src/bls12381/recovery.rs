//! Reusable Lagrange recovery for BLS12-381 group values.
//!
//! Coefficient construction uses the same barycentric formula and Montgomery batch inversion as
//! `commonware_math::poly::Interpolator`, while accepting the native groups directly.

use crate::bls12381::{
    group::{G1, G2},
    scalar::Scalar,
};
use alloc::{vec, vec::Vec};
use commonware_cryptography_vroom::{
    Backend, BlsScalar, WithBackend,
    rns::{Ring, Standard},
    with_backend,
};
use thiserror::Error;

/// An error constructing or applying a recovery plan.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryError {
    /// No evaluation points were supplied.
    #[error("no evaluation points")]
    Empty,
    /// An evaluation point is zero, which is reserved for the recovered secret.
    #[error("zero evaluation point")]
    ZeroEvaluationPoint,
    /// Two partial values have the same evaluation point.
    #[error("duplicate evaluation point")]
    DuplicateEvaluationPoint,
    /// The number of partial values does not match the plan.
    #[error("partial-value count does not match recovery plan")]
    LengthMismatch,
}

/// Lagrange coefficients at zero for one ordered set of evaluation points.
///
/// Construct a plan once and reuse it to recover multiple group values whose partials use the
/// same ordered evaluation points. Evaluation points and partial values are public inputs. Plan
/// construction takes quadratic work in the number of points; callers must enforce their protocol's
/// participant bound before construction.
///
/// Recovery is algebraic and does not authenticate partial values. A protocol must verify partials
/// before recovery or verify the recovered result afterward.
#[derive(Clone, Debug)]
pub struct RecoveryPlan {
    coefficients: Vec<Scalar>,
}

struct Construct<'a>(&'a [Scalar]);

impl WithBackend for Construct<'_> {
    type Output = Result<RecoveryPlan, RecoveryError>;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let points = self.0;
        let ring = Ring::<BlsScalar, B>::new(backend);

        // lambda_i(0) = W / (x_i * product_{j != i}(x_j - x_i)), where W = product_j x_j.
        let mut total = Standard::ONE;
        let mut denominators = Vec::with_capacity(points.len());

        // Two independent rows share matrix coefficients in each base change.
        for (pair_index, pair) in points.as_chunks::<2>().0.iter().enumerate() {
            let i = pair_index * 2;
            let first = Standard::from(pair[0].0);
            let second = Standard::from(pair[1].0);
            total = ring.mul(total, first);
            total = ring.mul(total, second);
            let mut pair_denominators = [first, second];
            for (j, point_j) in points.iter().enumerate() {
                let point_j = Standard::from(point_j.0);
                if j == i {
                    let product = ring.prep_left(point_j + ring.standard_negate(second))
                        * pair_denominators[1];
                    pair_denominators[1] =
                        ring.batch_reduce_expand(&[ring.ready::<800>(product)])[0];
                } else if j == i + 1 {
                    let product = ring.prep_left(point_j + ring.standard_negate(first))
                        * pair_denominators[0];
                    pair_denominators[0] =
                        ring.batch_reduce_expand(&[ring.ready::<800>(product)])[0];
                } else {
                    let first_product = ring.prep_left(point_j + ring.standard_negate(first))
                        * pair_denominators[0];
                    let second_product = ring.prep_left(point_j + ring.standard_negate(second))
                        * pair_denominators[1];
                    pair_denominators = ring.batch_reduce_expand(&[
                        ring.ready::<800>(first_product),
                        ring.ready::<800>(second_product),
                    ]);
                }
            }
            denominators.push(pair_denominators[0]);
            denominators.push(pair_denominators[1]);
        }
        for (i, point_i) in points.iter().enumerate().skip(denominators.len()) {
            let point_i = Standard::from(point_i.0);
            total = ring.mul(total, point_i);
            let mut denominator = point_i;
            for (j, point_j) in points.iter().enumerate() {
                if i != j {
                    let point_j = Standard::from(point_j.0);
                    let product =
                        ring.prep_left(point_j + ring.standard_negate(point_i)) * denominator;
                    denominator = ring.batch_reduce_expand(&[ring.ready::<800>(product)])[0];
                }
            }
            denominators.push(denominator);
        }

        // Montgomery's trick computes every W / denominator_i with one inversion.
        let mut prefixes = Vec::with_capacity(denominators.len() + 1);
        let mut prefix = Standard::ONE;
        prefixes.push(prefix);
        for denominator in &denominators {
            prefix = ring.mul(prefix, *denominator);
            prefixes.push(prefix);
        }
        let mut inverse = ring.mul(
            total,
            ring.invert(prefixes[denominators.len()])
                .ok_or(RecoveryError::DuplicateEvaluationPoint)?,
        );
        let mut coefficients = vec![Scalar::ZERO; denominators.len()];
        for i in (0..denominators.len()).rev() {
            coefficients[i] = Scalar(ring.mul(inverse, prefixes[i]).into());
            inverse = ring.mul(inverse, denominators[i]);
        }
        Ok(RecoveryPlan { coefficients })
    }
}

impl RecoveryPlan {
    /// Constructs recovery coefficients for the supplied nonzero, distinct evaluation points.
    pub fn new(points: &[Scalar]) -> Result<Self, RecoveryError> {
        if points.is_empty() {
            return Err(RecoveryError::Empty);
        }
        if points.iter().any(Scalar::is_zero) {
            return Err(RecoveryError::ZeroEvaluationPoint);
        }

        with_backend(Construct(points))
    }

    /// Recovers a G1 value from partial evaluations aligned with this plan's points.
    ///
    /// Identity partial values are accepted.
    pub fn recover_g1(&self, partials: &[G1]) -> Result<G1, RecoveryError> {
        G1::msm_vartime(partials, &self.coefficients).ok_or(RecoveryError::LengthMismatch)
    }

    /// Recovers a G2 value from partial evaluations aligned with this plan's points.
    ///
    /// Identity partial values are accepted.
    pub fn recover_g2(&self, partials: &[G2]) -> Result<G2, RecoveryError> {
        G2::msm_vartime(partials, &self.coefficients).ok_or(RecoveryError::LengthMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(miri))]
    use commonware_codec::{Copying, Decode as _, Encode as _};
    #[cfg(not(miri))]
    use commonware_cryptography::bls12381::primitives::group::{
        Scalar as LegacyScalar, ScalarReadCfg,
    };
    #[cfg(not(miri))]
    use commonware_math::poly::Interpolator;
    #[cfg(not(miri))]
    use commonware_parallel::Sequential;
    use commonware_utils::TestRng;
    #[cfg(not(miri))]
    use commonware_utils::ordered::Map;
    use rand_core::Rng;

    const ARBITRARY_POINT_SEED: u64 = 0x7265_636f_7665_7279;
    const ORDER_BYTES: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];

    fn evaluate(secret: &Scalar, linear: &Scalar, quadratic: &Scalar, x: &Scalar) -> Scalar {
        secret.add(&linear.mul(x)).add(&quadratic.mul(&x.square()))
    }

    fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |value, coefficient| {
                value.mul(x).add(coefficient)
            })
    }

    fn scalar_below_order(offset: u64) -> Scalar {
        let mut bytes = ORDER_BYTES;
        let mut borrow = offset;
        for byte in bytes.iter_mut().rev() {
            let part = borrow as u8;
            let (value, underflow) = byte.overflowing_sub(part);
            *byte = value;
            borrow = (borrow >> 8) + u64::from(underflow);
        }
        assert_eq!(borrow, 0);
        Scalar::from_bytes(&bytes).unwrap()
    }

    fn arbitrary_points(count: usize) -> Vec<Scalar> {
        assert!(count >= 5);
        let mut points = vec![scalar_below_order(1), scalar_below_order(2)];
        let mut rng = TestRng::new(ARBITRARY_POINT_SEED);
        while points.len() < count {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            let point = Scalar::from_wide_bytes(&bytes);
            if !point.is_zero() && !points.contains(&point) {
                points.push(point);
            }
        }
        points
    }

    fn redundant_representative(value: u8) -> Scalar {
        let mut bytes = [0; 64];
        bytes[32..].copy_from_slice(&ORDER_BYTES);
        let mut carry = u16::from(value);
        for byte in bytes.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        Scalar::from_wide_bytes(&bytes)
    }

    #[cfg(not(miri))]
    fn assert_coefficients_match_legacy(points: &[Scalar]) {
        let legacy_points: Vec<_> = points
            .iter()
            .map(|point| {
                LegacyScalar::decode_cfg(Copying(&point.to_bytes()), &ScalarReadCfg::AllowZero)
                    .unwrap()
            })
            .collect();
        let interpolator =
            Interpolator::<usize, LegacyScalar>::new(legacy_points.into_iter().enumerate());
        let plan = RecoveryPlan::new(points).unwrap();
        let mut basis =
            Map::from_iter_dedup((0..points.len()).map(|index| (index, LegacyScalar::from_u64(0))));

        for (index, coefficient) in plan.coefficients.iter().enumerate() {
            basis.values_mut()[index] = LegacyScalar::from_u64(1);
            let expected = interpolator.interpolate(&basis, &Sequential).unwrap();
            assert_eq!(
                coefficient.to_bytes().as_slice(),
                expected.encode().as_ref()
            );
            basis.values_mut()[index] = LegacyScalar::from_u64(0);
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_consecutive_5() {
        let points: Vec<_> = (1..=5).map(Scalar::from_u64).collect();
        assert_coefficients_match_legacy(&points);
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_arbitrary_5() {
        assert_coefficients_match_legacy(&arbitrary_points(5));
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_consecutive_100() {
        let points: Vec<_> = (1..=100).map(Scalar::from_u64).collect();
        assert_coefficients_match_legacy(&points);
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_arbitrary_100() {
        assert_coefficients_match_legacy(&arbitrary_points(100));
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_consecutive_1000() {
        let points: Vec<_> = (1..=1000).map(Scalar::from_u64).collect();
        assert_coefficients_match_legacy(&points);
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_arbitrary_1000() {
        assert_coefficients_match_legacy(&arbitrary_points(1000));
    }

    #[cfg(not(miri))]
    #[test]
    fn coefficients_match_legacy_small_cardinalities() {
        for count in [2, 3, 4, 5, 6] {
            let points: Vec<_> = (1..=count).map(Scalar::from_u64).collect();
            assert_coefficients_match_legacy(&points);
        }
    }

    #[test]
    fn singleton_has_unit_coefficient() {
        for point in [
            Scalar::ONE,
            Scalar::from_u64(u64::MAX),
            scalar_below_order(1),
        ] {
            let plan = RecoveryPlan::new(&[point]).unwrap();
            assert_eq!(plan.coefficients, [Scalar::ONE]);
            assert_eq!(
                plan.recover_g1(&[G1::generator()]).unwrap(),
                G1::generator()
            );
            assert_eq!(
                plan.recover_g2(&[G2::generator()]).unwrap(),
                G2::generator()
            );
        }
    }

    #[test]
    fn coefficients_follow_point_permutations() {
        let points = arbitrary_points(7);
        let plan = RecoveryPlan::new(&points).unwrap();
        let permutation = [5, 0, 6, 2, 4, 1, 3];
        let permuted_points: Vec<_> = permutation.iter().map(|&index| points[index]).collect();
        let permuted = RecoveryPlan::new(&permuted_points).unwrap();
        for (new_index, &old_index) in permutation.iter().enumerate() {
            assert_eq!(
                permuted.coefficients[new_index],
                plan.coefficients[old_index]
            );
        }
        #[cfg(not(miri))]
        {
            for count in [2, 3] {
                assert_coefficients_match_legacy(&points[..count]);
            }
            assert_coefficients_match_legacy(&permuted_points);
        }
    }

    #[test]
    fn accepts_near_order_and_64_bit_boundaries() {
        let mut two_to_64 = [0; 32];
        two_to_64[23] = 1;
        let points = [
            scalar_below_order(1),
            scalar_below_order(2),
            Scalar::from_u64(u64::MAX),
            Scalar::from_bytes(&two_to_64).unwrap(),
            Scalar::from_u64(1 << 63),
        ];
        assert!(RecoveryPlan::new(&points).is_ok());
        #[cfg(not(miri))]
        assert_coefficients_match_legacy(&points);
    }

    #[test]
    fn redundant_arithmetic_representatives_have_canonical_behavior() {
        let reduced = [1, 2, 4, 7].map(redundant_representative);
        let canonical = [1, 2, 4, 7].map(Scalar::from_u64);
        assert_eq!(reduced, canonical);
        assert_eq!(
            RecoveryPlan::new(&reduced).unwrap().coefficients,
            RecoveryPlan::new(&canonical).unwrap().coefficients,
        );
    }

    #[test]
    fn rejects_structural_errors_with_zero_precedence() {
        assert!(matches!(RecoveryPlan::new(&[]), Err(RecoveryError::Empty)));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ZERO]),
            Err(RecoveryError::ZeroEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ONE, Scalar::ZERO, Scalar::ONE]),
            Err(RecoveryError::ZeroEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ONE, Scalar::ONE]),
            Err(RecoveryError::DuplicateEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ONE, redundant_representative(1)]),
            Err(RecoveryError::DuplicateEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ONE, Scalar::from_u64(2), Scalar::ONE]),
            Err(RecoveryError::DuplicateEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[redundant_representative(0)]),
            Err(RecoveryError::ZeroEvaluationPoint)
        ));

        for count in [4, 5] {
            for duplicate in 1..count {
                let mut points = [1, 2, 4, 7, 11].map(Scalar::from_u64);
                points[duplicate] = redundant_representative(1);
                assert!(matches!(
                    RecoveryPlan::new(&points[..count]),
                    Err(RecoveryError::DuplicateEvaluationPoint)
                ));
            }
        }
    }

    #[test]
    fn recovers_full_degree_polynomials_and_reuses_plan() {
        let points = [1, 2, 4, 7, 11, 19].map(Scalar::from_u64);
        let plan = RecoveryPlan::new(&points).unwrap();

        let coefficients = [13, 9, 5, 8, 2, 6].map(Scalar::from_u64);
        let evaluations: Vec<_> = points
            .iter()
            .map(|point| evaluate_polynomial(&coefficients, point))
            .collect();
        let g1: Vec<_> = evaluations
            .iter()
            .map(|value| G1::generator().mul(value))
            .collect();
        let g2: Vec<_> = evaluations
            .iter()
            .map(|value| G2::generator().mul(value))
            .collect();
        assert_eq!(
            plan.recover_g1(&g1).unwrap(),
            G1::generator().mul(&coefficients[0])
        );
        assert_eq!(
            plan.recover_g2(&g2).unwrap(),
            G2::generator().mul(&coefficients[0])
        );

        let factor = points[2];
        let quotient = [3, 1, 4, 1, 5].map(Scalar::from_u64);
        let mixed: Vec<_> = points
            .iter()
            .map(|point| {
                point
                    .sub(&factor)
                    .mul(&evaluate_polynomial(&quotient, point))
            })
            .collect();
        assert!(mixed[2].is_zero());
        let mixed_secret = factor.neg().mul(&quotient[0]);
        let mixed_g1: Vec<_> = mixed
            .iter()
            .map(|value| G1::generator().mul(value))
            .collect();
        let mixed_g2: Vec<_> = mixed
            .iter()
            .map(|value| G2::generator().mul(value))
            .collect();
        assert_eq!(
            plan.recover_g1(&mixed_g1).unwrap(),
            G1::generator().mul(&mixed_secret)
        );
        assert_eq!(
            plan.recover_g2(&mixed_g2).unwrap(),
            G2::generator().mul(&mixed_secret)
        );

        assert_eq!(plan.recover_g1(&[G1::IDENTITY; 6]).unwrap(), G1::IDENTITY);
        assert_eq!(plan.recover_g2(&[G2::IDENTITY; 6]).unwrap(), G2::IDENTITY);
        assert_eq!(
            plan.recover_g1(&g1[..5]),
            Err(RecoveryError::LengthMismatch)
        );
        assert_eq!(
            plan.recover_g2(&g2[..5]),
            Err(RecoveryError::LengthMismatch)
        );
        let mut extra_g1 = g1;
        extra_g1.push(G1::IDENTITY);
        let mut extra_g2 = g2;
        extra_g2.push(G2::IDENTITY);
        assert_eq!(
            plan.recover_g1(&extra_g1),
            Err(RecoveryError::LengthMismatch)
        );
        assert_eq!(
            plan.recover_g2(&extra_g2),
            Err(RecoveryError::LengthMismatch)
        );
    }

    #[test]
    fn recovers_both_signature_groups_and_reuses_plan() {
        let points = [
            Scalar::from_u64(1),
            Scalar::from_u64(2),
            Scalar::from_u64(4),
            Scalar::from_u64(7),
        ];
        let secret = Scalar::from_u64(13);
        let linear = Scalar::from_u64(9);
        let quadratic = Scalar::from_u64(5);
        let evaluations: Vec<_> = points
            .iter()
            .map(|x| evaluate(&secret, &linear, &quadratic, x))
            .collect();
        let plan = RecoveryPlan::new(&points).unwrap();
        let g1: Vec<_> = evaluations
            .iter()
            .map(|value| G1::generator().mul(value))
            .collect();
        let g2: Vec<_> = evaluations
            .iter()
            .map(|value| G2::generator().mul(value))
            .collect();
        assert_eq!(plan.recover_g1(&g1).unwrap(), G1::generator().mul(&secret));
        assert_eq!(plan.recover_g2(&g2).unwrap(), G2::generator().mul(&secret));

        let reversed_points: Vec<_> = points.iter().rev().copied().collect();
        let reversed_g1: Vec<_> = g1.iter().rev().copied().collect();
        assert_eq!(
            RecoveryPlan::new(&reversed_points)
                .unwrap()
                .recover_g1(&reversed_g1)
                .unwrap(),
            G1::generator().mul(&secret),
        );
    }

    #[test]
    fn rejects_structural_errors_and_accepts_identity_values() {
        assert!(matches!(RecoveryPlan::new(&[]), Err(RecoveryError::Empty)));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ZERO]),
            Err(RecoveryError::ZeroEvaluationPoint)
        ));
        assert!(matches!(
            RecoveryPlan::new(&[Scalar::ONE, Scalar::ONE]),
            Err(RecoveryError::DuplicateEvaluationPoint)
        ));
        let plan = RecoveryPlan::new(&[Scalar::ONE]).unwrap();
        assert_eq!(plan.recover_g1(&[]), Err(RecoveryError::LengthMismatch));
        assert_eq!(plan.recover_g1(&[G1::IDENTITY]).unwrap(), G1::IDENTITY);
        assert_eq!(plan.recover_g2(&[G2::IDENTITY]).unwrap(), G2::IDENTITY);
    }
}
