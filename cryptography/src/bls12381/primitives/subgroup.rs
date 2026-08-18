//! Batched subgroup-membership checking for BLS12-381 G1.
//!
//! Verifying that a point lies in the prime-order subgroup G1 is a significant
//! part of the cost of decoding an untrusted point (it dominates the field
//! square root of decompression). When many points must be checked at once —
//! for example every point in a block of transactions — checking them together
//! is cheaper than checking each individually.
//!
//! # Method
//!
//! Given points `P_0, ..., P_{n-1}` (already verified to lie on the curve, e.g.
//! via [`G1::read_unchecked`]), each round samples coefficients `c_i` uniformly
//! from `{0, 1, 2}`, forms the combination `Q = sum_i c_i P_i`, and applies the
//! exact per-point check [`G1::in_subgroup`] to the single point `Q`. If every
//! round's combination is in G1, all points are accepted.
//!
//! The points are converted to affine once, and each round's combination is a
//! two-bit multi-scalar multiplication: blst's Pippenger routine buckets the
//! points by coefficient and sums each bucket with a single shared field
//! inversion, which is much cheaper than adding the points one at a time.
//!
//! # Soundness
//!
//! Write each point as its in-subgroup part plus a "cofactor part" living in the
//! group of order `h` (the G1 cofactor). `Q` lies in G1 exactly when the
//! coefficient-weighted sum of the cofactor parts vanishes. If some `P_j` has a
//! nonzero cofactor part, consider the smallest prime `p | h` where it is
//! nonzero. Because the three coefficients `{0, 1, 2}` take three distinct
//! values modulo any prime `p >= 3` (and are uniform modulo `3`), the weighted
//! sum hits the single value `0` in that component with probability at most
//! `1/3` per round. So `r` rounds accept a bad point with probability at most
//! `3^{-r}`, independent of the cofactor's factorization.
//!
//! For BLS12-381 the G1 cofactor's smallest prime factor is `3`, so this `1/3`
//! bound is tight and small coefficients are optimal: larger coefficients could
//! not lower the per-round error, only make each round more expensive.

use super::group::G1;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use rand_core::CryptoRng;

/// One thousand times a strict lower bound on `log2(3)`.
///
/// `log2(3) = 1.58496...`, and `1.584 < log2(3)`, so dividing by this bound
/// never underestimates the number of rounds.
const LOG2_3_SCALED_LOWER_BOUND: usize = 1584;

/// Number of rounds needed for a soundness error of at most `2^-security`.
///
/// Each round has error at most `1/3`, so `r` rounds give `3^-r <= 2^-security`
/// once `r >= security / log2(3)`.
pub const fn rounds_for_security(security: usize) -> usize {
    security
        .saturating_mul(1000)
        .div_ceil(LOG2_3_SCALED_LOWER_BOUND)
}

/// Verify that every point in `points` lies in the prime-order subgroup G1,
/// with a soundness error of at most `2^-security`.
///
/// The points must already be valid curve points (for example decoded with
/// [`G1::read_unchecked`]); this establishes only subgroup membership. An empty
/// slice is accepted.
///
/// `rng` must be a cryptographically secure source the prover cannot predict:
/// the coefficients are the verifier's private randomness, exactly as in a
/// batched signature check.
#[must_use]
pub fn batch_in_g1(points: &[G1], security: usize, rng: &mut impl CryptoRng) -> bool {
    let rounds = rounds_for_security(security);
    // Batching pays a fixed cost of one subgroup check per round regardless of
    // the input size, so for few points the exact per-point path is cheaper.
    if points.len() <= 2 * rounds {
        return points.iter().all(G1::in_subgroup);
    }
    // One shared inversion converts every point to affine; the per-round
    // combinations then reuse them.
    let affine = G1::batch_to_affine(points);
    let mut coefficients = vec![0u8; points.len()];
    let mut trits = Trits::new(rng);
    for _ in 0..rounds {
        for coefficient in &mut coefficients {
            *coefficient = trits.next();
        }
        // Two-bit MSM: coefficients are 0, 1, or 2.
        if !G1::small_msm(&affine, &coefficients, 2).in_subgroup() {
            return false;
        }
    }
    true
}

/// A stream of uniform trits over a cryptographic RNG.
///
/// Each accepted byte below `3^5 = 243` yields five independent uniform trits
/// (its base-3 digits); bytes at or above 243 are rejected so the trits stay
/// exactly uniform. Bytes are drawn in bulk to amortize RNG calls.
struct Trits<'a, R: CryptoRng> {
    rng: &'a mut R,
    buffer: [u8; 256],
    filled: usize,
    position: usize,
    current: u8,
    remaining: u8,
}

impl<'a, R: CryptoRng> Trits<'a, R> {
    const fn new(rng: &'a mut R) -> Self {
        Self {
            rng,
            buffer: [0u8; 256],
            filled: 0,
            position: 0,
            current: 0,
            remaining: 0,
        }
    }

    /// Return the next uniform value in `{0, 1, 2}`.
    fn next(&mut self) -> u8 {
        if self.remaining == 0 {
            self.current = self.next_byte();
            self.remaining = 5;
        }
        let trit = self.current % 3;
        self.current /= 3;
        self.remaining -= 1;
        trit
    }

    /// Return the next byte strictly below 243, refilling the buffer as needed.
    fn next_byte(&mut self) -> u8 {
        loop {
            if self.position == self.filled {
                self.rng.fill_bytes(&mut self.buffer);
                self.filled = self.buffer.len();
                self.position = 0;
            }
            let byte = self.buffer[self.position];
            self.position += 1;
            if byte < 243 {
                return byte;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::{G1, Scalar};
    use commonware_codec::FixedSize;
    use commonware_math::algebra::{Additive, CryptoGroup, Random};
    use commonware_utils::test_rng;

    /// Standard soundness target for the tests.
    const SECURITY: usize = 128;

    fn in_subgroup_point(rng: &mut impl CryptoRng) -> G1 {
        G1::generator() * &Scalar::random(rng)
    }

    /// Build a valid curve point that is (almost surely) outside G1.
    ///
    /// A uniformly random on-curve point lies in the prime-order subgroup with
    /// probability `1/h` (negligible), so decoding random compressed bytes and
    /// keeping the ones that are on-curve yields off-subgroup points.
    fn off_subgroup_point(rng: &mut impl CryptoRng) -> G1 {
        loop {
            let mut bytes = [0u8; G1::SIZE];
            rng.fill_bytes(&mut bytes);
            // Compression flag set, infinity flag clear; keep a random y-sign.
            bytes[0] = (bytes[0] & 0x3f) | 0x80;
            if let Ok(point) = G1::read_unchecked(&mut &bytes[..])
                && !point.in_subgroup()
            {
                return point;
            }
        }
    }

    #[test]
    fn round_count_matches_security() {
        assert_eq!(rounds_for_security(128), 81);
        assert_eq!(rounds_for_security(0), 0);
        // 3^r >= 2^security must hold at the returned r.
        for security in [1usize, 40, 80, 100, 128, 200, 256] {
            let rounds = rounds_for_security(security);
            assert!(f64::from(rounds as u32) * 3f64.log2() >= security as f64);
        }
    }

    #[test]
    fn empty_batch_is_accepted() {
        assert!(batch_in_g1(&[], SECURITY, &mut test_rng()));
    }

    #[test]
    fn small_msm_matches_naive_combination() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..20).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        let coefficients: Vec<u8> = (0..points.len()).map(|i| (i % 3) as u8).collect();

        let mut expected = G1::zero();
        for (point, &c) in points.iter().zip(&coefficients) {
            expected += &(*point * &Scalar::from(u64::from(c)));
        }
        assert_eq!(G1::small_msm(&affine, &coefficients, 2), expected);
    }

    #[test]
    fn valid_points_are_accepted() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..64).map(|_| in_subgroup_point(&mut rng)).collect();
        for point in &points {
            assert!(point.in_subgroup());
        }
        assert!(batch_in_g1(&points, SECURITY, &mut rng));
        // A single valid point, and the identity, are both accepted.
        assert!(batch_in_g1(&points[..1], SECURITY, &mut rng));
        assert!(batch_in_g1(&[G1::zero()], SECURITY, &mut rng));
    }

    #[test]
    fn off_subgroup_point_is_rejected() {
        let mut rng = test_rng();
        let bad = off_subgroup_point(&mut rng);
        assert!(!bad.in_subgroup());
        // The exact and batched checks agree on the single bad point.
        assert!(!batch_in_g1(&[bad], SECURITY, &mut rng));
    }

    #[test]
    fn one_bad_point_in_a_batch_is_rejected() {
        let mut rng = test_rng();
        let mut points: Vec<G1> = (0..32).map(|_| in_subgroup_point(&mut rng)).collect();
        points.insert(17, off_subgroup_point(&mut rng));
        assert!(!batch_in_g1(&points, SECURITY, &mut rng));
    }

    #[test]
    fn batch_agrees_with_per_point() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let points: Vec<G1> = (0..16)
                .map(|i| {
                    if i % 5 == 0 {
                        off_subgroup_point(&mut rng)
                    } else {
                        in_subgroup_point(&mut rng)
                    }
                })
                .collect();
            let all_valid = points.iter().all(G1::in_subgroup);
            assert_eq!(batch_in_g1(&points, SECURITY, &mut rng), all_valid);
        }
    }
}
