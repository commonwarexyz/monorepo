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
//! coefficient-weighted sum of the cofactor parts vanishes. The G1 cofactor
//! `h = 3 * (11 * 10177 * 859267 * 52437899)^2` is odd, so every nonzero
//! cofactor part `T` has order at least 3, making `0*T`, `1*T`, and `2*T` three
//! distinct group elements. Pick any bad point `P_j` (nonzero `T_j`) and
//! condition on every other coefficient: the round accepts only if `c_j * T_j`
//! hits the single fixed value `-sum_{i != j} c_i T_i`, and as `c_j` ranges
//! uniformly over `{0, 1, 2}` it takes three distinct values, so at most one
//! works — probability at most `1/3`, for any number of bad points and any
//! structure of the cofactor group. `r` rounds accept with probability at most
//! `3^{-r}`.
//!
//! The bound requires an odd cofactor: an order-2 part `T` has `2*T = 0`, so
//! `c * T` escapes with probability `2/3` per round. A curve whose cofactor is
//! even (e.g. BLS12-377 G1, with `2^92 | h`) cannot use this scheme as-is.
//!
//! For BLS12-381 the `1/3` bound is also tight (a lone bad point escapes a
//! round exactly when `c_j = 0`, and `3 | h`), so for a single combination per
//! round larger coefficients cannot lower the error, only make each round more
//! expensive. This is not the only design point, though. Partitioning the
//! points into `B` buckets and checking each bucket sum separately lowers the
//! per-round error to `1/B` (needing fewer rounds), at the cost of `B` subgroup
//! checks per round instead of one; which is faster depends on the relative
//! cost of a subgroup check and a point summation. This module takes the
//! single-combination approach, whose one fast check per round pairs well with
//! blst's endomorphism-based test. See `cryptography/BATCHED_SUBGROUP.md` for
//! the full comparison.

use super::group::G1;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_parallel::Strategy;
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
///
/// The independent rounds are run through `strategy`; an adaptive strategy such
/// as [`commonware_parallel::Rayon`] runs them serially for small inputs and
/// across threads once the work is large enough. Pass
/// [`commonware_parallel::Sequential`] to stay single-threaded.
#[must_use]
pub fn batch_in_g1(
    points: &[G1],
    security: usize,
    strategy: &impl Strategy,
    rng: &mut impl CryptoRng,
) -> bool {
    let rounds = rounds_for_security(security);
    // Batching pays a fixed cost of one subgroup check per round regardless of
    // the input size, so for few points the exact per-point path is cheaper.
    // This crossover is algorithmic and cannot be delegated to `strategy`
    // (which only chooses serial vs parallel execution of a single algorithm),
    // but the per-point checks still run through `strategy` so a parallel one
    // spreads them across threads just as it does the batched rounds.
    if points.len() <= 2 * rounds {
        return strategy
            .map_collect_vec_with_multiplier(points.iter(), 1, |point| point.in_subgroup())
            .into_iter()
            .all(|in_subgroup| in_subgroup);
    }
    // One shared inversion converts every point to affine; the per-round
    // combinations then reuse them.
    let affine = G1::batch_to_affine(points);
    // The RNG is sequential, so draw every round's coefficients up front; the
    // rounds themselves are independent and run through the strategy.
    let mut trits = Trits::new(rng);
    let coefficient_sets: Vec<Vec<u8>> = (0..rounds)
        .map(|_| (0..points.len()).map(|_| trits.next()).collect())
        .collect();
    // Each round is a two-bit MSM over `points.len()` points, so weight the
    // per-round cost by that size for the adaptive serial/parallel choice.
    strategy
        .map_collect_vec_with_multiplier(coefficient_sets.iter(), points.len(), |coefficients| {
            G1::small_msm(&affine, coefficients, 2).in_subgroup()
        })
        .into_iter()
        .all(|in_subgroup| in_subgroup)
}

/// A stream of uniform trits over a cryptographic RNG.
///
/// Each accepted byte below `3^5 = 243` yields five independent uniform trits
/// (its base-3 digits); bytes at or above 243 are rejected so the trits stay
/// exactly uniform. Bytes are drawn in bulk to amortize RNG calls.
///
/// Exact uniformity is load-bearing: at 81 rounds the margin over `2^-128` is
/// only `0.38` bits, and the bias of a `byte % 3` shortcut (max probability
/// `86/256`) would drop the total to `127.5` bits, below the target.
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
    use commonware_parallel::Sequential;
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
        assert!(batch_in_g1(&[], SECURITY, &Sequential, &mut test_rng()));
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
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        // A single valid point, and the identity, are both accepted.
        assert!(batch_in_g1(&points[..1], SECURITY, &Sequential, &mut rng));
        assert!(batch_in_g1(&[G1::zero()], SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn off_subgroup_point_is_rejected() {
        let mut rng = test_rng();
        let bad = off_subgroup_point(&mut rng);
        assert!(!bad.in_subgroup());
        // The exact and batched checks agree on the single bad point.
        assert!(!batch_in_g1(&[bad], SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn one_bad_point_in_a_batch_is_rejected() {
        let mut rng = test_rng();
        let mut points: Vec<G1> = (0..32).map(|_| in_subgroup_point(&mut rng)).collect();
        points.insert(17, off_subgroup_point(&mut rng));
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn parallel_strategy_agrees_with_serial() {
        use commonware_parallel::Rayon;
        use core::num::NonZeroUsize;
        let mut rng = test_rng();
        // Large enough to exceed the per-point fallback and exercise the
        // adaptive strategy's parallel path.
        let mut points: Vec<G1> = (0..400).map(|_| in_subgroup_point(&mut rng)).collect();
        let rayon = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
        assert!(batch_in_g1(&points, SECURITY, &rayon, &mut rng));
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));

        points[123] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &rayon, &mut rng));
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));

        // Small batches take the per-point fallback, which also runs through the
        // strategy; a parallel strategy must handle it correctly too.
        let mut small: Vec<G1> = (0..50).map(|_| in_subgroup_point(&mut rng)).collect();
        assert!(batch_in_g1(&small, SECURITY, &rayon, &mut rng));
        small[7] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&small, SECURITY, &rayon, &mut rng));
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
            assert_eq!(
                batch_in_g1(&points, SECURITY, &Sequential, &mut rng),
                all_valid
            );
        }
    }
}
