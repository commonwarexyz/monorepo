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
//! via [`G1::read_unchecked`]), the check runs `r` rounds of `m` parallel
//! random linear combinations. Each round draws an independent uniform
//! coefficient `c_{j,i}` in `{0, 1, 2}` for every combination `j < m` and every
//! point `i`, and applies the exact per-point test [`G1::in_subgroup`] to the
//! `m` points `Q_j = sum_i c_{j,i} P_i`. The batch is accepted if every
//! combination in every round lies in G1.
//!
//! Rather than computing each `Q_j` separately, a round groups the points by
//! their coefficient *vector* `(c_{0,i}, ..., c_{m-1,i})` — one of `3^m`
//! buckets — sums each bucket once, and recovers every combination from the
//! bucket sums: `Q_j = sum_{v: v_j=1} S_v + 2 * sum_{v: v_j=2} S_v`, where
//! `v_j` is the `j`-th base-3 digit of bucket index `v`. The combine weights
//! are the *deterministic* digits of the bucket index — all randomness lives in
//! the vector assignment — so this evaluates exactly the `m` combinations
//! above. (It is not the unsound shortcut of re-randomizing over bucket sums,
//! which would collapse the `m` combinations back into one.)
//!
//! Summing `n` points into `3^m` buckets costs the same `n` point additions as
//! summing them into one, so a single accumulation pass over the points serves
//! all `m` combinations, and only `ceil(81/m)` passes are needed at 128-bit
//! security instead of 81. The additions are batch-affine: each pass pairs up
//! the remaining points of every bucket and completes all pairs with one shared
//! field inversion (Montgomery's trick), about six field multiplications per
//! addition. The per-batch choice of `m` (and of batching at all, versus
//! checking each point individually) is a pure performance decision made by a
//! cost model; soundness holds for every choice.
//!
//! # Soundness
//!
//! Write each point as its in-subgroup part plus a "cofactor part" living in
//! the group of order `h` (the G1 cofactor). A combination `Q_j` lies in G1
//! exactly when its coefficient-weighted sum of cofactor parts vanishes. The
//! G1 cofactor `h = 3 * (11 * 10177 * 859267 * 52437899)^2` is odd, so every
//! nonzero cofactor part `T` has order at least 3, making `0*T`, `1*T`, and
//! `2*T` three distinct group elements. Pick any bad point (nonzero `T_i`) and
//! condition on every other coefficient of combination `j`: the combination
//! vanishes only if `c_{j,i} * T_i` hits one fixed value, and it takes three
//! distinct values as `c_{j,i}` ranges over `{0, 1, 2}`, so at most one works —
//! probability at most `1/3`, for any number of bad points and any structure of
//! the cofactor group. The `m` combinations of a round use disjoint independent
//! coefficients, so a round accepts a bad batch with probability at most
//! `3^-m`, and `r` rounds with probability at most `3^{-rm}`. The check uses
//! `r*m >= ceil(security / log2(3))` total combinations (81 at 128-bit).
//!
//! The bound needs no independence between the combinations and the points:
//! the points are fixed — arbitrarily and adversarially correlated — before
//! the coefficients are drawn, and the conditioning argument is uniform over
//! that choice (a cancelling pair achieves exactly `1/3`, never more). What it
//! does not survive is coefficient reuse across batches or a randomness source
//! the point-chooser can predict. Larger coefficients would not strengthen a
//! combination: in a component of order 3 a coefficient acts through its
//! residue mod 3, so even full-width random weights leave a cancelling pair a
//! `1/3` escape.
//!
//! The bound requires an odd cofactor: an order-2 part `T` has `2*T = 0`, so
//! `c * T` escapes with probability `2/3` per combination. A curve whose
//! cofactor is even (e.g. BLS12-377 G1, with `2^92 | h`) cannot use this
//! scheme as-is.
//!
//! See `cryptography/BATCHED_SUBGROUP.md` for the comparison against the
//! alternatives (per-point checking, one combination per round, and random
//! bucketing with per-bucket checks) and measured results.

use super::group::G1;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use blst::{
    blst_fp, blst_fp_add, blst_fp_inverse, blst_fp_mul, blst_fp_sqr, blst_fp_sub, blst_p1,
    blst_p1_add_or_double, blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_affine_is_inf,
    blst_p1_double, blst_p1_in_g1,
};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// One thousand times a strict lower bound on `log2(3)`.
///
/// `log2(3) = 1.58496...`, and `1.584 < log2(3)`, so dividing by this bound
/// never underestimates the number of combinations.
const LOG2_3_SCALED_LOWER_BOUND: usize = 1584;

/// Total number of `{0,1,2}`-coefficient combinations needed for a soundness
/// error of at most `2^-security`.
///
/// Each combination has error at most `1/3`, so `t` of them give
/// `3^-t <= 2^-security` once `t >= security / log2(3)` (81 at 128-bit).
const fn combinations_for_security(security: usize) -> usize {
    security
        .saturating_mul(1000)
        .div_ceil(LOG2_3_SCALED_LOWER_BOUND)
}

/// Approximate cost of one [`G1::in_subgroup`] check, in units of one
/// batch-affine point addition.
///
/// Machine-rough (measured ~22us per check against ~150ns per addition); it
/// only steers the cost model's choice of `m` and the per-point fallback,
/// never soundness.
const CHECK_COST: usize = 150;

/// Approximate cost of one Jacobian mixed addition (used by the bucket
/// combine), in units of one batch-affine point addition.
const MIXED_ADD_COST: usize = 3;

/// Pick the number of parallel combinations per round, or `None` if checking
/// each point individually is cheaper.
///
/// Returns `(m, rounds)` minimizing the modeled cost
/// `rounds * (n additions + combine + m checks)` subject to
/// `rounds * m >= combinations`; soundness holds for every choice, so the
/// constants above only affect performance.
fn plan(n: usize, combinations: usize) -> Option<(u32, usize)> {
    let mut best_cost = n.saturating_mul(CHECK_COST);
    let mut best = None;
    let mut pow3 = 1usize;
    for m in 1..=5u32 {
        pow3 *= 3;
        let rounds = combinations.div_ceil(m as usize);
        // Combining bucket sums into output j touches the 2*3^(m-1) buckets
        // whose j-th digit is nonzero, for each of the m outputs.
        let combine = MIXED_ADD_COST * 2 * (m as usize) * (pow3 / 3);
        let cost = rounds.saturating_mul(n + combine + (m as usize) * CHECK_COST);
        if cost < best_cost {
            best_cost = cost;
            best = Some((m, rounds));
        }
    }
    best
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
    let combinations = combinations_for_security(security);
    // Whether to batch at all, and at what width, is an algorithmic choice the
    // cost model makes; it cannot be delegated to `strategy` (which only
    // chooses serial vs parallel execution of a single algorithm). Either
    // path's independent units still run through `strategy`.
    let Some((m, rounds)) = plan(points.len(), combinations) else {
        return strategy
            .map_collect_vec_with_multiplier(points.iter(), 1, |point| point.in_subgroup())
            .into_iter()
            .all(|in_subgroup| in_subgroup);
    };
    // One shared inversion converts every point to affine; the per-round
    // accumulations then reuse them.
    let affine = G1::batch_to_affine(points);
    // The RNG is sequential, so draw every round's coefficient vectors (as
    // base-3 bucket ids) up front; the rounds themselves are independent and
    // run through the strategy, weighted by the per-round accumulation size.
    let mut trits = Trits::new(rng);
    let id_sets: Vec<Vec<u8>> = (0..rounds)
        .map(|_| (0..points.len()).map(|_| trits.bucket(m)).collect())
        .collect();
    strategy
        .map_collect_vec_with_multiplier(id_sets.iter(), points.len(), |ids| {
            round_in_g1(&affine, ids, m)
        })
        .into_iter()
        .all(|in_subgroup| in_subgroup)
}

/// Run one round: sum the points into `3^m` buckets keyed by coefficient
/// vector, recover the `m` combinations from the bucket sums, and check each.
fn round_in_g1(affine: &[blst_p1_affine], ids: &[u8], m: u32) -> bool {
    let sums = sum_buckets(affine, ids, 3usize.pow(m));
    for j in 0..m {
        let divisor = 3usize.pow(j);
        // Output j is (sum of buckets with digit_j = 1) + 2 * (digit_j = 2).
        let mut ones = blst_p1::default();
        let mut twos = blst_p1::default();
        for (v, sum) in sums.iter().enumerate() {
            if affine_is_inf(sum) {
                continue;
            }
            let acc = match (v / divisor) % 3 {
                1 => &mut ones,
                2 => &mut twos,
                _ => continue,
            };
            // SAFETY: acc and sum are valid points; blst_p1_add_or_double_affine
            // handles identity and equal operands, and permits out == a.
            unsafe { blst_p1_add_or_double_affine(acc, acc, sum) };
        }
        let mut combination = blst_p1::default();
        // SAFETY: all operands are valid blst_p1 values (identity included).
        unsafe {
            blst_p1_double(&mut combination, &twos);
            blst_p1_add_or_double(&mut combination, &combination, &ones);
            if !blst_p1_in_g1(&combination) {
                return false;
            }
        }
    }
    true
}

/// A pending affine addition or doubling. Operands are copied out when the
/// pass is scheduled so results can be written back without aliasing hazards.
struct Arith {
    a: blst_p1_affine,
    b: blst_p1_affine,
    out: usize,
    double: bool,
}

/// Sum `points` into `num_buckets` buckets given by `ids` (each id less than
/// `num_buckets`), returning one affine sum per bucket (the identity for empty
/// buckets).
///
/// Each pass pairs up the remaining points within every bucket and completes
/// all pairs with a single shared field inversion (Montgomery's trick), so an
/// addition costs about six field multiplications instead of an inversion.
fn sum_buckets(points: &[blst_p1_affine], ids: &[u8], num_buckets: usize) -> Vec<blst_p1_affine> {
    debug_assert_eq!(points.len(), ids.len());
    // Counting sort the points into contiguous per-bucket runs.
    let mut lens = vec![0usize; num_buckets];
    for &id in ids {
        lens[id as usize] += 1;
    }
    let mut starts = vec![0usize; num_buckets];
    let mut acc = 0;
    for (start, len) in starts.iter_mut().zip(&lens) {
        *start = acc;
        acc += len;
    }
    let mut buf = vec![blst_p1_affine::default(); points.len()];
    let mut cursor = starts.clone();
    for (point, &id) in points.iter().zip(ids) {
        buf[cursor[id as usize]] = *point;
        cursor[id as usize] += 1;
    }

    // Halve every bucket per pass until each holds at most one point. Copies
    // (identity-involved pairs and odd leftovers) are deferred alongside the
    // arithmetic so all reads complete before any write.
    let mut arith: Vec<Arith> = Vec::new();
    let mut denominators: Vec<blst_fp> = Vec::new();
    let mut copies: Vec<(usize, blst_p1_affine)> = Vec::new();
    loop {
        arith.clear();
        denominators.clear();
        copies.clear();
        for b in 0..num_buckets {
            let (start, len) = (starts[b], lens[b]);
            if len < 2 {
                continue;
            }
            for k in 0..len / 2 {
                let a = buf[start + 2 * k];
                let c = buf[start + 2 * k + 1];
                let out = start + k;
                if affine_is_inf(&a) {
                    copies.push((out, c));
                } else if affine_is_inf(&c) {
                    copies.push((out, a));
                } else if a.x.l == c.x.l {
                    // Same x: on the curve y is determined up to sign, so this
                    // is either P + (-P) = identity or a doubling.
                    let two_y = fp_add(&a.y, &c.y);
                    if two_y.l == [0u64; 6] {
                        copies.push((out, blst_p1_affine::default()));
                    } else {
                        // y_a == y_c != 0, so two_y = 2*y_a is the doubling
                        // denominator. (y == 0 cannot occur: the group order
                        // h * r is odd, so the curve has no 2-torsion.)
                        denominators.push(two_y);
                        arith.push(Arith {
                            a,
                            b: c,
                            out,
                            double: true,
                        });
                    }
                } else {
                    denominators.push(fp_sub(&c.x, &a.x));
                    arith.push(Arith {
                        a,
                        b: c,
                        out,
                        double: false,
                    });
                }
            }
            if len % 2 == 1 {
                copies.push((start + len / 2, buf[start + len - 1]));
            }
            lens[b] = len.div_ceil(2);
        }
        if arith.is_empty() && copies.is_empty() {
            break;
        }
        batch_invert(&mut denominators);
        for (op, inverse) in arith.iter().zip(&denominators) {
            // Affine chord/tangent formulas (curve coefficient a = 0):
            //   add:    lambda = (y_b - y_a) / (x_b - x_a)
            //   double: lambda = 3 * x_a^2 / (2 * y_a)
            //   x_out = lambda^2 - x_a - x_b;  y_out = lambda*(x_a - x_out) - y_a
            let lambda = if op.double {
                let x_sq = fp_sqr(&op.a.x);
                fp_mul(&fp_add(&fp_add(&x_sq, &x_sq), &x_sq), inverse)
            } else {
                fp_mul(&fp_sub(&op.b.y, &op.a.y), inverse)
            };
            let x_out = fp_sub(&fp_sub(&fp_sqr(&lambda), &op.a.x), &op.b.x);
            let y_out = fp_sub(&fp_mul(&lambda, &fp_sub(&op.a.x, &x_out)), &op.a.y);
            buf[op.out] = blst_p1_affine { x: x_out, y: y_out };
        }
        for &(out, value) in &copies {
            buf[out] = value;
        }
    }

    (0..num_buckets)
        .map(|b| {
            if lens[b] == 0 {
                blst_p1_affine::default()
            } else {
                buf[starts[b]]
            }
        })
        .collect()
}

/// Replace every element with its inverse using Montgomery's trick: one field
/// inversion plus three multiplications per element.
///
/// Every element MUST be nonzero (`blst_fp_inverse(0) == 0` would silently
/// poison the shared product); [`sum_buckets`]'s classification guarantees it.
fn batch_invert(values: &mut [blst_fp]) {
    if values.is_empty() {
        return;
    }
    // prefix[i] = values[0] * ... * values[i]
    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = values[0];
    prefix.push(acc);
    for value in &values[1..] {
        acc = fp_mul(&acc, value);
        prefix.push(acc);
    }
    // inverse = (values[0] * ... * values[i])^-1, walking i down from the end.
    let mut inverse = blst_fp::default();
    // SAFETY: both pointers reference valid blst_fp values.
    unsafe { blst_fp_inverse(&mut inverse, &acc) };
    for i in (1..values.len()).rev() {
        let value_inverse = fp_mul(&inverse, &prefix[i - 1]);
        inverse = fp_mul(&inverse, &values[i]);
        values[i] = value_inverse;
    }
    values[0] = inverse;
}

fn affine_is_inf(p: &blst_p1_affine) -> bool {
    // SAFETY: p is a valid blst_p1_affine.
    unsafe { blst_p1_affine_is_inf(p) }
}

fn fp_add(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut out = blst_fp::default();
    // SAFETY: all pointers reference valid blst_fp values.
    unsafe { blst_fp_add(&mut out, a, b) };
    out
}

fn fp_sub(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut out = blst_fp::default();
    // SAFETY: all pointers reference valid blst_fp values.
    unsafe { blst_fp_sub(&mut out, a, b) };
    out
}

fn fp_mul(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut out = blst_fp::default();
    // SAFETY: all pointers reference valid blst_fp values.
    unsafe { blst_fp_mul(&mut out, a, b) };
    out
}

fn fp_sqr(a: &blst_fp) -> blst_fp {
    let mut out = blst_fp::default();
    // SAFETY: all pointers reference valid blst_fp values.
    unsafe { blst_fp_sqr(&mut out, a) };
    out
}

/// A stream of uniform trits over a cryptographic RNG.
///
/// Each accepted byte below `3^5 = 243` yields five independent uniform trits
/// (its base-3 digits); bytes at or above 243 are rejected so the trits stay
/// exactly uniform. Bytes are drawn in bulk to amortize RNG calls.
///
/// Exact uniformity is load-bearing: the soundness bound leaves a fraction of
/// a bit of margin over the security target, and the bias of a `byte % 3`
/// shortcut (max probability `86/256`) compounds across every coefficient,
/// dropping the total below it.
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

    /// Return a uniform bucket id in `[0, 3^m)` — the next `m` trits as base-3
    /// digits. `m` must be at most 5.
    fn bucket(&mut self, m: u32) -> u8 {
        debug_assert!((1..=5).contains(&m));
        let mut id = 0u8;
        let mut weight = 1u8;
        for _ in 0..m {
            id += weight * self.next();
            weight = weight.wrapping_mul(3);
        }
        id
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
    use rand_core::Rng;

    /// Standard soundness target for the tests.
    const SECURITY: usize = 128;

    /// A batch size comfortably above the per-point fallback threshold, so the
    /// batched path is exercised.
    const LARGE: usize = 1000;

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

    /// Assert that [`sum_buckets`] agrees with naive per-bucket G1 addition.
    fn assert_sums_match(points: &[G1], ids: &[u8], num_buckets: usize) {
        let affine = G1::batch_to_affine(points);
        let sums = sum_buckets(&affine, ids, num_buckets);
        assert_eq!(sums.len(), num_buckets);
        for (b, got) in sums.iter().enumerate() {
            let mut expected = G1::zero();
            for (point, &id) in points.iter().zip(ids) {
                if id as usize == b {
                    expected += point;
                }
            }
            let expected = G1::batch_to_affine(&[expected]);
            assert_eq!(
                affine_is_inf(got),
                affine_is_inf(&expected[0]),
                "bucket {b} identity mismatch"
            );
            if !affine_is_inf(got) {
                assert_eq!(got.x.l, expected[0].x.l, "bucket {b} x mismatch");
                assert_eq!(got.y.l, expected[0].y.l, "bucket {b} y mismatch");
            }
        }
    }

    #[test]
    fn plan_meets_security() {
        assert_eq!(combinations_for_security(128), 81);
        assert_eq!(combinations_for_security(0), 0);
        for security in [1usize, 40, 80, 100, 128, 256] {
            let combinations = combinations_for_security(security);
            // 3^t >= 2^security must hold at the returned t.
            assert!(f64::from(combinations as u32) * 3f64.log2() >= security as f64);
            // Every plan must cover the required number of combinations.
            for n in [0usize, 1, 50, 130, 200, 1000, 6000, 100_000] {
                if let Some((m, rounds)) = plan(n, combinations) {
                    assert!((1..=5).contains(&m));
                    assert!(rounds * m as usize >= combinations, "n={n} s={security}");
                }
            }
        }
        // Small batches fall back to per-point checking; large ones batch.
        assert!(plan(1, 81).is_none());
        assert!(plan(50, 81).is_none());
        assert!(plan(6000, 81).is_some());
    }

    #[test]
    fn bucket_ids_are_in_range() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        for m in 1..=5u32 {
            for _ in 0..1000 {
                assert!((trits.bucket(m) as usize) < 3usize.pow(m));
            }
        }
    }

    #[test]
    fn bucket_ids_are_roughly_uniform() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        let mut counts = [0usize; 9];
        for _ in 0..9000 {
            counts[trits.bucket(2) as usize] += 1;
        }
        // Expected 1000 per id; the window is ~6.7 standard deviations wide.
        for &count in &counts {
            assert!((800..1200).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn round_isolates_each_combination() {
        // A round's soundness multiplies across its m combinations only if the
        // combine actually wires digit j of the bucket index to combination j.
        // Placing a single bad point at a chosen bucket makes combination j's
        // cofactor part exactly digit_j(bucket) * T, so each bucket id below
        // deterministically isolates one digit position and value; a wiring
        // bug (a stuck or truncated digit) accepts one of the rejecting cases.
        let mut rng = test_rng();
        const M: u32 = 5;
        let mut points: Vec<G1> = (0..300).map(|_| in_subgroup_point(&mut rng)).collect();
        let bad_index = points.len();
        points.push(off_subgroup_point(&mut rng));
        let affine = G1::batch_to_affine(&points);
        // Good points are spread arbitrarily; their in-subgroup parts cannot
        // mask a cofactor part in any combination.
        let mut ids: Vec<u8> = (0..points.len()).map(|i| (i % 243) as u8).collect();
        // Vector 0 assigns the bad point coefficient 0 in every combination,
        // so the round must accept.
        ids[bad_index] = 0;
        assert!(round_in_g1(&affine, &ids, M));
        // Any nonzero vector leaves a nonzero digit in some combination, which
        // must reject: 3^j isolates digit j with value 1; 2 and 162 = 2 * 3^4
        // cover value 2 at the lowest and highest positions.
        for v in [1u8, 2, 3, 9, 27, 81, 162] {
            ids[bad_index] = v;
            assert!(
                !round_in_g1(&affine, &ids, M),
                "bad point at bucket {v} escaped"
            );
        }
    }

    #[test]
    fn batch_invert_matches_single() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..17).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        for take in [0usize, 1, 2, 17] {
            let original: Vec<blst_fp> = affine.iter().take(take).map(|p| p.x).collect();
            let mut inverted = original.clone();
            batch_invert(&mut inverted);
            // value * inverse must be the same element (one) for every entry,
            // and multiplying by it must be the identity map.
            if take == 0 {
                continue;
            }
            let one = fp_mul(&original[0], &inverted[0]);
            for (value, inverse) in original.iter().zip(&inverted) {
                assert_eq!(fp_mul(value, inverse).l, one.l);
                assert_eq!(fp_mul(&one, value).l, value.l);
            }
        }
    }

    #[test]
    fn sum_buckets_handles_special_pairs() {
        let mut rng = test_rng();
        let p = in_subgroup_point(&mut rng);
        let q = off_subgroup_point(&mut rng);
        let cases: Vec<(Vec<G1>, Vec<u8>, usize)> = vec![
            // Cancelling pair produces the identity.
            (vec![p, -p], vec![0, 0], 1),
            // Duplicates force the doubling path.
            (vec![p, p], vec![0, 0], 1),
            (vec![q, q, q], vec![0, 0, 0], 1),
            // Identity inputs and identity-only buckets.
            (vec![p, G1::zero()], vec![0, 0], 1),
            (vec![G1::zero(), G1::zero()], vec![0, 0], 1),
            // Cancellation in a later pass: (p+q) + -(p+q).
            (vec![p, q, -p, -q], vec![0, 0, 0, 0], 1),
            // Odd leftovers and cancellation combined.
            (vec![p, -p, p], vec![0, 0, 0], 1),
            // Singleton with empty buckets around it.
            (vec![p], vec![1], 3),
        ];
        for (points, ids, num_buckets) in cases {
            assert_sums_match(&points, &ids, num_buckets);
        }
    }

    #[test]
    fn sum_buckets_matches_naive() {
        let mut rng = test_rng();
        for round in 0..20usize {
            let n = 1 + (round * 37) % 150;
            let num_buckets = [1usize, 2, 3, 9, 27, 243][round % 6];
            let mut points: Vec<G1> = Vec::with_capacity(n);
            for i in 0..n {
                let point = match i % 7 {
                    0 => G1::zero(),
                    1 | 2 => off_subgroup_point(&mut rng),
                    3 if i > 0 => -points[i - 1],
                    4 if i > 1 => points[i - 2],
                    _ => in_subgroup_point(&mut rng),
                };
                points.push(point);
            }
            let mut id_bytes = vec![0u8; n];
            rng.fill_bytes(&mut id_bytes);
            let ids: Vec<u8> = id_bytes
                .iter()
                .map(|&b| (b as usize % num_buckets) as u8)
                .collect();
            assert_sums_match(&points, &ids, num_buckets);
        }
    }

    #[test]
    fn empty_batch_is_accepted() {
        assert!(batch_in_g1(&[], SECURITY, &Sequential, &mut test_rng()));
    }

    #[test]
    fn valid_points_are_accepted() {
        let mut rng = test_rng();
        // A large batch exercises the bucketed path; small ones the fallback.
        let points: Vec<G1> = (0..LARGE).map(|_| in_subgroup_point(&mut rng)).collect();
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        assert!(batch_in_g1(&points[..64], SECURITY, &Sequential, &mut rng));
        assert!(batch_in_g1(&points[..1], SECURITY, &Sequential, &mut rng));
        assert!(batch_in_g1(&[G1::zero()], SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn all_identity_batch_is_accepted() {
        let points = vec![G1::zero(); LARGE];
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut test_rng()));
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
    fn one_bad_point_in_a_large_batch_is_rejected() {
        let mut rng = test_rng();
        let mut points: Vec<G1> = (0..LARGE).map(|_| in_subgroup_point(&mut rng)).collect();
        points[LARGE / 2] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn cancelling_bad_pair_is_rejected() {
        let mut rng = test_rng();
        // Two bad points whose cofactor parts cancel: they escape a round only
        // by drawing identical coefficient vectors.
        let mut points: Vec<G1> = (0..LARGE).map(|_| in_subgroup_point(&mut rng)).collect();
        let bad = off_subgroup_point(&mut rng);
        points[100] = bad;
        points[200] = -bad;
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn repeated_bad_point_is_rejected() {
        let mut rng = test_rng();
        let bad = off_subgroup_point(&mut rng);
        // Many duplicates of one bad point stress same-bucket doubling chains.
        let points = vec![bad; LARGE];
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn parallel_strategy_agrees_with_serial() {
        use commonware_parallel::Rayon;
        use core::num::NonZeroUsize;
        let mut rng = test_rng();
        let rayon = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();

        // Large batch: the batched path, serial and parallel, must agree.
        let mut points: Vec<G1> = (0..LARGE).map(|_| in_subgroup_point(&mut rng)).collect();
        assert!(batch_in_g1(&points, SECURITY, &rayon, &mut rng));
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        points[LARGE / 3] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &rayon, &mut rng));
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));

        // Small batch: the per-point fallback also runs through the strategy.
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

    /// Stage gate: isolated accumulator throughput. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_accumulator -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_accumulator() {
        use std::time::Instant;
        let mut rng = test_rng();
        for n in [1000usize, 6000, 100_000] {
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            let affine = G1::batch_to_affine(&points);
            let mut ids = vec![0u8; n];
            rng.fill_bytes(&mut ids);
            for num_buckets in [27usize, 81, 243] {
                for id in &mut ids {
                    *id %= num_buckets as u8;
                }
                let reps = 50;
                let start = Instant::now();
                for _ in 0..reps {
                    std::hint::black_box(sum_buckets(&affine, &ids, num_buckets));
                }
                let per_point = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
                println!("n={n} buckets={num_buckets} {per_point:.0} ns/point");
            }
        }
    }

    /// End-to-end timing across sizes. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_scheme -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_scheme() {
        use commonware_parallel::Rayon;
        use std::{thread::available_parallelism, time::Instant};
        let threads = available_parallelism().unwrap();
        let rayon = Rayon::new(threads).unwrap();
        println!("threads = {threads}");
        for n in [200usize, 1000, 6000, 100_000] {
            let mut rng = test_rng();
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            println!("n={n} plan={:?}", plan(n, combinations_for_security(128)));
            let start = Instant::now();
            assert!(points.iter().all(G1::in_subgroup));
            println!("n={n} per_point_serial = {:?}", start.elapsed());
            let start = Instant::now();
            assert!(batch_in_g1(&points, 128, &Sequential, &mut test_rng()));
            println!("n={n} batch_serial    = {:?}", start.elapsed());
            let start = Instant::now();
            assert!(batch_in_g1(&points, 128, &rayon, &mut test_rng()));
            println!("n={n} batch_parallel  = {:?}", start.elapsed());
        }
    }

    /// Compare the shipping scheme (C) against the two alternatives from
    /// `cryptography/BATCHED_SUBGROUP.md`, all on the same accumulation engine:
    /// A is one combination per round (m = 1, 81 rounds); B is random bucketing
    /// with every bucket sum exact-checked (shared-inversion steelman). Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_strategies -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_strategies() {
        use blst::blst_p1_affine_in_g1;
        use commonware_parallel::Rayon;
        use std::{thread::available_parallelism, time::Instant};

        /// Strategy A/C with a forced width and round count.
        fn forced(
            points: &[G1],
            m: u32,
            rounds: usize,
            strategy: &impl Strategy,
            rng: &mut impl CryptoRng,
        ) -> bool {
            let affine = G1::batch_to_affine(points);
            let mut trits = Trits::new(rng);
            let id_sets: Vec<Vec<u8>> = (0..rounds)
                .map(|_| (0..points.len()).map(|_| trits.bucket(m)).collect())
                .collect();
            strategy
                .map_collect_vec_with_multiplier(id_sets.iter(), points.len(), |ids| {
                    round_in_g1(&affine, ids, m)
                })
                .into_iter()
                .all(|in_subgroup| in_subgroup)
        }

        /// Strategy B: `num_buckets` a power of two, every bucket sum checked.
        fn bucketed(
            points: &[G1],
            num_buckets: usize,
            rounds: usize,
            strategy: &impl Strategy,
            rng: &mut impl CryptoRng,
        ) -> bool {
            let affine = G1::batch_to_affine(points);
            let mask = (num_buckets - 1) as u8;
            let id_sets: Vec<Vec<u8>> = (0..rounds)
                .map(|_| {
                    let mut ids = vec![0u8; points.len()];
                    rng.fill_bytes(&mut ids);
                    for id in &mut ids {
                        *id &= mask;
                    }
                    ids
                })
                .collect();
            strategy
                .map_collect_vec_with_multiplier(id_sets.iter(), points.len(), |ids| {
                    sum_buckets(&affine, ids, num_buckets).iter().all(|sum| {
                        // SAFETY: sum is a valid blst_p1_affine.
                        affine_is_inf(sum) || unsafe { blst_p1_affine_in_g1(sum) }
                    })
                })
                .into_iter()
                .all(|in_subgroup| in_subgroup)
        }

        let threads = available_parallelism().unwrap();
        let rayon = Rayon::new(threads).unwrap();
        println!("threads = {threads}");
        for n in [1000usize, 6000, 100_000] {
            let mut rng = test_rng();
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            let start = Instant::now();
            assert!(points.iter().all(G1::in_subgroup));
            println!("n={n} per_point serial = {:?}", start.elapsed());
            // A: one combination per round, 81 rounds.
            let start = Instant::now();
            assert!(forced(&points, 1, 81, &Sequential, &mut test_rng()));
            println!("n={n} A m=1 r=81   serial = {:?}", start.elapsed());
            let start = Instant::now();
            assert!(forced(&points, 1, 81, &rayon, &mut test_rng()));
            println!("n={n} A m=1 r=81 parallel = {:?}", start.elapsed());
            // B: buckets with per-bucket checks, rounds = ceil(128 / log2 B).
            for (num_buckets, rounds) in [(16usize, 32usize), (64, 22), (256, 16)] {
                let start = Instant::now();
                assert!(bucketed(
                    &points,
                    num_buckets,
                    rounds,
                    &Sequential,
                    &mut test_rng()
                ));
                println!(
                    "n={n} B B={num_buckets:>3} r={rounds}   serial = {:?}",
                    start.elapsed()
                );
                let start = Instant::now();
                assert!(bucketed(
                    &points,
                    num_buckets,
                    rounds,
                    &rayon,
                    &mut test_rng()
                ));
                println!(
                    "n={n} B B={num_buckets:>3} r={rounds} parallel = {:?}",
                    start.elapsed()
                );
            }
            // C: the shipping scheme.
            let start = Instant::now();
            assert!(batch_in_g1(&points, 128, &Sequential, &mut test_rng()));
            println!(
                "n={n} C plan={:?} serial = {:?}",
                plan(n, 81),
                start.elapsed()
            );
            let start = Instant::now();
            assert!(batch_in_g1(&points, 128, &rayon, &mut test_rng()));
            println!(
                "n={n} C plan={:?} parallel = {:?}",
                plan(n, 81),
                start.elapsed()
            );
        }
    }
}
