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
//! via [`G1::read_unchecked`]), the check runs rounds of `m` parallel random
//! linear combinations. Each round draws an independent uniform coefficient
//! `c_{j,i}` in `{0, 1, 2}` for every combination `j < m` and every point `i`,
//! and applies the exact per-point test [`G1::in_subgroup`] to the `m` points
//! `Q_j = sum_i c_{j,i} P_i`. The batch is accepted if every combination in
//! every round lies in G1.
//!
//! Rather than computing each `Q_j` separately, a round groups the points by
//! their coefficient *vector* `(c_{0,i}, ..., c_{m-1,i})` — one of `3^m`
//! buckets, drawn as a single exactly uniform bucket id — sums each bucket
//! once, and recovers every combination from the bucket sums:
//! `Q_j = sum_{v: v_j=1} S_v + 2 * sum_{v: v_j=2} S_v`, where `v_j` is the
//! `j`-th base-3 digit of bucket index `v`. The combine weights are the
//! *deterministic* digits of the bucket index — all randomness lives in the
//! vector assignment — so this evaluates exactly the `m` combinations above.
//! (It is not the unsound shortcut of re-randomizing over bucket sums, which
//! would collapse the `m` combinations back into one.)
//!
//! Summing `n` points into `3^m` buckets costs the same point additions as
//! summing them into one, so a single accumulation pass over the points serves
//! all `m` combinations, and only `ceil(81/m)` passes are needed at 128-bit
//! security instead of 81 (the widths of the passes sum to exactly 81: the
//! last pass covers the remainder). The additions are batch-affine: each pass
//! pairs up the remaining points of every bucket and completes all pairs with
//! shared field inversions (Montgomery's trick), about six field
//! multiplications per addition. The per-digit sums `sum_{v_j=1} S_v` and
//! `sum_{v_j=2} S_v` for all `m` digits are then extracted together by a
//! marginal-merge tree over the bucket array (about `2 * 3^m` further batched
//! additions in total, rather than `m` scans of the buckets). The per-batch
//! choice of `m` (and of batching at all, versus checking each point
//! individually) is a pure performance decision made by a cost model;
//! soundness holds for every choice.
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
//! the cofactor group. A uniform bucket id in `[0, 3^m)` is exactly `m`
//! independent uniform trits (its base-3 digits), so the `m` combinations of a
//! round use disjoint independent coefficients and a round accepts a bad batch
//! with probability at most `3^-m`. Rounds multiply, and the round widths sum
//! to `ceil(security / log2(3))` total combinations (81 at 128-bit), for a
//! total error of at most `2^-security`.
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
    blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_double, blst_p1_in_g1,
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
/// Machine-rough (measured ~50us per check against ~280ns per addition on an
/// x86 server); it only steers the cost model's choice of `m` and the
/// per-point fallback, never soundness.
const CHECK_COST: usize = 180;

/// Modeled per-point bookkeeping cost of one accumulation pass (bucket
/// sorting and id handling), as a percentage of one batch-affine addition.
const PASS_OVERHEAD_PERCENT: usize = 50;

/// Maximum combinations per round.
///
/// Bucket ids are `u16` (up to `3^10 = 59049` buckets), and the combine cost
/// of about `2 * 3^m` additions makes wider rounds unprofitable until batches
/// far larger than that.
const MAX_WIDTH: u32 = 10;

/// Expected number of nonempty buckets when `n` points draw uniform ids over
/// `buckets` buckets: `buckets * (1 - (1 - 1/buckets)^n)`.
///
/// Computed with core-only f64 arithmetic (binary exponentiation; `powi`
/// needs std). Steers the cost model only.
fn expected_nonempty(n: usize, buckets: usize) -> usize {
    let mut miss = 1.0f64;
    let mut base = 1.0 - 1.0 / (buckets as f64);
    let mut exp = n;
    while exp > 0 {
        if exp & 1 == 1 {
            miss *= base;
        }
        base *= base;
        exp >>= 1;
    }
    ((buckets as f64) * (1.0 - miss)) as usize
}

/// Modeled cost of one round of `width` combinations over `n` points, in
/// units of one batch-affine addition: the accumulation's `n - nonempty`
/// additions plus per-pass bookkeeping, the `~2 * 3^width` additions of the
/// marginal-merge tree, and one exact check per combination.
fn round_cost(n: usize, width: u32) -> usize {
    let buckets = 3usize.pow(width);
    n.saturating_sub(expected_nonempty(n, buckets))
        + n * PASS_OVERHEAD_PERCENT / 100
        + 2 * buckets
        + (width as usize) * CHECK_COST
}

/// Pick the number of parallel combinations per round, or `None` if checking
/// each point individually is cheaper.
///
/// Returns `(m, rounds)` minimizing the modeled cost over widths `1..=10`,
/// where all rounds use width `m` except a final short round (see
/// [`round_widths`]); soundness holds for every choice, so the model's
/// constants only affect performance.
fn plan(n: usize, combinations: usize) -> Option<(u32, usize)> {
    if combinations == 0 {
        return Some((1, 0));
    }
    let mut best_cost = n.saturating_mul(CHECK_COST);
    let mut best = None;
    for m in 1..=MAX_WIDTH {
        let rounds = combinations.div_ceil(m as usize);
        let last = combinations - (rounds - 1) * (m as usize);
        let cost = (rounds - 1)
            .saturating_mul(round_cost(n, m))
            .saturating_add(round_cost(n, last as u32));
        if cost < best_cost {
            best_cost = cost;
            best = Some((m, rounds));
        }
    }
    best
}

/// Widths of the `rounds` rounds: full `m` for all but the last round, which
/// covers the exact remainder so the widths sum to `combinations`.
fn round_widths(m: u32, rounds: usize, combinations: usize) -> impl Iterator<Item = u32> {
    (0..rounds).map(move |round| {
        if round + 1 < rounds {
            m
        } else {
            (combinations - (rounds - 1) * (m as usize)) as u32
        }
    })
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
    // The RNG is sequential, so draw every round's bucket ids up front; the
    // rounds themselves are independent and run through the strategy,
    // weighted by the per-round accumulation size.
    let mut source = UniformIds::new(rng);
    let id_sets: Vec<(u32, Vec<u16>)> = round_widths(m, rounds, combinations)
        .map(|width| {
            let buckets = 3u32.pow(width);
            let threshold = rejection_threshold(buckets);
            let ids = (0..points.len())
                .map(|_| source.next(buckets, threshold))
                .collect();
            (width, ids)
        })
        .collect();
    strategy
        .map_collect_vec_with_multiplier(id_sets.iter(), points.len(), |(width, ids)| {
            round_in_g1(&affine, ids, *width)
        })
        .into_iter()
        .all(|in_subgroup| in_subgroup)
}

/// Run one round: sum the points into `3^m` buckets keyed by coefficient
/// vector, recover the `m` combinations from the bucket sums, and check each.
fn round_in_g1(affine: &[blst_p1_affine], ids: &[u16], m: u32) -> bool {
    let buckets = 3usize.pow(m);
    let mut batch = AddBatch::default();
    // Bucket sums land in the arena's front; the rest is marginal-tree space.
    let mut arena = vec![blst_p1_affine::default(); 2 * buckets];
    sum_buckets(affine, ids, &mut batch, &mut arena[..buckets]);
    for (ones, twos) in digit_marginals(&mut arena, m, &mut batch) {
        // Output j is (sum of buckets with digit_j = 1) + 2 * (digit_j = 2);
        // the add-or-double primitives handle identity-valued operands.
        let mut combination = blst_p1::default();
        // SAFETY: all operands are valid blst points (identity included).
        unsafe {
            blst_p1_add_or_double_affine(&mut combination, &combination, &twos);
            blst_p1_double(&mut combination, &combination);
            blst_p1_add_or_double_affine(&mut combination, &combination, &ones);
            if !blst_p1_in_g1(&combination) {
                return false;
            }
        }
    }
    true
}

/// Operations completed per shared inversion, sized so a chunk's operands
/// stay cache-resident between scheduling and completion.
const INVERSION_CHUNK: usize = 2048;

/// One scheduled affine addition or doubling: operand and output slots of the
/// pass's shared buffer.
struct PendingAdd {
    a: u32,
    b: u32,
    out: u32,
    double: bool,
}

/// Batches independent affine additions so the group operations of a pass
/// share field inversions (Montgomery's trick), costing about six field
/// multiplications per addition instead of an inversion.
///
/// Operands are recorded by index and read in place both when an operation is
/// [pushed](Self::push) (classification) and when the batch is
/// [run](Self::run) (completion), so callers must guarantee that no operation
/// writes a slot a later operation of the same pass reads — identity-involved
/// cases are exempt, since they capture their result when pushed.
#[derive(Default)]
struct AddBatch {
    ops: Vec<PendingAdd>,
    dens: Vec<blst_fp>,
    prefix: Vec<blst_fp>,
    copies: Vec<(u32, blst_p1_affine)>,
}

impl AddBatch {
    /// Schedule `buf[a] + buf[b]` into `buf[out]`.
    fn push(&mut self, buf: &[blst_p1_affine], a: usize, b: usize, out: usize) {
        let pa = &buf[a];
        let pb = &buf[b];
        if affine_is_inf(pa) {
            self.copies.push((out as u32, *pb));
        } else if affine_is_inf(pb) {
            self.copies.push((out as u32, *pa));
        } else if pa.x.l == pb.x.l {
            // Same x: on the curve y is determined up to sign, so this is
            // either P + (-P) = identity or a doubling.
            let two_y = fp_add(&pa.y, &pb.y);
            if two_y.l == [0u64; 6] {
                self.copies.push((out as u32, blst_p1_affine::default()));
            } else {
                // y_a == y_b != 0, so two_y = 2*y_a is the doubling
                // denominator. (y == 0 cannot occur: the group order h * r is
                // odd, so the curve has no 2-torsion.)
                self.dens.push(two_y);
                self.ops.push(PendingAdd {
                    a: a as u32,
                    b: b as u32,
                    out: out as u32,
                    double: true,
                });
            }
        } else {
            self.dens.push(fp_sub(&pb.x, &pa.x));
            self.ops.push(PendingAdd {
                a: a as u32,
                b: b as u32,
                out: out as u32,
                double: false,
            });
        }
    }

    /// Complete every scheduled operation with one shared inversion and write
    /// all results (deferred identity-case copies last).
    fn run(&mut self, buf: &mut [blst_p1_affine]) {
        batch_invert(&mut self.dens, &mut self.prefix);
        for (op, inverse) in self.ops.iter().zip(&self.dens) {
            let pa = buf[op.a as usize];
            let pb = buf[op.b as usize];
            // Affine chord/tangent formulas (curve coefficient a = 0):
            //   add:    lambda = (y_b - y_a) / (x_b - x_a)
            //   double: lambda = 3 * x_a^2 / (2 * y_a)
            //   x_out = lambda^2 - x_a - x_b;  y_out = lambda*(x_a - x_out) - y_a
            let lambda = if op.double {
                let x_sq = fp_sqr(&pa.x);
                fp_mul(&fp_add(&fp_add(&x_sq, &x_sq), &x_sq), inverse)
            } else {
                fp_mul(&fp_sub(&pb.y, &pa.y), inverse)
            };
            let x_out = fp_sub(&fp_sub(&fp_sqr(&lambda), &pa.x), &pb.x);
            let y_out = fp_sub(&fp_mul(&lambda, &fp_sub(&pa.x, &x_out)), &pa.y);
            buf[op.out as usize] = blst_p1_affine { x: x_out, y: y_out };
        }
        for &(out, value) in &self.copies {
            buf[out as usize] = value;
        }
        self.ops.clear();
        self.dens.clear();
        self.copies.clear();
    }
}

/// Sum `points` into buckets given by `ids` (each id below `out.len()`),
/// writing one affine sum per bucket into `out` (the identity for empty
/// buckets).
///
/// The points are counting-sorted into contiguous per-bucket runs, then every
/// bucket is halved in place each pass: pairs are formed left to right (an
/// odd bucket keeps its first element in place), so each result lands at or
/// before the slots it read and strictly before every slot a later pair
/// reads — the ordering [`AddBatch`] requires.
fn sum_buckets(
    points: &[blst_p1_affine],
    ids: &[u16],
    batch: &mut AddBatch,
    out: &mut [blst_p1_affine],
) {
    debug_assert_eq!(points.len(), ids.len());
    let num_buckets = out.len();
    // The schedule indexes the buffer with u32.
    assert!(points.len() <= u32::MAX as usize);

    // Counting sort the points into contiguous per-bucket runs.
    let mut lens = vec![0u32; num_buckets];
    for &id in ids {
        lens[id as usize] += 1;
    }
    let mut starts = vec![0u32; num_buckets];
    let mut acc = 0u32;
    for (start, len) in starts.iter_mut().zip(&lens) {
        *start = acc;
        acc += len;
    }
    let mut buf = vec![blst_p1_affine::default(); points.len()];
    let mut cursor = starts.clone();
    for (point, &id) in points.iter().zip(ids) {
        let slot = &mut cursor[id as usize];
        buf[*slot as usize] = *point;
        *slot += 1;
    }

    // Halve every bucket per pass until each holds at most one point.
    loop {
        let mut active = false;
        for b in 0..num_buckets {
            let (start, len) = (starts[b] as usize, lens[b] as usize);
            if len < 2 {
                continue;
            }
            active = true;
            let keep = len & 1;
            for k in 0..len / 2 {
                let a = start + keep + 2 * k;
                batch.push(&buf, a, a + 1, start + keep + k);
                if batch.ops.len() >= INVERSION_CHUNK {
                    batch.run(&mut buf);
                }
            }
            lens[b] = (keep + len / 2) as u32;
        }
        batch.run(&mut buf);
        if !active {
            break;
        }
    }

    for (b, slot) in out.iter_mut().enumerate() {
        *slot = if lens[b] == 0 {
            blst_p1_affine::default()
        } else {
            buf[starts[b] as usize]
        };
    }
}

/// For each digit position `j < m`, compute the sums of the buckets whose
/// `j`-th base-3 digit is 1 and 2 respectively, over the `3^m` bucket sums in
/// `arena[..3^m]`. `arena` must have length `2 * 3^m`; the tail is working
/// space.
///
/// The tree merges one digit at a time: after `k` merges the arena holds
/// `3^(m-k)` records `[total, ones_0, twos_0, ..., ones_{k-1}, twos_{k-1}]`
/// over disjoint bucket ranges. Merging three consecutive records sums their
/// fields (two batched additions per field) and starts the new digit's
/// marginals as copies of the second and third records' totals, for about
/// `2 * 3^m` additions in total. All weights are the deterministic digits of
/// the bucket index — the randomness lives entirely in the bucket assignment
/// (see module docs). Records ping-pong between the arena's front and back,
/// so no operation writes a slot a later operation reads.
fn digit_marginals(
    arena: &mut [blst_p1_affine],
    m: u32,
    batch: &mut AddBatch,
) -> Vec<(blst_p1_affine, blst_p1_affine)> {
    let capacity = arena.len();
    debug_assert_eq!(capacity, 2 * 3usize.pow(m));
    let mut groups = 3usize.pow(m) / 3;
    let mut stride = 1usize;
    let mut in_off = 0usize;
    loop {
        let out_stride = stride + 2;
        let out_off = if in_off == 0 {
            capacity - groups * out_stride
        } else {
            0
        };
        // Two batched steps: field-wise sums of the first two records, then
        // the third record's fields on top.
        for step in 0..2 {
            for g in 0..groups {
                let in_base = in_off + 3 * g * stride;
                let out_base = out_off + g * out_stride;
                for f in 0..stride {
                    let (a, b) = if step == 0 {
                        (in_base + f, in_base + stride + f)
                    } else {
                        (out_base + f, in_base + 2 * stride + f)
                    };
                    batch.push(arena, a, b, out_base + f);
                    if batch.ops.len() >= INVERSION_CHUNK {
                        batch.run(arena);
                    }
                }
            }
            batch.run(arena);
        }
        // The new digit's marginals are the second and third records' totals.
        for g in 0..groups {
            let in_base = in_off + 3 * g * stride;
            let out_base = out_off + g * out_stride;
            arena[out_base + stride] = arena[in_base + stride];
            arena[out_base + stride + 1] = arena[in_base + 2 * stride];
        }
        if groups == 1 {
            // One record left: [total, ones_0, twos_0, ..., ones_m, twos_m].
            return (0..m as usize)
                .map(|j| (arena[out_off + 1 + 2 * j], arena[out_off + 2 + 2 * j]))
                .collect();
        }
        in_off = out_off;
        stride = out_stride;
        groups /= 3;
    }
}

/// Replace every element with its inverse using Montgomery's trick: one field
/// inversion plus three multiplications per element. `prefix` is reusable
/// scratch.
///
/// Every element MUST be nonzero (`blst_fp_inverse(0) == 0` would silently
/// poison the shared product); [`AddBatch::push`]'s classification guarantees
/// it.
fn batch_invert(values: &mut [blst_fp], prefix: &mut Vec<blst_fp>) {
    if values.is_empty() {
        return;
    }
    // prefix[i] = values[0] * ... * values[i]
    prefix.clear();
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

/// Whether an affine point is the identity, which blst encodes as the
/// all-zero point (matching `blst_p1_affine_is_inf`, without the FFI call per
/// operand).
///
/// A zero x alone would not do: `(0, ±2)` satisfies `y^2 = x^3 + 4`.
fn affine_is_inf(p: &blst_p1_affine) -> bool {
    p.x.l == [0u64; 6] && p.y.l == [0u64; 6]
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

/// Largest multiple of `buckets` representable in 32 bits, the rejection
/// threshold for [`UniformIds::next`]. `buckets` must be at least 2.
fn rejection_threshold(buckets: u32) -> u32 {
    debug_assert!(buckets >= 2);
    (((1u64 << 32) / u64::from(buckets)) * u64::from(buckets)) as u32
}

/// A stream of exactly uniform bucket ids over a cryptographic RNG.
///
/// Ids are drawn by rejection-sampling 32-bit words: a word is accepted when
/// it is below the largest multiple of `buckets` that fits in 32 bits
/// (rejecting fewer than one word in `2^16` for any `buckets <= 3^10`) and
/// reduced modulo `buckets`, which is exactly uniform over `[0, buckets)`.
/// Words are drawn in bulk to amortize RNG calls.
///
/// Exact uniformity is load-bearing: the soundness bound leaves a fraction of
/// a bit of margin over the security target, and any per-coefficient bias
/// compounds across every coefficient of every combination.
struct UniformIds<'a, R: CryptoRng> {
    rng: &'a mut R,
    buffer: [u8; 1024],
    position: usize,
}

impl<'a, R: CryptoRng> UniformIds<'a, R> {
    fn new(rng: &'a mut R) -> Self {
        let buffer = [0u8; 1024];
        Self {
            rng,
            position: buffer.len(),
            buffer,
        }
    }

    /// Return the next exactly uniform id in `[0, buckets)`; `threshold` must
    /// be [`rejection_threshold`]`(buckets)` and `buckets` at most `3^10`.
    fn next(&mut self, buckets: u32, threshold: u32) -> u16 {
        debug_assert!(buckets <= 3u32.pow(MAX_WIDTH));
        debug_assert_eq!(threshold, rejection_threshold(buckets));
        loop {
            if self.position + 4 > self.buffer.len() {
                self.rng.fill_bytes(&mut self.buffer);
                self.position = 0;
            }
            let bytes = self.buffer[self.position..self.position + 4]
                .try_into()
                .expect("four bytes remain below the buffer length");
            self.position += 4;
            let word = u32::from_le_bytes(bytes);
            if word < threshold {
                return (word % buckets) as u16;
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

    /// Run [`sum_buckets`] over G1 points with fresh scratch.
    fn run_sum_buckets(points: &[G1], ids: &[u16], num_buckets: usize) -> Vec<blst_p1_affine> {
        let affine = G1::batch_to_affine(points);
        let mut batch = AddBatch::default();
        let mut out = vec![blst_p1_affine::default(); num_buckets];
        sum_buckets(&affine, ids, &mut batch, &mut out);
        out
    }

    /// Assert an affine point equals a G1 point (identity included).
    fn assert_affine_eq(got: &blst_p1_affine, expected: &G1, context: &str) {
        let expected = G1::batch_to_affine(core::slice::from_ref(expected));
        assert_eq!(
            affine_is_inf(got),
            affine_is_inf(&expected[0]),
            "{context} identity mismatch"
        );
        if !affine_is_inf(got) {
            assert_eq!(got.x.l, expected[0].x.l, "{context} x mismatch");
            assert_eq!(got.y.l, expected[0].y.l, "{context} y mismatch");
        }
    }

    /// Assert that [`sum_buckets`] agrees with naive per-bucket G1 addition.
    fn assert_sums_match(points: &[G1], ids: &[u16], num_buckets: usize) {
        let sums = run_sum_buckets(points, ids, num_buckets);
        assert_eq!(sums.len(), num_buckets);
        for (b, got) in sums.iter().enumerate() {
            let mut expected = G1::zero();
            for (point, &id) in points.iter().zip(ids) {
                if id as usize == b {
                    expected += point;
                }
            }
            assert_affine_eq(got, &expected, &format!("bucket {b}"));
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
            for n in [0usize, 1, 50, 130, 200, 1000, 6000, 100_000, 1_000_000] {
                if let Some((m, rounds)) = plan(n, combinations) {
                    assert!((1..=MAX_WIDTH).contains(&m));
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
    fn widths_sum_to_combinations() {
        for combinations in [1usize, 5, 81, 100, 137] {
            for m in 1..=MAX_WIDTH {
                let rounds = combinations.div_ceil(m as usize);
                let widths: Vec<u32> = round_widths(m, rounds, combinations).collect();
                assert_eq!(widths.len(), rounds);
                let total: usize = widths.iter().map(|w| *w as usize).sum();
                assert_eq!(total, combinations);
                assert!(widths.iter().all(|w| (1..=m).contains(w)));
                assert!(widths[..rounds - 1].iter().all(|w| *w == m));
            }
        }
    }

    #[test]
    fn rejection_threshold_is_exact() {
        for width in 1..=MAX_WIDTH {
            let buckets = 3u32.pow(width);
            let threshold = rejection_threshold(buckets);
            // A multiple of the bucket count, with no room for one more.
            assert_eq!(threshold % buckets, 0);
            assert!(u64::from(threshold) + u64::from(buckets) > 1u64 << 32);
        }
    }

    #[test]
    fn bucket_ids_are_in_range() {
        let mut rng = test_rng();
        let mut source = UniformIds::new(&mut rng);
        for width in 1..=MAX_WIDTH {
            let buckets = 3u32.pow(width);
            let threshold = rejection_threshold(buckets);
            for _ in 0..1000 {
                assert!(u32::from(source.next(buckets, threshold)) < buckets);
            }
        }
    }

    #[test]
    fn bucket_ids_are_roughly_uniform() {
        let mut rng = test_rng();
        let mut source = UniformIds::new(&mut rng);
        let threshold = rejection_threshold(9);
        let mut counts = [0usize; 9];
        for _ in 0..9000 {
            counts[source.next(9, threshold) as usize] += 1;
        }
        // Expected 1000 per id; the window is ~6.7 standard deviations wide.
        for &count in &counts {
            assert!((800..1200).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn affine_identity_matches_blst() {
        use blst::blst_p1_affine_is_inf;
        let mut rng = test_rng();
        let mut points = vec![G1::zero(), G1::generator()];
        points.extend((0..8).map(|_| in_subgroup_point(&mut rng)));
        points.extend((0..8).map(|_| off_subgroup_point(&mut rng)));
        for affine in G1::batch_to_affine(&points) {
            // SAFETY: affine is a valid blst_p1_affine.
            let expected = unsafe { blst_p1_affine_is_inf(&affine) };
            assert_eq!(affine_is_inf(&affine), expected);
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
        const M: u32 = MAX_WIDTH;
        let mut points: Vec<G1> = (0..300).map(|_| in_subgroup_point(&mut rng)).collect();
        let bad_index = points.len();
        points.push(off_subgroup_point(&mut rng));
        let affine = G1::batch_to_affine(&points);
        // Good points are spread arbitrarily; their in-subgroup parts cannot
        // mask a cofactor part in any combination.
        let buckets = 3usize.pow(M);
        let mut ids: Vec<u16> = (0..points.len())
            .map(|i| ((i * 977) % buckets) as u16)
            .collect();
        // Vector 0 assigns the bad point coefficient 0 in every combination,
        // so the round must accept.
        ids[bad_index] = 0;
        assert!(round_in_g1(&affine, &ids, M));
        // Any nonzero vector leaves a nonzero digit in some combination, which
        // must reject: 3^j isolates digit j with value 1, and 2 * 3^j value 2.
        for j in 0..M {
            for digit in [1u32, 2] {
                let v = digit * 3u32.pow(j);
                ids[bad_index] = v as u16;
                assert!(
                    !round_in_g1(&affine, &ids, M),
                    "bad point at bucket {v} escaped"
                );
            }
        }
    }

    #[test]
    fn digit_marginals_match_naive() {
        // The tree must produce, for every digit j, the exact sums of the
        // points whose bucket id has digit_j = 1 and digit_j = 2.
        let mut rng = test_rng();
        for m in 1..=MAX_WIDTH {
            let buckets = 3usize.pow(m);
            let n = 120;
            let points: Vec<G1> = (0..n)
                .map(|i| match i % 5 {
                    0 => G1::zero(),
                    1 => off_subgroup_point(&mut rng),
                    _ => in_subgroup_point(&mut rng),
                })
                .collect();
            let ids: Vec<u16> = (0..n)
                .map(|_| (rng.next_u32() as usize % buckets) as u16)
                .collect();
            let affine = G1::batch_to_affine(&points);
            let mut batch = AddBatch::default();
            let mut arena = vec![blst_p1_affine::default(); 2 * buckets];
            sum_buckets(&affine, &ids, &mut batch, &mut arena[..buckets]);
            let marginals = digit_marginals(&mut arena, m, &mut batch);
            assert_eq!(marginals.len(), m as usize);
            for (j, (ones, twos)) in marginals.iter().enumerate() {
                let mut expected_ones = G1::zero();
                let mut expected_twos = G1::zero();
                for (point, &id) in points.iter().zip(&ids) {
                    match (id as usize / 3usize.pow(j as u32)) % 3 {
                        1 => expected_ones += point,
                        2 => expected_twos += point,
                        _ => {}
                    }
                }
                assert_affine_eq(ones, &expected_ones, &format!("m={m} ones_{j}"));
                assert_affine_eq(twos, &expected_twos, &format!("m={m} twos_{j}"));
            }
        }
    }

    #[test]
    fn sum_buckets_handles_special_pairs() {
        let mut rng = test_rng();
        let p = in_subgroup_point(&mut rng);
        let q = off_subgroup_point(&mut rng);
        let cases: Vec<(Vec<G1>, Vec<u16>, usize)> = vec![
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
            // A wide, mostly-empty bucket space.
            (vec![p, q, p], vec![0, 977, 59_048], 59_049),
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
            let num_buckets = [1usize, 2, 3, 9, 243, 6561][round % 6];
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
            let ids: Vec<u16> = (0..n)
                .map(|_| (rng.next_u32() as usize % num_buckets) as u16)
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
            for width in [5u32, 7, 9] {
                let num_buckets = 3usize.pow(width);
                let ids: Vec<u16> = (0..n)
                    .map(|_| (rng.next_u32() as usize % num_buckets) as u16)
                    .collect();
                let mut batch = AddBatch::default();
                let mut out = vec![blst_p1_affine::default(); num_buckets];
                let reps = 50;
                let start = Instant::now();
                for _ in 0..reps {
                    sum_buckets(&affine, &ids, &mut batch, &mut out);
                    std::hint::black_box(&mut out);
                }
                let per_point = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
                println!("n={n} buckets={num_buckets} {per_point:.0} ns/point");
            }
        }
    }

    /// Temporary cost breakdown of one n=100k round. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_breakdown -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_breakdown() {
        use std::time::Instant;
        let mut rng = test_rng();
        let n = 100_000usize;
        let m = 9u32;
        let buckets = 3usize.pow(m);
        let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();

        let start = Instant::now();
        let affine = G1::batch_to_affine(&points);
        println!("affine conversion = {:?}", start.elapsed());

        let start = Instant::now();
        let mut source = UniformIds::new(&mut rng);
        let threshold = rejection_threshold(buckets as u32);
        let id_sets: Vec<Vec<u16>> = (0..9)
            .map(|_| {
                (0..n)
                    .map(|_| source.next(buckets as u32, threshold))
                    .collect()
            })
            .collect();
        println!("ids (9 rounds) = {:?}", start.elapsed());
        let ids = &id_sets[0];

        // Counting sort alone.
        let start = Instant::now();
        for _ in 0..10 {
            let mut lens = vec![0u32; buckets];
            for &id in ids {
                lens[id as usize] += 1;
            }
            let mut starts = vec![0u32; buckets];
            let mut acc = 0u32;
            for (s, l) in starts.iter_mut().zip(&lens) {
                *s = acc;
                acc += l;
            }
            let mut buf = vec![blst_p1_affine::default(); n];
            let mut cursor = starts.clone();
            for (point, &id) in affine.iter().zip(ids) {
                let slot = &mut cursor[id as usize];
                buf[*slot as usize] = *point;
                *slot += 1;
            }
            std::hint::black_box(&mut buf);
        }
        println!("counting sort = {:?} / round", start.elapsed() / 10);

        // Full bucket accumulation.
        let mut batch = AddBatch::default();
        let mut out = vec![blst_p1_affine::default(); buckets];
        let start = Instant::now();
        for _ in 0..10 {
            sum_buckets(&affine, ids, &mut batch, &mut out);
            std::hint::black_box(&mut out);
        }
        println!("sum_buckets = {:?} / round", start.elapsed() / 10);

        // Marginal tree alone.
        let mut arena = vec![blst_p1_affine::default(); 2 * buckets];
        sum_buckets(&affine, ids, &mut batch, &mut arena[..buckets]);
        let saved: Vec<blst_p1_affine> = arena[..buckets].to_vec();
        let start = Instant::now();
        for _ in 0..10 {
            arena[..buckets].copy_from_slice(&saved);
            std::hint::black_box(digit_marginals(&mut arena, m, &mut batch));
        }
        println!("digit_marginals = {:?} / round", start.elapsed() / 10);

        // Exact checks.
        let start = Instant::now();
        for point in points.iter().take(81) {
            std::hint::black_box(point.in_subgroup());
        }
        println!("81 checks = {:?}", start.elapsed());

        // Raw field-op costs.
        let mut x = affine[0].x;
        let y = affine[1].x;
        let start = Instant::now();
        for _ in 0..1_000_000 {
            x = fp_mul(std::hint::black_box(&x), &y);
        }
        println!("fp_mul = {:?} / 1M", start.elapsed());
        let start = Instant::now();
        for _ in 0..1_000_000 {
            x = fp_sqr(std::hint::black_box(&x));
        }
        println!("fp_sqr = {:?} / 1M", start.elapsed());
        let start = Instant::now();
        for _ in 0..1000 {
            let mut inv = blst_fp::default();
            // SAFETY: valid blst_fp values.
            unsafe { blst_fp_inverse(&mut inv, std::hint::black_box(&x)) };
            x = inv;
        }
        println!("fp_inverse = {:?} / 1k", start.elapsed());

        // Engine phases on a synthetic level-0 schedule (pairs within runs).
        let mut buf = affine.clone();
        let mut batch = AddBatch::default();
        let start = Instant::now();
        for _ in 0..10 {
            for k in 0..n / 2 {
                batch.push(&buf, 2 * k, 2 * k + 1, k);
                if batch.ops.len() >= INVERSION_CHUNK {
                    batch.ops.clear();
                    batch.dens.clear();
                    batch.copies.clear();
                }
            }
            batch.ops.clear();
            batch.dens.clear();
            batch.copies.clear();
        }
        println!("classify only = {:?} / {} pairs", start.elapsed() / 10, n / 2);
        let start = Instant::now();
        for _ in 0..10 {
            for k in 0..n / 2 {
                batch.push(&buf, 2 * k, 2 * k + 1, k);
                if batch.ops.len() >= INVERSION_CHUNK {
                    batch.run(&mut buf);
                }
            }
            batch.run(&mut buf);
            buf.copy_from_slice(&affine);
        }
        println!(
            "classify+invert+complete = {:?} / {} pairs (incl. buf restore)",
            start.elapsed() / 10,
            n / 2
        );
        let dens: Vec<blst_fp> = affine.iter().take(50_000).map(|p| p.x).collect();
        let mut values = dens.clone();
        let mut prefix = Vec::new();
        let start = Instant::now();
        for _ in 0..10 {
            values.copy_from_slice(&dens);
            for chunk in values.chunks_mut(INVERSION_CHUNK) {
                batch_invert(chunk, &mut prefix);
            }
        }
        println!("batch_invert = {:?} / 50k", start.elapsed() / 10);
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
            let buckets = 3u32.pow(m);
            let threshold = rejection_threshold(buckets);
            let mut source = UniformIds::new(rng);
            let id_sets: Vec<Vec<u16>> = (0..rounds)
                .map(|_| {
                    (0..points.len())
                        .map(|_| source.next(buckets, threshold))
                        .collect()
                })
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
            let mask = (num_buckets - 1) as u16;
            let id_sets: Vec<Vec<u16>> = (0..rounds)
                .map(|_| {
                    let mut bytes = vec![0u8; 2 * points.len()];
                    rng.fill_bytes(&mut bytes);
                    bytes
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]) & mask)
                        .collect()
                })
                .collect();
            strategy
                .map_collect_vec_with_multiplier(id_sets.iter(), points.len(), |ids| {
                    let mut batch = AddBatch::default();
                    let mut sums = vec![blst_p1_affine::default(); num_buckets];
                    sum_buckets(&affine, ids, &mut batch, &mut sums);
                    sums.iter().all(|sum| {
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
