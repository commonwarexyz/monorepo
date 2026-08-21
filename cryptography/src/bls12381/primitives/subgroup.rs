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
//! security instead of 81. Two pieces keep wide rounds (large `m`) cheap:
//!
//! - **Slot accumulation.** A pass streams the points once through a table of
//!   `3^m` slots: a point landing on an empty slot parks there, a point landing
//!   on an occupied slot pairs with the parked one, and completed sums re-enter
//!   at their slot. Pending pairs are completed in chunks, all pairs of a chunk
//!   sharing one field inversion (Montgomery's trick), about six field
//!   multiplications per addition. The working set is the slot table, not the
//!   point buffer, and the addition count — `n` minus the number of nonempty
//!   buckets — *shrinks* as buckets multiply.
//! - **Digit-peeling combine.** Recovering the `m` combinations by scanning all
//!   `3^m` sums once per combination would cost `m * 3^m` additions and cap the
//!   useful width. Instead, the top digit is peeled off: splitting the sums by
//!   the top digit gives three contiguous thirds `T0 | T1 | T2`, the top
//!   digit's combination inputs are `sum(T1)` and `sum(T2)`, and the
//!   element-wise sum `T0 + T1 + T2` is a `3^(m-1)`-entry table with the same
//!   remaining digits — recurse. This computes exactly the same per-digit sums
//!   (it merely reassociates them, so soundness is untouched) in about
//!   `2 * 3^m` batch-affine additions; the last few digits, where the table is
//!   small, use the direct scan.
//!
//! The per-batch choice of `m` (and of batching at all, versus checking each
//! point individually) is a pure performance decision made by a cost model;
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
//! Exact coefficient uniformity is load-bearing: the bound leaves a fraction
//! of a bit of margin over the security target, and a biased shortcut (e.g.
//! `byte % 3`, max probability `86/256`) compounds across every coefficient
//! and drops the total below it. Coefficient vectors are drawn as bucket ids
//! by rejection (Lemire's method): a uniform 16-bit value either maps to a
//! bucket id or is rejected, with exactly `floor(2^16 / 3^m)` values mapping
//! to every id, so accepted ids — and therefore all `m` digits of each — are
//! exactly uniform.
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

/// Widest supported coefficient vector: `3^10 = 59049` bucket ids fit a `u16`.
const MAX_WIDTH: u32 = 10;

/// The cost model's unit is one thousandth of a batch-affine point addition.
/// The constants are machine-rough (calibrated against measurement); they only
/// steer the choice of `m` and the per-point fallback, never soundness.
///
/// Cost of one batch-affine addition.
const ADD_COST: usize = 1000;

/// Per-point per-round overhead besides the additions: drawing its bucket id,
/// streaming it through the slot table.
const POINT_COST: usize = 350;

/// Per-bucket per-round overhead: slot-table initialization plus the two
/// digit-peeling additions each bucket sum feeds.
const BUCKET_COST: usize = 2600;

/// Cost of one [`G1::in_subgroup`] check (measured ~150-180x a batch-affine
/// addition, depending on the machine).
const CHECK_COST: usize = 150 * ADD_COST;

/// Expected number of nonempty buckets when `n` points land uniformly in `b`
/// buckets: `b * (1 - (1 - 1/b)^n)`, in Q32 fixed point (integer-only for
/// no_std; performance model only, so truncation error is irrelevant).
fn expected_nonempty(n: usize, b: usize) -> usize {
    debug_assert!(b >= 2);
    // (1 - 1/b) in Q32, raised to the n-th power by squaring.
    let mut base = ((b as u64 - 1) << 32) / b as u64;
    let mut exponent = n;
    let mut survive = 1u64 << 32;
    while exponent > 0 {
        if exponent & 1 == 1 {
            survive = (survive * base) >> 32;
        }
        base = (base * base) >> 32;
        exponent >>= 1;
    }
    // Round to nearest so tiny n (where truncation error is a whole bucket)
    // stay sensible, and clamp to the trivial bounds.
    let empty = ((b as u64 * survive + (1 << 31)) >> 32) as usize;
    (b - empty.min(b)).min(n)
}

/// Pick the number of parallel combinations per round, or `None` if checking
/// each point individually is cheaper.
///
/// Returns `(m, rounds)` minimizing the modeled cost subject to
/// `rounds * m >= combinations`; soundness holds for every choice, so the
/// constants above only affect performance.
fn plan(n: usize, combinations: usize) -> Option<(u32, usize)> {
    let mut best_cost = n.saturating_mul(CHECK_COST);
    let mut best = None;
    let mut pow3 = 1usize;
    for m in 1..=MAX_WIDTH {
        pow3 *= 3;
        let rounds = combinations.div_ceil(m as usize);
        let additions = n.saturating_sub(expected_nonempty(n, pow3));
        let round_cost = n
            .saturating_mul(POINT_COST)
            .saturating_add(additions.saturating_mul(ADD_COST))
            .saturating_add(pow3.saturating_mul(BUCKET_COST))
            .saturating_add((m as usize).saturating_mul(CHECK_COST));
        let cost = rounds.saturating_mul(round_cost);
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
    let num_buckets = 3usize.pow(m);
    let id_sets: Vec<Vec<u16>> = (0..rounds)
        .map(|_| draw_ids(rng, points.len(), num_buckets))
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
fn round_in_g1(affine: &[blst_p1_affine], ids: &[u16], m: u32) -> bool {
    let mut sums = sum_buckets(affine, ids, 3usize.pow(m));
    for (ones, twos) in combine(&mut sums, m) {
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

/// Map a uniform 16-bit value to a bucket id in `[0, num_buckets)`, or reject
/// it (Lemire's method: `value * num_buckets` splits into a high word — the
/// candidate id — and a low word; low words below `2^16 mod num_buckets` are
/// rejected). Exactly `floor(2^16 / num_buckets)` values map to every id, so
/// accepted ids are exactly uniform — see the module docs for why exactness
/// is load-bearing.
#[inline]
fn map_id(value: u16, num_buckets: usize) -> Option<u16> {
    debug_assert!((2..=59049).contains(&num_buckets));
    let scaled = (value as u32) * (num_buckets as u32);
    let threshold = (65536 % num_buckets) as u32;
    ((scaled & 0xFFFF) >= threshold).then_some((scaled >> 16) as u16)
}

/// Draw `n` independent uniform bucket ids in `[0, num_buckets)`.
fn draw_ids(rng: &mut impl CryptoRng, n: usize, num_buckets: usize) -> Vec<u16> {
    let mut ids = Vec::with_capacity(n);
    if n == 0 {
        return ids;
    }
    let mut buffer = [0u8; 8192];
    loop {
        rng.fill_bytes(&mut buffer);
        for pair in buffer.chunks_exact(2) {
            if let Some(id) = map_id(u16::from_le_bytes([pair[0], pair[1]]), num_buckets) {
                ids.push(id);
                if ids.len() == n {
                    return ids;
                }
            }
        }
    }
}

/// Pending pairs are completed once this many accumulate, keeping the chunk's
/// operands and denominators cache-resident while still amortizing the single
/// field inversion each completion shares.
const PENDING_CHUNK: usize = 1024;

/// A batch-affine addition awaiting completion. Operands are copied out when
/// the pair is scheduled, so slots and tables can be freely overwritten while
/// the pair is in flight.
struct PendingOp {
    a: blst_p1_affine,
    b: blst_p1_affine,
    tag: u32,
    double: bool,
}

/// A scheduler completing independent affine additions in shared-inversion
/// batches (Montgomery's trick): about six field multiplications per addition
/// instead of an inversion.
struct Pending {
    ops: Vec<PendingOp>,
    denominators: Vec<blst_fp>,
    scratch: Vec<blst_fp>,
}

impl Pending {
    fn new() -> Self {
        Self {
            ops: Vec::with_capacity(PENDING_CHUNK),
            denominators: Vec::with_capacity(PENDING_CHUNK),
            scratch: Vec::with_capacity(PENDING_CHUNK),
        }
    }

    const fn len(&self) -> usize {
        self.ops.len()
    }

    const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Schedule `a + b`, tagged for the caller. Sums that need no field
    /// arithmetic — an identity operand, or a cancelling pair — resolve
    /// immediately and are returned instead of scheduled.
    fn schedule(&mut self, a: &blst_p1_affine, b: &blst_p1_affine, tag: u32) -> Option<blst_p1_affine> {
        if affine_is_inf(a) {
            return Some(*b);
        }
        if affine_is_inf(b) {
            return Some(*a);
        }
        if a.x.l == b.x.l {
            // Same x: on the curve y is determined up to sign, so this is
            // either P + (-P) = identity or a doubling.
            let two_y = fp_add(&a.y, &b.y);
            if two_y.l == [0u64; 6] {
                return Some(blst_p1_affine::default());
            }
            // y_a == y_b != 0, so two_y = 2*y_a is the doubling denominator.
            // (y == 0 cannot occur: the group order h * r is odd, so the curve
            // has no 2-torsion.)
            self.denominators.push(two_y);
            self.ops.push(PendingOp {
                a: *a,
                b: *b,
                tag,
                double: true,
            });
        } else {
            self.denominators.push(fp_sub(&b.x, &a.x));
            self.ops.push(PendingOp {
                a: *a,
                b: *b,
                tag,
                double: false,
            });
        }
        None
    }

    /// Complete every scheduled pair with one shared inversion, writing each
    /// sum to its tagged index of `table`, and clear the schedule. Sound only
    /// when the caller guarantees no scheduled pair still needs to *read* a
    /// written index (operands were copied at scheduling time, so overlap with
    /// operand positions is fine).
    fn complete_write(&mut self, table: &mut [blst_p1_affine]) {
        batch_invert_with_scratch(&mut self.denominators, &mut self.scratch);
        for (op, inverse) in self.ops.iter().zip(&self.denominators) {
            table[op.tag as usize] = complete(op, inverse);
        }
        self.ops.clear();
        self.denominators.clear();
    }
}

/// Finish one scheduled addition given the inverse of its denominator, using
/// the affine chord/tangent formulas (curve coefficient a = 0):
///   add:    lambda = (y_b - y_a) / (x_b - x_a)
///   double: lambda = 3 * x_a^2 / (2 * y_a)
///   x_out = lambda^2 - x_a - x_b;  y_out = lambda*(x_a - x_out) - y_a
#[inline]
fn complete(op: &PendingOp, inverse: &blst_fp) -> blst_p1_affine {
    let lambda = if op.double {
        let x_sq = fp_sqr(&op.a.x);
        fp_mul(&fp_add(&fp_add(&x_sq, &x_sq), &x_sq), inverse)
    } else {
        fp_mul(&fp_sub(&op.b.y, &op.a.y), inverse)
    };
    let x_out = fp_sub(&fp_sub(&fp_sqr(&lambda), &op.a.x), &op.b.x);
    let y_out = fp_sub(&fp_mul(&lambda, &fp_sub(&op.a.x, &x_out)), &op.a.y);
    blst_p1_affine { x: x_out, y: y_out }
}

/// Sum `points` into `num_buckets` buckets given by `ids` (each id less than
/// `num_buckets`), returning one affine sum per bucket (the identity for empty
/// buckets).
///
/// Streams the points once through a slot table: a point landing on an empty
/// slot parks there, a point landing on an occupied slot pairs with the parked
/// point, and completed pair sums re-enter at their slot. See [`Pending`] for
/// the shared-inversion completion.
fn sum_buckets(points: &[blst_p1_affine], ids: &[u16], num_buckets: usize) -> Vec<blst_p1_affine> {
    debug_assert_eq!(points.len(), ids.len());
    // A slot's emptiness marker is the affine identity encoding (x = y = 0),
    // which no real curve point can collide with (y^2 = x^3 + 4 has no root at
    // the origin). This doubles as the correct semantics: parking an identity
    // sum leaves the slot empty, exactly as adding zero should.
    let mut slots = vec![blst_p1_affine::default(); num_buckets];
    let mut pending = Pending::new();
    let mut batch = Pending::new();

    /// How many points ahead to prefetch the slot for. The ids are known up
    /// front, so the (data-dependent, cache-unfriendly) slot reads can be
    /// requested early enough to hide their latency behind the stream.
    const PREFETCH_AHEAD: usize = 8;

    #[inline]
    fn prefetch_slot(slots: &[blst_p1_affine], id: usize) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: prefetch is a pure cache hint with no observable memory
        // effect; the pointer is in bounds (id indexes slots) and the point
        // spans two cache lines.
        unsafe {
            let line = core::ptr::from_ref(&slots[id]).cast::<i8>();
            core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(line);
            core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(line.add(64));
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (slots, id);
        }
    }

    /// Merge `point` into its slot: park it if the slot is empty, otherwise
    /// pair it with the parked point — resolving on the spot when no field
    /// arithmetic is needed, and emptying the slot until the pending pair sum
    /// re-enters otherwise.
    #[inline]
    fn feed(point: blst_p1_affine, id: usize, slots: &mut [blst_p1_affine], pending: &mut Pending) {
        let parked = slots[id];
        if affine_is_inf(&parked) {
            slots[id] = point;
            return;
        }
        match pending.schedule(&parked, &point, id as u32) {
            Some(resolved) => slots[id] = resolved,
            None => slots[id] = blst_p1_affine::default(),
        }
    }

    /// Complete all pending pairs (one shared inversion) and re-enter their
    /// sums, which may schedule follow-up pairs.
    fn drain(pending: &mut Pending, batch: &mut Pending, slots: &mut [blst_p1_affine]) {
        core::mem::swap(pending, batch);
        let (ops, denominators) = (&batch.ops, &mut batch.denominators);
        batch_invert_with_scratch(denominators, &mut batch.scratch);
        for (i, (op, inverse)) in ops.iter().zip(denominators.iter()).enumerate() {
            if let Some(ahead) = ops.get(i + PREFETCH_AHEAD) {
                prefetch_slot(slots, ahead.tag as usize);
            }
            feed(complete(op, inverse), op.tag as usize, slots, pending);
        }
        batch.ops.clear();
        batch.denominators.clear();
    }

    for (i, (point, &id)) in points.iter().zip(ids).enumerate() {
        if let Some(&ahead) = ids.get(i + PREFETCH_AHEAD) {
            prefetch_slot(&slots, ahead as usize);
        }
        feed(*point, id as usize, &mut slots, &mut pending);
        if pending.len() >= PENDING_CHUNK {
            drain(&mut pending, &mut batch, &mut slots);
        }
    }
    while !pending.is_empty() {
        drain(&mut pending, &mut batch, &mut slots);
    }
    slots
}

/// Table sizes at or below this use the direct per-digit scan; above it, the
/// digit-peeling reduction is cheaper. Also the exact combine path for narrow
/// rounds (`m <= 5`).
const SCAN_CUTOFF: usize = 243;

/// Recover, for every digit `j < m`, the pair of sums
/// `(sum of buckets with digit_j = 1, sum of buckets with digit_j = 2)` from
/// the `3^m` bucket sums (consumed as scratch).
///
/// Digits are peeled from the top: splitting the table by the top digit gives
/// contiguous thirds `T0 | T1 | T2`; the top digit's pair is
/// `(sum(T1), sum(T2))`, and the element-wise sum `T0 + T1 + T2` is a table
/// one digit shorter with all remaining digit sums unchanged. Each peel is a
/// pure reassociation of the same bucket sums, so the recovered combinations
/// are exactly those specified in the module docs. Once the table is at most
/// [`SCAN_CUTOFF`] entries, the remaining digits use the direct scan.
fn combine(sums: &mut [blst_p1_affine], m: u32) -> Vec<(blst_p1, blst_p1)> {
    let mut digits = vec![(blst_p1::default(), blst_p1::default()); m as usize];
    let mut pending = Pending::new();

    /// Schedule one in-place pairwise-halving step over `table[base..base+len]`
    /// (results land in the region's front half; an odd element carries over),
    /// returning the reduced length. Safe against the deferred writes because
    /// every write index is below every operand index still to be read.
    fn halve(pending: &mut Pending, table: &mut [blst_p1_affine], base: usize, len: usize) -> usize {
        if len <= 1 {
            return len;
        }
        for k in 0..len / 2 {
            if let Some(sum) = pending.schedule(&table[base + 2 * k], &table[base + 2 * k + 1], (base + k) as u32)
            {
                table[base + k] = sum;
            }
            if pending.len() >= PENDING_CHUNK {
                // Safe mid-pass: writes land at indexes at most base + k, all
                // strictly below the base + 2k reads still to come (and below
                // the other third's region, which sits at a disjoint base).
                pending.complete_write(table);
            }
        }
        if len % 2 == 1 {
            table[base + len / 2] = table[base + len - 1];
        }
        len.div_ceil(2)
    }

    let mut size = sums.len();
    let mut remaining = m as usize;
    while size > SCAN_CUTOFF {
        size /= 3;
        remaining -= 1;
        // Element-wise folds T0 += T1, then T0 += T2 (each completed before
        // the next reads what it wrote).
        for third in [size, 2 * size] {
            for u in 0..size {
                if let Some(sum) = pending.schedule(&sums[u], &sums[third + u], u as u32) {
                    sums[u] = sum;
                }
                if pending.len() >= PENDING_CHUNK {
                    // Safe mid-pass: writes land at already-consumed indexes
                    // (at most the current u), behind the reads still to come.
                    pending.complete_write(sums);
                }
            }
            pending.complete_write(sums);
        }
        // The middle and top thirds are dead copies now; reduce each to its
        // sum in place, sharing completion batches between the two trees.
        let (mut ones_len, mut twos_len) = (size, size);
        while ones_len > 1 || twos_len > 1 {
            ones_len = halve(&mut pending, sums, size, ones_len);
            twos_len = halve(&mut pending, sums, 2 * size, twos_len);
            pending.complete_write(sums);
        }
        digits[remaining] = (p1_from_affine(&sums[size]), p1_from_affine(&sums[2 * size]));
    }

    // Direct scan for the remaining digits of the folded table.
    for (j, digit) in digits.iter_mut().enumerate().take(remaining) {
        let divisor = 3usize.pow(j as u32);
        let mut ones = blst_p1::default();
        let mut twos = blst_p1::default();
        for (v, sum) in sums[..size].iter().enumerate() {
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
        *digit = (ones, twos);
    }
    digits
}

/// Lift an affine point (identity included) to a Jacobian one.
fn p1_from_affine(point: &blst_p1_affine) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: out is the identity and point is a valid blst_p1_affine;
    // blst_p1_add_or_double_affine handles identity and permits out == a.
    unsafe { blst_p1_add_or_double_affine(&mut out, &out, point) };
    out
}

/// Replace every element with its inverse using Montgomery's trick: one field
/// inversion plus three multiplications per element. `prefix` is caller-owned
/// scratch, so hot paths reuse its allocation across batches.
///
/// Every element MUST be nonzero (`blst_fp_inverse(0) == 0` would silently
/// poison the shared product); [`Pending::schedule`]'s classification
/// guarantees it.
fn batch_invert_with_scratch(values: &mut [blst_fp], prefix: &mut Vec<blst_fp>) {
    if values.is_empty() {
        return;
    }
    // prefix[i] = values[0] * ... * values[i]
    prefix.clear();
    prefix.reserve(values.len());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::{G1, Scalar};
    use blst::blst_p1_is_equal;
    use commonware_codec::FixedSize;
    use commonware_math::algebra::{Additive, CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use rand_core::Rng;

    /// Standard soundness target for the tests.
    const SECURITY: usize = 128;

    /// [`batch_invert_with_scratch`] with a throwaway scratch buffer.
    fn batch_invert(values: &mut [blst_fp]) {
        let mut scratch = Vec::with_capacity(values.len());
        batch_invert_with_scratch(values, &mut scratch);
    }

    /// A batch size comfortably above the per-point fallback threshold, so the
    /// batched path is exercised.
    const LARGE: usize = 1000;

    /// A batch size whose plan is wide enough (`3^m > SCAN_CUTOFF`) that the
    /// digit-peeling combine is exercised end to end.
    const WIDE: usize = 4000;

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
    fn assert_sums_match(points: &[G1], ids: &[u16], num_buckets: usize) {
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
    fn expected_nonempty_is_sane() {
        // Exact when n = 1, monotone in n, never exceeding b or n-ish bounds.
        assert_eq!(expected_nonempty(1, 27), 1);
        for b in [3usize, 243, 19683] {
            let mut last = 0;
            for n in [1usize, 10, 100, 1000, 100_000] {
                let nonempty = expected_nonempty(n, b);
                assert!(nonempty <= b);
                assert!(nonempty <= n);
                assert!(nonempty >= last);
                last = nonempty;
            }
            // Far more points than buckets: essentially every bucket hit.
            assert!(expected_nonempty(100 * b, b) >= b - b / 50);
        }
    }

    #[test]
    fn map_id_is_exactly_uniform() {
        // Sweep the entire 16-bit domain: every id must be produced by exactly
        // floor(2^16 / num_buckets) inputs — exact uniformity, not statistical.
        for m in 1..=MAX_WIDTH {
            let num_buckets = 3usize.pow(m);
            let per_id = 65536 / num_buckets;
            let mut counts = vec![0usize; num_buckets];
            for value in 0..=u16::MAX {
                if let Some(id) = map_id(value, num_buckets) {
                    counts[id as usize] += 1;
                }
            }
            for (id, &count) in counts.iter().enumerate() {
                assert_eq!(count, per_id, "m={m} id={id}");
            }
        }
    }

    #[test]
    fn draw_ids_are_in_range() {
        let mut rng = test_rng();
        for m in [1u32, 5, 9, MAX_WIDTH] {
            let num_buckets = 3usize.pow(m);
            let ids = draw_ids(&mut rng, 5000, num_buckets);
            assert_eq!(ids.len(), 5000);
            assert!(ids.iter().all(|&id| (id as usize) < num_buckets));
        }
        assert!(draw_ids(&mut test_rng(), 0, 27).is_empty());
    }

    #[test]
    fn round_isolates_each_combination() {
        // A round's soundness multiplies across its m combinations only if the
        // combine actually wires digit j of the bucket index to combination j.
        // Placing a single bad point at a chosen bucket makes combination j's
        // cofactor part exactly digit_j(bucket) * T, so each bucket id below
        // deterministically isolates one digit position and value; a wiring
        // bug (a stuck or truncated digit) accepts one of the rejecting cases.
        // M = 9 forces the digit-peeling combine (table 19683 > SCAN_CUTOFF)
        // including its scan tail, covering both paths.
        let mut rng = test_rng();
        const M: u32 = 9;
        let num_buckets = 3usize.pow(M);
        let mut points: Vec<G1> = (0..800).map(|_| in_subgroup_point(&mut rng)).collect();
        let bad_index = points.len();
        points.push(off_subgroup_point(&mut rng));
        let affine = G1::batch_to_affine(&points);
        // Good points are spread arbitrarily (most buckets stay empty); their
        // in-subgroup parts cannot mask a cofactor part in any combination.
        let mut ids: Vec<u16> = (0..points.len())
            .map(|i| ((i * 37) % num_buckets) as u16)
            .collect();
        // Vector 0 assigns the bad point coefficient 0 in every combination,
        // so the round must accept.
        ids[bad_index] = 0;
        assert!(round_in_g1(&affine, &ids, M));
        // Any nonzero vector leaves a nonzero digit in some combination, which
        // must reject: probe digit values 1 and 2 at every position j.
        for j in 0..M {
            for value in [1u16, 2] {
                ids[bad_index] = value * 3u16.pow(j);
                assert!(
                    !round_in_g1(&affine, &ids, M),
                    "bad point at digit {j} value {value} escaped"
                );
            }
        }
    }

    #[test]
    fn combine_matches_direct_scan() {
        // The digit-peeling combine must produce exactly the per-digit sums of
        // the direct scan — same points, same wiring — for every width,
        // including tables with identities, duplicates, and cancelling pairs.
        let mut rng = test_rng();
        for m in 1..=9u32 {
            let num_buckets = 3usize.pow(m);
            let base: Vec<G1> = (0..7)
                .map(|i| {
                    if i == 0 {
                        G1::zero()
                    } else if i % 3 == 0 {
                        off_subgroup_point(&mut rng)
                    } else {
                        in_subgroup_point(&mut rng)
                    }
                })
                .collect();
            let table: Vec<G1> = (0..num_buckets)
                .map(|v| match v % 11 {
                    0 => G1::zero(),
                    1..=6 => base[v % 7],
                    7 => -base[v % 7],
                    _ => in_subgroup_point(&mut rng),
                })
                .collect();
            let affine = G1::batch_to_affine(&table);

            // Reference: the direct scan over the full table.
            let mut expected = Vec::new();
            for j in 0..m {
                let divisor = 3usize.pow(j);
                let mut ones = blst_p1::default();
                let mut twos = blst_p1::default();
                for (v, sum) in affine.iter().enumerate() {
                    if affine_is_inf(sum) {
                        continue;
                    }
                    let acc = match (v / divisor) % 3 {
                        1 => &mut ones,
                        2 => &mut twos,
                        _ => continue,
                    };
                    // SAFETY: valid points; handles identity and out == a.
                    unsafe { blst_p1_add_or_double_affine(acc, acc, sum) };
                }
                expected.push((ones, twos));
            }

            let mut scratch = affine.clone();
            let got = combine(&mut scratch, m);
            assert_eq!(got.len(), expected.len());
            for (j, ((got_ones, got_twos), (want_ones, want_twos))) in
                got.iter().zip(&expected).enumerate()
            {
                // SAFETY: all operands are valid blst_p1 values.
                unsafe {
                    assert!(blst_p1_is_equal(got_ones, want_ones), "m={m} digit={j} ones");
                    assert!(blst_p1_is_equal(got_twos, want_twos), "m={m} digit={j} twos");
                }
            }
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
        let cases: Vec<(Vec<G1>, Vec<u16>, usize)> = vec![
            // Cancelling pair produces the identity.
            (vec![p, -p], vec![0, 0], 1),
            // Duplicates force the doubling path.
            (vec![p, p], vec![0, 0], 1),
            (vec![q, q, q], vec![0, 0, 0], 1),
            // Identity inputs and identity-only buckets.
            (vec![p, G1::zero()], vec![0, 0], 1),
            (vec![G1::zero(), G1::zero()], vec![0, 0], 1),
            // Cancellation of intermediate sums: (p+q) + -(p+q).
            (vec![p, q, -p, -q], vec![0, 0, 0, 0], 1),
            // Odd counts and cancellation combined.
            (vec![p, -p, p], vec![0, 0, 0], 1),
            // Singleton with empty buckets around it.
            (vec![p], vec![1], 3),
            // A displaced stale slot must read as empty, not as its old point.
            (vec![p, p, q], vec![4, 4, 4], 19683),
        ];
        for (points, ids, num_buckets) in cases {
            assert_sums_match(&points, &ids, num_buckets);
        }
    }

    #[test]
    fn sum_buckets_matches_naive() {
        let mut rng = test_rng();
        for round in 0..24usize {
            let n = 1 + (round * 37) % 150;
            let num_buckets = [1usize, 2, 3, 9, 27, 243, 2187, 19683][round % 8];
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
            let mut id_bytes = vec![0u8; 2 * n];
            rng.fill_bytes(&mut id_bytes);
            let ids: Vec<u16> = id_bytes
                .chunks_exact(2)
                .map(|pair| (u16::from_le_bytes([pair[0], pair[1]]) as usize % num_buckets) as u16)
                .collect();
            assert_sums_match(&points, &ids, num_buckets);
        }
    }

    #[test]
    fn sum_buckets_flushes_mid_stream() {
        // More same-bucket points than PENDING_CHUNK forces mid-stream drains
        // whose completed sums re-enter occupied slots.
        let mut rng = test_rng();
        let p = in_subgroup_point(&mut rng);
        let n = 2 * PENDING_CHUNK + 3;
        let points = vec![p; n];
        let ids = vec![1u16; n];
        assert_sums_match(&points, &ids, 3);
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
    fn wide_batch_agrees_end_to_end() {
        // Wide enough that the plan uses the digit-peeling combine.
        let mut rng = test_rng();
        let (m, _) = plan(WIDE, combinations_for_security(SECURITY)).unwrap();
        assert!(3usize.pow(m) > SCAN_CUTOFF, "plan too narrow to cover the peel");
        let mut points: Vec<G1> = (0..WIDE).map(|_| in_subgroup_point(&mut rng)).collect();
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        points[WIDE - 1] = off_subgroup_point(&mut rng);
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
            for num_buckets in [243usize, 2187, 19683] {
                let ids = draw_ids(&mut rng, n, num_buckets);
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

    /// Stage gate: where one wide round's combine spends its time. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_combine -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_combine() {
        use std::time::Instant;
        let mut rng = test_rng();
        // One field inversion, amortized across a Pending flush.
        let xs: Vec<blst_fp> = (0..64)
            .map(|_| G1::batch_to_affine(&[in_subgroup_point(&mut rng)])[0].x)
            .collect();
        let start = Instant::now();
        for x in &xs {
            let mut out = blst_fp::default();
            // SAFETY: valid blst_fp values.
            unsafe { blst_fp_inverse(&mut out, x) };
            std::hint::black_box(out);
        }
        println!("blst_fp_inverse = {:?}", start.elapsed() / 64);

        // A full m=9 table, timed phase by phase.
        let m = 9u32;
        let num_buckets = 3usize.pow(m);
        let table: Vec<G1> = (0..num_buckets)
            .map(|_| in_subgroup_point(&mut rng))
            .collect();
        let affine = G1::batch_to_affine(&table);
        for _ in 0..3 {
            let mut sums = affine.clone();
            let mut pending = Pending::new();
            let mut size = sums.len();
            let mut elementwise = std::time::Duration::ZERO;
            let mut trees = std::time::Duration::ZERO;
            while size > SCAN_CUTOFF {
                size /= 3;
                let start = Instant::now();
                for third in [size, 2 * size] {
                    for u in 0..size {
                        if let Some(sum) = pending.schedule(&sums[u], &sums[third + u], u as u32) {
                            sums[u] = sum;
                        }
                    }
                    pending.complete_write(&mut sums);
                }
                elementwise += start.elapsed();
                let start = Instant::now();
                let (mut ones_len, mut twos_len) = (size, size);
                while ones_len > 1 || twos_len > 1 {
                    ones_len = tree_halve(&mut pending, &mut sums, size, ones_len);
                    twos_len = tree_halve(&mut pending, &mut sums, 2 * size, twos_len);
                    pending.complete_write(&mut sums);
                }
                trees += start.elapsed();
            }
            let start = Instant::now();
            let mut scanned = blst_p1::default();
            for j in 0..5u32 {
                let divisor = 3usize.pow(j);
                for (v, sum) in sums[..size].iter().enumerate() {
                    if affine_is_inf(sum) || (v / divisor) % 3 != 1 {
                        continue;
                    }
                    // SAFETY: valid points; handles identity and out == a.
                    unsafe { blst_p1_add_or_double_affine(&mut scanned, &scanned, sum) };
                }
            }
            let scan = start.elapsed();
            std::hint::black_box(&scanned);
            println!("elementwise={elementwise:?} trees={trees:?} scan(5 digits, ones only)={scan:?}");
        }

        /// Test-local copy of combine's halving step.
        fn tree_halve(
            pending: &mut Pending,
            table: &mut [blst_p1_affine],
            base: usize,
            len: usize,
        ) -> usize {
            if len <= 1 {
                return len;
            }
            for k in 0..len / 2 {
                if let Some(sum) = pending.schedule(
                    &table[base + 2 * k],
                    &table[base + 2 * k + 1],
                    (base + k) as u32,
                ) {
                    table[base + k] = sum;
                }
            }
            if len % 2 == 1 {
                table[base + len / 2] = table[base + len - 1];
            }
            len.div_ceil(2)
        }
    }

    /// Stage gate: end-to-end cost of forced round widths, and the split
    /// between accumulation, combine, and id drawing. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_widths -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_widths() {
        use std::time::Instant;
        let mut rng = test_rng();
        let n = 100_000;
        let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        for m in [7u32, 8, 9, 10] {
            let num_buckets = 3usize.pow(m);
            let rounds = 81usize.div_ceil(m as usize);
            let start = Instant::now();
            let id_sets: Vec<Vec<u16>> = (0..rounds)
                .map(|_| draw_ids(&mut rng, n, num_buckets))
                .collect();
            let ids_time = start.elapsed();
            let start = Instant::now();
            let mut sums_sets: Vec<Vec<blst_p1_affine>> = id_sets
                .iter()
                .map(|ids| sum_buckets(&affine, ids, num_buckets))
                .collect();
            let accumulate_time = start.elapsed();
            let start = Instant::now();
            let mut ok = true;
            for sums in &mut sums_sets {
                for (ones, twos) in combine(sums, m) {
                    let mut combination = blst_p1::default();
                    // SAFETY: all operands are valid blst_p1 values.
                    unsafe {
                        blst_p1_double(&mut combination, &twos);
                        blst_p1_add_or_double(&mut combination, &combination, &ones);
                        ok &= blst_p1_in_g1(&combination);
                    }
                }
            }
            let combine_time = start.elapsed();
            assert!(ok);
            println!(
                "m={m} rounds={rounds}: ids={ids_time:?} accumulate={accumulate_time:?} combine+check={combine_time:?} total={:?}",
                ids_time + accumulate_time + combine_time
            );
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
            let num_buckets = 3usize.pow(m);
            let id_sets: Vec<Vec<u16>> = (0..rounds)
                .map(|_| draw_ids(rng, points.len(), num_buckets))
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
