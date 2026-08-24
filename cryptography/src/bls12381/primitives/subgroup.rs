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
//! all `m` combinations, and about `81/m` passes are needed at 128-bit security
//! instead of 81. Four properties keep the constant small:
//!
//! - **Batch-affine additions.** Additions are queued rather than performed,
//!   and a chunk of them shares one field inversion (Montgomery's trick) — six
//!   field multiplications per addition instead of an inversion.
//! - **Streaming accumulation.** A bucket's slot holds its running sum, so a
//!   point is read once, added once, and never copied to a work list. A bucket
//!   whose addition is still queued is closed until the chunk completes, and a
//!   point that arrives meanwhile is carried to the next pass; with random
//!   bucket ids only a few percent of points ever are.
//! - **A shared collapse for the combine.** Recovering the `m` combinations one
//!   at a time would touch `2 * 3^(m-1)` bucket sums each, which caps `m` where
//!   the combine costs more than the accumulation it saves. Summing away one
//!   digit at a time instead yields every digit's marginals for about two
//!   additions per bucket in total, which is what makes wide rounds — and so
//!   few passes — affordable.
//! - **Widths chosen per round.** The plan spreads the required combinations
//!   over its rounds as evenly as it can, so a round count that does not divide
//!   them wastes at most one combination.
//!
//! The per-batch choice of widths (and of batching at all, versus checking each
//! point individually) is a pure performance decision made by a cost model;
//! soundness holds for every choice.
//!
//! What a batch cannot escape is one pass over the points per `log2(3^m)` bits
//! of soundness (see below), so the cost per point falls only with the
//! logarithm of the round width — and the width is bounded by what a round's
//! bucket slots can hold in cache. That is why the speedup over per-point
//! checking keeps growing with the batch: at `2^-128`, nine passes is the floor,
//! and the fixed per-round overheads only amortize away as `n` grows.
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
//! A round cannot do better than `3^-m` either, whatever it does with the
//! bucket sums: a lone bad point escapes whenever its coefficient vector is the
//! zero vector, which happens with probability `3^-m` however the `m`
//! combinations are wired. A pass over the points is therefore worth at most
//! `log2(3^m)` bits of soundness, and the accumulation cost is what decides how
//! large `3^m` can usefully be.
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
    blst_fp, blst_fp_inverse, blst_fp_mul, blst_fp_sqr, blst_p1, blst_p1_add_or_double_affine,
    blst_p1_affine, blst_p1_double, blst_p1_from_affine, blst_p1_in_g1,
};
use commonware_parallel::Strategy;
use core::mem::{MaybeUninit, size_of};
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

/// Largest supported number of parallel combinations per round.
///
/// A round's collapse workspace holds about `1.5 * 3^m` points, so this bounds
/// what a round can allocate; in practice [`SLOT_BUDGET`] binds first.
const MAX_WIDTH: u32 = 11;

/// Largest bucket-slot footprint a round should ask for, in bytes.
///
/// Points arrive in random bucket order, so the accumulator's working set is
/// the whole slot array. A wider round needs fewer passes over the points, but
/// once its slots outgrow the cache every point pays a miss that the saved
/// passes do not repay — measured here as a 20-35% jump in cost per addition
/// one step past the budget. Two MiB holds `3^9` slots.
const SLOT_BUDGET: usize = 2 << 20;

/// Approximate cost of one [`G1::in_subgroup`] check, in units of one
/// batch-affine point addition.
///
/// Machine-rough (measured ~52us per check against ~350ns per addition); it
/// only steers the cost model's choice of widths and the per-point fallback,
/// never soundness.
const CHECK_COST: usize = 150;

/// Number of point additions completed per shared field inversion.
///
/// Sized so that a chunk's denominators, prefix products and freshly written
/// results stay in cache while the inversion amortizes to well under one field
/// multiplication per addition.
const CHUNK: usize = 1024;

/// Flag stored in the high bit of a queued job's output slot, marking its
/// operands equal (a doubling rather than a chord).
const DOUBLE: u32 = 1 << 31;

/// Bucket slot holding nothing, i.e. standing for the identity.
const EMPTY: u8 = 0;

/// Bucket slot holding a running sum that further points can be added to.
const FILLED: u8 = 1;

/// Bucket slot closed by an addition that is queued but not yet completed.
const BUSY: u8 = 2;

/// How far ahead the accumulator prefetches the slot a point will land in.
///
/// The loop body is short, so this needs to cover an L2 or L3 miss; overshooting
/// only costs a cache line that would have been fetched anyway.
const PREFETCH_DISTANCE: usize = 24;

/// Expected number of occupied buckets when `n` points fall uniformly into `b`
/// of them: `b * (1 - e^(-n/b))`, with a cheap rational stand-in for the
/// exponential (the cost model only needs the shape).
fn expected_occupied(n: usize, b: usize) -> usize {
    let x = n as f64 / b as f64;
    if x > 32.0 {
        return b.min(n);
    }
    let series = 1.0 + x + x * x / 2.0 + x * x * x / 6.0;
    ((b as f64 * (1.0 - 1.0 / series)) as usize).min(n)
}

/// Modeled cost of one round at width `m`, in units of one batch-affine point
/// addition.
///
/// Summing `n` points into `3^m` buckets takes one addition per point that is
/// not the last one left in its bucket, and recovering the `m` combinations
/// takes about two additions per occupied bucket (one for the collapse chain,
/// one for the marginals it feeds). The `m` exact checks are charged too, since
/// they are what makes narrow rounds expensive on small batches.
fn round_cost(n: usize, m: u32) -> usize {
    let buckets = 3usize.pow(m);
    let occupied = expected_occupied(n, buckets);
    (n - occupied) + 2 * occupied + (m as usize) * CHECK_COST
}

/// Plan the rounds: one width per round, summing to at least `combinations`.
///
/// Returns `None` if checking each point individually is cheaper. The widths of
/// a plan differ by at most one, so a round count that does not divide
/// `combinations` wastes no more than one combination — which matters, since
/// the round count is what the batch pays for.
///
/// Soundness holds for every plan (a round of width `m` has error `3^-m`, and
/// the widths sum to at least `combinations`), so the cost model's constants
/// only affect performance.
fn plan(n: usize, combinations: usize) -> Option<Vec<u32>> {
    if combinations == 0 {
        return Some(Vec::new());
    }
    // A width is only usable if its buckets are neither hopelessly sparse nor
    // too many to keep close to the CPU.
    let mut widest = 0u32;
    while widest < MAX_WIDTH
        && 3usize.pow(widest + 1) <= 4 * n.max(1)
        && 3usize.pow(widest + 1) * size_of::<blst_p1_affine>() <= SLOT_BUDGET
    {
        widest += 1;
    }
    if widest == 0 {
        return None;
    }
    let mut best_cost = n.saturating_mul(CHECK_COST);
    let mut best = None;
    for rounds in combinations.div_ceil(widest as usize)..=combinations {
        let width = (combinations / rounds) as u32;
        let wide = combinations % rounds;
        // Spreading combinations evenly cannot push a round past `widest`: a
        // round count that leaves a remainder also leaves `width < widest`.
        debug_assert!(width < widest || wide == 0);
        let cost = wide.saturating_mul(round_cost(n, width + 1))
            + (rounds - wide).saturating_mul(round_cost(n, width));
        if cost < best_cost {
            best_cost = cost;
            best = Some(
                (0..rounds)
                    .map(|round| if round < wide { width + 1 } else { width })
                    .collect(),
            );
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
    // Whether to batch at all, and at what widths, is an algorithmic choice the
    // cost model makes; it cannot be delegated to `strategy` (which only
    // chooses serial vs parallel execution of a single algorithm). Either
    // path's independent units still run through `strategy`.
    let Some(widths) = plan(points.len(), combinations) else {
        return strategy
            .map_collect_vec_with_multiplier(points.iter(), 1, |point| point.in_subgroup())
            .into_iter()
            .all(|in_subgroup| in_subgroup);
    };
    let Some(&widest) = widths.iter().max() else {
        return true;
    };
    // One shared inversion converts every point to affine; the per-round
    // accumulations then reuse them.
    let affine = to_affine(points);

    // The RNG is sequential, so draw every round's coefficient vectors (as
    // base-3 bucket ids) up front; the rounds themselves are independent and
    // run through the strategy, weighted by the per-round accumulation size.
    let mut trits = Trits::new(rng);
    let id_sets: Vec<(u32, Vec<u32>)> = widths
        .iter()
        .map(|&m| (m, trits.fill(m, affine.len())))
        .collect();
    strategy
        .map_init_collect_vec_with_multiplier(
            id_sets.iter(),
            affine.len(),
            || Round::new(widest),
            |round, (m, ids)| round.run(&affine, ids, *m),
        )
        .into_iter()
        .all(|in_subgroup| in_subgroup)
}

/// Convert `points` to affine, dropping the identities among them.
///
/// One shared inversion serves a chunk of the batch (Montgomery's trick), so a
/// point costs about seven field multiplications. The chunking keeps the
/// inversion's running products in cache, which on a large batch matters more
/// than the handful of extra inversions it costs. The identity contributes
/// nothing to any combination, so dropping it here spares the accumulator a
/// test for it on every pass.
fn to_affine(points: &[G1]) -> Vec<blst_p1_affine> {
    let mut affine = Vec::with_capacity(points.len());
    let mut inverses = Vec::with_capacity(CHUNK);
    let mut prefix = Vec::with_capacity(CHUNK);
    for chunk in points.chunks(CHUNK) {
        inverses.clear();
        inverses.extend(
            chunk
                .iter()
                .map(G1::as_blst_p1)
                .map(|point| point.z)
                .filter(|z| !fp_is_zero(z) && !fp_is_one(z)),
        );
        batch_invert(&mut inverses, &mut prefix);
        let mut inverses = inverses.iter();
        for point in chunk.iter().map(G1::as_blst_p1) {
            if fp_is_zero(&point.z) {
                continue;
            }
            // A point decoded from the wire is already normalized, which is the
            // common case for a batch of untrusted points.
            if fp_is_one(&point.z) {
                affine.push(blst_p1_affine {
                    x: point.x,
                    y: point.y,
                });
                continue;
            }
            let inverse = inverses.next().expect("one inverse per surviving point");
            let squared = fp_sqr(inverse);
            let cubed = fp_mul(&squared, inverse);
            affine.push(blst_p1_affine {
                x: fp_mul(&point.x, &squared),
                y: fp_mul(&point.y, &cubed),
            });
        }
    }
    affine
}

/// Working state for one round, reused across the round's passes — and, under a
/// sequential strategy, across every round.
struct Round {
    /// Number of parallel combinations of the round being run, i.e. base-3
    /// digits per bucket id.
    m: u32,
    /// Start of each collapse level within [`Self::sums`]. Level `j` holds
    /// `3^(m-j)` entries: level 0 is the bucket sums themselves (and doubles as
    /// the accumulator's per-bucket slots), and level `j+1` is level `j` with
    /// its lowest remaining digit summed away.
    levels: Vec<usize>,
    /// The concatenated collapse levels.
    sums: Vec<blst_p1_affine>,
    /// Whether the matching entry of [`Self::sums`] holds a point; an entry
    /// that does not stands for the identity.
    live: Vec<bool>,
    /// Per-bucket accumulator state over level 0 of [`Self::sums`]: empty,
    /// holding a running sum, or closed by an addition awaiting its inversion.
    state: Vec<u8>,
    /// Ping-pong lists of points still to be paired, with their bucket ids.
    lists: [Vec<blst_p1_affine>; 2],
    ids: [Vec<u32>; 2],
    /// Additions queued for the next shared inversion.
    pending: Pending,
    /// Entries still to be summed for each of the `2m` marginals.
    marginals: Vec<Vec<u32>>,
}

impl Round {
    /// Allocate state able to run any round up to width `widest`.
    fn new(widest: u32) -> Self {
        debug_assert!((1..=MAX_WIDTH).contains(&widest));
        let total = (3usize.pow(widest + 1) - 3) / 2;
        Self {
            m: 0,
            levels: Vec::with_capacity(widest as usize),
            sums: vec![blst_p1_affine::default(); total],
            live: vec![false; total],
            state: vec![EMPTY; 3usize.pow(widest)],
            lists: [Vec::new(), Vec::new()],
            ids: [Vec::new(), Vec::new()],
            pending: Pending::new(),
            marginals: (0..2 * widest as usize).map(|_| Vec::new()).collect(),
        }
    }

    /// Lay out the collapse levels for a round of width `m`.
    fn widen(&mut self, m: u32) {
        debug_assert!((1..=MAX_WIDTH).contains(&m));
        debug_assert!(3usize.pow(m) <= self.state.len());
        if self.m == m {
            return;
        }
        self.m = m;
        self.pending.bound(3usize.pow(m));
        self.levels.clear();
        let mut total = 0usize;
        for j in 0..m {
            self.levels.push(total);
            total += 3usize.pow(m - j);
        }
    }

    /// Sum `points` into the `3^m` buckets named by `ids`, leaving each bucket's
    /// sum in its slot at level 0 of [`Self::sums`].
    fn accumulate(&mut self, points: &[blst_p1_affine], ids: &[u32]) {
        self.state[..3usize.pow(self.m)].fill(EMPTY);
        accumulate_pass(
            points,
            ids,
            &mut self.lists[0],
            &mut self.ids[0],
            &mut self.sums,
            &mut self.state,
            &mut self.pending,
        );
        while !self.lists[0].is_empty() {
            let ([front, back], [front_ids, back_ids]) = (&mut self.lists, &mut self.ids);
            accumulate_pass(
                front,
                front_ids,
                back,
                back_ids,
                &mut self.sums,
                &mut self.state,
                &mut self.pending,
            );
            self.lists.swap(0, 1);
            self.ids.swap(0, 1);
        }
        // The collapse works off the shared liveness flags; level 0's come from
        // the accumulator's per-bucket state.
        let buckets = 3usize.pow(self.m);
        for (live, &state) in self.live[..buckets].iter_mut().zip(&self.state[..buckets]) {
            *live = state != EMPTY;
        }
    }

    /// Run one round: sum the points into `3^m` buckets keyed by coefficient
    /// vector, recover the `m` combinations from the bucket sums, and check
    /// each.
    fn run(&mut self, points: &[blst_p1_affine], ids: &[u32], m: u32) -> bool {
        self.widen(m);
        self.accumulate(points, ids);

        // Collapse chain: level `j+1` sums away level `j`'s lowest digit, so
        // every digit position's marginals come out of one shared walk over the
        // bucket sums rather than one walk per combination.
        for j in 0..(self.m as usize).saturating_sub(1) {
            let (source, target) = (self.levels[j], self.levels[j + 1]);
            let width = 3usize.pow(self.m - j as u32 - 1);
            for digit in [1usize, 2] {
                for k in 0..width {
                    let out = (target + k) as u32;
                    let first = if digit == 1 {
                        (source + 3 * k) as u32
                    } else {
                        out
                    };
                    queue_add(
                        &mut self.sums,
                        &mut self.live,
                        &mut self.pending,
                        out,
                        first,
                        (source + 3 * k + digit) as u32,
                    );
                }
                complete(&mut self.sums, &mut self.pending);
            }
        }

        // Combination `j` is the sum of the buckets whose `j`-th digit is 1 plus
        // twice the sum of those whose digit is 2, and level `j` has every other
        // digit already summed away.
        for j in 0..self.m as usize {
            let level = self.levels[j];
            let width = 3usize.pow(self.m - j as u32 - 1);
            for digit in [1usize, 2] {
                let list = &mut self.marginals[2 * j + digit - 1];
                list.clear();
                list.extend(
                    (0..width)
                        .map(|k| (level + digit + 3 * k) as u32)
                        .filter(|&index| self.live[index as usize]),
                );
            }
        }
        reduce(
            &mut self.sums,
            &mut self.live,
            &mut self.marginals,
            &mut self.pending,
        );

        for j in 0..self.m as usize {
            let mut combination = blst_p1::default();
            if let Some(&twos) = self.marginals[2 * j + 1].first() {
                let mut point = blst_p1::default();
                // SAFETY: the index names a live affine point, and blst_p1
                // defaults to the identity.
                unsafe {
                    blst_p1_from_affine(&mut point, &self.sums[twos as usize]);
                    blst_p1_double(&mut combination, &point);
                }
            }
            if let Some(&ones) = self.marginals[2 * j].first() {
                // SAFETY: both operands are valid; the routine handles the
                // identity and equal operands, and permits out == a.
                unsafe {
                    blst_p1_add_or_double_affine(
                        &mut combination,
                        &combination,
                        &self.sums[ones as usize],
                    );
                }
            }
            // SAFETY: combination is a valid blst_p1 (identity included).
            if !unsafe { blst_p1_in_g1(&combination) } {
                return false;
            }
        }
        true
    }
}

/// Add each point of `src` into its bucket's running sum.
///
/// The sum stays in the bucket's slot, so a point is read once and written once
/// rather than travelling down a pairing tree. An addition is only queued, not
/// completed, until its chunk shares an inversion, so a bucket with an
/// outstanding addition is closed and any further point for it moves to
/// `carry`, to be retried on the next pass. The pass returns with `carry` empty
/// exactly when every point has been absorbed.
fn accumulate_pass(
    src: &[blst_p1_affine],
    src_ids: &[u32],
    carry: &mut Vec<blst_p1_affine>,
    carry_ids: &mut Vec<u32>,
    slots: &mut [blst_p1_affine],
    state: &mut [u8],
    pending: &mut Pending,
) {
    debug_assert_eq!(src.len(), src_ids.len());
    carry.clear();
    carry_ids.clear();
    let mut deferred = 0usize;
    for (index, (point, &id)) in src.iter().zip(src_ids).enumerate() {
        // Bucket ids are uniform, so the slot a point lands in is a cache miss
        // the loop can see coming a long way off.
        if let Some(&ahead) = src_ids.get(index + PREFETCH_DISTANCE) {
            prefetch(slots, ahead as usize);
        }
        let bucket = id as usize;
        match state[bucket] {
            EMPTY => {
                state[bucket] = FILLED;
                slots[bucket] = *point;
                continue;
            }
            BUSY => {
                carry.push(*point);
                carry_ids.push(id);
                // Bound the share of a pass that defers, so a batch whose ids
                // collide constantly still converges in a few passes.
                deferred += 1;
                if deferred > pending.jobs.len() {
                    absorb(src, slots, state, pending);
                    deferred = 0;
                }
                continue;
            }
            _ => {}
        }
        // Only the x coordinates decide which formula applies, so the running
        // sum is read a field element at a time rather than copied whole.
        let held = &slots[bucket];
        if fp_eq(&held.x, &point.x) {
            // Same x: on the curve y is determined up to sign, so this is
            // either P + (-P) = identity or a doubling.
            let two_y = fp_add(&held.y, &point.y);
            if fp_is_zero(&two_y) {
                // The sum cancels, and an empty slot is the identity.
                state[bucket] = EMPTY;
                continue;
            }
            // y_held == y_point != 0, so two_y = 2*y_held is the doubling
            // denominator. (y == 0 cannot occur: the group order h * r is odd,
            // so the curve has no 2-torsion.)
            pending.push(bucket as u32 | DOUBLE, index as u32, two_y);
        } else {
            pending.push(bucket as u32, index as u32, fp_sub(&point.x, &held.x));
        }
        state[bucket] = BUSY;
        if pending.is_full() {
            absorb(src, slots, state, pending);
            deferred = 0;
        }
    }
    absorb(src, slots, state, pending);
}

/// Finish the additions queued by [`accumulate_pass`] and reopen their buckets.
///
/// The shared inversion's backward walk hands each addition its inverse just as
/// the addition needs it, so no inverse is ever written to memory.
fn absorb(
    src: &[blst_p1_affine],
    slots: &mut [blst_p1_affine],
    state: &mut [u8],
    pending: &mut Pending,
) {
    let Some(mut running) = prefix_inverse(&pending.denominators, &mut pending.prefix) else {
        return;
    };
    for index in (0..pending.jobs.len()).rev() {
        let (slot, point) = pending.jobs[index];
        let inverse = pending.unwind(index, &mut running);
        let bucket = (slot & !DOUBLE) as usize;
        let sum = chord(
            &slots[bucket],
            &src[point as usize],
            &inverse,
            slot & DOUBLE != 0,
        );
        slots[bucket] = sum;
        state[bucket] = FILLED;
    }
    pending.clear();
}

/// Queue `slots[out] = slots[first] + slots[second]`.
///
/// The first operand is moved into the output slot immediately, so a completed
/// job needs only the output and the second operand. Queued jobs must never
/// read a slot another queued job writes; every caller below queues a wave of
/// disjoint outputs and completes it before starting the next.
fn queue_add(
    slots: &mut [blst_p1_affine],
    live: &mut [bool],
    pending: &mut Pending,
    out: u32,
    first: u32,
    second: u32,
) {
    let (out_index, first_index, second_index) = (out as usize, first as usize, second as usize);
    if !live[second_index] {
        if live[first_index] && out != first {
            slots[out_index] = slots[first_index];
        }
        live[out_index] = live[first_index];
        return;
    }
    if !live[first_index] {
        slots[out_index] = slots[second_index];
        live[out_index] = true;
        return;
    }
    if out != first {
        slots[out_index] = slots[first_index];
    }
    live[out_index] = true;
    let (held, point) = (&slots[out_index], &slots[second_index]);
    if fp_eq(&held.x, &point.x) {
        let two_y = fp_add(&held.y, &point.y);
        if fp_is_zero(&two_y) {
            live[out_index] = false;
            return;
        }
        pending.push(out | DOUBLE, second, two_y);
    } else {
        pending.push(out, second, fp_sub(&point.x, &held.x));
    }
    if pending.is_full() {
        complete(slots, pending);
    }
}

/// Finish the additions queued by [`queue_add`].
fn complete(slots: &mut [blst_p1_affine], pending: &mut Pending) {
    let Some(mut running) = prefix_inverse(&pending.denominators, &mut pending.prefix) else {
        return;
    };
    for index in (0..pending.jobs.len()).rev() {
        let (slot, second) = pending.jobs[index];
        let inverse = pending.unwind(index, &mut running);
        let out = (slot & !DOUBLE) as usize;
        let sum = chord(
            &slots[out],
            &slots[second as usize],
            &inverse,
            slot & DOUBLE != 0,
        );
        slots[out] = sum;
    }
    pending.clear();
}

/// Sum each list of slot indices down to a single entry, in place.
///
/// Every list halves on each wave and all lists share the wave's inversion, so
/// the whole combine costs a handful of inversions rather than one per list.
fn reduce(
    slots: &mut [blst_p1_affine],
    live: &mut [bool],
    lists: &mut [Vec<u32>],
    pending: &mut Pending,
) {
    while lists.iter().any(|list| list.len() > 1) {
        for list in lists.iter() {
            for pair in list.chunks_exact(2) {
                queue_add(slots, live, pending, pair[0], pair[0], pair[1]);
            }
        }
        complete(slots, pending);
        for list in lists.iter_mut() {
            let len = list.len();
            let mut kept = 0;
            for index in 0..len / 2 {
                let slot = list[2 * index];
                if live[slot as usize] {
                    list[kept] = slot;
                    kept += 1;
                }
            }
            if len % 2 == 1 {
                list[kept] = list[len - 1];
                kept += 1;
            }
            list.truncate(kept);
        }
    }
}

/// Additions queued for the next shared field inversion.
///
/// A queued job names the slot its result belongs in (with [`DOUBLE`] set when
/// its operands are equal) and the second operand; the first operand is
/// wherever the completing routine knows to find it.
struct Pending {
    jobs: Vec<(u32, u32)>,
    denominators: Vec<blst_fp>,
    /// Running products of the denominators, walked back down as each addition
    /// takes its inverse.
    prefix: Vec<blst_fp>,
    /// How many additions to queue before sharing an inversion.
    limit: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            jobs: Vec::with_capacity(CHUNK),
            denominators: Vec::with_capacity(CHUNK),
            prefix: vec![blst_fp::default(); CHUNK],
            limit: CHUNK,
        }
    }

    /// Bound the chunk so a round with few buckets does not spend most of a
    /// chunk unable to touch any of them.
    ///
    /// An accumulating bucket is closed until its addition completes, so at
    /// most one addition per bucket can be in flight; queueing past that only
    /// defers points to another pass.
    fn bound(&mut self, buckets: usize) {
        self.limit = CHUNK.min(buckets);
    }

    /// Queue one addition.
    #[inline(always)]
    fn push(&mut self, slot: u32, second: u32, denominator: blst_fp) {
        self.jobs.push((slot, second));
        self.denominators.push(denominator);
    }

    /// Whether the queue has grown to a full inversion's worth of work.
    #[inline(always)]
    const fn is_full(&self) -> bool {
        self.jobs.len() >= self.limit
    }

    /// Return the inverse of job `index`'s denominator, advancing `running` (the
    /// inverse of the running product through `index`) to the next job down.
    #[inline(always)]
    fn unwind(&self, index: usize, running: &mut blst_fp) -> blst_fp {
        if index == 0 {
            return *running;
        }
        let inverse = fp_mul(running, &self.prefix[index - 1]);
        *running = fp_mul(running, &self.denominators[index]);
        inverse
    }

    fn clear(&mut self) {
        self.jobs.clear();
        self.denominators.clear();
    }
}

/// Complete one affine addition (or doubling) given the inverse of its
/// denominator.
///
/// Chord/tangent formulas for curve coefficient `a = 0`:
/// `add: lambda = (y_b - y_a) / (x_b - x_a)`,
/// `double: lambda = 3 x_a^2 / (2 y_a)`,
/// `x_out = lambda^2 - x_a - x_b`, `y_out = lambda (x_a - x_out) - y_a`.
#[inline(always)]
fn chord(
    first: &blst_p1_affine,
    second: &blst_p1_affine,
    inverse: &blst_fp,
    double: bool,
) -> blst_p1_affine {
    let lambda = if double {
        let square = fp_sqr(&first.x);
        fp_mul(&fp_add(&fp_add(&square, &square), &square), inverse)
    } else {
        fp_mul(&fp_sub(&second.y, &first.y), inverse)
    };
    let x = fp_sub(&fp_sub(&fp_sqr(&lambda), &first.x), &second.x);
    let y = fp_sub(&fp_mul(&lambda, &fp_sub(&first.x, &x)), &first.y);
    blst_p1_affine { x, y }
}

/// Fill `prefix` with the running products of `values` and return the inverse
/// of their total, or `None` when there is nothing to invert.
///
/// This is the forward half of Montgomery's trick; each caller walks back down
/// the prefix products itself so that an element's inverse is consumed where it
/// is produced. Together the two halves cost one field inversion plus three
/// multiplications per element.
///
/// Every element MUST be nonzero (`blst_fp_inverse(0) == 0` would silently
/// poison the shared product); the callers' classification guarantees it.
fn prefix_inverse(values: &[blst_fp], prefix: &mut Vec<blst_fp>) -> Option<blst_fp> {
    let (first, rest) = values.split_first()?;
    if prefix.len() < values.len() {
        prefix.resize(values.len(), blst_fp::default());
    }
    let mut running = *first;
    prefix[0] = running;
    for (value, slot) in rest.iter().zip(prefix[1..].iter_mut()) {
        running = fp_mul(&running, value);
        *slot = running;
    }
    let mut inverse = blst_fp::default();
    // SAFETY: both pointers reference valid blst_fp values.
    unsafe { blst_fp_inverse(&mut inverse, &running) };
    Some(inverse)
}

/// Hint that `slots[index]` will be read soon.
///
/// A point spans two cache lines, and the caller reads both.
#[inline(always)]
fn prefetch(slots: &[blst_p1_affine], index: usize) {
    let _ = (slots, index);
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
        let base = slots.as_ptr().wrapping_add(index).cast::<i8>();
        // SAFETY: _mm_prefetch never dereferences its argument, so any address
        // is allowed; the index is in range for the slice regardless.
        unsafe {
            _mm_prefetch(base, _MM_HINT_T0);
            _mm_prefetch(base.wrapping_add(64), _MM_HINT_T0);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::{_PREFETCH_LOCALITY3, _PREFETCH_READ, _prefetch};
        let base = slots.as_ptr().wrapping_add(index).cast::<i8>();
        // SAFETY: _prefetch never dereferences its argument.
        unsafe {
            _prefetch::<_PREFETCH_READ, _PREFETCH_LOCALITY3>(base);
            _prefetch::<_PREFETCH_READ, _PREFETCH_LOCALITY3>(base.wrapping_add(64));
        }
    }
}

/// Replace every element with its inverse, using one shared field inversion.
fn batch_invert(values: &mut [blst_fp], prefix: &mut Vec<blst_fp>) {
    let Some(mut running) = prefix_inverse(values, prefix) else {
        return;
    };
    for index in (1..values.len()).rev() {
        let inverse = fp_mul(&running, &prefix[index - 1]);
        running = fp_mul(&running, &values[index]);
        values[index] = inverse;
    }
    values[0] = running;
}

/// The BLS12-381 base field modulus, as little-endian 64-bit limbs.
///
/// `2 * MODULUS < 2^384`, so adding two reduced elements never carries out of
/// the top limb.
const MODULUS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// Whether two field elements are equal.
///
/// Written as a short-circuiting limb comparison: the accumulator's hot path
/// asks this of two unrelated points, which almost always differ in the first
/// limb.
#[inline(always)]
const fn fp_eq(a: &blst_fp, b: &blst_fp) -> bool {
    a.l[0] == b.l[0]
        && a.l[1] == b.l[1]
        && a.l[2] == b.l[2]
        && a.l[3] == b.l[3]
        && a.l[4] == b.l[4]
        && a.l[5] == b.l[5]
}

/// Whether a field element is zero.
#[inline(always)]
const fn fp_is_zero(a: &blst_fp) -> bool {
    (a.l[0] | a.l[1] | a.l[2] | a.l[3] | a.l[4] | a.l[5]) == 0
}

/// One in the field's Montgomery form, `R mod MODULUS` for `R = 2^384`.
///
/// A point decoded from the wire carries this as its `z`.
const MONTGOMERY_ONE: blst_fp = blst_fp {
    l: [
        0x7609_0000_0002_fffd,
        0xebf4_000b_c40c_0002,
        0x5f48_9857_53c7_58ba,
        0x77ce_5853_7052_5745,
        0x5c07_1a97_a256_ec6d,
        0x15f6_5ec3_fa80_e493,
    ],
};

/// Whether a field element is one, i.e. whether a point is already normalized.
#[inline(always)]
const fn fp_is_one(a: &blst_fp) -> bool {
    fp_eq(a, &MONTGOMERY_ONE)
}

/// Add two reduced field elements.
///
/// Inlined rather than delegated to `blst_fp_add`: the batch-affine addition
/// spends several of these per point addition, where the call and the mandatory
/// zeroing of the out-parameter cost more than the arithmetic itself. The
/// carry chains are written in the form that lowers to `adc`/`sbb`.
#[inline(always)]
fn fp_add(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut sum = [0u64; 6];
    let mut carry = false;
    for (out, (left, right)) in sum.iter_mut().zip(a.l.iter().zip(&b.l)) {
        let (limb, first) = left.overflowing_add(*right);
        let (limb, second) = limb.overflowing_add(carry as u64);
        *out = limb;
        carry = first | second;
    }
    debug_assert!(!carry, "2 * MODULUS fits in 384 bits");
    subtract_modulus(sum)
}

/// Subtract one reduced field element from another.
#[inline(always)]
fn fp_sub(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut difference = [0u64; 6];
    let mut borrow = false;
    for (out, (left, right)) in difference.iter_mut().zip(a.l.iter().zip(&b.l)) {
        let (limb, first) = left.overflowing_sub(*right);
        let (limb, second) = limb.overflowing_sub(borrow as u64);
        *out = limb;
        borrow = first | second;
    }
    // The subtraction underflowed exactly when a < b; add the modulus back.
    let mask = 0u64.wrapping_sub(borrow as u64);
    let mut sum = [0u64; 6];
    let mut carry = false;
    for (out, (limb, modulus)) in sum.iter_mut().zip(difference.iter().zip(&MODULUS)) {
        let (limb, first) = limb.overflowing_add(modulus & mask);
        let (limb, second) = limb.overflowing_add(carry as u64);
        *out = limb;
        carry = first | second;
    }
    blst_fp { l: sum }
}

/// Reduce a value known to be below `2 * MODULUS`.
#[inline(always)]
fn subtract_modulus(value: [u64; 6]) -> blst_fp {
    let mut reduced = [0u64; 6];
    let mut borrow = false;
    for (out, (limb, modulus)) in reduced.iter_mut().zip(value.iter().zip(&MODULUS)) {
        let (limb, first) = limb.overflowing_sub(*modulus);
        let (limb, second) = limb.overflowing_sub(borrow as u64);
        *out = limb;
        borrow = first | second;
    }
    // Keep the reduced value unless subtracting the modulus underflowed.
    let mask = 0u64.wrapping_sub(borrow as u64);
    let mut out = [0u64; 6];
    for (out, (value, reduced)) in out.iter_mut().zip(value.iter().zip(&reduced)) {
        *out = (value & mask) | (reduced & !mask);
    }
    blst_fp { l: out }
}

#[inline(always)]
fn fp_mul(a: &blst_fp, b: &blst_fp) -> blst_fp {
    let mut out = MaybeUninit::<blst_fp>::uninit();
    // SAFETY: the operands are valid blst_fp values and blst_fp_mul writes the
    // whole result before returning.
    unsafe {
        blst_fp_mul(out.as_mut_ptr(), a, b);
        out.assume_init()
    }
}

#[inline(always)]
fn fp_sqr(a: &blst_fp) -> blst_fp {
    let mut out = MaybeUninit::<blst_fp>::uninit();
    // SAFETY: the operand is a valid blst_fp value and blst_fp_sqr writes the
    // whole result before returning.
    unsafe {
        blst_fp_sqr(out.as_mut_ptr(), a);
        out.assume_init()
    }
}

/// Number of exactly uniform trits carried by one accepted word.
///
/// `3^20 < 2^32 <= 3^21`, so twenty is the most a `u32` can hold.
const TRITS_PER_WORD: u32 = 20;

/// `3^TRITS_PER_WORD`: the rejection bound for one drawn word.
const TRIT_WORD_BOUND: u32 = 3u32.pow(TRITS_PER_WORD);

/// A stream of uniform coefficient vectors over a cryptographic RNG.
///
/// Each accepted word below `3^20` yields twenty independent uniform trits (its
/// base-3 digits); words at or above the bound are rejected so the trits stay
/// exactly uniform. A vector of `m` trits is the word's residue modulo `3^m`,
/// and the quotient stays uniform over the remaining digits, so one word serves
/// `floor(20 / m)` vectors. Words are drawn in bulk to amortize RNG calls.
///
/// Exact uniformity is load-bearing: the soundness bound leaves a fraction of
/// a bit of margin over the security target, and the bias of a `byte % 3`
/// shortcut (max probability `86/256`) compounds across every coefficient,
/// dropping the total below it.
struct Trits<'a, R: CryptoRng> {
    rng: &'a mut R,
    buffer: [u8; 1024],
    filled: usize,
    position: usize,
}

impl<'a, R: CryptoRng> Trits<'a, R> {
    const fn new(rng: &'a mut R) -> Self {
        Self {
            rng,
            buffer: [0u8; 1024],
            filled: 0,
            position: 0,
        }
    }

    /// Draw `count` uniform bucket ids in `[0, 3^m)`.
    ///
    /// The width is dispatched once for the whole run rather than per id, so
    /// the inner loop divides by a literal and the compiler turns each division
    /// into a multiply and a shift. Trits left over from a word are dropped
    /// when the run ends; they are only ever a fraction of one draw.
    fn fill(&mut self, m: u32, count: usize) -> Vec<u32> {
        debug_assert!((1..=MAX_WIDTH).contains(&m));
        let mut ids = Vec::with_capacity(count);
        macro_rules! draw {
            ($modulus:literal, $per_word:literal) => {{
                while ids.len() < count {
                    let mut word = self.next_word();
                    for _ in 0..$per_word {
                        if ids.len() == count {
                            break;
                        }
                        ids.push(word % $modulus);
                        word /= $modulus;
                    }
                }
            }};
        }
        match m {
            1 => draw!(3, 20),
            2 => draw!(9, 10),
            3 => draw!(27, 6),
            4 => draw!(81, 5),
            5 => draw!(243, 4),
            6 => draw!(729, 3),
            7 => draw!(2187, 2),
            8 => draw!(6561, 2),
            9 => draw!(19683, 2),
            10 => draw!(59049, 2),
            11 => draw!(177147, 1),
            _ => unreachable!("width is at most MAX_WIDTH"),
        }
        ids
    }

    /// Return the next word strictly below `3^20`, refilling the buffer as
    /// needed.
    fn next_word(&mut self) -> u32 {
        loop {
            if self.position == self.filled {
                self.rng.fill_bytes(&mut self.buffer);
                self.filled = self.buffer.len();
                self.position = 0;
            }
            let word = u32::from_le_bytes(
                self.buffer[self.position..self.position + 4]
                    .try_into()
                    .expect("four bytes"),
            );
            self.position += 4;
            if word < TRIT_WORD_BOUND {
                return word;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::{G1, Scalar};
    use commonware_codec::{Encode, FixedSize};
    use commonware_math::algebra::{Additive, CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    /// Standard soundness target for the tests.
    const SECURITY: usize = 128;

    /// A batch size comfortably above the per-point fallback threshold, so the
    /// batched path is exercised.
    const LARGE: usize = 1000;

    /// Whether an affine point is the point at infinity.
    fn affine_is_inf(p: &blst_p1_affine) -> bool {
        // SAFETY: p is a valid blst_p1_affine.
        unsafe { blst::blst_p1_affine_is_inf(p) }
    }

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

    /// Drop identity points exactly as [`batch_in_g1`] does, keeping the ids
    /// aligned with the points that survive.
    fn affine_with_ids(points: &[G1], ids: &[u32]) -> (Vec<blst_p1_affine>, Vec<u32>) {
        let kept: Vec<u32> = points
            .iter()
            .zip(ids)
            .filter(|(point, _)| !fp_is_zero(&point.as_blst_p1().z))
            .map(|(_, &id)| id)
            .collect();
        (to_affine(points), kept)
    }

    /// Run the accumulator and return each bucket's sum, with `None` for the
    /// buckets that sum to the identity.
    fn bucket_sums(points: &[G1], ids: &[u32], m: u32) -> Vec<Option<blst_p1_affine>> {
        let (affine, affine_ids) = affine_with_ids(points, ids);
        let mut round = Round::new(m);
        round.widen(m);
        round.accumulate(&affine, &affine_ids);
        (0..3usize.pow(m))
            .map(|bucket| round.live[bucket].then_some(round.sums[bucket]))
            .collect()
    }

    /// Assert that the accumulator agrees with naive per-bucket G1 addition.
    fn assert_sums_match(points: &[G1], ids: &[u32], m: u32) {
        let sums = bucket_sums(points, ids, m);
        assert_eq!(sums.len(), 3usize.pow(m));
        for (bucket, got) in sums.iter().enumerate() {
            let mut expected = G1::zero();
            for (point, &id) in points.iter().zip(ids) {
                if id as usize == bucket {
                    expected += point;
                }
            }
            let expected = G1::batch_to_affine(&[expected]);
            let expected = (!affine_is_inf(&expected[0])).then_some(expected[0]);
            match (got, expected) {
                (None, None) => {}
                (Some(got), Some(expected)) => {
                    assert_eq!(got.x.l, expected.x.l, "bucket {bucket} x mismatch");
                    assert_eq!(got.y.l, expected.y.l, "bucket {bucket} y mismatch");
                }
                _ => panic!("bucket {bucket} identity mismatch"),
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
            for n in [0usize, 1, 50, 130, 200, 1000, 6000, 100_000, 2_000_000] {
                let Some(widths) = plan(n, combinations) else {
                    continue;
                };
                for &m in &widths {
                    assert!((1..=MAX_WIDTH).contains(&m));
                    assert!(3usize.pow(m) <= 4 * n.max(1));
                    assert!(3usize.pow(m) * size_of::<blst_p1_affine>() <= SLOT_BUDGET);
                }
                // Every plan must cover the required number of combinations,
                // and must not waste more than one on rounding.
                let total: usize = widths.iter().map(|&m| m as usize).sum();
                assert!(total >= combinations, "n={n} s={security}");
                assert!(
                    total < combinations + widths.len(),
                    "n={n} s={security} wastes combinations"
                );
            }
        }
        // Small batches fall back to per-point checking; large ones batch.
        assert!(plan(1, 81).is_none());
        assert!(plan(50, 81).is_none());
        assert!(plan(6000, 81).is_some());
        // A zero soundness target needs no rounds at all.
        assert_eq!(plan(6000, 0), Some(Vec::new()));
        // Wider rounds, and so fewer of them, pay off as the batch grows, until
        // the slot budget stops the widening.
        let rounds = |n| plan(n, 81).map(|widths| widths.len());
        assert!(rounds(1000) > rounds(100_000));
        assert_eq!(rounds(100_000), rounds(2_000_000));
        let widest = |n| plan(n, 81).and_then(|widths| widths.into_iter().max());
        assert!(widest(1000) < widest(100_000));
        assert_eq!(widest(2_000_000), widest(100_000));
        let budgeted = widest(2_000_000).expect("batched");
        assert!(3usize.pow(budgeted) * size_of::<blst_p1_affine>() <= SLOT_BUDGET);
        assert!(3usize.pow(budgeted + 1) * size_of::<blst_p1_affine>() > SLOT_BUDGET);
    }

    #[test]
    fn bucket_ids_are_in_range() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        for m in 1..=MAX_WIDTH {
            assert!(trits.fill(m, 1000).into_iter().all(|id| id < 3u32.pow(m)));
        }
    }

    #[test]
    fn bucket_ids_are_roughly_uniform() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        let mut counts = [0usize; 9];
        for id in trits.fill(2, 9000) {
            counts[id as usize] += 1;
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
        // Good points are spread arbitrarily; their in-subgroup parts cannot
        // mask a cofactor part in any combination.
        let mut ids: Vec<u32> = (0..points.len()).map(|i| (i % 243) as u32).collect();
        let mut round = Round::new(M);
        // Vector 0 assigns the bad point coefficient 0 in every combination,
        // so the round must accept.
        ids[bad_index] = 0;
        let (affine, affine_ids) = affine_with_ids(&points, &ids);
        assert!(round.run(&affine, &affine_ids, M));
        // Any nonzero vector leaves a nonzero digit in some combination, which
        // must reject: 3^j isolates digit j with value 1; 2 and 162 = 2 * 3^4
        // cover value 2 at the lowest and highest positions.
        for v in [1u32, 2, 3, 9, 27, 81, 162] {
            ids[bad_index] = v;
            let (affine, affine_ids) = affine_with_ids(&points, &ids);
            assert!(
                !round.run(&affine, &affine_ids, M),
                "bad point at bucket {v} escaped"
            );
        }
    }

    #[test]
    fn field_helpers_match_blst() {
        use blst::{blst_fp_add, blst_fp_sub};
        let mut rng = test_rng();
        // Coordinates of random curve points are reduced field elements
        // covering the whole range, and the modulus-boundary cases are added
        // explicitly.
        let points: Vec<G1> = (0..64).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        let mut values: Vec<blst_fp> = affine.iter().flat_map(|p| [p.x, p.y]).collect();
        values.push(blst_fp { l: [0u64; 6] });
        let mut largest = MODULUS;
        largest[0] -= 1;
        values.push(blst_fp { l: largest });
        values.push(blst_fp {
            l: [1, 0, 0, 0, 0, 0],
        });
        for a in &values {
            for b in &values {
                let mut expected = blst_fp::default();
                // SAFETY: all pointers reference valid blst_fp values.
                unsafe { blst_fp_add(&mut expected, a, b) };
                assert_eq!(fp_add(a, b).l, expected.l, "add");
                // SAFETY: all pointers reference valid blst_fp values.
                unsafe { blst_fp_sub(&mut expected, a, b) };
                assert_eq!(fp_sub(a, b).l, expected.l, "sub");
                assert_eq!(fp_eq(a, b), a.l == b.l, "eq");
            }
            assert_eq!(fp_is_zero(a), a.l == [0u64; 6], "zero");
        }
    }

    #[test]
    fn montgomery_one_is_one() {
        use blst::blst_fp_from_uint64;
        let mut one = blst_fp::default();
        // SAFETY: both pointers reference valid, correctly sized values.
        unsafe { blst_fp_from_uint64(&mut one, [1u64, 0, 0, 0, 0, 0].as_ptr()) };
        assert_eq!(one.l, MONTGOMERY_ONE.l);
        assert!(fp_is_one(&one));
        assert!(!fp_is_one(&blst_fp::default()));
        // A decoded point is normalized, so the conversion's fast path applies.
        let mut rng = test_rng();
        let point = in_subgroup_point(&mut rng);
        let bytes = point.encode();
        let decoded = G1::read_unchecked(&mut bytes.as_ref()).expect("decodes");
        assert!(fp_is_one(&decoded.as_blst_p1().z));
    }

    #[test]
    fn to_affine_matches_blst() {
        let mut rng = test_rng();
        let mut points: Vec<G1> = (0..33).map(|_| in_subgroup_point(&mut rng)).collect();
        // Identities are dropped, wherever they sit.
        points[0] = G1::zero();
        points[17] = G1::zero();
        points.push(G1::zero());
        let expected: Vec<blst_p1_affine> = G1::batch_to_affine(&points)
            .into_iter()
            .filter(|point| !affine_is_inf(point))
            .collect();
        let got = to_affine(&points);
        assert_eq!(got.len(), expected.len());
        for (got, expected) in got.iter().zip(&expected) {
            assert_eq!(got.x.l, expected.x.l);
            assert_eq!(got.y.l, expected.y.l);
        }
        // An all-identity batch converts to nothing.
        assert!(to_affine(&[G1::zero()]).is_empty());
        assert!(to_affine(&[]).is_empty());
    }

    #[test]
    fn batch_invert_matches_single() {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..17).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        let mut prefix = Vec::new();
        for take in [0usize, 1, 2, 17] {
            let original: Vec<blst_fp> = affine.iter().take(take).map(|p| p.x).collect();
            let mut inverted = original.clone();
            batch_invert(&mut inverted, &mut prefix);
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
    fn accumulator_handles_special_pairs() {
        let mut rng = test_rng();
        let p = in_subgroup_point(&mut rng);
        let q = off_subgroup_point(&mut rng);
        let cases: Vec<(Vec<G1>, Vec<u32>, u32)> = vec![
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
            (vec![p], vec![1], 1),
            // A doubling chain that spans several passes.
            (vec![p; 9], vec![2; 9], 2),
        ];
        for (points, ids, m) in cases {
            assert_sums_match(&points, &ids, m);
        }
    }

    #[test]
    fn accumulator_matches_naive() {
        let mut rng = test_rng();
        for round in 0..24usize {
            let n = 1 + (round * 37) % 150;
            let m = 1 + (round % 5) as u32;
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
            let ids = Trits::new(&mut rng).fill(m, n);
            assert_sums_match(&points, &ids, m);
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
    fn identity_padding_does_not_hide_a_bad_point() {
        let mut rng = test_rng();
        let mut points = vec![G1::zero(); LARGE];
        points[LARGE / 2] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
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
    fn wide_rounds_agree_with_per_point() {
        // A batch large enough for the cost model to pick a wide round, so the
        // collapse chain runs at full depth.
        let mut rng = test_rng();
        let n = 20_000;
        let widths = plan(n, 81).expect("batched");
        assert!(widths[0] >= 7, "expected a wide plan, got {widths:?}");
        let mut points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        points[n - 1] = off_subgroup_point(&mut rng);
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

    /// Cost of the pieces of one batch-affine addition. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_addition -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_addition() {
        use std::time::Instant;
        let mut rng = test_rng();
        let n = 8192;
        let points: Vec<G1> = (0..2 * n).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        let originals: Vec<blst_fp> = (0..n)
            .map(|i| fp_sub(&affine[2 * i + 1].x, &affine[2 * i].x))
            .collect();
        let mut prefix = Vec::new();

        // Raw field-op throughput, over arrays rather than a dependency chain.
        let mut out = vec![blst_fp::default(); n];
        let reps = 200;
        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..n {
                out[i] = fp_mul(&affine[i].x, &affine[i].y);
            }
            std::hint::black_box(&out);
        }
        println!(
            "fp_mul  array {:.1} ns",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        );
        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..n {
                out[i] = fp_sub(&affine[i].x, &affine[i].y);
            }
            std::hint::black_box(&out);
        }
        println!(
            "fp_sub  array {:.1} ns",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        );

        for size in [128usize, 256, 512, 1024, 2048, 8192] {
            let mut values = originals[..size].to_vec();
            let reps = 400_000 / size;
            let start = Instant::now();
            for _ in 0..reps {
                values.copy_from_slice(&originals[..size]);
                batch_invert(&mut values, &mut prefix);
                std::hint::black_box(&values);
            }
            let invert = start.elapsed().as_nanos() as f64 / (reps * size) as f64;
            println!("batch_invert size={size:>5} {invert:.1} ns/element");
        }

        let mut values = originals;
        batch_invert(&mut values, &mut prefix);
        let mut out = vec![blst_p1_affine::default(); n];
        let reps = 200;
        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..n {
                out[i] = chord(&affine[2 * i], &affine[2 * i + 1], &values[i], false);
            }
            std::hint::black_box(&out);
        }
        let chord_cost = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
        println!("chord         {chord_cost:.1} ns/addition");
    }

    /// Where a large batch's time goes, phase by phase. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_phases -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_phases() {
        use std::time::Instant;
        let mut rng = test_rng();
        let n = 1_000_000usize;
        let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
        for pass in 0..2 {
            let total = Instant::now();
            let start = Instant::now();
            let affine = to_affine(&points);
            let converted = start.elapsed();
            let start = Instant::now();
            std::hint::black_box(G1::batch_to_affine(&points));
            let blst_converted = start.elapsed();
            let start = Instant::now();
            let widths = plan(n, 81).expect("batched");
            let mut trits = Trits::new(&mut rng);
            let id_sets: Vec<(u32, Vec<u32>)> = widths
                .iter()
                .map(|&m| (m, trits.fill(m, affine.len())))
                .collect();
            let sampled = start.elapsed();
            let start = Instant::now();
            let mut round = Round::new(*widths.iter().max().expect("nonempty"));
            let allocated = start.elapsed();
            let start = Instant::now();
            let ok = id_sets.iter().all(|(m, ids)| round.run(&affine, ids, *m));
            let rounds = start.elapsed();
            assert!(ok);
            println!(
                "pass={pass} to_affine={converted:?} (blst {blst_converted:?}) \
                 sampling={sampled:?} alloc={allocated:?} rounds={rounds:?} total={:?}",
                total.elapsed()
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
        for n in [1000usize, 6000, 100_000, 1_000_000] {
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            let passes = if n > 500_000 { 3 } else { 20 };
            let start = Instant::now();
            for _ in 0..passes {
                std::hint::black_box(G1::batch_to_affine(&points));
            }
            println!(
                "n={n} batch_to_affine={:.0} ns/point",
                start.elapsed().as_nanos() as f64 / (passes * n) as f64
            );
            let affine = G1::batch_to_affine(&points);
            for m in [6u32, 7, 8, 9] {
                let ids = Trits::new(&mut rng).fill(m, n);
                if 3usize.pow(m) > 4 * n {
                    continue;
                }
                let mut round = Round::new(m);
                round.widen(m);
                let reps = if n > 500_000 { 3 } else { 20 };
                let start = Instant::now();
                for _ in 0..reps {
                    round.accumulate(&affine, &ids);
                    std::hint::black_box(&round.sums[0]);
                }
                let accumulate = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
                let start = Instant::now();
                for _ in 0..reps {
                    std::hint::black_box(round.run(&affine, &ids, m));
                }
                let full = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
                println!(
                    "n={n} m={m} accumulate={accumulate:.0} ns/point round={full:.0} ns/point"
                );
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
        use std::{thread::available_parallelism, time::Duration, time::Instant};

        /// Best of three, which on a shared machine is the estimate least
        /// contaminated by whatever else is running.
        fn best(mut run: impl FnMut() -> Duration) -> Duration {
            (0..3).map(|_| run()).min().expect("three runs")
        }

        let threads = available_parallelism().unwrap();
        let rayon = Rayon::new(threads).unwrap();
        println!("threads = {threads}");
        for n in [200usize, 1000, 6000, 100_000, 300_000, 1_000_000, 3_000_000] {
            let mut rng = test_rng();
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            let widths = plan(n, combinations_for_security(128)).unwrap_or_default();
            let mut distinct = widths.clone();
            distinct.dedup();
            println!("n={n} rounds={} widths={distinct:?}", widths.len());

            // The per-point cost is exactly linear in n, so a bounded prefix
            // measures it without spending a minute on the baseline alone.
            let sample = n.min(20_000);
            let per_point = best(|| {
                let start = Instant::now();
                assert!(points[..sample].iter().all(G1::in_subgroup));
                start.elapsed()
            })
            .mul_f64(n as f64 / sample as f64);
            println!("n={n} per_point_serial = {per_point:?}");
            let serial = best(|| {
                let start = Instant::now();
                assert!(batch_in_g1(&points, 128, &Sequential, &mut test_rng()));
                start.elapsed()
            });
            println!(
                "n={n} batch_serial    = {serial:?} ({:.1}x)",
                per_point.as_secs_f64() / serial.as_secs_f64()
            );
            let parallel = best(|| {
                let start = Instant::now();
                assert!(batch_in_g1(&points, 128, &rayon, &mut test_rng()));
                start.elapsed()
            });
            println!(
                "n={n} batch_parallel  = {parallel:?} ({:.1}x)",
                per_point.as_secs_f64() / parallel.as_secs_f64()
            );
        }
    }

    /// Compare the shipping scheme (C) against the two alternatives from
    /// `cryptography/BATCHED_SUBGROUP.md`, all on the same accumulation engine:
    /// A is one combination per round (m = 1, 81 rounds); B is random bucketing
    /// with every bucket sum exact-checked (shared-inversion steelman). Run
    /// with: `cargo test -p commonware-cryptography --release --features
    /// bls12381 subgroup::tests::measure_strategies -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_strategies() {
        use blst::blst_p1_affine_in_g1;
        use commonware_parallel::Rayon;
        use std::{thread::available_parallelism, time::Instant};

        /// Strategy A/C with a forced width and round count.
        ///
        /// At `m = 1` this is not a fair rendering of A: three buckets leave at
        /// most three additions in flight, so the shared inversion has nothing
        /// to amortize over and the engine is the wrong one for the strategy. A
        /// real A would accumulate in Jacobian coordinates (as blst's MSM
        /// does); its cost is 81 passes over the points either way.
        fn forced(
            points: &[G1],
            m: u32,
            rounds: usize,
            strategy: &impl Strategy,
            rng: &mut impl CryptoRng,
        ) -> bool {
            let affine = G1::batch_to_affine(points);
            let mut trits = Trits::new(rng);
            let id_sets: Vec<Vec<u32>> = (0..rounds)
                .map(|_| trits.fill(m, affine.len()))
                .collect();
            strategy
                .map_init_collect_vec_with_multiplier(
                    id_sets.iter(),
                    affine.len(),
                    || Round::new(m),
                    |round, ids| round.run(&affine, ids, m),
                )
                .into_iter()
                .all(|in_subgroup| in_subgroup)
        }

        /// Strategy B: `3^m` buckets, every bucket sum exact-checked.
        fn bucketed(
            points: &[G1],
            m: u32,
            rounds: usize,
            strategy: &impl Strategy,
            rng: &mut impl CryptoRng,
        ) -> bool {
            let affine = G1::batch_to_affine(points);
            let mut trits = Trits::new(rng);
            let id_sets: Vec<Vec<u32>> = (0..rounds)
                .map(|_| trits.fill(m, affine.len()))
                .collect();
            strategy
                .map_init_collect_vec_with_multiplier(
                    id_sets.iter(),
                    affine.len(),
                    || Round::new(m),
                    |round, ids| {
                        round.widen(m);
                        round.accumulate(&affine, ids);
                        (0..3usize.pow(m)).all(|bucket| {
                            // SAFETY: the slot holds a valid affine point.
                            !round.live[bucket] || unsafe {
                                blst_p1_affine_in_g1(&round.sums[bucket])
                            }
                        })
                    },
                )
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
            // B: buckets with per-bucket checks, rounds = ceil(81 / m).
            for m in [2u32, 4, 6] {
                let rounds = 81usize.div_ceil(m as usize);
                let start = Instant::now();
                assert!(bucketed(&points, m, rounds, &Sequential, &mut test_rng()));
                println!(
                    "n={n} B B={:>5} r={rounds}   serial = {:?}",
                    3usize.pow(m),
                    start.elapsed()
                );
                let start = Instant::now();
                assert!(bucketed(&points, m, rounds, &rayon, &mut test_rng()));
                println!(
                    "n={n} B B={:>5} r={rounds} parallel = {:?}",
                    3usize.pow(m),
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
