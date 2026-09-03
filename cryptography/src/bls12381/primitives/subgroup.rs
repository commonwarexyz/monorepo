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
//! coefficient `c_{j,i}` in `{-1, 0, 1}` for every combination `j < m` and
//! every point `i`, and applies the exact per-point test [`G1::in_subgroup`] to
//! the `m` points `Q_j = sum_i c_{j,i} P_i`. The batch is accepted if every
//! combination in every round lies in G1.
//!
//! Rather than computing each `Q_j` separately, a round groups the points by
//! their coefficient *vector* `(c_{0,i}, ..., c_{m-1,i})`, sums each group
//! once, and recovers every combination from the group sums:
//! `Q_j = sum_{v: v_j=1} S_v - sum_{v: v_j=-1} S_v`, where `v_j` is the `j`-th
//! balanced-ternary digit of the vector `v`. The combine weights are the
//! *deterministic* digits of the vector — all randomness lives in the vector
//! assignment — so this evaluates exactly the `m` combinations above. (It is
//! not the unsound shortcut of re-randomizing over bucket sums, which would
//! collapse the `m` combinations back into one.)
//!
//! A vector and its negation are stored together: negating an affine point
//! costs nothing but the sign of its `y`, so a point whose vector is `-v` is
//! stored negated in `v`'s bucket, leaving `(3^m + 1) / 2` buckets rather than
//! `3^m`. Reading a bucket's index as a balanced-ternary *value* makes the
//! canonical vectors exactly the non-negative values, so the bucket is the
//! value's absolute value and the sign says whether the point enters negated.
//! Halving the buckets halves both the combine and the cache footprint of a
//! round, and the sign costs no arithmetic even in the accumulator: negating an
//! addition's second operand negates the chord's numerator, so taking its
//! denominator the other way round cancels the sign back out.
//!
//! Summing `n` points into many buckets costs the same `n` point additions as
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
//!   at a time would touch most of the bucket sums each, which caps `m` where
//!   the combine costs more than the accumulation it saves. Folding away one
//!   digit at a time instead yields every digit's marginal for about two
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
//! nonzero cofactor part `T` has order at least 3 — and odd, so never 2 —
//! making `-1*T`, `0*T` and `1*T` three distinct group elements: two of them
//! coinciding would need the order to divide their difference, one of `1` or
//! `2`. Pick any bad point (nonzero `T_i`) and condition on every other
//! coefficient of combination `j`: the combination vanishes only if
//! `c_{j,i} * T_i` hits one fixed value, and it takes three distinct values as
//! `c_{j,i}` ranges over `{-1, 0, 1}`, so at most one works —
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
//! `1/3` escape. Nor does folding weaken it — folding is a change of storage,
//! not of the coefficients drawn: a point stored negated in `v`'s bucket
//! contributes `d_j(v) * (-P)`, which is the `d_j(-v) * P` its own vector
//! calls for.
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
    blst_fp, blst_fp_inverse, blst_fp_mul, blst_fp_sqr, blst_p1, blst_p1_affine,
    blst_p1_from_affine, blst_p1_in_g1,
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
///
/// The scaling is done in `u128` and saturates upward, so an absurd target asks
/// for more combinations than any batch can afford — which falls back to
/// per-point checking — rather than silently asking for fewer.
const fn combinations_for_security(security: usize) -> usize {
    let scaled = (security as u128) * 1000;
    let combinations = scaled.div_ceil(LOG2_3_SCALED_LOWER_BOUND as u128);
    if combinations > usize::MAX as u128 {
        usize::MAX
    } else {
        combinations as usize
    }
}

/// Largest supported number of parallel combinations per round.
///
/// Set to where the sampler runs out rather than to a performance judgement,
/// so that [`SLOT_BUDGET`] is what decides the width: `3^13` is the largest
/// power of three a drawn `u32` word can carry, and one id per word is the
/// least the packing can do. [`SLOT_BUDGET`] binds well before this.
const MAX_WIDTH: u32 = 13;

/// Largest bucket-slot footprint a round should ask for, in bytes.
///
/// Points arrive in random bucket order, so the accumulator's working set is
/// the whole slot array, and a round's collapse workspace is half as large
/// again. A wider round needs fewer passes over the points, but its slots pay
/// for a deeper level of the memory hierarchy on every point, and its workspace
/// grows threefold per step, per thread.
///
/// Only two widths change the round count at 128-bit security, and this admits
/// both: width 11 gives `ceil(81/11) = 8` passes rather than nine, and width 12
/// gives seven. Measured here, the first is worth 9% at a million points and
/// the second 8% at three million — 19.3x to 20.8x against per-point checking.
/// Folding is what brings them inside a budget this size: width 12's slots are
/// 25 MB folded against 51 MB unfolded.
///
/// A wider round is not free, which is why the budget is not simply the largest
/// width the sampler supports. Each step triples the slot array the accumulator
/// touches at random, and triples the per-thread workspace with it, while the
/// combine it pays for grows as `3^m` against the single pass it saves. The
/// cost model weighs that per batch, so a smaller batch declines the width a
/// larger one takes: at a hundred thousand points it still plans nine rounds of
/// width nine, and only past a million does width 12 start to pay.
///
/// This is the constant most worth re-measuring on a new machine. It trades
/// against the last level of cache that holds the slot array, so a machine with
/// a smaller one wants it lower; the width it admits is a performance choice
/// only, and every width is equally sound.
const SLOT_BUDGET: usize = 32 << 20;

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

/// Number of independent chains the shared inversion is split into, which is
/// also how many additions are completed side by side.
///
/// A field multiplication's latency is well above its throughput, and both the
/// running product of Montgomery's trick and the three multiplications of an
/// addition are serial. Walking one chain would leave the core waiting on each
/// result before it could start the next; interleaving this many independent
/// chains keeps the multiplier busy. The chains cost a few extra
/// multiplications per chunk to split one inversion between them. Measured
/// flat from four upwards.
const LANES: usize = 4;

/// Flag stored in the high bit of a queued job's output slot, marking its
/// operands equal (a doubling rather than a chord).
const DOUBLE: u32 = 1 << 31;

/// Flag stored in a queued job's output slot, marking its second operand
/// subtracted rather than added.
const OP_NEGATE: u32 = 1 << 30;

/// The slot index of a queued job, with [`DOUBLE`] and [`OP_NEGATE`] masked off.
const SLOT_MASK: u32 = !(DOUBLE | OP_NEGATE);

/// Flag stored in the high bit of a drawn bucket id, marking the point stored
/// negated because its coefficient vector was folded onto the vector's negation.
const ID_NEGATE: u32 = 1 << 31;

/// Number of canonical buckets at width `m`.
///
/// Coefficient vectors are drawn from `{-1,0,1}^m` and a vector is stored
/// together with its negation (see [`Trits`]), so the `3^m` vectors occupy
/// `(3^m + 1) / 2` buckets: one per `{v, -v}` pair, plus the zero vector.
const fn folded(m: u32) -> usize {
    3usize.pow(m).div_ceil(2)
}

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
/// Summing `n` points into the round's buckets takes one addition per point
/// that is not the last one left in its bucket, and recovering the `m`
/// combinations takes about two additions per occupied bucket (one for the
/// collapse chain, one for the marginals it feeds). The `m` exact checks are
/// charged too, since they are what makes narrow rounds expensive on small
/// batches.
fn round_cost(n: usize, m: u32) -> usize {
    let buckets = folded(m);
    let occupied = expected_occupied(n, buckets);
    (n - occupied) + 2 * occupied + (m as usize) * CHECK_COST
}

/// Spread `combinations` over `rounds` rounds as evenly as possible.
///
/// The widths differ by at most one, so a round count that does not divide the
/// combinations wastes none of them — which matters, since the round count is
/// what the batch pays for.
fn spread(combinations: usize, rounds: usize) -> Vec<u32> {
    debug_assert!(combinations / rounds <= MAX_WIDTH as usize);
    let width = (combinations / rounds) as u32;
    let wide = combinations % rounds;
    (0..rounds)
        .map(|round| if round < wide { width + 1 } else { width })
        .collect()
}

/// Modeled cost of the plan that spreads `combinations` over `rounds` rounds,
/// or `None` if that spread needs a round wider than `widest`.
fn plan_cost(n: usize, combinations: usize, rounds: usize, widest: u32) -> Option<usize> {
    // Compared before narrowing, so a round count far too small to be usable is
    // rejected rather than wrapping into a plausible-looking width.
    let width = combinations / rounds;
    let wide = combinations % rounds;
    if width + usize::from(wide > 0) > widest as usize {
        return None;
    }
    let width = width as u32;
    Some(
        wide.saturating_mul(round_cost(n, width + 1))
            .saturating_add((rounds - wide).saturating_mul(round_cost(n, width))),
    )
}

/// Plan the rounds: one width per round, together covering `combinations`.
///
/// Returns `None` if checking each point individually is cheaper.
///
/// Only a couple of round counts per width can be worth considering. Round
/// counts sharing a base width form a contiguous band, and within a band the
/// modeled cost is linear in the round count, so an optimum always sits at a
/// band's edge — which keeps the search proportional to the widths available
/// rather than to the combinations required, and so bounded whatever soundness
/// target a caller asks for.
///
/// Soundness holds for every plan (a round of width `m` has error `3^-m`, and
/// the widths sum to `combinations`), so the cost model's constants only affect
/// performance.
fn plan(n: usize, combinations: usize) -> Option<Vec<u32>> {
    if combinations == 0 {
        return Some(Vec::new());
    }
    // A width is only usable if its buckets are neither hopelessly sparse nor
    // too many to keep close to the CPU.
    let mut widest = 0u32;
    while widest < MAX_WIDTH
        && folded(widest + 1) <= 4 * n.max(1)
        && folded(widest + 1) * size_of::<blst_p1_affine>() <= SLOT_BUDGET
    {
        widest += 1;
    }
    let mut best_cost = n.saturating_mul(CHECK_COST);
    let mut best = None;
    for width in 1..=widest as usize {
        // The round counts whose spread has base width `width`, which is where
        // the modeled cost is linear.
        let band = [combinations / (width + 1) + 1, combinations / width];
        for rounds in band {
            if rounds == 0 || rounds > combinations {
                continue;
            }
            let Some(cost) = plan_cost(n, combinations, rounds, widest) else {
                continue;
            };
            if cost < best_cost {
                best_cost = cost;
                best = Some(rounds);
            }
        }
    }
    best.map(|rounds| spread(combinations, rounds))
}

/// Verify that every point in `points` lies in the prime-order subgroup G1,
/// with a soundness error of at most `2^-security`.
///
/// The points must already be valid curve points (for example decoded with
/// [`G1::read_unchecked`]); this establishes only subgroup membership. An empty
/// slice is accepted.
///
/// A `security` of zero asks for no soundness at all — an error of `2^0` — and
/// accepts without examining the points; every positive target examines them.
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
    /// `folded(m-j)` entries: level 0 is the bucket sums themselves (and
    /// doubles as the accumulator's per-bucket slots), and level `j+1` is level
    /// `j` with its top remaining digit folded away.
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
    /// Entries still to be summed for each of the `m` marginals.
    marginals: Vec<Vec<u32>>,
}

impl Round {
    /// Allocate state able to run any round up to width `widest`.
    fn new(widest: u32) -> Self {
        debug_assert!((1..=MAX_WIDTH).contains(&widest));
        let total: usize = (1..=widest).map(folded).sum();
        Self {
            m: 0,
            levels: Vec::with_capacity(widest as usize),
            sums: vec![blst_p1_affine::default(); total],
            live: vec![false; total],
            state: vec![EMPTY; folded(widest)],
            lists: [Vec::new(), Vec::new()],
            ids: [Vec::new(), Vec::new()],
            pending: Pending::new(),
            marginals: (0..widest as usize).map(|_| Vec::new()).collect(),
        }
    }

    /// Lay out the collapse levels for a round of width `m`.
    fn widen(&mut self, m: u32) {
        debug_assert!((1..=MAX_WIDTH).contains(&m));
        debug_assert!(folded(m) <= self.state.len());
        if self.m == m {
            return;
        }
        self.m = m;
        self.pending.bound(folded(m));
        self.levels.clear();
        let mut total = 0usize;
        for j in 0..m {
            self.levels.push(total);
            total += folded(m - j);
        }
    }

    /// Sum `points` into the canonical buckets named by `ids`, leaving each
    /// bucket's sum in its slot at level 0 of [`Self::sums`].
    fn accumulate(&mut self, points: &[blst_p1_affine], ids: &[u32]) {
        self.state[..folded(self.m)].fill(EMPTY);
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
        let buckets = folded(self.m);
        for (live, &state) in self.live[..buckets].iter_mut().zip(&self.state[..buckets]) {
            *live = state != EMPTY;
        }
    }

    /// Run one round: sum the points into the canonical buckets keyed by
    /// coefficient vector, recover the `m` combinations from the bucket sums,
    /// and check each.
    fn run(&mut self, points: &[blst_p1_affine], ids: &[u32], m: u32) -> bool {
        self.widen(m);
        self.accumulate(points, ids);

        // Collapse chain: level `j+1` folds away level `j`'s top digit, so
        // every digit position's marginal comes out of one shared walk over the
        // bucket sums rather than one walk per combination.
        //
        // A canonical vector splits as `[d, u]` with `d` its top digit, which
        // is `0` or `+1` — never `-1`, since a leading `-1` is exactly what
        // folding negates away. Writing `S` for a level indexed by balanced
        // ternary value and `H = 3^(level digits - 1)`, the `d = +1` half
        // covers the full cube in `u`, so pairing `u` with `-u` there gives
        //
        //     L[a] = S[a] + S[H + a] - S[H - a]
        //
        // whose three terms are the canonical values of `[0, u]`, `[1, u]` and
        // `[1, -u]`. Index 0 is the all-zero vector: no marginal reads it, so
        // it is neither folded nor summed.
        for j in 0..(self.m as usize).saturating_sub(1) {
            let (source, target) = (self.levels[j], self.levels[j + 1]);
            let half = 3usize.pow(self.m - j as u32 - 1);
            for subtract in [false, true] {
                for a in 1..=(half - 1) / 2 {
                    let out = (target + a) as u32;
                    let (first, second) = if subtract {
                        (out, (source + half - a) as u32)
                    } else {
                        ((source + a) as u32, (source + half + a) as u32)
                    };
                    queue_add(
                        &mut self.sums,
                        &mut self.live,
                        &mut self.pending,
                        out,
                        first,
                        second,
                        subtract,
                    );
                }
                complete(&mut self.sums, &mut self.pending);
            }
        }

        // Combination `j` is the sum of the canonical buckets whose digit `j`
        // is `+1`, taken at the level where `j` is the top digit — the folding
        // already carried the `-1` side across, so there is nothing to subtract
        // and no weight-2 class to double. Those buckets are the values of
        // `[1, u]`, a contiguous range.
        for j in 0..self.m as usize {
            let level = self.levels[self.m as usize - 1 - j];
            let half = 3usize.pow(j as u32);
            let list = &mut self.marginals[j];
            list.clear();
            list.extend(
                (half.div_ceil(2)..=(3 * half - 1) / 2)
                    .map(|b| (level + b) as u32)
                    .filter(|&index| self.live[index as usize]),
            );
        }
        reduce(
            &mut self.sums,
            &mut self.live,
            &mut self.marginals[..self.m as usize],
            &mut self.pending,
        );

        for j in 0..self.m as usize {
            let mut combination = blst_p1::default();
            if let Some(&marginal) = self.marginals[j].first() {
                // SAFETY: the index names a live affine point, and blst_p1
                // defaults to the identity.
                unsafe { blst_p1_from_affine(&mut combination, &self.sums[marginal as usize]) };
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
            prefetch(slots, (ahead & !ID_NEGATE) as usize);
        }
        // A point whose vector folded onto its negation enters negated. The
        // negation is free everywhere but here: an affine point negates in its
        // y alone, and the addition formulas below absorb the sign by choosing
        // which way round to subtract.
        let negate = id & ID_NEGATE != 0;
        let bucket = (id & !ID_NEGATE) as usize;
        match state[bucket] {
            EMPTY => {
                state[bucket] = FILLED;
                slots[bucket] = if negate { neg_affine(point) } else { *point };
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
        let flag = if negate { OP_NEGATE } else { 0 };
        if fp_eq(&held.x, &point.x) {
            // Same x: on the curve y is determined up to sign, so this is
            // either P + (-P) = identity or a doubling.
            let two_y = if negate {
                fp_sub(&held.y, &point.y)
            } else {
                fp_add(&held.y, &point.y)
            };
            if fp_is_zero(&two_y) {
                // The sum cancels, and an empty slot is the identity.
                state[bucket] = EMPTY;
                continue;
            }
            // The operands are equal, so two_y = 2*y_held is the doubling
            // denominator. (y == 0 cannot occur: the group order h * r is odd,
            // so the curve has no 2-torsion.)
            pending.push(bucket as u32 | DOUBLE | flag, index as u32, two_y);
        } else {
            // Negating the operand negates the chord's numerator, so taking the
            // denominator the other way round cancels it back out and the sign
            // costs no arithmetic at all.
            let denominator = if negate {
                fp_sub(&held.x, &point.x)
            } else {
                fp_sub(&point.x, &held.x)
            };
            pending.push(bucket as u32 | flag, index as u32, denominator);
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
    let Some(mut running) = pending.chain_inverses() else {
        return;
    };
    let mut end = pending.jobs.len();
    while end > 0 {
        let start = end.saturating_sub(LANES);
        // The walk runs backwards, so the slot a job below will reopen is as
        // far off as the one the accumulation loop looks ahead for.
        for index in start..end {
            if let Some(&(ahead, _)) = pending.jobs.get(index.wrapping_sub(PREFETCH_DISTANCE)) {
                prefetch(slots, (ahead & SLOT_MASK) as usize);
            }
        }
        let inverses = pending.unwind(start, end, &mut running);
        finish(
            slots,
            &pending.jobs[start..end],
            &inverses[..end - start],
            Seconds::Points(src),
        );
        for &(slot, _) in &pending.jobs[start..end] {
            state[(slot & SLOT_MASK) as usize] = FILLED;
        }
        end = start;
    }
    pending.clear();
}

/// Queue `slots[out] = slots[first] +/- slots[second]`, subtracting when
/// `subtract` is set.
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
    subtract: bool,
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
        slots[out_index] = if subtract {
            neg_affine(&slots[second_index])
        } else {
            slots[second_index]
        };
        live[out_index] = true;
        return;
    }
    if out != first {
        slots[out_index] = slots[first_index];
    }
    live[out_index] = true;
    let flag = if subtract { OP_NEGATE } else { 0 };
    let (held, point) = (&slots[out_index], &slots[second_index]);
    if fp_eq(&held.x, &point.x) {
        let two_y = if subtract {
            fp_sub(&held.y, &point.y)
        } else {
            fp_add(&held.y, &point.y)
        };
        if fp_is_zero(&two_y) {
            live[out_index] = false;
            return;
        }
        pending.push(out | DOUBLE | flag, second, two_y);
    } else {
        let denominator = if subtract {
            fp_sub(&held.x, &point.x)
        } else {
            fp_sub(&point.x, &held.x)
        };
        pending.push(out | flag, second, denominator);
    }
    if pending.is_full() {
        complete(slots, pending);
    }
}

/// Finish the additions queued by [`queue_add`].
fn complete(slots: &mut [blst_p1_affine], pending: &mut Pending) {
    let Some(mut running) = pending.chain_inverses() else {
        return;
    };
    let mut end = pending.jobs.len();
    while end > 0 {
        let start = end.saturating_sub(LANES);
        for index in start..end {
            if let Some(&(ahead, _)) = pending.jobs.get(index.wrapping_sub(PREFETCH_DISTANCE)) {
                prefetch(slots, (ahead & SLOT_MASK) as usize);
            }
        }
        let inverses = pending.unwind(start, end, &mut running);
        finish(
            slots,
            &pending.jobs[start..end],
            &inverses[..end - start],
            Seconds::Slots,
        );
        end = start;
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
                queue_add(slots, live, pending, pair[0], pair[0], pair[1], false);
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
    /// Running products of the denominators along [`LANES`] interleaved
    /// chains (entry `i` continues entry `i - LANES`), walked back down as each
    /// addition takes its inverse.
    prefix: Vec<blst_fp>,
    /// How many additions to queue before sharing an inversion.
    limit: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            jobs: Vec::with_capacity(CHUNK),
            denominators: Vec::with_capacity(CHUNK),
            prefix: Vec::with_capacity(CHUNK),
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
    ///
    /// The running product the shared inversion needs is extended here rather
    /// than in a pass of its own, so the queue is written once and walked once:
    /// the multiplication rides along with work that is already touching the
    /// denominator.
    #[inline(always)]
    fn push(&mut self, slot: u32, second: u32, denominator: blst_fp) {
        let product = match self.prefix.len().checked_sub(LANES) {
            Some(previous) => fp_mul(&self.prefix[previous], &denominator),
            None => denominator,
        };
        self.prefix.push(product);
        self.jobs.push((slot, second));
        self.denominators.push(denominator);
    }

    /// Invert every chain's running product, or `None` when nothing is queued.
    ///
    /// One field inversion serves all the chains: their totals are multiplied
    /// together, the product inverted, and each chain's inverse recovered from
    /// that by Montgomery's trick once more, over [`LANES`] values.
    ///
    /// Every denominator MUST be nonzero (`blst_fp_inverse(0) == 0` would
    /// silently poison the shared product); the callers' classification
    /// guarantees it.
    fn chain_inverses(&self) -> Option<[blst_fp; LANES]> {
        let len = self.prefix.len();
        if len == 0 {
            return None;
        }
        // Chain `c` holds the indices congruent to `c` modulo LANES, so its
        // total is its last entry; chains past `len` are empty.
        let chains = len.min(LANES);
        let mut totals = [blst_fp::default(); LANES];
        for (chain, total) in totals[..chains].iter_mut().enumerate() {
            *total = self.prefix[len - 1 - (len - 1 - chain) % LANES];
        }
        let mut products = [blst_fp::default(); LANES];
        products[0] = totals[0];
        for chain in 1..chains {
            products[chain] = fp_mul(&products[chain - 1], &totals[chain]);
        }
        let mut running = blst_fp::default();
        // SAFETY: both pointers reference valid blst_fp values.
        unsafe { blst_fp_inverse(&mut running, &products[chains - 1]) };
        let mut inverses = [blst_fp::default(); LANES];
        for chain in (1..chains).rev() {
            inverses[chain] = fp_mul(&running, &products[chain - 1]);
            running = fp_mul(&running, &totals[chain]);
        }
        inverses[0] = running;
        Some(inverses)
    }

    /// Whether the queue has grown to a full inversion's worth of work.
    #[inline(always)]
    const fn is_full(&self) -> bool {
        self.jobs.len() >= self.limit
    }

    /// Return the inverses of the denominators of jobs `start..end` (at most
    /// [`LANES`] consecutive jobs, so each on a different chain), advancing
    /// each chain's `running` inverse to its next job down.
    ///
    /// The chains are independent, so the multiplications here overlap rather
    /// than wait on one another.
    #[inline(always)]
    fn unwind(&self, start: usize, end: usize, running: &mut [blst_fp; LANES]) -> [blst_fp; LANES] {
        debug_assert!(end - start <= LANES);
        let mut inverses = [blst_fp::default(); LANES];
        for (lane, index) in (start..end).enumerate() {
            let running = &mut running[index % LANES];
            inverses[lane] = index
                .checked_sub(LANES)
                .map_or(*running, |previous| fp_mul(running, &self.prefix[previous]));
        }
        for index in start..end {
            if index >= LANES {
                let running = &mut running[index % LANES];
                *running = fp_mul(running, &self.denominators[index]);
            }
        }
        inverses
    }

    fn clear(&mut self) {
        self.jobs.clear();
        self.denominators.clear();
        self.prefix.clear();
    }
}

/// Where a queued job's second operand lives.
#[derive(Clone, Copy)]
enum Seconds<'a> {
    /// In the batch being accumulated, at the job's second index.
    Points(&'a [blst_p1_affine]),
    /// In the slot array itself, at the job's second index.
    Slots,
}

/// Complete up to [`LANES`] queued additions (or doublings) side by side,
/// given the inverses of their denominators, writing each result over the slot
/// that held its first operand.
///
/// Chord/tangent formulas for curve coefficient `a = 0`:
/// `add: lambda = (y_b - y_a) / (x_b - x_a)`,
/// `double: lambda = 3 x_a^2 / (2 y_a)`,
/// `x_out = lambda^2 - x_a - x_b`, `y_out = lambda (x_a - x_out) - y_a`.
///
/// The three multiplications of one addition depend on each other; those of
/// different additions do not. Each step is taken for every job before the
/// next step for any, so consecutive multiplications are independent and the
/// core can overlap them. Every operand is read before any result is written,
/// which the callers' waves of disjoint outputs make sound.
#[inline(always)]
fn finish(
    slots: &mut [blst_p1_affine],
    jobs: &[(u32, u32)],
    inverses: &[blst_fp],
    seconds: Seconds<'_>,
) {
    let count = jobs.len();
    debug_assert!((1..=LANES).contains(&count) && inverses.len() == count);
    let mut results = [blst_p1_affine::default(); LANES];
    {
        let slots: &[blst_p1_affine] = slots;
        let placeholder = &slots[0];
        let mut firsts = [placeholder; LANES];
        let mut others = [placeholder; LANES];
        for (lane, &(slot, second)) in jobs.iter().enumerate() {
            firsts[lane] = &slots[(slot & SLOT_MASK) as usize];
            others[lane] = match seconds {
                Seconds::Points(points) => &points[second as usize],
                Seconds::Slots => &slots[second as usize],
            };
        }
        let mut lambdas = [blst_fp::default(); LANES];
        for (lane, &(slot, _)) in jobs.iter().enumerate() {
            let (first, second) = (firsts[lane], others[lane]);
            lambdas[lane] = if slot & DOUBLE != 0 {
                let square = fp_sqr(&first.x);
                fp_mul(&fp_add(&fp_add(&square, &square), &square), &inverses[lane])
            } else if slot & OP_NEGATE != 0 {
                // The second operand enters negated, which negates the
                // numerator; the caller took its denominator the other way
                // round, so the two signs cancel and the negation costs no
                // arithmetic at all. Only x is read below, and negation leaves
                // x alone.
                fp_mul(&fp_add(&second.y, &first.y), &inverses[lane])
            } else {
                fp_mul(&fp_sub(&second.y, &first.y), &inverses[lane])
            };
        }
        for lane in 0..count {
            let (first, second) = (firsts[lane], others[lane]);
            results[lane].x = fp_sub(&fp_sub(&fp_sqr(&lambdas[lane]), &first.x), &second.x);
        }
        for lane in 0..count {
            let first = firsts[lane];
            results[lane].y = fp_sub(
                &fp_mul(&lambdas[lane], &fp_sub(&first.x, &results[lane].x)),
                &first.y,
            );
        }
    }
    for (lane, &(slot, _)) in jobs.iter().enumerate() {
        slots[(slot & SLOT_MASK) as usize] = results[lane];
    }
}

/// Complete one affine addition (or doubling) given the inverse of its
/// denominator; the single-job form of [`finish`], for the measurements.
#[cfg(test)]
#[inline(always)]
fn chord(
    first: &blst_p1_affine,
    second: &blst_p1_affine,
    inverse: &blst_fp,
    double: bool,
    negate: bool,
) -> blst_p1_affine {
    let lambda = if double {
        let square = fp_sqr(&first.x);
        fp_mul(&fp_add(&fp_add(&square, &square), &square), inverse)
    } else if negate {
        // The second operand enters negated, which negates the numerator; the
        // caller took its denominator the other way round, so the two signs
        // cancel and the negation costs no arithmetic. Only x is read below,
        // and negation leaves x alone.
        fp_mul(&fp_add(&second.y, &first.y), inverse)
    } else {
        fp_mul(&fp_sub(&second.y, &first.y), inverse)
    };
    let x = fp_sub(&fp_sub(&fp_sqr(&lambda), &first.x), &second.x);
    let y = fp_sub(&fp_mul(&lambda, &fp_sub(&first.x, &x)), &first.y);
    blst_p1_affine { x, y }
}

/// Negate an affine point, which negates its `y` alone.
#[inline(always)]
fn neg_affine(point: &blst_p1_affine) -> blst_p1_affine {
    blst_p1_affine {
        x: point.x,
        y: fp_neg(&point.y),
    }
}

/// Negate a field element.
///
/// Zero is its own negation; every other value is `MODULUS - value`, which is
/// already reduced.
#[inline(always)]
fn fp_neg(a: &blst_fp) -> blst_fp {
    if fp_is_zero(a) {
        return *a;
    }
    let mut difference = [0u64; 6];
    let mut borrow = false;
    for (out, (modulus, limb)) in difference.iter_mut().zip(MODULUS.iter().zip(&a.l)) {
        let (value, first) = modulus.overflowing_sub(*limb);
        let (value, second) = value.overflowing_sub(borrow as u64);
        *out = value;
        borrow = first | second;
    }
    debug_assert!(!borrow, "a reduced element is at most MODULUS");
    blst_fp { l: difference }
}

/// Fill `prefix` with the running products of `values` and return the inverse
/// of their total, or `None` when there is nothing to invert.
///
/// This is the forward half of Montgomery's trick, for a caller holding its
/// values before it needs any inverse; [`Pending`] instead extends the same
/// running product as it queues, which is cheaper when the two coincide.
/// Either way the caller walks back down the prefix products itself, so that an
/// element's inverse is consumed where it is produced, and the two halves
/// together cost one field inversion plus three multiplications per element.
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
/// A point spans two cache lines, and the caller reads both. This is only a
/// hint, so a target without one is slower here, never wrong.
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
        let base = slots.as_ptr().wrapping_add(index);
        // SAFETY: `prfm` is architecturally a hint. It takes its address as an
        // addressing mode rather than dereferencing it, cannot fault whatever
        // the address, and changes nothing a program can observe apart from
        // the cache; the index is in range for the slice regardless. The
        // intrinsic wrapping this instruction is still unstable, so it is
        // written out; `readonly` matches the memory clobber the x86 arm's
        // intrinsic carries.
        unsafe {
            core::arch::asm!(
                "prfm pldl1keep, [{base}]",
                "prfm pldl1keep, [{base}, #64]",
                base = in(reg) base,
                options(nostack, preserves_flags, readonly),
            );
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

    /// Draw `count` uniform canonical bucket ids in `[0, (3^m+1)/2)`, each with
    /// [`ID_NEGATE`] set when its coefficient vector was folded onto its
    /// negation.
    ///
    /// A uniform residue in `[0, 3^m)` is a uniform balanced-ternary *value*
    /// once centred, and centring is the whole of the fold: a vector's value is
    /// positive exactly when its top nonzero digit is `+1`, so the canonical
    /// bucket is the absolute value and the sign says whether the point enters
    /// negated. The draw itself is unchanged, and so is its exact uniformity.
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
                const HALF: u32 = ($modulus - 1) / 2;
                while ids.len() < count {
                    let mut word = self.next_word();
                    for _ in 0..$per_word {
                        if ids.len() == count {
                            break;
                        }
                        let residue = word % $modulus;
                        word /= $modulus;
                        ids.push(if residue >= HALF {
                            residue - HALF
                        } else {
                            (HALF - residue) | ID_NEGATE
                        });
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
            12 => draw!(531441, 1),
            13 => draw!(1594323, 1),
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

    /// The `m` balanced-ternary digits of the coefficient vector a drawn id
    /// stands for, lowest digit first.
    ///
    /// An id is the absolute value of the vector's balanced-ternary value, with
    /// [`ID_NEGATE`] recording that the vector was folded onto its negation.
    fn signed_digits(id: u32, m: u32) -> Vec<i64> {
        let mut value = signed_value(id);
        (0..m)
            .map(|_| {
                let digit = match value.rem_euclid(3) {
                    2 => -1,
                    other => other,
                };
                value = (value - digit) / 3;
                digit
            })
            .collect()
    }

    /// The balanced-ternary value a drawn id stands for, sign included.
    fn signed_value(id: u32) -> i64 {
        let magnitude = i64::from(id & !ID_NEGATE);
        if id & ID_NEGATE != 0 {
            -magnitude
        } else {
            magnitude
        }
    }

    /// The point an id contributes to its bucket, negated when the id's vector
    /// was folded.
    fn folded_point(point: &G1, id: u32) -> G1 {
        if id & ID_NEGATE != 0 { -*point } else { *point }
    }

    /// Run the accumulator and return each bucket's sum, with `None` for the
    /// buckets that sum to the identity.
    fn bucket_sums(points: &[G1], ids: &[u32], m: u32) -> Vec<Option<blst_p1_affine>> {
        let (affine, affine_ids) = affine_with_ids(points, ids);
        let mut round = Round::new(m);
        round.widen(m);
        round.accumulate(&affine, &affine_ids);
        (0..folded(m))
            .map(|bucket| round.live[bucket].then_some(round.sums[bucket]))
            .collect()
    }

    /// Assert that the accumulator agrees with naive per-bucket G1 addition.
    fn assert_sums_match(points: &[G1], ids: &[u32], m: u32) {
        let sums = bucket_sums(points, ids, m);
        assert_eq!(sums.len(), folded(m));
        for (bucket, got) in sums.iter().enumerate() {
            let mut expected = G1::zero();
            for (point, &id) in points.iter().zip(ids) {
                if (id & !ID_NEGATE) as usize == bucket {
                    expected += &folded_point(point, id);
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
                    assert!(folded(m) <= 4 * n.max(1));
                    assert!(folded(m) * size_of::<blst_p1_affine>() <= SLOT_BUDGET);
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
        // Wider rounds, and so fewer of them, pay off as the batch grows: a
        // wider round spends more on its combine and saves it on every point,
        // so the crossover moves with n. Pinned as monotonicity rather than as
        // particular widths, which move with the slot budget.
        let rounds = |n| plan(n, 81).map(|widths| widths.len());
        assert!(rounds(1000) > rounds(100_000));
        assert!(rounds(100_000) >= rounds(2_000_000));
        let widest = |n| plan(n, 81).and_then(|widths| widths.into_iter().max());
        assert!(widest(1000) < widest(100_000));
        assert!(widest(100_000) <= widest(2_000_000));
        // Whatever the model picks, it stays inside the budget it is given, and
        // the budget rather than the width cap is what stops the widening.
        for n in [100_000usize, 2_000_000] {
            let budgeted = widest(n).expect("batched");
            assert!(folded(budgeted) * size_of::<blst_p1_affine>() <= SLOT_BUDGET);
        }
        let budgeted = widest(2_000_000).expect("batched");
        assert!(
            budgeted == MAX_WIDTH
                || folded(budgeted + 1) * size_of::<blst_p1_affine>() > SLOT_BUDGET
        );
    }

    #[test]
    fn plan_matches_exhaustive_search() {
        // The search only visits the edges of each base-width band, on the
        // argument that the modeled cost is linear inside one. Check that
        // against the exhaustive search it replaces.
        for combinations in [1usize, 2, 5, 37, 81, 128, 200] {
            for n in [0usize, 1, 7, 130, 200, 999, 1000, 6000, 20_000, 100_000, 400_000] {
                let mut widest = 0u32;
                while widest < MAX_WIDTH
                    && folded(widest + 1) <= 4 * n.max(1)
                    && folded(widest + 1) * size_of::<blst_p1_affine>() <= SLOT_BUDGET
                {
                    widest += 1;
                }
                let mut best = (n.saturating_mul(CHECK_COST), None);
                for rounds in 1..=combinations {
                    let Some(cost) = plan_cost(n, combinations, rounds, widest) else {
                        continue;
                    };
                    if cost < best.0 {
                        best = (cost, Some(rounds));
                    }
                }
                let exhaustive = best.1.map(|rounds| spread(combinations, rounds));
                let got = plan(n, combinations);
                // Equal cost is enough; ties may be broken differently.
                match (&got, &exhaustive) {
                    (None, None) => {}
                    (Some(got), Some(exhaustive)) => {
                        let cost = |widths: &[u32]| {
                            widths.iter().map(|&m| round_cost(n, m)).sum::<usize>()
                        };
                        assert_eq!(
                            cost(got),
                            cost(exhaustive),
                            "n={n} c={combinations}: {got:?} vs {exhaustive:?}"
                        );
                    }
                    _ => panic!("n={n} c={combinations}: {got:?} vs {exhaustive:?}"),
                }
            }
        }
    }

    #[test]
    fn plan_is_bounded_for_absurd_targets() {
        // `security` is a caller-supplied parameter with no upper bound, so the
        // search must not grow with it. These return promptly, and ask for
        // per-point checking rather than a plan that is short of the target.
        for security in [1_000_000usize, usize::MAX / 2, usize::MAX] {
            let combinations = combinations_for_security(security);
            assert!(combinations >= security / 2, "saturated downward");
            for n in [1000usize, 100_000] {
                assert_eq!(plan(n, combinations), None);
            }
        }
        // The scaling never rounds down below the target either.
        for security in [1usize, 40, 128, 1000, 100_000] {
            let combinations = combinations_for_security(security);
            assert!((combinations as f64) * 3f64.log2() >= security as f64);
        }
    }

    #[test]
    fn spread_is_even_and_complete() {
        for combinations in [1usize, 2, 7, 81, 128, 255] {
            // Too few rounds to carry the combinations at all is not a spread
            // this has to be even about: it is the precondition `spread`
            // asserts and `plan_cost` rejects before ever calling it.
            let fewest = combinations.div_ceil(MAX_WIDTH as usize).max(1);
            for rounds in fewest..=combinations {
                let widths = spread(combinations, rounds);
                assert!(widths.iter().all(|&m| m <= MAX_WIDTH));
                assert_eq!(widths.len(), rounds);
                // Every combination is placed, and none is wasted.
                assert_eq!(
                    widths.iter().map(|&m| m as usize).sum::<usize>(),
                    combinations
                );
                // Widths differ by at most one, widest first.
                let (&first, &last) = (
                    widths.first().expect("nonempty"),
                    widths.last().expect("nonempty"),
                );
                assert!(first - last <= 1);
                assert!(widths.windows(2).all(|pair| pair[0] >= pair[1]));
            }
        }
    }

    #[test]
    fn bucket_ids_are_in_range() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        for m in 1..=MAX_WIDTH {
            assert!(
                trits
                    .fill(m, 1000)
                    .into_iter()
                    .all(|id| ((id & !ID_NEGATE) as usize) < folded(m))
            );
        }
    }

    #[test]
    fn bucket_ids_are_roughly_uniform() {
        let mut rng = test_rng();
        let mut trits = Trits::new(&mut rng);
        // Folding is a bijection onto the signed values, so uniformity of the
        // ids is uniformity over the nine vectors of width two.
        let mut counts = [0usize; 9];
        for id in trits.fill(2, 9000) {
            counts[(signed_value(id) + 4) as usize] += 1;
        }
        // Expected 1000 per id; the window is ~6.7 standard deviations wide.
        for &count in &counts {
            assert!((800..1200).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn coefficients_are_uniform_and_independent() {
        // Exact uniformity of every coefficient is soundness-bearing, and the
        // sampler packs several ids into one drawn word, so a skew could hide in
        // one digit position or in the correlation between two of them rather
        // than in the ids overall. Windows below are ~6 standard deviations.
        const DRAWS: usize = 90_000;
        let mut rng = test_rng();
        for m in [5u32, 9, 10] {
            // Drawing in one call and in many small ones exercise different
            // word-boundary behaviour; both must be unbiased.
            for batch in [DRAWS, 7] {
                let mut trits = Trits::new(&mut rng);
                let mut ids = Vec::with_capacity(DRAWS);
                while ids.len() < DRAWS {
                    ids.extend(trits.fill(m, batch.min(DRAWS - ids.len())));
                }
                let mut digits = vec![[0usize; 3]; m as usize];
                let mut pairs = vec![[0usize; 9]; m as usize - 1];
                for id in ids {
                    assert!(((id & !ID_NEGATE) as usize) < folded(m));
                    let mut value = signed_value(id);
                    let mut previous = None;
                    for (position, counts) in digits.iter_mut().enumerate() {
                        // Balanced-ternary digits, shifted to index {0,1,2}.
                        let signed = match value.rem_euclid(3) {
                            2 => -1,
                            other => other,
                        };
                        value = (value - signed) / 3;
                        let digit = (signed + 1) as usize;
                        counts[digit] += 1;
                        if let Some(previous) = previous {
                            pairs[position - 1][previous * 3 + digit] += 1;
                        }
                        previous = Some(digit);
                    }
                }
                for (position, counts) in digits.iter().enumerate() {
                    let expected = DRAWS / 3;
                    let window = 6 * ((DRAWS * 2 / 9) as f64).sqrt() as usize;
                    for &count in counts {
                        assert!(
                            count.abs_diff(expected) < window,
                            "m={m} batch={batch} digit {position} skewed: {counts:?}"
                        );
                    }
                }
                for (position, counts) in pairs.iter().enumerate() {
                    let expected = DRAWS / 9;
                    let window = 6 * ((DRAWS * 8 / 81) as f64).sqrt() as usize;
                    for &count in counts {
                        assert!(
                            count.abs_diff(expected) < window,
                            "m={m} batch={batch} digits {position},{} correlated: {counts:?}",
                            position + 1
                        );
                    }
                }
            }
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
        let mut ids: Vec<u32> = (0..points.len())
            .map(|i| (i % folded(M)) as u32)
            .collect();
        let mut round = Round::new(M);
        // Vector 0 assigns the bad point coefficient 0 in every combination,
        // so the round must accept.
        ids[bad_index] = 0;
        let (affine, affine_ids) = affine_with_ids(&points, &ids);
        assert!(round.run(&affine, &affine_ids, M));
        // Any nonzero vector leaves a nonzero digit in some combination, which
        // must reject. A value of 3^j isolates digit j at +1, and the same
        // value folded isolates it at -1, so these cover both signs at the
        // lowest and highest positions as well as a two-digit vector.
        for v in [
            1u32,
            3,
            9,
            27,
            81,
            1 | ID_NEGATE,
            81 | ID_NEGATE,
            4,
            82 | ID_NEGATE,
        ] {
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

        // Decoded points are already normalized and take the fast path; mixing
        // them with projective ones must keep the shared inversion in step.
        let mixed: Vec<G1> = points
            .iter()
            .enumerate()
            .map(|(index, point)| {
                // The wire format has no infinity that decodes back, so the
                // identities in the batch stay as they are.
                if index % 3 == 0 && point != &G1::zero() {
                    G1::read_unchecked(&mut point.encode().as_ref()).expect("decodes")
                } else {
                    *point
                }
            })
            .collect();
        let expected: Vec<blst_p1_affine> = G1::batch_to_affine(&mixed)
            .into_iter()
            .filter(|point| !affine_is_inf(point))
            .collect();
        let got = to_affine(&mixed);
        assert_eq!(got.len(), expected.len());
        for (got, expected) in got.iter().zip(&expected) {
            assert_eq!(got.x.l, expected.x.l);
            assert_eq!(got.y.l, expected.y.l);
        }
    }

    #[test]
    fn decoded_points_are_accepted() {
        // The batch a caller actually has: points decoded from the wire, which
        // arrive normalized and so skip the affine conversion's inversion.
        let mut rng = test_rng();
        let mut points: Vec<G1> = (0..LARGE)
            .map(|_| {
                let point = in_subgroup_point(&mut rng);
                G1::read_unchecked(&mut point.encode().as_ref()).expect("decodes")
            })
            .collect();
        assert!(points.iter().all(|point| fp_is_one(&point.as_blst_p1().z)));
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        points[LARGE / 4] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
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


    /// Stress the accumulator where collisions dominate: few buckets, many
    /// points, and heavy duplication/cancellation.
    #[test]
    fn accumulator_stress_collisions() {
        let mut rng = test_rng();
        for &(n, m) in &[
            (3000usize, 1u32),
            (3000, 2),
            (5000, 3),
            (4000, 5),
            (1, 1),
            (2, 1),
        ] {
            // Pool of distinct points, reused heavily so doublings abound.
            let pool: Vec<G1> = (0..8).map(|_| in_subgroup_point(&mut rng)).collect();
            let bad: Vec<G1> = (0..3).map(|_| off_subgroup_point(&mut rng)).collect();
            let mut points: Vec<G1> = Vec::with_capacity(n);
            for i in 0..n {
                let point = match i % 11 {
                    0 => G1::zero(),
                    1 => pool[i % pool.len()],
                    2 => -pool[i % pool.len()],
                    3 => bad[i % bad.len()],
                    4 => -bad[i % bad.len()],
                    5 => pool[0],
                    6 => -pool[0],
                    _ => in_subgroup_point(&mut rng),
                };
                points.push(point);
            }
            let ids = Trits::new(&mut rng).fill(m, n);
            assert_sums_match(&points, &ids, m);
        }
    }

    /// All points land in one bucket, so every pass but the first is pure
    /// carry: the worst case for termination and for the doubling chain.
    #[test]
    fn accumulator_single_bucket() {
        let mut rng = test_rng();
        for &n in &[1usize, 2, 3, 7, 64, 1000, 3000] {
            for m in [1u32, 2, 5] {
                let p = in_subgroup_point(&mut rng);
                // Same point repeated: every addition after the first is a
                // doubling or a chord against a running multiple.
                let points = vec![p; n];
                let ids = vec![1u32; n];
                assert_sums_match(&points, &ids, m);
            }
        }
    }

    /// A wide round with enough points to fill whole inversion chunks, so the
    /// `is_full` flush path and the collapse chain both run at scale.
    #[test]
    fn accumulator_wide_round_chunks() {
        let mut rng = test_rng();
        for m in [4u32, 6, 7] {
            let n = 6 * 3usize.pow(m);
            let base: Vec<G1> = (0..64).map(|_| in_subgroup_point(&mut rng)).collect();
            let points: Vec<G1> = (0..n)
                .map(|i| match i % 5 {
                    0 => base[i % base.len()],
                    1 => -base[i % base.len()],
                    2 => G1::zero(),
                    _ => in_subgroup_point(&mut rng),
                })
                .collect();
            let ids = Trits::new(&mut rng).fill(m, n);
            assert_sums_match(&points, &ids, m);
        }
    }

    /// Reuse one `Round` across widths, as the strategy does, and check the
    /// combines still agree with a direct computation of each combination.
    #[test]
    fn combinations_match_direct() {
        let mut rng = test_rng();
        let widest = 4u32;
        let mut round = Round::new(widest);
        for m in [1u32, 3, 4, 2, 4, 1] {
            let n = 400usize;
            let points: Vec<G1> = (0..n)
                .map(|i| match i % 6 {
                    0 => G1::zero(),
                    1 => off_subgroup_point(&mut rng),
                    _ => in_subgroup_point(&mut rng),
                })
                .collect();
            let ids = Trits::new(&mut rng).fill(m, n);
            let (affine, affine_ids) = affine_with_ids(&points, &ids);
            // Direct per-combination computation over the surviving points.
            let mut expected_ok = true;
            for j in 0..m {
                let mut acc = G1::zero();
                for (point, &id) in points.iter().zip(&ids) {
                    match signed_digits(id, m)[j as usize] {
                        1 => acc += point,
                        -1 => acc += &-*point,
                        _ => {}
                    }
                }
                if !acc.in_subgroup() {
                    expected_ok = false;
                }
            }
            assert_eq!(
                round.run(&affine, &affine_ids, m),
                expected_ok,
                "m={m} mismatch"
            );
        }
    }

    /// Randomized differential fuzz: every combination's exact value against a
    /// direct computation, over adversarial id and point distributions.
    #[test]
    fn round_fuzz_against_direct() {
        use commonware_utils::TestRng;
        let mut round: Option<(u32, Round)> = None;
        for seed in 0..400u64 {
            let mut rng = TestRng::new(seed);
            let m = 1 + (seed % 9) as u32;
            let widest = 9u32;
            let n = match seed % 7 {
                0 => 1,
                1 => 2,
                2 => 17,
                3 => 300,
                4 => 3000,
                5 => 9000,
                _ => 1 + (seed as usize * 137) % 4000,
            };
            let pool: Vec<G1> = (0..4).map(|_| in_subgroup_point(&mut rng)).collect();
            let points: Vec<G1> = (0..n)
                .map(|i| match (i as u64 + seed) % 8 {
                    0 => G1::zero(),
                    1 => pool[i % pool.len()],
                    2 => -pool[i % pool.len()],
                    3 => pool[0],
                    4 => -pool[0],
                    _ => in_subgroup_point(&mut rng),
                })
                .collect();
            // Id distributions: uniform, all-equal, and a tiny support.
            let buckets = folded(m) as u32;
            let ids: Vec<u32> = match seed % 4 {
                0 => Trits::new(&mut rng).fill(m, n),
                // All points on one folded vector, half of them negated.
                1 => (0..n)
                    .map(|i| {
                        ((seed as u32) % buckets) | if i % 2 == 0 { ID_NEGATE } else { 0 }
                    })
                    .collect(),
                // A tiny support, so collisions and cancellations dominate.
                2 => (0..n)
                    .map(|i| ((i as u32) % buckets.min(3)) | ((i as u32 & 1) << 31))
                    .collect(),
                _ => Trits::new(&mut rng).fill(m, n),
            };
            let (affine, affine_ids) = affine_with_ids(&points, &ids);
            let round = &mut round.get_or_insert_with(|| (widest, Round::new(widest))).1;
            assert!(round.run(&affine, &affine_ids, m), "seed={seed} rejected");
            let kept: Vec<G1> = points.iter().copied().filter(|p| p != &G1::zero()).collect();
            assert_eq!(kept.len(), affine_ids.len());
            for j in 0..m {
                let mut expected = G1::zero();
                for (point, &id) in kept.iter().zip(&affine_ids) {
                    match signed_digits(id, m)[j as usize] {
                        1 => expected += point,
                        -1 => expected += &-*point,
                        _ => {}
                    }
                }
                // Rebuild the combination from the round's marginals exactly
                // as `run` does, so a wiring bug shows up as a value mismatch.
                let mut got = blst_p1::default();
                if let Some(&marginal) = round.marginals[j as usize].first() {
                    // SAFETY: the index names a live affine point, and blst_p1
                    // defaults to the identity.
                    unsafe { blst_p1_from_affine(&mut got, &round.sums[marginal as usize]) };
                }
                let mut got_affine = blst_p1_affine::default();
                // SAFETY: both pointers reference valid blst values.
                unsafe { blst::blst_p1_to_affine(&mut got_affine, &got) };
                let expected_affine = G1::batch_to_affine(&[expected])[0];
                assert_eq!(
                    affine_is_inf(&got_affine),
                    affine_is_inf(&expected_affine),
                    "seed={seed} m={m} n={n} j={j} identity mismatch"
                );
                if !affine_is_inf(&got_affine) {
                    assert_eq!(got_affine.x.l, expected_affine.x.l, "seed={seed} m={m} j={j}");
                    assert_eq!(got_affine.y.l, expected_affine.y.l, "seed={seed} m={m} j={j}");
                }
            }
        }
    }

    /// Chi-square-ish uniformity of drawn ids, per width and per position in
    /// the word that produced them.
    #[test]
    fn trit_ids_are_uniform_per_position() {
        let mut rng = test_rng();
        for m in 1..=MAX_WIDTH {
            let buckets = 3usize.pow(m);
            if buckets > 6561 {
                continue;
            }
            let per_word = (20 / m) as usize;
            let target = 400usize;
            let count = buckets * target;
            let ids = Trits::new(&mut rng).fill(m, count);
            let mut counts = vec![0usize; buckets];
            let mut per_pos = vec![vec![0usize; buckets]; per_word];
            // Uniformity is a property of the vector drawn, not of the bucket
            // it folds onto: two vectors share a bucket, so counting buckets
            // would pass even if the sign were biased.
            let centre = (buckets as i64 - 1) / 2;
            for (i, &id) in ids.iter().enumerate() {
                let vector = (signed_value(id) + centre) as usize;
                counts[vector] += 1;
                per_pos[i % per_word][vector] += 1;
            }
            let chi: f64 = counts
                .iter()
                .map(|&c| {
                    let d = c as f64 - target as f64;
                    d * d / target as f64
                })
                .sum();
            let df = (buckets - 1) as f64;
            assert!(chi < df + 8.0 * (2.0 * df).sqrt(), "m={m} chi={chi} df={df}");
            for (pos, counts) in per_pos.iter().enumerate() {
                let expect = count as f64 / per_word as f64 / buckets as f64;
                let chi: f64 = counts
                    .iter()
                    .map(|&c| {
                        let d = c as f64 - expect;
                        d * d / expect
                    })
                    .sum();
                assert!(
                    chi < df + 8.0 * (2.0 * df).sqrt(),
                    "m={m} pos={pos} chi={chi} df={df}"
                );
            }
        }
    }

    /// The widest plans the cost model can pick, checked bucket by bucket
    /// against a naive running sum.
    #[test]
    fn accumulate_large_widths_match_naive() {
        for seed in 0..3u64 {
            let mut rng = commonware_utils::TestRng::new(seed);
            for m in [8u32, 9] {
                let n = 5 * 3usize.pow(m);
                let pool: Vec<G1> = (0..16).map(|_| in_subgroup_point(&mut rng)).collect();
                let points: Vec<G1> = (0..n)
                    .map(|i| match i % 7 {
                        0 => G1::zero(),
                        1 => pool[i % pool.len()],
                        2 => -pool[i % pool.len()],
                        3 => pool[0],
                        _ => in_subgroup_point(&mut rng),
                    })
                    .collect();
                let ids = Trits::new(&mut rng).fill(m, n);
                // Naive: one running G1 sum per bucket, each point entering
                // negated when its vector folded onto its negation.
                let mut expected = vec![G1::zero(); folded(m)];
                for (point, &id) in points.iter().zip(&ids) {
                    expected[(id & !ID_NEGATE) as usize] += &folded_point(point, id);
                }
                let expected = G1::batch_to_affine(&expected);
                let (affine, affine_ids) = affine_with_ids(&points, &ids);
                let mut round = Round::new(m);
                round.widen(m);
                round.accumulate(&affine, &affine_ids);
                for (bucket, expected) in expected.iter().enumerate() {
                    let empty = affine_is_inf(expected);
                    assert_eq!(
                        round.live[bucket], !empty,
                        "seed={seed} m={m} bucket {bucket} liveness"
                    );
                    if !empty {
                        let got = round.sums[bucket];
                        assert_eq!(got.x.l, expected.x.l, "seed={seed} m={m} bucket {bucket} x");
                        assert_eq!(got.y.l, expected.y.l, "seed={seed} m={m} bucket {bucket} y");
                    }
                }
            }
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
        // A batch large enough for the cost model to pick its widest round, so
        // the collapse chain runs at full depth end to end. The points are
        // drawn from a small pool and cycled, both to keep the batch cheap to
        // build and because the duplicates stress the doubling path.
        let mut rng = test_rng();
        let n = 100_000;
        let widths = plan(n, 81).expect("batched");
        let widest = *widths.iter().max().expect("nonempty");
        // What matters here is that the plan is wide, so the collapse runs at
        // full depth — not which of the two limits stopped the widening, since
        // that moves with the slot budget.
        assert!(widest >= 8, "expected a wide plan, got {widths:?}");
        assert!(folded(widest) * size_of::<blst_p1_affine>() <= SLOT_BUDGET);
        let pool: Vec<G1> = (0..64).map(|_| in_subgroup_point(&mut rng)).collect();
        let mut points: Vec<G1> = (0..n).map(|i| pool[i % pool.len()]).collect();
        assert!(batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
        points[n - 1] = off_subgroup_point(&mut rng);
        assert!(!batch_in_g1(&points, SECURITY, &Sequential, &mut rng));
    }

    #[test]
    fn zero_security_accepts_without_checking() {
        // An error bound of 2^0 is no bound, so the check is entitled to accept
        // anything. Pin it, so the boundary is a decision rather than an
        // accident, and pin that the very next target does examine the points.
        let mut rng = test_rng();
        let bad: Vec<G1> = (0..LARGE).map(|_| off_subgroup_point(&mut rng)).collect();
        assert_eq!(combinations_for_security(0), 0);
        assert_eq!(plan(bad.len(), 0), Some(Vec::new()));
        assert!(batch_in_g1(&bad, 0, &Sequential, &mut rng));
        // One bit of soundness is still one round: rejection is then only
        // probable, so the certain part is that a round runs at all.
        assert_eq!(combinations_for_security(1), 1);
        assert_eq!(plan(bad.len(), 1).map(|widths| widths.len()), Some(1));
        assert!(!batch_in_g1(&bad, SECURITY, &Sequential, &mut rng));
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

    /// Latency vs throughput of the addition's pieces, and what interleaving
    /// independent additions buys. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_interleave -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_interleave() {
        use std::time::Instant;
        let mut rng = test_rng();
        let n = 8192;
        let points: Vec<G1> = (0..2 * n).map(|_| in_subgroup_point(&mut rng)).collect();
        let affine = G1::batch_to_affine(&points);
        let denominators: Vec<blst_fp> = (0..n)
            .map(|i| fp_sub(&affine[2 * i + 1].x, &affine[2 * i].x))
            .collect();

        // Dependent chain: latency of one multiplication.
        let reps = 2_000_000;
        let mut x = affine[0].x;
        let start = Instant::now();
        for _ in 0..reps {
            x = fp_mul(&x, &affine[1].x);
        }
        std::hint::black_box(&x);
        println!(
            "fp_mul dependent chain {:.1} ns",
            start.elapsed().as_nanos() as f64 / reps as f64
        );

        // k independent chains interleaved: does the core overlap them?
        for k in [1usize, 2, 4, 8] {
            let mut xs: Vec<blst_fp> = affine[..k].iter().map(|p| p.x).collect();
            let start = Instant::now();
            for _ in 0..reps / k {
                for chain in xs.iter_mut() {
                    *chain = fp_mul(chain, &affine[1].x);
                }
            }
            std::hint::black_box(&xs);
            println!(
                "fp_mul {k} interleaved chains {:.1} ns/mul",
                start.elapsed().as_nanos() as f64 / reps as f64
            );
        }

        let mut prefix = Vec::new();
        let mut inverses = denominators.clone();
        batch_invert(&mut inverses, &mut prefix);

        // Chord: one at a time (as `complete` does), then k interleaved.
        let reps = 200;
        let mut out = vec![blst_p1_affine::default(); n];
        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..n {
                out[i] = chord(&affine[2 * i], &affine[2 * i + 1], &inverses[i], false, false);
            }
            std::hint::black_box(&out);
        }
        println!(
            "chord x1            {:.1} ns/addition",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        );
        let start = Instant::now();
        for _ in 0..reps {
            for i in (0..n).step_by(2) {
                let (a, b) = (&affine[2 * i], &affine[2 * i + 1]);
                let (c, d) = (&affine[2 * i + 2], &affine[2 * i + 3]);
                let l0 = fp_mul(&fp_sub(&b.y, &a.y), &inverses[i]);
                let l1 = fp_mul(&fp_sub(&d.y, &c.y), &inverses[i + 1]);
                let x0 = fp_sub(&fp_sub(&fp_sqr(&l0), &a.x), &b.x);
                let x1 = fp_sub(&fp_sub(&fp_sqr(&l1), &c.x), &d.x);
                let y0 = fp_sub(&fp_mul(&l0, &fp_sub(&a.x, &x0)), &a.y);
                let y1 = fp_sub(&fp_mul(&l1, &fp_sub(&c.x, &x1)), &c.y);
                out[i] = blst_p1_affine { x: x0, y: y0 };
                out[i + 1] = blst_p1_affine { x: x1, y: y1 };
            }
            std::hint::black_box(&out);
        }
        println!(
            "chord x2 interleaved {:.1} ns/addition",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        );
        let start = Instant::now();
        for _ in 0..reps {
            for i in (0..n).step_by(4) {
                let mut l = [blst_fp::default(); 4];
                for j in 0..4 {
                    let (a, b) = (&affine[2 * (i + j)], &affine[2 * (i + j) + 1]);
                    l[j] = fp_mul(&fp_sub(&b.y, &a.y), &inverses[i + j]);
                }
                let mut xs = [blst_fp::default(); 4];
                for j in 0..4 {
                    let (a, b) = (&affine[2 * (i + j)], &affine[2 * (i + j) + 1]);
                    xs[j] = fp_sub(&fp_sub(&fp_sqr(&l[j]), &a.x), &b.x);
                }
                for j in 0..4 {
                    let a = &affine[2 * (i + j)];
                    let y = fp_sub(&fp_mul(&l[j], &fp_sub(&a.x, &xs[j])), &a.y);
                    out[i + j] = blst_p1_affine { x: xs[j], y };
                }
            }
            std::hint::black_box(&out);
        }
        println!(
            "chord x4 interleaved {:.1} ns/addition",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        );

        // Backward walk of the inversion: one serial chain vs four.
        let reps = 400;
        let start = Instant::now();
        for _ in 0..reps {
            let mut values = denominators.clone();
            batch_invert(&mut values, &mut prefix);
            std::hint::black_box(&values);
        }
        let clone_cost = {
            let start = Instant::now();
            for _ in 0..reps {
                let values = denominators.clone();
                std::hint::black_box(&values);
            }
            start.elapsed().as_nanos() as f64 / (reps * n) as f64
        };
        println!(
            "batch_invert 1 chain {:.1} ns/element",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64 - clone_cost
        );
        let start = Instant::now();
        for _ in 0..reps {
            let values = denominators.clone();
            // Forward: four interleaved prefix chains.
            let mut pre = vec![blst_fp::default(); n];
            pre[..4].copy_from_slice(&values[..4]);
            for i in 4..n {
                pre[i] = fp_mul(&pre[i - 4], &values[i]);
            }
            // One inversion of the product of the four totals, then split.
            let t01 = fp_mul(&pre[n - 4], &pre[n - 3]);
            let t23 = fp_mul(&pre[n - 2], &pre[n - 1]);
            let total = fp_mul(&t01, &t23);
            let mut inv = blst_fp::default();
            // SAFETY: both pointers reference valid blst_fp values.
            unsafe { blst_fp_inverse(&mut inv, &total) };
            let inv01 = fp_mul(&inv, &t23);
            let inv23 = fp_mul(&inv, &t01);
            let mut running = [
                fp_mul(&inv01, &pre[n - 3]),
                fp_mul(&inv01, &pre[n - 4]),
                fp_mul(&inv23, &pre[n - 1]),
                fp_mul(&inv23, &pre[n - 2]),
            ];
            let mut out = vec![blst_fp::default(); n];
            let mut i = n;
            while i > 4 {
                i -= 4;
                for c in 0..4 {
                    out[i + c] = fp_mul(&running[c], &pre[i + c - 4]);
                }
                for c in 0..4 {
                    running[c] = fp_mul(&running[c], &values[i + c]);
                }
            }
            out[..4].copy_from_slice(&running);
            std::hint::black_box(&out);
        }
        println!(
            "batch_invert 4 chains {:.1} ns/element (incl. alloc)",
            start.elapsed().as_nanos() as f64 / (reps * n) as f64 - clone_cost
        );
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
                out[i] = chord(&affine[2 * i], &affine[2 * i + 1], &values[i], false, false);
            }
            std::hint::black_box(&out);
        }
        let chord_cost = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
        println!("chord         {chord_cost:.1} ns/addition");
    }

    /// Whether the cost model picks the cheapest plan. Run with:
    /// `cargo test -p commonware-cryptography --release --features bls12381 \
    ///   subgroup::tests::measure_plans -- --ignored --nocapture`
    #[test]
    #[ignore = "manual benchmark"]
    fn measure_plans() {
        use std::time::Instant;

        /// Time the rounds of a forced plan, best of three.
        fn timed(affine: &[blst_p1_affine], widths: &[u32], rng: &mut impl CryptoRng) -> f64 {
            let widest = *widths.iter().max().expect("nonempty");
            let mut round = Round::new(widest);
            let best = (0..3)
                .map(|_| {
                    let mut trits = Trits::new(rng);
                    let id_sets: Vec<(u32, Vec<u32>)> = widths
                        .iter()
                        .map(|&m| (m, trits.fill(m, affine.len())))
                        .collect();
                    let start = Instant::now();
                    let ok = id_sets.iter().all(|(m, ids)| round.run(affine, ids, *m));
                    assert!(ok);
                    start.elapsed().as_micros()
                })
                .min()
                .expect("three runs");
            best as f64 / 1000.0
        }

        let mut rng = test_rng();
        for n in [100_000usize, 1_000_000] {
            let points: Vec<G1> = (0..n).map(|_| in_subgroup_point(&mut rng)).collect();
            let affine = to_affine(&points);
            let chosen = plan(n, 81).expect("batched");
            // Compare the model's choice against its neighbours: the same
            // combinations spread over one fewer and a few more rounds.
            for rounds in chosen.len().saturating_sub(1)..=chosen.len() + 3 {
                let widths = spread(81, rounds);
                if widths.iter().any(|&m| m > MAX_WIDTH) {
                    continue;
                }
                let mut distinct = widths.clone();
                distinct.dedup();
                println!(
                    "n={n} rounds={rounds} widths={distinct:?} rounds_time={:.1} ms{}",
                    timed(&affine, &widths, &mut rng),
                    if widths == chosen { "  <- chosen by the model" } else { "" }
                );
            }
        }
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
            for m in [8u32, 9, 10, 11] {
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
