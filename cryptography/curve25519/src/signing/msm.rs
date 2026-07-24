//! Multi-scalar multiplication (MSM): computing `sum(term.point * term.scalar)` for many
//! [`Term`]s at once.
//!
//! Batch signature verification needs exactly one such sum, over roughly `2n` points for a batch
//! of `n` signatures (see [`super::verify_batch`]). Computing each term independently and adding
//! the results costs `O(n * 256)` point additions (one addition per scalar bit, per term).
//! Pippenger's bucket method below instead processes the terms window by window: within each
//! window it buckets every term by its digit in a single pass, then folds the buckets together,
//! so the `256/WIDTH` windows share the cost of the additions across all `n` terms. This is
//! variable-time, which is fine since verification only ever operates on public data.
//!
//! Terms arrive already decompressed and digit-recoded (see [`Term::new`]), as a list of chunks
//! (`&[Vec<Term>]`): the chunks are whatever units the caller's parallel decompression produced,
//! and every function here iterates them in order as one logical term sequence -- so the caller
//! never pays to flatten its per-chunk output into one contiguous allocation. Two
//! implementations of the same bucket algorithm run over them:
//!
//! - [`scalar`]: the classic, non-vectorized version, operating on [`EdwardsPoint`] directly.
//! - [`transposed`]: the same algorithm reorganized so bucket fills and bucket reductions run as
//!   vectorized [`super::point::PointVec`] operations across [`LANES`] independent lanes -- each
//!   lane owns the terms whose index is congruent to its own mod `LANES` within its chunk, plus
//!   a private bucket array, so no two lanes ever collide on a bucket (the design notes'
//!   "transposed Pippenger").
//!
//! The serial paths pick whichever is actually faster on the running CPU
//! ([`crate::field_vec::simd_available`]): packing/unpacking `PointVec` lanes costs the same
//! either way, so the transposed version is strictly *more* work than the scalar one unless the
//! packed arithmetic is genuinely hardware-accelerated (see [`crate::field_vec`]'s docs). Without
//! real SIMD it is pure overhead; with it, the packed multiplies run 8-wide instead of one at a
//! time.
//!
//! # Parallelization
//!
//! [`multiscalar_mul_terms_parallel`] decomposes the MSM by *window*, the way state-of-the-art
//! CPU libraries (blst, gnark-crypto, arkworks, halo2curves, constantine) do, rather than by
//! replicating bucket state per thread:
//!
//! 1. The bucket work is split into `(window, contiguous chunk range)` tiles: each tile fills
//!    only its own window's buckets over its own chunks and immediately folds them down to a
//!    single partial point (each module's `window_partial`). Distinct windows are independent by
//!    construction, and -- because bucket-filling is linear in its terms -- two tiles of the
//!    *same* window combine with one point addition. No bucket-array state is ever shared or
//!    merged across threads. (An earlier design gave each thread a private copy of *every*
//!    window's buckets and merged the copies elementwise; the merge cost
//!    `threads * NUM_WINDOWS * NUM_BUCKETS` serial additions, and dominated the profile past ~8
//!    cores.)
//! 2. The per-window partials are combined by one short Horner ladder
//!    ([`fold_window_partials`]): `WIDTH` doublings plus one addition per window. This is the
//!    only sequential stage, and it is `O(NUM_WINDOWS * WIDTH)` regardless of batch size.

use super::{
    point::{EdwardsPoint, MixedPoint},
    scalar::Scalar,
};
use crate::field_vec::{self, LANES};
use commonware_parallel::Strategy;

/// Window width in bits. Widening it shrinks the number of windows (fewer bucket-fill passes
/// over the terms, and fewer ladder doublings) at the cost of a larger bucket array
/// (`2^(WIDTH-1)` points per lane) for every tile to fill and fold.
///
/// Measured on an AMD EPYC 9354P (32 cores, AVX-512), `7` is the best *fixed* value across batch
/// sizes: versus `6` it gains 5-8% on 10k-16k-signature batches at every thread count and loses
/// nowhere meaningful, while `8` adds a further ~3% at 16k signatures but costs 6-10% on
/// 1k-signature batches (its `2^7`-bucket fold stops being amortized by each tile's fill work).
/// The right width grows with the term count -- every major MSM library picks it per call, as
/// roughly `log2(n) - 3..4` -- so per-batch *adaptive* selection is deliberately deferred as a
/// future tuning opportunity rather than baked in now.
const WIDTH: u32 = 7;

/// `256` scalar bits divided into `WIDTH`-bit windows, rounding up to cover the top window, plus
/// one: recoding into *signed* digits (see [`Scalar::signed_digits`]) can carry a final `+1` past
/// the naive window count, and this spare window is where it lands.
const NUM_WINDOWS: usize = 256usize.div_ceil(WIDTH as usize) + 1;

/// One bucket per nonzero digit *magnitude*: a signed digit only ever needs a bucket for
/// `abs(digit)`, which ranges `1..=2^(WIDTH-1)` -- half as many buckets as the `1..2^WIDTH` an
/// unsigned digit would need (see [`Scalar::signed_digits`]).
const NUM_BUCKETS: usize = 1usize << (WIDTH - 1);

/// One MSM term: a decompressed, mixed-addition-prepared point together with its scalar's signed
/// digits. Recoding happens exactly once, here, no matter how many bucket-fill passes later read
/// the digits (up to `NUM_WINDOWS` of them, one per window). Digits are stored as `i16` (ample
/// for any `WIDTH` up to 16) to keep the per-term footprint, and therefore each pass's memory
/// traffic, small.
pub(super) struct Term {
    point: MixedPoint,
    digits: [i16; NUM_WINDOWS],
}

impl Term {
    pub(super) fn new(point: MixedPoint, scalar: &Scalar) -> Self {
        let digits: [i32; NUM_WINDOWS] = scalar.signed_digits(WIDTH);
        Self {
            point,
            digits: digits.map(|d| d as i16),
        }
    }
}

/// Total number of terms across `chunks`.
fn total_terms(chunks: &[Vec<Term>]) -> usize {
    chunks.iter().map(Vec::len).sum()
}

/// One past the highest bucket any of `chunks`' digits in `window` lands in (`0` if none does,
/// i.e. the largest digit *magnitude*; see [`Scalar::signed_digits`]). Every bucket at or above
/// this is still the identity after a fill and would contribute nothing to the bucket fold, and
/// when the terms are a small or sparse range -- a tiny batch, or the recoding's spare top
/// window -- that is *most* of the buckets. Computed as a standalone prescan over the recoded
/// digits (cheap: two byte-sized loads and a compare per term, no point arithmetic) rather than
/// tracked inside the bucket-fill loop, which measurably slows the fill's hot wave prologue.
fn used_buckets(chunks: &[Vec<Term>], window: usize) -> usize {
    chunks
        .iter()
        .flatten()
        .map(|term| term.digits[window].unsigned_abs() as usize)
        .max()
        .unwrap_or(0)
}

mod scalar {
    use super::{EdwardsPoint, NUM_BUCKETS, Term};

    /// Fills one window's buckets (`buckets[m - 1]` sums every, possibly negated, point whose
    /// digit in this window has magnitude `m`) via a single pass over `chunks`' terms, negating
    /// the point for a negative digit (cheap; see [`super::MixedPoint::negate`]). Bucket-fill
    /// additions use [`EdwardsPoint::add_mixed`] (7 field multiplies) rather than the general
    /// [`EdwardsPoint::add`] (9): every term is mixed-addition-eligible, since its point is
    /// always freshly decompressed (or the hardcoded basepoint), never the output of a prior
    /// addition or doubling.
    fn window_buckets(chunks: &[Vec<Term>], window: usize) -> [EdwardsPoint; NUM_BUCKETS] {
        let mut buckets = [EdwardsPoint::IDENTITY; NUM_BUCKETS];
        for term in chunks.iter().flatten() {
            let digit = term.digits[window];
            if digit > 0 {
                let i = digit as usize - 1;
                buckets[i] = buckets[i].add_mixed(&term.point);
            } else if digit < 0 {
                let i = digit.unsigned_abs() as usize - 1;
                buckets[i] = buckets[i].add_mixed(&term.point.negate());
            }
        }
        buckets
    }

    /// Folds one window's filled buckets into `sum(m * buckets[m - 1])` via a running sum, from
    /// the highest *touched* magnitude (`used`, from [`super::used_buckets`]) down: adding each
    /// bucket into `sum` and then `sum` into `window_sum` accumulates every bucket once for
    /// every magnitude at or below its own, which is exactly its weight `m`. Starting below the
    /// untouched top buckets is exact, not an approximation: an identity bucket leaves `sum`
    /// unchanged, and while `sum` is still the identity, `window_sum` stays the identity too.
    fn fold_buckets(buckets: &[EdwardsPoint], used: usize) -> EdwardsPoint {
        let mut sum = EdwardsPoint::IDENTITY;
        let mut window_sum = EdwardsPoint::IDENTITY;
        for bucket in buckets[..used].iter().rev() {
            sum = sum.add(bucket);
            window_sum = window_sum.add(&sum);
        }
        window_sum
    }

    /// One window's contribution to the MSM over `chunks`, *before* the doubling shift that
    /// positions it (see [`super::fold_window_partials`]).
    pub(super) fn window_partial(chunks: &[Vec<Term>], window: usize) -> EdwardsPoint {
        let used = super::used_buckets(chunks, window);
        fold_buckets(&window_buckets(chunks, window), used)
    }

    /// Computes the full MSM over `chunks` via Pippenger's bucket method, one window at a time
    /// from the top down, interleaving each window's fill/fold with the `WIDTH` doublings that
    /// shift every window accumulated so far up one position.
    pub(super) fn multiscalar_mul(chunks: &[Vec<Term>]) -> EdwardsPoint {
        let mut result = EdwardsPoint::IDENTITY;
        for window in (0..super::NUM_WINDOWS).rev() {
            for _ in 0..super::WIDTH {
                result = result.double();
            }
            result = result.add(&window_partial(chunks, window));
        }
        result
    }
}

mod transposed {
    use super::{EdwardsPoint, LANES, MixedPoint, NUM_BUCKETS, Term};
    use crate::signing::point::{MixedPointVec, PointVec};

    /// Every lane's buckets for one window: within each chunk, lane `l` owns the terms whose
    /// index is `l mod LANES`, plus this private bucket array, so the wave loop below can update
    /// `LANES` buckets with one vectorized addition and no two lanes ever collide on a bucket.
    type WindowBuckets = [[EdwardsPoint; NUM_BUCKETS]; LANES];

    /// Fills one window's [`WindowBuckets`] via one vectorized "wave" pass, one wave of `LANES`
    /// consecutive terms (one per lane) at a time: gather each lane's current bucket value (a
    /// scalar array read, cheap and branch-free since a digit of 0 just gathers-and-discards the
    /// identity), add the wave's incoming (possibly negated, for a negative digit) points via one
    /// vectorized [`PointVec::add_mixed`], then scatter the results back (again cheap scalar
    /// writes, skipped only for zero-digit lanes since there is no bucket to write into). Waves
    /// never straddle a chunk boundary; each chunk's `len % LANES` tail rides as a short wave,
    /// its missing lanes no-op identity additions.
    #[allow(clippy::needless_range_loop)]
    fn window_buckets(chunks: &[Vec<Term>], window: usize) -> WindowBuckets {
        let identity_point = MixedPoint::new(&EdwardsPoint::IDENTITY);
        let mut buckets = [[EdwardsPoint::IDENTITY; NUM_BUCKETS]; LANES];
        for terms in chunks {
            for wave in terms.chunks(LANES) {
                let mut incoming = [identity_point; LANES];
                let mut current = [EdwardsPoint::IDENTITY; LANES];
                let mut bucket_index = [None::<usize>; LANES];
                for (lane, term) in wave.iter().enumerate() {
                    let digit = term.digits[window];
                    if digit > 0 {
                        bucket_index[lane] = Some(digit as usize - 1);
                        incoming[lane] = term.point;
                    } else if digit < 0 {
                        bucket_index[lane] = Some(digit.unsigned_abs() as usize - 1);
                        incoming[lane] = term.point.negate();
                    }
                    if let Some(i) = bucket_index[lane] {
                        current[lane] = buckets[lane][i];
                    }
                }
                let updated = PointVec::from_lanes(&current)
                    .add_mixed(&MixedPointVec::from_lanes(&incoming))
                    .to_lanes();
                for lane in 0..LANES {
                    if let Some(i) = bucket_index[lane] {
                        buckets[lane][i] = updated[lane];
                    }
                }
            }
        }
        buckets
    }

    /// Folds `LANES` lanes' worth of one window's [`WindowBuckets`] into `result`, vectorized
    /// across all `LANES` lanes via [`PointVec`] (see [`super::scalar::fold_buckets`] for the
    /// non-transposed version of this running-sum trick, and for why starting below the
    /// untouched top buckets is exact).
    fn fold_buckets(result: PointVec, buckets: &WindowBuckets, used: usize) -> PointVec {
        let mut sum = PointVec::identity();
        let mut window_sum = PointVec::identity();
        for d in (0..used).rev() {
            let bucket_group: [EdwardsPoint; LANES] = core::array::from_fn(|lane| buckets[lane][d]);
            sum = sum.add(&PointVec::from_lanes(&bucket_group));
            window_sum = window_sum.add(&sum);
        }
        result.add(&window_sum)
    }

    /// One window's contribution to the MSM over `chunks`, *before* the doubling shift that
    /// positions it -- the vectorized counterpart of [`super::scalar::window_partial`], with the
    /// `LANES` per-lane partials summed down to a single point at the end (valid because MSM is
    /// linear in its terms).
    pub(super) fn window_partial(chunks: &[Vec<Term>], window: usize) -> EdwardsPoint {
        let used = super::used_buckets(chunks, window);
        let buckets = window_buckets(chunks, window);
        fold_buckets(PointVec::identity(), &buckets, used)
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }

    /// Computes the full MSM over `chunks` via the lane-transposed Pippenger bucket method,
    /// window by window from the top down. Unlike [`window_partial`], the running `result` stays
    /// a [`PointVec`] across all windows -- the inter-window doublings run `LANES` wide, and the
    /// lanes are only summed down to a single point once, at the very end.
    pub(super) fn multiscalar_mul(chunks: &[Vec<Term>]) -> EdwardsPoint {
        let mut result = PointVec::identity();
        for window in (0..super::NUM_WINDOWS).rev() {
            for _ in 0..super::WIDTH {
                result = result.double();
            }
            let used = super::used_buckets(chunks, window);
            let buckets = window_buckets(chunks, window);
            result = fold_buckets(result, &buckets, used);
        }

        result
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }
}

/// Computes the full MSM over `chunks` serially, dispatching to whichever of [`scalar`]'s or
/// [`transposed`]'s implementation is actually faster on the running CPU (see the module docs).
fn multiscalar_mul_terms(chunks: &[Vec<Term>]) -> EdwardsPoint {
    if total_terms(chunks) > 0 && field_vec::simd_available() {
        transposed::multiscalar_mul(chunks)
    } else {
        scalar::multiscalar_mul(chunks)
    }
}

/// Computes `sum(points[i] * scalars[i])` serially: the reference the differential tests below
/// compare every parallel path against (production callers all go through
/// [`multiscalar_mul_terms_parallel`], which falls back to the same serial code for small or
/// single-threaded inputs).
#[cfg(test)]
fn multiscalar_mul(points: &[MixedPoint], scalars: &[Scalar]) -> EdwardsPoint {
    debug_assert_eq!(points.len(), scalars.len());
    let terms: Vec<Term> = points
        .iter()
        .zip(scalars)
        .map(|(point, scalar)| Term::new(*point, scalar))
        .collect();
    multiscalar_mul_terms(core::slice::from_ref(&terms))
}

/// Horner-folds per-window partial sums into the final MSM result: from the top window down,
/// `WIDTH` doublings shift everything accumulated so far up one window, then the next window's
/// partial joins.
fn fold_window_partials(windows: &[EdwardsPoint; NUM_WINDOWS]) -> EdwardsPoint {
    let mut result = EdwardsPoint::IDENTITY;
    for window in windows.iter().rev() {
        for _ in 0..WIDTH {
            result = result.double();
        }
        result = result.add(window);
    }
    result
}

/// Floor on terms per parallel MSM: below this, the whole bucket phase is a few thousand point
/// additions and tile dispatch overhead stops being amortized, so the serial path wins. Not yet
/// tuned against real hardware.
const MIN_PARALLEL_TERMS: usize = 64;

/// Floor on terms per tile range: a shorter range's fixed per-tile cost (folding `NUM_BUCKETS`
/// buckets down to a partial point) stops being amortized by its fill work.
const MIN_RANGE_LEN: usize = 64;

/// How many contiguous ranges to split `len` terms into: enough that every thread `strategy`
/// actually has available gets a few `(window, range)` tiles to chew through (so work stealing
/// evens out the tail), without shrinking any range below [`MIN_RANGE_LEN`].
fn range_count(len: usize, strategy: &impl Strategy) -> usize {
    let parallelism = strategy.manual().parallelism();
    (3 * parallelism)
        .div_ceil(NUM_WINDOWS)
        .clamp(1, len.div_ceil(MIN_RANGE_LEN))
}

/// Splits the chunk list into up to `ranges` contiguous runs of whole chunks with near-equal
/// term counts, returned as `(start, end)` chunk-index pairs. Ranges never split a chunk: the
/// chunks are the caller's parallel-decompression output, and keeping them whole is what lets
/// tiles read them with no flattening or copying.
fn partition_chunks(chunks: &[Vec<Term>], ranges: usize, total: usize) -> Vec<(usize, usize)> {
    let target = total.div_ceil(ranges);
    let mut out = Vec::with_capacity(ranges);
    let mut start = 0;
    let mut in_range = 0;
    for (i, chunk) in chunks.iter().enumerate() {
        in_range += chunk.len();
        if in_range >= target && out.len() + 1 < ranges {
            out.push((start, i + 1));
            start = i + 1;
            in_range = 0;
        }
    }
    if start < chunks.len() {
        out.push((start, chunks.len()));
    }
    out
}

/// Computes the full MSM over `chunks` with the bucket phase spread across `strategy`'s threads
/// as `(window, chunk range)` tiles (see the module docs' "Parallelization" section): each tile
/// fills and folds one window's buckets over one contiguous run of chunks into a single partial
/// point, the tiles of each window are summed, and one short serial Horner ladder
/// ([`fold_window_partials`]) positions the windows.
pub(super) fn multiscalar_mul_terms_parallel(
    chunks: &[Vec<Term>],
    strategy: &impl Strategy,
) -> EdwardsPoint {
    let total = total_terms(chunks);
    if total < MIN_PARALLEL_TERMS || strategy.manual().parallelism() <= 1 {
        return multiscalar_mul_terms(chunks);
    }

    let ranges = partition_chunks(chunks, range_count(total, strategy), total);
    let simd = field_vec::simd_available();
    let tiles = (0..NUM_WINDOWS)
        .flat_map(|window| ranges.iter().map(move |&(a, b)| (window, a, b)));
    let partials = strategy.map_collect_vec(tiles, |(window, a, b)| {
        let range = &chunks[a..b];
        let partial = if simd {
            transposed::window_partial(range, window)
        } else {
            scalar::window_partial(range, window)
        };
        (window, partial)
    });

    let mut windows = [EdwardsPoint::IDENTITY; NUM_WINDOWS];
    for (window, partial) in partials {
        windows[window] = windows[window].add(&partial);
    }
    fold_window_partials(&windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::scalar::test_support::rand_scalar;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey;
    use rand_core::Rng;

    /// Returns `n` distinct valid 32-byte point encodings, using `ed25519-consensus` verification
    /// keys as a source of arbitrary valid points (this crate has no point *compression* yet, only
    /// decompression, so real signature-scheme keys are the easiest way to get valid encodings).
    fn valid_point_bytes(n: usize) -> Vec<[u8; 32]> {
        let mut rng = test_rng();
        (0..n)
            .map(|_| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                SigningKey::from(seed).verification_key().to_bytes()
            })
            .collect()
    }

    /// Returns `n` distinct, `Z = 1` points, via [`valid_point_bytes`] and decompression --
    /// every point this crate's MSM is ever fed in production is either freshly decompressed or
    /// the hardcoded basepoint, so tests generate points the same way rather than via `scalar_mul`
    /// (whose output generally has `Z != 1`, violating [`MixedPoint::new`]'s precondition).
    fn rand_affine_points(n: usize) -> Vec<EdwardsPoint> {
        valid_point_bytes(n)
            .iter()
            .map(|b| EdwardsPoint::decompress(b).unwrap())
            .collect()
    }

    /// Returns `n` [`Term`]s over random points and scalars.
    fn rand_terms(n: usize) -> Vec<Term> {
        let mut rng = test_rng();
        rand_affine_points(n)
            .iter()
            .map(|p| Term::new(MixedPoint::new(p), &rand_scalar(&mut rng)))
            .collect()
    }

    /// Splits `terms` into chunks of the given (deliberately uneven, `LANES`-unaligned) sizes,
    /// with any remainder in one final chunk.
    fn split_terms(mut terms: Vec<Term>, sizes: &[usize]) -> Vec<Vec<Term>> {
        let mut chunks = Vec::new();
        for &size in sizes {
            if terms.len() <= size {
                break;
            }
            let rest = terms.split_off(size);
            chunks.push(terms);
            terms = rest;
        }
        chunks.push(terms);
        chunks
    }

    #[test]
    fn matches_naive_double_and_add() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 8, 9, 32, 64, 100] {
            let points = rand_affine_points(n);
            let mixed: Vec<MixedPoint> = points.iter().map(MixedPoint::new).collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = points
                .iter()
                .zip(&scalars)
                .fold(EdwardsPoint::IDENTITY, |acc, (p, s)| {
                    acc.add(&p.scalar_mul(s))
                });
            let actual = multiscalar_mul(&mixed, &scalars);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn transposed_matches_scalar() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let chunks = split_terms(rand_terms(n), &[7, 9, 24]);
            let expected = scalar::multiscalar_mul(&chunks);
            let actual = transposed::multiscalar_mul(&chunks);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    /// Chunk boundaries are pure layout: any split of the same terms (including `LANES`-unaligned
    /// and empty chunks, whose tail waves pad with identity lanes) must produce the same point as
    /// one contiguous chunk.
    #[test]
    fn chunked_matches_single_chunk() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let terms = rand_terms(n);
            let single = split_terms(rand_terms(n), &[]);
            let mut chunks = split_terms(terms, &[1, 3, 7, 9, 24]);
            chunks.push(Vec::new());

            let expected = multiscalar_mul_terms(&single);
            let actual = multiscalar_mul_terms(&chunks);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn parallel_matches_serial() {
        for n in [0, 1, 2, 5, 32, 600] {
            let chunks = split_terms(rand_terms(n), &[64, 64, 64, 64]);
            let expected = multiscalar_mul_terms(&chunks);
            let actual = multiscalar_mul_terms_parallel(&chunks, &Sequential);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn tile_parallel_matches_serial_under_real_parallelism() {
        // `Manual` disables the adaptive serial/parallel policy, forcing every call through
        // actual Rayon dispatch (rather than the policy falling back to serial for small inputs).
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();

        for n in [0, 1, 300, 600, 1000] {
            let chunks = split_terms(rand_terms(n), &[128, 128, 128, 128, 128, 128]);
            let expected = multiscalar_mul_terms(&chunks);
            let actual = multiscalar_mul_terms_parallel(&chunks, &strategy);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    /// Splitting a window's bucket fill across two disjoint chunk ranges and summing the partials
    /// must Horner-fold to the exact same point as running the whole MSM over the full range at
    /// once, for both backends -- this is the correctness argument the tile-parallel
    /// [`multiscalar_mul_terms_parallel`] relies on to combine same-window tiles with a single
    /// addition.
    #[test]
    fn split_window_partials_match_whole_range() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let chunks = split_terms(rand_terms(n), &[n / 3, n / 3]);
            let mid = chunks.len() / 2;
            let (c1, c2) = chunks.split_at(mid);

            let expected = multiscalar_mul_terms(&chunks);

            let mut scalar_windows = [EdwardsPoint::IDENTITY; NUM_WINDOWS];
            let mut transposed_windows = [EdwardsPoint::IDENTITY; NUM_WINDOWS];
            for window in 0..NUM_WINDOWS {
                scalar_windows[window] =
                    scalar::window_partial(c1, window).add(&scalar::window_partial(c2, window));
                transposed_windows[window] = transposed::window_partial(c1, window)
                    .add(&transposed::window_partial(c2, window));
            }

            assert!(
                fold_window_partials(&scalar_windows)
                    .add(&expected.negate())
                    .is_identity()
            );
            assert!(
                fold_window_partials(&transposed_windows)
                    .add(&expected.negate())
                    .is_identity()
            );
        }
    }

    #[test]
    fn partition_chunks_covers_all_chunks_contiguously() {
        for sizes in [vec![10usize], vec![64, 64, 64], vec![512; 9], vec![1, 700, 1]] {
            let chunks: Vec<Vec<Term>> = sizes.iter().map(|&s| rand_terms(s)).collect();
            let total = total_terms(&chunks);
            for ranges in [1, 2, 3, 5] {
                let parts = partition_chunks(&chunks, ranges, total);
                assert!(!parts.is_empty());
                assert!(parts.len() <= ranges);
                assert_eq!(parts[0].0, 0);
                assert_eq!(parts.last().unwrap().1, chunks.len());
                for pair in parts.windows(2) {
                    assert_eq!(pair[0].1, pair[1].0);
                }
            }
        }
    }
}
