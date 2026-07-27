//! Multi-scalar multiplication (MSM): computing `sum(term.point * term.scalar)` for many
//! [`Term`]s at once.
//!
//! Batch signature verification needs exactly one such sum, over roughly `2n` points for a batch
//! of `n` signatures (see [`super::verify_batch`]). Computing each term independently and adding
//! the results costs `O(n * 256)` point additions (one addition per scalar bit, per term).
//! Pippenger's bucket method below instead processes the terms window by window: within each
//! window it buckets every term by its digit in a single pass, then folds the buckets together,
//! so the `256/width` windows share the cost of the additions across all `n` terms. This is
//! variable-time, which is fine since verification only ever operates on public data.
//!
//! Terms arrive already decompressed and digit-recoded (see [`Term::new`]), as a short list of
//! contiguous slices (`&[&[Term]]`: the caller's bulk decompression output plus a couple of small
//! appendices -- see [`super::verify_batch`]), treated everywhere as one logical term sequence
//! indexed globally across the slices in order ([`pieces`]). Two implementations of the same
//! bucket algorithm run over them:
//!
//! - [`scalar`]: the classic, non-vectorized version, operating on [`EdwardsPoint`] directly.
//! - [`transposed`]: the same algorithm reorganized so bucket fills and bucket reductions run as
//!   vectorized [`super::point::PointVec`] operations across [`LANES`] independent lanes -- each
//!   lane owns the terms whose index is congruent to its own mod `LANES` within its piece, plus
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
//! 1. The bucket work is split into `(window, global term range)` tiles: each tile fills only its
//!    own window's buckets over its own range and immediately folds them down to a single partial
//!    point (each module's `window_partial`). Distinct windows are independent by construction,
//!    and -- because bucket-filling is linear in its terms -- two tiles of the *same* window
//!    combine with one point addition. No bucket-array state is ever shared or merged across
//!    threads. (An earlier design gave each thread a private copy of *every* window's buckets and
//!    merged the copies elementwise; the merge cost `threads * windows * buckets` serial
//!    additions, and dominated the profile past ~8 cores.) Ranges are plain cuts of the global
//!    index space -- subslicing is free, so tile granularity is a pure tuning knob.
//! 2. The per-window partials are combined by one short Horner ladder
//!    ([`fold_window_partials`]): `width` doublings plus one addition per window. This is the
//!    only sequential stage, and it is `O(windows * width)` regardless of batch size.

use super::{
    point::{EdwardsPoint, MixedPoint},
    scalar::Scalar,
};
use crate::field_vec::{self, LANES};
use commonware_parallel::Strategy;

/// Bounds on the per-batch window width [`width_for`] may pick. The lower bound sizes every
/// term's digit array ([`MAX_WINDOWS`]); the upper bound caps each tile's bucket-array footprint.
const MIN_WIDTH: u32 = 6;
const MAX_WIDTH: u32 = 10;

/// Digit capacity per [`Term`]: enough windows for the narrowest width. Recoding at a wider
/// width simply leaves the top entries zero (see [`Scalar::signed_digits`]).
const MAX_WINDOWS: usize = 256usize.div_ceil(MIN_WIDTH as usize) + 1;

/// `256` scalar bits divided into `width`-bit windows, rounding up to cover the top window, plus
/// one: recoding into *signed* digits (see [`Scalar::signed_digits`]) can carry a final `+1` past
/// the naive window count, and this spare window is where it lands.
const fn num_windows(width: u32) -> usize {
    256usize.div_ceil(width as usize) + 1
}

/// One bucket per nonzero digit *magnitude*: a signed digit only ever needs a bucket for
/// `abs(digit)`, which ranges `1..=2^(width-1)` -- half as many buckets as the `1..2^width` an
/// unsigned digit would need (see [`Scalar::signed_digits`]).
const fn num_buckets(width: u32) -> usize {
    1usize << (width - 1)
}

/// Picks the window width for a batch of `terms` MSM terms executed at `parallelism`: wider
/// windows mean fewer bucket-fill passes over the terms (the input-proportional cost) but a
/// bigger bucket array for every fill/fold instance to initialize, fold, and keep cache-resident.
///
/// Fit to a measured sweep (width 6-10 x batch 1k-64k signatures x 1/32 threads, AMD EPYC 9354P,
/// AVX-512): the optimum grows at almost exactly half a bit of width per bit of batch size --
/// shallower than the textbook `log2(terms) - 4` rule, because the wide-window penalty on real
/// hardware includes the per-lane bucket array (`8 * 2^(width-1)` points, ~320KB at width 9)
/// spilling L2, not just the fold-count arithmetic. Parallel runs want one step narrower than
/// serial: folds replicate once per tile range, and every concurrent tile holds its own bucket
/// array. Every prediction below matched the sweep's measured optimum (or a runner-up within
/// ~0.5%): serial 7/8/9/10 and parallel 7/8/9/9 for 1k/4k/16k/64k-signature batches.
pub(super) fn width_for(terms: usize, parallelism: usize) -> u32 {
    let bits = terms.max(2).ilog2();
    if parallelism > 1 {
        ((bits + 3) / 2).clamp(MIN_WIDTH, MAX_WIDTH - 1)
    } else {
        ((bits + 4) / 2).clamp(MIN_WIDTH, MAX_WIDTH)
    }
}

/// One MSM term: a decompressed, mixed-addition-prepared point together with its scalar's signed
/// digits. Recoding happens exactly once, here, no matter how many bucket-fill passes later read
/// the digits (one per window). Digits are stored as `i16` (ample for any width up to 16) to
/// keep the per-term footprint, and therefore each pass's memory traffic, small; entries above
/// the chosen width's window count stay zero.
pub(super) struct Term {
    point: MixedPoint,
    digits: [i16; MAX_WINDOWS],
}

impl Term {
    /// Recodes `scalar` at `width` (the batch-wide value from [`width_for`]; every term of one
    /// MSM must use the same width).
    pub(super) fn new(point: MixedPoint, scalar: &Scalar, width: u32) -> Self {
        let digits: [i32; MAX_WINDOWS] = scalar.signed_digits(width);
        Self {
            point,
            digits: digits.map(|d| d as i16),
        }
    }
}

/// Total number of terms across `chunks`.
fn total_terms(chunks: &[&[Term]]) -> usize {
    chunks.iter().map(|chunk| chunk.len()).sum()
}

/// The subslices of `chunks` covering global term indices `[start, end)`, where the global index
/// runs across the chunks in order: how every consumer here reads an arbitrary cut of the logical
/// term sequence without the caller ever flattening its slices into one allocation.
fn pieces<'a>(
    chunks: &'a [&'a [Term]],
    start: usize,
    end: usize,
) -> impl Iterator<Item = &'a [Term]> + 'a {
    let mut offset = 0;
    chunks.iter().filter_map(move |chunk| {
        let chunk_start = offset;
        offset += chunk.len();
        let lo = start.max(chunk_start);
        let hi = end.min(chunk_start + chunk.len());
        (lo < hi).then(|| &chunk[lo - chunk_start..hi - chunk_start])
    })
}

/// One past the highest bucket any digit of `window` lands in over global range `[start, end)`
/// (`0` if none does, i.e. the largest digit *magnitude*; see [`Scalar::signed_digits`]). Every
/// bucket at or above this is still the identity after a fill and would contribute nothing to
/// the bucket fold, and when the terms are a small or sparse range -- a tiny batch, the
/// recoding's spare top window, or the windows above a short (e.g. 128-bit batch-coefficient)
/// scalar's digits -- that is *most* of the buckets. Computed as a standalone prescan over the
/// recoded digits (cheap: two byte-sized loads and a compare per term, no point arithmetic)
/// rather than tracked inside the bucket-fill loop, which measurably slows the fill's hot wave
/// prologue.
fn used_buckets(chunks: &[&[Term]], start: usize, end: usize, window: usize) -> usize {
    pieces(chunks, start, end)
        .flatten()
        .map(|term| term.digits[window].unsigned_abs() as usize)
        .max()
        .unwrap_or(0)
}

mod scalar {
    use super::{EdwardsPoint, Term};

    /// Adds one contiguous run of terms into one window's buckets (`buckets[m - 1]` sums every,
    /// possibly negated, point whose digit in this window has magnitude `m`), negating the point
    /// for a negative digit (cheap; see [`super::MixedPoint::negate`]). Accumulating (rather
    /// than returning fresh buckets) lets a caller fill the same buckets from several pieces of
    /// the logical term sequence and fold only once. Bucket-fill additions use
    /// [`EdwardsPoint::add_mixed`] (7 field multiplies) rather than the general
    /// [`EdwardsPoint::add`] (9): every term is mixed-addition-eligible, since its point is
    /// always freshly decompressed (or the hardcoded basepoint), never the output of a prior
    /// addition or doubling.
    fn fill_buckets(buckets: &mut [EdwardsPoint], terms: &[Term], window: usize) {
        for term in terms {
            let digit = term.digits[window];
            if digit > 0 {
                let i = digit as usize - 1;
                buckets[i] = buckets[i].add_mixed(&term.point);
            } else if digit < 0 {
                let i = digit.unsigned_abs() as usize - 1;
                buckets[i] = buckets[i].add_mixed(&term.point.negate());
            }
        }
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

    /// One window's contribution to the MSM over global term range `[start, end)`, *before* the
    /// doubling shift that positions it (see [`super::fold_window_partials`]).
    pub(super) fn window_partial(
        chunks: &[&[Term]],
        start: usize,
        end: usize,
        window: usize,
        width: u32,
    ) -> EdwardsPoint {
        let used = super::used_buckets(chunks, start, end, window);
        let mut buckets = vec![EdwardsPoint::IDENTITY; super::num_buckets(width)];
        for piece in super::pieces(chunks, start, end) {
            fill_buckets(&mut buckets, piece, window);
        }
        fold_buckets(&buckets, used)
    }

    /// Computes the full MSM over `chunks` via Pippenger's bucket method, one window at a time
    /// from the top down, interleaving each window's fill/fold with the `width` doublings that
    /// shift every window accumulated so far up one position.
    pub(super) fn multiscalar_mul(chunks: &[&[Term]], width: u32) -> EdwardsPoint {
        let total = super::total_terms(chunks);
        let mut result = EdwardsPoint::IDENTITY;
        for window in (0..super::num_windows(width)).rev() {
            for _ in 0..width {
                result = result.double();
            }
            result = result.add(&window_partial(chunks, 0, total, window, width));
        }
        result
    }
}

mod transposed {
    use super::{EdwardsPoint, LANES, MixedPoint, Term};
    use crate::signing::point::{MixedPointVec, PointVec};

    /// Every lane's buckets for one window, flattened lane-major (`buckets[lane * nb + m]`, with
    /// `nb = num_buckets(width)`): within each piece, lane `l` owns the terms whose index is
    /// `l mod LANES`, plus this private bucket stripe, so the wave loop below can update `LANES`
    /// buckets with one vectorized addition and no two lanes ever collide on a bucket.
    /// Heap-allocated because the width (and so the array size) is a per-batch runtime value.
    fn identity_buckets(nb: usize) -> Vec<EdwardsPoint> {
        vec![EdwardsPoint::IDENTITY; LANES * nb]
    }

    /// Adds one contiguous run of terms into one window's bucket stripes via vectorized "wave"
    /// passes, one wave of `LANES` consecutive terms (one per lane) at a time: gather each
    /// lane's current bucket value (a scalar array read, cheap and branch-free since a digit of
    /// 0 just gathers-and-discards the identity), add the wave's incoming (possibly negated, for
    /// a negative digit) points via one vectorized [`PointVec::add_mixed`], then scatter the
    /// results back (again cheap scalar writes, skipped only for zero-digit lanes since there is
    /// no bucket to write into). A wave whose digits are *all* zero is skipped outright before
    /// any point arithmetic -- common, not rare: batch verification's `R` terms carry 128-bit
    /// coefficients, so every window above ~128 bits has zero digits for half the term sequence.
    /// The `terms.len() % LANES` tail rides as a short wave, its missing lanes no-op identity
    /// additions -- so a caller filling from several pieces pays at most one short wave per
    /// piece. Accumulating (rather than returning fresh buckets) is what lets those pieces share
    /// one bucket set and one fold.
    #[allow(clippy::needless_range_loop)]
    fn fill_buckets(buckets: &mut [EdwardsPoint], nb: usize, terms: &[Term], window: usize) {
        let identity_point = MixedPoint::new(&EdwardsPoint::IDENTITY);
        for wave in terms.chunks(LANES) {
            let mut incoming = [identity_point; LANES];
            let mut current = [EdwardsPoint::IDENTITY; LANES];
            let mut bucket_index = [None::<usize>; LANES];
            let mut any = false;
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
                    current[lane] = buckets[lane * nb + i];
                    any = true;
                }
            }
            if !any {
                continue;
            }
            let updated = PointVec::from_lanes(&current)
                .add_mixed(&MixedPointVec::from_lanes(&incoming))
                .to_lanes();
            for lane in 0..LANES {
                if let Some(i) = bucket_index[lane] {
                    buckets[lane * nb + i] = updated[lane];
                }
            }
        }
    }

    /// Folds `LANES` lanes' worth of one window's bucket stripes into `result`, vectorized
    /// across all `LANES` lanes via [`PointVec`] (see [`super::scalar::fold_buckets`] for the
    /// non-transposed version of this running-sum trick, and for why starting below the
    /// untouched top buckets is exact).
    fn fold_buckets(
        result: PointVec,
        buckets: &[EdwardsPoint],
        nb: usize,
        used: usize,
    ) -> PointVec {
        let mut sum = PointVec::identity();
        let mut window_sum = PointVec::identity();
        for d in (0..used).rev() {
            let bucket_group: [EdwardsPoint; LANES] =
                core::array::from_fn(|lane| buckets[lane * nb + d]);
            sum = sum.add(&PointVec::from_lanes(&bucket_group));
            window_sum = window_sum.add(&sum);
        }
        result.add(&window_sum)
    }

    /// One window's contribution to the MSM over global term range `[start, end)`, *before* the
    /// doubling shift that positions it -- the vectorized counterpart of
    /// [`super::scalar::window_partial`], with the `LANES` per-lane partials summed down to a
    /// single point at the end (valid because MSM is linear in its terms).
    pub(super) fn window_partial(
        chunks: &[&[Term]],
        start: usize,
        end: usize,
        window: usize,
        width: u32,
    ) -> EdwardsPoint {
        let nb = super::num_buckets(width);
        let used = super::used_buckets(chunks, start, end, window);
        let mut buckets = identity_buckets(nb);
        for piece in super::pieces(chunks, start, end) {
            fill_buckets(&mut buckets, nb, piece, window);
        }
        fold_buckets(PointVec::identity(), &buckets, nb, used)
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }

    /// Computes the full MSM over `chunks` via the lane-transposed Pippenger bucket method,
    /// window by window from the top down. Unlike [`window_partial`], the running `result` stays
    /// a [`PointVec`] across all windows -- the inter-window doublings run `LANES` wide, and the
    /// lanes are only summed down to a single point once, at the very end. One bucket allocation
    /// is reused (re-set to the identity) across every window.
    pub(super) fn multiscalar_mul(chunks: &[&[Term]], width: u32) -> EdwardsPoint {
        let nb = super::num_buckets(width);
        let total = super::total_terms(chunks);
        let mut result = PointVec::identity();
        let mut buckets = identity_buckets(nb);
        for window in (0..super::num_windows(width)).rev() {
            for _ in 0..width {
                result = result.double();
            }
            let used = super::used_buckets(chunks, 0, total, window);
            for piece in super::pieces(chunks, 0, total) {
                fill_buckets(&mut buckets, nb, piece, window);
            }
            result = fold_buckets(result, &buckets, nb, used);
            buckets.fill(EdwardsPoint::IDENTITY);
        }

        result
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }
}

/// Computes the full MSM over `chunks` serially, dispatching to whichever of [`scalar`]'s or
/// [`transposed`]'s implementation is actually faster on the running CPU (see the module docs).
fn multiscalar_mul_terms(chunks: &[&[Term]], width: u32) -> EdwardsPoint {
    if total_terms(chunks) > 0 && field_vec::simd_available() {
        transposed::multiscalar_mul(chunks, width)
    } else {
        scalar::multiscalar_mul(chunks, width)
    }
}

/// Computes `sum(points[i] * scalars[i])` serially: the reference the differential tests below
/// compare every parallel path against (production callers all go through
/// [`multiscalar_mul_terms_parallel`], which falls back to the same serial code for small or
/// single-threaded inputs).
#[cfg(test)]
fn multiscalar_mul(points: &[MixedPoint], scalars: &[Scalar], width: u32) -> EdwardsPoint {
    debug_assert_eq!(points.len(), scalars.len());
    let terms: Vec<Term> = points
        .iter()
        .zip(scalars)
        .map(|(point, scalar)| Term::new(*point, scalar, width))
        .collect();
    multiscalar_mul_terms(&[&terms], width)
}

/// Horner-folds per-window partial sums into the final MSM result: from the top window down,
/// `width` doublings shift everything accumulated so far up one window, then the next window's
/// partial joins.
fn fold_window_partials(windows: &[EdwardsPoint], width: u32) -> EdwardsPoint {
    let mut result = EdwardsPoint::IDENTITY;
    for window in windows.iter().rev() {
        for _ in 0..width {
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

/// Floor on terms per tile range: a shorter range's fixed per-tile cost (folding the bucket
/// array down to a partial point) stops being amortized by its fill work.
const MIN_RANGE_LEN: usize = 64;

/// How many contiguous ranges to split `len` terms into: enough that every thread `strategy`
/// actually has available gets a few `(window, range)` tiles to chew through (so work stealing
/// evens out the tail), without shrinking any range below [`MIN_RANGE_LEN`].
fn range_count(len: usize, windows: usize, strategy: &impl Strategy) -> usize {
    let parallelism = strategy.manual().parallelism();
    (3 * parallelism)
        .div_ceil(windows)
        .clamp(1, len.div_ceil(MIN_RANGE_LEN))
}

/// Cuts the global term-index space `[0, total)` into up to `ranges` near-equal contiguous
/// ranges. Ranges are pure index arithmetic -- [`pieces`] resolves them onto the underlying
/// slices at read time -- so a cut may land anywhere, including mid-slice.
fn partition_ranges(total: usize, ranges: usize) -> Vec<(usize, usize)> {
    let target = total.div_ceil(ranges).max(1);
    (0..total)
        .step_by(target)
        .map(|start| (start, (start + target).min(total)))
        .collect()
}

/// Computes the full MSM over `chunks` (whose terms were recoded at `width`; see [`width_for`]
/// and [`Term::new`]) with the bucket phase spread across `strategy`'s threads as
/// `(window, global term range)` tiles (see the module docs' "Parallelization" section): each
/// tile fills and folds one window's buckets over one contiguous range into a single partial
/// point, the tiles of each window are summed, and one short serial Horner ladder
/// ([`fold_window_partials`]) positions the windows.
pub(super) fn multiscalar_mul_terms_parallel(
    chunks: &[&[Term]],
    width: u32,
    strategy: &impl Strategy,
) -> EdwardsPoint {
    let total = total_terms(chunks);
    if total < MIN_PARALLEL_TERMS || strategy.manual().parallelism() <= 1 {
        return multiscalar_mul_terms(chunks, width);
    }

    let nw = num_windows(width);
    let ranges = partition_ranges(total, range_count(total, nw, strategy));
    let simd = field_vec::simd_available();
    let tiles = (0..nw).flat_map(|window| ranges.iter().map(move |&(a, b)| (window, a, b)));
    let partials = strategy.map_collect_vec(tiles, |(window, a, b)| {
        let partial = if simd {
            transposed::window_partial(chunks, a, b, window, width)
        } else {
            scalar::window_partial(chunks, a, b, window, width)
        };
        (window, partial)
    });

    let mut windows = vec![EdwardsPoint::IDENTITY; nw];
    for (window, partial) in partials {
        windows[window] = windows[window].add(&partial);
    }
    fold_window_partials(&windows, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::scalar::test_support::rand_scalar;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey;
    use rand_core::Rng;

    /// The widths every differential test sweeps: [`width_for`]'s full output range.
    const TEST_WIDTHS: [u32; 5] = [6, 7, 8, 9, 10];

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

    /// Returns `n` [`Term`]s over random points and scalars, recoded at `width`.
    fn rand_terms(n: usize, width: u32) -> Vec<Term> {
        let mut rng = test_rng();
        rand_affine_points(n)
            .iter()
            .map(|p| Term::new(MixedPoint::new(p), &rand_scalar(&mut rng), width))
            .collect()
    }

    /// Splits `terms` into owned chunks of the given (deliberately uneven, `LANES`-unaligned)
    /// sizes, with any remainder in one final chunk.
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

    /// Borrows a set of owned chunks as the slice-of-slices shape the MSM API takes.
    fn refs(chunks: &[Vec<Term>]) -> Vec<&[Term]> {
        chunks.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn width_for_matches_measured_optima() {
        // The sweep's measured optima (see `width_for`'s doc comment), as (signatures, threads,
        // width): terms per batch are ~2 * signatures + 1.
        for (sigs, parallelism, expected) in [
            (1024, 32, 7),
            (4096, 32, 8),
            (16384, 32, 9),
            (65536, 32, 9),
            (1024, 1, 7),
            (4096, 1, 8),
            (16384, 1, 9),
            (65536, 1, 10),
        ] {
            assert_eq!(
                width_for(2 * sigs + 1, parallelism),
                expected,
                "sigs={sigs} parallelism={parallelism}"
            );
        }
        // Clamps: tiny batches never drop below MIN_WIDTH, huge parallel batches never exceed
        // MAX_WIDTH - 1 (bucket footprint), huge serial batches never exceed MAX_WIDTH.
        assert_eq!(width_for(1, 32), MIN_WIDTH);
        assert_eq!(width_for(usize::MAX, 32), MAX_WIDTH - 1);
        assert_eq!(width_for(usize::MAX, 1), MAX_WIDTH);
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
            for width in TEST_WIDTHS {
                let actual = multiscalar_mul(&mixed, &scalars, width);
                assert!(
                    actual.add(&expected.negate()).is_identity(),
                    "n={n} width={width}"
                );
            }
        }
    }

    #[test]
    fn transposed_matches_scalar() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            for width in TEST_WIDTHS {
                let chunks = split_terms(rand_terms(n, width), &[7, 9, 24]);
                let chunks = refs(&chunks);
                let expected = scalar::multiscalar_mul(&chunks, width);
                let actual = transposed::multiscalar_mul(&chunks, width);
                assert!(
                    actual.add(&expected.negate()).is_identity(),
                    "n={n} width={width}"
                );
            }
        }
    }

    /// Slice boundaries are pure layout: any split of the same terms (including `LANES`-unaligned
    /// and empty slices, whose tail waves pad with identity lanes) must produce the same point as
    /// one contiguous slice.
    #[test]
    fn chunked_matches_single_chunk() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let terms = rand_terms(n, 7);
            let single = split_terms(rand_terms(n, 7), &[]);
            let mut chunks = split_terms(terms, &[1, 3, 7, 9, 24]);
            chunks.push(Vec::new());

            let expected = multiscalar_mul_terms(&refs(&single), 7);
            let actual = multiscalar_mul_terms(&refs(&chunks), 7);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn parallel_matches_serial() {
        for n in [0, 1, 2, 5, 32, 600] {
            for width in TEST_WIDTHS {
                let chunks = split_terms(rand_terms(n, width), &[64, 64, 64, 64]);
                let chunks = refs(&chunks);
                let expected = multiscalar_mul_terms(&chunks, width);
                let actual = multiscalar_mul_terms_parallel(&chunks, width, &Sequential);
                assert!(
                    actual.add(&expected.negate()).is_identity(),
                    "n={n} width={width}"
                );
            }
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
            for width in [6, 8, 10] {
                let chunks = split_terms(rand_terms(n, width), &[128, 128, 128, 128, 128, 128]);
                let chunks = refs(&chunks);
                let expected = multiscalar_mul_terms(&chunks, width);
                let actual = multiscalar_mul_terms_parallel(&chunks, width, &strategy);
                assert!(
                    actual.add(&expected.negate()).is_identity(),
                    "n={n} width={width}"
                );
            }
        }
    }

    /// Splitting a window's bucket fill at an arbitrary global index (deliberately not a slice
    /// boundary) and summing the two partials must Horner-fold to the exact same point as
    /// running the whole MSM over the full range at once, for both backends -- this is the
    /// correctness argument the tile-parallel [`multiscalar_mul_terms_parallel`] relies on to
    /// combine same-window tiles with a single addition.
    #[test]
    fn split_window_partials_match_whole_range() {
        const WIDTH: u32 = 7;
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let chunks = split_terms(rand_terms(n, WIDTH), &[n / 3, n / 3]);
            let chunks = refs(&chunks);
            let total = total_terms(&chunks);
            let mid = total / 2;

            let expected = multiscalar_mul_terms(&chunks, WIDTH);

            let nw = num_windows(WIDTH);
            let mut scalar_windows = vec![EdwardsPoint::IDENTITY; nw];
            let mut transposed_windows = vec![EdwardsPoint::IDENTITY; nw];
            for window in 0..nw {
                scalar_windows[window] = scalar::window_partial(&chunks, 0, mid, window, WIDTH)
                    .add(&scalar::window_partial(&chunks, mid, total, window, WIDTH));
                transposed_windows[window] =
                    transposed::window_partial(&chunks, 0, mid, window, WIDTH)
                        .add(&transposed::window_partial(&chunks, mid, total, window, WIDTH));
            }

            assert!(
                fold_window_partials(&scalar_windows, WIDTH)
                    .add(&expected.negate())
                    .is_identity()
            );
            assert!(
                fold_window_partials(&transposed_windows, WIDTH)
                    .add(&expected.negate())
                    .is_identity()
            );
        }
    }

    /// [`pieces`] must hand back exactly the requested global range, in order, for any cut --
    /// including cuts inside slices, across slice boundaries, and touching empty slices.
    #[test]
    fn pieces_covers_exact_global_ranges() {
        let chunks = split_terms(rand_terms(50, 7), &[1, 7, 0, 24]);
        let mut chunks = refs(&chunks);
        chunks.insert(2, &[]);
        let total = total_terms(&chunks);
        assert_eq!(total, 50);

        let flat: Vec<*const Term> = chunks
            .iter()
            .flat_map(|chunk| chunk.iter().map(|t| t as *const Term))
            .collect();
        for (start, end) in [(0, 50), (0, 0), (3, 3), (0, 1), (7, 9), (1, 40), (49, 50)] {
            let got: Vec<*const Term> = pieces(&chunks, start, end)
                .flat_map(|piece| piece.iter().map(|t| t as *const Term))
                .collect();
            assert_eq!(got, flat[start..end], "range ({start}, {end})");
        }
    }

    #[test]
    fn partition_ranges_covers_index_space_contiguously() {
        for total in [1usize, 10, 63, 64, 65, 700] {
            for ranges in [1, 2, 3, 5] {
                let parts = partition_ranges(total, ranges);
                assert!(!parts.is_empty());
                assert_eq!(parts[0].0, 0);
                assert_eq!(parts.last().unwrap().1, total);
                for pair in parts.windows(2) {
                    assert_eq!(pair[0].1, pair[1].0);
                }
            }
        }
    }
}
