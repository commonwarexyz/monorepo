//! Multi-scalar multiplication (MSM): computing `sum(points[i] * scalars[i])` for many
//! `(point, scalar)` pairs at once.
//!
//! Batch signature verification needs exactly one such sum, over roughly `2n` points for a batch
//! of `n` signatures (see [`super::verify_batch`]). Computing each term independently and adding
//! the results costs `O(n * 256)` point additions (one addition per scalar bit, per term).
//! Pippenger's bucket method below instead processes the terms window by window: within each
//! window it buckets every term by its digit in a single pass, then folds the buckets together,
//! so the `256/WIDTH` windows share the cost of the additions across all `n` terms. This is
//! variable-time, which is fine since verification only ever operates on public data.
//!
//! Every entry point first flattens its input into [`Term`]s (a decompressed point plus its
//! scalar's signed digits, recoded exactly once), then runs one of two implementations of the
//! same bucket algorithm over them:
//!
//! - [`scalar`]: the classic, non-vectorized version, operating on [`EdwardsPoint`] directly.
//! - [`transposed`]: the same algorithm reorganized so bucket fills and bucket reductions run as
//!   vectorized [`super::point::PointVec`] operations across [`LANES`] independent lanes -- each
//!   lane owns the terms whose index is congruent to its own mod `LANES`, plus a private bucket
//!   array, so no two lanes ever collide on a bucket (the design notes' "transposed Pippenger").
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
//! The parallel entry points decompose the MSM by *window*, the way state-of-the-art CPU
//! libraries (blst, gnark-crypto, arkworks, halo2curves, constantine) do, rather than by
//! replicating bucket state per thread:
//!
//! 1. Decompression and digit recoding are embarrassingly parallel over point chunks, producing
//!    one shared, read-only term list (see [`decompress_terms`]).
//! 2. The bucket work is split into `(window, contiguous term range)` tiles: each tile fills
//!    only its own window's buckets over its own range and immediately folds them down to a
//!    single partial point (each module's `window_partial`). Distinct windows are independent by
//!    construction, and -- because bucket-filling is linear in its terms -- two tiles of the
//!    *same* window combine with one point addition. No bucket-array state is ever shared or
//!    merged across threads. (An earlier design gave each thread a private copy of *every*
//!    window's buckets and merged the copies elementwise; the merge cost
//!    `threads * NUM_WINDOWS * NUM_BUCKETS` serial additions, and dominated the profile past ~8
//!    cores.)
//! 3. The per-window partials are combined by one short Horner ladder
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
struct Term {
    point: MixedPoint,
    digits: [i16; NUM_WINDOWS],
}

impl Term {
    fn new(point: MixedPoint, scalar: &Scalar) -> Self {
        let digits: [i32; NUM_WINDOWS] = scalar.signed_digits(WIDTH);
        Self {
            point,
            digits: digits.map(|d| d as i16),
        }
    }
}

/// One past the highest bucket any of `terms`' digits in `window` lands in (`0` if none does,
/// i.e. the largest digit *magnitude*; see [`Scalar::signed_digits`]). Every bucket at or above
/// this is still the identity after a fill and would contribute nothing to the bucket fold, and
/// when `terms` is a small or sparse range -- a tiny batch, or the recoding's spare top window
/// -- that is *most* of the buckets. Computed as a standalone prescan over the recoded digits
/// (cheap: two byte-sized loads and a compare per term, no point arithmetic) rather than
/// tracked inside the bucket-fill loop, which measurably slows the fill's hot wave prologue.
fn used_buckets(terms: &[Term], window: usize) -> usize {
    terms
        .iter()
        .map(|term| term.digits[window].unsigned_abs() as usize)
        .max()
        .unwrap_or(0)
}

mod scalar {
    use super::{EdwardsPoint, NUM_BUCKETS, Term};

    /// Fills one window's buckets (`buckets[m - 1]` sums every, possibly negated, point whose
    /// digit in this window has magnitude `m`) via a single pass over `terms`, negating the point
    /// for a negative digit (cheap; see [`super::MixedPoint::negate`]). Bucket-fill additions use
    /// [`EdwardsPoint::add_mixed`] (7 field multiplies) rather than the general
    /// [`EdwardsPoint::add`] (9): every term is mixed-addition-eligible, since its point is
    /// always freshly decompressed (or the hardcoded basepoint), never the output of a prior
    /// addition or doubling.
    /// Fills one window's buckets (`buckets[m - 1]` sums every, possibly negated, point whose
    /// digit in this window has magnitude `m`) via a single pass over `terms`, negating the point
    /// for a negative digit (cheap; see [`super::MixedPoint::negate`]). Bucket-fill additions use
    /// [`EdwardsPoint::add_mixed`] (7 field multiplies) rather than the general
    /// [`EdwardsPoint::add`] (9): every term is mixed-addition-eligible, since its point is
    /// always freshly decompressed (or the hardcoded basepoint), never the output of a prior
    /// addition or doubling.
    fn window_buckets(terms: &[Term], window: usize) -> [EdwardsPoint; NUM_BUCKETS] {
        let mut buckets = [EdwardsPoint::IDENTITY; NUM_BUCKETS];
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

    /// One window's contribution to `terms`' MSM, *before* the doubling shift that positions it
    /// (see [`super::fold_window_partials`]).
    pub(super) fn window_partial(terms: &[Term], window: usize) -> EdwardsPoint {
        let used = super::used_buckets(terms, window);
        fold_buckets(&window_buckets(terms, window), used)
    }

    /// Computes the full MSM over `terms` via Pippenger's bucket method, one window at a time
    /// from the top down, interleaving each window's fill/fold with the `WIDTH` doublings that
    /// shift every window accumulated so far up one position.
    pub(super) fn multiscalar_mul(terms: &[Term]) -> EdwardsPoint {
        let mut result = EdwardsPoint::IDENTITY;
        for window in (0..super::NUM_WINDOWS).rev() {
            for _ in 0..super::WIDTH {
                result = result.double();
            }
            result = result.add(&window_partial(terms, window));
        }
        result
    }
}

mod transposed {
    use super::{EdwardsPoint, LANES, MixedPoint, NUM_BUCKETS, Term};
    use crate::signing::point::{MixedPointVec, PointVec};

    /// Every lane's buckets for one window: lane `l` owns the terms whose index is `l mod
    /// LANES`, plus this private bucket array, so the wave loop below can update `LANES` buckets
    /// with one vectorized addition and no two lanes ever collide on a bucket.
    type WindowBuckets = [[EdwardsPoint; NUM_BUCKETS]; LANES];

    /// Fills one window's [`WindowBuckets`] via one vectorized "wave" pass, one wave of `LANES`
    /// consecutive terms (one per lane) at a time: gather each lane's current bucket value (a
    /// scalar array read, cheap and branch-free since a digit of 0 just gathers-and-discards the
    /// identity), add the wave's incoming (possibly negated, for a negative digit) points via one
    /// vectorized [`PointVec::add_mixed`], then scatter the results back (again cheap scalar
    /// writes, skipped only for zero-digit lanes since there is no bucket to write into). A
    /// final short wave handles the `terms.len() % LANES` tail, its missing lanes riding along
    /// as no-op identity additions.
    #[allow(clippy::needless_range_loop)]
    fn window_buckets(terms: &[Term], window: usize) -> WindowBuckets {
        let identity_point = MixedPoint::new(&EdwardsPoint::IDENTITY);
        let mut buckets = [[EdwardsPoint::IDENTITY; NUM_BUCKETS]; LANES];
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

    /// One window's contribution to `terms`' MSM, *before* the doubling shift that positions it
    /// -- the vectorized counterpart of [`super::scalar::window_partial`], with the `LANES`
    /// per-lane partials summed down to a single point at the end (valid because MSM is linear
    /// in its terms).
    pub(super) fn window_partial(terms: &[Term], window: usize) -> EdwardsPoint {
        let used = super::used_buckets(terms, window);
        let buckets = window_buckets(terms, window);
        fold_buckets(PointVec::identity(), &buckets, used)
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }

    /// Computes the full MSM over `terms` via the lane-transposed Pippenger bucket method,
    /// window by window from the top down. Unlike [`window_partial`], the running `result` stays
    /// a [`PointVec`] across all windows -- the inter-window doublings run `LANES` wide, and the
    /// lanes are only summed down to a single point once, at the very end.
    ///
    /// `terms` must not be empty.
    pub(super) fn multiscalar_mul(terms: &[Term]) -> EdwardsPoint {
        debug_assert!(!terms.is_empty());

        let mut result = PointVec::identity();
        for window in (0..super::NUM_WINDOWS).rev() {
            for _ in 0..super::WIDTH {
                result = result.double();
            }
            let used = super::used_buckets(terms, window);
            let buckets = window_buckets(terms, window);
            result = fold_buckets(result, &buckets, used);
        }

        result
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }
}

/// Computes the full MSM over `terms` serially, dispatching to whichever of [`scalar`]'s or
/// [`transposed`]'s implementation is actually faster on the running CPU (see the module docs).
fn multiscalar_mul_terms(terms: &[Term]) -> EdwardsPoint {
    if !terms.is_empty() && field_vec::simd_available() {
        transposed::multiscalar_mul(terms)
    } else {
        scalar::multiscalar_mul(terms)
    }
}

/// Computes `sum(points[i] * scalars[i])` serially: the reference the differential tests below
/// compare every parallel path against (production callers all go through the parallel entry
/// points, which fall back to the same serial code for small or single-threaded inputs).
#[cfg(test)]
fn multiscalar_mul(points: &[MixedPoint], scalars: &[Scalar]) -> EdwardsPoint {
    debug_assert_eq!(points.len(), scalars.len());
    let terms: Vec<Term> = points
        .iter()
        .zip(scalars)
        .map(|(point, scalar)| Term::new(*point, scalar))
        .collect();
    multiscalar_mul_terms(&terms)
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

/// Splits `len` terms into as many contiguous, near-equal ranges as gives every thread
/// `strategy` actually has available a few `(window, range)` tiles to chew through -- enough
/// that work stealing evens out the tail without shrinking any range below [`MIN_RANGE_LEN`].
fn range_count(len: usize, strategy: &impl Strategy) -> usize {
    let parallelism = strategy.manual().parallelism();
    (3 * parallelism)
        .div_ceil(NUM_WINDOWS)
        .clamp(1, len.div_ceil(MIN_RANGE_LEN))
}

/// Computes the full MSM over `terms` with the bucket phase spread across `strategy`'s threads
/// as `(window, term range)` tiles (see the module docs' "Parallelization" section): each tile
/// fills and folds one window's buckets over one contiguous range of terms into a single partial
/// point, the tiles of each window are summed, and one short serial Horner ladder
/// ([`fold_window_partials`]) positions the windows.
fn multiscalar_mul_terms_parallel(terms: &[Term], strategy: &impl Strategy) -> EdwardsPoint {
    if terms.len() < MIN_PARALLEL_TERMS || strategy.manual().parallelism() <= 1 {
        return multiscalar_mul_terms(terms);
    }

    let range_len = terms.len().div_ceil(range_count(terms.len(), strategy));
    let simd = field_vec::simd_available();
    let tiles = (0..NUM_WINDOWS)
        .flat_map(|window| terms.chunks(range_len).map(move |range| (window, range)));
    let partials = strategy.map_collect_vec(tiles, |(window, range)| {
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

/// Parallel counterpart to [`multiscalar_mul`]; see [`multiscalar_mul_terms_parallel`] for how
/// this parallelizes. Digit recoding (one pass per scalar) is itself spread across `strategy`'s
/// threads before the bucket phase starts.
///
/// `points` and `scalars` must have equal length.
pub(crate) fn multiscalar_mul_parallel(
    points: &[MixedPoint],
    scalars: &[Scalar],
    strategy: &impl Strategy,
) -> EdwardsPoint {
    debug_assert_eq!(points.len(), scalars.len());
    let terms = strategy.map_collect_vec(points.iter().zip(scalars), |(point, scalar)| {
        Term::new(*point, scalar)
    });
    multiscalar_mul_terms_parallel(&terms, strategy)
}

/// Decompresses one chunk of raw point encodings into [`Term`]s (batching the decompression
/// arithmetic [`LANES`]-wide; see [`EdwardsPoint::decompress_batch`]), recoding each scalar's
/// digits in the same pass -- one unit of parallel work, so a decompressed point is always
/// consumed on the thread that produced it.
///
/// Returns `None` if any point in `bytes` fails to decompress.
fn decompress_terms(bytes: &[[u8; 32]], scalars: &[Scalar]) -> Option<Vec<Term>> {
    debug_assert_eq!(bytes.len(), scalars.len());
    let mut terms = Vec::with_capacity(bytes.len());
    for (chunk, scalar_chunk) in bytes.chunks(LANES).zip(scalars.chunks(LANES)) {
        if let Ok(chunk) = <[[u8; 32]; LANES]>::try_from(chunk) {
            let points = EdwardsPoint::decompress_batch(&chunk);
            for (point, scalar) in points.into_iter().zip(scalar_chunk) {
                terms.push(Term::new(MixedPoint::new(&point?), scalar));
            }
        } else {
            for (b, scalar) in chunk.iter().zip(scalar_chunk) {
                let point = EdwardsPoint::decompress(b)?;
                terms.push(Term::new(MixedPoint::new(&point), scalar));
            }
        }
    }
    Some(terms)
}

/// Floor on points per decompression chunk (a multiple of [`LANES`], so whole chunks feed
/// [`EdwardsPoint::decompress_batch`]): below this, per-chunk dispatch overhead stops being
/// amortized against the chunk's modular exponentiations.
const MIN_DECOMPRESS_CHUNK: usize = 64;

/// Parallel counterpart to [`decompress_terms`] plus [`multiscalar_mul_terms_parallel`]: every
/// `(bytes, scalars)` pair in `sources` is split into decompression chunks (sized from every
/// source's combined length, so the total chunk count across all sources -- not each source
/// individually -- targets a few chunks per thread), all sources' chunks are decompressed and
/// digit-recoded in one parallel pass, and the resulting flat term list (plus `extra`, when
/// present, as one more ordinary term) feeds the tile-parallel bucket phase.
///
/// Every `(bytes, scalars)` pair in `sources` must have equal-length `bytes`/`scalars`. Returns
/// `None` if any point across every source fails to decompress.
pub(crate) fn multiscalar_mul_from_bytes_parallel(
    sources: &[(&[[u8; 32]], &[Scalar])],
    extra: Option<(EdwardsPoint, Scalar)>,
    strategy: &impl Strategy,
) -> Option<EdwardsPoint> {
    let total_len: usize = sources.iter().map(|(bytes, _)| bytes.len()).sum();
    let parallelism = strategy.manual().parallelism();
    let chunk_size = total_len
        .div_ceil(2 * parallelism)
        .next_multiple_of(LANES)
        .max(MIN_DECOMPRESS_CHUNK);

    let mut chunks: Vec<(&[[u8; 32]], &[Scalar])> = Vec::new();
    for &(bytes, scalars) in sources {
        debug_assert_eq!(bytes.len(), scalars.len());
        chunks.extend(bytes.chunks(chunk_size).zip(scalars.chunks(chunk_size)));
    }

    let chunk_terms: Result<Vec<Vec<Term>>, ()> =
        strategy.try_map_collect_vec(chunks, |(bytes, scalars)| {
            decompress_terms(bytes, scalars).ok_or(())
        });
    let mut terms: Vec<Term> = chunk_terms.ok()?.into_iter().flatten().collect();
    if let Some((point, scalar)) = extra {
        terms.push(Term::new(MixedPoint::new(&point), &scalar));
    }

    Some(multiscalar_mul_terms_parallel(&terms, strategy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::scalar::test_support::rand_scalar;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey;
    use rand_core::Rng;

    /// A 32-byte encoding with no corresponding curve point (`y = 2`, for which `x^2 = u/v` has no
    /// square root -- see the module's differential tests below).
    const INVALID_POINT_BYTES: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 2;
        b
    };

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

    #[test]
    fn decompress_terms_matches_decompress_then_multiscalar_mul() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 8, 9, 32] {
            let bytes = valid_point_bytes(n);
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let points: Vec<MixedPoint> = bytes
                .iter()
                .map(|b| MixedPoint::new(&EdwardsPoint::decompress(b).unwrap()))
                .collect();
            let expected = multiscalar_mul(&points, &scalars);

            let terms = decompress_terms(&bytes, &scalars).unwrap();
            let actual = multiscalar_mul_terms(&terms);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn decompress_terms_rejects_invalid_point() {
        let bytes = [INVALID_POINT_BYTES];
        let scalars = [Scalar::from_u128(1)];
        assert!(decompress_terms(&bytes, &scalars).is_none());
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_matches_decompress_then_parallel() {
        let mut rng = test_rng();
        for sizes in [
            vec![0usize, 0],
            vec![1, 0],
            vec![0, 5],
            vec![3, 4],
            vec![300, 5],
            vec![256, 256, 1],
        ] {
            let sources_bytes: Vec<Vec<[u8; 32]>> =
                sizes.iter().map(|&n| valid_point_bytes(n)).collect();
            let sources_scalars: Vec<Vec<Scalar>> = sizes
                .iter()
                .map(|&n| (0..n).map(|_| rand_scalar(&mut rng)).collect())
                .collect();
            let extra_point = rand_affine_points(1)[0];
            let extra_scalar = rand_scalar(&mut rng);

            for extra in [None, Some((extra_point, extra_scalar))] {
                let mut expected_points: Vec<MixedPoint> = sources_bytes
                    .iter()
                    .flatten()
                    .map(|b| MixedPoint::new(&EdwardsPoint::decompress(b).unwrap()))
                    .collect();
                let mut expected_scalars: Vec<Scalar> =
                    sources_scalars.iter().flatten().copied().collect();
                if let Some((p, s)) = extra {
                    expected_points.push(MixedPoint::new(&p));
                    expected_scalars.push(s);
                }
                let expected =
                    multiscalar_mul_parallel(&expected_points, &expected_scalars, &Sequential);

                let sources: Vec<(&[[u8; 32]], &[Scalar])> = sources_bytes
                    .iter()
                    .zip(&sources_scalars)
                    .map(|(b, s)| (b.as_slice(), s.as_slice()))
                    .collect();
                let actual =
                    multiscalar_mul_from_bytes_parallel(&sources, extra, &Sequential).unwrap();
                assert!(actual.add(&expected.negate()).is_identity());
            }
        }
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_matches_under_real_parallelism() {
        // `Manual` disables the adaptive serial/parallel policy, forcing every call through actual
        // Rayon dispatch (rather than the policy falling back to serial for small inputs) -- this
        // and `tile_parallel_matches_serial_under_real_parallelism` are the only tests in the
        // module exercising genuine concurrent execution, since every other test uses
        // `Sequential`.
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();

        let mut rng = test_rng();
        let a_bytes = valid_point_bytes(600);
        let a_scalars: Vec<Scalar> = (0..600).map(|_| rand_scalar(&mut rng)).collect();
        let r_bytes = valid_point_bytes(500);
        let r_scalars: Vec<Scalar> = (0..500).map(|_| rand_scalar(&mut rng)).collect();
        let extra = (rand_affine_points(1)[0], rand_scalar(&mut rng));

        let mut expected_points: Vec<MixedPoint> = a_bytes
            .iter()
            .chain(&r_bytes)
            .map(|b| MixedPoint::new(&EdwardsPoint::decompress(b).unwrap()))
            .collect();
        let mut expected_scalars: Vec<Scalar> =
            a_scalars.iter().chain(&r_scalars).copied().collect();
        expected_points.push(MixedPoint::new(&extra.0));
        expected_scalars.push(extra.1);
        let expected = multiscalar_mul_parallel(&expected_points, &expected_scalars, &Sequential);

        let sources: Vec<(&[[u8; 32]], &[Scalar])> =
            vec![(&a_bytes, &a_scalars), (&r_bytes, &r_scalars)];
        let actual = multiscalar_mul_from_bytes_parallel(&sources, Some(extra), &strategy).unwrap();
        assert!(actual.add(&expected.negate()).is_identity());
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_rejects_invalid_point() {
        let bytes = vec![INVALID_POINT_BYTES];
        let scalars = vec![Scalar::from_u128(1)];
        let sources: Vec<(&[[u8; 32]], &[Scalar])> = vec![(&bytes, &scalars)];
        assert!(multiscalar_mul_from_bytes_parallel(&sources, None, &Sequential).is_none());
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
            let terms = rand_terms(n);
            let expected = scalar::multiscalar_mul(&terms);
            let actual = transposed::multiscalar_mul(&terms);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn parallel_matches_serial() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 32, 600] {
            let points: Vec<MixedPoint> =
                rand_affine_points(n).iter().map(MixedPoint::new).collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = multiscalar_mul(&points, &scalars);
            let actual = multiscalar_mul_parallel(&points, &scalars, &Sequential);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn tile_parallel_matches_serial_under_real_parallelism() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();

        let mut rng = test_rng();
        for n in [0, 1, 300, 600, 1000] {
            let points: Vec<MixedPoint> =
                rand_affine_points(n).iter().map(MixedPoint::new).collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = multiscalar_mul(&points, &scalars);
            let actual = multiscalar_mul_parallel(&points, &scalars, &strategy);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    /// Splitting a window's bucket fill across two disjoint sub-ranges and summing the partials
    /// must Horner-fold to the exact same point as running the whole MSM over the full range at
    /// once, for both backends -- this is the correctness argument the tile-parallel
    /// [`multiscalar_mul_terms_parallel`] relies on to combine same-window tiles with a single
    /// addition.
    #[test]
    fn split_window_partials_match_whole_range() {
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let terms = rand_terms(n);
            let (t1, t2) = terms.split_at(n / 2);

            let expected = multiscalar_mul_terms(&terms);

            let mut scalar_windows = [EdwardsPoint::IDENTITY; NUM_WINDOWS];
            let mut transposed_windows = [EdwardsPoint::IDENTITY; NUM_WINDOWS];
            for window in 0..NUM_WINDOWS {
                scalar_windows[window] =
                    scalar::window_partial(t1, window).add(&scalar::window_partial(t2, window));
                transposed_windows[window] = transposed::window_partial(t1, window)
                    .add(&transposed::window_partial(t2, window));
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
}
