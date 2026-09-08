//! Variable-time Pippenger multi-scalar multiplication for batch signature verification.
//!
//! [`Term`]s arrive decompressed and recoded into signed digits. The bucket kernel processes
//! one term per private bucket stripe at once, so updates within each wave never collide.
//!
//! [`multiscalar_mul`] exposes one execution shape for every [`Strategy`]: `(window, term range)`
//! tiles. A window can be split across several point ranges when there are fewer windows than
//! workers. Each strategy partition reuses private bucket scratch, tiles of the same window are
//! added together, and one short Horner fold positions the window sums.

use super::scalar::Scalar;
#[cfg(not(target_arch = "aarch64"))]
use crate::curve::GAffineVec;
use crate::curve::{Backend, G, GAffine, GVec, LANES};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
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
/// hardware includes the AVX-512 bucket array (`8 * 2^(width-1)` points, ~320KB at width 9)
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
#[derive(Clone, Copy)]
pub(super) struct Term {
    point: GAffine,
    digits: [i16; MAX_WINDOWS],
}

impl Term {
    /// Recodes `scalar` at `width` (the batch-wide value from [`width_for`]; every term of one
    /// MSM must use the same width).
    pub(super) fn new(point: GAffine, scalar: &Scalar, width: u32) -> Self {
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

mod transposed {
    #[cfg(not(target_arch = "aarch64"))]
    use super::GAffineVec;
    use super::{Backend, G, GAffine, GVec, LANES, Term};

    // NEON fills one stripe per physical mixed-addition lane, keeping wave updates independent.
    // Folds retain LANES independent bucket indices.
    #[cfg(target_arch = "aarch64")]
    const STRIPES: usize = 2;
    #[cfg(not(target_arch = "aarch64"))]
    const STRIPES: usize = LANES;
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    /// Independent bucket stripes, indexed by `stripe * nb + abs(digit) - 1`.
    ///
    /// Each wave assigns one term to each stripe, so updates within a wave cannot collide.
    /// Heap allocation accommodates the per-batch bucket count.
    pub(super) fn identity_buckets(nb: usize) -> Vec<G> {
        vec![G::IDENTITY; STRIPES * nb]
    }

    /// Adds each run in waves of one term per bucket stripe.
    ///
    /// Missing or zero-digit lanes use identity inputs and never scatter a result. Entirely
    /// zero waves skip group arithmetic, including the high windows of short coefficients.
    /// Each piece may restart stripe assignment because the fold sums every stripe.
    #[allow(clippy::needless_range_loop)]
    fn fill_buckets<B: Backend>(
        backend: B,
        buckets: &mut [G],
        nb: usize,
        terms: &[Term],
        window: usize,
    ) {
        let identity_point = GAffine::IDENTITY;
        for wave in terms.chunks(STRIPES) {
            let mut incoming = [identity_point; STRIPES];
            let mut negative = [false; STRIPES];
            let mut current = [G::IDENTITY; STRIPES];
            let mut bucket_index = [None::<usize>; STRIPES];
            let mut any = false;
            for (lane, term) in wave.iter().enumerate() {
                let digit = term.digits[window];
                if digit > 0 {
                    bucket_index[lane] = Some(digit as usize - 1);
                    incoming[lane] = term.point;
                } else if digit < 0 {
                    bucket_index[lane] = Some(digit.unsigned_abs() as usize - 1);
                    incoming[lane] = term.point;
                    negative[lane] = true;
                }
                if let Some(i) = bucket_index[lane] {
                    current[lane] = buckets[lane * nb + i];
                    any = true;
                }
            }
            if !any {
                continue;
            }
            #[cfg(target_arch = "aarch64")]
            let updated = backend.g_add_mixed_pair(current, incoming, negative);
            #[cfg(not(target_arch = "aarch64"))]
            let updated = backend
                .g_add_mixed(
                    GVec::transpose(current),
                    GAffineVec::from_signed_lanes(backend, &incoming, &negative),
                )
                .untranspose();
            for lane in 0..STRIPES {
                if let Some(i) = bucket_index[lane] {
                    buckets[lane * nb + i] = updated[lane];
                }
            }
        }
    }

    /// Folds each bucket stripe into its corresponding result lane with a running sum.
    ///
    /// Lanes without a stripe contribute the identity. Untouched top buckets can be skipped
    /// because their identity values leave both running sums unchanged.
    #[cfg(any(test, not(target_arch = "aarch64")))]
    fn fold_buckets<B: Backend>(
        backend: B,
        result: GVec,
        buckets: &[G],
        nb: usize,
        used: usize,
    ) -> GVec {
        let mut sum = GVec::identity();
        let mut window_sum = GVec::identity();
        for d in (0..used).rev() {
            let bucket_group: [G; LANES] = core::array::from_fn(|lane| {
                if lane < STRIPES {
                    buckets[lane * nb + d]
                } else {
                    G::IDENTITY
                }
            });
            sum = backend.g_add(sum, GVec::transpose(bucket_group));
            window_sum = backend.g_add(window_sum, sum);
        }
        backend.g_add(result, window_sum)
    }

    /// Returns lanes whose sum is the weighted sum of all bucket stripes.
    ///
    /// Let `B[k, lane]` sum the stripes at bucket index `k*LANES + lane`. The descending pass
    /// builds `sum[lane] = sum_k B[k, lane]` and `rows[lane] = sum_k k*B[k, lane]`.
    /// Final weighting gives `LANES*rows[lane] + (lane + 1)*sum[lane]`, assigning each bucket
    /// its index-plus-one weight. The lane count is a power of two.
    #[cfg(target_arch = "aarch64")]
    fn fold_buckets_merged<B: Backend>(backend: B, buckets: &[G], nb: usize, used: usize) -> GVec {
        // A single used bucket has weight one, so return the stripes without weighting.
        if used == 1 {
            return GVec::transpose(core::array::from_fn(|lane| {
                if lane < STRIPES {
                    buckets[lane * nb]
                } else {
                    G::IDENTITY
                }
            }));
        }
        let mut sum = GVec::identity();
        let mut rows = GVec::identity();
        for block in (0..used.div_ceil(LANES)).rev() {
            let gather = |stripe: usize| {
                GVec::transpose(core::array::from_fn(|lane| {
                    let digit = block * LANES + lane;
                    if digit < used {
                        buckets[stripe * nb + digit]
                    } else {
                        G::IDENTITY
                    }
                }))
            };
            let mut combined = gather(0);
            for stripe in 1..STRIPES {
                combined = backend.g_add(combined, gather(stripe));
            }
            rows = backend.g_add(rows, sum);
            sum = backend.g_add(sum, combined);
        }

        // Seed the high bit of lane + 1, then fold its remaining bits.
        let lanes = sum.untranspose();
        let mut weighted = GVec::transpose(core::array::from_fn(|lane| {
            if lane == LANES - 1 {
                lanes[lane]
            } else {
                G::IDENTITY
            }
        }));
        for bit in (0..3).rev() {
            rows = backend.g_double(rows);
            weighted = backend.g_double(weighted);
            let selected = core::array::from_fn(|lane| {
                if (lane + 1) & (1 << bit) != 0 {
                    lanes[lane]
                } else {
                    G::IDENTITY
                }
            });
            weighted = backend.g_add(weighted, GVec::transpose(selected));
        }
        backend.g_add(rows, weighted)
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    mod merged_tests {
        use super::*;

        #[test]
        fn merged_fold_preserves_every_bucket_weight() {
            struct Check;
            impl crate::curve::WithBackend for Check {
                type Output = ();
                fn call<B: Backend>(self, backend: B) {
                    let base = GAffine::BASEPOINT.to_extended();
                    let torsion = GAffine::decompress(&[0; 32]).unwrap().to_extended();
                    for width in [6, 7, 8, 9, 10] {
                        let nb = super::super::num_buckets(width);
                        let mut point = base;
                        let buckets: Vec<G> = (0..STRIPES * nb)
                            .map(|i| {
                                point = point.add(base);
                                match i % 7 {
                                    0 => torsion,
                                    1 => point.add(torsion),
                                    2 => point.negate(),
                                    3 => G::IDENTITY,
                                    _ => point,
                                }
                            })
                            .collect();
                        let mut expected = G::IDENTITY;
                        for used in 0..=nb {
                            if used != 0 {
                                let bucket = (0..STRIPES).fold(G::IDENTITY, |sum, stripe| {
                                    sum.add(buckets[stripe * nb + used - 1])
                                });
                                let weighted = bucket.scalar_mul(
                                    (0..usize::BITS).rev().map(|bit| used & (1 << bit) != 0),
                                );
                                expected = expected.add(weighted);
                            }
                            let actual =
                                fold_buckets_merged(backend, &buckets, nb, used).sum_lanes(backend);
                            assert!(
                                actual.add(expected.negate()).is_identity(),
                                "width={width} used={used}"
                            );
                        }
                    }
                }
            }
            crate::curve::WithBackend::call(Check, crate::curve::test_backend());
            crate::curve::with_backend(Check);
        }
    }

    /// One window's contribution to the MSM over global term range `[start, end)`, *before* the
    /// doubling shift that positions it -- the vectorized counterpart of
    /// the scalar bucket algorithm, with the `LANES` per-lane partials summed down to a
    /// single point at the end (valid because MSM is linear in its terms).
    pub(super) fn window_partial<B: Backend>(
        backend: B,
        chunks: &[&[Term]],
        start: usize,
        end: usize,
        window: usize,
        width: u32,
        buckets: &mut [G],
    ) -> G {
        let nb = super::num_buckets(width);
        debug_assert_eq!(buckets.len(), STRIPES * nb);
        let used = super::used_buckets(chunks, start, end, window);
        if used == 0 {
            // An all-zero window contributes the identity without resetting or folding scratch.
            return G::IDENTITY;
        }
        buckets.fill(G::IDENTITY);
        for piece in super::pieces(chunks, start, end) {
            fill_buckets(backend, buckets, nb, piece, window);
        }
        #[cfg(target_arch = "aarch64")]
        let partial = fold_buckets_merged(backend, buckets, nb, used);
        #[cfg(not(target_arch = "aarch64"))]
        let partial = fold_buckets(backend, GVec::identity(), buckets, nb, used);
        partial.sum_lanes(backend)
    }

    /// Computes the full MSM over `chunks` via the lane-transposed Pippenger bucket method,
    /// window by window from the top down. Unlike [`window_partial`], the running `result` stays
    /// a [`GVec`] across all windows -- the inter-window doublings run `LANES` wide, and the
    /// lanes are only summed down to a single point once, at the very end. One bucket allocation
    /// is reused (re-set to the identity) across every window.
    #[cfg(test)]
    pub(super) fn multiscalar_mul_serial<B: Backend>(
        backend: B,
        chunks: &[&[Term]],
        width: u32,
    ) -> G {
        let nb = super::num_buckets(width);
        let total = super::total_terms(chunks);
        let mut result = GVec::identity();
        let mut buckets = identity_buckets(nb);
        for window in (0..super::num_windows(width)).rev() {
            for _ in 0..width {
                result = backend.g_double(result);
            }
            let used = super::used_buckets(chunks, 0, total, window);
            for piece in super::pieces(chunks, 0, total) {
                fill_buckets(backend, &mut buckets, nb, piece, window);
            }
            result = fold_buckets(backend, result, &buckets, nb, used);
            buckets.fill(G::IDENTITY);
        }

        result.sum_lanes(backend)
    }
}

/// Computes the full MSM over `chunks` serially using the backend's transposed lanes.
#[cfg(test)]
fn multiscalar_mul_terms_serial<B: Backend>(backend: B, chunks: &[&[Term]], width: u32) -> G {
    transposed::multiscalar_mul_serial(backend, chunks, width)
}

/// Computes `sum(points[i] * scalars[i])` serially: the reference the differential tests below
/// compare the strategy-generic path against.
#[cfg(test)]
fn multiscalar_mul_points_serial<B: Backend>(
    backend: B,
    points: &[GAffine],
    scalars: &[Scalar],
    width: u32,
) -> G {
    debug_assert_eq!(points.len(), scalars.len());
    let terms: Vec<Term> = points
        .iter()
        .zip(scalars)
        .map(|(point, scalar)| Term::new(*point, scalar, width))
        .collect();
    multiscalar_mul_terms_serial(backend, &[&terms], width)
}

/// Horner-folds per-window partial sums into the final MSM result: from the top window down,
/// `width` doublings shift everything accumulated so far up one window, then the next window's
/// partial joins. Scalar recombination computes each point once, avoiding duplicate SIMD lanes.
#[cfg(target_arch = "aarch64")]
fn fold_windows<B: Backend>(_: B, windows: &[G], width: u32) -> G {
    let mut result = G::IDENTITY;
    for window in windows.iter().rev() {
        for _ in 0..width {
            result = result.double();
        }
        result = result.add(*window);
    }
    result
}

#[cfg(not(target_arch = "aarch64"))]
fn fold_windows<B: Backend>(backend: B, windows: &[G], width: u32) -> G {
    let mut result = GVec::identity();
    for window in windows.iter().rev() {
        for _ in 0..width {
            result = backend.g_double(result);
        }
        result = backend.g_add(result, GVec::splat(*window));
    }
    result.untranspose()[0]
}

/// Floor on terms per tile range: a shorter range's fixed per-tile cost (folding the bucket
/// array down to a partial point) stops being amortized by its fill work.
const MIN_RANGE_LEN: usize = 64;

/// Target number of independently schedulable tiles per worker.
const TILES_PER_WORKER: usize = 3;

/// How many contiguous ranges to split `len` terms into: enough that every thread `strategy`
/// actually has available gets a few `(window, range)` tiles to chew through (so work stealing
/// evens out the tail), without shrinking any range below [`MIN_RANGE_LEN`].
fn range_count(len: usize, windows: usize, parallelism: usize) -> usize {
    let max_ranges = (len / MIN_RANGE_LEN).max(1);
    parallelism
        .saturating_mul(TILES_PER_WORKER)
        .div_ceil(windows)
        .clamp(1, max_ranges)
}

/// Cuts the global term-index space `[0, total)` into up to `ranges` near-equal contiguous
/// ranges. Ranges are pure index arithmetic -- [`pieces`] resolves them onto the underlying
/// slices at read time -- so a cut may land anywhere, including mid-slice.
fn partition_ranges(total: usize, ranges: usize) -> Vec<(usize, usize)> {
    if total == 0 {
        return Vec::new();
    }
    let ranges = ranges.min(total);
    let range_len = total / ranges;
    let remainder = total % ranges;
    let mut result = Vec::with_capacity(ranges);
    let mut start = 0;
    for range in 0..ranges {
        let len = range_len + usize::from(range < remainder);
        result.push((start, start + len));
        start += len;
    }
    result
}

/// Computes the full MSM over `chunks` (whose terms were recoded at `width`; see [`width_for`]
/// and [`Term::new`]) with the bucket phase spread across `strategy`'s threads as
/// `(window, global term range)` tiles. Each tile reduces to one point, same-window points are
/// added, and [`fold_windows`] positions the resulting window sums.
pub(super) fn multiscalar_mul<B: Backend>(
    backend: B,
    chunks: &[&[Term]],
    width: u32,
    strategy: &impl Strategy,
) -> G {
    #[derive(Clone, Copy)]
    struct Tile {
        window: usize,
        start: usize,
        end: usize,
    }

    let parallelism = strategy.manual().parallelism();
    let total = total_terms(chunks);
    let windows = num_windows(width);
    let ranges = partition_ranges(total, range_count(total, windows, parallelism));
    let mut tiles = Vec::with_capacity(windows * ranges.len());
    for &(start, end) in &ranges {
        for window in 0..windows {
            tiles.push(Tile { window, start, end });
        }
    }
    let buckets = num_buckets(width);
    let partials = strategy.map_init_collect_vec(
        tiles,
        || transposed::identity_buckets(buckets),
        |scratch, tile| {
            let partial = transposed::window_partial(
                backend,
                chunks,
                tile.start,
                tile.end,
                tile.window,
                width,
                scratch,
            );
            (tile.window, partial)
        },
    );
    #[cfg(target_arch = "aarch64")]
    let window_sums = {
        let mut window_sums = vec![G::IDENTITY; windows];
        for (window, partial) in partials {
            window_sums[window] = window_sums[window].add(partial);
        }
        window_sums
    };
    #[cfg(not(target_arch = "aarch64"))]
    let window_sums = {
        let mut window_sums = vec![GVec::identity(); windows];
        for (window, partial) in partials {
            window_sums[window] = backend.g_add(window_sums[window], GVec::splat(partial));
        }
        window_sums
            .into_iter()
            .map(|window| window.untranspose()[0])
            .collect::<Vec<_>>()
    };
    fold_windows(backend, &window_sums, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz::Builder;
    use commonware_parallel::Sequential;

    /// The widths every differential test sweeps: [`width_for`]'s full output range.
    const TEST_WIDTHS: [u32; 5] = [6, 7, 8, 9, 10];

    /// Returns `n` affine points selected directly from arbitrary encodings. Invalid encodings
    /// map to one of the two basic subgroup edge cases so every input remains usable.
    fn arbitrary_affine_points(
        u: &mut Unstructured<'_>,
        n: usize,
    ) -> arbitrary::Result<Vec<GAffine>> {
        (0..n)
            .map(|_| {
                let bytes: [u8; 32] = u.arbitrary()?;
                Ok(GAffine::decompress(&bytes).unwrap_or_else(|| {
                    if bytes[0] & 1 == 0 {
                        GAffine::IDENTITY
                    } else {
                        GAffine::BASEPOINT
                    }
                }))
            })
            .collect()
    }

    /// Returns `n` [`Term`]s over arbitrary points and scalars, recoded at `width`.
    fn arbitrary_terms(
        u: &mut Unstructured<'_>,
        n: usize,
        width: u32,
    ) -> arbitrary::Result<Vec<Term>> {
        arbitrary_affine_points(u, n)?
            .into_iter()
            .map(|point| {
                let scalar: Scalar = u.arbitrary()?;
                Ok(Term::new(point, &scalar, width))
            })
            .collect()
    }

    fn points_equal(actual: G, expected: G) -> bool {
        actual.add(expected.negate()).is_identity()
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
        struct Compute<'a> {
            points: &'a [GAffine],
            scalars: &'a [Scalar],
            width: u32,
        }

        impl crate::curve::WithBackend for Compute<'_> {
            type Output = G;

            fn call<B: Backend>(self, backend: B) -> G {
                multiscalar_mul_points_serial(backend, self.points, self.scalars, self.width)
            }
        }

        let backend = crate::curve::test_backend();
        Builder::default()
            .with_seed(0)
            .with_search_limit(8)
            .test(|u| {
                let points = arbitrary_affine_points(u, 100)?;
                let scalars = (0..100)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<Vec<Scalar>>>()?;

                for n in [0, 1, 2, 5, 8, 9, 32, 64, 100] {
                    let points = &points[..n];
                    let scalars = &scalars[..n];
                    let expected =
                        points
                            .iter()
                            .zip(scalars)
                            .fold(G::IDENTITY, |acc, (point, scalar)| {
                                acc.add(point.to_extended().scalar_mul(scalar.bits_be()))
                            });
                    for width in TEST_WIDTHS {
                        let actual = multiscalar_mul_points_serial(backend, points, scalars, width);
                        assert!(points_equal(actual, expected), "n={n} width={width}");
                        let accelerated = crate::curve::with_backend(Compute {
                            points,
                            scalars,
                            width,
                        });
                        assert!(points_equal(accelerated, expected), "n={n} width={width}");
                    }
                }
                Ok(())
            });
    }

    /// Slice boundaries are pure layout: any split of the same terms (including `LANES`-unaligned
    /// and empty slices, whose tail waves pad with identity lanes) must produce the same point as
    /// one contiguous slice.
    #[test]
    fn chunked_matches_single_chunk() {
        let backend = crate::curve::test_backend();
        Builder::default()
            .with_seed(0)
            .with_search_limit(8)
            .test(|u| {
                let terms = arbitrary_terms(u, 100, 7)?;
                for n in [1, 2, 5, 8, 9, 32, 64, 100] {
                    let terms = terms[..n].to_vec();
                    let single = split_terms(terms.clone(), &[]);
                    let mut chunks = split_terms(terms, &[1, 3, 7, 9, 24]);
                    chunks.push(Vec::new());

                    let expected = multiscalar_mul_terms_serial(backend, &refs(&single), 7);
                    let actual = multiscalar_mul_terms_serial(backend, &refs(&chunks), 7);
                    assert!(points_equal(actual, expected));
                }
                Ok(())
            });
    }

    #[test]
    fn strategy_path_matches_serial() {
        let backend = crate::curve::test_backend();
        Builder::default()
            .with_seed(0)
            .with_search_limit(2)
            .test(|u| {
                for width in TEST_WIDTHS {
                    let terms = arbitrary_terms(u, 600, width)?;
                    for n in [0, 1, 2, 5, 32, 600] {
                        let chunks = split_terms(terms[..n].to_vec(), &[64, 64, 64, 64]);
                        let chunks = refs(&chunks);
                        let expected = multiscalar_mul_terms_serial(backend, &chunks, width);
                        let actual = multiscalar_mul(backend, &chunks, width, &Sequential);
                        assert!(points_equal(actual, expected), "n={n} width={width}");
                    }
                }
                Ok(())
            });
    }

    #[test]
    fn tile_parallel_matches_serial_under_real_parallelism() {
        let backend = crate::curve::test_backend();
        // `Manual` disables the adaptive serial/parallel policy, forcing every call through
        // actual Rayon dispatch (rather than the policy falling back to serial for small inputs).
        // Planning parallelism above the pool size splits every width below into several term
        // ranges, which the assertion inside the loop pins.
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .with_parallelism(commonware_utils::NZUsize!(32))
            .manual();

        Builder::default()
            .with_seed(0)
            .with_search_limit(2)
            .test(|u| {
                for width in [6, 8, 10] {
                    let terms = arbitrary_terms(u, 1000, width)?;
                    assert!(
                        range_count(terms.len(), num_windows(width), strategy.parallelism()) > 1
                    );
                    for n in [0, 1, 300, 600, 1000] {
                        let chunks =
                            split_terms(terms[..n].to_vec(), &[128, 128, 128, 128, 128, 128]);
                        let chunks = refs(&chunks);
                        let expected = multiscalar_mul_terms_serial(backend, &chunks, width);
                        let actual = multiscalar_mul(backend, &chunks, width, &strategy);
                        assert!(points_equal(actual, expected), "n={n} width={width}");
                    }
                }
                Ok(())
            });
    }

    #[test]
    fn window_partials_reuse_scratch_across_zero_windows() {
        let backend = crate::curve::test_backend();
        let point = GAffine::BASEPOINT;
        for width in TEST_WIDTHS {
            let scalar = Scalar::from_u128((1u128 << (2 * width)) | 1);
            let terms = [Term::new(point, &scalar, width)];
            let mut buckets = transposed::identity_buckets(num_buckets(width));
            for (window, expected) in [point.to_extended(), G::IDENTITY, point.to_extended()]
                .into_iter()
                .enumerate()
            {
                let actual = transposed::window_partial(
                    backend,
                    &[&terms],
                    0,
                    terms.len(),
                    window,
                    width,
                    &mut buckets,
                );
                assert!(
                    points_equal(actual, expected),
                    "window={window} width={width}"
                );
            }
        }
    }

    /// Splitting a window's bucket fill at an arbitrary global index (deliberately not a slice
    /// boundary) and summing the two partials must Horner-fold to the exact same point as
    /// running the whole MSM over the full range at once -- this is the
    /// correctness argument the tile-parallel [`multiscalar_mul`] relies on to
    /// combine same-window tiles with a single addition.
    #[test]
    fn split_window_partials_match_whole_range() {
        let backend = crate::curve::test_backend();
        const WIDTH: u32 = 7;
        Builder::default()
            .with_seed(0)
            .with_search_limit(8)
            .test(|u| {
                let terms = arbitrary_terms(u, 100, WIDTH)?;
                for n in [1, 2, 5, 8, 9, 32, 64, 100] {
                    let chunks = split_terms(terms[..n].to_vec(), &[n / 3, n / 3]);
                    let chunks = refs(&chunks);
                    let total = total_terms(&chunks);
                    let mid = total / 2;

                    let expected = multiscalar_mul_terms_serial(backend, &chunks, WIDTH);

                    let nw = num_windows(WIDTH);
                    let mut transposed_windows = vec![G::IDENTITY; nw];
                    let mut buckets = transposed::identity_buckets(num_buckets(WIDTH));
                    for (window, partial) in transposed_windows.iter_mut().enumerate() {
                        let left = transposed::window_partial(
                            backend,
                            &chunks,
                            0,
                            mid,
                            window,
                            WIDTH,
                            &mut buckets,
                        );
                        let right = transposed::window_partial(
                            backend,
                            &chunks,
                            mid,
                            total,
                            window,
                            WIDTH,
                            &mut buckets,
                        );
                        *partial = left.add(right);
                    }

                    assert!(points_equal(
                        fold_windows(backend, &transposed_windows, WIDTH),
                        expected,
                    ));
                }
                Ok(())
            });
    }

    /// [`pieces`] must hand back exactly the requested global range, in order, for any cut --
    /// including cuts inside slices, across slice boundaries, and touching empty slices.
    #[test]
    fn pieces_covers_exact_global_ranges() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(8)
            .test(|u| {
                let chunks = split_terms(arbitrary_terms(u, 50, 7)?, &[1, 7, 0, 24]);
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
                Ok(())
            });
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
