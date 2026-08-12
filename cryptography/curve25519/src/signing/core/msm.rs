//! Variable-time Pippenger multi-scalar multiplication for batch signature verification.
//!
//! [`Term`]s arrive decompressed and recoded into signed digits. The bucket kernel processes
//! [`LANES`] terms at once, with one private bucket stripe per SIMD lane so updates never collide.
//!
//! [`multiscalar_mul`] exposes one execution shape for every [`Strategy`]: `(window, term range)`
//! tiles. A window can be split across several point ranges when there are fewer windows than
//! workers. Each strategy partition reuses private bucket scratch, tiles of the same window are
//! added together, and one short Horner fold positions the window sums.

use super::scalar::Scalar;
use crate::curve::{Backend, G, GAffine, GAffineVec, GVec, LANES};
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
    use super::{Backend, G, GAffine, GAffineVec, GVec, LANES, Term};
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    /// Every lane's buckets for one window, flattened lane-major (`buckets[lane * nb + m]`, with
    /// `nb = num_buckets(width)`): within each piece, lane `l` owns the terms whose index is
    /// `l mod LANES`, plus this private bucket stripe, so the wave loop below can update `LANES`
    /// buckets with one vectorized addition and no two lanes ever collide on a bucket.
    /// Heap-allocated because the width (and so the array size) is a per-batch runtime value.
    pub(super) fn identity_buckets(nb: usize) -> Vec<G> {
        vec![G::IDENTITY; LANES * nb]
    }

    /// Adds one contiguous run of terms into one window's bucket stripes via vectorized "wave"
    /// passes, one wave of `LANES` consecutive terms (one per lane) at a time: gather each
    /// lane's current bucket value (a scalar array read, cheap and branch-free since a digit of
    /// 0 just gathers-and-discards the identity), add the wave's incoming (possibly negated, for
    /// a negative digit) points via one vectorized backend mixed addition, then scatter the
    /// results back (again cheap scalar writes, skipped only for zero-digit lanes since there is
    /// no bucket to write into). A wave whose digits are *all* zero is skipped outright before
    /// any point arithmetic -- common, not rare: batch verification's `R` terms carry 128-bit
    /// coefficients, so every window above ~128 bits has zero digits for half the term sequence.
    /// The `terms.len() % LANES` tail rides as a short wave, its missing lanes no-op identity
    /// additions -- so a caller filling from several pieces pays at most one short wave per
    /// piece. Accumulating (rather than returning fresh buckets) is what lets those pieces share
    /// one bucket set and one fold.
    #[allow(clippy::needless_range_loop)]
    fn fill_buckets<B: Backend>(
        backend: B,
        buckets: &mut [G],
        nb: usize,
        terms: &[Term],
        window: usize,
    ) {
        let identity_point = GAffine::IDENTITY;
        for wave in terms.chunks(LANES) {
            let mut incoming = [identity_point; LANES];
            let mut negative = [false; LANES];
            let mut current = [G::IDENTITY; LANES];
            let mut bucket_index = [None::<usize>; LANES];
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
            let updated = backend
                .g_add_mixed(
                    GVec::transpose(current),
                    GAffineVec::from_signed_lanes(backend, &incoming, &negative),
                )
                .untranspose();
            for lane in 0..LANES {
                if let Some(i) = bucket_index[lane] {
                    buckets[lane * nb + i] = updated[lane];
                }
            }
        }
    }

    /// Folds `LANES` lanes' worth of one window's bucket stripes into `result` with the standard
    /// running-sum trick: starting below untouched top buckets is exact because identity buckets
    /// leave both the running sum and window sum unchanged.
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
            let bucket_group: [G; LANES] = core::array::from_fn(|lane| buckets[lane * nb + d]);
            sum = backend.g_add(sum, GVec::transpose(bucket_group));
            window_sum = backend.g_add(window_sum, sum);
        }
        backend.g_add(result, window_sum)
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
        debug_assert_eq!(buckets.len(), LANES * nb);
        buckets.fill(G::IDENTITY);
        let used = super::used_buckets(chunks, start, end, window);
        for piece in super::pieces(chunks, start, end) {
            fill_buckets(backend, buckets, nb, piece, window);
        }
        fold_buckets(backend, GVec::identity(), buckets, nb, used).sum_lanes(backend)
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
/// partial joins.
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

    let strategy = strategy.manual();
    let total = total_terms(chunks);
    let windows = num_windows(width);
    let ranges = partition_ranges(total, range_count(total, windows, strategy.parallelism()));
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
    let mut window_sums = vec![GVec::identity(); windows];
    for (window, partial) in partials {
        window_sums[window] = backend.g_add(window_sums[window], GVec::splat(partial));
    }
    let window_sums: Vec<G> = window_sums
        .into_iter()
        .map(|window| window.untranspose()[0])
        .collect();
    fold_windows(backend, &window_sums, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::core::scalar::test_support::rand_scalar;
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

    /// Returns `n` distinct affine points via [`valid_point_bytes`] and decompression.
    fn rand_affine_points(n: usize) -> Vec<GAffine> {
        valid_point_bytes(n)
            .iter()
            .map(|b| GAffine::decompress(b).unwrap())
            .collect()
    }

    /// Returns `n` [`Term`]s over random points and scalars, recoded at `width`.
    fn rand_terms(n: usize, width: u32) -> Vec<Term> {
        let mut rng = test_rng();
        rand_affine_points(n)
            .iter()
            .map(|p| Term::new(*p, &rand_scalar(&mut rng), width))
            .collect()
    }

    fn add_points(left: G, right: G) -> G {
        left.add(right)
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
        let backend = crate::curve::test_backend();
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 8, 9, 32, 64, 100] {
            let points = rand_affine_points(n);
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = points
                .iter()
                .zip(&scalars)
                .fold(G::IDENTITY, |acc, (point, scalar)| {
                    acc.add(point.to_extended().scalar_mul(scalar.bits_be()))
                });
            for width in TEST_WIDTHS {
                let actual = multiscalar_mul_points_serial(backend, &points, &scalars, width);
                assert!(points_equal(actual, expected), "n={n} width={width}");
            }
        }
    }

    /// Slice boundaries are pure layout: any split of the same terms (including `LANES`-unaligned
    /// and empty slices, whose tail waves pad with identity lanes) must produce the same point as
    /// one contiguous slice.
    #[test]
    fn chunked_matches_single_chunk() {
        let backend = crate::curve::test_backend();
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let terms = rand_terms(n, 7);
            let single = split_terms(rand_terms(n, 7), &[]);
            let mut chunks = split_terms(terms, &[1, 3, 7, 9, 24]);
            chunks.push(Vec::new());

            let expected = multiscalar_mul_terms_serial(backend, &refs(&single), 7);
            let actual = multiscalar_mul_terms_serial(backend, &refs(&chunks), 7);
            assert!(points_equal(actual, expected));
        }
    }

    #[test]
    fn strategy_path_matches_serial() {
        let backend = crate::curve::test_backend();
        for n in [0, 1, 2, 5, 32, 600] {
            for width in TEST_WIDTHS {
                let chunks = split_terms(rand_terms(n, width), &[64, 64, 64, 64]);
                let chunks = refs(&chunks);
                let expected = multiscalar_mul_terms_serial(backend, &chunks, width);
                let actual = multiscalar_mul(backend, &chunks, width, &Sequential);
                assert!(points_equal(actual, expected), "n={n} width={width}");
            }
        }
    }

    #[test]
    fn tile_parallel_matches_serial_under_real_parallelism() {
        let backend = crate::curve::test_backend();
        // `Manual` disables the adaptive serial/parallel policy, forcing every call through
        // actual Rayon dispatch (rather than the policy falling back to serial for small inputs).
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();

        for n in [0, 1, 300, 600, 1000] {
            for width in [6, 8, 10] {
                let chunks = split_terms(rand_terms(n, width), &[128, 128, 128, 128, 128, 128]);
                let chunks = refs(&chunks);
                let expected = multiscalar_mul_terms_serial(backend, &chunks, width);
                let actual = multiscalar_mul(backend, &chunks, width, &strategy);
                assert!(points_equal(actual, expected), "n={n} width={width}");
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
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let chunks = split_terms(rand_terms(n, WIDTH), &[n / 3, n / 3]);
            let chunks = refs(&chunks);
            let total = total_terms(&chunks);
            let mid = total / 2;

            let expected = multiscalar_mul_terms_serial(backend, &chunks, WIDTH);

            let nw = num_windows(WIDTH);
            let mut transposed_windows = vec![G::IDENTITY; nw];
            let mut buckets = transposed::identity_buckets(num_buckets(WIDTH));
            for (window, partial) in transposed_windows.iter_mut().enumerate() {
                *partial = add_points(
                    transposed::window_partial(
                        backend,
                        &chunks,
                        0,
                        mid,
                        window,
                        WIDTH,
                        &mut buckets,
                    ),
                    transposed::window_partial(
                        backend,
                        &chunks,
                        mid,
                        total,
                        window,
                        WIDTH,
                        &mut buckets,
                    ),
                );
            }

            assert!(points_equal(
                fold_windows(backend, &transposed_windows, WIDTH),
                expected,
            ));
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
