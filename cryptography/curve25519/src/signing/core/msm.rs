//! Variable-time multi-scalar multiplication for batch signature verification.
//!
//! [`Term`]s arrive decompressed and recoded into signed digits. Small serial batches use
//! Straus's method, whose only per-window fixed cost is the shared doublings. Larger serial
//! batches and parallel batches use Pippenger's bucket method: the kernel processes one term
//! per private bucket stripe at once, so updates within each wave never collide.
//!
//! Bucket multiplication runs on strategy-supplied `(window, term range)` tiles. The strategy
//! cuts a window into term ranges only where the extra tile's fold pays for itself. Each worker
//! reuses private bucket scratch across its tiles. Tiles of the same window are added together,
//! and one short Horner fold positions the window sums.

use super::scalar::Scalar;
use crate::curve::{G, GAffine, LANES, msm::Backend};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;

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
/// `abs(digit)`, which ranges `1..=2^(width-1)`, half as many buckets as the `1..2^width` an
/// unsigned digit would need (see [`Scalar::signed_digits`]).
const fn num_buckets(width: u32) -> usize {
    1usize << (width - 1)
}

/// Picks the window width for a batch of `terms` MSM terms, run in parallel or serially: wider
/// windows mean fewer bucket-fill passes over the terms (the input-proportional cost) but a
/// bigger bucket array for every fill/fold instance to initialize, fold, and keep cache-resident.
///
/// Fit to a measured sweep (width 6-10 x batch 1k-64k signatures x 1/32 threads, AMD EPYC 9354P,
/// AVX-512): the optimum grows at almost exactly half a bit of width per bit of batch size,
/// shallower than the textbook `log2(terms) - 4` rule, because the wide-window penalty on real
/// hardware includes the AVX-512 bucket array (`8 * 2^(width-1)` points, ~320KB at width 9)
/// spilling L2, not just the fold-count arithmetic. Parallel runs want one step narrower than
/// serial: every concurrent batch holds its own bucket array, and a window split between batches
/// is folded once in each. Every prediction below matched the sweep's measured optimum (or a
/// runner-up within ~0.5%): serial 7/8/9/10 and parallel 7/8/9/9 for 1k/4k/16k/64k-signature
/// batches.
pub(super) fn width_for(terms: usize, parallel: bool) -> u32 {
    let bits = terms.max(2).ilog2();
    if parallel {
        ((bits + 3) / 2).clamp(MIN_WIDTH, MAX_WIDTH - 1)
    } else {
        ((bits + 4) / 2).clamp(MIN_WIDTH, MAX_WIDTH)
    }
}

/// One MSM term: a decompressed, mixed-addition-prepared point together with its scalar's signed
/// digits. The digits are recoded before the MSM, which then reads them once per window. Digits
/// are stored as `i16` (ample for any width up to 16) to keep the per-term footprint, and
/// therefore each pass's memory traffic, small; entries above the chosen width's window count
/// stay zero.
#[derive(Clone, Copy)]
pub(super) struct Term {
    point: GAffine,
    digits: [i16; MAX_WINDOWS],
}

impl Term {
    /// Recodes `scalar` at `width` (the batch-wide value from [`width_for`]; every term of one
    /// MSM must use the same width).
    pub(super) fn new(point: GAffine, scalar: &Scalar, width: u32) -> Self {
        let mut term = Self::zero(point);
        term.recode(scalar, width);
        term
    }

    /// A term for `point` with scalar zero.
    pub(super) const fn zero(point: GAffine) -> Self {
        Self {
            point,
            digits: [0; MAX_WINDOWS],
        }
    }

    /// Replaces this term's scalar with `scalar`, recoded as in [`Term::new`].
    pub(super) fn recode(&mut self, scalar: &Scalar, width: u32) {
        let digits: [i32; MAX_WINDOWS] = scalar.signed_digits(width);
        self.digits = digits.map(|d| d as i16);
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
/// the bucket fold. When the terms are a small or sparse range (a tiny batch, the recoding's
/// spare top window, or the windows above the digits of a short scalar such as a 128-bit batch
/// coefficient), that is *most* of the buckets. Computed as a standalone prescan over the
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

mod bucketed {
    use super::{Backend, G, Term};
    use crate::curve::msm::fold_buckets;
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    /// Independent bucket stripes that a worker reuses across tiles, with the largest digit
    /// magnitude its current tile has added (zero until the tile adds a nonzero digit).
    pub(super) struct Scratch {
        buckets: Vec<G>,
        used: usize,
    }

    impl Scratch {
        /// Allocates bucket stripes for windows of `width` bits.
        pub(super) fn new<B: Backend>(_: B, width: u32) -> Self {
            Self {
                buckets: vec![G::IDENTITY; B::STRIPES * super::num_buckets(width)],
                used: 0,
            }
        }

        /// Adds the digits of `window` over global term range `[start, end)` to the current
        /// tile.
        pub(super) fn fill<B: Backend>(
            &mut self,
            backend: B,
            chunks: &[&[Term]],
            start: usize,
            end: usize,
            window: usize,
            width: u32,
        ) {
            let used = super::used_buckets(chunks, start, end, window);
            if used == 0 {
                return;
            }

            // The tile's first nonzero digits clear the buckets the previous tile left behind.
            if self.used == 0 {
                self.buckets.fill(G::IDENTITY);
            }
            let nb = super::num_buckets(width);
            for piece in super::pieces(chunks, start, end) {
                backend.fill_buckets(&mut self.buckets, nb, piece, |term| {
                    (&term.point, term.digits[window])
                });
            }
            self.used = self.used.max(used);
        }

        /// Ends the current tile and returns its window's contribution, *before* the doubling
        /// shift that positions it. A tile without nonzero digits contributes the identity
        /// without a fold.
        pub(super) fn finish<B: Backend>(&mut self, backend: B, width: u32) -> G {
            match core::mem::take(&mut self.used) {
                0 => G::IDENTITY,
                used => fold_buckets(backend, &self.buckets, super::num_buckets(width), used),
            }
        }
    }

    /// Computes the full MSM with backend bucket filling and an independent scalar fold.
    /// One bucket allocation is reused across every window.
    #[cfg(test)]
    pub(super) fn multiscalar_mul_serial<B: Backend>(
        backend: B,
        chunks: &[&[Term]],
        width: u32,
    ) -> G {
        let nb = super::num_buckets(width);
        let total = super::total_terms(chunks);
        let mut result = G::IDENTITY;
        let mut buckets = vec![G::IDENTITY; B::STRIPES * nb];
        for window in (0..super::num_windows(width)).rev() {
            for _ in 0..width {
                result = result.double();
            }
            let used = super::used_buckets(chunks, 0, total, window);
            for piece in super::pieces(chunks, 0, total) {
                backend.fill_buckets(&mut buckets, nb, piece, |term| {
                    (&term.point, term.digits[window])
                });
            }
            let mut sum = G::IDENTITY;
            for digit in (0..used).rev() {
                for stripe in 0..B::STRIPES {
                    sum = sum.add(buckets[stripe * nb + digit]);
                }
                result = result.add(sum);
            }
            buckets.fill(G::IDENTITY);
        }

        result
    }
}

/// Computes the full MSM over `chunks` with an independent scalar fold.
#[cfg(test)]
fn multiscalar_mul_terms_serial<B: Backend>(backend: B, chunks: &[&[Term]], width: u32) -> G {
    bucketed::multiscalar_mul_serial(backend, chunks, width)
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

/// Serial batches below this term count use Straus's method, whose only per-window fixed cost is
/// the shared doublings, rather than the bucket method's per-window fold.
const STRAUS_TERM_CUTOFF: usize = 384;

/// Parallel batches below this term count split Straus across workers. Parallel bucket batches
/// add a fold for every window they share, so Straus stays cheaper for longer there.
const PARALLEL_STRAUS_TERM_CUTOFF: usize = 1024;

/// Straus's method (see [`crate::curve::msm::straus`]) over `terms`.
fn straus<B: Backend>(backend: B, terms: &[&Term], width: u32) -> G {
    backend.with_lanes(crate::curve::msm::Straus::new(
        terms,
        num_windows(width),
        width,
        |term| (&term.point, term.digits.as_slice()),
    ))
}

/// A bucket tile's fixed cost, in terms: folding its buckets. Merging the stripes and updating two
/// running sums takes about `STRIPES + 1` additions per bucket, on lanes where each addition
/// fills one term per stripe.
const fn tile_cost<B: Backend>(width: u32) -> NonZeroUsize {
    NZUsize!(num_buckets(width) * (B::STRIPES + 1))
}

/// The window at tile row `slot`. Low and high windows alternate: short scalars leave the high
/// windows sparse, and a worker starts on a share of consecutive rows, so each share should mix
/// cheap and expensive windows.
const fn interleaved_window(slot: usize, windows: usize) -> usize {
    if slot.is_multiple_of(2) {
        slot / 2
    } else {
        windows - 1 - slot / 2
    }
}

/// Pippenger's bucket method over `chunks`. Each strategy-supplied `(window, term range)` tile
/// fills its window's buckets piece by piece and folds them once, the partials of each window are
/// added, and the backend positions the window sums.
fn buckets<B: Backend>(backend: B, chunks: &[&[Term]], width: u32, strategy: &impl Strategy) -> G {
    let windows = num_windows(width);
    let total = total_terms(chunks);
    let partials = strategy.run_tiles(windows, total, tile_cost::<B>(width), 1, |tiles| {
        tiles.fill_collect_vec(
            || bucketed::Scratch::new(backend, width),
            |scratch, slot, range| {
                let window = interleaved_window(slot, windows);
                scratch.fill(backend, chunks, range.start, range.end, window, width);
            },
            |scratch, slot| {
                let window = interleaved_window(slot, windows);
                (window, scratch.finish(backend, width))
            },
        )
    });
    backend.combine_windows(partials, windows, width)
}

/// Computes the full MSM over `chunks`, whose terms were recoded at `width` (see [`width_for`] and
/// [`Term::new`]). From [`PARALLEL_STRAUS_TERM_CUTOFF`] terms, [`buckets`] runs its tiles serially
/// or in parallel. Below it, the strategy chooses between a serial body, which uses [`straus`]
/// below [`STRAUS_TERM_CUTOFF`] and [`buckets`] above it, and Straus split across workers.
pub(super) fn multiscalar_mul<B: Backend>(
    backend: B,
    chunks: &[&[Term]],
    width: u32,
    strategy: &impl Strategy,
) -> G {
    let total = total_terms(chunks);
    if total >= PARALLEL_STRAUS_TERM_CUTOFF {
        return buckets(backend, chunks, width, strategy);
    }
    let terms = || -> Vec<&Term> { pieces(chunks, 0, total).flatten().collect() };
    strategy.run(
        total,
        || {
            if total < STRAUS_TERM_CUTOFF {
                return straus(backend, &terms(), width);
            }
            buckets(backend, chunks, width, &Sequential)
        },
        || {
            // Consecutive lane groups split into contiguous parts, one per strategy batch, each
            // with its own accumulator.
            let terms = terms();
            strategy
                .run_batches(total.div_ceil(LANES), NonZeroUsize::MIN, LANES, |batches| {
                    batches.map_collect_vec(
                        |ranges| ranges,
                        |groups| {
                            let part =
                                &terms[groups.start * LANES..(groups.end * LANES).min(total)];
                            straus(backend, part, width)
                        },
                    )
                })
                .into_iter()
                .fold(G::IDENTITY, G::add)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Backend;
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz::Builder;
    use commonware_parallel::Sequential;
    use rand_core::Rng as _;

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

    /// Expands one drawn seed into enough bytes for every draw a test makes, so its points and
    /// scalars stay random however short the fuzzer's input is.
    fn expand(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
        let mut bytes = vec![0; 1 << 19];
        commonware_utils::TestRng::new(u.arbitrary()?).fill_bytes(&mut bytes);
        Ok(bytes)
    }

    fn points_equal(actual: G, expected: G) -> bool {
        actual.add(expected.negate()).is_identity()
    }

    /// Splits `terms` into owned chunks of the given (deliberately uneven, stripe-unaligned)
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
        // The sweep's measured optima (see `width_for`'s doc comment), as (signatures, parallel,
        // width): terms per batch are ~2 * signatures + 1.
        for (sigs, parallel, expected) in [
            (1024, true, 7),
            (4096, true, 8),
            (16384, true, 9),
            (65536, true, 9),
            (1024, false, 7),
            (4096, false, 8),
            (16384, false, 9),
            (65536, false, 10),
        ] {
            assert_eq!(
                width_for(2 * sigs + 1, parallel),
                expected,
                "sigs={sigs} parallel={parallel}"
            );
        }
        // Clamps: tiny batches never drop below MIN_WIDTH, huge parallel batches never exceed
        // MAX_WIDTH - 1 (bucket footprint), huge serial batches never exceed MAX_WIDTH.
        assert_eq!(width_for(1, true), MIN_WIDTH);
        assert_eq!(width_for(usize::MAX, true), MAX_WIDTH - 1);
        assert_eq!(width_for(usize::MAX, false), MAX_WIDTH);
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
            .with_search_limit(1)
            .test(|u| {
                let bytes = expand(u)?;
                let u = &mut Unstructured::new(&bytes);
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

    /// Slice boundaries are pure layout: any split of the same terms (including stripe-unaligned
    /// and empty slices, whose tail waves pad with identity lanes) must produce the same point as
    /// one contiguous slice.
    #[test]
    fn chunked_matches_single_chunk() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let bytes = expand(u)?;
                        let u = &mut Unstructured::new(&bytes);
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
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    #[test]
    fn strategy_path_matches_serial() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let bytes = expand(u)?;
                        let u = &mut Unstructured::new(&bytes);
                        for width in TEST_WIDTHS {
                            let terms = arbitrary_terms(u, 600, width)?;
                            let cutoff = STRAUS_TERM_CUTOFF;
                            for n in [0, 1, 2, 5, 32, cutoff - 1, cutoff, 600] {
                                let chunks = split_terms(terms[..n].to_vec(), &[64, 64, 64, 64]);
                                let chunks = refs(&chunks);
                                let expected =
                                    multiscalar_mul_terms_serial(backend, &chunks, width);
                                let actual = multiscalar_mul(backend, &chunks, width, &Sequential);
                                assert!(points_equal(actual, expected), "n={n} width={width}");
                            }
                        }
                        Ok(())
                    });
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    #[test]
    fn straus_matches_serial_across_lane_boundaries() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let bytes = expand(u)?;
                        let u = &mut Unstructured::new(&bytes);
                        for width in [6, 8, 10] {
                            let terms = arbitrary_terms(u, 383, width)?;
                            for n in [1, 7, 8, 9, 16, 17, 33, 383] {
                                let expected =
                                    multiscalar_mul_terms_serial(backend, &[&terms[..n]], width);
                                let refs: Vec<&Term> = terms[..n].iter().collect();
                                let sequential = straus(backend, &refs, width);
                                assert!(points_equal(sequential, expected), "n={n} width={width}");
                            }
                        }
                        Ok(())
                    });
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    /// Straus over hand-picked digits matches an independent Horner evaluation exactly, so
    /// torsion components are checked too.
    #[test]
    fn straus_matches_horner_for_edge_digits() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                let base = GAffine::BASEPOINT.to_extended();
                let torsion = GAffine::decompress(&[0; 32]).unwrap();
                let mixed =
                    GAffine::decompress(&base.add(torsion.to_extended()).to_bytes()).unwrap();
                let points = [GAffine::BASEPOINT, torsion, GAffine::IDENTITY, mixed];
                for width in TEST_WIDTHS {
                    let nb = num_buckets(width) as i16;
                    let windows = num_windows(width);
                    let cycle = [0, 1, -1, 2, -2, nb - 1, 1 - nb, nb, -nb];

                    // The top window and window 1 are zero for every term, so every kernel skips
                    // all of their groups. Window 2 is `-nb` in every lane.
                    let terms: Vec<Term> = (0..17)
                        .map(|i| Term {
                            point: points[i % points.len()],
                            digits: core::array::from_fn(|window| match window {
                                1 => 0,
                                2 => -nb,
                                _ if window + 1 >= windows => 0,
                                _ => cycle[(i + window) % cycle.len()],
                            }),
                        })
                        .collect();

                    // Evaluate each term's digits by Horner's rule with scalar arithmetic.
                    let values: Vec<G> = terms
                        .iter()
                        .map(|term| {
                            let point = term.point.to_extended();
                            (0..windows).rev().fold(G::IDENTITY, |acc, window| {
                                let acc = (0..width).fold(acc, |acc, _| acc.double());
                                let digit = term.digits[window];
                                let magnitude = digit.unsigned_abs();
                                let multiple = point.scalar_mul(
                                    (0..width).rev().map(|bit| magnitude & (1 << bit) != 0),
                                );
                                acc.add(if digit < 0 {
                                    multiple.negate()
                                } else {
                                    multiple
                                })
                            })
                        })
                        .collect();
                    for n in [1, 2, 3, 7, 8, 9, 16, 17] {
                        let terms = &terms[..n];
                        let expected = values[..n]
                            .iter()
                            .fold(G::IDENTITY, |sum, &value| sum.add(value));
                        let direct = backend.with_lanes(crate::curve::msm::Straus::new(
                            terms,
                            windows,
                            width,
                            |term| (&term.point, term.digits.as_slice()),
                        ));
                        let refs: Vec<&Term> = terms.iter().collect();
                        assert!(points_equal(direct, expected), "n={n} width={width}");
                        assert!(
                            points_equal(straus(backend, &refs, width), expected),
                            "n={n} width={width}"
                        );
                    }
                }
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    #[test]
    fn tile_parallel_matches_serial_under_real_parallelism() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                // `Manual` disables the adaptive serial/parallel policy, forcing every call
                // through Rayon dispatch. Planning parallelism above the pool size makes more
                // shares than threads, so shares straddle windows and threads that finish take
                // halves of the shares still pending, cutting windows at arbitrary terms.
                let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
                    .unwrap()
                    .with_parallelism(commonware_utils::NZUsize!(32))
                    .manual();

                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let bytes = expand(u)?;
                        let u = &mut Unstructured::new(&bytes);
                        for width in [6, 8, 10] {
                            let terms = arbitrary_terms(u, 1100, width)?;
                            for n in [0, 1, 300, 1024, 1100] {
                                let chunks = split_terms(
                                    terms[..n].to_vec(),
                                    &[128, 128, 128, 128, 128, 128],
                                );
                                let chunks = refs(&chunks);
                                let expected =
                                    multiscalar_mul_terms_serial(backend, &chunks, width);
                                let actual = multiscalar_mul(backend, &chunks, width, &strategy);
                                assert!(points_equal(actual, expected), "n={n} width={width}");
                            }
                        }
                        Ok(())
                    });
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    #[test]
    fn window_partials_reuse_scratch_across_zero_windows() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                let point = GAffine::BASEPOINT;
                for width in TEST_WIDTHS {
                    let scalar = Scalar::from_u128((1u128 << (2 * width)) | 1);
                    let terms = [Term::new(point, &scalar, width)];
                    let mut scratch = bucketed::Scratch::new(backend, width);
                    for (window, expected) in
                        [point.to_extended(), G::IDENTITY, point.to_extended()]
                            .into_iter()
                            .enumerate()
                    {
                        scratch.fill(backend, &[&terms], 0, terms.len(), window, width);
                        let actual = scratch.finish(backend, width);
                        assert!(
                            points_equal(actual, expected),
                            "window={window} width={width}"
                        );
                    }
                }
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    /// Splitting a window's bucket fill at an arbitrary global index (deliberately not a slice
    /// boundary), either into two tiles whose partials are added or into two pieces of one tile,
    /// must Horner-fold to the exact same point as running the whole MSM over the full range at
    /// once. This is the correctness argument the tile-parallel [`multiscalar_mul`] relies on to
    /// combine same-window tiles with a single addition and to fill a tile in pieces.
    #[test]
    fn split_window_partials_match_whole_range() {
        struct Check;
        impl crate::curve::WithBackend for Check {
            type Output = ();
            fn call<B: Backend>(self, backend: B) {
                const WIDTH: u32 = 7;
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let bytes = expand(u)?;
                        let u = &mut Unstructured::new(&bytes);
                        let terms = arbitrary_terms(u, 100, WIDTH)?;
                        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
                            let chunks = split_terms(terms[..n].to_vec(), &[n / 3, n / 3]);
                            let chunks = refs(&chunks);
                            let total = total_terms(&chunks);
                            let mid = total / 2;

                            let expected = multiscalar_mul_terms_serial(backend, &chunks, WIDTH);

                            let nw = num_windows(WIDTH);
                            let mut split = vec![G::IDENTITY; nw];
                            let mut pieced = vec![G::IDENTITY; nw];
                            let mut scratch = bucketed::Scratch::new(backend, WIDTH);
                            for window in 0..nw {
                                scratch.fill(backend, &chunks, 0, mid, window, WIDTH);
                                let left = scratch.finish(backend, WIDTH);
                                scratch.fill(backend, &chunks, mid, total, window, WIDTH);
                                split[window] = left.add(scratch.finish(backend, WIDTH));

                                scratch.fill(backend, &chunks, 0, mid, window, WIDTH);
                                scratch.fill(backend, &chunks, mid, total, window, WIDTH);
                                pieced[window] = scratch.finish(backend, WIDTH);
                            }

                            for partials in [split, pieced] {
                                assert!(points_equal(
                                    backend.combine_windows(
                                        partials.into_iter().enumerate(),
                                        nw,
                                        WIDTH
                                    ),
                                    expected,
                                ));
                            }
                        }
                        Ok(())
                    });
            }
        }
        crate::curve::WithBackend::call(Check, crate::curve::test_backend());
        crate::curve::with_backend(Check);
    }

    /// [`pieces`] must hand back exactly the requested global range, in order, for any cut,
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
}
