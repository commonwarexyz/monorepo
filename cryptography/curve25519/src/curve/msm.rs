//! Backend kernels for variable-time multi-scalar multiplication.
//!
//! Backends own the bucket geometry and native lane arithmetic. Digit recoding, range
//! partitioning, and scheduling remain independent of that choice.

use super::{G, GAffine, GAffineVec, GBackend, GVec};
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Bucket filling, window recombination, and native lane dispatch for public scalar digits.
///
/// The bucket defaults use one stripe per logical lane and vector point arithmetic. Backends
/// with narrower physical tiles can override these kernels without changing MSM scheduling.
pub trait Backend: GBackend + Send + Sync {
    /// Independent bucket stripes, indexed by `stripe * nb + abs(digit) - 1`.
    ///
    /// Must be nonzero. The default fill requires [`super::LANES`] stripes. Override it for other
    /// geometries.
    const STRIPES: usize;

    /// Adds the projected points and signed digits to `Self::STRIPES * nb` buckets.
    ///
    /// Digits must have magnitude at most `nb`. Each wave assigns one term to each stripe,
    /// so updates within a wave cannot collide.
    fn fill_buckets<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (&GAffine, i16),
    ) {
        fill_buckets(
            |current, incoming, negative| {
                self.g_add_mixed(
                    GVec::transpose(current),
                    GAffineVec::from_signed_lanes(self, &incoming, &negative),
                )
                .untranspose()
            },
            buckets,
            nb,
            terms,
            term,
        );
    }

    /// Sums `(window, point)` partials, then Horner-folds the windows with `width` doublings.
    ///
    /// Window indices must be less than `windows`. Partials are added in their iteration order.
    fn combine_windows(
        self,
        partials: impl IntoIterator<Item = (usize, G)>,
        windows: usize,
        width: u32,
    ) -> G {
        let mut window_sums = vec![GVec::identity(); windows];
        for (window, partial) in partials {
            window_sums[window] = self.g_add(window_sums[window], GVec::splat(partial));
        }
        let mut result = GVec::identity();
        for window in window_sums.iter().rev() {
            for _ in 0..width {
                result = self.g_double(result);
            }
            result = self.g_add(result, *window);
        }
        result.untranspose()[0]
    }

    /// Runs a computation with the backend's native lane width and required CPU features.
    fn with_lanes<C: WithLanes>(self, computation: C) -> C::Output;
}

/// Native lane operations for variable-time multiplication of public scalar digits.
pub trait Lanes<const N: usize>: Copy {
    /// Extended points, one per native lane.
    type Point: Copy;

    /// Affine points, one per native lane.
    type Affine: Copy;

    /// Whether table construction should skip groups whose digits are all zero.
    const SKIP_ZERO_GROUPS: bool = false;

    /// Returns the identity in every lane.
    fn identity(self) -> Self::Point;

    /// Loads one affine point per lane.
    fn load(self, points: [&GAffine; N]) -> Self::Affine;

    /// Loads one extended point per lane.
    fn load_extended(self, points: [&G; N]) -> Self::Point;

    /// Adds an affine point to each extended lane.
    fn add_mixed(self, point: Self::Point, affine: Self::Affine) -> Self::Point;

    /// Adds the extended points in each lane.
    fn add(self, a: Self::Point, b: Self::Point) -> Self::Point;

    /// Doubles every extended lane.
    fn double(self, point: Self::Point) -> Self::Point;

    /// Adds each lane's signed table entry, indexed by its digit's magnitude.
    ///
    /// Every magnitude must be less than `table.len()`. Negation changes X and T only.
    fn add_signed(self, point: Self::Point, table: &[Self::Point], digits: [i16; N])
    -> Self::Point;

    /// Keeps the lanes `keep` selects and replaces every other lane with the identity.
    fn select(self, point: Self::Point, keep: [bool; N]) -> Self::Point;

    /// Returns the sum of the extended lanes.
    fn sum(self, point: Self::Point) -> G;
}

/// A computation generic over native lane widths and representations.
pub trait WithLanes {
    /// The result of the computation.
    type Output;

    /// Runs with the selected native lane operations.
    fn call<B: Lanes<N>, const N: usize>(self, backend: B) -> Self::Output;
}

/// Inputs to a Straus computation dispatched through [`Backend::with_lanes`].
pub struct Straus<'a, T, F> {
    terms: &'a [T],
    windows: usize,
    width: u32,
    term: F,
}

impl<'a, T, F: Fn(&T) -> (&GAffine, &[i16])> Straus<'a, T, F> {
    /// Describes the terms, digit geometry, and projection for [`straus`].
    pub const fn new(terms: &'a [T], windows: usize, width: u32, term: F) -> Self {
        Self {
            terms,
            windows,
            width,
            term,
        }
    }
}

impl<T, F: Fn(&T) -> (&GAffine, &[i16])> WithLanes for Straus<'_, T, F> {
    type Output = G;

    #[inline(always)]
    fn call<B: Lanes<N>, const N: usize>(self, backend: B) -> G {
        straus(backend, self.terms, self.windows, self.width, self.term)
    }
}

/// Returns the sum of each term's point times its signed digits in base `2^width`.
///
/// `N` must be nonzero. Every term must have at least `windows` digits, each with magnitude
/// at most `2^(width-1)`, and `width` must be in `1..usize::BITS`.
#[inline(always)]
pub fn straus<B: Lanes<N>, const N: usize, T>(
    backend: B,
    terms: &[T],
    windows: usize,
    width: u32,
    term: impl Fn(&T) -> (&GAffine, &[i16]),
) -> G {
    // Signed radix-2^width digits include both endpoints, -2^(width-1) and 2^(width-1).
    // Each group's table holds lane-wise multiples 0*P through 2^(width-1)*P, including
    // the identity at index zero, so it needs 2^(width-1) + 1 entries.
    let entries = (1usize << (width - 1)) + 1;
    let mut tables = Vec::with_capacity(terms.len().div_ceil(N) * entries);
    for group in terms.chunks(N) {
        // All-zero groups contribute the identity in every window. Their table slots remain
        // present so the table chunks retain the same order as the term groups.
        if B::SKIP_ZERO_GROUPS
            && group
                .iter()
                .all(|item| term(item).1[..windows].iter().all(|&digit| digit == 0))
        {
            tables.extend(core::iter::repeat_n(backend.identity(), entries));
            continue;
        }
        let mut points = [&GAffine::IDENTITY; N];
        for (point, item) in points.iter_mut().zip(group) {
            *point = term(item).0;
        }
        let points = backend.load(points);
        let mut multiple = backend.identity();
        tables.push(multiple);
        for _ in 1..entries {
            multiple = backend.add_mixed(multiple, points);
            tables.push(multiple);
        }
    }

    let mut accumulator = backend.identity();
    for window in (0..windows).rev() {
        // Horner evaluation shares one doubling chain across all terms. Multiplying the
        // accumulated higher windows by 2^width makes room for this window's digits.
        for _ in 0..width {
            accumulator = backend.double(accumulator);
        }
        for (group, table) in terms.chunks(N).zip(tables.chunks_exact(entries)) {
            let mut digits = [0; N];
            let mut any = false;
            for (digit, item) in digits.iter_mut().zip(group) {
                *digit = term(item).1[window];
                any |= *digit != 0;
            }

            // Missing lanes use digit zero. A group with no nonzero digit contributes only
            // identities, including the high windows of short coefficients.
            if !any {
                continue;
            }

            // A digit's magnitude selects its positive multiple. Edwards negation changes
            // X and T while preserving Y and Z, giving the signed multiple in each lane.
            accumulator = backend.add_signed(accumulator, table, digits);
        }
    }
    backend.sum(accumulator)
}

/// Adds each run in waves of one term per bucket stripe.
///
/// Missing or zero-digit lanes use identity inputs and never scatter a result. Entirely
/// zero waves skip group arithmetic, including the high windows of short coefficients.
/// Each piece may restart stripe assignment because the fold sums every stripe.
#[allow(clippy::needless_range_loop)]
pub fn fill_buckets<const STRIPES: usize, T>(
    add: impl Fn([G; STRIPES], [GAffine; STRIPES], [bool; STRIPES]) -> [G; STRIPES],
    buckets: &mut [G],
    nb: usize,
    terms: &[T],
    term: impl Fn(&T) -> (&GAffine, i16),
) {
    let identity_point = GAffine::IDENTITY;
    for wave in terms.chunks(STRIPES) {
        let mut incoming = [identity_point; STRIPES];
        let mut negative = [false; STRIPES];
        let mut current = [G::IDENTITY; STRIPES];
        let mut bucket_index = [None::<usize>; STRIPES];
        let mut any = false;
        for (lane, item) in wave.iter().enumerate() {
            let (point, digit) = term(item);
            if digit > 0 {
                bucket_index[lane] = Some(digit as usize - 1);
                incoming[lane] = *point;
            } else if digit < 0 {
                bucket_index[lane] = Some(digit.unsigned_abs() as usize - 1);
                incoming[lane] = *point;
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
        let updated = add(current, incoming, negative);
        for lane in 0..STRIPES {
            if let Some(i) = bucket_index[lane] {
                buckets[lane * nb + i] = updated[lane];
            }
        }
    }
}

/// Returns the sum of all stripes, weighting each bucket by its index plus one.
///
/// `used <= nb` is the largest nonzero digit magnitude. Buckets above it contribute nothing.
pub fn fold_buckets<B: Backend>(backend: B, buckets: &[G], nb: usize, used: usize) -> G {
    backend.with_lanes(Fold {
        buckets,
        nb,
        used,
        stripes: B::STRIPES,
    })
}

/// Inputs to [`fold`] dispatched through [`Backend::with_lanes`].
struct Fold<'a> {
    buckets: &'a [G],
    nb: usize,
    used: usize,
    stripes: usize,
}

impl WithLanes for Fold<'_> {
    type Output = G;

    #[inline(always)]
    fn call<B: Lanes<N>, const N: usize>(self, backend: B) -> G {
        fold(backend, self.buckets, self.nb, self.used, self.stripes)
    }
}

/// Weights and sums `stripes` bucket stripes, with `N` consecutive buckets in each vector.
///
/// Let `B[k, lane]` sum the stripes at bucket index `k*N + lane`. The descending pass builds
/// `sum[lane] = sum_k B[k, lane]` and `rows[lane] = sum_k k*B[k, lane]`, and the final weighting
/// gives `N*rows[lane] + (lane + 1)*sum[lane]`, so every bucket gets its index-plus-one weight.
/// Merging the stripes first lets each pair of running-sum additions cover `N` buckets. `N` must
/// be a power of two.
#[inline(always)]
fn fold<B: Lanes<N>, const N: usize>(
    backend: B,
    buckets: &[G],
    nb: usize,
    used: usize,
    stripes: usize,
) -> G {
    const { assert!(N.is_power_of_two()) };

    // A lone bucket has weight one, so its stripes only need summing.
    if used == 1 {
        let mut total = backend.identity();
        for first in (0..stripes).step_by(N) {
            let group = backend.load_extended(core::array::from_fn(|lane| {
                if first + lane < stripes {
                    &buckets[(first + lane) * nb]
                } else {
                    &G::IDENTITY
                }
            }));
            total = backend.add(total, group);
        }
        return backend.sum(total);
    }

    let mut sum = backend.identity();
    let mut rows = backend.identity();
    for block in (0..used.div_ceil(N)).rev() {
        let gather = |stripe: usize| {
            backend.load_extended(core::array::from_fn(|lane| {
                let index = block * N + lane;
                if index < used {
                    &buckets[stripe * nb + index]
                } else {
                    &G::IDENTITY
                }
            }))
        };
        let mut combined = gather(0);
        for stripe in 1..stripes {
            combined = backend.add(combined, gather(stripe));
        }
        rows = backend.add(rows, sum);
        sum = backend.add(sum, combined);
    }

    // Seed the row weight and the high bit of lane + 1. Doubling shifts both together.
    let top = core::array::from_fn(|lane| lane + 1 == N);
    let mut weighted = backend.add(rows, backend.select(sum, top));
    for bit in (0..N.ilog2()).rev() {
        weighted = backend.double(weighted);
        let keep = core::array::from_fn(|lane| (lane + 1) & (1 << bit) != 0);
        weighted = backend.add(weighted, backend.select(sum, keep));
    }
    backend.sum(weighted)
}

#[test]
fn fold_preserves_every_bucket_weight() {
    struct Check;
    impl crate::curve::WithBackend for Check {
        type Output = ();
        fn call<B: crate::curve::Backend>(self, backend: B) {
            let base = GAffine::BASEPOINT.to_extended();
            let torsion = GAffine::decompress(&[0; 32]).unwrap().to_extended();
            for width in [6, 7, 8, 9, 10] {
                let nb = 1usize << (width - 1);
                let mut point = base;
                let buckets: Vec<G> = (0..B::STRIPES * nb)
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
                        let bucket = (0..B::STRIPES).fold(G::IDENTITY, |sum, stripe| {
                            sum.add(buckets[stripe * nb + used - 1])
                        });
                        let weighted = bucket
                            .scalar_mul((0..usize::BITS).rev().map(|bit| used & (1 << bit) != 0));
                        expected = expected.add(weighted);
                    }
                    let actual = fold_buckets(backend, &buckets, nb, used);
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

/// Checks every bucket a backend fills against a scalar fill, with edge digits on every stripe.
#[test]
fn fill_matches_scalar_fill_for_edge_digits() {
    struct Check;
    impl crate::curve::WithBackend for Check {
        type Output = ();
        fn call<B: crate::curve::Backend>(self, backend: B) {
            let base = GAffine::BASEPOINT.to_extended();
            let torsion = GAffine::decompress(&[0; 32]).unwrap();
            let mixed = GAffine::decompress(&base.add(torsion.to_extended()).to_bytes()).unwrap();
            let points = [
                GAffine::IDENTITY,
                GAffine::BASEPOINT,
                torsion,
                mixed,
                GAffine::BASEPOINT,
            ];
            for width in [6, 10] {
                let nb = 1usize << (width - 1);
                let edge = nb as i16;
                let cycle = [1, -1, 2, -2, edge - 1, 1 - edge, edge, -edge, 0];

                // Sixteen zero digits, eight digits of `-nb`, each cycle digit on every stripe, and
                // five trailing digits of `nb`.
                let terms: Vec<(GAffine, i16)> = (0..16 + 8 + 72 + 5)
                    .map(|i| {
                        let digit = match i {
                            0..16 => 0,
                            16..24 => -edge,
                            24..96 => cycle[((i - 24) / 8 + (i - 24) % 8) % cycle.len()],
                            _ => edge,
                        };
                        (points[i % points.len()], digit)
                    })
                    .collect();
                for split in [0, 37] {
                    // Fill a scalar reference, restarting stripes at each piece.
                    let mut expected = vec![G::IDENTITY; B::STRIPES * nb];
                    for piece in [&terms[..split], &terms[split..]] {
                        for (j, &(point, digit)) in piece.iter().enumerate() {
                            if digit != 0 {
                                let point = point.to_extended();
                                let point = if digit < 0 { point.negate() } else { point };
                                let slot =
                                    (j % B::STRIPES) * nb + usize::from(digit.unsigned_abs()) - 1;
                                expected[slot] = expected[slot].add(point);
                            }
                        }
                    }

                    // Fill through the backend with a guard point after the last bucket.
                    let mut storage = vec![G::IDENTITY; B::STRIPES * nb + 1];
                    storage[B::STRIPES * nb] = base;
                    for piece in [&terms[..split], &terms[split..]] {
                        backend.fill_buckets(
                            &mut storage[..B::STRIPES * nb],
                            nb,
                            piece,
                            |(point, digit)| (point, *digit),
                        );
                    }
                    for (bucket, (actual, expected)) in storage.iter().zip(&expected).enumerate() {
                        assert!(
                            actual.add(expected.negate()).is_identity(),
                            "width={width} split={split} bucket={bucket}"
                        );
                    }
                    let guard = storage[B::STRIPES * nb];
                    assert_eq!(
                        [guard.x.0, guard.y.0, guard.t.0, guard.z.0],
                        [base.x.0, base.y.0, base.t.0, base.z.0],
                        "width={width} split={split}"
                    );
                }
            }
        }
    }
    crate::curve::WithBackend::call(Check, crate::curve::test_backend());
    crate::curve::with_backend(Check);
}
