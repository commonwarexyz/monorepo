//! Backend kernels for variable-time multi-scalar multiplication.
//!
//! Backends own the bucket and table geometry and the point arithmetic. Digit recoding, range
//! partitioning, and scheduling remain independent of that choice.

use super::{G, GAffine, GAffineVec, GBackend, GVec, LANES};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Bucket filling, weighted folding, window recombination, and Straus accumulation for public
/// scalar digits.
///
/// The defaults use one bucket stripe per logical lane and vector point arithmetic. Backends
/// with narrower physical tiles can override these kernels without changing MSM scheduling.
pub trait Backend: GBackend + Send + Sync {
    /// Independent bucket stripes, indexed by `stripe * nb + abs(digit) - 1`.
    ///
    /// Must be nonzero. The default fill requires [`super::LANES`] stripes, and the default fold
    /// supports at most [`super::LANES`] stripes. Override those methods for other geometries.
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

    /// Returns the sum of all stripes, weighting each bucket by its index plus one.
    ///
    /// `used <= nb` is the largest nonzero digit magnitude. Buckets above it contribute nothing.
    #[inline(always)]
    fn fold_buckets(self, buckets: &[G], nb: usize, used: usize) -> G {
        fold_buckets(self, GVec::identity(), buckets, nb, used).sum_lanes(self)
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

    /// Returns the sum of every term's point times its digits read in base `2^width`, using
    /// Straus's method.
    ///
    /// Every term must have at least `windows` digits, each with magnitude at most
    /// `2^(width-1)`. The default keeps one table of multiples per group of [`super::LANES`]
    /// terms and adds every group into one shared accumulator.
    fn straus<T>(
        self,
        terms: &[T],
        windows: usize,
        width: u32,
        term: impl Fn(&T) -> (&GAffine, &[i16]),
    ) -> G {
        straus(self, terms, windows, width, term).sum_lanes(self)
    }
}

/// Accumulates [`Backend::straus`] into lanes whose sum is the result.
fn straus<B: GBackend, T>(
    backend: B,
    terms: &[T],
    windows: usize,
    width: u32,
    term: impl Fn(&T) -> (&GAffine, &[i16]),
) -> GVec {
    let entries = (1usize << (width - 1)) + 1;
    let tables: Vec<Vec<GVec>> = terms
        .chunks(LANES)
        .map(|group| {
            let points = GAffineVec::transpose(core::array::from_fn(|lane| {
                group
                    .get(lane)
                    .map_or(GAffine::IDENTITY, |item| *term(item).0)
            }));
            let mut multiple = GVec::identity();
            let mut table = Vec::with_capacity(entries);
            table.push(multiple);
            for _ in 1..entries {
                multiple = backend.g_add_mixed(multiple, points);
                table.push(multiple);
            }
            table
        })
        .collect();
    let mut accumulator = GVec::identity();
    let mut started = false;
    for window in (0..windows).rev() {
        if started {
            for _ in 0..width {
                accumulator = backend.g_double(accumulator);
            }
        }
        for (group, table) in terms.chunks(LANES).zip(&tables) {
            let digits: [i16; LANES] =
                core::array::from_fn(|lane| group.get(lane).map_or(0, |item| term(item).1[window]));
            if digits.iter().all(|&digit| digit == 0) {
                continue;
            }
            let index = digits.map(|digit| digit.unsigned_abs() as usize);
            let negative = digits.map(|digit| digit < 0);
            accumulator = backend.g_add(
                accumulator,
                GVec::select_signed(backend, table, &index, &negative),
            );
            started = true;
        }
    }
    accumulator
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

/// Folds each bucket stripe into its corresponding result lane with a running sum.
///
/// Lanes without a stripe contribute the identity. Untouched top buckets can be skipped
/// because their identity values leave both running sums unchanged.
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
            if lane < B::STRIPES {
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
                    let actual = backend.fold_buckets(&buckets, nb, used);
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

                // Two all-zero waves, a wave of `-nb` on every stripe, each cycle digit on every
                // stripe, and a partial wave of `nb`.
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
