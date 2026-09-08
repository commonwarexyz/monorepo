//! Backend bucket arithmetic for variable-time multi-scalar multiplication.
//!
//! Backends own the bucket geometry and point arithmetic. Digit recoding, range partitioning,
//! and scheduling remain independent of that choice.

use super::{G, GAffine, GAffineVec, GBackend, GVec, LANES};
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(all(test, not(feature = "std")))]
use alloc::vec::Vec;

/// Bucket filling, weighted folding, and window recombination for public scalar digits.
///
/// The defaults use one bucket stripe per logical lane and vector point arithmetic. Backends
/// with narrower physical tiles can override these kernels without changing MSM scheduling.
pub trait Backend: GBackend {
    /// Independent bucket stripes, indexed by `stripe * nb + abs(digit) - 1`.
    ///
    /// Override [`Self::fill_buckets`] when changing this from [`LANES`]. The default fold
    /// supports at most [`LANES`] stripes.
    const STRIPES: usize = LANES;

    /// Adds the projected points and signed digits to `Self::STRIPES * nb` buckets.
    ///
    /// Digits must have magnitude at most `nb`. Each wave assigns one term to each stripe,
    /// so updates within a wave cannot collide.
    fn fill_buckets<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (GAffine, i16),
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

    /// Returns lanes whose sum weights each bucket by its index plus one, across all stripes.
    ///
    /// `used <= nb` is the largest nonzero digit magnitude. Buckets above it contribute nothing.
    fn fold_buckets(self, buckets: &[G], nb: usize, used: usize) -> GVec {
        fold_buckets(self, GVec::identity(), buckets, nb, used)
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
    term: impl Fn(&T) -> (GAffine, i16),
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
                incoming[lane] = point;
            } else if digit < 0 {
                bucket_index[lane] = Some(digit.unsigned_abs() as usize - 1);
                incoming[lane] = point;
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
pub fn fold_buckets<B: Backend>(
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

#[cfg(test)]
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
                    let actual = backend.fold_buckets(&buckets, nb, used).sum_lanes(backend);
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
