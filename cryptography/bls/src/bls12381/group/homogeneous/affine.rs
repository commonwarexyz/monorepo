// Adapted from VROOM src/ec.hpp.
// Copyright 2026 Simon Langowski
// SPDX-License-Identifier: MIT

//! Finite affine inputs for homogeneous MSM buckets.

use super::{G1Point, G2Point};
use crate::bls12381::{
    Fp,
    extension::{
        Fp2,
        bounded::{Fp2Ready, Fp2Ring, Fp2Standard},
    },
    group::{G1, G2, msm},
};
use alloc::vec::Vec;
use commonware_cryptography_vroom::{
    Backend, Bls12381,
    rns::{Ready, Ring, Standard},
};
use subtle::{Choice, ConditionallySelectable};

const PREFIX_SCRATCH_BYTES: usize = 192 * 1024;

macro_rules! invert_product {
    (base, $product:expr, $base:expr) => {
        $base.invert($product)
    };
    (fp2, $product:expr, $base:expr) => {
        Fp2::from($product).invert().map(Fp2Standard::from)
    };
}

macro_rules! affine {
    (
        $name:ident, $group:ident, $point:ident, $field:ty, $standard:ty, $ready:ty,
        $chunk:literal, chains[$($chain:literal),*], $invert:ident,
        $base:ident, $ring:ident = $ring_value:expr, $value:ident => $mul_3b:expr
    ) => {
        const _: () = assert!($chunk * core::mem::size_of::<$standard>() <= PREFIX_SCRATCH_BYTES);

        #[derive(Clone, Copy)]
        #[cfg_attr(target_arch = "x86_64", repr(align(64)))]
        pub(in crate::bls12381::group) struct $name {
            x: $standard,
            y: $standard,
        }

        impl $name {
            // Interleaved product chains per chunk. One multiplication is a
            // dependency chain longer than its issue time, so a batch of this
            // many independent products keeps the vector units busy.
            const CHAINS: usize = [$($chain,)*].len();


            /// Consumes the indexed terms and returns only finite affine terms.
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn normalize<B: Backend>(
                points: &[$group],
                terms: Vec<msm::Term<usize>>,
                $base: &Ring<Bls12381, B>,
            ) -> Vec<msm::Term<Self>> {
                let $ring = $ring_value;
                let mut normalized = Vec::with_capacity(terms.len());
                let mut prefixes = Vec::with_capacity($chunk);
                let mut finite = Vec::new();
                for chunk in terms.chunks($chunk) {
                    // Identity inputs are rare, so a chunk is first converted as if
                    // every Z were finite. A zero product reveals an identity, and
                    // only then is the chunk redone with the per-term test.
                    if Self::convert(points, chunk, &[], &mut normalized, &mut prefixes, $base) {
                        continue;
                    }
                    finite.clear();
                    finite.extend(chunk.iter().map(|term| {
                        !bool::from($ring.is_zero(<$standard>::from(points[term.point].z)))
                    }));
                    let converted =
                        Self::convert(points, chunk, &finite, &mut normalized, &mut prefixes, $base);
                    debug_assert!(converted);
                }
                normalized
            }

            /// Converts one chunk, treating terms flagged non-finite as ones and
            /// omitting them. Returns false when the chunk contains an identity
            /// that `finite` did not flag.
            #[cfg_attr(not(debug_assertions), inline(always))]
            fn convert<B: Backend>(
                points: &[$group],
                chunk: &[msm::Term<usize>],
                finite: &[bool],
                normalized: &mut Vec<msm::Term<Self>>,
                prefixes: &mut Vec<$standard>,
                $base: &Ring<Bls12381, B>,
            ) -> bool {
                let $ring = $ring_value;
                let one: $standard = <$field>::ONE.into();
                let is_finite = |i: usize| i < chunk.len() && (finite.is_empty() || finite[i]);
                let coordinate = |i: usize, coordinate: fn(&$group) -> $field| -> $standard {
                    if is_finite(i) {
                        coordinate(&points[chunk[i].point]).into()
                    } else {
                        one
                    }
                };
                let point_at = |i: usize| chunk.get(i).map(|term| &points[term.point]);

                // Rows of CHAINS terms form independent product chains; a short
                // tail row is padded with ones.
                let rows = chunk.len().div_ceil(Self::CHAINS);
                prefixes.clear();
                prefixes.resize(rows * Self::CHAINS, one);
                for row in 0..rows {
                    for lane in 0..Self::CHAINS {
                        if let Some(point) = point_at((row + 2) * Self::CHAINS + lane) {
                            msm::prefetch(&point.z);
                        }
                    }
                    let z: [$standard; Self::CHAINS] =
                        core::array::from_fn(|lane| coordinate(row * Self::CHAINS + lane, |point| point.z));
                    let start = row * Self::CHAINS;
                    if row == 0 {
                        prefixes[..Self::CHAINS].copy_from_slice(&z);
                    } else {
                        let previous = prefixes[start - Self::CHAINS..start].try_into().unwrap();
                        let next = Self::products(&previous, &z, $base);
                        prefixes[start..start + Self::CHAINS].copy_from_slice(&next);
                    }
                }

                // One inversion serves every chain: each chain total is inverted
                // through the products of the other totals.
                let totals: [$standard; Self::CHAINS] =
                    prefixes[(rows - 1) * Self::CHAINS..].try_into().unwrap();
                let mut product = totals[0];
                for total in &totals[1..] {
                    product = $ring.mul(product, *total);
                }
                let Some(inverse) = invert_product!($invert, product, $base) else {
                    return false;
                };
                let mut before = [one; Self::CHAINS];
                for lane in 1..Self::CHAINS {
                    before[lane] = $ring.mul(before[lane - 1], totals[lane - 1]);
                }
                let mut after = [one; Self::CHAINS];
                for lane in (0..Self::CHAINS - 1).rev() {
                    after[lane] = $ring.mul(after[lane + 1], totals[lane + 1]);
                }
                let mut inverses = Self::products(&before, &after, $base);
                inverses = Self::products(&inverses, &[inverse; Self::CHAINS], $base);

                // Reverse recovery appends terms backwards, then reverses this suffix.
                let output_start = normalized.len();
                for row in (0..rows).rev() {
                    for lane in 0..Self::CHAINS {
                        if let Some(point) = row.checked_sub(2).and_then(|row| point_at(row * Self::CHAINS + lane)) {
                            msm::prefetch(point);
                        }
                    }
                    let start = row * Self::CHAINS;
                    let z: [$standard; Self::CHAINS] =
                        core::array::from_fn(|lane| coordinate(start + lane, |point| point.z));
                    let inverse_z = if row == 0 {
                        inverses
                    } else {
                        let previous = prefixes[start - Self::CHAINS..start].try_into().unwrap();
                        Self::products(&inverses, &previous, $base)
                    };
                    if row != 0 {
                        inverses = Self::products(&inverses, &z, $base);
                    }

                    // Finite Jacobian coordinates represent X/Z^2 and Y/Z^3.
                    let x: [$standard; Self::CHAINS] =
                        core::array::from_fn(|lane| coordinate(start + lane, |point| point.x));
                    let y: [$standard; Self::CHAINS] =
                        core::array::from_fn(|lane| coordinate(start + lane, |point| point.y));
                    let inverse_z_squared = Self::products(&inverse_z, &inverse_z, $base);
                    let x = Self::products(&x, &inverse_z_squared, $base);
                    let inverse_z_cubed = Self::products(&inverse_z_squared, &inverse_z, $base);
                    let y = Self::products(&y, &inverse_z_cubed, $base);
                    for lane in (0..Self::CHAINS).rev() {
                        let i = start + lane;
                        if is_finite(i) {
                            normalized.push(msm::Term {
                                point: Self { x: x[lane], y: y[lane] },
                                scalar: chunk[i].scalar,
                            });
                        }
                    }
                }
                normalized[output_start..].reverse();
                true
            }

            /// Multiplies lane pairs in one reduction batch.
            #[cfg_attr(not(debug_assertions), inline(always))]
            fn products<B: Backend>(
                a: &[$standard; Self::CHAINS],
                b: &[$standard; Self::CHAINS],
                $base: &Ring<Bls12381, B>,
            ) -> [$standard; Self::CHAINS] {
                let $ring = $ring_value;
                $ring.batch_reduce_expand(&[$(
                    $ring.ready::<800>($ring.prep_left(a[$chain]) * b[$chain]),
                )*])
            }

            /// VROOM PointMixedAdd, ec.hpp:228-269 (RCB Algorithm 8), lines 1-5:
            /// the five products awaiting reduction. The sign is applied without
            /// a branch, which a data-dependent digit would mispredict.
            #[cfg_attr(not(debug_assertions), inline(always))]
            fn front<B: Backend>(
                &self,
                bucket: &$point,
                negative: bool,
                $base: &Ring<Bls12381, B>,
            ) -> [$ready; 5] {
                let $ring = $ring_value;
                let y = <$standard>::conditional_select(
                    &self.y,
                    &$ring.standard_negate(self.y),
                    Choice::from(negative as u8),
                );
                let t3_4 = bucket.x + bucket.y;
                let t4_5 = self.x + y;
                [
                    $ring.ready::<800>($ring.prep_left(bucket.x) * self.x),
                    $ring.ready::<800>($ring.prep_left(bucket.y) * y),
                    $ring.ready::<800>($ring.prep_left(t3_4) * $ring.prep(t4_5)),
                    $ring.ready::<800>($ring.prep_left(bucket.z) * y),
                    $ring.ready::<800>($ring.prep_left(bucket.z) * self.x),
                ]
            }

            /// RCB Algorithm 8 lines 6-32: the coordinates awaiting reduction.
            #[cfg_attr(not(debug_assertions), inline(always))]
            fn back<B: Backend>(
                bucket: &$point,
                [t0_1, t1_2, t3_6, t5_11, x3_16]: [$standard; 5],
                $base: &Ring<Bls12381, B>,
            ) -> [$ready; 3] {
                let $ring = $ring_value;
                let t4_7 = t0_1 + t1_2;
                let y3_18 = x3_16 + bucket.x;
                let $value = bucket.z;
                let t2_21 = $mul_3b;

                let t3_8 = $ring.prep(t3_6 - t4_7);
                let $value = y3_18;
                let y3_24 = $ring.prep($mul_3b);
                let z3_22 = $ring.prep(t1_2 + t2_21);
                let t1_23 = $ring.prep_left(t1_2 - t2_21);
                let t4_13 = $ring.prep_left(t5_11 + bucket.y);
                let x3_19 = t0_1 + t0_1;
                let t0_20 = $ring.prep_left(t0_1 + x3_19);

                let x3_25 = t4_13 * $ring.negate(y3_24);
                let t2_26 = t1_23 * t3_8;
                let y3_28 = t0_20 * y3_24;
                let t1_29 = t1_23 * z3_22;
                let t0_31 = t0_20 * t3_8;
                let z3_32 = t4_13 * z3_22;
                [
                    $ring.ready::<800>(t2_26 + x3_25),
                    $ring.ready::<800>(t1_29 + y3_28),
                    $ring.ready::<800>(z3_32 + t0_31),
                ]
            }
        }

        impl<B: Backend> msm::BucketInput<$point, Ring<Bls12381, B>> for $name {
            #[cfg_attr(not(debug_assertions), inline(always))]
            fn add_to(&self, bucket: &$point, negative: bool, $base: &Ring<Bls12381, B>) -> $point {
                let $ring = $ring_value;
                let reduced = $ring.batch_reduce_expand(&self.front(bucket, negative, $base));
                let [x, y, z] = $ring.batch_reduce_expand(&Self::back(bucket, reduced, $base));
                $point { x, y, z }
            }
        }
    };
}

affine!(
    G1Affine, G1, G1Point, Fp, Standard<Bls12381>, Ready<Bls12381>, 1536,
    chains[0, 1, 2, 3, 4, 5, 6, 7], base,
    base, ring = base, value => value.scale::<12>()
);
affine!(
    G2Affine, G2, G2Point, Fp2, Fp2Standard, Fp2Ready, 768,
    chains[0, 1, 2, 3], fp2,
    base, ring = Fp2Ring::new(base), value => ring.mul_3b(value)
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::scalar::Scalar;
    use commonware_cryptography_vroom::{WithBackend, with_backend};
    use subtle::ConstantTimeEq;

    macro_rules! test_mixed_add {
        ($test:ident, $check:ident, $group:ident, $point:ident, $affine:ident) => {
            struct $check;

            impl WithBackend for $check {
                type Output = ();

                fn call<B: Backend>(self, backend: B) {
                    let ring = Ring::<Bls12381, B>::new(backend);
                    let raw_input = $group::generator();
                    let (x, y) = raw_input.to_affine().expect("the generator is finite");
                    let input = $affine {
                        x: x.into(),
                        y: y.into(),
                    };
                    let complete_input = $point::from_jacobian(&raw_input, &ring);

                    // These operands cover identity, P = Q, P = -Q, and a distinct
                    // finite bucket for both input signs.
                    for raw_bucket in [
                        $group::IDENTITY,
                        raw_input,
                        raw_input.neg(),
                        raw_input.double(),
                    ] {
                        let bucket = $point::from_jacobian(&raw_bucket, &ring);
                        for negative in [false, true] {
                            let signed_input = if negative {
                                complete_input.neg(&ring)
                            } else {
                                complete_input
                            };
                            let expected = bucket.add(&signed_input, &ring).to_jacobian(&ring);
                            let actual = msm::BucketInput::add_to(&input, &bucket, negative, &ring)
                                .to_jacobian(&ring);
                            assert_eq!(actual, expected);
                        }
                    }

                    // The affine input is immutable and can be reused after cancellation.
                    let bucket = $point::identity();
                    let bucket = msm::BucketInput::add_to(&input, &bucket, false, &ring);
                    let bucket = msm::BucketInput::add_to(&input, &bucket, true, &ring);
                    assert_eq!(bucket.to_jacobian(&ring), $group::IDENTITY);
                    let bucket = msm::BucketInput::add_to(&input, &bucket, false, &ring);
                    assert_eq!(bucket.to_jacobian(&ring), raw_input);
                }
            }

            #[test]
            fn $test() {
                with_backend($check);
            }
        };
    }

    test_mixed_add!(
        g1_mixed_add_matches_complete,
        CheckG1,
        G1,
        G1Point,
        G1Affine
    );
    test_mixed_add!(
        g2_mixed_add_matches_complete,
        CheckG2,
        G2,
        G2Point,
        G2Affine
    );

    macro_rules! test_normalize {
        ($test:ident, $check:ident, $group:ident, $affine:ident) => {
            struct $check;

            impl WithBackend for $check {
                type Output = ();

                fn call<B: Backend>(self, backend: B) {
                    let ring = Ring::<Bls12381, B>::new(backend);
                    // Enough terms for several rows plus a partial one, with
                    // identities in different rows and a projective input.
                    let mut points = Vec::new();
                    let mut point = $group::generator();
                    for i in 0..37 {
                        points.push(if i % 11 == 5 { $group::IDENTITY } else { point });
                        point = point.double();
                    }
                    // Scalar 2^i has i + 1 bits, which identifies the term.
                    let terms: Vec<_> = (0..points.len())
                        .map(|i| msm::Term {
                            point: i,
                            scalar: msm::EncodedScalar::new(&Scalar::from_u64(1 << i)),
                        })
                        .collect();
                    let normalized = $affine::normalize(&points, terms, &ring);
                    let expected: Vec<_> = points
                        .iter()
                        .enumerate()
                        .filter_map(|(i, point)| point.to_affine().map(|affine| (i, affine)))
                        .collect();
                    assert_eq!(normalized.len(), expected.len());
                    for (term, (i, (x, y))) in normalized.iter().zip(expected) {
                        assert_eq!(term.scalar.bits(), i + 1);
                        assert!(bool::from(<$affine as Coordinates>::x(term).ct_eq(&x)));
                        assert!(bool::from(<$affine as Coordinates>::y(term).ct_eq(&y)));
                    }
                }
            }

            #[test]
            fn $test() {
                with_backend($check);
            }
        };
    }

    trait Coordinates {
        type Field;
        fn x(term: &msm::Term<Self>) -> Self::Field
        where
            Self: Sized;
        fn y(term: &msm::Term<Self>) -> Self::Field
        where
            Self: Sized;
    }

    impl Coordinates for G1Affine {
        type Field = Fp;
        fn x(term: &msm::Term<Self>) -> Fp {
            term.point.x.into()
        }
        fn y(term: &msm::Term<Self>) -> Fp {
            term.point.y.into()
        }
    }

    impl Coordinates for G2Affine {
        type Field = Fp2;
        fn x(term: &msm::Term<Self>) -> Fp2 {
            term.point.x.into()
        }
        fn y(term: &msm::Term<Self>) -> Fp2 {
            term.point.y.into()
        }
    }

    test_normalize!(g1_normalize_skips_identities, NormalizeG1, G1, G1Affine);
    test_normalize!(g2_normalize_skips_identities, NormalizeG2, G2, G2Affine);
}
