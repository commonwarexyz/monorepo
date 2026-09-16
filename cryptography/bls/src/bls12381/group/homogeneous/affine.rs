// Adapted from VROOM src/ec.hpp.
// Copyright 2026 Simon Langowski
// SPDX-License-Identifier: MIT

//! Finite affine inputs for homogeneous MSM buckets.

use super::{G1Point, G2Point};
use crate::bls12381::{
    extension::{
        Fp2,
        bounded::{Fp2Ring, Fp2Standard},
    },
    group::{G1, G2, msm},
};
use alloc::vec::Vec;
use commonware_cryptography_vroom::{
    Backend, Bls12381,
    rns::{Ring, Standard},
};

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
        $name:ident, $group:ident, $point:ident, $standard:ty, $chunk:literal,
        $invert:ident,
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
            /// Consumes the indexed terms and returns only finite affine terms.
            #[inline(always)]
            pub(super) fn normalize<B: Backend>(
                points: &[$group],
                terms: Vec<msm::Term<usize>>,
                $base: &Ring<Bls12381, B>,
            ) -> Vec<msm::Term<Self>> {
                let $ring = $ring_value;
                let mut normalized = Vec::with_capacity(terms.len());

                for chunk in terms.chunks($chunk) {
                    let output_start = normalized.len();
                    let mut prefixes: Vec<$standard> = Vec::with_capacity(chunk.len());
                    let mut positions = Vec::with_capacity(chunk.len());

                    // Prefixes contain only finite Z coordinates. Positions retain
                    // their original order without a second coordinate allocation.
                    for (position, term) in chunk.iter().enumerate() {
                        let z = <$standard>::from(points[term.point].z);
                        if bool::from($ring.is_zero(z)) {
                            continue;
                        }
                        let product = if let Some(prefix) = prefixes.last() {
                            $ring.mul(*prefix, z)
                        } else {
                            z
                        };
                        prefixes.push(product);
                        positions.push(position);
                    }

                    let Some(&product) = prefixes.last() else {
                        continue;
                    };
                    let mut inverse = invert_product!($invert, product, $base)
                        .expect("a product of finite Jacobian Z coordinates is nonzero");

                    // Reverse recovery uses one inverse for the chunk. Appending in
                    // reverse and reversing only this suffix restores term order.
                    for prefix_index in (0..positions.len()).rev() {
                        let term = &chunk[positions[prefix_index]];
                        let point = &points[term.point];
                        let z = <$standard>::from(point.z);
                        let inverse_z = if prefix_index == 0 {
                            inverse
                        } else {
                            $ring.mul(inverse, prefixes[prefix_index - 1])
                        };
                        if prefix_index != 0 {
                            inverse = $ring.mul(inverse, z);
                        }

                        // Finite Jacobian coordinates represent X/Z^2 and Y/Z^3.
                        let inverse_z_squared = $ring.mul(inverse_z, inverse_z);
                        let x = $ring.mul(<$standard>::from(point.x), inverse_z_squared);
                        let inverse_z_cubed = $ring.mul(inverse_z_squared, inverse_z);
                        let y = $ring.mul(<$standard>::from(point.y), inverse_z_cubed);
                        normalized.push(msm::Term {
                            point: Self { x, y },
                            scalar: term.scalar,
                        });
                    }
                    normalized[output_start..].reverse();
                }

                normalized
            }
        }

        impl<B: Backend> msm::BucketInput<$point, Ring<Bls12381, B>> for $name {
            /// VROOM PointMixedAdd, ec.hpp:228-269 (RCB Algorithm 8).
            #[inline(always)]
            fn add_to(&self, bucket: &$point, negative: bool, $base: &Ring<Bls12381, B>) -> $point {
                let $ring = $ring_value;
                let y = if negative {
                    $ring.standard_negate(self.y)
                } else {
                    self.y
                };
                let t3_4 = bucket.x + bucket.y;
                let t4_5 = self.x + y;

                let [t0_1, t1_2, t3_6, t5_11, x3_16] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>($ring.prep_left(bucket.x) * self.x),
                    $ring.ready::<800>($ring.prep_left(bucket.y) * y),
                    $ring.ready::<800>($ring.prep_left(t3_4) * $ring.prep(t4_5)),
                    $ring.ready::<800>($ring.prep_left(bucket.z) * y),
                    $ring.ready::<800>($ring.prep_left(bucket.z) * self.x),
                ]);
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
                let [x, y, z] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>(t2_26 + x3_25),
                    $ring.ready::<800>(t1_29 + y3_28),
                    $ring.ready::<800>(z3_32 + t0_31),
                ]);
                $point { x, y, z }
            }
        }
    };
}

affine!(
    G1Affine, G1, G1Point, Standard<Bls12381>, 1536,
    base,
    base, ring = base, value => value.scale::<12>()
);
affine!(
    G2Affine, G2, G2Point, Fp2Standard, 768,
    fp2,
    base, ring = Fp2Ring::new(base), value => ring.mul_3b(value)
);

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography_vroom::{WithBackend, with_backend};

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
}
