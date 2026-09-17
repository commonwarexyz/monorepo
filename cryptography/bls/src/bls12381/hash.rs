// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from blst 0.3.16's hash_to_field.c, map_to_g1.c, map_to_g2.c,
// and sqrt-addchain.h.

//! RFC 9380 hash-to-curve for BLS12-381.

mod constants;

use crate::{
    bls12381::{
        Fp,
        extension::{
            Fp2,
            bounded::{Fp2 as RnsFp2, Fp2Ring, Fp2Standard},
        },
        group::{G1, G2},
    },
    hash::expand_message_xmd,
};
use commonware_cryptography_vroom::{
    Backend, Bls12381, WithBackend,
    rns::{Ring, Standard},
    with_backend,
};
use constants::{
    FP_HALF, G1_A, G1_B, G1_SQRT_MINUS_Z_CUBED, G1_X_DEN, G1_X_NUM, G1_Y_DEN, G1_Y_NUM, G1_Z, G2_A,
    G2_B, G2_RECIP_Z_CUBED, G2_RECIP_Z_CUBED_MAGIC, G2_X_DEN, G2_X_NUM, G2_Y_DEN, G2_Y_NUM, G2_Z,
    SQRT_I, SQRT_MINUS_I,
};

const HASH_TO_FIELD_L: usize = 64;
#[cfg(test)]
const G1_COFACTOR: [u64; 1] = [0xd201_0000_0001_0001];
#[cfg(test)]
const G2_COFACTOR: [u64; 10] = [
    0xe802_0005_aaa9_5551,
    0x5989_4c0a_debb_f6b4,
    0xe954_cbc0_6689_f6a3,
    0x2ec0_ec69_d747_7c1a,
    0x6d82_bf01_5d12_12b0,
    0x329c_2f17_8731_db95,
    0x9986_ff03_1508_ffe1,
    0x88e2_a8e9_145a_d768,
    0x584c_6a0e_a91b_3528,
    0x0bc6_9f08_f2ee_75b3,
];

type RnsFp = Standard<Bls12381>;

#[derive(Clone, Copy)]
pub(super) struct RnsG1 {
    pub(super) x: RnsFp,
    pub(super) y: RnsFp,
    pub(super) z: RnsFp,
}

#[derive(Clone, Copy)]
pub(super) struct RnsG2 {
    pub(super) x: Fp2Standard,
    pub(super) y: Fp2Standard,
    pub(super) z: Fp2Standard,
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp_eq<B: Backend>(left: RnsFp, right: RnsFp, ring: &Ring<Bls12381, B>) -> bool {
    bool::from(ring.is_zero(ring.sub(left, right)))
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_eq<B: Backend>(left: Fp2Standard, right: Fp2Standard, ring: &Ring<Bls12381, B>) -> bool {
    fp_eq(left.c0, right.c0, ring) && fp_eq(left.c1, right.c1, ring)
}

fn reduce_uniform<const N: usize>(uniform: &[u8]) -> [Fp; N] {
    core::array::from_fn(|i| {
        let start = i * HASH_TO_FIELD_L;
        Fp::from_bytes_mod_order(&uniform[start..start + HASH_TO_FIELD_L])
    })
}

// Scalar and paired roots use the same exponentiation schedule.
macro_rules! reciprocal_sqrt_chain {
    ($input:expr, $one:expr, $product:ident, $square:ident) => {{
        let input = $input;
        const ADDITION_CHAIN: [(usize, usize); 66] = [
            (12, 15),
            (7, 7),
            (4, 1),
            (6, 6),
            (7, 11),
            (5, 4),
            (2, 8),
            (6, 3),
            (6, 3),
            (6, 9),
            (3, 8),
            (7, 3),
            (4, 3),
            (6, 7),
            (6, 14),
            (3, 13),
            (8, 3),
            (7, 11),
            (5, 12),
            (6, 3),
            (6, 5),
            (4, 9),
            (8, 5),
            (4, 3),
            (7, 11),
            (9, 10),
            (2, 8),
            (5, 6),
            (7, 1),
            (7, 9),
            (6, 11),
            (5, 5),
            (5, 10),
            (5, 10),
            (8, 3),
            (7, 2),
            (9, 7),
            (5, 3),
            (3, 8),
            (8, 7),
            (3, 8),
            (7, 9),
            (9, 7),
            (6, 2),
            (6, 4),
            (5, 4),
            (5, 4),
            (4, 3),
            (3, 8),
            (8, 2),
            (7, 4),
            (5, 4),
            (5, 4),
            (4, 7),
            (4, 6),
            (7, 4),
            (5, 5),
            (5, 4),
            (5, 4),
            (5, 4),
            (5, 4),
            (5, 4),
            (5, 4),
            (4, 3),
            (6, 2),
            (4, 1),
        ];
        const PRECOMPUTE: [(usize, usize, usize); 17] = [
            (0, 13, 13),
            (8, 0, 13),
            (4, 0, 0),
            (1, 8, 0),
            (6, 4, 8),
            (9, 1, 4),
            (12, 6, 4),
            (3, 9, 4),
            (7, 12, 4),
            (15, 3, 4),
            (10, 7, 4),
            (2, 15, 4),
            (11, 10, 4),
            (0, 3, 3),
            (14, 11, 4),
            (5, 0, 8),
            (4, 0, 1),
        ];

        let t = {
            let mut t = [$one; 16];
            t[13] = input;
            for &(destination, left, right) in &PRECOMPUTE {
                t[destination] = $product!(t[left], t[right]);
            }
            t
        };

        let mut result = t[0];
        for &(squarings, factor) in &ADDITION_CHAIN {
            for _ in 0..squarings {
                result = $square!(result);
            }
            result = $product!(result, t[factor]);
        }
        $square!(result)
    }};
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn reciprocal_sqrt_fp<B: Backend>(input: RnsFp, ring: &Ring<Bls12381, B>) -> (bool, RnsFp) {
    macro_rules! product {
        ($left:expr, $right:expr) => {
            ring.mul($left, $right)
        };
    }
    macro_rules! square {
        ($value:expr) => {
            product!($value, $value)
        };
    }
    let result = reciprocal_sqrt_chain!(input, RnsFp::ONE, product, square);
    let check = ring.mul(result, input);
    (fp_eq(ring.mul(check, check), input, ring), result)
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn reciprocal_sqrt_fp_pair<B: Backend>(
    input: [RnsFp; 2],
    ring: &Ring<Bls12381, B>,
) -> [(bool, RnsFp); 2] {
    macro_rules! product {
        ($left:expr, $right:expr) => {{
            let left = $left;
            let right = $right;
            ring.batch_reduce_expand(&[
                ring.ready::<800>(ring.prep_left(left[0]) * right[0]),
                ring.ready::<800>(ring.prep_left(left[1]) * right[1]),
            ])
        }};
    }
    macro_rules! square {
        ($value:expr) => {
            product!($value, $value)
        };
    }
    let result = reciprocal_sqrt_chain!(input, [RnsFp::ONE; 2], product, square);
    let check = product!(result, input);
    let square = product!(check, check);
    [
        (fp_eq(square[0], input[0], ring), result[0]),
        (fp_eq(square[1], input[1], ring), result[1]),
    ]
}

// Hash-to-curve inputs are public, so square-class and rotation branches do not
// expose secret-dependent control flow.
#[cfg_attr(not(debug_assertions), inline(always))]
fn reciprocal_sqrt_fp2<B: Backend>(
    input: Fp2Standard,
    ring: &Ring<Bls12381, B>,
    fp2: &Fp2Ring<'_, B>,
) -> Option<(bool, Fp2Standard)> {
    let norm = ring.add(ring.mul(input.c0, input.c0), ring.mul(input.c1, input.c1));
    let (is_square, inverse_norm_root) = reciprocal_sqrt_fp(norm, ring);
    let (input, norm, inverse_norm_root) = if is_square {
        (input, norm, inverse_norm_root)
    } else {
        (
            fp2_mul(fp2, input, G2_RECIP_Z_CUBED.into()),
            ring.mul(norm, G2_RECIP_Z_CUBED_MAGIC.c0.into()),
            ring.mul(inverse_norm_root, G2_RECIP_Z_CUBED_MAGIC.c1.into()),
        )
    };

    let norm_root = ring.mul(norm, inverse_norm_root);
    let sum = ring.add(input.c0, norm_root);
    let component = if bool::from(ring.is_zero(sum)) {
        ring.sub(input.c0, norm_root)
    } else {
        sum
    };
    let component = ring.mul(component, FP_HALF.into());
    let (_, inverse_component_root) = reciprocal_sqrt_fp(component, ring);
    let root = RnsFp2 {
        c0: ring.mul(component, inverse_component_root),
        c1: ring.mul(ring.mul(input.c1, FP_HALF.into()), inverse_component_root),
    };

    let square = fp2_square(fp2, root);
    let rotated = RnsFp2 {
        c0: ring.standard_negate(input.c1),
        c1: input.c0,
    };
    let coefficient = if fp2_eq(square, input, ring) {
        Fp2::ONE.into()
    } else if fp2_eq(square, fp2_neg(fp2, input), ring) {
        RnsFp2 {
            c0: RnsFp::ZERO,
            c1: RnsFp::ONE,
        }
    } else if fp2_eq(square, fp2_neg(fp2, rotated), ring) {
        SQRT_I.into()
    } else if fp2_eq(square, rotated, ring) {
        SQRT_MINUS_I.into()
    } else {
        return None;
    };
    let root = fp2_mul(fp2, root, coefficient);
    Some((
        is_square,
        RnsFp2 {
            c0: ring.mul(root.c0, inverse_norm_root),
            c1: ring.standard_negate(ring.mul(root.c1, inverse_norm_root)),
        },
    ))
}

// Evaluates sum(c_i * (x / h)^i) without dividing, returning the result scaled
// by h^(n - 1) for n coefficients.
#[cfg_attr(not(debug_assertions), inline(always))]
fn evaluate_homogeneous_fp<B: Backend>(
    x: RnsFp,
    homogenizer: RnsFp,
    coefficients: &[Fp],
    ring: &Ring<Bls12381, B>,
) -> RnsFp {
    let Some((&leading, coefficients)) = coefficients.split_last() else {
        return RnsFp::ONE;
    };
    let mut value = leading.into();
    let mut power = homogenizer;
    for coefficient in coefficients.iter().rev() {
        value = ring.add(ring.mul(value, x), ring.mul((*coefficient).into(), power));
        power = ring.mul(power, homogenizer);
    }
    value
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn evaluate_homogeneous_fp2<B: Backend>(
    x: Fp2Standard,
    homogenizer: Fp2Standard,
    coefficients: &[Fp2],
    ring: &Ring<Bls12381, B>,
    fp2: &Fp2Ring<'_, B>,
) -> Fp2Standard {
    let Some((&leading, coefficients)) = coefficients.split_last() else {
        return Fp2::ONE.into();
    };
    let mut value = leading.into();
    let mut power = homogenizer;
    for coefficient in coefficients.iter().rev() {
        let left = fp2_mul(fp2, value, x);
        let right = fp2_mul(fp2, (*coefficient).into(), power);
        value = RnsFp2 {
            c0: ring.add(left.c0, right.c0),
            c1: ring.add(left.c1, right.c1),
        };
        power = fp2_mul(fp2, power, homogenizer);
    }
    value
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn isogeny_map_g1<B: Backend>(point: RnsG1, ring: &Ring<Bls12381, B>) -> RnsG1 {
    let zz = ring.mul(point.z, point.z);
    let x_num = evaluate_homogeneous_fp(point.x, zz, G1_X_NUM, ring);
    let x_den = ring.mul(evaluate_homogeneous_fp(point.x, zz, G1_X_DEN, ring), zz);
    let y_num = ring.mul(
        evaluate_homogeneous_fp(point.x, zz, G1_Y_NUM, ring),
        point.y,
    );
    let y_den = ring.mul(
        evaluate_homogeneous_fp(point.x, zz, G1_Y_DEN, ring),
        ring.mul(zz, point.z),
    );
    let z = ring.mul(x_den, y_den);
    RnsG1 {
        x: ring.mul(ring.mul(x_num, y_den), z),
        y: ring.mul(ring.mul(y_num, x_den), ring.mul(z, z)),
        z,
    }
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn isogeny_map_g2<B: Backend>(
    point: RnsG2,
    ring: &Ring<Bls12381, B>,
    fp2: &Fp2Ring<'_, B>,
) -> RnsG2 {
    let zz = fp2_square(fp2, point.z);
    let x_num = evaluate_homogeneous_fp2(point.x, zz, G2_X_NUM, ring, fp2);
    let x_den = fp2_mul(
        fp2,
        evaluate_homogeneous_fp2(point.x, zz, G2_X_DEN, ring, fp2),
        zz,
    );
    let y_num = fp2_mul(
        fp2,
        evaluate_homogeneous_fp2(point.x, zz, G2_Y_NUM, ring, fp2),
        point.y,
    );
    let y_den = fp2_mul(
        fp2,
        evaluate_homogeneous_fp2(point.x, zz, G2_Y_DEN, ring, fp2),
        fp2_mul(fp2, zz, point.z),
    );
    let z = fp2_mul(fp2, x_den, y_den);
    RnsG2 {
        x: fp2_mul(fp2, fp2_mul(fp2, x_num, y_den), z),
        y: fp2_mul(fp2, fp2_mul(fp2, y_num, x_den), fp2_square(fp2, z)),
        z,
    }
}

struct PendingG1 {
    u: RnsFp,
    uu: RnsFp,
    x1: RnsFp,
    x2: RnsFp,
    denominator: RnsFp,
    denominator_cubed: RnsFp,
    ratio: RnsFp,
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn prepare_g1<B: Backend>(u: RnsFp, ring: &Ring<Bls12381, B>) -> (PendingG1, RnsFp) {
    let uu = ring.mul(u, u);
    let zuu = ring.mul(G1_Z.into(), uu);
    let t = ring.add(ring.mul(zuu, zuu), zuu);
    let x1 = ring.mul(G1_B.into(), ring.add(t, RnsFp::ONE));
    let x2 = ring.mul(zuu, x1);
    let denominator = if bool::from(ring.is_zero(t)) {
        ring.mul(G1_Z.into(), G1_A.into())
    } else {
        ring.mul(ring.standard_negate(G1_A.into()), t)
    };
    let denominator_squared = ring.mul(denominator, denominator);
    let denominator_cubed = ring.mul(denominator_squared, denominator);
    let gx1 = ring.add(
        ring.mul(
            ring.add(ring.mul(x1, x1), ring.mul(G1_A.into(), denominator_squared)),
            x1,
        ),
        ring.mul(G1_B.into(), denominator_cubed),
    );
    let ratio = ring.mul(gx1, denominator_cubed);
    let denominator_sixth = ring.mul(denominator_cubed, denominator_cubed);
    (
        PendingG1 {
            u,
            uu,
            x1,
            x2,
            denominator,
            denominator_cubed,
            ratio,
        },
        ring.mul(ratio, denominator_sixth),
    )
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn finish_isogenous_g1<B: Backend>(
    pending: PendingG1,
    is_square: bool,
    inverse_root: RnsFp,
    ring: &Ring<Bls12381, B>,
) -> RnsG1 {
    let PendingG1 {
        u,
        uu,
        x1,
        x2,
        denominator,
        denominator_cubed,
        ratio,
    } = pending;
    let y1 = ring.mul(inverse_root, ratio);
    let (x, y) = if is_square {
        (x1, y1)
    } else {
        (
            x2,
            ring.mul(ring.mul(ring.mul(y1, G1_SQRT_MINUS_Z_CUBED.into()), uu), u),
        )
    };
    let y = if bool::from(Fp::from(y).sgn0()) == bool::from(Fp::from(u).sgn0()) {
        y
    } else {
        ring.standard_negate(y)
    };
    RnsG1 {
        x: ring.mul(x, denominator),
        y: ring.mul(y, denominator_cubed),
        z: denominator,
    }
}

#[cfg(test)]
#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_isogenous_g1<B: Backend>(u: RnsFp, ring: &Ring<Bls12381, B>) -> RnsG1 {
    let (pending, input) = prepare_g1(u, ring);
    let (is_square, inverse_root) = reciprocal_sqrt_fp(input, ring);
    finish_isogenous_g1(pending, is_square, inverse_root, ring)
}

#[cfg(test)]
#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_g1<B: Backend>(u: RnsFp, ring: &Ring<Bls12381, B>) -> RnsG1 {
    isogeny_map_g1(map_to_isogenous_g1(u, ring), ring)
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_g1_pair<B: Backend>(input: [RnsFp; 2], ring: &Ring<Bls12381, B>) -> [RnsG1; 2] {
    let (first, first_input) = prepare_g1(input[0], ring);
    let (second, second_input) = prepare_g1(input[1], ring);
    let [(first_square, first_root), (second_square, second_root)] =
        reciprocal_sqrt_fp_pair([first_input, second_input], ring);
    [
        isogeny_map_g1(
            finish_isogenous_g1(first, first_square, first_root, ring),
            ring,
        ),
        isogeny_map_g1(
            finish_isogenous_g1(second, second_square, second_root, ring),
            ring,
        ),
    ]
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_add<B: Backend>(
    left: Fp2Standard,
    right: Fp2Standard,
    ring: &Ring<Bls12381, B>,
) -> Fp2Standard {
    RnsFp2 {
        c0: ring.add(left.c0, right.c0),
        c1: ring.add(left.c1, right.c1),
    }
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_mul<B: Backend>(fp2: &Fp2Ring<'_, B>, left: Fp2Standard, right: Fp2Standard) -> Fp2Standard {
    fp2.mul(left, right)
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_square<B: Backend>(fp2: &Fp2Ring<'_, B>, value: Fp2Standard) -> Fp2Standard {
    fp2.square(value)
}

#[cfg_attr(debug_assertions, inline(never))]
#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_neg<B: Backend>(fp2: &Fp2Ring<'_, B>, value: Fp2Standard) -> Fp2Standard {
    fp2.standard_negate(value)
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_g2<B: Backend>(u: Fp2Standard, ring: &Ring<Bls12381, B>, fp2: &Fp2Ring<'_, B>) -> RnsG2 {
    let uu = fp2_square(fp2, u);
    let zuu = fp2_mul(fp2, G2_Z.into(), uu);
    let t = fp2_add(fp2_square(fp2, zuu), zuu, ring);
    let x1 = fp2_mul(fp2, G2_B.into(), fp2_add(t, Fp2::ONE.into(), ring));
    let x2 = fp2_mul(fp2, zuu, x1);
    let denominator = if Fp2::from(t).is_zero() {
        fp2_mul(fp2, G2_Z.into(), G2_A.into())
    } else {
        fp2_mul(fp2, fp2_neg(fp2, G2_A.into()), t)
    };
    let denominator_squared = fp2_square(fp2, denominator);
    let denominator_cubed = fp2_mul(fp2, denominator_squared, denominator);
    let gx1 = fp2_add(
        fp2_mul(
            fp2,
            fp2_add(
                fp2_square(fp2, x1),
                fp2_mul(fp2, G2_A.into(), denominator_squared),
                ring,
            ),
            x1,
        ),
        fp2_mul(fp2, G2_B.into(), denominator_cubed),
        ring,
    );
    let ratio = fp2_mul(fp2, gx1, denominator_cubed);
    let denominator_sixth = fp2_square(fp2, denominator_cubed);
    let Some((is_square, inverse_root)) =
        reciprocal_sqrt_fp2(fp2_mul(fp2, ratio, denominator_sixth), ring, fp2)
    else {
        return RnsG2 {
            x: Fp2::ZERO.into(),
            y: Fp2::ONE.into(),
            z: Fp2::ZERO.into(),
        };
    };
    let y1 = fp2_mul(fp2, inverse_root, ratio);
    let (x, y) = if is_square {
        (x1, y1)
    } else {
        (x2, fp2_mul(fp2, fp2_mul(fp2, y1, uu), u))
    };
    let y = if sgn0_fp2(Fp2::from(y)) == sgn0_fp2(Fp2::from(u)) {
        y
    } else {
        fp2_neg(fp2, y)
    };
    isogeny_map_g2(
        RnsG2 {
            x: fp2_mul(fp2, x, denominator),
            y: fp2_mul(fp2, y, denominator_cubed),
            z: denominator,
        },
        ring,
        fp2,
    )
}

struct MapG1<'a>(&'a [Fp; 2]);

impl WithBackend for MapG1<'_> {
    type Output = G1;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        let points = map_to_g1_pair([self.0[0].into(), self.0[1].into()], &ring);
        G1::sum_and_clear_cofactor(&points, &ring)
    }
}

struct MapG2<'a>(&'a [Fp2; 2]);

impl WithBackend for MapG2<'_> {
    type Output = G2;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        let fp2 = Fp2Ring::new(&ring);
        let points = [
            map_to_g2(self.0[0].into(), &ring, &fp2),
            map_to_g2(self.0[1].into(), &ring, &fp2),
        ];
        G2::sum_and_clear_cofactor(&points, &ring)
    }
}

#[cfg(test)]
struct MapSingleG1(Fp);

#[cfg(test)]
impl WithBackend for MapSingleG1 {
    type Output = G1;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        let point = map_to_g1(self.0.into(), &ring);
        G1 {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        }
    }
}

#[cfg(test)]
fn map_single_g1(u: Fp) -> G1 {
    with_backend(MapSingleG1(u))
}

#[cfg(test)]
struct MapSingleG2(Fp2);

#[cfg(test)]
impl WithBackend for MapSingleG2 {
    type Output = G2;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        let fp2 = Fp2Ring::new(&ring);
        let point = map_to_g2(self.0.into(), &ring, &fp2);
        G2 {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        }
    }
}

#[cfg(test)]
fn map_single_g2(u: Fp2) -> G2 {
    with_backend(MapSingleG2(u))
}

fn sgn0_fp2(value: Fp2) -> bool {
    if value.c0.is_zero() {
        bool::from(value.c1.sgn0())
    } else {
        bool::from(value.c0.sgn0())
    }
}

pub(crate) fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let u = reduce_uniform::<2>(&expand_message_xmd::<128>(msg, dst));
    with_backend(MapG1(&u))
}

pub(crate) fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let elements = reduce_uniform::<4>(&expand_message_xmd::<256>(msg, dst));
    let u = [
        Fp2 {
            c0: elements[0],
            c1: elements[1],
        },
        Fp2 {
            c0: elements[2],
            c1: elements[3],
        },
    ];
    with_backend(MapG2(&u))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::scalar::ORDER;

    fn raw_g1(point: G1) -> RnsG1 {
        let (x, y, z) = (point.x, point.y, point.z);
        RnsG1 {
            x: x.into(),
            y: y.into(),
            z: z.into(),
        }
    }

    struct SumAndClearG1([RnsG1; 2]);

    impl WithBackend for SumAndClearG1 {
        type Output = G1;

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let ring = Ring::<Bls12381, B>::new(backend);
            G1::sum_and_clear_cofactor(&self.0, &ring)
        }
    }

    fn assert_sum_and_clear_g1(points: [RnsG1; 2]) {
        let expected = points.map(|point| G1 {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        });
        let expected = expected[0]
            .add_jacobian(&expected[1])
            .mul_words_jacobian(&G1_COFACTOR);
        let actual = with_backend(SumAndClearG1(points));
        assert_eq!(actual, expected);
        assert_eq!(actual.to_bytes(), expected.to_bytes());
    }

    fn raw_g2(point: G2) -> RnsG2 {
        let (x, y, z) = (point.x, point.y, point.z);
        RnsG2 {
            x: x.into(),
            y: y.into(),
            z: z.into(),
        }
    }

    struct SumAndClearG2([RnsG2; 2]);

    impl WithBackend for SumAndClearG2 {
        type Output = G2;

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let ring = Ring::<Bls12381, B>::new(backend);
            G2::sum_and_clear_cofactor(&self.0, &ring)
        }
    }

    fn assert_sum_and_clear_g2(points: [RnsG2; 2]) {
        let expected = points.map(|point| G2 {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        });
        let expected = expected[0]
            .add_jacobian(&expected[1])
            .mul_words_jacobian(&G2_COFACTOR);
        let actual = with_backend(SumAndClearG2(points));
        assert_eq!(actual, expected);
        assert_eq!(actual.to_bytes(), expected.to_bytes());
    }

    fn clear_cofactor_g2(point: G2) -> G2 {
        with_backend(SumAndClearG2([point, G2::IDENTITY].map(raw_g2)))
    }

    fn g1_root_predicate_oracle<B: Backend>(u: RnsFp, ring: &Ring<Bls12381, B>) -> (bool, [Fp; 3]) {
        let uu = ring.mul(u, u);
        let zuu = ring.mul(G1_Z.into(), uu);
        let t = ring.add(ring.mul(zuu, zuu), zuu);
        let x1 = ring.mul(G1_B.into(), ring.add(t, RnsFp::ONE));
        let x2 = ring.mul(zuu, x1);
        let denominator = if bool::from(ring.is_zero(t)) {
            ring.mul(G1_Z.into(), G1_A.into())
        } else {
            ring.mul(ring.standard_negate(G1_A.into()), t)
        };
        assert_ne!(Fp::from(denominator), Fp::ZERO);
        if Fp::from(u) == Fp::ZERO {
            assert_eq!(Fp::from(t), Fp::ZERO);
            assert_eq!(Fp::from(denominator), G1_Z.mul(G1_A));
        }
        let denominator_squared = ring.mul(denominator, denominator);
        let denominator_cubed = ring.mul(denominator_squared, denominator);
        let gx1 = ring.add(
            ring.mul(
                ring.add(ring.mul(x1, x1), ring.mul(G1_A.into(), denominator_squared)),
                x1,
            ),
            ring.mul(G1_B.into(), denominator_cubed),
        );
        let ratio = ring.mul(gx1, denominator_cubed);
        let denominator_sixth = ring.mul(denominator_cubed, denominator_cubed);
        let (helper_is_square, inverse_root) =
            reciprocal_sqrt_fp(ring.mul(ratio, denominator_sixth), ring);
        let y1 = ring.mul(inverse_root, ratio);
        let map_is_square = fp_eq(ring.mul(ring.mul(y1, y1), denominator_cubed), gx1, ring);
        assert_eq!(helper_is_square, map_is_square, "G1 root predicates");

        // The direct curve equation supplies the coordinate-selection oracle.
        let (x, y) = if map_is_square {
            (x1, y1)
        } else {
            (
                x2,
                ring.mul(ring.mul(ring.mul(y1, G1_SQRT_MINUS_Z_CUBED.into()), uu), u),
            )
        };
        let y = if bool::from(Fp::from(y).sgn0()) == bool::from(Fp::from(u).sgn0()) {
            y
        } else {
            ring.standard_negate(y)
        };
        let expected = [
            ring.mul(x, denominator),
            ring.mul(y, denominator_cubed),
            denominator,
        ];
        (map_is_square, expected.map(Fp::from))
    }

    struct CheckG1RootPredicate;

    impl WithBackend for CheckG1RootPredicate {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            let ring = Ring::<Bls12381, B>::new(backend);
            assert_ne!(G1_A, Fp::ZERO);
            assert_ne!(G1_Z, Fp::ZERO);
            let mut classes = [false; 2];
            for value in 0..8 {
                let input = Fp::from_u64(value);
                let canonical = RnsFp::from(input);
                let negative = Fp::from_bytes(&input.neg().to_bytes()).expect("canonical negation");
                let redundant = ring.standard_negate(RnsFp::from(negative));
                assert_ne!(
                    alloc::format!("{canonical:?}"),
                    alloc::format!("{redundant:?}")
                );
                assert_eq!(Fp::from(redundant), input);

                let mut observations = [(false, [Fp::ZERO; 3]); 2];
                for (result, u) in observations.iter_mut().zip([canonical, redundant]) {
                    *result = g1_root_predicate_oracle(u, &ring);
                    let actual = map_to_isogenous_g1(u, &ring);
                    assert_eq!(
                        [actual.x, actual.y, actual.z].map(Fp::from),
                        result.1,
                        "complete G1 projective coordinates"
                    );
                }
                assert_eq!(observations[0], observations[1]);
                classes[usize::from(observations[0].0)] = true;
            }
            assert_eq!(classes, [true, true], "both G1 selection classes");
        }
    }

    #[test]
    fn g1_root_predicate_matches_map_for_canonical_and_redundant_inputs() {
        with_backend(CheckG1RootPredicate);
    }

    macro_rules! assert_decoder_membership {
        ($point:expr, $group:ident, $accepted:ident, $rejected:ident) => {{
            let point = $point;
            let bytes = point.to_bytes();
            let expected = point.mul_words_jacobian(&ORDER).is_identity();
            let decoded = $group::from_bytes(&bytes);
            assert_eq!(decoded.is_some(), expected);
            if let Some(decoded) = decoded {
                assert_eq!(decoded.to_bytes(), bytes);
                assert_eq!(decoded.to_affine(), point.to_affine());
                $accepted += 1;
            } else {
                $rejected += 1;
            }
        }};
    }

    #[test]
    fn mapped_full_curve_decoder_membership_matches_order() {
        let g1_zero = map_single_g1(Fp::ZERO);
        let g1_one = map_single_g1(Fp::ONE);
        let g1_sum = g1_zero.add_jacobian(&g1_one);
        let g1_cofactor = with_backend(SumAndClearG1([g1_zero, g1_one].map(raw_g1)));
        let mut g1_accepted = 0;
        let mut g1_rejected = 0;
        for point in [
            g1_zero,
            g1_one,
            g1_sum,
            g1_sum.neg(),
            g1_sum.endomorphism(),
            g1_sum.mul_words_jacobian(&[0x0000_0001_0000_0000, 0xac45_a401_0001_a402]),
            g1_cofactor,
        ] {
            assert_decoder_membership!(point, G1, g1_accepted, g1_rejected);
        }
        assert!(g1_accepted > 0);
        assert!(g1_rejected > 0);

        let g2_zero = map_single_g2(Fp2::ZERO);
        let g2_one = map_single_g2(Fp2::ONE);
        let g2_sum = g2_zero.add_jacobian(&g2_one);
        let g2_cofactor = with_backend(SumAndClearG2([g2_zero, g2_one].map(raw_g2)));
        let mut g2_accepted = 0;
        let mut g2_rejected = 0;
        for point in [
            g2_zero,
            g2_one,
            g2_sum,
            g2_sum.neg(),
            g2_sum.psi(),
            g2_sum.mul_by_x(),
            g2_cofactor,
        ] {
            assert_decoder_membership!(point, G2, g2_accepted, g2_rejected);
        }
        assert!(g2_accepted > 0);
        assert!(g2_rejected > 0);
    }

    #[test]
    fn zero_g1_field_element() {
        let g1 = map_single_g1(Fp::ZERO).mul_words_jacobian(&G1_COFACTOR);
        assert_eq!(G1::from_bytes(&g1.to_bytes()), Some(g1));
        assert!(!g1.is_identity());
    }

    #[test]
    fn zero_g2_field_element() {
        let g2 = map_single_g2(Fp2::ZERO).mul_words_jacobian(&G2_COFACTOR);
        assert_eq!(G2::from_bytes(&g2.to_bytes()), Some(g2));
        assert!(!g2.is_identity());
    }

    #[test]
    fn fast_g2_cofactor_matches_effective_cofactor() {
        for point in [
            G2::identity(),
            map_single_g2(Fp2::ZERO),
            map_single_g2(Fp2::ONE),
            map_single_g2(G2_Z),
        ] {
            assert_eq!(
                clear_cofactor_g2(point),
                point.mul_words_jacobian(&G2_COFACTOR)
            );
        }
    }

    #[test]
    fn retained_tail_matches_effective_cofactor() {
        let g1_torsion = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
        let g1_mixed = G1::generator().add_jacobian(&g1_torsion);
        let g1_scale = Fp::from_u64(7);
        let (x, y, z) = (g1_mixed.x, g1_mixed.y, g1_mixed.z);
        let g1_mixed_scaled = RnsG1 {
            x: x.mul(g1_scale.square()).into(),
            y: y.mul(g1_scale.square().mul(g1_scale)).into(),
            z: z.mul(g1_scale).into(),
        };
        let g1_infinity = RnsG1 {
            x: Fp::from_u64(5).into(),
            y: Fp::from_u64(9).into(),
            z: Fp::ZERO.into(),
        };
        assert!(!g1_mixed.mul_words_jacobian(&G1_COFACTOR).is_identity());
        for points in [
            [raw_g1(g1_torsion), raw_g1(g1_torsion)],
            [raw_g1(g1_torsion), raw_g1(g1_torsion.neg())],
            [raw_g1(g1_mixed), raw_g1(G1::IDENTITY)],
            [g1_mixed_scaled, g1_infinity],
            [g1_infinity, g1_mixed_scaled],
        ] {
            assert_sum_and_clear_g1(points);
        }

        let g2_point = map_single_g2(Fp2::ZERO);
        assert!(!g2_point.mul_words_jacobian(&ORDER).is_identity());
        let g2_scale = Fp2 {
            c0: Fp::from_u64(7),
            c1: Fp::ONE,
        };
        let (x, y, z) = (g2_point.x, g2_point.y, g2_point.z);
        let g2_scaled = RnsG2 {
            x: x.mul(g2_scale.square()).into(),
            y: y.mul(g2_scale.square().mul(g2_scale)).into(),
            z: z.mul(g2_scale).into(),
        };
        let g2_infinity = RnsG2 {
            x: Fp2::from_u64(5).into(),
            y: Fp2::from_u64(9).into(),
            z: Fp2::ZERO.into(),
        };
        assert!(!g2_point.mul_words_jacobian(&G2_COFACTOR).is_identity());
        for points in [
            [raw_g2(g2_point), raw_g2(g2_point)],
            [g2_scaled, raw_g2(g2_point.neg())],
            [raw_g2(g2_point), raw_g2(g2_point.neg())],
            [g2_infinity, g2_scaled],
            [g2_scaled, g2_infinity],
        ] {
            assert_sum_and_clear_g2(points);
        }
    }

    fn p_minus_one() -> Fp {
        Fp::from_raw(&[
            0xb9fe_ffff_ffff_aaaa,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ])
        .expect("p - 1 is canonical")
    }

    fn representative<B: Backend>(input: Fp, redundant: bool, ring: &Ring<Bls12381, B>) -> RnsFp {
        let canonical = RnsFp::from(input);
        if !redundant {
            return canonical;
        }

        let negative = Fp::from_bytes(&input.neg().to_bytes()).expect("negation is canonical");
        let value = ring.standard_negate(RnsFp::from(negative));
        assert_ne!(alloc::format!("{value:?}"), alloc::format!("{canonical:?}"));
        assert_eq!(Fp::from(value), input);
        value
    }

    fn observe_roots<B: Backend>(
        name: &str,
        values: [Fp; 2],
        redundant: [bool; 2],
        known_square: [bool; 2],
        ring: &Ring<Bls12381, B>,
    ) -> [(bool, Fp); 2] {
        let inputs = [
            representative(values[0], redundant[0], ring),
            representative(values[1], redundant[1], ring),
        ];
        let paired = reciprocal_sqrt_fp_pair(inputs, ring);
        let actual = paired.map(|(is_square, root)| (is_square, Fp::from(root)));
        let expected = inputs.map(|input| {
            let (is_square, root) = reciprocal_sqrt_fp(input, ring);
            (is_square, Fp::from(root))
        });
        assert_eq!(actual, expected, "{name} paired roots");
        assert_eq!(
            actual.map(|result| result.0),
            known_square,
            "{name} classes"
        );

        for lane in 0..2 {
            let check = ring.mul(paired[lane].1, inputs[lane]);
            assert_eq!(
                Fp::from(ring.mul(check, check)) == values[lane],
                paired[lane].0,
                "{name} lane {lane} verified predicate"
            );
        }
        actual
    }

    struct CheckPairedRoots;

    impl WithBackend for CheckPairedRoots {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            let ring = Ring::<Bls12381, B>::new(backend);
            let zero_one = observe_roots(
                "zero/one",
                [Fp::ZERO, Fp::ONE],
                [false, true],
                [true, true],
                &ring,
            );
            let one_zero = observe_roots(
                "one/zero",
                [Fp::ONE, Fp::ZERO],
                [true, false],
                [true, true],
                &ring,
            );
            assert_eq!(zero_one, [one_zero[1], one_zero[0]], "mixed-zero swap");
            let redundant_zero = observe_roots(
                "redundant-zero/canonical-zero",
                [Fp::ZERO, Fp::ZERO],
                [true, false],
                [true, true],
                &ring,
            );
            assert_eq!(redundant_zero, [zero_one[0]; 2], "redundant zero");

            let two_four = observe_roots(
                "two/four",
                [Fp::from_u64(2), Fp::from_u64(4)],
                [true, false],
                [false, true],
                &ring,
            );
            let four_two = observe_roots(
                "four/two",
                [Fp::from_u64(4), Fp::from_u64(2)],
                [false, true],
                [true, false],
                &ring,
            );
            assert_ne!(two_four[0].0, two_four[1].0, "asymmetric classes");
            assert_eq!(two_four, [four_two[1], four_two[0]], "class swap");

            let changed = observe_roots(
                "two/p-1",
                [Fp::from_u64(2), p_minus_one()],
                [true, true],
                [false, false],
                &ring,
            );
            assert_eq!(changed[0], two_four[0], "unchanged lane");
            assert_ne!(changed[1], two_four[1], "changed lane");
        }
    }

    #[test]
    fn paired_reciprocal_roots_match_independent_scalar_calls() {
        with_backend(CheckPairedRoots);
    }

    fn coordinates(point: RnsG1) -> [Fp; 3] {
        [point.x, point.y, point.z].map(Fp::from)
    }

    struct MapCase {
        name: &'static str,
        values: [Fp; 2],
        redundant: [bool; 2],
    }

    struct MapObservation {
        coordinates: [[Fp; 3]; 2],
        output: G1,
    }

    impl WithBackend for MapCase {
        type Output = MapObservation;

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let ring = Ring::<Bls12381, B>::new(backend);
            let inputs = [
                representative(self.values[0], self.redundant[0], &ring),
                representative(self.values[1], self.redundant[1], &ring),
            ];
            let points = map_to_g1_pair(inputs, &ring);
            let actual = points.map(coordinates);
            let expected = inputs.map(|input| coordinates(map_to_g1(input, &ring)));
            assert_eq!(actual, expected, "{} complete coordinates", self.name);
            MapObservation {
                coordinates: actual,
                output: G1::sum_and_clear_cofactor(&points, &ring),
            }
        }
    }

    fn observe_map(case: MapCase) -> MapObservation {
        let name = case.name;
        let values = case.values;
        let actual = with_backend(case);
        let expected = with_backend(MapG1(&values));
        assert_eq!(
            (actual.output.x, actual.output.y, actual.output.z),
            (expected.x, expected.y, expected.z),
            "{name} complete public output"
        );
        assert_eq!(
            actual.output.to_affine(),
            expected.to_affine(),
            "{name} affine"
        );
        assert_eq!(
            actual.output.to_bytes(),
            expected.to_bytes(),
            "{name} encoding"
        );
        actual
    }

    #[test]
    fn paired_g1_maps_match_scalar_coordinates_and_public_output() {
        let zero_one = observe_map(MapCase {
            name: "zero/one",
            values: [Fp::ZERO, Fp::ONE],
            redundant: [false, true],
        });
        let one_zero = observe_map(MapCase {
            name: "one/zero",
            values: [Fp::ONE, Fp::ZERO],
            redundant: [true, false],
        });
        assert_eq!(
            zero_one.coordinates,
            [one_zero.coordinates[1], one_zero.coordinates[0]],
            "mixed-zero input order"
        );
        assert_eq!(zero_one.output.to_bytes(), one_zero.output.to_bytes());

        let left_redundant = observe_map(MapCase {
            name: "two/four left redundant",
            values: [Fp::from_u64(2), Fp::from_u64(4)],
            redundant: [true, false],
        });
        let right_redundant = observe_map(MapCase {
            name: "two/four right redundant",
            values: [Fp::from_u64(2), Fp::from_u64(4)],
            redundant: [false, true],
        });
        assert_eq!(left_redundant.coordinates, right_redundant.coordinates);
        assert_eq!(
            left_redundant.output.to_bytes(),
            right_redundant.output.to_bytes()
        );

        let swapped = observe_map(MapCase {
            name: "four/two",
            values: [Fp::from_u64(4), Fp::from_u64(2)],
            redundant: [true, false],
        });
        assert_eq!(
            left_redundant.coordinates,
            [swapped.coordinates[1], swapped.coordinates[0]],
            "mixed-representation input order"
        );
        assert_eq!(left_redundant.output.to_bytes(), swapped.output.to_bytes());
    }

    const RECIPROCAL_ROOT_EXPONENT: [u64; 6] = [
        0xee7f_bfff_ffff_eaaa,
        0x07aa_ffff_ac54_ffff,
        0xd9cc_34a8_3dac_3d89,
        0xd91d_d2e1_3ce1_44af,
        0x92c6_e9ed_90d2_eb35,
        0x0680_447a_8e5f_f9a6,
    ];

    fn binary_reciprocal_root<B: Backend>(input: RnsFp, ring: &Ring<Bls12381, B>) -> RnsFp {
        let mut result = RnsFp::ONE;
        for &word in RECIPROCAL_ROOT_EXPONENT.iter().rev() {
            for bit in (0..64).rev() {
                result = ring.mul(result, result);
                if word & (1 << bit) != 0 {
                    result = ring.mul(result, input);
                }
            }
        }
        result
    }

    struct CheckReciprocalRoots;

    impl WithBackend for CheckReciprocalRoots {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            let ring = Ring::<Bls12381, B>::new(backend);
            let cases = [
                ("zero", Fp::ZERO, true),
                ("one", Fp::ONE, true),
                ("square", Fp::from_u64(4), true),
                ("nonresidue", Fp::from_u64(2), false),
                ("near-p nonresidue", p_minus_one(), false),
            ];

            for (name, input, known_square) in cases {
                let canonical = RnsFp::from(input);
                let expected = binary_reciprocal_root(canonical, &ring);
                let check = ring.mul(expected, canonical);
                let expected_square = Fp::from(ring.mul(check, check)) == input;
                assert_eq!(expected_square, known_square, "{name} fixture class");

                let redundant = representative(input, true, &ring);
                assert_eq!(Fp::from(redundant), input, "{name} redundant input");

                for (representation, value) in [("canonical", canonical), ("redundant", redundant)]
                {
                    let (actual_square, actual) = reciprocal_sqrt_fp(value, &ring);
                    assert_eq!(
                        actual_square, expected_square,
                        "{name} {representation} predicate"
                    );
                    assert_eq!(
                        Fp::from(actual),
                        Fp::from(expected),
                        "{name} {representation} candidate"
                    );

                    let actual_check = ring.mul(actual, value);
                    assert_eq!(
                        Fp::from(ring.mul(actual_check, actual_check)) == input,
                        actual_square,
                        "{name} {representation} verified predicate"
                    );
                }
            }
        }
    }

    #[test]
    fn reciprocal_sqrt_matches_binary_exponent_for_canonical_and_redundant_inputs() {
        with_backend(CheckReciprocalRoots);
    }
}
