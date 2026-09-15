// Adapted from blst 0.3.16, blst/src/fp12_tower.c.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0
//
// Frobenius maps adapted from VROOM/src/fp12.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! Fixed-word BLS12-381 extension-field arithmetic.

use commonware_cryptography_vroom::{
    Bls12381,
    word::{
        Wide, Word, add_fp2 as word_add_fp2, mul_by_u_plus_one_fp2, mul_fp2 as word_mul_fp2,
        mul_fp2_wide, square_fp2 as word_square_fp2, square_fp2_wide, sub_fp2 as word_sub_fp2,
    },
};

pub(crate) type Fp = Word<Bls12381>;
pub(crate) type Fp2 = [Fp; 2];
pub(crate) type Fp6 = [Fp2; 3];
pub(crate) type Fp12 = [Fp6; 2];

type WideFp2 = [Wide<Bls12381>; 2];
type WideFp6 = [WideFp2; 3];

#[inline]
pub(crate) const fn zero() -> Fp12 {
    [[[Fp::ZERO; 2]; 3]; 2]
}

#[inline]
pub(crate) fn one() -> Fp12 {
    let mut result = zero();
    result[0][0][0] = Fp::one();
    result
}

#[inline(always)]
pub(super) fn fp2_add(a: &Fp2, b: &Fp2) -> Fp2 {
    word_add_fp2(a, b)
}

#[inline(always)]
pub(super) fn fp2_sub(a: &Fp2, b: &Fp2) -> Fp2 {
    word_sub_fp2(a, b)
}

#[inline(always)]
pub(super) fn fp2_double(a: &Fp2) -> Fp2 {
    word_add_fp2(a, a)
}

#[inline(always)]
pub(super) fn fp2_mul_by_u_plus_one(a: &Fp2) -> Fp2 {
    mul_by_u_plus_one_fp2(a)
}

#[inline(always)]
pub(super) fn fp2_mul(a: &Fp2, b: &Fp2) -> Fp2 {
    word_mul_fp2(a, b)
}

#[inline(always)]
pub(super) fn fp2_square(a: &Fp2) -> Fp2 {
    word_square_fp2(a)
}

#[inline(always)]
pub(super) fn fp2_mul_by_fp(a: &Fp2, b: &Fp) -> Fp2 {
    [a[0].mul(b), a[1].mul(b)]
}

#[inline(always)]
pub(super) fn fp2_neg(a: &Fp2) -> Fp2 {
    [a[0].neg(), a[1].neg()]
}

#[inline(always)]
fn wide_fp2_add(a: &WideFp2, b: &WideFp2) -> WideFp2 {
    [a[0].add(&b[0]), a[1].add(&b[1])]
}

#[inline(always)]
fn wide_fp2_sub(a: &WideFp2, b: &WideFp2) -> WideFp2 {
    [a[0].sub(&b[0]), a[1].sub(&b[1])]
}

#[inline(always)]
fn wide_fp2_mul_by_u_plus_one(a: &WideFp2) -> WideFp2 {
    [a[0].sub(&a[1]), a[0].add(&a[1])]
}

#[inline(always)]
fn reduce_fp2(a: &WideFp2) -> Fp2 {
    [a[0].reduce(), a[1].reduce()]
}

#[inline(always)]
fn fp6_add(a: &Fp6, b: &Fp6) -> Fp6 {
    [
        fp2_add(&a[0], &b[0]),
        fp2_add(&a[1], &b[1]),
        fp2_add(&a[2], &b[2]),
    ]
}

#[inline(always)]
fn fp6_sub(a: &Fp6, b: &Fp6) -> Fp6 {
    [
        fp2_sub(&a[0], &b[0]),
        fp2_sub(&a[1], &b[1]),
        fp2_sub(&a[2], &b[2]),
    ]
}

#[inline(always)]
fn fp6_double(a: &Fp6) -> Fp6 {
    [fp2_double(&a[0]), fp2_double(&a[1]), fp2_double(&a[2])]
}

#[inline(always)]
fn fp6_neg(a: &Fp6) -> Fp6 {
    [fp2_neg(&a[0]), fp2_neg(&a[1]), fp2_neg(&a[2])]
}

#[inline(always)]
fn fp6_mul_by_v(a: &Fp6) -> Fp6 {
    [fp2_mul_by_u_plus_one(&a[2]), a[0], a[1]]
}

#[inline(always)]
fn reduce_fp6(a: &WideFp6) -> Fp6 {
    [reduce_fp2(&a[0]), reduce_fp2(&a[1]), reduce_fp2(&a[2])]
}

// Fp2 products remain wide until all three Fp6 coefficients are assembled.
#[inline(always)]
fn mul_fp6_wide(a: &Fp6, b: &Fp6) -> WideFp6 {
    let t0 = mul_fp2_wide(&a[0], &b[0]);
    let t1 = mul_fp2_wide(&a[1], &b[1]);
    let t2 = mul_fp2_wide(&a[2], &b[2]);

    let a12 = fp2_add(&a[1], &a[2]);
    let b12 = fp2_add(&b[1], &b[2]);
    let cross12 = wide_fp2_sub(&wide_fp2_sub(&mul_fp2_wide(&a12, &b12), &t1), &t2);
    let r0 = wide_fp2_add(&wide_fp2_mul_by_u_plus_one(&cross12), &t0);

    let a01 = fp2_add(&a[0], &a[1]);
    let b01 = fp2_add(&b[0], &b[1]);
    let cross01 = wide_fp2_sub(&wide_fp2_sub(&mul_fp2_wide(&a01, &b01), &t0), &t1);
    let r1 = wide_fp2_add(&cross01, &wide_fp2_mul_by_u_plus_one(&t2));

    let a02 = fp2_add(&a[0], &a[2]);
    let b02 = fp2_add(&b[0], &b[2]);
    let cross02 = wide_fp2_sub(&wide_fp2_sub(&mul_fp2_wide(&a02, &b02), &t0), &t2);
    let r2 = wide_fp2_add(&cross02, &t1);

    [r0, r1, r2]
}

#[inline(always)]
fn mul_fp6(a: &Fp6, b: &Fp6) -> Fp6 {
    reduce_fp6(&mul_fp6_wide(a, b))
}

#[inline(always)]
fn square_fp6(a: &Fp6) -> Fp6 {
    let s0 = square_fp2_wide(&a[0]);
    let m01 = mul_fp2_wide(&a[0], &a[1]);
    let m01 = wide_fp2_add(&m01, &m01);
    let m12 = mul_fp2_wide(&a[1], &a[2]);
    let m12 = wide_fp2_add(&m12, &m12);
    let s2 = square_fp2_wide(&a[2]);

    let sum = fp2_add(&fp2_add(&a[2], &a[1]), &a[0]);
    let r2 = wide_fp2_sub(
        &wide_fp2_sub(
            &wide_fp2_sub(&wide_fp2_sub(&square_fp2_wide(&sum), &s0), &s2),
            &m01,
        ),
        &m12,
    );
    let r0 = wide_fp2_add(&s0, &wide_fp2_mul_by_u_plus_one(&m12));
    let r1 = wide_fp2_add(&m01, &wide_fp2_mul_by_u_plus_one(&s2));

    [reduce_fp2(&r0), reduce_fp2(&r1), reduce_fp2(&r2)]
}

#[inline(always)]
fn mul_by_0y0_fp6_wide(a: &Fp6, b: &Fp2) -> WideFp6 {
    let a2b = mul_fp2_wide(&a[2], b);
    [
        wide_fp2_mul_by_u_plus_one(&a2b),
        mul_fp2_wide(&a[0], b),
        mul_fp2_wide(&a[1], b),
    ]
}

#[inline(always)]
fn mul_by_xy0_fp6_wide(a: &Fp6, b0: &Fp2, b1: &Fp2) -> WideFp6 {
    let t0 = mul_fp2_wide(&a[0], b0);
    let t1 = mul_fp2_wide(&a[1], b1);
    let r0 = wide_fp2_add(&wide_fp2_mul_by_u_plus_one(&mul_fp2_wide(&a[2], b1)), &t0);

    let a01 = fp2_add(&a[0], &a[1]);
    let b01 = fp2_add(b0, b1);
    let r1 = wide_fp2_sub(&wide_fp2_sub(&mul_fp2_wide(&a01, &b01), &t0), &t1);
    let r2 = wide_fp2_add(&mul_fp2_wide(&a[2], b0), &t1);
    [r0, r1, r2]
}

/// Multiplies two canonical FP12 values while retaining blst's widened FP2 products.
#[inline]
pub(crate) fn mul(a: &Fp12, b: &Fp12) -> Fp12 {
    let t0 = mul_fp6_wide(&a[0], &b[0]);
    let t1 = mul_fp6_wide(&a[1], &b[1]);

    let a01 = fp6_add(&a[0], &a[1]);
    let b01 = fp6_add(&b[0], &b[1]);
    let cross = mul_fp6_wide(&a01, &b01);
    let r1 = [
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[0], &t0[0]), &t1[0])),
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[1], &t0[1]), &t1[1])),
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[2], &t0[2]), &t1[2])),
    ];

    let r0 = [
        reduce_fp2(&wide_fp2_add(&t0[0], &wide_fp2_mul_by_u_plus_one(&t1[2]))),
        reduce_fp2(&wide_fp2_add(&t0[1], &t1[0])),
        reduce_fp2(&wide_fp2_add(&t0[2], &t1[1])),
    ];

    [r0, r1]
}

/// Multiplies by an FP12 value whose only nonzero FP2 coefficients are 0, 1, and 4.
#[inline]
pub(super) fn mul_by_014(a: &Fp12, c0: &Fp2, c1: &Fp2, c4: &Fp2) -> Fp12 {
    let t0 = mul_by_xy0_fp6_wide(&a[0], c0, c1);
    let t1 = mul_by_0y0_fp6_wide(&a[1], c4);

    let a01 = fp6_add(&a[0], &a[1]);
    let c14 = fp2_add(c1, c4);
    let cross = mul_by_xy0_fp6_wide(&a01, c0, &c14);
    let r1 = [
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[0], &t0[0]), &t1[0])),
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[1], &t0[1]), &t1[1])),
        reduce_fp2(&wide_fp2_sub(&wide_fp2_sub(&cross[2], &t0[2]), &t1[2])),
    ];
    let r0 = [
        reduce_fp2(&wide_fp2_add(&t0[0], &wide_fp2_mul_by_u_plus_one(&t1[2]))),
        reduce_fp2(&wide_fp2_add(&t0[1], &t1[0])),
        reduce_fp2(&wide_fp2_add(&t0[2], &t1[1])),
    ];
    [r0, r1]
}

#[inline]
pub(super) fn invert_fp2(a: &Fp2) -> Option<Fp2> {
    let denominator = a[0].square().add(&a[1].square()).invert()?;
    Some([a[0].mul(&denominator), a[1].neg().mul(&denominator)])
}

#[inline]
fn invert_fp6(a: &Fp6) -> Option<Fp6> {
    let c0 = fp2_sub(
        &fp2_square(&a[0]),
        &fp2_mul_by_u_plus_one(&fp2_mul(&a[1], &a[2])),
    );
    let c1 = fp2_sub(
        &fp2_mul_by_u_plus_one(&fp2_square(&a[2])),
        &fp2_mul(&a[0], &a[1]),
    );
    let c2 = fp2_sub(&fp2_square(&a[1]), &fp2_mul(&a[0], &a[2]));

    let denominator = fp2_add(
        &fp2_mul_by_u_plus_one(&fp2_add(&fp2_mul(&c1, &a[2]), &fp2_mul(&c2, &a[1]))),
        &fp2_mul(&c0, &a[0]),
    );
    let reciprocal = invert_fp2(&denominator)?;
    Some([
        fp2_mul(&c0, &reciprocal),
        fp2_mul(&c1, &reciprocal),
        fp2_mul(&c2, &reciprocal),
    ])
}

/// Returns the multiplicative inverse, or `None` for zero.
#[inline]
pub(super) fn invert(a: &Fp12) -> Option<Fp12> {
    let denominator = fp6_sub(&square_fp6(&a[0]), &fp6_mul_by_v(&square_fp6(&a[1])));
    let reciprocal = invert_fp6(&denominator)?;
    Some([
        mul_fp6(&a[0], &reciprocal),
        fp6_neg(&mul_fp6(&a[1], &reciprocal)),
    ])
}

/// Applies the quadratic-extension conjugation.
#[inline(always)]
pub(super) fn conjugate(a: &Fp12) -> Fp12 {
    [a[0], fp6_neg(&a[1])]
}

const FROB1_2: [u64; 6] = [
    0x8bfd00000000aaac,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
];
const FROB1_3: [u64; 6] = [
    0x8bfd00000000aaad,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
];
const FROB1_4: [u64; 6] = [
    0x2e01fffffffefffe,
    0xde17d813620a0002,
    0xddb3a93be6f89688,
    0xba69c6076a0f77ea,
    0x5f19672fdf76ce51,
    0,
];
const FROB1_5: [u64; 6] = [
    0x8d0775ed92235fb8,
    0xf67ea53d63e7813d,
    0x7b2443d784bab9c4,
    0x0fd603fd3cbd5f4f,
    0xc231beb4202c0d1f,
    0x1904d3bf02bb0667,
];
const FROB1_6: [u64; 6] = [
    0x2cf78a126ddc4af3,
    0x282d5ac14d6c7ec2,
    0xec0c8ec971f63c5f,
    0x54a14787b6c7b36f,
    0x88e9e902231f9fb8,
    0x00fc3e2b36c4e032,
];
const FROB1_7: [u64; 6] = [
    0xc81084fbede3cc09,
    0xee67992f72ec05f4,
    0x77f76e17009241c5,
    0x48395dabc2d3435e,
    0x6831e36d6bd17ffe,
    0x06af0e0437ff400b,
];
const FROB1_8: [u64; 6] = [
    0xf1ee7b04121bdea2,
    0x304466cf3e67fa0a,
    0xef396489f61eb45e,
    0x1c3dedd930b1cf60,
    0xe2e9c448d77a2cd9,
    0x135203e60180a68e,
];
const FROB1_9: [u64; 6] = [
    0x9b18fae980078116,
    0xc63a3e6e257f8732,
    0x8beadf4d8e9c0566,
    0xf39816240c0b8fee,
    0xdf47fa6b48b1e045,
    0x05b2cfd9013a5fd8,
];
const FROB1_10: [u64; 6] = [
    0x1ee605167ff82995,
    0x5871c1908bd478cd,
    0xdb45f3536814f0bd,
    0x70df3560e77982d0,
    0x6bd3ad4afa99cc91,
    0x144e4211384586c1,
];
const FROB2_3: [u64; 6] = [
    0x2e01fffffffeffff,
    0xde17d813620a0002,
    0xddb3a93be6f89688,
    0xba69c6076a0f77ea,
    0x5f19672fdf76ce51,
    0,
];

#[inline]
fn frobenius_coefficient(words: [u64; 6]) -> Fp {
    // The stored constants are canonical integers. This conversion applies the
    // single Montgomery R factor required by Word's representation.
    Fp::from_canonical(words).expect("canonical Frobenius coefficient")
}

#[inline(always)]
const fn flatten(a: &Fp12) -> [Fp; 12] {
    [
        a[0][0][0], a[0][0][1], a[0][1][0], a[0][1][1], a[0][2][0], a[0][2][1], a[1][0][0],
        a[1][0][1], a[1][1][0], a[1][1][1], a[1][2][0], a[1][2][1],
    ]
}

#[inline(always)]
const fn unflatten(a: [Fp; 12]) -> Fp12 {
    [
        [[a[0], a[1]], [a[2], a[3]], [a[4], a[5]]],
        [[a[6], a[7]], [a[8], a[9]], [a[10], a[11]]],
    ]
}

/// Applies the first BLS12-381 Frobenius map.
#[inline]
pub(super) fn frobenius1(a: &Fp12) -> Fp12 {
    let x = flatten(a);
    let c2 = frobenius_coefficient(FROB1_2);
    let c3 = frobenius_coefficient(FROB1_3);
    let c4 = frobenius_coefficient(FROB1_4);
    let c5 = frobenius_coefficient(FROB1_5);
    let c6 = frobenius_coefficient(FROB1_6);
    let c7 = frobenius_coefficient(FROB1_7);
    let c8 = frobenius_coefficient(FROB1_8);
    let c9 = frobenius_coefficient(FROB1_9);
    let c10 = frobenius_coefficient(FROB1_10);

    let x7c6 = x[7].mul(&c6);
    let x8c7 = x[8].mul(&c7);
    let x11c10 = x[11].mul(&c10);
    unflatten([
        x[0],
        x[1].neg(),
        x[3].mul(&c2),
        x[2].mul(&c2),
        x[4].mul(&c3),
        x[5].mul(&c4),
        x7c6.add(&x[6].mul(&c5)),
        x7c6.add(&x[6].mul(&c6)),
        x8c7.add(&x[9].mul(&c7)),
        x8c7.add(&x[9].mul(&c8)),
        x11c10.add(&x[10].mul(&c9)),
        x11c10.add(&x[10].mul(&c10)),
    ])
}

/// Applies the second BLS12-381 Frobenius map.
#[inline]
pub(super) fn frobenius2(a: &Fp12) -> Fp12 {
    let x = flatten(a);
    let c1 = frobenius_coefficient(FROB1_4);
    let c2 = frobenius_coefficient(FROB1_2);
    let c3 = frobenius_coefficient(FROB2_3);
    let c5 = frobenius_coefficient(FROB1_3);
    unflatten([
        x[0],
        x[1],
        x[2].mul(&c1),
        x[3].mul(&c1),
        x[4].mul(&c2),
        x[5].mul(&c2),
        x[6].mul(&c3),
        x[7].mul(&c3),
        x[8].neg(),
        x[9].neg(),
        x[10].mul(&c5),
        x[11].mul(&c5),
    ])
}

/// Applies the third BLS12-381 Frobenius map.
#[inline]
pub(super) fn frobenius3(a: &Fp12) -> Fp12 {
    let x = flatten(a);
    let c2 = frobenius_coefficient(FROB1_8);
    let c3 = frobenius_coefficient(FROB1_7);
    let x7c3 = x[7].mul(&c3);
    let x8c2 = x[8].mul(&c2);
    let x11c2 = x[11].mul(&c2);
    unflatten([
        x[0],
        x[1].neg(),
        x[3],
        x[2],
        x[4].neg(),
        x[5],
        x7c3.add(&x[6].mul(&c2)),
        x7c3.add(&x[6].mul(&c3)),
        x8c2.add(&x[9].mul(&c2)),
        x8c2.add(&x[9].mul(&c3)),
        x11c2.add(&x[10].mul(&c3)),
        x11c2.add(&x[10].mul(&c2)),
    ])
}

/// Squares a canonical FP12 value with blst's dedicated tower formula.
#[inline]
pub(crate) fn square(a: &Fp12) -> Fp12 {
    let a01 = fp6_add(&a[0], &a[1]);
    let a0_plus_va1 = fp6_add(&a[0], &fp6_mul_by_v(&a[1]));
    let combined = mul_fp6(&a01, &a0_plus_va1);
    let cross = mul_fp6(&a[0], &a[1]);
    [
        fp6_sub(&fp6_sub(&combined, &cross), &fp6_mul_by_v(&cross)),
        fp6_double(&cross),
    ]
}

#[inline(always)]
fn square_fp4(a0: &Fp2, a1: &Fp2) -> [Fp2; 2] {
    let t0 = square_fp2_wide(a0);
    let t1 = square_fp2_wide(a1);
    let sum = fp2_add(a0, a1);

    let r0 = reduce_fp2(&wide_fp2_add(&t0, &wide_fp2_mul_by_u_plus_one(&t1)));
    let r1 = reduce_fp2(&wide_fp2_sub(
        &wide_fp2_sub(&square_fp2_wide(&sum), &t0),
        &t1,
    ));
    [r0, r1]
}

/// Squares an FP12 value known to be in the cyclotomic subgroup.
#[inline]
pub(crate) fn cyclotomic_square(a: &Fp12) -> Fp12 {
    let t0 = square_fp4(&a[0][0], &a[1][1]);
    let t1 = square_fp4(&a[1][0], &a[0][2]);
    let mut t2 = square_fp4(&a[0][1], &a[1][2]);

    let r00 = fp2_add(&fp2_double(&fp2_sub(&t0[0], &a[0][0])), &t0[0]);
    let r01 = fp2_add(&fp2_double(&fp2_sub(&t1[0], &a[0][1])), &t1[0]);
    let r02 = fp2_add(&fp2_double(&fp2_sub(&t2[0], &a[0][2])), &t2[0]);

    t2[1] = fp2_mul_by_u_plus_one(&t2[1]);
    let r10 = fp2_add(&fp2_double(&fp2_add(&t2[1], &a[1][0])), &t2[1]);
    let r11 = fp2_add(&fp2_double(&fp2_add(&t0[1], &a[1][1])), &t0[1]);
    let r12 = fp2_add(&fp2_double(&fp2_add(&t1[1], &a[1][2])), &t1[1]);

    [[r00, r01, r02], [r10, r11, r12]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        Fp as RnsFp,
        extension::{
            Fp2 as RnsFp2, Fp6 as RnsFp6, Fp12 as RnsFp12,
            tests::{oracle_bytes, oracle_fp12},
        },
    };
    use blst::{blst_fp12, blst_fp12_frobenius_map, blst_fp12_inverse, blst_fp12_mul};

    fn rns_fp2(c0: u64, c1: u64) -> RnsFp2 {
        RnsFp2 {
            c0: RnsFp::from_u64(c0),
            c1: RnsFp::from_u64(c1),
        }
    }

    fn fixture() -> RnsFp12 {
        RnsFp12([
            RnsFp6([rns_fp2(1, 2), rns_fp2(3, 4), rns_fp2(5, 6)]),
            RnsFp6([rns_fp2(7, 8), rns_fp2(9, 10), rns_fp2(11, 12)]),
        ])
    }

    fn import_fp2(value: RnsFp2) -> Fp2 {
        [Fp::from_element(value.c0), Fp::from_element(value.c1)]
    }

    fn import(value: RnsFp12) -> Fp12 {
        value.0.map(|half| half.0.map(import_fp2))
    }

    fn export_fp2(value: &Fp2) -> RnsFp2 {
        RnsFp2 {
            c0: value[0].to_element(),
            c1: value[1].to_element(),
        }
    }

    fn export(value: &Fp12) -> RnsFp12 {
        RnsFp12(value.map(|half| RnsFp6(half.map(|coefficient| export_fp2(&coefficient)))))
    }

    #[test]
    fn word_tower_new_operations_match_rns_and_blst() {
        let input = fixture();
        let word_input = import(input);
        let c0 = rns_fp2(13, 14);
        let c1 = rns_fp2(15, 16);
        let c4 = rns_fp2(17, 18);
        let word_c0 = import_fp2(c0);
        let word_c1 = import_fp2(c1);
        let word_c4 = import_fp2(c4);
        let sparse = RnsFp12([
            RnsFp6([c0, c1, RnsFp2::ZERO]),
            RnsFp6([RnsFp2::ZERO, c4, RnsFp2::ZERO]),
        ]);

        let sparse_result = mul_by_014(&word_input, &word_c0, &word_c1, &word_c4);
        let dense_result = mul(&word_input, &import(sparse));
        let mut oracle = blst_fp12::default();
        let oracle_input = oracle_fp12(input);
        let oracle_sparse = oracle_fp12(sparse);
        // SAFETY: All pointers reference initialized, non-overlapping FP12 values.
        unsafe { blst_fp12_mul(&mut oracle, &oracle_input, &oracle_sparse) };
        assert_eq!(
            export(&sparse_result).to_bytes(),
            input.mul(sparse).to_bytes()
        );
        assert_eq!(
            export(&sparse_result).to_bytes(),
            export(&dense_result).to_bytes()
        );
        assert_eq!(export(&sparse_result).to_bytes(), oracle_bytes(&oracle));

        assert!(invert(&zero()).is_none());
        let inverse = invert(&word_input).expect("nonzero fixture");
        // SAFETY: The nonzero input and output are initialized FP12 values.
        unsafe { blst_fp12_inverse(&mut oracle, &oracle_input) };
        assert_eq!(mul(&word_input, &inverse), one());
        assert_eq!(
            export(&inverse).to_bytes(),
            input.invert().expect("nonzero fixture").to_bytes()
        );
        assert_eq!(export(&inverse).to_bytes(), oracle_bytes(&oracle));
        assert_eq!(
            export(&conjugate(&word_input)).to_bytes(),
            input.conjugate().to_bytes()
        );

        let frobenius1_rns = input.frobenius();
        let frobenius2_rns = frobenius1_rns.frobenius();
        let frobenius3_rns = frobenius2_rns.frobenius();
        for (power, actual, expected_rns) in [
            (1, frobenius1(&word_input), frobenius1_rns),
            (2, frobenius2(&word_input), frobenius2_rns),
            (3, frobenius3(&word_input), frobenius3_rns),
        ] {
            // SAFETY: The power is in blst's supported range 1..=3 and all values are initialized.
            unsafe { blst_fp12_frobenius_map(&mut oracle, &oracle_input, power) };
            assert_eq!(export(&actual).to_bytes(), expected_rns.to_bytes());
            assert_eq!(export(&actual).to_bytes(), oracle_bytes(&oracle));
        }
    }
}
