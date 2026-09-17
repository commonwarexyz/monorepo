// Adapted from VROOM/src/fp12.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! Bounded flattened arithmetic for the degree-twelve extension field.

use super::bounded::Fp2;
use crate::bls12381::Fp;
use commonware_cryptography_vroom::{
    Bls12381,
    rns::{
        Backend, Expanded, Ring, Standard as RnsStandard,
        bounds::{Bound, Range},
    },
};

pub(crate) type Fp12<const N: i64> = [Expanded<Bls12381, Range<0, 2>, Range<0, N>>; 12];
pub(crate) type Standard = Fp12<1>;

#[inline]
pub(crate) const fn one() -> Standard {
    let mut result = [RnsStandard::<Bls12381>::ZERO; 12];
    result[0] = RnsStandard::<Bls12381>::ONE;
    result
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn mul<const N1: i64, const N2: i64, B: Backend>(
    x: &Fp12<N1>,
    y: &Fp12<N2>,
    ring: &Ring<Bls12381, B>,
) -> Standard
where
    Range<0, N1>: Bound,
    Range<0, N2>: Bound,
{
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_y1 = ring.negate(y[1]);
    let minus_y3 = ring.negate(y[3]);
    let minus_y5 = ring.negate(y[5]);
    let minus_y7 = ring.negate(y[7]);
    let minus_y9 = ring.negate(y[9]);
    let minus_y11 = ring.negate(y[11]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared = offset
        + x_left[2] * y[4]
        + x_left[3] * minus_y5
        + x_left[4] * y[2]
        + x_left[5] * minus_y3
        + x_left[6] * y[10]
        + x_left[7] * minus_y11
        + x_left[8] * y[8]
        + x_left[9] * minus_y9
        + x_left[10] * y[6]
        + x_left[11] * minus_y7;
    let poly_0_neg_shared = (x_left[2] * y[5]).complete()
        + x_left[3] * y[4]
        + x_left[4] * y[3]
        + x_left[5] * y[2]
        + x_left[6] * y[11]
        + x_left[7] * y[10]
        + x_left[8] * y[9]
        + x_left[9] * y[8]
        + x_left[10] * y[7]
        + x_left[11] * y[6];
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * y[0] + x_left[1] * minus_y1;
    let poly_1_unique = poly_0_pos_shared + poly_0_neg_shared + x_left[0] * y[1] + x_left[1] * y[0];

    let poly_2_pos_shared = offset
        + x_left[4] * y[4]
        + x_left[5] * minus_y5
        + x_left[8] * y[10]
        + x_left[9] * minus_y11
        + x_left[10] * y[8]
        + x_left[11] * minus_y9;
    let poly_2_neg_shared = (x_left[4] * y[5]).complete()
        + x_left[5] * y[4]
        + x_left[8] * y[11]
        + x_left[9] * y[10]
        + x_left[10] * y[9]
        + x_left[11] * y[8];
    let poly_2_unique = poly_2_pos_shared - poly_2_neg_shared
        + x_left[0] * y[2]
        + x_left[1] * minus_y3
        + x_left[2] * y[0]
        + x_left[3] * minus_y1
        + x_left[6] * y[6]
        + x_left[7] * minus_y7;
    let poly_3_unique = poly_2_pos_shared
        + poly_2_neg_shared
        + x_left[0] * y[3]
        + x_left[1] * y[2]
        + x_left[2] * y[1]
        + x_left[3] * y[0]
        + x_left[6] * y[7]
        + x_left[7] * y[6];

    let poly_4_pos_shared = offset + x_left[10] * y[10] + x_left[11] * minus_y11;
    let poly_4_neg_shared = (x_left[10] * y[11]).complete() + x_left[11] * y[10];
    let poly_4_unique = poly_4_pos_shared - poly_4_neg_shared
        + x_left[0] * y[4]
        + x_left[1] * minus_y5
        + x_left[2] * y[2]
        + x_left[3] * minus_y3
        + x_left[4] * y[0]
        + x_left[5] * minus_y1
        + x_left[6] * y[8]
        + x_left[7] * minus_y9
        + x_left[8] * y[6]
        + x_left[9] * minus_y7;
    let poly_5_unique = poly_4_pos_shared
        + poly_4_neg_shared
        + x_left[0] * y[5]
        + x_left[1] * y[4]
        + x_left[2] * y[3]
        + x_left[3] * y[2]
        + x_left[4] * y[1]
        + x_left[5] * y[0]
        + x_left[6] * y[9]
        + x_left[7] * y[8]
        + x_left[8] * y[7]
        + x_left[9] * y[6];

    let poly_6_pos_shared = offset
        + x_left[2] * y[10]
        + x_left[3] * minus_y11
        + x_left[4] * y[8]
        + x_left[5] * minus_y9
        + x_left[8] * y[4]
        + x_left[9] * minus_y5
        + x_left[10] * y[2]
        + x_left[11] * minus_y3;
    let poly_6_neg_shared = (x_left[2] * y[11]).complete()
        + x_left[3] * y[10]
        + x_left[4] * y[9]
        + x_left[5] * y[8]
        + x_left[8] * y[5]
        + x_left[9] * y[4]
        + x_left[10] * y[3]
        + x_left[11] * y[2];
    let poly_6_unique = poly_6_pos_shared - poly_6_neg_shared
        + x_left[0] * y[6]
        + x_left[1] * minus_y7
        + x_left[6] * y[0]
        + x_left[7] * minus_y1;
    let poly_7_unique = poly_6_pos_shared
        + poly_6_neg_shared
        + x_left[0] * y[7]
        + x_left[1] * y[6]
        + x_left[6] * y[1]
        + x_left[7] * y[0];

    let poly_8_pos_shared = offset
        + x_left[4] * y[10]
        + x_left[5] * minus_y11
        + x_left[10] * y[4]
        + x_left[11] * minus_y5;
    let poly_8_neg_shared =
        (x_left[4] * y[11]).complete() + x_left[5] * y[10] + x_left[10] * y[5] + x_left[11] * y[4];
    let poly_8_unique = poly_8_pos_shared - poly_8_neg_shared
        + x_left[0] * y[8]
        + x_left[1] * minus_y9
        + x_left[2] * y[6]
        + x_left[3] * minus_y7
        + x_left[6] * y[2]
        + x_left[7] * minus_y3
        + x_left[8] * y[0]
        + x_left[9] * minus_y1;
    let poly_9_unique = poly_8_pos_shared
        + poly_8_neg_shared
        + x_left[0] * y[9]
        + x_left[1] * y[8]
        + x_left[2] * y[7]
        + x_left[3] * y[6]
        + x_left[6] * y[3]
        + x_left[7] * y[2]
        + x_left[8] * y[1]
        + x_left[9] * y[0];

    let poly_10_unique = (x_left[0] * y[10]).complete()
        + x_left[1] * minus_y11
        + x_left[2] * y[8]
        + x_left[3] * minus_y9
        + x_left[4] * y[6]
        + x_left[5] * minus_y7
        + x_left[6] * y[4]
        + x_left[7] * minus_y5
        + x_left[8] * y[2]
        + x_left[9] * minus_y3
        + x_left[10] * y[0]
        + x_left[11] * minus_y1;
    let poly_11_unique = (x_left[0] * y[11]).complete()
        + x_left[1] * y[10]
        + x_left[2] * y[9]
        + x_left[3] * y[8]
        + x_left[4] * y[7]
        + x_left[5] * y[6]
        + x_left[6] * y[5]
        + x_left[7] * y[4]
        + x_left[8] * y[3]
        + x_left[9] * y[2]
        + x_left[10] * y[1]
        + x_left[11] * y[0];

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
        ring.ready::<800>(poly_6_unique),
        ring.ready::<800>(poly_7_unique),
        ring.ready::<800>(poly_8_unique),
        ring.ready::<800>(poly_9_unique),
        ring.ready::<800>(poly_10_unique),
        ring.ready::<800>(poly_11_unique),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn mul_by_014<L0, R0, L1, R1, B: Backend>(
    x: &Standard,
    c0: Fp2<Expanded<Bls12381, L0, R0>, Expanded<Bls12381, L1, R1>>,
    c1: Fp2<RnsStandard<Bls12381>>,
    c4: Fp2<RnsStandard<Bls12381>>,
    ring: &Ring<Bls12381, B>,
) -> Standard
where
    L0: Bound,
    R0: Bound,
    L1: Bound,
    R1: Bound,
{
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let y0 = c0.c0;
    let y1 = c0.c1;
    let y2 = c1.c0;
    let y3 = c1.c1;
    let y8 = c4.c0;
    let y9 = c4.c1;
    let minus_y1 = ring.negate(y1);
    let minus_y3 = ring.negate(y3);
    let minus_y9 = ring.negate(y9);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared =
        offset + x_left[4] * y2 + x_left[5] * minus_y3 + x_left[8] * y8 + x_left[9] * minus_y9;
    let poly_0_neg_shared =
        (x_left[4] * y3).complete() + x_left[5] * y2 + x_left[8] * y9 + x_left[9] * y8;
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * y0 + x_left[1] * minus_y1;
    let poly_1_unique = poly_0_pos_shared + poly_0_neg_shared + x_left[0] * y1 + x_left[1] * y0;

    let poly_2_pos_shared = offset + x_left[10] * y8 + x_left[11] * minus_y9;
    let poly_2_neg_shared = (x_left[10] * y9).complete() + x_left[11] * y8;
    let poly_2_unique = poly_2_pos_shared - poly_2_neg_shared
        + x_left[0] * y2
        + x_left[1] * minus_y3
        + x_left[2] * y0
        + x_left[3] * minus_y1;
    let poly_3_unique = poly_2_pos_shared
        + poly_2_neg_shared
        + x_left[0] * y3
        + x_left[1] * y2
        + x_left[2] * y1
        + x_left[3] * y0;

    let poly_4_unique = (x_left[2] * y2).complete()
        + x_left[3] * minus_y3
        + x_left[4] * y0
        + x_left[5] * minus_y1
        + x_left[6] * y8
        + x_left[7] * minus_y9;
    let poly_5_unique = (x_left[2] * y3).complete()
        + x_left[3] * y2
        + x_left[4] * y1
        + x_left[5] * y0
        + x_left[6] * y9
        + x_left[7] * y8;

    let poly_6_pos_shared =
        offset + x_left[4] * y8 + x_left[5] * minus_y9 + x_left[10] * y2 + x_left[11] * minus_y3;
    let poly_6_neg_shared =
        (x_left[4] * y9).complete() + x_left[5] * y8 + x_left[10] * y3 + x_left[11] * y2;
    let poly_6_unique =
        poly_6_pos_shared - poly_6_neg_shared + x_left[6] * y0 + x_left[7] * minus_y1;
    let poly_7_unique = poly_6_pos_shared + poly_6_neg_shared + x_left[6] * y1 + x_left[7] * y0;

    let poly_8_unique = (x_left[0] * y8).complete()
        + x_left[1] * minus_y9
        + x_left[6] * y2
        + x_left[7] * minus_y3
        + x_left[8] * y0
        + x_left[9] * minus_y1;
    let poly_9_unique = (x_left[0] * y9).complete()
        + x_left[1] * y8
        + x_left[6] * y3
        + x_left[7] * y2
        + x_left[8] * y1
        + x_left[9] * y0;
    let poly_10_unique = (x_left[2] * y8).complete()
        + x_left[3] * minus_y9
        + x_left[8] * y2
        + x_left[9] * minus_y3
        + x_left[10] * y0
        + x_left[11] * minus_y1;
    let poly_11_unique = (x_left[2] * y9).complete()
        + x_left[3] * y8
        + x_left[8] * y3
        + x_left[9] * y2
        + x_left[10] * y1
        + x_left[11] * y0;

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
        ring.ready::<800>(poly_6_unique),
        ring.ready::<800>(poly_7_unique),
        ring.ready::<800>(poly_8_unique),
        ring.ready::<800>(poly_9_unique),
        ring.ready::<800>(poly_10_unique),
        ring.ready::<800>(poly_11_unique),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn square<B: Backend>(x: &Standard, ring: &Ring<Bls12381, B>) -> Standard {
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_x1 = ring.negate(x[1]);
    let minus_x3 = ring.negate(x[3]);
    let minus_x5 = ring.negate(x[5]);
    let minus_x7 = ring.negate(x[7]);
    let minus_x9 = ring.negate(x[9]);
    let minus_x11 = ring.negate(x[11]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared = offset
        + ((x_left[2] * x[4]).complete()
            + x_left[3] * minus_x5
            + x_left[6] * x[10]
            + x_left[7] * minus_x11)
            .scale::<2>()
        + x_left[8] * x[8]
        + x_left[9] * minus_x9;
    let poly_0_neg_shared = ((x_left[2] * x[5]).complete()
        + x_left[3] * x[4]
        + x_left[6] * x[11]
        + x_left[7] * x[10]
        + x_left[8] * x[9])
        .scale::<2>();
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * x[0] + x_left[1] * minus_x1;
    let poly_1_unique =
        poly_0_pos_shared + poly_0_neg_shared + (x_left[0] * x[1]).complete().scale::<2>();

    let poly_2_pos_shared = offset
        + ((x_left[8] * x[10]).complete() + x_left[9] * minus_x11).scale::<2>()
        + x_left[4] * x[4]
        + x_left[5] * minus_x5;
    let poly_2_neg_shared =
        ((x_left[4] * x[5]).complete() + x_left[8] * x[11] + x_left[9] * x[10]).scale::<2>();
    let poly_2_unique = poly_2_pos_shared - poly_2_neg_shared
        + ((x_left[0] * x[2]).complete() + x_left[1] * minus_x3).scale::<2>()
        + x_left[6] * x[6]
        + x_left[7] * minus_x7;
    let poly_3_unique = poly_2_pos_shared
        + poly_2_neg_shared
        + ((x_left[0] * x[3]).complete() + x_left[1] * x[2] + x_left[6] * x[7]).scale::<2>();

    let poly_4_pos_shared = (x_left[10] * x[10]).complete() + x_left[11] * minus_x11;
    let poly_4_unique = poly_4_pos_shared
        + ((x_left[0] * x[4]).complete()
            + x_left[1] * minus_x5
            + x_left[6] * x[8]
            + x_left[7] * minus_x9
            + x_left[10] * minus_x11)
            .scale::<2>()
        + x_left[2] * x[2]
        + x_left[3] * minus_x3;
    let poly_5_unique = poly_4_pos_shared
        + ((x_left[0] * x[5]).complete()
            + x_left[1] * x[4]
            + x_left[2] * x[3]
            + x_left[6] * x[9]
            + x_left[7] * x[8]
            + x_left[10] * x[11])
            .scale::<2>();

    let poly_6_pos_shared = offset
        + x_left[2] * x[10]
        + x_left[3] * minus_x11
        + x_left[4] * x[8]
        + x_left[5] * minus_x9;
    let poly_6_neg_shared =
        (x_left[2] * x[11]).complete() + x_left[3] * x[10] + x_left[4] * x[9] + x_left[5] * x[8];
    let poly_6_unique =
        (poly_6_pos_shared - poly_6_neg_shared + x_left[0] * x[6] + x_left[1] * minus_x7)
            .scale::<2>();
    let poly_7_unique =
        (poly_6_pos_shared + poly_6_neg_shared + x_left[0] * x[7] + x_left[1] * x[6]).scale::<2>();

    let poly_8_pos_shared = offset + x_left[4] * x[10] + x_left[5] * minus_x11;
    let poly_8_neg_shared = (x_left[4] * x[11]).complete() + x_left[5] * x[10];
    let poly_8_unique = (poly_8_pos_shared - poly_8_neg_shared
        + x_left[0] * x[8]
        + x_left[1] * minus_x9
        + x_left[2] * x[6]
        + x_left[3] * minus_x7)
        .scale::<2>();
    let poly_9_unique = (poly_8_pos_shared
        + poly_8_neg_shared
        + x_left[0] * x[9]
        + x_left[1] * x[8]
        + x_left[2] * x[7]
        + x_left[3] * x[6])
        .scale::<2>();

    let poly_10_unique = ((x_left[0] * x[10]).complete()
        + x_left[1] * minus_x11
        + x_left[2] * x[8]
        + x_left[3] * minus_x9
        + x_left[4] * x[6]
        + x_left[5] * minus_x7)
        .scale::<2>();
    let poly_11_unique = ((x_left[0] * x[11]).complete()
        + x_left[1] * x[10]
        + x_left[2] * x[9]
        + x_left[3] * x[8]
        + x_left[4] * x[7]
        + x_left[5] * x[6])
        .scale::<2>();

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
        ring.ready::<800>(poly_6_unique),
        ring.ready::<800>(poly_7_unique),
        ring.ready::<800>(poly_8_unique),
        ring.ready::<800>(poly_9_unique),
        ring.ready::<800>(poly_10_unique),
        ring.ready::<800>(poly_11_unique),
    ])
}

const ONE_THIRD_FP: Fp = Fp::from_raw(&[
    0x26a9ffffffffc71d,
    0x1472aaa9cb8d5555,
    0x9a208c6b4f20a418,
    0x984f87adf7ae0c7f,
    0x32126fced787c88f,
    0x11560bf17baa99bc,
])
.expect("canonical one-third coefficient");
const NEG_TWO_THIRDS_FP: Fp = Fp::from_raw(&[
    0x26a9ffffffffc71c,
    0x1472aaa9cb8d5555,
    0x9a208c6b4f20a418,
    0x984f87adf7ae0c7f,
    0x32126fced787c88f,
    0x11560bf17baa99bc,
])
.expect("canonical negative two-thirds coefficient");

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn cyclotomic_square<const N: i64, B: Backend>(
    x: &Fp12<N>,
    ring: &Ring<Bls12381, B>,
) -> Fp12<6>
where
    Range<0, N>: Bound,
{
    let one_third: RnsStandard<Bls12381> = ONE_THIRD_FP.into();
    let neg_two_thirds: RnsStandard<Bls12381> = NEG_TWO_THIRDS_FP.into();
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_x1 = ring.negate(x[1]);
    let minus_x3 = ring.negate(x[3]);
    let minus_x5 = ring.negate(x[5]);
    let minus_x7 = ring.negate(x[7]);
    let minus_x9 = ring.negate(x[9]);
    let minus_x11 = ring.negate(x[11]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared = (x_left[8] * x[8]).complete() + x_left[9] * minus_x9;
    let poly_0_unique = poly_0_pos_shared
        + (x_left[8] * minus_x9).complete().scale::<2>()
        + x_left[0] * x[0]
        + x_left[0] * neg_two_thirds
        + x_left[1] * minus_x1;
    let poly_1_unique = poly_0_pos_shared
        + ((x_left[0] * x[1]).complete() + x_left[8] * x[9]).scale::<2>()
        + x_left[1] * neg_two_thirds;

    let poly_2_pos_shared = (x_left[4] * x[4]).complete() + x_left[5] * minus_x5;
    let poly_2_unique = poly_2_pos_shared
        + (x_left[4] * minus_x5).complete().scale::<2>()
        + x_left[2] * neg_two_thirds
        + x_left[6] * x[6]
        + x_left[7] * minus_x7;
    let poly_3_unique = poly_2_pos_shared
        + ((x_left[6] * x[7]).complete() + x_left[4] * x[5]).scale::<2>()
        + x_left[3] * neg_two_thirds;

    let poly_4_pos_shared = (x_left[10] * x[10]).complete() + x_left[11] * minus_x11;
    let poly_4_unique = poly_4_pos_shared
        + (x_left[10] * minus_x11).complete().scale::<2>()
        + x_left[2] * x[2]
        + x_left[3] * minus_x3
        + x_left[4] * neg_two_thirds;
    let poly_5_unique = poly_4_pos_shared
        + ((x_left[2] * x[3]).complete() + x_left[10] * x[11]).scale::<2>()
        + x_left[5] * neg_two_thirds;

    let first_half = ring.batch_reduce(&[
        ring.ready::<200>(poly_0_unique),
        ring.ready::<200>(poly_1_unique),
        ring.ready::<200>(poly_2_unique),
        ring.ready::<200>(poly_3_unique),
        ring.ready::<200>(poly_4_unique),
        ring.ready::<200>(poly_5_unique),
    ]);
    let mut first_prepared = [ring
        .prep_expand(first_half[0].scale::<3>())
        .recast_rns::<Range<0, 6>>(); 6];
    for (output, value) in first_prepared[1..].iter_mut().zip(&first_half[1..]) {
        *output = ring
            .prep_expand(value.scale::<3>())
            .recast_rns::<Range<0, 6>>();
    }
    let first_half = ring.batch_expand(&first_prepared);

    let poly_6_pos_shared = offset + x_left[2] * x[10] + x_left[3] * minus_x11;
    let poly_6_neg_shared = (x_left[2] * x[11]).complete() + x_left[3] * x[10];
    let poly_6_unique = poly_6_pos_shared - poly_6_neg_shared + x_left[6] * one_third;
    let poly_7_unique = poly_6_pos_shared + poly_6_neg_shared + x_left[7] * one_third;
    let poly_8_unique =
        (x_left[0] * x[8]).complete() + x_left[1] * minus_x9 + x_left[8] * one_third;
    let poly_9_unique = (x_left[0] * x[9]).complete() + x_left[1] * x[8] + x_left[9] * one_third;
    let poly_10_unique =
        (x_left[4] * x[6]).complete() + x_left[5] * minus_x7 + x_left[10] * one_third;
    let poly_11_unique = (x_left[4] * x[7]).complete() + x_left[5] * x[6] + x_left[11] * one_third;

    let second_half = ring.batch_reduce(&[
        ring.ready::<200>(poly_6_unique),
        ring.ready::<200>(poly_7_unique),
        ring.ready::<200>(poly_8_unique),
        ring.ready::<200>(poly_9_unique),
        ring.ready::<200>(poly_10_unique),
        ring.ready::<200>(poly_11_unique),
    ]);
    let mut second_prepared = [ring
        .prep_expand(second_half[0].scale::<6>())
        .recast_rns::<Range<0, 6>>(); 6];
    for (output, value) in second_prepared[1..].iter_mut().zip(&second_half[1..]) {
        *output = ring
            .prep_expand(value.scale::<6>())
            .recast_rns::<Range<0, 6>>();
    }
    let second_half = ring.batch_expand(&second_prepared);

    core::array::from_fn(|i| {
        if i < 6 {
            first_half[i]
        } else {
            second_half[i - 6]
        }
    })
}

const FROB1_2_FP: Fp = fp(&[
    0x8bfd00000000aaac,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
]);
const FROB1_3_FP: Fp = fp(&[
    0x8bfd00000000aaad,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
]);
const FROB1_4_FP: Fp = fp(&[
    0x2e01fffffffefffe,
    0xde17d813620a0002,
    0xddb3a93be6f89688,
    0xba69c6076a0f77ea,
    0x5f19672fdf76ce51,
    0,
]);
const FROB1_5_FP: Fp = fp(&[
    0x8d0775ed92235fb8,
    0xf67ea53d63e7813d,
    0x7b2443d784bab9c4,
    0x0fd603fd3cbd5f4f,
    0xc231beb4202c0d1f,
    0x1904d3bf02bb0667,
]);
const FROB1_6_FP: Fp = fp(&[
    0x2cf78a126ddc4af3,
    0x282d5ac14d6c7ec2,
    0xec0c8ec971f63c5f,
    0x54a14787b6c7b36f,
    0x88e9e902231f9fb8,
    0x00fc3e2b36c4e032,
]);
const FROB1_7_FP: Fp = fp(&[
    0xc81084fbede3cc09,
    0xee67992f72ec05f4,
    0x77f76e17009241c5,
    0x48395dabc2d3435e,
    0x6831e36d6bd17ffe,
    0x06af0e0437ff400b,
]);
const FROB1_8_FP: Fp = fp(&[
    0xf1ee7b04121bdea2,
    0x304466cf3e67fa0a,
    0xef396489f61eb45e,
    0x1c3dedd930b1cf60,
    0xe2e9c448d77a2cd9,
    0x135203e60180a68e,
]);
const FROB1_9_FP: Fp = fp(&[
    0x9b18fae980078116,
    0xc63a3e6e257f8732,
    0x8beadf4d8e9c0566,
    0xf39816240c0b8fee,
    0xdf47fa6b48b1e045,
    0x05b2cfd9013a5fd8,
]);
const FROB1_10_FP: Fp = fp(&[
    0x1ee605167ff82995,
    0x5871c1908bd478cd,
    0xdb45f3536814f0bd,
    0x70df3560e77982d0,
    0x6bd3ad4afa99cc91,
    0x144e4211384586c1,
]);
const FROB2_3_FP: Fp = fp(&[
    0x2e01fffffffeffff,
    0xde17d813620a0002,
    0xddb3a93be6f89688,
    0xba69c6076a0f77ea,
    0x5f19672fdf76ce51,
    0,
]);

const fn fp(words: &[u64]) -> Fp {
    Fp::from_raw(words).expect("canonical FP12 coefficient")
}

#[inline]
fn standard(value: Fp) -> RnsStandard<Bls12381> {
    value.into()
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn frobenius1<B: Backend>(x: &Standard, ring: &Ring<Bls12381, B>) -> Standard {
    let mut x_left = [ring.prep_left(x[0]); 12];
    for (output, value) in x_left[1..].iter_mut().zip(&x[1..]) {
        *output = ring.prep_left(*value);
    }
    let frob1_2 = standard(FROB1_2_FP);
    let frob1_3 = standard(FROB1_3_FP);
    let frob1_4 = standard(FROB1_4_FP);
    let frob1_5 = standard(FROB1_5_FP);
    let frob1_6 = standard(FROB1_6_FP);
    let frob1_7 = standard(FROB1_7_FP);
    let frob1_8 = standard(FROB1_8_FP);
    let frob1_9 = standard(FROB1_9_FP);
    let frob1_10 = standard(FROB1_10_FP);

    let frob1_2_2 = x_left[2] * frob1_2;
    let frob1_2_3 = x_left[3] * frob1_2;
    let frob1_3_4 = x_left[4] * frob1_3;
    let frob1_4_5 = x_left[5] * frob1_4;
    let frob1_5_6 = x_left[6] * frob1_5;
    let frob1_6_6 = x_left[6] * frob1_6;
    let frob1_6_7 = x_left[7] * frob1_6;
    let frob1_7_8 = x_left[8] * frob1_7;
    let frob1_7_9 = x_left[9] * frob1_7;
    let frob1_8_9 = x_left[9] * frob1_8;
    let frob1_9_10 = x_left[10] * frob1_9;
    let frob1_10_10 = x_left[10] * frob1_10;
    let frob1_10_11 = x_left[11] * frob1_10;
    let poly6_unique = frob1_6_7.complete() + frob1_5_6;
    let poly7_unique = frob1_6_7.complete() + frob1_6_6;
    let poly8_unique = frob1_7_8.complete() + frob1_7_9;
    let poly9_unique = frob1_7_8.complete() + frob1_8_9;
    let poly10_unique = frob1_10_11.complete() + frob1_9_10;
    let poly11_unique = frob1_10_11.complete() + frob1_10_10;
    let reduced = ring.batch_reduce_expand(&[
        ring.ready::<800>(frob1_2_3),
        ring.ready::<800>(frob1_2_2),
        ring.ready::<800>(frob1_3_4),
        ring.ready::<800>(frob1_4_5),
        ring.ready::<800>(poly6_unique),
        ring.ready::<800>(poly7_unique),
        ring.ready::<800>(poly8_unique),
        ring.ready::<800>(poly9_unique),
        ring.ready::<800>(poly10_unique),
        ring.ready::<800>(poly11_unique),
    ]);
    [
        x[0],
        ring.standard_negate(x[1]),
        reduced[0],
        reduced[1],
        reduced[2],
        reduced[3],
        reduced[4],
        reduced[5],
        reduced[6],
        reduced[7],
        reduced[8],
        reduced[9],
    ]
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn frobenius2<const N: i64, B: Backend>(x: &Fp12<N>, ring: &Ring<Bls12381, B>) -> Fp12<N>
where
    Range<0, N>: Bound,
{
    let mut x_left = [ring.prep_left(x[0]); 12];
    let mut i = 1;
    while i < x_left.len() {
        x_left[i] = ring.prep_left(x[i]);
        i += 1;
    }
    let frob2_1 = standard(FROB1_4_FP);
    let frob2_2 = standard(FROB1_2_FP);
    let frob2_3 = standard(FROB2_3_FP);
    let frob2_5 = standard(FROB1_3_FP);
    let reduced = ring.batch_reduce_expand(&[
        ring.ready::<800>(x_left[2] * frob2_1),
        ring.ready::<800>(x_left[3] * frob2_1),
        ring.ready::<800>(x_left[4] * frob2_2),
        ring.ready::<800>(x_left[5] * frob2_2),
        ring.ready::<800>(x_left[6] * frob2_3),
        ring.ready::<800>(x_left[7] * frob2_3),
        ring.ready::<800>(x_left[10] * frob2_5),
        ring.ready::<800>(x_left[11] * frob2_5),
    ]);
    [
        x[0],
        x[1],
        reduced[0].recast_rns::<Range<0, N>>(),
        reduced[1].recast_rns::<Range<0, N>>(),
        reduced[2].recast_rns::<Range<0, N>>(),
        reduced[3].recast_rns::<Range<0, N>>(),
        reduced[4].recast_rns::<Range<0, N>>(),
        reduced[5].recast_rns::<Range<0, N>>(),
        ring.standard_negate(x[8]),
        ring.standard_negate(x[9]),
        reduced[6].recast_rns::<Range<0, N>>(),
        reduced[7].recast_rns::<Range<0, N>>(),
    ]
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn frobenius3<B: Backend>(x: &Standard, ring: &Ring<Bls12381, B>) -> Standard {
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let frob3_2 = standard(FROB1_8_FP);
    let frob3_3 = standard(FROB1_7_FP);
    let frob3_2_6 = x_left[6] * frob3_2;
    let frob3_2_8 = x_left[8] * frob3_2;
    let frob3_2_9 = x_left[9] * frob3_2;
    let frob3_2_10 = x_left[10] * frob3_2;
    let frob3_2_11 = x_left[11] * frob3_2;
    let frob3_3_9 = x_left[9] * frob3_3;
    let frob3_3_10 = x_left[10] * frob3_3;
    let frob3_3_6 = x_left[6] * frob3_3;
    let frob3_3_7 = x_left[7] * frob3_3;
    let poly6_unique = frob3_3_7.complete() + frob3_2_6;
    let poly7_unique = frob3_3_7.complete() + frob3_3_6;
    let poly8_unique = frob3_2_8.complete() + frob3_2_9;
    let poly9_unique = frob3_2_8.complete() + frob3_3_9;
    let poly10_unique = frob3_2_11.complete() + frob3_3_10;
    let poly11_unique = frob3_2_11.complete() + frob3_2_10;
    let reduced = ring.batch_reduce_expand(&[
        ring.ready::<800>(poly6_unique),
        ring.ready::<800>(poly7_unique),
        ring.ready::<800>(poly8_unique),
        ring.ready::<800>(poly9_unique),
        ring.ready::<800>(poly10_unique),
        ring.ready::<800>(poly11_unique),
    ]);
    [
        x[0],
        ring.standard_negate(x[1]),
        x[3],
        x[2],
        ring.standard_negate(x[4]),
        x[5],
        reduced[0],
        reduced[1],
        reduced[2],
        reduced[3],
        reduced[4],
        reduced[5],
    ]
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn conjugate<const N: i64, B: Backend>(x: &Fp12<N>, ring: &Ring<Bls12381, B>) -> Fp12<N>
where
    Range<0, N>: Bound,
{
    [
        x[0],
        x[1],
        x[2],
        x[3],
        x[4],
        x[5],
        ring.standard_negate(x[6]),
        ring.standard_negate(x[7]),
        ring.standard_negate(x[8]),
        ring.standard_negate(x[9]),
        ring.standard_negate(x[10]),
        ring.standard_negate(x[11]),
    ]
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn inverse_to_fp6<B: Backend>(
    x: &Standard,
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 6] {
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_x1 = ring.negate(x[1]);
    let minus_x3 = ring.negate(x[3]);
    let minus_x5 = ring.negate(x[5]);
    let minus_x6 = ring.negate(x[6]);
    let minus_x7 = ring.negate(x[7]);
    let minus_x8 = ring.negate(x[8]);
    let minus_x9 = ring.negate(x[9]);
    let minus_x10 = ring.negate(x[10]);
    let minus_x11 = ring.negate(x[11]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared = offset
        + ((x_left[2] * x[4]).complete()
            + x_left[3] * minus_x5
            + x_left[6] * minus_x10
            + x_left[7] * x[11])
            .scale::<2>()
        + x_left[8] * minus_x8
        + x_left[9] * x[9];
    let poly_0_neg_shared = ((x_left[2] * x[5]).complete()
        + x_left[3] * x[4]
        + x_left[6] * minus_x11
        + x_left[7] * minus_x10
        + x_left[8] * minus_x9)
        .scale::<2>();
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * x[0] + x_left[1] * minus_x1;
    let poly_1_unique =
        poly_0_pos_shared + poly_0_neg_shared + (x_left[0] * x[1]).complete().scale::<2>();

    let poly_2_pos_shared = offset
        + ((x_left[8] * minus_x10).complete() + x_left[9] * x[11]).scale::<2>()
        + x_left[4] * x[4]
        + x_left[5] * minus_x5;
    let poly_2_neg_shared =
        ((x_left[4] * x[5]).complete() + x_left[8] * minus_x11 + x_left[9] * minus_x10)
            .scale::<2>();
    let poly_2_unique = poly_2_pos_shared - poly_2_neg_shared
        + ((x_left[0] * x[2]).complete() + x_left[1] * minus_x3).scale::<2>()
        + x_left[6] * minus_x6
        + x_left[7] * x[7];
    let poly_3_unique = poly_2_pos_shared
        + poly_2_neg_shared
        + ((x_left[0] * x[3]).complete() + x_left[1] * x[2] + x_left[6] * minus_x7).scale::<2>();

    let poly_4_pos_shared = offset + x_left[10] * minus_x10 + x_left[11] * x[11];
    let poly_4_unique = poly_4_pos_shared
        + ((x_left[0] * x[4]).complete()
            + x_left[1] * minus_x5
            + x_left[6] * minus_x8
            + x_left[7] * x[9]
            + x_left[10] * x[11])
            .scale::<2>()
        + x_left[2] * x[2]
        + x_left[3] * minus_x3;
    let poly_5_unique = poly_4_pos_shared
        + ((x_left[0] * x[5]).complete()
            + x_left[1] * x[4]
            + x_left[2] * x[3]
            + x_left[6] * minus_x9
            + x_left[7] * minus_x8
            + x_left[10] * minus_x11)
            .scale::<2>();

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp6_inverse_cofactors<B: Backend>(
    x: &[RnsStandard<Bls12381>; 6],
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 6] {
    let x_left: [_; 6] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_x1 = ring.negate(x[1]);
    let minus_x2 = ring.negate(x[2]);
    let minus_x3 = ring.negate(x[3]);
    let minus_x4 = ring.negate(x[4]);
    let minus_x5 = ring.negate(x[5]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared = offset + x_left[2] * minus_x4 + x_left[3] * x[5];
    let poly_0_neg_shared = (x_left[2] * minus_x5).complete() + x_left[3] * minus_x4;
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * x[0] + x_left[1] * minus_x1;
    let poly_1_unique =
        poly_0_pos_shared + poly_0_neg_shared + (x_left[0] * x[1]).complete().scale::<2>();

    let poly_2_pos_shared = offset + x_left[4] * x[4] + x_left[5] * minus_x5;
    let poly_2_unique = poly_2_pos_shared
        + (x_left[4] * minus_x5).complete().scale::<2>()
        + x_left[0] * minus_x2
        + x_left[1] * x[3];
    let poly_3_unique = poly_2_pos_shared
        + (x_left[4] * x[5]).complete().scale::<2>()
        + x_left[0] * minus_x3
        + x_left[1] * minus_x2;
    let poly_4_unique = (x_left[2] * x[2]).complete()
        + x_left[3] * minus_x3
        + x_left[0] * minus_x4
        + x_left[1] * x[5];
    let poly_5_unique =
        (x_left[2] * x[3]).complete().scale::<2>() + x_left[0] * minus_x5 + x_left[1] * minus_x4;

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp6_inverse_to_fp2<B: Backend>(
    x: &[RnsStandard<Bls12381>; 6],
    y: &[RnsStandard<Bls12381>; 6],
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 2] {
    let x_left: [_; 6] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_y1 = ring.negate(y[1]);
    let minus_y3 = ring.negate(y[3]);
    let minus_y5 = ring.negate(y[5]);
    let offset = ring.wide_offset::<80, 1440>();
    let poly_0_pos_shared =
        offset + x_left[2] * y[4] + x_left[3] * minus_y5 + x_left[4] * y[2] + x_left[5] * minus_y3;
    let poly_0_neg_shared =
        (x_left[2] * y[5]).complete() + x_left[3] * y[4] + x_left[4] * y[3] + x_left[5] * y[2];
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * y[0] + x_left[1] * minus_y1;
    let poly_1_unique = poly_0_pos_shared + poly_0_neg_shared + x_left[0] * y[1] + x_left[1] * y[0];
    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
    ])
}

#[inline]
fn fp2_inverse_to_fp<B: Backend>(
    x: &[RnsStandard<Bls12381>; 2],
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 1] {
    let x_left: [_; 2] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let poly_0_unique = (x_left[0] * x[0]).complete() + x_left[1] * x[1];
    ring.batch_reduce_expand(&[ring.ready::<800>(poly_0_unique)])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp_inverse_to_fp2<B: Backend>(
    x: &[RnsStandard<Bls12381>; 2],
    inverse: RnsStandard<Bls12381>,
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 2] {
    let x_left = [ring.prep_left(x[0]), ring.prep_left(x[1])];
    let minus_inverse = ring.negate(inverse);
    ring.batch_reduce_expand(&[
        ring.ready::<800>(x_left[0] * inverse),
        ring.ready::<800>(x_left[1] * minus_inverse),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp2_inverse_to_fp6<B: Backend>(
    x: &[RnsStandard<Bls12381>; 6],
    y: &[RnsStandard<Bls12381>; 2],
    ring: &Ring<Bls12381, B>,
) -> [RnsStandard<Bls12381>; 6] {
    let y_left = [ring.prep_left(y[0]), ring.prep_left(y[1])];
    let minus_x1 = ring.negate(x[1]);
    let minus_x3 = ring.negate(x[3]);
    let minus_x5 = ring.negate(x[5]);
    ring.batch_reduce_expand(&[
        ring.ready::<800>((y_left[0] * x[0]).complete() + y_left[1] * minus_x1),
        ring.ready::<800>((y_left[0] * x[1]).complete() + y_left[1] * x[0]),
        ring.ready::<800>((y_left[0] * x[2]).complete() + y_left[1] * minus_x3),
        ring.ready::<800>((y_left[0] * x[3]).complete() + y_left[1] * x[2]),
        ring.ready::<800>((y_left[0] * x[4]).complete() + y_left[1] * minus_x5),
        ring.ready::<800>((y_left[0] * x[5]).complete() + y_left[1] * x[4]),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn fp6_inverse_to_fp12<B: Backend>(
    x: &Standard,
    y: &[RnsStandard<Bls12381>; 6],
    ring: &Ring<Bls12381, B>,
) -> Standard {
    let x_left: [_; 12] = core::array::from_fn(
        #[inline(always)]
        |i| ring.prep_left(x[i]),
    );
    let minus_y0 = ring.negate(y[0]);
    let minus_y1 = ring.negate(y[1]);
    let minus_y2 = ring.negate(y[2]);
    let minus_y3 = ring.negate(y[3]);
    let minus_y4 = ring.negate(y[4]);
    let minus_y5 = ring.negate(y[5]);
    let offset = ring.wide_offset::<80, 1440>();

    let poly_0_pos_shared =
        offset + x_left[2] * y[4] + x_left[3] * minus_y5 + x_left[4] * y[2] + x_left[5] * minus_y3;
    let poly_0_neg_shared =
        (x_left[2] * y[5]).complete() + x_left[3] * y[4] + x_left[4] * y[3] + x_left[5] * y[2];
    let poly_0_unique =
        poly_0_pos_shared - poly_0_neg_shared + x_left[0] * y[0] + x_left[1] * minus_y1;
    let poly_1_unique = poly_0_pos_shared + poly_0_neg_shared + x_left[0] * y[1] + x_left[1] * y[0];

    let poly_2_pos_shared = offset + x_left[4] * y[4] + x_left[5] * minus_y5;
    let poly_2_neg_shared = (x_left[4] * y[5]).complete() + x_left[5] * y[4];
    let poly_2_unique = poly_2_pos_shared - poly_2_neg_shared
        + x_left[0] * y[2]
        + x_left[1] * minus_y3
        + x_left[2] * y[0]
        + x_left[3] * minus_y1;
    let poly_3_unique = poly_2_pos_shared
        + poly_2_neg_shared
        + x_left[0] * y[3]
        + x_left[1] * y[2]
        + x_left[2] * y[1]
        + x_left[3] * y[0];
    let poly_4_unique = (x_left[0] * y[4]).complete()
        + x_left[1] * minus_y5
        + x_left[2] * y[2]
        + x_left[3] * minus_y3
        + x_left[4] * y[0]
        + x_left[5] * minus_y1;
    let poly_5_unique = (x_left[0] * y[5]).complete()
        + x_left[1] * y[4]
        + x_left[2] * y[3]
        + x_left[3] * y[2]
        + x_left[4] * y[1]
        + x_left[5] * y[0];

    let poly_6_pos_shared = offset
        + x_left[8] * minus_y4
        + x_left[9] * y[5]
        + x_left[10] * minus_y2
        + x_left[11] * y[3];
    let poly_6_neg_shared = (x_left[8] * minus_y5).complete()
        + x_left[9] * minus_y4
        + x_left[10] * minus_y3
        + x_left[11] * minus_y2;
    let poly_6_unique =
        poly_6_pos_shared - poly_6_neg_shared + x_left[6] * minus_y0 + x_left[7] * y[1];
    let poly_7_unique =
        poly_6_pos_shared + poly_6_neg_shared + x_left[6] * minus_y1 + x_left[7] * minus_y0;

    let poly_8_pos_shared = offset + x_left[10] * minus_y4 + x_left[11] * y[5];
    let poly_8_neg_shared = (x_left[10] * minus_y5).complete() + x_left[11] * minus_y4;
    let poly_8_unique = poly_8_pos_shared - poly_8_neg_shared
        + x_left[6] * minus_y2
        + x_left[7] * y[3]
        + x_left[8] * minus_y0
        + x_left[9] * y[1];
    let poly_9_unique = poly_8_pos_shared
        + poly_8_neg_shared
        + x_left[6] * minus_y3
        + x_left[7] * minus_y2
        + x_left[8] * minus_y1
        + x_left[9] * minus_y0;
    let poly_10_unique = (x_left[6] * minus_y4).complete()
        + x_left[7] * y[5]
        + x_left[8] * minus_y2
        + x_left[9] * y[3]
        + x_left[10] * minus_y0
        + x_left[11] * y[1];
    let poly_11_unique = (x_left[6] * minus_y5).complete()
        + x_left[7] * minus_y4
        + x_left[8] * minus_y3
        + x_left[9] * minus_y2
        + x_left[10] * minus_y1
        + x_left[11] * minus_y0;

    ring.batch_reduce_expand(&[
        ring.ready::<800>(poly_0_unique),
        ring.ready::<800>(poly_1_unique),
        ring.ready::<800>(poly_2_unique),
        ring.ready::<800>(poly_3_unique),
        ring.ready::<800>(poly_4_unique),
        ring.ready::<800>(poly_5_unique),
        ring.ready::<800>(poly_6_unique),
        ring.ready::<800>(poly_7_unique),
        ring.ready::<800>(poly_8_unique),
        ring.ready::<800>(poly_9_unique),
        ring.ready::<800>(poly_10_unique),
        ring.ready::<800>(poly_11_unique),
    ])
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn invert<B: Backend>(x: &Standard, ring: &Ring<Bls12381, B>) -> Option<Standard> {
    let fp6 = inverse_to_fp6(x, ring);
    let cofactors = fp6_inverse_cofactors(&fp6, ring);
    let fp2 = fp6_inverse_to_fp2(&cofactors, &fp6, ring);
    let fp = fp2_inverse_to_fp(&fp2, ring);
    let fp_inverse = ring.invert(fp[0])?;
    let fp2_inverse = fp_inverse_to_fp2(&fp2, fp_inverse, ring);
    let fp6_inverse = fp2_inverse_to_fp6(&cofactors, &fp2_inverse, ring);
    Some(fp6_inverse_to_fp12(x, &fp6_inverse, ring))
}
