//! RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_.

use super::{Arithmetic, Curve, Fp, Fp2, G2, MAX_LANES, MINUS_Z, PSI_X, Projective, Workload, psi};
use crate::hash::{self, fp};
use alloc::vec::Vec;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// RFC 9380 Sections 8.8.2 and E.3, in ascending polynomial order.
const G2_A: Fp2 = Fp2::new(Fp::ZERO, Fp::from_u64(240));
const G2_B: Fp2 = Fp2::new(Fp::from_u64(1012), Fp::from_u64(1012));
const G2_Z: Fp2 = Fp2::new(Fp::from_u64(2).neg(), Fp::ONE.neg());

const G2_X_NUM: &[Fp2] = &[
    Fp2::new(
        fp([
            0x6238_aaaa_aaaa_97d6,
            0x5c26_38e3_43d9_c71c,
            0x88b5_8423_c50a_e15d,
            0x32c5_2d39_fd3a_042a,
            0xbb5b_7a9a_47d7_ed85,
            0x05c7_5950_7e8e_333e,
        ]),
        fp([
            0x6238_aaaa_aaaa_97d6,
            0x5c26_38e3_43d9_c71c,
            0x88b5_8423_c50a_e15d,
            0x32c5_2d39_fd3a_042a,
            0xbb5b_7a9a_47d7_ed85,
            0x05c7_5950_7e8e_333e,
        ]),
    ),
    Fp2::new(
        Fp::ZERO,
        fp([
            0x26a9_ffff_ffff_c71a,
            0x1472_aaa9_cb8d_5555,
            0x9a20_8c6b_4f20_a418,
            0x984f_87ad_f7ae_0c7f,
            0x3212_6fce_d787_c88f,
            0x1156_0bf1_7baa_99bc,
        ]),
    ),
    Fp2::new(
        fp([
            0x26a9_ffff_ffff_c71e,
            0x1472_aaa9_cb8d_5555,
            0x9a20_8c6b_4f20_a418,
            0x984f_87ad_f7ae_0c7f,
            0x3212_6fce_d787_c88f,
            0x1156_0bf1_7baa_99bc,
        ]),
        fp([
            0x9354_ffff_ffff_e38d,
            0x0a39_5554_e5c6_aaaa,
            0xcd10_4635_a790_520c,
            0xcc27_c3d6_fbd7_063f,
            0x1909_37e7_6bc3_e447,
            0x08ab_05f8_bdd5_4cde,
        ]),
    ),
    Fp2::new(
        fp([
            0x88e2_aaaa_aaaa_5ed1,
            0x7098_e38d_0f67_1c71,
            0x22d6_108f_142b_8575,
            0xcb14_b4e7_f4e8_10aa,
            0xed6d_ea69_1f5f_b614,
            0x171d_6541_fa38_ccfa,
        ]),
        Fp::ZERO,
    ),
];
const G2_X_DEN: &[Fp2] = &[
    Fp2::new(
        Fp::ZERO,
        fp([
            0xb9fe_ffff_ffff_aa63,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
    ),
    Fp2::new(
        Fp::from_u64(12),
        fp([
            0xb9fe_ffff_ffff_aa9f,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
    ),
    Fp2::new(Fp::from_u64(1), Fp::ZERO),
];
const G2_Y_NUM: &[Fp2] = &[
    Fp2::new(
        fp([
            0x12cf_c71c_71c6_d706,
            0xfc8c_25eb_f8c9_2f68,
            0xf544_39d8_7d27_e500,
            0x0f7d_a5d4_a07f_649b,
            0x59a4_c18b_076d_1193,
            0x1530_477c_7ab4_113b,
        ]),
        fp([
            0x12cf_c71c_71c6_d706,
            0xfc8c_25eb_f8c9_2f68,
            0xf544_39d8_7d27_e500,
            0x0f7d_a5d4_a07f_649b,
            0x59a4_c18b_076d_1193,
            0x1530_477c_7ab4_113b,
        ]),
    ),
    Fp2::new(
        Fp::ZERO,
        fp([
            0x6238_aaaa_aaaa_97be,
            0x5c26_38e3_43d9_c71c,
            0x88b5_8423_c50a_e15d,
            0x32c5_2d39_fd3a_042a,
            0xbb5b_7a9a_47d7_ed85,
            0x05c7_5950_7e8e_333e,
        ]),
    ),
    Fp2::new(
        fp([
            0x26a9_ffff_ffff_c71c,
            0x1472_aaa9_cb8d_5555,
            0x9a20_8c6b_4f20_a418,
            0x984f_87ad_f7ae_0c7f,
            0x3212_6fce_d787_c88f,
            0x1156_0bf1_7baa_99bc,
        ]),
        fp([
            0x9354_ffff_ffff_e38f,
            0x0a39_5554_e5c6_aaaa,
            0xcd10_4635_a790_520c,
            0xcc27_c3d6_fbd7_063f,
            0x1909_37e7_6bc3_e447,
            0x08ab_05f8_bdd5_4cde,
        ]),
    ),
    Fp2::new(
        fp([
            0xe1b3_71c7_1c71_8b10,
            0x4e79_097a_56dc_4bd9,
            0xb0e9_77c6_9aa2_7452,
            0x761b_0f37_a1e2_6286,
            0xfbf7_043d_e381_1ad0,
            0x124c_9ad4_3b6c_f79b,
        ]),
        Fp::ZERO,
    ),
];
const G2_Y_DEN: &[Fp2] = &[
    Fp2::new(
        fp([
            0xb9fe_ffff_ffff_a8fb,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
        fp([
            0xb9fe_ffff_ffff_a8fb,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
    ),
    Fp2::new(
        Fp::ZERO,
        fp([
            0xb9fe_ffff_ffff_a9d3,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
    ),
    Fp2::new(
        Fp::from_u64(18),
        fp([
            0xb9fe_ffff_ffff_aa99,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]),
    ),
    Fp2::new(Fp::from_u64(1), Fp::ZERO),
];

/// (p^2 - 9) / 16 for RFC 9380 F.2.1.1.
const ROOT_EXPONENT: [u64; 12] = [
    0xb26a_a000_01c7_18e3,
    0xd7ce_d6b1_d763_82ea,
    0x3162_c338_3621_13cf,
    0x966b_f91e_d3e7_1b74,
    0xb292_e85a_8709_1a04,
    0x11d6_8619_c861_85c7,
    0xef53_1493_3097_8ef0,
    0x050a_62cf_d16d_dca6,
    0x466e_59e4_9349_e8bd,
    0x9e2d_c90e_50e7_046b,
    0x74bd_278e_aa22_f25e,
    0x002a_437a_4b8c_35fc,
];

/// Z^((p^2 - 1) / 8), a primitive eighth root of unity.
const ROOT_OF_UNITY: Fp2 = Fp2::new(
    fp([
        0xc810_84fb_ede3_cc09,
        0xee67_992f_72ec_05f4,
        0x77f7_6e17_0092_41c5,
        0x4839_5dab_c2d3_435e,
        0x6831_e36d_6bd1_7ffe,
        0x06af_0e04_37ff_400b,
    ]),
    fp([
        0xc810_84fb_ede3_cc09,
        0xee67_992f_72ec_05f4,
        0x77f7_6e17_0092_41c5,
        0x4839_5dab_c2d3_435e,
        0x6831_e36d_6bd1_7ffe,
        0x06af_0e04_37ff_400b,
    ]),
);

/// Z^((p^2 + 7) / 16), the nonsquare correction in sqrt_ratio.
const ROOT_CORRECTION: Fp2 = Fp2::new(
    fp([
        0xfe9d_9a32_3433_6d5e,
        0x6dfa_0340_c422_fb7e,
        0xe484_fcb2_7b8b_e0b3,
        0x57f1_57e1_7f0c_8db4,
        0x6592_4cb0_b6f7_bb98,
        0x13dc_0969_311e_2ba5,
    ]),
    fp([
        0x1b86_84a6_76a8_1381,
        0x73c5_b0e0_2c05_ec38,
        0x2659_dc2f_8263_f1ca,
        0x9a83_0a2c_9691_28d2,
        0x21ac_f918_7d46_9d91,
        0x071d_42ac_9c54_001a,
    ]),
);

/// Hashes to two extension-field elements (RFC 9380, 5.2, m = 2 and L = 64).
fn hash_to_field(dst: &[u8], message: &[u8]) -> [Fp2; 2] {
    let [a, b, c, d] = hash::hash_to_field::<4, 256>(dst, message);
    [Fp2::new(a, b), Fp2::new(c, d)]
}

/// Selects independently in each lane after conversion to scalar coordinates.
#[inline(always)]
fn select<F: Arithmetic<Scalar = Fp2>>(
    f: F,
    a: F::Element,
    b: F::Element,
    choices: &[Choice; MAX_LANES],
) -> F::Element {
    let mut aa = [Fp2::ZERO; MAX_LANES];
    let mut bb = [Fp2::ZERO; MAX_LANES];
    f.store(a, &mut aa);
    f.store(b, &mut bb);
    for lane in 0..F::LANES {
        aa[lane] = Fp2::conditional_select(&aa[lane], &bb[lane], choices[lane]);
    }
    f.load(&aa, Fp2::ZERO)
}

/// Tests equality to one independently in each lane.
#[inline(always)]
fn equal_one<F: Arithmetic<Scalar = Fp2>>(f: F, value: F::Element) -> [Choice; MAX_LANES] {
    let mut values = [Fp2::ZERO; MAX_LANES];
    f.store(value, &mut values);
    let mut choices = [Choice::from(0); MAX_LANES];
    for lane in 0..F::LANES {
        choices[lane] = values[lane].ct_eq(&Fp2::ONE);
    }
    choices
}

/// Returns sqrt(u / v) if square, or sqrt(Z * u / v), with one exponentiation.
///
/// RFC 9380 F.2.1.1, specialized to p^2 = 9 mod 16 (c1 = 3).
#[cfg_attr(not(debug_assertions), inline(always))]
fn sqrt_ratio<F: Arithmetic<Scalar = Fp2>>(
    f: F,
    u: F::Element,
    v: F::Element,
) -> ([Choice; MAX_LANES], F::Element) {
    let mut tv1 = f.constant(ROOT_OF_UNITY);
    let v2 = f.square(v);
    let v3 = f.mul(v2, v);
    let mut tv2 = f.mul(f.square(v3), v);
    let mut tv3 = f.mul(f.square(tv2), v);
    let mut tv5 = f.pow(f.mul(u, tv3), &ROOT_EXPONENT);
    tv5 = f.mul(tv5, tv2);
    tv2 = f.mul(tv5, v);
    tv3 = f.mul(tv5, u);
    let mut tv4 = f.mul(tv3, tv2);
    let square = equal_one(f, f.square(f.square(tv4)));
    tv2 = f.mul(tv3, f.constant(ROOT_CORRECTION));
    tv5 = f.mul(tv4, tv1);
    tv3 = select(f, tv2, tv3, &square);
    tv4 = select(f, tv5, tv4, &square);
    for i in (2..=3).rev() {
        tv5 = tv4;
        for _ in 0..i - 2 {
            tv5 = f.square(tv5);
        }
        let equal = equal_one(f, tv5);
        tv2 = f.mul(tv3, tv1);
        tv1 = f.square(tv1);
        tv5 = f.mul(tv4, tv1);
        tv3 = select(f, tv2, tv3, &equal);
        tv4 = select(f, tv5, tv4, &equal);
    }
    (square, tv3)
}

/// RFC 9380 sgn0 over Fp2, with the real coefficient first.
#[inline(always)]
fn sign(value: Fp2) -> Choice {
    value.c0.is_odd() | (value.c0.is_zero() & value.c1.is_odd())
}

/// Maps to E2' in homogeneous coordinates with one exponentiation per lane.
#[cfg_attr(not(debug_assertions), inline(always))]
fn map_to_curve<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    u: F::Element,
) -> Projective<F::Element> {
    let f = curve.field;
    let hash::Swu {
        zuu,
        x1,
        x2,
        denominator,
        d3,
        numerator,
    } = hash::swu(curve, u, G2_A, G2_B, G2_Z);
    let (square, y1) = sqrt_ratio(f, numerator, d3);
    let y2 = f.mul(f.mul(zuu, u), y1);
    let x = select(f, x2, x1, &square);
    let y = select(f, y2, y1, &square);
    let mut us = [Fp2::ZERO; MAX_LANES];
    let mut ys = [Fp2::ZERO; MAX_LANES];
    f.store(u, &mut us);
    f.store(y, &mut ys);
    for lane in 0..F::LANES {
        ys[lane] =
            Fp2::conditional_select(&ys[lane], &ys[lane].neg(), sign(ys[lane]) ^ sign(us[lane]));
    }
    Projective {
        x,
        y: f.mul(f.load(&ys, Fp2::ZERO), denominator),
        z: denominator,
    }
}

/// Applies the 3-isogeny without an inversion.
#[cfg_attr(not(debug_assertions), inline(always))]
fn isogeny<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    hash::isogeny(curve, p, G2_X_NUM, G2_X_DEN, G2_Y_NUM, G2_Y_DEN)
}

/// Applies psi twice using its constant x factor and y negation (RFC 9380, G.3).
#[inline(always)]
fn psi2<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    const FACTOR: Fp2 = PSI_X.conjugate().mul(PSI_X);
    let f = curve.field;
    Projective {
        x: f.mul(p.x, f.constant(FACTOR)),
        y: f.neg(p.y),
        z: p.z,
    }
}

/// Clears the cofactor by the Budroni-Pintore method (RFC 9380, G.3).
#[cfg_attr(not(debug_assertions), inline(always))]
fn clear_cofactor<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    // Reduce the sum's X coordinate before Frobenius negates its imaginary part.
    let f = curve.field;
    let one = f.constant(Fp2::ONE);
    let p = Projective {
        x: f.mul(p.x, one),
        y: p.y,
        z: p.z,
    };
    let minus_t1 = curve.mul_public(p, &MINUS_Z);
    let t1 = curve.neg(minus_t1);
    let mut t2 = psi(curve, p);
    let mut t3 = psi2(curve, curve.double(p));
    t3 = curve.add(t3, curve.neg(t2));
    t2 = curve.add(t1, t2);
    t2 = curve.neg(curve.mul_public(t2, &MINUS_Z));
    t3 = curve.add(t3, t2);
    t3 = curve.add(t3, minus_t1);
    curve.add(t3, curve.neg(p))
}

/// Hashes one independent message per field lane.
#[derive(Clone, Copy)]
pub(super) struct HashToCurve<'a> {
    pub dst: &'a [u8],
    pub messages: &'a [&'a [u8]],
}

impl Workload<G2> for HashToCurve<'_> {
    type Output = Vec<G2>;

    fn parallel(&self) -> bool {
        self.messages.len() > 1
    }

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> Vec<G2> {
        let f = curve.field;
        let mut output = Vec::with_capacity(self.messages.len());
        for messages in self.messages.chunks(F::LANES) {
            let mut u0 = [Fp2::ZERO; MAX_LANES];
            let mut u1 = [Fp2::ZERO; MAX_LANES];
            for (lane, message) in messages.iter().enumerate() {
                [u0[lane], u1[lane]] = hash_to_field(self.dst, message);
            }
            let p = isogeny(curve, map_to_curve(curve, f.load(&u0, Fp2::ZERO)));
            let q = isogeny(curve, map_to_curve(curve, f.load(&u1, Fp2::ZERO)));
            let point = clear_cofactor(curve, curve.add(p, q));
            let mut points = [G2::IDENTITY.0; MAX_LANES];
            curve.store(point, &mut points);
            for point in &points[..messages.len()] {
                output.push(G2(*point));
            }
        }
        output
    }
}

#[cfg(test)]
mod tests;
