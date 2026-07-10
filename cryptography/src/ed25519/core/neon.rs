//! Four-lane NEON field kernels for batched point decompression on aarch64.
//!
//! The square-root chain in [`super::fe`] interleaves four independent
//! computations to fill the multiplier pipes; this module runs the same four
//! lanes in NEON vectors instead, which roughly doubles throughput again on
//! cores with wider vector than scalar multiply issue (Apple M-series has
//! four 128-bit NEON pipes against two scalar multiply pipes).
//!
//! Field elements use ten unsigned limbs in radix 2^25.5 (even limbs 26
//! bits, odd limbs 25 bits), with vector i holding limb i of all four lanes.
//! The multiplication, squaring, and carry schedules and their bounds are
//! curve25519-dalek's serial u32 backend, verbatim.

use super::fe::{sqrt_fixup, Fe};
use core::arch::aarch64::{
    uint32x4_t, uint64x2_t, vaddq_u64, vandq_u64, vdupq_n_u32, vdupq_n_u64, vget_low_u32,
    vld1q_u32, vmlal_high_u32, vmlal_u32, vmull_high_u32, vmull_u32, vmulq_u32,
    vreinterpretq_u32_u64, vshlq_n_u32, vshlq_n_u64, vshrq_n_u64, vst1q_u32, vuzp1q_u32,
};

/// Four field elements, limb i of every lane in vector i.
#[derive(Copy, Clone)]
pub(crate) struct Fe25x4([uint32x4_t; 10]);

/// A 64-bit accumulator column: lanes 0-1 and lanes 2-3.
type Acc = (uint64x2_t, uint64x2_t);

impl Fe25x4 {
    /// Pack four elements. Input limbs must be below 2^52, which keeps every
    /// split limb within one excess bit of its 26/25-bit radix (the schedules
    /// below tolerate up to 1.75 excess bits).
    pub(crate) fn pack(lanes: &[Fe; 4]) -> Self {
        let mut split = [[0u32; 4]; 10];
        for (l, fe) in lanes.iter().enumerate() {
            for i in 0..5 {
                debug_assert!(fe.0[i] < 1 << 52);
                split[2 * i][l] = (fe.0[i] & ((1 << 26) - 1)) as u32;
                split[2 * i + 1][l] = (fe.0[i] >> 26) as u32;
            }
        }
        // SAFETY: NEON is a mandatory feature of every aarch64 target.
        Self(core::array::from_fn(|i| unsafe {
            vld1q_u32(split[i].as_ptr())
        }))
    }

    /// Unpack four elements (limbs below 2^52).
    pub(crate) fn unpack(&self) -> [Fe; 4] {
        let mut split = [[0u32; 4]; 10];
        for (dst, src) in split.iter_mut().zip(&self.0) {
            // SAFETY: NEON is a mandatory feature of every aarch64 target.
            unsafe { vst1q_u32(dst.as_mut_ptr(), *src) };
        }
        core::array::from_fn(|l| {
            Fe(core::array::from_fn(|i| {
                split[2 * i][l] as u64 + ((split[2 * i + 1][l] as u64) << 26)
            }))
        })
    }

    /// Lane-wise multiplication (dalek's serial u32 schedule).
    fn mul(&self, rhs: &Self) -> Self {
        let x = &self.0;
        let y = &rhs.0;
        // SAFETY: NEON is a mandatory feature of every aarch64 target.
        unsafe {
            let nineteen = vdupq_n_u32(19);
            let y1_19 = vmulq_u32(y[1], nineteen);
            let y2_19 = vmulq_u32(y[2], nineteen);
            let y3_19 = vmulq_u32(y[3], nineteen);
            let y4_19 = vmulq_u32(y[4], nineteen);
            let y5_19 = vmulq_u32(y[5], nineteen);
            let y6_19 = vmulq_u32(y[6], nineteen);
            let y7_19 = vmulq_u32(y[7], nineteen);
            let y8_19 = vmulq_u32(y[8], nineteen);
            let y9_19 = vmulq_u32(y[9], nineteen);
            let x1_2 = vshlq_n_u32::<1>(x[1]);
            let x3_2 = vshlq_n_u32::<1>(x[3]);
            let x5_2 = vshlq_n_u32::<1>(x[5]);
            let x7_2 = vshlq_n_u32::<1>(x[7]);
            let x9_2 = vshlq_n_u32::<1>(x[9]);

            macro_rules! dot {
                ($(($a:expr, $b:expr)),+ $(,)?) => {{
                    let mut acc: Option<Acc> = None;
                    $(
                        acc = Some(match acc {
                            None => (
                                vmull_u32(vget_low_u32($a), vget_low_u32($b)),
                                vmull_high_u32($a, $b),
                            ),
                            Some(z) => (
                                vmlal_u32(z.0, vget_low_u32($a), vget_low_u32($b)),
                                vmlal_high_u32(z.1, $a, $b),
                            ),
                        });
                    )+
                    acc.unwrap()
                }};
            }

            let z = [
                dot!(
                    (x[0], y[0]),
                    (x1_2, y9_19),
                    (x[2], y8_19),
                    (x3_2, y7_19),
                    (x[4], y6_19),
                    (x5_2, y5_19),
                    (x[6], y4_19),
                    (x7_2, y3_19),
                    (x[8], y2_19),
                    (x9_2, y1_19)
                ),
                dot!(
                    (x[0], y[1]),
                    (x[1], y[0]),
                    (x[2], y9_19),
                    (x[3], y8_19),
                    (x[4], y7_19),
                    (x[5], y6_19),
                    (x[6], y5_19),
                    (x[7], y4_19),
                    (x[8], y3_19),
                    (x[9], y2_19)
                ),
                dot!(
                    (x[0], y[2]),
                    (x1_2, y[1]),
                    (x[2], y[0]),
                    (x3_2, y9_19),
                    (x[4], y8_19),
                    (x5_2, y7_19),
                    (x[6], y6_19),
                    (x7_2, y5_19),
                    (x[8], y4_19),
                    (x9_2, y3_19)
                ),
                dot!(
                    (x[0], y[3]),
                    (x[1], y[2]),
                    (x[2], y[1]),
                    (x[3], y[0]),
                    (x[4], y9_19),
                    (x[5], y8_19),
                    (x[6], y7_19),
                    (x[7], y6_19),
                    (x[8], y5_19),
                    (x[9], y4_19)
                ),
                dot!(
                    (x[0], y[4]),
                    (x1_2, y[3]),
                    (x[2], y[2]),
                    (x3_2, y[1]),
                    (x[4], y[0]),
                    (x5_2, y9_19),
                    (x[6], y8_19),
                    (x7_2, y7_19),
                    (x[8], y6_19),
                    (x9_2, y5_19)
                ),
                dot!(
                    (x[0], y[5]),
                    (x[1], y[4]),
                    (x[2], y[3]),
                    (x[3], y[2]),
                    (x[4], y[1]),
                    (x[5], y[0]),
                    (x[6], y9_19),
                    (x[7], y8_19),
                    (x[8], y7_19),
                    (x[9], y6_19)
                ),
                dot!(
                    (x[0], y[6]),
                    (x1_2, y[5]),
                    (x[2], y[4]),
                    (x3_2, y[3]),
                    (x[4], y[2]),
                    (x5_2, y[1]),
                    (x[6], y[0]),
                    (x7_2, y9_19),
                    (x[8], y8_19),
                    (x9_2, y7_19)
                ),
                dot!(
                    (x[0], y[7]),
                    (x[1], y[6]),
                    (x[2], y[5]),
                    (x[3], y[4]),
                    (x[4], y[3]),
                    (x[5], y[2]),
                    (x[6], y[1]),
                    (x[7], y[0]),
                    (x[8], y9_19),
                    (x[9], y8_19)
                ),
                dot!(
                    (x[0], y[8]),
                    (x1_2, y[7]),
                    (x[2], y[6]),
                    (x3_2, y[5]),
                    (x[4], y[4]),
                    (x5_2, y[3]),
                    (x[6], y[2]),
                    (x7_2, y[1]),
                    (x[8], y[0]),
                    (x9_2, y9_19)
                ),
                dot!(
                    (x[0], y[9]),
                    (x[1], y[8]),
                    (x[2], y[7]),
                    (x[3], y[6]),
                    (x[4], y[5]),
                    (x[5], y[4]),
                    (x[6], y[3]),
                    (x[7], y[2]),
                    (x[8], y[1]),
                    (x[9], y[0])
                ),
            ];
            Self(reduce(z))
        }
    }

    /// Lane-wise squaring (dalek's serial u32 schedule: the doubled product
    /// group is accumulated separately and doubled once as a 64-bit value).
    fn square(&self) -> Self {
        let x = &self.0;
        // SAFETY: NEON is a mandatory feature of every aarch64 target.
        unsafe {
            let nineteen = vdupq_n_u32(19);
            let x0_2 = vshlq_n_u32::<1>(x[0]);
            let x1_2 = vshlq_n_u32::<1>(x[1]);
            let x2_2 = vshlq_n_u32::<1>(x[2]);
            let x3_2 = vshlq_n_u32::<1>(x[3]);
            let x4_2 = vshlq_n_u32::<1>(x[4]);
            let x5_2 = vshlq_n_u32::<1>(x[5]);
            let x6_2 = vshlq_n_u32::<1>(x[6]);
            let x7_2 = vshlq_n_u32::<1>(x[7]);
            let x5_19 = vmulq_u32(x[5], nineteen);
            let x6_19 = vmulq_u32(x[6], nineteen);
            let x7_19 = vmulq_u32(x[7], nineteen);
            let x8_19 = vmulq_u32(x[8], nineteen);
            let x9_19 = vmulq_u32(x[9], nineteen);

            macro_rules! dot {
                ($(($a:expr, $b:expr)),+ $(,)?) => {{
                    let mut acc: Option<Acc> = None;
                    $(
                        acc = Some(match acc {
                            None => (
                                vmull_u32(vget_low_u32($a), vget_low_u32($b)),
                                vmull_high_u32($a, $b),
                            ),
                            Some(z) => (
                                vmlal_u32(z.0, vget_low_u32($a), vget_low_u32($b)),
                                vmlal_high_u32(z.1, $a, $b),
                            ),
                        });
                    )+
                    acc.unwrap()
                }};
            }
            // Combine a plain group with a group whose sum is doubled.
            macro_rules! plus2x {
                ($plain:expr, $dbl:expr) => {{
                    let p: Acc = $plain;
                    let d: Acc = $dbl;
                    (
                        vaddq_u64(p.0, vshlq_n_u64::<1>(d.0)),
                        vaddq_u64(p.1, vshlq_n_u64::<1>(d.1)),
                    )
                }};
            }

            let z = [
                plus2x!(
                    dot!((x[0], x[0]), (x2_2, x8_19), (x4_2, x6_19)),
                    dot!((x1_2, x9_19), (x3_2, x7_19), (x[5], x5_19))
                ),
                plus2x!(
                    dot!((x0_2, x[1]), (x3_2, x8_19), (x5_2, x6_19)),
                    dot!((x[2], x9_19), (x[4], x7_19))
                ),
                plus2x!(
                    dot!((x0_2, x[2]), (x1_2, x[1]), (x4_2, x8_19), (x[6], x6_19)),
                    dot!((x3_2, x9_19), (x5_2, x7_19))
                ),
                plus2x!(
                    dot!((x0_2, x[3]), (x1_2, x[2]), (x5_2, x8_19)),
                    dot!((x[4], x9_19), (x[6], x7_19))
                ),
                plus2x!(
                    dot!((x0_2, x[4]), (x1_2, x3_2), (x[2], x[2]), (x6_2, x8_19)),
                    dot!((x5_2, x9_19), (x[7], x7_19))
                ),
                plus2x!(
                    dot!((x0_2, x[5]), (x1_2, x[4]), (x2_2, x[3]), (x7_2, x8_19)),
                    dot!((x[6], x9_19))
                ),
                plus2x!(
                    dot!(
                        (x0_2, x[6]),
                        (x1_2, x5_2),
                        (x2_2, x[4]),
                        (x3_2, x[3]),
                        (x[8], x8_19)
                    ),
                    dot!((x7_2, x9_19))
                ),
                plus2x!(
                    dot!((x0_2, x[7]), (x1_2, x[6]), (x2_2, x[5]), (x3_2, x[4])),
                    dot!((x[8], x9_19))
                ),
                plus2x!(
                    dot!(
                        (x0_2, x[8]),
                        (x1_2, x7_2),
                        (x2_2, x[6]),
                        (x3_2, x5_2),
                        (x[4], x[4])
                    ),
                    dot!((x[9], x9_19))
                ),
                dot!(
                    (x0_2, x[9]),
                    (x1_2, x[8]),
                    (x2_2, x[7]),
                    (x3_2, x[6]),
                    (x4_2, x[5])
                ),
            ];
            Self(reduce(z))
        }
    }

    /// `self^(2^k)` by repeated squaring.
    fn pow2k(&self, k: u32) -> Self {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }
}

/// Carry-propagate ten accumulator columns (dalek's u32 reduce chain).
#[inline(always)]
fn reduce(mut z: [Acc; 10]) -> [uint32x4_t; 10] {
    // SAFETY: NEON is a mandatory feature of every aarch64 target.
    unsafe {
        macro_rules! carry {
            ($i:expr, $bits:literal) => {{
                let mask = vdupq_n_u64((1u64 << $bits) - 1);
                z[$i + 1].0 = vaddq_u64(z[$i + 1].0, vshrq_n_u64::<$bits>(z[$i].0));
                z[$i + 1].1 = vaddq_u64(z[$i + 1].1, vshrq_n_u64::<$bits>(z[$i].1));
                z[$i].0 = vandq_u64(z[$i].0, mask);
                z[$i].1 = vandq_u64(z[$i].1, mask);
            }};
        }
        carry!(0, 26);
        carry!(4, 26);
        carry!(1, 25);
        carry!(5, 25);
        carry!(2, 26);
        carry!(6, 26);
        carry!(3, 25);
        carry!(7, 25);
        carry!(4, 26);
        carry!(8, 26);
        // z[0] += 19 * (z[9] >> 25), as shift-adds (NEON has no 64-bit
        // vector multiply): 19c = 16c + 2c + c.
        let mask25 = vdupq_n_u64((1 << 25) - 1);
        let c = (vshrq_n_u64::<25>(z[9].0), vshrq_n_u64::<25>(z[9].1));
        z[0].0 = vaddq_u64(
            z[0].0,
            vaddq_u64(vaddq_u64(vshlq_n_u64::<4>(c.0), vshlq_n_u64::<1>(c.0)), c.0),
        );
        z[0].1 = vaddq_u64(
            z[0].1,
            vaddq_u64(vaddq_u64(vshlq_n_u64::<4>(c.1), vshlq_n_u64::<1>(c.1)), c.1),
        );
        z[9].0 = vandq_u64(z[9].0, mask25);
        z[9].1 = vandq_u64(z[9].1, mask25);
        carry!(0, 26);

        // Every column is now below 2^32: keep the even 32-bit halves.
        core::array::from_fn(|i| {
            vuzp1q_u32(vreinterpretq_u32_u64(z[i].0), vreinterpretq_u32_u64(z[i].1))
        })
    }
}

/// `x^(2^250 - 1)` for four lanes (dalek's `pow22501` chain).
fn pow_p22501_x4(x: &Fe25x4) -> Fe25x4 {
    let t0 = x.square();
    let t1 = t0.square().square();
    let t2 = x.mul(&t1);
    let t3 = t0.mul(&t2);
    let t4 = t3.square();
    let t5 = t2.mul(&t4);
    let t6 = t5.pow2k(5);
    let t7 = t6.mul(&t5);
    let t8 = t7.pow2k(10);
    let t9 = t8.mul(&t7);
    let t10 = t9.pow2k(20);
    let t11 = t10.mul(&t9);
    let t12 = t11.pow2k(10);
    let t13 = t12.mul(&t7);
    let t14 = t13.pow2k(50);
    let t15 = t14.mul(&t13);
    let t16 = t15.pow2k(100);
    let t17 = t16.mul(&t15);
    let t18 = t17.pow2k(50);
    t18.mul(&t13)
}

/// Square roots of `u/v` for four lanes, with the semantics of
/// [`super::fe::sqrt_ratio_i_w`].
pub(crate) fn sqrt_ratio_i_x4(u: &[Fe; 4], v: &[Fe; 4]) -> ([bool; 4], [Fe; 4]) {
    let uv = (Fe25x4::pack(u), Fe25x4::pack(v));
    let v3 = uv.1.square().mul(&uv.1);
    let v7 = v3.square().mul(&uv.1);
    let uv3 = uv.0.mul(&v3);
    let uv7 = uv.0.mul(&v7);
    // x^((p - 5) / 8) = x^(2^252 - 3).
    let p58 = pow_p22501_x4(&uv7).pow2k(2).mul(&uv7);
    let r = uv3.mul(&p58);
    let check = uv.1.mul(&r.square());

    let (checks, rs) = (check.unpack(), r.unpack());
    let mut ok = [false; 4];
    let mut out = [Fe::ZERO; 4];
    for i in 0..4 {
        let (lane_ok, lane_r) = sqrt_fixup(&u[i], checks[i], rs[i]);
        ok[i] = lane_ok;
        out[i] = lane_r;
    }
    (ok, out)
}

#[cfg(test)]
mod tests {
    use super::{
        super::fe::{sqrt_ratio_i_w, Fe},
        *,
    };
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    fn random_fe(rng: &mut impl rand::Rng) -> Fe {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Fe::from_bytes(&bytes)
    }

    #[test]
    fn test_pack_mul_square_match_scalar() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let b: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let (av, bv) = (Fe25x4::pack(&a), Fe25x4::pack(&b));
            let prod = av.mul(&bv).unpack();
            let sq = av.square().unpack();
            let chain = av.pow2k(64).unpack();
            for i in 0..4 {
                assert_eq!(prod[i].to_bytes(), a[i].mul(&b[i]).to_bytes());
                assert_eq!(sq[i].to_bytes(), a[i].square().to_bytes());
                assert_eq!(chain[i].to_bytes(), a[i].pow2k(64).to_bytes());
            }
        }
    }

    #[test]
    fn test_sqrt_ratio_matches_scalar() {
        let mut rng = test_rng();
        for round in 0..64 {
            let mut us: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            let mut vs: [Fe; 4] = core::array::from_fn(|_| random_fe(&mut rng));
            // Exercise the special cases in some lanes.
            if round % 4 == 0 {
                us[0] = Fe::ZERO;
                vs[1] = Fe::ZERO;
                us[2] = vs[2].square().mul(&vs[2]);
            }
            let (ok_neon, r_neon) = sqrt_ratio_i_x4(&us, &vs);
            let (ok_scalar, r_scalar) = sqrt_ratio_i_w(&us, &vs);
            for i in 0..4 {
                assert_eq!(ok_neon[i], ok_scalar[i], "round={round} lane={i}");
                assert_eq!(
                    r_neon[i].to_bytes(),
                    r_scalar[i].to_bytes(),
                    "round={round} lane={i}"
                );
            }
        }
    }
}
