use crate::bls12381::primitives::group::Scalar;
use blst::blst_fr;
use commonware_math::algebra::{msm_naive, Additive, Multiplicative, Object, Ring, Space};
use commonware_parallel::Strategy;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Represents the scalar field for the Banderwagon group [`G`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F {
    limbs: [u64; 4],
}

/// The Bandersnatch twisted Edwards `a` coefficient, `-5`, in Montgomery form.
#[allow(dead_code)]
const A: Scalar = Scalar(blst_fr {
    l: [
        0xffff_fff4_0000_000c,
        0xece3_b023_ffec_4ff3,
        0x66b6_2060_7396_203f,
        0x6f23_d7e5_f361_df62,
    ],
});

/// The Bandersnatch twisted Edwards `d` coefficient in Montgomery form.
#[allow(dead_code)]
const D: Scalar = Scalar(blst_fr {
    l: [
        0xa8dc_ed1b_47a2_c730,
        0x381c_065a_ad3c_ccc7,
        0x53ff_52e1_1883_51f8,
        0x362e_8d63_990f_e940,
    ],
});

/// Represents a point in the Banderwagon group.
///
/// This group is defined over the BLS12-381 [`Scalar`] field.
/// Because of that, we can efficiently use it in ZK proofs using BLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G {
    // We use a projective representation where xy = tz.
    x: Scalar,
    y: Scalar,
    t: Scalar,
    z: Scalar,
}

impl G {
    /// Returns the prime-order Bandersnatch generator in extended coordinates.
    pub const fn generator() -> Self {
        Self {
            // x = 0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18
            x: Scalar(blst_fr {
                l: [
                    0xec26_27e1_e7ab_47f5,
                    0x3e63_de48_4f01_aa9c,
                    0xfe0f_5c3b_5394_6dc4,
                    0x2d71_920b_aeb2_cfcd,
                ],
            }),
            // y = 0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166
            y: Scalar(blst_fr {
                l: [
                    0x4e30_593e_1895_bd34,
                    0x156d_738f_32af_be4b,
                    0x45ef_0b1c_cdeb_75f4,
                    0x6a7c_ca00_37d2_e71f,
                ],
            }),
            // t = x * y = 0x5e61c8a110562844571f0fdc470ac5ea53e51c121b538d00e2594f7a0d4781ab
            t: Scalar(blst_fr {
                l: [
                    0x5a92_e8f6_97ad_b6b9,
                    0xf138_8d46_06b1_4609,
                    0x101c_7836_40a6_4516,
                    0x1e9a_e707_3cc7_a9fc,
                ],
            }),
            // z = 0x1
            z: Scalar(blst_fr {
                l: [
                    0x0000_0001_ffff_fffe,
                    0x5884_b7fa_0003_4802,
                    0x998c_4fef_ecbc_4ff5,
                    0x1824_b159_acc5_056f,
                ],
            }),
        }
    }
}

impl Object for G {}

impl<'a> AddAssign<&'a Self> for G {
    fn add_assign(&mut self, rhs: &'a Self) {
        // A bit of a trick to take ownership of the fields.
        let Self {
            x: x1,
            y: y1,
            t: t1,
            z: z1,
        } = core::mem::replace(self, Self::zero());
        // These are by reference.
        let Self {
            x: x2,
            y: y2,
            t: t2,
            z: z2,
        } = rhs;

        let x1_y2 = x1.clone() * y2;
        let y1_x2 = y1.clone() * x2;
        let y1_y2 = y1 * y2;
        let x1_x2 = x1 * x2;
        let z1_z2 = z1 * z2;
        let t1_t2 = t1 * t2;

        let x1_y2_plus_y1_x2 = x1_y2 + &y1_x2;
        let y1_y2_minus_a_x1_x2 = y1_y2 - &(x1_x2 * &A);
        let d_t1_t2 = t1_t2 * &D;
        let z_minus_d_t = z1_z2.clone() - &d_t1_t2;
        let z_plus_d_t = z1_z2 + &d_t1_t2;

        *self = Self {
            x: x1_y2_plus_y1_x2.clone() * &z_minus_d_t,
            y: y1_y2_minus_a_x1_x2.clone() * &z_plus_d_t,
            t: x1_y2_plus_y1_x2 * &y1_y2_minus_a_x1_x2,
            z: z_minus_d_t * &z_plus_d_t,
        }
    }
}

impl<'a> Add<&'a Self> for G {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for G {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let rhs = -rhs.clone();
        *self += &rhs;
    }
}

impl<'a> Sub<&'a Self> for G {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for G {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: -self.x,
            y: self.y,
            t: -self.t,
            z: self.z,
        }
    }
}

impl Additive for G {
    fn zero() -> Self {
        Self {
            x: Scalar::zero(),
            y: Scalar::one(),
            t: Scalar::zero(),
            z: Scalar::one(),
        }
    }

    fn double(&mut self) {
        let x_sq = {
            let mut out = self.x.clone();
            out.square();
            out
        };

        let y_sq = {
            let mut out = self.y.clone();
            out.square();
            out
        };

        let z_sq_twice = {
            let mut out = self.z.clone();
            out.square();
            out.double();
            out
        };

        let a_x_sq = x_sq.clone() * &A;

        let x_plus_y_sq = {
            let mut out = self.x.clone() + &self.y;
            out.square();
            out -= &x_sq;
            out -= &y_sq;
            out
        };

        let g = a_x_sq.clone() + &y_sq;
        let f = g.clone() - &z_sq_twice;
        let h = a_x_sq - &y_sq;

        self.x = x_plus_y_sq.clone() * &f;
        self.y = g.clone() * &h;
        self.t = x_plus_y_sq * &h;
        self.z = f * &g;
    }
}

impl<'a> MulAssign<&'a F> for G {
    fn mul_assign(&mut self, rhs: &'a F) {
        *self = self.scale(&rhs.limbs);
    }
}

impl<'a> Mul<&'a F> for G {
    type Output = Self;

    fn mul(mut self, rhs: &'a F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<F> for G {
    fn msm(points: &[Self], scalars: &[F], _strategy: &impl Strategy) -> Self {
        msm_naive(points, scalars)
    }
}
