//! The group G2: the prime-order subgroup of `y^2 = x^3 + 4(1 + i)` over the quadratic extension.
//!
//! The formulas are the ones G1 uses, instantiated over the extension field context. Only
//! scalar evaluation exists so far; the dispatched workloads follow once the G1 workloads are
//! generic over the group.

use crate::{
    curve::{Curve, Projective},
    fp::{Field, Fp, Single},
    fp2::{Ext, Fp2},
};
use subtle::{Choice, ConstantTimeEq};

/// `3b = 12 + 12 i`, the constant the curve formulas use.
const B3: Fp2 = Fp2::new(Fp::from_u64(12), Fp::from_u64(12));

/// Converts a canonical coordinate given as two little-endian word arrays.
const fn coordinate(c0: [u64; 6], c1: [u64; 6]) -> Fp2 {
    match (Fp::from_words(c0), Fp::from_words(c1)) {
        (Some(c0), Some(c1)) => Fp2::new(c0, c1),
        _ => panic!("coordinate is canonical"),
    }
}

/// An element of G2 in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G2(Projective<Fp2>);

impl G2 {
    /// The identity element.
    pub const IDENTITY: Self = Self(Projective {
        x: Fp2::ZERO,
        y: Fp2::ONE,
        z: Fp2::ZERO,
    });

    /// The standard generator.
    pub const GENERATOR: Self = Self::from_affine_unchecked(
        coordinate(
            [
                0xd480_56c8_c121_bdb8,
                0x0bac_0326_a805_bbef,
                0xb451_0b64_7ae3_d177,
                0xc6e4_7ad4_fa40_3b02,
                0x2608_0527_2dc5_1051,
                0x024a_a2b2_f08f_0a91,
            ],
            [
                0xe5ac_7d05_5d04_2b7e,
                0x334c_f112_1394_5d57,
                0xb5da_61bb_dc7f_5049,
                0x596b_d0d0_9920_b61a,
                0x7dac_d3a0_8827_4f65,
                0x13e0_2b60_5271_9f60,
            ],
        ),
        coordinate(
            [
                0xe193_5486_08b8_2801,
                0x923a_c9cc_3bac_a289,
                0x6d42_9a69_5160_d12c,
                0xadfd_9baa_8cbd_d3a7,
                0x8cc9_cdc6_da2e_351a,
                0x0ce5_d527_727d_6e11,
            ],
            [
                0xaaa9_075f_f05f_79be,
                0x3f37_0d27_5cec_1da1,
                0x2674_92ab_572e_99ab,
                0xcb3e_287e_85a7_63af,
                0x32ac_d2b0_2bc2_8b99,
                0x0606_c4a0_2ea7_34cc,
            ],
        ),
    );

    /// Builds a point from affine coordinates without checking the curve equation or subgroup.
    pub(crate) const fn from_affine_unchecked(x: Fp2, y: Fp2) -> Self {
        Self(Projective { x, y, z: Fp2::ONE })
    }

    /// Evaluates a formula on scalar coordinates.
    fn scalar(
        &self,
        formula: impl FnOnce(&Curve<Ext<Single>>, Projective<<Ext<Single> as Field>::Element>) -> Projective<<Ext<Single> as Field>::Element>,
    ) -> Self {
        let curve = Curve::new(Ext(Single), B3);
        let mut output = [Self::IDENTITY.0];
        curve.store(formula(&curve, curve.load([&self.0])), &mut output);
        Self(output[0])
    }

    /// Returns `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        self.scalar(|curve, p| curve.add(p, curve.load([&other.0])))
    }

    /// Returns `2 * self`.
    pub fn double(&self) -> Self {
        self.scalar(|curve, p| curve.double(p))
    }

    /// Returns `-self`.
    pub fn neg(&self) -> Self {
        self.scalar(|curve, p| curve.neg(p))
    }

    /// Returns whether this is the identity.
    pub fn is_identity(&self) -> Choice {
        self.0.z.is_zero()
    }

    /// Returns the affine coordinates, or `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let z = self.0.z.invert();
        Some((self.0.x.mul(z), self.0.y.mul(z)))
    }

    /// Returns whether the coordinates satisfy `Y^2 Z = X^3 + b Z^3`.
    pub fn is_on_curve(&self) -> Choice {
        let Projective { x, y, z } = self.0;
        let b = Fp2::new(Fp::from_u64(4), Fp::from_u64(4));
        let lhs = y.square().mul(z);
        let rhs = x.square().mul(x).add(b.mul(z.square().mul(z)));
        lhs.ct_eq(&rhs)
    }
}

impl ConstantTimeEq for G2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        let (p, q) = (self.0, other.0);
        p.x.mul(q.z).ct_eq(&q.x.mul(p.z)) & p.y.mul(q.z).ct_eq(&q.y.mul(p.z))
    }
}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for G2 {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fp2::tests as fp2;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;

    pub(crate) fn to_blst(point: &G2) -> blst::blst_p2 {
        let mut out = blst::blst_p2::default();
        if let Some((x, y)) = point.to_affine() {
            let affine = blst::blst_p2_affine {
                x: fp2::to_blst(x),
                y: fp2::to_blst(y),
            };
            // SAFETY: valid pointers to point structures.
            unsafe { blst::blst_p2_from_affine(&mut out, &affine) };
        }
        out
    }

    pub(crate) fn from_blst(point: &blst::blst_p2) -> G2 {
        let mut affine = blst::blst_p2_affine::default();
        // SAFETY: valid pointers to point structures.
        unsafe {
            if blst::blst_p2_is_inf(point) {
                return G2::IDENTITY;
            }
            blst::blst_p2_to_affine(&mut affine, point);
        }
        G2::from_affine_unchecked(fp2::from_blst(&affine.x), fp2::from_blst(&affine.y))
    }

    /// Draws a random point of the prime-order subgroup, occasionally the identity.
    pub(crate) fn point(u: &mut Unstructured<'_>) -> arbitrary::Result<G2> {
        if u.ratio(1, 16)? {
            return Ok(G2::IDENTITY);
        }
        let scalar: [u8; 32] = u.arbitrary()?;
        let mut out = blst::blst_p2::default();
        // SAFETY: valid pointers; the scalar buffer holds 256 bits.
        unsafe { blst::blst_p2_mult(&mut out, blst::blst_p2_generator(), scalar.as_ptr(), 256) };
        Ok(from_blst(&out))
    }

    #[test]
    fn generator_matches_blst() {
        // SAFETY: the generator pointer is valid for the program's lifetime.
        let generator = unsafe { *blst::blst_p2_generator() };
        assert_eq!(from_blst(&generator), G2::GENERATOR);
        assert!(bool::from(G2::GENERATOR.is_on_curve()));
        assert!(bool::from(G2::IDENTITY.is_on_curve()));
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let p = point(u)?;
            let q = point(u)?;
            let (bp, bq) = (to_blst(&p), to_blst(&q));
            let mut out = blst::blst_p2::default();
            // SAFETY: valid pointers to point structures.
            unsafe {
                blst::blst_p2_add_or_double(&mut out, &bp, &bq);
                assert_eq!(from_blst(&out), p.add(&q));
                blst::blst_p2_double(&mut out, &bp);
                assert_eq!(from_blst(&out), p.double());
            }
            assert_eq!(p.add(&p.neg()), G2::IDENTITY);
            assert_eq!(p.add(&G2::IDENTITY), p);
            assert!(bool::from(p.add(&q).is_on_curve()));
            Ok(())
        });
    }
}
