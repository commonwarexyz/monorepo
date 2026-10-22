//! The group G2: the prime-order subgroup of `y^2 = x^3 + 4(1 + i)` over the quadratic extension.
//!
//! The shared operations live in the group module, instantiated over the extension field
//! context built on each base context.

use crate::{
    curve::{Curve, Projective},
    fp::{
        Arithmetic, Fp, SQRT_EXPONENT,
        lanes::{Lanes, MAX_LANES},
        rns::Rns,
    },
    fp2::{BYTES, Ext, Fp2},
    group::{Group, Run, Workload, first},
    scalar::{Digits, Scalar},
};
use alloc::vec::Vec;
use commonware_simd::{Simd, X86V4C, dispatch};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The curve coefficient `b = 4(1 + i)`.
const B: Fp2 = Fp2::new(Fp::from_u64(4), Fp::from_u64(4));

/// `1 / (1 + i)^((p - 1) / 3)`, the x coordinate's factor in the endomorphism `psi`.
const PSI_X: Fp2 = coordinate(
    [0; 6],
    [
        0x8bfd_0000_0000_aaad,
        0x4094_27eb_4f49_fffd,
        0x897d_2965_0fb8_5f9b,
        0xaa0d_857d_8975_9ad4,
        0xec02_4086_63d4_de85,
        0x1a01_11ea_397f_e699,
    ],
);

/// `1 / (1 + i)^((p - 1) / 2)`, the y coordinate's factor in the endomorphism `psi`.
const PSI_Y: Fp2 = coordinate(
    [
        0xf1ee_7b04_121b_dea2,
        0x3044_66cf_3e67_fa0a,
        0xef39_6489_f61e_b45e,
        0x1c3d_edd9_30b1_cf60,
        0xe2e9_c448_d77a_2cd9,
        0x1352_03e6_0180_a68e,
    ],
    [
        0xc810_84fb_ede3_cc09,
        0xee67_992f_72ec_05f4,
        0x77f7_6e17_0092_41c5,
        0x4839_5dab_c2d3_435e,
        0x6831_e36d_6bd1_7ffe,
        0x06af_0e04_37ff_400b,
    ],
);

/// `-z` for the curve parameter `z`, used by the subgroup check.
const MINUS_Z: [u64; 1] = [0xd201_0000_0001_0000];

/// `(p - 3) / 4` and `(p - 1) / 2`, the exponents of the `p = 3 mod 4` square root in Fp2.
const SQRT_EXPONENT_A: [u64; 6] = {
    let mut exponent = SQRT_EXPONENT;
    exponent[0] -= 1;
    exponent
};
const SQRT_EXPONENT_B: [u64; 6] = {
    let mut half = [0u64; 6];
    let mut i = 0;
    while i < 6 {
        half[i] = crate::fp::MODULUS[i] >> 1;
        if i + 1 < 6 {
            half[i] |= crate::fp::MODULUS[i + 1] << 63;
        }
        i += 1;
    }
    half
};

/// Flag bits in the first byte of the compressed encoding.
const COMPRESSED: u8 = 0x80;
const INFINITY: u8 = 0x40;
const SIGN: u8 = 0x20;

/// Applies the endomorphism `psi(x, y) = (PSI_X * x^p, PSI_Y * y^p)`, which acts as
/// multiplication by `z` on the prime-order subgroup.
#[inline(always)]
fn psi<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    let f = curve.field;
    Projective {
        x: f.mul(f.frobenius(p.x), f.constant(PSI_X)),
        y: f.mul(f.frobenius(p.y), f.constant(PSI_Y)),
        z: f.frobenius(p.z),
    }
}

/// Returns a point that is the identity exactly when `p` lies in the prime-order subgroup.
///
/// This is Scott's test (<https://eprint.iacr.org/2021/1130>): `psi(P) = [z]P`, written as
/// `psi(P) + [-z]P = O`.
#[inline(always)]
fn subgroup_witness<F: Arithmetic<Scalar = Fp2>>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    curve.add(psi(curve, p), curve.mul_public(p, &MINUS_Z))
}

/// Decodes compressed points, validating the encoding, curve equation, and subgroup.
///
/// Square roots and subgroup checks run one point per lane.
#[derive(Clone, Copy)]
struct Decode<'a>(&'a [[u8; BYTES]]);

impl Workload<G2> for Decode<'_> {
    type Output = Option<Vec<G2>>;

    fn parallel(&self) -> bool {
        self.0.len() > 1
    }

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> Option<Vec<G2>> {
        let f = curve.field;
        let b = f.constant(B);
        let mut points = Vec::with_capacity(self.0.len());
        for chunk in self.0.chunks(F::LANES) {
            // Parse the x coordinates and flags on the scalar side.
            let mut xs = [Fp2::ZERO; MAX_LANES];
            let mut signs = [false; MAX_LANES];
            let mut infinities = [false; MAX_LANES];
            for (lane, bytes) in chunk.iter().enumerate() {
                let flags = bytes[0] & (COMPRESSED | INFINITY | SIGN);
                let mut bytes = *bytes;
                bytes[0] &= !(COMPRESSED | INFINITY | SIGN);
                if flags & COMPRESSED == 0 {
                    return None;
                }
                if flags & INFINITY != 0 {
                    if flags & SIGN != 0 || bytes.iter().any(|byte| *byte != 0) {
                        return None;
                    }
                    infinities[lane] = true;
                    continue;
                }
                xs[lane] = Fp2::from_bytes(&bytes)?;
                signs[lane] = flags & SIGN != 0;
            }

            // Recover y = sqrt(x^3 + b) in every lane: both candidate roots of the p = 3 mod 4
            // algorithm are computed, and the scalar side picks and validates one.
            let x = f.load(&xs, Fp2::ZERO);
            let rhs = f.add(f.mul(f.square(x), x), b);
            let a1 = f.pow(rhs, &SQRT_EXPONENT_A);
            let alpha = f.mul(f.square(a1), rhs);
            let x0 = f.mul(a1, rhs);
            let x0_i = f.mul(x0, f.constant(Fp2::ONE.mul_i()));
            let other = f.mul(f.pow(f.add(alpha, f.constant(Fp2::ONE)), &SQRT_EXPONENT_B), x0);
            let mut rhs_lanes = [Fp2::ZERO; MAX_LANES];
            let mut alphas = [Fp2::ZERO; MAX_LANES];
            let mut roots_i = [Fp2::ZERO; MAX_LANES];
            let mut roots = [Fp2::ZERO; MAX_LANES];
            f.store(rhs, &mut rhs_lanes);
            f.store(alpha, &mut alphas);
            f.store(x0_i, &mut roots_i);
            f.store(other, &mut roots);
            let mut candidates = [G2::IDENTITY.0; MAX_LANES];
            for lane in 0..chunk.len() {
                if infinities[lane] {
                    continue;
                }
                let minus_one = alphas[lane].ct_eq(&Fp2::ONE.neg());
                let y = Fp2::conditional_select(&roots[lane], &roots_i[lane], minus_one);
                if y.square() != rhs_lanes[lane] {
                    return None;
                }
                let flip = y.is_lexicographically_largest() ^ Choice::from(signs[lane] as u8);
                let y = Fp2::conditional_select(&y, &y.neg(), flip);
                candidates[lane] = G2::from_affine_unchecked(xs[lane], y).0;
            }

            // Check subgroup membership in every lane; identities pass trivially.
            let witness = subgroup_witness(curve, curve.load(&candidates[..chunk.len()]));
            let mut witnesses = [G2::GENERATOR.0; MAX_LANES];
            curve.store(witness, &mut witnesses);
            for witness in &witnesses[..chunk.len()] {
                if !bool::from(witness.z.is_zero()) {
                    return None;
                }
            }
            points.extend(candidates[..chunk.len()].iter().map(|p| G2(*p)));
        }
        Some(points)
    }
}

/// Checks subgroup membership of one point.
#[derive(Clone, Copy)]
struct InSubgroup(G2);

impl Workload<G2> for InSubgroup {
    type Output = bool;

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = Fp2>>(self, curve: &Curve<F>) -> bool {
        let witness: G2 = first(curve, subgroup_witness(curve, curve.load([&self.0.0])));
        bool::from(witness.is_identity())
    }
}

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

    /// Returns whether the coordinates satisfy `Y^2 Z = X^3 + b Z^3`.
    pub fn is_on_curve(&self) -> Choice {
        let Projective { x, y, z } = self.0;
        let lhs = y.square().mul(z);
        let rhs = x.square().mul(x).add(B.mul(z.square().mul(z)));
        lhs.ct_eq(&rhs)
    }

    /// Decodes a compressed point, checking the encoding, the curve equation, and subgroup
    /// membership.
    pub fn from_bytes(bytes: &[u8; BYTES]) -> Option<Self> {
        Self::decode_many(core::slice::from_ref(bytes)).map(|points| points[0])
    }

    /// Decodes compressed points, returning `None` if any of them is invalid.
    ///
    /// Batches amortize the vectorized square roots and subgroup checks across lanes.
    pub fn decode_many(encodings: &[[u8; BYTES]]) -> Option<Vec<Self>> {
        dispatch(Run::new(Decode(encodings)))
    }

    /// Returns the compressed encoding.
    pub fn to_bytes(&self) -> [u8; BYTES] {
        let Some((x, y)) = self.to_affine() else {
            let mut bytes = [0; BYTES];
            bytes[0] = COMPRESSED | INFINITY;
            return bytes;
        };
        let mut bytes = x.to_bytes();
        bytes[0] |= COMPRESSED | (SIGN & y.is_lexicographically_largest().unwrap_u8().wrapping_neg());
        bytes
    }

    /// Returns whether the point lies in the prime-order subgroup.
    pub fn is_in_subgroup(&self) -> bool {
        dispatch(Run::new(InSubgroup(*self)))
    }
}

impl Group for G2 {
    type Coordinate = Fp2;

    type Lanes<S: Simd> = Ext<Lanes<S>>;

    type Rns<S: X86V4C> = Ext<Rns<S>>;

    const B3: Fp2 = B3;

    const IDENTITY: Self = Self::IDENTITY;

    #[inline(always)]
    fn lanes<S: Simd>(simd: S) -> Ext<Lanes<S>> {
        Ext(Lanes(simd))
    }

    #[inline(always)]
    fn rns<S: X86V4C>(simd: S) -> Ext<Rns<S>> {
        Ext(Rns(simd))
    }

    #[inline(always)]
    fn projective(&self) -> &Projective<Fp2> {
        &self.0
    }

    #[inline(always)]
    fn from_projective(point: Projective<Fp2>) -> Self {
        Self(point)
    }

    const DIMENSION: usize = 4;

    const COMPONENT_BITS: usize = 64;

    fn decompose(scalar: &Scalar) -> [Digits<2>; 4] {
        scalar.split_gls().map(Scalar::widen)
    }

    /// `psi(P) = [z]P` with `z` negative, so the images of `|z|^i` alternate in sign.
    #[inline(always)]
    fn images<F: Arithmetic<Scalar = Fp2>>(
        curve: &Curve<F>,
        p: Projective<F::Element>,
    ) -> [Projective<F::Element>; 4] {
        let psi1 = psi(curve, p);
        let psi2 = psi(curve, psi1);
        let psi3 = psi(curve, psi2);
        [p, curve.neg(psi1), psi2, curve.neg(psi3)]
    }
}

crate::group::group_api!(G2, Fp2);

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
    use crate::{
        fp::Single,
        fp2::tests as fp2,
        group::{Add, Double, Msm, Mul, Sum, tests::Reference},
        scalar::Scalar,
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;

    impl Reference for G2 {
        type Single = Ext<Single>;

        fn single() -> Ext<Single> {
            Ext(Single)
        }
    }

    fn every_context<W: crate::group::Workload<G2> + Copy>(workload: W) -> W::Output
    where
        W::Output: PartialEq + core::fmt::Debug,
    {
        crate::group::tests::every_context::<G2, W>(workload)
    }

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
                assert_eq!(from_blst(&out), every_context(Add(p, q)));
                blst::blst_p2_double(&mut out, &bp);
                assert_eq!(from_blst(&out), every_context(Double(p)));
            }
            assert_eq!(p.add(&p.neg()), G2::IDENTITY);
            assert_eq!(p.add(&G2::IDENTITY), p);
            assert!(bool::from(p.add(&q).is_on_curve()));
            Ok(())
        });
    }

    /// Draws a random curve point outside the prime-order subgroup, as a compressed encoding.
    fn non_subgroup_encoding(u: &mut Unstructured<'_>) -> arbitrary::Result<[u8; BYTES]> {
        loop {
            if u.is_empty() {
                return Err(arbitrary::Error::NotEnoughData);
            }
            let x = fp2::element(u)?;
            if let Some(y) = x.square().mul(x).add(B).sqrt() {
                return Ok(G2::from_affine_unchecked(x, y).to_bytes());
            }
        }
    }

    #[test]
    fn psi_constants_match_their_definition() {
        let xi = Fp2::new(Fp::ONE, Fp::ONE);
        let mut third = crate::fp::MODULUS;
        third[0] -= 1;
        let mut carry = 0u128;
        for word in third.iter_mut().rev() {
            let value = (carry << 64) | u128::from(*word);
            *word = (value / 3) as u64;
            carry = value % 3;
        }
        assert_eq!(xi.pow(&third).mul(PSI_X), Fp2::ONE);
        assert_eq!(xi.pow(&SQRT_EXPONENT_B).mul(PSI_Y), Fp2::ONE);
    }

    #[test]
    fn encoding_matches_blst() {
        assert_eq!(G2::from_bytes(&G2::IDENTITY.to_bytes()), Some(G2::IDENTITY));
        minifuzz::test(|u| {
            let p = point(u)?;
            let bytes = p.to_bytes();
            let mut expected = [0u8; BYTES];
            // SAFETY: valid pointers; the output buffer holds 96 bytes.
            unsafe { blst::blst_p2_compress(expected.as_mut_ptr(), &to_blst(&p)) };
            assert_eq!(bytes, expected);
            assert_eq!(G2::from_bytes(&bytes), Some(p));
            assert!(p.is_in_subgroup());

            let outside = non_subgroup_encoding(u)?;
            let mut affine = blst::blst_p2_affine::default();
            // SAFETY: valid pointers; the input buffer holds 96 bytes.
            let status = unsafe { blst::blst_p2_uncompress(&mut affine, outside.as_ptr()) };
            assert_eq!(status, blst::BLST_ERROR::BLST_SUCCESS);
            // SAFETY: valid pointer to a decoded affine point.
            assert!(!unsafe { blst::blst_p2_affine_in_g2(&affine) });
            assert_eq!(G2::from_bytes(&outside), None);
            Ok(())
        });
    }

    /// Vectorized decoding is slow under emulation, so it runs once on fixed inputs.
    #[test]
    fn decoding_agrees_across_contexts() {
        let mut u = Unstructured::new(&[0x5a; 512]);
        let points = [point(&mut u).unwrap(), point(&mut u).unwrap(), G2::IDENTITY];
        let mut encodings = points.map(|p| p.to_bytes());
        assert_eq!(
            every_context(Decode(&encodings)).as_deref(),
            Some(points.as_slice())
        );
        encodings[1] = non_subgroup_encoding(&mut u).unwrap();
        assert_eq!(every_context(Decode(&encodings)), None);
    }

    #[test]
    fn scalar_multiplication_matches_blst() {
        minifuzz::test(|u| {
            let p = point(u)?;
            let scalar = Scalar::from_bytes(&u.arbitrary()?).unwrap_or(Scalar::ONE);
            let mut out = blst::blst_p2::default();
            let bytes = scalar.to_words().map(u64::to_le_bytes).concat();
            // SAFETY: valid pointers; the scalar buffer holds 256 little-endian bits.
            unsafe { blst::blst_p2_mult(&mut out, &to_blst(&p), bytes.as_ptr(), 256) };
            assert_eq!(from_blst(&out), p.mul(&scalar));
            Ok(())
        });
    }

    /// Vectorized scalar multiplication is slow under emulation, so it runs once.
    #[test]
    fn scalar_multiplication_agrees_across_contexts() {
        let mut u = Unstructured::new(&[0x77; 256]);
        let p = point(&mut u).unwrap();
        let scalar = Scalar::from_bytes(&u.arbitrary().unwrap()).unwrap_or(Scalar::ONE);
        assert_eq!(every_context(Mul(p, scalar)), p.mul(&scalar));
    }

    #[test]
    fn sum_and_msm_agree_across_contexts() {
        let mut u = Unstructured::new(&[0x3c; 512]);
        let points: Vec<G2> = (0..5).map(|_| point(&mut u).unwrap()).collect();
        let scalars: Vec<Scalar> = (0..5)
            .map(|_| Scalar::from_bytes(&u.arbitrary().unwrap()).unwrap_or(Scalar::ONE))
            .collect();
        let sum = points.iter().fold(G2::IDENTITY, |acc, p| acc.add(p));
        assert_eq!(every_context(Sum(&points)), sum);
        let expected = points
            .iter()
            .zip(&scalars)
            .fold(G2::IDENTITY, |acc, (p, s)| acc.add(&p.mul(s)));
        assert_eq!(
            every_context(Msm {
                points: &points,
                scalars: &scalars
            }),
            expected
        );
        assert_eq!(G2::msm(&points, &scalars), expected);
    }
}
