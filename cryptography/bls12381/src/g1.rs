//! The group G1: the prime-order subgroup of `y^2 = x^3 + 4` over the base field.
//!
//! Each public operation is written once over a field context and dispatched through
//! `commonware-simd`: the portable path uses scalar arithmetic, and x86v4c uses one point per
//! lane with the 52-bit multipliers.

use crate::{
    curve::{Affine, Curve, Projective},
    fp::{
        BYTES, Field, Fp, SQRT_EXPONENT, Single,
        lanes::{Lanes, MAX_LANES},
    },
    scalar::{self, Scalar},
};
use alloc::{vec, vec::Vec};
use commonware_simd::{Operation, Simd, X86V4C, dispatch};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The curve coefficient `b`.
const B: Fp = Fp::from_u64(4);

/// `3b`, the constant the curve formulas use.
const B3: Fp = Fp::from_u64(12);

/// A primitive cube root of unity. `(x, y) -> (BETA * x, y)` is an endomorphism of the curve.
const BETA: Fp = match Fp::from_words([
    0x8bfd_0000_0000_aaac,
    0x4094_27eb_4f49_fffd,
    0x897d_2965_0fb8_5f9b,
    0xaa0d_857d_8975_9ad4,
    0xec02_4086_63d4_de85,
    0x1a01_11ea_397f_e699,
]) {
    Some(beta) => beta,
    None => panic!("beta is canonical"),
};

/// `(z^2 - 1) / 3` for the curve parameter `z`, used by the subgroup check.
const SUBGROUP_SCALAR: [u64; 2] = [0x5555_5555, 0x396c_8c00_5555_e156];

/// Flag bits in the first byte of the compressed encoding.
const COMPRESSED: u8 = 0x80;
const INFINITY: u8 = 0x40;
const SIGN: u8 = 0x20;

/// An element of G1 in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G1(Projective<Fp>);

/// One G1 operation, described once over any field context.
trait Workload: Sized {
    type Output;

    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> Self::Output;
}

/// Runs a workload on the field context selected for the backend profile.
struct Run<W>(W);

impl<S: Simd, W: Workload> Operation<S> for Run<W> {
    type Output = W::Output;

    #[inline(always)]
    fn portable(self, _: S) -> W::Output {
        self.0.run(&Curve::new(Single, B3))
    }

    #[inline(always)]
    fn x86_v4c(self, simd: S) -> W::Output
    where
        S: X86V4C,
    {
        simd.execute(OnLanes(self.0))
    }
}

/// Runs a workload with one point per lane.
struct OnLanes<W>(W);

impl<S: Simd, W: Workload> Operation<S> for OnLanes<W> {
    type Output = W::Output;

    #[inline(always)]
    fn portable(self, simd: S) -> W::Output {
        self.0.run(&Curve::new(Lanes(simd), B3))
    }
}

/// Reads the single point back from lane zero.
#[inline(always)]
fn first<F: Field<Scalar = Fp>>(curve: &Curve<F>, point: Projective<F::Element>) -> G1 {
    let mut output = [G1::IDENTITY.0];
    curve.store(point, &mut output);
    G1(output[0])
}

/// Adds two points.
#[derive(Clone, Copy)]
struct Add(G1, G1);

impl Workload for Add {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        first(
            curve,
            curve.add(curve.load([&self.0.0]), curve.load([&self.1.0])),
        )
    }
}

/// Doubles a point.
#[derive(Clone, Copy)]
struct Double(G1);

impl Workload for Double {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        first(curve, curve.double(curve.load([&self.0.0])))
    }
}

/// Negates a point.
#[derive(Clone, Copy)]
struct Neg(G1);

impl Workload for Neg {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        first(curve, curve.neg(curve.load([&self.0.0])))
    }
}

/// Multiplies a point by a scalar.
#[derive(Clone, Copy)]
struct Mul(G1, Scalar);

impl Workload for Mul {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        first(curve, curve.mul(curve.load([&self.0.0]), &self.1))
    }
}

/// Applies the endomorphism `(x, y) -> (beta * x, y)`.
#[inline(always)]
fn endomorphism<F: Field<Scalar = Fp>>(
    curve: &Curve<F>,
    beta: F::Element,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    Projective {
        x: curve.field.mul(p.x, beta),
        y: p.y,
        z: p.z,
    }
}

/// Returns a point that is the identity exactly when `p` lies in the prime-order subgroup.
///
/// This is Bowe's test ("Faster subgroup checks for BLS12-381", 2019):
/// `[(z^2 - 1) / 3](2 s(P) - P - s^2(P)) - s^2(P) = O` for the endomorphism `s`.
#[inline(always)]
fn subgroup_witness<F: Field<Scalar = Fp>>(
    curve: &Curve<F>,
    beta: F::Element,
    p: Projective<F::Element>,
) -> Projective<F::Element> {
    let s1 = endomorphism(curve, beta, p);
    let s2 = endomorphism(curve, beta, s1);
    let inner = curve.add(curve.double(s1), curve.neg(curve.add(p, s2)));
    curve.add(curve.mul_public(inner, &SUBGROUP_SCALAR), curve.neg(s2))
}

/// Decodes compressed points, validating the encoding, curve equation, and subgroup.
///
/// Square roots and subgroup checks run one point per lane.
#[derive(Clone, Copy)]
struct Decode<'a>(&'a [[u8; BYTES]]);

impl Workload for Decode<'_> {
    type Output = Option<Vec<G1>>;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> Option<Vec<G1>> {
        let f = curve.field;
        let b = f.constant(B);
        let beta = f.constant(BETA);
        let mut points = Vec::with_capacity(self.0.len());
        for chunk in self.0.chunks(F::LANES) {
            // Parse the x coordinates and flags on the scalar side.
            let mut xs = [Fp::ZERO; MAX_LANES];
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
                xs[lane] = Fp::from_bytes(&bytes)?;
                signs[lane] = flags & SIGN != 0;
            }

            // Recover y = sqrt(x^3 + b) in every lane and validate it on the scalar side.
            let x = f.load(&xs, Fp::ZERO);
            let rhs = f.add(f.mul(f.square(x), x), b);
            let root = f.pow(rhs, &SQRT_EXPONENT);
            let mut rhs_lanes = [Fp::ZERO; MAX_LANES];
            let mut ys = [Fp::ZERO; MAX_LANES];
            f.store(rhs, &mut rhs_lanes);
            f.store(root, &mut ys);
            let mut candidates = [G1::IDENTITY.0; MAX_LANES];
            for lane in 0..chunk.len() {
                if infinities[lane] {
                    continue;
                }
                let y = ys[lane];
                if y.square() != rhs_lanes[lane] {
                    return None;
                }
                let flip = y.is_lexicographically_largest() ^ Choice::from(signs[lane] as u8);
                let y = Fp::conditional_select(&y, &y.neg(), flip);
                candidates[lane] = G1::from_affine_unchecked(xs[lane], y).0;
            }

            // Check subgroup membership in every lane; identities pass trivially.
            let witness = subgroup_witness(curve, beta, curve.load(&candidates[..chunk.len()]));
            let mut witnesses = [G1::GENERATOR.0; MAX_LANES];
            curve.store(witness, &mut witnesses);
            for witness in &witnesses[..chunk.len()] {
                if !bool::from(witness.z.is_zero()) {
                    return None;
                }
            }
            points.extend(candidates[..chunk.len()].iter().map(|p| G1(*p)));
        }
        Some(points)
    }
}

/// Checks subgroup membership of one point.
#[derive(Clone, Copy)]
struct InSubgroup(G1);

impl Workload for InSubgroup {
    type Output = bool;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> bool {
        let beta = curve.field.constant(BETA);
        let witness = first(curve, subgroup_witness(curve, beta, curve.load([&self.0.0])));
        bool::from(witness.is_identity())
    }
}

/// Multi-scalar multiplication by Pippenger's bucket method, with one scalar window per lane.
///
/// Every window of every scalar accumulates into its own bucket table, so adding one point
/// to `F::LANES` windows at once is a gather, one mixed addition, and a scatter, with no
/// data-dependent control flow. Bucket reduction likewise runs one window per lane.
#[derive(Clone, Copy)]
struct Msm<'a> {
    points: &'a [G1],
    scalars: &'a [Scalar],
}

impl Msm<'_> {
    /// Returns the window width balancing accumulation against bucket reduction.
    fn width(count: usize) -> usize {
        (usize::BITS - count.max(1).leading_zeros()) as usize - 1
    }
}

impl Workload for Msm<'_> {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        let f = curve.field;
        let width = Self::width(self.points.len()).clamp(2, 10);
        let windows = scalar::BITS.div_ceil(width);
        let table = 1 << width;
        let identity = curve.stored_identity();

        // Bucket 0 of each window is scratch space that absorbs zero digits.
        let mut buckets = vec![identity; windows * table];
        let mut gathered = [identity; MAX_LANES];
        for (point, scalar) in G1::to_affine_many(self.points).into_iter().zip(self.scalars) {
            let Some((x, y)) = point else {
                continue;
            };
            let q = Affine {
                x: f.constant(x),
                y: f.constant(y),
            };
            for first in (0..windows).step_by(F::LANES) {
                let lanes = first..windows.min(first + F::LANES);
                let index = |window: usize| {
                    window * table + scalar.bits(window * width, width) as usize
                };
                let acc = curve.gather(lanes.clone().map(|window| &buckets[index(window)]));
                curve.scatter(curve.add_affine(acc, q), gathered.iter_mut());
                for (lane, window) in lanes.enumerate() {
                    buckets[index(window)] = gathered[lane];
                }
            }
        }

        // Reduce each window's buckets: sum_d d * B_d as a running sum from the top.
        let mut sums = vec![identity; windows];
        for first in (0..windows).step_by(F::LANES) {
            let lanes = first..windows.min(first + F::LANES);
            let mut running = curve.identity();
            let mut total = curve.identity();
            for digit in (1..table).rev() {
                let bucket = curve.gather(lanes.clone().map(|window| &buckets[window * table + digit]));
                running = curve.add(running, bucket);
                total = curve.add(total, running);
            }
            curve.scatter(total, sums[lanes].iter_mut());
        }

        // Combine the windows from the top with Horner's rule.
        let mut result = curve.identity();
        for sum in sums.iter().rev() {
            for _ in 0..width {
                result = curve.double(result);
            }
            result = curve.add(result, curve.gather([sum]));
        }
        first(curve, result)
    }
}

/// Sums a sequence of points.
#[derive(Clone, Copy)]
struct Sum<'a>(&'a [G1]);

impl Workload for Sum<'_> {
    type Output = G1;

    #[inline(always)]
    fn run<F: Field<Scalar = Fp>>(self, curve: &Curve<F>) -> G1 {
        // Accumulate one partial sum per lane, then fold the lanes together.
        let mut partial = curve.identity();
        for chunk in self.0.chunks(F::LANES) {
            partial = curve.add(partial, curve.load(chunk.iter().map(|p| &p.0)));
        }
        let mut partials = [G1::IDENTITY.0; MAX_LANES];
        curve.store(partial, &mut partials);
        let mut total = curve.identity();
        for partial in &partials[..F::LANES] {
            total = curve.add(total, curve.load([partial]));
        }
        first(curve, total)
    }
}

impl G1 {
    /// The identity element.
    pub const IDENTITY: Self = Self(Projective {
        x: Fp::ZERO,
        y: Fp::ONE,
        z: Fp::ZERO,
    });

    /// The standard generator.
    pub const GENERATOR: Self = match (
        Fp::from_words([
            0xfb3a_f00a_db22_c6bb,
            0x6c55_e83f_f97a_1aef,
            0xa14e_3a3f_171b_ac58,
            0xc368_8c4f_9774_b905,
            0x2695_638c_4fa9_ac0f,
            0x17f1_d3a7_3197_d794,
        ]),
        Fp::from_words([
            0x0caa_2329_46c5_e7e1,
            0xd03c_c744_a288_8ae4,
            0x00db_18cb_2c04_b3ed,
            0xfcf5_e095_d5d0_0af6,
            0xa09e_30ed_741d_8ae4,
            0x08b3_f481_e3aa_a0f1,
        ]),
    ) {
        (Some(x), Some(y)) => Self::from_affine_unchecked(x, y),
        _ => panic!("generator coordinates are canonical"),
    };

    /// Builds a point from affine coordinates without checking the curve equation or subgroup.
    pub(crate) const fn from_affine_unchecked(x: Fp, y: Fp) -> Self {
        Self(Projective { x, y, z: Fp::ONE })
    }

    /// Returns `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        dispatch(Run(Add(*self, *other)))
    }

    /// Returns `2 * self`.
    pub fn double(&self) -> Self {
        dispatch(Run(Double(*self)))
    }

    /// Returns `-self`.
    pub fn neg(&self) -> Self {
        dispatch(Run(Neg(*self)))
    }

    /// Returns `scalar * self`, in constant time with respect to the scalar.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        dispatch(Run(Mul(*self, *scalar)))
    }

    /// Returns the sum of `points`.
    pub fn sum(points: &[Self]) -> Self {
        dispatch(Run(Sum(points)))
    }

    /// Returns `sum(scalars[i] * points[i])`.
    ///
    /// Variable-time; the scalars must be public.
    ///
    /// # Panics
    ///
    /// Panics if the slices have different lengths.
    pub fn msm(points: &[Self], scalars: &[Scalar]) -> Self {
        assert_eq!(points.len(), scalars.len());
        dispatch(Run(Msm { points, scalars }))
    }

    /// Converts points to affine coordinates with one shared inversion.
    ///
    /// Identities map to `None`.
    pub fn to_affine_many(points: &[Self]) -> Vec<Option<(Fp, Fp)>> {
        // Montgomery's trick: prefix products of the nonzero Z coordinates, one inversion, then
        // peel each inverse off from the top.
        let mut prefix = Vec::with_capacity(points.len());
        let mut product = Fp::ONE;
        for point in points {
            prefix.push(product);
            if !bool::from(point.is_identity()) {
                product = product.mul(point.0.z);
            }
        }
        let mut inverse = product.invert();
        let mut affine = vec![None; points.len()];
        for (i, point) in points.iter().enumerate().rev() {
            if bool::from(point.is_identity()) {
                continue;
            }
            let z = inverse.mul(prefix[i]);
            inverse = inverse.mul(point.0.z);
            affine[i] = Some((point.0.x.mul(z), point.0.y.mul(z)));
        }
        affine
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
        dispatch(Run(Decode(encodings)))
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
        dispatch(Run(InSubgroup(*self)))
    }

    /// Returns whether this is the identity.
    pub fn is_identity(&self) -> Choice {
        self.0.z.is_zero()
    }

    /// Returns the affine coordinates, or `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let z = self.0.z.invert();
        Some((self.0.x.mul(z), self.0.y.mul(z)))
    }

    /// Returns whether the coordinates satisfy `Y^2 Z = X^3 + 4 Z^3`.
    pub fn is_on_curve(&self) -> Choice {
        let Projective { x, y, z } = self.0;
        let lhs = y.square().mul(z);
        let rhs = x.square().mul(x).add(B.mul(z.square().mul(z)));
        lhs.ct_eq(&rhs)
    }
}

impl ConstantTimeEq for G1 {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Equal projective points have proportional coordinates. Identities have Z = 0 and
        // nonzero Y, so the cross-multiplications also separate them from finite points.
        let (p, q) = (self.0, other.0);
        p.x.mul(q.z).ct_eq(&q.x.mul(p.z)) & p.y.mul(q.z).ct_eq(&q.y.mul(p.z))
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for G1 {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fp::tests as fp;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{check_consistent, test_dispatch};

    pub(crate) fn to_blst(point: &G1) -> blst::blst_p1 {
        let mut out = blst::blst_p1::default();
        if let Some((x, y)) = point.to_affine() {
            let affine = blst::blst_p1_affine {
                x: fp::to_blst(x),
                y: fp::to_blst(y),
            };
            // SAFETY: valid pointers to point structures.
            unsafe { blst::blst_p1_from_affine(&mut out, &affine) };
        }
        out
    }

    pub(crate) fn from_blst(point: &blst::blst_p1) -> G1 {
        let mut affine = blst::blst_p1_affine::default();
        // SAFETY: valid pointers to point structures.
        unsafe {
            if blst::blst_p1_is_inf(point) {
                return G1::IDENTITY;
            }
            blst::blst_p1_to_affine(&mut affine, point);
        }
        G1::from_affine_unchecked(fp::from_blst(&affine.x), fp::from_blst(&affine.y))
    }

    /// Draws a random point of the prime-order subgroup, occasionally the identity.
    pub(crate) fn point(u: &mut Unstructured<'_>) -> arbitrary::Result<G1> {
        if u.ratio(1, 16)? {
            return Ok(G1::IDENTITY);
        }
        let scalar: [u8; 32] = u.arbitrary()?;
        let mut out = blst::blst_p1::default();
        // SAFETY: valid pointers; the scalar buffer holds 256 bits.
        unsafe { blst::blst_p1_mult(&mut out, blst::blst_p1_generator(), scalar.as_ptr(), 256) };
        Ok(from_blst(&out))
    }

    /// Runs a workload on every field context, checking that they agree, and returns the
    /// portable result.
    fn every_context<W: Workload + Copy>(workload: W) -> W::Output
    where
        W::Output: PartialEq + core::fmt::Debug,
    {
        let expected = test_dispatch(Run(workload));
        assert_eq!(test_dispatch(OnLanes(workload)), expected);
        check_consistent(|| OnLanes(workload));
        expected
    }

    #[test]
    fn generator_matches_blst() {
        // SAFETY: the generator pointer is valid for the program's lifetime.
        let generator = unsafe { *blst::blst_p1_generator() };
        assert_eq!(from_blst(&generator), G1::GENERATOR);
        assert!(bool::from(G1::GENERATOR.is_on_curve()));
        assert!(bool::from(G1::IDENTITY.is_on_curve()));
        assert_eq!(G1::IDENTITY.to_affine(), None);
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let p = point(u)?;
            let q = point(u)?;
            let (bp, bq) = (to_blst(&p), to_blst(&q));
            let mut out = blst::blst_p1::default();
            // SAFETY: valid pointers to point structures.
            unsafe {
                blst::blst_p1_add_or_double(&mut out, &bp, &bq);
                assert_eq!(from_blst(&out), every_context(Add(p, q)));
                blst::blst_p1_double(&mut out, &bp);
                assert_eq!(from_blst(&out), every_context(Double(p)));
                blst::blst_p1_cneg(&mut out, true);
                assert_eq!(from_blst(&out), p.double().neg());
            }
            assert_eq!(p.add(&p), p.double());
            assert_eq!(p.add(&p.neg()), G1::IDENTITY);
            assert_eq!(p.add(&G1::IDENTITY), p);
            assert!(bool::from(p.add(&q).is_on_curve()));
            Ok(())
        });
    }

    #[test]
    fn sum_matches_sequential_addition() {
        minifuzz::test(|u| {
            let count = u.int_in_range(0..=40)?;
            let mut points = Vec::with_capacity(count);
            for _ in 0..count {
                points.push(point(u)?);
            }
            let expected = points.iter().fold(G1::IDENTITY, |acc, p| acc.add(p));
            assert_eq!(G1::sum(&points), expected);
            assert_eq!(every_context(Sum(&points)), expected);
            Ok(())
        });
    }

    /// Draws a random curve point outside the prime-order subgroup, as a compressed encoding.
    fn non_subgroup_encoding(u: &mut Unstructured<'_>) -> arbitrary::Result<[u8; BYTES]> {
        loop {
            let x = fp::canonical(u)?;
            if let Some(y) = x.square().mul(x).add(B).sqrt() {
                return Ok(G1::from_affine_unchecked(x, y).to_bytes());
            }
        }
    }

    #[test]
    fn encoding_matches_blst() {
        assert_eq!(G1::IDENTITY.to_bytes()[0], COMPRESSED | INFINITY);
        assert_eq!(G1::from_bytes(&G1::IDENTITY.to_bytes()), Some(G1::IDENTITY));
        minifuzz::test(|u| {
            let count = u.int_in_range(1..=4)?;
            let mut points = Vec::with_capacity(count);
            let mut encodings = Vec::with_capacity(count);
            for _ in 0..count {
                let p = point(u)?;
                let bytes = p.to_bytes();
                let mut expected = [0u8; BYTES];
                // SAFETY: valid pointers; the output buffer holds 48 bytes.
                unsafe { blst::blst_p1_compress(expected.as_mut_ptr(), &to_blst(&p)) };
                assert_eq!(bytes, expected);
                assert_eq!(G1::from_bytes(&bytes), Some(p));
                assert!(p.is_in_subgroup());
                points.push(p);
                encodings.push(bytes);
            }
            assert_eq!(G1::decode_many(&encodings).as_deref(), Some(points.as_slice()));

            // Points off the subgroup pass blst's decoder (except (0, 2)) but fail its
            // membership test; our decoder rejects them outright.
            let outside = non_subgroup_encoding(u)?;
            let mut affine = blst::blst_p1_affine::default();
            // SAFETY: valid pointers; the input buffer holds 48 bytes.
            let status = unsafe { blst::blst_p1_uncompress(&mut affine, outside.as_ptr()) };
            if status == blst::BLST_ERROR::BLST_SUCCESS {
                // SAFETY: valid pointer to a decoded affine point.
                assert!(!unsafe { blst::blst_p1_affine_in_g1(&affine) });
            } else {
                assert_eq!(status, blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP);
            }
            assert_eq!(G1::from_bytes(&outside), None);
            let index = u.int_in_range(0..=count - 1)?;
            encodings[index] = outside;
            assert_eq!(G1::decode_many(&encodings), None);

            // Corrupted flags and non-canonical coordinates are rejected.
            let mut bad = points[0].to_bytes();
            bad[0] &= !COMPRESSED;
            assert_eq!(G1::from_bytes(&bad), None);
            let mut bad = [0xff; BYTES];
            bad[0] = COMPRESSED | 0x1f;
            assert_eq!(G1::from_bytes(&bad), None);
            let mut bad = [0; BYTES];
            bad[0] = COMPRESSED | INFINITY;
            bad[BYTES - 1] = 1;
            assert_eq!(G1::from_bytes(&bad), None);
            Ok(())
        });
    }

    #[test]
    fn msm_matches_blst() {
        minifuzz::test(|u| {
            let count = u.int_in_range(0..=20)?;
            let mut points = Vec::with_capacity(count);
            let mut scalars = Vec::with_capacity(count);
            for _ in 0..count {
                points.push(point(u)?);
                scalars.push(match u.int_in_range(0..=3)? {
                    0 => Scalar::ZERO,
                    1 => Scalar::ONE,
                    _ => Scalar::from_bytes(&u.arbitrary()?).unwrap_or(Scalar::ONE),
                });
            }
            let expected = points
                .iter()
                .zip(&scalars)
                .fold(G1::IDENTITY, |acc, (p, s)| acc.add(&p.mul(s)));
            assert_eq!(G1::msm(&points, &scalars), expected);
            let affine = G1::to_affine_many(&points);
            for (point, affine) in points.iter().zip(affine) {
                assert_eq!(point.to_affine(), affine);
            }
            Ok(())
        });
    }

    /// Vectorized multi-scalar multiplication is slow under emulation, so it runs once.
    #[test]
    fn msm_agrees_across_contexts() {
        let mut u = Unstructured::new(&[0xa5; 512]);
        let points: Vec<G1> = (0..5).map(|_| point(&mut u).unwrap()).collect();
        let scalars: Vec<Scalar> = (0..5)
            .map(|_| Scalar::from_bytes(&u.arbitrary().unwrap()).unwrap_or(Scalar::ONE))
            .collect();
        let expected = points
            .iter()
            .zip(&scalars)
            .fold(G1::IDENTITY, |acc, (p, s)| acc.add(&p.mul(s)));
        assert_eq!(
            every_context(Msm {
                points: &points,
                scalars: &scalars
            }),
            expected
        );
    }

    /// Vectorized decoding is slow under emulation, so it runs once on fixed inputs.
    #[test]
    fn decoding_agrees_across_contexts() {
        let mut u = Unstructured::new(&[0x5a; 256]);
        let points = [point(&mut u).unwrap(), point(&mut u).unwrap(), G1::IDENTITY];
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
            let scalar = match u.int_in_range(0..=3)? {
                0 => Scalar::ZERO,
                1 => Scalar::ONE,
                _ => Scalar::from_bytes(&u.arbitrary()?).unwrap_or(Scalar::ONE),
            };
            let mut out = blst::blst_p1::default();
            let bytes = scalar.to_words().map(u64::to_le_bytes).concat();
            // SAFETY: valid pointers; the scalar buffer holds 256 little-endian bits.
            unsafe { blst::blst_p1_mult(&mut out, &to_blst(&p), bytes.as_ptr(), 256) };
            assert_eq!(from_blst(&out), p.mul(&scalar));
            if u.ratio(1, 8)? {
                assert_eq!(from_blst(&out), every_context(Mul(p, scalar)));
            }
            Ok(())
        });
    }
}
