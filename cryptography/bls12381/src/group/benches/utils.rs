//! Inputs shared by the group benchmarks, as elements of the public API and as their blst
//! counterparts.

use commonware_cryptography_bls12381::{G1, G2, Scalar};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_utils::TestRng;
use std::ptr;

/// Returns `count` deterministic scalars, uniform over the scalar field.
pub fn scalars(count: usize, seed: u64) -> Vec<Scalar> {
    let mut rng = TestRng::new(seed);
    (0..count).map(|_| Scalar::random(&mut rng)).collect()
}

/// Returns a scalar as the little-endian bytes blst reads.
pub fn le_bytes(scalar: &Scalar) -> [u8; Scalar::BYTES] {
    let mut bytes = [0; Scalar::BYTES];
    for (chunk, word) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(scalar.to_words())
    {
        *chunk = word.to_le_bytes();
    }
    bytes
}

/// A group of the public API with its blst counterpart.
pub trait Curve: CryptoGroup<Scalar = Scalar> + Copy {
    /// The group's name in benchmark labels.
    const NAME: &'static str;

    /// blst's projective points.
    type Blst: Copy + Default;

    /// blst's affine points.
    type BlstAffine: Copy + Default;

    /// Returns the sum of the points.
    fn sum(points: &[Self]) -> Self;

    /// Multiplies each point by the scalar at the same index, in place.
    fn mul_each(points: &mut [Self], scalars: &[Scalar]);

    /// Returns `scalar` times the generator, and the same point in blst.
    fn multiple(scalar: &Scalar) -> (Self, Self::Blst) {
        (
            Self::generator() * scalar,
            Self::blst_mul(&Self::blst_generator(), scalar),
        )
    }

    /// Returns `count` distinct points, and the same points in blst.
    fn points(count: usize, seed: u64) -> (Vec<Self>, Vec<Self::Blst>) {
        // The points step from one multiple of the generator by another, so that preparing many
        // costs additions rather than multiplications.
        let scalars = scalars(2, seed);
        let (mut point, mut blst_point) = Self::multiple(&scalars[0]);
        let (step, blst_step) = Self::multiple(&scalars[1]);
        let mut points = Vec::with_capacity(count);
        let mut blst_points = Vec::with_capacity(count);
        for _ in 0..count {
            points.push(point);
            blst_points.push(blst_point);
            point += &step;
            blst_point = Self::blst_add(&blst_point, &blst_step);
        }
        (points, blst_points)
    }

    /// Returns blst's generator.
    fn blst_generator() -> Self::Blst;

    /// Returns `a + b` in blst.
    fn blst_add(a: &Self::Blst, b: &Self::Blst) -> Self::Blst;

    /// Returns `2 * a` in blst.
    fn blst_double(a: &Self::Blst) -> Self::Blst;

    /// Returns `scalar * a` in blst.
    fn blst_mul(a: &Self::Blst, scalar: &Scalar) -> Self::Blst;

    /// Converts points to affine coordinates in blst, with one shared inversion.
    fn blst_to_affine(points: &[Self::Blst]) -> Vec<Self::BlstAffine>;

    /// Returns the sum of the points with blst's bulk addition, converting the points to affine
    /// coordinates first, as it requires.
    fn blst_sum(points: &[Self::Blst]) -> Self::Blst;

    /// Returns `sum(scalars[i] * points[i])` with blst's Pippenger method, converting the points
    /// to affine coordinates first, as an MSM over projective points must.
    fn blst_msm(points: &[Self::Blst], scalars: &[u8]) -> Self::Blst;
}

impl Curve for G1 {
    const NAME: &'static str = "g1";

    type Blst = blst::blst_p1;
    type BlstAffine = blst::blst_p1_affine;

    fn sum(points: &[Self]) -> Self {
        Self::sum(points)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar]) {
        Self::mul_each(points, scalars);
    }

    fn blst_generator() -> Self::Blst {
        // SAFETY: blst returns a pointer to its static generator.
        unsafe { *blst::blst_p1_generator() }
    }

    fn blst_add(a: &Self::Blst, b: &Self::Blst) -> Self::Blst {
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point.
        unsafe { blst::blst_p1_add_or_double(&mut out, a, b) };
        out
    }

    fn blst_double(a: &Self::Blst) -> Self::Blst {
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point.
        unsafe { blst::blst_p1_double(&mut out, a) };
        out
    }

    fn blst_mul(a: &Self::Blst, scalar: &Scalar) -> Self::Blst {
        let bytes = le_bytes(scalar);
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point, and the scalar holds 255 bits.
        unsafe { blst::blst_p1_mult(&mut out, a, bytes.as_ptr(), 255) };
        out
    }

    fn blst_to_affine(points: &[Self::Blst]) -> Vec<Self::BlstAffine> {
        let mut out = vec![Self::BlstAffine::default(); points.len()];
        let pointers: Vec<*const Self::Blst> = points.iter().map(ptr::from_ref).collect();
        // SAFETY: `pointers` holds one valid point per output slot.
        unsafe { blst::blst_p1s_to_affine(out.as_mut_ptr(), pointers.as_ptr(), points.len()) };
        out
    }

    fn blst_sum(points: &[Self::Blst]) -> Self::Blst {
        let affine = Self::blst_to_affine(points);
        // blst reads one contiguous array through the first of null-terminated pointers.
        let points = [affine.as_ptr(), ptr::null()];
        let mut out = Self::Blst::default();
        // SAFETY: the array holds `affine.len()` points.
        unsafe { blst::blst_p1s_add(&mut out, points.as_ptr(), affine.len()) };
        out
    }

    fn blst_msm(points: &[Self::Blst], scalars: &[u8]) -> Self::Blst {
        let affine = Self::blst_to_affine(points);
        // SAFETY: blst returns the scratch size in bytes for any point count.
        let scratch = unsafe { blst::blst_p1s_mult_pippenger_scratch_sizeof(points.len()) };
        let mut scratch = vec![0u64; scratch.div_ceil(8)];
        // blst reads one contiguous array through the first of null-terminated pointers.
        let points = [affine.as_ptr(), ptr::null()];
        let scalars = [scalars.as_ptr(), ptr::null()];
        let mut out = Self::Blst::default();
        // SAFETY: the arrays hold `affine.len()` points and as many 255-bit scalars, and the
        // scratch space has the size blst requested.
        unsafe {
            blst::blst_p1s_mult_pippenger(
                &mut out,
                points.as_ptr(),
                affine.len(),
                scalars.as_ptr(),
                255,
                scratch.as_mut_ptr(),
            )
        };
        out
    }
}

impl Curve for G2 {
    const NAME: &'static str = "g2";

    type Blst = blst::blst_p2;
    type BlstAffine = blst::blst_p2_affine;

    fn sum(points: &[Self]) -> Self {
        Self::sum(points)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar]) {
        Self::mul_each(points, scalars);
    }

    fn blst_generator() -> Self::Blst {
        // SAFETY: blst returns a pointer to its static generator.
        unsafe { *blst::blst_p2_generator() }
    }

    fn blst_add(a: &Self::Blst, b: &Self::Blst) -> Self::Blst {
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point.
        unsafe { blst::blst_p2_add_or_double(&mut out, a, b) };
        out
    }

    fn blst_double(a: &Self::Blst) -> Self::Blst {
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point.
        unsafe { blst::blst_p2_double(&mut out, a) };
        out
    }

    fn blst_mul(a: &Self::Blst, scalar: &Scalar) -> Self::Blst {
        let bytes = le_bytes(scalar);
        let mut out = Self::Blst::default();
        // SAFETY: every pointer references a valid point, and the scalar holds 255 bits.
        unsafe { blst::blst_p2_mult(&mut out, a, bytes.as_ptr(), 255) };
        out
    }

    fn blst_to_affine(points: &[Self::Blst]) -> Vec<Self::BlstAffine> {
        let mut out = vec![Self::BlstAffine::default(); points.len()];
        let pointers: Vec<*const Self::Blst> = points.iter().map(ptr::from_ref).collect();
        // SAFETY: `pointers` holds one valid point per output slot.
        unsafe { blst::blst_p2s_to_affine(out.as_mut_ptr(), pointers.as_ptr(), points.len()) };
        out
    }

    fn blst_sum(points: &[Self::Blst]) -> Self::Blst {
        let affine = Self::blst_to_affine(points);
        // blst reads one contiguous array through the first of null-terminated pointers.
        let points = [affine.as_ptr(), ptr::null()];
        let mut out = Self::Blst::default();
        // SAFETY: the array holds `affine.len()` points.
        unsafe { blst::blst_p2s_add(&mut out, points.as_ptr(), affine.len()) };
        out
    }

    fn blst_msm(points: &[Self::Blst], scalars: &[u8]) -> Self::Blst {
        let affine = Self::blst_to_affine(points);
        // SAFETY: blst returns the scratch size in bytes for any point count.
        let scratch = unsafe { blst::blst_p2s_mult_pippenger_scratch_sizeof(points.len()) };
        let mut scratch = vec![0u64; scratch.div_ceil(8)];
        // blst reads one contiguous array through the first of null-terminated pointers.
        let points = [affine.as_ptr(), ptr::null()];
        let scalars = [scalars.as_ptr(), ptr::null()];
        let mut out = Self::Blst::default();
        // SAFETY: the arrays hold `affine.len()` points and as many 255-bit scalars, and the
        // scratch space has the size blst requested.
        unsafe {
            blst::blst_p2s_mult_pippenger(
                &mut out,
                points.as_ptr(),
                affine.len(),
                scalars.as_ptr(),
                255,
                scratch.as_mut_ptr(),
            )
        };
        out
    }
}

/// A pair of points in blst.
pub type BlstPair = (blst::blst_p1, blst::blst_p2);

/// Returns `count` pairs of points, and the same pairs in blst.
pub fn pairs(count: usize) -> (Vec<(G1, G2)>, Vec<BlstPair>) {
    let (ps, blst_ps) = G1::points(count, 1);
    let (qs, blst_qs) = G2::points(count, 2);
    (
        ps.into_iter().zip(qs).collect(),
        blst_ps.into_iter().zip(blst_qs).collect(),
    )
}

/// Returns the product of the pairings of `pairs` in blst, converting the points to affine
/// coordinates first, as a pairing of projective points must.
pub fn blst_multi_pairing(pairs: &[BlstPair]) -> blst::blst_fp12 {
    let (ps, qs): (Vec<_>, Vec<_>) = pairs.iter().copied().unzip();
    let ps = G1::blst_to_affine(&ps);
    let qs = G2::blst_to_affine(&qs);
    let ps: Vec<*const blst::blst_p1_affine> = ps.iter().map(ptr::from_ref).collect();
    let qs: Vec<*const blst::blst_p2_affine> = qs.iter().map(ptr::from_ref).collect();
    let mut lines = blst::blst_fp12::default();
    let mut out = blst::blst_fp12::default();
    // SAFETY: both arrays hold `pairs.len()` pointers to valid affine points, and the outputs
    // are valid elements.
    unsafe {
        blst::blst_miller_loop_n(&mut lines, qs.as_ptr(), ps.as_ptr(), pairs.len());
        blst::blst_final_exp(&mut out, &lines);
    }
    out
}
