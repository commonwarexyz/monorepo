//! Fixtures shared by the curve benchmarks.

use commonware_cryptography_bls12381::core::{
    curve::{g1, g2},
    field::{
        arithmetic::Field,
        fp::{BYTES, rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
        fp2,
    },
};
use commonware_simd::Simd;

/// A base field representation, selecting its element type on every backend.
pub trait Representation {
    /// The representation's name in benchmark labels.
    const NAME: &'static str;

    /// Elements in this representation on backend `S`.
    type Field<S: Simd>: Field<S>;
}

macro_rules! representations {
    ($($marker:ident => $field:ident: $name:literal),*) => {$(
        #[doc = concat!("Selects [`", stringify!($field), "`].")]
        pub struct $marker;

        impl Representation for $marker {
            const NAME: &'static str = $name;
            type Field<S: Simd> = $field<S>;
        }
    )*};
}

representations!(
    Radix28 => Unsat28: "unsat28",
    Radix49 => Unsat49: "unsat49",
    Residues => Rns: "rns"
);

/// One as a big-endian integer.
const ONE: [u8; BYTES] = {
    let mut bytes = [0; BYTES];
    bytes[BYTES - 1] = 1;
    bytes
};

/// Fills `bytes` deterministically from `seed`.
fn fill(seed: u64, bytes: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    for byte in bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

/// One as an extension element.
const ONE2: [u8; fp2::BYTES] = {
    let mut bytes = [0; fp2::BYTES];
    bytes[fp2::BYTES - 1] = 1;
    bytes
};

/// Returns `count` distinct deterministic G1 points, as affine coordinates with `z = 1` and in
/// blst's representation.
pub fn g1_points(count: usize) -> (Vec<g1::Coordinates>, Vec<blst::blst_p1>) {
    let mut coordinates = Vec::with_capacity(count);
    let mut points = Vec::with_capacity(count);
    for i in 0..count {
        let mut scalar = [0u8; 32];
        fill(i as u64 + 1, &mut scalar);
        let mut point = blst::blst_p1::default();
        let mut affine = blst::blst_p1_affine::default();
        let (mut x, mut y) = ([0; BYTES], [0; BYTES]);
        // SAFETY: every pointer references a valid value of the expected type, and the scalar
        // holds 256 bits.
        unsafe {
            blst::blst_p1_mult(&mut point, blst::blst_p1_generator(), scalar.as_ptr(), 256);
            blst::blst_p1_to_affine(&mut affine, &point);
            blst::blst_bendian_from_fp(x.as_mut_ptr(), &affine.x);
            blst::blst_bendian_from_fp(y.as_mut_ptr(), &affine.y);
        }
        coordinates.push([x, y, ONE]);
        points.push(point);
    }
    (coordinates, points)
}

/// Returns `count` distinct deterministic G2 points, as affine coordinates with `z = 1` and in
/// blst's representation.
pub fn g2_points(count: usize) -> (Vec<g2::Coordinates>, Vec<blst::blst_p2>) {
    let mut coordinates = Vec::with_capacity(count);
    let mut points = Vec::with_capacity(count);
    for i in 0..count {
        let mut scalar = [0u8; 32];
        fill(i as u64 + 1, &mut scalar);
        let mut point = blst::blst_p2::default();
        let mut affine = blst::blst_p2_affine::default();
        let (mut x, mut y) = ([0; fp2::BYTES], [0; fp2::BYTES]);
        // SAFETY: every pointer references a valid value of the expected type, the scalar holds
        // 256 bits, and each output buffer holds a base field element.
        unsafe {
            blst::blst_p2_mult(&mut point, blst::blst_p2_generator(), scalar.as_ptr(), 256);
            blst::blst_p2_to_affine(&mut affine, &point);
            // Extension elements encode the imaginary component first.
            blst::blst_bendian_from_fp(x.as_mut_ptr(), &affine.x.fp[1]);
            blst::blst_bendian_from_fp(x[BYTES..].as_mut_ptr(), &affine.x.fp[0]);
            blst::blst_bendian_from_fp(y.as_mut_ptr(), &affine.y.fp[1]);
            blst::blst_bendian_from_fp(y[BYTES..].as_mut_ptr(), &affine.y.fp[0]);
        }
        coordinates.push([x, y, ONE2]);
        points.push(point);
    }
    (coordinates, points)
}
