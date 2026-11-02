//! Fixtures shared by the pairing benchmarks.

use commonware_cryptography_bls12381::{
    field::{
        arithmetic::Field,
        fp::{BYTES, rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
        fp2, fp12,
    },
    pairing::{G1Affine, G2Affine},
};
use commonware_simd::Simd;

/// Independent pairs or checks per iteration, a multiple of every representation's lane count.
pub const POINTS: usize = 16;

/// The G1 coordinates of the neutral pair, which fills unused slots of a lane.
pub const NEUTRAL: G1Affine = [[0; BYTES]; 2];

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

/// A pair of points as affine encodings, and in blst's representation.
pub type Pair = (
    (G1Affine, G2Affine),
    (blst::blst_p1_affine, blst::blst_p2_affine),
);

/// Returns `count` distinct deterministic pairs of nonidentity points.
pub fn pairs(count: usize) -> Vec<Pair> {
    let mut pairs = Vec::with_capacity(count);
    for i in 0..count as u64 {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill(2 * i + 1, &mut a);
        fill(2 * i + 2, &mut b);
        // Nonzero little-endian scalars below 2^254.
        a[0] |= 1;
        b[0] |= 1;
        a[31] &= 0x3f;
        b[31] &= 0x3f;
        let mut p = blst::blst_p1::default();
        let mut q = blst::blst_p2::default();
        let mut p_affine = blst::blst_p1_affine::default();
        let mut q_affine = blst::blst_p2_affine::default();
        let mut g1 = [[0; BYTES]; 2];
        let mut g2 = [[0; fp2::BYTES]; 2];
        // SAFETY: every pointer references a valid value of the expected type, each scalar holds
        // 256 bits, and each output buffer holds a base field element.
        unsafe {
            blst::blst_p1_mult(&mut p, blst::blst_p1_generator(), a.as_ptr(), 256);
            blst::blst_p2_mult(&mut q, blst::blst_p2_generator(), b.as_ptr(), 256);
            blst::blst_p1_to_affine(&mut p_affine, &p);
            blst::blst_p2_to_affine(&mut q_affine, &q);
            blst::blst_bendian_from_fp(g1[0].as_mut_ptr(), &p_affine.x);
            blst::blst_bendian_from_fp(g1[1].as_mut_ptr(), &p_affine.y);
            // Extension elements encode the imaginary component first.
            for (coordinate, value) in g2.iter_mut().zip([&q_affine.x, &q_affine.y]) {
                blst::blst_bendian_from_fp(coordinate.as_mut_ptr(), &value.fp[1]);
                blst::blst_bendian_from_fp(coordinate[BYTES..].as_mut_ptr(), &value.fp[0]);
            }
        }
        pairs.push(((g1, g2), (p_affine, q_affine)));
    }
    pairs
}

/// Returns the affine encodings of pairs.
pub fn encodings(pairs: &[Pair]) -> Vec<(G1Affine, G2Affine)> {
    pairs.iter().map(|(encoding, _)| *encoding).collect()
}

/// Converts blst's representation of an element of `Fp12` to its encoding.
pub fn from_blst(value: &blst::blst_fp12) -> [u8; fp12::BYTES] {
    let mut bytes = [0; fp12::BYTES];
    let (chunks, _) = bytes.as_chunks_mut::<BYTES>();
    // Every encoding lists its highest coefficient first.
    for (k, chunk) in chunks.iter_mut().enumerate() {
        let (fp6, fp2, fp) = (1 - k / 6, 2 - (k / 2) % 3, 1 - k % 2);
        let component = &value.fp6[fp6].fp2[fp2].fp[fp];
        // SAFETY: the pointers reference a valid field element and 48 writable bytes.
        unsafe { blst::blst_bendian_from_fp(chunk.as_mut_ptr(), component) };
    }
    bytes
}

/// Returns blst's product of the Miller loops of pairs, before the final exponentiation.
pub fn blst_miller_loop(pairs: &[(blst::blst_p1_affine, blst::blst_p2_affine)]) -> blst::blst_fp12 {
    let ps: Vec<*const blst::blst_p1_affine> = pairs.iter().map(|(p, _)| p as *const _).collect();
    let qs: Vec<*const blst::blst_p2_affine> = pairs.iter().map(|(_, q)| q as *const _).collect();
    let mut out = blst::blst_fp12::default();
    // SAFETY: both arrays hold `pairs.len()` pointers to valid affine points.
    unsafe { blst::blst_miller_loop_n(&mut out, qs.as_ptr(), ps.as_ptr(), pairs.len()) };
    out
}

/// Returns blst's final exponentiation.
pub fn blst_final_exponentiation(f: &blst::blst_fp12) -> blst::blst_fp12 {
    let mut out = blst::blst_fp12::default();
    // SAFETY: the pointers reference valid field elements.
    unsafe { blst::blst_final_exp(&mut out, f) };
    out
}
