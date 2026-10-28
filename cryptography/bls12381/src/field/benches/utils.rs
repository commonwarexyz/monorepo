//! Fixtures shared by the field benchmarks.

use commonware_cryptography_bls12381::{fp::Fp, g1::G1, scalar::Scalar};

/// Number of elements each lane operation covers, regardless of the backend's lane count.
pub const LANES: usize = 8;

/// The identity point in projective coordinates.
pub const IDENTITY: [Fp; 3] = [Fp::ZERO, Fp::ONE, Fp::ZERO];

/// Returns a deterministic scalar derived from `seed`.
pub fn scalar(seed: u64) -> Scalar {
    let mut words = [0u64; 4];
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    for word in &mut words {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *word = state;
    }
    words[3] &= (1 << 62) - 1;
    Scalar::from_words(words).expect("masked words are below the group order")
}

/// Returns `count` deterministic field elements.
pub fn elements(count: usize) -> Vec<Fp> {
    (0..count)
        .map(|i| Fp::from_u64(i as u64 + 2).invert())
        .collect()
}

/// Returns `count` distinct deterministic points.
pub fn points(count: usize) -> Vec<G1> {
    (0..count)
        .map(|i| G1::GENERATOR.mul(&scalar(i as u64 + 1)))
        .collect()
}

/// Returns a point's projective coordinates `[x, y, 1]`.
pub fn projective(point: &G1) -> [Fp; 3] {
    let (x, y) = point.to_affine().expect("fixtures are not the identity");
    [x, y, Fp::ONE]
}

/// Converts a point to blst's representation.
pub fn to_blst(point: &G1) -> blst::blst_p1 {
    let (x, y) = point.to_affine().expect("fixtures are not the identity");
    let fp = |value: Fp| {
        let mut out = blst::blst_fp::default();
        // SAFETY: both pointers reference valid 48-byte buffers.
        unsafe { blst::blst_fp_from_bendian(&mut out, value.to_bytes().as_ptr()) };
        out
    };
    let affine = blst::blst_p1_affine { x: fp(x), y: fp(y) };
    let mut out = blst::blst_p1::default();
    // SAFETY: valid pointers to point structures.
    unsafe { blst::blst_p1_from_affine(&mut out, &affine) };
    out
}
