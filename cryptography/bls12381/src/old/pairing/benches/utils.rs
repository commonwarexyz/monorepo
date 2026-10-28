//! Fixtures shared by the pairing benchmarks.

use commonware_cryptography_bls12381::old::{fp::Fp, fp2::Fp2, g1::G1, g2::G2, scalar::Scalar};
use std::ptr::null;

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

/// Returns `count` distinct deterministic pairs of nonidentity points.
pub fn pairs(count: usize) -> Vec<(G1, G2)> {
    (0..count as u64)
        .map(|i| {
            (
                G1::GENERATOR.mul(&scalar(2 * i + 1)),
                G2::GENERATOR.mul(&scalar(2 * i + 2)),
            )
        })
        .collect()
}

/// Returns `count` pairs whose pairings multiply to one: the last pair cancels the others.
pub fn balanced_pairs(count: usize) -> Vec<(G1, G2)> {
    let mut pairs = pairs(count - 1);
    let mut total = Scalar::ZERO;
    for i in 0..count as u64 - 1 {
        total = total.add(scalar(2 * i + 1).mul(scalar(2 * i + 2)));
    }
    pairs.push((G1::GENERATOR.mul(&total.neg()), G2::GENERATOR));
    pairs
}

fn fp(value: Fp) -> blst::blst_fp {
    let mut out = blst::blst_fp::default();
    // SAFETY: both pointers reference valid 48-byte buffers.
    unsafe { blst::blst_fp_from_bendian(&mut out, value.to_bytes().as_ptr()) };
    out
}

fn fp2(value: Fp2) -> blst::blst_fp2 {
    blst::blst_fp2 {
        fp: [fp(value.c0), fp(value.c1)],
    }
}

/// Converts pairs to blst's affine representation.
pub fn to_blst(pairs: &[(G1, G2)]) -> (Vec<blst::blst_p1_affine>, Vec<blst::blst_p2_affine>) {
    let p = pairs
        .iter()
        .map(|(p, _)| {
            let (x, y) = p.to_affine().expect("fixtures are not the identity");
            blst::blst_p1_affine { x: fp(x), y: fp(y) }
        })
        .collect();
    let q = pairs
        .iter()
        .map(|(_, q)| {
            let (x, y) = q.to_affine().expect("fixtures are not the identity");
            blst::blst_p2_affine {
                x: fp2(x),
                y: fp2(y),
            }
        })
        .collect();
    (p, q)
}

/// Returns blst's product of the Miller loops of the pairs.
pub fn blst_miller_loop(p: &[blst::blst_p1_affine], q: &[blst::blst_p2_affine]) -> blst::blst_fp12 {
    let mut out = blst::blst_fp12::default();
    let (p_ptrs, q_ptrs) = ([p.as_ptr(), null()], [q.as_ptr(), null()]);
    // SAFETY: the pointer arrays are null-terminated and address `n` consecutive points.
    unsafe { blst::blst_miller_loop_n(&mut out, q_ptrs.as_ptr(), p_ptrs.as_ptr(), p.len()) };
    out
}

/// Returns blst's final exponentiation of `f`.
pub fn blst_final_exp(f: &blst::blst_fp12) -> blst::blst_fp12 {
    let mut out = blst::blst_fp12::default();
    // SAFETY: both pointers reference valid field elements.
    unsafe { blst::blst_final_exp(&mut out, f) };
    out
}
