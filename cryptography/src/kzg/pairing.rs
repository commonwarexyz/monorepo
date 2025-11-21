use crate::bls12381::primitives::group::{G1, G2, GT};
use blst::{blst_final_exp, blst_fp12, blst_miller_loop};

/// Computes the pairing `e(G1, G2) -> GT`.
pub fn pairing(point: &G1, g2: &G2) -> GT {
    let p1_affine = point.as_blst_p1_affine();
    let p2_affine = g2.as_blst_p2_affine();

    let mut result = blst_fp12::default();
    unsafe {
        blst_miller_loop(&mut result, &p2_affine, &p1_affine);
        blst_final_exp(&mut result, &result);
    }

    GT::from_blst_fp12(result)
}
