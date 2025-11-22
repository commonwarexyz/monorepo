use crate::bls12381::primitives::group::{Element, G1, G2, GT};
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

/// Computes the product of pairings `\prod e(g1_i, g2_i) -> GT`.
pub fn multi_pairing(g1: &[G1], g2: &[G2]) -> GT {
    assert_eq!(g1.len(), g2.len(), "mismatched lengths");

    // We can accumulate the miller loops and then do one final exponentiation.
    let mut acc = blst_fp12::default();
    let mut first = true;

    for (p1, p2) in g1.iter().zip(g2.iter()) {
        let p1_affine = p1.as_blst_p1_affine();
        let p2_affine = p2.as_blst_p2_affine();

        let mut ml = blst_fp12::default();
        unsafe {
            blst_miller_loop(&mut ml, &p2_affine, &p1_affine);
        }

        if first {
            acc = ml;
            first = false;
        } else {
            unsafe {
                let mut next_acc = blst_fp12::default();
                blst::blst_fp12_mul(&mut next_acc, &acc, &ml);
                acc = next_acc;
            }
        }
    }

    if first {
        // Empty input, return identity.
        return pairing(&G1::zero(), &G2::zero());
    }

    let mut result = blst_fp12::default();
    unsafe {
        blst_final_exp(&mut result, &acc);
    }

    GT::from_blst_fp12(result)
}
