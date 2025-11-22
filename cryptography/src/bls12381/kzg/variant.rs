use crate::bls12381::primitives::group::{Point, G1, G2};
use super::setup::Setup;

/// Trait for KZG variants (G1 or G2).
pub trait Variant<S: Setup>: Point {
    type CheckGroup: Point;

    fn commitment_powers(setup: &S) -> &[Self];
    fn check_powers(setup: &S) -> (&Self::CheckGroup, &Self::CheckGroup);
    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup);
}

impl<S: Setup> Variant<S> for G1 {
    type CheckGroup = G2;

    fn commitment_powers(setup: &S) -> &[Self] {
        setup.g1_powers()
    }

    fn check_powers(setup: &S) -> (&Self::CheckGroup, &Self::CheckGroup) {
        setup.g2_check_powers()
    }

    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup) {
        let g_affine = g.as_blst_p1_affine();
        let check_affine = check.as_blst_p2_affine();
        pairing.raw_aggregate(&check_affine, &g_affine);
    }
}

impl<S: Setup> Variant<S> for G2 {
    type CheckGroup = G1;

    fn commitment_powers(setup: &S) -> &[Self] {
        setup.g2_powers()
    }

    fn check_powers(setup: &S) -> (&Self::CheckGroup, &Self::CheckGroup) {
        setup.g1_check_powers()
    }

    fn accumulate_pairing(pairing: &mut blst::Pairing, g: &Self, check: &Self::CheckGroup) {
        let g_affine = g.as_blst_p2_affine();
        let check_affine = check.as_blst_p1_affine();
        pairing.raw_aggregate(&g_affine, &check_affine);
    }
}
