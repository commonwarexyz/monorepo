use super::setup::Setup;
use crate::bls12381::primitives::group::{Point, G1, G2};

/// Trait for KZG variants supporting commitments in either BLS12-381 group.
///
/// KZG commitments can be created in either G1 or G2, with verification performed using
/// pairings against the opposite group. This trait abstracts over the two variants, allowing
/// the same code to work with both G1 and G2 commitments.
///
/// # Variants
///
/// - **G1 commitments**: Commitments are in G1, verified against G2 check powers `[1]` and `[tau]`
/// - **G2 commitments**: Commitments are in G2, verified against G1 check powers `[1]` and `[tau]`
///
/// The maximum supported polynomial degree is determined by the number of commitment powers
/// available in the [Setup] implementation.
pub trait Variant<S: Setup>: Point {
    /// The group used for verification check powers.
    ///
    /// For G1 commitments, this is G2. For G2 commitments, this is G1.
    type CheckGroup: Point;

    /// Returns the powers of tau for creating commitments in this group.
    ///
    /// These are the powers `[1], [tau], [tau^2], ...` used to commit to polynomial coefficients.
    /// The length of the returned slice determines the maximum supported polynomial degree.
    fn commitment_powers(setup: &S) -> &[Self];

    /// Returns the check powers `[1]` and `[tau]` in the opposite group for verification.
    ///
    /// These powers are used during proof verification to check that commitments open correctly
    /// at evaluation points. Only the first two powers are required for verification.
    ///
    /// # Returns
    ///
    /// A tuple `(check_one, check_tau)` where:
    /// - `check_one`: The first power `[1]` in the check group
    /// - `check_tau`: The second power `[tau]` in the check group
    fn check_powers(setup: &S) -> (&Self::CheckGroup, &Self::CheckGroup);

    /// Accumulates a pairing into the provided [blst::Pairing] structure.
    ///
    /// This method is used during proof verification to accumulate pairings between elements
    /// in the commitment group and elements in the check group. The pairing order depends on
    /// which variant is being used (G1 or G2).
    ///
    /// # Arguments
    ///
    /// * `pairing`: The pairing accumulator to add to
    /// * `g`: An element in the commitment group (Self)
    /// * `check`: An element in the check group (CheckGroup)
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
