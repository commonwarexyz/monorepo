//! Fuzzing operations for this crate.

use crate::{
    core::{
        curve,
        field::{
            arithmetic,
            fp::{rns, unsat28, unsat49},
            fp2, fp12,
        },
        pairing,
    },
    group::{self, G1, G2},
    montgomery,
};
use arbitrary::{Arbitrary, Unstructured};

/// A fuzzing operation.
#[derive(Clone, Copy, Debug, Arbitrary)]
pub enum Plan {
    /// Exercise the word arithmetic shared by the base and scalar fields.
    Montgomery(montgomery::fuzz::Plan),
    /// Exercise the base field in 49-bit limbs.
    Unsat49(unsat49::fuzz::Plan),
    /// Exercise the base field in 28-bit limbs.
    Unsat28(unsat28::fuzz::Plan),
    /// Exercise the base field in residues.
    Rns(rns::fuzz::Plan),
    /// Exercise the arithmetic shared by every base field representation.
    Arithmetic(arithmetic::fuzz::Plan),
    /// Exercise the quadratic extension.
    Fp2(fp2::fuzz::Plan),
    /// Exercise the degree-12 extension and its cubic subfield.
    Fp12(fp12::fuzz::Plan),
    /// Exercise the curve formulas.
    Curve(curve::fuzz::Plan),
    /// Exercise the steps of the pairing.
    Pairing(pairing::fuzz::Plan),
    /// Exercise the scalar field.
    Scalar(group::fuzz::scalar::Plan),
    /// Exercise the group G1.
    G1(group::fuzz::Plan),
    /// Exercise the group G2.
    G2(group::fuzz::Plan),
    /// Exercise the pairing of the groups and the target group.
    GT(group::fuzz::pairing::Plan),
}

impl Plan {
    /// Runs the fuzzing operation using the remaining input.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Montgomery(plan) => plan.run(u),
            Self::Unsat49(plan) => plan.run(u),
            Self::Unsat28(plan) => plan.run(u),
            Self::Rns(plan) => plan.run(u),
            Self::Arithmetic(plan) => plan.run(u),
            Self::Fp2(plan) => plan.run(u),
            Self::Fp12(plan) => plan.run(u),
            Self::Curve(plan) => plan.run(u),
            Self::Pairing(plan) => plan.run(u),
            Self::Scalar(plan) => plan.run(u),
            Self::G1(plan) => plan.run::<G1>(u),
            Self::G2(plan) => plan.run::<G2>(u),
            Self::GT(plan) => plan.run(u),
        }
    }
}
