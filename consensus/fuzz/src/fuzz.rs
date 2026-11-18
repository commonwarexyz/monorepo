//! Property checks for consensus simulations.
//!
//! The generated scenario is private so new checks can be added behind the same entry point.

use crate::{
    plan::ConnectedPlan,
    simplex::{
        SimplexBls12381MinPk, SimplexBls12381MinSig, SimplexBls12381MultisigMinPk,
        SimplexBls12381MultisigMinSig, SimplexEd25519, SimplexSecp256r1,
    },
};
use arbitrary::{Arbitrary, Unstructured};

/// A generated scenario for exercising consensus invariants.
#[derive(Arbitrary, Debug)]
pub struct Plan(Scenario);

#[derive(Arbitrary, Debug)]
enum Scenario {
    Connected { scheme: Scheme, plan: ConnectedPlan },
}

#[derive(Arbitrary, Clone, Copy, Debug)]
pub(crate) enum Scheme {
    Ed25519,
    Secp256r1,
    MultisigMinPk,
    MultisigMinSig,
    ThresholdMinPk,
    ThresholdMinSig,
}

impl Scheme {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::Ed25519,
        Self::Secp256r1,
        Self::MultisigMinPk,
        Self::MultisigMinSig,
        Self::ThresholdMinPk,
        Self::ThresholdMinSig,
    ];

    fn run_connected(self, plan: ConnectedPlan) {
        match self {
            Self::Ed25519 => plan.run::<SimplexEd25519>(),
            Self::Secp256r1 => plan.run::<SimplexSecp256r1>(),
            Self::MultisigMinPk => plan.run::<SimplexBls12381MultisigMinPk>(),
            Self::MultisigMinSig => plan.run::<SimplexBls12381MultisigMinSig>(),
            Self::ThresholdMinPk => plan.run::<SimplexBls12381MinPk>(),
            Self::ThresholdMinSig => plan.run::<SimplexBls12381MinSig>(),
        }
    }
}

impl Plan {
    #[cfg(test)]
    pub(crate) fn connected(scheme: Scheme, plan: ConnectedPlan) -> Self {
        Self(Scenario::Connected { scheme, plan })
    }

    /// Runs the generated scenario and asserts its invariants.
    pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self.0 {
            Scenario::Connected { scheme, plan } => scheme.run_connected(plan),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Plan;
    use commonware_invariants::minifuzz;

    #[test]
    fn test_fuzz_plan() {
        minifuzz::Builder::default()
            .with_search_limit(8)
            .test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
