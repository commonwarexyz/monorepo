//! Fuzzing operations for this crate.

use arbitrary::{Arbitrary, Unstructured};

/// A fuzzing operation.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Exercise bounded RNS operations against the portable backend.
    Rns(crate::rns::test::Plan),
}

impl Plan {
    /// Runs the fuzzing operation using the remaining input.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Rns(plan) => plan.run(u),
        }
    }
}
