//! Fuzzing operations for composed public APIs.

use arbitrary::{Arbitrary, Unstructured};

/// A fuzzing operation.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Exercise BLS12-381 and Banderwagon public API composition.
    Test(crate::test::fuzz::Plan),
}

impl Plan {
    /// Runs the fuzzing operation using the remaining input.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Test(plan) => plan.run(u),
        }
    }
}
