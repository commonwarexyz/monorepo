//! Fuzzing operations for this crate.

use arbitrary::{Arbitrary, Unstructured};

/// A fuzzing operation.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Exercise the field and group arithmetic implementation.
    Curve(crate::curve::test::Plan),
}

impl Plan {
    /// Runs the fuzzing operation using the remaining input.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Curve(plan) => plan.run(u),
        }
    }
}
