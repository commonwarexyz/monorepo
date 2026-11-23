//! Property checks for parallel strategies.
//!
//! The generated scenario is private so new checks can be added behind the same entry point.

use crate::fold_plan;
use arbitrary::{Arbitrary, Unstructured};

/// A generated scenario for exercising parallel strategy invariants.
#[derive(Arbitrary, Debug)]
pub struct Plan(Scenario);

#[derive(Arbitrary, Debug)]
enum Scenario {
    Fold(fold_plan::Plan),
}

impl Plan {
    /// Runs the generated scenario and asserts its invariants.
    pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self.0 {
            Scenario::Fold(plan) => plan.run(),
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
            .with_search_limit(16)
            .test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
