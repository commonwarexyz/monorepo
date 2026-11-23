//! Property checks for utilities.
//!
//! The generated scenario is private so new checks can be added behind the same entry point.

use crate::{
    bitmap::{IsUnsetPlan, roaring},
    cache, faults,
};
use arbitrary::{Arbitrary, Unstructured};

/// A generated scenario for exercising utility invariants.
#[derive(Arbitrary, Debug)]
pub struct Plan(Scenario);

#[derive(Arbitrary, Debug)]
enum Scenario {
    Roaring(roaring::fuzz::Plan),
    Cache(cache::fuzz::Plan<false>),
    WideCache(cache::fuzz::Plan<true>),
    BitmapIsUnset(IsUnsetPlan),
    N5f1Quorum(faults::N5f1QuorumPlan),
    QuorumSafety(faults::QuorumSafetyPlan),
}

impl Plan {
    /// Runs the generated scenario and asserts its invariants.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self.0 {
            Scenario::Roaring(plan) => return plan.run(u),
            Scenario::Cache(plan) => plan.run(),
            Scenario::WideCache(plan) => plan.run(),
            Scenario::BitmapIsUnset(plan) => plan.run(),
            Scenario::N5f1Quorum(plan) => plan.run(),
            Scenario::QuorumSafety(plan) => plan.run(),
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
            .with_search_limit(32)
            .test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
