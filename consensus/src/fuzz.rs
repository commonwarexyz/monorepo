//! Property checks for consensus simulations.
//!
//! The generated scenario is private so new checks can be added behind the same entry point.

use arbitrary::{Arbitrary, Unstructured};
use simplex::{ConnectedPlan, Scheme};

pub mod simplex;

/// A generated scenario for exercising consensus invariants.
#[derive(Arbitrary, Debug)]
pub struct Plan(Scenario);

#[derive(Arbitrary, Debug)]
enum Scenario {
    Connected { scheme: Scheme, plan: ConnectedPlan },
}

impl Plan {
    #[cfg(test)]
    const fn connected(scheme: Scheme, plan: ConnectedPlan) -> Self {
        Self(Scenario::Connected { scheme, plan })
    }

    /// Runs the generated scenario and asserts its invariants.
    pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self.0 {
            Scenario::Connected { scheme, plan } => plan.run(scheme),
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
