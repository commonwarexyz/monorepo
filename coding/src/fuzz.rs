//! Externally driven property checks for coding primitives.
//!
//! Enable the `fuzz` feature to generate a [`Plan`] and run it with bytes supplied
//! by a fuzzing engine. Individual suites are available through their local plans.
//!
//! # Examples
//!
//! ```
//! use arbitrary::Unstructured;
//! use commonware_coding::fuzz::Plan;
//!
//! # let input = &[];
//! let mut u = Unstructured::new(input);
//! if let Ok(plan) = u.arbitrary::<Plan>() {
//!     let _ = plan.run(&mut u);
//! }
//! ```

pub use crate::ocelot::fuzz as ocelot;
use arbitrary::{Arbitrary, Unstructured};

/// A property check for a coding primitive.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Check Ocelot's arithmetic and coding properties.
    Ocelot(ocelot::Plan),
}

impl Plan {
    /// Run the selected check with the remaining input bytes.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Ocelot(plan) => plan.run(u),
        }
    }
}
