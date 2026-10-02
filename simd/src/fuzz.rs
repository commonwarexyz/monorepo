//! Shared dispatch and hardware/emulator differential fuzz plans.

use arbitrary::{Arbitrary, Unstructured};

/// A bounded SIMD execution check.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Checks runtime backend selection and composed operations.
    Dispatch(crate::dispatch::fuzz::Plan),
    /// Checks native NEON against its emulator.
    #[cfg(target_arch = "aarch64")]
    Neon(crate::native::neon::fuzz::Plan),
}

impl Plan {
    /// Runs the selected check, consuming its inputs from `u`.
    ///
    /// Native instruction checks run only on supported architectures.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Dispatch(plan) => plan.run(u),
            #[cfg(target_arch = "aarch64")]
            Self::Neon(plan) => plan.run(u),
        }
    }
}
