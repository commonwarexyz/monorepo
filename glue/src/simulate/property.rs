//! Safety and liveness property traits for simulation testing.

use super::tracker::ProgressTracker;
use commonware_cryptography::PublicKey;

/// A safety property checked after each finalization.
///
/// Receives the inspectable states of all active (non-crashed) validators.
pub trait SafetyProperty<S>: Send + Sync {
    /// Human-readable name for error reporting.
    fn name(&self) -> &str;

    /// Check the property. Returns `Err` with a description if violated.
    fn check(&self, states: &[&S]) -> Result<(), String>;
}

/// A liveness property checked at simulation end.
pub trait LivenessProperty<P: PublicKey>: Send + Sync {
    /// Human-readable name for error reporting.
    fn name(&self) -> &str;

    /// Check the property against the final progress tracker state.
    fn check(&self, tracker: &ProgressTracker<P>) -> Result<(), String>;
}
