//! Property traits for simulation testing.

use super::tracker::ProgressTracker;
use commonware_cryptography::PublicKey;
use std::{future::Future, pin::Pin};

/// A property checked after each finalization.
///
/// Receives the inspectable states of all active (non-crashed) validators.
pub trait FinalizationProperty<S>: Send + Sync {
    /// Human-readable name for error reporting.
    fn name(&self) -> &str;

    /// Check the property. Returns `Err` with a description if violated.
    fn check<'a>(
        &'a self,
        states: &'a [&'a S],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// A property checked once at simulation end with access to both the
/// progress tracker and all validator states (inside the runtime,
/// before it shuts down).
pub trait Property<P: PublicKey, S>: Send + Sync {
    /// Human-readable name for error reporting.
    fn name(&self) -> &str;

    /// Check the property. Returns `Err` with a description if violated.
    fn check<'a>(
        &'a self,
        tracker: &'a ProgressTracker<P>,
        states: &'a [&'a S],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
