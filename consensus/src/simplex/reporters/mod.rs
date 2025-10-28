//! Reporter implementations for consensus activity monitoring.
//!
//! This module provides various reporter implementations that can be used to
//! monitor and expose consensus activities. Reporters implement the [`crate::Reporter`]
//! trait and can be composed together to create sophisticated monitoring pipelines.

mod attributable;
pub use attributable::AttributableReporter;
