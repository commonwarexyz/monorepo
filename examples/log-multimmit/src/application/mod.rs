//! The mock application attachment used by this example.
//!
//! Multimmit exchanges payload commitments rather than application bytes. This example keeps the
//! attachment deliberately minimal: proposals are deterministic commitments and relay is a no-op.

mod actor;
pub use actor::Application;
