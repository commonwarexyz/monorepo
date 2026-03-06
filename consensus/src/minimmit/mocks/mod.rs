//! Mock implementations for Minimmit testing.
//!
//! These mocks are used for testing the Minimmit consensus engine and can also be
//! used by downstream crates for integration testing.

// Re-export shared mocks (protocol-agnostic)
pub use crate::mocks::{application, relay, twins};

// Minimmit-specific mocks
pub mod reporter;
