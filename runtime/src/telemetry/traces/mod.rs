//! Utility functions for traces

pub mod status;

#[cfg(any(test, feature = "test-utils"))]
pub mod collector;
