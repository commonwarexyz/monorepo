//! Collection of mocks used to test `simplex`.

// Re-export shared mocks (protocol-agnostic)
pub use crate::mocks::{application, relay, twins};

// Simplex-specific mocks
pub mod conflicter;
pub mod equivocator;
pub mod impersonator;
pub mod nuller;
pub mod nullify_only;
pub mod outdated;
pub mod reconfigurer;
pub mod reporter;
