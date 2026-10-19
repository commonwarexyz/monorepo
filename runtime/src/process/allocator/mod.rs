//! Metrics for the process's global allocator.
//!
//! Each supported allocator has a submodule that names its exported
//! statistics and registers them under the `allocator` family, and
//! [`super::metered::Metrics`] refreshes the one the binary enabled.

#[cfg(feature = "mimalloc")]
pub mod mimalloc;
