//! Metrics for the process's global allocator.
//!
//! Each supported allocator has a submodule that registers its statistics
//! under the `allocator` family. [`super::metered::Metrics`] refreshes the
//! enabled one.

pub mod mimalloc;
