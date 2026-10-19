//! Utilities for running benchmarks.

pub mod context;
commonware_macros::stability_mod!(BETA, pub mod tokio);

/// Installs mimalloc as the global allocator of every binary that links this
/// crate with the `bench-mimalloc` feature, so allocator comparisons can be
/// run across all workspace benchmarks without editing each entry point. The
/// crate's own test binary is left free to install an allocator of its own.
#[cfg(all(feature = "bench-mimalloc", not(test)))]
#[global_allocator]
static GLOBAL_ALLOCATOR: commonware_allocator::mimalloc::MiMalloc =
    commonware_allocator::mimalloc::MiMalloc::new(commonware_allocator::mimalloc::Config::DEFAULT);
