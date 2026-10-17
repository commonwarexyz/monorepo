//! Utilities for running benchmarks.

pub mod context;
commonware_macros::stability_mod!(BETA, pub mod tokio);

/// Installs mimalloc as the global allocator of every bench binary linking
/// this crate with the `bench-mimalloc` feature, so allocator comparisons can
/// be run across all workspace benchmarks without editing each entry point.
/// The crate's own test binary keeps the system allocator.
#[cfg(all(feature = "bench-mimalloc", not(test)))]
#[global_allocator]
static GLOBAL_ALLOCATOR: commonware_allocator::mimalloc::MiMalloc =
    commonware_allocator::mimalloc::MiMalloc::new(commonware_allocator::mimalloc::Config::DEFAULT);
