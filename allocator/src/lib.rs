//! Configure and observe the global allocator.
//!
//! Allocator behavior that matters for I/O-heavy services (how long freed
//! memory is retained, whether a fixed amount is kept committed, how much is
//! purged back to the operating system) is usually set through environment
//! variables read by the allocator at startup. This crate makes that
//! configuration part of the binary instead, and exposes the allocator's
//! statistics so a runtime can export them as metrics.
//!
//! # Allocators
//!
//! - [`mimalloc`]: a `#[global_allocator]` wrapper around a vendored build of
//!   mimalloc with a [`mimalloc::Config`] applied on the first allocation,
//!   plus [`mimalloc::Stats`] for process-wide allocator statistics.
//!
//! # Features
//!
//! - `mimalloc` (default): Builds the vendored mimalloc and enables the
//!   [`mimalloc`] module.
//! - `large-objects-1m`, `large-objects-2m`, `large-objects-4m`: Raise the
//!   largest allocation served from thread-local pages from 512 KiB to the
//!   named size (see [`mimalloc::LARGE_OBJECT_LIMIT`]). The largest enabled
//!   feature wins (so `--all-features` selects 4 MiB); 4 MiB is the most
//!   mimalloc's size-class table supports. Only binaries should enable them:
//!   the choice applies to the whole process.

commonware_macros::stability_scope!(ALPHA, cfg(feature = "mimalloc") {
    pub mod mimalloc;
});
