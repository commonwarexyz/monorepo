//! Allocate and manage memory.
//!
//! Allocator behavior that matters for I/O-heavy services (how long freed
//! memory is retained, whether a fixed amount is kept committed, how much is
//! purged back to the operating system) is usually set through environment
//! variables read by the allocator at startup. This crate makes that
//! configuration part of the binary instead, and exposes the allocator's
//! statistics so a runtime can export them as metrics.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(ALPHA, cfg(feature = "mimalloc") {
    pub mod mimalloc;
});
