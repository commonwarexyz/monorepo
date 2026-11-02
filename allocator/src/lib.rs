//! Allocate and manage memory.
//!
//! Allocators usually read their tuning (how long freed memory is retained,
//! how much is reserved up front, when memory returns to the operating
//! system) from environment variables at startup. This crate sets that
//! configuration in the binary and exposes allocator statistics for export as
//! metrics.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(ALPHA, cfg(feature = "mimalloc") {
    pub mod mimalloc;
});
