//! Procedural macros for async select, stability annotations, and test utilities.
//!
//! This crate provides:
//! - [`select!`] - Biased async select over multiple futures (requires `std` feature)
//! - [`select_loop!`] - Continuous select loop with shutdown handling (requires `std` feature)
//! - [`stability`], [`stability_mod!`], [`stability_scope!`] - API stability annotations
//! - [`test_async`], [`test_traced`], [`test_collect_traces`] - Test utilities
//! - [`test_group`] - Nextest filter group annotations

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub use commonware_macros_impl::{select, select_loop};
pub use commonware_macros_impl::{
    stability, stability_mod, stability_scope, test_async, test_collect_traces, test_group,
    test_traced,
};

#[doc(hidden)]
#[cfg(feature = "std")]
pub mod __reexport {
    pub use tokio;
}
