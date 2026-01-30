//! Procedural macros for async select, stability annotations, and test utilities.
//!
//! This crate provides:
//! - [`select!`] - Biased async select over multiple futures
//! - [`select_loop!`] - Continuous select loop with shutdown handling
//! - [`stability`], [`stability_mod!`], [`stability_scope!`] - API stability annotations
//! - [`test_async`], [`test_traced`], [`test_collect_traces`] - Test utilities
//! - [`test_group`] - Nextest filter group annotations

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub use commonware_macros_impl::{
    select, select_loop, stability, stability_mod, stability_scope, test_async,
    test_collect_traces, test_group, test_traced,
};

#[doc(hidden)]
pub mod __reexport {
    pub use futures;
}
