//! Formatter for Commonware macro invocations.

#![doc(hidden)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

#[cfg(not(commonware_stability_RESERVED))]
pub mod macros;
#[cfg(not(commonware_stability_RESERVED))]
pub mod pretty;
#[cfg(not(commonware_stability_RESERVED))]
pub mod source;

mod writer;
