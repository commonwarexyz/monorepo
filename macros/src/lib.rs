//! Augment the development of primitives with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub use commonware_proc_macros::{select, test_async, test_traced};

// Hidden from docs because these are needed for the proc macros to use 3rd
// party crates.
#[doc(hidden)]
pub use ::futures;
#[doc(hidden)]
pub use ::tracing;
#[doc(hidden)]
pub use ::tracing_subscriber;
