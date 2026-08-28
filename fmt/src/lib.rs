//! Formatter for Commonware macro invocations.
//!
//! The crate locates supported macro bodies in Rust source, formats their ordinary
//! Rust fragments with `rustfmt`, and renders macro-specific shells. Unsupported
//! or unsafe-to-rewrite source is preserved.

#![doc(hidden)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod file;
pub mod fragment;
pub mod macros;
pub mod rustfmt;
pub mod source;

mod marker;
mod skip;
mod trivia;
mod writer;
