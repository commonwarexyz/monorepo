//! Formatter for Commonware macro invocations.

#![doc(hidden)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod file;
pub mod macros;
pub mod pretty;
pub mod rustfmt;
pub mod source;

mod marker;
mod skip;
mod trivia;
mod writer;
