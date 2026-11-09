// edition:2021

// Stands in for `commonware_macros` under its crate name.

extern crate commonware_macros_impl;

pub use commonware_macros_impl::{select, select_loop};

#[doc(hidden)]
pub mod __reexport {
    pub extern crate tokio;
}
