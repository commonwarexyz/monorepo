#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

commonware_macros::stability_scope!(ALPHA {
    mod consistency;
    pub use consistency::check_consistent;
    mod core;
    pub use core::{ArmV9, X86V4C, Neon, Operation, Simd};
    mod dispatch;
    pub use dispatch::{dispatch, test_dispatch};
    pub mod emulated;
    pub mod native;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
});
