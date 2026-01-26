#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use commonware_macros::ready_mod;

ready_mod!(WIRE_STABLE, pub mod algebra);
// Raw cfg required: inline module contains external submodule (Rust #54727)
// TESTED: excluded at WIRE_STABLE, API_STABLE, or PRODUCTION
#[cfg(not(min_readiness_WIRE_STABLE))]
#[cfg(not(min_readiness_API_STABLE))]
#[cfg(not(min_readiness_PRODUCTION))]
pub mod fields {
    pub mod goldilocks;
}
ready_mod!(TESTED, pub mod ntt);
ready_mod!(WIRE_STABLE, pub mod poly);
#[cfg(test)]
pub mod test;
