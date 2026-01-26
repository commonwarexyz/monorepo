#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use commonware_macros::ready_mod;

ready_mod!(GAMMA, pub mod algebra);
// Raw cfg required: inline module contains external submodule (Rust #54727)
#[cfg(not(min_readiness_GAMMA))]
#[cfg(not(min_readiness_DELTA))]
#[cfg(not(min_readiness_EPSILON))]
pub mod fields { // BETA
    pub mod goldilocks;
}
ready_mod!(BETA, pub mod ntt);
ready_mod!(GAMMA, pub mod poly);
#[cfg(test)]
pub mod test;
