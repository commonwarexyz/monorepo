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
// Use cfg_ready! for inline module with external submodule (Rust #54727)
commonware_utils::cfg_ready!(
    BETA,
    pub mod fields {
        pub mod goldilocks;
    }
);
ready_mod!(BETA, pub mod ntt);
ready_mod!(GAMMA, pub mod poly);
#[cfg(test)]
pub mod test;
