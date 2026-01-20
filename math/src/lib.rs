#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use commonware_macros::ready_mod;

ready_mod!(2, pub mod algebra);
#[cfg(not(min_readiness_2))]
pub mod fields {
    pub mod goldilocks;
}
ready_mod!(1, pub mod ntt);
ready_mod!(2, pub mod poly);
#[cfg(test)]
pub mod test;
