#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use commonware_macros::stability_mod;

stability_mod!(GAMMA, pub mod algebra);
commonware_utils::stability_cfg!(
    BETA,
    pub mod fields {
        pub mod goldilocks;
    }
);
stability_mod!(BETA, pub mod ntt);
stability_mod!(GAMMA, pub mod poly);
#[cfg(test)]
pub(crate) mod test;
