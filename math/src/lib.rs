#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

commonware_macros::stability_scope!(ALPHA {
    pub mod fields {
        pub mod goldilocks;
    }
    pub mod ntt;
});
commonware_macros::stability_scope!(BETA {
    pub mod algebra;
    pub mod poly;
});

#[cfg(test)]
pub(crate) mod test;
