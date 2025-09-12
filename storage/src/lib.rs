//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! `commonware-storage` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub mod mmr;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod adb;
        pub mod archive;
        pub mod bmt;
        pub mod cache;
        pub mod freezer;
        pub mod index;
        pub mod journal;
        pub mod metadata;
        pub mod ordinal;
        pub mod rmap;
        pub mod store;
        pub mod translator;
    }
}
