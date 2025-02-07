//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! `commonware-storage` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

pub mod bmt;
pub mod mmr;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod archive;
        pub mod journal;
        pub mod metadata;
    }
}
