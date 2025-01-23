//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! `commonware-storage` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#[cfg(not(target_arch = "wasm32"))]
pub mod archive;
#[cfg(not(target_arch = "wasm32"))]
pub mod journal;
#[cfg(not(target_arch = "wasm32"))]
pub mod metadata;
pub mod mmr;
