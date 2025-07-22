//! Provide an ordered stream of finalized blocks.
//!
//! This module is responsible for taking the output of the consensus protocol,
//! which may be out of order and have gaps, and ordering it into a canonical,
//! contiguous sequence of finalized blocks. It handles fetching missing data
//! from peers.
//!
//! The main component is the [`actor::Actor`], which drives the process.

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actor;
        pub use actor::Actor;
        mod config;
        mod handler;
        mod ingress;
    }
}
