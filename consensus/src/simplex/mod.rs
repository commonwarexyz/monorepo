//! Simplex
//!
//! PoA Consensus useful for running a DKG
//!
//! # Sync
//!
//! Wait for block finalization at tip (2f+1), fetch heights backwards (don't
//! need to backfill views).

mod backfiller;
mod config;
mod engine;
mod store;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid signature")]
    InvalidSignature,
}
