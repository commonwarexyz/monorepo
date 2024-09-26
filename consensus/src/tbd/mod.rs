//! TBD
//!
//! Produces threshold signatures over each notarization/finalization. Produces
//! a separate threshold signature for producer selection.

pub mod reactor;

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
}
