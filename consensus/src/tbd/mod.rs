//! TBD
//!
//! Produces threshold signatures over each notarization/finalization. Produces
//! a separate threshold signature for producer selection.

pub mod block;
pub mod reactor;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sender closed")]
    SenderClosed,
}
