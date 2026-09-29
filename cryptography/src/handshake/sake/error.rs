use core::ops::Range;
use thiserror::Error;

/// Errors relating to the handshake.
#[derive(Error, Debug)]
pub enum Error {
    /// A peer's signature, ephemeral key, or confirmation was invalid.
    #[error("handshake failed")]
    HandshakeFailed,
    /// The timestamp is not in the allowable bounds
    #[error("timestamp {0} not in {1:?}")]
    InvalidTimestamp(u64, Range<u64>),
}
