use core::ops::Range;
use thiserror::Error;

/// Errors relating to the handshake.
#[derive(Error, Debug)]
pub enum Error {
    /// The handshake failed.
    ///
    /// The error does not say why. The application cannot act on the reason, and revealing it
    /// could help an adversary.
    #[error("handshake failed")]
    HandshakeFailed,
    /// The timestamp is not in the allowable bounds
    #[error("timestamp {0} not in {1:?}")]
    InvalidTimestamp(u64, Range<u64>),
}
