//! Error types for codec operations

use thiserror::Error;

/// Error type for codec operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("unexpected end of buffer")]
    EndOfBuffer,
    #[error("extra data found: {0} bytes")]
    ExtraData(usize),
    #[error("invalid data in {0}: {1}")]
    InvalidData(String, String), // context, message
    #[error("length exceeded: {0} > {1}")]
    LengthExceeded(usize, usize), // found, max
    #[error("invalid varint")]
    InvalidVarint,
    #[error("invalid bool")]
    InvalidBool,
}
