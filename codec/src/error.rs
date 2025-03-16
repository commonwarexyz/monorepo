//! Error types for codec operations

use thiserror::Error;

/// Error type for codec operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unexpected End-of-Buffer")]
    EndOfBuffer,
    #[error("Extra Data: {0} bytes")]
    ExtraData(usize),
    #[error("Length Exceeded: {0} > {1}")]
    LengthExceeded(usize, usize), // found, max
    #[error("Invalid Varint")]
    InvalidVarint,
    #[error("Invalid Bool")]
    InvalidBool,

    #[error("Invalid. Context({0}), Message({1})")]
    Invalid(&'static str, &'static str), // context, message

    #[error("Invalid: Err({1})")]
    Wrapped(&'static str, Box<dyn std::error::Error>),
}
