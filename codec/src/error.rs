//! Error types for codec operations.

use thiserror::Error;

/// Error type for codec operations
#[derive(Error, Debug)]
pub enum Error {
    /// Indicates that the input buffer (`Buf`) did not contain enough bytes to read
    /// the next piece of data required by a [`Read`](crate::Read) implementation.
    /// This suggests the input data is truncated or incomplete.
    #[error("Unexpected End-of-Buffer: Not enough bytes remaining to read data")]
    EndOfBuffer,

    /// Indicates that after successfully decoding a value using a method like
    /// [`Decode::decode_cfg`](crate::Decode::decode_cfg), there were still
    /// unconsumed bytes remaining in the input buffer.
    ///
    /// This usually means the input data contained more than just the expected encoded value.
    /// The contained `usize` is the number of bytes that remained unconsumed.
    #[error("Extra Data: {0} bytes remained in buffer after decoding")]
    ExtraData(usize),

    /// A variable-length integer (varint), often used for encoding lengths,
    /// could not be decoded correctly. This might happen if:
    /// - The varint encoding itself is malformed (e.g., too long).
    /// - The decoded varint value exceeds the capacity of the target integer type.
    ///
    /// See the [`varint`](crate::varint) module for encoding details.
    #[error("Invalid Varint: Malformed or value out of range")]
    InvalidVarint,

    /// A byte representing a boolean was expected to be `0` (false) or `1` (true),
    /// but a different value was encountered during decoding.
    #[error("Invalid Bool: Expected 0 or 1, found different value")]
    InvalidBool,

    /// A length prefix (e.g., for `Vec<T>`, `Bytes`, `HashMap<K, V>`) was decoded,
    /// but its value fell outside the permitted range.
    ///
    /// This range is typically configured via a [`RangeConfig`](crate::RangeConfig)
    /// passed within the `Cfg` parameter to [`Read::read_cfg`](crate::Read::read_cfg).
    /// The contained `usize` is the invalid length that was decoded.
    #[error("Invalid Length: Decoded length {0} is outside the allowed range")]
    InvalidLength(usize),

    /// A semantic validation error occurred during decoding, indicating the data,
    /// while perhaps structurally valid, does not meet application-specific criteria.
    ///
    /// - The first `&'static str` provides context (e.g., the name of the type being decoded).
    /// - The second `&'static str` provides a specific error message.
    ///
    /// Example: Trying to decode a `HashMap` where keys were not in ascending order.
    #[error("Validation Error: Context({0}), Message({1})")]
    Invalid(&'static str, &'static str),

    /// An error occurred in underlying code (e.g., external library call, complex validation)
    /// and has been wrapped into a codec [`enum@Error`].
    ///
    /// - The `&'static str` provides context about the operation being performed.
    /// - The boxed [`std::error::Error`] is the original source error.
    ///
    /// Allows propagating custom errors through the codec reading process.
    #[error("Wrapped Error: Context({0}), Source({1})")]
    Wrapped(&'static str, Box<dyn std::error::Error + Send + Sync>),
}
