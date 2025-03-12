use commonware_codec::SizedCodec;
use std::{
    cmp::{Ord, PartialOrd},
    error::Error as StdError,
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

pub mod fixed_bytes;
pub use fixed_bytes::FixedBytes;
pub mod u64;
pub use u64::U64;

/// Errors returned by the `Array` trait's functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error<E: StdError + Send + Sync + 'static> {
    #[error("invalid bytes")]
    InsufficientBytes,
    #[error("other: {0}")]
    Other(E),
}

/// Types that can be fallibly read from a fixed-size byte sequence.
///
/// `Array` is typically used to parse things like `PublicKeys` and `Signatures`
/// from an untrusted network connection. Once parsed, these types are assumed
/// to be well-formed (which prevents duplicate validation).
///
/// If a byte sequencer is not properly formatted, `TryFrom` must return an error.
pub trait Array:
    Clone
    + Send
    + Sync
    + 'static
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Debug
    + Hash
    + Display
    + AsRef<[u8]>
    + Deref<Target = [u8]>
    + SizedCodec
{
}

/// To prevent the need for constant implementation of `Array` for all types,
/// we can implement `Array` for types that implement the necessary traits.
impl<
        T: Clone
            + Send
            + Sync
            + 'static
            + Eq
            + PartialEq
            + Ord
            + PartialOrd
            + Debug
            + Hash
            + Display
            + AsRef<[u8]>
            + Deref<Target = [u8]>
            + SizedCodec,
    > Array for T
{
}
