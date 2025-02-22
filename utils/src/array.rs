use crate::SizedSerialize;
use bytes::Buf;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

/// Errors that can occur when interacting with cryptographic primitives.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid bytes")]
    InsufficientBytes,
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
    + for<'a> TryFrom<&'a [u8], Error = <Self as Array>::Error>
    + for<'a> TryFrom<&'a Vec<u8>, Error = <Self as Array>::Error>
    + TryFrom<Vec<u8>, Error = <Self as Array>::Error>
    + SizedSerialize
{
    /// Associated error type for conversions
    type Error: std::error::Error + Send + Sync + 'static + From<Error>;

    /// Attempts to read an array from the provided buffer.
    fn read_from<B: Buf>(buf: &mut B) -> Result<Self, <Self as Array>::Error> {
        let len = Self::SERIALIZED_LEN;
        if buf.remaining() < len {
            return Err(<Self as Array>::Error::from(Error::InsufficientBytes));
        }

        let chunk = buf.chunk();
        if chunk.len() >= len {
            let array = Self::try_from(&chunk[..len])?;
            buf.advance(len);
            return Ok(array);
        }

        let mut temp = vec![0u8; len];
        buf.copy_to_slice(&mut temp);
        Self::try_from(temp)
    }
}
