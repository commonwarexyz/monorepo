use crate::SizedSerialize;
use bytes::Buf;
use std::{
    cmp::{Ord, PartialOrd},
    error::Error as StdError,
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

/// Errors that can occur when interacting with cryptographic primitives.
#[derive(Error, Debug, PartialEq)]
pub enum Error<E: StdError + Send + Sync + 'static> {
    #[error("invalid bytes")]
    InsufficientBytes,
    #[error("invalid u64 length")]
    InvalidU64Length,
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
    + for<'a> TryFrom<&'a [u8], Error = <Self as Array>::Error>
    + for<'a> TryFrom<&'a Vec<u8>, Error = <Self as Array>::Error>
    + TryFrom<Vec<u8>, Error = <Self as Array>::Error>
    + SizedSerialize
{
    /// Errors returned when parsing an invalid byte sequence.
    type Error: StdError + Send + Sync + 'static;

    /// Attempts to read an array from the provided buffer.
    fn read_from<B: Buf>(buf: &mut B) -> Result<Self, Error<<Self as Array>::Error>> {
        let len = Self::SERIALIZED_LEN;
        if buf.remaining() < len {
            return Err(Error::InsufficientBytes);
        }

        let chunk = buf.chunk();
        if chunk.len() >= len {
            let array = Self::try_from(&chunk[..len]).map_err(Error::Other)?;
            buf.advance(len);
            return Ok(array);
        }

        let mut temp = vec![0u8; len];
        buf.copy_to_slice(&mut temp);
        Self::try_from(temp).map_err(Error::Other)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct U64([u8; U64::SERIALIZED_LEN]);

impl U64 {
    pub fn new(value: u64) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl Array for U64 {
    type Error = Error<std::convert::Infallible>;
}

impl SizedSerialize for U64 {
    const SERIALIZED_LEN: usize = u64::SERIALIZED_LEN;
}

impl From<[u8; U64::SERIALIZED_LEN]> for U64 {
    fn from(value: [u8; U64::SERIALIZED_LEN]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for U64 {
    type Error = Error<std::convert::Infallible>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != U64::SERIALIZED_LEN {
            return Err(Error::InvalidU64Length);
        }
        let array: [u8; U64::SERIALIZED_LEN] =
            value.try_into().map_err(|_| Error::InvalidU64Length)?;
        Ok(Self(array))
    }
}

impl TryFrom<&Vec<u8>> for U64 {
    type Error = Error<std::convert::Infallible>;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for U64 {
    type Error = Error<std::convert::Infallible>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != U64::SERIALIZED_LEN {
            return Err(Error::InvalidU64Length);
        }

        // If the length is correct, we can safely convert the vector into a boxed slice without any
        // copies.
        let boxed_slice = value.into_boxed_slice();
        let boxed_array: Box<[u8; U64::SERIALIZED_LEN]> = boxed_slice
            .try_into()
            .map_err(|_| Error::InvalidU64Length)?;
        Ok(Self(*boxed_array))
    }
}

impl AsRef<[u8]> for U64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for U64 {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for U64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from_be_bytes(self.0))
    }
}

impl Display for U64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from_be_bytes(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64() {
        let value = 42u64;
        let array = U64::new(value);
        assert_eq!(value, U64::try_from(array.as_ref()).unwrap().to_u64());
        assert_eq!(value, U64::from(array.0).to_u64());

        let vec = array.to_vec();
        assert_eq!(value, U64::try_from(&vec).unwrap().to_u64());
        assert_eq!(value, U64::try_from(vec).unwrap().to_u64());
    }
}
