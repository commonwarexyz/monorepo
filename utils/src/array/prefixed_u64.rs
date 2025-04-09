//! A `u64` array type with a prefix byte to allow for multiple key contexts.

use crate::Array;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

// Errors returned by `U64` functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
}

/// An `Array` implementation for prefixed `U64`
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct U64([u8; u64::LEN_ENCODED + 1]);

impl U64 {
    pub fn new(prefix: u8, value: u64) -> Self {
        let mut arr = [0; u64::LEN_ENCODED + 1];
        arr[0] = prefix;
        arr[1..].copy_from_slice(&u64::to_be_bytes(value));

        Self(arr)
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[1..].try_into().unwrap())
    }

    pub fn prefix(&self) -> u8 {
        self.0[0]
    }
}

impl Write for U64 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for U64 {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, CodecError> {
        <[u8; Self::LEN_ENCODED]>::read(buf).map(Self)
    }
}

impl FixedSize for U64 {
    const LEN_ENCODED: usize = u64::LEN_ENCODED + 1;
}

impl Array for U64 {
    type Error = Error;
}

impl From<[u8; U64::LEN_ENCODED]> for U64 {
    fn from(value: [u8; U64::LEN_ENCODED]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for U64 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != U64::LEN_ENCODED {
            return Err(Error::InvalidLength);
        }
        let array: [u8; U64::LEN_ENCODED] = value.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self(array))
    }
}

impl TryFrom<&Vec<u8>> for U64 {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for U64 {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != U64::LEN_ENCODED {
            return Err(Error::InvalidLength);
        }

        // If the length is correct, we can safely convert the vector into a boxed slice without any
        // copies.
        let boxed_slice = value.into_boxed_slice();
        let boxed_array: Box<[u8; U64::LEN_ENCODED]> =
            boxed_slice.try_into().map_err(|_| Error::InvalidLength)?;
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
        write!(
            f,
            "{}:{}",
            self.0[0],
            u64::from_be_bytes(self.0[1..].try_into().unwrap())
        )
    }
}

impl Display for U64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt, Encode};

    use super::*;

    #[test]
    fn test_prefixed_u64() {
        let prefix = 69u8;
        let value = 42u64;
        let array = U64::new(prefix, value);
        let try_from = U64::try_from(array.as_ref()).unwrap();
        assert_eq!(value, try_from.to_u64());
        assert_eq!(prefix, try_from.prefix());
        let from = U64::from(array.0);
        assert_eq!(value, from.to_u64());
        assert_eq!(prefix, from.prefix());

        let vec = array.to_vec();
        let from_vec = U64::try_from(&vec).unwrap();
        assert_eq!(value, from_vec.to_u64());
        assert_eq!(prefix, from_vec.prefix());
        let from_vec = U64::try_from(vec).unwrap();
        assert_eq!(value, from_vec.to_u64());
        assert_eq!(prefix, from_vec.prefix());
    }

    #[test]
    fn test_prefixed_u64_codec() {
        let original = U64::new(69, 42u64);

        let encoded = original.encode();
        assert_eq!(encoded.len(), U64::LEN_ENCODED);
        assert_eq!(encoded, original.as_ref());

        let decoded = U64::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
