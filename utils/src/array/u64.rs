use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use thiserror::Error;

use crate::Array;

// Errors returned by `U64` functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
}

/// An `Array` implementation for `u64`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct U64([u8; u64::SIZE]);

impl U64 {
    pub fn new(value: u64) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl Write for U64 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for U64 {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        <[u8; U64::SIZE]>::read(buf).map(Self)
    }
}

impl FixedSize for U64 {
    const SIZE: usize = u64::SIZE;
}

impl Array for U64 {}

impl From<[u8; U64::SIZE]> for U64 {
    fn from(value: [u8; U64::SIZE]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for U64 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != U64::SIZE {
            return Err(Error::InvalidLength);
        }
        let array: [u8; U64::SIZE] = value.try_into().map_err(|_| Error::InvalidLength)?;
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
        if value.len() != U64::SIZE {
            return Err(Error::InvalidLength);
        }

        // If the length is correct, we can safely convert the vector into a boxed slice without any
        // copies.
        let boxed_slice = value.into_boxed_slice();
        let boxed_array: Box<[u8; U64::SIZE]> =
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
    use commonware_codec::{DecodeExt, Encode};

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

    #[test]
    fn test_codec() {
        let original = U64::new(42u64);

        let encoded = original.encode();
        assert_eq!(encoded.len(), U64::SIZE);
        assert_eq!(encoded, original.as_ref());

        let decoded = U64::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
