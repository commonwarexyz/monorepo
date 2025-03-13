use commonware_codec::{Codec, Reader, SizedCodec, Writer};
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

/// An `Array` implementation for `u64`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct U64(pub [u8; u64::LEN_CODEC]);

impl Codec for U64 {
    fn len_encoded(&self) -> usize {
        Self::LEN_CODEC
    }

    fn write(&self, writer: &mut impl Writer) {
        writer.write(&self.0);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, commonware_codec::Error> {
        reader.read().map(Self)
    }
}

impl SizedCodec for U64 {
    const LEN_CODEC: usize = u64::LEN_CODEC;
}

impl U64 {
    pub fn new(value: u64) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl From<[u8; U64::LEN_CODEC]> for U64 {
    fn from(value: [u8; U64::LEN_CODEC]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for U64 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != U64::LEN_CODEC {
            return Err(Error::InvalidLength);
        }
        let array: [u8; U64::LEN_CODEC] = value.try_into().map_err(|_| Error::InvalidLength)?;
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
        if value.len() != U64::LEN_CODEC {
            return Err(Error::InvalidLength);
        }

        // If the length is correct, we can safely convert the vector into a boxed slice without any
        // copies.
        let boxed_slice = value.into_boxed_slice();
        let boxed_array: Box<[u8; U64::LEN_CODEC]> =
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
