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

// Errors returned by [U32] functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
}

/// An [Array] implementation for u32.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct U32([u8; u32::SIZE]);

impl U32 {
    pub fn new(value: u32) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

impl Write for U32 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for U32 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        <[u8; U32::SIZE]>::read(buf).map(Self)
    }
}

impl FixedSize for U32 {
    const SIZE: usize = u32::SIZE;
}

impl Array for U32 {}

impl From<[u8; U32::SIZE]> for U32 {
    fn from(value: [u8; U32::SIZE]) -> Self {
        Self(value)
    }
}

impl From<u32> for U32 {
    fn from(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}

impl AsRef<[u8]> for U32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for U32 {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for U32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u32::from_be_bytes(self.0))
    }
}

impl Display for U32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u32::from_be_bytes(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_u32() {
        let value = 42u32;
        let array = U32::new(value);
        assert_eq!(value, U32::decode(array.as_ref()).unwrap().to_u32());
        assert_eq!(value, U32::from(array.0).to_u32());

        let vec = array.to_vec();
        assert_eq!(value, U32::decode(vec.as_ref()).unwrap().to_u32());
    }

    #[test]
    fn test_codec() {
        let original = U32::new(42u32);

        let encoded = original.encode();
        assert_eq!(encoded.len(), U32::SIZE);
        assert_eq!(encoded, original.as_ref());

        let decoded = U32::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
