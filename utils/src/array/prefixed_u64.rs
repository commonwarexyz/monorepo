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
pub struct U64([u8; u64::SIZE + 1]);

impl U64 {
    pub fn new(prefix: u8, value: u64) -> Self {
        let mut arr = [0; u64::SIZE + 1];
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
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        <[u8; Self::SIZE]>::read(buf).map(Self)
    }
}

impl FixedSize for U64 {
    const SIZE: usize = u64::SIZE + 1;
}

impl Array for U64 {}

impl From<[u8; U64::SIZE]> for U64 {
    fn from(value: [u8; U64::SIZE]) -> Self {
        Self(value)
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
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_prefixed_u64() {
        let prefix = 69u8;
        let value = 42u64;
        let array = U64::new(prefix, value);
        let decoded = U64::decode(array.as_ref()).unwrap();
        assert_eq!(value, decoded.to_u64());
        assert_eq!(prefix, decoded.prefix());
        let from = U64::from(array.0);
        assert_eq!(value, from.to_u64());
        assert_eq!(prefix, from.prefix());

        let vec = array.to_vec();
        let from_vec = U64::decode(vec.as_ref()).unwrap();
        assert_eq!(value, from_vec.to_u64());
        assert_eq!(prefix, from_vec.prefix());
    }

    #[test]
    fn test_prefixed_u64_codec() {
        let original = U64::new(69, 42u64);

        let encoded = original.encode();
        assert_eq!(encoded.len(), U64::SIZE);
        assert_eq!(encoded, original.as_ref());

        let decoded = U64::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
