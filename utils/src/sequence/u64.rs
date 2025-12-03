use crate::{Array, Span};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use core::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display, Formatter},
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
pub struct U64([u8; u64::SIZE]);

impl U64 {
    pub const fn new(value: u64) -> Self {
        Self(value.to_be_bytes())
    }
}

impl Write for U64 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for U64 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        <[u8; Self::SIZE]>::read(buf).map(Self)
    }
}

impl FixedSize for U64 {
    const SIZE: usize = u64::SIZE;
}

impl Span for U64 {}

impl Array for U64 {}

impl From<[u8; Self::SIZE]> for U64 {
    fn from(value: [u8; Self::SIZE]) -> Self {
        Self(value)
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self {
        Self(value.to_be_bytes())
    }
}

impl From<U64> for u64 {
    fn from(value: U64) -> Self {
        Self::from_be_bytes(value.0)
    }
}

impl From<&U64> for u64 {
    fn from(value: &U64) -> Self {
        Self::from_be_bytes(value.0)
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
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", u64::from_be_bytes(self.0))
    }
}

impl Display for U64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", u64::from_be_bytes(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_u64() {
        let value = 42u64;
        let array = U64::new(value);
        assert_eq!(value, U64::decode(array.as_ref()).unwrap().into());
        assert_eq!(value, U64::from(array.0).into());

        let vec = array.to_vec();
        assert_eq!(value, U64::decode(vec.as_ref()).unwrap().into());
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
