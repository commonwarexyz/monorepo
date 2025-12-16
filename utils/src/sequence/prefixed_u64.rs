//! A `u64` array type with a prefix byte to allow for multiple key contexts.

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

/// An `Array` implementation for prefixed `U64`
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct U64([u8; u64::SIZE + 1]);

impl U64 {
    pub const fn new(prefix: u8, value: u64) -> Self {
        // TODO: #![feature(const_index)]
        // https://github.com/rust-lang/rust/issues/143775
        let [b0, b1, b2, b3, b4, b5, b6, b7] = value.to_be_bytes();
        Self([prefix, b0, b1, b2, b3, b4, b5, b6, b7])
    }

    pub const fn prefix(&self) -> u8 {
        self.0[0]
    }

    pub fn value(&self) -> u64 {
        u64::from_be_bytes(self.0[1..].try_into().unwrap())
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
    const SIZE: usize = u64::SIZE + 1;
}

impl Span for U64 {}

impl Array for U64 {}

impl From<[u8; Self::SIZE]> for U64 {
    fn from(value: [u8; Self::SIZE]) -> Self {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.0[0],
            u64::from_be_bytes(self.0[1..].try_into().unwrap())
        )
    }
}

impl Display for U64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
        assert_eq!(value, decoded.value());
        assert_eq!(prefix, decoded.prefix());
        let from = U64::from(array.0);
        assert_eq!(value, from.value());
        assert_eq!(prefix, from.prefix());

        let vec = array.to_vec();
        let from_vec = U64::decode(vec.as_ref()).unwrap();
        assert_eq!(value, from_vec.value());
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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<U64>,
        }
    }
}
