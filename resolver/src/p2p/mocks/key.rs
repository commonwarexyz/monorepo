use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::Array;
use std::{fmt, ops::Deref};
use thiserror::Error;

/// A key that can be used for testing
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Key(pub u8);

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.0)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        std::slice::from_ref(&self.0)
    }
}

impl Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        std::slice::from_ref(&self.0)
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(Error::TryFrom);
        }
        Ok(Key(value[0]))
    }
}

impl TryFrom<&Vec<u8>> for Key {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl Write for Key {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Key {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        u8::read(buf).map(Self)
    }
}

impl FixedSize for Key {
    const SIZE: usize = u8::SIZE;
}

impl Array for Key {
    type Error = Error;
}

/// Error type for the Array trait
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("try_from failed")]
    TryFrom,
}
