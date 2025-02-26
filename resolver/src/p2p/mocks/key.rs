use commonware_utils::{Array, SizedSerialize};
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

impl SizedSerialize for Key {
    const SERIALIZED_LEN: usize = 1;
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
