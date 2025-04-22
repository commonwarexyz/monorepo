use commonware_codec::FixedSize;
use commonware_cryptography::sha256::Digest;
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};

const SERIALIZED_LEN: usize = 1 + Digest::SIZE;

pub enum Value {
    Notarized(u64),
    Finalized(u64),
    Digest(Digest),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct MultiIndex([u8; SERIALIZED_LEN]);

impl MultiIndex {
    pub fn new(value: Value) -> Self {
        let mut bytes = [0; SERIALIZED_LEN];
        match value {
            Value::Notarized(value) => {
                bytes[0] = 0;
                bytes[1..9].copy_from_slice(&value.to_be_bytes());
            }
            Value::Finalized(value) => {
                bytes[0] = 1;
                bytes[1..9].copy_from_slice(&value.to_be_bytes());
            }
            Value::Digest(digest) => {
                bytes[0] = 2;
                bytes[1..].copy_from_slice(&digest);
            }
        }
        Self(bytes)
    }

    pub fn to_value(&self) -> Value {
        match self.0[0] {
            0 => {
                let bytes: [u8; u64::SERIALIZED_LEN] = self.0[1..9].try_into().unwrap();
                let value = u64::from_be_bytes(bytes);
                Value::Notarized(value)
            }
            1 => {
                let bytes: [u8; u64::SERIALIZED_LEN] = self.0[1..9].try_into().unwrap();
                let value = u64::from_be_bytes(bytes);
                Value::Finalized(value)
            }
            2 => {
                let bytes: [u8; Digest::SERIALIZED_LEN] = self.0[1..].try_into().unwrap();
                let digest = Digest::from(bytes);
                Value::Digest(digest)
            }
            _ => unreachable!(),
        }
    }
}

impl Array for MultiIndex {}

impl FixedSize for MultiIndex {
    const SIZE: usize = SERIALIZED_LEN;
}

impl From<[u8; MultiIndex::SERIALIZED_LEN]> for MultiIndex {
    fn from(value: [u8; MultiIndex::SERIALIZED_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for MultiIndex {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for MultiIndex {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for MultiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0[0] {
            0 => {
                let bytes: [u8; u64::SERIALIZED_LEN] = self.0[1..9].try_into().unwrap();
                write!(f, "notarized({})", u64::from_be_bytes(bytes))
            }
            1 => {
                let bytes: [u8; u64::SERIALIZED_LEN] = self.0[1..9].try_into().unwrap();
                write!(f, "finalized({})", u64::from_be_bytes(bytes))
            }
            2 => {
                let bytes: [u8; Digest::SERIALIZED_LEN] = self.0[1..].try_into().unwrap();
                write!(f, "digest({})", Digest::from(bytes))
            }
            _ => unreachable!(),
        }
    }
}

impl Display for MultiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}
