//! Operations that can be applied to an authenticated database.
//!
//! The `Operation` enum implements the `Array` trait, allowing for a persistent log of operations
//! based on a `crate::Journal`.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, Write};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

/// Errors returned by `Operation` functions.
#[derive(Error, Debug)]
pub enum Error<K: Array, V: Array> {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid key: {0}")]
    InvalidKey(<K as Array>::Error),
    #[error("invalid value: {0}")]
    InvalidValue(<V as Array>::Error),
    #[error("invalid context byte")]
    InvalidContextByte,
    #[error("delete operation has non-zero value")]
    InvalidDeleteOp,
    #[error("commit operation has non-zero bytes after location")]
    InvalidCommitOp,
}

/// The types of operations that can change the state of a database.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Type<K: Array, V: Array> {
    /// Indicates the key no longer has a value.
    Deleted(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    Commit(u64),
}

/// An `Array` implementation for operations applied to an authenticated database.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct Operation<K: Array, V: Array> {
    pub data: Vec<u8>,
    _phantom: std::marker::PhantomData<(K, V)>,
}

impl<K: Array, V: Array> Operation<K, V> {
    const DELETE_CONTEXT: u8 = 0;
    const UPDATE_CONTEXT: u8 = 1;
    const COMMIT_CONTEXT: u8 = 2;

    // A compile-time assertion that operation's array size is large enough to handle the commit
    // operation, which requires 9 bytes.
    const _MIN_OPERATION_LEN: usize = 9;
    const _COMMIT_OP_ASSERT: () = assert!(
        Self::SIZE >= Self::_MIN_OPERATION_LEN,
        "array size too small for commit op"
    );

    /// Create a new operation of the given type.
    pub fn new(t: Type<K, V>) -> Self {
        match t {
            Type::Deleted(key) => Self::delete(key),
            Type::Update(key, value) => Self::update(key, value),
            Type::Commit(loc) => Self::commit(loc),
        }
    }

    /// Create a new update operation that makes `key` have value `value`.
    pub fn update(key: K, value: V) -> Self {
        let mut data = Vec::with_capacity(Self::SIZE);
        data.push(Self::UPDATE_CONTEXT);
        data.extend_from_slice(&key);
        data.extend_from_slice(&value);

        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new delete operation that removes any value assigned to `key`.
    pub fn delete(key: K) -> Self {
        let mut data = Vec::with_capacity(Self::SIZE);
        data.push(Self::DELETE_CONTEXT);
        data.extend_from_slice(&key);
        data.resize(Self::SIZE, 0);

        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new commit operation that indicates the current floor on inactive operations is
    /// `loc`.
    pub fn commit(loc: u64) -> Self {
        let mut data = Vec::with_capacity(Self::SIZE);
        data.push(Self::COMMIT_CONTEXT);
        data.extend_from_slice(&loc.to_be_bytes());
        data.resize(Self::SIZE, 0);

        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn to_key(&self) -> K {
        K::try_from(&self.data[1..K::SIZE + 1]).unwrap()
    }

    pub fn to_type(&self) -> Type<K, V> {
        let key = K::try_from(&self.data[1..K::SIZE + 1]).unwrap();
        match self.data[0] {
            Self::DELETE_CONTEXT => Type::Deleted(key),
            Self::UPDATE_CONTEXT => {
                let value = V::try_from(&self.data[K::SIZE + 1..]).unwrap();
                Type::Update(key, value)
            }
            Self::COMMIT_CONTEXT => {
                let loc = u64::from_be_bytes(self.data[1..9].try_into().unwrap());
                Type::Commit(loc)
            }
            _ => unreachable!(),
        }
    }

    pub fn to_value(&self) -> Option<V> {
        match self.data[0] {
            Self::DELETE_CONTEXT => None,
            Self::UPDATE_CONTEXT => Some(V::try_from(&self.data[K::SIZE + 1..]).unwrap()),
            Self::COMMIT_CONTEXT => None,
            _ => unreachable!(),
        }
    }
}

impl<K: Array, V: Array> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        assert!(self.data.len() == Self::SIZE);
        buf.put_slice(&self.data);
    }
}

impl<K: Array, V: Array> Read for Operation<K, V> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let mut value = vec![0u8; Self::SIZE];
        buf.copy_to_slice(&mut value);
        Self::try_from(&value).map_err(|e: Error<K, V>| CodecError::Wrapped("Operation", e.into()))
    }
}

impl<K: Array, V: Array> FixedSize for Operation<K, V> {
    const SIZE: usize = K::SIZE + 1 + V::SIZE;
}

impl<K: Array, V: Array> Array for Operation<K, V> {
    type Error = Error<K, V>;
}

impl<K: Array, V: Array> TryFrom<&[u8]> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            return Err(Error::InvalidLength);
        }

        let _ = K::try_from(&value[1..K::SIZE + 1]).map_err(|e| Error::InvalidKey(e))?;

        match value[0] {
            Self::UPDATE_CONTEXT => {
                let _ = V::try_from(&value[K::SIZE + 1..]).map_err(|e| Error::InvalidValue(e))?;
            }
            Self::DELETE_CONTEXT => {
                // Check if the remaining bytes are all zeros
                if !value[K::SIZE + 1..].iter().all(|&b| b == 0) {
                    return Err(Error::InvalidDeleteOp);
                }
            }
            Self::COMMIT_CONTEXT => {
                // Check if the remaining bytes are all zeros
                if !value[9..].iter().all(|&b| b == 0) {
                    return Err(Error::InvalidCommitOp);
                }
            }
            _ => {
                return Err(Error::InvalidContextByte);
            }
        }

        Ok(Self {
            data: value.to_vec(),
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<K: Array, V: Array> TryFrom<&Vec<u8>> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<K: Array, V: Array> TryFrom<Vec<u8>> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<K: Array, V: Array> AsRef<[u8]> for Operation<K, V> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<K: Array, V: Array> Deref for Operation<K, V> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl<K: Array, V: Array> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_type() {
            Type::Deleted(key) => write!(f, "[key:{} <deleted>]", key),
            Type::Update(key, value) => write!(f, "[key:{} value:{}]", key, value),
            Type::Commit(loc) => write!(f, "[commit with inactivity floor: {}]", loc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::array::U64;

    #[test]
    fn test_operation_array_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Operation::update(key.clone(), value.clone());

        let from = Operation::try_from(update_op.as_ref()).unwrap();
        assert_eq!(key, from.to_key());
        assert_eq!(value, from.to_value().unwrap());
        assert_eq!(update_op, from);

        let vec = update_op.to_vec();

        let from = Operation::<U64, U64>::try_from(&vec).unwrap();
        assert_eq!(key, from.to_key());
        assert_eq!(value, from.to_value().unwrap());
        assert_eq!(update_op, from);

        let from = Operation::<U64, U64>::try_from(vec).unwrap();
        assert_eq!(key, from.to_key());
        assert_eq!(value, from.to_value().unwrap());
        assert_eq!(update_op, from);

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::delete(key2.clone());
        let from = Operation::<U64, U64>::try_from(delete_op.as_ref()).unwrap();
        assert_eq!(key2, from.to_key());
        assert_eq!(None, from.to_value());
        assert_eq!(delete_op, from);

        let commit_op = Operation::<U64, U64>::new(Type::Commit(42));
        let from = Operation::<U64, U64>::try_from(commit_op.as_ref()).unwrap();
        assert_eq!(None, from.to_value());
        assert!(matches!(from.to_type(), Type::Commit(42)));
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.to_vec();
        invalid[U64::SIZE + 4] = 0xFF;
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidDeleteOp));

        // test invalid context byte detection
        let mut invalid = delete_op.to_vec();
        invalid[0] = 0xFF;
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidContextByte));

        // test invalid length detection
        let mut invalid = update_op.to_vec();
        invalid.pop();
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidLength));
    }

    #[test]
    fn test_operation_array_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Operation::update(key.clone(), value.clone());
        assert_eq!(
            format!("{}", update_op),
            format!("[key:{} value:{}]", key, value)
        );

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::delete(key2.clone());
        assert_eq!(
            format!("{}", delete_op),
            format!("[key:{} <deleted>]", key2)
        );
    }

    #[test]
    fn test_operation_array_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let update_op = Operation::update(key, value);

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), Operation::<U64, U64>::SIZE);
        assert_eq!(encoded, update_op.as_ref());

        let decoded = Operation::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);
    }
}
