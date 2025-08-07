//! Operations that can be applied to an authenticated database.
//!
//! The `Operation` enum implements the `Array` trait, allowing for a persistent log of operations
//! based on a `crate::Journal`.

use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, Codec, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
};
use thiserror::Error;

/// Errors returned by operation functions.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid key: {0}")]
    InvalidKey(CodecError),
    #[error("invalid value: {0}")]
    InvalidValue(CodecError),
    #[error("invalid context byte")]
    InvalidContextByte,
    #[error("delete operation has non-zero value")]
    InvalidDeleteOp,
    #[error("commit operation has non-zero bytes after location")]
    InvalidCommitOp,
}

/// An operation applied to an authenticated database with a fixed size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Fixed<K: Array, V: Array> {
    /// Indicates the key no longer has a value.
    Deleted(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    Commit(u64),
}

/// An operation applied to an authenticated database with a variable size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Variable<K: Array, V: Codec> {
    Set(K, V),
    Commit(),
}

impl<K: Array, V: Array> FixedSize for Fixed<K, V> {
    const SIZE: usize = u8::SIZE + K::SIZE + V::SIZE;
}

impl<K: Array, V: Codec> EncodeSize for Variable<K, V> {
    fn encode_size(&self) -> usize {
        match self {
            // 1 byte for the context + fixed key size + value’s own size
            Variable::Set(_, v) => 1 + K::SIZE + v.encode_size(),
            // Only the context byte
            Variable::Commit() => 1,
        }
    }
}

const DELETE_CONTEXT: u8 = 0;
const UPDATE_CONTEXT: u8 = 1;
const COMMIT_CONTEXT: u8 = 2;
const SET_CONTEXT: u8 = 3;

impl<K: Array, V: Array> Fixed<K, V> {
    // A compile-time assertion that operation's array size is large enough to handle the commit
    // operation, which requires 9 bytes.
    const _MIN_OPERATION_LEN: usize = 9;
    const _COMMIT_OP_ASSERT: () = assert!(
        Self::SIZE >= Self::_MIN_OPERATION_LEN,
        "array size too small for commit op"
    );

    /// If this is a [Fixed::Update] or [Fixed::Deleted] operation, returns the key.
    /// Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Fixed::Deleted(key) => Some(key),
            Fixed::Update(key, _) => Some(key),
            Fixed::Commit(_) => None,
        }
    }

    ///If this is a [Fixed::Update] operation, returns the value.
    /// Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Fixed::Deleted(_) => None,
            Fixed::Update(_, value) => Some(value),
            Fixed::Commit(_) => None,
        }
    }
}

impl<K: Array, V: Codec> Variable<K, V> {
    /// If this is a [Variable::Set] operation, returns the key. Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Variable::Set(key, _) => Some(key),
            Variable::Commit() => None,
        }
    }

    /// If this is a [Variable::Set] operation, returns the value. Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Variable::Set(_, value) => Some(value),
            Variable::Commit() => None,
        }
    }
}

impl<K: Array, V: Array> Write for Fixed<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Fixed::Deleted(k) => {
                buf.put_u8(DELETE_CONTEXT);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, V::SIZE);
            }
            Fixed::Update(k, v) => {
                buf.put_u8(UPDATE_CONTEXT);
                k.write(buf);
                v.write(buf);
            }
            Fixed::Commit(floor_loc) => {
                buf.put_u8(COMMIT_CONTEXT);
                buf.put_slice(&floor_loc.to_be_bytes());
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - 1 - u64::SIZE);
            }
        }
    }
}

impl<K: Array, V: Codec> Write for Variable<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Variable::Set(k, v) => {
                buf.put_u8(SET_CONTEXT);
                k.write(buf);
                v.write(buf);
            }
            Variable::Commit() => {
                buf.put_u8(COMMIT_CONTEXT);
            }
        }
    }
}

impl<K: Array, V: Array> Read for Fixed<K, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read(buf)?;
                Ok(Self::Update(key, value))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                // Check that the value is all zeroes
                for _ in 0..V::SIZE {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::Operation",
                            "delete value non-zero",
                        ));
                    }
                }
                Ok(Self::Deleted(key))
            }
            COMMIT_CONTEXT => {
                let floor_loc = u64::read(buf)?;
                for _ in 0..(Self::SIZE - 1 - u64::SIZE) {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::Operation",
                            "commit value non-zero",
                        ));
                    }
                }
                Ok(Self::Commit(floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Codec> Read for Variable<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            SET_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Set(key, value))
            }
            COMMIT_CONTEXT => Ok(Self::Commit()),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Array> Display for Fixed<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fixed::Deleted(key) => write!(f, "[key:{key} <deleted>]"),
            Fixed::Update(key, value) => write!(f, "[key:{key} value:{value}]"),
            Fixed::Commit(loc) => write!(f, "[commit with inactivity floor: {loc}]"),
        }
    }
}

impl<K: Array, V: Array> Display for Variable<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Variable::Set(key, value) => write!(f, "[key:{key} value:{value}]"),
            Variable::Commit() => write!(f, "[commit]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::sequence::U64;

    #[test]
    fn test_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Fixed::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.to_key().unwrap());

        let delete_op = Fixed::<U64, U64>::Deleted(key.clone());
        assert_eq!(&key, delete_op.to_key().unwrap());

        let commit_op = Fixed::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_key());
    }

    #[test]
    fn test_to_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Fixed::Update(key.clone(), value.clone());
        assert_eq!(&value, update_op.to_value().unwrap());

        let delete_op = Fixed::<U64, U64>::Deleted(key.clone());
        assert_eq!(None, delete_op.to_value());

        let commit_op = Fixed::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_value());
    }

    #[test]
    fn test_operation_array_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Fixed::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.to_key().unwrap());
        assert_eq!(&value, update_op.to_value().unwrap());

        let from = Fixed::<U64, U64>::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.to_key().unwrap());
        assert_eq!(&value, from.to_value().unwrap());
        assert_eq!(update_op, from);

        let key2 = U64::new(42);
        let delete_op = Fixed::<U64, U64>::Deleted(key2.clone());
        let from = Fixed::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.to_key().unwrap());
        assert_eq!(None, from.to_value());
        assert_eq!(delete_op, from);

        let commit_op = Fixed::<U64, U64>::Commit(42);
        let from = Fixed::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.to_value());
        assert!(matches!(from, Fixed::Commit(42)));
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = Fixed::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = Fixed::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = Fixed::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_array_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Fixed::Update(key.clone(), value.clone());
        assert_eq!(format!("{update_op}"), format!("[key:{key} value:{value}]"));

        let key2 = U64::new(42);
        let delete_op = Fixed::<U64, U64>::Deleted(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));
    }

    #[test]
    fn test_operation_array_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let update_op = Fixed::Update(key, value);

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), Fixed::<U64, U64>::SIZE);

        let decoded = Fixed::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);
    }
}
