//! Operations that can be applied to an authenticated database.
//!
//! The `Operation` enum implements the `Array` trait, allowing for a persistent log of operations
//! based on a `crate::Journal`.

use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
};
use thiserror::Error;

/// Errors returned by [Operation] functions.
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

/// An operation applied to an authenticated database.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: Array> {
    /// Indicates the key no longer has a value.
    Deleted(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    Commit(u64),
}

impl<K: Array, V: Array> FixedSize for Operation<K, V> {
    const SIZE: usize = u8::SIZE + K::SIZE + V::SIZE;
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

    /// If this is a [Operation::Update] or [Operation::Deleted] operation, returns the key.
    /// Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Operation::Deleted(key) => Some(key),
            Operation::Update(key, _) => Some(key),
            Operation::Commit(_) => None,
        }
    }

    ///If this is a [Operation::Update] operation, returns the value.
    /// Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Operation::Deleted(_) => None,
            Operation::Update(_, value) => Some(value),
            Operation::Commit(_) => None,
        }
    }
}

impl<K: Array, V: Array> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Operation::Deleted(k) => {
                buf.put_u8(Self::DELETE_CONTEXT);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, V::SIZE);
            }
            Operation::Update(k, v) => {
                buf.put_u8(Self::UPDATE_CONTEXT);
                k.write(buf);
                v.write(buf);
            }
            Operation::Commit(loc) => {
                buf.put_u8(Self::COMMIT_CONTEXT);
                buf.put_slice(&loc.to_be_bytes());
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - 1 - u64::SIZE);
            }
        }
    }
}

impl<K: Array, V: Array> Read for Operation<K, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            Self::UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read(buf)?;
                Ok(Self::Update(key, value))
            }
            Self::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                // Check that the value is all zeroes
                for _ in 0..V::SIZE {
                    if buf.get_u8() != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::Operation",
                            "delete value non-zero",
                        ));
                    }
                }
                Ok(Self::Deleted(key))
            }
            Self::COMMIT_CONTEXT => {
                let loc = u64::read(buf)?;
                for _ in 0..(Self::SIZE - 1 - u64::SIZE) {
                    if buf.get_u8() != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::Operation",
                            "commit value non-zero",
                        ));
                    }
                }
                Ok(Self::Commit(loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Array> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Deleted(key) => write!(f, "[key:{key} <deleted>]"),
            Operation::Update(key, value) => write!(f, "[key:{key} value:{value}]"),
            Operation::Commit(loc) => write!(f, "[commit with inactivity floor: {loc}]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::array::U64;

    #[test]
    fn test_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.to_key().unwrap());

        let delete_op = Operation::<U64, U64>::Deleted(key.clone());
        assert_eq!(&key, delete_op.to_key().unwrap());

        let commit_op = Operation::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_key());
    }

    #[test]
    fn test_to_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(&value, update_op.to_value().unwrap());

        let delete_op = Operation::<U64, U64>::Deleted(key.clone());
        assert_eq!(None, delete_op.to_value());

        let commit_op = Operation::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_value());
    }

    #[test]
    fn test_operation_array_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.to_key().unwrap());
        assert_eq!(&value, update_op.to_value().unwrap());

        let from = Operation::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.to_key().unwrap());
        assert_eq!(&value, from.to_value().unwrap());
        assert_eq!(update_op, from);

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::Deleted(key2.clone());
        let from = Operation::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.to_key().unwrap());
        assert_eq!(None, from.to_value());
        assert_eq!(delete_op, from);

        let commit_op = Operation::<U64, U64>::Commit(42);
        let from = Operation::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.to_value());
        assert!(matches!(from, Operation::Commit(42)));
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_array_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(format!("{update_op}"), format!("[key:{key} value:{value}]"));

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::Deleted(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));
    }

    #[test]
    fn test_operation_array_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let update_op = Operation::Update(key, value);

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), Operation::<U64, U64>::SIZE);

        let decoded = Operation::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);
    }
}
