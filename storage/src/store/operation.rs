//! Operations that can be applied to an authenticated database.
//!
//! The `Operation` enum implements the `Array` trait, allowing for a persistent log of operations
//! based on a `crate::Journal`.

use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, varint::UInt, Codec, CodecFixed, EncodeSize, Error as CodecError, FixedSize,
    Read, ReadExt, Write,
};
use commonware_utils::{hex, Array};
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
};
use thiserror::Error;

// Context byte prefixes for identifying the operation type.
const DELETE_CONTEXT: u8 = 0;
const UPDATE_CONTEXT: u8 = 1;
const COMMIT_FLOOR_CONTEXT: u8 = 2;
const SET_CONTEXT: u8 = 3;
const COMMIT_CONTEXT: u8 = 4;
const APPEND_CONTEXT: u8 = 5;

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
    #[error("commit floor operation has non-zero bytes after location")]
    InvalidCommitFloorOp,
}

/// An operation applied to an authenticated database with a fixed size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Fixed<K: Array, V: CodecFixed> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(u64),
}

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Keyless<V: Codec> {
    /// Wraps the value appended to the database by this operation.
    Append(V),

    /// Indicates the database has been committed.
    Commit(Option<V>),
}

/// An operation applied to an authenticated database with a variable size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Variable<K: Array, V: Codec> {
    // Operations for immutable stores.
    Set(K, V),
    Commit(Option<V>),
    // Operations for mutable stores.
    Delete(K),
    Update(K, V),
    CommitFloor(Option<V>, u64),
}

impl<K: Array, V: CodecFixed> FixedSize for Fixed<K, V> {
    const SIZE: usize = u8::SIZE + K::SIZE + V::SIZE;
}

impl<K: Array, V: Codec> EncodeSize for Variable<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Variable::Delete(_) => K::SIZE,
            Variable::Update(_, v) => K::SIZE + v.encode_size(),
            Variable::CommitFloor(v, floor_loc) => v.encode_size() + UInt(*floor_loc).encode_size(),
            Variable::Set(_, v) => K::SIZE + v.encode_size(),
            Variable::Commit(v) => v.encode_size(),
        }
    }
}

impl<V: Codec> EncodeSize for Keyless<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Keyless::Append(v) => v.encode_size(),
            Keyless::Commit(v) => v.encode_size(),
        }
    }
}

impl<K: Array, V: CodecFixed> Fixed<K, V> {
    // A compile-time assertion that operation's array size is large enough to handle the commit
    // operation, which requires 9 bytes.
    const _MIN_OPERATION_LEN: usize = 9;
    const _COMMIT_OP_ASSERT: () = assert!(
        Self::SIZE >= Self::_MIN_OPERATION_LEN,
        "array size too small for commit op"
    );

    /// If this is a [Fixed::Update] or [Fixed::Delete] operation, returns the key.
    /// Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Fixed::Delete(key) => Some(key),
            Fixed::Update(key, _) => Some(key),
            Fixed::CommitFloor(_) => None,
        }
    }

    ///If this is a [Fixed::Update] operation, returns the value.
    /// Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Fixed::Delete(_) => None,
            Fixed::Update(_, value) => Some(value),
            Fixed::CommitFloor(_) => None,
        }
    }
}

impl<K: Array, V: Codec> Variable<K, V> {
    /// If this is an operation involving a key, returns the key. Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Variable::Set(key, _) => Some(key),
            Variable::Commit(_) => None,
            Variable::Delete(key) => Some(key),
            Variable::Update(key, _) => Some(key),
            Variable::CommitFloor(_, _) => None,
        }
    }

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Variable::Set(_, value) => Some(value),
            Variable::Commit(value) => value.as_ref(),
            Variable::Delete(_) => None,
            Variable::Update(_, value) => Some(value),
            Variable::CommitFloor(value, _) => value.as_ref(),
        }
    }
}

impl<V: Codec> Write for Keyless<V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Keyless::Append(value) => {
                APPEND_CONTEXT.write(buf);
                value.write(buf);
            }
            Keyless::Commit(metadata) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
            }
        }
    }
}

impl<K: Array, V: CodecFixed> Write for Fixed<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Fixed::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, V::SIZE);
            }
            Fixed::Update(k, v) => {
                UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Fixed::CommitFloor(floor_loc) => {
                COMMIT_FLOOR_CONTEXT.write(buf);
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
                SET_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Variable::Commit(v) => {
                COMMIT_CONTEXT.write(buf);
                v.write(buf);
            }
            Variable::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Variable::Update(k, v) => {
                UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Variable::CommitFloor(v, floor_loc) => {
                COMMIT_FLOOR_CONTEXT.write(buf);
                v.write(buf);
                UInt(*floor_loc).write(buf);
            }
        }
    }
}

impl<V: Codec> Read for Keyless<V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            APPEND_CONTEXT => Ok(Self::Append(V::read_cfg(buf, cfg)?)),
            COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: CodecFixed> Read for Fixed<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Update(key, value))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                // Check that the value is all zeroes
                for _ in 0..V::SIZE {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::Fixed",
                            "delete value non-zero",
                        ));
                    }
                }
                Ok(Self::Delete(key))
            }
            COMMIT_FLOOR_CONTEXT => {
                let floor_loc = u64::read(buf)?;
                for _ in 0..(Self::SIZE - 1 - u64::SIZE) {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::Fixed",
                            "commit value non-zero",
                        ));
                    }
                }
                Ok(Self::CommitFloor(floor_loc))
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
            COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Update(key, value))
            }
            COMMIT_FLOOR_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                Ok(Self::CommitFloor(metadata, floor_loc.into()))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: Codec> Display for Keyless<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keyless::Append(value) => write!(f, "[append value:{}]", hex(&value.encode())),
            Keyless::Commit(value) => {
                if let Some(value) = value {
                    write!(f, "[commit {}]", hex(&value.encode()))
                } else {
                    write!(f, "[commit]")
                }
            }
        }
    }
}

impl<K: Array, V: CodecFixed> Display for Fixed<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fixed::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Fixed::Update(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Fixed::CommitFloor(loc) => write!(f, "[commit with inactivity floor: {loc}]"),
        }
    }
}

impl<K: Array, V: Codec> Display for Variable<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Variable::Set(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Variable::Commit(value) => {
                if let Some(value) = value {
                    write!(f, "[commit {}]", hex(&value.encode()))
                } else {
                    write!(f, "[commit]")
                }
            }
            Variable::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Variable::Update(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Variable::CommitFloor(value, loc) => {
                if let Some(value) = value {
                    write!(
                        f,
                        "[commit {} with inactivity floor: {loc}]",
                        hex(&value.encode())
                    )
                } else {
                    write!(f, "[commit with inactivity floor: {loc}]")
                }
            }
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

        let delete_op = Fixed::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.to_key().unwrap());

        let commit_op = Fixed::<U64, U64>::CommitFloor(42);
        assert_eq!(None, commit_op.to_key());
    }

    #[test]
    fn test_to_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = Fixed::Update(key.clone(), value.clone());
        assert_eq!(&value, update_op.to_value().unwrap());

        let delete_op = Fixed::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.to_value());

        let commit_op = Fixed::<U64, U64>::CommitFloor(42);
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
        let delete_op = Fixed::<U64, U64>::Delete(key2.clone());
        let from = Fixed::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.to_key().unwrap());
        assert_eq!(None, from.to_value());
        assert_eq!(delete_op, from);

        let commit_op = Fixed::<U64, U64>::CommitFloor(42);
        let from = Fixed::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.to_value());
        assert!(matches!(from, Fixed::CommitFloor(42)));
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
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        let key2 = U64::new(42);
        let delete_op = Fixed::<U64, U64>::Delete(key2.clone());
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

    #[test]
    fn test_keyless_append() {
        let append_op = Keyless::Append(U64::new(12345));

        let encoded = append_op.encode();
        assert_eq!(encoded.len(), 1 + U64::SIZE);

        let decoded = Keyless::<U64>::decode(encoded).unwrap();
        assert_eq!(append_op, decoded);
        assert_eq!(
            format!("{append_op}"),
            format!("[append value:{}]", hex(&U64::new(12345).encode()))
        );
    }

    #[test]
    fn test_keyless_commit() {
        let metadata = Some(U64::new(12345));
        let commit_op = Keyless::<U64>::Commit(metadata.clone());

        let encoded = commit_op.encode();
        assert_eq!(encoded.len(), 1 + metadata.encode_size());

        let decoded = Keyless::<U64>::decode(encoded).unwrap();
        let Keyless::Commit(metadata_decoded) = decoded else {
            panic!("expected commit operation");
        };
        assert_eq!(metadata, metadata_decoded);
    }

    #[test]
    fn test_keyless_invalid_context() {
        let invalid = vec![0xFF; 1];
        let decoded = Keyless::<U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }
}
