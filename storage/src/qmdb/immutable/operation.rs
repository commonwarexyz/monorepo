//! Operations for immutable authenticated databases.
//!
//! This module provides the [Operation] type for databases that only support
//! adding new keyed values (no updates or deletions).

use crate::{
    mmr::Location,
    qmdb::{any::VariableValue, operation::Operation as OperationTrait},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_utils::{hex, Array};
use core::fmt::Display;

// Context byte prefixes for identifying the operation type.
const SET_CONTEXT: u8 = 0;
const COMMIT_CONTEXT: u8 = 1;

/// An operation applied to an immutable authenticated database.
///
/// Unlike mutable database operations, immutable operations only support
/// setting new values and committing - no updates or deletions.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: VariableValue> {
    /// Set a key to a value. The key must not already exist.
    Set(K, V),

    /// Commit with optional metadata.
    Commit(Option<V>),
}

impl<K: Array, V: VariableValue> Operation<K, V> {
    /// If this is an operation involving a key, returns the key. Otherwise, returns None.
    pub const fn key(&self) -> Option<&K> {
        match self {
            Self::Set(key, _) => Some(key),
            Self::Commit(_) => None,
        }
    }

    /// Returns true if this is a commit operation.
    pub const fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }
}

impl<K: Array, V: VariableValue> EncodeSize for Operation<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Set(_, v) => K::SIZE + v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

impl<K: Array, V: VariableValue> OperationTrait for Operation<K, V> {
    type Key = K;

    fn key(&self) -> Option<&Self::Key> {
        self.key()
    }

    fn is_delete(&self) -> bool {
        // Immutable databases don't support deletion
        false
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Set(_, _))
    }

    fn has_floor(&self) -> Option<Location> {
        // Immutable databases don't have inactivity floors
        None
    }
}

impl<K: Array, V: VariableValue> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Set(k, v) => {
                SET_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Self::Commit(v) => {
                COMMIT_CONTEXT.write(buf);
                v.write(buf);
            }
        }
    }
}

impl<K: Array, V: VariableValue> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            SET_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Set(key, value))
            }
            COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: VariableValue> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Self::Commit(value) => {
                if let Some(value) = value {
                    write!(f, "[commit {}]", hex(&value.encode()))
                } else {
                    write!(f, "[commit]")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, EncodeSize, FixedSize as _};
    use commonware_utils::sequence::U64;

    #[test]
    fn test_operation_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&key, set_op.key().unwrap());

        let commit_op = Operation::<U64, U64>::Commit(Some(value));
        assert_eq!(None, commit_op.key());

        let commit_op_none = Operation::<U64, U64>::Commit(None);
        assert_eq!(None, commit_op_none.key());
    }

    #[test]
    fn test_operation_is_commit() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key, value.clone());
        assert!(!set_op.is_commit());

        let commit_op = Operation::<U64, U64>::Commit(Some(value));
        assert!(commit_op.is_commit());

        let commit_op_none = Operation::<U64, U64>::Commit(None);
        assert!(commit_op_none.is_commit());
    }

    #[test]
    fn test_operation_encode_decode() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key, value.clone());
        let encoded = set_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(set_op, decoded);

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value));
        let encoded = commit_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        let encoded = commit_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);
    }

    #[test]
    fn test_operation_encode_size() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key, value.clone());
        assert_eq!(set_op.encode_size(), 1 + U64::SIZE + value.encode_size());
        assert_eq!(set_op.encode().len(), set_op.encode_size());

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(commit_op.encode_size(), 1 + Some(value).encode_size());
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        assert_eq!(
            commit_op.encode_size(),
            1 + Option::<U64>::None.encode_size()
        );
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(
            format!("{set_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(
            format!("{commit_op}"),
            format!("[commit {}]", hex(&value.encode()))
        );

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        assert_eq!(format!("{commit_op}"), "[commit]");
    }

    #[test]
    fn test_operation_invalid_context() {
        let invalid = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn test_operation_insufficient_buffer() {
        // Test insufficient buffer for Set operation
        let invalid = vec![SET_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for Commit operation
        let invalid = vec![COMMIT_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_roundtrip_all_variants() {
        let key = U64::new(100);
        let value = U64::new(1000);

        // Test all operation variants
        let operations: Vec<Operation<U64, U64>> = vec![
            Operation::Set(key, value.clone()),
            Operation::Commit(Some(value)),
            Operation::Commit(None),
        ];

        for op in operations {
            let encoded = op.encode();
            let decoded = Operation::<U64, U64>::decode(encoded.clone()).unwrap();
            assert_eq!(op, decoded, "Failed to roundtrip: {op:?}");
            assert_eq!(encoded.len(), op.encode_size(), "Size mismatch for: {op:?}");
        }
    }
}
