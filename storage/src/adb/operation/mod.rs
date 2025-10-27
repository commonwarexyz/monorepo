//! Operations that can be applied to a database to modify its state.
//!
//! The various operation types implement the [commonware_codec::Codec] trait, allowing for a
//! persistent log of operations based on a `crate::Journal`. The _fixed_ variants additionally
//! implement [commonware_codec::CodecFixed].

use commonware_codec::Error as CodecError;
use std::fmt::Debug;
use thiserror::Error;

pub mod fixed;
pub mod keyless;
pub mod variable;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::{
            fixed::{
                ordered::{KeyData as OrderedKeyData, Operation as FixedOrdered},
                unordered::Operation as FixedUnordered,
                FixedOperation as _,
            },
            keyless::Operation as Keyless,
        },
        mmr::Location,
    };
    use commonware_codec::{DecodeExt, Encode, EncodeSize as _, FixedSize as _};
    use commonware_utils::{hex, sequence::U64};

    #[test]
    fn test_operation_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = FixedUnordered::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.key());

        let update_op = FixedOrdered::Update(OrderedKeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.key());
    }

    #[test]
    fn test_operation_to_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(&value, update_op.value().unwrap());

        let delete_op = FixedUnordered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.value());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.value());

        let update_op = FixedOrdered::Update(OrderedKeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(&value, update_op.value().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.value());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.value());
    }

    #[test]
    fn test_operation_into_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(value, update_op.into_value().unwrap());

        let delete_op = FixedUnordered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.into_value());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.into_value());

        let update_op = FixedOrdered::Update(OrderedKeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(value, update_op.into_value().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.into_value());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        assert_eq!(None, commit_op.into_value());
    }

    #[test]
    fn test_operation_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.key().unwrap());
        assert_eq!(&value, update_op.value().unwrap());

        let from = FixedUnordered::<U64, U64>::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.key().unwrap());
        assert_eq!(&value, from.value().unwrap());
        assert_eq!(update_op, from);

        let key2 = U64::new(42);
        let delete_op = FixedUnordered::<U64, U64>::Delete(key2.clone());
        let from = FixedUnordered::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(None, from.value());
        assert_eq!(delete_op, from);

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        let from = FixedUnordered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.value());
        assert!(
            matches!(from, FixedUnordered::CommitFloor(loc) if loc == Location::new_unchecked(42))
        );
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = FixedUnordered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = FixedUnordered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = FixedUnordered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        let key2 = U64::new(42);
        let delete_op = FixedUnordered::<U64, U64>::Delete(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));

        let key = U64::new(1234);
        let value = U64::new(5678);
        let key2 = U64::new(999);
        let update_op = FixedOrdered::Update(OrderedKeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key2.clone(),
        });
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} next_key:{key2} value:{}]", hex(&value.encode()))
        );
    }

    #[test]
    fn test_operation_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let update_op = FixedUnordered::Update(key, value);

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), FixedUnordered::<U64, U64>::SIZE);

        let decoded = FixedUnordered::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);

        let key = U64::new(1234);
        let value = U64::new(5678);
        let key2 = U64::new(999);
        let update_op = FixedOrdered::Update(OrderedKeyData {
            key,
            value,
            next_key: key2,
        });

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), FixedOrdered::<U64, U64>::SIZE);

        let decoded = FixedOrdered::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);
    }

    #[test]
    fn test_operation_keyless_append() {
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
    fn test_operation_keyless_commit() {
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
    fn test_operation_keyless_invalid_context() {
        let invalid = vec![0xFF; 1];
        let decoded = Keyless::<U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn test_operation_ordered_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedOrdered::Update(OrderedKeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(&key, update_op.key().unwrap());
        assert_eq!(&value, update_op.value().unwrap());

        let from = FixedOrdered::<U64, U64>::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.key().unwrap());
        assert_eq!(&value, from.value().unwrap());
        assert_eq!(update_op, from);

        let key2 = U64::new(42);
        let delete_op = FixedOrdered::<U64, U64>::Delete(key2.clone());
        let from = FixedOrdered::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(None, from.value());
        assert_eq!(delete_op, from);

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(Location::new_unchecked(42));
        let from = FixedOrdered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.value());
        assert!(
            matches!(from, FixedOrdered::CommitFloor(loc) if loc == Location::new_unchecked(42))
        );
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = FixedOrdered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = FixedOrdered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = FixedOrdered::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }
}
