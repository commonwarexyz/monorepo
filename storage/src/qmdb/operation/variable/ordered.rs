use crate::{
    mmr::Location,
    qmdb::operation::{self, variable::Value, Committable, KeyData, Keyed, Ordered},
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_utils::{hex, Array};
use core::fmt::Display;

/// An operation applied to an authenticated database with a variable sized value that supports
/// exclusion proofs over ordered keys.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: Value> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key within the wrapped structure has the associated value and next-key.
    Update(KeyData<K, V>),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(Option<V>, Location),
}

impl<K: Array, V: Value> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                operation::DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(data) => {
                operation::UPDATE_CONTEXT.write(buf);
                data.key.write(buf);
                data.value.write(buf);
                data.next_key.write(buf);
            }
            Self::CommitFloor(value, floor_loc) => {
                operation::COMMIT_FLOOR_CONTEXT.write(buf);
                value.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<K: Array, V: Value> EncodeSize for Operation<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(data) => K::SIZE + data.value.encode_size() + K::SIZE,
            Self::CommitFloor(v, floor_loc) => v.encode_size() + UInt(**floor_loc).encode_size(),
        }
    }
}

impl<K: Array, V: Value> Keyed for Operation<K, V> {
    type Key = K;
    type Value = V;

    fn key(&self) -> Option<&Self::Key> {
        match self {
            Self::Delete(key) => Some(key),
            Self::Update(data) => Some(&data.key),
            Self::CommitFloor(_, _) => None,
        }
    }

    fn has_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(_, loc) => Some(*loc),
            _ => None,
        }
    }

    fn is_delete(&self) -> bool {
        matches!(self, Self::Delete(_))
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Update(_))
    }

    fn value(&self) -> Option<&Self::Value> {
        match self {
            Self::Delete(_) => None,
            Self::Update(data) => Some(&data.value),
            Self::CommitFloor(value, _) => value.as_ref(),
        }
    }

    fn into_value(self) -> Option<Self::Value> {
        match self {
            Self::Delete(_) => None,
            Self::Update(data) => Some(data.value),
            Self::CommitFloor(value, _) => value,
        }
    }
}

impl<K: Array, V: Value> Committable for Operation<K, V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

impl<K: Array, V: Value> Ordered for Operation<K, V> {
    fn key_data(&self) -> Option<&KeyData<K, V>> {
        match self {
            Self::Update(data) => Some(data),
            _ => None,
        }
    }

    fn into_key_data(self) -> Option<KeyData<K, V>> {
        match self {
            Self::Update(data) => Some(data),
            _ => None,
        }
    }
}

impl<K: Array, V: Value> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            operation::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            operation::UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                let next_key = K::read(buf)?;
                Ok(Self::Update(KeyData {
                    key,
                    value,
                    next_key,
                }))
            }
            operation::COMMIT_FLOOR_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::operation::variable::ordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Value> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(data) => {
                write!(
                    f,
                    "[key:{} next_key:{} value:{}]",
                    data.key,
                    data.next_key,
                    hex(&data.value.encode())
                )
            }
            Self::CommitFloor(value, loc) => {
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
    use commonware_codec::{DecodeExt, Encode, EncodeSize, FixedSize as _};
    use commonware_utils::sequence::U64;

    #[test]
    fn test_operation_key() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value,
            next_key,
        });
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op.key());
    }

    #[test]
    fn test_operation_value() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        assert_eq!(&value, update_op.value().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(None, delete_op.value());

        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(&value, commit_floor_op.value().unwrap());

        let commit_floor_op_none =
            Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op_none.value());
    }

    #[test]
    fn test_operation_into_value() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        assert_eq!(value, update_op.into_value().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(None, delete_op.into_value());

        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(value, commit_floor_op.into_value().unwrap());

        let commit_floor_op_none =
            Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op_none.into_value());
    }

    #[test]
    fn test_operation_key_data() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        let key_data = KeyData {
            key: key.clone(),
            value,
            next_key,
        };

        let update_op = Operation::Update(key_data.clone());
        assert_eq!(&key_data, update_op.key_data().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(None, delete_op.key_data());

        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op.key_data());
    }

    #[test]
    fn test_operation_into_key_data() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        let key_data = KeyData {
            key: key.clone(),
            value,
            next_key,
        };

        let update_op = Operation::Update(key_data.clone());
        assert_eq!(key_data, update_op.into_key_data().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(None, delete_op.into_key_data());

        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op.into_key_data());
    }

    #[test]
    fn test_operation_has_floor() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);
        let location = Location::new_unchecked(42);

        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        assert_eq!(None, update_op.has_floor());

        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(None, delete_op.has_floor());

        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, location);
        assert_eq!(Some(location), commit_floor_op.has_floor());

        let commit_floor_op_with_value = Operation::<U64, U64>::CommitFloor(Some(value), location);
        assert_eq!(Some(location), commit_floor_op_with_value.has_floor());
    }

    #[test]
    fn test_operation_encode_decode() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        // Test Update operation
        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        let encoded = update_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key);
        let encoded = delete_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(delete_op, decoded);

        // Test CommitFloor operation with value
        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value), Location::new_unchecked(42));
        let encoded = commit_floor_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_floor_op, decoded);

        // Test CommitFloor operation without value
        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        let encoded = commit_floor_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_floor_op, decoded);
    }

    #[test]
    fn test_operation_encode_size() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        // Test Update operation
        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: next_key.clone(),
        });
        assert_eq!(
            update_op.encode_size(),
            1 + U64::SIZE + value.encode_size() + next_key.encode_size()
        );
        assert_eq!(update_op.encode().len(), update_op.encode_size());

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key);
        assert_eq!(delete_op.encode_size(), 1 + U64::SIZE);
        assert_eq!(delete_op.encode().len(), delete_op.encode_size());

        // Test CommitFloor operation
        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(
            commit_floor_op.encode_size(),
            1 + Some(value).encode_size() + UInt(42u64).encode_size()
        );
        assert_eq!(
            commit_floor_op.encode().len(),
            commit_floor_op.encode_size()
        );
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let next_key = U64::new(90);

        // Test Update operation
        let update_op = Operation::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: next_key.clone(),
        });
        assert_eq!(
            format!("{update_op}"),
            format!(
                "[key:{key} next_key:{next_key} value:{}]",
                hex(&value.encode()),
            )
        );

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key} <deleted>]"));

        // Test CommitFloor operation with value
        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_floor_op}"),
            format!(
                "[commit {} with inactivity floor: {}]",
                hex(&value.encode()),
                Location::new_unchecked(42)
            )
        );

        // Test CommitFloor operation without value
        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_floor_op}"),
            format!(
                "[commit with inactivity floor: {}]",
                Location::new_unchecked(42)
            )
        );
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
    fn test_operation_commit_floor_location_overflow() {
        use crate::mmr::MAX_LOCATION;

        // Create a commit floor operation with a valid location value
        let valid_loc = MAX_LOCATION / 2;
        let mut encoded = vec![operation::COMMIT_FLOOR_CONTEXT];
        // Add empty metadata
        encoded.push(0); // None for Option<V>
                         // Add valid location as varint
        encoded.extend_from_slice(&UInt(valid_loc).encode());

        let decoded = Operation::<U64, U64>::decode(encoded.as_ref());
        assert!(decoded.is_ok());
        if let Ok(Operation::CommitFloor(None, loc)) = decoded {
            assert_eq!(*loc, valid_loc);
        } else {
            panic!("Expected CommitFloor operation with valid location");
        }

        // Test with MAX_LOCATION - should be valid
        let mut encoded = vec![operation::COMMIT_FLOOR_CONTEXT];
        encoded.push(0); // None for Option<V>
        encoded.extend_from_slice(&UInt(MAX_LOCATION).encode());

        let decoded = Operation::<U64, U64>::decode(encoded.as_ref());
        assert!(decoded.is_ok());

        // Test with MAX_LOCATION + 1 - should fail
        let mut encoded = vec![operation::COMMIT_FLOOR_CONTEXT];
        encoded.push(0); // None for Option<V>
        encoded.extend_from_slice(&UInt(MAX_LOCATION + 1).encode());

        let decoded = Operation::<U64, U64>::decode(encoded.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::Invalid(_, "commit floor location overflow")
        ));
    }

    #[test]
    fn test_operation_insufficient_buffer() {
        // Test insufficient buffer for Delete operation
        let invalid = vec![operation::DELETE_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for Update operation
        let invalid = vec![operation::UPDATE_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for CommitFloor operation
        let invalid = vec![operation::COMMIT_FLOOR_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_roundtrip_all_variants() {
        let key1 = U64::new(100);
        let key2 = U64::new(200);
        let value1 = U64::new(1000);
        let value2 = U64::new(2000);
        let next_key2 = U64::new(201);
        let location = Location::new_unchecked(999);

        // Test all operation variants
        let operations: Vec<Operation<U64, U64>> = vec![
            Operation::Update(KeyData {
                key: key2,
                value: value2,
                next_key: next_key2,
            }),
            Operation::Delete(key1),
            Operation::CommitFloor(Some(value1), location),
            Operation::CommitFloor(None, location),
        ];

        for op in operations {
            let encoded = op.encode();
            let decoded = Operation::<U64, U64>::decode(encoded.clone()).unwrap();
            assert_eq!(op, decoded, "Failed to roundtrip: {op:?}");
            assert_eq!(encoded.len(), op.encode_size(), "Size mismatch for: {op:?}");
        }
    }
}
