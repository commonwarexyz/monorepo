use crate::{adb::operation, mmr::Location};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Codec, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;

/// An operation applied to an authenticated database with a variable size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: Codec> {
    // Operations for immutable stores.
    Set(K, V),
    Commit(Option<V>),
    // Operations for mutable stores.
    Delete(K),
    Update(K, V),
    CommitFloor(Option<V>, Location),
}

impl<K: Array, V: Codec> Operation<K, V> {
    /// If this is an operation involving a key, returns the key. Otherwise, returns None.
    pub fn key(&self) -> Option<&K> {
        match self {
            Self::Set(key, _) => Some(key),
            Self::Commit(_) => None,
            Self::Delete(key) => Some(key),
            Self::Update(key, _) => Some(key),
            Self::CommitFloor(_, _) => None,
        }
    }

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    pub fn value(&self) -> Option<&V> {
        match self {
            Self::Set(_, value) => Some(value),
            Self::Commit(value) => value.as_ref(),
            Self::Delete(_) => None,
            Self::Update(_, value) => Some(value),
            Self::CommitFloor(value, _) => value.as_ref(),
        }
    }

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    pub fn into_value(self) -> Option<V> {
        match self {
            Self::Set(_, value) => Some(value),
            Self::Commit(value) => value,
            Self::Delete(_) => None,
            Self::Update(_, value) => Some(value),
            Self::CommitFloor(value, _) => value,
        }
    }
}

impl<K: Array, V: Codec> EncodeSize for Operation<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(_, v) => K::SIZE + v.encode_size(),
            Self::CommitFloor(v, floor_loc) => v.encode_size() + UInt(**floor_loc).encode_size(),
            Self::Set(_, v) => K::SIZE + v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

impl<K: Array, V: Codec> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Set(k, v) => {
                operation::SET_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Self::Commit(v) => {
                operation::COMMIT_CONTEXT.write(buf);
                v.write(buf);
            }
            Self::Delete(k) => {
                operation::DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(k, v) => {
                operation::UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Self::CommitFloor(v, floor_loc) => {
                operation::COMMIT_FLOOR_CONTEXT.write(buf);
                v.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<K: Array, V: Codec> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            operation::SET_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Set(key, value))
            }
            operation::COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            operation::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            operation::UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Update(key, value))
            }
            operation::COMMIT_FLOOR_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::adb::operation::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Codec> Display for Operation<K, V> {
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
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
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
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&key, set_op.key().unwrap());

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = Operation::<U64, U64>::Commit(Some(value));
        assert_eq!(None, commit_op.key());

        let commit_floor_op = Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op.key());
    }

    #[test]
    fn test_operation_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&value, set_op.value().unwrap());

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(&value, update_op.value().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.value());

        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(&value, commit_op.value().unwrap());

        let commit_op_none = Operation::<U64, U64>::Commit(None);
        assert_eq!(None, commit_op_none.value());

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
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(value.clone(), set_op.into_value().unwrap());

        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(value.clone(), update_op.into_value().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.into_value());

        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(value.clone(), commit_op.into_value().unwrap());

        let commit_op_none = Operation::<U64, U64>::Commit(None);
        assert_eq!(None, commit_op_none.into_value());

        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(value, commit_floor_op.into_value().unwrap());

        let commit_floor_op_none =
            Operation::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_floor_op_none.into_value());
    }

    #[test]
    fn test_operation_encode_decode() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key.clone(), value.clone());
        let encoded = set_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(set_op, decoded);

        // Test Update operation
        let update_op = Operation::Update(key.clone(), value.clone());
        let encoded = update_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        let encoded = delete_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(delete_op, decoded);

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        let encoded = commit_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        let encoded = commit_op.encode();
        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);

        // Test CommitFloor operation with value
        let commit_floor_op =
            Operation::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
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
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(set_op.encode_size(), 1 + U64::SIZE + value.encode_size());
        assert_eq!(set_op.encode().len(), set_op.encode_size());

        // Test Update operation
        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(update_op.encode_size(), 1 + U64::SIZE + value.encode_size());
        assert_eq!(update_op.encode().len(), update_op.encode_size());

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(delete_op.encode_size(), 1 + U64::SIZE);
        assert_eq!(delete_op.encode().len(), delete_op.encode_size());

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(
            commit_op.encode_size(),
            1 + Some(value.clone()).encode_size()
        );
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        assert_eq!(
            commit_op.encode_size(),
            1 + Option::<U64>::None.encode_size()
        );
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());

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
        let value = U64::new(56789);

        // Test Set operation
        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(
            format!("{set_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        // Test Update operation
        let update_op = Operation::Update(key.clone(), value.clone());
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        // Test Delete operation
        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key} <deleted>]"));

        // Test Commit operation with value
        let commit_op = Operation::<U64, U64>::Commit(Some(value.clone()));
        assert_eq!(
            format!("{commit_op}"),
            format!("[commit {}]", hex(&value.encode()))
        );

        // Test Commit operation without value
        let commit_op = Operation::<U64, U64>::Commit(None);
        assert_eq!(format!("{commit_op}"), "[commit]");

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
        // Test insufficient buffer for Set operation
        let invalid = vec![operation::SET_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for Delete operation
        let invalid = vec![operation::DELETE_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for Update operation
        let invalid = vec![operation::UPDATE_CONTEXT];
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        // Test insufficient buffer for Commit operation
        let invalid = vec![operation::COMMIT_CONTEXT];
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
        let location = Location::new_unchecked(999);

        // Test all operation variants
        let operations: Vec<Operation<U64, U64>> = vec![
            Operation::Set(key1.clone(), value1.clone()),
            Operation::Update(key2.clone(), value2.clone()),
            Operation::Delete(key1.clone()),
            Operation::Commit(Some(value1.clone())),
            Operation::Commit(None),
            Operation::CommitFloor(Some(value2.clone()), location),
            Operation::CommitFloor(None, location),
        ];

        for op in operations {
            let encoded = op.encode();
            let decoded = Operation::<U64, U64>::decode(encoded.clone()).unwrap();
            assert_eq!(op, decoded, "Failed to roundtrip: {op:?}");
            assert_eq!(encoded.len(), op.encode_size(), "Size mismatch for: {op:?}");
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct VariableSizeValue(Vec<u8>);

    impl Write for VariableSizeValue {
        fn write(&self, buf: &mut impl BufMut) {
            UInt(self.0.len() as u64).write(buf);
            buf.put_slice(&self.0);
        }
    }

    impl EncodeSize for VariableSizeValue {
        fn encode_size(&self) -> usize {
            UInt(self.0.len() as u64).encode_size() + self.0.len()
        }
    }

    impl Read for VariableSizeValue {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let len = UInt::read(buf)?;
            let len: u64 = len.into();
            let len = usize::try_from(len)
                .map_err(|_| CodecError::Invalid("VariableSizeValue", "length overflow"))?;
            if buf.remaining() < len {
                return Err(CodecError::EndOfBuffer);
            }
            let mut data = vec![0u8; len];
            buf.copy_to_slice(&mut data);
            Ok(VariableSizeValue(data))
        }
    }

    #[test]
    fn test_operation_variable_size_values() {
        let key = U64::new(42);

        // Test with different sized values
        let small_value = VariableSizeValue(vec![1, 2, 3]);
        let large_value = VariableSizeValue(vec![0xFF; 1000]);
        let empty_value = VariableSizeValue(vec![]);

        // Test Set with variable sizes
        let set_small = Operation::Set(key.clone(), small_value.clone());
        let encoded = set_small.encode();
        let decoded = Operation::<U64, VariableSizeValue>::decode(encoded).unwrap();
        assert_eq!(set_small, decoded);

        let set_large = Operation::Set(key.clone(), large_value.clone());
        let encoded = set_large.encode();
        let decoded = Operation::<U64, VariableSizeValue>::decode(encoded).unwrap();
        assert_eq!(set_large, decoded);

        let set_empty = Operation::Set(key.clone(), empty_value.clone());
        let encoded = set_empty.encode();
        let decoded = Operation::<U64, VariableSizeValue>::decode(encoded).unwrap();
        assert_eq!(set_empty, decoded);

        // Test Commit with variable sizes
        let commit = Operation::<U64, VariableSizeValue>::Commit(Some(large_value.clone()));
        let encoded = commit.encode();
        let decoded = Operation::<U64, VariableSizeValue>::decode(encoded).unwrap();
        assert_eq!(commit, decoded);

        // Test encode_size is accurate for variable sizes
        assert_eq!(set_small.encode().len(), set_small.encode_size());
        assert_eq!(set_large.encode().len(), set_large.encode_size());
        assert_eq!(set_empty.encode().len(), set_empty.encode_size());
    }
}
