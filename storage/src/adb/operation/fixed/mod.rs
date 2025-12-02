use bytes::Buf;
use commonware_codec::{Error as CodecError, ReadExt};

pub mod ordered;
pub mod unordered;

/// Ensures the next `size` bytes are all zeroes in the provided buffer, returning a [CodecError]
/// otherwise.
#[inline]
fn ensure_zeros(buf: &mut impl Buf, size: usize) -> Result<(), CodecError> {
    for _ in 0..size {
        if u8::read(buf)? != 0 {
            return Err(CodecError::Invalid(
                "storage::adb::operation",
                "non-zero bytes",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::{
            fixed::{ordered::Operation as FixedOrdered, unordered::Operation as FixedUnordered},
            KeyData, Keyed as _, Ordered as _,
        },
        mmr::Location,
    };
    use commonware_codec::{DecodeExt, Encode, FixedSize as _};
    use commonware_utils::{hex, sequence::U64};

    #[test]
    fn test_operation_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = FixedUnordered::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.key());

        let update_op = FixedOrdered::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
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

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.value());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(
            Some(value.clone()),
            Location::new_unchecked(42),
        );
        assert_eq!(Some(&value), commit_op.value());

        let update_op = FixedOrdered::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(&value, update_op.value().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.value());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.value());

        let commit_op =
            FixedOrdered::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(Some(&value), commit_op.value());
    }

    #[test]
    fn test_operation_into_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = FixedUnordered::Update(key.clone(), value.clone());
        assert_eq!(value, update_op.into_value().unwrap());

        let delete_op = FixedUnordered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.into_value());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.into_value());

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(
            Some(value.clone()),
            Location::new_unchecked(42),
        );
        assert_eq!(Some(value.clone()), commit_op.into_value());

        let update_op = FixedOrdered::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        });
        assert_eq!(value, update_op.into_value().unwrap());

        let delete_op = FixedOrdered::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.into_value());

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.into_value());

        let commit_op =
            FixedOrdered::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        assert_eq!(Some(value), commit_op.into_value());
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
        assert!(update_op.has_floor().is_none());

        let key2 = U64::new(42);
        let delete_op = FixedUnordered::<U64, U64>::Delete(key2.clone());
        let from = FixedUnordered::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(None, from.value());
        assert_eq!(delete_op, from);

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        let from = FixedUnordered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.value());
        assert!(
            matches!(from, FixedUnordered::CommitFloor(None, loc) if loc == Location::new_unchecked(42))
        );
        assert_eq!(commit_op, from);

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(
            Some(value.clone()),
            Location::new_unchecked(42),
        );
        let from = FixedUnordered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(Some(&value), from.value());
        assert!(
            matches!(&from, FixedUnordered::CommitFloor(Some(v), loc) if v == &value && *loc == Location::new_unchecked(42))
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

        let commit_op = FixedUnordered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op}"),
            "[commit with inactivity floor: Location(42)]"
        );

        let commit_op_with_metadata = FixedUnordered::<U64, U64>::CommitFloor(
            Some(U64::new(1234)),
            Location::new_unchecked(42),
        );
        assert_eq!(
            format!("{commit_op_with_metadata}"),
            "[commit 00000000000004d2 with inactivity floor: Location(42)]"
        );

        let key = U64::new(1234);
        let value = U64::new(5678);
        let key2 = U64::new(999);
        let update_op = FixedOrdered::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key2.clone(),
        });
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} next_key:{key2} value:{}]", hex(&value.encode()))
        );

        let key2 = U64::new(42);
        let delete_op = FixedOrdered::<U64, U64>::Delete(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op}"),
            "[commit with inactivity floor: Location(42)]"
        );

        let commit_op_with_metadata = FixedOrdered::<U64, U64>::CommitFloor(
            Some(U64::new(1234)),
            Location::new_unchecked(42),
        );
        assert_eq!(
            format!("{commit_op_with_metadata}"),
            "[commit 00000000000004d2 with inactivity floor: Location(42)]"
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
        let update_op = FixedOrdered::Update(KeyData {
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
    fn test_operation_ordered_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let key_data = KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        };
        let update_op = FixedOrdered::Update(key_data.clone());
        assert_eq!(&key, update_op.key().unwrap());
        assert_eq!(&value, update_op.value().unwrap());
        assert_eq!(&key_data, update_op.key_data().unwrap());
        assert!(update_op.has_floor().is_none());

        let from = FixedOrdered::<U64, U64>::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.key().unwrap());
        assert_eq!(&value, from.value().unwrap());
        assert_eq!(update_op, from);
        assert_eq!(key_data, update_op.into_key_data().unwrap());

        let key2 = U64::new(42);
        let delete_op = FixedOrdered::<U64, U64>::Delete(key2.clone());
        let from = FixedOrdered::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(None, from.value());
        assert_eq!(delete_op, from);

        let commit_op = FixedOrdered::<U64, U64>::CommitFloor(None, Location::new_unchecked(42));
        let from = FixedOrdered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.value());
        assert!(
            matches!(from, FixedOrdered::CommitFloor(None, loc) if loc == Location::new_unchecked(42))
        );
        assert_eq!(commit_op, from);
        assert!(commit_op.key_data().is_none());
        assert!(commit_op.into_key_data().is_none());

        let commit_op =
            FixedOrdered::<U64, U64>::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        let from = FixedOrdered::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(Some(&value), from.value());
        assert!(
            matches!(&from, FixedOrdered::CommitFloor(Some(v), loc) if v == &value && *loc == Location::new_unchecked(42))
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
