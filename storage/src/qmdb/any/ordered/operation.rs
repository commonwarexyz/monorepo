use crate::{
    mmr::Location,
    qmdb::{
        any::{
            ordered::KeyData,
            value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
            COMMIT_FLOOR_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT,
        },
        operation::{Committable, Operation as OperationTrait},
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    varint::UInt,
    Codec, Encode as _, EncodeSize, Error as CodecError, FixedSize as CodecFixedSize, Read,
    ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;

pub type FixedOperation<K, V> = Operation<K, FixedEncoding<V>>;
pub type VariableOperation<K, V> = Operation<K, VariableEncoding<V>>;

/// An ordered operation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: ValueEncoding> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key within the wrapped structure has the associated value and next-key.
    Update(KeyData<K, V::Value>),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(Option<V::Value>, Location),
}

impl<K: Array, V: FixedValue> FixedOperation<K, V> {
    // Commit op has a context byte, an option indicator, a metadata value, and a u64 location.
    const COMMIT_OP_SIZE: usize = 1 + 1 + V::SIZE + u64::SIZE;

    // Update op has a context byte, a key, a value, and a next key.
    const UPDATE_OP_SIZE: usize = 1 + K::SIZE + V::SIZE + K::SIZE;

    // Delete op has a context byte and a key.
    const DELETE_OP_SIZE: usize = 1 + K::SIZE;
}

impl<K: Array, V: FixedValue> CodecFixedSize for FixedOperation<K, V> {
    // Make sure operation array is large enough to hold the maximum of all ops.
    const SIZE: usize = if Self::UPDATE_OP_SIZE > Self::COMMIT_OP_SIZE {
        Self::UPDATE_OP_SIZE
    } else {
        Self::COMMIT_OP_SIZE
    };
}

impl<K: Array, V: VariableValue> EncodeSize for VariableOperation<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(data) => K::SIZE + data.value.encode_size() + K::SIZE,
            Self::CommitFloor(v, floor_loc) => v.encode_size() + UInt(**floor_loc).encode_size(),
        }
    }
}

impl<K: Array, V: ValueEncoding> OperationTrait for Operation<K, V>
where
    Self: Codec,
{
    type Key = K;

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
}

impl<K: Array, V: ValueEncoding> Committable for Operation<K, V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

#[cfg(feature = "arbitrary")]
impl<K: Array, V: ValueEncoding> arbitrary::Arbitrary<'_> for Operation<K, V>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::Delete(u.arbitrary()?)),
            1 => Ok(Self::Update(u.arbitrary()?)),
            2 => Ok(Self::CommitFloor(u.arbitrary()?, u.arbitrary()?)),
            _ => unreachable!(),
        }
    }
}

impl<K: Array, V: FixedValue> Write for FixedOperation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::DELETE_OP_SIZE);
            }
            Self::Update(data) => {
                UPDATE_CONTEXT.write(buf);
                data.key.write(buf);
                data.value.write(buf);
                data.next_key.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::UPDATE_OP_SIZE);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                COMMIT_FLOOR_CONTEXT.write(buf);
                if let Some(metadata) = metadata {
                    true.write(buf);
                    metadata.write(buf);
                } else {
                    buf.put_bytes(0, V::SIZE + 1);
                }
                buf.put_slice(&floor_loc.to_be_bytes());
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::COMMIT_OP_SIZE);
            }
        }
    }
}

impl<K: Array, V: VariableValue> Write for VariableOperation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(data) => {
                UPDATE_CONTEXT.write(buf);
                data.key.write(buf);
                data.value.write(buf);
                data.next_key.write(buf);
            }
            Self::CommitFloor(value, floor_loc) => {
                COMMIT_FLOOR_CONTEXT.write(buf);
                value.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<K: Array, V: FixedValue> Read for FixedOperation<K, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                let next_key = K::read(buf)?;
                ensure_zeros(buf, Self::SIZE - Self::UPDATE_OP_SIZE)?;

                Ok(Self::Update(KeyData {
                    key,
                    value,
                    next_key,
                }))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                ensure_zeros(buf, Self::SIZE - Self::DELETE_OP_SIZE)?;

                Ok(Self::Delete(key))
            }
            COMMIT_FLOOR_CONTEXT => {
                let is_some = bool::read(buf)?;
                let metadata = if is_some {
                    Some(V::read_cfg(buf, cfg)?)
                } else {
                    ensure_zeros(buf, V::SIZE)?;
                    None
                };
                let floor_loc = u64::read(buf)?;
                let floor_loc = Location::new(floor_loc).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::operation::ordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                ensure_zeros(buf, Self::SIZE - Self::COMMIT_OP_SIZE)?;

                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: VariableValue> Read for VariableOperation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                let next_key = K::read(buf)?;
                Ok(Self::Update(KeyData {
                    key,
                    value,
                    next_key,
                }))
            }
            COMMIT_FLOOR_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::operation::ordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: ValueEncoding> Display for Operation<K, V>
where
    Self: Codec,
{
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
    use crate::mmr::Location;
    use commonware_codec::{DecodeExt, Encode, Error as CodecError, RangeCfg};
    use commonware_utils::{hex, sequence::U64};

    type TestOp = FixedOperation<U64, U64>;

    #[test]
    fn test_operation_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = TestOp::Update(KeyData {
            key: key.clone(),
            value,
            next_key: key.clone(),
        });
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = TestOp::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.key());
    }

    #[test]
    fn test_operation_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let key_data = KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key.clone(),
        };
        let update_op = TestOp::Update(key_data.clone());
        assert_eq!(&key, update_op.key().unwrap());
        assert_eq!(
            &key_data,
            match &update_op {
                TestOp::Update(data) => data,
                _ => panic!("expected update"),
            }
        );
        assert!(!matches!(update_op, TestOp::CommitFloor(_, _)));

        let from = TestOp::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.key().unwrap());
        assert_eq!(update_op, from);
        assert_eq!(
            key_data,
            match update_op {
                TestOp::Update(data) => data,
                _ => panic!("expected update"),
            }
        );

        let key2 = U64::new(42);
        let delete_op = TestOp::Delete(key2.clone());
        let from = TestOp::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(delete_op, from);

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        let from = TestOp::decode(commit_op.encode()).unwrap();
        assert!(matches!(
            from,
            TestOp::CommitFloor(None, loc) if loc == Location::new_unchecked(42)
        ));
        assert_eq!(commit_op, from);
        assert!(matches!(commit_op, TestOp::CommitFloor(_, _)));

        let commit_op = TestOp::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        let from = TestOp::decode(commit_op.encode()).unwrap();
        assert!(matches!(
            &from,
            TestOp::CommitFloor(Some(v), loc) if v == &value && *loc == Location::new_unchecked(42)
        ));
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let key2 = U64::new(999);
        let update_op = TestOp::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key: key2.clone(),
        });
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} next_key:{key2} value:{}]", hex(&value.encode()))
        );

        let key2 = U64::new(42);
        let delete_op = TestOp::Delete(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op}"),
            "[commit with inactivity floor: Location(42)]"
        );

        let commit_op_with_metadata =
            TestOp::CommitFloor(Some(U64::new(1234)), Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op_with_metadata}"),
            "[commit 00000000000004d2 with inactivity floor: Location(42)]"
        );
    }

    #[test]
    fn test_operation_codec_fixed() {
        let key = U64::new(1);
        let next_key = U64::new(2);
        let value = U64::new(5678);
        let floor_loc = Location::new_unchecked(5);

        let update_op = TestOp::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        let delete_op = TestOp::Delete(key);
        let commit_none = TestOp::CommitFloor(None, floor_loc);
        let commit_some = TestOp::CommitFloor(Some(value), floor_loc);

        assert_eq!(update_op, TestOp::decode(update_op.encode()).unwrap());
        assert_eq!(delete_op, TestOp::decode(delete_op.encode()).unwrap());
        assert_eq!(commit_none, TestOp::decode(commit_none.encode()).unwrap());
        assert_eq!(commit_some, TestOp::decode(commit_some.encode()).unwrap());
    }

    #[test]
    fn test_operation_codec_variable() {
        type VarOp = VariableOperation<U64, Vec<u8>>;

        let key = U64::new(1);
        let next_key = U64::new(2);
        let value = b"variable".to_vec();
        let floor_loc = Location::new_unchecked(5);

        let update_op = VarOp::Update(KeyData {
            key: key.clone(),
            value: value.clone(),
            next_key,
        });
        let delete_op = VarOp::Delete(key);
        let commit_none = VarOp::CommitFloor(None, floor_loc);
        let commit_some = VarOp::CommitFloor(Some(value), floor_loc);

        assert_eq!(
            update_op,
            VarOp::read_cfg(&mut update_op.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            delete_op,
            VarOp::read_cfg(&mut delete_op.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            commit_none,
            VarOp::read_cfg(&mut commit_none.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            commit_some,
            VarOp::read_cfg(&mut commit_some.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<FixedOperation<U64, U64>>,
            CodecConformance<VariableOperation<U64, Vec<u8>>>,
        }
    }
}
