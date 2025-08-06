//! Operations that can be applied to a [`Store`] database.
//!
//! The [`Operation`] enum implements the `Array` trait, allowing for a persistent log of operations
//! based on a `crate::Journal`.
//!
//! [`Store`]: crate::store::Store

use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
};

/// An operation applied to an unauthenticated database with a variable size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: Codec> {
    /// Indicates the key now has the wrapped value.
    Set(K, V),

    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    Commit(u64),
}

impl<K: Array, V: Codec> EncodeSize for Operation<K, V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            // 1 byte for the context + fixed key size + value’s own size
            Operation::Set(_, v) => K::SIZE + v.encode_size(),
            // 1 byte for the context + fixed key size
            Operation::Delete(_) => K::SIZE,
            // Only the context byte
            Operation::Commit(floor_num) => floor_num.encode_size(),
        }
    }
}

const SET_CONTEXT: u8 = 0;
const DELETE_CONTEXT: u8 = 1;
const COMMIT_CONTEXT: u8 = 2;

impl<K: Array, V: Codec> Operation<K, V> {
    /// If this is a [`Operation::Set`] operation, returns the key. Otherwise, returns None.
    pub fn to_key(&self) -> Option<&K> {
        match self {
            Operation::Set(key, _) => Some(key),
            Operation::Delete(key) => Some(key),
            Operation::Commit(_) => None,
        }
    }

    /// If this is a [`Operation::Set`] operation, returns the value. Otherwise, returns None.
    pub fn to_value(&self) -> Option<&V> {
        match self {
            Operation::Set(_, value) => Some(value),
            Operation::Delete(_) => None,
            Operation::Commit(_) => None,
        }
    }
}

impl<K: Array, V: Codec> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Operation::Set(k, v) => {
                buf.put_u8(SET_CONTEXT);
                k.write(buf);
                v.write(buf);
            }
            Operation::Delete(k) => {
                buf.put_u8(DELETE_CONTEXT);
                k.write(buf);
            }
            Operation::Commit(n) => {
                buf.put_u8(COMMIT_CONTEXT);
                n.write(buf);
            }
        }
    }
}

impl<K: Array, V: Codec> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            SET_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Set(key, value))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            COMMIT_CONTEXT => {
                let num = u64::read(buf)?;
                Ok(Self::Commit(num))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Array> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Set(key, value) => write!(f, "[key:{key} value:{value}]"),
            Operation::Delete(key) => write!(f, "[delete key:{key}]"),
            Operation::Commit(num) => write!(f, "[commit floor:{num}]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_utils::sequence::U64;

    #[test]
    fn test_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&key, set_op.to_key().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(&key, delete_op.to_key().unwrap());

        let commit_op = Operation::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_key());
    }

    #[test]
    fn test_to_value() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&value, set_op.to_value().unwrap());

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(None, delete_op.to_value());

        let commit_op = Operation::<U64, U64>::Commit(42);
        assert_eq!(None, commit_op.to_value());
    }

    #[test]
    fn test_operation_array_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(&key, set_op.to_key().unwrap());
        assert_eq!(&value, set_op.to_value().unwrap());

        let from = Operation::<U64, U64>::decode(set_op.encode()).unwrap();
        assert_eq!(&key, from.to_key().unwrap());
        assert_eq!(&value, from.to_value().unwrap());
        assert_eq!(set_op, from);

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        let from = Operation::<U64, U64>::decode(delete_op.encode()).unwrap();
        assert_eq!(&key, from.to_key().unwrap());
        assert_eq!(None, from.to_value());
        assert!(matches!(from, Operation::Delete(_)));
        assert_eq!(delete_op, from);

        let commit_op = Operation::<U64, U64>::Commit(42);
        let from = Operation::<U64, U64>::decode(commit_op.encode()).unwrap();
        assert_eq!(None, from.to_value());
        assert!(matches!(from, Operation::Commit(42)));
        assert_eq!(commit_op, from);

        // test invalid context byte detection
        let mut invalid = set_op.encode();
        invalid[0] = 0xFF;
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = set_op.encode().to_vec();
        invalid.pop();
        let decoded = Operation::<U64, U64>::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_array_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let set_op = Operation::Set(key.clone(), value.clone());
        assert_eq!(format!("{set_op}"), format!("[key:{key} value:{value}]"));

        let delete_op = Operation::<U64, U64>::Delete(key.clone());
        assert_eq!(format!("{delete_op}"), format!("[delete key:1234]"));

        let commit_op = Operation::<U64, U64>::Commit(42);
        assert_eq!(format!("{commit_op}"), format!("[commit floor:42]"));
    }

    #[test]
    fn test_operation_array_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let set_op = Operation::Set(key, value);

        let encoded = set_op.encode();
        assert_eq!(encoded.len(), 1 + U64::SIZE + U64::SIZE);

        let decoded = Operation::<U64, U64>::decode(encoded).unwrap();
        assert_eq!(set_op, decoded);
    }
}
