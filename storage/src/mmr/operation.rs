//! An `Array` implementation for operations applied to a `MutableMmr` K/V store, making them
//! storable in a `fixed::Journal`.

use commonware_codec::{Codec, Error as CodecError, Reader, SizedCodec, Writer};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

/// Errors returned by `Operation` functions.
#[derive(Error, Debug)]
pub enum Error<K: Array, V: Array> {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid key: {0}")]
    InvalidKey(<K as Array>::Error),
    #[error("invalid value: {0}")]
    InvalidValue(<V as Array>::Error),
    #[error("invalid context byte")]
    InvalidContextByte,
    #[error("delete operation as non-zero value")]
    InvalidDeleteOp,
}

/// The types of operations that change a key's state in the store.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Type<V: Array> {
    /// Indicates the key no longer has a value.
    Deleted,

    /// Indicates the key now has the wrapped value.
    Update(V),
}

/// An `Array` implementation for operations applied to a `MutableMmr` K/V store.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct Operation<K: Array, V: Array> {
    pub data: Vec<u8>,
    _phantom: std::marker::PhantomData<(K, V)>,
}

impl<K: Array, V: Array> Operation<K, V> {
    const DELETE_CONTEXT: u8 = 0;
    const UPDATE_CONTEXT: u8 = 1;

    /// Create a new operation from `key` and `op_type`.
    pub fn new(key: K, op_type: Type<V>) -> Self {
        let mut data = Vec::with_capacity(Self::LEN_ENCODED);
        data.extend_from_slice(&key);
        match op_type {
            Type::Deleted => {
                data.push(Self::DELETE_CONTEXT);
                data.resize(Self::LEN_ENCODED, 0);
            }
            Type::Update(value) => {
                data.push(Self::UPDATE_CONTEXT);
                data.extend_from_slice(&value);
            }
        }

        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn to_key(&self) -> K {
        K::try_from(&self.data[..K::LEN_ENCODED]).unwrap()
    }

    pub fn to_type(&self) -> Type<V> {
        if self.data[K::LEN_ENCODED] == 0 {
            return Type::Deleted;
        }

        Type::Update(V::try_from(&self.data[K::LEN_ENCODED + 1..]).unwrap())
    }

    pub fn to_value(&self) -> Option<V> {
        match self.to_type() {
            Type::Deleted => None,
            Type::Update(v) => Some(v),
        }
    }
}

impl<K: Array, V: Array> Codec for Operation<K, V> {
    fn write(&self, writer: &mut impl Writer) {
        writer.write_fixed(&self.data);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let value = reader.read_n_bytes(Self::LEN_ENCODED)?;
        Self::try_from(value.as_ref()).map_err(|e| CodecError::Wrapped("Operation", e.into()))
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }
}

impl<K: Array, V: Array> SizedCodec for Operation<K, V> {
    const LEN_ENCODED: usize = K::LEN_ENCODED + 1 + V::LEN_ENCODED;
}

impl<K: Array, V: Array> Array for Operation<K, V> {
    type Error = Error<K, V>;
}

impl<K: Array, V: Array> TryFrom<&[u8]> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::LEN_ENCODED {
            return Err(Error::InvalidLength);
        }

        let _ = K::try_from(&value[..K::LEN_ENCODED]).map_err(|e| Error::InvalidKey(e))?;

        match value[K::LEN_ENCODED] {
            Self::UPDATE_CONTEXT => {
                let _ = V::try_from(&value[K::LEN_ENCODED + 1..])
                    .map_err(|e| Error::InvalidValue(e))?;
            }
            Self::DELETE_CONTEXT => {
                // Check if the remaining bytes are all zeros
                if !value[K::LEN_ENCODED + 1..].iter().all(|&b| b == 0) {
                    return Err(Error::InvalidDeleteOp);
                }
            }
            _ => {
                return Err(Error::InvalidContextByte);
            }
        }

        Ok(Self {
            data: value.to_vec(),
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<K: Array, V: Array> TryFrom<&Vec<u8>> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<K: Array, V: Array> TryFrom<Vec<u8>> for Operation<K, V> {
    type Error = Error<K, V>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<K: Array, V: Array> AsRef<[u8]> for Operation<K, V> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<K: Array, V: Array> Deref for Operation<K, V> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl<K: Array, V: Array> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_type() {
            Type::Deleted => write!(f, "[key:{} <deleted>]", self.to_key()),
            Type::Update(value) => write!(f, "[key:{} value:{}]", self.to_key(), value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::array::U64;

    #[test]
    fn test_operation_array_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Operation::new(key.clone(), Type::Update(value.clone()));

        let try_from = Operation::try_from(update_op.as_ref()).unwrap();
        assert_eq!(key, try_from.to_key());
        assert_eq!(Type::Update(value.clone()), try_from.to_type());
        assert_eq!(try_from.to_value().unwrap(), value);

        let vec = update_op.to_vec();

        let from_vec_ref = Operation::<U64, U64>::try_from(&vec).unwrap();
        assert_eq!(Type::Update(value.clone()), from_vec_ref.to_type());

        let from_vec = Operation::<U64, U64>::try_from(vec).unwrap();
        assert_eq!(Type::Update(value.clone()), from_vec.to_type());

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::new(key2.clone(), Type::Deleted);
        let try_from = Operation::<U64, U64>::try_from(delete_op.as_ref()).unwrap();
        assert_eq!(key2, try_from.to_key());
        assert_eq!(Type::Deleted, try_from.to_type());
        assert_eq!(try_from.to_value(), None);

        // test extra byte detection in delete operation
        let mut invalid = delete_op.to_vec();
        invalid[U64::LEN_ENCODED + 2] = 0xFF;
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidDeleteOp));

        // test invalid context byte detection
        let mut invalid = update_op.to_vec();
        invalid[U64::LEN_ENCODED] = 2;
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidContextByte));

        // test invalid length detection
        let mut invalid = update_op.to_vec();
        invalid.pop();
        let try_from = Operation::<U64, U64>::try_from(&invalid);
        assert!(matches!(try_from.unwrap_err(), Error::InvalidLength));
    }

    #[test]
    fn test_operation_array_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = Operation::new(key.clone(), Type::Update(value.clone()));
        assert_eq!(
            format!("{}", update_op),
            format!("[key:{} value:{}]", key, value)
        );

        let key2 = U64::new(42);
        let delete_op = Operation::<U64, U64>::new(key2.clone(), Type::Deleted);
        assert_eq!(
            format!("{}", delete_op),
            format!("[key:{} <deleted>]", key2)
        );
    }

    #[test]
    fn test_operation_array_codec() {
        let key = U64::new(1234);
        let value = U64::new(5678);
        let update_op = Operation::new(key, Type::Update(value));

        let encoded = update_op.encode();
        assert_eq!(encoded.len(), Operation::<U64, U64>::LEN_ENCODED);
        assert_eq!(encoded, update_op.as_ref());

        let decoded = Operation::decode(encoded).unwrap();
        assert_eq!(update_op, decoded);
    }
}
