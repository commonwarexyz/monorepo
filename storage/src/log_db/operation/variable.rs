use crate::{log_db::operation, mmr::Location};
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
                        "storage::log_db::operation::Operation",
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
