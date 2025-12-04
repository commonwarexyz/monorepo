use crate::{
    adb::operation::{
        self,
        fixed::{ensure_zeros, Value},
        Committable, KeyData, Keyed, Ordered,
    },
    mmr::Location,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, Error as CodecError, FixedSize as CodecFixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;

/// An operation applied to an authenticated database with a fixed size value that supports
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

impl<K: Array, V: Value> Operation<K, V> {
    // Commit op has a context byte, an option indicator, a metadata value, and a u64 location.
    const COMMIT_OP_SIZE: usize = 1 + 1 + V::SIZE + u64::SIZE;

    // Update op has a context byte, a key, a value, and a next key.
    const UPDATE_OP_SIZE: usize = 1 + K::SIZE + V::SIZE + K::SIZE;

    // Delete op has a context byte and a key.
    const DELETE_OP_SIZE: usize = 1 + K::SIZE;
}

const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

impl<K: Array, V: Value> CodecFixedSize for Operation<K, V> {
    // Make sure operation array is large enough to hold the maximum of all ops.
    const SIZE: usize = max(Self::UPDATE_OP_SIZE, Self::COMMIT_OP_SIZE);
}

impl<K: Array, V: Value> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                operation::DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::DELETE_OP_SIZE);
            }
            Self::Update(data) => {
                operation::UPDATE_CONTEXT.write(buf);
                data.key.write(buf);
                data.value.write(buf);
                data.next_key.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::UPDATE_OP_SIZE);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                operation::COMMIT_FLOOR_CONTEXT.write(buf);
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
            Self::CommitFloor(metadata, _) => metadata.as_ref(),
        }
    }

    fn into_value(self) -> Option<Self::Value> {
        match self {
            Self::Delete(_) => None,
            Self::Update(data) => Some(data.value),
            Self::CommitFloor(metadata, _) => metadata,
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
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            operation::UPDATE_CONTEXT => {
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
            operation::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                ensure_zeros(buf, Self::SIZE - Self::DELETE_OP_SIZE)?;

                Ok(Self::Delete(key))
            }
            operation::COMMIT_FLOOR_CONTEXT => {
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
                        "storage::adb::operation::fixed::ordered::Operation",
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
            Self::CommitFloor(metadata, loc) => {
                if let Some(value) = metadata {
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
