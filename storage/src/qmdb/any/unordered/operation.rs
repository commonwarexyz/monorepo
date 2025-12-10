//! Operations that can be applied to a QMDB.

use crate::{
    mmr::Location,
    qmdb::{
        any::{Encoding, Fixed, Variable, COMMIT_FLOOR_CONTEXT, DELETE_CONTEXT, UPDATE_CONTEXT},
        operation::{
            fixed::Value as FixedValue, variable::Value as VariableValue, Committable, Keyed,
        },
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, varint::UInt, Codec, EncodeSize, Error as CodecError,
    FixedSize as CodecFixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;
use std::marker::PhantomData;

pub type FixedOperation<K, V> = Operation<K, V, Fixed>;
pub type VariableOperation<K, V> = Operation<K, V, Variable>;

/// An operation applied to an authenticated database with a fixed size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: Codec + Clone, E: Encoding> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(Option<V>, Location, PhantomData<E>),
}

impl<K: Array + Ord, V: FixedValue> Operation<K, V, Fixed> {
    // Commit op has a context byte, an option indicator, a metadata value, and a u64 location.
    const COMMIT_OP_SIZE: usize = 1 + 1 + V::SIZE + u64::SIZE;

    // Update op has a context byte, a key, and a value.
    const UPDATE_OP_SIZE: usize = 1 + K::SIZE + V::SIZE;

    // Delete op has a context byte and a key.
    const DELETE_OP_SIZE: usize = 1 + K::SIZE;
}

impl<K: Array + Ord, V: FixedValue> CodecFixedSize for Operation<K, V, Fixed> {
    // Make sure operation array is large enough to hold the maximum of all ops.
    const SIZE: usize = if Self::UPDATE_OP_SIZE > Self::COMMIT_OP_SIZE {
        Self::UPDATE_OP_SIZE
    } else {
        Self::COMMIT_OP_SIZE
    };
}

impl<K: Array, V: VariableValue> EncodeSize for Operation<K, V, Variable> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(_, v) => K::SIZE + v.encode_size(),
            Self::CommitFloor(v, floor_loc, _) => v.encode_size() + UInt(**floor_loc).encode_size(),
        }
    }
}

impl<K: Array, V: Codec + Clone, E: Encoding> Keyed for Operation<K, V, E>
where
    Self: Codec,
{
    type Key = K;
    type Value = V;

    fn key(&self) -> Option<&Self::Key> {
        match self {
            Self::Delete(key) => Some(key),
            Self::Update(key, _) => Some(key),
            Self::CommitFloor(_, _, _) => None,
        }
    }

    fn is_delete(&self) -> bool {
        matches!(self, Self::Delete(_))
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Update(_, _))
    }

    fn has_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(_, loc, _) => Some(*loc),
            _ => None,
        }
    }

    fn value(&self) -> Option<&Self::Value> {
        match self {
            Self::Delete(_) => None,
            Self::Update(_, value) => Some(value),
            Self::CommitFloor(metadata, _, _) => metadata.as_ref(),
        }
    }

    fn into_value(self) -> Option<Self::Value> {
        match self {
            Self::Delete(_) => None,
            Self::Update(_, value) => Some(value),
            Self::CommitFloor(metadata, _, _) => metadata,
        }
    }
}

impl<K: Array, V: Codec + Clone, E: Encoding> Committable for Operation<K, V, E> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _, _))
    }
}

impl<K: Array, V: FixedValue> Write for Operation<K, V, Fixed> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::DELETE_OP_SIZE);
            }
            Self::Update(k, v) => {
                UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - Self::UPDATE_OP_SIZE);
            }
            Self::CommitFloor(metadata, floor_loc, _) => {
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

impl<K: Array, V: VariableValue> Write for Operation<K, V, Variable> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(k, v) => {
                UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Self::CommitFloor(v, floor_loc, _) => {
                COMMIT_FLOOR_CONTEXT.write(buf);
                v.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<K: Array, V: FixedValue> Read for Operation<K, V, Fixed> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                ensure_zeros(buf, Self::SIZE - Self::UPDATE_OP_SIZE)?;
                Ok(Self::Update(key, value))
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
                        "storage::qmdb::operation::fixed::unordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                ensure_zeros(buf, Self::SIZE - Self::COMMIT_OP_SIZE)?;

                Ok(Self::CommitFloor(metadata, floor_loc, PhantomData))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: VariableValue> Read for Operation<K, V, Variable> {
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
                Ok(Self::Update(key, value))
            }
            COMMIT_FLOOR_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::operation::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc, PhantomData))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: Codec + Clone, E: Encoding> Display for Operation<K, V, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Self::CommitFloor(metadata, loc, _) => {
                if let Some(metadata) = metadata {
                    write!(
                        f,
                        "[commit {} with inactivity floor: {loc}]",
                        hex(&metadata.encode())
                    )
                } else {
                    write!(f, "[commit with inactivity floor: {loc}]")
                }
            }
        }
    }
}

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
