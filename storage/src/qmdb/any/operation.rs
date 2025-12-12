use std::fmt;

use bytes::{Buf, BufMut};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    varint::UInt,
    Codec, Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};

use crate::{
    mmr::Location,
    qmdb::{
        any::{
            update::Update,
            value::{FixedEncoding, ValueEncoding, VariableEncoding},
            FixedValue, OrderedUpdate, UnorderedUpdate, VariableValue,
        },
        operation::Committable,
    },
};

const DELETE_CONTEXT: u8 = 0xD1;
const UPDATE_CONTEXT: u8 = 0xD2;
const COMMIT_CONTEXT: u8 = 0xD3;

pub type OrderedOperation<K, V> = Operation<OrderedUpdate<K, V>, K, V>;
pub type UnorderedOperation<K, V> = Operation<UnorderedUpdate<K, V>, K, V>;

#[derive(Clone, PartialEq, Debug)]
pub enum Operation<S, K: Array, V: ValueEncoding>
where
    S: Update<K, V>,
{
    Delete(K),
    Update(S),
    CommitFloor(Option<V::Value>, Location),
}

impl<S, K, V> Operation<S, K, FixedEncoding<V>>
where
    S: Update<K, FixedEncoding<V>> + FixedSize,
    K: Array,
    V: FixedValue,
{
    const UPDATE_OP_SIZE: usize = 1 + S::SIZE;
    const COMMIT_OP_SIZE: usize = 1 + 1 + V::SIZE + u64::SIZE;
    const DELETE_OP_SIZE: usize = 1 + K::SIZE;
}

impl<S, K, V> FixedSize for Operation<S, K, FixedEncoding<V>>
where
    S: Update<K, FixedEncoding<V>> + FixedSize,
    K: Array,
    V: FixedValue,
{
    const SIZE: usize = {
        let max = if Self::UPDATE_OP_SIZE > Self::COMMIT_OP_SIZE {
            Self::UPDATE_OP_SIZE
        } else {
            Self::COMMIT_OP_SIZE
        };
        if max > Self::DELETE_OP_SIZE {
            max
        } else {
            Self::DELETE_OP_SIZE
        }
    };
}

impl<S, K, V> Write for Operation<S, K, FixedEncoding<V>>
where
    S: Update<K, FixedEncoding<V>> + FixedSize + Write,
    K: Array + Codec,
    V: FixedValue,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
                buf.put_bytes(0, Self::SIZE - Self::DELETE_OP_SIZE);
            }
            Self::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
                buf.put_bytes(0, Self::SIZE - Self::UPDATE_OP_SIZE);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                if let Some(metadata) = metadata {
                    true.write(buf);
                    metadata.write(buf);
                } else {
                    buf.put_bytes(0, V::SIZE + 1);
                }
                buf.put_slice(&floor_loc.to_be_bytes());
                buf.put_bytes(0, Self::SIZE - Self::COMMIT_OP_SIZE);
            }
        }
    }
}

impl<S, K, V> Read for Operation<S, K, FixedEncoding<V>>
where
    S: Update<K, FixedEncoding<V>> + FixedSize + Read<Cfg = ()>,
    K: Array + Codec,
    V: FixedValue,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                ensure_zeros(buf, Self::SIZE - Self::UPDATE_OP_SIZE)?;
                Ok(Self::Update(payload))
            }
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                ensure_zeros(buf, Self::SIZE - Self::DELETE_OP_SIZE)?;
                Ok(Self::Delete(key))
            }
            COMMIT_CONTEXT => {
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
                        "storage::qmdb::any::todo::Operation2",
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

impl<S, K, V> EncodeSize for Operation<S, K, VariableEncoding<V>>
where
    S: Update<K, VariableEncoding<V>> + EncodeSize,
    K: Array,
    V: VariableValue,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Delete(_) => K::SIZE,
            Self::Update(p) => p.encode_size(),
            Self::CommitFloor(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<S, K, V> Write for Operation<S, K, VariableEncoding<V>>
where
    S: Update<K, VariableEncoding<V>> + Write,
    K: Array + Codec,
    V: VariableValue,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Delete(k) => {
                DELETE_CONTEXT.write(buf);
                k.write(buf);
            }
            Self::Update(p) => {
                UPDATE_CONTEXT.write(buf);
                p.write(buf);
            }
            Self::CommitFloor(metadata, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<S, K, V> Read for Operation<S, K, VariableEncoding<V>>
where
    S: Update<K, VariableEncoding<V>> + Read<Cfg = <V as Read>::Cfg>,
    K: Array + Codec,
    V: VariableValue,
{
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DELETE_CONTEXT => {
                let key = K::read(buf)?;
                Ok(Self::Delete(key))
            }
            UPDATE_CONTEXT => {
                let payload = S::read_cfg(buf, cfg)?;
                Ok(Self::Update(payload))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor_loc = UInt::read(buf)?;
                let floor_loc = Location::new(floor_loc.into()).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::qmdb::any::todo::Operation2",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<S, K, V> crate::qmdb::operation::Operation for Operation<S, K, V>
where
    S: Update<K, V>,
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
{
    type Key = K;

    fn key(&self) -> Option<&Self::Key> {
        match self {
            Self::Delete(k) => Some(k),
            Self::Update(p) => Some(p.key()),
            Self::CommitFloor(_, _) => None,
        }
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Update(_))
    }

    fn is_delete(&self) -> bool {
        matches!(self, Self::Delete(_))
    }

    fn has_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(_, loc) => Some(*loc),
            _ => None,
        }
    }
}

impl<S, K, V> Committable for Operation<S, K, V>
where
    S: Update<K, V>,
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
{
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

impl<K, V> fmt::Display for Operation<OrderedUpdate<K, V>, K, V>
where
    K: Array + fmt::Display,
    V: ValueEncoding,
    V::Value: Codec,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(payload) => payload.fmt(f),
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
