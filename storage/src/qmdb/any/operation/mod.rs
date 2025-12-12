use crate::{
    mmr::Location,
    qmdb::{
        any::{update::Update, value::ValueEncoding, OrderedUpdate, UnorderedUpdate},
        operation::Committable,
    },
};
use commonware_codec::{Codec, Encode as _};
use commonware_utils::{hex, Array};
use std::fmt;

mod fixed;
mod variable;

const DELETE_CONTEXT: u8 = 0xD1;
const UPDATE_CONTEXT: u8 = 0xD2;
const COMMIT_CONTEXT: u8 = 0xD3;

pub type OrderedOperation<K, V> = Operation<K, V, OrderedUpdate<K, V>>;
pub type UnorderedOperation<K, V> = Operation<K, V, UnorderedUpdate<K, V>>;

#[derive(Clone, PartialEq, Debug)]
pub enum Operation<K: Array, V: ValueEncoding, S: Update<K, V>> {
    Delete(K),
    Update(S),
    CommitFloor(Option<V::Value>, Location),
}

impl<K, V, S> crate::qmdb::operation::Operation for Operation<K, V, S>
where
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
    S: Update<K, V>,
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

impl<K, V, S> Committable for Operation<K, V, S>
where
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
    S: Update<K, V>,
{
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

impl<K, V> fmt::Display for Operation<K, V, OrderedUpdate<K, V>>
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
