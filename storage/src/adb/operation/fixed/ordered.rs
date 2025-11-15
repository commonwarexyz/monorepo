use crate::{
    adb::operation::{self, Committable, Keyed},
    mmr::Location,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, CodecFixed, Error as CodecError, FixedSize as CodecFixedSize, Read,
    ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;

/// An operation applied to an authenticated database with a fixed size value that supports
/// exclusion proofs over ordered keys.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array + Ord, V: CodecFixed> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key within the wrapped structure has the associated value and next-key.
    Update(KeyData<K, V>),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(Location),
}

/// Data about a key in an ordered database or an ordered database operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyData<K: Array + Ord, V: CodecFixed> {
    /// The key that exists in the database or in the database operation.
    pub key: K,
    /// The value of `key` in the database or operation.
    pub value: V,
    /// The next-key of `key` in the database or operation.
    ///
    /// The next-key is the next active key that lexicographically follows it in the key space. If
    /// the key is the lexicographically-last active key, then next-key is the
    /// lexicographically-first of all active keys (in a DB with only one key, this means its
    /// next-key is itself)
    pub next_key: K,
}

impl<K: Array + Ord, V: CodecFixed> Operation<K, V> {
    // For a compile-time assertion that operation's array size is large enough to handle the commit
    // operation, which requires 9 bytes.
    const _MIN_OPERATION_LEN: usize = 9;

    /// Asserts that the size of `Self` is greater than the minimum operation size.
    #[inline(always)]
    const fn assert_valid_size() {
        assert!(
            Self::SIZE >= Self::_MIN_OPERATION_LEN,
            "array size too small for commit op"
        );
    }
}

impl<K: Array + Ord, V: CodecFixed> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                operation::DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - 1 - K::SIZE);
            }
            Self::Update(data) => {
                operation::UPDATE_CONTEXT.write(buf);
                data.key.write(buf);
                data.value.write(buf);
                data.next_key.write(buf);
            }
            Self::CommitFloor(floor_loc) => {
                operation::COMMIT_FLOOR_CONTEXT.write(buf);
                buf.put_slice(&floor_loc.to_be_bytes());
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, Self::SIZE - 1 - u64::SIZE);
            }
        }
    }
}

impl<K: Array + Ord, V: CodecFixed> CodecFixedSize for Operation<K, V> {
    const SIZE: usize = u8::SIZE + K::SIZE + V::SIZE + K::SIZE;
}

impl<K: Array + Ord, V: CodecFixed<Cfg = ()>> Keyed for Operation<K, V> {
    type Key = K;
    type Value = V;

    fn key(&self) -> Option<&Self::Key> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            Self::assert_valid_size();
        }

        match self {
            Self::Delete(key) => Some(key),
            Self::Update(data) => Some(&data.key),
            Self::CommitFloor(_) => None,
        }
    }

    fn has_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(loc) => Some(*loc),
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
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            Self::assert_valid_size();
        }

        match self {
            Self::Delete(_) => None,
            Self::Update(data) => Some(&data.value),
            Self::CommitFloor(_) => None,
        }
    }

    fn into_value(self) -> Option<Self::Value> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            Self::assert_valid_size();
        }

        match self {
            Self::Delete(_) => None,
            Self::Update(data) => Some(data.value),
            Self::CommitFloor(_) => None,
        }
    }
}

impl<K: Array + Ord, V: CodecFixed> Committable for Operation<K, V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_))
    }
}

impl<K: Array + Ord, V: CodecFixed> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            operation::UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                let next_key = K::read(buf)?;
                Ok(Self::Update(KeyData {
                    key,
                    value,
                    next_key,
                }))
            }
            operation::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                // Check that the value is all zeroes
                for _ in 0..(Self::SIZE - 1 - K::SIZE) {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::FixedOrdered",
                            "delete value non-zero",
                        ));
                    }
                }
                Ok(Self::Delete(key))
            }
            operation::COMMIT_FLOOR_CONTEXT => {
                let floor_loc = u64::read(buf)?;
                let floor_loc = Location::new(floor_loc).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::adb::operation::fixed::ordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                for _ in 0..(Self::SIZE - 1 - u64::SIZE) {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::fixed::ordered::Operation",
                            "commit value non-zero",
                        ));
                    }
                }
                Ok(Self::CommitFloor(floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array + Ord, V: CodecFixed> Display for Operation<K, V> {
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
            Self::CommitFloor(loc) => write!(f, "[commit with inactivity floor: {loc}]"),
        }
    }
}
