use crate::{
    adb::operation::{self, fixed::FixedOperation},
    mmr::Location,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    util::at_least, CodecFixed, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use core::fmt::Display;

/// An operation applied to an authenticated database with a fixed size value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<K: Array, V: CodecFixed> {
    /// Indicates the key no longer has a value.
    Delete(K),

    /// Indicates the key now has the wrapped value.
    Update(K, V),

    /// Indicates all prior operations are no longer subject to rollback, and the floor on inactive
    /// operations has been raised to the wrapped value.
    CommitFloor(Location),
}

impl<K: Array, V: CodecFixed> Operation<K, V> {
    // A compile-time assertion that operation's array size is large enough to handle the commit
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

impl<K: Array, V: CodecFixed> FixedSize for Operation<K, V> {
    const SIZE: usize = u8::SIZE + K::SIZE + V::SIZE;
}

impl<K: Array, V: CodecFixed<Cfg = ()>> FixedOperation for Operation<K, V> {
    type Key = K;
    type Value = V;

    fn commit_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(loc) => Some(*loc),
            _ => None,
        }
    }

    fn key(&self) -> Option<&Self::Key> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            Self::assert_valid_size();
        }

        match self {
            Self::Delete(key) => Some(key),
            Self::Update(key, _) => Some(key),
            Self::CommitFloor(_) => None,
        }
    }

    fn value(&self) -> Option<&Self::Value> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            Self::assert_valid_size();
        }

        match self {
            Self::Delete(_) => None,
            Self::Update(_, value) => Some(value),
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
            Self::Update(_, value) => Some(value),
            Self::CommitFloor(_) => None,
        }
    }
}

impl<K: Array, V: CodecFixed> Write for Operation<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Delete(k) => {
                operation::DELETE_CONTEXT.write(buf);
                k.write(buf);
                // Pad with 0 up to [Self::SIZE]
                buf.put_bytes(0, V::SIZE);
            }
            Self::Update(k, v) => {
                operation::UPDATE_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
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

impl<K: Array, V: CodecFixed> Read for Operation<K, V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        at_least(buf, Self::SIZE)?;

        match u8::read(buf)? {
            operation::UPDATE_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read_cfg(buf, cfg)?;
                Ok(Self::Update(key, value))
            }
            operation::DELETE_CONTEXT => {
                let key = K::read(buf)?;
                // Check that the value is all zeroes
                for _ in 0..V::SIZE {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::fixed::unordered::Operation",
                            "delete value non-zero",
                        ));
                    }
                }
                Ok(Self::Delete(key))
            }
            operation::COMMIT_FLOOR_CONTEXT => {
                let floor_loc = u64::read(buf)?;
                for _ in 0..(Self::SIZE - 1 - u64::SIZE) {
                    if u8::read(buf)? != 0 {
                        return Err(CodecError::Invalid(
                            "storage::adb::operation::fixed::unordered::Operation",
                            "commit value non-zero",
                        ));
                    }
                }
                let floor_loc = Location::new(floor_loc).ok_or_else(|| {
                    CodecError::Invalid(
                        "storage::adb::operation::fixed::unordered::Operation",
                        "commit floor location overflow",
                    )
                })?;
                Ok(Self::CommitFloor(floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<K: Array, V: CodecFixed> Display for Operation<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(key, value) => write!(f, "[key:{key} value:{}]", hex(&value.encode())),
            Self::CommitFloor(loc) => write!(f, "[commit with inactivity floor: {loc}]"),
        }
    }
}
