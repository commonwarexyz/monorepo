use crate::adb::operation::{self, Committable};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::hex;
use core::fmt::Display;

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<V: Codec> {
    /// Wraps the value appended to the database by this operation.
    Append(V),

    /// Indicates the database has been committed.
    Commit(Option<V>),
}

impl<V: Codec> Operation<V> {
    /// Returns the value (if any) wrapped by this operation.
    pub fn into_value(self) -> Option<V> {
        match self {
            Self::Append(value) => Some(value),
            Self::Commit(value) => value,
        }
    }
}

impl<V: Codec> EncodeSize for Operation<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Append(v) => v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

impl<V: Codec> Write for Operation<V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Append(value) => {
                operation::APPEND_CONTEXT.write(buf);
                value.write(buf);
            }
            Self::Commit(metadata) => {
                operation::COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
            }
        }
    }
}

impl<V: Codec> Committable for Operation<V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }
}

impl<V: Codec> Read for Operation<V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            operation::APPEND_CONTEXT => Ok(Self::Append(V::read_cfg(buf, cfg)?)),
            operation::COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: Codec> Display for Operation<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Append(value) => write!(f, "[append value:{}]", hex(&value.encode())),
            Self::Commit(value) => {
                if let Some(value) = value {
                    write!(f, "[commit {}]", hex(&value.encode()))
                } else {
                    write!(f, "[commit]")
                }
            }
        }
    }
}
