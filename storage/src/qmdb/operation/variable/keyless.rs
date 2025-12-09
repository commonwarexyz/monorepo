use crate::qmdb::operation::{self, variable::Value, Committable};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::hex;
use core::fmt::Display;

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<V: Value> {
    /// Wraps the value appended to the database by this operation.
    Append(V),

    /// Indicates the database has been committed.
    Commit(Option<V>),
}

impl<V: Value> Operation<V> {
    /// Returns the value (if any) wrapped by this operation.
    pub fn into_value(self) -> Option<V> {
        match self {
            Self::Append(value) => Some(value),
            Self::Commit(value) => value,
        }
    }
}

impl<V: Value> EncodeSize for Operation<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Append(v) => v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

impl<V: Value> Write for Operation<V> {
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

impl<V: Value> Committable for Operation<V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }
}

impl<V: Value> Read for Operation<V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            operation::APPEND_CONTEXT => Ok(Self::Append(V::read_cfg(buf, cfg)?)),
            operation::COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: Value> Display for Operation<V> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize as _};
    use commonware_utils::{hex, sequence::U64};

    #[test]
    fn test_operation_keyless_append() {
        let append_op = Operation::Append(U64::new(12345));

        let encoded = append_op.encode();
        assert_eq!(encoded.len(), 1 + U64::SIZE);

        let decoded = Operation::<U64>::decode(encoded).unwrap();
        assert_eq!(append_op, decoded);
        assert_eq!(
            format!("{append_op}"),
            format!("[append value:{}]", hex(&U64::new(12345).encode()))
        );
    }

    #[test]
    fn test_operation_keyless_commit() {
        let metadata = Some(U64::new(12345));
        let commit_op = Operation::Commit(metadata.clone());

        let encoded = commit_op.encode();
        assert_eq!(encoded.len(), 1 + metadata.encode_size());

        let decoded = Operation::<U64>::decode(encoded).unwrap();
        let Operation::Commit(metadata_decoded) = decoded else {
            panic!("expected commit operation");
        };
        assert_eq!(metadata, metadata_decoded);
    }

    #[test]
    fn test_operation_keyless_invalid_context() {
        let invalid = vec![0xFF; 1];
        let decoded = Operation::<U64>::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }
}
