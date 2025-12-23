use crate::qmdb::{any::VariableValue, operation::Committable};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::hex;
use core::fmt::Display;

// Context byte prefixes for identifying the operation type.
const COMMIT_CONTEXT: u8 = 0;
const APPEND_CONTEXT: u8 = 1;

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<V: VariableValue> {
    /// Wraps the value appended to the database by this operation.
    Append(V),

    /// Indicates the database has been committed.
    Commit(Option<V>),
}

impl<V: VariableValue> Operation<V> {
    /// Returns the value (if any) wrapped by this operation.
    pub fn into_value(self) -> Option<V> {
        match self {
            Self::Append(value) => Some(value),
            Self::Commit(value) => value,
        }
    }
}

impl<V: VariableValue> EncodeSize for Operation<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Append(v) => v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

impl<V: VariableValue> Write for Operation<V> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Append(value) => {
                APPEND_CONTEXT.write(buf);
                value.write(buf);
            }
            Self::Commit(metadata) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
            }
        }
    }
}

impl<V: VariableValue> Committable for Operation<V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }
}

impl<V: VariableValue> Read for Operation<V> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            APPEND_CONTEXT => Ok(Self::Append(V::read_cfg(buf, cfg)?)),
            COMMIT_CONTEXT => Ok(Self::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: VariableValue> Display for Operation<V> {
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

#[cfg(feature = "arbitrary")]
impl<V: VariableValue> arbitrary::Arbitrary<'_> for Operation<V>
where
    V: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => Ok(Self::Append(V::arbitrary(u)?)),
            1 => Ok(Self::Commit(Option::<V>::arbitrary(u)?)),
            _ => unreachable!(),
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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Operation<U64>>
        }
    }
}
