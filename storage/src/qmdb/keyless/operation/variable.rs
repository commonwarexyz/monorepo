use crate::qmdb::{
    any::{value::VariableEncoding, VariableValue},
    keyless::operation::{Codec, Operation, APPEND_CONTEXT, COMMIT_CONTEXT},
};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<V: VariableValue> Codec for VariableEncoding<V> {
    type ReadCfg = <V as Read>::Cfg;

    fn write_operation(op: &Operation<Self>, buf: &mut impl BufMut) {
        match op {
            Operation::Append(value) => {
                APPEND_CONTEXT.write(buf);
                value.write(buf);
            }
            Operation::Commit(metadata) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
            }
        }
    }

    fn read_operation(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<Self>, CodecError> {
        match u8::read(buf)? {
            APPEND_CONTEXT => Ok(Operation::Append(V::read_cfg(buf, cfg)?)),
            COMMIT_CONTEXT => Ok(Operation::Commit(Option::<V>::read_cfg(buf, cfg)?)),
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: VariableValue> EncodeSize for Operation<VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Append(v) => v.encode_size(),
            Self::Commit(v) => v.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, EncodeSize};
    use commonware_utils::sequence::U64;

    // Use U64 as the value type: it implements VariableValue and has Cfg = ().
    type Op = Operation<VariableEncoding<U64>>;

    #[test]
    fn append_roundtrip() {
        let op = Op::Append(U64::new(12345));
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn commit_some_roundtrip() {
        let op = Op::Commit(Some(U64::new(999)));
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn commit_none_roundtrip() {
        let op = Op::Commit(None);
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn encode_size_matches_encoded_len() {
        let cases: Vec<Op> = vec![
            Op::Append(U64::new(0)),
            Op::Append(U64::new(u64::MAX)),
            Op::Commit(None),
            Op::Commit(Some(U64::new(42))),
        ];
        for op in cases {
            assert_eq!(op.encode_size(), op.encode().len(), "mismatch for {op:?}");
        }
    }

    #[test]
    fn invalid_context_byte_rejected() {
        let op = Op::Append(U64::new(1));
        let mut buf: Vec<u8> = op.encode().to_vec();
        buf[0] = 0xFF;
        assert!(matches!(
            Op::decode(buf.as_ref()).unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn empty_input_rejected() {
        assert!(Op::decode(&[] as &[u8]).is_err());
    }

    #[test]
    fn append_and_commit_have_different_encodings() {
        let append = Op::Append(U64::new(1));
        let commit = Op::Commit(Some(U64::new(1)));
        assert_ne!(append.encode().as_ref(), commit.encode().as_ref());
    }

    #[test]
    fn context_byte_is_first() {
        let append = Op::Append(U64::new(0));
        let commit = Op::Commit(None);
        assert_eq!(append.encode()[0], APPEND_CONTEXT);
        assert_eq!(commit.encode()[0], COMMIT_CONTEXT);
    }
}
