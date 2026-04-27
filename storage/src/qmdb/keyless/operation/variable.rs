use crate::{
    merkle::{Family, Location},
    qmdb::{
        any::{value::VariableEncoding, VariableValue},
        keyless::operation::{Codec, Operation, APPEND_CONTEXT, COMMIT_CONTEXT},
    },
};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<V: VariableValue> Codec for VariableEncoding<V> {
    type ReadCfg = <V as Read>::Cfg;

    fn write_operation<F: Family>(op: &Operation<F, Self>, buf: &mut impl BufMut) {
        match op {
            Operation::Append(value) => {
                APPEND_CONTEXT.write(buf);
                value.write(buf);
            }
            Operation::Commit(metadata, floor) => {
                COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                floor.write(buf);
            }
        }
    }

    fn read_operation<F: Family>(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<F, Self>, CodecError> {
        match u8::read(buf)? {
            APPEND_CONTEXT => Ok(Operation::Append(V::read_cfg(buf, cfg)?)),
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, cfg)?;
                let floor = Location::<F>::read(buf)?;
                Ok(Operation::Commit(metadata, floor))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<F: Family, V: VariableValue> EncodeSize for Operation<F, VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Append(v) => v.encode_size(),
            Self::Commit(v, floor) => v.encode_size() + floor.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_codec::{DecodeExt, Encode, EncodeSize};
    use commonware_utils::sequence::U64;

    // Use U64 as the value type: it implements VariableValue and has Cfg = ().
    type Op = Operation<mmr::Family, VariableEncoding<U64>>;

    #[test]
    fn append_roundtrip() {
        let op = Op::Append(U64::new(12345));
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn commit_some_roundtrip() {
        let op = Op::Commit(Some(U64::new(999)), Location::new(77));
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn commit_none_roundtrip() {
        let op = Op::Commit(None, Location::new(42));
        let decoded = Op::decode(op.encode()).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn encode_size_matches_encoded_len() {
        let cases: Vec<Op> = vec![
            Op::Append(U64::new(0)),
            Op::Append(U64::new(u64::MAX)),
            Op::Commit(None, Location::new(0)),
            Op::Commit(Some(U64::new(42)), Location::new(1234)),
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
        let commit = Op::Commit(Some(U64::new(1)), Location::new(0));
        assert_ne!(append.encode().as_ref(), commit.encode().as_ref());
    }

    #[test]
    fn context_byte_is_first() {
        let append = Op::Append(U64::new(0));
        let commit = Op::Commit(None, Location::new(0));
        assert_eq!(append.encode()[0], APPEND_CONTEXT);
        assert_eq!(commit.encode()[0], COMMIT_CONTEXT);
    }

    #[test]
    fn commit_floor_overflow_rejected() {
        // Hand-build a Commit with a varint floor of u64::MAX, which exceeds MAX_LEAVES.
        use commonware_codec::{varint::UInt, Write};
        let mut buf = Vec::new();
        COMMIT_CONTEXT.write(&mut buf);
        Option::<U64>::None.write(&mut buf);
        UInt(u64::MAX).write(&mut buf);
        assert!(matches!(
            Op::decode(buf.as_ref()).unwrap_err(),
            CodecError::Invalid(_, _)
        ));
    }
}
