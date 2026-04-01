use crate::qmdb::{
    any::{value::FixedEncoding, FixedValue},
    keyless::operation::{Codec, Operation, APPEND_CONTEXT, COMMIT_CONTEXT},
};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    Error as CodecError, FixedSize, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};

/// Total padded operation size: context byte + option-tag byte + value.
/// Append: 1 (context) + V::SIZE + 1 (padding for the option tag).
/// Commit: 1 (context) + 1 (option tag) + V::SIZE.
/// Both are 2 + V::SIZE.
const fn op_size<V: FixedSize>() -> usize {
    2 + V::SIZE
}

impl<V: FixedValue> Codec for FixedEncoding<V> {
    type ReadCfg = ();

    fn write_operation(op: &Operation<Self>, buf: &mut impl BufMut) {
        let total = op_size::<V>();
        match op {
            Operation::Append(value) => {
                APPEND_CONTEXT.write(buf);
                value.write(buf);
                // Pad to uniform size (1 byte for the option-tag gap).
                buf.put_bytes(0, total - 1 - V::SIZE);
            }
            Operation::Commit(metadata) => {
                COMMIT_CONTEXT.write(buf);
                if let Some(metadata) = metadata {
                    true.write(buf);
                    metadata.write(buf);
                } else {
                    buf.put_bytes(0, 1 + V::SIZE);
                }
            }
        }
    }

    fn read_operation(
        buf: &mut impl Buf,
        _cfg: &Self::ReadCfg,
    ) -> Result<Operation<Self>, CodecError> {
        let total = op_size::<V>();
        at_least(buf, total)?;

        match u8::read(buf)? {
            APPEND_CONTEXT => {
                let value = V::read(buf)?;
                ensure_zeros(buf, total - 1 - V::SIZE)?;
                Ok(Operation::Append(value))
            }
            COMMIT_CONTEXT => {
                let is_some = bool::read(buf)?;
                let metadata = if is_some {
                    Some(V::read(buf)?)
                } else {
                    ensure_zeros(buf, V::SIZE)?;
                    None
                };
                Ok(Operation::Commit(metadata))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

impl<V: FixedValue> FixedSize for Operation<FixedEncoding<V>> {
    const SIZE: usize = op_size::<V>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_utils::sequence::U64;

    type Op = Operation<FixedEncoding<U64>>;

    #[test]
    fn all_variants_have_same_encoded_size() {
        let append = Op::Append(U64::new(42));
        let commit_some = Op::Commit(Some(U64::new(99)));
        let commit_none = Op::Commit(None);

        let a = append.encode();
        let b = commit_some.encode();
        let c = commit_none.encode();

        assert_eq!(a.len(), Op::SIZE);
        assert_eq!(b.len(), Op::SIZE);
        assert_eq!(c.len(), Op::SIZE);
        assert_eq!(Op::SIZE, 2 + U64::SIZE);
    }

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
    fn invalid_context_byte_rejected() {
        let mut buf = vec![0u8; Op::SIZE];
        buf[0] = 0xFF;
        assert!(matches!(
            Op::decode(buf.as_ref()).unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn non_zero_padding_rejected() {
        // Encode an Append, then corrupt the padding byte.
        let op = Op::Append(U64::new(1));
        let mut buf: Vec<u8> = op.encode().to_vec();
        // Padding is the last byte (option-tag gap).
        *buf.last_mut().unwrap() = 0x01;
        assert!(Op::decode(buf.as_ref()).is_err());
    }

    #[test]
    fn truncated_input_rejected() {
        let op = Op::Append(U64::new(1));
        let buf = op.encode();
        // One byte short.
        assert!(Op::decode(&buf[..buf.len() - 1]).is_err());
    }

    #[test]
    fn commit_none_has_zero_value_bytes() {
        let op = Op::Commit(None);
        let buf: Vec<u8> = op.encode().to_vec();
        // After context byte (0) and option-tag byte (0), all value bytes should be zero.
        assert!(buf[2..].iter().all(|&b| b == 0));
    }
}
