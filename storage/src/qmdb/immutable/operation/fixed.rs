use super::{Operation, COMMIT_CONTEXT, SET_CONTEXT};
use crate::qmdb::any::{value::FixedEncoding, FixedValue};
use commonware_codec::{
    util::{at_least, ensure_zeros},
    Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::Array;

/// `max(a, b)` in a const context.
const fn const_max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

const fn set_op_size<K: Array, V: FixedSize>() -> usize {
    1 + K::SIZE + V::SIZE
}

const fn commit_op_size<V: FixedSize>() -> usize {
    1 + 1 + V::SIZE
}

const fn total_op_size<K: Array, V: FixedSize>() -> usize {
    const_max(set_op_size::<K, V>(), commit_op_size::<V>())
}

impl<K: Array, V: FixedValue> FixedSize for Operation<K, FixedEncoding<V>> {
    const SIZE: usize = total_op_size::<K, V>();
}

impl<K: Array, V: FixedValue> Write for Operation<K, FixedEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        let total = total_op_size::<K, V>();
        match &self {
            Self::Set(k, v) => {
                SET_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
                buf.put_bytes(0, total - set_op_size::<K, V>());
            }
            Self::Commit(v) => {
                COMMIT_CONTEXT.write(buf);
                if let Some(v) = v {
                    true.write(buf);
                    v.write(buf);
                } else {
                    buf.put_bytes(0, 1 + V::SIZE);
                }
                buf.put_bytes(0, total - commit_op_size::<V>());
            }
        }
    }
}

impl<K: Array, V: FixedValue> Read for Operation<K, FixedEncoding<V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let total = total_op_size::<K, V>();
        at_least(buf, total)?;

        match u8::read(buf)? {
            SET_CONTEXT => {
                let key = K::read(buf)?;
                let value = V::read(buf)?;
                ensure_zeros(buf, total - set_op_size::<K, V>())?;
                Ok(Self::Set(key, value))
            }
            COMMIT_CONTEXT => {
                let is_some = bool::read(buf)?;
                let value = if is_some {
                    Some(V::read(buf)?)
                } else {
                    ensure_zeros(buf, V::SIZE)?;
                    None
                };
                ensure_zeros(buf, total - commit_op_size::<V>())?;
                Ok(Self::Commit(value))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::sequence::U64;

    type FixedOp = Operation<U64, FixedEncoding<U64>>;

    #[test]
    fn test_fixed_size() {
        // Set: 1 + 8 + 8 = 17
        // Commit: 1 + 1 + 8 = 10
        // Max = 17
        assert_eq!(FixedOp::SIZE, 17);
    }

    #[test]
    fn test_uniform_encoding_size() {
        let set_op = FixedOp::Set(U64::new(1), U64::new(2));
        let commit_some = FixedOp::Commit(Some(U64::new(3)));
        let commit_none = FixedOp::Commit(None);

        assert_eq!(set_op.encode().len(), FixedOp::SIZE);
        assert_eq!(commit_some.encode().len(), FixedOp::SIZE);
        assert_eq!(commit_none.encode().len(), FixedOp::SIZE);
    }

    #[test]
    fn test_roundtrip() {
        let operations: Vec<FixedOp> = vec![
            FixedOp::Set(U64::new(1234), U64::new(56789)),
            FixedOp::Commit(Some(U64::new(42))),
            FixedOp::Commit(None),
        ];

        for op in operations {
            let encoded = op.encode();
            assert_eq!(encoded.len(), FixedOp::SIZE);
            let decoded = FixedOp::decode(encoded).unwrap();
            assert_eq!(op, decoded, "Failed to roundtrip: {op:?}");
        }
    }

    #[test]
    fn test_invalid_context() {
        let mut invalid = vec![0xFF];
        invalid.resize(FixedOp::SIZE, 0);
        let decoded = FixedOp::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn test_insufficient_buffer() {
        let invalid = vec![SET_CONTEXT];
        let decoded = FixedOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_nonzero_padding_rejected() {
        let op = FixedOp::Set(U64::new(1), U64::new(2));
        let mut encoded: Vec<u8> = op.encode().to_vec();
        // Corrupt padding byte (only if there is padding)
        if set_op_size::<U64, U64>() < total_op_size::<U64, U64>() {
            let last = encoded.len() - 1;
            encoded[last] = 0xFF;
            let decoded = FixedOp::decode(encoded.as_ref());
            assert!(decoded.is_err());
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<FixedOp>
        }
    }
}
