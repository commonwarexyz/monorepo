use super::{Operation, COMMIT_CONTEXT, SET_CONTEXT};
use crate::{
    merkle::{Family, Location},
    qmdb::{
        any::{value::VariableEncoding, VariableValue},
        operation::Key,
    },
};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut};

impl<F: Family, K: Key, V: VariableValue> EncodeSize for Operation<F, K, VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Set(k, v) => k.encode_size() + v.encode_size(),
            Self::Commit(v, floor) => v.encode_size() + UInt(**floor).encode_size(),
        }
    }
}

impl<F: Family, K: Key, V: VariableValue> Write for Operation<F, K, VariableEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        match &self {
            Self::Set(k, v) => {
                SET_CONTEXT.write(buf);
                k.write(buf);
                v.write(buf);
            }
            Self::Commit(v, floor_loc) => {
                COMMIT_CONTEXT.write(buf);
                v.write(buf);
                UInt(**floor_loc).write(buf);
            }
        }
    }
}

impl<F: Family, K: Key, V: VariableValue> Read for Operation<F, K, VariableEncoding<V>> {
    type Cfg = (<K as Read>::Cfg, <V as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            SET_CONTEXT => {
                let key = K::read_cfg(buf, &cfg.0)?;
                let value = V::read_cfg(buf, &cfg.1)?;
                Ok(Self::Set(key, value))
            }
            COMMIT_CONTEXT => {
                let metadata = Option::<V>::read_cfg(buf, &cfg.1)?;
                let floor_loc = Location::read(buf)?;
                Ok(Self::Commit(metadata, floor_loc))
            }
            e => Err(CodecError::InvalidEnum(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_codec::{DecodeExt, Encode, EncodeSize, FixedSize as _};
    use commonware_utils::sequence::U64;

    type VarOp = Operation<mmr::Family, U64, VariableEncoding<U64>>;

    #[test]
    fn test_operation_encode_decode() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        // Test Set operation
        let set_op = VarOp::Set(key, value.clone());
        let encoded = set_op.encode();
        let decoded = VarOp::decode(encoded).unwrap();
        assert_eq!(set_op, decoded);

        // Test Commit operation with value
        let commit_op = VarOp::Commit(Some(value), Location::new(100));
        let encoded = commit_op.encode();
        let decoded = VarOp::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);

        // Test Commit operation without value
        let commit_op = VarOp::Commit(None, Location::new(0));
        let encoded = commit_op.encode();
        let decoded = VarOp::decode(encoded).unwrap();
        assert_eq!(commit_op, decoded);
    }

    #[test]
    fn test_operation_encode_size() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = VarOp::Set(key, value.clone());
        assert_eq!(set_op.encode_size(), 1 + U64::SIZE + value.encode_size());
        assert_eq!(set_op.encode().len(), set_op.encode_size());

        let floor = Location::new(100);
        let commit_op = VarOp::Commit(Some(value.clone()), floor);
        assert_eq!(
            commit_op.encode_size(),
            1 + Some(value).encode_size() + UInt(*floor).encode_size()
        );
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());

        let commit_op = VarOp::Commit(None, Location::new(0));
        assert_eq!(
            commit_op.encode_size(),
            1 + Option::<U64>::None.encode_size() + UInt(0u64).encode_size()
        );
        assert_eq!(commit_op.encode().len(), commit_op.encode_size());
    }

    #[test]
    fn test_operation_invalid_context() {
        let invalid = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = VarOp::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn test_operation_insufficient_buffer() {
        let invalid = vec![SET_CONTEXT];
        let decoded = VarOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));

        let invalid = vec![COMMIT_CONTEXT];
        let decoded = VarOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_roundtrip_all_variants() {
        let key = U64::new(100);
        let value = U64::new(1000);

        let operations: Vec<VarOp> = vec![
            VarOp::Set(key, value.clone()),
            VarOp::Commit(Some(value), Location::new(50)),
            VarOp::Commit(None, Location::new(0)),
        ];

        for op in operations {
            let encoded = op.encode();
            let decoded = VarOp::decode(encoded.clone()).unwrap();
            assert_eq!(op, decoded, "Failed to roundtrip: {op:?}");
            assert_eq!(encoded.len(), op.encode_size(), "Size mismatch for: {op:?}");
        }
    }

    #[test]
    fn test_operation_variable_key_roundtrip() {
        use commonware_codec::Decode as _;

        type VecOp = Operation<mmr::Family, Vec<u8>, VariableEncoding<U64>>;

        let key = vec![1u8, 2, 3, 4, 5];
        let cfg = ((commonware_codec::RangeCfg::from(0..=100usize), ()), ());

        // Test Set with variable-length key
        let set_op = VecOp::Set(key, U64::new(42));
        let encoded = set_op.encode();
        assert_eq!(encoded.len(), set_op.encode_size());
        let decoded = VecOp::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(set_op, decoded);

        // Test Commit (key-independent, should work the same)
        let commit_op = VecOp::Commit(Some(U64::new(42)), Location::new(10));
        let encoded = commit_op.encode();
        let decoded = VecOp::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(commit_op, decoded);

        // Test empty key
        let empty_key_op = VecOp::Set(vec![], U64::new(99));
        let encoded = empty_key_op.encode();
        let decoded = VecOp::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(empty_key_op, decoded);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        type VarKeyOp = Operation<mmr::Family, Vec<u8>, VariableEncoding<U64>>;

        commonware_conformance::conformance_tests! {
            CodecConformance<VarOp>,
            CodecConformance<VarKeyOp>
        }
    }
}
