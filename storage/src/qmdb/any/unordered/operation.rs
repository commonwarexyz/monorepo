//! Operations that can be applied to a QMDB.

use crate::qmdb::any::{
    todo::UnorderedUpdate,
    value::{FixedEncoding, VariableEncoding},
    Operation,
};

pub type FixedOperation<K, V> =
    Operation<UnorderedUpdate<K, FixedEncoding<V>>, K, FixedEncoding<V>>;
pub type VariableOperation<K, V> =
    Operation<UnorderedUpdate<K, VariableEncoding<V>>, K, VariableEncoding<V>>;

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::Location;
    use commonware_codec::{DecodeExt, Encode, Error as CodecError, RangeCfg};
    use commonware_utils::{hex, sequence::U64};

    type TestOp = FixedOperation<U64, U64>;

    #[test]
    fn test_operation_to_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = TestOp::Update(key.clone(), value);
        assert_eq!(&key, update_op.key().unwrap());

        let delete_op = TestOp::Delete(key.clone());
        assert_eq!(&key, delete_op.key().unwrap());

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(None, commit_op.key());
    }

    #[test]
    fn test_operation_basic() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let update_op = TestOp::Update(key.clone(), value.clone());
        assert_eq!(&key, update_op.key().unwrap());

        let from = TestOp::decode(update_op.encode()).unwrap();
        assert_eq!(&key, from.key().unwrap());
        assert_eq!(update_op, from);
        assert!(update_op.has_floor().is_none());

        let key2 = U64::new(42);
        let delete_op = TestOp::Delete(key2.clone());
        let from = TestOp::decode(delete_op.encode()).unwrap();
        assert_eq!(&key2, from.key().unwrap());
        assert_eq!(delete_op, from);

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        let from = TestOp::decode(commit_op.encode()).unwrap();
        assert!(matches!(
            from,
            TestOp::CommitFloor(None, loc) if loc == Location::new_unchecked(42)
        ));
        assert_eq!(commit_op, from);

        let commit_op = TestOp::CommitFloor(Some(value.clone()), Location::new_unchecked(42));
        let from = TestOp::decode(commit_op.encode()).unwrap();
        assert!(matches!(
            &from,
            TestOp::CommitFloor(Some(v), loc) if v == &value && *loc == Location::new_unchecked(42)
        ));
        assert_eq!(commit_op, from);

        // test non-zero byte detection in delete operation
        let mut invalid = delete_op.encode();
        invalid[U64::SIZE + 4] = 0xFF;
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::Invalid(_, _)));

        // test invalid context byte detection
        let mut invalid = delete_op.encode();
        invalid[0] = 0xFF;
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(
            decoded.unwrap_err(),
            CodecError::InvalidEnum(0xFF)
        ));

        // test invalid length detection
        let mut invalid = delete_op.encode().to_vec();
        invalid.pop();
        let decoded = TestOp::decode(invalid.as_ref());
        assert!(matches!(decoded.unwrap_err(), CodecError::EndOfBuffer));
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);
        let update_op = TestOp::Update(key.clone(), value.clone());
        assert_eq!(
            format!("{update_op}"),
            format!("[key:{key} value:{}]", hex(&value.encode()))
        );

        let key2 = U64::new(42);
        let delete_op = TestOp::Delete(key2.clone());
        assert_eq!(format!("{delete_op}"), format!("[key:{key2} <deleted>]"));

        let commit_op = TestOp::CommitFloor(None, Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op}"),
            "[commit with inactivity floor: Location(42)]"
        );

        let commit_op_with_metadata =
            TestOp::CommitFloor(Some(U64::new(1234)), Location::new_unchecked(42));
        assert_eq!(
            format!("{commit_op_with_metadata}"),
            "[commit 00000000000004d2 with inactivity floor: Location(42)]"
        );
    }

    #[test]
    fn test_operation_codec_fixed() {
        let key = U64::new(1);
        let value = U64::new(5678);
        let floor_loc = Location::new_unchecked(5);

        let update_op = TestOp::Update(key.clone(), value.clone());
        let delete_op = TestOp::Delete(key);
        let commit_none = TestOp::CommitFloor(None, floor_loc);
        let commit_some = TestOp::CommitFloor(Some(value), floor_loc);

        assert_eq!(update_op, TestOp::decode(update_op.encode()).unwrap());
        assert_eq!(delete_op, TestOp::decode(delete_op.encode()).unwrap());
        assert_eq!(commit_none, TestOp::decode(commit_none.encode()).unwrap());
        assert_eq!(commit_some, TestOp::decode(commit_some.encode()).unwrap());
    }

    #[test]
    fn test_operation_codec_variable() {
        type VarOp = VariableOperation<U64, Vec<u8>>;

        let key = U64::new(1);
        let value = b"variable".to_vec();
        let floor_loc = Location::new_unchecked(5);

        let update_op = VarOp::Update(key.clone(), value.clone());
        let delete_op = VarOp::Delete(key);
        let commit_none = VarOp::CommitFloor(None, floor_loc);
        let commit_some = VarOp::CommitFloor(Some(value), floor_loc);

        assert_eq!(
            update_op,
            VarOp::read_cfg(&mut update_op.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            delete_op,
            VarOp::read_cfg(&mut delete_op.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            commit_none,
            VarOp::read_cfg(&mut commit_none.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
        assert_eq!(
            commit_some,
            VarOp::read_cfg(&mut commit_some.encode(), &(RangeCfg::new(..), ())).unwrap()
        );
    }
}
*/
