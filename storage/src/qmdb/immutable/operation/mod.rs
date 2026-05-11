//! Operations for immutable authenticated databases.
//!
//! This module provides the [Operation] type for databases that only support
//! adding new keyed values (no updates or deletions).
//!
//! The operation type is generic over the value encoding, which determines
//! whether operations are fixed-size or variable-size on disk.

pub(crate) mod fixed;
pub(crate) mod variable;

use crate::{
    merkle::{Family, Location},
    qmdb::{
        any::ValueEncoding,
        operation::{Key, Operation as OperationTrait},
    },
};
use commonware_codec::Encode;
use commonware_formatting::hex;
use core::fmt::Display;

// Context byte prefixes for identifying the operation type.
pub(crate) const SET_CONTEXT: u8 = 0;
pub(crate) const COMMIT_CONTEXT: u8 = 1;

/// An operation applied to an immutable authenticated database.
///
/// Unlike mutable database operations, immutable operations only support
/// setting new values and committing - no updates or deletions.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<F: Family, K: Key, V: ValueEncoding> {
    /// Set a key to a value. The key must not already exist.
    Set(K, V::Value),

    /// Commit with optional metadata and the inactivity floor location.
    /// Operations before the floor are declared inactive by the application.
    Commit(Option<V::Value>, Location<F>),
}

impl<F: Family, K: Key, V: ValueEncoding> Operation<F, K, V> {
    /// If this is an operation involving a key, returns the key. Otherwise, returns None.
    pub const fn key(&self) -> Option<&K> {
        match self {
            Self::Set(key, _) => Some(key),
            Self::Commit(_, _) => None,
        }
    }

    /// Returns true if this is a commit operation.
    pub const fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_, _))
    }

    /// Returns the inactivity floor location if this is a commit operation.
    pub const fn has_floor(&self) -> Option<Location<F>> {
        match self {
            Self::Commit(_, loc) => Some(*loc),
            Self::Set(_, _) => None,
        }
    }
}

impl<F: Family, K: Key, V: ValueEncoding> OperationTrait<F> for Operation<F, K, V> {
    type Key = K;

    fn key(&self) -> Option<&Self::Key> {
        self.key()
    }

    fn is_delete(&self) -> bool {
        // Immutable databases don't support deletion
        false
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Set(_, _))
    }

    fn has_floor(&self) -> Option<Location<F>> {
        self.has_floor()
    }
}

impl<F: Family, K: Key, V: ValueEncoding> Display for Operation<F, K, V>
where
    V::Value: Encode,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set(key, value) => {
                write!(f, "[key:{} value:{}]", hex(key), hex(&value.encode()))
            }
            Self::Commit(value, floor) => {
                if let Some(value) = value {
                    write!(f, "[commit {} floor:{}]", hex(&value.encode()), **floor)
                } else {
                    write!(f, "[commit floor:{}]", **floor)
                }
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, K: Key, V: ValueEncoding> arbitrary::Arbitrary<'_> for Operation<F, K, V>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => {
                let key = K::arbitrary(u)?;
                let value = V::Value::arbitrary(u)?;
                Ok(Self::Set(key, value))
            }
            1 => {
                let metadata = Option::<V::Value>::arbitrary(u)?;
                let max_loc = F::MAX_LEAVES;
                let floor = u.int_in_range(0..=*max_loc)?;
                Ok(Self::Commit(metadata, Location::new(floor)))
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkle::mmr, qmdb::any::value::VariableEncoding};
    use commonware_codec::Encode;
    use commonware_utils::sequence::U64;

    type VarOp = Operation<mmr::Family, U64, VariableEncoding<U64>>;

    #[test]
    fn test_operation_key() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = VarOp::Set(key.clone(), value.clone());
        assert_eq!(&key, set_op.key().unwrap());

        let commit_op = VarOp::Commit(Some(value), Location::new(0));
        assert_eq!(None, commit_op.key());

        let commit_op_none = VarOp::Commit(None, Location::new(0));
        assert_eq!(None, commit_op_none.key());
    }

    #[test]
    fn test_operation_is_commit() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = VarOp::Set(key, value.clone());
        assert!(!set_op.is_commit());

        let commit_op = VarOp::Commit(Some(value), Location::new(0));
        assert!(commit_op.is_commit());

        let commit_op_none = VarOp::Commit(None, Location::new(0));
        assert!(commit_op_none.is_commit());
    }

    #[test]
    fn test_operation_has_floor() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = VarOp::Set(key, value.clone());
        assert_eq!(
            <VarOp as OperationTrait<mmr::Family>>::has_floor(&set_op),
            None
        );

        let commit_op = VarOp::Commit(Some(value), Location::new(42));
        assert_eq!(
            <VarOp as OperationTrait<mmr::Family>>::has_floor(&commit_op),
            Some(Location::new(42))
        );

        let commit_op_none = VarOp::Commit(None, Location::new(0));
        assert_eq!(
            <VarOp as OperationTrait<mmr::Family>>::has_floor(&commit_op_none),
            Some(Location::new(0))
        );
    }

    #[test]
    fn test_operation_display() {
        let key = U64::new(1234);
        let value = U64::new(56789);

        let set_op = VarOp::Set(key.clone(), value.clone());
        assert_eq!(
            format!("{set_op}"),
            format!("[key:{} value:{}]", hex(&key), hex(&value.encode()))
        );

        let commit_op = VarOp::Commit(Some(value.clone()), Location::new(10));
        assert_eq!(
            format!("{commit_op}"),
            format!("[commit {} floor:10]", hex(&value.encode()))
        );

        let commit_op = VarOp::Commit(None, Location::new(0));
        assert_eq!(format!("{commit_op}"), "[commit floor:0]");
    }
}
