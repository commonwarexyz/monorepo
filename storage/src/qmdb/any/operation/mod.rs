use crate::{
    mmr::Location,
    qmdb::{any::value::ValueEncoding, operation::Committable},
};
use commonware_codec::{Codec, Encode as _};
use commonware_utils::{hex, Array};
use std::fmt;

mod fixed;
mod variable;

pub(super) mod update;
pub(super) use update::Update;

const DELETE_CONTEXT: u8 = 0xD1;
const UPDATE_CONTEXT: u8 = 0xD2;
const COMMIT_CONTEXT: u8 = 0xD3;

pub type Ordered<K, V> = Operation<K, V, update::Ordered<K, V>>;
pub type Unordered<K, V> = Operation<K, V, update::Unordered<K, V>>;

#[derive(Clone, PartialEq, Debug)]
pub enum Operation<K: Array, V: ValueEncoding, S: Update<K, V>> {
    Delete(K),
    Update(S),
    CommitFloor(Option<V::Value>, Location),
}

#[cfg(feature = "arbitrary")]
impl<K: Array, V: ValueEncoding, S: Update<K, V>> arbitrary::Arbitrary<'_> for Operation<K, V, S>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
    S: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::Delete(u.arbitrary()?)),
            1 => Ok(Self::Update(u.arbitrary()?)),
            2 => Ok(Self::CommitFloor(u.arbitrary()?, u.arbitrary()?)),
            _ => unreachable!(),
        }
    }
}

impl<K, V, S> crate::qmdb::operation::Operation for Operation<K, V, S>
where
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
    S: Update<K, V>,
{
    type Key = K;

    fn key(&self) -> Option<&Self::Key> {
        match self {
            Self::Delete(k) => Some(k),
            Self::Update(p) => Some(p.key()),
            Self::CommitFloor(_, _) => None,
        }
    }

    fn is_update(&self) -> bool {
        matches!(self, Self::Update(_))
    }

    fn is_delete(&self) -> bool {
        matches!(self, Self::Delete(_))
    }

    fn has_floor(&self) -> Option<Location> {
        match self {
            Self::CommitFloor(_, loc) => Some(*loc),
            _ => None,
        }
    }
}

impl<K, V, S> Committable for Operation<K, V, S>
where
    K: Array,
    V: ValueEncoding,
    V::Value: Codec,
    S: Update<K, V>,
{
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

impl<K, V> fmt::Display for Operation<K, V, update::Ordered<K, V>>
where
    K: Array + fmt::Display,
    V: ValueEncoding,
    V::Value: Codec,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{key} <deleted>]"),
            Self::Update(payload) => payload.fmt(f),
            Self::CommitFloor(value, loc) => {
                if let Some(value) = value {
                    write!(
                        f,
                        "[commit {} with inactivity floor: {loc}]",
                        hex(&value.encode())
                    )
                } else {
                    write!(f, "[commit with inactivity floor: {loc}]")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmdb::any::value::{FixedEncoding, VariableEncoding};
    use commonware_codec::{Codec, RangeCfg, Read};
    use commonware_utils::sequence::FixedBytes;

    fn roundtrip<T>(value: &T, cfg: &<T as Read>::Cfg)
    where
        T: Codec + PartialEq + std::fmt::Debug,
    {
        let encoded = value.encode().freeze();
        let decoded = T::decode_cfg(encoded.clone(), cfg).expect("decode");
        assert_eq!(decoded, *value);
        let encoded2 = decoded.encode();
        assert_eq!(encoded, encoded2.freeze());
    }

    #[test]
    fn ordered_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;
        type Op = Ordered<K, FixedEncoding<V>>;

        let delete = Op::Delete(FixedBytes::from([1, 2, 3, 4]));
        let update = Op::Update(update::Ordered {
            key: FixedBytes::from([4, 3, 2, 1]),
            value: 0xdead_beef_u64,
            next_key: FixedBytes::from([9, 9, 9, 9]),
        });
        let commit_some = Op::CommitFloor(Some(123u64), crate::mmr::Location::new_unchecked(5));
        let commit_none = Op::CommitFloor(None, crate::mmr::Location::new_unchecked(7));

        roundtrip(&delete, &());
        roundtrip(&update, &());
        roundtrip(&commit_some, &());
        roundtrip(&commit_none, &());
    }

    #[test]
    fn unordered_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;
        type Op = Unordered<K, FixedEncoding<V>>;

        let delete = Op::Delete(FixedBytes::from([0, 0, 0, 1]));
        let update = Op::Update(update::Unordered(FixedBytes::from([9, 8, 7, 6]), 77u64));
        let commit = Op::CommitFloor(Some(555u64), crate::mmr::Location::new_unchecked(3));

        roundtrip(&delete, &());
        roundtrip(&update, &());
        roundtrip(&commit, &());
    }

    #[test]
    fn ordered_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;
        type Op = Ordered<K, VariableEncoding<V>>;
        let cfg = (RangeCfg::from(..), ());

        let delete = Op::Delete(FixedBytes::from([1, 1, 1, 1]));
        let update = Op::Update(update::Ordered {
            key: FixedBytes::from([2, 2, 2, 2]),
            value: vec![1, 2, 3, 4, 5],
            next_key: FixedBytes::from([3, 3, 3, 3]),
        });
        let commit_some =
            Op::CommitFloor(Some(vec![9, 9, 9]), crate::mmr::Location::new_unchecked(9));
        let commit_none = Op::CommitFloor(None, crate::mmr::Location::new_unchecked(10));

        roundtrip(&delete, &cfg);
        roundtrip(&update, &cfg);
        roundtrip(&commit_some, &cfg);
        roundtrip(&commit_none, &cfg);
    }

    #[test]
    fn unordered_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;
        type Op = Unordered<K, VariableEncoding<V>>;
        let cfg = (RangeCfg::from(..), ());

        let delete = Op::Delete(FixedBytes::from([4, 4, 4, 4]));
        let update = Op::Update(update::Unordered(
            FixedBytes::from([5, 5, 5, 5]),
            vec![7, 7, 7, 7],
        ));
        let commit = Op::CommitFloor(Some(vec![8, 8]), crate::mmr::Location::new_unchecked(12));

        roundtrip(&delete, &cfg);
        roundtrip(&update, &cfg);
        roundtrip(&commit, &cfg);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::qmdb::any::{
            ordered::Operation as OrderedOperation, unordered::Operation as UnorderedOperation,
        };
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<OrderedOperation<U64, FixedEncoding<U64>>>,
            CodecConformance<OrderedOperation<U64, VariableEncoding<Vec<u8>>>>,
            CodecConformance<UnorderedOperation<U64, FixedEncoding<U64>>>,
            CodecConformance<UnorderedOperation<U64, VariableEncoding<Vec<u8>>>>,
        }
    }
}
