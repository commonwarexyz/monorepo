use crate::{
    mmr::Location,
    qmdb::{
        any::encoding::Encoding,
        operation::{Committable, Key},
    },
};
use commonware_codec::{Codec, Encode as _};
use commonware_utils::{hex, Array};
use std::fmt;

pub(crate) mod fixed;
pub(crate) mod update;
pub(crate) mod variable;
mod variable_codec;
pub(crate) mod varkey;
pub(crate) use update::Update;

const DELETE_CONTEXT: u8 = 0xD1;
const UPDATE_CONTEXT: u8 = 0xD2;
const COMMIT_CONTEXT: u8 = 0xD3;

pub type Ordered<E> = Operation<E, update::Ordered<E>>;
pub type Unordered<E> = Operation<E, update::Unordered<E>>;

#[derive(Clone, PartialEq, Debug)]
pub enum Operation<E: Encoding, S: Update<E>> {
    Delete(E::Key),
    Update(S),
    CommitFloor(Option<E::Value>, Location),
}

#[cfg(feature = "arbitrary")]
impl<E: Encoding, S: Update<E>> arbitrary::Arbitrary<'_> for Operation<E, S>
where
    E::Key: for<'a> arbitrary::Arbitrary<'a>,
    E::Value: for<'a> arbitrary::Arbitrary<'a>,
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

impl<E, S> crate::qmdb::operation::Operation for Operation<E, S>
where
    E: Encoding,
    E::Value: Codec,
    S: Update<E>,
{
    type Key = E::Key;

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

impl<E, S> Committable for Operation<E, S>
where
    E: Encoding,
    E::Value: Codec,
    S: Update<E>,
{
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

impl<E> fmt::Display for Operation<E, update::Ordered<E>>
where
    E: Encoding,
    E::Key: Array + fmt::Display,
    E::Value: Codec,
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

impl<E> fmt::Display for Operation<E, update::Unordered<E>>
where
    E: Encoding,
    E::Key: Key,
    E::Value: Codec,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delete(key) => write!(f, "[key:{} <deleted>]", hex(key)),
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
    use crate::qmdb::any::encoding::{Fixed, VariableValue};
    use commonware_codec::{Codec, RangeCfg, Read};
    use commonware_utils::sequence::FixedBytes;

    fn roundtrip<T>(value: &T, cfg: &<T as Read>::Cfg)
    where
        T: Codec + PartialEq + std::fmt::Debug,
    {
        let encoded = value.encode();
        let decoded = T::decode_cfg(encoded.clone(), cfg).expect("decode");
        assert_eq!(decoded, *value);
        let encoded2 = decoded.encode();
        assert_eq!(encoded, encoded2);
    }

    #[test]
    fn ordered_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;
        type Op = Ordered<Fixed<K, V>>;

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
        type Op = Unordered<Fixed<K, V>>;

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
        type Op = Ordered<VariableValue<K, V>>;
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
        type Op = Unordered<VariableValue<K, V>>;
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
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<Ordered<Fixed<U64, U64>>>,
            CodecConformance<Ordered<VariableValue<U64, Vec<u8>>>>,
            CodecConformance<Unordered<Fixed<U64, U64>>>,
            CodecConformance<Unordered<VariableValue<U64, Vec<u8>>>>,
        }
    }
}
