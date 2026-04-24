use crate::{
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, operation::Committable},
};
use commonware_codec::{Encode as _, Error as CodecError, Read, Write};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::hex;
use std::fmt;

pub(crate) mod fixed;
pub(crate) mod update;
pub(crate) mod variable;
pub use update::Update;

pub(crate) const DELETE_CONTEXT: u8 = 0xD1;
pub(crate) const UPDATE_CONTEXT: u8 = 0xD2;
pub(crate) const COMMIT_CONTEXT: u8 = 0xD3;

pub type Ordered<F, K, V> = Operation<F, update::Ordered<K, V>>;
pub type Unordered<F, K, V> = Operation<F, update::Unordered<K, V>>;

/// Delegates Operation-level codec (Write, Read) to the value encoding.
///
/// Fixed and variable encodings have different wire formats. Fixed pads to a uniform size,
/// variable does not. A single blanket `impl Write for Operation<F, S>` dispatches here, while the
/// two impls of this trait (on FixedEncoding and VariableEncoding) live on different Self types
/// and therefore do not overlap.
pub trait OperationCodec<F: Family, S: Update<ValueEncoding = Self>>:
    ValueEncoding + Sized
{
    type ReadCfg: Clone + Send + Sync + 'static;

    fn write_operation(op: &Operation<F, S>, buf: &mut impl BufMut);
    fn read_operation(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<F, S>, CodecError>;
}

#[derive(Clone, PartialEq, Debug)]
pub enum Operation<F: Family, S: Update> {
    Delete(S::Key),
    Update(S),
    CommitFloor(Option<S::Value>, Location<F>),
}

#[cfg(feature = "arbitrary")]
impl<F: Family, S: Update> arbitrary::Arbitrary<'_> for Operation<F, S>
where
    S::Key: for<'a> arbitrary::Arbitrary<'a>,
    S::Value: for<'a> arbitrary::Arbitrary<'a>,
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

impl<F: Family, S: Update> crate::qmdb::operation::Operation<F> for Operation<F, S> {
    type Key = S::Key;

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

    fn has_floor(&self) -> Option<Location<F>> {
        match self {
            Self::CommitFloor(_, loc) => Some(*loc),
            _ => None,
        }
    }
}

impl<F: Family, S: Update> Committable for Operation<F, S> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::CommitFloor(_, _))
    }
}

// Blanket Write via delegation.
impl<F: Family, S: Update> Write for Operation<F, S>
where
    S::ValueEncoding: OperationCodec<F, S>,
{
    fn write(&self, buf: &mut impl BufMut) {
        S::ValueEncoding::write_operation(self, buf)
    }
}

// Blanket Read via delegation.
impl<F: Family, S: Update> Read for Operation<F, S>
where
    S::ValueEncoding: OperationCodec<F, S>,
{
    type Cfg = <S::ValueEncoding as OperationCodec<F, S>>::ReadCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        S::ValueEncoding::read_operation(buf, cfg)
    }
}

impl<F: Family, S: Update> fmt::Display for Operation<F, S> {
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
    use crate::qmdb::any::value::{FixedEncoding, VariableEncoding};
    use commonware_codec::{Codec, RangeCfg, Read};
    use commonware_utils::sequence::FixedBytes;

    type F = crate::merkle::mmr::Family;

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
        type Op = Ordered<F, K, FixedEncoding<V>>;

        let delete = Op::Delete(FixedBytes::from([1, 2, 3, 4]));
        let update = Op::Update(update::Ordered {
            key: FixedBytes::from([4, 3, 2, 1]),
            value: 0xdead_beef_u64,
            next_key: FixedBytes::from([9, 9, 9, 9]),
        });
        let commit_some = Op::CommitFloor(Some(123u64), crate::mmr::Location::new(5));
        let commit_none = Op::CommitFloor(None, crate::mmr::Location::new(7));

        roundtrip(&delete, &());
        roundtrip(&update, &());
        roundtrip(&commit_some, &());
        roundtrip(&commit_none, &());
    }

    #[test]
    fn unordered_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;
        type Op = Unordered<F, K, FixedEncoding<V>>;

        let delete = Op::Delete(FixedBytes::from([0, 0, 0, 1]));
        let update = Op::Update(update::Unordered(FixedBytes::from([9, 8, 7, 6]), 77u64));
        let commit = Op::CommitFloor(Some(555u64), crate::mmr::Location::new(3));

        roundtrip(&delete, &());
        roundtrip(&update, &());
        roundtrip(&commit, &());
    }

    #[test]
    fn ordered_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;
        type Op = Ordered<F, K, VariableEncoding<V>>;
        let cfg = ((), (RangeCfg::from(..), ()));

        let delete = Op::Delete(FixedBytes::from([1, 1, 1, 1]));
        let update = Op::Update(update::Ordered {
            key: FixedBytes::from([2, 2, 2, 2]),
            value: vec![1, 2, 3, 4, 5],
            next_key: FixedBytes::from([3, 3, 3, 3]),
        });
        let commit_some = Op::CommitFloor(Some(vec![9, 9, 9]), crate::mmr::Location::new(9));
        let commit_none = Op::CommitFloor(None, crate::mmr::Location::new(10));

        roundtrip(&delete, &cfg);
        roundtrip(&update, &cfg);
        roundtrip(&commit_some, &cfg);
        roundtrip(&commit_none, &cfg);
    }

    #[test]
    fn unordered_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;
        type Op = Unordered<F, K, VariableEncoding<V>>;
        let cfg = ((), (RangeCfg::from(..), ()));

        let delete = Op::Delete(FixedBytes::from([4, 4, 4, 4]));
        let update = Op::Update(update::Unordered(
            FixedBytes::from([5, 5, 5, 5]),
            vec![7, 7, 7, 7],
        ));
        let commit = Op::CommitFloor(Some(vec![8, 8]), crate::mmr::Location::new(12));

        roundtrip(&delete, &cfg);
        roundtrip(&update, &cfg);
        roundtrip(&commit, &cfg);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::{
            merkle::{mmb, mmr},
            qmdb::any::{
                ordered::Operation as OrderedOperation, unordered::Operation as UnorderedOperation,
            },
        };
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<OrderedOperation<mmr::Family, U64, FixedEncoding<U64>>>,
            CodecConformance<OrderedOperation<mmr::Family, U64, VariableEncoding<Vec<u8>>>>,
            CodecConformance<UnorderedOperation<mmr::Family, U64, FixedEncoding<U64>>>,
            CodecConformance<UnorderedOperation<mmr::Family, U64, VariableEncoding<Vec<u8>>>>,
            CodecConformance<OrderedOperation<mmb::Family, U64, FixedEncoding<U64>>>,
            CodecConformance<OrderedOperation<mmb::Family, U64, VariableEncoding<Vec<u8>>>>,
            CodecConformance<UnorderedOperation<mmb::Family, U64, FixedEncoding<U64>>>,
            CodecConformance<UnorderedOperation<mmb::Family, U64, VariableEncoding<Vec<u8>>>>,
        }
    }
}
