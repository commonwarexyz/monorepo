use crate::{
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, operation::Committable},
};
use commonware_codec::{Encode as _, Error as CodecError, Read, Write};
use commonware_formatting::hex;
use commonware_runtime::{Buf, BufMut};
use core::fmt::Display;

pub(crate) mod fixed;
pub(crate) mod variable;

// Context byte prefixes for identifying the operation type.
const COMMIT_CONTEXT: u8 = 0;
const APPEND_CONTEXT: u8 = 1;

/// Delegates Operation-level codec (Write, Read) to the value encoding.
///
/// Fixed and variable encodings have different wire formats. Fixed pads to a uniform size,
/// variable does not. A single blanket `impl Write for Operation<F, V>` dispatches here, while
/// the two impls of this trait (on FixedEncoding and VariableEncoding) live on different Self
/// types and therefore do not overlap.
pub trait Codec: ValueEncoding + Sized {
    type ReadCfg: Clone + Send + Sync + 'static;

    fn write_operation<F: Family>(op: &Operation<F, Self>, buf: &mut impl BufMut);
    fn read_operation<F: Family>(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<F, Self>, CodecError>;
}

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<F: Family, V: ValueEncoding> {
    /// Wraps the value appended to the database by this operation.
    Append(V::Value),

    /// Indicates the database has been committed, carrying optional metadata and the inactivity
    /// floor location declared by the application at commit time.
    Commit(Option<V::Value>, Location<F>),
}

impl<F: Family, V: ValueEncoding> Operation<F, V> {
    /// Returns the value (if any) wrapped by this operation.
    pub fn into_value(self) -> Option<V::Value> {
        match self {
            Self::Append(value) => Some(value),
            Self::Commit(value, _) => value,
        }
    }

    /// Returns the inactivity floor location if this is a commit operation.
    pub const fn has_floor(&self) -> Option<Location<F>> {
        match self {
            Self::Commit(_, loc) => Some(*loc),
            Self::Append(_) => None,
        }
    }
}

impl<F: Family, V: Codec> Write for Operation<F, V> {
    fn write(&self, buf: &mut impl BufMut) {
        V::write_operation(self, buf)
    }
}

impl<F: Family, V: Codec> Committable for Operation<F, V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_, _))
    }
}

impl<F: Family, V: Codec> Read for Operation<F, V> {
    type Cfg = <V as Codec>::ReadCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        V::read_operation(buf, cfg)
    }
}

impl<F: Family, V: ValueEncoding> Display for Operation<F, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Append(value) => write!(f, "[append value:{}]", hex(&value.encode())),
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
impl<F: Family, V: ValueEncoding> arbitrary::Arbitrary<'_> for Operation<F, V>
where
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => Ok(Self::Append(V::Value::arbitrary(u)?)),
            1 => {
                let metadata = Option::<V::Value>::arbitrary(u)?;
                let floor = Location::<F>::arbitrary(u)?;
                Ok(Self::Commit(metadata, floor))
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
    use commonware_formatting::hex;
    use commonware_utils::sequence::U64;

    #[test]
    fn display_append() {
        let op = Operation::<mmr::Family, VariableEncoding<U64>>::Append(U64::new(12345));
        assert_eq!(
            format!("{op}"),
            format!("[append value:{}]", hex(&U64::new(12345).encode()))
        );
    }

    #[test]
    fn display_commit_some() {
        let op = Operation::<mmr::Family, VariableEncoding<U64>>::Commit(
            Some(U64::new(42)),
            Location::new(7),
        );
        assert_eq!(
            format!("{op}"),
            format!("[commit {} floor:7]", hex(&U64::new(42).encode()))
        );
    }

    #[test]
    fn display_commit_none() {
        let op = Operation::<mmr::Family, VariableEncoding<U64>>::Commit(None, Location::new(3));
        assert_eq!(format!("{op}"), "[commit floor:3]");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Operation;
        use crate::{
            merkle::mmr,
            qmdb::any::value::{FixedEncoding, VariableEncoding},
        };
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<Operation<mmr::Family, VariableEncoding<U64>>>,
            CodecConformance<Operation<mmr::Family, FixedEncoding<U64>>>
        }
    }
}
