use crate::qmdb::{any::value::ValueEncoding, operation::Committable};
use commonware_codec::{Encode as _, Error as CodecError, Read, Write};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::hex;
use core::fmt::Display;

pub(crate) mod fixed;
pub(crate) mod variable;

// Context byte prefixes for identifying the operation type.
const COMMIT_CONTEXT: u8 = 0;
const APPEND_CONTEXT: u8 = 1;

/// Delegates Operation-level codec (Write, Read) to the value encoding.
///
/// Fixed and variable encodings have different wire formats. Fixed pads to a uniform size,
/// variable does not. A single blanket `impl Write for Operation<V>` dispatches here, while the
/// two impls of this trait (on FixedEncoding and VariableEncoding) live on different Self types
/// and therefore do not overlap.
pub trait Codec: ValueEncoding + Sized {
    type ReadCfg: Clone + Send + Sync + 'static;

    fn write_operation(op: &Operation<Self>, buf: &mut impl BufMut);
    fn read_operation(
        buf: &mut impl Buf,
        cfg: &Self::ReadCfg,
    ) -> Result<Operation<Self>, CodecError>;
}

/// Operations for keyless stores.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Operation<V: ValueEncoding> {
    /// Wraps the value appended to the database by this operation.
    Append(V::Value),

    /// Indicates the database has been committed.
    Commit(Option<V::Value>),
}

impl<V: ValueEncoding> Operation<V> {
    /// Returns the value (if any) wrapped by this operation.
    pub fn into_value(self) -> Option<V::Value> {
        match self {
            Self::Append(value) => Some(value),
            Self::Commit(value) => value,
        }
    }
}

impl<V: Codec> Write for Operation<V> {
    fn write(&self, buf: &mut impl BufMut) {
        V::write_operation(self, buf)
    }
}

impl<V: Codec> Committable for Operation<V> {
    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }
}

impl<V: Codec> Read for Operation<V> {
    type Cfg = <V as Codec>::ReadCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        V::read_operation(buf, cfg)
    }
}

impl<V: ValueEncoding> Display for Operation<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Append(value) => write!(f, "[append value:{}]", hex(&value.encode())),
            Self::Commit(value) => {
                if let Some(value) = value {
                    write!(f, "[commit {}]", hex(&value.encode()))
                } else {
                    write!(f, "[commit]")
                }
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: ValueEncoding> arbitrary::Arbitrary<'_> for Operation<V>
where
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => Ok(Self::Append(V::Value::arbitrary(u)?)),
            1 => Ok(Self::Commit(Option::<V::Value>::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmdb::any::value::VariableEncoding;
    use commonware_codec::Encode;
    use commonware_utils::{hex, sequence::U64};

    #[test]
    fn display_append() {
        let op = Operation::<VariableEncoding<U64>>::Append(U64::new(12345));
        assert_eq!(
            format!("{op}"),
            format!("[append value:{}]", hex(&U64::new(12345).encode()))
        );
    }

    #[test]
    fn display_commit_some() {
        let op = Operation::<VariableEncoding<U64>>::Commit(Some(U64::new(42)));
        assert_eq!(
            format!("{op}"),
            format!("[commit {}]", hex(&U64::new(42).encode()))
        );
    }

    #[test]
    fn display_commit_none() {
        let op = Operation::<VariableEncoding<U64>>::Commit(None);
        assert_eq!(format!("{op}"), "[commit]");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Operation;
        use crate::qmdb::any::value::{FixedEncoding, VariableEncoding};
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<Operation<VariableEncoding<U64>>>,
            CodecConformance<Operation<FixedEncoding<U64>>>
        }
    }
}
