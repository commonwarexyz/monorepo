use crate::adb::operation::Keyed;
use commonware_codec::{CodecFixed, FixedSize as CodecFixedSize};

pub mod ordered;
pub mod unordered;

/// Methods common to operation types with fixed-sized values.
pub trait FixedSize: Keyed + CodecFixedSize + Sized {
    /// The value type for this operation.
    type Value: CodecFixed;

    /// Returns the value if this operation involves a value, None otherwise.
    fn value(&self) -> Option<&Self::Value>;

    /// Consumes the operation and returns the value if this operation involves a value, None otherwise.
    fn into_value(self) -> Option<Self::Value>;
}
