use commonware_codec::{CodecFixed, FixedSize as CodecFixedSize, Read, Write};

pub mod ordered;
pub mod unordered;

/// Methods common to operation types with fixed-sized values.
pub trait FixedSize: CodecFixedSize + Sized + Read<Cfg = ()> + Write {
    /// The value type for this operation.
    type Value: CodecFixed;

    /// Returns the value if this operation involves a value, None otherwise.
    fn value(&self) -> Option<&Self::Value>;

    /// Consumes the operation and returns the value if this operation involves a value, None otherwise.
    fn into_value(self) -> Option<Self::Value>;
}
