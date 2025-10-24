use crate::mmr::Location;
use commonware_codec::{CodecFixed, FixedSize, Read, Write};
use commonware_utils::Array;

pub mod ordered;
pub mod unordered;

/// Methods common to fixed-size operation types.
pub trait FixedOperation: Read<Cfg = ()> + Write + FixedSize + Sized {
    /// The key type for this operation.
    type Key: Array;

    /// The value type for this operation.
    type Value: CodecFixed;

    /// Returns the commit floor location if this operation is a commit operation with a floor
    /// value, None otherwise.
    fn commit_floor(&self) -> Option<Location>;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// Returns the value if this operation involves a value, None otherwise.
    fn value(&self) -> Option<&Self::Value>;

    /// Consumes the operation and returns the value if this operation involves a value, None otherwise.
    fn into_value(self) -> Option<Self::Value>;
}
