use commonware_codec::{FixedSize, Read, Write};
use commonware_utils::Span;
use std::fmt;

/// A key that can be used for testing
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash, FixedSize, Read, Write)]
pub struct Key(pub u8);

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.0)
    }
}

impl Span for Key {}
