use crate::qmdb::any::value::ValueEncoding;
use commonware_utils::Array;
use std::fmt;

mod ordered;
pub use ordered::OrderedUpdate;

mod unordered;
pub use unordered::UnorderedUpdate;

/// An operation that updates a key-value pair.
pub trait Update<K: Array, V: ValueEncoding>: Clone {
    /// The updated key.
    fn key(&self) -> &K;

    /// Format the update for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
