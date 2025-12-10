//! Operations that can be applied to a database to modify its state.
//!
//! The various operation types implement the [commonware_codec::Codec] trait, allowing for a
//! persistent log of operations based on a `crate::Journal`. The _fixed_ variants additionally
//! implement [commonware_codec::CodecFixed].

use crate::mmr::Location;
use commonware_codec::Codec;
use commonware_utils::Array;

pub mod fixed;
pub mod variable;

// Context byte prefixes for identifying the operation type.
const SET_CONTEXT: u8 = 3;
const COMMIT_CONTEXT: u8 = 4;
const APPEND_CONTEXT: u8 = 5;

/// Errors returned by operation functions.

/// A trait for operations used by database variants that support mutable keyed values.
pub trait Keyed: Codec {
    /// The key type for this operation.
    type Key: Array;

    /// The value type for this operation.
    type Value: Codec + Clone;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// If this operation updates its key's value.
    fn is_update(&self) -> bool;

    /// If this operation deletes its key's value.
    fn is_delete(&self) -> bool;

    /// The inactivity floor location if this operation is a commit operation with a floor value,
    /// None otherwise.
    fn has_floor(&self) -> Option<Location>;

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    fn value(&self) -> Option<&Self::Value>;

    /// If this is an operation involving a value, returns the value. Otherwise, returns None.
    fn into_value(self) -> Option<Self::Value>;
}

/// A trait for operations used by database variants that support commit operations.
pub trait Committable {
    /// If this operation is a commit operation.
    fn is_commit(&self) -> bool;
}
