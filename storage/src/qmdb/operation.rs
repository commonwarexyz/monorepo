//! Operations that can be applied to a database to modify its state.
//!
//! The various operation types implement the [commonware_codec::Codec] trait, allowing for a
//! persistent log of operations based on a `crate::Journal`. The _fixed_ variants additionally
//! implement [commonware_codec::CodecFixed].

use crate::mmr::Location;
use commonware_utils::Array;

/// A trait for operations used by database variants that support mutable keyed values.
pub trait Keyed {
    /// The key type for this operation.
    type Key: Array;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// If this operation updates its key's value.
    fn is_update(&self) -> bool;

    /// If this operation deletes its key's value.
    fn is_delete(&self) -> bool;

    /// The inactivity floor location if this operation is a commit operation with a floor value,
    /// None otherwise.
    fn has_floor(&self) -> Option<Location>;
}

/// A trait for operations used by database variants that support commit operations.
pub trait Committable {
    /// If this operation is a commit operation.
    fn is_commit(&self) -> bool;
}
