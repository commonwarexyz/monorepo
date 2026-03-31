use crate::merkle::{Family, Location};
use commonware_codec::CodecShared;
use core::{fmt::Debug, hash::Hash, ops::Deref};

/// Trait bound for key types used in QMDB operations. Satisfied by both fixed-size keys
/// (`Array` types) and variable-length keys (`Vec<u8>`).
pub trait Key:
    CodecShared + Clone + 'static + Eq + Ord + Hash + AsRef<[u8]> + Deref<Target = [u8]> + Debug
{
}

impl<T> Key for T where
    T: CodecShared + Clone + 'static + Eq + Ord + Hash + AsRef<[u8]> + Deref<Target = [u8]> + Debug
{
}

/// An operation that can be applied to a database.
pub trait Operation<F: Family> {
    /// The key type for this operation.
    type Key: Key;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// If this operation updates its key's value.
    fn is_update(&self) -> bool;

    /// If this operation deletes its key's value.
    fn is_delete(&self) -> bool;

    /// The inactivity floor location if this operation is a commit operation with a floor value,
    /// None otherwise.
    fn has_floor(&self) -> Option<Location<F>>;
}

/// A trait for operations used by database variants that support commit operations.
pub trait Committable {
    /// If this operation is a commit operation.
    fn is_commit(&self) -> bool;
}
