//! What the compact db needs from its operation type.

use crate::{
    merkle::{Family, Location},
    qmdb::operation::Floored,
};

pub(in crate::qmdb) mod sealed {
    pub trait Sealed {}
}

/// An operation type a compact db is built over: how its commit operations are built and read,
/// and how a batch accumulates the operations before its commit.
///
/// [`Db`](super::Db) only builds and reads commit operations and turns a batch's mutations
/// into operations; everything else about the operation type is opaque to it.
pub trait Variant<F: Family>: sealed::Sealed + Floored<F> + Clone + Send + Sync + 'static {
    /// The commit metadata type.
    type Metadata: Clone + Send + Sync + 'static;

    /// The mutations a batch accumulates before merkleization.
    type Mutations: Default + Send;

    /// The variant's name, recorded on tracing spans.
    const NAME: &'static str;

    /// Build a commit operation.
    fn commit_op(metadata: Option<Self::Metadata>, inactivity_floor_loc: Location<F>) -> Self;

    /// Split a commit operation into its metadata and inactivity floor, or `None` for any
    /// other operation.
    fn into_commit(self) -> Option<(Option<Self::Metadata>, Location<F>)>;

    /// Turn a batch's mutations into operations, in application order.
    fn into_ops(mutations: Self::Mutations) -> impl ExactSizeIterator<Item = Self> + Send;
}
