//! What the compact db needs from its operation type.

use crate::{
    merkle::{Family, Location},
    qmdb::operation::Floored,
};
use commonware_codec::CodecShared;

pub(in crate::qmdb) mod sealed {
    pub trait Sealed {}
}

/// An operation type a compact db is built over: how its commit operations are built and
/// inspected,
/// and how a batch accumulates the operations before its commit.
///
/// [`Db`](super::Db) only builds and inspects commit operations and turns a batch's mutations
/// into operations; everything else about the operation type is opaque to it. The codec is a
/// supertrait because the witness journal persists the commit operation itself, decoding it
/// with [`commonware_codec::Read::Cfg`].
pub trait Variant<F: Family>: sealed::Sealed + Floored<F> + CodecShared + Clone + 'static {
    /// The commit metadata type.
    type Metadata: Clone + Send + Sync + 'static;

    /// The mutations a batch accumulates before merkleization.
    type Mutations: Default + Send;

    /// The variant's name, recorded on tracing spans.
    const NAME: &'static str;

    /// Build a commit operation.
    fn commit_op(metadata: Option<Self::Metadata>, inactivity_floor_loc: Location<F>) -> Self;

    /// The metadata carried by a commit operation; `None` for any other operation.
    fn metadata(&self) -> Option<&Self::Metadata>;

    /// Turn a batch's mutations into operations, in application order.
    fn into_ops(mutations: Self::Mutations) -> impl ExactSizeIterator<Item = Self> + Send;
}
