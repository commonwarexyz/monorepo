//! The operation type a compact db is built over.

use crate::{
    merkle::{Family, Location},
    qmdb::operation::Floored,
};
use commonware_codec::CodecShared;

pub(in crate::qmdb) mod sealed {
    pub trait Sealed {}
}

/// The operation type a compact db is built over.
pub trait Variant<F: Family>: sealed::Sealed + Floored<F> + CodecShared + Clone + 'static {
    /// The commit metadata type.
    type Metadata: Clone + Send + Sync + 'static;

    /// The mutations a batch accumulates before merkleization.
    type Mutations: Default + Send;

    /// The variant's name, recorded on tracing spans.
    const NAME: &'static str;

    /// Build a commit operation.
    fn commit(metadata: Option<Self::Metadata>, inactivity_floor_loc: Location<F>) -> Self;

    /// The metadata carried by a commit operation; `None` for any other operation.
    fn metadata(&self) -> Option<&Self::Metadata>;

    /// Turn a batch's mutations into operations, in application order.
    fn into_ops(mutations: Self::Mutations) -> impl ExactSizeIterator<Item = Self> + Send;
}
