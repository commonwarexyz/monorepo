//! The operation type a compact db is built over.

use crate::{
    merkle::{Family, Location},
    qmdb::operation::Floored,
};
use commonware_codec::CodecShared;

pub(in crate::qmdb) mod sealed {
    use crate::merkle::Family;

    /// The parts of [`super::Operation`] only the compact db uses.
    pub trait Sealed<F: Family> {
        /// The mutations a batch accumulates before merkleization. Their iteration order is the
        /// order their operations are appended.
        type Mutations: Default + Send + IntoIterator<IntoIter: ExactSizeIterator + Send>;

        /// The name recorded on tracing spans.
        const NAME: &'static str;

        /// Build the operation for one of a batch's mutations.
        fn mutation(mutation: <Self::Mutations as IntoIterator>::Item) -> Self;
    }
}

/// The operation type a compact db is built over.
///
/// Sealed: implemented by [`crate::qmdb::keyless::Operation`] and
/// [`crate::qmdb::immutable::Operation`].
pub trait Operation<F: Family>:
    sealed::Sealed<F> + Floored<F> + CodecShared + Clone + 'static
{
    /// The commit metadata type.
    type Metadata: Clone + Send + Sync + 'static;

    /// Build a commit operation.
    fn commit(metadata: Option<Self::Metadata>, inactivity_floor_loc: Location<F>) -> Self;

    /// The metadata carried by a commit operation; `None` for any other operation.
    fn metadata(&self) -> Option<&Self::Metadata>;
}
