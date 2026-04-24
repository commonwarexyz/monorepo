//! Async read-only trait for merkleized data structures.

use crate::merkle::{mem::Mem, Error, Family, Position};
use commonware_cryptography::Digest;
use core::future::Future;

/// An async trait for accessing Merkle node digests from storage.
pub trait Storage<F: Family>: Send + Sync {
    /// The digest type used by this storage.
    type Digest: Digest;

    /// Return the number of nodes in the structure.
    fn size(&self) -> impl Future<Output = Position<F>> + Send;

    /// Return the specified node of the structure if it exists and hasn't been pruned.
    fn get_node(
        &self,
        position: Position<F>,
    ) -> impl Future<Output = Result<Option<Self::Digest>, Error<F>>> + Send;
}

impl<F, D> Storage<F> for Mem<F, D>
where
    F: Family,
    D: Digest,
{
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Ok(Self::get_node(self, position))
    }
}
