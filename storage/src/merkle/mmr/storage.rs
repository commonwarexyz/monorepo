//! Defines the abstraction allowing MMRs with differing backends and representations to be
//! uniformly accessed.

use crate::mmr::{hasher::Hasher, mem::Mmr, Error, Position};
use commonware_cryptography::Digest;
use std::future::Future;

/// A trait for accessing MMR digests from storage.
pub trait Storage: Send + Sync {
    /// The digest type used by this MMR.
    type Digest: Digest;

    /// Return the number of elements in the MMR.
    fn size(&self) -> impl Future<Output = Position> + Send;

    /// Return the specified node of the MMR if it exists & hasn't been pruned.
    fn get_node(
        &self,
        position: Position,
    ) -> impl Future<Output = Result<Option<Self::Digest>, Error>> + Send;
}

impl<H> Storage for Mmr<H>
where
    H: Hasher,
{
    type Digest = H::Digest;

    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<H::Digest>, Error> {
        Ok(Self::get_node(self, position))
    }
}
