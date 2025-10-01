//! Defines the abstraction allowing MMRs with differing backends and representations to be
//! uniformly accessed.

use crate::mmr::{mem::Mmr as MemMmr, Error, Position};
use commonware_cryptography::{Digest, Hasher as CHasher};
use std::future::Future;

/// A trait for accessing MMR digests from storage.
pub trait Storage<D: Digest>: Send + Sync {
    /// Return the number of elements in the MMR.
    fn size(&self) -> Position;

    /// Return the specified node of the MMR if it exists & hasn't been pruned.
    fn get_node(&self, position: Position)
        -> impl Future<Output = Result<Option<D>, Error>> + Send;
}

impl<H: CHasher> Storage<H::Digest> for MemMmr<H>
where
    H: CHasher,
{
    fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<H::Digest>, Error> {
        Ok(MemMmr::get_node(self, position))
    }
}
