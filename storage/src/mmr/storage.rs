//! Defines the abstraction allowing MMRs with differing backends and representations to be
//! uniformly accessed.

use crate::mmr::{mem::Mmr as MemMmr, Error};
use commonware_cryptography::{Digest, Hasher as CHasher};
use std::future::Future;

/// A trait for accessing MMR digests from storage.
pub trait Storage<D: Digest>: Send + Sync {
    /// Return the number of elements in the MMR.
    fn size(&self) -> u64;

    /// Return the specified node of the MMR if it exists & hasn't been pruned.
    fn get_node(&self, position: u64) -> impl Future<Output = Result<Option<D>, Error>> + Send;
}

impl<H: CHasher> Storage<H::Digest> for MemMmr<H>
where
    H: CHasher,
{
    fn size(&self) -> u64 {
        self.size()
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        Ok(MemMmr::get_node(self, position))
    }
}
