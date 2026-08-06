//! Async read-only trait for merkleized data structures.

use crate::merkle::{Error, Family, Location, Position, mem::Mem};
use commonware_cryptography::Digest;
use core::future::Future;

/// An async trait for accessing Merkle node digests from storage.
pub trait Storage: Send + Sync {
    /// The Merkle family implemented by this storage.
    type Family: Family;

    /// The digest type used by this storage.
    type Digest: Digest;

    /// Return the number of nodes in the structure.
    fn size(&self) -> Position<Self::Family>;

    /// Return the specified node of the structure if it exists and hasn't been pruned.
    fn get_node(
        &self,
        position: Position<Self::Family>,
    ) -> impl Future<Output = Result<Option<Self::Digest>, Error<Self::Family>>> + Send;

    /// Return the pinned nodes needed to authenticate a lower leaf boundary at `loc`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if `loc` is not a valid location.
    /// - Returns [Error::ElementPruned] if a node the boundary requires has been pruned.
    fn pinned_nodes_at(
        &self,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Vec<Self::Digest>, Error<Self::Family>>> + Send {
        async move {
            if !loc.is_valid() {
                return Err(Error::LocationOverflow(loc));
            }
            let nodes = Self::Family::nodes_to_pin(loc)
                .map(|p| async move { self.get_node(p).await?.ok_or(Error::ElementPruned(p)) })
                .collect::<Vec<_>>();
            futures::future::try_join_all(nodes).await
        }
    }
}

impl<F, D> Storage for Mem<F, D>
where
    F: Family,
    D: Digest,
{
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Ok(Self::get_node(self, position))
    }
}
