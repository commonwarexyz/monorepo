//! Defines the abstraction allowing Merkle structures with differing backends and representations
//! to be uniformly accessed.

use super::{Error, MerkleFamily, Position};
use commonware_cryptography::Digest;
use std::future::Future;

/// A trait for accessing Merkle structure digests from storage.
pub trait Storage<F: MerkleFamily, D: Digest>: Send + Sync {
    /// Return the number of nodes in the structure.
    fn size(&self) -> impl Future<Output = Position<F>> + Send;

    /// Return the specified node if it exists and has not been pruned.
    fn get_node(
        &self,
        position: Position<F>,
    ) -> impl Future<Output = Result<Option<D>, Error<F>>> + Send;
}
