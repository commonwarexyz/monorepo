//! Abstraction over a store for finalized blocks.

use crate::Block;
use commonware_cryptography::Committable;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive, Identifier},
    translator::Translator,
};
use std::{error::Error, future::Future};

// Please document the `FinalizedBlockStore` trait in consensus/src/marshal/store.rs with the expected semantics. The base implementation is on `immutable::Archive`; Take a look at `RMap` for `missing_items` and `next_gaps`. It should especially be highlighted that on `put`, the database is expected to be synced.

/// A store for finalized blocks.
pub trait FinalizedBlockStore: Send + Sync + 'static {
    /// The type of block that is stored.
    type Block: Block;

    /// The type of error returned when storing or retrieving blocks.
    type Error: Error + Send + Sync + 'static;

    /// Store a finalized block, keyed by index and commitment.
    fn put(&mut self, block: Self::Block) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Get a finalized block from the archive by its identifier.
    fn get(
        &self,
        id: Identifier<<Self::Block as Committable>::Commitment>,
    ) -> impl Future<Output = Result<Option<Self::Block>, Self::Error>> + Send;

    /// Prune the archive to the minimum index passed.
    fn prune(&mut self, min: u64) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Return the latest `n` missing items, starting from `from_height` (inclusive).
    fn missing_items(&self, from_height: u64, n: usize) -> Vec<u64>;

    /// Returns the next gap in finalized blocks.
    fn next_gap(&self, from_height: u64) -> (Option<u64>, Option<u64>);
}

impl<E, B> FinalizedBlockStore for immutable::Archive<E, B::Commitment, B>
where
    E: Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.put_sync(block.height(), block.commitment(), block)
            .await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Committable>::Commitment>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: u64) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    fn missing_items(&self, from_height: u64, n: usize) -> Vec<u64> {
        <Self as Archive>::missing_items(self, from_height, n)
    }

    fn next_gap(&self, from_height: u64) -> (Option<u64>, Option<u64>) {
        <Self as Archive>::next_gap(self, from_height)
    }
}

impl<T, E, B> FinalizedBlockStore for prunable::Archive<T, E, B::Commitment, B>
where
    T: Translator<Key = B::Commitment> + Send + Sync + 'static,
    E: Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.put_sync(block.height(), block.commitment(), block)
            .await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Committable>::Commitment>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: u64) -> Result<(), Self::Error> {
        prunable::Archive::prune(self, min).await
    }

    fn missing_items(&self, from_height: u64, n: usize) -> Vec<u64> {
        <Self as Archive>::missing_items(self, from_height, n)
    }

    fn next_gap(&self, from_height: u64) -> (Option<u64>, Option<u64>) {
        <Self as Archive>::next_gap(self, from_height)
    }
}
