//! Interface for a store of finalized blocks, used by [Actor](super::Actor).

use crate::Block;
use commonware_cryptography::Committable;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive, Identifier},
    translator::Translator,
};
use std::{error::Error, future::Future};

/// Durable store for finalized [Blocks](Block) keyed by height and commitment.
pub trait FinalizedBlockStore: Send + Sync + 'static {
    /// The type of [Block] that is stored.
    type Block: Block;

    /// The type of error returned when storing or retrieving blocks.
    type Error: Error + Send + Sync + 'static;

    /// Store a finalized block, keyed by height and commitment.
    ///
    /// Implementations must durably sync the write before returning; successful completion
    /// implies that the block is persisted.
    ///
    /// # Arguments
    ///
    /// * `block`: The finalized block, which provides its `height()` and `commitment()`.
    ///
    /// # Returns
    ///
    /// `Ok(())` once the write is synced, or `Err` if persistence fails.
    fn put(&mut self, block: Self::Block) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieve a finalized block by height or commitment.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the block height or
    /// its commitment.
    ///
    /// # Arguments
    ///
    /// * `id`: The block identifier (height or commitment) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(block))` if present, `Ok(None)` if missing, or `Err` on read failure.
    fn get(
        &self,
        id: Identifier<<Self::Block as Committable>::Commitment>,
    ) -> impl Future<Output = Result<Option<Self::Block>, Self::Error>> + Send;

    /// Prune the archive to the provided minimum height (inclusive).
    ///
    /// # Arguments
    ///
    /// * `min`: The lowest height that must remain after pruning.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is applied or unnecessary; `Err` if pruning fails.
    fn prune(&mut self, min: u64) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    ///
    /// # Arguments
    ///
    /// * `start`: The index to start searching from (inclusive).
    /// * `max`: The maximum number of missing items to return.
    ///
    /// # Returns
    ///
    /// A vector containing up to `max` missing indices from gaps between ranges.
    /// The vector may contain fewer than `max` items if there aren't enough gaps.
    /// If there are no more ranges after the current position, no items are returned.
    fn missing_items(&self, start: u64, max: usize) -> Vec<u64>;

    /// Finds the end of the range containing `value` and the start of the
    /// range succeeding `value`. This method is useful for identifying gaps around a given point.
    ///
    /// # Arguments
    ///
    /// - `value`: The `u64` value to query around.
    ///
    /// # Behavior
    ///
    /// - If `value` falls within an existing range `[r_start, r_end]`, `current_range_end` will be `Some(r_end)`.
    /// - If `value` falls in a gap between two ranges `[..., prev_end]` and `[next_start, ...]`,
    ///   `current_range_end` will be `None` and `next_range_start` will be `Some(next_start)`.
    /// - If `value` is before all ranges in the store, `current_range_end` will be `None`.
    /// - If `value` is after all ranges in the store (or within the last range), `next_range_start` will be `None`.
    /// - If the store is empty, both will be `None`.
    ///
    /// # Returns
    ///
    /// A tuple `(Option<u64>, Option<u64>)` where:
    /// - The first element (`current_range_end`) is `Some(end)` of the range that contains `value`. It's `None` if `value` is before all ranges, the store is empty, or `value` is not in any range.
    /// - The second element (`next_range_start`) is `Some(start)` of the first range that begins strictly after `value`. It's `None` if no range starts after `value` or the store is empty.
    fn next_gap(&self, value: u64) -> (Option<u64>, Option<u64>);
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

    fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        <Self as Archive>::missing_items(self, start, max)
    }

    fn next_gap(&self, value: u64) -> (Option<u64>, Option<u64>) {
        <Self as Archive>::next_gap(self, value)
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

    fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        <Self as Archive>::missing_items(self, start, max)
    }

    fn next_gap(&self, value: u64) -> (Option<u64>, Option<u64>) {
        <Self as Archive>::next_gap(self, value)
    }
}
