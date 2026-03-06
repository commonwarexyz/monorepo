//! Interfaces for stores of finalized certificates and blocks.

use crate::{types::Height, Block};
use commonware_codec::CodecShared;
use commonware_cryptography::{Digest, Digestible};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive, Identifier},
    translator::Translator,
};
use std::{error::Error, future::Future};

/// Durable store for finalizations keyed by height and block digest.
pub trait Certificates: Send + Sync + 'static {
    /// The type of [Digest] used for block digests.
    type BlockDigest: Digest;

    /// The type of finalized certificate stored by this backend.
    type Finalization: CodecShared + Clone + Send + Sync + 'static;

    /// The type of error returned when storing, retrieving, or pruning finalizations.
    type Error: Error + Send + Sync + 'static;

    /// Buffer a finalization certificate for storage, keyed by height and block digest.
    ///
    /// The write is not durable until [sync](Self::sync) is called.
    ///
    /// Implementations must ignore overwrites for an existing finalization at the same
    /// height or commitment.
    ///
    /// # Arguments
    ///
    /// * `height`: The application height associated with the finalization.
    /// * `digest`: The block digest associated with the finalization.
    /// * `finalization`: The finalization certificate to store.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err` if the write fails.
    fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Self::Finalization,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Flush all buffered writes to durable storage.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieve a finalization by height or corresponding block digest.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the application height or
    /// its corresponding block digest.
    ///
    /// # Arguments
    ///
    /// * `id`: The finalization identifier (height or digest) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(finalization))` if present, `Ok(None)` if missing, or `Err` on read failure.
    #[allow(clippy::type_complexity)]
    fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> impl Future<Output = Result<Option<Self::Finalization>, Self::Error>> + Send;

    /// Prune the store to the provided minimum height (inclusive).
    ///
    /// # Arguments
    ///
    /// * `min`: The lowest height that must remain after pruning.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is applied or unnecessary; `Err` if pruning fails.
    fn prune(&mut self, min: Height) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the highest stored finalization's application height.
    ///
    /// # Returns
    /// `Some(height)` if there are any stored finalizations, or `None` if the store is empty.
    fn last_index(&self) -> Option<Height>;
}

/// Durable store for finalized [Blocks](Block) keyed by height and block digest.
pub trait Blocks: Send + Sync + 'static {
    /// The type of [Block] that is stored.
    type Block: Block;

    /// The type of error returned when storing, retrieving, or pruning blocks.
    type Error: Error + Send + Sync + 'static;

    /// Buffer a finalized block for storage, keyed by height and block digest.
    ///
    /// The write is not durable until [sync](Self::sync) is called.
    ///
    /// Implementations must ignore overwrites for an existing block at the same
    /// height or commitment.
    ///
    /// # Arguments
    ///
    /// * `block`: The finalized block, which provides its `height()` and `digest()`.
    fn put(&mut self, block: Self::Block) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Flush all buffered writes to durable storage.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieve a finalized block by height or block digest.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the block height or
    /// its block digest.
    ///
    /// # Arguments
    ///
    /// * `id`: The block identifier (height or digest) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(block))` if present, `Ok(None)` if missing, or `Err` on read failure.
    fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> impl Future<Output = Result<Option<Self::Block>, Self::Error>> + Send;

    /// Prune the store to the provided minimum height (inclusive).
    ///
    /// # Arguments
    ///
    /// * `min`: The lowest height that must remain after pruning.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is applied or unnecessary; `Err` if pruning fails.
    fn prune(&mut self, min: Height) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    ///
    /// # Arguments
    ///
    /// * `start`: The height to start searching from (inclusive).
    /// * `max`: The maximum number of missing items to return.
    ///
    /// # Returns
    ///
    /// A vector containing up to `max` missing heights from gaps between ranges.
    /// The vector may contain fewer than `max` items if there aren't enough gaps.
    /// If there are no more ranges after the current position, no items are returned.
    fn missing_items(&self, start: Height, max: usize) -> Vec<Height>;

    /// Finds the end of the range containing `value` and the start of the
    /// range succeeding `value`. This method is useful for identifying gaps around a given point.
    ///
    /// # Arguments
    ///
    /// - `value`: The height to query around.
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
    /// A tuple `(Option<Height>, Option<Height>)` where:
    /// - The first element (`current_range_end`) is `Some(end)` of the range that contains `value`. It's `None` if `value` is before all ranges, the store is empty, or `value` is not in any range.
    /// - The second element (`next_range_start`) is `Some(start)` of the first range that begins strictly after `value`. It's `None` if no range starts after `value` or the store is empty.
    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>);
}

impl<E, B, F> Certificates for immutable::Archive<E, B, F>
where
    E: BufferPooler + Storage + Metrics + Clock,
    B: Digest,
    F: CodecShared + Clone + Send + Sync + 'static,
{
    type BlockDigest = B;
    type Finalization = F;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Self::Finalization,
    ) -> Result<(), Self::Error> {
        Archive::put(self, height.get(), digest, finalization).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Self::Finalization>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }
}

impl<E, B> Blocks for immutable::Archive<E, B::Digest, B>
where
    E: BufferPooler + Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        Archive::put(self, block.height().get(), block.digest(), block).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        <Self as Archive>::missing_items(self, start.get(), max)
            .into_iter()
            .map(Height::new)
            .collect()
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        (a.map(Height::new), b.map(Height::new))
    }
}

impl<T, E, B, F> Certificates for prunable::Archive<T, E, B, F>
where
    T: Translator,
    E: BufferPooler + Storage + Metrics + Clock,
    B: Digest,
    F: CodecShared + Clone + Send + Sync + 'static,
{
    type BlockDigest = B;
    type Finalization = F;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Self::Finalization,
    ) -> Result<(), Self::Error> {
        Archive::put(self, height.get(), digest, finalization).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::BlockDigest>,
    ) -> Result<Option<Self::Finalization>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    fn last_index(&self) -> Option<Height> {
        <Self as Archive>::last_index(self).map(Height::new)
    }
}

impl<T, E, B> Blocks for prunable::Archive<T, E, B::Digest, B>
where
    T: Translator,
    E: BufferPooler + Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        Archive::put(self, block.height().get(), block.digest(), block).await
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Archive::sync(self).await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        <Self as Archive>::missing_items(self, start.get(), max)
            .into_iter()
            .map(Height::new)
            .collect()
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        (a.map(Height::new), b.map(Height::new))
    }
}
