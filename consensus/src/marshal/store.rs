//! Interface for a store of finalized blocks, used by [Actor](super::Actor).

use crate::{simplex::types::Finalization, types::Height, Block};
use commonware_cryptography::{certificate::Scheme, Committable, Digest};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive, Identifier},
    translator::Translator,
};
use futures::Stream;
use std::{error::Error, future::Future, pin::Pin};

/// Durable store for [Finalizations](Finalization) keyed by height and commitment.
pub trait Certificates: Send + Sync + 'static {
    /// The type of commitment included in consensus certificates.
    type Commitment: Digest;

    /// The type of signing [Scheme] used by consensus.
    type Scheme: Scheme;

    /// The type of error returned when storing, retrieving, or pruning finalizations.
    type Error: Error + Send + Sync + 'static;

    /// Store a finalization certificate, keyed by height and commitment.
    ///
    /// Implementations must:
    /// - Durably sync the write before returning; successful completion implies that the certificate is persisted.
    /// - Ignore overwrites for an existing finalization at the same height or commitment.
    ///
    /// # Arguments
    ///
    /// * `height`: The application height associated with the finalization.
    /// * `commitment`: The block commitment associated with the finalization.
    /// * `finalization`: The finalization certificate.
    ///
    /// # Returns
    ///
    /// `Ok(())` once the write is synced, or `Err` if persistence fails.
    fn put(
        &mut self,
        height: Height,
        commitment: Self::Commitment,
        finalization: Finalization<Self::Scheme, Self::Commitment>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieve a [Finalization] by height or commitment.
    ///
    /// The [Identifier] is borrowed from the [archive] API and allows lookups via either the application height or
    /// its commitment.
    ///
    /// # Arguments
    ///
    /// * `id`: The finalization identifier (height or commitment) to fetch.
    ///
    /// # Returns
    ///
    /// `Ok(Some(finalization))` if present, `Ok(None)` if missing, or `Err` on read failure.
    #[allow(clippy::type_complexity)]
    fn get(
        &self,
        id: Identifier<'_, Self::Commitment>,
    ) -> impl Future<
        Output = Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error>,
    > + Send;

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
    fn last_index(&self) -> impl Future<Output = Result<Option<Height>, Self::Error>> + Send;
}

/// Durable store for finalized [Blocks](Block) keyed by height and commitment.
pub trait Blocks: Send + Sync + 'static {
    /// The type of [Block] that is stored.
    type Block: Block;

    /// The type of error returned when storing, retrieving, or pruning blocks.
    type Error: Error + Send + Sync + 'static;

    type MissingItemsStream<'a>: Stream<Item = Result<Height, Self::Error>> + Send + 'a
    where
        Self: 'a;

    /// Store a finalized block, keyed by height and commitment.
    ///
    /// Implementations must:
    /// - Durably sync the write before returning; successful completion implies that the block is persisted.
    /// - Ignore overwrites for an existing block at the same height or commitment.
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
        id: Identifier<'_, <Self::Block as Committable>::Commitment>,
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
    fn missing_items(
        &self,
        start: Height,
        max: usize,
    ) -> impl Future<Output = Result<Self::MissingItemsStream<'_>, Self::Error>> + Send;

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
    fn next_gap(
        &self,
        value: Height,
    ) -> impl Future<Output = Result<(Option<Height>, Option<Height>), Self::Error>> + Send;
}

impl<E, C, S> Certificates for immutable::Archive<E, C, Finalization<S, C>>
where
    E: Storage + Metrics + Clock,
    C: Digest,
    S: Scheme,
{
    type Commitment = C;
    type Scheme = S;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        commitment: Self::Commitment,
        finalization: Finalization<S, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        self.put_sync(height.get(), commitment, finalization).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::Commitment>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    async fn last_index(&self) -> Result<Option<Height>, Self::Error> {
        Ok(<Self as Archive>::last_index(self).map(Height::new))
    }
}

impl<E, B> Blocks for immutable::Archive<E, B::Commitment, B>
where
    E: Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    type MissingItemsStream<'a>
        = Pin<Box<dyn Stream<Item = Result<Height, Self::Error>> + Send + 'a>>
    where
        Self: 'a;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.put_sync(block.height().get(), block.commitment(), block)
            .await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Committable>::Commitment>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, _: Height) -> Result<(), Self::Error> {
        // Pruning is a no-op for immutable archives.
        Ok(())
    }

    async fn missing_items(
        &self,
        start: Height,
        max: usize,
    ) -> Result<Self::MissingItemsStream<'_>, Self::Error> {
        Ok(Box::pin(futures::stream::iter(
            <Self as Archive>::missing_items(self, start.get(), max)
                .into_iter()
                .map(Height::new)
                .map(Ok),
        )))
    }

    async fn next_gap(
        &self,
        value: Height,
    ) -> Result<(Option<Height>, Option<Height>), Self::Error> {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        Ok((a.map(Height::new), b.map(Height::new)))
    }
}

impl<T, E, C, S> Certificates for prunable::Archive<T, E, C, Finalization<S, C>>
where
    T: Translator,
    E: Storage + Metrics + Clock,
    C: Digest,
    S: Scheme,
{
    type Commitment = C;
    type Scheme = S;
    type Error = archive::Error;

    async fn put(
        &mut self,
        height: Height,
        commitment: Self::Commitment,
        finalization: Finalization<S, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        self.put_sync(height.get(), commitment, finalization).await
    }

    async fn get(
        &self,
        id: Identifier<'_, Self::Commitment>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    async fn last_index(&self) -> Result<Option<Height>, Self::Error> {
        Ok(<Self as Archive>::last_index(self).map(Height::new))
    }
}

impl<T, E, B> Blocks for prunable::Archive<T, E, B::Commitment, B>
where
    T: Translator,
    E: Storage + Metrics + Clock,
    B: Block,
{
    type Block = B;
    type Error = archive::Error;

    type MissingItemsStream<'a>
        = Pin<Box<dyn Stream<Item = Result<Height, Self::Error>> + Send + 'a>>
    where
        Self: 'a;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.put_sync(block.height().get(), block.commitment(), block)
            .await
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Committable>::Commitment>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        <Self as Archive>::get(self, id).await
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        Self::prune(self, min.get()).await
    }

    async fn missing_items(
        &self,
        start: Height,
        max: usize,
    ) -> Result<Self::MissingItemsStream<'_>, Self::Error> {
        Ok(Box::pin(futures::stream::iter(
            <Self as Archive>::missing_items(self, start.get(), max)
                .into_iter()
                .map(Height::new)
                .map(Ok),
        )))
    }

    async fn next_gap(
        &self,
        value: Height,
    ) -> Result<(Option<Height>, Option<Height>), Self::Error> {
        let (a, b) = <Self as Archive>::next_gap(self, value.get());
        Ok((a.map(Height::new), b.map(Height::new)))
    }
}
