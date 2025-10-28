//! An interface for journaling with position-indexed reads.
//!
//! This module includes:
//!
//! - [Contiguous]: Trait for append-only log
//! - [Variable]: Wrapper for [super::variable::Journal] that implements [Contiguous]
//! - Implementation of [Contiguous] for [super::fixed::Journal]

use super::Error;
use futures::Stream;
use std::num::NonZeroUsize;

mod fixed;
mod variable;

// Re-export public types
pub use variable::{Config, Variable};

#[cfg(test)]
pub(super) mod tests;

/// Core trait for contiguous journals supporting sequential append operations.
///
/// A contiguous journal maintains a consecutively increasing position counter where each
/// appended item receives a unique position starting from 0.
pub trait Contiguous {
    /// The type of items stored in the journal.
    type Item;

    /// Append a new item to the journal, returning its position.
    ///
    /// Positions are consecutively increasing starting from 0. The position of each item
    /// is stable across pruning (i.e., if item X has position 5, it will always have
    /// position 5 even if earlier items are pruned).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    fn append(
        &mut self,
        item: Self::Item,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send;

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    fn size(&self) -> impl std::future::Future<Output = Result<u64, Error>> + Send;

    /// Return the position of the oldest item still retained in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    ///
    /// After pruning, this returns the position of the first item that remains.
    /// Note that due to section/blob alignment, this may be less than the `min_position`
    /// passed to `prune()`.
    fn oldest_retained_pos(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Error>> + Send;

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Behavior
    ///
    /// - If `min_position > size()`, the prune is capped to `size()` (no error is returned)
    /// - Some items with positions less than `min_position` may be retained due to
    ///   section/blob alignment
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during pruning
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    fn prune(
        &mut self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<bool, Error>> + Send;

    /// Rewind the journal to the given size, discarding items from the end.
    ///
    /// After rewinding to size N, the journal will contain exactly N items
    /// (positions 0 to N-1), and the next append will receive position N.
    ///
    /// # Behavior
    ///
    /// - If `size > current_size()`, returns [Error::InvalidRewind]
    /// - If `size == current_size()`, this is a no-op
    /// - If `size < oldest_retained_pos()`, returns [Error::InvalidRewind] (can't rewind to pruned data)
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during rewinding
    ///
    /// # Warnings
    ///
    /// - This operation is not guaranteed to survive restarts until `sync()` is called
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if size is invalid (too large or points to pruned data).
    /// Returns an error if the underlying storage operation fails.
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Return a stream of all items in the journal starting from `start_pos`.
    ///
    /// Each item is yielded as a tuple `(position, item)` where position is the item's
    /// stable position in the journal.
    ///
    /// # Errors
    ///
    /// Returns an error if `start_pos` exceeds the journal size or if any storage/decoding
    /// errors occur during replay.
    fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> impl std::future::Future<
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error>,
    > + Send;

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - Returns [Error::ItemPruned] if the item at `position` has been pruned.
    /// - Returns [Error::ItemOutOfRange] if the item at `position` does not exist.
    fn read(
        &self,
        position: u64,
    ) -> impl std::future::Future<Output = Result<Self::Item, Error>> + Send;

    /// Sync all pending writes to storage.
    ///
    /// This ensures all previously appended items are durably persisted.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Close the journal, syncing all pending writes and releasing resources.
    fn close(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data including blobs,
    /// metadata, and any other storage artifacts. Use this for cleanup in tests or when
    /// permanently removing a journal.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}
