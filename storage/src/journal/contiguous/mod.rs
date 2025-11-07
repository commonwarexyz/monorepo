//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.

use super::Error;
use futures::Stream;
use std::num::NonZeroUsize;

pub mod fixed;
pub mod variable;

#[cfg(test)]
mod tests;

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
    fn append(&mut self, item: Self::Item)
        -> impl std::future::Future<Output = Result<u64, Error>>;

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    fn size(&self) -> u64;

    /// Return the position of the oldest item still retained in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    ///
    /// After pruning, this returns the position of the first item that remains.
    /// Note that due to section/blob alignment, this may be less than the `min_position`
    /// passed to `prune()`.
    fn oldest_retained_pos(&self) -> Option<u64>;

    /// Return the location before which all items have been pruned.
    ///
    /// If this is the same as `size()`, then all items have been pruned.
    fn pruning_boundary(&self) -> u64;

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
    ) -> impl std::future::Future<Output = Result<bool, Error>>;

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
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>>;

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
    >;

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - Returns [Error::ItemPruned] if the item at `position` has been pruned.
    /// - Returns [Error::ItemOutOfRange] if the item at `position` does not exist.
    fn read(&self, position: u64) -> impl std::future::Future<Output = Result<Self::Item, Error>>;

    /// Durably persist the journal but does not write all data, potentially leaving recovery
    /// required on startup.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(&mut self) -> impl std::future::Future<Output = Result<(), Error>>;

    /// Durably persist the journal and write all data, guaranteeing no recovery will be required
    /// on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>>;

    /// Close the journal, syncing all pending writes and releasing resources.
    fn close(self) -> impl std::future::Future<Output = Result<(), Error>>;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data including blobs,
    /// metadata, and any other storage artifacts. Use this for cleanup in tests or when
    /// permanently removing a journal.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>>;
}
