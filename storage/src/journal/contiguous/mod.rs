//! A contiguous journal interface for position-based append-only logging.
//!
//! This module includes:
//!
//! - [Contiguous]: Trait for append-only log
//! - [Variable]: Wrapper for [super::variable::Journal] that implements [Contiguous]

use super::Error;
use futures::Stream;
use std::num::NonZeroUsize;

mod fixed;
mod variable;

#[cfg(test)]
pub(super) mod tests;

// Re-export public types
pub use variable::{Config, Variable};

/// Core trait for contiguous journals supporting sequential append operations.
///
/// A contiguous journal maintains a monotonically increasing position counter where each
/// appended item receives a unique position starting from 0.
pub trait Contiguous {
    /// The type of items stored in the journal.
    type Item;

    /// Append a new item to the journal, returning its position.
    ///
    /// Positions are monotonically increasing starting from 0. The position of each item
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

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Note on Section Alignment
    ///
    /// Some items with positions less than `min_position` may be retained.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    fn prune(
        &mut self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<bool, Error>> + Send;

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
    /// - Returns other errors if storage or decoding fails.
    fn read(
        &self,
        position: u64,
    ) -> impl std::future::Future<Output = Result<Self::Item, Error>> + Send;

    /// Sync all pending writes to storage.
    ///
    /// This ensures all previously appended items are durably persisted.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Close the journal, syncing all pending writes and releasing resources.
    ///
    /// After calling close, the journal cannot be used again.
    fn close(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data including blobs,
    /// metadata, and any other storage artifacts. Use this for cleanup in tests or when
    /// permanently removing a journal.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operations fail.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}
